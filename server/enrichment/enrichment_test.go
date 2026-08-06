package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/claims"
)

func writeMapping(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapping.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestFileResolverUsesSubjectBeforeEmail(t *testing.T) {
	path := writeMapping(t, `{
  "version": 1,
  "provider": "google",
  "allowEmailLookup": true,
  "allowedRoles": ["reader"],
  "entries": {
    "subject": {"enabled": true, "email": "user@example.com", "claims": {"employeeId": "subject-value"}, "roles": ["reader"]},
    "other": {"enabled": true, "email": "other@example.com", "claims": {"employeeId": "other-value"}, "roles": []}
  }
}`)
	resolver, err := NewFileResolver(path, "google")
	require.NoError(t, err)

	result, err := resolver.Resolve(context.Background(), Input{Identity: connector.Identity{UserID: "subject", Email: "other@example.com"}})
	require.NoError(t, err)
	require.Equal(t, "mapped", result.Status)
	require.Equal(t, claims.String("subject-value"), result.Claims["employeeId"])

	result, err = resolver.Resolve(context.Background(), Input{Identity: connector.Identity{UserID: "missing", Email: "user@example.com"}})
	require.NoError(t, err)
	require.Equal(t, "mapped", result.Status)
	require.Equal(t, claims.String("subject-value"), result.Claims["employeeId"])
}

func TestFileResolverRejectsAmbiguousEmail(t *testing.T) {
	path := writeMapping(t, `{
  "version": 1,
  "provider": "google",
  "entries": {
    "one": {"enabled": true, "email": "User@example.com"},
    "two": {"enabled": true, "email": " user@example.com "}
  }
}`)
	_, err := NewFileResolver(path, "google")
	require.ErrorContains(t, err, "ambiguous normalized email")
}

func TestRegistryAppliesApprovedClaimsAndRoles(t *testing.T) {
	path := writeMapping(t, `{
  "version": 1,
  "provider": "google",
  "allowedRoles": ["reader"],
	"entries": {"subject": {"enabled": true, "claims": {"employeeId": "  ABC  ", "secret": "do-not-emit"}, "roles": ["reader"]}}
}`)
	registry, err := NewRegistry(context.Background(), Config{
		Version: 1,
		Connectors: map[string]ConnectorConfig{
			"google-workspace": {
				Provider: "google",
				Resolver: ResolverConfig{Type: "file", Path: path},
				Claims: map[string]ClaimPolicy{
					"employeeId": {Source: "resolver.claims.employeeId", Type: "string", Emit: []string{"profile"}, Transform: "trim"},
				},
				ServerClaims: map[string][]string{"upstreamProvider": {"profile"}, "enrichmentStatus": {"profile"}},
				Groups:       &GroupPolicy{Source: "resolver.roles", Allowed: []string{"reader"}, Emit: []string{"groups"}},
			},
		},
	})
	require.NoError(t, err)

	identity, err := registry.Enrich(context.Background(), "google-workspace", connector.Identity{UserID: "subject"})
	require.NoError(t, err)
	require.Equal(t, claims.String("ABC"), identity.CustomClaims["employeeId"])
	require.Equal(t, claims.String("google"), identity.CustomClaims["upstreamProvider"])
	require.Equal(t, claims.String("mapped"), identity.CustomClaims["enrichmentStatus"])
	require.NotContains(t, identity.CustomClaims, "secret")
	require.Equal(t, []string{"reader"}, identity.Groups)
	require.Empty(t, identity.SourceClaims)
}

func TestRegistryFiltersSourceClaimsToPolicy(t *testing.T) {
	registry, err := NewRegistry(context.Background(), Config{Version: Version, Connectors: map[string]ConnectorConfig{
		"connector": {
			Provider: "test",
			Claims: map[string]ClaimPolicy{
				"department": {Source: "upstream.department", Type: "string", Emit: []string{"profile"}},
			},
		},
	}})
	require.NoError(t, err)

	identity, err := registry.Enrich(context.Background(), "connector", connector.Identity{
		SourceClaims: claims.JSONClaims{
			"department": claims.String("engineering"),
			"secret":     claims.String("must-not-reach-policy"),
		},
	})
	require.NoError(t, err)
	require.Equal(t, claims.String("engineering"), identity.CustomClaims["department"])
	require.NotContains(t, identity.CustomClaims, "secret")
	require.Empty(t, identity.SourceClaims)
}

type staticResolver struct {
	result Result
}

func (r staticResolver) Resolve(context.Context, Input) (Result, error) {
	return r.result, nil
}

func newGroupTestRegistry(roles []string, deduplicate bool, maxCount int) *Registry {
	return &Registry{policies: map[string]*policy{
		"connector": {
			groups: &compiledGroups{
				policy:     GroupPolicy{Source: "resolver.roles", Deduplicate: deduplicate},
				allowed:    map[string]struct{}{"reader": {}, "resolver": {}, "other": {}},
				maxCount:   maxCount,
				emitGroups: true,
			},
			resolver: staticResolver{result: Result{Groups: roles, Status: "mapped"}},
		},
	}}
}

func TestRegistryGroupDeduplicationSemantics(t *testing.T) {
	identity := connector.Identity{Groups: []string{"reader", "reader", "existing"}}

	deduplicated, err := newGroupTestRegistry([]string{"reader", "resolver"}, true, 2).Enrich(context.Background(), "connector", identity)
	require.NoError(t, err)
	require.Equal(t, []string{"reader", "existing", "resolver"}, deduplicated.Groups)

	withDuplicates, err := newGroupTestRegistry([]string{"reader", "resolver"}, false, 2).Enrich(context.Background(), "connector", identity)
	require.NoError(t, err)
	require.Equal(t, []string{"reader", "reader", "existing", "reader", "resolver"}, withDuplicates.Groups)
}

func TestRegistryGroupMaxCountLimitsResolverRoles(t *testing.T) {
	identity := connector.Identity{Groups: []string{"existing"}}
	_, err := newGroupTestRegistry([]string{"reader", "resolver"}, false, 1).Enrich(context.Background(), "connector", identity)
	require.ErrorContains(t, err, "resolver returned too many roles")
}

func TestServerClaimsAreOwnedAndStatusIsEmittedForUnmappedIdentity(t *testing.T) {
	path := writeMapping(t, `{"version":1,"provider":"trusted","entries":{}}`)
	_, err := NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
		"connector": {
			Provider:     "trusted",
			Resolver:     ResolverConfig{Type: "file", Path: path},
			ServerClaims: map[string][]string{"upstreamProvider": {"profile"}, "enrichmentStatus": {"profile"}},
			Claims:       map[string]ClaimPolicy{"upstreamProvider": {Source: "identity.email", Type: "string", Emit: []string{"profile"}}},
		},
	}})
	require.ErrorContains(t, err, "reserved claim")

	registry, err := NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
		"connector": {
			Provider:     "trusted",
			Resolver:     ResolverConfig{Type: "file", Path: path},
			ServerClaims: map[string][]string{"upstreamProvider": {"profile"}, "enrichmentStatus": {"profile"}},
		},
	}})
	require.NoError(t, err)
	identity, err := registry.Enrich(context.Background(), "connector", connector.Identity{
		UserID:       "missing",
		Email:        "attacker@example.com",
		SourceClaims: claims.JSONClaims{"upstreamProvider": claims.String("forged")},
	})
	require.NoError(t, err)
	require.Equal(t, claims.String("trusted"), identity.CustomClaims["upstreamProvider"])
	require.Equal(t, claims.String("unmapped"), identity.CustomClaims["enrichmentStatus"])
	require.Empty(t, identity.SourceClaims)
}

func TestRegistryRejectsReservedClaimAndMissingRequiredValue(t *testing.T) {
	_, err := NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
		"connector": {Provider: "test", Claims: map[string]ClaimPolicy{
			"email": {Source: "identity.email", Type: "string", Emit: []string{"profile"}},
		}},
	}})
	require.ErrorContains(t, err, "reserved claim")

	path := writeMapping(t, `{"version":1,"entries":{"subject":{"enabled":true}}}`)
	_, err = NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
		"connector": {Provider: "test", Resolver: ResolverConfig{Type: "file", Path: path}, Claims: map[string]ClaimPolicy{
			"employeeId": {Source: "resolver.claims.employeeId", Type: "string", Required: true, Emit: []string{"profile"}},
		}},
	}})
	require.ErrorContains(t, err, "missing required claim")
}

func TestRegistryRejectsReservedClaimsAndInvalidSources(t *testing.T) {
	for _, name := range []string{
		"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "azp", "nonce", "auth_time", "at_hash", "c_hash", "s_hash",
		"acr", "amr", "sid", "typ", "cty", "email", "email_verified", "name", "family_name", "given_name", "preferred_username", "groups",
		"federated_claims", "address", "birthdate", "gender", "locale", "middle_name", "nickname",
		"phone_number", "phone_number_verified", "picture", "profile", "updated_at", "website", "zoneinfo",
		"upstreamProvider", "enrichmentStatus",
	} {
		_, err := NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
			"connector": {Provider: "test", Claims: map[string]ClaimPolicy{
				name: {Source: "identity.email", Type: "string", Emit: []string{"profile"}},
			}},
		}})
		require.ErrorContains(t, err, "reserved claim")
	}

	for _, source := range []string{"identity.unknown", "upstream.", "upstream.\u0001", "resolver.claims.", "resolver.roles"} {
		_, err := NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
			"connector": {Provider: "test", Claims: map[string]ClaimPolicy{
				"employeeId": {Source: source, Type: "string", Emit: []string{"profile"}},
			}},
		}})
		require.ErrorContains(t, err, "unsupported source")
	}

	_, err := NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
		"connector": {Provider: "test", Resolver: ResolverConfig{Type: "database", Path: "unused"}},
	}})
	require.ErrorContains(t, err, "unknown resolver type")
}

func TestRegistryRejectsStaticRoleLimitMismatch(t *testing.T) {
	path := writeMapping(t, `{"version":1,"allowedRoles":["reader","writer"],"entries":{"subject":{"enabled":true,"roles":["reader","writer"]}}}`)
	_, err := NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
		"connector": {
			Provider: "test",
			Resolver: ResolverConfig{Type: "file", Path: path},
			Groups:   &GroupPolicy{Source: "resolver.roles", Allowed: []string{"reader", "writer"}, MaxCount: 1, Emit: []string{"groups"}},
		},
	}})
	require.ErrorContains(t, err, "too many roles")
}

func TestRegistryMakesUnmappedIdentityUnprivileged(t *testing.T) {
	path := writeMapping(t, `{"version":1,"entries":{}}`)
	registry, err := NewRegistry(context.Background(), Config{Version: 1, Connectors: map[string]ConnectorConfig{
		"connector": {Provider: "test", Resolver: ResolverConfig{Type: "file", Path: path}},
	}})
	require.NoError(t, err)

	identity, err := registry.Enrich(context.Background(), "connector", connector.Identity{
		UserID:       "missing",
		Groups:       []string{"upstream-group"},
		SourceClaims: claims.JSONClaims{"department": claims.String("engineering")},
	})
	require.NoError(t, err)
	require.Empty(t, identity.Groups)
	require.Empty(t, identity.CustomClaims)
	require.Empty(t, identity.SourceClaims)
}

func TestRegistryMakesUnconfiguredConnectorUnprivileged(t *testing.T) {
	registry, err := NewRegistry(context.Background(), Config{Version: 1, DefaultPolicy: "unprivileged"})
	require.NoError(t, err)

	identity, err := registry.Enrich(context.Background(), "unconfigured", connector.Identity{
		Groups:       []string{"upstream-group"},
		CustomClaims: claims.JSONClaims{"legacy": claims.String("value")},
		SourceClaims: claims.JSONClaims{"department": claims.String("engineering")},
	})
	require.NoError(t, err)
	require.Empty(t, identity.Groups)
	require.Empty(t, identity.CustomClaims)
	require.Empty(t, identity.SourceClaims)
}

func TestRegistryHonorsPolicyEmailFallbackOptIn(t *testing.T) {
	path := writeMapping(t, `{"version":1,"allowEmailLookup":true,"entries":{"subject":{"enabled":true,"email":"user@example.com","claims":{"employeeId":"mapped"}}}}`)
	config := Config{Version: 1, Connectors: map[string]ConnectorConfig{
		"connector": {
			Provider:      "test",
			EmailFallback: false,
			Resolver:      ResolverConfig{Type: "file", Path: path},
			Claims:        map[string]ClaimPolicy{"employeeId": {Source: "resolver.claims.employeeId", Type: "string", Emit: []string{"profile"}}},
		},
	}}
	registry, err := NewRegistry(context.Background(), config)
	require.NoError(t, err)
	identity, err := registry.Enrich(context.Background(), "connector", connector.Identity{UserID: "missing", Email: "user@example.com"})
	require.NoError(t, err)
	require.Empty(t, identity.CustomClaims)

	connectorConfig := config.Connectors["connector"]
	connectorConfig.EmailFallback = true
	config.Connectors["connector"] = connectorConfig
	registry, err = NewRegistry(context.Background(), config)
	require.NoError(t, err)
	identity, err = registry.Enrich(context.Background(), "connector", connector.Identity{UserID: "missing", Email: "user@example.com"})
	require.NoError(t, err)
	require.Equal(t, claims.String("mapped"), identity.CustomClaims["employeeId"])

	fileOptOutPath := writeMapping(t, `{"version":1,"entries":{"subject":{"enabled":true,"email":"user@example.com","claims":{"employeeId":"mapped"}}}}`)
	config.Connectors["connector"] = ConnectorConfig{
		Provider:      "test",
		EmailFallback: true,
		Resolver:      ResolverConfig{Type: "file", Path: fileOptOutPath},
		Claims:        map[string]ClaimPolicy{"employeeId": {Source: "resolver.claims.employeeId", Type: "string", Emit: []string{"profile"}}},
	}
	registry, err = NewRegistry(context.Background(), config)
	require.NoError(t, err)
	identity, err = registry.Enrich(context.Background(), "connector", connector.Identity{UserID: "missing", Email: "user@example.com"})
	require.NoError(t, err)
	require.Empty(t, identity.CustomClaims)
}

func TestFileResolverValidatesAllowedRolesWithoutEntries(t *testing.T) {
	path := writeMapping(t, `{"version":1,"allowedRoles":["\u0001"],"entries":{}}`)
	_, err := NewFileResolver(path, "test")
	require.ErrorContains(t, err, "control character")
}

func TestFileResolverRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	unknown := writeMapping(t, `{"version":1,"unknown":true}`)
	_, err := NewFileResolver(unknown, "test")
	require.ErrorContains(t, err, "unknown field")

	trailing := writeMapping(t, `{"version":1} {"version":1}`)
	_, err = NewFileResolver(trailing, "test")
	require.ErrorContains(t, err, "multiple JSON values")
}

func TestRegistryRejectsInvalidPolicyConfiguration(t *testing.T) {
	base := ClaimPolicy{Source: "identity.email", Type: "string", Emit: []string{"profile"}}
	tests := []struct {
		name    string
		policy  ClaimPolicy
		errText string
	}{
		{name: "unsupported type", policy: ClaimPolicy{Source: base.Source, Type: "integer", Emit: base.Emit}, errText: "unsupported type"},
		{name: "unsupported scope", policy: ClaimPolicy{Source: base.Source, Type: base.Type, Emit: []string{"groups"}}, errText: "unsupported output scope"},
		{name: "unsupported transform", policy: ClaimPolicy{Source: base.Source, Type: base.Type, Emit: base.Emit, Transform: "split"}, errText: "unsupported transform"},
		{name: "invalid pattern", policy: ClaimPolicy{Source: base.Source, Type: base.Type, Emit: base.Emit, Pattern: "["}, errText: "invalid pattern"},
		{name: "negative max length", policy: ClaimPolicy{Source: base.Source, Type: base.Type, Emit: base.Emit, MaxLength: -1}, errText: "invalid maxLength"},
		{name: "oversized max length", policy: ClaimPolicy{Source: base.Source, Type: base.Type, Emit: base.Emit, MaxLength: DefaultMaxLength + 1}, errText: "maxLength exceeds"},
		{name: "negative max items", policy: ClaimPolicy{Source: base.Source, Type: base.Type, Emit: base.Emit, MaxItems: -1}, errText: "invalid maxItems"},
		{name: "oversized max items", policy: ClaimPolicy{Source: base.Source, Type: base.Type, Emit: base.Emit, MaxItems: DefaultMaxArraySize + 1}, errText: "maxItems exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRegistry(context.Background(), Config{Version: Version, Connectors: map[string]ConnectorConfig{
				"connector": {Provider: "test", Claims: map[string]ClaimPolicy{"claim": test.policy}},
			}})
			require.ErrorContains(t, err, test.errText)
		})
	}

	_, err := NewRegistry(context.Background(), Config{Version: Version + 1})
	require.ErrorContains(t, err, "unsupported identity enrichment version")
	_, err = NewRegistry(context.Background(), Config{Version: Version, DefaultPolicy: "unknown"})
	require.ErrorContains(t, err, "unsupported identity enrichment defaultPolicy")
}

func TestFileResolverRejectsInvalidValuesAndRoles(t *testing.T) {
	longString, err := json.Marshal(strings.Repeat("x", DefaultMaxLength+1))
	require.NoError(t, err)
	longArray, err := json.Marshal(make([]string, DefaultMaxArraySize+1))
	require.NoError(t, err)
	controlString, err := json.Marshal("value\x00")
	require.NoError(t, err)

	tests := []struct {
		name    string
		content string
		errText string
	}{
		{
			name:    "duplicate allowed role",
			content: `{"version":1,"allowedRoles":["reader","reader"],"entries":{}}`,
			errText: "duplicate allowed role",
		},
		{
			name:    "duplicate entry role",
			content: `{"version":1,"allowedRoles":["reader"],"entries":{"subject":{"enabled":true,"roles":["reader","reader"]}}}`,
			errText: "duplicate role",
		},
		{
			name:    "unknown entry role",
			content: `{"version":1,"allowedRoles":["reader"],"entries":{"subject":{"enabled":true,"roles":["writer"]}}}`,
			errText: "unknown role",
		},
		{
			name:    "oversized string",
			content: fmt.Sprintf(`{"version":1,"entries":{"subject":{"enabled":true,"claims":{"value":%s}}}}`, longString),
			errText: "maximum is",
		},
		{
			name:    "oversized array",
			content: fmt.Sprintf(`{"version":1,"entries":{"subject":{"enabled":true,"claims":{"value":%s}}}}`, longArray),
			errText: "maximum is",
		},
		{
			name:    "control character",
			content: fmt.Sprintf(`{"version":1,"entries":{"subject":{"enabled":true,"claims":{"value":%s}}}}`, controlString),
			errText: "control character",
		},
		{
			name:    "non-finite number",
			content: `{"version":1,"entries":{"subject":{"enabled":true,"claims":{"value":1e309}}}}`,
			errText: "not finite",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewFileResolver(writeMapping(t, test.content), "test")
			require.ErrorContains(t, err, test.errText)
		})
	}
}

func TestRegistryRejectsDuplicateGroupRoles(t *testing.T) {
	_, err := NewRegistry(context.Background(), Config{Version: Version, Connectors: map[string]ConnectorConfig{
		"connector": {
			Provider: "test",
			Groups:   &GroupPolicy{Source: "resolver.roles", Allowed: []string{"reader", "reader"}, Emit: []string{"groups"}},
		},
	}})
	require.ErrorContains(t, err, "duplicate allowed role")
}
