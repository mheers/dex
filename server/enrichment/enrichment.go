// Package enrichment implements trusted, policy-driven identity enrichment.
package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/claims"
)

const (
	Version             = 1
	DefaultMaxLength    = claims.DefaultMaxStringLength
	DefaultMaxArraySize = claims.DefaultMaxArraySize
	DefaultMaxRoleCount = 32
)

var claimNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,127}$`)

// Config is the trusted top-level identity enrichment configuration.
type Config struct {
	Version       int                        `json:"version" yaml:"version"`
	DefaultPolicy string                     `json:"defaultPolicy" yaml:"defaultPolicy"`
	Connectors    map[string]ConnectorConfig `json:"connectors" yaml:"connectors"`
}

// ConnectorConfig defines the policy for one trusted connector ID.
type ConnectorConfig struct {
	Provider      string                 `json:"provider" yaml:"provider"`
	Resolver      ResolverConfig         `json:"resolver" yaml:"resolver"`
	EmailFallback bool                   `json:"emailFallback" yaml:"emailFallback"`
	Claims        map[string]ClaimPolicy `json:"claims" yaml:"claims"`
	ServerClaims  map[string][]string    `json:"serverClaims" yaml:"serverClaims"`
	Groups        *GroupPolicy           `json:"groups" yaml:"groups"`
}

// ResolverConfig selects a resolver implementation.
type ResolverConfig struct {
	Type string `json:"type" yaml:"type"`
	Path string `json:"path" yaml:"path"`
}

// ClaimPolicy controls one custom claim's source, type, bounds, and scopes.
type ClaimPolicy struct {
	Source    string   `json:"source" yaml:"source"`
	Type      string   `json:"type" yaml:"type"`
	Required  bool     `json:"required" yaml:"required"`
	Emit      []string `json:"emit" yaml:"emit"`
	MaxLength int      `json:"maxLength" yaml:"maxLength"`
	MaxItems  int      `json:"maxItems" yaml:"maxItems"`
	Pattern   string   `json:"pattern" yaml:"pattern"`
	Transform string   `json:"transform" yaml:"transform"`
}

// GroupPolicy controls explicit resolver role augmentation of groups.
type GroupPolicy struct {
	Source      string   `json:"source" yaml:"source"`
	Allowed     []string `json:"allowed" yaml:"allowed"`
	MaxCount    int      `json:"maxCount" yaml:"maxCount"`
	Deduplicate bool     `json:"deduplicate" yaml:"deduplicate"`
	Emit        []string `json:"emit" yaml:"emit"`
}

// Input is the immutable input supplied to a resolver.
type Input struct {
	ConnectorID string
	Provider    string
	Identity    connector.Identity
}

// Result is resolver output. Claims and groups remain untrusted until the
// configured policy validates and selects them.
type Result struct {
	Claims         claims.JSONClaims
	Groups         []string
	Status         string
	Resolver       string
	MappingVersion string
}

// RequiredClaimError identifies a mapped identity that cannot satisfy a
// required claim policy.
type RequiredClaimError struct {
	Err error
}

func (e *RequiredClaimError) Error() string { return e.Err.Error() }

func (e *RequiredClaimError) Unwrap() error { return e.Err }

// Resolver obtains enrichment data from a trusted source.
type Resolver interface {
	Resolve(context.Context, Input) (Result, error)
}

// Registry is immutable after construction and safe for concurrent use.
type Registry struct {
	defaultPolicy string
	policies      map[string]*policy
}

type policy struct {
	config       ConnectorConfig
	claims       map[string]compiledClaim
	sourceClaims map[string]struct{}
	serverClaims map[string][]string
	groups       *compiledGroups
	resolver     Resolver
}

type compiledClaim struct {
	name      string
	policy    ClaimPolicy
	pattern   *regexp.Regexp
	maxLength int
	maxItems  int
}

type compiledGroups struct {
	policy     GroupPolicy
	allowed    map[string]struct{}
	maxCount   int
	emitGroups bool
}

// NewRegistry validates policies and loads all configured resolvers.
func NewRegistry(ctx context.Context, config Config) (*Registry, error) {
	if config.Version != Version {
		return nil, fmt.Errorf("unsupported identity enrichment version %d", config.Version)
	}
	if config.DefaultPolicy == "" {
		config.DefaultPolicy = "disabled"
	}
	if config.DefaultPolicy != "disabled" && config.DefaultPolicy != "unprivileged" {
		return nil, fmt.Errorf("unsupported identity enrichment defaultPolicy %q", config.DefaultPolicy)
	}

	registry := &Registry{defaultPolicy: config.DefaultPolicy, policies: make(map[string]*policy, len(config.Connectors))}
	connectorIDs := make([]string, 0, len(config.Connectors))
	for connectorID := range config.Connectors {
		connectorIDs = append(connectorIDs, connectorID)
	}
	sort.Strings(connectorIDs)
	for _, connectorID := range connectorIDs {
		compiled, err := compilePolicy(ctx, connectorID, config.Connectors[connectorID])
		if err != nil {
			return nil, err
		}
		registry.policies[connectorID] = compiled
	}
	return registry, nil
}

func compilePolicy(ctx context.Context, connectorID string, config ConnectorConfig) (*policy, error) {
	if connectorID == "" {
		return nil, errors.New("identity enrichment connector ID cannot be empty")
	}
	if config.Provider == "" {
		return nil, fmt.Errorf("identity enrichment connector %q has no provider", connectorID)
	}
	if err := validateRole(config.Provider); err != nil {
		return nil, fmt.Errorf("identity enrichment connector %q provider: %v", connectorID, err)
	}

	compiled := &policy{
		config:       config,
		claims:       make(map[string]compiledClaim, len(config.Claims)),
		sourceClaims: make(map[string]struct{}),
		serverClaims: make(map[string][]string, len(config.ServerClaims)),
	}
	for name, scopes := range config.ServerClaims {
		if name != "upstreamProvider" && name != "enrichmentStatus" {
			return nil, fmt.Errorf("identity enrichment connector %q has unsupported server claim %q", connectorID, name)
		}
		if len(scopes) == 0 {
			return nil, fmt.Errorf("identity enrichment connector %q server claim %q must specify emit", connectorID, name)
		}
		for _, scope := range scopes {
			if scope != "profile" {
				return nil, fmt.Errorf("identity enrichment connector %q server claim %q has unsupported output scope %q", connectorID, name, scope)
			}
		}
		compiled.serverClaims[name] = append([]string(nil), scopes...)
	}
	claimNames := make([]string, 0, len(config.Claims))
	for name := range config.Claims {
		claimNames = append(claimNames, name)
	}
	sort.Strings(claimNames)
	for _, name := range claimNames {
		claimPolicy := config.Claims[name]
		if !claimNamePattern.MatchString(name) {
			return nil, fmt.Errorf("identity enrichment connector %q has invalid claim name %q", connectorID, name)
		}
		if isReservedClaim(name) {
			return nil, fmt.Errorf("identity enrichment connector %q cannot configure reserved claim %q", connectorID, name)
		}
		if !validSource(claimPolicy.Source) {
			return nil, fmt.Errorf("identity enrichment connector %q claim %q has unsupported source %q", connectorID, name, claimPolicy.Source)
		}
		if strings.HasPrefix(claimPolicy.Source, "upstream.") {
			compiled.sourceClaims[strings.TrimPrefix(claimPolicy.Source, "upstream.")] = struct{}{}
		}
		if !validClaimType(claimPolicy.Type) {
			return nil, fmt.Errorf("identity enrichment connector %q claim %q has unsupported type %q", connectorID, name, claimPolicy.Type)
		}
		if len(claimPolicy.Emit) == 0 {
			return nil, fmt.Errorf("identity enrichment connector %q claim %q must specify emit", connectorID, name)
		}
		for _, scope := range claimPolicy.Emit {
			if scope != "profile" {
				return nil, fmt.Errorf("identity enrichment connector %q claim %q has unsupported output scope %q", connectorID, name, scope)
			}
		}
		maxLength := claimPolicy.MaxLength
		if maxLength == 0 {
			maxLength = DefaultMaxLength
		}
		if maxLength < 1 {
			return nil, fmt.Errorf("identity enrichment connector %q claim %q has invalid maxLength", connectorID, name)
		}
		if maxLength > DefaultMaxLength {
			return nil, fmt.Errorf("identity enrichment connector %q claim %q maxLength exceeds %d", connectorID, name, DefaultMaxLength)
		}
		maxItems := claimPolicy.MaxItems
		if maxItems == 0 {
			maxItems = DefaultMaxArraySize
		}
		if maxItems < 1 {
			return nil, fmt.Errorf("identity enrichment connector %q claim %q has invalid maxItems", connectorID, name)
		}
		if maxItems > DefaultMaxArraySize {
			return nil, fmt.Errorf("identity enrichment connector %q claim %q maxItems exceeds %d", connectorID, name, DefaultMaxArraySize)
		}
		var pattern *regexp.Regexp
		if claimPolicy.Pattern != "" {
			var err error
			pattern, err = regexp.Compile(claimPolicy.Pattern)
			if err != nil {
				return nil, fmt.Errorf("identity enrichment connector %q claim %q has invalid pattern: %v", connectorID, name, err)
			}
		}
		if !validTransform(claimPolicy.Transform) {
			return nil, fmt.Errorf("identity enrichment connector %q claim %q has unsupported transform %q", connectorID, name, claimPolicy.Transform)
		}
		compiled.claims[name] = compiledClaim{name: name, policy: claimPolicy, pattern: pattern, maxLength: maxLength, maxItems: maxItems}
	}

	if config.EmailFallback && config.Resolver.Type != "file" {
		return nil, fmt.Errorf("identity enrichment connector %q emailFallback requires a file resolver", connectorID)
	}
	if config.Groups != nil {
		groups := config.Groups
		if groups.Source != "resolver.roles" {
			return nil, fmt.Errorf("identity enrichment connector %q groups source must be resolver.roles", connectorID)
		}
		if len(groups.Emit) == 0 {
			return nil, fmt.Errorf("identity enrichment connector %q groups must specify emit", connectorID)
		}
		for _, scope := range groups.Emit {
			if scope != "groups" {
				return nil, fmt.Errorf("identity enrichment connector %q groups has unsupported output scope %q", connectorID, scope)
			}
		}
		allowed := make(map[string]struct{}, len(groups.Allowed))
		for _, role := range groups.Allowed {
			if err := validateRole(role); err != nil {
				return nil, fmt.Errorf("identity enrichment connector %q: %v", connectorID, err)
			}
			if _, exists := allowed[role]; exists {
				return nil, fmt.Errorf("identity enrichment connector %q has duplicate allowed role %q", connectorID, role)
			}
			allowed[role] = struct{}{}
		}
		maxCount := groups.MaxCount
		if maxCount == 0 {
			maxCount = DefaultMaxRoleCount
		}
		if maxCount < 1 {
			return nil, fmt.Errorf("identity enrichment connector %q has invalid groups maxCount", connectorID)
		}
		if maxCount > DefaultMaxRoleCount {
			return nil, fmt.Errorf("identity enrichment connector %q groups maxCount exceeds %d", connectorID, DefaultMaxRoleCount)
		}
		compiled.groups = &compiledGroups{policy: *groups, allowed: allowed, maxCount: maxCount, emitGroups: true}
	}

	if config.Resolver.Type == "" {
		for name, claimPolicy := range compiled.claims {
			if strings.HasPrefix(claimPolicy.policy.Source, "resolver.") || compiled.groups != nil {
				return nil, fmt.Errorf("identity enrichment connector %q claim %q requires a resolver", connectorID, name)
			}
		}
	} else {
		if config.Resolver.Type != "file" {
			return nil, fmt.Errorf("identity enrichment connector %q has unknown resolver type %q", connectorID, config.Resolver.Type)
		}
		if config.Resolver.Path == "" {
			return nil, fmt.Errorf("identity enrichment connector %q file resolver has no path", connectorID)
		}
		resolver, err := NewFileResolver(config.Resolver.Path, config.Provider)
		if err != nil {
			return nil, fmt.Errorf("identity enrichment connector %q file resolver: %v", connectorID, err)
		}
		file := resolver.(*fileResolver)
		if err := validateMappingAgainstPolicy(connectorID, file.document, compiled); err != nil {
			return nil, err
		}
		file.allowEmailLookup = config.EmailFallback && file.document.AllowEmailLookup
		compiled.resolver = resolver
	}

	return compiled, nil
}

// Enrich applies the configured policy to an identity. A connector without a
// configured policy is deliberately a no-op.
func (r *Registry) Enrich(ctx context.Context, connectorID string, identity connector.Identity) (connector.Identity, error) {
	enriched, _, err := r.EnrichWithOutcome(ctx, connectorID, identity)
	return enriched, err
}

// EnrichWithOutcome applies policy and returns a finite operational outcome
// independently of whether that outcome is emitted as a custom claim.
func (r *Registry) EnrichWithOutcome(ctx context.Context, connectorID string, identity connector.Identity) (connector.Identity, string, error) {
	if r == nil {
		return identity, "disabled", nil
	}
	p, ok := r.policies[connectorID]
	if !ok {
		if r.defaultPolicy == "unprivileged" {
			identity.Groups = nil
		}
		identity.CustomClaims = nil
		identity.SourceClaims = nil
		return identity, "disabled", nil
	}
	identity = identity.Clone()
	identity.SourceClaims = filterSourceClaims(identity.SourceClaims, p.sourceClaims)
	identity.CustomClaims = claims.New()

	result := Result{Status: "mapped"}
	if p.resolver != nil {
		var err error
		result, err = p.resolver.Resolve(ctx, Input{ConnectorID: connectorID, Provider: p.config.Provider, Identity: identity})
		if err != nil {
			return identity, "resolver_error", fmt.Errorf("identity enrichment connector %q: resolve: %w", connectorID, err)
		}
		if result.Status == "" {
			result.Status = "mapped"
		}
		if result.Status != "mapped" && result.Status != "unmapped" && result.Status != "disabled" {
			return identity, "resolver_error", fmt.Errorf("identity enrichment connector %q: resolver returned invalid status %q", connectorID, result.Status)
		}
	}
	if result.Status == "unmapped" || result.Status == "disabled" {
		identity.Groups = nil
		addServerClaims(identity.CustomClaims, p, result.Status)
		identity.SourceClaims = nil
		return identity, result.Status, nil
	}
	addServerClaims(identity.CustomClaims, p, result.Status)

	for name, compiled := range p.claims {
		value, found := sourceValue(compiled.policy.Source, identity, result)
		if !found {
			if compiled.policy.Required {
				err := fmt.Errorf("identity enrichment connector %q: required claim %q is unavailable", connectorID, name)
				return identity, "required_claim_failure", &RequiredClaimError{Err: err}
			}
			continue
		}
		value, err := transformValue(value, compiled.policy.Transform)
		if err != nil {
			return identity, "resolver_error", fmt.Errorf("identity enrichment connector %q claim %q: %v", connectorID, name, err)
		}
		if err := validatePolicyValue(value, compiled); err != nil {
			return identity, "resolver_error", fmt.Errorf("identity enrichment connector %q claim %q: %v", connectorID, name, err)
		}
		identity.CustomClaims[name] = append(json.RawMessage(nil), value...)
	}

	if p.groups != nil {
		roles, found := sourceRoles(p.groups.policy.Source, result)
		if !found {
			roles = nil
		}
		seen := make(map[string]struct{}, len(identity.Groups)+len(roles))
		if p.groups.policy.Deduplicate {
			uniqueGroups := make([]string, 0, len(identity.Groups))
			for _, group := range identity.Groups {
				if _, exists := seen[group]; exists {
					continue
				}
				seen[group] = struct{}{}
				uniqueGroups = append(uniqueGroups, group)
			}
			identity.Groups = uniqueGroups
		}
		added := 0
		for _, role := range roles {
			if err := validateRole(role); err != nil {
				return identity, "resolver_error", fmt.Errorf("identity enrichment connector %q: resolver role: %v", connectorID, err)
			}
			if _, allowed := p.groups.allowed[role]; !allowed {
				return identity, "resolver_error", fmt.Errorf("identity enrichment connector %q: resolver returned disallowed role %q", connectorID, role)
			}
			if p.groups.policy.Deduplicate {
				if _, exists := seen[role]; exists {
					continue
				}
				seen[role] = struct{}{}
			}
			if added >= p.groups.maxCount {
				return identity, "resolver_error", fmt.Errorf("identity enrichment connector %q: resolver returned too many roles", connectorID)
			}
			identity.Groups = append(identity.Groups, role)
			added++
		}
	}

	identity.SourceClaims = nil
	return identity, result.Status, nil
}

func filterSourceClaims(source claims.JSONClaims, allowed map[string]struct{}) claims.JSONClaims {
	if len(source) == 0 || len(allowed) == 0 {
		return nil
	}
	filtered := claims.New()
	for name, value := range source {
		if _, ok := allowed[name]; ok {
			filtered[name] = append(json.RawMessage(nil), value...)
		}
	}
	return filtered
}

// ClaimsForScopes returns only policy-approved claims whose configured output
// scope was granted to the client.
func (r *Registry) ClaimsForScopes(connectorID string, custom claims.JSONClaims, scopes []string) claims.JSONClaims {
	filtered := claims.New()
	if r == nil {
		return filtered
	}
	p, ok := r.policies[connectorID]
	if !ok {
		return filtered
	}
	granted := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		granted[scope] = struct{}{}
	}
	for name, value := range custom {
		scopesForClaim, ok := p.claimScopes(name)
		if !ok {
			continue
		}
		for _, scope := range scopesForClaim {
			if _, ok := granted[scope]; ok {
				filtered[name] = append(json.RawMessage(nil), value...)
				break
			}
		}
	}
	return filtered
}

func (p *policy) claimScopes(name string) ([]string, bool) {
	if compiled, ok := p.claims[name]; ok {
		return compiled.policy.Emit, true
	}
	scopes, ok := p.serverClaims[name]
	return scopes, ok
}

func addServerClaims(custom claims.JSONClaims, p *policy, status string) {
	if _, emit := p.serverClaims["upstreamProvider"]; emit {
		custom["upstreamProvider"] = claims.String(p.config.Provider)
	}
	if _, emit := p.serverClaims["enrichmentStatus"]; emit {
		custom["enrichmentStatus"] = claims.String(status)
	}
}

func sourceValue(source string, identity connector.Identity, result Result) (json.RawMessage, bool) {
	switch {
	case strings.HasPrefix(source, "identity."):
		name := strings.TrimPrefix(source, "identity.")
		switch name {
		case "userID":
			return claims.String(identity.UserID), identity.UserID != ""
		case "username":
			return claims.String(identity.Username), identity.Username != ""
		case "preferredUsername":
			return claims.String(identity.PreferredUsername), identity.PreferredUsername != ""
		case "email":
			return claims.String(identity.Email), identity.Email != ""
		case "emailVerified":
			return claims.Bool(identity.EmailVerified), true
		}
	case strings.HasPrefix(source, "upstream."):
		value, ok := identity.SourceClaims[strings.TrimPrefix(source, "upstream.")]
		return value, ok
	case strings.HasPrefix(source, "resolver.claims."):
		value, ok := result.Claims[strings.TrimPrefix(source, "resolver.claims.")]
		return value, ok
	}
	return nil, false
}

func sourceRoles(source string, result Result) ([]string, bool) {
	if source != "resolver.roles" {
		return nil, false
	}
	return result.Groups, true
}

func transformValue(value json.RawMessage, transform string) (json.RawMessage, error) {
	if transform == "" {
		return value, nil
	}
	var decoded interface{}
	decoder := json.NewDecoder(strings.NewReader(string(value)))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	transformString := func(value string) string {
		switch transform {
		case "trim":
			return strings.TrimSpace(value)
		case "lower":
			return strings.ToLower(value)
		case "upper":
			return strings.ToUpper(value)
		default:
			return value
		}
	}
	switch typed := decoded.(type) {
	case string:
		return claims.String(transformString(typed)), nil
	case []interface{}:
		for i, item := range typed {
			if stringValue, ok := item.(string); ok {
				typed[i] = transformString(stringValue)
			}
		}
		return json.Marshal(typed)
	default:
		return value, nil
	}
}

func validatePolicyValue(value json.RawMessage, compiled compiledClaim) error {
	if err := claims.ValidateScalarOrArray(value, compiled.maxLength, compiled.maxItems); err != nil {
		return err
	}
	var decoded interface{}
	decoder := json.NewDecoder(strings.NewReader(string(value)))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	validType := false
	switch compiled.policy.Type {
	case "string":
		_, validType = decoded.(string)
	case "boolean":
		_, validType = decoded.(bool)
	case "number":
		_, validType = decoded.(json.Number)
	case "string_array":
		values, ok := decoded.([]interface{})
		validType = ok
		for _, value := range values {
			if _, ok := value.(string); !ok {
				validType = false
			}
		}
	default:
		validType = false
	}
	if !validType {
		return fmt.Errorf("value does not match configured type %q", compiled.policy.Type)
	}
	if compiled.pattern != nil {
		stringValue, ok := decoded.(string)
		if !ok || !compiled.pattern.MatchString(stringValue) {
			return fmt.Errorf("value does not match configured pattern")
		}
	}
	return nil
}

func validSource(source string) bool {
	if strings.HasPrefix(source, "identity.") {
		switch strings.TrimPrefix(source, "identity.") {
		case "userID", "username", "preferredUsername", "email", "emailVerified":
			return true
		}
	}
	if strings.HasPrefix(source, "upstream.") {
		return claimNamePattern.MatchString(strings.TrimPrefix(source, "upstream."))
	}
	return strings.HasPrefix(source, "resolver.claims.") && claimNamePattern.MatchString(strings.TrimPrefix(source, "resolver.claims."))
}

func validClaimType(value string) bool {
	switch value {
	case "string", "boolean", "number", "string_array":
		return true
	default:
		return false
	}
}

func validTransform(value string) bool {
	return value == "" || value == "trim" || value == "lower" || value == "upper"
}

func validateRole(role string) error {
	if role == "" || len(role) > DefaultMaxLength {
		return fmt.Errorf("role %q is empty or too long", role)
	}
	for _, character := range role {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("role contains a control character")
		}
	}
	return nil
}

func isReservedClaim(name string) bool {
	reserved := map[string]struct{}{
		"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {}, "azp": {},
		"nonce": {}, "auth_time": {}, "at_hash": {}, "c_hash": {}, "s_hash": {}, "acr": {}, "amr": {},
		"sid": {}, "typ": {}, "cty": {}, "email": {}, "email_verified": {}, "name": {},
		"family_name": {}, "given_name": {}, "preferred_username": {}, "groups": {},
		"federated_claims": {}, "address": {}, "birthdate": {}, "gender": {}, "locale": {},
		"middle_name": {}, "nickname": {}, "phone_number": {}, "phone_number_verified": {},
		"picture": {}, "profile": {}, "updated_at": {}, "website": {}, "zoneinfo": {},
		"upstreamProvider": {}, "enrichmentStatus": {},
	}
	_, ok := reserved[name]
	return ok
}

func validateMappingAgainstPolicy(connectorID string, document fileDocument, compiled *policy) error {
	for subject, entry := range document.Entries {
		if !entry.Enabled {
			continue
		}
		for name, claim := range compiled.claims {
			resolverClaim, isResolverClaim := strings.CutPrefix(claim.policy.Source, "resolver.claims.")
			if !isResolverClaim {
				continue
			}
			value, found := entry.Claims[resolverClaim]
			if !found {
				if claim.policy.Required {
					return fmt.Errorf("identity enrichment connector %q mapping subject %q is missing required claim %q", connectorID, subject, resolverClaim)
				}
				continue
			}
			transformed, err := transformValue(value, claim.policy.Transform)
			if err != nil {
				return fmt.Errorf("identity enrichment connector %q mapping subject %q claim %q: %v", connectorID, subject, name, err)
			}
			if err := validatePolicyValue(transformed, claim); err != nil {
				return fmt.Errorf("identity enrichment connector %q mapping subject %q claim %q: %v", connectorID, subject, name, err)
			}
		}
		if compiled.groups == nil {
			continue
		}
		if len(entry.Roles) > compiled.groups.maxCount {
			return fmt.Errorf("identity enrichment connector %q mapping subject %q has too many roles", connectorID, subject)
		}
		for _, role := range entry.Roles {
			if _, allowed := compiled.groups.allowed[role]; !allowed {
				return fmt.Errorf("identity enrichment connector %q mapping subject %q has disallowed role %q", connectorID, subject, role)
			}
		}
	}
	return nil
}

// NewFileResolver loads and validates a complete mapping document once.
func NewFileResolver(path, provider string) (Resolver, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document fileDocument
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode mapping: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("decode mapping: document contains multiple JSON values")
	}
	if document.Version != Version {
		return nil, fmt.Errorf("unsupported mapping version %d", document.Version)
	}
	if document.Provider != "" && document.Provider != provider {
		return nil, fmt.Errorf("mapping provider %q does not match policy provider %q", document.Provider, provider)
	}
	allowed := make(map[string]struct{}, len(document.AllowedRoles))
	for _, role := range document.AllowedRoles {
		if err := validateRole(role); err != nil {
			return nil, err
		}
		if _, exists := allowed[role]; exists {
			return nil, fmt.Errorf("mapping has duplicate allowed role %q", role)
		}
		allowed[role] = struct{}{}
	}
	if len(document.Entries) == 0 {
		return &fileResolver{document: document, emails: make(map[string]string), allowEmailLookup: document.AllowEmailLookup}, nil
	}
	emails := make(map[string]string)
	for subject, entry := range document.Entries {
		if subject == "" {
			return nil, errors.New("mapping contains an empty subject")
		}
		if len(entry.Roles) > DefaultMaxRoleCount {
			return nil, fmt.Errorf("mapping subject %q has too many roles", subject)
		}
		seenRoles := make(map[string]struct{}, len(entry.Roles))
		for _, role := range entry.Roles {
			if err := validateRole(role); err != nil {
				return nil, fmt.Errorf("mapping subject %q: %v", subject, err)
			}
			if _, exists := seenRoles[role]; exists {
				return nil, fmt.Errorf("mapping subject %q has duplicate role %q", subject, role)
			}
			if _, allowed := allowed[role]; !allowed {
				return nil, fmt.Errorf("mapping subject %q has unknown role %q", subject, role)
			}
			seenRoles[role] = struct{}{}
		}
		if entry.Email != "" {
			if err := validateRole(entry.Email); err != nil {
				return nil, fmt.Errorf("mapping subject %q email: %v", subject, err)
			}
			email := normalizeEmail(entry.Email)
			if previous, exists := emails[email]; exists && previous != subject {
				return nil, fmt.Errorf("mapping has ambiguous normalized email %q", email)
			}
			emails[email] = subject
		}
		for name, value := range entry.Claims {
			if !claimNamePattern.MatchString(name) {
				return nil, fmt.Errorf("mapping subject %q has invalid claim name %q", subject, name)
			}
			if err := claims.ValidateScalarOrArray(value, DefaultMaxLength, DefaultMaxArraySize); err != nil {
				return nil, fmt.Errorf("mapping subject %q claim %q: %v", subject, name, err)
			}
		}
	}
	return &fileResolver{document: document, emails: emails, allowEmailLookup: document.AllowEmailLookup}, nil
}

type fileDocument struct {
	Version          int                  `json:"version"`
	Provider         string               `json:"provider"`
	AllowEmailLookup bool                 `json:"allowEmailLookup"`
	AllowedRoles     []string             `json:"allowedRoles"`
	Entries          map[string]fileEntry `json:"entries"`
}

type fileEntry struct {
	Enabled bool              `json:"enabled"`
	Email   string            `json:"email"`
	Claims  claims.JSONClaims `json:"claims"`
	Roles   []string          `json:"roles"`
}

type fileResolver struct {
	document         fileDocument
	emails           map[string]string
	allowEmailLookup bool
}

func (r *fileResolver) Resolve(_ context.Context, input Input) (Result, error) {
	result := Result{Resolver: "file", MappingVersion: fmt.Sprintf("%d", r.document.Version)}
	entry, ok := r.document.Entries[input.Identity.UserID]
	if !ok && input.Identity.Email != "" && r.allowEmailLookup {
		if subject, exists := r.emails[normalizeEmail(input.Identity.Email)]; exists {
			entry, ok = r.document.Entries[subject]
		}
	}
	if !ok {
		result.Status = "unmapped"
		return result, nil
	}
	if !entry.Enabled {
		result.Status = "disabled"
		return result, nil
	}
	result.Status = "mapped"
	result.Claims = entry.Claims.Clone()
	result.Groups = append([]string(nil), entry.Roles...)
	return result, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
