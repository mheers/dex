package server

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/claims"
	"github.com/dexidp/dex/server/enrichment"
	"github.com/dexidp/dex/storage"
)

type identityEnricher interface {
	Enrich(context.Context, string, connector.Identity) (connector.Identity, error)
	ClaimsForScopes(string, claims.JSONClaims, []string) claims.JSONClaims
}

type identityEnricherWithOutcome interface {
	identityEnricher
	EnrichWithOutcome(context.Context, string, connector.Identity) (connector.Identity, string, error)
}

func (s *Server) enrichIdentity(ctx context.Context, connectorID string, identity connector.Identity) (connector.Identity, error) {
	started := time.Now()
	if s.enricher == nil {
		identity.SourceClaims = nil
		return identity, nil
	}
	var enriched connector.Identity
	var outcome string
	var err error
	if enricher, ok := s.enricher.(identityEnricherWithOutcome); ok {
		enriched, outcome, err = enricher.EnrichWithOutcome(ctx, connectorID, identity)
	} else {
		enriched, err = s.enricher.Enrich(ctx, connectorID, identity)
		outcome = enrichmentOutcome(enriched, err)
	}
	if s.identityEnrichmentCounter != nil {
		s.identityEnrichmentCounter.WithLabelValues(connectorID, outcome).Inc()
		s.identityEnrichmentDuration.WithLabelValues(connectorID).Observe(time.Since(started).Seconds())
	}
	if s.logger != nil {
		s.logger.DebugContext(ctx, "identity enrichment completed", "connector_id", connectorID, "outcome", outcome, "custom_claim_count", len(enriched.CustomClaims))
	}
	return enriched, err
}

func enrichmentOutcome(identity connector.Identity, err error) string {
	if err != nil {
		var requiredClaimErr *enrichment.RequiredClaimError
		if errors.As(err, &requiredClaimErr) {
			return "required_claim_failure"
		}
		return "resolver_error"
	}
	if status, ok := identity.CustomClaims["enrichmentStatus"]; ok {
		var value string
		if json.Unmarshal(status, &value) == nil {
			switch value {
			case "mapped", "unmapped", "disabled":
				return value
			}
		}
	}
	return "mapped"
}

func (s *Server) claimsForScopes(connectorID string, custom claims.JSONClaims, scopes []string) claims.JSONClaims {
	if s.enricher == nil {
		return claims.New()
	}
	return s.enricher.ClaimsForScopes(connectorID, custom, scopes)
}

func claimsFromIdentity(identity connector.Identity) storage.Claims {
	return storage.Claims{
		UserID:            identity.UserID,
		Username:          identity.Username,
		PreferredUsername: identity.PreferredUsername,
		Email:             identity.Email,
		EmailVerified:     identity.EmailVerified,
		Groups:            append([]string(nil), identity.Groups...),
		CustomClaims:      identity.CustomClaims.Clone(),
	}
}
