package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/claims"
	"github.com/dexidp/dex/server/enrichment"
	"github.com/dexidp/dex/storage"
)

type countingSAMLConnector struct {
	identity connector.Identity
	calls    int
}

type limitedTokenConnector struct{}

type unknownScopeTokenConnector struct{}

func (limitedTokenConnector) TokenIdentity(context.Context, string, string) (connector.Identity, error) {
	return connector.Identity{UserID: "limited-user", AuthorizedScopes: []string{"openid"}}, nil
}

func (unknownScopeTokenConnector) TokenIdentity(context.Context, string, string) (connector.Identity, error) {
	return connector.Identity{UserID: "unknown-scope-user"}, nil
}

func (c *countingSAMLConnector) POSTData(connector.Scopes, string) (string, string, error) {
	return "https://sso.example.com", "request", nil
}

func (c *countingSAMLConnector) HandlePOST(connector.Scopes, string, string) (connector.Identity, error) {
	c.calls++
	return c.identity, nil
}

func TestHandleSAMLCallbackEnrichesExactlyOnce(t *testing.T) {
	httpServer, s := newTestServer(t, nil)
	defer httpServer.Close()

	saml := &countingSAMLConnector{identity: connector.Identity{
		UserID:        "saml-user",
		Username:      "SAML User",
		Email:         "saml@example.com",
		EmailVerified: true,
	}}
	s.mu.Lock()
	s.connectors["mock"] = Connector{ResourceVersion: "1", Connector: saml}
	s.mu.Unlock()

	const authRequestID = "saml-state"
	err := s.storage.CreateAuthRequest(t.Context(), storage.AuthRequest{
		ID:            authRequestID,
		ConnectorID:   "mock",
		RedirectURI:   "cb",
		Expiry:        time.Now().Add(time.Minute),
		ResponseTypes: []string{responseTypeCode},
	})
	require.NoError(t, err)

	enricher := &countingEnricher{}
	s.enricher = enricher
	form := url.Values{
		"RelayState":   {authRequestID},
		"SAMLResponse": {"signed-response"},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/callback/mock", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleConnectorCallback(recorder, request)

	require.Equal(t, http.StatusSeeOther, recorder.Code)
	require.Equal(t, 1, saml.calls)
	require.Equal(t, 1, enricher.calls)
}

func TestEnrichmentOutcomeIsFinite(t *testing.T) {
	for _, test := range []struct {
		name     string
		identity connector.Identity
		err      error
		want     string
	}{
		{name: "mapped", identity: connector.Identity{CustomClaims: claims.JSONClaims{"enrichmentStatus": claims.String("mapped")}}, want: "mapped"},
		{name: "unmapped", identity: connector.Identity{CustomClaims: claims.JSONClaims{"enrichmentStatus": claims.String("unmapped")}}, want: "unmapped"},
		{name: "disabled", identity: connector.Identity{CustomClaims: claims.JSONClaims{"enrichmentStatus": claims.String("disabled")}}, want: "disabled"},
		{name: "required claim failure", err: &enrichment.RequiredClaimError{Err: errors.New("required claim employeeId is unavailable")}, want: "required_claim_failure"},
		{name: "resolver error", err: errors.New("resolver unavailable"), want: "resolver_error"},
		{name: "unknown status", identity: connector.Identity{CustomClaims: claims.JSONClaims{"enrichmentStatus": claims.String("unexpected")}}, want: "mapped"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, enrichmentOutcome(test.identity, test.err))
		})
	}
}

func TestTokenExchangeCannotWidenSubjectScopes(t *testing.T) {
	httpServer, s := newTestServer(t, func(config *Config) {
		require.NoError(t, config.Storage.CreateClient(t.Context(), storage.Client{ID: "client_1", Secret: "secret_1"}))
	})
	defer httpServer.Close()

	s.mu.Lock()
	s.connectors["mock"] = Connector{ResourceVersion: "1", Connector: limitedTokenConnector{}}
	s.mu.Unlock()
	enricher := &countingEnricher{}
	s.enricher = enricher

	values := url.Values{
		"grant_type":           {grantTypeTokenExchange},
		"connector_id":         {"mock"},
		"scope":                {"openid profile"},
		"requested_token_type": {tokenTypeAccess},
		"subject_token_type":   {tokenTypeID},
		"subject_token":        {"limited"},
		"client_id":            {"client_1"},
		"client_secret":        {"secret_1"},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleToken(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "subject token does not authorize scope")
	require.Equal(t, 0, enricher.calls)
}

func TestTokenExchangeRejectsUnknownSubjectScopes(t *testing.T) {
	httpServer, s := newTestServer(t, func(config *Config) {
		require.NoError(t, config.Storage.CreateClient(t.Context(), storage.Client{ID: "client_1", Secret: "secret_1"}))
	})
	defer httpServer.Close()

	s.mu.Lock()
	s.connectors["mock"] = Connector{ResourceVersion: "1", Connector: unknownScopeTokenConnector{}}
	s.mu.Unlock()
	enricher := &countingEnricher{}
	s.enricher = enricher

	values := url.Values{
		"grant_type":           {grantTypeTokenExchange},
		"connector_id":         {"mock"},
		"scope":                {"openid"},
		"requested_token_type": {tokenTypeAccess},
		"subject_token_type":   {tokenTypeID},
		"subject_token":        {"unknown"},
		"client_id":            {"client_1"},
		"client_secret":        {"secret_1"},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleToken(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "subject token scope metadata unavailable")
	require.Equal(t, 0, enricher.calls)
}
