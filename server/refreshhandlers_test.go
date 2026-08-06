package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/claims"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

type countingEnricher struct {
	calls int
}

func (e *countingEnricher) Enrich(_ context.Context, _ string, identity connector.Identity) (connector.Identity, error) {
	e.calls++
	return identity, nil
}

func (*countingEnricher) ClaimsForScopes(_ string, _ claims.JSONClaims, _ []string) claims.JSONClaims {
	return claims.New()
}

func mockRefreshTokenTestStorage(t *testing.T, s storage.Storage, useObsolete bool) {
	ctx := t.Context()
	c := storage.Client{
		ID:           "test",
		Secret:       "barfoo",
		RedirectURIs: []string{"foo://bar.com/", "https://auth.example.com"},
		Name:         "dex client",
		LogoURL:      "https://goo.gl/JIyzIC",
	}

	err := s.CreateClient(ctx, c)
	require.NoError(t, err)

	c1 := storage.Connector{
		ID:     "test",
		Type:   "mockCallback",
		Name:   "mockCallback",
		Config: nil,
	}

	err = s.CreateConnector(ctx, c1)
	require.NoError(t, err)

	refresh := storage.RefreshToken{
		ID:            "test",
		Token:         "bar",
		ObsoleteToken: "",
		Nonce:         "foo",
		ClientID:      "test",
		ConnectorID:   "test",
		Scopes:        []string{"openid", "email", "profile"},
		CreatedAt:     time.Now().UTC().Round(time.Millisecond),
		LastUsed:      time.Now().UTC().Round(time.Millisecond),
		Claims: storage.Claims{
			UserID:        "1",
			Username:      "jane",
			Email:         "jane.doe@example.com",
			EmailVerified: true,
			Groups:        []string{"a", "b"},
		},
		ConnectorData: []byte(`{"some":"data"}`),
	}

	if useObsolete {
		refresh.Token = "testtest"
		refresh.ObsoleteToken = "bar"
	}

	err = s.CreateRefresh(ctx, refresh)
	require.NoError(t, err)

	offlineSessions := storage.OfflineSessions{
		UserID:        "1",
		ConnID:        "test",
		Refresh:       map[string]*storage.RefreshTokenRef{"test": {ID: "test", ClientID: "test"}},
		ConnectorData: nil,
	}

	err = s.CreateOfflineSessions(ctx, offlineSessions)
	require.NoError(t, err)
}

func TestRefreshReuseDoesNotReenrich(t *testing.T) {
	httpServer, server := newTestServer(t, nil)
	defer httpServer.Close()

	mockRefreshTokenTestStorage(t, server.storage, false)
	enricher := &countingEnricher{}
	server.enricher = enricher
	server.refreshTokenPolicy = &RefreshTokenPolicy{
		rotateRefreshTokens: true,
		now:                 time.Now,
		logger:              server.logger,
	}

	ctx := t.Context()
	firstContext, refreshErr := server.getRefreshTokenFromStorage(ctx, stringPtr("test"), &internal.RefreshToken{RefreshId: "test", Token: "bar"})
	require.Nil(t, refreshErr)
	firstContext.scopes = firstContext.storageToken.Scopes
	_, _, refreshErr = server.updateRefreshToken(ctx, firstContext)
	require.Nil(t, refreshErr)
	require.Equal(t, 1, enricher.calls)
	server.refreshTokenPolicy.reuseInterval = time.Minute

	reuseContext, refreshErr := server.getRefreshTokenFromStorage(ctx, stringPtr("test"), &internal.RefreshToken{RefreshId: "test", Token: "bar"})
	require.Nil(t, refreshErr)
	reuseContext.scopes = reuseContext.storageToken.Scopes
	_, _, refreshErr = server.updateRefreshToken(ctx, reuseContext)
	require.Nil(t, refreshErr)
	require.Equal(t, 1, enricher.calls)
}

func TestRefreshHTTPReuseDoesNotReenrich(t *testing.T) {
	httpServer, server := newTestServer(t, nil)
	defer httpServer.Close()

	mockRefreshTokenTestStorage(t, server.storage, false)
	enricher := &countingEnricher{}
	server.enricher = enricher
	fixedNow := time.Now().Add(2 * time.Minute)
	server.now = func() time.Time { return fixedNow }
	server.refreshTokenPolicy = &RefreshTokenPolicy{
		rotateRefreshTokens: true,
		reuseInterval:       time.Minute,
		now:                 func() time.Time { return fixedNow },
		logger:              server.logger,
	}

	refreshToken, err := internal.Marshal(&internal.RefreshToken{RefreshId: "test", Token: "bar"})
	require.NoError(t, err)
	request := func() *httptest.ResponseRecorder {
		values := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
		}
		req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test", "barfoo")
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, req)
		return recorder
	}

	first := request()
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Equal(t, 1, enricher.calls)

	second := request()
	require.Equal(t, http.StatusOK, second.Code, second.Body.String())
	require.Equal(t, 1, enricher.calls)
}

func stringPtr(value string) *string {
	return &value
}

func TestRefreshTokenExpirationScenarios(t *testing.T) {
	t0 := time.Now()
	tests := []struct {
		name        string
		policy      *RefreshTokenPolicy
		useObsolete bool
		error       string
	}{
		{
			name:   "Normal",
			policy: &RefreshTokenPolicy{rotateRefreshTokens: true},
			error:  ``,
		},
		{
			name: "Not expired because used",
			policy: &RefreshTokenPolicy{
				rotateRefreshTokens: false,
				validIfNotUsedFor:   time.Second * 60,
				now:                 func() time.Time { return t0.Add(time.Second * 25) },
			},
			error: ``,
		},
		{
			name: "Expired because not used",
			policy: &RefreshTokenPolicy{
				rotateRefreshTokens: false,
				validIfNotUsedFor:   time.Second * 60,
				now:                 func() time.Time { return t0.Add(time.Hour) },
			},
			error: `{"error":"invalid_request","error_description":"Refresh token expired."}`,
		},
		{
			name: "Absolutely expired",
			policy: &RefreshTokenPolicy{
				rotateRefreshTokens: true,
				absoluteLifetime:    time.Second * 60,
				now:                 func() time.Time { return t0.Add(time.Hour) },
			},
			error: `{"error":"invalid_request","error_description":"Refresh token expired."}`,
		},
		{
			name:        "Obsolete tokens are allowed",
			useObsolete: true,
			policy: &RefreshTokenPolicy{
				rotateRefreshTokens: true,
				reuseInterval:       time.Second * 30,
				now:                 func() time.Time { return t0.Add(time.Second * 25) },
			},
			error: ``,
		},
		{
			name:        "Obsolete tokens are not allowed",
			useObsolete: true,
			policy: &RefreshTokenPolicy{
				rotateRefreshTokens: true,
				now:                 func() time.Time { return t0.Add(time.Second * 25) },
			},
			error: `{"error":"invalid_request","error_description":"Refresh token is invalid or has already been claimed by another client."}`,
		},
		{
			name:        "Obsolete tokens are allowed but token is expired globally",
			useObsolete: true,
			policy: &RefreshTokenPolicy{
				rotateRefreshTokens: true,
				reuseInterval:       time.Second * 30,
				absoluteLifetime:    time.Second * 20,
				now:                 func() time.Time { return t0.Add(time.Second * 25) },
			},
			error: `{"error":"invalid_request","error_description":"Refresh token expired."}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(*testing.T) {
			// Setup a dex server.
			httpServer, s := newTestServer(t, func(c *Config) {
				c.RefreshTokenPolicy = tc.policy
				c.Now = func() time.Time { return t0 }
			})
			defer httpServer.Close()

			mockRefreshTokenTestStorage(t, s.storage, tc.useObsolete)

			u, err := url.Parse(s.issuerURL.String())
			require.NoError(t, err)

			tokenData, err := internal.Marshal(&internal.RefreshToken{RefreshId: "test", Token: "bar"})
			require.NoError(t, err)

			u.Path = path.Join(u.Path, "/token")
			v := url.Values{}
			v.Add("grant_type", "refresh_token")
			v.Add("refresh_token", tokenData)

			req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(v.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			req.SetBasicAuth("test", "barfoo")

			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)

			if tc.error == "" {
				require.Equal(t, 200, rr.Code)
			} else {
				require.Equal(t, rr.Body.String(), tc.error)
				return
			}

			// Check that we received expected refresh token
			var ref struct {
				Token string `json:"refresh_token"`
			}
			err = json.Unmarshal(rr.Body.Bytes(), &ref)
			require.NoError(t, err)

			if tc.policy.rotateRefreshTokens == false {
				require.Equal(t, tokenData, ref.Token)
			} else {
				require.NotEqual(t, tokenData, ref.Token)
			}

			if tc.useObsolete {
				updatedTokenData, err := internal.Marshal(&internal.RefreshToken{RefreshId: "test", Token: "testtest"})
				require.NoError(t, err)
				require.Equal(t, updatedTokenData, ref.Token)
			}
		})
	}
}

func TestRefreshTokenPolicy(t *testing.T) {
	lastTime := time.Now()
	l := slog.New(slog.DiscardHandler)

	r, err := NewRefreshTokenPolicy(l, true, "1m", "1m", "1m")
	require.NoError(t, err)

	t.Run("Allowed", func(t *testing.T) {
		r.now = func() time.Time { return lastTime }
		require.Equal(t, true, r.AllowedToReuse(lastTime))
		require.Equal(t, false, r.ExpiredBecauseUnused(lastTime))
		require.Equal(t, false, r.CompletelyExpired(lastTime))
	})

	t.Run("Expired", func(t *testing.T) {
		r.now = func() time.Time { return lastTime.Add(2 * time.Minute) }
		require.Equal(t, false, r.AllowedToReuse(lastTime))
		require.Equal(t, true, r.ExpiredBecauseUnused(lastTime))
		require.Equal(t, true, r.CompletelyExpired(lastTime))
	})
}
