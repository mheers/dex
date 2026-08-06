// Package connector defines interfaces for federated identity strategies.
package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dexidp/dex/pkg/claims"
)

// JSONClaims is the JSON-preserving representation used for approved custom
// claims and transient upstream source claims.
type JSONClaims = claims.JSONClaims

// UserNotInRequiredGroupsError is returned by a connector when a user
// successfully authenticates but is not a member of any of the required groups.
// The server will respond with HTTP 403 Forbidden instead of 500.
type UserNotInRequiredGroupsError struct {
	UserID string
	Groups []string
}

func (e *UserNotInRequiredGroupsError) Error() string {
	return fmt.Sprintf("user %q is not in any of the required groups %v", e.UserID, e.Groups)
}

// Connector is a mechanism for federating login to a remote identity service.
//
// Implementations are expected to implement either the PasswordConnector or
// CallbackConnector interface.
type Connector interface{}

// Scopes represents additional data requested by the clients about the end user.
type Scopes struct {
	// The client has requested a refresh token from the server.
	OfflineAccess bool

	// The client has requested group information about the end user.
	Groups bool
}

// Identity represents the ID Token claims supported by the server.
type Identity struct {
	UserID            string
	Username          string
	PreferredUsername string
	Email             string
	EmailVerified     bool

	Groups []string

	// CustomClaims contains claims approved for downstream OIDC emission.
	CustomClaims JSONClaims

	// SourceClaims contains selected upstream claims available only to the
	// enrichment stage. It must never be persisted or emitted directly.
	SourceClaims JSONClaims

	// AuthorizedScopes contains scopes verified for a token-exchange subject.
	// A nil slice means that the connector could not establish the subject
	// token's scopes. It is transient and must never be persisted or emitted
	// directly.
	AuthorizedScopes []string

	// ConnectorData holds data used by the connector for subsequent requests after initial
	// authentication, such as access tokens for upstream provides.
	//
	// This data is never shared with end users, OAuth clients, or through the API.
	ConnectorData []byte
}

// Clone returns an independent identity copy, including all mutable claim and
// slice fields. SourceClaims remains transient on the returned identity.
func (i Identity) Clone() Identity {
	i.Groups = append([]string(nil), i.Groups...)
	i.CustomClaims = i.CustomClaims.Clone()
	i.SourceClaims = i.SourceClaims.Clone()
	if i.AuthorizedScopes != nil {
		i.AuthorizedScopes = append([]string{}, i.AuthorizedScopes...)
	}
	i.ConnectorData = append([]byte(nil), i.ConnectorData...)
	return i
}

// ClearSourceClaims removes transient upstream claims before persistence.
func (i *Identity) ClearSourceClaims() {
	i.SourceClaims = nil
}

// SetSourceClaim adds a JSON-preserving source claim. It is intended for
// connector code that has already verified the upstream claim.
func (i *Identity) SetSourceClaim(name string, value json.RawMessage) {
	if i.SourceClaims == nil {
		i.SourceClaims = claims.New()
	}
	i.SourceClaims[name] = append(json.RawMessage(nil), value...)
}

// CopySourceClaims copies only selected verified upstream values into an
// identity's transient source claims. Unsupported nested JSON values are
// rejected before they can cross the connector boundary.
func CopySourceClaims(identity *Identity, names []string, values map[string]interface{}) error {
	for _, name := range names {
		value, ok := values[name]
		if !ok {
			continue
		}
		rawValue, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to encode source claim %q: %w", name, err)
		}
		if err := claims.ValidateScalarOrArray(rawValue, claims.DefaultMaxStringLength, claims.DefaultMaxArraySize); err != nil {
			return fmt.Errorf("unsupported source claim %q: %w", name, err)
		}
		identity.SetSourceClaim(name, rawValue)
	}
	return nil
}

// PasswordConnector is an interface implemented by connectors which take a
// username and password.
// Prompt() is used to inform the handler what to display in the password
// template. If this returns an empty string, it'll default to "Username".
type PasswordConnector interface {
	Prompt() string
	Login(ctx context.Context, s Scopes, username, password string) (identity Identity, validPassword bool, err error)
}

// CallbackConnector is an interface implemented by connectors which use an OAuth
// style redirect flow to determine user information.
type CallbackConnector interface {
	// The initial URL to redirect the user to.
	//
	// OAuth2 implementations should request different scopes from the upstream
	// identity provider based on the scopes requested by the downstream client.
	// For example, if the downstream client requests a refresh token from the
	// server, the connector should also request a token from the provider.
	//
	// Many identity providers have arbitrary restrictions on refresh tokens. For
	// example Google only allows a single refresh token per client/user/scopes
	// combination, and wont return a refresh token even if offline access is
	// requested if one has already been issues. There's no good general answer
	// for these kind of restrictions, and may require this package to become more
	// aware of the global set of user/connector interactions.
	LoginURL(s Scopes, callbackURL, state string) (string, []byte, error)

	// Handle the callback to the server and return an identity.
	HandleCallback(s Scopes, connData []byte, r *http.Request) (identity Identity, err error)
}

// SAMLConnector represents SAML connectors which implement the HTTP POST binding.
//
//	RelayState is handled by the server.
//
// See: https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
// "3.5 HTTP POST Binding"
type SAMLConnector interface {
	// POSTData returns an encoded SAML request and SSO URL for the server to
	// render a POST form with.
	//
	// POSTData should encode the provided request ID in the returned serialized
	// SAML request.
	POSTData(s Scopes, requestID string) (ssoURL, samlRequest string, err error)

	// HandlePOST decodes, verifies, and maps attributes from the SAML response.
	// It passes the expected value of the "InResponseTo" response field, which
	// the connector must ensure matches the response value.
	//
	// See: https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
	// "3.2.2 Complex Type StatusResponseType"
	HandlePOST(s Scopes, samlResponse, inResponseTo string) (identity Identity, err error)
}

// RefreshConnector is a connector that can update the client claims.
type RefreshConnector interface {
	// Refresh is called when a client attempts to claim a refresh token. The
	// connector should attempt to update the identity object to reflect any
	// changes since the token was last refreshed.
	Refresh(ctx context.Context, s Scopes, identity Identity) (Identity, error)
}

type TokenIdentityConnector interface {
	TokenIdentity(ctx context.Context, subjectTokenType, subjectToken string) (Identity, error)
}
