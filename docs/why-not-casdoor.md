# Why identity enrichment is implemented in Dex and not Casdoor

This document explains why the identity-enrichment feature ([`identity-enrichment.md`](identity-enrichment.md))
is built into Dex instead of relying on [Casdoor](https://casdoor.org) to provide the same
capability. It is aimed at future maintainers and anyone evaluating the architecture.

## Requirements

The identity-enrichment implementation exists to satisfy two requirements:

1. **Custom IDP support** — authenticate against an identity provider that we implement
   ourselves (not one of the well-known public providers).
2. **Transparent claim forwarding** — forward *all* claims issued by that IDP into the
   tokens Dex produces (ID token, access token, and `/userinfo`), preserving their names,
   values, and types, without an intermediate mapping step.

Secondary requirements that shaped the design:

- Claims must be gated by an allowlist (connector `sourceClaims`) and a trusted,
  server-side enrichment policy before they are emitted.
- Claims must be re-evaluated on refresh outside the token-reuse window, so downstream
  consumers see current identity data.
- Upstream groups must be forwardable and augmentable, with deduplication.
- Claim emission must be scope-aware (`profile`, `groups`).

## What Casdoor offers

Casdoor is a mature IAM with many features that overlap Dex (OIDC/OAuth/SAML provider,
login UI, roles, MFA, syncers). We evaluated it as a replacement for the enrichment layer
before committing to the Dex implementation. Two Casdoor mechanisms are relevant:

- **Custom OAuth provider** (`Custom` .. `Custom10`): a generic OAuth 2.0 three-legged
  provider configured with Auth URL, Token URL, UserInfo URL, and optional PKCE.
- **Token customization** (`JWT-Custom` token format with `TokenFields` / `TokenAttributes`):
  per-application selection of which user fields appear as claims.

## Why Casdoor does not satisfy the requirements

### 1. The custom provider does not capture arbitrary claims

The Casdoor custom provider decodes the UserInfo response into exactly six fields:
`id`, `username`, `displayName`, `email`, `phone`, `avatarUrl`
([`idp/custom.go`](https://github.com/casdoor/casdoor/blob/master/idp/custom.go)).
All other claims returned by the IDP are silently dropped — they are not stored and cannot
be referenced by token configuration. There is no claim allowlist or passthrough.

Some built-in providers (for example Okta or Azure AD) do store extra claims, but they are
collapsed into a single string-valued user property (`oauth_<provider>_extra`) and can only
be re-emitted into a token as one opaque JSON-string claim. Individual claims with their
original names, types, and structure cannot be forwarded.

### 2. Claims are mapped into Casdoor's user model, not forwarded

Casdoor is a user store first: claims are ingested at login time into its own user schema
(a fixed set of fields, optionally via user mapping). Token claims are then re-exported from
that stored record. This is an *import-and-export* pipeline, not transparent forwarding:

- Claim names change (mapped to Casdoor field names).
- Values are stringified; booleans, numbers, and arrays lose their types.
- Claims that do not fit a mapped field are lost.

The Dex implementation, by contrast, keeps upstream claims as typed JSON values
(scalars and arrays of scalars), intersects the policy's `upstream.<claim>` references with
the connector allowlist, and emits them under their original names.

### 3. No refresh-time re-evaluation

Casdoor syncs identity data only at sign-in. A refresh token exchange reads the stored
Casdoor user record; the upstream IDP is never consulted again. The Dex implementation
re-invokes the connector and the enrichment resolver for refresh requests outside the
token-reuse window, so claims and groups reflect current upstream state.

### 4. Groups and roles are Casdoor-managed

Casdoor derives token groups from its own roles/group model. Upstream group membership is
not forwarded; importing it requires a syncer with a fixed schema (AD, LDAP, Okta, ...).
The Dex implementation forwards connector groups and supports resolver-based role
augmentation with deduplication and a configurable maximum.

### 5. Scope-aware emission

Casdoor's custom scopes apply only to "Agent" category applications. Standard applications
cannot gate claim emission per scope. Dex's enrichment ties each claim to an output scope
(`profile`, `groups`) and enforces scope restrictions on token exchange to prevent
scope widening.

## Where Casdoor is still a good fit

None of this is a criticism of Casdoor — it is simply a different architectural model.
Casdoor is an excellent choice for scenarios where a managed user directory and login UI
are the goal:

- Self-service login, signup, MFA, and user management.
- Social/enterprise sign-in via its built-in provider catalog.
- Applications that can consume the fixed set of Casdoor user fields as claims.
- Sitting in front of Dex as the user-facing login layer, with Dex performing enrichment.

The decision to build identity enrichment into Dex only covers the claim-transparency
requirement described above. For deployments that do not need transparent upstream claim
forwarding, Casdoor (or stock Dex) may be the simpler option.
