# Identity enrichment

Dex identity enrichment is configured in the trusted server configuration. It
runs after a connector has verified an identity and before claims are stored or
tokens are signed.

## Configuration

The top-level configuration has two independent parts:

```yaml
identity:
  enrichment:
    version: 1
    defaultPolicy: disabled
    connectors:
      google-workspace:
        provider: google
        resolver:
          type: file
          path: /etc/dex/google-enrichment.json
        emailFallback: false
        serverClaims:
          upstreamProvider: [profile]
          enrichmentStatus: [profile]
        claims:
          employeeId:
            source: resolver.claims.employeeId
            type: string
            emit: [profile]
            maxLength: 256
        groups:
          source: resolver.roles
          allowed: [reader]
          emit: [groups]
```

`serverClaims` is optional. Its supported names are `upstreamProvider` and
`enrichmentStatus`; Dex derives their values from the configured provider and
resolver result. Resolver data and upstream claims cannot override them.

The connector must separately opt in to the upstream claims that a policy may
consume. For an OIDC or Google connector, add for example:

```yaml
config:
  sourceClaims: [department]
```

A policy can then use `upstream.department` as its source. Claims are copied
only when selected by the connector and are limited to scalar JSON values or
arrays of scalars. At the server boundary, the policy's `upstream.<claim>`
references are intersected with the connector allowlist before a resolver sees
the identity, so a dynamic connector update cannot add resolver input by
itself. Source claims are transient and are never stored.

Version 1 supports only these source forms: `identity.userID`,
`identity.username`, `identity.preferredUsername`, `identity.email`,
`identity.emailVerified`, `upstream.<claim>`, and
`resolver.claims.<claim>`. Generic `resolver.<field>` traversal is intentionally
not supported. The connector `sourceClaims` list is an input allowlist; the
trusted enrichment policy still controls which values reach the resolver and
which values can be emitted.

With `defaultPolicy: disabled`, connectors without an explicit policy retain
Dex's existing behavior. `defaultPolicy: unprivileged` clears groups for
connectors without a policy. Configured `unmapped` and `disabled` resolver
entries are always unprivileged and do not retain connector groups.

## Mapping data

The file resolver is loaded once during startup. It is separate from the
policy and is strict about its version, provider, roles, values, unknown JSON
fields, and trailing data. Subject lookup is primary. Email lookup requires
both `emailFallback: true` in the policy and `allowEmailLookup: true` in the
mapping file.

A minimal mapping is available at
[`examples/identity-enrichment.json`](../examples/identity-enrichment.json).
The matching policy example is at
[`examples/identity-enrichment.yaml`](../examples/identity-enrichment.yaml).

Only policy-approved claims are copied into `storage.Claims`. The same
scope-filtered claims are emitted by the signed ID-token and access-token
serializers, and `/userinfo` returns the claims present in the verified token.
`profile` controls the example custom claim; `groups` controls explicit role
augmentation.

Token exchange accepts only supported standard scopes and trusted cross-client
scopes before resolving the subject token. When a connector returns verified
subject-token scope metadata, the requested scopes must be a subset of it.
The OIDC connector reads a verified `scope` claim when available and otherwise
uses its configured upstream scopes as the explicit compatibility policy for
standard ID tokens and UserInfo responses, which normally omit OAuth grant
scopes. A connector that cannot establish subject-token scopes cannot perform a
scoped token exchange, which prevents scope widening. Claim emission still
requires the requested output scope, and unsupported or untrusted scopes are
rejected before identity resolution.

When group augmentation is configured, `deduplicate: true` removes duplicates
against both existing connector groups and resolver roles. With
`deduplicate: false`, duplicates are preserved. `maxCount` limits the number
of resolver roles appended during enrichment; it does not count groups that
the connector supplied initially.

## Operational behavior

Invalid policy or mapping data prevents startup. Resolver statuses are finite:
`mapped`, `unmapped`, and `disabled`. Required claims fail the authentication
when a mapped entry does not provide them; optional claims are omitted. The
resolver does not log complete mapping entries or claim values. Enrichment
metrics use only connector ID, outcome, and latency; outcomes are finite and
do not include subjects, emails, roles, claim values, tokens, or codes.

For a refresh request outside the token reuse window, the connector and
enricher are invoked once and the resulting claims are stored on the rotated
refresh token. Requests inside the reuse window return the stored enrichment
and do not invoke the resolver again.
