# ADR 0038: Provider Caller Issuer Trust Model

- Status: Accepted
- Date: 2026-09-07

## Context

ADR 0037 removed the retired Agent Platform as an architectural dependency but
left protected admission bound in implementation to the opaque issuer
`agent-platform`. The repository-owned Provider Contract did not define who
selects a replacement issuer, how that issuer relates to verification keys and
mTLS identities, or which values prevent a caller from making a bearer token
and Admission Context agree with each other while targeting the wrong Provider
revision or instance.

Issuer flexibility cannot mean accepting an issuer named by an incoming token,
performing remote discovery from that value, or accepting several callers in
one undifferentiated trust bundle. Those designs would move trust selection onto
untrusted input and would require tenant, replay, fencing, key-ID, and identity
namespaces that this Provider does not have.

## Decision

### One configured issuer per listener

Every protected Provider listener has exactly one operator-configured caller
issuer. The value is required: there is no default issuer, fallback issuer,
issuer alias, discovery rule, or normalization. Comparison with the bearer
`iss` claim is exact and case-sensitive.

The issuer is a bounded JWT StringOrURI. It contains between 1 and 200
characters. Under the RFC 7519 StringOrURI rule, a value containing `:` is an
absolute URI; comparison still uses the original string and performs no URI
canonicalization. An opaque value without `:` is allowed only when explicitly
configured. In particular, legacy `agent-platform` behavior is available only
when an operator configures that exact value for the listener.

One listener does not accept a set of issuers. Supporting simultaneous
multi-issuer or multi-consumer admission would require a separate protocol and
storage design for key IDs, replay, fencing, identity, and policy namespaces.

### Provider-local authority anchors

The listener also freezes one exact Provider-instance audience and one exact
Provider revision. They come from Provider configuration and the locally
advertised immutable capability revision, not from the bearer or Admission
Context. Protected admission compares the signed `aud` and
`provider_revision_id` claims and the corresponding Admission Context fields
against those local anchors.

The Admission Context remains caller-supplied evidence bound by its own RFC
8785 digest. Agreement between the bearer and that context is necessary but not
sufficient; both must independently equal the Provider-local audience and
revision. This prevents two caller-controlled documents from authorizing an
unselected Provider target merely by agreeing with each other.

### Issuer-scoped identities and keys

All URI SAN controller identities admitted by the listener and every frozen
JWS verification key are scoped to its one configured issuer. A `kid` is unique
within that issuer-scoped frozen bundle. The Provider never selects a trust
bundle from `iss`, `kid`, `sub`, an HTTP header, or an Admission Context.

Key rotation retains ADR 0002's explicit overlap-and-restart model. An operator
first installs a bounded bundle containing the old and new public keys under
distinct key IDs and restarts the listener. The caller then stops all signing
with the old key and moves to the new key. Because the maximum bearer lifetime
is 300 seconds, the operator waits 300 seconds after old-key signing has stopped
before removing the old public key and restarting the listener again. There is
no remote JWKS discovery, background refresh, implicit key, or cross-issuer key
lookup.

The signed `sub` claim must still exactly equal the one configured URI SAN
identity selected from the TLS-verified peer certificate. Every admitted URI
SAN is therefore an identity within the configured issuer's listener-local
trust domain. This decision does not add certificate-thumbprint or JWT `cnf`
binding and does not weaken the existing exact URI-SAN selection rules.

### Wire profile and rejection classes

Every protected operation carries exactly one
`X-Sandbox-Runtime-Admission-Context` header field value. Its value is an
unpadded base64url encoding of the closed Admission Context JSON document and
is bounded to 16,384 encoded characters and 16,384 decoded bytes. Capability
discovery does not carry this header.

The bearer uses compact JWS serialization and the closed header and claims
schemas registered by the Provider Contract. Unknown members, unsupported
algorithms, an unknown issuer, unknown key ID, invalid signature, malformed
serialization, or an inactive token are authentication failures and map to an
authorized `401` response. After a signature has been verified under the
configured issuer's key bundle, an exact mismatch in the mTLS subject, local
audience, local Provider revision, request, policy, operation, or Admission
Context binding is an authorization failure and maps to an authorized `403`
response. Replay and stale fencing conflicts retain ADR 0002's `409` mapping.

Responses remain caller-safe and do not reveal which issuer, key, SAN, audience,
revision, signature, or internal comparison failed.

### Migration

A deployment adopts a generic caller issuer through an explicit coordinated
cutover:

1. lock and review the Contract revision containing this profile;
2. configure the listener's exact issuer, audience, Provider revision, admitted
   URI SAN identities, and frozen verification-key bundle;
3. restart the listener and verify its local authority before routing protected
   traffic; and
4. have the caller mint tokens and Admission Context documents against those
   exact values, then run the named Contract and external-caller gates.

A deployment that must temporarily retain the historical behavior configures
`agent-platform` explicitly and remains a legacy-mode deployment. Changing to a
generic issuer is a configuration rollout, not a fallback. A single listener
cannot accept both values during the transition, and historical
`agent-platform-candidate` code, names, locks, and evidence retain their exact
recorded meaning.

## Consequences

- Any independently implemented caller can use the protected Provider API by
  conforming to the repository-owned issuer, JWS, mTLS, Admission Context, and
  local-authority bindings.
- The Provider does not need a consumer-specific adapter or a registry of
  external platform types.
- A configuration change that selects a different issuer changes the complete
  listener trust domain and requires coordinated key, identity, and caller
  rollout.
- The existing issuer-scoped `kid` namespace and restart-based overlap rotation
  remain sufficient for this single-issuer model.
- Contract publication, implementation projection, configuration composition,
  and external-caller evidence remain separate gates.

## Alternatives rejected

- Accepting the bearer `iss` as the authority selector: untrusted input would
  choose its own trust domain.
- A default or fallback issuer: omitted or misspelled configuration could
  silently retain legacy trust.
- Several issuers in one listener: the current replay, fencing, key-ID, and
  controller identity namespaces do not establish safe multi-consumer
  isolation.
- Trusting bearer and Admission Context agreement alone: both documents are
  caller-controlled and cannot establish the Provider's selected audience or
  revision.
- Remote JWKS discovery: no Contract defines discovery authorization, caching,
  availability, rollover, or revocation semantics.
- Certificate-thumbprint or `cnf` binding in this slice: URI-SAN binding is the
  existing Contract boundary, and changing proof-of-possession semantics needs
  a separate protocol review.

## Non-goals and evidence boundary

This decision does not define a caller product, SDK, public Gateway, production
PKI, remote key service, multi-issuer listener, multi-consumer or hostile
multi-tenant boundary, multi-controller storage, deployment, or production
readiness. It does not reclassify historical Agent Platform candidate evidence.
Passing schema or component tests does not prove interoperability with an
independently implemented generic caller; that requires its separately named
black-box gate against the exact reviewed Contract lock.
