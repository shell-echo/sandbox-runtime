# ADR 0002: Provider Operation Admission Trust and Guard State

- Status: Accepted
- Date: 2026-08-19

## Context

The local Provider Contract OpenAPI applies mutual TLS and bearer security to
every protected operation. The local JWS header permits only `EdDSA` and
`ES256`, and its token claims bind one exact Provider revision, caller,
operation, request or read descriptor, policy digest, deadline, attempt, and
fencing token. P1.1c must enforce those bindings before any application,
repository, or driver dispatch.

The local Contract does not choose this deployment's key distribution,
multi-URI certificate selection, local replay/fencing retention, or precedence
between operation-authorized authentication, authorization, and conflict
responses. These are provider-local security decisions. They must not change
the Contract or promote this service into a caller's authoritative
operation ledger.

## Decision

### Trust bundle

Protected-operation admission uses an operator-supplied, bounded local bundle
of public verification keys. The composition root loads and validates the
bundle before the Provider listener starts, freezes an exact `kid` to public-key
mapping, and gives the admission application only a lookup port. A missing,
duplicate, malformed, unsupported, or algorithm-incompatible key fails startup
when protected admission is enabled.

The bundle may contain overlapping old and new public keys for a planned
rotation. It has no remote discovery, background refresh, fallback issuer,
implicit default key, symmetric secret, or development bypass. A key change
requires an explicit configuration rollout and listener restart. Private keys
and raw bearer values never enter provider configuration, errors, logs, or
stable responses.

### JWS and caller binding

Admission accepts only compact JWS values whose header has the local type,
contains no unrecognized header members, and uses `EdDSA` or `ES256` with a
matching frozen public key. It rejects `none`, every other algorithm, detached
or non-compact serialization, duplicate JSON members, an unknown `kid`, and
any verification ambiguity.

The bearer `sub` must exactly equal one distinct URI SAN in the TLS-verified
peer leaf that is also present in the configured Provider identity allowlist.
Zero or multiple matches reject admission. This comparison is made from the
request TLS verification state, not from a header supplied by the caller. The
same caller must also bind to the configured immutable Provider revision and
the local audience, operation, sandbox, operation/attempt, tenant, work
order, policy digest, request Contract ID, and digest profile claims.

### Time and canonical digest

Admission uses an injected UTC clock. It validates the Contract issuance,
not-before, expiry, deadline, and policy-decision relationships with no
unbounded skew window. Request and read-descriptor digests use only the local
RFC 8785 JCS profile for that operation; neither a caller-supplied profile nor
the same digest under a different Contract ID is interchangeable. Any parsing,
canonicalization, clock, or comparison uncertainty fails closed.

### Admitted operation context

For every protected route, transport must obtain an independently trusted
admitted-operation context before it can call the gate. That context supplies
the active ProviderRevision and audience plus the tenant, WorkOrder, policy
digest, policy-decision time, attempt, and fencing facts that the locked token
must bind. Path and request-document values may supplement it, but transport
must never derive a missing context field by copying it from the bearer being
verified.

The local Provider Contract now supplies an Admission Context carrier for this
purpose. Protected transport accepts exactly one strictly decoded carrier,
binds its controller subject to the TLS-verified caller, and verifies the
carrier's Contract ID, digest, target, and token binding before the admission
gate. The carrier is neither a Provider-local lifecycle cache nor a substitute
for a caller's durable operation ledger; P1.2 reconciliation
and lifecycle authority remain outside this decision.

### Replay and fencing guard

Mutation admission uses a bounded, atomically persisted local guard. It stores
only a one-way JTI fingerprint with its expiry plus the minimum scoped
high-water fencing observation needed to reject replay and stale attempts. It
does not store request bodies, bearer values, Provider responses, lifecycle
state, events, or caller business truth.

The guard is required whenever a protected mutation listener is enabled. It is
single-controller state protected by an exclusive local lock and atomic replace;
the listener must fail closed if its configured state path cannot be opened,
locked, written, or recovered. Multi-controller replay/fencing reliability
remains outside P1.1 and is not claimed. Read operations do not consume a
mutation JTI, but still require every other binding.

### Response precedence

Transport mTLS failure remains a TLS-handshake failure before HTTP routing.
For a request that reaches protected HTTP admission:

1. malformed, absent, unverified, not-yet-valid, expired, or otherwise
   unauthenticated bearer material maps to the operation's authorized `401`
   response;
2. a verified token that fails caller, Provider revision, audience, operation,
   request, policy, or deadline authorization binding maps to the operation's
   authorized `403` response; and
3. a replayed mutation JTI or stale fencing token maps to that mutation
   operation's authorized `409` response.

The response mapper must build only the local safe error document and must
not disclose tokens, keys, peer certificates, normalized request data, backend
identifiers, or internal guard state. When an operation does not authorize the
needed response, its route remains absent rather than introducing a private
wire behavior. Discovery `400`/`501` semantics are defined by the local
Contract and remain separate from this decision.

## Consequences

- P1.1c code can use a pure admission application port and test-local keys,
  clocks, certificates, and guards without importing Gin, `instance`, a
  repository implementation, or a driver.
- Production key rotation requires an intentional overlap-and-restart rollout;
  it cannot silently fetch trust material at request time.
- Protected mutation admission has durable single-controller replay/fencing
  protection without claiming an asynchronous Provider operation ledger.
- Protected transport consumes only the local Admission Context carrier; it
  does not derive or cache context from bearer claims or local lifecycle state.
- A future multi-controller deployment must replace the local guard with a
  coordination mechanism that proves equivalent atomic semantics before any
  multi-controller claim.
- The caller remains authoritative for ProviderResolution, policy
  decisions, work state, and its aggregate operation ledger.

## Alternatives rejected

- Remote JWKS discovery or runtime key refresh: no locked source, cache,
  availability, or rotation authority exists for it.
- A process-memory-only replay cache: restart would silently reopen the replay
  window.
- Trusting the first or lexicographically chosen URI SAN: it can bind a bearer
  to an identity other than the one intended by the token.
- mTLS-only protected operations: the locked OpenAPI requires the bearer layer
  in addition to mTLS.
- Using the local `/instances` state or repository as the guard: it would mix
  Provider admission with the management API and prematurely create lifecycle
  authority.
- Constructing route context from bearer claims: this would compare a signed
  value with itself and cannot establish its relation to the admitted
  SandboxOperation Attempt.

## Evidence boundary

This ADR is a local provider security decision. It does not modify the local
Contract, establish aggregate conformance, or create Provider lifecycle
authority. Protected transport may consume the local Admission Context carrier
without resolving P1.2. This ADR does not establish
aggregate lifecycle conformance, or prove caller interoperability,
multi-controller reliability, multi-tenant safety, deployment readiness, or
production readiness.
