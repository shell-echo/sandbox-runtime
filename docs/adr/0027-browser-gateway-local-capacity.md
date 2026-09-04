# ADR 0027: Browser Gateway Process-Local Connection Capacity

- Status: Accepted for the P4 Browser Gateway capacity component
- Date: 2026-09-04

## Context

The Browser reference caller proves authorization, revocation, expiry,
reconnect, and private Provider resolution, but the caller-owned Gateway has no
explicit concurrent-connection bound. Browser runtime allocation is already
bounded inside one Provider process; that does not bound the number of public
connections, authorization attempts, revocation watches, or private dials for
an allocated Browser session.

This is a resource and abuse boundary, not a Provider Contract change. The
caller still owns user and tenant authorization, revocation, audit, and public
edge policy. A local counter also cannot establish distributed capacity or
multi-controller correctness.

## Decision

Add an optional process-local capacity ledger to the shared Gateway state
machine. The Browser composition requires explicit total and per-session
limits, with `1 <= per_session <= total <= 1000`. The hard ceiling matches the
existing Browser Docker adapter's maximum per-controller allocation bound; it
is a defensive component ceiling, not a throughput forecast. The composition
supplies no unbounded Browser default. Existing terminal composition is
unchanged because terminal capacity and deployment need a separate
compatibility decision.

The Gateway validates the request, obtains caller authorization, and verifies
the exact grant binding before attempting to acquire capacity. This prevents
invalid or unauthorized requests from consuming a slot. Acquisition is
non-blocking and occurs before the revocation source, authorized audit event,
Provider reference resolver, or backend dial. A rejected request returns the
stable `ErrCapacityExhausted` error and emits a metadata-only
`capacity_rejected` audit event without reaching Provider state.

Per-session identity is the tuple of tenant, sandbox, and the mutually
exclusive terminal or Browser session identifier. It deliberately excludes
caller and grant IDs so that minting another grant or using another authorized
caller cannot bypass the same-session limit. One slot covers the entire
logical Gateway connection, including all bounded reconnect attempts. A
deferred idempotent release returns it on every error, cancellation,
revocation, expiry, client close, backend failure, and reconnect-exhaustion
path.

The reference Browser Gateway uses a total limit of 16 and a per-session limit
of 1. The same-repository Docker vertical uses 4 and 1. These values are test
composition inputs, not production sizing recommendations.

## Release Boundary

Focused race/shuffle tests must prove invalid configuration rejection,
per-session rejection while global capacity remains, global rejection,
concurrent contention, no Provider resolution on rejection, metadata-only
audit identity, stream closure, and slot reuse after connection close and
revocation. Full repository race/shuffle, vet, the unchanged Contract verifier,
and the 48-case Conformance Suite remain required.

This component limits only connections that have entered the Gateway policy
state machine. `BrowserService.Serve` still upgrades the WebSocket before
authorization and capacity acquisition, so this result does not bound TCP,
TLS, HTTP, WebSocket-handshake, or authorizer load. It also does not provide a
distributed counter, durable revocation, hostile multi-tenant isolation, a
deployable public edge, production storage, production advertisement, or
production readiness.

## Consequences

- Browser composition fails closed unless both local capacity limits are
  explicit and valid.
- A full Browser connection or reconnect storm cannot cause unbounded Provider
  resolution and backend dialing inside one Gateway process.
- A later deployable edge must add pre-upgrade load shedding and rate limits,
  shared or partition-aware capacity, distributed revocation, and operational
  metrics without moving caller policy into the Provider.
- Production Browser advertisement remains disabled until those independent
  deployment, multi-controller, tenant-security, and operational gates pass.
