# ADR 0025: Browser Command Composition and Caller Edge

- Status: Accepted for the P4 Browser command-composition slice
- Date: 2026-09-04

## Context

ADRs 0019 through 0024 define the signed Browser image, Provider-local Docker
runtime, provenance verifier, restricted-egress network, protected Provider
routes, and caller-owned Browser Gateway as separately tested components. None
of those components alone makes the Browser profile runnable. A command root
must bind the exact components without adding a weaker fallback, while keeping
the public Gateway outside Provider ownership.

The Browser lifecycle differs from coding/shell. Creating a Browser sandbox
establishes durable Provider authority and proves that the signed image,
restricted network, and local immutable image metadata are ready. Chromium is
allocated only after an admitted Browser session request. Treating lifecycle
create as session allocation would duplicate runtime identity and make retry,
expiry, and usage evidence ambiguous.

## Decision

Add an explicit `browser` Provider lifecycle driver and a default-disabled
Browser configuration graph. Enabling it requires protected admission, a
file-backed lifecycle repository, durable Browser session and opaque-reference
stores, durable usage evidence, the exact digest-pinned Browser image, pinned
provenance executable, one immutable restricted-network Gateway image, one
operator-owned uplink, an exact create-time network policy, bounded resources,
and stable single-controller ownership identities. Missing or inconsistent
dependencies fail startup. Disabled Browser configuration is inert.

The Browser lifecycle readiness adapter performs no Chromium allocation. It
revalidates the restricted network policy, signed publication, and local image
metadata on create and recovery. The Browser application separately allocates
Chromium, registers an opaque handoff, contributes its operation family to the
Provider operation reader, and contributes bounded duration evidence to the
shared usage route.

Startup order is Browser stores and runtime, lifecycle recovery, protected
admission, usage storage, Browser application recovery, operation/usage
aggregation, then the mTLS Provider server. Every failure closes already-owned
resources in reverse dependency order. The Browser application owns the
Browser runtime close exactly once; the lifecycle adapter borrows it and does
not close it.

Graceful shutdown preserves successful, unexpired Browser allocations and
accepted requests without allocations so a later process can reconstruct
them. Running, failed, cancelled, outcome-unknown, and expired allocations are
revoked before identity-bound runtime cleanup. Browser repositories and the
restricted-network/runtime clients close only after that cleanup attempt.

The Provider command exposes only the protected Browser control-plane routes.
It does not expose a public Browser WebSocket route. A separate caller process
must explicitly compose the Browser Gateway with its own user/tenant
authorizer, revocation source, metadata-only recorder, WebSocket admission,
and reconnect policy around the Provider opaque-reference resolver.

Capability advertisement remains unchanged. In particular, this slice does
not add a Browser advertisement switch and does not advertise
`sandbox.browser`, even when the development Browser graph is enabled.

## Release Boundary

Component tests must cover disabled configuration, complete fail-closed
validation, runtime readiness, operation and usage aggregation, startup
recovery, durable lock ownership, idempotent close, cleanup ordering, and
preservation of recoverable sessions. A tagged real-Docker vertical test must
cover Browser lifecycle create, session open and opaque handoff, a caller-owned
Gateway CDP round trip, allowed and denied egress, process reconstruction,
usage evidence, and cleanup using the locked signed image.

Only after that graph passes may the separate `e2e` module add Browser
scenarios through independent caller and reference-stack processes. The
Browser caller result remains distinct from Contract projection, Provider
admission, repository CI, aggregate conformance, real Agent Platform
compatibility, multi-controller reliability, hostile multi-tenant isolation,
deployment readiness, and production readiness.

## Consequences

- Browser can be exercised as a complete development graph without claiming
  capability availability to general callers.
- Runtime readiness and session allocation retain separate identities and
  recovery behavior.
- No allow-all public Gateway or Provider-owned user authorization is created.
- Multi-controller storage and production-capable adapters remain future
  release gates rather than implications of this composition.
