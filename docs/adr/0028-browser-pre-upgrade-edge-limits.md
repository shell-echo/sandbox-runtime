# ADR 0028: Browser Pre-Upgrade Edge Limits

- Status: Accepted for the P4 Browser public-edge limiter component
- Date: 2026-09-04

## Context

ADR 0027 bounds total and per-session Browser connections inside the Gateway
policy state machine, but `BrowserService.Serve` first completes the public
WebSocket upgrade. A connection burst can therefore consume WebSocket and
Gateway-authorizer work before the existing capacity check. The reference
caller proves that post-upgrade capacity works; it does not prove public-edge
load shedding or request-rate recovery.

The public edge is caller-owned. It must not move user or tenant authorization,
public routing, or platform policy into the Provider. A local limiter also
cannot establish shared capacity, distributed revocation, multi-controller
correctness, hostile-tenant isolation, or production deployment.

## Decision

Add a narrow `gateway/edge.Gate` port and an explicit process-local
implementation. Browser composition requires the port; terminal composition is
unchanged pending its own compatibility review. `BrowserService.Serve` acquires
one edge lease before WebSocket handshake admission and upgrade. The lease is
held across Gateway authorization, Provider resolution, reconnects, and the
entire public connection, then released idempotently on every return path.
Direct `BrowserService.Connect` remains an already-adapted-stream entry point
and does not claim this public-edge control.

The local implementation combines a non-queueing global concurrent-connection
bound with a global fixed-window request limit. Every attempt reaching
`BrowserService.Serve`, including later admission or upgrade failures, consumes
the request budget; a capacity-rejected attempt also consumes it. This prevents
repeated probes from bypassing the rate boundary. Configuration is explicit and
bounded: concurrent connections cannot exceed 1,000, requests per window cannot
exceed 100,000, and a window must be between 100 milliseconds and one minute.
The clock fails closed if it is zero or moves backwards.

Capacity and rate rejection occur before WebSocket upgrade and return only a
generic HTTP `429` with an integer `Retry-After` value. Unknown limiter failures
return a generic `503`. Cancellation is propagated without attempting to write
a new response. No unauthenticated tenant or user identity is recorded at this
layer. The existing Gateway audit remains the authority for admitted connection
metadata.

The Browser reference stack uses 32 public-edge connections and eight attempts
per one-second window. These are test inputs, not production sizing guidance.
Its handler still performs bounded bearer parsing before `BrowserService.Serve`;
therefore this component does not bound TLS, HTTP parsing, that preliminary
handler work, or traffic rejected before the service is called.

## Release Boundary

Focused race/shuffle tests must cover invalid configuration, fixed-window
recovery, concurrent contention, rate-before-capacity accounting, cancellation,
clock failure, idempotent release, pre-admission rejection, generic `429` and
`Retry-After`, generic `503`, and release after handshake failure and successful
connection close. Full repository race/shuffle, vet, the unchanged Contract
verifier, and the 48-case Conformance Suite remain required.

The black-box Browser caller must burst authenticated requests with a rejected
Origin, observe both ordinary handshake rejection and pre-upgrade `429`, wait
the published retry interval, and observe ordinary handshake admission again.
The burst must not reach Gateway authorization, revocation, Provider resolution,
or add identity-bearing Gateway audit events.

This gate is process-local, global rather than tenant-partitioned, and attached
only to the Browser service. It is not a deployable public Gateway, shared or
distributed capacity, durable revocation, production identity, hostile
multi-tenant evidence, deployment readiness, or production readiness.

## Consequences

- Browser composition now fails closed without both pre-upgrade edge limits and
  the existing post-authorization Gateway capacity limits.
- A burst that reaches the Browser service cannot create unbounded upgraded
  WebSockets or downstream Gateway authorization work in that process.
- A deployable edge still needs listener/TLS/HTTP limits, authenticated
  partition-aware and distributed policy, durable revocation, production
  storage/configuration, metrics, and hostile-tenant evidence.
- Production Browser advertisement remains disabled.
