# ADR 0029: Browser Public TLS Edge

- Status: Accepted for the P4 Browser listener/TLS/HTTP component
- Date: 2026-09-04

## Context

ADR 0028 bounds requests only after Go's HTTP server has accepted a connection,
completed TLS and parsed the request. The Browser reference deployment sets
ordinary `net/http` timeouts and a header budget, but those values are assembled
inside the test stack, its listener accepts an unbounded number of concurrent
connections, and its TLS policy is left to `ListenAndServeTLS` defaults. The
existing Browser caller therefore does not prove that slow or oversized input is
bounded before the Browser handler runs.

The public Gateway remains caller-owned. This component must not move tenant or
user authorization, routing policy, revocation, audit, or Provider endpoint
resolution into the Provider. A bounded listener in one process is also not
shared capacity, distributed abuse control, or production deployment evidence.

## Decision

Add an explicit `gateway/edge.TLSServer` for a caller-owned public Gateway. Its
constructor fails closed unless it receives a concrete TCP address, handler,
server-auth certificate and private key, positive accepted-connection limit,
bounded HTTP timeouts, and a bounded request-header budget.

Certificate and key files are read as bounded regular files before the listener
starts. The key pair and certificate validity are checked and frozen into an
immutable server TLS configuration. The edge accepts TLS 1.3 and HTTP/1.1 only;
HTTP/2 is outside the current RFC 6455 Gateway profile. Plaintext and older TLS
versions never reach the HTTP handler.

The TCP listener is wrapped with a simultaneous accepted-connection limit before
TLS. Connections over that limit remain outside the server's accepted set until
a slot is released or the client abandons them. `ReadHeaderTimeout` bounds both
TLS handshake/header progress, `MaxHeaderBytes` bounds parsed request headers,
and explicit read, write, and idle timeouts bound later HTTP work. Startup bind
and shutdown preserve caller cancellation and deadlines.

The Browser reference deployment uses explicit test values and the black-box
caller verifies:

- TLS 1.2 is rejected while TLS 1.3 with HTTP/1.1 succeeds;
- a connection that stops during request headers is reclaimed;
- an oversized request header is rejected before the handler; and
- filling the accepted-connection limit prevents further TLS work and service
  recovers after a connection is released.

These checks use the public TCP/TLS endpoint only. They do not import Provider
implementation packages or add identity-bearing Gateway audit records.

## Release Boundary

Focused tests must cover invalid and typed-nil configuration, bounded and
regular TLS material, certificate semantics, fixed TLS/HTTP protocol policy,
listener saturation and recovery, slow-header timeout, oversized-header
rejection, cancellation before bind, and graceful shutdown. Full repository
race/shuffle, vet, unchanged Contract verification, and the locked Conformance
Suite remain required. The independent Browser caller must pass the public-edge
scenario over the separately built reference stack.

This is a bounded listener/TLS/HTTP component and Browser reference-caller
result only. It is not authenticated tenant-partitioned or shared capacity,
distributed rate limiting, durable distributed revocation, a deployable
production configuration, hostile multi-tenant evidence, aggregate conformance,
multi-controller reliability, deployment readiness, or production readiness.

## Consequences

- The Browser reference Gateway no longer starts with implicit TLS or HTTP
  listener defaults.
- TCP clients cannot create more than the configured number of concurrently
  accepted TLS/HTTP connections in one process, and slow connections lose their
  slot within the configured header deadline.
- The service-level limiter from ADR 0028 remains required because listener
  bounds do not replace request-rate or WebSocket connection policy.
- Partition-aware shared capacity, durable distributed revocation, metrics,
  production storage/configuration, and hostile-tenant evidence remain open
  before any production Browser advertisement.
