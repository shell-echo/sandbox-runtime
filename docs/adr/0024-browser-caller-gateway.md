# ADR 0024: Caller-Owned Browser Gateway Boundary

- Status: Accepted for the P4 Browser Gateway component
- Date: 2026-09-04

## Context

ADR 0023 added the two protected Provider Browser handlers, while the Browser
reference resolver already rechecks a durable opaque handoff and committed
session state at resolution and again at every dial. The remaining data-plane
boundary is owned by the caller: user and tenant authorization, revocation,
audit, reconnect policy, public WebSocket admission, and conversion between a
public WebSocket message and the private post-handshake CDP WebSocket stream.

The existing Runtime Gateway policy state machine already provides those
controls for terminal sessions, but its identity model and Provider adapter are
terminal-specific. Browser uses a distinct session identity and
`ref:browser-session:*` namespace. Its private adapter also returns RFC 6455
wire bytes after completing a separate handshake with Chromium, rather than a
PTY byte stream. Treating either boundary as terminal data would weaken type,
reference, and framing checks.

## Decision

Keep one caller-owned Gateway policy state machine and extend its identity
model with a mutually exclusive Browser session field. A request and its grant
must select exactly one of `runtime_session_id` and `browser_session_id`; the
selected identity determines the only accepted opaque-reference namespace.
Authorization grants continue to bind caller, tenant, sandbox, capability,
session, reference, connection generation, and expiry exactly. Audit events
record the selected session identity and bounded counters, never frame payloads
or Provider endpoint details.

Add a separate Browser composition entry point. It requires explicit caller
authorizer, revocation source, recorder, WebSocket handshake admission,
Provider Browser reference resolver, and bounded reconnect settings. It
supplies no allow-all or public-listener default. The Provider resolver is
called again for every reconnect and its dial closure performs the second
fresh reference and committed-session check.

Adapt the private post-handshake Chromium stream with the MIT-licensed
`github.com/gobwas/ws` RFC 6455 implementation. Incoming server frames must be
unmasked and protocol-valid; outgoing client frames are masked. Text and binary
messages, fragmentation, ping/pong, close, UTF-8 validation, partial writes,
and a hard message limit are handled at this boundary. Compression and
extensions are not negotiated. The existing public WebSocket adapter retains
the same bounded frame limit, so the Browser bridge cannot silently expand the
reviewed data-plane budget.

## Release Boundary

Focused tests cover mutually exclusive identities and reference namespaces,
grant and cross-tenant denial before resolution, metadata-only audit, exact
Browser reference projection, RFC 6455 masking and frame validation,
fragmentation, control frames, oversize rejection, expiry, active revocation,
fresh resolution on reconnect, typed-nil dependencies, and stream closure.
Full race/shuffle, vet, Contract verification, and the unchanged 48-case Suite
must pass.

This component does not add a public Gateway route or deployment, inject the
Browser application into `cmd/serve`, compose the complete runtime graph,
enable `sandbox.browser` advertisement, or establish Browser external-caller
E2E. It does not establish aggregate conformance, real Agent Platform
compatibility, multi-controller reliability, hostile multi-tenant isolation,
deployment readiness, or production readiness.

## Consequences

- Terminal and Browser share reviewed caller-policy behavior without sharing
  Provider DTOs, reference namespaces, or backend adapters.
- A future caller process can expose its own authenticated route around the
  Browser service; this repository still supplies no platform policy default.
- Browser startup composition remains fail closed until the real runtime,
  resolver, protected transport, and operation aggregation are wired together.
- Capability advertisement remains disabled until complete composition,
  security/fault evidence, and Browser external-caller E2E pass independently.
