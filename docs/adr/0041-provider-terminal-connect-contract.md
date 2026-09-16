# ADR 0041: Provider terminal-connect contract

## Status

Accepted as a Contract-change candidate. It is not effective until a reviewed
Contract lock selects the revision and tree containing the normative resources.

## Context

The Provider terminal-session API returns an opaque, expiring handoff, while
the caller-owned Gateway must resolve that handoff through Provider authority.
The existing Go resolver is private in-process composition. An independently
owned caller cannot consume it without importing Provider implementation code,
inventing a Provider-specific adapter, or receiving a raw backend endpoint.
All three outcomes violate the repository-owned calling-standard boundary.

Adding a resolver obligation to `sandbox.terminal@1.0.0` would also silently
change the meaning of an already advertised capability. A Provider that
correctly implements the existing terminal control plane may not expose a
network resolver.

## Decision

Define the optional `sandbox.terminal-connect@1.0.0` capability with profile
`terminal-connect-v1`. It may be advertised only on a runtime profile that also
maps `sandbox.terminal@1.0.0` profile `terminal-v1` and has a composed terminal
resolver and WebSocket byte transport.
For the coding/shell composition, `exec-v1`, `terminal-v1`, and the optional
`terminal-connect-v1` all map to the same
`sandbox-runtime-coding-shell-v1` profile; the existing two-capability profile
remains valid when no network resolver is composed.

The capability authorizes one static Provider route,
`GET /v1/runtime-sessions:connect`, derived from the already trusted Provider
origin. The route uses the standard mTLS and protected JWS admission. The
caller supplies exactly one bounded, unpadded-base64url
`X-Sandbox-Runtime-Session-Handoff` header containing the closed terminal
connect descriptor. The Admission Context and JWS bind the full RFC 8785
descriptor digest, the static HTTP target, Provider revision, caller, tenant,
operation, attempt, fencing token, deadline, and policy decision.
The Browser `Origin` header and logging the handoff carrier are forbidden.

The Provider rechecks the committed session, opaque reference, expiry,
revocation, generation, and fencing bindings before the WebSocket upgrade and
again before every attach. Successful upgrade negotiates only
`sandbox-runtime-terminal.v1`; compression is forbidden, only binary messages
carry ordered terminal bytes, and message boundaries have no terminal
semantics. The Provider closes an active stream no later than the retained
handoff expiry; admission before expiry does not extend stream authority.

The caller-owned Gateway remains authoritative for end-user and tenant
authorization, grants, revocation, public connection admission, reconnect
policy, and metadata-only audit. The Provider route is a controller data-plane
boundary, not a public end-user Gateway.

## Consequences

- Existing `sandbox.terminal@1.0.0` advertisements remain valid but do not
  imply an externally consumable resolver.
- Independent callers can require the new capability and fail closed when it
  is absent; they do not import Provider packages or receive backend details.
- Each initial connection and reconnect requires fresh protected admission and
  fresh Provider resolution. A retained handoff is not itself a bearer secret.
- The Contract schema, fixture, OpenAPI route, semantic rules, and the named
  cases in the lock-selected local Conformance Suite must agree before the lock
  is refreshed.
- This ADR and candidate resources are definition evidence only. They do not
  prove that the production command serves the route or that an external
  caller has completed a terminal byte round trip.
