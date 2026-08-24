# ADR 0011: Terminal Session Contract and Gateway Handoff

- Status: Accepted for P2.3a-P2.3c0 Contract and projection scope
- Date: 2026-08-21

## Context

The architecture includes a future terminal session and Runtime Gateway, but
the locked Provider Contract previously had no runtime-session route, session
request, handoff document, or read descriptor. Existing unprojected DTOs and a
fail-closed protected transport placeholder do not supply Contract authority.

## Decision

P2.3a adds a narrow additive v1 Contract for an asynchronous terminal session
only:

- `POST /v1/sandboxes/{sandbox_id}/runtime-sessions` accepts a protected,
  idempotent terminal-session open request and returns a Provider operation.
- `GET /v1/operations/{operation_id}/runtime-session` reads a protected,
  bounded terminal handoff document after the open operation has succeeded.
- The open request binds operation, attempt, fencing token, idempotency key,
  request digest, deadline, expected sandbox generation, session identity,
  terminal capability profile, and expiry. Browser, desktop, port-forward,
  target-port, and Gateway user scopes are excluded.
- A handoff contains only operation identity, terminal session identity,
  capability profile, WebSocket protocol label, connection generation, expiry,
  and a strictly opaque internal endpoint reference. It must not contain a URL,
  network address, port, backend identifier, credential, or provider access
  token reference.
- The Provider creates provider-local evidence only. The calling platform
  Runtime Gateway owns end-user authorization, public proxying, reconnect
  policy, and recording metadata. The opaque reference is resolved through a
  trusted control-plane/Gateway channel and is not a public bearer credential.
- A terminal capability and profile must be advertised and admitted before an
  open request may be accepted. Expiry may not exceed the admitted policy,
  sandbox lease, or operation deadline. A stale generation or fencing token
  fails before dispatch. Unknown outcome never creates or reopens a handoff.

## Consequences

- P2.3a changes only Contract authority: OpenAPI, Schemas, semantic rules,
  fixtures, Suite IDs, and this ADR. It adds no router, application, driver,
  terminal process, or Gateway implementation.
- PR #43 added the P2.3a/b resources, lock, strict wire DTO projection,
  admission binding, and Suite runner mappings.
- P2.3c0 defines a strict zero-or-terminal-only capability snapshot. Disabled
  configurations retain empty arrays. A nonempty snapshot must advertise only
  `sandbox.terminal` at semver `1.0.0` and map the canonical `terminal-v1`
  capability profile to exactly one advertised runtime profile. Local resource,
  lock, DTO, handler projection, cross-resource consistency, and 26-case Suite
  evidence exists. PR #44 head `16136d2` passed exact-head CI `32685685846`,
  merged as `6c1fc90`, and passed post-merge CI `32686754674`.
- This Contract reconciliation does not accept an open request. P2.3c1-c3 must
  separately establish the session application, durable authority, and
  protected transport before either route can be enabled.
- Later slices require separate evidence for the session application, protected
  transport projection, and a trusted Runtime Gateway integration.
- This decision excludes browser, desktop, port-forward, Docker or other
  backend selection, shell data-plane proxying, `/instances`, artifacts, usage,
  snapshots, public session revocation, external-caller E2E, multi-controller
  reliability, multi-tenant security, deployment, and production readiness.
