# ADR 0007: Provider Lifecycle Projection Boundary

- Status: Accepted for P1.2.4 implementation
- Date: 2026-08-20

## Context

P1.2.3 supplies provider-local create coordination, persistence, deadlines,
fencing, and restart reconciliation. Those values are not wire DTOs and must
not be exposed by serializing lifecycle, instance, repository, or driver
models directly. The repository-owned Contract authorizes only a bounded
create/status/operation surface; all other lifecycle families remain reserved.

## Decision

The protected Provider transport receives a narrow `LifecycleApplication` port
with create acceptance, sandbox read, and operation read methods. After mTLS,
JWS, context, target, digest, replay, and fencing admission succeeds, the
transport strictly decodes the create request, binds its identity fields to
the admitted context, and dispatches only through that port. Domain values are
validated before projection into the locked Provider DTOs.

The implementation supports only the Contract's safe create profile: pinned
SHA-256 image, no requested capabilities, no network access, ephemeral
read-only workspace, bounded positive resources, and the required unprivileged
security policy. It returns bounded standard errors with stable conflict
codes, and never emits backend identifiers, host paths, raw endpoints,
diagnostics, secrets, or credentials. A missing application remains fail-closed
with `503`; reserved routes remain absent after admission.

The command composition root does not construct a new Provider lifecycle
repository/driver graph in this slice. Wiring that graph is a separate
composition and release decision; it must not reuse the local `/instances`
repository or driver model.

## Consequences

- Projection tests prove transport/application boundary behavior only.
- The local Contract lock and Conformance Suite remain the wire authority.
- This ADR does not establish aggregate lifecycle conformance, external-caller
  compatibility, multi-controller reliability, multi-tenant safety, deployment
  readiness, or production readiness.
- P1.2.5 must close the lifecycle fault/concurrency release gate before the
  Provider lifecycle surface is treated as generally available.
