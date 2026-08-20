# ADR 0004: Minimal Provider Lifecycle Contract

- Status: Accepted for P1.2.0 Contract scope
- Date: 2026-08-20

## Context

The repository-owned Provider Contract currently authorizes capability discovery
and protected admission only. The architecture describes a larger asynchronous
lifecycle surface, but that narrative is not wire authority. Runtime code must
not be inferred from the local `/instances` API or from DTO types that are not
yet projected by the Contract.

P1.2 needs a small, reviewable Contract boundary before domain, persistence, or
coordinator work can begin. The first lifecycle slice must establish enough
authority to represent an idempotent create request and to observe its bounded
provider-local operation and sandbox status.

## Decision

The additive `v1` Contract revision adds only these operations:

- `POST /v1/sandboxes` accepts a protected, asynchronous create request and
  returns a `202` Provider operation document;
- `GET /v1/sandboxes/{sandbox_id}` reads the provider-local desired and
  observed status document; and
- `GET /v1/operations/{operation_id}` reads the bounded provider-local create
  operation document.

The request is strict and bounded. It carries an operation/attempt identity,
positive fencing token, idempotency key, request digest, deadline, protocol
version, and a pinned-image, provider-revision-bound sandbox specification.
The security policy is fail-closed by schema: unprivileged execution, a
read-only root filesystem, no host namespace access, and no privilege
escalation are required. The request body is limited to 1 MiB.

Semantic rules require the same idempotency key and digest to return the same
logical operation, while a different digest is a `409` conflict. Create starts
at generation one. Stale attempts and fencing tokens fail before repository or
driver dispatch. Deadlines are checked before dispatch; cancellation remains
intent, and a lost response that may have taken effect is `outcome_unknown`.
Operation states are `accepted`, `running`, `succeeded`, `failed`, `cancelled`,
and `outcome_unknown`.

All other lifecycle families in the architecture, including restore, desired
state mutation, lease extension, terminate, events, exec, sessions, and
snapshots, remain reserved and are absent from this Contract revision. No
Provider route, repository behavior, driver behavior, or lifecycle code is
implemented by this ADR.

The calling platform remains authoritative for tenant/user authorization,
desired state, ProviderRevision selection, aggregate operation truth, retries,
and final workflow status. This service exposes only provider-local status and
evidence, with opaque bounded references and no backend identifiers, host
paths, raw endpoints, secrets, or credentials.

## Consequences

- P1.2.1 may define pure value objects and transitions only after this Contract
  tree and lock pass review and the local projection gate.
- A later additive revision may expand operation types, status transitions,
  leases, events, results, and optional capabilities without silently changing
  this revision's create semantics.
- Contract fixtures and Suite cases prove schema/declaration projection only;
  they do not prove runtime lifecycle behavior, aggregate conformance,
  multi-controller reliability, tenancy, deployment, or production readiness.

## Evidence boundary

This decision replaces no external or proprietary Contract text. It is an
MIT-licensed local authority and does not establish compatibility with an
external caller or Agent Platform implementation.
