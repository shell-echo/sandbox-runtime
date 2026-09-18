# Phase 2 Step 1: Provider Lifecycle Authority Gap Audit

- Status: Complete as read-only implementation audit and scope input
- Date: 2026-09-18
- Code snapshot inspected: `e5bc9bd7039e01a1898f90fbd77684a1cb6699ad`
- Contract authority inspected: revision
  `22ba6987ea5fbc37d53942720133c0acad199edd`, tree
  `c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38`

## Question

Which minimum Provider lifecycle capabilities are already authorized, which
exist only as internal scaffolding, and which must be designed and implemented
before the target Product can safely reconcile a sandbox?

This audit distinguishes four different facts that must not be collapsed:

1. a route and document shape selected by the locked Provider Contract;
2. an admission name, route matcher, or transport DTO reserved in Go;
3. a provider-local domain, repository, or runtime capability; and
4. a composed, advertised, and tested Provider behavior.

Only the first category is wire authority. Only all four together, plus the
named gates, may support a capability advertisement or readiness claim.

## Locked surface

The lock-selected OpenAPI has 15 operations:

| Family | Locked operations |
| --- | --- |
| Discovery | `GET /v1/capabilities` |
| Sandbox lifecycle | `POST /v1/sandboxes`; `GET /v1/sandboxes/{sandbox_id}` |
| Exec | `POST /v1/sandboxes/{sandbox_id}/exec`; `POST /v1/sandboxes/{sandbox_id}/exec:cancel`; `GET /v1/operations/{operation_id}/exec-result` |
| Artifact and usage evidence | `POST /v1/sandboxes/{sandbox_id}/artifacts:stage`; `GET /v1/operations/{operation_id}/artifact-staging-evidence`; `GET /v1/operations/{operation_id}/usage-evidence` |
| Terminal | `POST /v1/sandboxes/{sandbox_id}/runtime-sessions`; `GET /v1/operations/{operation_id}/runtime-session`; optional `GET /v1/runtime-sessions:connect` |
| Browser | `POST /v1/sandboxes/{sandbox_id}/browser-sessions`; `GET /v1/operations/{operation_id}/browser-session` |
| Operation read | `GET /v1/operations/{operation_id}` |

The locked OpenAPI does **not** authorize restore, desired-state mutation,
lease renewal, snapshot, termination, snapshot-manifest read, event read,
runtime-session close, or runtime-session resize. The current 53-case local
Suite and six-case remote discovery Suite therefore do not establish those
behaviors.

## Gap matrix

| Capability | Contract authority | Internal evidence | Missing closure |
| --- | --- | --- | --- |
| Sandbox termination | Absent | Admission operation and route matcher; strict-decoding DTO; desired/observed terminal states; Docker driver's exact-owned idempotent `Remove` | Closed schema and semantics, operation type, atomic reservation, coordinator, cleanup confirmation, transport, capability composition, Contract cases, and runtime evidence |
| Desired-state mutation | Absent | Admission operation and route matcher; DTO accepts only `ready` or `suspended`; domain transition increments generation | No suspend/resume runtime port or adapter, no durable operation reservation, coordinator, transport, or capability advertisement |
| Lease renewal and expiry | Absent | Admission operation and route matcher; DTO; repository stores and atomically replaces a lease; domain can mark expiry | No application command, idempotency record, bounded renewal policy, expiry worker, cleanup dispatch, transport, or restart evidence |
| Lifecycle events | Absent | Admission read descriptor; provider-local event model; repositories append contiguous per-sandbox sequences and page after a cursor | No wire event/page schema, retention-floor or cursor-ahead rule, application read port, transport, or gap/restart tests |
| Terminal-session close | Absent | Terminal runtime exposes idempotent receipt-bound `Cleanup`; session recovery cleans failed, cancelled, or expired allocations | No close admission operation, request/operation schema, durable close intent, reference revocation order, active attachment closure authority, or transport |
| Terminal-session resize | Absent | None in terminal/session runtime ports or Docker adapter | No capability exists to authorize; it cannot enter this phase without first adding a real runtime port and evidence |
| Snapshot and restore | Absent | Reserved admission names, DTOs, and route matchers | No selected wire authority or complete runtime/application graph; not required for minimum lifecycle closure |

The reserved lifecycle route matchers return a safe unavailable response when
no application handles them. That is useful admission scaffolding, but it is
not an implementation and cannot authorize a caller to send those requests.

The provider-local lifecycle package is also narrower than its vocabulary
suggests. Its `OperationType` validates only `create`, and its application and
coordinator accept and reconcile only create operations. Repository lease and
event methods are unused by a public lifecycle command. `OrphanCleaner.Remove`
is deliberately outside the active driver port. These are explicit gaps, not
hidden completed behavior.

## State and failure findings

- `DesiredStateRequest` already separates reversible `ready`/`suspended`
  mutation from irreversible termination. The architecture text that included
  `terminated` on the desired-state route was too broad and is corrected by
  ADR 0048.
- A lifecycle attempt may end as `outcome_unknown` after dispatch. That state
  is terminal evidence for the attempt, not permission to dispatch a blind
  replacement. Reconciliation may still advance sandbox observation and emit
  evidence; a later mutation requires an admitted idempotent replay or a new,
  higher-fenced attempt.
- The current Docker lifecycle adapter can prove exact-owned absence and remove
  deterministic mount state, but it cannot suspend or resume a sandbox. Docker
  pause/unpause support must be introduced behind focused optional driver
  interfaces and exercised by the tagged integration gate.
- Current event storage retains all events and rejects a cursor beyond the
  list. That does not yet define a stable retention floor, cursor expiry, or a
  caller-visible gap recovery protocol.
- Terminal expiry and process shutdown invoke receipt-bound cleanup, but there
  is no caller-authorized close command. Stream close methods are connection
  teardown and must not be mistaken for durable session-close authority.

## Scope conclusion

Phase 2 includes one complete, capability-gated lifecycle-control slice:

- irreversible sandbox termination;
- reversible `ready`/`suspended` desired-state mutation;
- explicit lease renewal plus expiry-driven cleanup;
- bounded resumable lifecycle event reads with detectable gaps; and
- terminal runtime-session close because the runtime already has an
  identity-bound cleanup primitive.

Phase 2 excludes terminal resize, snapshots, restore, Browser-session close,
public Gateway behavior, Product persistence, and Product UI. Exclusion means
unadvertised and unauthorized, not silently emulated.

The exact semantics, capability identities, dependency order, evidence rules,
and compatibility decision are frozen in
[ADR 0048](../adr/0048-provider-lifecycle-closure-scope.md). The executable
sequence is fixed in the
[Phase 2 plan](../plan/product-v1-phase-2-provider-lifecycle.md).

## Evidence boundary

This document is inspection evidence only. It changes no Provider Contract
resource, lock, Go code, runtime behavior, capability advertisement, or release
claim. The Phase 1 design and Product Contract changes in this worktree remain
uncommitted and separate from this Phase 2 audit.
