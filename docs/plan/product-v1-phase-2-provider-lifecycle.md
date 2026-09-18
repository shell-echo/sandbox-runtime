# Product v1 Phase 2: Provider Lifecycle Closure

- Status: complete for the fixed nine-step scope
- Date: 2026-09-18
- Scope: minimum Provider lifecycle needed by a reconciled Product caller

## Outcome

Phase 2 produced a new exact Provider Contract revision and a composed,
capability-gated implementation for termination, reversible desired state,
lease renewal and expiry cleanup, resumable lifecycle events, and terminal
session close. It does not implement Product persistence, Product UI, a public
Gateway, or a Guest Agent.

The plan is fixed at nine independently reviewable steps. A later step may not
claim authority from a document or implementation layer that its predecessor
did not complete.

## Fixed steps

| Step | Deliverable | Acceptance gate | Status |
| --- | --- | --- | --- |
| 1. Authority gap audit and scope freeze | Compare lock-selected wire authority with admission/DTO, domain, repository, driver, application, and transport code; decide included and excluded operations; accept the scope ADR | Provider lock verifies unchanged; documentation links and diff checks pass; no implementation claim | **Complete** |
| 2. Contract authority and projections | Add coordinated OpenAPI, closed schemas, semantic rules, fixtures, definition cases, manifest resources, DTO projections, capability identities, Calling Standard text, and a refreshed exact lock | JSON/YAML/schema/ref validation, projection tests, content-derived Suite verification, and Provider lock verifier pass; capabilities remain unadvertised | **Complete** |
| 3. Lifecycle domain and persistence | Add immutable operation types and atomic reservations for terminate, suspend/resume, and lease renewal; define generation/fencing/idempotency/event transactions and retained expiry work | Memory/file repository race/shuffle tests prove replay, conflicts, stale fences, crash reload, monotonic events, and no mutation before acceptance | **Complete** |
| 4. Runtime lifecycle capabilities | Add focused optional terminate, suspend, resume, and observation ports; implement fake and exact-owned Docker adapters without widening every driver | Unit tests plus tagged Docker integration prove idempotent removal, mount cleanup, pause/resume observation, ownership rejection, cancellation, and bounded failures | **Complete** |
| 5. Lifecycle application and reconciliation | Compose commands, lease-expiry processing, recovery, deadlines, cancellation, unknown outcomes, and exact-resource reconciliation | Race/shuffle tests cover create/terminate races, lease expiry, stale generations/fences, lost responses, restart, and no blind redispatch | **Complete** |
| 6. Lifecycle event read vertical | Project bounded event pages, retention floor, next/latest cursors, `410` expired and `409` ahead behavior through application and protected transport | Schema/projection/transport/restart tests prove contiguous resume and explicit gaps; no SSE claim | **Complete** |
| 7. Terminal-session close vertical | Add close authority, reference revocation, active attachment termination, exact receipt cleanup, reconciliation, and retained operation projection | Race/shuffle and tagged Docker tests prove idempotent close, stale generation rejection, reconnect denial, active close, expiry races, restart, and unknown outcomes; resize remains rejected | **Complete** |
| 8. Protected transport and capability composition | Wire lifecycle and terminal-control handlers, operation aggregation, command configuration, readiness, and all-or-nothing capability advertisement | Protected admission, strict bounds, safe errors, startup equality, route projection, and default-disabled tests pass | **Complete** |
| 9. Integrated release gate and handoff | Complete behavior cases and lock refresh, run full gates and coding/shell black-box lifecycle scenarios, synchronize docs, and publish the future external-caller qualification boundary | `gofmt`, full race/shuffle, vet, Contract verifier, clean VCS-built local Suite, tagged Docker tests, restart/cleanup evidence, doc checks; exact non-claims recorded | **Complete** |

## Frozen scope

The normative scope decision is [ADR 0048](../adr/0048-provider-lifecycle-closure-scope.md).
In brief:

- lifecycle control is one optional all-or-nothing capability covering
  termination, `ready`/`suspended`, lease renewal/expiry, and event reads;
- terminal close is a separate optional control capability layered on the
  existing terminal capability;
- resize, snapshot/restore, Browser close, Product services, and deployment
  work are excluded;
- operation success never outruns confirmed runtime state and cleanup;
- unknown outcomes remain explicit and reconcile by observation rather than
  blind retry; and
- the exact Provider v1 revision selected by Step 2 is the coordinated
  additive authority for this surface.

## Release claims

Completing a step proves only its acceptance gate. In particular:

- Contract selection does not prove implementation or advertisement;
- component tests do not prove the composed command or Docker behavior;
- repository-local black-box tests do not prove an independent external
  caller;
- file-backed repositories remain single-controller development evidence; and
- Phase 2 completion will not by itself establish Product readiness,
  standalone deployment, HA, hostile multi-tenant safety, or production
  readiness.

## Subsequent large phases

After Phase 2, the Product v1 delivery horizon has four large phases:

1. Product control-plane foundation: package boundary guard, PostgreSQL
   migrations, command transaction, idempotency, operations, events, and
   outbox.
2. Minimal Workspace vertical: Provider adapter, reconciler, one
   `primary-code` slot, revision materialization, and restart recovery.
3. Runtime data plane: public Gateway, connection grants, terminal profile,
   Guest Agent slices, recording, and further capability-gated session kinds.
4. Deployment qualification: standalone first, then production topology,
   security, reliability, SLO, provenance, backup/restore, and operational
   evidence gates.

The future hostile-multitenant track remains outside the Product v1 delivery
horizon and requires its own strong-isolation program.

## Completion result

The completed audit is
[Phase 2 Step 1: Provider Lifecycle Authority Gap Audit](../audits/phase-2-step-1-provider-lifecycle-authority-gap.md).
It found that the earlier lifecycle names and storage methods were scaffolding,
not locked behavior; runtime cleanup supported a terminal-close slice, while no
resize capability existed. Implementation revision
`98995384c60a924f25ca58d3b7e561207bfa5be8` contains the coordinated Contract
and lifecycle implementation. Lock-selection revision
`3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1` selects its exact Contract tree,
and the clean-VCS 60-case Suite, full repository gates, tagged Docker lifecycle
integration, and 15+5+9 independent-process reference black-box run pass. The
completion record is
[Phase 2 Provider Lifecycle Completion](../audits/phase-2-provider-lifecycle-completion.md).

The black-box caller is repository-owned rather than separately implemented.
No new independent external-caller, multi-controller, deployment,
hostile-multitenant, or production result is claimed.
