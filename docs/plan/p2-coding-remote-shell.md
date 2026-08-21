# P2.0 Coding and Remote-Shell Authority Inventory

Status: P2.0a authority inventory passed in PR #29 merge `83965a2` and
post-merge CI `32440383198`. P2.0b/c bounded exec resources, lock, and
projection gate passed in PR #30 merge `9d00212`; post-merge CI
`32444266288` passed. P2.1 local domain/application-port work passed in PR #31
merge `67b64a9`; post-merge CI `32445893337` passed. P2.2a result and
cancellation-intent domain passed in PR #33 merge `ba39053`; post-merge CI
`32454054853` passed. P2.2b persistence is implemented and locally verified
on the current feature branch; commit, PR, and post-merge evidence are pending.
ADR 0009 records the ownership boundary and ADR 0010 records the bounded exec
Contract decision.

## Authority stop condition

The current repository-owned Contract authorizes capability discovery, the
bounded create/status/operation lifecycle projection, and bounded `exec`,
exec-cancellation-intent, and retained-result wire resources. Runtime sessions,
terminal endpoints, usage evidence, and artifact staging remain unauthorized.
The architecture narrative is not sufficient authority to implement any route
or runtime behavior beyond the locked resources and this delivery order.

Before runtime behavior changes, this slice must:

1. inventory the P2 responsibilities against the ownership boundary and current
   Provider DTO packages;
2. define additive v1 OpenAPI resources and JSON Schemas, or record a new
   namespace when an additive change is not safe;
3. define semantic rules for argv/environment references, working-directory and
   path bounds, stdin policy, deadlines, cancellation intent, output limits,
   result retention, opaque session references, and artifact authority;
4. add valid/rejection fixtures and executable Conformance Suite case IDs;
5. update the Contract lock, projection tests, CI gate, and an ADR together.

No exec, terminal, session, snapshot, artifact, or public endpoint code may be
implemented before those inputs are locked. Do not copy or restore an absent
external Contract, and do not reuse `/instances` or backend structs as Provider
wire DTOs. The P2.0b resource commit intentionally has no runtime dispatch;
P2.1 remains uncomposed from Provider HTTP and contains no durable operation
acceptance, result retention, cancellation, reconciliation, or backend adapter.

## Delivery order

- P2.0a: ownership and authority inventory, including caller/runtime-gateway
  boundaries and security-base assumptions (passed; ADR 0009);
- P2.0b: additive Contract resources, semantic rules, fixtures, and Suite
  (implemented in resource commit `4a2a58f`);
- P2.0c: lock and projection gate with no runtime dispatch (passed in PR #30
  merge `9d00212`; post-merge CI `32444266288` passed; ADR 0010);
- P2.1: bounded exec application/domain ports after P2.0 closes (passed in PR
  #31 merge `67b64a9`; post-merge CI `32445893337` passed);
- P2.2: retained result and cancellation behavior;
- P2.3: opaque terminal/session application and gateway handoff;
- P2.4: artifact staging and usage evidence.

Each implementation slice requires its own focused tests, race/shuffle suite,
Contract lock verification, Conformance evidence, PR CI, and post-merge CI.
None of these slices establishes external-caller compatibility, multi-tenant
security, deployment readiness, or production readiness by itself.

## P2.1 Boundary

Status: passed as a local component/application boundary only. It does not
establish Provider HTTP compatibility, durable operation semantics, runtime
execution behavior, external-caller compatibility, multi-controller
reliability, multi-tenant safety, deployment readiness, or production
readiness.

P2.1 owns only a backend-neutral Provider-local request model, strict bounded
validation, immutable invocation copy, execution port, and application service.
It derives a context deadline for the port and reports a cancellation or
deadline during dispatch as an unknown outcome. The opaque execution receipt is
validated before it can leave the application boundary.

P2.1 excludes Provider HTTP dispatch, `202` operation projection, lifecycle
repository reuse, backend/Docker selection, retained results, cancellation
intent, reconciliation, sessions, artifacts, usage, and `/instances`. An
`expected_generation` is bounded but not compared to sandbox state until a
future explicitly authorized persistence/reconciliation slice supplies that
state boundary.

## P2.2 Delivery Breakdown

P2.2a defines only the provider-local retained-result and cancellation-intent
domain. Result retention is derived from the admitted exec request; an intent
does not claim process cancellation. PR #33 and post-merge CI
`32454054853` close this domain slice as local component evidence.

P2.2b adds a separate exec ledger with atomic idempotency, immutable snapshots,
result-expiry tombstones, and restart recovery. Its local implementation and
verification are complete, pending commit and PR evidence. It must not reuse
the lifecycle repository or dispatch an executor during recovery. P2.2c may add
bounded coordination and an optional cancellation port, but continues to
exclude Provider HTTP composition and Docker/backend adapters. The current
repository port records an already-produced opaque dispatch receipt; it is not
a durable pre-dispatch accept. P2.2c must not start an executor before that
acceptance is durable and must introduce an explicit reservation/attach design.
