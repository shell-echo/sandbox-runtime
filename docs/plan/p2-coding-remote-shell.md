# P2.0 Coding and Remote-Shell Authority Inventory

Status: next planning slice after the bounded P1.2 lifecycle subset passed in
PR #27 merge `28076a7` and post-merge CI `32439289227`.

## Authority stop condition

The current repository-owned Contract authorizes only capability discovery and
the bounded create/status/operation lifecycle projection. It does not yet
authorize `exec`, cancellation, retained exec results, runtime sessions,
terminal endpoints, usage evidence, or artifact staging wire mappings. The
architecture narrative is not sufficient authority to implement those routes.

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
wire DTOs.

## Delivery order

- P2.0a: ownership and authority inventory, including caller/runtime-gateway
  boundaries and security-base assumptions;
- P2.0b: additive Contract resources, semantic rules, fixtures, and Suite;
- P2.0c: lock and projection gate with no runtime dispatch;
- P2.1: bounded exec application/domain ports after P2.0 closes;
- P2.2: retained result and cancellation behavior;
- P2.3: opaque terminal/session application and gateway handoff;
- P2.4: artifact staging and usage evidence.

Each implementation slice requires its own focused tests, race/shuffle suite,
Contract lock verification, Conformance evidence, PR CI, and post-merge CI.
None of these slices establishes external-caller compatibility, multi-tenant
security, deployment readiness, or production readiness by itself.
