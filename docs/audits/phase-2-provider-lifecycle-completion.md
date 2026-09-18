# Phase 2 Provider Lifecycle Candidate Completion

- Date: 2026-09-18
- Status: implementation-complete source candidate; not yet an exact locked
  Provider revision
- Scope authority: ADR 0048 and the nine-step Phase 2 plan

## Result

The current worktree completes the planned implementation and Contract-source
families for Provider lifecycle closure:

- reversible `ready`/`suspended` desired-state control;
- bounded lease renewal and reconciled expiry cleanup;
- irreversible explicit termination with exact-owned runtime absence proof;
- finite lifecycle-event pages with durable high-water cursors, bounded
  retention, explicit `409` ahead and `410` expired gaps;
- terminal-session close with durable intent, handoff revocation, exact
  allocation cleanup, absence confirmation, replay, restart recovery, and
  immutable unknown-attempt evidence; and
- optional all-or-nothing `sandbox.lifecycle-control@1.0.0` and
  `sandbox.terminal-control@1.0.0` capability composition.

The implementation keeps Provider wire DTOs separate from lifecycle,
repository, terminal, and Docker types. It retains caller ownership of business
desired state, end-user authorization, aggregate operations, public Gateway
policy, and final workflow decisions.

## Contract candidate

The coordinated source candidate includes five OpenAPI operations, five closed
request/response schemas, fixtures, admission-operation enums and bindings,
semantic rules, capability identities, operation types, manifest resources,
DTO projections, Calling Standard choreography, and seven additional local
Suite cases. The local Suite candidate contains 60 cases with content-derived
digest
`sha256:7db1d28d35ca193632c395247cc71eeaaff48b027964b9ea9da247eaad5e3991`.

Candidate projection tests compile and validate the new schemas, fixtures,
routes, semantic requirements, manifest inventory, cursor error details, and
Suite membership directly from the source tree. This is candidate evidence,
not a substitute for the exact Contract lock.

## Implementation evidence

The candidate adds:

- atomic durable mutation reservation with idempotency, digest, generation,
  fencing, lease, operation, and event updates across memory and file stores;
- restart-stable per-sandbox event high-water marks and a 1,000-event retained
  body window;
- fake and Docker suspend, resume, inspect, and exact-owned remove controls;
- lifecycle application recovery plus periodic pending-operation and expired-
  lease reconciliation;
- a separate versioned terminal-close record family and migration path;
- close reconciliation that never blindly repeats cleanup for an immutable
  `outcome_unknown` attempt;
- protected strict decoding and admission binding for every new mutation and
  read route; and
- fail-closed command readiness nodes for lifecycle control, expiry, event
  reads, and terminal close before capability advertisement.

Focused repository, coordinator, application, transport, capability, command,
and candidate-Contract tests pass under `-race -shuffle=on -count=1`. Event
reads reject bodies, unknown or duplicate query parameters, empty cursors, bad
encoding, negative values, and values beyond the JSON exact-integer range. The
tagged Docker integration passes on Docker Engine 29.7.2/Linux and now
exercises pause, suspended observation, idempotent pause, resume, ready
observation, idempotent resume, terminal and exec cleanup, exact removal, and
mount-root removal.

`go vet ./...`, `git diff --check`, JSON parsing, OpenAPI YAML parsing, and
manifest-path existence checks also pass. The required full-repository race
command was run; its only failing packages are the eight qualification,
remote-conformance, and locked-projection packages whose setup deliberately
invokes the exact Contract lock verifier. The verifier itself fails at the
intended clean-checkout boundary because this candidate changes tracked and
untracked files below `contract/`. No unrelated failure appeared before or
after that boundary.

## Formal completion blocker

The published compatibility lock still selects revision
`22ba6987ea5fbc37d53942720133c0acad199edd` and Contract tree
`c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38`. A replacement lock must name the
actual immutable commit and its Contract subtree. The current dirty worktree
has neither identity, and inventing one would invalidate the lock.

Therefore these final release gates remain deliberately open until commit
authority exists:

1. create the immutable revision containing the complete candidate;
2. refresh the Provider lock to that exact revision/tree and resource digests;
3. run the Provider Contract verifier against that lock;
4. build the Conformance Runner with clean VCS metadata and execute the 60-case
   local Suite from the revision archive; and
5. run the planned independent-process coding/shell lifecycle black-box
   scenarios through the protected wire surface, including restart and exact
   cleanup checks; the seven new Suite cases are Contract/schema/semantic
   projections and do not substitute for this gate; and
6. record any resulting CI or external-caller evidence under its exact
   identities.

The historical lock, 53-case Suite result, and prior external-caller
qualification remain valid only for their recorded surface. This candidate
does not claim a new independent external caller, multi-controller storage,
deployment qualification, hostile-multitenant isolation, HA, or production
readiness.

## Exclusions retained

Phase 2 still excludes snapshot/restore, terminal resize, Browser-session
close, Product persistence and APIs, a public Gateway, Guest Agent work,
deployment changes, and production readiness. Reserved names or existing
runtime primitives do not authorize any of those families.
