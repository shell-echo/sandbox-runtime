# P2.0 Coding and Remote-Shell Authority Inventory

Status: P2.0a authority inventory passed in PR #29 merge `83965a2` and
post-merge CI `32440383198`. P2.0b/c bounded exec resources, lock, and
projection gate passed in PR #30 merge `9d00212`; post-merge CI
`32444266288` passed. P2.1 local domain/application-port work passed in PR #31
merge `67b64a9`; post-merge CI `32445893337` passed. P2.2a result and
cancellation-intent domain passed in PR #33 merge `ba39053`; post-merge CI
`32454054853` passed. P2.2b persistence passed in PR #35 merge `c467cd4`;
PR CI `32456100570` and post-merge CI `32456279722` passed.
P2.2c reservation/attach and bounded coordinator passed in PR #39 merge
`17072e6`; PR CI `32460695928` and post-merge CI `32460914417` passed.
P2.3a/b terminal-session resources, lock, and projection merged in PR #43 as
`21f5236`; PR CI `32468912019` and post-merge CI `32469390678` passed. P2.3c0
corrected resources `71fee34` and projection/lock `ab9defc` reconcile the
capability prerequisite. PR #44 head `16136d2` passed exact-head CI
`32685685846`, merged as `6c1fc90`, and passed post-merge CI `32686754674`.
P2.3c1 has provider-only domain and transactional authority-port evidence. PR
#45 merged it as `4c37d8c`; PR CI `32696507856` and post-merge CI `32696727371`
passed all three jobs. P2.3c2 adds independent durable session authority
adapters on `main@e5c9dec`. Post-push CI #103 / run `32698606341` passed all
three jobs; Node.js 20 deprecation warnings remain. P2.3c3 implementation
commit `186190b` and post-push CI run `32799871307` passed all three jobs.
ADR 0009 records the ownership boundary and ADR 0010 records the bounded exec
Contract decision.

## Authority stop condition

The current repository-owned Contract contains terminal-only session routes and
a strict zero-or-terminal-only capability mapping. The default remains zero
advertisement; a terminal advertisement must associate its version and profile
with an explicit runtime profile. The protected routes are opt-in: the
transport accepts an independently composed session application, while the
command composition root still creates none by default. This slice adds no
Gateway, allocator, runtime driver, or WebSocket data plane. The architecture
narrative is not sufficient authority to implement behavior beyond the locked
resources and this delivery order.

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
- P2.3a/b: terminal session Contract authority, lock, DTO/admission projection,
  and Suite gate (merged in PR #43);
- P2.3c0: reconcile terminal capability/profile advertisement in the Contract,
  fixture, semantic rules, Suite, projection, and lock (passed in PR #44 merge
  `6c1fc90`; exact-head and post-merge CI passed);
- P2.3c1: provider-local terminal session domain and transactional authority
  port, without transport, allocator, driver, or Gateway;
- P2.3c2: durable session ledger and atomic sandbox ready/generation/lease/
  fencing authority check (memory/file adapters, idempotency replay, expiry,
  restart, and compare-and-set evidence; no transport or dispatch);
- P2.3c3: protected transport projection and opaque handoff retrieval (passed
  for bounded Provider transport evidence in `186190b`; CI run `32799871307`);
- P2.3c4: separately owned Runtime Gateway integration evidence;
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
result-expiry tombstones, and restart recovery. Its local implementation,
verification, and merge evidence are complete. It must not reuse
the lifecycle repository or dispatch an executor during recovery. P2.2c may add
bounded coordination and an optional cancellation port, but continues to
exclude Provider HTTP composition and Docker/backend adapters. The current
repository port records an already-produced opaque dispatch receipt; it is not
a durable pre-dispatch accept. P2.2c must not start an executor before that
acceptance is durable and must introduce an explicit reservation/attach design.

P2.2c implements the reservation/attach ordering and optional Canceler boundary
without HTTP, Docker/backend selection, or lifecycle repository reuse. It keeps
known non-context dispatch errors as durable pending state, maps context/receipt
uncertainty to no-redispatch recovery, and treats cancellation replay as query-
only until a separately observed confirmation exists.

P2.2c is closed as provider-local coordination evidence only. P2.3c0 has locally
reconciled and re-locked the zero-or-terminal-only advertisement rule, with full
race/shuffle, vet, lock, 26-case Suite, JSON, and diff evidence. The canonical
terminal advertisement is version `1.0.0`, capability profile `terminal-v1`,
and runtime profile `sandbox-runtime-terminal-v1`. PR #44's prior-head CI passed
but was superseded. Exact-head CI `32685685846`, merge `6c1fc90`, and post-merge
CI `32686754674` then passed, closing P2.3c0 as Contract/projection evidence.
P2.3c1 locally defines only the provider-local terminal session request and
record state, successful-only opaque WebSocket handoff derivation, and the
transactional authority port that P2.3c2 must implement. Focused/full
race-shuffle, vet, unchanged Contract lock, 26-case Suite, JSON, dependency,
and diff checks passed. PR #45 and its post-merge CI close P2.3c1 as
provider-local domain/authority evidence only. P2.3c2 adds independent memory
and file persistence with restart, expiry, idempotency, CAS generation/fencing,
and same-transaction authority rechecks. Direct-main commit `e5c9dec` and
post-push CI #103 / run `32698606341` passed. P2.3c3 now provides an
independently composed terminal-session application boundary and protected
transport projection for the two locked session routes. It strictly binds body
and descriptor admission context, returns the accepted operation projection,
and returns only successful, unexpired opaque handoff data. Error mapping
covers pending, expired, missing, unsupported, conflict, and unknown-outcome
states; endpoint non-disclosure and reserved-route regression tests are
included. The command composition root still leaves this application nil, so
no allocator, runtime driver, WebSocket data plane, or Gateway is started.
P2.3c3 is closed for bounded Provider transport evidence by implementation
commit `186190b` and post-push CI `32799871307`; P2.3c4 is the next
implementation entry.
