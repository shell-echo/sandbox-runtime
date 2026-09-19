# Product v1 Phase 5: Desktop Development and Unified Product

Status: 2/15 complete

Started: 2026-09-19

Baseline: `e3c839fbb6a040a2b31a36ec05212924a69237fe`

## Objective

Deliver a bounded Product Desktop development environment and a unified
Product experience without weakening the Provider boundary: a locked Desktop
Contract, durable Provider and Product authorities, immutable runtime and
broker, opaque private handoff, authenticated public display/control, explicit
input and transfer policy, recovery, recording/catalog, development templates,
and one Web shell across Workspace, Terminal, Files, Browser, Desktop, and
recordings.

Capability advertisement remains unavailable until the complete dependency
graph and Slice 15 gate pass for an exact topology. Historical Terminal and
Browser evidence remains valid only for its recorded identities and cannot be
relabeled as Desktop evidence.

## Fixed slice order

| Slice | Deliverable | Required acceptance gate | Status |
| --- | --- | --- | --- |
| 1 | Startup audit; ADR 0050; separate Provider Desktop capability/profile/runtime authority; Desktop open/read/handoff/close/expiry/revocation and usage semantics; OpenAPI/schemas/rules/fixtures/manifest/Suite; Go DTO, strict decode, admission, projection, and executable case mappings | Exact immutable Contract revision/tree and derived lock; all 71 Suite cases mapped to tests; focused/full race-shuffle, vet, both Contract verifiers, clean-VCS local Conformance, retained Phase 3/4 evidence regressions, structured-data parse, diff, and status checks | **Complete: Contract/projection authority only; advertisement remains off** |
| 2 | Product Desktop slot/session authority and relational-store state/outbox isolation | Strict authenticated API; exact immutable Desktop kind/profile; expected-version/idempotency/quota races; absorbing states; atomic operation/event/audit/outbox; cross-tenant nondisclosure; migration replay and restart-safe reads | **Complete: Product intent authority only; dispatch and advertisement remain off** |
| 3 | Provider Desktop domain, application policy, persistence, reconciliation, and protected handlers with capability still unadvertised | State/fence/replay/deadline/cancellation matrices; restart at every commit/effect boundary; exact-owned cleanup; unknown-outcome reconciliation; safe-error and nondisclosure tests | Planned |
| 4 | Reproducible immutable Desktop runtime image plus display/session broker protocol and provenance | Locked inputs and outputs; architecture matrix; unprivileged process/device policy; broker protocol bounds; native smoke; independent provenance verification; no mutable tag selection | Planned |
| 5 | Provider Desktop runtime adapter, private resolver, lifecycle, usage, revocation, and cleanup composition | Real runtime open/attach/reconnect/close/expiry; generation fencing; no private-coordinate projection; revoke-before-cleanup; absence confirmation; duration evidence; fault injection | Planned |
| 6 | Product network-only Provider adapter with exact readiness, Desktop dispatch/observation, close, and cleanup | Locked discovery/profile selection; protected requests; timeout/cancellation/replay/drift; retained operation recovery; Product/Provider generation separation; real store integration | Planned |
| 7 | Product view/control grants, one-controller fencing, quotas, revocation, and metadata audit | Viewer mutation denial; one live controller; database-time expiry; one-use grants; stale-fence and quota races; continuous authority checks; nondisclosing failures | Planned |
| 8 | Public Desktop display/audio/signaling/input plane with bounded negotiation and backpressure | Authenticated encrypted signaling; exact origin; supported codec/resolution/bitrate matrix; viewer/control separation; ordered input; slow-consumer closure; no private handoff disclosure | Planned |
| 9 | Keyboard, pointer, touch, clipboard, and Product-bound transfer policy | Deny-by-default matrix; activation/consent; size/type/count/digest/path bounds; exact transfer identity; policy-revision revocation; microphone/camera/device denial | Planned |
| 10 | Recovery, reconnect, resynchronization, resolution/audio-device changes, and session/slot replacement | Fresh-grant reconnect; authority and generation recheck; visual/audio resync bounds; no stale input; restart recovery; deterministic replacement and exact cleanup | Planned |
| 11 | Desktop recording/replay/catalog/retention/quota/integrity composition | Visible consent/mode; required-recorder fail closed; encrypted integrity-linked media/control segments; authorized replay; retention/deletion and quota races; content excluded from logs | Planned |
| 12 | Development-environment templates, startup, toolchains, workspace materialization, and Guest health | Immutable template selection; bounded startup; exact workspace mounts; health/liveness/readiness; failure rollback; restart persistence; no host-path or credential disclosure | Planned |
| 13 | Unified Product Web shell integrating Workspace, Terminal, Files, Browser, Desktop, and recordings | Generated checked client; authenticated end-to-end flows; capability-derived navigation; origin/request-forgery/content policy; accessibility; recovery/error UX; no private coordinates | Planned |
| 14 | Exact cleanup, quota, fault, security, and regression gates for the composed Desktop product | Cross-layer fault matrix; restart and dependency loss; stale/replay/tenant attacks; capacity recovery; row/object/process/runtime cleanup; retained Phase 3/4 regressions | Planned |
| 15 | Product Phase 5 independent-process release gate and reproducible evidence bundle | Fresh stores; separate Product/Gateway/Provider/Desktop/Guest roles as required; exact locked identities; real display/control and development scenarios; restart/fault/security/recording/cleanup matrix; strict independent validation | Planned |

Slices are dependency ordered. A visual demo, runtime image, or public route
cannot replace durable authority, exact Provider selection, policy, recovery,
cleanup, or the final release gate.

## Slice 1 exact boundary

The selected Provider Contract revision is
`720ad15c343e71f36615dc4499edd5e764178bca`, with Contract tree
`343ffde0819207cf99c005096c336735dd33a735`. It introduces the exact
`sandbox.desktop@1.0.0` / `desktop-v1` capability and
`sandbox-runtime-desktop-v1` runtime profile, separate open/close mutation
documents, retained Desktop operation and handoff reads, the
`sandbox.desktop_session_milliseconds` usage meter, and explicit security,
state-machine, cleanup, admission, error, and capacity semantics.

The derived repository lock selects:

- manifest digest
  `sha256:483111511a588b41bd40d3fef686f0b21f465bb65d3215450ebb2ccf37a5de89`;
- OpenAPI digest
  `sha256:5a3da5d239f83e94eff09fc75438755f834e77bce8cd1c0f91c25055bf0cba2a`;
- semantic-rules digest
  `sha256:7953d05e65f00c68e0428b6dd4fcebef1af103f2cab2fa6b214905b2496c8785`;
- 71-case local Suite digest
  `sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`;
  and
- unchanged six-case remote-discovery Suite digest
  `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0`.

Go projection adds closed DTOs and bounded strict decoding for Desktop open and
close, operation and usage enums, opaque handoff projection, exact admission
bindings, and capability/runtime-profile mapping. The projection code does not
enable startup advertisement, register a Desktop route, or compose an
application/runtime dependency.

The historical coding/shell qualification Profile retains its original
60-case Contract identity through a dedicated immutable-revision lock and a
historical verifier path. The normal Provider verifier still requires the
current checkout to match the current 71-case lock. This preserves old evidence
without weakening or relabeling current compatibility checks.

### Slice 1 evidence boundary

Slice 1 is complete only as Provider Contract and repository projection
evidence. No runtime image, driver, broker, private resolver, Guest Agent,
Product Desktop state, public data plane, Web UI, deployment, independently
implemented caller, multi-controller, hostile-multitenant, HA, or production
evidence follows. Product Phase 3 and Phase 4 evidence retains its original
Provider identities and is used only as a regression check.

## Slice 2 exact boundary

Implementation revision `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`
adds Product-owned Desktop intent authority without calling Provider or
advertising Desktop readiness:

- auxiliary Desktop slots accept only kind `desktop`, Product runtime profile
  `sandbox-runtime-desktop-v1`, and the single exact Provider requirement
  `sandbox.desktop@1.0.0` / `desktop-v1`;
- Product Desktop sessions accept only kind `desktop` and public protocol
  profile `product-desktop.v1`, require a current ready Desktop slot, and use
  the existing absorbing Product session state machine;
- PostgreSQL migration 8 locks both shapes, adds bounded per-tenant Desktop
  slot/session quotas and supporting indexes, and permits at most one live
  Desktop session for a slot;
- authenticated strict Product routes commit slot/session state, operation,
  contiguous event, security audit, idempotency result, and outbox intent in
  one transaction with expected-version checks;
- Desktop session work uses `desktop_session.open` and
  `desktop_session.close`; Terminal and Browser workers cannot lease it, and
  Browser slot workers reject Desktop `slot.reconcile` work by kind; and
- fresh-store reads and idempotent replay use only committed PostgreSQL state.

The real-adapter gate replays all eight migrations against fresh pinned
PostgreSQL and covers concurrent slot and session idempotency, expected-version
and quota races, exact database constraints, absorbing terminal states,
transactional row counts, cross-tenant/owner nondisclosure, worker isolation,
and reconstructed-Store reads. Focused tests, the complete tagged PostgreSQL
package with race/shuffle, the full repository race/shuffle gate, vet, both
Contract verifiers, and retained Phase 3/4 evidence verification pass.

### Slice 2 evidence boundary

Slice 2 creates durable Product intent only. No Desktop outbox consumer,
Provider Desktop application, runtime image, broker, adapter, handoff
resolution, public Gateway, connection grant, input policy, recording, Web UI,
capability advertisement, independent-process run, deployment, HA,
hostile-multitenant, or production evidence follows.

## Deferred beyond Phase 5

Multi-user collaboration, simultaneous controllers, controller queues,
presence, shared cursors, HA, hostile multi-tenant qualification, production
deployment, and production release operations are Phase 6 or later work. They
must not be inferred from the Phase 5 single-controller release gate.
