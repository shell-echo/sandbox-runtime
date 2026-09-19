# Product v1 Phase 5: Desktop Development and Unified Product

Status: 5/15 complete

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
| 3 | Provider Desktop domain, application policy, persistence, reconciliation, and protected handlers with capability still unadvertised | State/fence/replay/deadline/cancellation matrices; restart at every commit/effect boundary; exact-owned cleanup; unknown-outcome reconciliation; safe-error and nondisclosure tests | **Complete: Provider-local component authority only; no runtime or advertisement** |
| 4 | Reproducible immutable Desktop runtime image plus display/session broker protocol and provenance | Locked inputs and outputs; architecture matrix; unprivileged process/device policy; broker protocol bounds; native smoke; independent provenance verification; no mutable tag selection | **Complete:** native amd64/arm64/v8 run `35447651328` published signed index `sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`; independent verification passed |
| 5 | Provider Desktop runtime adapter, private resolver, lifecycle, usage, revocation, and cleanup composition | Real runtime open/attach/reconnect/close/expiry; generation fencing; no private-coordinate projection; revoke-before-cleanup; absence confirmation; duration evidence; fault injection | **Complete: Provider-local runtime/component authority only; production composition and advertisement remain off** |
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

## Slice 3 exact boundary

Implementation revision `f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5`
adds the separate `provider/desktop` domain and application boundary:

- open and close operations have independent durable identities, replay keys,
  fences, deadlines, states, and exact source-operation linkage;
- sandbox revision/generation/profile/network/lease authority is checked before
  mutation, while higher valid close fences can advance authority;
- accepted/running state is committed before an external effect, immutable
  allocation evidence is committed before handoff publication, and restart
  from every commit/effect boundary either resumes a safe commit or observes
  the exact allocation without blindly redispatching it;
- close and expiry durably revoke the source handoff, revoke private handoff
  authority, clean only the retained allocation receipt, and confirm absence;
  outcome-unknown reconciliation observes revocation/allocation state only;
- memory and exclusive-lock atomic-file repositories preserve the same
  idempotency, transition, fencing, snapshot, corruption, and restart rules;
  retained operation reads survive handoff expiry; and
- the protected transport optionally exposes the locked Desktop open, close,
  operation, and handoff routes with strict bounded decoding, existing
  admission, correlation checks, safe errors, and opaque output only.

The operation aggregator recognizes both Desktop operation families. The
Desktop lifecycle profile accepts only restricted networking with an explicit
egress policy. No runtime implementation is supplied by Slice 3; allocation,
handoff registration/revocation, and observation remain narrow injected ports.

### Slice 3 evidence boundary

Slice 3 is Provider-local component and protected-handler evidence. The
production command does not inject the Desktop application, discovery remains
unchanged, and no Desktop runtime image, broker, adapter, private resolver,
usage collector, Product dispatcher, public display/control Gateway, Web UI,
independent-process run, deployment, HA, hostile-multitenant, or production
claim follows. Twelve slices remain, beginning with the immutable Desktop
runtime image and broker protocol in Slice 4.

## Slice 4 publication boundary

Implementation revision `163dd8a258a24cf4727169b1cbd8ed7c0fe29292`
adds the repository-owned Desktop image manifest/build, fixed display/session
broker, tagged native image smoke, and manual-only publication workflow. The
manifest locks the Alpine 3.23 index, both architecture manifests, exact
package versions, per-architecture recursive APK archive sets, installed
package set, broker protocol, fixed display shape, runtime mounts, non-root
identity, process/device policy, and local reproducibility outputs.

The broker owns a fixed Xvfb/Openbox session and exposes only bounded strict
`probe` and `describe` operations on a `0600` Unix socket. It returns an opaque
display reference and fixed profile metadata, not an X11 coordinate, PID,
port, backend ID, host path, credential, or diagnostic. It has no arbitrary
process, stop, input-execution, media, signaling, authorization, clipboard, or
transfer method.

The native linux/arm64/v8 smoke passes two-build identity, non-root and
read-only execution, dropped capabilities, `no-new-privileges`, private IPC,
no devices, finite resources, broker/display observation, nonempty X root
capture, fixed process tree, policy inspection, and cleanup. The amd64
candidate output was reproduced by cross-build only and is not relabeled as a
native amd64 smoke.

The checked-in workflow ran from `main` source
`e4a940bda6c5172a78d0dbe40963ca1a99911976` as run `35447651328`. Separate
native amd64 and arm64/v8 hosted runners passed the image gate and published
platform manifests `sha256:ae1b71855f879066caf73f1056039d52b796d936a19f4b34a58a5565dd89609b`
and `sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505`.
The immutable index is
`sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`.
GitHub OIDC/Sigstore attestation `48643717`, registry attestation object
`sha256:2abf3a1c0304bac70f3118d4b16c193cc1cf2abaa83c144efdd15a365998faf8`,
and Rekor entry `2892645362` bind the repository, signer workflow, source,
`main` ref, and GitHub-hosted runner.

### Slice 4 evidence boundary

Slice 4 is complete within its immutable image/provenance boundary. The fresh
independent job verified the attestation constraints and exact two-platform
matrix; a constrained development-host verification returned the same signed
identity. `profiles/desktop/image/publication.go` is the fail-closed repository
authority that Slice 5 may select. The production command still must not
compose Desktop and capability advertisement remains empty until later gates.
The local candidate and accepted publication records are in
[`../audits/product-phase-5-desktop-slice-4-candidate.md`](../audits/product-phase-5-desktop-slice-4-candidate.md)
and
[`../audits/product-phase-5-desktop-slice-4-publication.md`](../audits/product-phase-5-desktop-slice-4-publication.md).

## Slice 5 runtime-composition boundary

Implementation revision `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b`
adds the fail-closed Docker adapter, durable opaque private-reference registry,
fresh attach/reconnect resolution, Desktop lifecycle readiness, exact duration
usage, provenance verification, revocation, and cleanup composition.

The Docker adapter selects only the accepted Slice 4 publication and requires
an injected restricted-network authority. Its private state binds the exact
allocation, receipt, image, resource policy, controller namespace, network
lease, backend ownership labels, and fixed connection generation. Recovery
observes retained state and owned runtime resources instead of blindly
redispatching. Every attach revalidates durable reference/source/generation
authority and executes a fresh bounded broker description. The result exposes
only fixed profile/display metadata and no container, network, socket, path,
credential, or signaling coordinate.

Close and expiry use the durable reference registry as the real application
revoker. Successful completion requires reference revocation, exact receipt
cleanup, and an absent/expired runtime observation in that order. Desktop usage
starts after successful handoff commit and stops at the earliest durable
revocation, endpoint/sandbox termination, or expiry.

### Slice 5 evidence boundary

Focused and full race/shuffle, vet, lock/evidence regressions, native arm64/v8
real-image broker attach/reconnect/removal, restart, generation, drift,
corruption, cancellation, unknown-outcome, revoke/cleanup/absence, and duration
tests pass. The real transport test deliberately does not claim a deployed
restricted-egress gateway; later composed security and independent-process
gates retain that responsibility. The exact evidence and non-claims are in
[`../audits/product-phase-5-desktop-slice-5.md`](../audits/product-phase-5-desktop-slice-5.md).

The production command still does not compose Desktop, discovery remains
unchanged, and no Product dispatcher, public data plane, grant/policy,
recording, unified Web, deployment, or production claim follows.

## Deferred beyond Phase 5

Multi-user collaboration, simultaneous controllers, controller queues,
presence, shared cursors, HA, hostile multi-tenant qualification, production
deployment, and production release operations are Phase 6 or later work. They
must not be inferred from the Phase 5 single-controller release gate.
