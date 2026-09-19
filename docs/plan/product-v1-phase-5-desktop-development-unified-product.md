# Product v1 Phase 5: Desktop Development and Unified Product

Status: 14/15 complete

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
| 6 | Product network-only Provider adapter with exact readiness, Desktop dispatch/observation, close, and cleanup | Locked discovery/profile selection; protected requests; timeout/cancellation/replay/drift; retained operation recovery; Product/Provider generation separation; real store integration | **Complete: Product network adapter and real-store component authority only; production composition and advertisement remain off** |
| 7 | Product view/control grants, one-controller fencing, quotas, revocation, and metadata audit | Viewer mutation denial; one live controller; database-time expiry; one-use grants; stale-fence and quota races; continuous authority checks; nondisclosing failures | **Complete: Product connection authority and real-store component evidence only; no public data plane** |
| 8 | Public Desktop display/audio/signaling/input plane with bounded negotiation and backpressure | Authenticated encrypted signaling; exact origin; supported codec/resolution/bitrate matrix; viewer/control separation; ordered input; slow-consumer closure; no private handoff disclosure | **Complete: same-process public-handler and real-WebRTC component evidence only; policy and production composition remain off** |
| 9 | Keyboard, pointer, touch, clipboard, and Product-bound transfer policy | Deny-by-default matrix; activation/consent; size/type/count/digest/path bounds; exact transfer identity; policy-revision revocation; microphone/camera/device denial | **Complete: durable Product policy and real-store component evidence only; recovery and production composition remain off** |
| 10 | Recovery, reconnect, resynchronization, resolution/audio-device changes, and session/slot replacement | Fresh-grant reconnect; authority and generation recheck; visual/audio resync bounds; no stale input; restart recovery; deterministic replacement and exact cleanup | **Complete: Product Gateway/repository recovery and replacement component evidence only; no real Provider media bridge or production composition** |
| 11 | Desktop recording/replay/catalog/retention/quota/integrity composition | Visible consent/mode; required-recorder fail closed; encrypted integrity-linked media/control segments; authorized replay; retention/deletion and quota races; content excluded from logs | **Complete: Product recording/Gateway/PostgreSQL component evidence only; no real Provider media bridge or production composition** |
| 12 | Development-environment templates, startup, toolchains, workspace materialization, and Guest health | Immutable template selection; bounded startup; exact workspace mounts; health/liveness/readiness; failure rollback; restart persistence; no host-path or credential disclosure | **Complete: Product/Guest protocol, local content-store, and real-PostgreSQL component evidence only; no unified Web or production composition** |
| 13 | Unified Product Web shell integrating Workspace, Terminal, Files, Browser, Desktop, and recordings | Generated checked client; authenticated end-to-end flows; capability-derived navigation; origin/request-forgery/content policy; accessibility; recovery/error UX; no private coordinates | **Complete: authenticated Web/BFF and real-headless-browser component evidence only; production Desktop advertisement remains off** |
| 14 | Exact cleanup, quota, fault, security, and regression gates for the composed Desktop product | Cross-layer fault matrix; restart and dependency loss; stale/replay/tenant attacks; capacity recovery; row/object/process/runtime cleanup; retained Phase 3/4 regressions | **Complete: private Provider/Gateway bridge and same-process real-store composition evidence; independent-process release gate remains** |
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

## Slice 6 Product Provider-adapter boundary

Implementation revision `2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240`
adds the Product-owned network-only Desktop Provider client, isolated Desktop
slot/lifecycle/session/observation workers, PostgreSQL migration 9, retained
attempt recovery, and Desktop-specific close cleanup.

The client accepts only the current Desktop Contract revision/tree, one exact
signed-image runtime profile, bounded resources and request timeout, and an
explicit restricted-network policy. Each authorization or dispatch rechecks
the exact Desktop discovery entry, runtime class, isolation, selected
architecture, and Provider limits. All mutations and retained reads use the
protected Provider HTTP surface with exact Contract identities, correlation,
fencing, deterministic digest/idempotency, bounded strict decoding, and
outcome-unknown preservation.

Product slot generation is the Product fence; the separately stored Provider
generation is the Provider expected generation. Dedicated leases prevent the
generic, Terminal, or Browser workers from consuming Desktop work. Successful
Desktop close clears only the Product handoff and terminalizes the Desktop
session while keeping its current slot binding; Browser's terminate-and-
replace policy is not reused.

### Slice 6 evidence boundary

Focused tests cover lock/profile/readiness drift, timeout, cancellation,
replay, protected requests, ambiguity, retry, generation separation, and
worker isolation. The real PostgreSQL gate runs create, reconstructed
observation, open, opaque handoff recovery, reconstructed close, and exact
session cleanup through the network adapter while retaining the slot. Full
race/shuffle, vet, Contract/evidence verifiers, and existing Docker lifecycle
integration pass. Exact evidence and non-claims are in
[`../audits/product-phase-5-desktop-slice-6.md`](../audits/product-phase-5-desktop-slice-6.md).

This remains same-repository component evidence. Production startup,
end-user grants, public signaling/media/input, policy, recording, development
templates, unified Web, capability advertisement, independent-process release
evidence, deployment, HA, hostile-multitenant, and production readiness remain
open.

## Slice 7 Product connection-authority boundary

Implementation revision `0649d62911abb89229de40136347286736152ec6`
extends the existing Product grant and control-lease authority only for an
exact ready `desktop` / `product-desktop.v1` session. A viewer grant carries no
control lease or fence. A controller grant requires the current actor-bound,
session-scoped lease and monotonic fence, and at most one live controller grant
may exist for a session.

Tickets remain public Product tickets: random, at most 60 seconds, encrypted
at rest for exact idempotent replay, and one-use on consume. The internal
Gateway binding includes the opaque Provider handoff only after consumption;
the public grant response and metadata audit do not. Database time bounds the
grant by session, handoff, and control-lease expiry. Continuous checks match
the complete actor, Workspace, slot generation, session, profile, Provider
binding, handoff generation, access mode, lease, fence, and recording-policy
tuple.

PostgreSQL migration 10 adds independent Desktop viewer and controller tenant
quotas and the live-grant admission index. A tenant advisory lock closes quota
races. The existing partial unique controller index is renamed to its actual
session-wide scope and continues to protect Terminal and Browser behavior
without changing their grant semantics.

### Slice 7 evidence boundary

Focused API tests prove viewer control denial. The real PostgreSQL gate proves
encrypted retained replay, one-use consumption, cross-owner nondisclosure,
one-controller fencing, release and database-time expiry revocation, complete
binding tamper rejection, concurrent viewer/controller quota admission, safe
metadata audit, and migration replay while retaining Terminal and Browser
regressions. Full race/shuffle, vet, Contract verifiers, and retained Phase 3/4
evidence verification pass. Exact evidence and non-claims are in
[`../audits/product-phase-5-desktop-slice-7.md`](../audits/product-phase-5-desktop-slice-7.md).

At the Slice 7 boundary there was still no public Desktop signaling, media,
audio, or input plane. Production startup composition, policy, recovery,
recording, development templates, unified Web, advertisement, deployment, and
production readiness remained later gates.

## Slice 8 public Desktop data-plane boundary

Implementation revision `040c560f3701b7c972c25f05928dd435d9f55c20`
adds a separate Product Desktop WebRTC handler behind the exact Slice 7 grant
binding. Signaling is bounded closed JSON over HTTPS with an exact Origin and
one-use ticket. Production options require relay-only `turns:` ICE. Offers may
contain exactly one receive-only VP8 display and optional receive-only Opus
audio section; upstream camera or microphone media is rejected.

The selected matrix bounds resolution, frame rate, video/audio bitrate, RTP
packet size, signaling size, peer count, per-session count, and video/audio/
input/control queues. Viewers cannot negotiate control. Controllers require
the current lease/fence and exactly one reliable ordered data channel. Each
strictly sequenced keyboard, pointer, or touch message rechecks grant authority
and a required injected Product input-authority port before private execution.
Overflow, slow consumption, malformed input, authority loss, expiry, or a
second channel closes the peer.

The public response returns only the Product connection ID, access mode,
selected media matrix, and WebRTC answer. The Provider handoff is supplied
only to the injected private media source and is excluded from responses and
metadata audit. Required recording fails closed until Slice 11.

### Slice 8 evidence boundary

Real in-process WebRTC tests carry VP8, optional Opus, and fenced ordered input
for viewer/controller bindings. Focused ten-run race, full race/shuffle, vet,
Contract verifiers, and retained Phase 3/4 evidence verification pass. Exact
evidence and non-claims are in
[`../audits/product-phase-5-desktop-slice-8.md`](../audits/product-phase-5-desktop-slice-8.md).

This is same-process handler/component evidence. The durable Desktop policy,
real Provider media bridge, recovery, recording, development templates,
unified Web, production startup, advertisement, deployment, and production
readiness remain later gates.

## Slice 9 durable Desktop policy boundary

Implementation revision `24f5c741eb605614f77f8d9d546708b9993e42dd`
adds a separate immutable Product Desktop policy model and PostgreSQL migration
11. Workspace-owner updates are idempotent and expected-revision guarded;
every revision is retained so an old idempotency key returns its exact original
result after later updates. Missing or invalid policy fails closed.

The zero-permission matrix denies keyboard, pointer, touch, clipboard, upload,
and download. Explicit policy independently enables each input family and
bounds clipboard bytes, transfer file count, per-file and aggregate bytes,
canonical media types, SHA-256 digests, and UTF-8 `/workspace/...` paths.
Configured activation and consent are mandatory. Microphone, camera, and
device forwarding remain unconditionally denied.

The Desktop Gateway fixes one policy revision at connection admission, checks
that revision during continuous authority polling and before every input, and
closes the peer on change or read failure. Clipboard results are UTF-8 and
size bounded. Each transfer descriptor must also match an existing complete
Product transfer for the exact tenant, actor, Workspace, transfer ID,
direction, digest, and byte count; object references never reach the Gateway.

### Slice 9 evidence boundary

Focused ten-run Desktop race tests, full race/shuffle, vet, Contract and
retained-evidence verifiers, migration replay, concurrent update, historical
idempotency replay, cross-owner nondisclosure, audit minimization, and
reconstructed-Store reads pass. Exact evidence and non-claims are in
[`../audits/product-phase-5-desktop-slice-9.md`](../audits/product-phase-5-desktop-slice-9.md).

This is Product policy, PostgreSQL, and same-process Gateway component
evidence. A real Provider media/input bridge, reconnect/resynchronization,
restart recovery, recording, development templates, unified Web, production
startup, advertisement, deployment, and production readiness remain later
gates.

## Slice 10 recovery and replacement boundary

Implementation revision `f23b16130c97e99d5d28008b01346779a0c681ee`
adds Product-owned reconnect and replacement behavior without treating an old
WebRTC transport as a reusable authority:

- every reconnect consumes a new encrypted one-use grant and rebinds the exact
  tenant, actor, Workspace, slot/session generation, Provider revision,
  sandbox, opaque handoff, connection generation, access mode, lease, and
  fence;
- PostgreSQL migration 12 gives consumed Desktop grants a five-second
  database-time Gateway lease. Continuous authority checks renew only an exact
  current binding; a crashed Gateway's expired lease is revoked before quota
  or one-controller admission, allowing bounded restart recovery;
- each initial connection and in-grace transport recovery requests a complete
  media-source resynchronization plus a keyframe. Ordered `stream.resync` and
  `stream.configure` controls share a fail-closed rate bound;
- stream changes retain fixed negotiated VP8/optional-Opus codecs and bitrate
  ceilings while bounding resolution/frame rate and exposing only the closed
  audio-output aliases `default` and `disabled`;
- every queued control carries its connection epoch, and input payloads are
  decoded again against the current display dimensions before private
  execution, so pre-disconnect or pre-resize input cannot execute later; and
- successful slot termination/replacement revokes all live grants, clears
  opaque handoff authority, closes affected sessions, retires the old Provider
  binding, and creates exactly one next-generation provision intent in the
  same transaction. Explicit Desktop session close also revokes all grants.

### Slice 10 evidence boundary

Focused ten-run race tests cover WebRTC reconnect timers, resynchronization,
closed configuration, current-dimension input validation, and rate bounds. A
fresh disposable PostgreSQL 16 gate covers migration replay, crashed-Gateway
lease reclamation, fresh-grant reconnect, generation substitution denial,
restart from a reconstructed repository, deterministic replacement, and exact
grant/handoff/session/binding cleanup. Exact evidence and non-claims are in
[`../audits/product-phase-5-desktop-slice-10.md`](../audits/product-phase-5-desktop-slice-10.md).

This is Product Gateway and PostgreSQL component evidence. The media/input
source remains injected; no real Provider bridge, recording, development
template, unified Web, production startup, capability advertisement,
deployment, HA, hostile-multitenant, or production-readiness claim follows.

## Slice 11 Desktop recording boundary

Implementation revision `c5b045abc5192b76b7d615ddbb0858b998ef98d5`
composes the existing Product recording authority into the Desktop Gateway
without changing the Provider Contract or reusing metadata audit as content
recording:

- required mode admits only an explicit bounded consent reference, reports the
  exact selected mode in signaling, initializes recording before opening the
  private media source, and fails closed on initialization or live recorder
  loss;
- the Desktop recorder writes bounded VP8 and optional Opus RTP plus ordered,
  minimized input, stream-configuration, and resynchronization events. It
  preserves monotonic event time under concurrent audio/video/control calls;
- immutable encrypted segments use the existing sequence and previous-digest
  chain, tenant active/byte quotas, owner-authorized catalog/replay, replay
  integrity validation, and retention expiry/deletion;
- control recording retains only closed action kind/event/touch count and
  public display/audio aliases. Clipboard content, transfer paths, transfer
  identities, digests, private Provider coordinates, and result text are not
  recorded as control metadata or written to ordinary audit; and
- PostgreSQL recording admission now accepts `media` only for Browser Live or
  Desktop sessions and continues to reject unknown recording types.

### Slice 11 evidence boundary

Focused Gateway race tests cover consent/mode visibility, pre-media fail-closed
admission, live-recorder loss, and the retained real-WebRTC transport matrix. A
fresh disposable PostgreSQL 16 gate covers concurrent one-winner quota
admission, encrypted at-rest Desktop segments, digest linkage and tamper
rejection, owner-only replay, public catalog/audit content exclusion, expiry,
row deletion, and exact encrypted-object cleanup. The complete tagged Product
PostgreSQL package, ten shuffled Gateway race repetitions, full repository
race/shuffle, vet, Contract verifiers, and retained Phase 3/4 evidence
verification pass. Exact evidence and non-claims are in
[`../audits/product-phase-5-desktop-slice-11.md`](../audits/product-phase-5-desktop-slice-11.md).

This is Product recording service, local encrypted-store, PostgreSQL, and
same-process Gateway component evidence. The Desktop media/input source remains
injected; no real Provider bridge, development template/toolchain/Guest health,
unified Web, production startup, capability advertisement, independent-process
release evidence, deployment, HA, hostile-multitenant, or production-readiness
claim follows.

## Slice 12 development-environment boundary

Implementation revision `490c2db96d6ba7a851d7846bc9e5f818dae2be77`
adds the Product development startup authority and the Guest workspace
materialization protocol without changing the Provider Contract:

- `coding-shell-base-v1` selects only the immutable repository publication,
  exact runtime profile, ordered `/inputs`, `/workspace`, `/outputs`, and
  `/tmp` mounts, and digest-bound toolchain metadata;
- migration 13 persists validated revision manifests and development attempts
  bound to the current primary code slot and exact connected Guest generation;
- Product streams private content-addressed objects in bounded chunks and
  requires exact file sizes/digests, Guest authority, template/workspace
  revisions, mounts, toolchains, and health before committing readiness;
- Guest rejects unsafe paths, links, manifest/size/offset/digest drift, and uses
  a private two-phase transaction journal so Product persistence failure rolls
  back the visible workspace while restart deterministically recovers; and
- public health and audit/event projections exclude host paths, credentials,
  object paths, raw endpoints, Guest identity, and runtime coordinates.

### Slice 12 evidence boundary

Focused race/shuffle and vet, exact Guest protocol and rollback/restart cases,
the complete tagged Product PostgreSQL package against fresh PostgreSQL 16,
and the clean E2E parent-lock regression pass. Exact evidence and non-claims
are in
[`../audits/product-phase-5-desktop-slice-12.md`](../audits/product-phase-5-desktop-slice-12.md).

This is Product/Guest protocol, local content-store, and real-PostgreSQL
component evidence. No real Provider Desktop media bridge, unified Web,
production startup, capability advertisement, independent-process release
evidence, deployment, HA, hostile-multitenant, or production-readiness claim
follows.

## Slice 13 unified Product Web boundary

Implementation revision `84698c371d35edb862ffc81b484a3e31cc8120d9`
extends the authenticated Product Web/BFF without adding consumer-specific
Provider behavior or exposing private runtime coordinates:

- the generated checked client reads and strictly selects exact ready Product
  capabilities before enabling Workspace, Terminal, Files, Browser, Desktop,
  or recording navigation;
- the Desktop experience composes the public slot/session DTOs, fresh view or
  controller grants, same-origin HTTPS WebRTC signaling, ordered fenced input,
  controller state, recording consent/mode, bounded reconnect, stream
  resynchronization/configuration, clipboard consent, and Product-bound
  transfer flows;
- the neutral shared transfer route retains authenticated session,
  Origin/CSRF, size/digest, and nondisclosure controls while preserving the
  previous Browser route; and
- labeled controls, ARIA tab keyboard navigation, live status/recovery state,
  reduced-motion behavior, strict no-inline CSP, and browser-storage exclusion
  retain the Web security and accessibility boundary.

### Slice 13 evidence boundary

The generated-client lock, focused and full race/shuffle, vet, real headless
Chrome authentication/capability navigation, Product and Provider Contract
verification, and retained Phase 3/4 evidence verification pass. Exact
evidence and non-claims are in
[`../audits/product-phase-5-desktop-slice-13.md`](../audits/product-phase-5-desktop-slice-13.md).

This is Product Web/BFF and real-headless-browser component evidence. Desktop
advertisement remains off until the real Provider media/input bridge and exact
production startup graph are composed and pass the later gates. No Slice 14
composed fault/security result, independent-process release evidence,
deployment, HA, hostile-multitenant qualification, or production-readiness
claim follows.

## Slice 14 composed fault/security boundary

Implementation revision `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d`
adds a separate private Provider-to-Product-Gateway Desktop bridge without
moving Product authority into Provider packages or importing Provider
authority into Product packages:

- the closed repository-private protocol binds every connection to the exact
  opaque handoff, sandbox, Desktop session, capability profile, connection
  generation, handoff expiry, and negotiated VP8/optional-Opus bounds;
- the Provider handler requires an explicit trusted-peer authorizer outside
  tests, freshly resolves and attaches the durable handoff before opening
  media, continuously re-resolves it, bounds sessions and RTP/control traffic,
  and closes on revocation, dependency failure, malformed input, timeout, or
  backpressure;
- the Product network source carries the already-consumed binding only over
  the private WebSocket and maps the closed keyboard/pointer/touch/clipboard/
  Product-transfer protocol without projecting the handoff publicly; and
- the real-PostgreSQL composition gate joins grants, policy, public WebRTC,
  the private bridge, ordered fenced input, required encrypted recording,
  continuous policy revocation, ticket replay denial, cross-origin and
  cross-owner denial, retention object deletion, and exact tenant-row cleanup.

Focused bridge races also prove sandbox/generation substitution denial,
continuous Provider handoff revocation, private-session capacity exhaustion
and recovery, typed-nil/dependency fail-closed construction, and closed input
shapes. The complete tagged Product PostgreSQL package retains quota,
reconciliation/restart, replacement, recording, and development cleanup
coverage; full race/shuffle, vet, both Contract verifiers, and retained Phase
3/4 evidence verifiers pass. Exact commands and non-claims are recorded in
[`../audits/product-phase-5-desktop-slice-14.md`](../audits/product-phase-5-desktop-slice-14.md).

### Slice 14 evidence boundary

This is same-repository bridge, same-process Product/Gateway/Provider
composition, and real-store evidence. The Provider media executor used by the
composition gate is a bounded reference implementation; the independent
Desktop and Guest roles, real display/control development scenario, complete
restart/fault matrix, strict evidence bundle, exact release-topology
advertisement, deployment, HA, hostile-multitenant qualification, and
production-readiness claims remain Slice 15 or later. Desktop advertisement
therefore remains off.

## Deferred beyond Phase 5

Multi-user collaboration, simultaneous controllers, controller queues,
presence, shared cursors, HA, hostile multi-tenant qualification, production
deployment, and production release operations are Phase 6 or later work. They
must not be inferred from the Phase 5 single-controller release gate.
