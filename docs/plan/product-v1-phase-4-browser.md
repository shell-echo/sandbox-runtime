# Product v1 Phase 4: Browser

Status: Complete at 13/13 for the bounded same-repository separate-process scope

Started: 2026-09-18

Baseline: `e9bdc77478f4df15b53f6b7e3fa3fbdda9d76d4f`

## Objective

Deliver the Product Browser capability defined by ADRs 0042-0047 and 0049:
durable Browser slot/session authority, exact Provider adaptation, automation
and remote visual control data planes, one-controller fencing, safe recovery,
policy-bounded content transfer and permissions, recording/catalog
composition, Web experience, cleanup, and an independent-process release gate.

The historical Provider "P4 Browser" track is an input, not completion
evidence for this phase. Product capability advertisement remains unavailable
until Slice 13 passes for the exact composed topology.

## Fixed slice order

| Slice | Deliverable | Required acceptance gate | Status |
| --- | --- | --- | --- |
| 1 | Startup audit; Product Browser session kind/profile authority; ready-browser-slot binding; absorbing state machine; Browser-specific outbox isolation; PostgreSQL migration constraint; strict authenticated API projection | Focused race tests; strict input/profile rejection; tenant/actor nondisclosure; idempotency; migration replay; real PostgreSQL transaction/outbox isolation; full race/shuffle, vet, and Contract verifiers | **Implemented; local and real-PostgreSQL gates passed** |
| 2 | Auxiliary Browser slot create/read/update authority and reconciliation intent | Expected-version/idempotency/quota races; immutable key/kind; exact capability request; event/outbox atomicity; cross-tenant nondisclosure; restart-safe reads | **Implemented; local and real-PostgreSQL gates passed** |
| 3 | Exact-revision Provider Browser readiness and network-only adapter for Browser sandbox plus session open/handoff observation | Locked capability/profile selection; mTLS/JWS; no private coordinate projection; timeout, cancellation, replay, stale generation, ambiguous outcome, and capability-drift tests | **Implemented; local and real-PostgreSQL gates passed** |
| 4 | Browser lifecycle reconciliation, disconnect/expiry/close cleanup, unknown-outcome recovery, slot replacement, and retained evidence | Restart at every commit/dispatch/observe boundary; no duplicate current binding; no session resurrection; exact-owned cleanup; coordinated Contract decision for missing Provider close semantics | **Implemented; local and real-PostgreSQL gates passed** |
| 5 | Viewer/control authorization, single-controller Product lease/fence binding, one-use grants, revocation, and Browser quotas; multi-human collaboration remains deferred | Viewer cannot mutate; one live controller; stale fence/replay/revocation/expiry/limit races; database-time authority; nondisclosing errors | **Implemented; local and real-PostgreSQL gates passed** |
| 6 | Public Browser automation WSS data plane with closed action/result messages and downstream action fencing | Separate-process edge/Gateway/Provider test; bounded messages/queues; ordered actions; stale-owner suspension; reconnect; no raw CDP or endpoint exposure | **Implemented; local and separate-process gates passed** |
| 7 | Public Browser live viewing/control data plane with authenticated signaling, bounded media/input channels, resolution/encoding negotiation, bitrate, and backpressure | Origin/TLS/authentication; unsupported codec/size rejection; slow-consumer closure; control fence per input; view-only admission; no unauthenticated upgrade | **Implemented; local real-WebRTC gates passed** |
| 8 | Explicit keyboard/pointer/touch, clipboard, upload, download, navigation, popup, and permission policy | Deny-by-default matrix; size/type/count/digest bounds; activation/consent; filename/path confinement; cross-origin and policy-change revocation tests | **Implemented; local policy/data-plane gates passed** |
| 9 | Browser network and runtime isolation composition | Exact restricted-egress policy; DNS/IP/metadata/private-network denial; immutable verified image; permission/device denial; resource bounds; cleanup and fault injection | **Implemented; local and real-Docker gates passed** |
| 10 | Connection loss, Gateway/Provider restart, reconnect, visual resynchronization, resolution changes, and recovery UX | Fresh-grant reconnect; authority recheck; keyframe/resync bounds; no stale input; retained session recovery; dependency-loss fail-closed behavior | **Implemented; local real-WebRTC recovery gates passed** |
| 11 | Browser metadata audit, media/control-event recording, Product catalog, retention/deletion, integrity, and quota composition | Consent and visible mode; required-recorder fail closed; encrypted chained segments; authorized replay; content excluded from logs/control-plane lists; quota races | **Implemented; local and real-PostgreSQL gates passed** |
| 12 | Product Web Browser experience for slot/session lifecycle, live view, controller state, recovery, downloads/uploads, and recording catalog | Generated/checked client; authenticated browser E2E; CSP/CSRF/origin/accessibility; viewer/control UX; error/reconnect/cleanup cases; no private coordinates | **Implemented; local and real-headless-Chrome gates passed** |
| 13 | Product Phase 4 independent-process release gate and reproducible evidence bundle | Fresh PostgreSQL and required coordination/object storage; separate Product/Gateway/Provider/Browser roles; exact locked identities; restart/fault/security/backpressure/recording/cleanup matrix; strict independent validation | **Implemented; 12-scenario separate-process gate and strict evidence validation passed** |

Slices are dependency ordered. A later data-plane demo cannot replace Product
authority, exact Provider selection, recovery, policy, or cleanup gates.

## Slice 1 exact boundary

Slice 1 uses the Product Contract's existing generic session route and Browser
kind/profile names. It does not change or advertise the Contract. Browser work
is committed as `browser_session.open` or `browser_session.close`, which the
Terminal dispatcher cannot lease. The session remains `requested` or
`draining` until later Browser-specific workers reconcile retained external
evidence.

The Product Provider adapter still authorizes only Terminal in this slice, no
public Browser grant is issued by a complete readiness graph, and a fresh
Workspace still lacks an implemented auxiliary Browser-slot mutation. These
are deliberate fail-closed boundaries, not implied functionality.

### Slice 1 local evidence

Focused Product, Product API, and PostgreSQL adapter race/shuffle tests pass.
The full repository race/shuffle suite, `go vet ./...`, Provider Contract
verifier, Product Contract verifier, retained Phase 3 evidence verifier, and
`git diff --check` pass. The existing tagged four-process Phase 3 gate also
passes as a regression check; it is not counted as Browser evidence. A
disposable `postgres:16-alpine` container pinned to
`sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
passes the complete tagged Product PostgreSQL integration package, including
migration apply/replay, exact Browser kind/profile persistence, idempotent
replay and conflict, tenant/actor nondisclosure, Terminal-worker isolation,
close intent, and the database profile constraint. The exact container is
removed after the run.

This is local component and real-adapter evidence. No Browser runtime or
public data-plane integration was applicable to Slice 1, and no frontend was
changed. Docker Browser-driver and frontend build results are therefore not
claimed.

## Slice 2 exact boundary

The existing Product Contract `PUT` and `GET` slot routes now expose only an
auxiliary Browser slot shape. The slot key cannot be `primary-code`; kind,
runtime profile, and the single required capability are locked to `browser`,
`sandbox-runtime-browser-v1`, and `sandbox.browser@1.0.0` / `browser-v1`.
Product owns expected-Workspace-version admission, immutable slot identity and
shape, desired generation, tenant Browser-slot quota, operation/event/audit
records, and `slot.reconcile` intent. Tenant/owner mismatches remain
nondisclosing.

The migration adds a bounded per-tenant Browser-slot quota and an active-slot
index. A PUT atomically updates the Workspace and slot generations with the
operation, event, audit, idempotency record, and outbox message. Replaying the
same mutation returns the retained operation; reusing its key with a changed
request fails closed. New runtime allocation and Provider observation remain
Slice 3 work, so an accepted slot stays in a transitional observed state.

### Slice 2 local evidence

Focused domain and transport tests prove closed JSON, exact Browser shape,
policy-before-ID behavior, cancellation, and schema-valid projections. A
fresh disposable PostgreSQL 16 database applies and replays migrations 1-4;
race-enabled integration tests prove one retained operation under concurrent
idempotent PUTs, one winner under a one-slot concurrent tenant quota, exact
quota release after termination, cross-owner nondisclosure, event/outbox/audit
atomicity, and restart-safe reads. The complete tagged PostgreSQL package,
full repository race/shuffle and vet gates, and Contract verifiers are run at
the slice commit gate. No Provider dispatch, Browser runtime, public data
plane, capability advertisement, frontend, deployment, or production claim
follows from this slice.

## Slice 3 exact boundary

The Product Provider adapter now accepts a Browser dependency only when the
fresh Provider discovery response has the locked revision, the exact
Browser-only `sandbox.browser@1.0.0` / `browser-v1` advertisement, the canonical
`sandbox-runtime-browser-v1` container profile, and the configured
architecture. Discovery is re-read for every authorization/dispatch boundary,
so capability drift fails closed rather than surviving in a process cache.

Browser sandbox create uses only the protected Provider network Contract. It
pins the image, runtime profile, resources, base revision, restricted network,
explicit egress policy reference, mandatory egress Gateway, Browser placement,
lease, and unprivileged security shape. Dedicated Browser slot and Browser
session dispatchers lease only their own outbox types. Terminal workers cannot
lease either. Browser session open uses the locked mutation document; operation
observation reads the locked Browser handoff document and persists only its
opaque `ref:browser-session:*` reference, connection generation, and expiry.

Provider Browser session close is not present in the locked Provider Contract.
Accordingly Slice 3 does not lease `browser_session.close`; Slice 4 owns the
coordinated lifecycle/cleanup decision instead of inventing a wire route.

### Slice 3 local evidence

Focused race tests cover exact discovery/profile selection, restricted-network
create projection, protected signed requests, Browser session open and opaque
handoff observation, cancellation, capability drift, ambiguous response
classification, and isolated retry rules. Fresh pinned PostgreSQL integration
proves Terminal/Browser worker isolation, atomic dispatch evidence and binding,
slot observation without corrupting Workspace readiness, Browser session
handoff persistence, restart-safe observation leases, and stale-generation
non-dispatch. The complete repository and Contract gates are run at the slice
commit gate. This is network-adapter and real-database component evidence, not
a public Browser data plane, real Browser runtime, release topology,
deployment, or production result.

## Slice 4 exact boundary

Browser slot intents now carry an explicit provision, suspend, resume,
terminate, or replace action. Product stores Product slot fencing separately
from the Provider sandbox generation, preserves exactly one current Provider
binding per slot, and reconciles every ambiguous Provider operation from
retained operation evidence. Replacement terminates and observes the old
sandbox before a new deterministic Browser sandbox can become current.

The locked Provider Contract has no Browser-session close mutation. Product
therefore uses the existing protected sandbox terminate mutation for the
exact-owned Browser sandbox. A close or database-time expiry reaches its
absorbing session state only after termination is observed. If the slot is
still desired ready and its generation has not been superseded, the same
durable Product operation advances the slot generation and provisions a fresh
sandbox. Concurrent slot mutation suppresses that automatic replacement.
Late open observations cancel their superseded operation and cannot move a
draining or terminal session back to ready.

### Slice 4 local evidence

Focused tests cover lifecycle dispatch outcome classification, separate
Provider generation and Product fencing on signed suspend/resume/terminate
requests, database-time expiry intent, and the absorbing session state
machine. A fresh pinned PostgreSQL 16 database applies and replays migrations
1-5 and proves close cleanup plus replacement, exactly one current binding,
generation reset on a replacement Provider sandbox, expired-session cleanup
intent, stale-generation filtering, and no resurrection when close wins a
race with a retained open observation. Full repository race/shuffle, vet,
Provider Contract, Product Contract, retained Phase 3 evidence, and diff
checks pass. This remains control-plane lifecycle evidence; no public Browser
data plane or release topology is claimed.

## Slice 5 exact boundary

The locked Product connection-grant request and response now carry an explicit
`view` or `control` access mode. View grants never contain a control lease or
fence and cannot authorize mutating Browser traffic. Control grants require the
current session-scoped Product lease and its monotonic fence. Static viewer
principals may request view grants only; controller and owner principals may
request a control grant only after separately acquiring the lease. This is
role vocabulary and connection authority, not multi-human sharing or handoff.

Connection tickets remain encrypted at rest, one-use, and bounded by the
session, Provider handoff, and any control-lease expiry. PostgreSQL database
time decides grant and lease validity. Lease release or expiry revokes attached
grants, and the Gateway authority check continuously matches the complete
tenant, actor, Workspace, slot generation, session, profile, Provider binding,
handoff generation, access mode, lease, and fence tuple. A tenant advisory lock
serializes Browser connection quota admission; a partial unique index and the
session-scoped lease preserve one live controller connection per Browser
session. Viewer and controller totals have separate bounded tenant quotas.

### Slice 5 local evidence

Focused race tests cover strict access-mode projection, viewer mutation denial,
view/control separation, and malformed combinations. A pinned PostgreSQL 16
adapter run applies and replays migrations 1-6 and proves idempotent ticket
replay, one-use consumption, cross-owner nondisclosure, database-time expiry,
lease-release revocation, stale-fence rejection, monotonic reacquisition, exact
binding tamper rejection, and one winner under concurrent controller-grant
admission. Full repository race/shuffle, vet, Provider Contract, Product
Contract, retained Phase 3 evidence, and diff checks pass. The public Browser
automation/live data planes, downstream action fence, and continuous open-socket
watch are Slice 6 onward and are not claimed here.

## Slice 6 exact boundary

The public `product-browser-automation.v1` WSS edge accepts only Product
one-use control grants and closed text messages. The initial action allowlist is
`page.info` and bounded `page.text`; navigation, script execution, input,
clipboard, and transfer remain denied until their later explicit policy slice.
Action IDs are bounded, sequences start at one and increase without gaps, and
the per-connection pending set and complete logical message size are bounded.
Duplicate members, unknown members/actions, binary frames, raw CDP, oversized
messages, and ambiguous or unmatched private results fail closed. Private CDP
errors are reduced to stable Product errors before reaching the caller.

The Product Gateway translates an admitted action to private CDP only after
continuous Product authority, authenticated capacity, and downstream-fence
checks. Its resolver carries the opaque handoff and fence over WSS to a
separate private ingress; it never receives an endpoint address. Production
private ingress construction requires TLS plus an explicit Gateway peer
authorizer, and its unique action gate validates the fence on activation and
every complete private action. A newer owner suspends the stale stream. Backend
loss performs a fresh private resolution while the bounded public reader
survives; reconnect does not bypass Product authority or fencing.

### Slice 6 local evidence

Race-enabled component tests prove closed translation, exact Browser identity,
view-grant rejection, raw-CDP rejection, duplicate/unknown/order/queue/size
bounds, authority revocation closure, fresh fenced reconnect, TLS private
transport, and no private value in public results. Existing downstream-ingress
race tests retain the stale-owner suspension and per-action fence evidence.
The tagged Phase 4 Browser gate starts three independent test-binary processes:
a public TLS Edge, Product Gateway, and mTLS-authenticated private
ingress/Provider. It proves WSS upgrade, private reconnect after an initial
backend loss, one-use ticket replay rejection, a closed action/result round
trip, and public non-disclosure. This is same-repository separate-process
evidence with a bounded fake CDP backend, not real Chromium, deployment, HA,
hostile-multitenant, or production evidence.

## Slice 7 exact boundary

The public `product-browser-live.v1` edge now performs a closed HTTPS
offer/answer exchange only after TLS, exact HTTPS Origin, strict body, and
one-use Product-ticket checks. Production construction requires encrypted
TURN credentials and relay-only ICE, preventing the Product edge from
advertising host candidates. The initial negotiated media contract is VP8 with
explicit width, height, frame-rate, and bitrate ceilings. SDP, RTP packets,
media queues, input messages, input queues, peer totals, per-session totals,
and connection establishment time are bounded.

View grants create receive-only media sessions and cannot request or smuggle a
control data channel. Control grants carry the current Product lease and fence;
the initial closed `pointer.move` message is ordered and viewport-bounded, and
Product authority is rechecked before every forwarded input. Product authority
is also watched for the entire peer lifetime. Media queue overflow, invalid
RTP, bitrate excess, invalid or out-of-order input, authority loss, connection
failure, and establishment timeout close both the peer and its media source.
The media source is a trusted port bound to the exact Product/Provider handoff;
no Provider endpoint, handoff, backend identity, or relay credential appears
in public signaling.

### Slice 7 local evidence

Race-enabled tests use two real Pion WebRTC peers to exchange gathered
offer/answer SDP, establish DTLS/SRTP, receive an RTP video packet, open the
exact control data channel, and forward an input carrying the Product lease
and fence. Additional tests prove pre-consumption Origin/TLS/authentication,
viewer-control denial, unsupported codec/dimension/bitrate rejection,
production encrypted-relay construction, and deterministic slow-consumer
closure through a bounded RTP queue. Full repository race/shuffle, vet,
Provider Contract, Product Contract, retained Phase 3 evidence, and diff checks
run at the slice commit gate. The fake media source is component evidence; real
Chromium capture/input, complete input and content policy, reconnect/resync,
recording, Web UX, and the independent-process release topology remain Slices
8-13.

## Slice 8 exact boundary

Browser live control now uses one closed, ordered Product envelope whose action
union contains keyboard, pointer, touch, clipboard read/write, upload,
download, navigation, popup, and permission requests. Each shape rejects
unknown or duplicate members and carries bounded action-specific data. The
private media port receives the admitted Product action plus the current
controller lease and fence, and returns only a closed bounded result. Raw CDP,
backend input messages, storage references, and arbitrary permission names are
not accepted or projected.

An immutable Product policy snapshot is loaded at connection admission. Its
zero-value capabilities deny all mutations. Explicit policy independently
bounds keyboard/pointer/touch enablement, clipboard bytes, activation and
consent, transfer file count/per-file/total bytes/media types, canonical
single-component filenames, exact completed Product transfer identity and
digest, navigation origins, cross-origin behavior, popup count, and a closed
permission allowlist. Every input rechecks the current Product authority and
policy revision; any revision change closes the retained peer instead of
broadening it in place. Upload/download metadata is rebound to the same
tenant, actor, Workspace, direction, digest, size, and completed transfer
before it reaches the media adapter.

### Slice 8 local evidence

Race-enabled domain tests prove the deny-by-default matrix, activation and
consent requirements, clipboard bounds, origin and permission denial, transfer
count/type/size/digest bounds, duplicate filename rejection, and path
confinement. Gateway tests cover every closed action shape, viewport/touch/key
bounds, unknown-member/raw-action rejection, exact transfer rebinding, ordered
fenced forwarding, bounded result delivery, and active-peer revocation after a
policy revision. Full repository race/shuffle, vet, Provider Contract, Product
Contract, retained Phase 3 evidence, and diff checks run at the slice commit
gate. This is Product policy and adapter evidence; runtime/network isolation,
recovery, recording, Web UX, and the final independent-process composition
remain Slices 9-13.

## Slice 9 exact boundary

The Product Provider profile now refuses a Browser dependency unless its image
reference is immutable and ends in the exact configured SHA-256 digest, its
architecture is in the locked Provider matrix, and CPU, memory, ephemeral
storage, and PID values stay inside explicit Browser bounds. Browser creates
remain locked to restricted networking, one opaque policy reference, mandatory
egress Gateway, Browser placement, read-only ephemeral Workspace, unprivileged
execution, no service account, read-only root, and runtime-default seccomp.

The Provider Docker adapter now explicitly creates private IPC and cgroup
namespaces and re-inspects those values after restart. It additionally rejects
PID/UTS/user namespace sharing, device mappings, device cgroup rules, device
requests, extra hosts, additional groups, links, DNS options/search paths, and
sysctls, while retaining drop-all capabilities, no-new-privileges, the pinned
Chromium seccomp policy, no ports/binds/mounts, bounded tmpfs volumes, memory
without swap expansion, CPU/PID limits, and exactly one private network. The
dedicated egress Gateway continues to enforce normalized host policy, bounded
DNS, HTTP Host and TLS SNI, independent address resolution, and denial of
metadata, private, link-local, loopback, CGNAT, benchmark, documentation,
multicast, unspecified, and reserved addresses.

### Slice 9 local and real-Docker evidence

Race-enabled tests prove immutable Product profile selection, resource-bound
rejection, exact protected Provider create projection, device/namespace drift
rejection after restart, network/DNS ownership drift, rollback, dependency
failure, and exact cleanup. The tagged private-relay test runs the locked
published Chromium image with its real seccomp and runtime controls. The tagged
restricted-egress test builds immutable local Gateway and deterministic
upstream fixture images, creates a temporary public-looking uplink plus a
dedicated internal Browser network, proves allowed HTTP and TLS navigation,
denied unlisted and metadata destinations, process reconstruction, idempotent
recovery, and absence of all exact-owned resources after cleanup. The fixture
avoids host DNS interception without weakening the non-public-address deny
list. Full repository race/shuffle, vet, Contract, and retained evidence gates
run at the slice commit gate. Connection recovery, recording, Web UX, and the
final independent-process composition remain Slices 10-13.

## Slice 10 exact boundary

The live Gateway distinguishes transient WebRTC transport loss from durable
Product session state. A disconnect starts one bounded grace timer. A peer that
recovers before expiry rechecks its complete Product authority before resuming
and requests a keyframe; a stale timer cannot close that recovered peer.
Disconnect expiry, failed/closed peer state, media-source loss, authority loss,
or keyframe failure closes the live connection without closing or resurrecting
the durable Browser session. A subsequent connection therefore consumes a new
one-use Product grant and repeats the full admission and media-source open.

RTCP PLI/FIR, initial connection, recovery, and the closed ordered
`stream.resync` command share one bounded keyframe request limiter. Controllers
may also send a closed ordered `stream.resize` command, but only another
contract-bounded VP8 policy reaches the media adapter; bitrate enforcement and
input coordinate bounds switch atomically to the accepted viewport. Every
control command rechecks the current Product binding and immutable policy
revision. Control arriving while disconnected is stale and fails closed.

### Slice 10 local evidence

Race-enabled real-Pion tests recover a peer before an obsolete disconnect timer
fires, prove disconnect expiry closes the connection, bound repeated keyframe
requests, and exercise ordered resize/resync results over the actual WebRTC
data channel. Existing tests retain one-use ticket replay denial, continuous
authority and policy-revision revocation, dependency-loss closure, bounded
queues, and new media-source creation per admitted connection. Full repository
race/shuffle, vet, Contract, and retained evidence gates run at the slice commit
gate. Recovery UX presentation remains Slice 12; recording and the final
independent-process topology remain Slices 11 and 13.

## Slice 11 exact boundary

Browser live signaling now projects the exact committed `disabled`,
`metadata_only`, or `required` mode. Required recording consumes an explicit
bounded consent reference and initializes the recorder before opening the
private media source. Missing initialization, segment persistence loss, or
recorder loss closes admission or the active peer; the mode is never silently
downgraded. Metadata audit is a separate mandatory port and receives only safe
connection identifiers, counts, timestamps, and closed reasons.

The Browser media recorder writes an initial visible-mode record, accepted RTP,
content-minimized control events, viewport changes, and a final record as
bounded newline-delimited segments through the Product recording service.
Segments are encrypted at rest under a per-recording derived key, carry AEAD
additional-data binding, and form an ordered SHA-256 chain whose final digest
is the Product catalog integrity value. Replay reauthorizes the tenant actor
and verifies every size, predecessor, segment digest, final digest, and total.
Catalog projections omit media, control payloads, consent, object references,
key references, and host paths. Retention deletes encrypted content before the
catalog reaches `deleted`.

Migration 7 adds bounded per-tenant active-recording and retained-byte quotas.
Tenant advisory locking serializes both start and append accounting, so races
across sessions cannot exceed either limit. Media recordings are accepted only
for Browser-live sessions whose committed policy is `required`; terminal and
Browser recording types cannot be interchanged.

### Slice 11 local and real-PostgreSQL evidence

Race-enabled Gateway tests prove missing/failed required recorders reject before
media open and active recorder loss closes and marks the stream failed. A fresh
PostgreSQL migration replay plus encrypted local content store proves one
winner in a two-session active-recording quota race, byte-quota enforcement,
media/control/start/end capture, finalization and authorized integrity replay,
cross-owner nondisclosure, and metadata-only catalog projection. Existing
tamper, ciphertext, retention, and deletion tests remain green. Full repository
race/shuffle, vet, Contract, and retained evidence gates run at the slice commit
gate. Web presentation and the final independent-process topology remain
Slices 12 and 13.

## Slice 12 exact boundary

The authenticated Product Web BFF now presents Browser slot creation,
suspend/resume/terminate intents, Browser-live session creation and close,
explicit viewer or controller admission, and a same-origin HTTPS WebRTC client.
The client creates only the closed `product-browser-control.v1` data channel,
maps keyboard/pointer/navigation/resync actions into Product messages, shows the
committed recording mode, and requires an explicit per-connection consent
gesture for required recording. A failed live projection retries at most three
times with a fresh one-use grant while retaining the durable session; manual
disconnect releases its control lease and clears media and pending controls.

The BFF exposes a narrow Browser transfer port rather than storage
coordinates. Upload bodies are same-origin/CSRF protected, length-bounded to 64
MiB, streamed to Product in 1 MiB chunks, digest-checked on completion, and
project only safe transfer metadata. Downloads reauthorize each chunk and the
Web client verifies the declared size and SHA-256 digest before saving. The
recording tab reads only the Product metadata catalog. Gateway signaling must
share the Web origin, avoiding an arbitrary credential-bearing cross-origin
fetch and keeping the CSP closed.

### Slice 12 local and real-browser evidence

Race-enabled Web tests cover encrypted HttpOnly session authority, exact
Origin and CSRF rejection, bounded streaming transfer authority, private
storage nondisclosure, strict CSP including media policy, accessible Browser
landmarks, and generated-client/profile use. The generated client is recreated
from the locked Product OpenAPI and compared byte-for-byte. The JavaScript
module passes syntax validation with the bundled runtime. A tagged headless
Chrome gate performs a real HTTPS login, restores the HttpOnly session in the
actual Product Web application, calls the Product API, and renders the Browser
surface. This is local Web/BFF evidence; the complete separate-process Browser
topology remains Slice 13.

## Slice 13 exact boundary

The tagged release gate starts fresh digest-pinned PostgreSQL and Valkey
containers plus fresh encrypted recording storage. Four child OS processes
own the Product, Gateway, Provider, and Browser roles. Product uses its real
PostgreSQL repository and network-only Provider adapter; Gateway uses the real
PostgreSQL grant/audit repository, Redis-compatible capacity authority,
automation WSS, WebRTC live transport, and encrypted recorder; Browser exposes
only the private mTLS/fenced ingress and network media source; Provider remains
the exact locked-wire same-repository fixture for the selected Contract.

The gate passes the exact `contract-identities`, `product-authentication`,
`browser-slot-session-lifecycle`, `tenant-nondisclosure`,
`automation-roundtrip`, `viewer-controller-fencing`,
`browser-live-recording-integrity`, `product-restart-recovery`,
`gateway-restart-recovery`, `provider-fault-closure`,
`bounded-backpressure`, and `exact-cleanup` scenarios. Cleanup reaps all child
processes, removes the run-owned containers and recording objects, drains
coordination state, and removes scoped Product rows.

Run `20260918T152110.677058000Z` records source baseline
`322eb342650d2ade838f1b3a24e0d5bc0bfbb3e1`, the locked Provider revision and
tree, Product Contract tree, four process roles and executable digests, the
12/12 scenario result, exact cleanup, and explicit non-claims. The checked-in
manifest is independently parsed and semantically validated by
`cmd/verify-product-phase4-evidence`.

This closes the fixed Product Phase 4 plan only at the
same-repository-separate-process evidence tier. It is not a deployable topology,
independently implemented caller result, HA result, hostile multi-tenant result,
or production-readiness result.

## Evidence rules

Every slice records the lowest evidence tier it actually passed: unit,
Contract projection, real adapter, same-repository separate process,
independently implemented caller, deployment, multi-controller, hostile
multi-tenant, HA, or production. Historical Provider Browser evidence is cited
only as historical Provider/reference evidence.

Phase 4 is complete because Slice 13 passed its named bounded gate. Completion
does not imply production, HA, hostile-multitenant isolation, independently
implemented caller interoperability, or multi-human collaboration without
their separate named gates.
