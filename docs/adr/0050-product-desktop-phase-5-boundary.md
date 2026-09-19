# ADR 0050: Product Desktop Phase 5 Boundary

- Status: Accepted; Product Phase 5 is complete at 15/15 for the bounded
  same-repository independent-process scope
- Date: 2026-09-19

## Context

Product design already reserves a Desktop slot, Desktop session kind, and
`product-desktop.v1`, but those names are not an implementation or readiness
claim. At the Phase 5 baseline the locked Provider Contract did not authorize
Desktop, and the repository lacked a Desktop runtime image, display/input
broker, Provider application and adapter, Product persistence and
reconciliation, public data plane, recording composition, and unified Product
experience. Slices 1-3 have since added the Contract, Product intent, and
Provider-local application authorities. Slice 4 adds a separately published,
immutable, signed Desktop image and observation-only broker; its hosted native
publication and independent provenance gate now pass.
Slice 5 adds the Provider-local runtime adapter, private resolver, lifecycle,
usage, revocation, and cleanup composition while leaving startup and
advertisement disabled.
Slice 6 adds the Product network-only Provider adapter, isolated Desktop
dispatch/observation and close cleanup, and real-PostgreSQL recovery evidence
while leaving production composition and advertisement disabled.
Slice 7 adds Product-owned Desktop viewer/controller grants, one-controller
fencing, independent quotas, revocation, continuous authority, and
metadata-only audit while leaving the public Desktop data plane absent.
Slice 8 adds the separate bounded public Desktop WebRTC handler, display and
optional audio output, viewer/control separation, ordered fenced input,
continuous authority, and backpressure closure while leaving durable Desktop
policy and production composition absent.
Slice 9 adds durable versioned Desktop input/clipboard/transfer policy and
exact Product transfer binding. Slice 10 adds fresh-grant reconnect,
resynchronization, bounded Gateway crash recovery, and deterministic slot
replacement cleanup. Slice 11 composes required encrypted Desktop recording,
owner-authorized integrity replay, quotas, and retention deletion while
leaving the real Provider media bridge, development environment, startup, and
advertisement disabled.
Slice 12 adds immutable coding-shell development templates, validated revision
manifests, exact Guest health/authority, bounded digest-checked workspace
materialization, and two-phase rollback/restart recovery while leaving unified
Web, production composition, and advertisement disabled.
Slice 13 adds the capability-derived authenticated unified Product Web/BFF.
Slice 14 adds the private Provider/Gateway Desktop transport and the composed
real-store fault/security/cleanup gate while leaving independent-process
release evidence and advertisement disabled.
Slice 15 adds the exact five-process release topology, real display/control
and Guest development materialization, restart/fault/security/recording and
cleanup matrix, dependency-derived topology-specific advertisement, and a
strict reproducible evidence verifier. Production command composition and the
deployment/HA/hostile-tenant/independent-caller/production gates remain
outside Phase 5.

Starting with Product persistence would require Product code to invent a
Provider wire shape. Starting with a runtime image or driver would create an
unreviewed private protocol without stable lifecycle, security, cleanup, or
evidence semantics. Reusing Terminal or Browser routes would conflate distinct
session and data-plane authorities.

## Decision

Product Phase 5 follows the fixed 15-slice order in
`docs/plan/product-v1-phase-5-desktop-development-unified-product.md`.

The first slice is Provider Contract-first. Desktop has a separate capability,
capability profile, runtime profile, resource class, open/close lifecycle,
handoff document, operation family, usage meter, admission binding, and
Conformance cases. Terminal and Browser routes, DTOs, handoffs, profiles, and
runtime components cannot be used as Desktop substitutes.

Provider owns controller-to-Provider authentication and admission,
Provider-local execution, durable Provider operations, opaque handoff
resolution, generation and expiry enforcement, revocation, cleanup, and usage
evidence. Product owns business truth: users, tenants, Workspaces, slots,
sessions, desired state, aggregate operations, end-user grants, one-controller
leases, quotas, policy, audit, reconnect decisions, recording/catalog, and the
public Gateway.

The Provider handoff contains only an opaque `ref:desktop-session:*`, fixed
media/control profile identifiers, connection generation, and expiry. Public
signaling, relay credentials, session descriptions, candidates, and end-user
authorization belong outside the Provider control API. Raw addresses, ports,
backend identifiers, credentials, host paths, and diagnostics never enter the
stable Product or Provider DTOs.

The initial media authority is display video with optional audio output.
Keyboard, pointer, touch, clipboard, and transfer require explicit bounded
Product policy and current controller authority. Microphone input, camera
input, and host-device forwarding are denied. One session has at most one
controller; multi-user collaboration, controller queues, shared cursors, and
simultaneous control are deferred.

Desktop capability advertisement is the conjunction of the exact locked
Contract, Provider application/repository, verified immutable runtime image,
runtime adapter, broker, private resolver, revocation and cleanup, usage
evidence, and readiness graph. Product capability advertisement additionally
requires Product persistence/reconciliation, exact Provider adaptation,
public Gateway, grants/leases/policy, recovery, recording/catalog, Web
experience, and the final release gate. Until those dependencies pass,
advertisement remains empty.

The Slice 15 topology satisfies that conjunction only inside the tagged
release gate and continuously withdraws readiness when a required dependency
is absent. It does not change the production command's startup composition or
advertisement.

## Slice 1 authority

Slice 1 authorizes and projects only the Provider Desktop wire behavior. The
locked authority includes exact open/read/handoff/close semantics,
revoke-before-cleanup expiry behavior, absorbing terminal states, strict
request digests and replay protection, safe errors, capacity signaling,
nondisclosure, and correlated duration usage evidence. Every new Suite case is
mapped to an executable repository test.

No runtime, driver, image, Guest protocol, public route composition, Product
state, or Web feature is enabled by this slice.

## Slice 2 Product authority

Product Desktop intent is now a separate durable authority. A Desktop slot has
the immutable exact shape `desktop` / `sandbox-runtime-desktop-v1` /
`sandbox.desktop@1.0.0` / `desktop-v1`. A Product Desktop session has the exact
kind/profile pair `desktop` / `product-desktop.v1`, is bound to one current
ready Desktop slot generation, and follows the Product-owned absorbing session
state machine.

The authenticated Product API remains generic at its Contract-authorized slot
and session routes, but strict application validation and PostgreSQL migration
8 reject every alternate Desktop shape. Expected versions, mutation digests,
tenant quotas, and database serialization resolve concurrent commands. One
transaction commits Product state, operation, event, security audit,
idempotency result, and external-work intent.

Desktop session intents use the separate `desktop_session.open` and
`desktop_session.close` outbox family. Existing Terminal and Browser workers
cannot lease them; Browser slot workers also filter `slot.reconcile` by slot
kind. There is deliberately no Desktop dispatcher until the Provider and
network adapter slices exist. Capability advertisement remains empty.

## Slice 3 Provider authority

Provider Desktop execution policy is implemented as a separate domain,
application service, coordination authority, and protected transport
projection. It does not reuse Browser sessions, lifecycle repositories,
runtime-driver structs, or Product DTOs. The memory and atomically replaced
file repositories retain open/close operation, idempotency, fencing,
allocation receipt, handoff revocation, and exact source-operation linkage.

An open commits accepted/running state before an external allocation and
commits the immutable allocation receipt before handoff publication. Restart
from a running or outcome-unknown state observes the exact allocation identity
instead of redispatching it. Close and expiry use one policy: durably revoke
the source handoff, revoke the private handoff authority, clean only the exact
retained allocation, and observe absence before success. Unknown close effects
are reconciled by observation and are not repeated.

The optional protected open/close/operation/handoff handlers use the existing
admission boundary, strict bounded documents, safe error mapping, and opaque
handoff projection. The production command does not inject this application,
and capability discovery remains unchanged. At the Slice 3 boundary the
runtime image, broker, adapter, private resolver, usage collector, Product
dispatcher, and public data plane all remained later work; the following
section records the Slice 4 image publication without broadening composition.

## Slice 4 image and broker publication

Slice 4 locks a separate Desktop runtime image definition for native amd64 and
arm64/v8. Source manifests, exact package versions, recursive package archives,
the installed package set, build toolchain, runtime mounts, numeric identity,
device policy, broker protocol, fixed display shape, and candidate outputs are
strict manifest authority. The final image is repacked from scratch and has no
public port metadata. Its required execution policy is non-root, read-only,
drop-all, `no-new-privileges`, runtime-default seccomp, private IPC, finite
resources, no host device requests, and restricted egress when later composed.

The image entrypoint starts only the fixed broker. The broker owns Xvfb and
Openbox and exposes strict bounded `probe`/`describe` observation through one
`0600` Unix socket. The returned reference is opaque. Input execution, media,
public signaling, Product authorization, and arbitrary child-process control
remain outside this slice.

Local native arm64 reproducibility/runtime smoke passes. Manual publication
run `35447651328` from source
`e4a940bda6c5172a78d0dbe40963ca1a99911976` also passes native hosted amd64
and arm64/v8 builds, publishes immutable index
`sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`,
creates GitHub OIDC/Sigstore attestation `48643717`, and passes a separate
fresh verification job for repository, workflow, source, hosted-runner policy,
and exact platform matrix. Slice 5 may select only the fail-closed publication
authority recorded in `profiles/desktop/image/publication.go`.

## Slice 5 Provider runtime composition

The Desktop Docker adapter selects only the locked Slice 4 publication and
requires explicit provenance and restricted-network dependencies. Its durable
adapter-private state binds allocation identity, generation, controller
ownership, resource policy, network lease, and backend container identity;
none of that state is projected through Provider DTOs.

The opaque reference registry is the application handoff registrar and
revoker. It durably binds one succeeded open operation and exact allocation
receipt. Resolve and every fresh attach/reconnect recheck reference expiry and
revocation, the retained succeeded source, receipt, and connection generation
before executing the bounded in-container broker description. The attachment
is private fixed profile/display metadata, not a public media endpoint.

Close and expiry durably revoke the reference before exact runtime cleanup and
confirm absent/expired allocation state before success. Unknown close
reconciliation remains observation-only. Desktop duration usage begins at
successful handoff commit and stops at the earliest revocation, endpoint or
sandbox termination, or handoff expiry.

This is Provider-local component authority. Production command composition,
Product dispatch, public signaling/media/input, grants and policy, recording,
Web integration, and capability advertisement remain later slices.

## Slice 6 Product network adapter

The Product selects the exact Desktop Contract revision and tree through a
separate network-client constructor and accepts one exact
`sandbox-runtime-desktop-v1` profile backed by the signed Slice 4 image,
bounded resources, a selected architecture, and explicit restricted-network
policy. Readiness is re-evaluated from Provider discovery before authorization
or mutation; a revision, capability, profile, runtime class, isolation,
architecture, or limit drift fails closed.

Desktop create, lifecycle, open, close, retained-operation, and handoff reads
use only protected Provider routes and exact Desktop DTOs. The Product slot
generation is carried as the Product fence. Provider generation remains a
separate retained value and is never inferred from Product generation.

Dedicated PostgreSQL lease paths isolate Desktop slot, lifecycle, session,
expiry, and observation work from existing generic, Terminal, and Browser
workers. Desktop close revokes the Product handoff and terminalizes the
session but retains the current ready Desktop slot binding; it does not reuse
Browser's sandbox termination and replacement semantics. Dispatch remains
asynchronous, and outcome-unknown attempts are recovered by retained
operation observation after process reconstruction.

This is Product network-adapter and real-store component authority only. The
Provider peer in the real-store gate is a same-repository HTTP fixture.
Production process composition, end-user grants, public data planes, policy,
recording, Web integration, and advertisement remain later slices.

## Slice 7 Product connection authority

Only an exact ready `desktop` / `product-desktop.v1` session with a current
slot binding, positive Provider connection generation, live opaque handoff,
and unexpired Product authority may mint a Desktop connection grant. View
grants contain no control lease or fence. Control grants require the current
actor-bound session lease and monotonic fence; at most one live controller
grant may exist for a session.

The public grant contains only a Product Gateway URI, public protocol profile,
access mode, opaque one-use ticket, and bounded expiry. Tickets are retained as
a SHA-256 lookup digest plus AES-256-GCM ciphertext solely for exact
idempotent replay. The internal consumed binding may carry the Provider opaque
handoff to a trusted later Gateway composition, but neither the public response
nor metadata audit may expose it.

PostgreSQL database time decides grant, session, handoff, and lease expiry.
Migration 10 adds separate Desktop viewer/controller tenant quotas and a live
admission index. Tenant-scoped locking closes quota races, while the
session-wide partial unique index and control lease close controller races.
Continuous checks fail closed on release, expiry, closure, state change,
binding/handoff replacement, generation drift, or any tuple substitution.

This is Product authorization and real-store component authority only. It does
not compose a public signaling, display/audio, or input path and does not
enable Desktop advertisement.

## Slice 8 public Desktop data plane

The public Desktop edge is a separate Product WebRTC handler. It consumes the
one-use Product ticket, continuously checks the exact Desktop grant binding,
and gives the opaque Provider handoff only to an injected private media port.
Its public response contains no handoff, endpoint, backend identity,
credential, ticket, media, or input payload.

Production signaling requires HTTPS, one exact configured HTTPS Origin, and
relay-only password-authenticated `turns:` ICE. The initial matrix is one
receive-only VP8 display at bounded resolution/frame-rate/bitrate with optional
receive-only Opus output. Upstream microphone/camera media is invalid. Viewers
cannot negotiate control; controllers require the current lease/fence and one
reliable ordered data channel.

Only bounded keyboard, pointer, and touch shapes enter the private input port,
strictly in sequence and only after fresh grant plus injected Product-policy
authorization. Clipboard, file, microphone, camera, and device messages are
closed at this boundary. Signaling, peer/session capacity, RTP packets,
bitrate, and media/input/control queues are bounded; overflow or slow
consumption closes the peer. Required recording fails closed until Slice 11.

This is same-process public-handler and real-WebRTC component authority. It is
not a real Provider media bridge, the durable Slice 9 policy, production
composition, advertisement, or release evidence.

## Slice 9 durable Product policy

Desktop policy is a separate immutable Product authority, not Browser policy
reuse and not a Provider concern. PostgreSQL retains every Workspace-scoped
revision. Owner-scoped idempotent updates require the exact prior revision;
missing, malformed, stale, or unreadable policy denies access.

The policy independently controls keyboard, pointer, touch, clipboard read and
write, and Product-bound upload/download. It enforces configured activation
and consent, UTF-8 clipboard size, canonical media types, SHA-256 digest,
file-count and byte bounds, and confined `/workspace/...` paths. Microphone,
camera, and device forwarding are permanently outside this policy surface.

The public Desktop handler pins the admitted revision and continuously closes
on replacement or policy-source failure. Transfer authorization additionally
matches the exact current tenant, actor, Workspace, transfer ID, direction,
complete state, digest, and size in Product transfer authority. Backend object
references remain private.

This is durable Product policy and real-PostgreSQL component authority. It does
not provide the Slice 10 reconnect/recovery path, a real Provider media/input
bridge, production composition, advertisement, or release evidence.

## Slice 10 reconnect and replacement recovery

Every reconnect consumes a new Product grant and revalidates the complete
Product/Provider binding. A bounded database-time lease on consumed Desktop
grants permits restart reclamation without reviving the old ticket. Initial
connect and in-grace recovery require media resynchronization plus a keyframe;
ordered resync/configuration controls retain fixed codec/bitrate ceilings and
reject stale connection-epoch input.

Desktop session close and slot replacement revoke grants and handoff authority.
Replacement closes affected sessions, retires the old binding, and creates one
next-generation provision intent transactionally. This remains Product Gateway
and PostgreSQL component evidence, not a real Provider media bridge or
production recovery topology.

## Slice 11 required Desktop recording

Content recording remains separate from metadata audit. Required mode needs an
explicit bounded consent reference, reports the exact mode to the client, and
initializes before the private media source opens. Initialization or live
recorder failure closes admission/connection and cannot silently downgrade.

The Desktop recorder writes bounded VP8/optional-Opus RTP and only closed,
minimized control/synchronization metadata to the existing encrypted immutable
Product segment store. Sequence and previous-digest linkage, owner-only catalog
and replay, integrity validation, tenant quotas, and retention deletion remain
Product authorities. Clipboard content/results, transfer paths/identities/
digests, tickets, handoffs, and backend coordinates are excluded from control
metadata, public catalog, and ordinary audit.

This is Product recording/local encrypted-store/PostgreSQL and same-process
Gateway component evidence. It is not a real Provider media bridge,
development-environment composition, production startup, advertisement, or
release evidence.

## Slice 12 development environment

The Product selects only the immutable `coding-shell-base-v1` descriptor and
persists each startup against the exact current primary code slot, Guest
generation, template revision, and validated workspace revision manifest.
Content remains in the private content-addressed store and crosses the Guest
protocol only in bounded digest-checked chunks.

Guest owns filesystem truth. It accepts only the four exact public mount
points, locked toolchain identities, safe ordered relative paths, and matching
size/digest writes. Its private transaction journal retains the prior workspace
until Product commits readiness, allowing database failure rollback and
deterministic reconstruction of an interrupted swap. Public health returns only
liveness/readiness and locked public identities; host/object paths,
credentials, Guest identity, and runtime coordinates remain private.

This is Product/Guest protocol, local content-store, and PostgreSQL component
evidence. It is not a real Provider media bridge, unified Web, production
startup composition, advertisement, or release evidence.

## Slice 13 unified Product Web

The generated checked client enables Workspace, Terminal, Files, Browser,
Desktop, and recording navigation only from exact ready capabilities. The
Desktop experience uses public Product slot/session/grant DTOs and the public
same-origin WebRTC route, with ordered fenced control, bounded reconnect and
stream reconfiguration, explicit clipboard/recording consent, Product-bound
transfers, strict browser security, and accessible recovery state. Provider
handoffs and private coordinates remain outside the browser.

This is authenticated Web/BFF and real-headless-browser component evidence.
It is not a Provider media bridge, composed fault/security result,
independent-process release gate, or advertisement authority.

## Slice 14 private bridge and composed gates

The private Desktop transport is a closed repository-owned protocol shared as
neutral wire shapes, not Product or Provider business authority. The Product
Gateway opens it only from an already-consumed exact Desktop binding. The
Provider handler requires a trusted peer, freshly resolves and attaches the
opaque durable handoff, compares the complete private tuple, and continuously
re-resolves authority. RTP, control messages, sessions, deadlines, and queues
are bounded; revocation, dependency loss, stale tuple substitution, malformed
input, timeout, and backpressure close the connection.

The same-process composed gate joins real PostgreSQL grants/policy, public
WebRTC, the private bridge, ordered fenced input, required encrypted recording,
continuous policy revocation, Origin/ticket/owner attack denial, retention
object deletion, and exact tenant-row cleanup. Focused tests add private
capacity recovery and handoff/generation substitution coverage, while the
complete tagged store and retained Phase 3/4 gates preserve quota, restart,
replacement, runtime cleanup, and regression evidence.

This remains same-repository composition evidence with a bounded reference
media executor. Independent Product/Gateway/Provider/Desktop/Guest processes,
real display/control and development scenarios, the strict release evidence
bundle, and topology-specific advertisement remain Slice 15. No deployment,
HA, hostile-multitenant, or production-readiness conclusion follows.

## Slice 15 independent-process release gate

The final gate starts Product, Gateway, Provider, Desktop, and Guest as five
separate OS processes against fresh digest-pinned PostgreSQL and fresh object
and Guest state. It selects both exact locked Provider identities, the signed
Desktop image and native platform manifest, and the locked development
template. The public Desktop path crosses Product authority, HTTPS WebRTC,
the Product Gateway, private mTLS, and the Desktop runtime; controller input
changes the real X11 pointer position and the gate captures the real root
display. The Guest process materializes digest-checked revisions before and
after reconstruction.

Run `20260919T200125.484855000Z` at implementation
`024a768d51965f8949bacf3c97e499fb26a6e648` passes the exact 14-scenario
matrix, including Product/Gateway/Guest restart, Provider dependency loss,
Origin/ticket/tenant denial, encrypted recording replay, capability withdrawal,
and exact process/row/object/Guest/runtime/container cleanup. The strict
manifest binds the five roles, scenario set, Contract/runtime/template
identities, and explicit non-claims, and rejects unknown or private material.

This is same-repository, single-host, single-controller release evidence. The
roles use one repository-built test executable and the Provider is a
repository-owned fixture for the locked Contracts. Topology-specific
advertisement is authorized only by this gate. Deployment qualification, HA,
hostile multi-tenant isolation, independently implemented caller
interoperability, and general production readiness are not established.

## Consequences

- Product Desktop persistence begins only after the Provider wire authority is
  immutable and selected by the repository lock.
- Provider and Product implementations can evolve behind explicit ports while
  preserving their separate sources of truth.
- Close and expiry cannot report success until the handoff is revoked, active
  media/control authority is terminated, owned runtime resources are cleaned,
  and exact absence is confirmed.
- Unknown outcomes are reconciled from retained evidence; they are never
  blindly redispatched.
- Historical qualification definitions retain dedicated immutable-revision
  locks; they are not silently rebound to the current Desktop-extended
  authority.
- Local image reproducibility and native smoke remain component evidence.
  Slice 4 closes only because the exact hosted index, platform manifests,
  attestation, transparency-log identity, and independent verification are
  recorded separately; this is not adapter or production evidence.
- Slice 5 real-image broker and cleanup evidence plus composed fault tests are
  not a deployed restricted-egress topology or a public Desktop data plane.
- Slice 6 real-store recovery proves the Product adapter and durable worker
  boundary, not production process composition or an independently
  implemented Provider deployment.
- Slice 7 grants authorize Product access metadata only. They do not prove or
  compose the public Desktop signaling/media/input data plane.
- Slice 8 real-WebRTC evidence proves the separate public handler and bounded
  data-plane mechanics, not a real Provider media bridge, durable Desktop
  policy, production composition, or deployment.
- Slice 9 durable-policy evidence proves versioned Product authorization,
  exact Product transfer binding, and live revision revocation, not a real
  Provider media/input bridge, reconnect/recovery, production composition, or
  deployment.
- Slice 10 proves bounded reconnect/recovery and replacement cleanup only; it
  does not compose the injected media source into a production process graph.
- Slice 11 proves fail-closed encrypted recording/replay/retention composition
  only; it does not provide a real Provider media bridge or advertise Desktop.
- Slice 12 proves immutable template selection and exact Guest workspace
  materialization/rollback/recovery only; it does not compose unified Web or
  advertise Desktop.
- Phase 5 completion is established only for the named independent-process
  Slice 15 topology. It still does not establish multi-user collaboration, HA, hostile
  multi-tenant isolation, production deployment, or general production
  readiness. Those remain later scopes.
