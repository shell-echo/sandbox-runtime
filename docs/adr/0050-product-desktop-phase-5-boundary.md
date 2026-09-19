# ADR 0050: Product Desktop Phase 5 Boundary

- Status: Accepted for Product Phase 5 scope; Slices 1-6 are complete
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
- Phase 5 completion requires the named independent-process Slice 15 gate.
  It still does not establish multi-user collaboration, HA, hostile
  multi-tenant isolation, production deployment, or general production
  readiness. Those remain later scopes.
