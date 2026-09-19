# Project Context

Updated: 2026-09-20

This is the stable handoff index for a new developer, AI agent, development
device, or implementation session. It summarizes the system, engineering
constraints, verified maturity, and evidence boundary; it does not override
the Provider Contract, architecture, accepted ADRs, or reproducible evidence.

Current verified state:

- the fixed P2.7 independent external-caller qualification plan is **24/24**;
- the public `sandbox-runtime-external-caller` plan is **13/13**;
- hosted run `35203241121` executed all 15 initial and 5 reconstruction
  scenarios, matched all 91 required observations, and restored the exact
  run-owned resource scope to zero across three stable samples;
- artifact `10488622806` contains the accepted seven-file evidence archive,
  validator receipt, and bounded `qualified` result envelope; and
- post-documentation core CI run `35204434771` passed every required job; and
- Product v1 architecture Phase 1 is complete as committed design and
  Product Contract-definition authority; and
- Product v1 Phase 2 is complete for its fixed nine-step scope: implementation
  revision `98995384c60a924f25ca58d3b7e561207bfa5be8` is selected by lock
  revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`, the clean-VCS 60-case
  Suite and all required release gates pass, and the repository-owned
  independent-process reference run passes 15+5+9 scenarios; and
- Product v1 Phase 3 is complete at **13/13** for its bounded standalone scope.
  In addition to the Product authority, authenticated API, locked Provider
  reconciliation, control, Terminal/Gateway, Guest/Files, transfer/revision,
  Web, catalog, and recording components, run
  `20260918T111903.806694000Z` at implementation
  `04c2755bec125db7e2c04df3f4e2f8cfedb6ec1d` passed nine black-box scenarios
  through four separate role processes and fresh pinned PostgreSQL. Its strict
  evidence manifest records complete process, schema, and container cleanup.
  This same-repository Provider-fixture topology is not deployment, HA,
  hostile-multitenant, independently implemented caller, or production
  evidence; and
- Product v1 Phase 4 Browser is complete at **13/13** for its bounded
  same-repository separate-process scope. Run
  `20260918T152110.677058000Z` at source baseline
  `322eb342650d2ade838f1b3a24e0d5bc0bfbb3e1` passed 12 exact scenarios
  through separate Product, Gateway, Provider, and Browser OS processes with
  fresh digest-pinned PostgreSQL and Valkey plus fresh encrypted recording
  storage. Strict evidence validation confirms the locked Contract identities,
  four roles, scenario set, and cleanup. Deployment, HA, hostile multi-tenant,
  independently implemented caller, and production readiness remain explicit
  non-claims; and
- Product v1 Phase 5 Desktop is **15/15 complete** for its bounded
  same-repository independent-process topology. Slice 1 establishes the
  separate Provider Desktop Contract and Go projection authority at revision
  `720ad15c343e71f36615dc4499edd5e764178bca`, tree
  `343ffde0819207cf99c005096c336735dd33a735`, with a content-derived 71-case
  local Suite. Slice 2 implementation
  `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00` adds exact Product Desktop
  slot/session intent, PostgreSQL migration 8, atomic audit/outbox persistence,
  quotas, concurrency closure, nondisclosure, and restart-safe reads. Slice 3
  implementation `f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5` adds the separate
  Provider Desktop domain, application policy, memory/atomic-file authority,
  restart and unknown-outcome reconciliation, operation projection, and
  optional protected handlers. Slice 4 candidate implementation
  `163dd8a258a24cf4727169b1cbd8ed7c0fe29292` adds the locked Desktop image
  inputs, fixed Unix-only broker, reproducible local outputs, passing native
  arm64 smoke, and a manual native publication/provenance workflow. Run
  `35447651328` at source `e4a940bda6c5172a78d0dbe40963ca1a99911976`
  passes native amd64/arm64/v8 gates, publishes exact signed index
  `sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`,
  and passes fresh independent provenance and architecture verification.
  Slice 5 implementation `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b`
  adds the Provider-local Docker adapter, durable opaque reference authority,
  fresh attach/reconnect checks, lifecycle readiness, exact duration usage,
  and revoke/cleanup/absence composition. Slice 6 implementation
  `2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240` adds the locked network-only
  Product adapter, isolated Desktop slot/lifecycle/session/observation workers,
  retained operation recovery, separate Product/Provider generations, and
  Desktop-specific close cleanup with a real-PostgreSQL gate. Slice 7
  implementation `0649d62911abb89229de40136347286736152ec6` adds exact
  Desktop-only viewer/controller grants, encrypted one-use tickets,
  session-scoped controller fencing, independent viewer/controller quotas,
  revocation, continuous authority checks, and metadata-only audit. At that
  boundary, production startup composition, public signaling/media/input,
  policy, unified Web, capability advertisement, and release evidence remained
  absent.

  Slice 8 implementation `040c560f3701b7c972c25f05928dd435d9f55c20`
  adds a separate bounded Desktop WebRTC handler with authenticated encrypted
  signaling, exact Origin, receive-only VP8/optional Opus, viewer/controller
  separation, ordered fenced input, continuous authority, and backpressure
  closure. Durable Desktop policy, a real Provider media bridge, recovery,
  recording, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 9 implementation `24f5c741eb605614f77f8d9d546708b9993e42dd`
  adds immutable versioned Workspace policy, PostgreSQL migration 11,
  deny-by-default keyboard/pointer/touch/clipboard/transfer authorization,
  activation and consent, bounded clipboard/media/digest/count/size/path
  rules, exact Product transfer binding, and continuous policy-revision
  revocation. A real Provider media/input bridge, reconnect/recovery,
  recording, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 10 implementation `f23b16130c97e99d5d28008b01346779a0c681ee`
  adds database-time Desktop Gateway leases for bounded crash recovery,
  fresh-grant reconnect with exact authority/generation rebinding, visual and
  audio resynchronization with rate bounds, closed display/audio-output
  changes, connection-epoch stale-input rejection, and transactional cleanup
  plus one-generation replacement for a replaced Desktop slot. A real Provider
  media/input bridge, recording, production composition, unified Web,
  capability advertisement, and release evidence remain absent.

  Slice 11 implementation `c5b045abc5192b76b7d615ddbb0858b998ef98d5`
  composes required Desktop content recording into the public Gateway. The
  client supplies an explicit bounded consent reference and receives the exact
  selected recording mode; missing initialization or live recorder loss closes
  admission/connection. Encrypted immutable segments retain bounded VP8/Opus
  RTP plus minimized control/synchronization metadata, monotonic timestamps,
  and digest linkage. Existing Product authorization, quotas, integrity replay,
  retention, and deletion apply to Desktop media. Clipboard text, transfer
  paths/identities, private coordinates, and content are absent from public
  catalog and metadata audit. A real Provider media/input bridge, development
  templates, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 12 implementation `490c2db96d6ba7a851d7846bc9e5f818dae2be77`
  adds the immutable development template catalog, validated revision-manifest
  persistence, exact Guest generation/capability/health authority, bounded
  content-addressed workspace materialization, and private two-phase
  rollback/restart recovery. Migration 13 and the complete fresh PostgreSQL
  package pass. Host paths, object paths, credentials, Guest IDs, and runtime
  coordinates remain outside stable health, event, and audit projections. A
  real Provider media/input bridge, unified Web, production composition,
  capability advertisement, and release evidence remain absent.

  Slice 13 implementation `84698c371d35edb862ffc81b484a3e31cc8120d9`
  adds the capability-derived authenticated unified Product Web/BFF for
  Workspace, Terminal, Files, Browser, Desktop, and recordings. Exact public
  Desktop slot/session shapes, fresh grants and controller leases,
  same-origin WebRTC, bounded recovery/configuration, explicit clipboard and
  recording consent, digest-checked transfers, keyboard-accessible tabs, and
  strict browser security/nondisclosure pass focused, full repository, and
  real headless-Chrome gates. Desktop advertisement remains off pending the
  real Provider media/input bridge, production startup composition, Slice 14
  composed security/fault cleanup, and Slice 15 independent-process release.

  Slice 14 implementation `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d`
  adds the closed neutral private Desktop media/control protocol, Product
  network source, Provider trusted-peer handler, fresh attach and continuous
  handoff authority, capacity/backpressure bounds, and a real-PostgreSQL
  composed public-WebRTC/private-bridge/recording/security/cleanup gate. Full
  race/vet, tagged store, Contract, and retained Phase 3/4 evidence regressions
  pass. This is same-repository same-process composition evidence with a
  reference media executor.

  Slice 15 implementation `024a768d51965f8949bacf3c97e499fb26a6e648`
  adds the strict independent-process release gate. Run
  `20260919T200125.484855000Z` passes 14 exact scenarios through separate
  Product, Gateway, Provider, Desktop, and Guest OS processes with fresh
  pinned PostgreSQL, the exact signed Desktop runtime, real X11 capture and
  fenced pointer control over public WebRTC/private mTLS, encrypted recording
  replay, actual Guest development materialization, Product/Gateway/Guest
  restart recovery, Provider-dependency fault closure, and exact cleanup. The
  exact gate topology derives Desktop/development capability readiness from
  live dependencies. The strict manifest rejects identity/scenario drift,
  incomplete cleanup, secrets, private coordinates, and host paths. This does
  not compose the production command or establish deployment, HA, hostile
  multi-tenant, independently implemented caller, or production readiness.
  Corrective commit `59de37d5ee22776305dfaab866c25ea6bd5406bc`
  deterministically closes the Provider media session before its private
  WebSocket closure becomes observable. E2E lock
  `d5d6ed1a815b49625a054d9931a8cec2234d8e7e` binds all eight
  parent checks to evidence/CI baseline
  `59de37d5ee22776305dfaab866c25ea6bd5406bc`; full E2E race/shuffle, vet,
  and all eight clean-checkout checks pass.

The qualification applies only to Provider revision
`170459266af5f4fad359ca8c63f2ae19741055c5`, external-caller revision
`b3ebcc783e5db20395e29b029e0eb55f7819b49b`, and the recorded Contract,
profile, artifacts, topology, and scenarios. Aggregate conformance,
multi-controller reliability, hostile multi-tenant isolation, HA, deployment,
and production readiness remain separate non-claims.

The Product Phase 1 result adds no implemented Product API, database migration,
public Gateway, Guest Agent, capability advertisement, deployment, or SLO
attainment claim. See
[`plan/product-v1-phase-1.md`](plan/product-v1-phase-1.md) for its exact output
and [`plan/product-v1-phase-2-provider-lifecycle.md`](plan/product-v1-phase-2-provider-lifecycle.md)
for the fixed nine-step Provider lifecycle closure plan. ADR 0048 and the
Step 1 audit and completion record include termination, reversible desired
state, lease renewal/expiry, resumable events, and terminal-session close; they
exclude resize and snapshot/restore from Phase 2. See
[`audits/phase-2-provider-lifecycle-completion.md`](audits/phase-2-provider-lifecycle-completion.md)
for the selected authority, release evidence, and exact non-claims.
The Phase 3 startup inventory, fixed slice order, and completion evidence are
recorded in
[`audits/phase-3-product-surface-startup.md`](audits/phase-3-product-surface-startup.md)
[`plan/product-v1-phase-3-product-kernel-terminal-files-web.md`](plan/product-v1-phase-3-product-kernel-terminal-files-web.md),
with the accepted standalone run in
[`audits/product-phase-3-standalone-completion.md`](audits/product-phase-3-standalone-completion.md).
Product Phase 4 startup scope and slice order are recorded in
[`audits/phase-4-product-browser-startup.md`](audits/phase-4-product-browser-startup.md)
and [`plan/product-v1-phase-4-browser.md`](plan/product-v1-phase-4-browser.md),
with the bounded release result in
[`audits/product-phase-4-browser-completion.md`](audits/product-phase-4-browser-completion.md).
Product Phase 5 startup findings, boundary decision, and fixed slice order are
recorded in
[`audits/product-phase-5-desktop-startup.md`](audits/product-phase-5-desktop-startup.md),
[`audits/product-phase-5-desktop-slice-2.md`](audits/product-phase-5-desktop-slice-2.md),
[`audits/product-phase-5-desktop-slice-3.md`](audits/product-phase-5-desktop-slice-3.md),
[`audits/product-phase-5-desktop-slice-4-candidate.md`](audits/product-phase-5-desktop-slice-4-candidate.md),
[`audits/product-phase-5-desktop-slice-4-publication.md`](audits/product-phase-5-desktop-slice-4-publication.md),
[`audits/product-phase-5-desktop-slice-5.md`](audits/product-phase-5-desktop-slice-5.md),
[`audits/product-phase-5-desktop-slice-6.md`](audits/product-phase-5-desktop-slice-6.md),
[`audits/product-phase-5-desktop-slice-7.md`](audits/product-phase-5-desktop-slice-7.md),
[`audits/product-phase-5-desktop-slice-8.md`](audits/product-phase-5-desktop-slice-8.md),
[`audits/product-phase-5-desktop-slice-9.md`](audits/product-phase-5-desktop-slice-9.md),
[`audits/product-phase-5-desktop-slice-10.md`](audits/product-phase-5-desktop-slice-10.md),
[`audits/product-phase-5-desktop-slice-11.md`](audits/product-phase-5-desktop-slice-11.md),
[`audits/product-phase-5-desktop-slice-12.md`](audits/product-phase-5-desktop-slice-12.md),
[`audits/product-phase-5-desktop-completion.md`](audits/product-phase-5-desktop-completion.md),
[`adr/0050-product-desktop-phase-5-boundary.md`](adr/0050-product-desktop-phase-5-boundary.md),
and
[`plan/product-v1-phase-5-desktop-development-unified-product.md`](plan/product-v1-phase-5-desktop-development-unified-product.md).

See [`STATUS.md`](STATUS.md) for the complete evidence ledger and
[`qualification/external-caller-coding-shell-v1.md`](qualification/external-caller-coding-shell-v1.md)
for the exact qualification boundary.

## Start Here

Read this document after `AGENTS.md`, then verify the checkout before relying on
the snapshot:

```bash
git status --short --branch
git branch -vv
git rev-parse HEAD main origin/main
git log --oneline --decorate -8
```

Preserve uncommitted work. Do not reset, switch away from a dirty checkout, or
assume that a recorded evidence baseline is the current `HEAD`.

Use these sources in authority order:

1. The repository-owned MIT Provider Contract under `contract/`, including its
   Provider Calling Standard, OpenAPI, JSON Schemas, semantic rules, fixtures,
   Conformance Suite, and
   `compatibility/sandbox-runtime/contract.lock.json`, defines authorized wire
   behavior and caller obligations.
2. The independent Product Contract under `product-contract/` defines the
   target client-to-Product control protocol. It is Phase 1 design authority,
   not implementation or readiness evidence.
3. [`architecture.md`](architecture.md) and accepted
   [ADRs](adr/) define ownership, boundaries, delivery order, and release
   gates.
4. [`development.md`](development.md) and `AGENTS.md` define engineering and
   validation rules.
5. [Phase plans](plan/README.md) refine implementation slices without relaxing
   architecture gates.
6. [`STATUS.md`](STATUS.md) is the detailed evidence ledger. Code, Git state,
   and reproducible test or CI results must still support every status claim.

Start external integrations with the normative
[`Sandbox Provider Calling Standard`](../contract/specification/provider-calling-standard-v1.md).
The [`Provider Integration Guide`](platform-integration-profile.md) is a
non-normative implementation summary; the Contract resources and lock remain
authoritative.

When sources disagree, do not silently blend them. Apply the higher-authority
source, verify the implementation, and update the stale narrative document.

## System in One Page

`sandbox-runtime` is a backend-independent sandbox Provider and local runtime
control plane. The first intended compatibility profile is coding and remote
shell. Browser, desktop, snapshots, GPU, and stronger isolation remain optional
until their own Contract and evidence gates pass.

Three API surfaces must remain separate:

| Surface | Purpose | Ownership boundary |
| --- | --- | --- |
| Local `/instances` API | Local instance management over fake or Docker drivers | Internal implementation; its DTOs and state are not Provider wire models |
| Provider API v1 | mTLS/JWS-protected asynchronous Provider protocol | Repository Contract controls routes, documents, semantics, and projection |
| Target Product API v1alpha1 | End-user Workspace control plane | Independent Product Contract; Slice 2 handler subset with empty capabilities and no deployable listener |

The calling service owns its business correlation records, desired business
state, tenant/user authorization, ProviderRevision selection, Artifact
publication, billing/accounting, aggregate operation ledger, and public Gateway
policy. It adapts to this repository's Contract; the Provider does not carry a
consumer-specific adapter.
The target Product is the calling service defined by ADRs 0042-0047. It owns
Workspace aggregates, user/Agent authorization, Product operations, outbox,
reconciliation, sessions, public Gateway policy, and catalogs. This repository
owns provider-local execution, durable Provider operations,
runtime/session resources, and bounded evidence. Provider storage references
and backend endpoints are never public artifact URLs or client endpoints.

Protected admission uses one caller trust domain per listener. The issuer is an
explicit exact value with no default or fallback; the Provider-instance
audience and Provider revision are local startup anchors rather than facts
accepted from the bearer or Admission Context. The listener freezes 1..32
issuer-scoped verification keys and its admitted URI SAN identities. One
listener does not currently support multiple issuers or consumers.

Dependencies point inward:

```text
Provider HTTP/mTLS/JWS transport
              |
              v
application policy and coordinators
              |
              v
repository and capability ports
              |
              v
runtime, persistence, session, and evidence adapters
```

Provider operations are asynchronous and preserve idempotency, attempts,
fencing, deadlines, cancellation, and unknown-outcome reconciliation. A
compatible coding/shell runtime must eventually expose stable guest paths
`/inputs`, `/workspace`, `/outputs`, and `/tmp`. Terminal clients receive only
an expiring opaque handoff; a Runtime Gateway resolves and proxies the internal
endpoint after its own authorization.

The default security posture is deny and fail closed. Do not expose backend
IDs, host paths, raw endpoints, daemon diagnostics, credentials, or secrets.
The existing Docker defaults and mTLS admission are useful component controls,
but they are not evidence of hostile multi-tenant isolation or production
readiness.

## Development Contract

- Keep transport, application policy, repositories, and runtime drivers in
  separate packages. Provider DTOs must not reuse local `instance` or backend
  engine structs.
- Preserve `context.Context` cancellation and deadlines for external work.
- Reject unknown, malformed, and oversized input before mutation when the
  Contract requires it. Unsafe production configuration must fail closed.
- Use narrow optional capability interfaces. Advertise a capability only when
  the complete configured dependency set and its named gate pass.
- Scope each change to one delivery slice. Ownership, public protocol,
  reliability, or security-boundary changes require an ADR and coordinated
  Contract review.
- Preserve unrelated worktree changes. Never turn local callbacks, fakes, or
  same-repository tests into external compatibility claims.

For Go changes, format with `gofmt` and run:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

For driver or lifecycle changes, also run the tagged Docker integration test in
an available Docker environment. For Contract metadata, DTO, Provider API, or
conformance changes, also run:

```bash
go run ./cmd/verify-contract -source-root .
runner_dir="$(mktemp -d)"
go build -buildvcs=true -o "$runner_dir/run-conformance" ./cmd/run-conformance
"$runner_dir/run-conformance" -source-root . -race -shuffle
```

The local Suite runner requires a clean VCS-built binary, records its revision
and Go version from build information, and executes a bounded read-only archive
of that revision. Every case declares an exact mapped-test count and requires
all matching tests to appear as distinct, started, non-skipped passes in `go
test -json`. The Runner rejects an explicit `GOROOT`, resolves Git once to a
single absolute executable path reused for verification and archive creation,
and records that the host OS, filesystem, initial Git selection, and Go and Git
executables remain trusted local inputs. `go run ./cmd/run-conformance` lacks
the required VCS settings under Go 1.26.5 and correctly fails. The separate
remote discovery prerequisites and command are documented in
[`compatibility/sandbox-runtime/README.md`](../compatibility/sandbox-runtime/README.md).

Record an unavailable environment separately from a failed test. Keep these
evidence tiers distinct: component, Contract projection, CI, Provider
admission, external caller E2E, aggregate conformance, multi-controller,
multi-tenant, deployment, and production readiness.

## Current Snapshot

The selected Product Phase 2 implementation snapshot is
`98995384c60a924f25ca58d3b7e561207bfa5be8`; lock-selection revision
`3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1` binds its exact Provider Contract
tree and E2E metadata. No remote CI result is assigned to these local release
revisions.

The latest remotely verified documentation baseline remains
`27081dfde4dfc726ba4df06d1f3b50012a04d2f2`. Core CI run `35204434771`
passed all six jobs, including the current Contract and clean VCS-built local
Suite, full race tests, vet, Docker integration, Browser provenance, and the
Ubuntu/macOS qualification-supervisor matrix. The detailed component ledger
below retains older per-gate commits and run IDs because those identify exact
historical evidence rather than the newest documentation commit.

The ADR 0038 calling-standard slice remains implemented. The current Contract
authority is revision `720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`, and a content-derived 71-case
local Suite. Product Phase 5 Slice 1 maps every case to executable repository
tests and keeps Desktop advertisement disabled. The historical Phase 2
60-case Runner, remote Runner, hosted CI, Product Phase 3/4, and external-caller
results retain their recorded identities and are not relabeled as current
runs. Product Phase 5 Slice 2 separately adds Product Desktop intent at
implementation `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`. Slice 3 adds
Provider-local Desktop authority and optional protected handlers at
`f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5`; neither slice changes the
Provider Contract identity or any historical result, and Slice 3 is not
production startup composition or capability advertisement.
The independently implemented caller result is instead the separate bounded
P2.7 qualification recorded above. Rotation remains operator-driven, and
protected/mutating remote conformance, aggregate conformance, multi-controller,
hostile multi-tenant safety, HA, deployment, and production readiness remain
outside the completed first-version claim.

This snapshot was audited on 2026-09-06 against browser Contract authority
`5096e71fb84fbec22aa3487a0e55a1b49602ab8b`, Provider projection baseline
`24b2e36485c334634e561009850d1905ec3115d5`, browser session implementation
`9a5d225f793f37ccafdac31c276ccbcb1bc862ad`, sandbox/provenance implementation
`6e02f1c22f489802b0b2c9f06f4a807d2e7c36e5`, Browser Docker adapter
`cd33ba35c59bba62c48d13c0dcd08aeef5d9a434`, Browser provenance verifier
`939055475f73b0023b3946172a2c40750a99c7ea`, Browser restricted-egress and
create-policy implementation `7e60340`, protected Browser transport
implementation `b8423f5`, caller-owned Browser Gateway implementation
`5aae2810c4957ec7abad7de0e67f9507d9543c81`, default-disabled Browser command
composition `66183b1f49b22c211e43c841d15383b745e89967`, Browser DNS compatibility
implementation `f760369dd4b71f507b15a2aecf988e98ca74854b`, Browser Gateway local
capacity implementation `7b062e6511f73b916dd18977041d83732e590088`, Browser
pre-upgrade edge implementation `44ea2eecc75752870d4e8580a75be26578dcd63a`,
Browser listener/TLS/HTTP implementation
`b8f89413cb34110793fa552ba1620f1529f6f416`,
Browser authenticated-capacity implementation
`997fb0db9d3517cf1c3e153217b1ac7305b4ebfd`, its co-located E2E lock
`49d1c20`, and hosted harness/evidence baseline
`6b01b75f0e1f6ca1c60f033f8d5bab3898720a3b`, plus Redis-compatible shared
capacity implementation `94345407c149eb095f27ac1c51f60fa38a16a4af`,
shared-capacity Provider baseline
`2ed5e689f68627c2d7c8e96cf903fc001ea4a546`, and local evidence
harness/Gateway source `ddbb2c4771a356bc3ab66295c93bef3b749e2c09`, plus hosted
shared-capacity harness/Gateway source
`de297e7d951881f8ed3792b4c3dd0553be87284c` and run `33949577876`, plus
durable exact-grant revocation component implementation
`c0a55d1e0a862f9e5a592abd27b1e25be3c85b3e` and earlier regression E2E
lock/harness baseline `59e08d542b05ad1a047f439f4ea72e82c8c37404`, plus durable-revocation
harness/Gateway source `e952ef9dabf4e9e6f2a984ce0c7944cb2bc569c7`, local run
`20260905T095109.569973000Z`, and hosted run `33959122456`, plus downstream CDP
fencing component and real-backend adapter integration implementation
`b4d41c9a32b4ccf39edaba3fb8bf5ad239c1f945`, downstream caller bootstrap
implementation `58488d70c0a43d68747ca6e14f81c56f1e23237a`, caller provisioning/process
implementation `8a1049bfa1d68bdd88c9df3ebd02c2c9ac0434b5`, local downstream-fencing
harness/run `550c7855704f22809e989ede0f67240033f320ba`/
`20260906T050213.016063000Z`, and hosted downstream-fencing harness/run
`2cadc534e54c6eacd37497887820a157a89585f5`/`34013982796`, plus fixed witnessed
v2 harness `059357cdd1f6f4ecd78ccbbaf9923add0fcd2230`, local run
`20260906T100233.295973000Z`, and hosted run `34026680591`, plus PostgreSQL
controlled-restore implementation `ffa40d643605e51d4ea1baebab1bd3f8bd710b5f`,
PR #47 merge `a0cddf40d07f9ad81b02d3eb028f141aeb424228`, and post-merge run
`34038556283`. The later main run `34069851741` at
`838d3bb2dea52c10fdc1ddf3136641709fedcb20` is the current canonical ADR 0036
run and passes the same 18/18 profile. Its independently inspected artifact is
`browser-postgres-controlled-restore-e2e-evidence-34069851741`, ID
`10000177842`, digest
`sha256:96817b74f3faabb0226d7dee1f2ac8128901865a3834f9bcadcaae6459b76032`.
Merge commit `a0cddf4` also passes repository CI `34038556281`,
Reference `34038556295`, Candidate `34038556284`, Browser `34038556297`,
shared-capacity `34038556314`, durable-revocation `34038556293`,
downstream-fencing v1 `34038556291`, downstream-fencing v2 `34038556299`, and
PostgreSQL witness `34038556301`. These remain distinct evidence tracks.
The Contract slice authorizes an atomic browser-only capability shape,
create/session/handoff schemas, protected admission bindings, opaque reference
security, operation/usage projection, and 10 new Suite cases. The browser image
component is implemented under
`profiles/browser/image/`. The Provider-local browser
session/application/reference/usage component is implemented under
`provider/browser/`. ADR 0020 and `provider/browser/driver/docker` add a
fail-closed Docker adapter for that runtime port. ADR 0023 and
`b8423f5` add protected Browser open/handoff routing, admission correlation,
bounded error projection, and opaque response projection through a narrow
application port. ADR 0024 and `5aae281` add a separate caller-owned Browser
Gateway component with exclusive Browser identity/reference binding, explicit
authorization/revocation/audit/WebSocket-admission dependencies, bounded
reconnect, and RFC 6455 CDP framing. ADR 0025 and `66183b1` add an explicit,
default-disabled Browser Provider graph. ADR 0026 and the co-located harness add
a separate Browser-only reference stack and black-box caller. ADR 0027 and
`7b062e6` add non-blocking process-local total/per-session connection capacity
before revocation and Provider resolution. ADR 0028 and `44ea2ee` add
process-local global connection/fixed-window request control before Browser
WebSocket admission and upgrade. ADR 0029 and `b8f8941` add a separate bounded
accepted-connection listener, frozen server-auth certificate, TLS
1.3/HTTP/1.1-only policy, header/time limits, and context-aware lifecycle for
the reference Gateway. ADR 0030 and `997fb0d` add an authenticated-capacity
port after exact grant binding, typed loss/unavailability events, bounded
release, stable revocation/expiry/capacity termination priority, and a
process-local memory reference with atomic global, tenant, and session
accounting. Browser composition requires the port. ADR 0031 and `9434540` add
a Redis-compatible implementation with one bounded atomic capacity record,
server-time leases, renewal, TTL reclamation, and stale-owner fencing. The
production command still exposes no public Browser Gateway route and does not
advertise Browser; only the reference stack advertises the exact locked Browser
profile.

The Contract verifier and root race/shuffle and vet gates pass against the
current projection. E2E race/shuffle passes except for its intentional clean
parent-checkout test, and E2E vet and all other lock tests pass. Clean Docker
reference run `20260907T044611.598221000Z` at harness
`b8d4829` and Provider baseline `af8a505` passed 15 initial and 5
process-reconstruction/resume coding/shell scenarios over real mTLS/JWS HTTPS,
WebSocket, separate caller/reference-stack processes, and Docker. Its manifest
SHA-256 is `60bda2dae83053db447417cea5c5e38d4798e1e90b91fbb5cfc75d2991c6993e`
and it pins locally built linux/amd64 runtime digest
`sha256:60baefac927a0a77743aeca268b271b62b07079f31521f98fd3a4cb33474a999`.
This is same-repository reference evidence; it does not execute the then-current
50-case
Suite or qualify an independently implemented caller. An earlier clean
reference run `20260904T081521.464863000Z` passed 15 initial and 5
process-reconstruction/resume coding/shell scenarios over real mTLS/JWS HTTPS,
WebSocket, separate caller/reference-stack processes, and Docker. Its manifest
pins Provider `44ea2ee`, harness `249cdd4`, the Contract, and linux/amd64 runtime
image digest
`sha256:bcd5dbff8b2d108ee7dab464a85ee7d39ef74a8616a6af73a94ebb10ff8eaf75`.
This is reference coding/shell evidence only; it does not exercise browser.
Hosted Reference E2E run `33854020874` passed the same 15 initial and 5
reconstruction/resume coding/shell scenarios against harness/Provider lock
`e7e7f03`/`44ea2ee`. Its artifact
`reference-e2e-evidence-33854020874` has digest
`sha256:220650f1b61b0297ec445ded03bf3a15870514a9482c9e55012ddfba8ae0da2d`.
This remains reference coding/shell evidence only and contains no browser
scenario.

The explicitly named `agent-platform-candidate` mode passed local run
`20260904T081706.648122000Z` against harness/Provider lock
`249cdd4`/`44ea2ee`: 15 initial and 5 resume coding/shell scenarios over
separate `platform-caller` and `reference-stack` processes with candidate
shadow/selection/rollback/drain policy and state reconstruction. Hosted
workflow run `33854020947` passed the same scenario set against
harness/Provider lock `e7e7f03`/`44ea2ee`. Its artifact
`platform-candidate-e2e-evidence-33854020947` has digest
`sha256:48cbe44c433e5b3a858a2691fe1f736469b2e8d71228541f2bdfcc4aab1c15b1`.
Local and hosted candidate results do not represent browser evidence, real
Veronica, aggregate conformance, hostile multi-tenant security, deployment, or
production readiness.

Hosted Browser Reference E2E run `33854020809` passed all 12 initial and 5
process-reconstruction scenarios against harness/Provider lock
`e7e7f03`/`44ea2ee`. The path uses separate reference-stack and black-box caller
processes over mTLS/JWS HTTPS and a caller-owned WebSocket Gateway, the exact
signed `linux/amd64` Browser image, real GitHub OIDC/Sigstore provenance,
restricted egress, durable state, duration usage evidence, and exact resource
cleanup. The capacity scenario holds one CDP connection, rejects a second
same-session grant without disrupting the first, and connects a replacement
after release. The edge scenario sends 16 authenticated wrong-Origin requests,
observes ordinary `403` plus generic pre-upgrade `429` with bounded
`Retry-After`, and recovers. Artifact
`browser-reference-e2e-evidence-33854020809` has digest
`sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`.
Its inspected run directory `20260904T083407.182245415Z` pins the Contract/tree,
48-case Suite, signed Browser image, and `linux/amd64`. Both reports contain
only passing scenarios. The 20-record metadata-only Gateway audit has six
`authorized`, six `connected`, four `client_closed`, and one each
`capacity_rejected`, `denied`, `expired`, and `revoked`; it contains no
`grant-browser-edge-*` identity, endpoint, token, or CDP payload. This closes
the process-local post-authorization capacity and pre-upgrade Browser service
scenarios within the Browser reference external-caller gate only.

Clean local Browser run `20260904T080946.250607000Z` then passed 12 initial and
5 process-reconstruction scenarios against harness/Provider lock
`249cdd4`/`44ea2ee` on `linux/arm64`. ADR 0028 adds a process-local global
connection and fixed-window request gate before Browser WebSocket admission and
upgrade. The added black-box scenario sends 16 authenticated wrong-Origin
requests, observes ordinary `403` plus generic pre-upgrade `429` with bounded
`Retry-After`, and observes ordinary `403` again after the window. The
20-record Gateway audit retains the six `authorized`, six `connected`, four
`client_closed`, and one each `capacity_rejected`, `denied`, `expired`, and
`revoked` events, with no `grant-browser-edge-*` identity.
At that baseline, listener/TLS/HTTP-layer limits remained open, together with
partition-aware shared or distributed capacity, durable distributed revocation,
production advertisement, generic-consumer interoperability, aggregate, multi-controller,
hostile multi-tenant, deployment, and production gates.

ADR 0029 and implementation `b8f8941` then add the bounded public TLS edge.
Clean local Browser run `20260904T091156.303717000Z` passed 13 initial and 5
process-reconstruction scenarios against harness/Provider lock
`35cf068`/`b8f8941` on `linux/arm64`. Hosted Browser run `33857739150` passed
the same 13+5 set against harness/Provider `7a20d9d`/`b8f8941` on
`linux/amd64`. The new black-box scenario rejects TLS 1.2, negotiates TLS 1.3
with HTTP/1.1, rejects slow and oversized request headers before the handler,
holds the configured accepted-connection limit, and recovers after release.
Artifact `browser-reference-e2e-evidence-33857739150` has digest
`sha256:94bcdfa53b667d4a6bc17fd6714cc9895e8402b830b8c6425c604c835f9228f`;
its inspected run directory is `20260904T091942.992885726Z`. Its 20-record
Gateway audit retains the prior type counts and contains no edge grant, token,
endpoint, credential, CDP, or payload field. This closes the listener/TLS/HTTP
component and Browser reference-caller scenario only. Authenticated
partition-aware shared or distributed capacity, durable distributed
revocation, production storage/configuration and metrics, production
advertisement, generic-consumer interoperability, aggregate, multi-controller, hostile
multi-tenant, deployment, and production gates remain open.

ADR 0030 and implementation `997fb0d` then add the post-binding
authenticated-capacity port and process-local global/tenant/session memory
reference. Hosted repository CI `33940332882` passes `provider-contract`,
`test`, `browser-provenance`, and `docker-integration`. Hosted Reference,
Candidate, and Browser runs `33940332897`/`33940332881`/`33940332911` all pin
harness `6b01b75`, Provider `997fb0d`, the Contract/tree, and 48 cases.
Reference and Candidate pass their separately named 15+5 coding/shell sets;
their artifacts have digests
`sha256:c5294520236200c06597bcc383455b9a74cb3668557cce313ab7e4dab0af0537`
and
`sha256:5fad63cd7dfc863af83faf2e5324529852cc8b741deeac5414f12d5fd0dd26f5`.
Browser passes 13+5 on `linux/amd64`; artifact
`browser-reference-e2e-evidence-33940332911` has digest
`sha256:f4133967b6e573c701b82c72dc4d101febd4e6b28199e188fa0c8db049bff9ae`.
Its active contention scenario reaches the authenticated memory authority, and
the 20-record metadata-only Gateway audit retains six `authorized`, six
`connected`, four `client_closed`, and one each `capacity_rejected`, `denied`,
`expired`, and `revoked`. This is a single reference Gateway process, not a
shared backend or two-Gateway-process capacity result. TTL/renewal, crash
reclamation, stale-owner fencing, durable distributed revocation, real Agent
Platform, aggregate, multi-controller, hostile multi-tenant, deployment, and
production gates remain open.

ADR 0031 and implementation `9434540` then add the Redis-compatible shared
capacity adapter, followed by the WebSocket close and deterministic stale-lease
harness and edge-timing corrections through `ddbb2c4`. Clean local evidence
`e2e/evidence/shared-capacity/20260905T061037.558537000Z` passes all 10 scenarios
on `linux/arm64` through two independent Gateway OS processes and a real pinned
Valkey authority. It covers cross-process global/tenant/session contention,
unaffected-tenant service, renewal beyond three lease TTLs, confirmed loss,
Gateway crash reclamation, stale-owner fencing, renew/release cleanup,
retained-store outage failure closure and recovery, and evidence sanitization.
Shared-capacity rejection occurs after WebSocket `101` and is observed as a
normal `1000` close, not the pre-upgrade limiter's HTTP `429`. The manifest pins
harness/Gateway source `ddbb2c4`, Provider baseline `2ed5e68`, policy fingerprint
`1b29321807530907a8407cd6d33bdefbbb980fd7cb0b297592181a2333a8bacd`, Valkey
index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`,
and arm64 child
`sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e`.
Valkey provenance is explicitly not established. The Contract revision/tree
and 48-case Suite are pinned as metadata with `exercised=false`; Provider API,
real Browser/CDP, image provenance, restricted egress, artifact/usage, HA,
durable distributed revocation, downstream fencing, Provider multi-controller,
hostile multi-tenant, generic-consumer interoperability, deployment, and production gates are
not established by this local run.

Hosted Browser Shared Capacity E2E run `33949577876` independently passes the
same 10 scenarios on `linux/amd64` against harness/Gateway source `de297e7` and
Provider baseline `2ed5e68`. Artifact
`browser-shared-capacity-e2e-evidence-33949577876` has GitHub digest
`sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`;
its downloaded run directory `20260905T062246.271594332Z` contains exactly the
manifest, report, two audit logs, and two observation logs. All 10 report
entries pass. The combined audits contain 22 `authorized`, 22 `connected`, 18
`client_closed`, five `capacity_rejected`, two `capacity_lost`, and two
`capacity_unavailable` records; the observations contain 22 `resolve` and 22
`dial` records. The manifest pins the same Contract/tree/48-case metadata with
`exercised=false`, the same Valkey index, amd64 child
`sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478`,
and `provenance_not_established=true`. This is hosted Gateway/Valkey
shared-capacity evidence only; it does not exercise Provider API, real
Browser/CDP, image provenance, restricted egress, Provider artifact/usage,
HA/failover, durable distributed revocation, downstream fencing, Provider
multi-controller, hostile multi-tenant, generic-consumer interoperability, aggregate,
deployment, or production behavior.

ADR 0032 and implementation `c0a55d1` then replace the split revocation
check/watch with one exact-grant level-triggered watch, cancel blocked Provider
resolution and dial work when the authority terminates, and add a
Redis-compatible retained-tombstone source/writer. The adapter verifies an
immutable policy, hashes namespace and grant identities, uses Redis server time
to bound grant lifetime and tombstone expiry, preserves the greatest expiry
under duplicate or out-of-order revoke, polls within bounded operations, and
fails closed on malformed state or authority loss. Focused/full race-shuffle,
vet, Contract verification, the unchanged 48-case Suite, and the tagged real
pinned-Valkey component integration pass locally. This establishes Gateway
revocation port semantics plus one retained-backend adapter component only.

Historical E2E lock `59e08d5` pins Provider `c0a55d1`. Its local Browser run
`20260905T080015.795386000Z` passes 13+5 scenarios, Reference run
`20260905T080530.577843000Z` and Platform Candidate run
`20260905T080623.861033000Z` each pass 15+5, and shared-capacity run
`20260905T080725.227680000Z` passes 10/10 on `linux/arm64`. These are regression
evidence within their existing names: Browser still uses one process-local
memory revocation authority, and shared capacity does not exercise revocation.
Harness/Gateway source `e952ef9` now supplies the separate durable-revocation
runner. Local `linux/arm64` run `20260905T095109.569973000Z` and hosted
`linux/amd64` run `33959122456` each pass all seven locked scenarios through
two independent Gateway OS processes, two independent black-box caller
processes, an independent revoker/control process, and the same retained Valkey
authority. They prove active and pre-resolution revocation, restart retention,
exact-grant scope, outage failure closure, recovery without resurrection,
bounded propagation, and sanitized evidence. The hosted artifact has digest
`sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`.
Contract/tree/48 cases are metadata with `exercised=false`; the fixture is not
a real Browser/CDP path, and downstream CDP fencing remains a separate later
ADR and gate.

Hosted pre-ADR0033 repository CI `33955437033` passes at repository revision
`c7fe24d`. Reference, Candidate, Browser, and shared-capacity runs
`33955436969`, `33955437046`, `33955436984`, and `33955436968` pass with harness
`c7fe24d` locked to Provider `c0a55d1`.
Downloaded artifacts pin the unchanged Contract/tree/48 cases and contain only
passing 15+5 Reference, 15+5 Candidate, 13+5 Browser, and 10/10 shared-capacity
reports. Their GitHub digests are recorded in `STATUS.md`. Browser still uses
the process-local memory revocation authority, while shared capacity still does
not exercise revocation, so these hosted runs also do not close ADR 0032's
independent caller gate.

The later dedicated hosted run `33959122456` is the separately named ADR 0032
caller gate; it must not be conflated with those four regression tracks.

ADR 0033 and implementation `b4d41c9` then add narrow downstream action-fence
ports, a Redis-compatible exact-member/session-high-water authority adapter, a
private ingress component that serializes complete CDP actions, and explicit
fail-closed Browser composition. Targeted and full race/shuffle tests, vet,
Contract verification, the unchanged locked 48-case Suite, and tagged real
integration against pinned Valkey index
`sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
pass. Local run `20260906T050213.016063000Z` at harness `550c785` additionally
passes all 13 ADR 0033 external-caller scenarios on `linux/arm64` through two
Gateway processes, two independent mTLS/JWS caller processes, one authenticated
unique ingress, retained Valkey state, and signed real Chromium. This closes
the local named caller gate; hosted run `34013982796` passes the same 13
scenarios on `linux/amd64` and closes that platform-specific caller gate. Its
artifact digest is
`sha256:9c00f3ba184e82d7eff661b831c05c1bdf331fa41caf2d8bbb3353168ab155b0`.
The Contract/tree/48-case identity is pinned, but the Suite is not exercised.

ADR 0034 then adds a separately selected v2 action-fencing component. One
bounded permanent Redis hash detects missing or malformed retained session
history, and an independent sequence/token witness rejects a Redis action state
restored behind it. The included Darwin/Linux `0600` file witness is
single-process component evidence and is valid only outside the Redis
snapshot/restore domain. Local focused/full race-shuffle, vet, Contract
verification, the unchanged 48-case Suite, and tagged integration against the
same pinned Valkey index pass. The existing downstream caller results still use
ADR 0033 v1, so neither prior run is deletion/restore evidence. A separately
locked 18-scenario v2 real-Chromium runner is implemented with an independent
file witness and orchestrator-only Redis fault credential. Clean local run
`20260906T100233.295973000Z` at fixed harness `059357c` passes all 18 scenarios
on `linux/arm64`, including retained-field and complete-state deletion,
restored-old snapshot rejection with the same numerical capacity fence, witness-adapter
reconstruction, exact one-ahead recovery, other checkpoint mismatch rejection,
and proof of no new upstream dial before the rejected actions. Its exact five
`0600` files pass cleanup and sanitization. This closes only the local ADR 0034
caller gate. Hosted run `34026680591` at the same checkout independently
passes the same 18 scenarios on `linux/amd64`. Its inspected artifact contains
evidence directory `20260906T101111.796974798Z` with exactly five sanitized
files; artifact ID `9987350368` has digest
`sha256:3e68f1c4b5bd74e0ae0ff0fde2c9ffefc63852cf9fc82b3019bedfb228bf2c9a`.
This closes only the hosted ADR 0034 caller gate; the Suite remains unexercised.
Production witness/storage, Valkey provenance/HA/failover, production
metrics/configuration and topology, deployment, multi-controller, hostile
multi-tenant, generic-consumer interoperability, aggregate conformance, and production
readiness remain unproved.

ADR 0035 now adds a PostgreSQL production-candidate witness adapter and strict
read-only `VerifyRestoredState`. Rows are isolated by both the private capacity
namespace digest and witnessed-v2 policy digest; mutations use atomic
conditional updates, force primary-local synchronous commit, preserve bounded
contexts, and redact database detail. The repository includes an explicit
migration, column-scoped runtime grants, real PostgreSQL/Redis integration
tests, and a separate workflow. Local full race/shuffle, vet, Contract
verification, the unchanged 48-case Suite, and the pinned-Valkey strict
one-ahead non-mutation case pass. Hosted workflow run `34031784793` at
implementation `3ff58dc` passes the exact migration, runtime and denied roles,
concurrent CAS/reconnect, missing and malformed state, bounded pool starvation,
and combined pinned-Valkey rollback cases against real PostgreSQL. Its initial
tag pull resolved PostgreSQL digest
`sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`,
which the workflow now pins. The local service remained unavailable. This is
not production or HA evidence; independent failure and backup domains, server
provenance, both stores' HA/failover, deployment, correlated rollback, and
deployment-owned controlled ingress operations remain open.

ADR 0036 now implements a separately locked same-runner operational reference
for the controlled ingress sequence. Its 18-scenario runner retains the first
ten real-Chromium fencing scenarios, stops both Provider/private-ingress
listeners, proves the live Gateways have no alternate downstream path, restores
an older Redis snapshot, and requires strict `VerifyRestoredState` to reject it
without advancing PostgreSQL or opening a listener. It then restores the exact
current Redis state, verifies without mutation, resumes the listeners, and
performs a real-CDP read and write. The runner uses an orchestrator-only Redis
restore credential and a PostgreSQL runtime role available only to the
orchestrator and Provider/private-ingress process. The latest canonical
`linux/amd64` main run is `34069851741` at
`838d3bb2dea52c10fdc1ddf3136641709fedcb20`; all 18 scenarios pass. Its
independently inspected artifact
`browser-postgres-controlled-restore-e2e-evidence-34069851741` contains
evidence directory `20260907T002737.609312407Z` with exactly five sanitized
files; the report is 18/18, and the manifest records three ingress
reconstructions, every cleanup and sanitization flag true, no file-witness v2
field, PostgreSQL restore evidence, and an unexercised Contract Suite. Artifact
ID `10000177842` has GitHub digest
`sha256:96817b74f3faabb0226d7dee1f2ac8128901865a3834f9bcadcaae6459b76032`.
This closes only the hosted same-runner ADR 0036 operational reference gate.
The lock and manifest record `same_runner=true` and
`independent_failure_domain=false`; this adds no independent host, storage,
backup, operator, HA, deployment, or production evidence.

Intermediate hosted run `34025787520` at documentation checkout `ef63be4`
failed in the restore-control verification rather than the fencing behavior.
The helper compared post-`RESTORE` hash `DUMP` bytes with the original dump,
although that binary encoding is not a canonical logical hash representation.
Fix `059357c` keeps real `DUMP`/`RESTORE` injection and instead compares Redis
type, logical string/hash/zset content, missing-key state, and TTL semantics.
The fresh local and hosted runs above establish the fixed-harness evidence.

ADR 0018 records the original reproducible browser image component, while ADR
0019 requires the current `sandbox.runtime/browser-image/v2` sandbox posture
and signed publication. The image has no `--no-sandbox` path and binds a
fail-closed Chromium seccomp profile with digest
`sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`.
Local arm64 and amd64 integration runs returned Chromium `151.0.7922.109` over
loopback, found a sandboxed zygote, and retained the numeric user, read-only
root, drop-all, no-new-privileges, network-none, mount, and resource controls.
Manual publication run `33724368530` passed both native-architecture gates and
published
`ghcr.io/shell-echo/sandbox-runtime-browser@sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`
under tag `sha-58ed0093816d3daa3000750013b8e5991ef4bcf7`. Attestation `44912296`
binds the GitHub OIDC/Sigstore signer to this repository, workflow, source
commit, and hosted runner, and a constrained `gh attestation verify`
invocation succeeded independently. Independent registry inspection found
exactly `linux/amd64` and `linux/arm64/v8` descriptors and no extra manifest.
This closes the exact browser image sandbox/provenance publication gate. No
Provider route, Gateway composition, advertisement, or caller scenario is
implied by the publication evidence.

ADR 0020 and the Browser Docker adapter machine-bind that exact publication,
the checked-in seccomp profile, numeric identity, bounded stable guest mounts,
finite resources, durable private allocation state, and a fresh non-TTY relay
to container-loopback CDP. Focused/full race-shuffle, vet, Contract verification,
the unchanged 48-case Suite, and the tagged Docker driver matrix pass locally.
The live Browser case deliberately uses `network=none`; it proves private CDP
discovery, RFC 6455 upgrade, and `Browser.getVersion` only, not restricted
egress or complete runtime startup. The public adapter still requires
provenance verification and restricted-network implementations and fails
closed without them. ADR 0021 and `provider/browser/provenance/ghcli` provide
the real provenance-verifier component. It pins and
rehashes an operator-supplied `gh` executable, verifies the immutable GHCR
bundle against exact GitHub OIDC/Sigstore identity and signed statement fields,
bounds output and environment inheritance, and preserves cancellation. Its
tagged live GHCR integration passes locally. ADR 0025 wires the exact verifier
only inside the default-disabled Browser graph.

ADR 0022 and implementation `7e60340` add the restricted-egress Gateway process,
Docker provisioner, and immutable lifecycle/create-policy binding. Each
allocation receives an internal bridge; the Browser has only that network and
the Gateway private IP as DNS, while the Gateway has that bridge plus one
explicitly owned uplink. DNS, HTTP Host, TLS SNI, resolved public-address,
image/container/network identity, policy digest, lease, and restart checks fail
closed. The original combined local tagged integration passed allowed
HTTP/HTTPS navigation, denied unlisted and metadata targets, reconstruction,
and exact cleanup. Implementation `f760369` additionally accepts only zero
additional DNS records or one bounded RFC 6891 EDNS0 OPT record; malformed,
repeated, non-OPT, wrong-version, unsafe-flag, and oversized forms remain
rejected. The current local tagged rerun reached the real provenance verifier
but timed out there after 120 seconds, so it is recorded as unavailable external
provenance rather than a passing or failing network scenario. Hosted Browser
run `33838215924` independently passes the complete restricted-egress scenario
on `linux/amd64` with this fix.

ADR 0023 and `b8423f5` compose the two protected Browser handlers behind
existing mTLS/JWS/admission controls. ADR 0024 and `5aae281` compose the
caller-owned Browser Gateway boundary with exclusive terminal/Browser identity,
exact endpoint binding, metadata-only audit, bounded reconnect/revocation, and
RFC 6455 validation. Caller authorization, revocation, recording, WebSocket
admission, and reconnect policy remain explicit dependencies. ADR 0025 and
`66183b1` bind those Provider-local runtime dependencies into a fail-closed,
default-disabled command graph with durable recovery and cleanup. It still adds
no Provider-owned user authorization, production Browser advertisement, or
public Browser Gateway. ADR 0026 and `79fee2b` supply those caller-owned policies
only in a separate reference deployment and first proved the complete 10+5
Browser external-caller path in hosted run `33838215924`. ADR 0027 and
`7b062e6` add process-local connection capacity; capacity harness `28a9a5e` and
hosted run `33846603547` add its active rejection/release scenario without
changing the production advertisement boundary. ADR 0028 and `44ea2ee` add the
process-local pre-upgrade connection/rate gate, and harness `249cdd4` proves its
rejection, recovery, and Gateway-audit exclusion locally; hosted run
`33854020809` passes that 12+5 baseline. ADR 0029 and `b8f8941` add the bounded
TLS listener/HTTP component; harness `7a20d9d` and hosted run `33857739150`
pass its 13+5 Browser reference scenarios.

The internal Block manifest foundation is available under `blocks/` with ADR
0016 and plan `block-manifest-loader.md`. It is a strict, bounded local
configuration registry only; it does not advertise Provider capabilities,
execute blocks, or establish browser/desktop, deployment, or production
evidence.

P4 authority planning is recorded in ADR 0017 and
[`plan/p4-optional-profiles.md`](plan/p4-optional-profiles.md). Browser Contract
authority and Go projection are locked; ADR 0018/0019 and run `33724368530`
provide exact amd64/arm64/v8 sandbox and signed publication evidence. ADRs 0020
through 0024 cover the Provider-local runtime, provenance, restricted egress,
protected transport, and caller-owned Browser Gateway components. ADR 0025 and
`66183b1` compose the default-disabled Provider graph; ADR 0026 defines the
independent reference caller. ADR 0027 and `7b062e6` add process-local Gateway
capacity, and harness `28a9a5e` exercises its original 11+5 hosted scenario.
ADR 0030 and `997fb0d` add the authenticated-capacity port and process-local
global/tenant/session memory component. E2E lock `49d1c20` passes all three
clean lock checks. Hosted CI `33940332882` and Reference/Candidate/Browser runs
`33940332897`/`33940332881`/`33940332911` pass against harness `6b01b75` and
Provider `997fb0d`. ADR 0031 and `9434540` add the Redis-compatible adapter;
local run `20260905T061037.558537000Z` passes its separate 10-scenario
real-Valkey, two-independent-Gateway black-box gate against harness/Gateway
source `ddbb2c4` and Provider baseline `2ed5e68`. Hosted run `33949577876`
passes the same 10-scenario gate on `linux/amd64` against harness/Gateway source
`de297e7` and the same Provider baseline.
ADR 0032 and `c0a55d1` add exact-grant level-triggered revocation port and
real-Valkey adapter component evidence. Historical E2E lock `59e08d5` passes local
Browser 13+5, Reference/Candidate 15+5, and shared-capacity 10/10 regressions;
none is the separately required two-Gateway/independent-revoker revocation
caller gate. Pre-ADR0033 hosted CI `33955437033` and four regressions also pass
against harness `c7fe24d` and Provider `c0a55d1`: Reference `33955436969`,
Candidate `33955437046`, Browser `33955436984`, and shared capacity
`33955436968`. They do not expand those boundaries.
Separate harness/Gateway `e952ef9`, local run
`20260905T095109.569973000Z`, and hosted run `33959122456` pass the seven-case
durable-revocation caller gate on arm64 and amd64. Its Contract identity is
unexercised metadata and its private echo path is not Browser/CDP.
ADR 0033/`b4d41c9` subsequently passes targeted/full race-shuffle, vet, Contract
verification, the unchanged locked 48-case Suite, and tagged pinned-Valkey
integration for its downstream CDP fencing component and real-backend adapter.
Implementation `58488d7` then wires Provider bootstrap into each persistent
downstream caller OS process. The dual-process test gives each caller a distinct
mTLS/JWS Controller identity, reconciles its own capability/create/operation/
sandbox/Browser-session/handoff chain, binds the opaque handoff only in private
process state, and confirms both processes remain in the JSONL control loop.
Implementation `8a1049b` adds the correlated FD 3/4/5 request, private endpoint
envelope, and exact final-configuration handoff; strict bounded EOF-framed JSON;
fixed direction validation and close-on-exec setup; canonical live expiry checks;
at-most-once delivery; cancellation, failure, and natural-exit cleanup; a
fail-closed parent process manager with kill plus bounded wait; and the full Contract handoff-reference
grammar in `gatewaystack`. FD5 delivery is not child acceptance; a correlated
JSONL response establishes readiness. FIFO type validation cannot distinguish a
named FIFO from an anonymous pipe, so the `os.Pipe` launcher is trusted. The
Contract has no Browser-session termination mutation, so handshake failure does
not prove Provider resource cleanup. These remain process/component boundaries.
Runner implementation `a2b82b0` and corrections through harness `550c785` then
compose the complete local topology. Clean run
`20260906T050213.016063000Z` passes 13/13 on `linux/arm64`, including stale
action rejection, higher-fence replacement, terminal closure without
reconnect, outage recovery, unaffected scopes, retained high-water across
ingress reconstruction, bypass exclusion, cleanup, and sanitization. The
Contract identity is pinned and six Provider routes are exercised, but the
48-case Suite remains unexercised (`suite_exercised=false`).
Hosted checkout `2cadc53` passes repository CI `34013982778`, Reference
`34013982794`, Candidate `34013982784`, Browser `34013982785`, shared-capacity
`34013982786`, durable-revocation `34013982798`, and downstream-fencing
`34013982796`. Downloaded downstream artifact
`browser-downstream-fencing-e2e-evidence-34013982796` contains evidence
directory `20260906T052710.781616339Z` with exactly five sanitized files; its
report passes 13/13 and its manifest pins the required amd64 image identities,
topology, and cleanup state.
ADR 0028 and `44ea2ee` add process-local pre-upgrade connection/rate control;
hosted run `33854020809` passes the combined 12+5 Browser caller against harness
`e7e7f03`. ADR 0029 and `b8f8941` add listener/TLS/HTTP bounds; hosted run
`33857739150` passes the 13+5 Browser caller against harness `7a20d9d`.
ADR 0034 separately passes its witnessed v2 deletion/rollback-detection
component and pinned-Valkey adapter gates. It is not selected by this v1 caller
topology. The separately locked v2 caller topology passes its 18-scenario local
`linux/arm64` gate in run `20260906T100233.295973000Z` at harness `059357c`;
hosted run `34026680591` passes the same 18 scenarios on `linux/amd64` at the
same checkout. Its Contract identity is pinned while the Suite remains
unexercised. Production Browser advertisement/public Gateway and v2
private-ingress deployment, a production independent witness, controlled
restore operations, Valkey provenance and HA/failover consistency, remaining
profile-specific security and concurrency, aggregate, multi-controller,
multi-tenant, deployment, and production gates remain separate and open.

Contract identity:

- namespace: `urn:shell-echo:sandbox-runtime:provider-v1`
- version/license: `1.0.0` / MIT
- revision: `720ad15c343e71f36615dc4499edd5e764178bca`
- Contract tree: `343ffde0819207cf99c005096c336735dd33a735`
- manifest digest:
  `sha256:483111511a588b41bd40d3fef686f0b21f465bb65d3215450ebb2ccf37a5de89`
- OpenAPI digest:
  `sha256:5a3da5d239f83e94eff09fc75438755f834e77bce8cd1c0f91c25055bf0cba2a`
- semantic-rules digest:
  `sha256:7953d05e65f00c68e0428b6dd4fcebef1af103f2cab2fa6b214905b2496c8785`
- local Suite: `sandbox-provider@1.0.0`, profile
  `sandbox-runtime-provider-v1`, `repository-go-test`, 71 cases, digest
  `sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`
- remote Suite: `sandbox-provider-remote@1.0.0`, profile
  `sandbox-runtime-provider-remote-discovery-v1`, `remote-http-black-box`, 6
  cases, digest
  `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0`

| Phase | Verified maturity | Open gate |
| --- | --- | --- |
| P0 | Passed: repository-owned MIT Contract migration and lock | Retain lock and projection regression |
| P1.1 | The DTO, mTLS discovery, JWS/digest/replay/fencing admission, ADR 0038 repository-local gates, and the exact P2.7 independent external-caller qualification pass. The listener has one explicit caller trust domain, Provider-local audience/revision anchors, and up to 32 frozen keys | Production identity infrastructure, multi-issuer admission, deployment-owned rotation, and qualification of other callers remain unproven |
| P1.2 | Passed for the selected Contract-authorized lifecycle subset and development composition | Snapshot/restore, resize, and production gates remain open |
| P2 components | P2.1-P2.5h local component, Contract projection, Docker, and recorded repository CI gates pass within their named boundaries | Retain single-controller/development constraints and exact Contract lock |
| P2.5i | Latest completed local run `20260907T044611.598221000Z` passed 15 initial plus 5 restart/resume coding/shell scenarios against historical harness/Provider lock `b8d4829`/`af8a505`; hosted regression `33970773414` remains historical evidence against `17ed6ca`/`b4d41c9` | Neither run contains a Browser scenario or proves interoperability with an independently implemented external caller, durable-revocation caller behavior, or production properties |
| P2.6 | The historical 50-case local and separate 6-case remote profiles passed at `3fe314a`/`ae476fe`. The later content-derived 60-case local Suite passed from a clean VCS-built Runner at lock-selection revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`; Product Phase 5 separately selects the current 71-case authority | Protected or mutating remote profiles and broader aggregate/reliability/deployment gates remain separate |
| P2.7 | Complete at **24/24**; the public independent caller is **13/13**. Hosted run `35203241121` executed all 15+5 cases against Provider `170459266af5f4fad359ca8c63f2ae19741055c5` and caller `b3ebcc783e5db20395e29b029e0eb55f7819b49b`, matched all 91 required observations, completed stable zero-resource teardown, and produced accepted seven-file artifact `10488622806` with result-envelope digest `sha256:d5e6fd528f2302252a38f49aa466c85767106a8bcef430120f230a8127f96758` | No step remains in the fixed first-version plan. Other callers/profiles, aggregate conformance, multi-controller, hostile multi-tenant, HA, deployment, and production readiness require new scopes and evidence |
| P2 | Reference coding/shell caller and Product Phase 2 lifecycle release gates passed; the latter includes a repository-owned independent-process 15+5+9 black-box run | Independently implemented external-caller lifecycle interoperability, aggregate conformance, multi-controller, hostile multi-tenant isolation, deployment, and production gates remain open |
| P3 | Retired by ADR 0037. Historical revision binding/shadow/metrics components and candidate runs retain their recorded evidence boundaries | No named-platform migration gate remains; external consumers adapt to the exact locked Provider Contract |
| P4 | Browser Contract authority/projection, exact sandboxed signed amd64/arm64/v8 publication, Provider-local components, default-disabled command/runtime composition, process-local Gateway limits, the separately recorded Browser/shared-capacity/durable-revocation caller gates, ADR 0033 component/caller evidence, the ADR 0034 v2 local/hosted deletion and rollback-detection gates, the ADR 0035 PostgreSQL component gate, and the ADR 0036 hosted same-runner controlled-restore gate pass within their named boundaries | Production independent witness/storage and restore operations, production Browser advertisement/public Gateway, Valkey/PostgreSQL provenance and HA, production configuration/metrics, aggregate, multi-controller, multi-tenant, deployment, and production gates remain open |
| Product Phase 5 | **15/15 complete** for the bounded same-repository independent-process topology. The exact Product/Gateway/Provider/Desktop/Guest process graph passes 14 strict scenarios with fresh pinned PostgreSQL, signed runtime, real display/control, Guest development materialization, restart/fault/security/recording checks, dependency-derived exact-topology advertisement, strict evidence validation, and exact cleanup | Production command composition and deployment qualification, HA, hostile multi-tenant isolation, independently implemented caller interoperability, and general production readiness remain later gates |

Production readiness is not a numbered phase shortcut. Aggregate conformance,
multi-controller reliability, hostile multi-tenant security, deployment, and
production operations remain separate and unproven after the reference P2 gate
and require their own future evidence.

The Browser protected-transport implementation `b8423f5` and harness lock refresh
`a2721ad` are covered by repository CI run `33760609353`, which passed
`provider-contract`, `test`, `docker-integration`, and the separately named
`browser-provenance` job. Its Docker job does not execute the Browser
restricted-egress tagged integration; that live evidence remains local. Hosted
Reference and Candidate runs `33760609272` and `33760609231` passed their
separately named coding/shell scenarios. Repository CI remains distinct from
caller evidence, and neither hosted caller run contains a Browser scenario.
The Browser Gateway implementation `5aae281` and harness lock `9eb32ba` were
pushed together after all local gates and fresh 15+5 Reference/Candidate
coding/shell runs passed. Repository CI `33826813073` passed
`provider-contract`, `test`, `browser-provenance`, and `docker-integration`;
hosted Reference and Candidate runs `33826813099`/`33826813100` also passed their
separately named coding/shell scenarios. None of these hosted results contains a
Browser caller scenario.
Previous implementation `f760369` and harness lock `79fee2b` are covered by
repository CI `33838215949`; all four `provider-contract`, `test`,
`browser-provenance`, and `docker-integration` jobs passed. Hosted coding/shell
Reference/Candidate regressions `33838215917`/`33838215882` also passed their
separate 15+5 scenarios, while hosted Browser Reference E2E `33838215924`
passed its separate 10+5 Browser scenarios. ADR 0027 capacity implementation
`7b062e6` and harness `28a9a5e` are covered by repository CI `33846603580`;
all four jobs passed. Hosted Reference/Candidate regressions
`33846603323`/`33846603454` pass 15+5 coding/shell scenarios, while Browser
Reference E2E `33846603547` passes its separate 11+5 scenarios including active
same-session capacity rejection/release. These three caller modes retain their
distinct evidence boundaries.

The GitHub Actions Node 24 migration `6c1ddde` and lock refresh `e75869d` are
covered by repository CI `33850219645`, Reference `33850219700`, Candidate
`33850219664`, and Browser `33850219667`; all passed without the previous Node
20 or `punycode` warnings. This is CI runtime maintenance only. The subsequent
Browser edge implementation `44ea2ee` and harness `249cdd4` pass all required
local Go/Contract/E2E gates and the clean local Browser 12+5 run described
above. Repository CI `33854020951` passes all four jobs. Hosted Reference
`33854020874`, Candidate `33854020947`, and Browser `33854020809` pass their
separate 15+5, 15+5, and 12+5 scenario sets against harness `e7e7f03` and
Provider `44ea2ee`; their artifact digests are
`sha256:220650f1b61b0297ec445ded03bf3a15870514a9482c9e55012ddfba8ae0da2d`,
`sha256:48cbe44c433e5b3a858a2691fe1f736469b2e8d71228541f2bdfcc4aab1c15b1`,
and `sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`,
respectively. The three caller modes retain distinct evidence boundaries.

## P2.5i Reference Result

The earlier audit correctly found no existing platform caller. A separately
versioned reference harness now exists as the `e2e/` Go module and process
boundary inside this Provider repository. Its caller module has an
import-boundary test that forbids Provider implementation imports; the separate
reference-stack process alone composes exported Provider/Gateway packages with
explicit caller-owned policy.

The clean `e329150` harness run against Provider `d58497e` verified exact
Contract/Suite identity, two ephemeral mTLS/JWS controller identities, locked
capability discovery, protected lifecycle, replay, exec/result/usage, stale
fencing, cancellation, opaque terminal handoff, Gateway bytes, wrong-caller and
cross-tenant denial, grant expiry, revocation, artifact staging/evidence,
process reconstruction, retained evidence, and same-shell reconnect. It
exposed no backend endpoint and left no managed container or new temporary run
directory.

This closes the reference external-caller P2.5i gate. It does not prove real
Veronica compatibility, aggregate conformance, distributed revocation caller behavior,
multi-controller reliability, hostile multi-tenant isolation, deployment, or
production readiness.

The latest local pre-ADR0033 coding/shell lock-refresh runs use harness
`59e08d542b05ad1a047f439f4ea72e82c8c37404` and Provider
`c0a55d1e0a862f9e5a592abd27b1e25be3c85b3e`. Reference evidence
`e2e/evidence/20260905T080530.577843000Z/manifest.json` and candidate evidence
`e2e/evidence/platform-candidate/20260905T080623.861033000Z/manifest.json` each
record 15 initial plus 5 reconstruction/resume coding/shell passes, Contract 48
cases, and linux/amd64 runtime digest
`sha256:c1da999518ed8cf3c422142b705f3eeca5d60104be07bc28c15a7d527d2907fc`.
Neither manifest contains a browser scenario; the candidate manifest also
remains explicitly bounded to candidate integration and does not represent real
Veronica or production traffic.

## Retired Platform Candidate Track

ADR 0037 retires the former named Agent Platform migration target. Earlier
audits correctly established that no runnable platform caller or migration
harness had been supplied, but that absence is no longer an active project
blocker because this repository will not implement or wait for a
consumer-specific adapter.

The historical `agent-platform-candidate` harness, commits, runs, and artifacts
remain valid only within their recorded revision-binding, shadow, canary,
rollback, drain, and metric-component boundaries. Their names and evidence are
not rewritten. A future consumer owns its integration and rollout evidence and
must conform to the exact locked Provider Contract.

## Completed Implementation History and Future Scope

The fixed first-version plan is complete; there is no remaining numbered P2.7
implementation step. The material below records the completed dependency order.
Any further multi-controller, HA, hostile multi-tenant, deployment, production,
or additional-profile work is a new scope with its own authority and gates.

P2.5a established [ADR 0015](adr/0015-coding-shell-vertical-composition.md) and
the [vertical-composition plan](plan/p2.5-coding-shell-vertical-composition.md).
P2.5b then locked one atomic exec+terminal coding/shell profile in Contract
commit `22a148e` and projected it fail closed in `123d16a`. Its local gates and
repository CI `32924361132` pass. P2.5c commits `6c2962b` and `6340604` move
create/session bounded strict decode ahead of mutation guard reservation and
bind the regression into the locked Suite runner; local gates and CI
`32926181615` pass. P2.5d commit `de18787` adds the independent Provider Docker
lifecycle adapter and passes its local fault/restart, full Go, Contract/Suite,
and real Docker integration gates; CI `32929140044` passed all three jobs.
P2.5e commit `5917a57` locally composes strict protected exec/cancel/result and
operation projection, durable accept-before-dispatch and restart
reconciliation, bounded private output capture, real Docker execution and
cancellation, and fail-closed development composition. Full race/shuffle, vet,
Contract verification, the locked 38-case Suite, diff checks, focused race
matrices, and real Docker integration passed locally. CI `32937530059` passed
all three jobs. P2.5f0 then audited terminal/Gateway authority, data-plane,
recovery, persistence, cleanup, capacity, and deployment boundaries without
changing runtime behavior. P2.5f1 commit `6778d3c` adds the backend-neutral
terminal runtime port, a PTY-owning guest broker, adapter-private durable Docker
identity, bounded per-sandbox/per-controller capacity, identity-bound cleanup,
and fresh attach to the same shell after Provider driver reconstruction. Full
race/shuffle, vet, module verification, unchanged Contract verification, the
locked 38-case Suite, diff checks, focused terminal tests, and live Docker
integration passed locally. This is runtime-adapter evidence only; repository
CI `33033284420` subsequently passed all three jobs for evidence baseline
`66dd3d1`. P2.5f2 implementation `ccffd52` then adds the uncomposed durable
session vertical, provider-neutral allocation evidence, v1-to-v2 migration,
trusted lifecycle projection, exact-identity allocation recovery, observation,
expiry cleanup, and a success-commit hook that accepts but does not mint opaque
reference evidence. Full race/shuffle, vet, module and Contract verification,
the locked 38-case Suite, diff checks, focused fault/restart/migration matrices,
and live Docker integration passed locally. Repository CI `33045725476`
subsequently passed all three jobs for evidence baseline `3abefd4`. P2.5f3
implementation `b1acdd1` adds a durable opaque reference registry and resolver
in a separate repository. Registration mints a random 128-bit
`ref:session:*` value for a running allocation; resolution rechecks registry
expiry/revocation and exact committed-handoff identity, then constructs a fresh
adapter-private attach for each dial. File-backed restart, collision, expiry,
revocation, generation/reference mismatch, and concurrent resolve/revoke tests
pass locally. The registry/session repositories are intentionally non-atomic,
and no command composition or public backend endpoint is added. Repository CI
`33059304542` passed all three jobs for evidence baseline `7138a4c`. P2.5f4
implementation `14f14cc` adds `gateway/adapter`: a direct
`github.com/coder/websocket@v1.8.15` dependency (ISC-licensed, source-reviewed
for context reads/writes, message limits, control frames, and close behavior),
plus bounded adapters between the WebSocket/terminal byte surfaces and
`gateway.Stream`. It requires a caller-supplied pre-upgrade admission callback,
rejects wildcard origin patterns, retains the library's default same-origin
protection and disabled compression, accepts only text/binary data-plane
frames, and uses a 32 KiB default with a 64 KiB hard cap. Focused adapter
race/shuffle tests cover admission, origin rejection, binary flow, control
frames, over-limit `1009` close, cancellation, close, abrupt disconnect, and
partial terminal I/O. Full race/shuffle, vet, module verification, unchanged
Contract verification, the locked 38-case Suite, diff checks, and both Docker
regression packages passed locally. Repository CI `33064864447` then passed
`provider-contract`, `test`, and `docker-integration` for evidence baseline
`1d9da67`. `govulncheck` and an OSV scanner were not available, so no
vulnerability scan is claimed. P2.5f5 implementation `fdfc771` adds
`gateway/composition`, which requires caller-owned `Authorizer`,
`RevocationSource`, `Recorder`, and WebSocket handshake admission together with
a Provider reference resolver. It projects each freshly resolved Provider
terminal dial through the bounded f4 terminal adapter, rejects missing and
typed-nil dependencies and incomplete endpoint data fail closed, and closes the
caller stream on all connection exits. Focused and full race/shuffle, vet,
module verification, unchanged Contract verification, and the locked 38-case
Suite passed locally. This is a composition component, not Provider command
configuration, external-caller E2E, aggregate conformance, multi-controller,
multi-tenant, deployment, or production
evidence. Repository CI `33067526022` then passed all three required jobs for
evidence baseline `754c57d`; it is still not external-caller, aggregate,
multi-controller, multi-tenant, deployment, or production evidence. P2.5f6
commits `c4c7cbc` and `8a794c0` then add default-disabled development terminal
command composition with recovery before protected transport injection,
idempotent reference registration, file locking, bounded cleanup, and
production rejection. P2.5f7 test `0e8b284` then closes the local
single-controller terminal vertical gate with a real Docker session, durable
handoff, test-supplied Gateway policy, and same-shell reconnect after process
reconstruction. Their full local gates pass, and evidence baseline `cefbc74`
passed repository CI `33134521467`. P2.5g implementation `0e6e108` then adds
the default-disabled artifact/usage command vertical. It
binds staging to lifecycle readiness, tenant, generation, lease, and fencing;
reads only regular files beneath the owned Docker `/outputs`; runs injected
content scanners without shell interpolation; returns only opaque private
staging references; persists async artifact outcomes and partial exec-derived
usage across restart; and includes artifact operations in the family reader.
Its focused, full local, and Docker-tagged gates pass, and repository CI
`33157119149` passes all three jobs. P2.5h implementation `2c55173` and
repository CI `33159099578` also pass their bounded readiness/projection gates.
Reviewed documentation baseline `bba02a6` passes repository CI `33160646494`.

The private FD 3/4/5 provisioning protocol, parent process manager, and
Contract-wide `gatewaystack` handoff validation are implemented at `8a1049b`.
Harness `550c785` composes them into the complete local ADR 0033 topology, and
run `20260906T050213.016063000Z` passes all 13 scenarios on `linux/arm64`.
Hosted harness `2cadc53` run `34013982796` passes the same scenarios on
`linux/amd64`; the downloaded artifact contains evidence directory
`20260906T052710.781616339Z` with exactly five sanitized files and has been
inspected.

P2.7b validation requires an operator-enforced writer handoff: the validator is
the evidence root's exclusive writer from `Verify` entry through return,
including against producers and other processes with the same UID. Its dirfd
and TOCTOU checks fail closed on detected changes; they do not prove integrity
against a continuously writable attacker. The validator stages its owned
receipt, repeats the final evidence checks, and commits only if cancellation or
a competing destination has not won; publication does not attest that reported
interactions correspond to original request bodies. External packaging and
archive digesting happen only after a successful return.

P2.7c.1 locks the language-neutral adapter JSON schema and its
first Darwin/Linux inherited-pipe transport semantics. Its protocol authority is
bound through startup, process-supervisor, validator, and receipt evidence.
All qualification Schema compilers use one ECMA-262 regexp engine and reject
ASCII controls without POSIX-only classes. Invocation paths/endpoints now use
closed canonical profiles. The definition requires digest-bound preflight
commitment before the supervisor or harness acquires or generates credential or
forbidden-correlation material, plus cross-phase byte identity; runtime proof
awaits the supervisor and operator-upstream non-derivation remains trusted.
Non-error output invocation IDs and phases now bind to the single validated
inbound invocation, including scenario case-ID phase prefixes. Protocol-error
branches now distinguish unbound `invalid_invocation` from
bound post-acceptance terminal failures. Its monotonic deadline anchors retain
one execution budget across reconstruction, clip each case to remaining global
and parent time, prevent resets, and bound failure termination separately.
P2.7c.2a adds the runtime-independent strict codec. Invocation bytes are counted
through EOF; output record limits exclude the LF delimiter while the stdout
total includes delimiters and invalid or truncated bytes. The codec rejects
invalid UTF-8, duplicate members, invalid surrogate escapes, multiple values,
unknown fields, wrong-direction messages, and mismatched startup protocol
authority with stable sanitized failures. It deliberately does not validate
message order, recompute transcripts, enforce deadlines, or launch a process.
P2.7c.2b.1 now locks the exact transition table, terminal-to-EOF-to-clean-exit
completion, cross-phase canonical startup equality, and the closed sanitized
transcript preimage Schema at
`sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293`.
This is definition evidence only, not runtime state or transcript evidence.
P2.7c.2b.2 adds the runtime-independent startup gate: it consumes the first
strictly decoded adapter record, requires `startup_identity` sequence zero,
rejects empty, duplicate, and out-of-order startup, preserves the first
sanitized failure, and grants invocation-input authorization once. It neither
performs I/O against a process nor advances into invocation acceptance.
P2.7c.2b.3 records the invocation only after the startup gate authorized input,
requires the invocation and output to originate from the same verified Codec
and stdout decoder, rejects skipped output records, and accepts only sequence
one with matching invocation ID and phase. A package-private document digest
and revalidation prevent mutable decoded fields from changing the bound
message; only a sanitized invocation reference is retained. P2.7c.2b.5 adds
the valid pre-binding error branch.
P2.7c.2b.4 obtains both phase case orders from that same verified profile
result, copies them into the per-phase machine, and accepts exactly one result
per case in order. `completed` requires an immediately preceding
`scenario_started` for the same case; `not_executed` forbids a preceding start.
Sequence, invocation, phase, Codec, stdout-stream, wire-byte, and decoded-record
integrity remain bound for every accepted scenario message. The machine stops
at `awaiting-terminal`. P2.7c.2b.5 accepts exactly one normal
`invocation_finished` whose completion matches all observed dispositions, or
the exact pre-/post-binding `protocol_error` branch. It rejects output after
terminal, requires EOF on the bound decoder, and accepts a clean-exit event only
after EOF. The pure state-machine slice neither launches nor waits on a process;
c3.6 now supplies this event from the owned child's bounded real exit observation.
A process boundary alone cannot prove caller source independence or exact
PID-level request attribution.

1. Retain the completed P2.7 publication, 24/24 qualification, and public
   caller 13/13 evidence at their exact recorded identities. Retain the
   completed Product Phase 2, Phase 3, and Phase 4 results at their exact
   historical Contract and topology identities; the current Desktop-extended
   Contract lock does not relabel them.
2. Before adding protected or mutating remote profiles, define their explicit
   cleanup authority, prerequisites, case-specific evidence, and incomplete-run
   semantics; do not reinterpret the discovery profile.
3. Preserve the Browser, coding/shell Reference, and historical Platform
   Candidate harnesses as separately named evidence modes. The candidate mode
   is historical and P3 is retired; future consumers own their adapters and
   rollout evidence.
4. Prove independent PostgreSQL/Valkey failure and backup domains, HA, and
   operator controls only in a deployment-owned environment. Retain hosted ADR
   0036 evidence as same-runner reference evidence.
5. Retain the completed Product Phase 5 15/15 evidence at its exact Contract,
   runtime, template, process, and scenario identities. Define a separate
   Phase 6 or deployment plan before enabling production command composition,
   production advertisement, collaboration, HA, hostile-tenant, or operational
   readiness claims.
6. Keep multi-issuer admission, aggregate conformance, multi-controller,
   multi-tenant, HA, independent external-caller interoperability, deployment,
   and production-readiness claims blocked until their separately named gates
   have reproducible evidence.

The detailed case-by-case evidence and exact open claims remain in
[`STATUS.md`](STATUS.md).

## Maintenance Rule

Update this document when architecture ownership, mandatory engineering gates,
phase maturity, Contract identity, primary blockers, or the next implementation
order changes. Put commit-by-commit evidence in `STATUS.md`, design rationale in
ADRs, and protocol details in `contract/`.

Use dated evidence baselines rather than statements such as `HEAD is <sha>`;
the latter becomes false as soon as a documentation update is committed. Every
handoff must leave facts, inference, and unproven claims visibly separate.
