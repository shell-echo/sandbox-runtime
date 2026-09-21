# sandbox-runtime

[简体中文](README.zh-CN.md)

`sandbox-runtime` is a backend-independent sandbox Provider and local runtime
control plane written in Go. It exposes a repository-owned Provider Contract
for coding and remote-shell workloads while keeping runtime implementation
details behind replaceable drivers.

The first-version engineering and independent external-caller qualification
plans are complete. This is a bounded interoperability result, not a claim of
general production readiness.

## Project status

| Track | Status |
| --- | --- |
| Main delivery plan | **24/24 complete** |
| Independent external caller | **13/13 complete** |
| Product v1 Phase 3 | **13/13 complete** for the bounded standalone topology |
| Product v1 Phase 4 Browser | **13/13 complete** for the bounded same-repository separate-process topology |
| Product v1 Phase 5 Desktop | **15/15 complete** for the bounded same-repository independent-process topology; 5 roles and 14 strict scenarios pass, with exact-topology dependency-derived advertisement |
| Product v1 Phase 6 production hardening | **4/15 complete**; independent Product, Provider, Gateway, Guest, Browser and Desktop role processes now pass the bounded local Slice 4 gate with real Chromium/Desktop media-input paths, restart/fault checks and exact cleanup; the Desktop OCI remains a non-release local candidate, and public E2E, deployment and production readiness remain unproved |
| Coding/shell qualification | **Qualified** for the exact caller, Provider revisions, topology, profile, and scenarios recorded below |
| Latest core CI | [Passed](https://github.com/shell-echo/sandbox-runtime/actions/runs/35204434771) |

The final hosted qualification run executed all 15 initial scenarios and all 5
reconstruction scenarios, matched all 91 required observations, and returned
the run-owned resource scope to zero for three stable samples.

- [Qualification run 35203241121](https://github.com/shell-echo/sandbox-runtime/actions/runs/35203241121)
- Provider source: `170459266af5f4fad359ca8c63f2ae19741055c5`
- External-caller source: `b3ebcc783e5db20395e29b029e0eb55f7819b49b`
- Evidence artifact: `10488622806`
- Evidence archive: `sha256:ada1cae128a41e6b694ff413aab179c0eff94b42663ece8233dbb358e319e9bd`
- Result envelope: `sha256:d5e6fd528f2302252a38f49aa466c85767106a8bcef430120f230a8127f96758`

See [Project status](docs/STATUS.md) for the full evidence ledger and
[External caller qualification](docs/qualification/external-caller-coding-shell-v1.md)
for the exact claim boundary.

The separate [Product v1 architecture Phase 1](docs/plan/product-v1-phase-1.md)
is also complete as design and Product Contract definition. It permits future
Product modules in this repository while preserving the Provider as a locked
network boundary, and defines Workspace/slot persistence, identity and Agent
delegation, Runtime Gateway and recording, and deployment levels. No Product
service, Product database migration, public Gateway, Guest Agent, or production
deployment has been implemented or qualified by that work.

The separate [Product v1 Phase 2 Provider lifecycle plan](docs/plan/product-v1-phase-2-provider-lifecycle.md)
is complete for termination, suspend/resume, lease expiry, finite event reads,
and terminal-session close. Implementation revision
`98995384c60a924f25ca58d3b7e561207bfa5be8` is selected by lock revision
`3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`; the clean-VCS 60-case Suite,
full repository gates, tagged Docker lifecycle integration, and the 15+5+9
independent-process reference black-box run pass. This does not add a new
separately implemented external-caller, deployment, or production-readiness
claim.

[Product v1 Phase 3](docs/plan/product-v1-phase-3-product-kernel-terminal-files-web.md)
is complete at **13/13** for its bounded standalone scope. In addition to the
Product authority, API, Gateway, Guest/Files, transfer, Web, catalog, and
recording components, the final tagged gate passed nine black-box scenarios
through separate Product, Gateway, Guest, and locked-Contract Provider-fixture
OS processes plus fresh pinned PostgreSQL. Capability readiness is now
tenant-aware and dependency-derived. The accepted evidence is independently
validated and retains explicit non-claims: this is not a deployable topology,
independently implemented caller result, HA, hostile-multitenant, or production
readiness.

[Product v1 Phase 4 Browser](docs/plan/product-v1-phase-4-browser.md) is complete
at **13/13** for its bounded release topology. Its final tagged gate passed 12
exact scenarios through separate Product, Gateway, Provider, and Browser OS
processes with fresh digest-pinned PostgreSQL and Valkey plus fresh encrypted
recording storage. The strict evidence manifest records restart, fault,
authentication, nondisclosure, automation, real-WebRTC viewer/controller,
recording-integrity, backpressure, lifecycle, and exact-cleanup results.
This is same-repository separate-process evidence, not deployment-qualified,
independently implemented caller, HA, hostile-multitenant, or production
evidence.

[Product v1 Phase 5 Desktop](docs/plan/product-v1-phase-5-desktop-development-unified-product.md)
has completed **15/15** dependency-ordered slices for its bounded release
topology. Slice 1 locks a separate
Provider Desktop capability/profile/runtime shape and complete session
open/read/handoff/close/expiry/revocation, usage, admission, security, and
cleanup semantics. Exact authority is Contract revision
`720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`, and a 71-case local Suite with
digest `sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`.
Slice 2 adds strict Product Desktop slot/session intent, PostgreSQL migration
8, atomic operation/event/audit/outbox persistence, isolated Desktop session
work, and real-database concurrency/restart evidence at implementation
`d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`. Slice 3 implementation
`f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5` adds Provider-local Desktop
domain/application policy, memory and atomic-file persistence, restart-safe
reconciliation, operation aggregation, and optional protected handlers. Slice
4 candidate implementation
`163dd8a258a24cf4727169b1cbd8ed7c0fe29292` adds locked dual-architecture
image inputs, a bounded Unix-only display/session broker, reproducible local
outputs, a passing native arm64 smoke, and a manual native publication/
attestation workflow. Publication run `35447651328` passes native amd64 and
arm64/v8 and selects signed index
`sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`.
Slice 5 implementation `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b`
adds the fail-closed Docker adapter, durable opaque private resolver, fresh
attach/reconnect checks, lifecycle readiness, revoke-before-cleanup/absence
composition, and exact Desktop duration evidence. Production startup, Product
dispatch, public data planes, Web experience, and capability advertisement
were still later gates at that boundary. Slice 6 implementation
`2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240` adds the exact-revision
network-only Product adapter, isolated Desktop dispatch and observation,
retained operation recovery, independent Product/Provider generations, and
Desktop-specific close cleanup. Its real PostgreSQL plus HTTP Provider-fixture
gate passes. Slice 7 implementation
`0649d62911abb89229de40136347286736152ec6` adds Product-owned Desktop
viewer/controller grants, encrypted one-use tickets, session-scoped controller
fencing, independent viewer/controller quotas, revocation, continuous authority
checks, and metadata-only audit. At that boundary, public signaling/media/input,
policy, Web experience, production composition, and capability advertisement
remained later gates.

Slice 8 implementation `040c560f3701b7c972c25f05928dd435d9f55c20`
adds a separate bounded Desktop WebRTC handler: authenticated TLS signaling,
exact Origin, relay-only production ICE, receive-only VP8 and optional Opus,
viewer/controller separation, reliable ordered fenced input, continuous grant
checks, and slow-consumer closure. Durable Desktop policy, a real Provider
media bridge, recovery, recording, unified Web, production composition, and
capability advertisement remain later gates.

Slice 9 implementation `24f5c741eb605614f77f8d9d546708b9993e42dd`
adds immutable versioned Desktop policy snapshots, PostgreSQL migration 11,
deny-by-default keyboard/pointer/touch/clipboard/transfer authorization,
activation and consent gates, bounded workspace paths and transfer metadata,
exact Product transfer-record binding, and continuous policy-revision
revocation. A real Provider media/input bridge, reconnect/recovery, recording,
unified Web, production composition, and capability advertisement remain later
gates.

Slice 10 implementation `f23b16130c97e99d5d28008b01346779a0c681ee`
adds fresh-grant reconnect recovery with a database-time Desktop Gateway lease,
full authority/generation rechecks, bounded visual/audio resynchronization,
closed resolution and audio-output changes, connection-epoch rejection of
pre-disconnect input, and transactional grant/handoff/session cleanup during
deterministic slot replacement. At that boundary a real Provider media/input
bridge, recording, unified Web, production composition, and capability
advertisement remained later gates.

Slice 11 implementation `c5b045abc5192b76b7d615ddbb0858b998ef98d5`
composes required Desktop recording into Gateway admission and live media/
control handling. Explicit consent and the selected mode are visible in
signaling; initialization and recorder loss fail closed. VP8/Opus RTP and
minimized control/synchronization events use the existing encrypted,
quota-bounded, integrity-linked Product recording service with owner-authorized
replay and retention deletion. Clipboard text, transfer paths/identities, and
content remain excluded from catalog and metadata audit. A real Provider
media/input bridge, unified Web, production composition, and capability
advertisement remain later gates.

Slice 12 implementation `490c2db96d6ba7a851d7846bc9e5f818dae2be77`
adds the immutable `coding-shell-base-v1` catalog, migration 13 revision/
development persistence, bounded content-addressed workspace streaming, exact
Guest authority/health/mount/toolchain checks, and private two-phase Guest
rollback/restart recovery. Host paths, object paths, credentials, Guest IDs,
and runtime coordinates remain outside public health and audit/event data. A
real Provider media/input bridge, unified Web, production composition, and
capability advertisement remain later gates.

Slice 13 implementation `84698c371d35edb862ffc81b484a3e31cc8120d9`
adds one capability-derived authenticated Product Web shell for Workspace,
Terminal, Files, Browser, Desktop, and recordings. Desktop view/control uses
fresh public grants, same-origin HTTPS WebRTC, ordered fenced input, visible
recording/controller state, bounded reconnect, stream configuration,
clipboard consent, and digest-checked Product transfers without exposing
Provider handoffs or private coordinates. Generated-client, full race/vet,
Contract/evidence, and real headless-Chrome gates pass. At that boundary the
private Provider bridge, composed Slice 14 fault/security gate, and the
independent-process Slice 15 release gate remained.

Slice 14 implementation `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d`
adds the closed private Provider-to-Product-Gateway Desktop media/control
bridge and a real-PostgreSQL composed gate spanning public WebRTC, private RTP
and fenced input, durable policy, required encrypted recording, continuous
revocation, Origin/ticket/owner attacks, capacity recovery, and exact
row/object/session cleanup. Full race/vet, Contract, tagged store, and retained
Phase 3/4 evidence regressions pass. This remains same-repository same-process
composition evidence with a reference media executor.

Slice 15 implementation `024a768d51965f8949bacf3c97e499fb26a6e648`
adds the strict independent-process release gate. Run
`20260919T200125.484855000Z` passes 14 exact scenarios through separate
Product, Gateway, Provider, Desktop, and Guest OS processes with fresh pinned
PostgreSQL, the exact signed Desktop image, real X11 display capture and
fenced pointer control, public WebRTC/private mTLS transport, encrypted
recording replay, actual Guest development materialization, Product/Gateway/
Guest restart recovery, Provider dependency-loss closure, and exact cleanup.
The exact gate topology derives Desktop/development capability readiness from
live dependencies. The retained strict manifest and completion record are in
[the Phase 5 completion audit](docs/audits/product-phase-5-desktop-completion.md).
This does not compose the production command or establish deployment, HA,
hostile multi-tenant, independently implemented caller, or production
readiness.

[Product v1 Phase 6](docs/plan/product-v1-phase-6-production-hardening.md) is
now **4/15 complete**. Slice 1 adds the independently runnable
`sandbox-runtime product serve` process with strict development-only
configuration, private PostgreSQL/identity files, real Product migrations and
store, separate liveness/readiness, empty capability advertisement, and
fail-closed runtime mutation. The
[startup audit](docs/audits/product-phase-6-production-startup.md) and
[Slice 1 record](docs/audits/product-phase-6-slice-1.md) retain the full gap
inventory and non-claims. Slice 2 adds production-kernel TLS 1.3, a closed
Ed25519 JWT key ring with overlap/revocation, distinct migration/runtime
PostgreSQL roles, exact schema checks, bounded dependency monitoring and an
explicit unavailable capability snapshot. The
[Slice 2 record](docs/audits/product-phase-6-slice-2.md) retains its gate and
non-claims. Slice 3 adds the independent production-only `provider serve`
control plane, role-separated transactional PostgreSQL state, exact protected
admission, bounded reconciliation, real coding-shell/Desktop backends, and
single-profile capability advertisement without a local API. The
[Slice 3 record](docs/audits/product-phase-6-slice-3.md) retains its real-process,
database, backend, and non-claim boundary.

Slice 4 adds separate `gateway serve`, `guest serve`, `browser serve`, and
`desktop serve` commands; strict executor v2 and Provider-owned Desktop broker
boundaries; sealed Browser/Desktop restricted-egress identities; and a strict
six-role/twelve-scenario local gate with exact cleanup. The accepted Desktop
image is explicitly `local-candidate-non-release`; this does not prove public
Product E2E, artifact publication, deployment or production readiness. Slice 5
secret-reference/KMS/rotation qualification is next.

## What the project provides

- A local instance-management API with in-memory and Docker runtime drivers.
- A separate Provider API with mTLS identity checks and JWS-protected operation
  admission.
- Asynchronous lifecycle, bounded exec, retained results, usage evidence,
  artifact staging, terminal sessions, and protected terminal connection.
- Opaque, expiring runtime-session handoffs; backend IDs, host paths, and raw
  runtime endpoints are not part of the public Provider protocol.
- Repository-owned OpenAPI, JSON Schemas, semantic rules, fixtures, and local
  and remote Conformance Suites.
- A locked, separately modeled Provider Desktop Contract surface exercised by
  the bounded Phase 5 release topology; production command composition remains
  disabled.
- Product-owned Desktop slot/session intent with exact profiles, transactional
  PostgreSQL persistence, quotas, audit, and isolated pending outbox work.
- A locked network-only Product Desktop Provider adapter with separate
  generation authorities, durable dispatch/observation recovery, and
  Desktop-specific session cleanup; it is not production-composed.
- Product-owned Desktop viewer/controller connection authority with encrypted
  one-use tickets, session-scoped controller fencing, independent quotas,
  revocation, and metadata-only audit; this grant layer exposes no private
  Provider coordinate.
- A separate bounded Product Desktop WebRTC handler for display, optional
  output audio, and ordered controller input; it is component evidence and is
  not production-composed.
- Durable versioned Product Desktop input/clipboard/transfer policy with exact
  Product transfer binding and live revision revocation; microphone, camera,
  and device forwarding remain denied.
- Bounded Desktop reconnect and visual/audio resynchronization with fresh
  grants, restart-safe Gateway lease reclamation, stale-input rejection, and
  deterministic slot-replacement cleanup.
- Required Desktop media/control recording with explicit consent/mode,
  encrypted integrity-linked segments, owner-authorized replay, bounded quotas,
  retention deletion, and content-minimized catalog/audit metadata.
- Immutable development templates with digest-checked workspace materialization,
  exact Guest readiness, failure rollback, restart recovery, durable
  PostgreSQL attempt/revision state, and independent-process release evidence.
- A capability-derived authenticated Product Web/BFF for Workspace, Terminal,
  Files, Browser, Desktop, and recordings, with fresh Desktop grants, bounded
  recovery, accessible controls, and no private runtime-coordinate projection.
- Provider-local Desktop operation authority with durable replay/fencing and
  exact-owned close/expiry cleanup policy; its protected handlers are selected
  only by explicit topologies.
- An exact signed Desktop image plus Provider-local Docker adapter, private
  reference resolver, lifecycle readiness, revocation/cleanup, and duration
  usage components; the release gate composes them without enabling production
  startup.
- Deterministic qualification tooling for an independently implemented caller.
- Optional Browser reference components and evidence tracks, kept separate from
  the qualified coding/shell profile.

Possible consumers include remote development environments, ephemeral coding
sandboxes, terminal services, browser automation infrastructure, and systems
that need a controlled runtime boundary for agent workloads.

## Architecture and ownership

The local management API and Provider API are deliberately separate:

| Surface | Purpose | Authority |
| --- | --- | --- |
| Local `/health` and `/instances` API | Operate one local runtime controller | Internal application models and configuration |
| Provider `/v1/*` API | Cross-service sandbox protocol | The locked repository-owned Provider Contract |
| Product `/api/v1/*` API | End-user Workspace control plane | The independently locked Product Contract; implemented components and tagged standalone gate, but no deployment-qualified listener composition |

```text
Calling service
  ├─ business state, users, tenants, authorization, billing, public Gateway
  └─ aggregate operation ledger and Provider revision selection
                         │
                         │ Sandbox Provider Contract v1
                         ▼
sandbox-runtime Provider
  ├─ admission and Provider-local operation state
  ├─ lifecycle, exec, terminal, artifacts, and usage evidence
  └─ runtime driver ──► Docker / future isolation backends
```

Callers adapt to this repository's Contract. The Provider does not implement
consumer-specific wire behavior and does not become authoritative for caller
users, business workflows, billing, or public session authorization.

Dependencies point inward from transport to application policy, repositories,
and runtime drivers. See [Architecture](docs/architecture.md) and
[ADR 0037](docs/adr/0037-sandbox-provider-calling-standard.md) for the complete
boundary.

## Quick start

### Requirements

- Go 1.26 or the exact version selected by `go.mod`
- Docker only for Docker-backed operation and integration tests
- Apple Container is optional for the local OCI application smoke test
- `kubectl` and a cluster are optional for the Kubernetes application smoke test

### Run the development server

```bash
git clone https://github.com/shell-echo/sandbox-runtime.git
cd sandbox-runtime
go test ./...
go run . serve
```

The default configuration uses the in-memory fake driver and listens on
`127.0.0.1:8080`:

```bash
curl http://127.0.0.1:8080/health
```

The default Provider listener and protected Provider features are disabled.

### Run the independent Product process

Phase 6 Slices 1-2 include a real Product process backed by PostgreSQL. The
development mode requires distinct DSN/static-identity files. The production
kernel requires TLS certificate/key files, an immutable Product verification
key ring, distinct migration/runtime DSNs and exact role names. Every authority
file is an absolute mode-`0600` regular file. Start either selected mode with:

```bash
go run . product serve -c /absolute/path/to/config.toml
```

Use `GET /livez` for process liveness and `GET /readyz` for the currently
composed PostgreSQL/schema dependency. Development advertises an empty
capability list. Production reports `product.workspace` as unavailable because
the separate Provider is not yet composed through a production Product worker
or public data plane. Workspace creation is denied before persistence in both
modes. See the [Slice 1](docs/audits/product-phase-6-slice-1.md)
and [Slice 2](docs/audits/product-phase-6-slice-2.md) records for exact formats
and evidence boundaries.

### Run the independent Provider process

Phase 6 Slice 3 adds a production-only Provider role backed by PostgreSQL and
real Docker adapters. It requires separate migration/runtime DSN files, exact
role names, TLS 1.3 mTLS material, frozen JWS verification keys, bounded
reconciliation, and exactly one `coding_shell` or `desktop` profile:

```bash
go run . provider serve -c /absolute/path/to/config.toml
```

Its loopback probe exposes only `GET /livez` and `GET /readyz`; the mTLS
listener exposes the locked Provider Contract and never `/instances` or the
Product API. The root `serve` and `product serve` commands reject an enabled
`provider_process` section. See the
[Slice 3 record](docs/audits/product-phase-6-slice-3.md) for the exact
configuration, evidence, and non-claims.

### Run the application with Docker

The Docker smoke test builds the root Dockerfile and exercises `/health` plus
the minimal local instance flow under a numeric non-root user, read-only root
filesystem, and restricted Linux privileges:

```bash
./scripts/docker-smoke.sh
```

See [Docker application deployment](docs/docker.md). This validates application
packaging with the fake runtime, not Docker-backed sandbox execution.

### Run the application with Apple Container

The existing Dockerfile can be built and run as a Linux OCI application with
Apple Container. The repository smoke test exercises `/health` and a minimal
local instance API round trip with the default in-memory fake runtime:

```bash
./scripts/apple-container-smoke.sh
```

See [Apple Container](docs/apple-container.md) for prerequisites, manual
commands, cleanup behavior, and the exact evidence boundary. This test proves
application packaging and basic startup only; it does not prove the protected
Provider surface or Docker-backed capabilities under Apple Container.

### Run the application on Kubernetes

The development Kustomize base can be rendered without a cluster:

```bash
./scripts/kubernetes-smoke.sh
```

With `sandbox-runtime:local` preloaded into a reachable cluster:

```bash
SANDBOX_RUNTIME_KUBERNETES_LIVE=1 \
  ./scripts/kubernetes-smoke.sh
```

See [Kubernetes application deployment](docs/kubernetes.md). These development
resources use the fake runtime and are not a production Provider deployment.

### Use a configuration file

```bash
cp config.tpl.toml config.toml
go run . serve -c config.toml
```

Do not commit `config.toml` when it contains environment-specific paths or
credentials. Configuration precedence is:

1. built-in defaults;
2. the optional TOML file;
3. `SANDBOX_RUNTIME_` environment variables.

For example:

```bash
SANDBOX_RUNTIME_APPLICATION_MODE=development \
SANDBOX_RUNTIME_LOGGER_LEVEL=debug \
SANDBOX_RUNTIME_SERVER_API_PORT=8081 \
go run . serve
```

### Local management API

```http
GET    /health
POST   /instances
GET    /instances
GET    /instances/:id
POST   /instances/:id/start
POST   /instances/:id/stop
DELETE /instances/:id
```

Example instance request:

```json
{
  "name": "my-shell",
  "workload": "shell"
}
```

The fake driver is the safe development default. Docker operation requires the
file repository, an operator-selected stable controller ID, resource limits,
and an appropriate image and command. Start from the documented defaults in
[`config.tpl.toml`](config.tpl.toml).

## Provider integration

The normative integration authority is under [`contract/`](contract/):

- [Provider Calling Standard](contract/specification/provider-calling-standard-v1.md)
- [OpenAPI](contract/openapi/sandbox-runtime-provider-v1.yaml)
- JSON Schemas and fixtures under `contract/schemas/` and `contract/fixtures/`
- semantic rules under `contract/semantic-rules/` and Conformance Suites under
  `contract/conformance/`
- [locked compatibility identity](compatibility/sandbox-runtime/contract.lock.json)

Read the [Provider integration guide](docs/platform-integration-profile.md) for
a concise implementation checklist. The separate public
[`sandbox-runtime-external-caller`](https://github.com/shell-echo/sandbox-runtime-external-caller)
repository is the independently implemented qualified caller for the first
version; other platforms should implement or adapt to the same calling
standard.

The Provider listener is default-disabled and separate from the local API. A
protected deployment must provide its own certificates, exact caller identity,
issuer, audience, verification-key bundle, Provider revision, durable state,
and complete capability dependencies. The template intentionally contains no
working production credentials.

## Validation

Run the normal Go checks:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

Verify the locked Contract and execute its local Conformance Suite:

```bash
go run ./cmd/verify-contract -source-root .

runner_dir="$(mktemp -d)"
go build -buildvcs=true -o "$runner_dir/run-conformance" ./cmd/run-conformance
"$runner_dir/run-conformance" -source-root . -race -shuffle
```

The Conformance runner requires a clean VCS-built binary because it verifies
and tests a read-only archive of the recorded source revision. `go run` is not
a substitute for that runner build.

When Docker is available:

```bash
SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 \
go test -tags=integration -count=1 \
  ./cmd ./driver/docker ./provider/lifecycle/driver/docker
```

Additional Browser, external-caller, and qualification gates are documented in
[Development standards](docs/development.md).

## Security and qualification boundary

The service fails closed on unsafe production configuration and applies
conservative Docker defaults, but these controls do not by themselves make
Docker a hardened hostile-workload boundary. The local management API has no
built-in end-user authentication; keep it on loopback or behind an
authenticated trusted boundary.

The completed first-version qualification proves only the named coding/shell
caller, Provider revisions, Contract/profile identities, artifacts, topology,
and scenarios. It does **not** establish:

- aggregate compatibility with every possible caller;
- multi-controller correctness or high availability;
- hostile multi-tenant isolation;
- a complete production deployment or operations model;
- general production readiness.

Treat those as new, separately designed and evidenced project scopes.

## Repository guide

| Path | Purpose |
| --- | --- |
| `contract/` | Normative Provider Contract authority |
| `provider/`, `providerapi/` | Provider domain, applications, adapters, and transport |
| `instance/`, `driver/` | Local instance service and runtime drivers |
| `qualification/`, `internal/qualification*` | External-caller qualification definitions and tooling |
| `profiles/` | Runtime-profile assets and locked image definitions |
| `compatibility/` | Contract identity and compatibility metadata |
| `e2e/` | Same-repository reference callers; not independent interoperability proof |
| `docs/` | Architecture, ADRs, plans, development rules, and evidence status |

Recommended reading order:

1. [Architecture](docs/architecture.md)
2. [Application deployment](docs/deployment.md)
3. [Provider integration guide](docs/platform-integration-profile.md)
4. [Development standards](docs/development.md)
5. [Project status and evidence](docs/STATUS.md)

## Contributing

Preserve the separation between local APIs and Provider wire models. Keep
transport, policy, repositories, and drivers in separate packages; preserve
deadlines and cancellation; reject unknown or oversized input; and do not turn
component or same-repository tests into broader compatibility claims.

See [`AGENTS.md`](AGENTS.md) and
[Development standards](docs/development.md) before changing behavior.

## License

[MIT](LICENSE)
