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
| Product v1 Phase 5 Desktop | **6/15 complete**; the exact Product network adapter, isolated Desktop workers, retained recovery, and real-store gate pass; grants are next, advertisement disabled |
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
has completed **6/15** dependency-ordered slices. Slice 1 locks a separate
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
gate passes; production composition, end-user grants, public data planes, Web
experience, and capability advertisement remain later gates.

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
- A locked, separately modeled Provider Desktop Contract surface whose runtime
  and capability advertisement remain disabled pending later Phase 5 slices.
- Product-owned Desktop slot/session intent with exact profiles, transactional
  PostgreSQL persistence, quotas, audit, and isolated pending outbox work.
- A locked network-only Product Desktop Provider adapter with separate
  generation authorities, durable dispatch/observation recovery, and
  Desktop-specific session cleanup; it is not production-composed.
- Provider-local Desktop operation authority with durable replay/fencing,
  exact-owned close/expiry cleanup policy, and unadvertised protected handlers.
- An exact signed Desktop image plus Provider-local Docker adapter, private
  reference resolver, lifecycle readiness, revocation/cleanup, and duration
  usage components; they are not composed into production startup or advertised.
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
