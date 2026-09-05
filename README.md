# sandbox-runtime

Composable Linux sandbox runtime for remote shells, desktops, browsers, and applications.

`sandbox-runtime` is an early-stage runtime project for launching, accessing, and controlling remote workloads inside isolated Linux sandbox instances. It is designed to become a reusable foundation for products such as remote shells, cloud browsers, remote desktops, browser automation workers, AI-operated sandboxes, and embedded remote application environments.

The project is intentionally **runtime-first**. It is not just a cloud browser UI, a room/session collaboration product, or a single-purpose remote desktop application. The goal is to define a composable runtime layer where display, audio, input, streaming, clipboard, storage, networking, automation, and application blocks can be combined according to the needs of the product built on top.

## Status

This repository is in active implementation. The coding/shell and Browser
reference-caller gates and the local plus hosted two-Gateway shared-capacity
gates pass within their separately named evidence boundaries. ADR 0032 also
passes its caller-owned exact-grant revocation port and real-Valkey adapter
component gate. Its separate two-Gateway/independent-revoker black-box gate,
real Agent Platform migration, production Browser advertisement and Gateway
deployment, aggregate conformance, multi-controller, hostile multi-tenant,
deployment, and production gates remain open.
Start a new development session with
[`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md). It summarizes the current
architecture, engineering rules, verified maturity, blockers, and next work;
the detailed implementation evidence ledger remains in
[`docs/STATUS.md`](docs/STATUS.md). For the caller-facing Provider routes,
ownership boundary, admission rules, and integration checklist, see the
[`Provider Integration Profile`](docs/platform-integration-profile.md).

Currently implemented:

- Go control-plane service
- Cobra-based CLI
- TOML configuration loader
- environment-variable overrides with the `SANDBOX_RUNTIME_` prefix
- structured logging with optional file rotation
- Gin-based HTTP API server
- uniform JSON response envelope
- `/health` endpoint
- graceful multi-server lifecycle management
- Dockerfile for packaging the control-plane binary
- backend-independent instance model and lifecycle state machine
- concurrency-safe fake driver for lifecycle validation
- configurable fake and Docker runtime drivers
- instance lifecycle HTTP API backed by the selected driver
- separate Provider API v1 wire DTOs and locked Contract projection validation
- Provider-specific fake and Docker lifecycle adapters kept separate from local
  `/instances`, with stable coding/shell mounts in the Docker development adapter
- default-disabled Provider capability discovery on a separate mTLS-only HTTPS
  listener
- default-disabled protected-operation admission with frozen public-key files
  and a single-controller replay/fencing guard
- default-disabled, development-only Provider exec composition over the Docker
  lifecycle runtime, a separate durable ledger, bounded private output capture,
  cancellation, result expiry, and restart reconciliation
- bounded `gateway.Stream` adapters for an admitted WebSocket edge and private
  terminal byte stream, plus a local composition that requires caller-owned
  authorization, revocation, recording, and a Provider reference resolver; no
  public Gateway route, command composition, or capability advertisement is
  enabled
- strict internal Block manifest parsing and a bounded read-only registry;
  this configuration format is not Provider wire behavior
- an optional Browser image component with native amd64/arm64 sandbox tests,
  a fixed fail-closed seccomp profile, an immutable GHCR index containing
  exactly linux/amd64 and linux/arm64/v8, and independently verified GitHub
  OIDC/Sigstore provenance; this image evidence does not by itself enable a
  Provider route
- Provider-local Browser session, opaque-reference, operation,
  duration-evidence, and fail-closed Docker runtime-adapter components; the
  adapter binds the exact signed image, private non-TTY CDP relay, stable guest
  mounts, and runtime limits
- a real GitHub CLI/Sigstore Browser provenance verifier and a real Docker
  restricted-egress provisioner. Browser lifecycle authority
  persists the create-time restricted policy; the adapter binds it to a
  per-allocation internal network, pinned private DNS/HTTP/TLS gateway, and
  exact hostname policy
- protected Browser open/handoff transport handlers that preserve admission
  correlation and project only an expiring opaque reference
- a caller-owned Browser Gateway boundary with separate
  `browser_session_id`/`ref:browser-session:*` identity, exact endpoint binding,
  metadata-only audit, bounded reconnect/revocation, RFC 6455 CDP framing, and
  explicit process-local total/per-session connection capacity. Its public
  Browser service also requires a process-local global connection/fixed-window
  request limiter before WebSocket admission and upgrade. A separate bounded
  TLS edge freezes server-auth material before bind, accepts only TLS 1.3 and
  HTTP/1.1, and limits accepted connections, header size, and HTTP timeouts.
  ADR 0030 also makes an authenticated-capacity authority explicit after exact
  grant binding; its memory reference atomically accounts for global, tenant,
  and session partitions and terminates an active connection if its lease is
  lost. ADR 0031 adds a Redis-compatible implementation with atomic shared
  global/tenant/session leases, renewal, TTL reclamation, and stale-owner
  fencing. A clean local `linux/arm64` black-box run passed all 10 scenarios
  through two independent Gateway OS processes and one pinned Valkey authority.
  Hosted workflow run `33955436968` separately passed the same 10 scenarios on
  `linux/amd64`; its GitHub Actions artifact digest is
  `sha256:d99d76374c745fb9a7adcc9b7e09e1f24963641e7d86b277a9a0647b870acdc2`.
  Its private echo fixture does not call the Provider API or a real Browser/CDP;
  capacity rejection is a post-WebSocket-`101` normal `1000` close, not the
  pre-upgrade limiter's HTTP `429`. Contract/Suite identity is metadata only
  (`exercised=false`), and neither run covers Browser image provenance,
  restricted egress, or Provider artifact/usage behavior.
  Those shared-capacity runs do not establish Valkey provenance, HA/failover
  consistency, durable distributed revocation, downstream fencing, or
  production deployment. ADR 0032 and `c0a55d1` replace the split revocation
  check/watch with an exact-grant level-triggered watch, cancel blocked
  resolution/dial work on authority termination, and add a Redis-compatible
  retained-tombstone source/writer with immutable policy, server-time lifetime
  bounds, monotonic expiry retention, bounded polling, and fail-closed outage
  behavior. This is Gateway port plus adapter component evidence only
- a default-disabled Browser Provider command/runtime graph and a separate
  Browser-only reference stack plus black-box caller. Hosted Browser Reference
  E2E run `33955436984` passes 13 initial and 5 process-reconstruction
  scenarios through real mTLS/JWS HTTPS, WebSocket, signed-image provenance,
  Docker, restricted egress, concurrent same-session capacity rejection and
  release, authenticated wrong-Origin pre-upgrade rate rejection and recovery,
  TLS downgrade rejection, slow/oversized HTTP input rejection, listener
  saturation/recovery, usage evidence, and cleanup. The production command
  still exposes no public Browser Gateway and does not advertise Browser

Planned but not yet implemented:

- production Browser advertisement and deployable caller-owned Gateway
  integration after the separately locked two-Gateway/independent-revoker
  durable-revocation caller gate, downstream fencing, HA/failover consistency,
  Valkey provenance, hostile-tenant, storage, configuration, metrics, and
  operational gates
- runtime images for desktop workloads
- display, audio, input, streaming, clipboard, and file-transfer modules
- deployable WebRTC / VNC / public WebSocket Gateway composition
- web viewer and management console
- SDKs for embedding and automation

## What this project is for

`sandbox-runtime` is meant to provide a lower-level runtime foundation for systems that need to run GUI workloads remotely.

Example use cases:

- remote shell and terminal environments
- cloud browser infrastructure
- remote desktop environments
- isolated browser sessions for automation
- AI agents operating real GUI applications
- browser-based access to Linux desktop applications
- ephemeral GUI sandboxes for testing, demos, support, or education
- managed runtime backends for products that need streamed application UI

The long-term direction is to make GUI runtime capabilities composable rather than hard-coded into one product shape.

## Core ideas

### Control plane

The Go service is the control plane. It owns configuration, APIs, runtime orchestration, lifecycle management, policy, and driver integration.

### Runtime instance

A runtime instance is a sandbox environment with a backend-independent lifecycle. An instance may host a shell, browser, desktop, or application using a container or another isolation backend.

### Workload

A workload identifies what an instance hosts. The core model currently supports shell workloads without coupling them to a concrete driver or access protocol. Desktop and browser workloads will be added when their runtime behavior is implemented.

### Block

A block describes a runnable capability or application, such as `browser-chrome`, `browser-firefox`, `desktop-xfce`, or `app-vscode`. Blocks should eventually be defined by manifests rather than hard-coded Go code.

### Module

A module represents a runtime capability used by one or more blocks, such as display, audio, input, streaming, clipboard, file transfer, storage, networking, or automation.

### Driver

A driver is responsible only for creating, inspecting, starting, stopping, and removing the underlying runtime resource. Instance identity, lifecycle policy, and metadata persistence remain in the control plane. Driver removal is idempotent so interrupted cleanup can be retried safely. The Docker driver uses the official Moby Engine client with API-version negotiation, resource limits, restricted networking and capabilities, ownership labels, and retry-safe removal. The fake driver remains available for local control-plane development without a container engine.

### Instance service and repository

The instance service owns IDs, validation, lifecycle transitions, and coordination
with runtime drivers. API reads reconcile stable and transitional states against
the runtime; successful mutations are confirmed before their terminal state is
persisted. Repository implementations remain replaceable: fake development uses
memory, while Docker uses an atomically replaced, versioned state file and runs
startup recovery before accepting requests.

### Connector

A connector exposes access to a running instance. Examples include HTTP, WebRTC, WebSocket control channels, VNC, HLS, or automation protocols.

### Policy

Policy defines what an instance is allowed to do: resource limits, network access, filesystem mounts, clipboard permissions, automation access, and other runtime constraints.

## Architecture direction

The provider boundary, repository-owned Contract, security baseline, and
authoritative phased delivery plan are defined in
[the architecture document](docs/architecture.md). The independent-provider
ownership decision is recorded in
[ADR 0001](docs/adr/0001-agent-platform-provider-boundary.md).

The intended long-term architecture is:

```text
sandbox-runtime/
├── cmd/            # CLI entrypoints and commands
├── config/         # typed configuration loading and validation
├── logger/         # structured logging abstraction
├── server/         # HTTP API server and lifecycle management
├── internal/       # internal error types and shared internals
├── option/         # reusable option/value objects
├── instance/       # instance model, service, repository contract and memory store
├── driver/         # runtime backends (fake and Docker)
│
├── blocks/         # future block manifests
├── runtime/        # future runtime images and guest scripts
├── webapp/         # future viewer and management console
├── docs/           # architecture, specs, and ADRs
└── deploy/         # deployment examples
```

The current repository starts with the Go control-plane foundation. Runtime images, block manifests, and web UI will be added as the project matures.

## Current HTTP API

The local management API and Provider API use separate listeners and wire
formats. Provider capability discovery is default-disabled. When explicitly
configured, its dedicated listener requires TLS 1.2 or newer, normal client
certificate chain verification, and an exact URI SAN match from an
operator-supplied allowlist of fragment-free absolute URI identities. No URI
scheme is hard-coded, and clients that fail certificate or URI identity
admission are rejected during the TLS handshake before HTTP routing.

With the default configuration, the admitted Provider surface contains only:

```http
GET /v1/capabilities
```

It returns a raw Provider API v1 document rather than the local management API
envelope. The immutable startup document intentionally advertises empty
`capabilities` and `runtime_profiles` arrays, plus at least one required,
content-addressed snapshot/restore compatibility profile. That compatibility
metadata does not advertise or authorize snapshot, restore, or another runtime
capability. The `protected_admission` configuration is independently disabled
by default. When explicitly enabled with an immutable public-key bundle and a
durable guard state file, it adds the protected-operation admission boundary.
Individually enabled Provider lifecycle and exec applications may then compose
only their locked routes. Exec requires the Provider Docker lifecycle runtime
and its own file ledger; the development adapters remain rejected in production.
A reconnectable terminal runtime/broker, Docker adapter, durable session
coordination application, and private opaque `ref:session:*` registry/resolver
now exist as development components. The file-backed registry reconstructs a
fresh terminal attach after restart and rechecks expiry, revocation, committed
session handoff, and identity bindings before each dial; it does not expose
backend data. A local Gateway composition requires caller-owned authorization,
revocation, recording, and WebSocket admission before it can proxy that fresh
attach. The Provider command root includes default-disabled development
artifact/usage composition but deliberately does not supply caller-owned public
Gateway policy. Default standalone startup therefore still advertises no
runtime capability. The separately versioned reference E2E stack in
 [`e2e/`](e2e/) supplies those caller-owned dependencies as an independent Go
 module and process boundary, and its exact atomic coding/shell advertisement
 and full reference caller scenarios pass locally; this does not turn the
 Provider default into a deployable production Gateway.

Capability discovery has no query parameters or request document. For request
metadata visible to the handler, a query string (including a bare trailing
`?`), nonzero or unknown `Content-Length`, and `chunked` transfer encoding are
rejected with an empty `400` before capability, application, repository, or
driver dispatch. The handler does not read or probe `Body`; this does not claim
that the Go server lifecycle never reads or drains request framing. Unsupported
transfer codings can instead be rejected by the Go `net/http` parser before the
handler with its standard-library `501` response. The repository-owned OpenAPI
authorizes both `400` and `501` for this operation; the implementation still
returns the bounded empty `400` handler response and observes the parser-level
`501` without claiming a Provider error document for either case until the
corresponding response projection tests pass.

### Health check

```http
GET /health
```

Example response:

```json
{
  "code": "ok",
  "message": "success",
  "success": true,
  "data": {
    "status": "ok"
  },
  "time": "2026-01-01T00:00:00Z",
  "latency": 0
}
```

All local management API handlers are expected to return the same response
envelope:

```json
{
  "code": "ok",
  "message": "success",
  "success": true,
  "data": {},
  "time": "...",
  "latency": 0
}
```

Typed errors are mapped to structured failure envelopes. Unexpected errors are hidden in production mode and only exposed in development mode.

### Instance lifecycle

The instance API uses the configured runtime driver. The default fake driver
validates the control-plane contract without creating containers. Selecting the
Docker driver creates real stopped containers that can be controlled through
the lifecycle API; interactive shell sessions are a later milestone.

```http
POST   /instances
GET    /instances
GET    /instances/:id
POST   /instances/:id/start
POST   /instances/:id/stop
DELETE /instances/:id
```

List instances:

```http
GET /instances
```

The response is an array sorted by instance ID. The service-level instance
quota bounds the size of this response.

Create a shell instance:

```json
{
  "name": "my-shell",
  "workload": "shell"
}
```

Instance names are limited to 128 characters. Request bodies are limited to
64 KiB, and the in-process service allows at most 1,000 instances by default.

### Docker runtime

The safe development default is the in-memory `fake` driver. Production mode
rejects that driver; to use Docker Engine, configure:

```toml
[runtime]
driver = "docker"

[repository]
driver = "file"

[repository.file]
path = "data/instances.json"

[runtime.docker]
host = ""                       # DOCKER_HOST or the default Docker socket
image = "alpine:3.23"
pull_policy = "if_not_present"  # never | if_not_present | always
memory_bytes = 536870912
nano_cpus = 1000000000
pids_limit = 256
operation_timeout_seconds = 30
pull_timeout_seconds = 300
stop_timeout_seconds = 10
user = "65532:65532"
namespace = "default"
controller_id = "runtime-dev-01"
command = ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]
```

The server checks Docker connectivity at startup when this backend is selected.
Containers have networking disabled, all Linux capabilities dropped,
`no-new-privileges` enabled, a read-only root filesystem, a bounded `/tmp`
tmpfs, bounded logs, a numeric non-root user, and CPU, memory, and PID limits.
Driver operations verify ownership labels before mutating a container. The
configured image must contain the configured command and allow it to run as the
configured user; override both values together for custom images. Give each
control-plane deployment a stable, unique controller ID when sharing a Docker
daemon. Namespace groups related resources, while controller ID establishes
ownership and must remain unchanged across restarts.
`controller_id` is required whenever the Docker driver is selected and is never
generated automatically. Changing it makes existing containers invisible to the
new controller; containers without the controller label are deliberately not
adopted.

Until an authentication layer is implemented, production mode accepts only a
loopback API listener. It also requires an image pinned by `@sha256:...` and
rejects plaintext remote Docker endpoints. Explicit Docker hosts continue to
honor the standard `DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH` settings.

Instance metadata is atomically persisted at `repository.file.path`. On startup
the service reconciles every persisted record with Docker, adopts correctly
labelled resources missing from the repository, rejects ownership metadata
conflicts, and finishes interrupted removals. Mount the parent directory on
durable storage when running the control plane itself in a container.
Only one process may open a repository path at a time; a stable `.lock`
companion file prevents two controllers from overwriting each other's snapshot.
The locked file repository currently supports Darwin and Linux.

The live Docker integration test is opt-in:

```bash
SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 go test -tags=integration ./driver/docker
```

## Quick start

### Requirements

- Go 1.26+
- Docker, optional

### Run locally

```bash
git clone https://github.com/shell-echo/sandbox-runtime.git
cd sandbox-runtime

go test ./...
go run . serve
```

The API server listens on `127.0.0.1:8080` by default. There is no application
authentication in v1. Production mode therefore rejects non-loopback listeners;
development deployments that override the bind address must provide their own
authenticated network boundary.

Test the health endpoint:

```bash
curl http://127.0.0.1:8080/health
```

### Run with a config file

A template config is provided at `config.tpl.toml`.

```bash
cp config.tpl.toml config.toml
go run . serve -c config.toml
```

`config.toml` is intended for local runtime configuration and should not be committed.

### Run with environment variables

Configuration values can be overridden with the `SANDBOX_RUNTIME_` prefix. Dotted config keys are converted to uppercase environment variables with `_` separators.

Examples:

```bash
SANDBOX_RUNTIME_APPLICATION_MODE=development \
SANDBOX_RUNTIME_LOGGER_LEVEL=debug \
SANDBOX_RUNTIME_SERVER_API_PORT=8081 \
go run . serve
```

## Docker

Build the image:

```bash
docker build -t sandbox-runtime .
```

Run it:

```bash
docker run --rm \
  -p 127.0.0.1:8080:8080 \
  -v sandbox-runtime-data:/app/data \
  sandbox-runtime
```

Then check:

```bash
curl http://127.0.0.1:8080/health
```

The current Docker image packages only the control-plane service. It does not yet include browser, desktop, or GUI runtime images.

## Configuration

The configuration system uses three sources, in increasing precedence:

1. built-in defaults
2. optional TOML config file
3. environment variables

Default config path:

```text
config.toml
```

Template config path:

```text
config.tpl.toml
```

Environment variable prefix:

```text
SANDBOX_RUNTIME_
```

Example config:

```toml
[application]
name = 'sandbox-runtime'
mode = 'development'

[application.timezone]
name = 'Asia/Shanghai'

[logger]
level = 'info'
add_source = false

[logger.file]
name = ''
max_size = 100
max_backups = 7
max_age = 30
compress = true

[server.api]
host = '127.0.0.1'
port = 8080
```

By default, file logging is disabled. Set `logger.file.name` to a non-empty path to enable rotated file output.

## CLI

```bash
sandbox-runtime --help
sandbox-runtime serve
sandbox-runtime serve -c config.toml
```

Current command:

| Command | Description |
| --- | --- |
| `serve` | Start the configured long-running servers. |

Future commands may include:

| Command | Purpose |
| --- | --- |
| `manifest validate` | Validate block manifests. |
| `block list` | List available runtime blocks. |
| `instance create` | Create a runtime instance. |
| `instance inspect` | Inspect a runtime instance. |
| `instance stop` | Stop a runtime instance. |

## Roadmap

The delivery phases and their release gates in
[the architecture document](docs/architecture.md#delivery-plan-and-release-gates)
are authoritative. Items below are ordered by dependency, not by product
visibility.

### Foundation

- [x] CLI skeleton
- [x] typed config loader
- [x] structured logger
- [x] HTTP API server
- [x] health endpoint
- [x] Docker packaging for the control plane

### Provider Contract and admission

- [x] define the independent Sandbox Provider ownership boundary
- [x] establish the MIT Provider Contract, namespace, schemas, semantic rules, fixtures, and Suite
- [x] add local Contract lock verification
- [x] define Provider DTOs separately from local instance and driver models
- [x] validate Provider DTOs and fixtures against the locked local Contract
- [x] implement mTLS-only capability discovery
- [x] implement per-operation JWS and request/descriptor digest admission
  boundary across the individually composed Provider routes

### Provider lifecycle

- [x] add durable Provider sandbox, operation, lease, and event models
- [x] add idempotency, generation, fencing, deadlines, and reconciliation
- [x] compose the authorized Provider lifecycle application for development (production driver and readiness remain gated)
- [x] add an independent Provider Docker lifecycle adapter with stable mounts,
  restart observation, unknown-outcome evidence, and cleanup
- [x] compose development exec/cancel/result routes over durable acceptance,
  Docker execution, bounded private capture, expiry, and reconciliation
- [x] add a reconnectable Provider terminal runtime/broker and Docker adapter
  with private backend identity and restart-reattach evidence
- [x] pass the locked local lifecycle/security Suite mappings (component evidence only)
- [x] compose durable terminal sessions and artifact/usage development verticals
- [x] derive the exact nonempty advertisement from a complete externally supplied readiness graph
- [x] pass the independent reference caller release gate (Agent Platform and production gates remain separate)

### Manifest and blocks

- [x] define internal block manifest format
- [x] load block manifests from disk
- [x] validate manifests
- [x] expose internal block registry APIs (no public route)
- [ ] add `browser-chrome` manifest prototype

### Instance lifecycle

- [x] define instance model
- [x] define lifecycle state machine
- [x] add fake driver
- [x] expose instance CRUD APIs

### Docker runtime

- [x] implement Docker driver
- [ ] create base runtime image
- [x] create and publish the exact sandboxed, signed amd64/arm64/v8 browser
  image component (Provider runtime composition remains open)
- [x] support container create/start/stop/inspect/remove
- [ ] support container logs
- [x] define runtime resource limits

### Remote GUI capabilities

- [ ] display module
- [ ] audio module
- [ ] input module
- [ ] streaming module
- [ ] clipboard module
- [ ] file-transfer module
- [ ] network policy module
- [ ] automation connector

### Product layer

- [ ] web viewer
- [ ] management console
- [ ] SDK
- [ ] examples
- [ ] deployment templates

## Non-goals for the first stage

The first stage is focused on runtime foundations. It intentionally does not prioritize:

- multi-user rooms
- chat
- billing
- team management
- collaboration UX
- full cloud-browser product features
- production-grade sandbox hardening guarantees

Those can be built on top later, but they should not shape the core runtime prematurely.

## Security note

`sandbox-runtime` applies conservative Docker defaults, but Docker Engine access
and container isolation alone are not a hardened multi-tenant security boundary.
The v1 API also has no built-in authentication. Keep it on loopback or behind an
authenticated trusted proxy in development; production mode currently enforces
loopback. Do not run hostile workloads in production
until the threat model, filesystem policy, seccomp/AppArmor profile, user
namespaces, secrets handling, and host isolation have been explicitly reviewed.

## Development

See [the development standards](docs/development.md) for package boundaries,
security rules, required gates, and Contract change discipline.

Run tests:

```bash
go test ./...
```

Build binary:

```bash
go build -o dist/sandbox-runtime .
```

Run server:

```bash
go run . serve
```

## License

MIT License.
