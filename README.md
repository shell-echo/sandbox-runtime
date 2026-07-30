# sandbox-runtime

Composable Linux sandbox runtime for remote shells, desktops, browsers, and applications.

`sandbox-runtime` is an early-stage runtime project for launching, accessing, and controlling remote workloads inside isolated Linux sandbox instances. It is designed to become a reusable foundation for products such as remote shells, cloud browsers, remote desktops, browser automation workers, AI-operated sandboxes, and embedded remote application environments.

The project is intentionally **runtime-first**. It is not just a cloud browser UI, a room/session collaboration product, or a single-purpose remote desktop application. The goal is to define a composable runtime layer where display, audio, input, streaming, clipboard, storage, networking, automation, and application blocks can be combined according to the needs of the product built on top.

## Status

This repository is in the foundation stage.

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

Planned but not yet implemented:

- Block manifest loader
- Block registry
- runtime images for browser and desktop workloads
- display, audio, input, streaming, clipboard, and file-transfer modules
- WebRTC / VNC / WebSocket connectors
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

The provider boundary, compatibility requirements for the Agent Platform,
security baseline, and authoritative phased delivery plan are defined in
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

All normal API handlers are expected to return the same response envelope:

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

### Agent Platform contract intake

- [x] define the independent Sandbox Provider ownership boundary
- [x] lock the upstream revision, Contract tree, manifest, OpenAPI, and Sandbox Suite
- [x] add read-only Contract lock verification
- [ ] define Provider DTOs separately from local instance and driver models
- [ ] validate Provider DTOs and fixtures against the locked Contract
- [ ] implement mTLS-only capability discovery
- [ ] implement per-operation JWS and request/descriptor digest admission

### Provider lifecycle

- [ ] add durable Provider sandbox, operation, lease, and event models
- [ ] add idempotency, generation, fencing, deadlines, and reconciliation
- [ ] expose the asynchronous Provider API v1 lifecycle subset
- [ ] pass the applicable `sandbox-core-v1` lifecycle and security tests

### Manifest and blocks

- [ ] define block manifest format
- [ ] load block manifests from disk
- [ ] validate manifests
- [ ] expose block registry APIs
- [ ] add `browser-chrome` manifest prototype

### Instance lifecycle

- [x] define instance model
- [x] define lifecycle state machine
- [x] add fake driver
- [x] expose instance CRUD APIs

### Docker runtime

- [x] implement Docker driver
- [ ] create base runtime image
- [ ] create browser runtime image
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
