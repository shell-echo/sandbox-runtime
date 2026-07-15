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
- instance lifecycle HTTP API backed by the fake driver

Planned but not yet implemented:

- Block manifest loader
- Block registry
- Docker driver
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

A driver is responsible only for creating, inspecting, starting, stopping, and removing the underlying runtime resource. Instance identity, lifecycle policy, and metadata persistence remain in the control plane. Driver removal is idempotent so interrupted cleanup can be retried safely. The first real driver is expected to be Docker; the current fake driver validates runtime behavior without requiring containers.

### Instance service and repository

The instance service owns IDs, validation, lifecycle transitions, and coordination with runtime drivers. Transitional states are reconciled against the driver's observed runtime state after ambiguous failures and when an interrupted instance is inspected again. Instance metadata is stored through a repository interface; the current in-memory repository can later be replaced by persistent storage without changing API handlers or drivers.

### Connector

A connector exposes access to a running instance. Examples include HTTP, WebRTC, WebSocket control channels, VNC, HLS, or automation protocols.

### Policy

Policy defines what an instance is allowed to do: resource limits, network access, filesystem mounts, clipboard permissions, automation access, and other runtime constraints.

## Architecture direction

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
├── driver/         # runtime backends (fake now, Docker later)
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

The current instance API uses the in-memory fake driver. It validates the
control-plane contract but does not yet start real containers or shells.

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

The API server listens on `0.0.0.0:8080` by default.

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
docker run --rm -p 8080:8080 sandbox-runtime
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
mode = 'production'

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
host = '0.0.0.0'
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

### Foundation

- [x] CLI skeleton
- [x] typed config loader
- [x] structured logger
- [x] HTTP API server
- [x] health endpoint
- [x] Docker packaging for the control plane

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
- [ ] add instance event model

### Docker runtime

- [ ] implement Docker driver
- [ ] create base runtime image
- [ ] create browser runtime image
- [ ] support container start/stop/inspect/logs
- [ ] define runtime resource limits

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

`sandbox-runtime` is not yet a hardened security boundary. Treat the current implementation as an early runtime prototype. Do not run untrusted workloads in production until the driver, isolation, filesystem, network, and policy layers have been explicitly designed and reviewed.

## Development

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
