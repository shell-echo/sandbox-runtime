# Development Standards

## Toolchain and commands

Use the Go version declared in `go.mod`. Docker is optional for ordinary unit
tests and required for the tagged Docker integration test.

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 go test -tags=integration -count=1 ./driver/docker ./provider/lifecycle/driver/docker
SANDBOX_RUNTIME_BROWSER_ADAPTER_INTEGRATION=1 go test -tags=integration -count=1 ./provider/browser/driver/docker
SANDBOX_RUNTIME_BROWSER_PROVENANCE_INTEGRATION=1 go test -tags=integration -count=1 ./provider/browser/provenance/ghcli
go run ./cmd/verify-contract -source-root .
go run ./cmd/run-conformance -source-root . -race -shuffle
```

Format changed Go files with `gofmt`. Do not weaken or skip a gate to make a
change pass. Record an unavailable integration environment separately from a
code failure.

## Package boundaries

- `server` and future `providerapi` packages own transport only.
- application services own lifecycle and coordination, without Gin or Docker
  types.
- repository and driver interfaces are ports; concrete implementations stay in
  their adapter packages.
- `driver/*` owns backend actions and observations, not public policy or durable
  platform truth.
- Provider wire DTOs must remain separate from `instance` models and backend
  engine types.
- optional capabilities such as exec, terminal, and snapshot use focused ports;
  do not grow one mandatory driver interface for unsupported features.

Dependencies point inward. Export the minimum surface and keep cross-package
calls on public contracts rather than implementation structs.

## Go and API rules

- accept `context.Context` on blocking or external operations and preserve
  cancellation and deadlines;
- wrap errors with operation context and map them to stable public codes only at
  the transport boundary;
- reject unknown JSON fields, multiple JSON values, oversized bodies, invalid
  identifiers, and unsafe defaults;
- return caller-safe snapshots from repositories and services;
- protect shared state explicitly and test races and cancellation paths;
- use injected clocks, ID generators, engines, and repositories where
  deterministic fault tests need them.

Never expose container IDs, host paths, daemon errors, raw endpoints, secrets,
or credentials through a stable API. Production configuration must fail closed
when authentication, persistence, image pinning, or transport safety is absent.

## Provider Contract discipline

The repository-owned MIT Contract under `contract/` defines wire behavior through
its locked OpenAPI, JSON Schemas, semantic rules, fixtures, and Conformance
Suite. Update `compatibility/sandbox-runtime/contract.lock.json` only as a
reviewed protocol change, then update DTOs, mappings, fixtures, tests, and
documentation together. Do not claim compatibility with an absent external
Contract.

Contract lock verification proves only the identity of consumed inputs. Unit
tests prove components. Conformance, multi-controller reliability, security,
deployment, and production readiness remain separate evidence tiers.

## Composition and advertisement discipline

Provider lifecycle, exec, terminal/Gateway, artifact/usage, and capability
advertisement are separate readiness boundaries. Development exec composition
requires the Provider Docker lifecycle runtime and its own durable file ledger;
it must not reuse local `/instances` persistence. Production continues to
reject the development Provider lifecycle and exec adapters.

Keep startup advertisement empty until the complete P2.5h dependency graph and
its named gates pass. A composed route, a Contract projection, a local Suite
mapping, and CI are distinct evidence and none substitutes for the independent
P2.5i caller/platform E2E gate.

## Terminal and Gateway discipline

A terminal runtime must be independently reattachable after Provider restart;
do not present a retained in-memory stream, one-shot Docker exec attach, or a
replacement shell as reconnect evidence. Persist provider-neutral allocation
receipts and opaque `ref:session:*` references separately from adapter-private
backend identity. Reconstruct a fresh dial operation through the resolver on
every Gateway connect or reconnect; never persist a Go closure.

The P2.5f1 Docker development adapter uses an in-sandbox PTY broker and keeps
its container, broker-exec, and Unix-socket identity in adapter-private state.
Its integration test builds the broker into the test sandbox's writable
`/workspace`; that is test deployment evidence only. A real deployment must
ship the broker at a fixed read-only image path before the adapter can be
considered for production configuration.

Gateway user and tenant authorization, revocation policy, and audit sinks are
caller-owned ports. Enabled composition must require them explicitly and fail
closed when any is absent. Do not add a static or allow-all authorizer. The
current Provider Contract does not authorize resize or explicit close-session
mutations, so either feature requires a coordinated protocol decision before
implementation.

## Change and review discipline

Keep changes scoped to one delivery slice and state its non-goals. New behavior
requires success, rejection, cancellation, and recovery tests proportional to
its failure modes. Changes to ownership, public protocol, reliability semantics,
or security boundaries require an ADR and coordinated compatibility review.
