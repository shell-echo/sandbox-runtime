# Repository Guidelines

Read `README.md`, `../docs/architecture.md`, and `../docs/STATUS.md` before
changing behavior.

This directory is an independently runnable reference caller and deployment
harness for `sandbox-runtime`, maintained as a separate Go module inside the
Provider repository. Keep these boundaries strict:

- `internal/caller`, `cmd/caller`, `cmd/browser-caller`,
  `internal/sharedcapacity/caller`, and `cmd/shared-capacity-caller` must not
  import any package from `github.com/shell-echo/sandbox-runtime`; they consume
  only locked inputs and public network endpoints.
- `internal/platform` and `cmd/platform-caller` are also black-box candidate
  caller code. They may compose `internal/caller` but must not import any
  Provider implementation package. Their reports are candidate integration
  evidence, not Agent Platform or production evidence.
- `internal/stack` may import exported Provider and Gateway composition
  packages to assemble the reference deployment. It must not import
  `sandbox-runtime/internal/*`, local `/instances` packages, or test helpers.
- `internal/sharedcapacity/stack` and `cmd/shared-capacity-gateway` are a
  separate Gateway fixture. They may compose the exported Browser Gateway and
  Redis capacity adapter, but they do not exercise the Provider API or a real
  Browser runtime.
- `internal/durablerevocation/caller` and `cmd/durable-revocation-caller` are
  black-box callers and must have no direct or transitive Provider dependency.
  `cmd/durable-revocation-revoker` is an independent control process and may
  depend, among Provider packages, only on the exported `gateway` and
  `gateway/revocation/redis` packages. The durable-revocation Gateway fixture
  may compose exported Gateway ports, but the profile does not exercise
  Provider protocol routes or a real Browser runtime.
- `internal/downstreamfencing/caller` and `cmd/downstream-fencing-caller` are
  black-box callers. They may compose `internal/caller`, but must have no
  direct or transitive Provider implementation dependency.
- `cmd/downstream-fencing-v2-e2e` is a separate ADR 0034 successor profile; do
  not relabel ADR 0033 v1 evidence as v2. Its Redis `DUMP`, `RESTORE`, `HDEL`,
  and `DEL` fault controls must remain orchestrator-only behind a separate
  credential, and the file witness must remain outside the Valkey snapshot and
  restore domain. Gateways and callers must never receive that credential or
  fault-control path.
- Never commit generated private keys, certificates, bearer tokens, runtime
  state, logs, or artifact bytes.
- Each passing run proves only its named reference or candidate scenarios. A
  candidate run is not real Agent Platform compatibility. Neither mode proves
  aggregate conformance, multi-controller reliability, hostile multi-tenant
  security, deployment readiness, or production readiness.

Format Go changes with `gofmt`, then run:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go run ./cmd/e2e -check
go run ./cmd/platform-e2e -check
go run ./cmd/browser-e2e -check
go run ./cmd/shared-capacity-e2e -check
go run ./cmd/durable-revocation-e2e -check
go run ./cmd/downstream-fencing-e2e -check
go run ./cmd/downstream-fencing-v2-e2e -check
```
