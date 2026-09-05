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
go run ./cmd/browser-e2e -check
go run ./cmd/shared-capacity-e2e -check
```
