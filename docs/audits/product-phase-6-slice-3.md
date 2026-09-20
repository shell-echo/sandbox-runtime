# Product v1 Phase 6 Slice 3 — Deployable Provider Control Plane

Date: 2026-09-20

Status: complete as local role-process, transactional-state, and real-backend
evidence. Phase 6 is **3/15 complete**; Slice 4 is next.

## Authority boundary

This slice adds the production-only `sandbox-runtime provider serve` role. It
does not run the local `/instances` API, import Product business truth, or host
the Product API. The root `serve`, `product serve`, and `provider serve`
commands reject mixed process authority.

The locked Provider v1 Contract permits one exact advertised runtime shape per
capability snapshot. Consequently one Provider process selects either the
atomic `coding_shell` profile or the Desktop-only profile. It does not combine
the two advertisements. Product remains responsible for desired state,
end-user authorization, and the aggregate operation ledger; this process owns
only Provider-local execution and retained evidence.

## Implemented control plane

- `provider_process` is default-disabled, production-only, rejects unknown
  fields, and requires explicit IP listeners, a distinct loopback probe,
  absolute private authority files, bounded timeouts/pools, exact database
  roles, immutable runtime inputs, and one profile.
- The Provider listener requires exact URI-SAN mTLS identity and TLS 1.3.
  Protected routes retain the locked mTLS plus JWS admission order and use a
  PostgreSQL-backed one-use replay/fencing guard.
- A separate migration role applies the digest-locked Provider schema. The
  runtime role has schema usage, read-only migration-ledger access, and only
  read/update authority on the singleton control-state row; schema create,
  ledger write, row insert, and row delete are denied. Migration connections
  close before listener bind.
- Lifecycle, exec/cancel/result, Terminal sessions and opaque references,
  artifact staging/evidence, usage, Desktop sessions and references, and
  admission guard state use Provider-local PostgreSQL repositories. One locked
  aggregate row serializes mutations across controllers with `SELECT FOR
  UPDATE`; every repository read observes only committed state.
- Existing repository snapshots can contain private NUL-separated scope keys.
  PostgreSQL `jsonb` rejects their valid JSON escape, so each bounded strict
  JSON snapshot is stored byte-exact as a base64 JSON string inside the
  aggregate object. Strict import still rejects unknown, corrupt, empty, and
  oversized state.
- Coding-shell composition uses the real Docker lifecycle/exec/Terminal/
  artifact adapters and advertises exactly `sandbox.exec`, `sandbox.terminal`,
  `sandbox.terminal-connect`, `sandbox.lifecycle-control`, and
  `sandbox.terminal-control` with the locked runtime/profile IDs.
- Desktop composition uses the repository-locked signed Desktop image,
  provenance verification, mandatory restricted egress, lifecycle/session/
  reference/usage applications, and advertises only `sandbox.desktop` with the
  locked Desktop runtime/profile IDs and configured architecture.
- Startup recovers every composed operation family before serving. A bounded
  reconciliation worker repeats recovery and closes readiness on any failed
  pass. `/readyz` also requires database connectivity and exact schema
  compatibility; `/livez` is process-only. The loopback probe serves no
  Provider Contract, Product API, local API, or diagnostic body.
- Shutdown is bounded and closes listeners, workers, state, runtime adapters,
  opaque references, and owned active sessions in dependency order.

## Gate evidence

Focused tests prove strict profile/configuration separation, command-role
separation, exact coding-shell and Desktop advertisements, TLS 1.3 policy,
probe route closure, first-pass readiness, reconciliation failure/recovery,
bounded state encoding, and safe shutdown.

The tagged PostgreSQL gate starts a digest-pinned PostgreSQL 16 container with
distinct migration/runtime identities. Across two runtime pools it persists
and rereads lifecycle, exec, Terminal, artifact, usage, Desktop, and admission
state; 32 concurrent reservations accept one JTI and replay the other 31. It
also proves runtime DDL/ledger-write denial, pause failure, recovery, database
restart with retained evidence, exact-schema rejection/recovery, and container
cleanup.

The real-process gate builds the actual binary and starts `provider serve`
against PostgreSQL and the real Docker backend. It proves TLS 1.3 mTLS,
unauthenticated and downgrade denial, exact capability discovery, absence of
`/instances`, migration-connection release, runtime-role denial, database-loss
readiness closure/recovery, process restart, nondisclosure, signal shutdown,
and cleanup. Retained Docker gates separately pass complete coding-shell
lifecycle/exec/Terminal behavior and the signed Desktop private broker with
exact cleanup.

Required acceptance commands:

```bash
gofmt -w <changed Go files>
go test -race -shuffle=on -count=1 ./...
go vet ./...
go vet -tags=integration ./cmd ./provider/adapter/postgres
go run ./cmd/verify-contract -source-root .
go run ./cmd/verify-product-contract -source-root .
go run ./cmd/verify-product-phase3-evidence \
  -manifest docs/audits/product-phase-3-standalone-evidence.json
go run ./cmd/verify-product-phase4-evidence \
  -manifest docs/audits/product-phase-4-browser-evidence.json
go run ./cmd/verify-product-phase5-evidence \
  -manifest docs/audits/product-phase-5-desktop-evidence.json
SANDBOX_RUNTIME_PROVIDER_PROCESS_INTEGRATION=1 \
  go test -race -tags=integration -count=1 \
  -run '^TestProviderTransactionalStateIntegration$' -v \
  ./provider/adapter/postgres
SANDBOX_RUNTIME_PROVIDER_PROCESS_INTEGRATION=1 \
  go test -race -tags=integration -count=1 \
  -run '^TestProviderProcessProductionIntegration$' -v ./cmd
SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 \
  go test -race -tags=integration -count=1 \
  -run '^TestProviderDockerLifecycleIntegration$' -v \
  ./provider/lifecycle/driver/docker
SANDBOX_RUNTIME_DESKTOP_ADAPTER_INTEGRATION=1 \
  go test -race -tags=integration -count=1 \
  -run '^TestDesktopBrokerTransportIntegration$' -v \
  ./provider/desktop/driver/docker
```

## Non-claims and next step

This is local single-host role-process/component evidence. The singleton-row
store is a correctness-first transactional boundary, not an HA or throughput
qualification. PostgreSQL TLS/HA, independently administered failure domains,
external coordination/object storage, secret providers/KMS, published
role-specific application images, deployment assets, backups, SLOs, hostile
multi-tenant isolation, and production readiness remain unproved.

The production Product process still reports runtime capability unavailable
because no Product-to-Provider production topology or public data plane is
composed. Slice 4 must add separate Gateway, Guest, Browser, and Desktop role
commands/configuration and prove their private/public trust and shutdown
graphs.
