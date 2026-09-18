# Product v1 Phase 3: Product Kernel, Terminal, Files, and Web

Status: Active; Slice 1 implemented as local component evidence

Started: 2026-09-18

Baseline: `477db77380708443917f6e6dea3555378fb3e39a`

## Objective

Build the target Product defined by ADRs 0042-0047 without collapsing the
Product, Provider, local `/instances`, public Gateway, or Guest Agent trust
boundaries. The phase ends only after the authenticated Product control plane,
primary-code reconciliation, Terminal and Files data planes, Web client,
recording/catalog policy, recovery, and standalone integrated gate pass for one
fixed topology.

This is not a production-readiness shortcut. HA, hostile multi-tenancy,
deployment promotion, capacity planning, SLO attainment, and production
operations remain separately named gates.

## Entry conditions

- Product Phase 1 design and Product Contract authority are fixed.
- Product Phase 2 Provider lifecycle implementation and exact 60-case Provider
  Contract selection are complete.
- The startup audit distinguishes Contract, component, independent-process,
  and Product-ready evidence.
- Every Product runtime action continues to cross the locked Provider network
  Contract; no Product application package imports Provider implementation.

## Fixed slice order

| Slice | Deliverable | Required acceptance gate | Status |
| --- | --- | --- | --- |
| 1 | Startup audit; production Go import guard; Product Contract content verifier; PostgreSQL schema and atomic primary-code Workspace acceptance transaction | Focused race tests; lock/resource/OpenAPI/Schema verification; real PostgreSQL migration/replay/concurrency/rollback test; full repository race/shuffle and vet | **Implemented; local gate passed** |
| 2 | Contract-checked Product DTO projection; strict authenticated `POST /api/v1/workspaces`, Workspace read, and Product operation read | Closed input/body/header tests, auth precedence, tenant/actor nondisclosure, schema projection, HTTP black-box test, Contract fixture/conformance seed | Planned |
| 3 | Leased outbox dispatcher and exact-revision Provider adapter for discovery/admission | No dispatch before commit; exact Contract revision/tree and capability/profile selection; retry/dead-letter/timeout/unknown-result tests; fake network and protected Provider integration | Planned |
| 4 | Primary-code slot reconciler, Provider operation evidence mapping, restart recovery, and Product event cursor/read model | Restart/duplicate/stale generation/ambiguous Provider outcome/event-contiguity tests; Workspace reaches a terminal Product decision only from retained evidence | Planned |
| 5 | Product authorization, resource filters, control leases/fences, quotas, and metadata audit | Cross-tenant nondisclosure, stale fence, concurrent controller, database-time expiry, quota race, audit failure/retention tests | Planned |
| 6 | Product Terminal session control plane and Provider terminal-control adapter | Durable session-before-grant, exact Workspace/slot/fence binding, create/read/close/resize capability honesty, restart and close-race tests | Planned |
| 7 | Public Terminal Gateway with one-use Product grants, bounded proxying, revocation, backpressure, reconnect, and metadata audit | Separate-process client/Product/Gateway/Provider test; no endpoint or ticket leakage; expiry/replay/revocation/capacity/backpressure/reconnect/cleanup cases | Planned |
| 8 | Outbound authenticated Guest Agent control channel and version/capability negotiation | Guest identity binding, replay protection, rotation, deadline/cancellation, reconnect, incompatible-version, and compromised/removed-guest tests | Planned |
| 9 | Files list/stat/watch with confined paths and durable change state | Symlink/traversal/special-file/rename/watch-gap/cursor-expiry/large-directory/cross-tenant tests; no host path or backend identity exposure | Planned |
| 10 | Digest-addressed upload/download, resumable transfer, revision staging, and compare-and-swap commit | Digest mismatch, partial/resume, cancellation, quota/backpressure, concurrent commit, crash recovery, retention and exact cleanup tests | Planned |
| 11 | Product Web control plane and client for Workspace, Terminal, and Files | Generated/checked client; authenticated browser E2E; CSP/CSRF/origin/session/accessibility/error/recovery tests; no private endpoint exposure | Planned |
| 12 | Product recording content pipeline and artifact/recording catalogs | Explicit policy/consent; encryption/redaction/integrity; retention/deletion; tenant-authorized replay/catalog tests; content remains outside control-plane list responses | Planned |
| 13 | Standalone integrated Phase 3 release gate and reproducible evidence bundle | Fresh PostgreSQL plus separate Product/Gateway/Guest/Provider processes; fixed Contract identities; restart/fault/security/cleanup matrix; exact evidence manifest and independent validation | Planned |

Slices are dependency ordered. Later UI or data-plane work cannot substitute
for an earlier authority, persistence, authentication, or recovery gate.
After Slice 1, 12 slices remain.

## Cross-cutting requirements

### Authority and compatibility

Product owns Workspace/slot aggregates, end-user and Agent authorization,
Product operations/events, outbox, control leases, sessions, public grants,
and catalogs. Provider owns provider-local execution and bounded evidence. The
Product adapter consumes the exact repository-owned Provider Contract through
network DTOs and never exposes a Provider operation, reference, endpoint,
backend ID, host path, or credential as a Product resource.

The Product Contract is independently content locked. A Contract-declared
route remains unavailable until its complete dependency graph and slice gate
pass. Capability documents must report unavailable or omit incomplete
profiles; schema enums and route registration are not readiness.

### Persistence and recovery

PostgreSQL is Product authority. Every mutation transaction atomically commits
the aggregate/version change, Product operation, contiguous event, scoped
idempotency result, and outbox work before external dispatch. Workers use
bounded leases and database time. Cancellation after possible external dispatch
does not erase evidence; ambiguous outcomes remain reconcilable and may require
manual review.

Cleanup is an explicit state machine, not a deferred best effort. Termination,
expiry, failed provisioning, disconnected Guests, abandoned transfers, closed
sessions, and retention expiry keep durable obligations until exact owned
resources are confirmed absent. Recovery tests must cover process restart at
each commit/dispatch/observation boundary.

### Security and tenancy

Product bearer authentication precedes resource authority. Tenant and actor
come only from verified identity. Authorization filters every lookup, list,
event stream, grant, catalog, and data-plane action without cross-tenant
existence disclosure. Control fences, quotas, bounded input, safe defaults,
one-use short-lived grants, credential nondisclosure, and metadata-only audit
are mandatory.

Guest Agent and public Gateway are separate identities and processes. Files
paths are guest-relative, normalized, confined, and never resolved by trusting
client-supplied host paths. Browser/Web security additionally requires explicit
origin policy, CSP, CSRF defense, secure cookies or equivalent token handling,
and no wildcard credentialed origin.

### Backpressure, quotas, and observability

Every queue, page, stream, watch, frame, upload, download, recording, audit,
retry, and retained result has a fixed bound and observable rejection mode.
Admission occurs before expensive allocation. Capacity loss and dependency
unavailability fail closed. Logs and metrics use Product public IDs and bounded
reason classes; tickets, payload bytes, filesystem content, secrets, private
Provider references, and raw diagnostics are forbidden.

### Evidence and release

Each slice records its exact authority and the lowest evidence tier actually
passed. Unit/component, Contract projection, real-adapter integration,
same-repository separate-process, independently implemented caller, deployment,
multi-controller, hostile multi-tenant, HA, and production readiness are never
inferred from one another.

Phase 3 completion requires Slice 13. It will still be a bounded standalone
Product result, not production readiness. Production promotion requires a
separate plan for deployable identity, secrets, database roles/migrations,
backups/restores, HA/failover, capacity, monitoring, incident response,
hostile-tenant security, rollout/rollback, SLOs, and independently retained
evidence.

## Slice 1 exact output

- [`phase-3-product-surface-startup.md`](../audits/phase-3-product-surface-startup.md)
  records the pre-implementation audit and non-claims.
- `internal/productboundary` enforces inward production imports.
- `internal/productcontract` and `cmd/verify-product-contract` verify the
  four-resource Product Contract lock, OpenAPI operations/references, and JSON
  Schema compilation.
- `product` defines the first application/port boundary and cryptographic
  public ID generator.
- `product/adapter/postgres` owns migration 1 and the atomic Workspace command
  transaction.

The slice deliberately contains no Product HTTP handler, Provider dispatch,
Terminal/Files/Browser data path, capability-readiness response, or deployment.

### Slice 1 local evidence

The full race/shuffle suite, `go vet ./...`, Provider Contract verifier, Product
Contract verifier, and `git diff --check` pass on 2026-09-18. The tagged Product
PostgreSQL integration package passes against a disposable
`postgres:16-alpine` image pinned to
`sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`.
That run applies and replays migration 1, proves same-result concurrent
idempotency, rejects a different digest, rolls back a constraint failure
without partial authority, and removes its exact temporary container. This is
real-adapter component evidence, not image provenance or deployment evidence.
