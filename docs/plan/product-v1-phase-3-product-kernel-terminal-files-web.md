# Product v1 Phase 3: Product Kernel, Terminal, Files, and Web

Status: Active; Slices 1-10 implemented as local component and real-PostgreSQL evidence

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
| 2 | Contract-checked Product DTO projection; strict authenticated `POST /api/v1/workspaces`, Workspace read, and Product operation read | Closed input/body/header tests, auth precedence, tenant/actor nondisclosure, schema projection, HTTP black-box test, Contract fixture/conformance seed | **Implemented; local and real-PostgreSQL HTTP gates passed** |
| 3 | Leased outbox dispatcher and exact-revision Provider adapter for discovery/admission | No dispatch before commit; exact Contract revision/tree and capability/profile selection; retry/dead-letter/timeout/unknown-result tests; fake network and protected Provider integration | **Implemented; local and real-PostgreSQL gates passed** |
| 4 | Primary-code slot reconciler, Provider operation evidence mapping, restart recovery, and Product event cursor/read model | Restart/duplicate/stale generation/ambiguous Provider outcome/event-contiguity tests; Workspace reaches a terminal Product decision only from retained evidence | **Implemented; local and real-PostgreSQL gates passed** |
| 5 | Product authorization, resource filters, control leases/fences, quotas, and metadata audit | Cross-tenant nondisclosure, stale fence, concurrent controller, database-time expiry, quota race, audit failure/retention tests | **Implemented; local and real-PostgreSQL gates passed** |
| 6 | Product Terminal session control plane and Provider terminal-control adapter | Durable session-before-grant, exact Workspace/slot/fence binding, create/read/close/resize capability honesty, restart and close-race tests | **Implemented; local and real-PostgreSQL gates passed** |
| 7 | Public Terminal Gateway with one-use Product grants, bounded proxying, revocation, backpressure, reconnect, and metadata audit | Separate-process client/Product/Gateway/Provider test; no endpoint or ticket leakage; expiry/replay/revocation/capacity/backpressure/reconnect/cleanup cases | **Implemented; local and real-PostgreSQL gates passed; standalone process matrix retained for Slice 13** |
| 8 | Outbound authenticated Guest Agent control channel and version/capability negotiation | Guest identity binding, replay protection, rotation, deadline/cancellation, reconnect, incompatible-version, and compromised/removed-guest tests | **Implemented; local and real-PostgreSQL gates passed** |
| 9 | Files list/stat/watch with confined paths and durable change state | Symlink/traversal/special-file/rename/watch-gap/cursor-expiry/large-directory/cross-tenant tests; no host path or backend identity exposure | **Implemented; local and real-PostgreSQL gates passed** |
| 10 | Digest-addressed upload/download, resumable transfer, revision staging, and compare-and-swap commit | Digest mismatch, partial/resume, cancellation, quota/backpressure, concurrent commit, crash recovery, retention and exact cleanup tests | **Implemented; local and real-PostgreSQL gates passed** |
| 11 | Product Web control plane and client for Workspace, Terminal, and Files | Generated/checked client; authenticated browser E2E; CSP/CSRF/origin/session/accessibility/error/recovery tests; no private endpoint exposure | Planned |
| 12 | Product recording content pipeline and artifact/recording catalogs | Explicit policy/consent; encryption/redaction/integrity; retention/deletion; tenant-authorized replay/catalog tests; content remains outside control-plane list responses | Planned |
| 13 | Standalone integrated Phase 3 release gate and reproducible evidence bundle | Fresh PostgreSQL plus separate Product/Gateway/Guest/Provider processes; fixed Contract identities; restart/fault/security/cleanup matrix; exact evidence manifest and independent validation | Planned |

Slices are dependency ordered. Later UI or data-plane work cannot substitute
for an earlier authority, persistence, authentication, or recovery gate.
After Slice 10, 3 slices remain.

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

## Slice 2 exact output

- `productapi` owns the bearer-authentication port and a bounded static-token
  development adapter; verified identity is projected to one tenant and actor.
- `productapi/v1` owns Product wire DTOs and authenticated handlers for
  capability discovery, Workspace creation/read, and Product-operation read.
- Authentication runs before body or resource authority. Duplicate security
  headers, duplicate JSON members, unknown fields, trailing values, oversized
  bodies, invalid content types, and malformed Product values fail before the
  command store is called.
- PostgreSQL provides consistent tenant-scoped Workspace/slot and operation
  reads; application policy returns nondisclosing not-found results across
  actors.
- Product Contract lock `sha256:a5c9cfa4fdfcdb481336732b4b33de39b57ef6e30dc668b95a0cf524b143b4d1`
  now contains four schema-valid fixtures and a three-case repository-Go-test
  conformance seed in addition to the original four resources.

Focused race/shuffle tests and a real-PostgreSQL `httptest` black-box create and
read flow pass. The capability response remains empty because Provider
dispatch, reconciliation, Terminal, Files, Gateway, and recording dependency
graphs are not yet complete. No deployable Product listener or readiness claim
follows from this slice.

## Slices 3-4 exact output

- Migration 2 establishes separate private authorities for Product attempts,
  Provider bindings, reconciliation checkpoints, control leases, sessions,
  one-use grants, Guest bindings, revisions/transfers, catalogs, recording
  segments, and metadata audit. It also adds database-time outbox leases.
- `product/adapter/provider` is the only Product package that imports Provider
  wire DTOs. It rejects every Provider revision/tree except the repository
  lock, selects exact runtime/capability profiles from one discovery snapshot,
  computes RFC 8785 request and descriptor digests, and independently creates
  the Contract Admission Context and Ed25519 compact JWS.
- The dispatcher uses stable Product operation/attempt/fence identities.
  Known pre-dispatch retryable rejection returns to a bounded exponential
  schedule, exhausted work dead-letters, and any possibly dispatched or
  malformed accepted response becomes retained `outcome_unknown` evidence.
- The level-triggered reconciler leases retained nonterminal attempts, performs
  a fresh protected Provider operation read, rejects substituted correlations
  and stale slot generations, and commits attempt/binding/operation/slot/
  Workspace projections plus the next contiguous event atomically.

Focused race/shuffle tests exercise exact discovery, signed protected create,
revision drift, ambiguous responses, retry classification, and worker policy.
A disposable PostgreSQL 16 adapter run applies and replays both migrations and
proves the complete create/outbox/dispatch/observe/terminal-event path. These
are component and real-adapter results, not a standalone deployment claim.

## Slice 5 exact output

- Authenticated principals now carry the reserved Product role vocabulary.
  Workspace creation and control authority require the owner role before body
  parsing; all resource reads remain tenant- and owner-filtered with
  nondisclosing not-found behavior.
- Product control leases are PostgreSQL authority. Acquire expires elapsed
  rows using database time, refuses live takeover, allocates a monotonic
  per-scope fence, and commits the lease, Workspace version, contiguous event,
  metadata audit, and scoped idempotency result together. Renew and release
  require the exact actor, lease, and fence.
- Tenant Workspace quota admission is serialized by a tenant-scoped database
  lock. A configured limit cannot be exceeded by concurrent acceptance; the
  conservative default remains bounded.
- Security audit stores only safe metadata identifiers and reason classes.
  Audit insertion is part of the mutation transaction, so audit storage
  failure cannot leave an unaudited successful authority change.

Focused race tests and disposable PostgreSQL evidence cover idempotent control
acquire, live-controller conflict, stale fence rejection, renewal/release,
event and audit counts, and concurrent quota admission. Collaboration roles,
operator revocation, external identity-provider configuration, and hostile
multi-tenant qualification remain outside this standalone slice.

## Slice 6 exact output

- Terminal session creation first commits a Product session, Product
  operation, contiguous Workspace event, metadata audit, idempotency result,
  and `session.open` outbox record. Close first commits `draining`, revocation
  intent, a separate operation/event, and `session.close` work.
- Session workers use the same database-time leased-outbox discipline and
  stable attempt/fence identities as Workspace provisioning. Provider
  `accepted` remains Product `provisioning`; only retained terminal evidence
  can select `ready`, `closed`, or `failed`.
- The caller-side Provider adapter independently signs the locked
  `open_runtime_session` and `close_runtime_session` requests and requires the
  exact terminal and terminal-control capability profiles on one selected
  runtime profile.
- Authenticated Product routes now create/list/read/close terminal sessions.
  Resize is deliberately unavailable because the locked Provider Contract has
  no terminal-resize operation; valid requests receive
  `PRODUCT_CAPABILITY_UNSUPPORTED` rather than an in-process fallback.

Focused race tests cover intent construction and capability failure. The real
PostgreSQL test proves create-before-dispatch, terminal evidence projection,
read/list authority, close-before-cleanup, and a terminal close decision. A
public connection grant and data path do not exist until Slice 7.

## Slice 7 exact output

- Product now mints session-version-bound, control-fenced connection grants.
  Tickets are cryptographically random, live for at most 60 seconds, are
  retained only as a SHA-256 lookup digest plus AES-256-GCM ciphertext for
  exact idempotent replay, and become unusable after their first consume.
- A successful terminal observation retains the opaque Provider handoff and
  connection generation only in private Product storage. The public Product
  response contains the Product Gateway URI and ticket, never the Provider
  sandbox, operation, handoff, or endpoint.
- `product/adapter/gateway` owns the `product-terminal.v1` WebSocket edge. It
  disables compression, accepts bounded binary frames, translates a consumed
  Product grant into private Gateway authority, uses shared authenticated
  capacity, and polls Product authority so session closure, grant expiry, a
  stale handoff generation, or control-lease loss terminates the connection.
- Gateway audit writes metadata-only events through a Product-owned durable
  audit port. Ticket, payload, handoff reference, endpoint, and raw dependency
  diagnostics are excluded.

Focused race tests cover binary proxying, ticket replay, protocol rejection,
and live authority revocation. A fresh disposable PostgreSQL 16 run proves
encrypted retained ticket replay, single-use consumption, exact control and
handoff binding, and revocation after session close. The final fresh-database,
separate-process client/Product/Gateway/Guest/Provider matrix remains the
Slice 13 phase gate; no deployment or production-readiness claim follows.

## Slice 8 exact output

- `guestagent` is a repository-enforced neutral protocol package: it cannot
  import Product, Provider, Gateway, driver, or local-instance authority. A
  Guest makes the outbound WebSocket connection; no inbound guest port or
  control-plane credential is required.
- Authentication uses a fresh 256-bit server challenge and a Guest-held
  Ed25519 key. The signature binds challenge and expiry, client nonce, guest
  identity, binding generation, exact protocol version, and sorted offered
  capabilities. Captured hellos therefore cannot authenticate a later
  challenge.
- Product PostgreSQL retains only the registered public key and its digest,
  exact Workspace/slot generation, monotonically increasing binding
  generation, configured capabilities, connection nonce, state, and expiry.
  Rotation revokes the prior live binding before the new generation becomes
  usable; a stale disconnect cannot clear a newer connection.
- The channel enforces exact version negotiation, bounded messages and
  in-flight work, capability-scoped calls, propagated deadlines and explicit
  cancellation. Product continuously checks durable Guest authority; removal,
  expiry, slot-generation drift, or lost readiness closes the channel. A
  transport-only disconnect permits a fresh-nonce reconnect.

Race tests cover authenticated calls, replay resistance, operation
cancellation, reconnect, live revocation, and rotated-key rejection. A fresh
PostgreSQL integration run proves idempotent registration, challenge proof,
generation rotation, old-key rejection, and removal. Runtime image injection,
deployment identity, and hostile-guest isolation remain later release gates.

## Slice 9 exact output

- `guestagent/files` resolves every guest-relative component from a retained
  root directory descriptor with `openat`, `O_NOFOLLOW`, and directory checks.
  Absolute paths, traversal, non-canonical paths, symlink roots/components,
  and direct stat of special files fail closed; no host path is projected.
- List and stat are bounded and sorted. Regular-file revisions are SHA-256
  content digests from the already confined descriptor. Recursive snapshots
  skip symlinks and special files, enforce entry/per-file/aggregate byte
  limits, propagate cancellation, and contain only regular files/directories.
- The Product Guest adapter returns the exact authenticated Guest ID, slot
  generation, and Guest binding generation with each result. Product
  PostgreSQL rechecks that authority after list/stat and atomically before
  accepting a snapshot, preventing a rotated or rebuilt Guest from committing
  stale observations.
- Current file metadata and a continuous per-slot change sequence are durable.
  Snapshot diff emits create/modify/remove and unambiguous content-preserving
  rename events, retains a bounded 1,000-change window, and reports expired
  cursors rather than silently skipping gaps. Reads remain owner- and
  tenant-filtered.

Race tests cover traversal, symlinks, FIFO handling, pagination, content
changes, rename, and the full Hub/Agent/Product projection. Fresh PostgreSQL
evidence covers create/rename/modify sequences, cross-tenant nondisclosure,
and stale Guest rejection. Files are not yet durable Workspace content; upload,
revision CAS, and transfer cleanup belong to Slice 10.

## Slice 10 exact output

- Upload acceptance first commits a tenant/actor/Workspace-bound transfer,
  expected digest and size, expiry, quota decision, contiguous event, audit,
  and idempotency result. Only then does the adapter create the private staging
  object. Public transfer state never contains its object reference or path.
- Chunks are bounded to 1 MiB and require the exact committed offset. The
  local standalone adapter uses no-follow private files, advisory file locking,
  durable sync, SHA-256 inspection, hard-link content-addressed commit, and
  digest-safe deduplication. Resume reconciles the authoritative object length
  back into a lagging Product transfer after a crash boundary.
- Completion requires exact size and digest. Mismatch becomes durable failure;
  cancellation and expiry move through `cleanup_pending` until the precise
  staging object is absent, then settle as `cancelled` or `expired`. Cleanup is
  bounded and restartable.
- A Workspace revision accepts only a complete upload containing an exact
  canonical, sorted, bounded manifest. PostgreSQL locks the Workspace and
  `main` head, requires the caller's expected head and Workspace version,
  creates an immutable parent-linked revision, and advances the branch with
  CAS. Concurrent stale commits cannot overwrite the winner.
- Revision-manifest download creates an actor-filtered short-lived transfer and
  streams bounded chunks from the private content-addressed reference.

Race tests cover private storage offset checks, resume, digest validation,
deduplication, download, symlink-root rejection, and exact deletion. Fresh
PostgreSQL evidence covers active-transfer quota, storage-ahead crash recovery,
idempotent completion and revision commit, digest mismatch, cancellation,
download, concurrent CAS, expiry, and restartable cleanup. This is a bounded
standalone storage adapter, not a claim about external object-store HA.
