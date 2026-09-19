# Product Phase 5 Desktop Slice 12 Evidence

Date: 2026-09-20

Implementation: `490c2db96d6ba7a851d7846bc9e5f818dae2be77`

E2E baseline lock: `80bac9d`

## Accepted boundary

Slice 12 adds a Product-owned development-environment startup service and a
Guest-owned workspace materialization protocol without extending the Provider
wire surface:

- the repository catalog selects only `coding-shell-base-v1`, the immutable
  signed coding-shell image publication, the exact runtime profile, four
  ordered mounts, and a digest-bound toolchain descriptor;
- PostgreSQL migration 13 persists validated revision manifests and development
  attempts bound to the current primary code slot and exact connected Guest
  generation. Owner authorization, idempotency, current-slot checks, required
  Guest capabilities, database-time state, event, and metadata-only audit are
  enforced before startup;
- Product streams only manifest-declared file content from the private
  content-addressed store in bounded chunks, verifies every size and SHA-256,
  and accepts readiness only when Guest authority, template revision, workspace
  revision, mounts, and toolchains match exactly;
- Guest materialization rejects traversal, links, unordered or oversized
  manifests, offset drift, digest drift, and unknown startup authority. A
  private transaction journal preserves the prior workspace through the Guest
  commit and Product ready commit, then finalizes cleanup. Failures roll back;
  reconstruction deterministically rolls an interrupted swap backward or a
  committed swap forward; and
- health exposes only liveness/readiness, locked template/workspace revisions,
  public Guest mount points, and toolchain identities. Host paths, object paths,
  credentials, raw endpoints, Guest IDs, and runtime coordinates are absent.

## Real-store and fault evidence

The complete tagged Product PostgreSQL package passed against a fresh
disposable PostgreSQL 16 instance. Migration replay, empty initial revision,
exact Guest capability and generation binding, idempotent replay/conflict,
ready persistence, reconstruction, cross-owner nondisclosure, and audit/event
minimization passed. The pre-existing revision-transfer integration also passed
with persisted validated manifests. The disposable database container was
removed after the run.

Focused race-enabled tests cover exact non-empty workspace replacement,
chunked Guest transport, digest mismatch, unsafe paths, database-ready failure,
pre-finalize rollback, interrupted-swap recovery, immutable catalog selection,
private blob reads, and exact authority projection.

## Validation

The implementation passed:

- focused race/shuffle tests for Product, Guest development, catalog, Guest
  adapter, local blob store, and PostgreSQL packages;
- focused `go vet` for the same packages;
- the complete tagged Product PostgreSQL race/shuffle package against fresh
  PostgreSQL 16; and
- the E2E parent-lock regression after advancing the repository baseline to the
  exact implementation revision.

The full repository, Contract, retained evidence, and CI gates are run from the
clean documented revision before Slice 12 is merged.

## Evidence boundary

This is Product/Guest protocol, local content-store, and real-PostgreSQL
component evidence. It does not provide a real Provider Desktop media/input
bridge, the unified Product Web shell, production startup composition,
capability advertisement, independent-process release evidence, deployment,
HA, hostile-multitenant isolation, or production readiness.
