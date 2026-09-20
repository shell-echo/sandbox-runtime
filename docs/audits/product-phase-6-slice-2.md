# Product v1 Phase 6 Slice 2 — Production Product Kernel

Date: 2026-09-20

Status: complete as local production-mode process/component evidence. Phase 6
is **2/15 complete**; Slice 3 is next.

## Authority boundary

This slice enables `sandbox-runtime product serve` with
`application.mode=production` and `product_process.deployment_level=production`.
It does not compose Provider, Gateway, Guest, Browser, Desktop, object storage,
coordination, KMS, deployment, HA, backup/restore, SLO attainment, hostile
multi-tenant isolation, or a production release.

The local `/instances` API and Provider API remain outside this process. The
root `serve` command still rejects an enabled Product section. Product runtime
execution can later occur only through the locked network Provider Contract.

## Implemented production kernel

- Configuration is exact and default-disabled. Development static bearer
  bindings and the shared development DSN are rejected in production.
- The Product listener loads bounded mode-`0600` certificate and PKCS#8 private
  key files, accepts an exact certificate PEM chain, requires explicit
  server-auth usage, and serves TLS 1.3 only with HSTS and bounded HTTP policy.
- The closed `sandbox-runtime-product-access-key-ring-v1` document contains
  1..32 unique Ed25519 public keys, exact validity windows, and an exact revoked
  key list. The JWT header and claim member sets are closed. Verification binds
  algorithm, type, key ID, issuer, audience, subject/actor, tenant, Product
  role, JTI, issued/not-before/expiry times, maximum lifetime, signature, key
  activity, and revocation. There is no network discovery or fallback key.
- Rotation is restart-based: deploy an overlapping ring, replace processes,
  move issuers to the new key, then deploy a ring that revokes the old key and
  replace processes again.
- Migration and runtime DSNs are distinct protected files. Their configured
  role names must be distinct and exactly equal PostgreSQL `current_user`.
- The migration role applies the digest-locked migration ledger and must retain
  schema-create authority. The runtime role must have schema usage,
  application-table SELECT/INSERT/UPDATE/DELETE, read-only access to the
  migration ledger, and no schema-create authority.
- The migration pool is capped at four connections (one by default) and closes
  before listener bind. No network request path retains DDL authority. The
  runtime pool is bounded to 1..64 connections and every store operation has a
  bounded context.
- Runtime startup performs a read-only, ordered, exact version/digest check for
  all 13 Product migrations and rejects missing, changed, duplicate, or newer
  state.
- An independent dependency worker continuously checks PostgreSQL and exact
  schema compatibility. `/readyz` closes on loss and recovers only after a
  complete successful check; `/livez` remains process-only.
- Because Slice 3 Provider and Slice 4 public data planes are absent, the
  authenticated complete snapshot reports `product.workspace@1.0.0` as
  `unavailable`. The primary-slot policy rejects Workspace mutation before
  persistence or outbox creation.

## Gate evidence

Focused tests cover strict production/development configuration separation,
unknown fields, key overlap, revoked-key rejection, issuer/audience and temporal
policy, cancellation, malformed key rings, private TLS files, certificate
usage, TLS version policy, dependency loss/recovery, and capability context
cancellation.

The tagged real-process gate builds the actual binary and starts a pinned
PostgreSQL 16 container. It creates separate migration/runtime login roles,
prepares their exact grants, and passes:

1. runtime schema-DDL and migration-ledger write denial;
2. bounded pool-exhaustion cancellation;
3. newer-schema rejection and exact-schema recovery;
4. TLS 1.3 listener and plaintext downgrade rejection;
5. authentication precedence over malformed mutation input;
6. authenticated dependency-derived unavailable capability projection;
7. pre-persistence Workspace mutation rejection with zero Workspace rows;
8. migration-role connection release before serving;
9. PostgreSQL pause causing readiness closure and unpause causing recovery;
10. clean Product process stop, restart against retained schema, and recovery;
11. log exclusion for DSN passwords, bearer, and private-key markers; and
12. signal shutdown plus exact PostgreSQL container cleanup.

Required acceptance commands:

```bash
gofmt -w <changed Go files>
go test -race -shuffle=on -count=1 ./...
go vet ./...
go vet -tags=integration ./cmd
go run ./cmd/verify-contract -source-root .
go run ./cmd/verify-product-contract -source-root .
go run ./cmd/verify-product-phase3-evidence \
  -manifest docs/audits/product-phase-3-standalone-evidence.json
go run ./cmd/verify-product-phase4-evidence \
  -manifest docs/audits/product-phase-4-browser-evidence.json
go run ./cmd/verify-product-phase5-evidence \
  -manifest docs/audits/product-phase-5-desktop-evidence.json
SANDBOX_RUNTIME_PRODUCT_PROCESS_INTEGRATION=1 \
  go test -race -tags=integration -count=1 \
  -run '^TestProductProcess(Development|ProductionKernel)Integration$' -v ./cmd
```

## Non-claims and next step

The word `production` in the configuration selects the hardened Product kernel
policy; it does not by itself establish a production deployment or release.
The gate is local, single-host, single-database, repository-built process
evidence. It does not prove database TLS/HA, independently administered failure
domains, external secret/KMS operation, public data planes, Provider runtime
execution, deployment artifacts, backup/restore, upgrades, SLOs, adversarial
tenant isolation, or release acceptance.

Slice 3 must add the deployable Provider control plane without importing
Product truth, exposing the local API, or weakening the locked Provider
Contract.
