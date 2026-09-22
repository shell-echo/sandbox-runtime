# Product v1 Phase 6 Slice 5 Startup Audit

Date: 2026-09-22

Status: implementation underway. Product Phase 6 remains **4/15**.

## Claim boundary

This audit freezes the Slice 5 work order and records bounded component and
real-adapter checkpoints. It is not deployment, independent-process,
break-glass or production evidence. The accepted Slice 4 result remains
historical under ADR 0053 and does not cover this source.

## Existing components and gaps

| Concern | Reused repository component | Open production gap |
|---|---|---|
| Opaque references | `internal/secretref.Reference` and `Provider` | Production commands still consume several raw secret file paths and do not resolve complete role/tenant/purpose/version bindings. |
| Private files | `internal/secretfile` and `secretref.FileProvider` enforce absolute path, regular-file, no-symlink, mode-`0600` and size rules | File secrets are bootstrap/development inputs, not an external secret provider or rotation authority. |
| Version/window state | `KeyProvider`, `KeyMaterial`, `KeyState`, `RotationWindow` and `RotatingKeySet` | There is no production provider event/revision controller spanning all six roles. |
| Local encryption | Existing AES envelope helper and local recording store | Raw local master keys remain process-held; no KMS/HSM seal/open path is connected to recording, tickets or data. |
| Dependency configuration | Phase 6 dependency references are strictly parsed | String validation does not resolve a secret, prove workload identity or enforce provider-side revocation. |
| Emergency access | Existing metadata-only audit foundations | No approved break-glass state machine, dual control, expiry or independently observed audit gate exists. |

## Frozen Slice 5 order

1. Define a closed, versioned purpose/tenant/role binding; add typed provider
   ports and a bounded fail-closed cache by extending existing `secretref`
   components.
2. Migrate Product, Provider, Gateway, Guest, Browser and Desktop production
   startup to role-owned providers; reject inline and long-lived path material.
3. Integrate a real KMS/HSM envelope adapter into recording first, then the
   exact ticket/data uses selected by the architecture; raw KMS keys must not
   enter role processes.
4. Add short-lived, least-scope workload credentials and bounded renewal.
5. Add overlap rotation, stale/revoked rejection, restart recovery and
   approved, expiring, metadata-only break-glass audit.
6. Run the complete real-adapter and independent-process gate for KMS loss,
   cache expiry, rotation, revocation, restart, plaintext exclusion and exact
   cleanup; then seal Slice 5 evidence.

The order is fixed for this slice. A component test cannot substitute for the
real KMS or independent-process gates.

## First component checkpoint

ADR 0054 adds:

- canonical closed `sandbox-runtime.secret-binding.v1` authority with strict
  `secret://`/`kms://` references and a digest over kind, reference, version,
  key ID, purpose, tenant and role;
- an exact-binding adapter over the existing `Provider` port, reusing
  `RotationWindow` and validating an expected material digest;
- a bounded TTL/count cache with caller-isolated copies, expiry, clearing and
  in-flight invalidation protection; and
- an opaque `EnvelopeKeyProvider` seal/open port that never returns KMS key
  bytes and validates binding, key, version, algorithm, AAD and size.

The checkpoint deliberately does not add another reference implementation,
file reader, state enum, rotation ledger or local envelope cipher.

## Recording and real Vault Transit checkpoint

The next vertical evolves the existing private `RecordingContentStore` port so
that authenticated tenant identity is explicit on every create, put, read and
delete operation. The local development store now binds `rkey2:` handles,
directory identity and AEAD associated data to tenant plus recording and
rejects legacy `rkey:` handles. Production-oriented recording storage adds:

- one random 256-bit DEK per recording, wrapped through the opaque
  `EnvelopeKeyProvider` and cleared after every use;
- immutable protected `EnvelopeBindingSet` authority that reconstructs the
  full KMS reference from tenant, configured key ID/version and scope;
- closed canonical `rkms1:` handles and closed canonical encrypted segment
  documents with no endpoint, full KMS reference, credential or host path;
- AES-256-GCM segment encryption with canonical tenant/recording/object/
  sequence/binding/version/algorithm AAD;
- active-key sealing, active/grace reads, revoked/expired read denial, and
  cleanup that authenticates the handle without reopening KMS material; and
- strict private directory/file checks, idempotent writes, substitution and
  corruption rejection, cancellation and exact deletion.

The real adapter uses digest-pinned HashiCorp Vault 2.1.1 Transit over TLS with
an exact non-exportable AES key, a least-scope encrypt/decrypt policy and a
five-minute non-renewable Product workload token resolved through
`BoundSecretProvider`. Its tagged integration gate proves v1 round-trip,
Transit rotation to v2, v1 grace read after store/client reconstruction, v2
selection, KMS-loss fail-closed behavior, KMS-independent cleanup and exact
container removal. This is real-adapter evidence; the token issuer and full
production command composition are not yet implemented.

Legacy recording formats are not auto-migrated or dual-read. Production
enablement requires either an empty legacy corpus or the separately authorized
offline process in
`docs/migrations/product-phase-6-recording-key-handle-v1.md`.

## Change-impact matrix

| Changed path | Reused authority | Required checkpoint validation | Not required at this checkpoint |
|---|---|---|---|
| `internal/secretref/scoped.go`, `scoped_cache.go` and focused tests | Existing reference/provider, `internal/secretfile`, `KeyState`, `RotationWindow`, errors and local envelope separation | Focused race/shuffle repetition, package vet, cancellation/scope/version/digest/expiry/revocation/cache/clearing negatives, retained Slice 4 verification | No Desktop candidate rebuild, six-process replay, Docker media stress or Slice 4 evidence regeneration: this leaf package is not imported by the Slice 4 runtime graph and changes no runtime/config/image identity. |
| `product/catalog.go`, recording stores, `internal/secretref/envelope_binding_set.go`, `internal/secretref/vaulttransit` | Existing Product catalog authority, private recording port, scoped binding and envelope provider | Focused race/shuffle, Product/PostgreSQL compile and persistence checks, real digest-pinned Vault TLS/rotation/loss/cleanup integration, package vet, root checkpoint, both Contract verifiers, retained Slice 4 verification | No Desktop candidate rebuild or media stress: the runtime candidate and Slice 4 evidence identities are unchanged. |
| ADR, plan, development and this audit | ADR 0051/0053 claim and evidence lifecycle | Documentation consistency and `git diff --check` | No runtime image build: documentation does not change candidate bytes. |

The root race/vet and both Contract verifiers remain mandatory at the stable
Slice 5 implementation checkpoint and final seal. Real KMS/database/Docker and
independent-process gates remain mandatory when the corresponding adapter,
composition and runtime paths are added. If dependency analysis becomes
uncertain, the stricter gate runs.

## Observed recording checkpoint validation

The recording/Vault checkpoint passed:

```bash
go test -race -shuffle=on -count=20 \
  ./internal/secretref ./internal/secretref/vaulttransit ./product \
  ./product/adapter/recording/local ./product/adapter/recording/kms
go vet ./internal/secretref ./internal/secretref/vaulttransit ./product \
  ./product/adapter/recording/local ./product/adapter/recording/kms

SANDBOX_RUNTIME_VAULT_TRANSIT_INTEGRATION=1 \
go test -tags=integration -count=1 \
  -run '^TestVaultTransitRecordingStoreIntegration$' -v \
  ./product/adapter/recording/kms

SANDBOX_RUNTIME_PRODUCT_POSTGRES_URL='<fresh-pinned-postgres-dsn>' \
go test -race -tags=integration -count=1 \
  -run '^(TestIntegrationArtifactCatalogAndEncryptedRecordingLifecycle|TestIntegrationBrowserRecordingQuotaIntegrityAndAuthorization|TestIntegrationDesktopRecordingQuotaIntegrityAuthorizationAndRetention)$' \
  ./product/adapter/postgres

go test -race -shuffle=on -count=1 ./...
go vet ./...
go run ./cmd/verify-contract
go run ./cmd/verify-product-contract -source-root .
```

The disposable Vault and PostgreSQL containers were removed and exact-name
queries returned no run-owned containers. No secret, DSN, private coordinate,
host path or provider diagnostic is recorded in this audit. These results do
not replace the still-open production registry and independent-process gate.

## Non-claims and next action

No production command uses the new providers yet. The real Vault recording
vertical described above has passed, including one rotation event, but there is
no production credential issuer/renewal controller, all-role secret migration,
independent-process Slice 5 campaign, break-glass decision, or Slice 5 evidence
manifest. Phase 6 therefore remains 4/15.

The next vertical step is production startup composition: replace raw
long-lived file/path inputs with role-owned scoped providers and short-lived
workload credentials without widening any stable API. Then add the controller
and break-glass state machine before the complete independent-process gate.
