# Product v1 Phase 6 Slice 5 Startup Audit

Date: 2026-09-22

Status: complete. Product Phase 6 is **5/15**.

## Claim boundary

This audit freezes the Slice 5 work order and records the completed bounded
component, real-adapter and local independent-process evidence. It is not HSM,
distinct-service-account, deployment, HA or production evidence. The accepted
Slice 4 result remains historical under ADR 0053 and does not cover this
source.

## Existing components and gaps

| Concern | Reused repository component | Open production gap |
|---|---|---|
| Opaque references | `internal/secretref.Reference`, scoped bindings and the role-owned registry | All six runtime roles now use isolated workload-material agents, while Product and Provider migrations use separate one-shot agents. Distinct service-account/OS-UID deployment identity remains unproven. |
| Private files | `internal/secretfile` and `secretref.FileProvider` enforce absolute path, regular-file, no-symlink, mode-`0600` and size rules | File secrets are bootstrap/development inputs, not an external secret provider or rotation authority. |
| Version/window state | `KeyProvider`, `KeyMaterial`, `KeyState`, `RotationWindow`, `RotatingKeySet` and the workload-credential controller | The repository gate proves bounded revision/renewal/revocation behavior, but platform-issued workload identity federation and HA deployment remain unproven. |
| Envelope encryption | Existing AES envelope helper, local recording store and the qualified Vault Transit recording adapter | Vault software Transit is real KMS-adapter evidence, not HSM evidence; Product recording-content and ticket/data consumers remain deliberately uncomposed. |
| Dependency configuration | Phase 6 dependency references are strictly parsed | String validation does not resolve a secret, prove workload identity or enforce provider-side revocation. |
| Emergency access | Persistent break-glass controller and metadata-only hash-chained audit | The repository gate proves dual approval, expiry, revocation and single online consumption; production operator identity, external audit export and deployment remain unproven. |

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

## Product registry and workload-material agent checkpoint

The shared registry implementation is instantiated separately by each role and
stores only provider/binding authority, never resolved material. Product also
splits bootstrap and runtime authority into distinct processes. The explicit
`sandbox-runtime.product-migration.v1` profile selects only one migration DSN,
forbids caching and uses a dedicated one-shot agent/socket. The long-running
`sandbox-runtime.product-process.v2` profile selects exactly four system-tenant
runtime bindings (TLS certificate/private key, runtime DSN and identity key
ring), requires the TLS pair at one version and rejects every migration,
legacy or mixed file/path field.

The repository-private Unix workload-material protocol is length-prefixed,
closed, canonical and bounded. Requests bind the complete authority, nonce,
deadline and request digest. Both peers verify UID/GID; the agent rechecks the
role, purpose and exact-binding allowlist, rejects replay/capacity overflow and
removes its socket on drain. The strict Vault KV v2 adapter uses TLS, an exact
mount/origin/reference/version and a separately scoped token provider. The
fixture environment token exists only in the isolated real-Vault integration
and is explicitly not a production bootstrap mechanism.

The real Product process gate first proves runtime startup cannot bind before
schema migration. A separate migration-agent OS process rejects runtime
bindings, permits exactly one migration resolution, automatically removes its
socket, and serves a separate `product migrate` OS process. Only after the
migration process, agent, socket, cache and database connection are absent does
the gate start a runtime agent; that agent rejects the migration binding. The
Product runtime validates the atomic TLS pair and monitors only its four
material dependencies. The gate observes readiness closure after bounded cache
expiry when the runtime agent stops, recovery after agent restart, Product
restart, PostgreSQL loss/recovery, TLS-only transport, database authority
separation and nondisclosure. It records
`distinct_os_uid_established=false`: same-host UID is functional evidence only,
not production least-privilege evidence.

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
container removal. This is real-adapter evidence; Product recording-content
composition is deliberately excluded from this slice. Production
configuration has no recording-content enablement field and rejects attempts
to advertise that uncomposed capability.

Legacy recording formats are not auto-migrated or dual-read. Production
enablement requires either an empty legacy corpus or the separately authorized
offline process in
`docs/migrations/product-phase-6-recording-key-handle-v1.md`.

## Change-impact matrix

| Changed path | Reused authority | Required checkpoint validation | Not required at this checkpoint |
|---|---|---|---|
| `internal/secretref/scoped.go`, `scoped_cache.go` and focused tests | Existing reference/provider, `internal/secretfile`, `KeyState`, `RotationWindow`, errors and local envelope separation | Focused race/shuffle repetition, package vet, cancellation/scope/version/digest/expiry/revocation/cache/clearing negatives, retained Slice 4 verification | No Desktop candidate rebuild, six-process replay, Docker media stress or Slice 4 evidence regeneration: this leaf package is not imported by the Slice 4 runtime graph and changes no runtime/config/image identity. |
| `product/catalog.go`, recording stores, `internal/secretref/envelope_binding_set.go`, `internal/secretref/vaulttransit` | Existing Product catalog authority, private recording port, scoped binding and envelope provider | Focused race/shuffle, Product/PostgreSQL compile and persistence checks, real digest-pinned Vault TLS/rotation/loss/cleanup integration, package vet, root checkpoint, both Contract verifiers, retained Slice 4 verification | No Desktop candidate rebuild or media stress: the runtime candidate and Slice 4 evidence identities are unchanged. |
| Role registries, Vault KV, workload-material agents, workload-credential/break-glass controllers and all production role configs/processes | Scoped binding authority, existing role TLS/identity/PostgreSQL parsing | Focused race repetition, all-role credential/break-glass process gate, six-role candidate gate, controller/agent/Vault loss, renewal/revocation/restart/plaintext/cleanup observations, root checkpoint and retained Slice 4 verification | Same-host UID only (`distinct_os_uid_established=false`); no claim for service-account/federated identity, deployment, HA or complete Slice 5 evidence before the formal immutable campaign. |
| `internal/productphase6slice5evidence`, aggregate verifier command and Slice 5 release gate | Slice 4 immutable runtime evidence and closure lifecycle | Closed canonical dual-gate manifest, identical runtime/evidence revisions, exact capability/nonclaim/future-gate/cleanup sets, finalization and retained-history verification | No inference of Product recording-content E2E, HSM, deployment or production readiness. |
| ADR, plan, development and this audit | ADR 0051/0053 claim and evidence lifecycle | Documentation consistency and `git diff --check` | No runtime image build: documentation does not change candidate bytes. |

The root race/vet and both Contract verifiers remain mandatory at the stable
Slice 5 implementation checkpoint and final seal. The formal real
KMS/database/Docker and independent-process gates remain mandatory even though
their focused pre-seal runs pass. If dependency analysis becomes uncertain,
the stricter gate runs.

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
not replace the formal immutable all-role and aggregate evidence campaign.

## Observed Product registry/migration checkpoint validation

The Product vertical passed the focused repeated race/vet checks and both real
process gates:

```bash
go test -race -shuffle=on -count=10 \
  ./config ./internal/secretref ./internal/secretref/vaultkv \
  ./internal/secretref/workloadagent ./productapi/process \
  ./productapi/tokenidentity ./product/adapter/postgres ./cmd

SANDBOX_RUNTIME_VAULT_AGENT_INTEGRATION=1 \
  go test -race -tags=integration -count=1 \
  -run '^TestVaultKVWorkloadAgentProductTLSIntegration$' -v \
  ./internal/secretref/workloadagent

SANDBOX_RUNTIME_PRODUCT_PROCESS_INTEGRATION=1 \
  go test -race -tags=integration -count=1 \
  -run '^TestProductProcess(Development|ProductionKernel)Integration$' -v ./cmd

go test -race -shuffle=on -count=1 ./...
go vet ./...
go run ./cmd/verify-contract -source-root .
go run ./cmd/verify-product-contract -source-root .
```

The production process test uses separate migration-agent, migration-job,
runtime-agent and Product OS processes. It records
`distinct_os_uid_established=false`, rejects cross-purpose bindings, proves the
one-shot socket cannot reconnect, verifies zero migration-role connections
before runtime bind, and leaves no run-owned container or socket. This is not
the distinct-service-account deployment gate.

## Formal immutable gate and closure

The formal campaign passed with one immutable runtime/evidence pair:

- runtime implementation revision:
  `c189330c5ed0aa52c60b6b85c5cd9c6b59fbef10`;
- evidence-tool revision:
  `39fd1025f6fa838325aced711d8a024a9ce5d1b6`;
- Desktop candidate image digest:
  `sha256:669f3baff87ae5eda45e9957e6cf25804ad8ad95ef47bbe9b8f14a76e71fc5cb`;
- Desktop candidate manifest digest:
  `sha256:90c7a5a8890feb9e841561a498ebd1bec4b2bc1346cff2ee1b6a75bb79cb3fc6`;
- aggregate manifest digest:
  `sha256:e6a6fdcc299c721e1fa2c48009d98a6ca4c52d59318c507af8b68fd8596e840c`.

The six-role gate ran 150 Desktop mux sessions and 750 inputs with zero
first-frame, input, timeout and cleanup failures. Its 20-session media sample
recorded a 163052 microsecond first-frame p95, zero RTP sequence gaps,
backpressure at the bounded media-reader queue, recovery, and an unchanged
41-to-41 goroutine boundary. Six renewable runtime agents and two
non-renewable migration agents were observed; break-glass ended with one
consumed, one revoked and one expired record, a valid 15-entry hash chain, and
zero plaintext matches across the declared scan boundary. The independent
Vault Transit/PostgreSQL gate passed all eight recording scenarios. Both gates
ended with the exact declared run-owned resource counts at zero.

The repository-wide race/shuffle suite, vet, both Contract verifiers, strict
aggregate verifier and retained Slice 4 verifier passed after the formal gate.
The byte-identical manifest is archived as
`docs/audits/product-phase-6-slice-5-evidence.json`; its closure record binds
the documentation-only archive revision and preserves this as a historical
claim once Slice 6 changes begin.

## Non-claims and next action

All six runtime roles now use separate instances of the closed role-owned
registry and workload-material agent. Product and Provider migrations use two
additional one-shot agents. The operator-owned workload-credential controller
issues distinct renewable short-lived credentials to the six runtime agents
and non-renewable credentials to the two migration agents; its persistent CAS
ledger stores no raw credential. A separate persistent break-glass controller
requires two distinct approvers and online single consumption, denies
migration use, and maintains a hash-chained metadata-only audit.

The focused real-process credential/break-glass gate and the enhanced real
Vault Transit plus fresh PostgreSQL recording-lifecycle gate pass locally.
The latter proves v1/v2 overlap, revoked-key, tenant, AAD/ciphertext, restart,
Vault-loss, scoped-token revocation and cleanup behavior. It does not claim
that the Product OS process composes recording content, and the production
schema rejects attempted recording-content enablement. Composition is fixed to
Slice 8, deployment rejection to Slice 11 and published-artifact black-box E2E
to Slice 14.

Phase 6 advances to 5/15. The next work is Slice 6. This result does not compose
Product recording content, qualify an HSM, establish distinct OS UIDs or
service accounts, publish signed artifacts, validate a deployment, establish
HA or claim production readiness. The fixed Slice 8/11/14 follow-on gates
remain mandatory.
