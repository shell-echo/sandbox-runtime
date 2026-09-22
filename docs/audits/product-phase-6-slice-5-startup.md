# Product v1 Phase 6 Slice 5 Startup Audit

Date: 2026-09-22

Status: implementation underway. Product Phase 6 remains **4/15**.

## Claim boundary

This audit freezes the Slice 5 work order and records the first component
checkpoint. It is not KMS/HSM, deployment, rotation, break-glass or production
evidence. The accepted Slice 4 result remains historical under ADR 0053 and
does not cover this source.

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

## Change-impact matrix

| Changed path | Reused authority | Required checkpoint validation | Not required at this checkpoint |
|---|---|---|---|
| `internal/secretref/scoped.go`, `scoped_cache.go` and focused tests | Existing reference/provider, `internal/secretfile`, `KeyState`, `RotationWindow`, errors and local envelope separation | Focused race/shuffle repetition, package vet, cancellation/scope/version/digest/expiry/revocation/cache/clearing negatives, retained Slice 4 verification | No Desktop candidate rebuild, six-process replay, Docker media stress or Slice 4 evidence regeneration: this leaf package is not imported by the Slice 4 runtime graph and changes no runtime/config/image identity. |
| ADR, plan, development and this audit | ADR 0051/0053 claim and evidence lifecycle | Documentation consistency and `git diff --check` | No runtime image build: documentation does not change candidate bytes. |

The root race/vet and both Contract verifiers remain mandatory at the stable
Slice 5 implementation checkpoint and final seal. Real KMS/database/Docker and
independent-process gates remain mandatory when the corresponding adapter,
composition and runtime paths are added. If dependency analysis becomes
uncertain, the stricter gate runs.

## Non-claims and next action

No production command uses the new providers yet. No real KMS call, recording
round trip, workload credential, rotation event, revocation event or
break-glass decision has been observed. No Slice 5 manifest exists and the
Phase 6 count does not advance.

The next vertical step is one real use: replace the local process-held
recording master-key boundary with a production KMS envelope adapter and prove
its normal, scope-mismatch, AAD-mismatch, KMS-loss and cancellation paths before
expanding startup composition.
