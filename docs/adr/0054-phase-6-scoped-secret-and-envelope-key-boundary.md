# ADR 0054: Phase 6 Scoped Secret and Envelope-Key Boundary

- Status: accepted
- Date: 2026-09-22

## Context

The repository already has a bounded `secretref.Reference`, generic
`Provider`, strict mode-`0600` no-symlink file resolution, versioned
`KeyProvider`, `RotationWindow`, local AES envelope helper and explicit
material clearing. Those components are useful foundations, but the generic
reference alone does not bind a value to one tenant, role, purpose and exact
version. The local envelope helper also returns key bytes to the process, so it
is not a production KMS/HSM boundary.

Phase 6 Slice 5 requires production secret references, opaque envelope-key
operations, bounded caching, rotation and revocation. It must add those
properties without creating a second reference parser, file reader, rotation
ledger or encryption implementation, and without changing the locked Provider
Contract.

## Decision

Add the repository-private canonical
`sandbox-runtime.secret-binding.v1` document. It is a closed object containing
exactly the material kind, opaque reference, version, KMS key ID when
applicable, purpose, tenant and consuming role. Decoding rejects unknown or
duplicate fields, non-canonical JSON, extra values, unsafe URL components,
unrecognised enum values and oversized input. Its domain-separated digest
binds every authority field.

Production scoped bindings accept only strict `secret://` and `kms://`
references. They do not accept inline values or `file://` paths. The existing
`FileProvider` and `internal/secretfile` remain the only file-secret reader for
the currently documented development/bootstrap paths; Slice 5 does not create
another reader or silently relabel a file as a production provider.

Reuse the existing `Provider`, `KeyState`, `RotationWindow` and secret error
semantics. `BoundSecretProvider` adapts one existing `Provider` to one exact
binding, active window, provider revision and canonical expected SHA-256. A
different tenant, role, purpose, reference, version or digest fails before the
value is returned. Rotation installs a new immutable binding/adapter rather
than mutating authority in place. Native production adapters may implement the
typed `SecretProvider` port directly.

`CachedSecretProvider` stores caller-isolated copies by complete binding
digest. Its TTL, entry count and material validity are bounded. It never serves
after either the cache TTL or provider validity window, clears values on
replacement, eviction, invalidation and close, and uses an invalidation epoch
so a concurrent provider response cannot repopulate a revoked cache entry.
Provider-specific errors are mapped to stable errors while context
cancellation and deadlines are preserved.

Add a separate `EnvelopeKeyProvider` port for external KMS/HSM adapters. It
performs seal/open operations without returning key material. The returned
`OpaqueEnvelope` binds the complete binding digest, KMS key ID, version,
algorithm and bounded ciphertext. Associated data is mandatory and bounded.
`BoundEnvelopeKeyProvider` rejects scope, version, key, algorithm, size and
provider-error substitution. The existing local AES `Envelope` remains a
separate component and is not production KMS evidence.

The binding document, provider ports and envelopes are internal composition
types. They are not Provider API DTOs and must not expose secret references,
KMS coordinates, credentials or provider diagnostics through stable APIs,
logs, probes, audit payloads or release evidence.

The first production-oriented vertical evolves the existing private
`RecordingContentStore` port rather than adding a parallel store. Every
operation carries the authenticated tenant and recording identity explicitly.
Each recording receives a random 256-bit data-encryption key; the KMS wraps or
unwraps that key through `EnvelopeKeyProvider`, while segment payloads use
AES-256-GCM locally. Canonical associated data binds tenant, recording, logical
object reference, sequence, complete binding digest, KMS key version, provider
key ID, wrap algorithm and content algorithm.

Persisted `rkms1:` handles are closed canonical documents. They contain only
format/version metadata, the binding digest, opaque provider key ID/version,
algorithms and the wrapped data key. A handle cannot introduce the full KMS
reference, endpoint, credential, filesystem path or a new authority. Product
reconstructs the complete binding from protected immutable configuration;
active versions seal, active or grace versions open, and revoked or expired
versions can only authenticate deletion. The development-only local store uses
tenant/recording-bound `rkey2:` handles and rejects old `rkey:` handles.

The initial real adapter is Vault Transit over HTTPS. It accepts exactly the
configured origin, mount and `kms://<authority>/<mount>/<key-id>` reference,
disables redirects and cookie storage, resolves a short-lived Product workload
token through the scoped secret provider, uses Transit `associated_data`, and
requests the exact key version. Vault response fields, sizes, content type,
ciphertext version and duplicate JSON keys are checked strictly. The adapter
does not export Transit key bytes or surface Vault diagnostics.

There is no production read-path fallback from `rkms1:` to legacy `rkey:`
material and no opportunistic rewrite. Enabling the KMS store therefore
requires either proof that no production legacy recording corpus exists or a
separately authorized offline migration with source/target counts, integrity
verification, deletion policy and rollback limits. The migration contract is
recorded in `docs/migrations/product-phase-6-recording-key-handle-v1.md`.

## Consequences

- Existing reference parsing, file hardening, state/window types and local
  envelope behavior remain the single implementations of those concerns.
- A production role can receive only a value whose complete non-secret
  authority matches its configured binding; cache lifetime cannot widen the
  provider validity window.
- A real KMS/HSM adapter can retain raw keys outside the role process and return
  only an opaque envelope.
- A real digest-pinned Vault Transit TLS integration now proves recording
  round-trip, version rotation with grace reads, process/client reconstruction,
  dependency loss, KMS-independent cleanup and exact container cleanup. This
  remains real-adapter component evidence, not production deployment evidence.
- This ADR is not Slice 5 completion. Production role startup has not migrated
  all secret inputs, the short-lived credential issuer/renewal controller and
  break-glass approval state machine remain open, and no full independent-role
  Slice 5 gate or immutable evidence manifest exists.
- Slice 5 remains open until the real-adapter and independent-process failure
  gates, plaintext-exclusion checks and immutable evidence all pass.
