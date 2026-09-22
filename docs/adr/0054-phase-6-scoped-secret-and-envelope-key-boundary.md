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

## Consequences

- Existing reference parsing, file hardening, state/window types and local
  envelope behavior remain the single implementations of those concerns.
- A production role can receive only a value whose complete non-secret
  authority matches its configured binding; cache lifetime cannot widen the
  provider validity window.
- A real KMS/HSM adapter can retain raw keys outside the role process and return
  only an opaque envelope.
- This ADR is a component boundary, not Slice 5 completion. It does not yet
  migrate role startup, integrate recording storage with a real KMS, issue
  workload credentials, implement a rotation/revocation controller or record
  break-glass approvals.
- Slice 5 remains open until the real-adapter and independent-process failure
  gates, plaintext-exclusion checks and immutable evidence all pass.
