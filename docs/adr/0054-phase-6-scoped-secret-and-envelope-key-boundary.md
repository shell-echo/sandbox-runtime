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

Production startup uses one shared registry implementation but never a shared
cross-role registry instance. Product, Provider, Gateway, Guest, Browser and
Desktop each construct an immutable registry containing only closed provider
types, allowed purposes and bindings for that exact role. Resolution requires
the configured binding ID, purpose and tenant to match; the caller cannot
substitute the reference, role, version or provider. Provider caches are also
role-local.

Production configuration moves to an explicit new schema containing typed
binding IDs or closed binding documents. Legacy path fields are not inferred,
auto-upgraded or used as fallback. They remain available only to an explicit
development/test or legacy-development profile; a production command rejects
legacy, raw, inline and mixed configuration. Non-secret policy/dependency
documents remain strict private configuration artifacts rather than being
misclassified as secrets, and their decoders reject embedded credentials.

TLS certificate, private-key and CA material participates in the same version,
scope, integrity and revocation lifecycle even though certificates and CAs are
public. A certificate/private-key bundle resolves at one binding version,
provider revision and validity window, then verifies the key pair, SAN,
extended usage and expiry before listener construction. Raw resolved bytes are
cleared. Automatic certificate issuance and service trust-edge rotation remain
Slice 6 responsibilities.

The bootstrap provider for production role registries is a restricted local
Unix workload-material agent, not a direct production file provider. Each role
owns a separate socket below a mode-`0700`, non-symlink directory; the socket
is mode `0600`, and client and server both verify the expected peer UID/GID.
The repository-private `sandbox-runtime.workload-material.v1` protocol uses a
bounded length prefix and closed canonical JSON. Every request carries the
complete binding, a fresh nonce, a bounded deadline and a domain-separated
request digest. The agent independently enforces its role, purpose and exact
binding allowlist, rejects replay and overload, and returns only a bounded
material document. Socket paths and agent/provider diagnostics are not stable
API data.

The initial secret backend is Vault KV v2 over TLS. The adapter pins the Vault
origin, mount, reference authority, role and purposes; disables redirects and
cookies; obtains its Vault token through a scoped provider; selects an exact KV
version; and strictly validates content type, response shape, binding digest,
material digest, revision and validity window.

Production workload agents obtain Vault tokens only from the independent
operator-owned `sandbox-runtime.workload-credential.v1` controller. Each of the
six runtime agents has a distinct Ed25519 identity and a renewable, short-lived
policy bound to its exact role, purpose, binding digest and backend. Product and
Provider migration agents have separate identities and one-shot,
non-renewable policies. The controller persists CAS lease revisions, replay
state, credential digests and opaque Vault accessors, but never credential
bytes. Renewal verifies the replacement token before scheduling revocation of
the previous accessor after a fixed overlap. The Vault management token enters
only the controller over inherited FD 3. It is absent from config, arguments,
environment variables, workload-agent protocols and evidence.

Emergency access is a separate controller, key, ledger, audit file and Unix
protocol. The requester, two distinct approvers, operator and target agent are
different signed actors. A capability binds the exact target, role, purpose,
tenant, binding and operation, has one use and at most a fifteen-minute TTL,
and is useful only after the target agent atomically consumes it online. The
audit is append-only, hash-chained and metadata-only; reason and ticket appear
only as digests. Migration purposes are categorically ineligible for
break-glass. A controller outage therefore fails closed rather than turning a
signed capability into an offline bearer token.

Product is the first production role migrated to this boundary, using two
physically separate process lifecycles. The one-shot `product migrate` command
accepts only `sandbox-runtime.product-migration.v1`, one migration DSN binding,
a no-cache registry and a dedicated one-shot agent socket. It applies and
verifies the exact schema, closes the pool/registry, then exits; its agent
permits one authorized resolution, closes its listener and removes its socket.
The long-running `product serve` command accepts only
`sandbox-runtime.product-process.v2` and exactly four runtime bindings: TLS
certificate/private key, runtime DSN and identity key ring. Migration provider,
binding and DDL credential fields are not part of that schema. Runtime startup
only verifies its restricted database role and exact schema compatibility; it
never reruns migration or requests migration authority. Readiness validates
only the four runtime dependencies. The migration and runtime agents use
different sockets, allowlists, registries, caches and nonce spaces.

Provider, Gateway, Guest, Browser and Desktop use the same registry and agent
implementation in separate role-owned instances. Provider has a separate
one-shot migration command and runtime schema; no runtime process can parse a
migration binding. Production schemas reject the legacy path fields rather
than inferring or falling back to them.

The single-host functional gate may run these processes under the same host
UID, but must record `distinct_os_uid_established=false`. Production/deployment
qualification requires distinct service accounts or platform-equivalent
workload identities for both migration jobs, all six runtime roles and all
agents; that isolation remains a Slice 6/11/14 gate.

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

Slice 5 qualifies this adapter through a separate real Vault Transit plus
fresh PostgreSQL recording-lifecycle gate and binds it into the same aggregate
manifest as the six-role credential gate. This is deliberately not a claim
that `product serve` composes a `RecordingContentStore`: the current Product
kernel has no public recording-content consumer. Production config has no
recording-content enablement field and rejects an attempted unknown section;
it cannot fall back to a local master key or legacy `rkey:` store. The aggregate
evidence must state `recording_content_store_composed=false` and
`recording_content_e2e=false`.

The deferred composition is a fixed dependency, not an open-ended TODO. Slice
8 must compose the KMS store into the real Product or recording worker when
external object storage is composed and prove write/read, rotation, restart,
loss, integrity and cleanup. Slice 11 must reject deployment configuration
that advertises or enables any uncomposed content capability. Slice 14 must run
black-box encrypted recording E2E from published artifacts; failure prevents
release-candidate eligibility. Ticket/data envelope purposes remain typed,
isolated and negatively tested, with `consumer_composed=false` until their
first real consumer is added and requalified.

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
- The digest-pinned Vault Transit/PostgreSQL gate proves tenant-bound recording
  lifecycle, v1/v2 overlap, stale/revoked rejection, restart reconstruction,
  Vault loss, AAD/ciphertext substitution denial, scoped-token revocation and
  exact cleanup. It is adapter qualification, not Product recording-content
  E2E, HSM or deployment evidence.
- The independent role gate composes two one-shot migration agents, six
  renewable runtime agents, the credential controller and the break-glass
  controller alongside the six Product/Gateway/Provider/Guest/Browser/Desktop
  processes. It proves rotation, revocation, expiry, Vault and agent loss,
  controller restart, dual approval, single consume, audit integrity,
  plaintext exclusion and exact cleanup.
- This ADR records the completed implementation boundary. The two real gates
  bind runtime revision `c189330c5ed0aa52c60b6b85c5cd9c6b59fbef10` and
  evidence-tool revision `39fd1025f6fa838325aced711d8a024a9ce5d1b6` in the
  accepted manifest digest
  `sha256:e6a6fdcc299c721e1fa2c48009d98a6ca4c52d59318c507af8b68fd8596e840c`.
  The strict aggregate verifier and required repository-wide checks passed, so
  Slice 5 advances the Phase 6 counter to 5/15 without widening its non-claims.
