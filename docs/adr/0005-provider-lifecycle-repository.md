# ADR 0005: Provider-Local Lifecycle Repository Boundary

- Status: Accepted for P1.2.2 development adapters
- Date: 2026-08-20

## Context

P1.2.1 supplies immutable provider-local lifecycle values and deterministic
transitions. P1.2.2 needs persistence ports before a coordinator can reconcile
after restart. The calling platform's aggregate operation ledger remains a
different authority and must not be recreated by this repository.

## Decision

The repository port is split conceptually into sandbox, operation, lease, and
event records, with one atomic `ReserveCreate` boundary that creates the
initial sandbox, accepted create operation, lease, idempotency record, and
fencing high-water mark together. A replay with the same ProviderRevision-
scoped idempotency key and request digest returns the original logical
operation. A different digest or operation identity is a conflict.

Subsequent sandbox writes carry an expected generation and current fencing
token. Operation, lease, and event writes must use the current fencing token.
Generation changes update the lease generation atomically. Events receive a
provider-assigned sequence, are strictly monotonic per sandbox, and accept an
identical event replay without creating a duplicate. Event reads reject a
cursor beyond the retained sequence and require a bounded page size.

The memory adapter is concurrency-safe and intended for tests and development.
The file adapter is explicitly single-controller development infrastructure. It
holds an exclusive advisory lock for its lifetime, rejects unknown/corrupt
snapshot data, writes versioned snapshots to a mode-0600 temporary file,
fsyncs file contents, atomically renames, and fsyncs the parent directory. A
failure before rename rolls back the in-memory mutation; a failure after rename
leaves the new state visible and returns an explicit durability error so the
caller can reconcile rather than silently reverting.

No adapter claims multi-controller safety, distributed fencing, transactional
database durability, or production readiness. A future production adapter must
prove equivalent atomic idempotency/fencing, crash recovery, event ordering,
and ownership semantics before the provider advertises such a profile.

## Consequences

- P1.2.3 can depend on narrow repository ports without importing file formats,
  locks, or transport packages.
- Repository snapshots contain provider-local records only; they do not store
  bearer values, credentials, backend IDs, host paths, or caller business
  truth.
- Restart loading is a corruption gate, not aggregate lifecycle conformance.
  Fault injection, multi-controller reliability, tenancy, deployment, and
  production evidence remain later release gates.

## Evidence boundary

This ADR does not add Provider routes or change the local `/instances` API. It
does not make the file adapter suitable for multi-controller production use.
