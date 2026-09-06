# ADR 0035: Browser PostgreSQL Action-History Witness

- Status: Accepted for the P4 production-candidate witness component and
  controlled-restore verification primitive
- Date: 2026-09-06

## Context

ADR 0034 proves deletion and older-snapshot detection with an independent
monotonic action-history witness. Its included `0600` file implementation has a
single-process lifetime lock and is valid only when the file is outside the
Redis-compatible snapshot and restore domain. It is not a multi-process or
high-availability witness and cannot become one through configuration alone.

A production candidate needs an atomic compare-and-swap shared by independent
ingress processes, durable acknowledgement, explicit time bounds, narrowly
scoped credentials, and a storage failure domain independent from the
Redis-compatible capacity authority. PostgreSQL can supply the component-level
transactional primitive, but choosing PostgreSQL does not itself prove the
database topology, durability configuration, backup independence, failover, or
operations.

ADR 0034 runtime `Verify` deliberately repairs the conservative crash case in
which Redis is exactly one checkpoint ahead of the witness. That behavior is
appropriate during ordinary runtime reconstruction. It is too permissive as
the final check after an administrator-selected restore: the restored data must
match the retained witness exactly before ingress resumes, and the check must
not mutate either authority.

## Decision

Add `PostgresActionHistoryWitness` as an explicitly selected implementation of
`ActionHistoryWitness`. Keep the file witness, witnessed-v2 policy, Redis keys,
Lua scripts, descriptors, Provider Contract, and default composition unchanged.

### Storage identity and schema

The repository-owned migration creates
`sandbox_runtime.action_history_witnesses`. Its primary key is the pair of:

- the 32-byte SHA-256 capacity-namespace fingerprint already used as the
  private Redis Cluster key tag; and
- the 32-byte witnessed-v2 action-policy fingerprint.

The namespace must participate in the key because the capacity-policy
fingerprint intentionally excludes it. Keying only by policy would alias
independent capacity namespaces with identical limits and timing policy.

The row contains a fixed format version, bounded nonnegative sequence, opaque
32-byte token, and database timestamp. The adapter converts the existing
lowercase hexadecimal values to fixed-size `bytea`; it does not persist raw
namespace, Redis key, tenant, sandbox, Browser-session, grant, endpoint,
credential, or CDP material.

Migration is an administrative operation. Runtime startup never issues DDL and
does not recreate a missing table, schema, or row. The runtime database role
receives only database `CONNECT`, schema `USAGE`, table `SELECT`, insert access
to the five required state columns, and update access to sequence, token, and
timestamp. It must not own the database, schema, or table and
must not receive `CREATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, role
management, or migration authority.

### Monotonic operations

`Load` selects one exact scope/policy row and distinguishes a missing row from
an unavailable or malformed authority. `Provision` inserts sequence zero with
`ON CONFLICT DO NOTHING`, then treats only the exact existing checkpoint as an
idempotent success. A different existing checkpoint is a conflict.

`CompareAndSwap` performs one conditional `UPDATE` over the exact format,
sequence, and token. Exactly one affected row is success. A valid existing row
that does not match the predecessor is a conflict; a missing or malformed row
is unavailable. Concurrent callers may produce one winner only. PostgreSQL
errors, SQL text, addresses, database/user names, and credentials are projected
to bounded witness errors. Caller cancellation and both caller and adapter
deadlines remain discoverable through `errors.Is`.

Each mutating statement locally sets `synchronous_commit=on` for its implicit
transaction before changing the row. A success therefore waits for the primary
to flush its commit locally even if a connection, role, or database default was
configured less safely. This does not prove synchronous-replica durability or
survival of a primary/storage-domain loss.

Every store operation has a whole-millisecond timeout between the existing
50-millisecond and 30-second capacity-adapter bounds. The supplied `pgxpool`
remains owned by the composition root; constructing or closing network pools is
not a witness side effect. The direct dependency is locked to locally cached
`pgx/v5 v5.9.2`, whose included license is MIT. An online latest-version query
was unavailable, so no claim that this is the newest release is made.

### Controlled restore check

Add `WitnessedActionFencer.VerifyRestoredState`. It loads the retained witness
and runs the existing verify-only Redis script, accepting only the exact
`ready` result. It rejects `ahead`, behind, divergent, missing, malformed, and
unavailable state and never invokes witness compare-and-swap. Existing runtime
`Verify` retains its one-ahead crash recovery behavior.

The controlled procedure is:

1. quarantine the unique private ingress and prevent every Gateway bypass;
2. retain the PostgreSQL witness and establish that it was not restored or
   failed over with the selected Redis snapshot;
3. restore the Redis-compatible authority through a separately held
   administrative credential;
4. run `VerifyRestoredState` against the intended namespace and exact policy;
5. resume ingress only after exact success; otherwise keep the namespace
   unavailable and use a separately reviewed drain/replacement procedure.

`VerifyRestoredState` is a component primitive, not an ingress suspension API
or workflow engine. The runtime role cannot choose, overwrite, delete, or
repair a checkpoint.

## Release Boundary

The component gate requires unit and race/shuffle tests for configuration and
input rejection, namespace separation, idempotent provision, atomic CAS
conflict, malformed state, bounded timeout, context propagation, and error
redaction. A separately named PostgreSQL integration gate must apply the exact
migration, use independent connection pools, prove one CAS winner,
reconstruction, missing-row behavior, schema constraints, runtime-role denial
of destructive/DDL operations, bounded pool starvation, and a combined real
Redis/PostgreSQL older-snapshot rejection.

The CI PostgreSQL service is currently selected by a fixed version/platform
tag rather than an immutable image digest. A passing run is therefore adapter
semantics evidence, not PostgreSQL image provenance or a reproducible
production deployment claim. Production evidence must pin and verify its
server artifact and configuration separately.

Passing these gates establishes only a production-candidate PostgreSQL witness
adapter and controlled-restore verification primitive. It does not establish:

- PostgreSQL HA, synchronous durability, backup or restore correctness,
  disaster recovery, monitoring, sizing, or latency under load;
- independence when PostgreSQL and Redis share a host, volume, orchestrator,
  backup set, credential plane, operator error, or correlated rollback;
- Valkey provenance, persistence, replication, promotion, partition, or
  failover consistency;
- safe online restore, automatic quarantine/resume, a repair endpoint, or
  protection from a trusted writer that coherently rewrites both authorities;
- CDP exactly-once execution, hostile multi-tenant isolation, Provider
  multi-controller behavior, real Agent Platform compatibility, aggregate
  conformance, production Browser advertisement, deployment readiness, or
  production readiness.

## Consequences

- Multiple ingress processes can share one atomic monotonic witness without
  copying a file or weakening the v2 checkpoint protocol.
- Capacity namespaces with identical policy remain isolated in PostgreSQL.
- Every activation that advances v2 state adds a PostgreSQL write and inherits
  its latency and availability; losing witness availability fails closed.
- Runtime and restore verification now have intentionally different semantics:
  runtime reconstruction may finish exact one-ahead state, while controlled
  restore verification is strictly read-only and exact-match only.
- Operational independence is part of the safety property. Correlated rollback
  of Redis and PostgreSQL to mutually matching older checkpoints remains
  undetectable.
