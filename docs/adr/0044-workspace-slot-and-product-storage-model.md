# ADR 0044: Workspace, Slot, and Product Storage Model

- Status: Accepted for Phase 1 architecture; schema implementation is not yet
  authorized
- Date: 2026-09-18

## Context

The Product Contract defines a Workspace aggregate with named sandbox slots,
durable Product operations, events, sessions, control leases, artifacts,
recordings, and Agent runs. The current Provider creates one sandbox per create
request and owns only provider-local execution state. It cannot atomically
create or mutate a multi-sandbox Workspace.

The target product needs one primary coding environment plus optional Browser,
Desktop, subagent, and isolated environments. Treating all of them as one
Provider sandbox would couple unrelated capability and isolation requirements.
Treating each as an unrelated Product Workspace would lose aggregate lifetime,
authorization, event ordering, artifact ownership, and user experience.

The current Provider accepts workspace identity and an ephemeral, read-only
workspace policy, but does not supply a Product workspace revision store. Its
file repositories and runtime mounts are not Product business persistence.

## Decision

### Workspace is a composite Product aggregate

One Product Workspace is the aggregate root for identity, lifetime, desired
state, authorization, event ordering, catalogs, and user-visible status. It
contains one required `primary-code` slot and zero or more auxiliary slots.

Each slot maps to an independently reconciled Provider sandbox or, where a
future capability explicitly requires it, another independently governed
runtime resource. The Product does not ask Provider to understand the
Workspace aggregate.

This is a composite model, not a single “main sandbox plus untracked helpers.”
Auxiliary slots are first-class children with durable desired state,
generation, operations, events, sessions, and cleanup obligations.

### Slot model

The initial slot kinds are:

| Kind | Purpose | Default isolation expectation |
| --- | --- | --- |
| `code` | Required primary coding/shell environment | One `primary-code` slot; durable Workspace content is materialized into an ephemeral Provider workspace |
| `browser` | Browser automation or live Browser session | Separate Provider sandbox and restricted network policy |
| `desktop` | Graphical desktop applications | Separate sandbox and media/input authority; unavailable until its Contract and security gates pass |
| `subagent` | Delegated Agent execution with narrower authority | Separate slot when isolation is required; never inherits human credentials |
| `isolated` | Explicitly separated untrusted or experimental work | Separate sandbox, capability profile, network policy, and storage view |

Slot keys are immutable, unique within the Workspace, and stable across
Provider sandbox replacement. `primary-code` is reserved, required, and has
kind `code`. An auxiliary slot may not impersonate or replace it.

Each slot stores:

- immutable `workspace_id`, `slot_key`, and kind;
- Product profile and required Provider capabilities;
- desired and observed state;
- desired generation and observed generation;
- Product version;
- current private Provider binding generation;
- last reconciled Product operation and Provider evidence cursor; and
- timestamps and terminal tombstone state.

Provider revision, sandbox ID, operation IDs, handoffs, backend IDs, and
private endpoints are stored in private adapter records. They never appear in
stable Product DTOs or event attributes.

### Workspace lifecycle

Workspace desired state is `active`, `suspended`, or `terminated`.
Termination is irreversible. Suspension is successful only after every
required slot reaches its capability-specific suspended or safely quiesced
state. A capability that cannot suspend must be terminated and marked for
recreation, or make the operation fail according to the Product profile.

Workspace observed state is a Product projection:

- `requested`: aggregate and initial operation committed;
- `provisioning`: at least one required slot is not ready and no terminal
  failure has been selected;
- `active`: every required slot for the selected Product profile is ready;
- `degraded`: the primary slot is usable but an optional or recoverable slot is
  unavailable;
- `suspending` or `suspended`: the corresponding aggregate transition;
- `terminating` or `terminated`: irreversible cleanup transition;
- `failed`: Product policy selected a terminal failure.

No single Provider sandbox status is copied into the Workspace observed state.

### Slot lifecycle and generation

A slot desired-state or profile change increments its Product generation. A
Provider binding is valid only for the exact tenant, Workspace, slot key, slot
generation, selected Provider revision, runtime profile, and capability set.

Replacing a Provider sandbox does not change the slot key. The binding
generation advances, all older sessions and connection grants are revoked, and
late Provider observations are retained as evidence but cannot mutate the
current slot.

At most one binding is current for a slot generation. Unknown create or
terminate outcomes remain reconcilable; Product never creates a replacement
until fencing and observation show that doing so cannot create two current
bindings.

### No cross-slot distributed transaction

PostgreSQL commits Product intent atomically, but Provider changes across slots
are a saga. Each slot action has its own Product attempt, idempotency key,
fencing value, Provider operation correlation, retry policy, and compensation.

A Workspace operation may coordinate several slot attempts, but it must expose
partial progress and cannot claim atomic Provider rollback. Compensation means
new explicit Product operations such as terminate, recreate, or restore; it is
not deletion of evidence.

### Product persistence authority

PostgreSQL is the Product source of truth. The logical schema contains these
separate authorities:

| Relation | Authority and important constraints |
| --- | --- |
| `workspaces` | Aggregate identity, owner, desired/observed state, version, lifetime, timestamps, tombstone; unique `(tenant_id, workspace_id)` |
| `workspace_slots` | Slot desired/observed state, profile, generation, version; unique `(workspace_id, slot_key)` and exactly one `primary-code` invariant |
| `provider_bindings` | Private selected Provider/revision/profile and opaque Provider correlations; unique current binding per slot generation |
| `product_operations` | Aggregate command ledger, actor, state, reconciliation, caller-safe error, retention |
| `product_operation_attempts` | Per-target dispatch attempts, idempotency/fence, deadlines, provider evidence, unknown outcomes |
| `workspace_events` | Immutable per-Workspace sequence and safe event data; unique `(workspace_id, sequence)` and `event_id` |
| `outbox` | Transactional external-dispatch and event-publication intents with bounded retry state |
| `idempotency_records` | Tenant/actor/method/path/key scope, canonical digest, retained result reference, expiry |
| `control_leases` | Product control scope, controller, monotonic fence, expiry, release/revocation state |
| `runtime_sessions` | Product session desired/observed state, protocol, policy, version, expiry |
| `connection_grants` | Hashed one-use tickets and bindings; never plaintext ticket retention |
| `agent_runs` | Delegated actor, task/tool references, state, expiry, trace correlation |
| `artifacts` | Product catalog metadata and authorization/retention state |
| `recordings` | Recording catalog, type, integrity metadata, retention and access state |
| `workspace_revisions` | Immutable content manifest identity, digest, parent, creator, and storage reference |
| `workspace_heads` | CAS pointer from Workspace and branch to one revision |
| `reconciliation_checkpoints` | Per-authority durable cursors and leases for resumable reconcilers |

The exact physical schema, indexes, partitions, and migration tooling require a
separate implementation slice. Different authorities may share one PostgreSQL
cluster initially, but they use distinct tables, roles, migrations, and access
paths. Provider and existing Gateway witness tables are never reused.

### Transaction boundary

One Product command transaction performs, in order:

1. authentication-derived tenant and actor authorization;
2. idempotency lookup or reservation;
3. aggregate row lock and expected-version check;
4. validation and aggregate mutation;
5. Product operation and initial attempt creation where external work is
   needed;
6. contiguous Workspace event append;
7. outbox append; and
8. idempotency result binding.

The transaction commits before any Provider, Gateway, Guest Agent, object
storage, or external identity call. Rollback leaves no dispatchable outbox
entry. A dispatcher claims committed outbox entries with a bounded lease and
records an attempt before sending external work.

External success is reconciled in a new Product transaction that locks the
current operation and slot generation, rejects stale evidence, updates the
projection, appends events, and advances checkpoints atomically.

### Outbox and reconciliation

The outbox is at-least-once. Every external mutation therefore uses a stable
idempotency identity derived from the Product operation and attempt, not a
random identity generated on each retry.

Reconcilers are level-triggered. They inspect retained Product intent and
Provider/Gateway/Guest evidence rather than assuming a dispatch response is
final. Process restart, timeout, connection loss, and ambiguous external
results produce `outcome_unknown` or continued reconciliation, not inferred
success or failure.

Reconciliation workers use database leases and checkpoints. Worker lease loss
stops dispatch; it does not transfer Product control-lease authority or reuse a
Provider fencing token.

### Workspace content and revisions

Product Workspace content is independent from a Provider sandbox filesystem.
The durable model is an immutable, content-addressed revision manifest plus a
CAS branch head. Blobs live in separately authorized object storage; PostgreSQL
stores metadata and opaque storage references, not large content.

The initial branch is `main`. A commit supplies the expected head revision and
creates a new immutable revision only if the head still matches. Conflicts are
Product CAS conflicts and do not overwrite another actor's revision.

A Provider sandbox receives an ephemeral materialization of one exact base
revision. Changes inside `/workspace` are not durable merely because the
sandbox remains running. A Product commit requires an authorized Guest Agent
or Contract-governed staging flow that:

- walks a bounded allowed tree without following unsafe links;
- produces a canonical manifest and content digests;
- uploads through short-lived storage grants;
- validates size, file count, MIME and active-content policy;
- commits the new revision and branch CAS in Product PostgreSQL; and
- never exposes host paths or object-store credentials through Product APIs.

The current Provider Contract does not complete this write-back path. Product
implementation must keep persistent Workspace commit unavailable until the
Guest Agent/data-plane and any required Provider Contract slices pass their
own gates. Direct host mounts and reading Provider runtime directories are
forbidden shortcuts.

### Artifacts and recordings

Artifacts and recordings store immutable content in object storage and
metadata in Product PostgreSQL. Catalog rows reference tenant-scoped opaque
object keys and cryptographic digests. Object keys and credentials are private
adapter state.

Provider artifact staging evidence can initiate Product publication only after
the Product independently checks operation, tenant, Workspace, slot,
generation, digest, policy, and retention bindings. Provider evidence is
retained separately from the Product artifact record.

Recording segments follow the same split. A catalog item is not `available`
until all required segments and the final integrity manifest are durably
committed.

### Retention and deletion

Workspace termination creates a tombstone and starts bounded cleanup. Product
operations, security events, control fences, artifact/recording retention, and
idempotency records follow explicit policies; they are not deleted as a side
effect of runtime cleanup.

Hard deletion is an operator workflow with authorization, legal/retention
checks, object-store deletion evidence, and an auditable terminal event. It is
not part of Product Contract `0.1.0`.

## Invariants

1. Every Workspace has exactly one `primary-code` slot.
2. Public Product resources contain no Provider or backend identity.
3. At most one current Provider binding exists per slot generation.
4. At most one unexpired Product control lease exists per control scope.
5. Workspace event sequences are contiguous and committed with the aggregate
   mutation they describe.
6. External work is never dispatched before Product intent and outbox commit.
7. Repeated dispatch is safe because the external idempotency identity is
   stable.
8. Stale Provider evidence cannot update a newer slot or binding generation.
9. Runtime cleanup cannot erase Product business or evidence authority.
10. Workspace file durability requires a committed Product revision; a live
    sandbox filesystem is insufficient.

## Consequences

- One Workspace can present a coherent product experience while preserving
  capability-specific Provider isolation and failure domains.
- Product workflows must handle partial progress and compensation explicitly.
- PostgreSQL and object storage become critical Product dependencies, while
  Redis-compatible storage remains coordination only.
- Persistent Workspace implementation is blocked until the safe
  materialize/commit path is designed and qualified.
- The schema is intentionally richer than a single-user UI so actor,
  generation, lease, and event authority do not require a breaking redesign.

## Rejected alternatives

### One Provider sandbox for every capability

Rejected because coding, Browser, Desktop, subagent, network, image, and
isolation policies have different lifecycles and evidence.

### A separate Product Workspace for each sandbox

Rejected because it loses aggregate lifetime, authorization, catalogs, event
ordering, and a stable user-facing Workspace identity.

### Directly share Provider or Gateway persistence

Rejected because those stores own different state machines and cannot provide
Product transactions, aggregate versions, events, or outbox guarantees.

### Treat `/workspace` as durable Product storage

Rejected because a Provider sandbox is replaceable and its filesystem is
provider-local execution state.

### Require atomic multi-slot Provider operations

Rejected because Providers expose per-sandbox operations and external work
cannot join the Product database transaction.

## Non-goals

This ADR does not create SQL migrations, choose an object-store product,
implement reconciliation, authorize persistent Workspace commit, or add
Provider lifecycle routes.
