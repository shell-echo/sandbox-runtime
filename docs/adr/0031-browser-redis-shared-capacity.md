# ADR 0031: Browser Redis-Compatible Shared Capacity Adapter

- Status: Accepted for the P4 Browser real shared-capacity adapter and
  two-independent-Gateway evidence slice
- Date: 2026-09-05

## Context

ADR 0030 defines the caller-owned authenticated-capacity port and proves its
Gateway ordering, loss handling, and process-local memory reference. It also
requires a separately reviewed real shared backend before the shared-capacity
gate can close. The backend must coordinate at least two independent Gateway
processes without moving tenant policy or public connection authority into the
Provider.

A shared implementation must reserve global, tenant, and exact Browser-session
capacity as one indivisible decision. It must reclaim a dead Gateway's lease,
prevent a stale owner from renewing or releasing a replacement lease, and fail
closed when it cannot prove ownership. A Redis transaction expressed as a Lua
script is isolated from concurrent commands, but Redis does not roll back
earlier writes when a later command in a script fails. A design that writes
three independent counters or sorted sets can therefore leave partial state on
a wrong-type, out-of-memory, or other runtime error even though the script is
atomic with respect to concurrency.

The repository currently has no Redis client or shared-capacity adapter. The
existing file repositories deliberately enforce exclusive single-process
ownership and cannot satisfy this gate. The locked Provider Contract does not
define public Gateway capacity and remains unchanged.

## Decision

Add a caller-owned Redis-compatible adapter for `gateway.ConnectionCapacity`.
The concrete adapter stays outside Provider packages and depends inward on the
Gateway capacity port. Browser composition continues to require an explicit
capacity implementation and supplies no shared-store, allow-all, or unbounded
default.

The adapter targets the bounded Redis command and scripting subset also
implemented by Valkey. The implementation and evidence must pin an exact
client version and an exact Redis-compatible server image digest. Selection of
Redis or Valkey for a deployment must separately account for server licensing,
support, and operational policy; protocol compatibility is not production
approval.

### Namespace and policy

One immutable deployment namespace owns three Redis keys:

- one policy hash containing a schema version, the canonical policy
  fingerprint, the global/tenant/session limits, lease TTL, renewal interval,
  and renewal safety margin;
- one monotonic fencing counter; and
- one deployment capacity sorted set.

All keys use the same fixed Redis Cluster hash tag derived from a SHA-256
fingerprint of the configured namespace. Raw tenant, sandbox, session, caller,
grant, handoff, endpoint, credential, or backend identifiers are not Redis key
components. A policy change uses a new namespace and drains the old namespace;
live processes may not silently rewrite policy in place.

Policy provisioning is an explicit administrative operation allowed only after
the caller independently confirms a namespace is virgin or fully drained.
Gateway startup uses a separate verify-only operation. The runtime adapter
validates the complete stored policy and fingerprint before it can acquire or
renew. The fingerprint includes all four Lua script hashes. A missing,
malformed, wrong-type, or mismatched policy fails closed. Startup and ordinary
acquisition must not recreate a missing policy, because transparent recreation
after store data loss could admit a replacement while an earlier Gateway still
believes its lease is valid.

The configured limits remain positive and ordered as required by ADR 0030 and
must not exceed `gateway.MaxConnectionCapacity`. Lease and renewal durations
are explicitly bounded and represented as whole milliseconds by both Go and
Redis. The command timeout and renewal safety margin must
leave enough time to stop an active connection before the last confirmed lease
expiry. These values are policy invariants for the evidence deployment, not
production sizing recommendations.

### Single capacity record

The deployment capacity key is one sorted set. Each active member represents
one logical connection's simultaneous contribution to all three dimensions.
The versioned, fixed-width member contains only:

- a cryptographically random opaque owner identity;
- the monotonically allocated, fixed-width fencing value, capped below the
  largest integer Lua can represent exactly;
- a SHA-256 fingerprint of the tenant scope; and
- a SHA-256 fingerprint of the exact tenant, sandbox, session kind, and Browser
  session scope; and
- the authorization grant expiry in Unix milliseconds, used only to bind an
  idempotent retry to the exact original lifetime.

The member excludes caller and grant identifiers, bearer material, the opaque
Provider handoff, endpoint data, and frame contents. A new grant or caller for
the same Browser session therefore selects the same session partition but gets
a distinct owner identity. Session-kind separation prevents a terminal and a
Browser identifier with the same text from selecting the same scope.

The sorted-set score is the lease expiry in Redis server Unix milliseconds.
The expiry is the earlier of Redis `TIME` plus the configured lease TTL and the
grant expiry rounded down to milliseconds. It can never intentionally extend
past authorization. Redis `TIME`, rather than a Gateway wall clock, orders
expiration and renewal inside scripts. The adapter converts the returned
server-relative lifetime to a conservative local monotonic deadline for its
renewal safety calculation.

This single-record model is intentionally O(N) for acquisition: the Lua script
counts active members for the requested tenant and session. N is bounded by the
global implementation ceiling of 1,000. The model avoids partial
global/tenant/session writes and keeps every ownership mutation to one sorted-
set member. A larger production scale requires a separate reviewed data model
and benchmark; it must not weaken atomicity by replacing this model with
independent best-effort counters.

### Atomic scripts

Acquire, renew, and release use separately versioned Lua scripts. Script source
digests are pinned in test evidence. The scripts validate key types, policy,
argument shape, fixed-width member encoding, and the hard cardinality bound
before an unsafe mutation. They return bounded status codes; raw Redis errors
remain internal diagnostics and never enter stable responses or audit reasons.

Acquire performs one serialized decision:

1. read Redis `TIME`, reject a grant that cannot leave the configured renewal
   safety margin plus one complete operation timeout, and remove sorted-set
   members whose scores are not later than that time;
2. fail unavailable if the remaining cardinality exceeds the hard bound or an
   active member has an invalid encoding;
3. recognize the same still-active opaque owner as an idempotent retry, while
   rejecting an owner collision bound to another subject;
4. verify the fencing counter is canonical, within its exact numeric bound, and
   not behind any active member, then count the global, requested-tenant, and
   requested-session contributions and return capacity exhausted without
   mutation if any configured limit is met;
5. allocate the next fencing value and add exactly one member with `ZADD`; and
6. set the capacity key expiry to the greatest active member score, so inactive
   deployment state is eventually removed.

An ambiguous acquisition result is unavailable to the caller. The client must
not blindly retry the write with a new owner. A retry of the same command may
recover only the same still-active owner record; otherwise any committed orphan
is left to its bounded TTL. Advancing the fencing counter without adding a
member may create a gap but cannot consume capacity or transfer ownership.

Renew validates the policy, obtains Redis `TIME`, validates the complete bounded
active set and fencing counter, and finds the exact version, owner, fence,
tenant, and session member. It extends that member with `ZADD XX`
only when the exact record is present and its previous score is still in the
future. It never recreates an absent or expired member. The new score is again
bounded by grant expiry, and the sorted-set key expiry is recomputed.

Release removes only the exact member. Absence is an idempotent success, and
the script deletes an empty capacity key or recomputes its greatest expiry.
Release does not require a currently matching policy because cleanup must
remain possible during a configuration fault. A stale owner has a different
owner/fence member and cannot remove a later owner's reservation.

Redis serializes renew and release. If renew executes first, release removes
the renewed member. If release executes first, the later `ZADD XX` cannot
recreate it. The Go lease also cancels its renewal loop and serializes its own
renew/release calls. A timed-out release remains retryable; TTL is the final
reclamation mechanism after process death.

### Renewal and loss

The returned `ConnectionLease` owns an internal renewal loop. Its event channel
is non-nil and remains open while the lease is healthy. The loop does not rely
on Redis Pub/Sub, keyspace notifications, or client-local counters as ownership
evidence.

A successful acquire or renew establishes a conservative local monotonic
deadline corresponding to the returned Redis expiry. Transient command errors
may be retried with bounded backoff only while the last confirmed ownership
still has the configured safety margin. The adapter never treats an ambiguous
renewal as proof of an extension.

When Redis reports that grant expiry, rather than lease TTL, bounds the current
reservation, another renewal cannot extend it. The adapter still validates the
exact shared ownership at each renewal interval while one complete operation
fits before the safety boundary. It emits `lost` at an otherwise healthy
grant-bound safety boundary; an unresolved backend error remains `unavailable`.

An exact script result proving that the member is absent, expired, or replaced
emits one `CapacityEventLost`. A policy mismatch, malformed shared state,
backend error that remains unresolved at the safety boundary, or any other
inability to prove ownership emits one `CapacityEventUnavailable`. Intentional
release suppresses a new loss event. The existing Gateway then closes public
and private streams, does not reconnect, records only bounded metadata, and
releases through its independent bounded cleanup context. Existing authority
priority remains revocation, then grant expiry, then capacity, then transport.

New acquisition fails unavailable during a Redis outage. An active lease stops
before its last confirmed expiry when renewal cannot be recovered. Recovery
means that the same authoritative store and policy become reachable again;
subsequent acquisition can succeed after earlier owners have released or
expired. Redis state loss, rollback, or restoration from an older snapshot is
not ordinary recovery and must remain unavailable until an operator applies a
separately reviewed quarantine/drain procedure.

### Redis-compatible deployment assumptions

The shared-capacity evidence environment uses one authoritative
Redis-compatible primary with scripting enabled, a dedicated ACL/key namespace,
and `noeviction`. Eviction or unauthorized deletion of the capacity key can
erase ownership before Gateways observe loss and can therefore violate the
capacity invariant. Out-of-memory writes under `noeviction` fail closed.

Lua execution on one authoritative primary provides the concurrency guarantee
for this slice. Redis asynchronous replication, Sentinel or Cluster failover,
`WAIT`, and replica promotion do not by themselves prove that an acknowledged
lease cannot be lost or rolled back during partition or failover. This ADR does
not claim high-availability or production distributed consistency. A future HA
design must use a reviewed consistency model that preserves the fencing and
no-oversubscription invariant through failover.

The deployment clocks must have a documented bound relative to authorization
grant timestamps. Rounding the grant expiry down and using Redis `TIME` is
fail-closed for the tested environment, but it is not evidence of arbitrary
cross-host clock correctness.

## Release Boundary

Component and real-backend integration tests must cover policy provisioning and
mismatch, wrong-type and malformed state, argument and subject validation,
grant-expiry bounding, global/tenant/session atomic contention, no partial
reservation, same-owner retry, opaque-owner collision, monotonic fencing,
idempotent release, renewal, natural expiry, context cancellation, command
timeouts, concurrent acquire/renew/release, stale renew and release after a
replacement, unavailable-store closure, recovery, and sensitive-data absence.
Tests must use a real pinned Redis-compatible server; an in-memory Redis fake is
not evidence for scripting, TTL, server time, or failure semantics.

Closing the shared-capacity gate additionally requires a black-box run with two
independently started Gateway OS processes using the same backend. Two service
objects in one process do not qualify. The run must prove:

- exact global, tenant, and session enforcement under simultaneous contention
  without oversubscription;
- continued service for an unaffected tenant while another tenant is full;
- no Provider resolution or backend dialing for capacity-rejected work;
- renewal beyond the initial TTL without exceeding grant expiry;
- crash reclamation after forcibly terminating the owning Gateway;
- rejection of a stale owner's renew and release after replacement;
- active connection termination without reconnect after confirmed loss;
- deterministic renew/release race behavior;
- fail-closed new acquisition and active-lease termination during a store
  outage, followed by recovery against retained store state; and
- absence of owner, fence, raw subject, endpoint, credential, handoff, or frame
  data from public errors and Gateway audit output.

The older process-local Gateway connection bound executes before the
authenticated shared authority. The evidence configuration must set that local
bound high enough that the intended cases demonstrably reach the shared
adapter. Authenticated capacity executes after the Browser WebSocket upgrade,
so a rejection is observed as a bounded connection close and Gateway audit,
not as the pre-upgrade edge limiter's HTTP `429`.

Evidence must pin the clean Gateway binary and source revision, independent
caller/harness revision, Redis-compatible image digest and configuration,
policy fingerprint, script digests, Provider revision, architecture, and run
manifest. Fault-control access used to delete or inspect test lease members is
E2E-only, must be isolated from the public Gateway, and must not expose owner or
fence data in the caller report or ordinary audit.

Passing these gates establishes only the real shared-capacity adapter and
two-independent-Gateway black-box evidence for the named Browser reference
boundary. It does not establish Redis or Valkey production deployment, HA
failover correctness, durable distributed revocation, downstream stream
fencing, arbitrary process-suspension safety, Provider multi-controller
reliability, hostile multi-tenant isolation, real Agent Platform compatibility,
aggregate conformance, deployment readiness, or production readiness.

## Consequences

- Global, tenant, and Browser-session capacity share one bounded ownership row,
  eliminating partial dimension reservations in the selected Redis model.
- Opaque random ownership plus a monotonic fence prevents stale Redis mutation
  while the namespace history is retained. The current Gateway port does not
  pass that fence to a downstream runtime, so it is not downstream action
  fencing.
- TTL reclaims a crashed process, while conservative internal renewal closes an
  active connection before ownership can no longer be proved under normal
  scheduling and network-failure assumptions.
- The single deployment sorted set is a deliberate bounded hot key. Its
  correctness is preferred over unreviewed sharding; throughput and HA remain
  later gates.
- A process suspended beyond its confirmed TTL cannot execute its renewal loop.
  The two-Gateway gate tests crash and network failure, not an absolute safety
  guarantee for arbitrary scheduler suspension. Stronger guarantees require a
  downstream-enforced fencing token or an equivalent reviewed mechanism.
- Durable distributed revocation remains a separate authority and decision. It
  must not be inferred from capacity leases or implemented by overloading the
  capacity namespace.
