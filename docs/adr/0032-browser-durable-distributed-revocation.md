# ADR 0032: Browser Durable Distributed Grant Revocation

- Status: Accepted for the P4 caller-owned durable revocation port and
  Redis-compatible component slice
- Date: 2026-09-05

## Context

ADR 0024 requires a caller-owned revocation source before the Runtime Gateway
may resolve or dial a Provider Browser handoff. The current memory adapter can
interrupt an active connection in one process, but its state disappears on
restart and is not shared by Gateway replicas. It cannot establish durable or
distributed revocation.

The existing port also separates `IsRevoked` from `Watch`. A revocation between
those calls can be missed by an edge-triggered implementation. Its untyped
closed channel cannot distinguish a confirmed revocation from loss of the
revocation authority. Treating both as revoked produces false audit evidence;
keeping a connection open when authority is unknown fails open.

Caller grant revocation is not Provider Browser handoff revocation. The caller
owns users, tenants, grants, and public Gateway policy. The Provider owns its
opaque reference and runtime state. ADR 0031 capacity leases are a third,
separate authority: their fence prevents a stale owner from changing the
capacity ledger, but it is not a grant revocation revision or a downstream CDP
action fence.

## Decision

Replace the split check/subscription port with one level-triggered watch for an
exact caller grant. `RevocationSubject` contains only the validated `grant_id`
and authoritative grant expiry. `RevocationSource.Watch` returns a stable
`RevocationWatch`:

- `Done` remains open while the source can prove that no tombstone exists;
- after `Done` closes, `Err` consistently reports confirmed revocation,
  authority unavailability, or observation-context cancellation; and
- a nil, typed-nil, nil-channel, closed-without-status, or otherwise malformed
  watch fails closed.

The source must perform its initial authoritative read before returning. A
durable implementation uses a retained tombstone as level state, so a
revocation committed between that read and a later poll remains observable.
Pub/Sub or another edge notification may reduce latency, but it cannot be the
only source of truth.

Add a separate `RevocationWriter` for the caller control plane. It accepts the
same exact grant subject and does not revoke, mutate, or interpret a Provider
handoff reference. No Provider route, DTO, schema, capability, or operation is
added by this decision.

### Redis-compatible authority

Add a Redis-compatible adapter in `gateway/revocation/redis`. It uses an
operator-provisioned namespace distinct from every capacity namespace. The raw
namespace and grant identifier are never Redis key components:

- a fixed policy hash is addressed by a SHA-256 namespace cluster tag; and
- each grant tombstone key uses the same tag plus a SHA-256 digest of the exact
  grant identifier.

The immutable policy records a versioned format, its canonical fingerprint,
the maximum accepted grant lifetime, polling interval, operation timeout, and
the hashes of every server-side script. Administrative provisioning is
separate from runtime verify-only startup. A missing, malformed, wrong-type, or
mismatched policy fails closed and is not recreated by ordinary watch or revoke
work.

The revocation script validates policy and Redis key types, reads Redis server
time, and requires the requested expiry to be in the future and within the
configured maximum grant lifetime. Its successful write is the revocation
linearization point. The tombstone value is one canonical expiry in Unix
milliseconds, and Redis expires the key at that same instant. Repeating or
reordering a revoke is idempotent: the stored expiry can only remain equal or
move later, never earlier. A successful response is returned only after the
authoritative primary acknowledges the write.

The check script validates policy and tombstone shape against Redis server
time. An unexpired tombstone is confirmed revoked. No tombstone is active.
Malformed shared state is unavailable, never active. Expired grant reuse and
global or session-wide revocation are outside this exact-grant component.

Watch performs one synchronous check, then bounded level-triggered polling.
The polling interval is the maximum normal propagation delay for this
component. Any read, policy, protocol, or state-validation failure ends the
watch with authority unavailable. The Gateway closes both streams without
reconnect and records only the fixed metadata reason `revocation authority
unavailable`. Raw Redis errors, addresses, credentials, keys, grant values,
handoff references, endpoints, and frame data must not enter stable errors,
ordinary audit, or caller evidence.

Redis client retries are disabled so one operation has one bounded application
decision. Context deadlines and cancellation are preserved. The adapter
requires RESP2, context-aware timeouts, disabled client identity metadata, and
bounded dial, read, write, and pool timeouts.

### Gateway ordering and priority

The established Browser ordering remains:

1. validate the public request;
2. authorize and exactly bind the caller grant;
3. acquire local and authenticated capacity;
4. establish and validate the revocation watch;
5. record the authorized event;
6. resolve and dial the Provider handoff; and
7. proxy while observing revocation, expiry, capacity, and transport.

A pre-revoked or unavailable grant must not reach authorized audit, Provider
resolution, or backend dialing. Reconnect uses the same live watch and cannot
bypass a tombstone. Simultaneous terminal causes retain the existing priority:
confirmed revocation, then grant expiry, then capacity loss/unavailability,
then revocation-authority unavailability, then transport or caller
cancellation. Authority unavailability is not recorded as confirmed
revocation.

The Gateway bounds audit reasons before passing them to the caller recorder.
An authorization adapter or shared backend error is diagnostic context only
and must not be copied to a stable audit reason.

## Release Boundary

Component and real-backend integration tests must cover:

- invalid, canceled, nil, typed-nil, and malformed watch behavior;
- an initial tombstone and revoke concurrent with watch establishment;
- active revocation during resolve, dial, proxy, and reconnect backoff;
- stable priority against expiry and capacity events;
- authority loss before connection and during an active connection;
- fixed audit reasons and absence of backend, grant, handoff, endpoint, and
  frame data;
- policy provision/verify/mismatch, wrong Redis types, malformed tombstones,
  strict client configuration, and context timeouts;
- server-time grant-expiry and maximum-lifetime bounds;
- duplicate, concurrent, and out-of-order revoke with monotonic retention;
- level-triggered catch-up, polling cancellation, watcher cleanup, natural
  tombstone expiry, and retained state across adapter reconstruction; and
- a real pinned Redis-compatible server rather than an in-memory Redis fake
  for scripting, server time, expiry, and persistence evidence.

Passing those tests establishes the Gateway port semantics and one real
Redis-compatible adapter component only. Closing the durable distributed
revocation caller gate additionally requires a separately locked black-box run
with two independent Gateway OS processes and an independent revoker/control
process against the same retained backend. That run must show active disconnect
and pre-resolution rejection on both Gateways, retained rejection after Gateway
restart, unaffected grants and tenants, store-outage failure closure, recovery
without resurrection, bounded propagation, and sanitized evidence.

This ADR does not establish downstream capacity fencing. A Gateway suspended
past a capacity lease can still race its renewal observer when resumed, and
Chromium does not understand the ADR 0031 fence. A later ADR must define a
private, independently enforced CDP ingress and its action linearization point.

It also does not establish Redis or Valkey provenance, HA/failover or rollback
consistency, Provider multi-controller reliability, hostile multi-tenant
isolation, real Agent Platform compatibility, aggregate conformance,
production advertisement, deployment readiness, or production readiness.

## Consequences

- Exact grant revocation remains caller-owned and separate from Provider
  handoff state and Gateway capacity ownership.
- Level-triggered retained state removes the check/watch lost-event window and
  lets a reconstructed Gateway catch up without relying on Pub/Sub history.
- Active connections fail closed when the revocation authority becomes
  unknown, while audit distinguishes that condition from confirmed revocation.
- One key per revoked grant is bounded by authoritative grant expiry. Namespace
  sizing, memory limits, ACLs, persistence, backup, and operational monitoring
  remain deployment responsibilities and later evidence gates.
- A single authoritative primary is the consistency model for this slice.
  Replica promotion, restored snapshots, or state loss can resurrect a revoked
  grant and therefore remain unavailable until a separately reviewed
  quarantine and drain procedure exists.
