# ADR 0030: Browser Authenticated Shared Capacity Boundary

- Status: Accepted for the P4 Browser authenticated-capacity port and memory
  reference component
- Date: 2026-09-04

## Context

ADR 0027 bounds total and per-session Browser Gateway connections inside one
Gateway process after caller authorization. ADR 0028 adds a process-local
global gate before WebSocket admission and upgrade, and ADR 0029 bounds accepted
TCP connections, TLS, and HTTP work. Those controls prevent unbounded work in
one process, but they do not coordinate capacity across Gateway replicas or
partition an authenticated workload by tenant.

The pre-upgrade edge deliberately has no trusted caller or tenant identity. It
must continue to apply only coarse global limits and must not trust a tenant,
caller, grant, or session value supplied by an unauthenticated request. Tenant
partitioning becomes valid only after the caller-owned authorizer returns a
valid grant and the Gateway verifies its exact binding to the connection
request.

This remains a caller-owned public Gateway concern. The Provider owns its own
runtime allocation capacity and may independently reject Provider operations
under pressure, but it does not own public user authorization, tenant quotas,
Gateway grants, or public connection capacity. The locked Provider OpenAPI,
Schemas, semantic rules, fixtures, and Conformance Suite do not define this
Gateway-internal mechanism and must remain unchanged.

## Decision

Add a narrow authenticated-capacity port to the caller-owned Gateway. Browser
composition requires an explicit implementation and supplies no allow-all,
unbounded, or production default. The Gateway invokes the port only after:

1. the connection request passes structural validation;
2. the caller-owned authorizer returns a grant;
3. the grant is valid and unexpired; and
4. every caller, tenant, sandbox, Browser session, capability, and opaque
   handoff field is bound exactly to the request.

Capacity acquisition remains before revocation subscription, Provider
reference resolution, backend dialing, or an authorized audit event. Invalid or
unauthorized requests cannot select or consume another tenant's partition.
The identity-free pre-upgrade gate remains independently required and unchanged.

One acquisition atomically reserves one unit in all of these dimensions or
reserves nothing:

- a deployment-wide global Browser connection partition;
- the authenticated tenant partition; and
- the exact tenant, sandbox, and Browser session partition.

The session key excludes caller and grant identifiers so that another caller or
newly minted grant cannot bypass the same-session limit. Limits are explicit,
positive, ordered so the session limit cannot exceed the tenant limit and the
tenant limit cannot exceed the global limit, and bounded by implementation
ceilings. They are capacity policy inputs from the calling platform, not fields
in a Provider request or capability response and not production sizing
recommendations.

Acquisition is non-queueing and returns either an owned lease or a bounded
capacity/unavailable error. The lease exposes a typed event stream and an
idempotent, context-aware release operation. A real shared adapter must assign
an opaque ownership identity, retain the reservation only through a bounded TTL
no later than the authorization grant expiry, and renew it internally. Each
renewal atomically proves that the same owner still holds all three reservations
and extends them or fails without restoring lost ownership. Expiry,
replacement, an unrecoverable renewal failure, or inability to prove ownership
emits a typed lost or unavailable event; the Gateway then closes the public and
private streams and must not reconnect. A stale owner cannot renew or release a
later owner's reservation. Release is safe to retry and TTL expiry provides
eventual reclamation after process death.

The boundary fails closed. Capacity-store unavailability cannot admit a new
connection. If an active lease cannot be renewed or its ownership becomes
unknown, the connection loses authority to consume capacity and is terminated.
Cancellation and deadlines propagate to acquire, renew, and release work.
Capacity rejection and loss are recorded only through the caller-owned Gateway
recorder using bounded metadata. Capacity state and audit must not contain bearer
credentials, frame payloads, handoff references, Provider endpoints, network
addresses, backend identifiers, or raw store diagnostics.

This slice supplies only the port and a concurrency-safe memory reference
implementation. The memory implementation exercises atomic global, tenant, and
session reservation plus idempotent release. It deliberately does not simulate
shared-store TTL, renewal, ownership loss, or backend failure; tests inject
those typed lease events at the port boundary. Its state is process-local and
disappears on restart. It is suitable for component tests and the existing
reference composition only. It is not a shared or distributed capacity backend.

## Release Boundary

Focused race/shuffle tests for this port slice must cover invalid and typed-nil
dependencies, explicit limit ordering, authorization-before-acquisition
ordering, exact grant binding, atomic global/tenant/session contention, no
partial reservation, same-session rejection across different callers and
grants, independence of distinct tenant partitions, cancellation, typed lease
loss/unavailability, idempotent release, and concurrent acquire/release races.
Rejection or loss must not expose sensitive fields, and rejection must not
reach revocation, Provider resolution, or backend dialing. Full repository
race/shuffle, vet, the unchanged Contract verifier, and the locked 48-case
Conformance Suite remain required.

Passing those gates establishes authenticated-capacity port and memory-reference
component evidence only. It does not close the partition-aware shared or
distributed capacity gate because no independently shared durable authority has
been exercised.

Closing the shared-capacity gate requires a separately reviewed real shared
backend and a black-box run with at least two independently started Gateway
processes using that backend. The run must prove atomic cross-process global,
tenant, and session enforcement without oversubscription; continued service for
an unaffected tenant; bounded TTL and internal renewal; crash reclamation;
stale-owner fencing; lease-loss termination; concurrent renewal/release races;
store-unavailable failure closure; recovery; and absence of Provider resolution
or dialing for rejected work. The evidence must pin the clean Gateway, caller,
backend, configuration, and Provider revisions. A single process, two
in-process service objects, or a shared memory adapter cannot satisfy that gate.

This ADR and its component gate do not establish durable distributed
revocation, Provider multi-controller reliability, hostile multi-tenant
isolation, a deployable public Gateway, real Agent Platform compatibility,
aggregate conformance, deployment readiness, or production readiness.

## Consequences

- Authenticated capacity policy remains in the caller-owned Gateway without
  adding user, grant, quota, or revocation fields to the Provider Contract.
- The Provider's Browser runtime allocation limit and the Gateway's public
  connection limits remain separate authorities and may reject independently.
- Coarse listener and pre-upgrade global limits still protect work performed
  before identity exists; they do not become tenant-aware.
- A future shared backend can implement the same lease semantics without making
  the memory adapter or Provider repositories authoritative.
- Durable distributed grant revocation remains a separate decision and release
  gate because its consistency, watch, retention, and active-disconnect
  semantics differ from capacity ownership.
