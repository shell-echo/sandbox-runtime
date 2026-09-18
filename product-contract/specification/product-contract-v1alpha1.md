# Sandbox Runtime Product Contract v1alpha1

## 1. Status and authority

This specification, the Product OpenAPI, Product JSON Schema, semantic rules,
manifest, and content-addressed lock jointly define Product Contract design
version `0.1.0` under namespace
`urn:shell-echo:sandbox-runtime:product-v1alpha1`.

This is pre-implementation design authority. It defines the Product boundary
that implementation must satisfy; it is not evidence that any route,
capability, deployment, or compatibility promise is available.

Normative keywords `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are interpreted as
requirements on a future conforming implementation.

## 2. Authority boundaries

The Product owns Workspace desired state, actors, Product operations, Product
events, control leases, public sessions, connection grants, artifact and
recording catalogs, and Agent runs.

The Provider remains authoritative only for provider-local execution and
evidence. The Product MUST use the locked Provider Contract through a
caller-side adapter. It MUST NOT expose Provider IDs, operation documents,
private references, backend endpoints, host paths, credentials, or repository
records through Product resources.

The local `/instances` API is outside this Contract.

## 3. Transport

The Product API is served on a listener distinct from Provider and local
management listeners. Every path begins with `/api/v1`.

Except for deployment-specific process health endpoints outside this Contract,
all Product routes require a bearer access credential. Authentication produces
an exact tenant and actor. Tenant and actor identity are not accepted from
mutation bodies.

JSON requests use `application/json`, reject unknown fields and trailing data,
and are limited to 262,144 bytes unless OpenAPI specifies a lower limit. List
responses contain at most 200 entries and 1 MiB of encoded JSON. Identifiers
are 1..200 characters matching `^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`.

Every response includes `X-Request-ID`. Clients MAY supply one exact bounded
`X-Request-ID`; the server MUST replace malformed input and MUST NOT echo
credentials or private references.

## 4. Mutation protocol

Every mutation requires exactly one `Idempotency-Key` header of 1..128 visible
ASCII characters without whitespace or control characters. The idempotency
record is scoped to tenant, authenticated actor, method, normalized path, and
canonical request digest.

Reusing a key with the same scope and digest returns the retained result.
Reusing it with a different digest returns `409 PRODUCT_IDEMPOTENCY_CONFLICT`.
An implementation MUST retain idempotency authority at least as long as the
corresponding Product operation and never less than 24 hours.

Aggregate mutations carry `expected_version`. A stale value returns
`409 PRODUCT_VERSION_CONFLICT` without starting external work. Accepted
external work returns `202` and a Product `Operation`. Control-lease mutations
are bounded database authority changes and return their resource directly.

## 5. Workspace aggregate

A Workspace is the Product aggregate root. It has one immutable tenant, owner,
and required `primary-code` slot. Auxiliary named slots have kind `browser`,
`desktop`, `subagent`, or `isolated`. Slot keys are immutable and unique within
the Workspace.

Workspace desired state is `active`, `suspended`, or `terminated`. Observed
state is a Product reconciliation projection and MUST NOT be copied from one
Provider sandbox. Termination is irreversible and retains a tombstone.

Each slot has its own desired state, generation, Product profile, required
capabilities, and observed state. A slot maps to at most one current Provider
sandbox binding, which is private Product state and absent from public DTOs.

## 6. Product operations

Product operations form the aggregate command ledger. They retain the command
type, actor, Workspace and optional slot correlation, state, retryability,
reconciliation status, timestamps, and a caller-safe error.

States are `accepted`, `running`, `succeeded`, `failed`, `cancelled`, and
`outcome_unknown`. `outcome_unknown` is nonterminal until reconciliation
records a terminal Product decision. Provider operation state is evidence for,
not a replacement for, this ledger.

## 7. Events

Every committed Workspace change appends one or more durable events in the
same Product database transaction. Sequence numbers are positive, contiguous,
and strictly increasing per Workspace.

Polling uses `after_sequence`; streaming uses Server-Sent Events with the same
sequence as the SSE `id`. Reconnect with `Last-Event-ID` resumes after that
sequence. If retained history no longer contains the requested sequence, the
server returns `410 PRODUCT_EVENT_CURSOR_EXPIRED` and the client must refresh
the Workspace snapshot.

Delivery may repeat the last event across reconnect. Consumers deduplicate by
Workspace and sequence. Silent sequence gaps are forbidden.

## 8. Product control leases

Control leases serialize mutating human or Agent input for one exact control
scope. A scope is either the Workspace aggregate or one runtime session. At
most one unexpired lease exists per scope.

The server derives the controller actor from authentication, uses database
time, and issues a monotonically increasing fence for the scope. Acquire,
renew, release, expiry, and administrative revocation are durable events.
Expired or stale leases cannot be renewed. A replacement controller receives a
strictly greater fence.

Read-only viewers do not need a control lease. Every control-bearing connection
or mutation carries the lease ID and fence where required; stale control is
rejected before data-plane work.

## 9. Sessions and connection grants

Session kinds are `terminal`, `browser_automation`, `browser_live`, `desktop`,
`editor`, `notebook`, `preview`, `files`, and `mcp`. A Product capability must
advertise a kind and protocol profile before creation is accepted.

Sessions are bound to one Workspace slot and have Product state independent of
Provider session state. Creation, close, and resize are durable Product
operations. A closed, expired, or revoked session cannot issue a connection
grant.

A connection grant contains only a public Product Gateway URI, a protocol
profile, explicit `view` or `control` access mode, an opaque one-use ticket,
and bounded expiry. It is bound to tenant, actor, Workspace, slot, session,
requested protocol, and any required control lease fence. A viewer grant has
no control lease or fence and cannot authorize a mutating data-plane action. A
control grant carries the current session-scoped lease and fence. It MUST NOT
contain a Provider handoff, Provider endpoint, backend ID, or storage
credential.

## 10. Agent runs

An Agent run is a delegated Product actor execution bound to one Workspace and
slot, one immutable task reference, one tool profile, and one expiry. The run
does not contain a reusable human credential. Cancellation is asynchronous.

Agent trace recording contains structured actions, tool invocations, resource
references, outcomes, and timestamps. It does not require or authorize
recording private model reasoning.

## 11. Artifact and recording catalogs

Artifact resources describe Product-published content after Product validates
Provider staging evidence and applies retention and authorization policy.
Recording resources describe Product-owned audit, terminal, media, or Agent
trace recordings. Catalog APIs do not return direct storage credentials or raw
Provider staging references.

Content upload, download, playback, and live media use separately authorized
bounded data-plane grants. They are outside this control-plane Contract
version.

## 12. Errors

All errors use `ProductError` with code, safe message, retryability, request ID,
and optional bounded field violations. Messages MUST NOT contain credentials,
tokens, private endpoints, database diagnostics, host paths, backend IDs, or
Provider private references.

Stable codes include:

- `PRODUCT_INVALID_REQUEST`
- `PRODUCT_UNAUTHENTICATED`
- `PRODUCT_FORBIDDEN`
- `PRODUCT_NOT_FOUND`
- `PRODUCT_VERSION_CONFLICT`
- `PRODUCT_IDEMPOTENCY_CONFLICT`
- `PRODUCT_CONTROL_CONFLICT`
- `PRODUCT_CONTROL_STALE`
- `PRODUCT_CAPABILITY_UNSUPPORTED`
- `PRODUCT_EVENT_CURSOR_EXPIRED`
- `PRODUCT_RATE_LIMITED`
- `PRODUCT_DEPENDENCY_UNAVAILABLE`
- `PRODUCT_OUTCOME_UNKNOWN`
- `PRODUCT_INTERNAL`

Retryable errors include `Retry-After` when the server has a safe lower bound.
Authentication and authorization precedence prevents resource-existence
disclosure across tenants.

## 13. Capability advertisement

`GET /api/v1/capabilities` is an authenticated, tenant-aware snapshot frozen
for the request. Each capability binds an ID, version, protocol profiles,
resource limits, and readiness state. Only `ready` capabilities can be selected
for new resources.

The snapshot is derived from the complete dependency graph. Configuration
cannot force an incomplete capability to `ready`. A caller must not infer
support from schema vocabulary or route presence.

## 14. Compatibility and evidence

The content lock protects design resources against accidental drift. A future
implementation claim additionally requires:

- strict DTO projections and bounds;
- a Contract verifier that recomputes the manifest and tree digests;
- fixtures and a content-derived conformance suite;
- transport, authentication, authorization, idempotency, version, pagination,
  and event-resume tests;
- Product database restart and outbox/reconciliation evidence; and
- black-box Product/Gateway/Provider evidence for every advertised capability.

Provider conformance, Product conformance, independent external-caller
qualification, deployment qualification, and production readiness remain
separate claims.
