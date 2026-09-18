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

For `product-browser-automation.v1`, the public WebSocket subprotocol is the
same profile identifier. A client sends only schema-valid
`BrowserAutomationAction` text messages with a strictly increasing sequence;
the Gateway returns only `BrowserAutomationResult` text messages. The initial
closed action set is `page.info` and bounded `page.text`. Unknown members,
unknown actions, binary messages, raw CDP messages, duplicate or skipped
sequences, oversized messages, and excess pending actions close the connection.

Browser automation requires a `control` grant carrying the current
session-scoped Product lease and fence. Product authority is watched for the
connection lifetime. The Product Gateway translates the closed public action
inside its trusted boundary and reaches Browser execution only through a
TLS-protected, Gateway-authenticated private ingress. That ingress validates a
downstream action fence on activation and every complete private action. A
reconnect performs fresh private resolution; neither the opaque Provider
handoff, the private endpoint, raw CDP, nor downstream-fence credentials may
appear in public messages, errors, audit events, or logs.

For `product-browser-live.v1`, a client exchanges the closed
`BrowserLiveSignalRequest` and `BrowserLiveSignalResponse` documents over an
authenticated HTTPS endpoint before WebRTC connectivity. Production admission
requires TLS, one exact allowlisted HTTPS Origin, a one-use Product ticket,
continuous Product authority, and relay-only ICE through configured encrypted
TURN. The initial negotiated video profile is bounded VP8 with explicit
resolution, frame-rate, and bitrate ceilings. Unsupported codecs, dimensions,
oversized signaling or media packets, excess media/input queues, and slow
consumers fail closed.

A view grant creates a receive-only media session and cannot negotiate the
control data channel. A control grant may negotiate only the
`product-browser-control.v1` channel. It carries closed
`BrowserLiveControlMessage` and `BrowserLiveControlResult` documents for
keyboard, pointer, touch, clipboard read/write, Product-bound upload/download,
navigation, popup, and permission actions. Sequences start at one and increase
without gaps; coordinates are further bounded by the negotiated viewport.

The immutable policy snapshot taken at admission denies every action that is
not explicitly enabled. Clipboard, transfer, popup, and permission actions may
require recent user activation and explicit consent. Clipboard bytes, file
count, per-file and total bytes, media type, transfer identity, digest,
filename, popup count, origins, and permission names are bounded. Filenames
are single path components. Navigation targets must be in the exact origin
allowlist, and cross-origin navigation is separately disabled unless enabled.
Product binds transfers to the same tenant, actor, Workspace, direction,
digest, size, and completed Product transfer. A policy revision change revokes
the existing control connection; it never broadens a retained connection.

After a live peer first connects or recovers inside the bounded disconnect
grace period, Product rechecks the complete Gateway authority before media or
control resumes and requests a rate-limited keyframe. RTCP loss and full-intra
requests, plus the closed ordered `stream.resync` control message, share the
same keyframe limiter. The closed ordered `stream.resize` message may change
only to another bounded VP8 video policy through the trusted media adapter.
Control messages received while the peer is disconnected are stale and close
the peer. An expired disconnect grace, media dependency loss, or failed
resynchronization closes the connection; reconnecting then requires a new
one-use Product grant and repeats signaling, policy, authority, and private
resolution. The durable Browser session is not closed merely because a client
connection is lost. Closing the live projection revokes its exact consumed
gateway binding so controller admission is released without making the ticket
reusable.

Signaling returns the exact committed recording mode so the client can keep a
visible recording indicator. A `required` Browser media recording additionally
requires an explicit bounded consent reference and a ready recorder before the
private media source opens; missing or lost recording storage fails closed.
Accepted RTP plus a content-minimized control-event timeline is serialized into
bounded encrypted segments. Segment digests form an ordered chain through the
final catalog digest. Product serializes per-tenant active-recording admission
and byte accounting, authorizes replay through Workspace ownership, and deletes
encrypted content before marking an expired catalog entry deleted. Catalog and
ordinary log projections contain metadata only, never captured media, control
payloads, object references, encryption-key references, or consent material.

Product rechecks the exact session control lease, fence, and unchanged policy
revision before every forwarded input. SDP responses, messages, errors, and
logs never project the Provider handoff, Browser endpoint, relay credentials,
storage reference, or backend identity.

Browser slot admission is also bound to an immutable image reference whose
digest exactly matches the selected Product profile, a bounded CPU, memory,
ephemeral-storage, and PID shape, the locked Browser runtime profile, and one
exact restricted-egress policy reference. Product requests an unprivileged,
read-only-root, no-service-account, seccomp-confined Provider sandbox with a
mandatory egress gateway. The Provider advertises Browser readiness only after
revalidating the pinned image/provenance and restricted-network dependencies.
The runtime uses private PID, IPC, cgroup, UTS, and user namespaces, no mapped
or requested devices, no added capabilities, no published ports, no host or
default bridge, no extra hosts or DNS search path, and bounded writable tmpfs
mounts. Device permissions remain denied unless separately admitted through
the Product Browser policy; policy admission never adds a runtime device.

The restricted egress path resolves every destination independently and
rejects IP literals, DNS rebinding to non-public addresses, metadata,
loopback, link-local, private, carrier-grade NAT, benchmark, documentation,
multicast, unspecified, and reserved ranges. HTTP Host and TLS SNI must match
the exact hostname policy. Cleanup removes only resources carrying the exact
sandbox/session/network ownership tuple.

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
