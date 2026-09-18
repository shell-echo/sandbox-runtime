# ADR 0043: Product Contract v1alpha1 Control-Plane Boundary

- Status: Accepted as Phase 1 design authority; no implementation or
  compatibility claim
- Date: 2026-09-18

## Context

ADR 0042 authorizes a first-party Product caller in this repository while
keeping Product API, Provider API, and the local `/instances` API separate. A
machine-readable Product Contract is required before Product transport or
application code can be added.

The first product version must represent an Agent workspace that can contain
multiple sandbox slots and expose durable operations, events, sessions,
control ownership, artifacts, recordings, and Agent runs. It must not expose
Provider IDs, backend endpoints, host paths, database identities, or private
Gateway references.

The complete target includes several data-plane protocols whose exact Provider
support is not yet available. Publishing control-plane resource types must not
pretend those protocols or Provider capabilities are implemented.

## Decision

### Contract identity and location

The Product Contract is independent from the Provider Contract and lives under
`product-contract/` with namespace
`urn:shell-echo:sandbox-runtime:product-v1alpha1` and design version `0.1.0`.
Its authoritative resources are:

- the Product Contract specification;
- OpenAPI;
- the closed JSON Schema vocabulary;
- semantic rules;
- the Contract manifest; and
- a content-addressed lock containing every normative resource digest.

The Product Contract is Phase 1 design authority only. Version `0.1.0` does not
claim an implementation, deployment, compatibility support window, or passing
conformance suite. The first implementation slice must add a verifier,
fixtures, conformance cases, and black-box transport evidence before changing
that claim.

### Separate Product surface

The Product API uses `/api/v1` on a separately configured authenticated
listener. It does not mount Provider `/v1` routes or local `/instances` routes.

The first control-plane resource families are:

- capabilities;
- Workspaces and named sandbox slots;
- asynchronous Product operations;
- durable Workspace events and resumable event streaming;
- Product control leases;
- runtime sessions and short-lived connection grants;
- artifact and recording catalogs; and
- Agent runs.

Mutations either return an asynchronous Product operation or perform one
bounded Product-database authority change such as control-lease acquisition.
No Product mutation returns a Provider operation as its public result.

### Stable protocol rules

- All input objects are closed and reject unknown fields.
- Request bodies, headers, identifiers, list sizes, and pages have explicit
  bounds.
- Every mutation requires `Idempotency-Key`; versioned aggregate mutations
  also require an expected Product version in the closed body.
- Authentication selects tenant and actor identity. Request bodies cannot
  assert a different tenant or actor.
- Product errors use one closed envelope and stable `PRODUCT_*` codes.
- Product operations and Workspace events are retained separately. An
  accepted operation is not proof that Provider work succeeded.
- Workspace event sequence is monotonic and contiguous per Workspace. Clients
  resume after an acknowledged sequence and must tolerate reconnects, but not
  silent gaps.
- Connection grants contain a public Product Gateway URI and an opaque,
  short-lived, one-use ticket. They never contain a Provider or backend
  endpoint.
- Artifact and recording catalog resources contain metadata and Product-owned
  access state, not storage credentials or raw content.
- Capability and protocol identifiers describe Product support only when the
  complete Product, Gateway, Provider, Guest Agent, persistence, and policy
  dependency graph is ready.

### Capability honesty

The Product capability document is derived from composed readiness. A schema
enum or route does not make a session kind available. Unimplemented terminal
close/resize, Browser data plane, Desktop, Files/watch, editor, notebook,
preview, MCP, recording, or Agent-run dependencies must be omitted from
advertisement or cause explicitly enabled startup to fail.

Product capability advertisement never substitutes for Provider capability
discovery. The Product reconciler still selects and pins an exact Provider
revision and capability profile for each slot.

### Authentication and authorization boundary

The OpenAPI defines bearer authentication as a transport requirement but does
not standardize an external identity provider. Product authentication maps the
credential to one tenant-scoped actor before decoding business authority. The
identity and threat-model ADR defines delegation and control fencing.

### Data-plane boundary

The Product Contract creates sessions and connection grants; it does not carry
terminal bytes, Browser messages, display frames, file contents, forwarded
HTTP bodies, or MCP messages. Those protocols terminate at the Runtime Gateway
and are governed by ADR 0046.

Closing or resizing a Product session is a durable Product intent. A session
is not reported closed or resized until the required Gateway, Guest Agent, and
Provider authorities are reconciled. When a Provider capability is missing,
the Product operation fails with a stable unsupported-capability result rather
than using a private adapter.

## Consequences

- Product transport implementation has one independent, content-addressed
  authority and cannot reuse Provider wire objects as Product resources.
- The initial API is larger than the first executable vertical. Honest
  capability advertisement and per-feature release gates prevent schemas from
  becoming false implementation claims.
- Async operations and durable events are required even for a single-user
  first version because Provider work is not transactionally coupled to the
  Product database.
- Data-plane protocol evolution can be gated independently from Product
  control-plane compatibility.

## Rejected alternatives

### Reuse the Provider OpenAPI

Rejected because Provider resources are execution-local and omit Product
identity, aggregate operations, control ownership, catalogs, and user-facing
policy.

### Add Product fields to Provider DTOs

Rejected because consumer business truth must not change the generic Provider
wire contract.

### Return direct Provider or backend connection details

Rejected because public clients must connect through Product authorization,
revocation, capacity, control fencing, and recording policy.

### Use synchronous create and terminate responses

Rejected because external runtime work has accepted, running, unknown, retry,
and reconciliation states that cannot be represented honestly by a single
request transaction.

## Non-goals

This ADR does not implement the Product API, select a web framework, define
database migrations, claim any capability is ready, or alter the Provider
Contract.
