# ADR 0042: Product and Provider Repository Governance

- Status: Accepted and effective for repository governance; Phase 1 design
  sequencing is complete, while implementation remains separately gated
- Date: 2026-09-18

## Context

ADR 0037 defines `sandbox-runtime` as an independently consumable Provider and
assigns tenant, user, desired-state, aggregate-operation, public Gateway,
Artifact, and billing truth to a generic caller. The repository now needs a
first-party product control plane for Agent workspaces without weakening that
boundary.

The current repository does not contain a Product API, product aggregate,
product business database, public Gateway service, Guest Agent protocol,
recording catalog, or Web Console. The local `/instances` API is an
unauthenticated development and management surface with its own models and
state machine. Provider packages own provider-local execution and evidence,
not product truth.

The Phase 1 step 1
[baseline audit](../audits/phase-1-step-1-current-baseline-and-contradictions.md)
also records three important collision risks:

- Provider fencing, Gateway capacity, Browser action fencing, and the future
  product control lease are different authorities;
- the existing Gateway `Recorder` is metadata-only audit, not terminal, media,
  or Agent-trace recording; and
- the existing PostgreSQL and Redis-compatible adapters serve specialized
  Browser/Gateway authority, not product business state.

Without an explicit governance decision, adding product code would invite one
of two invalid shortcuts: turning `/instances` into the Product API, or calling
Provider applications and repositories directly because they share a source
tree.

## Decision

### One repository, separate authorities

This repository may contain the first-party product control plane. The product
is a caller of the Provider Calling Standard even when both are built from this
repository, released together, or deployed on one host.

Co-location changes neither ownership nor protocol authority:

- Product owns end-user and Agent identity, tenant and Workspace truth,
  desired state, aggregate operations, control leases, public session grants,
  artifacts, recordings, and final product decisions.
- Provider owns provider-local sandboxes, attempts, leases, runtime sessions,
  backend work, retained results, and execution evidence.
- Runtime Gateway owns only the bounded data-plane authority explicitly
  delegated by Product and Provider handoffs. It does not become a source of
  Workspace or operation truth.
- Guest Agent owns only guest-local execution and observation allowed by its
  short-lived assignment. It is not a control-plane authority.

ADR 0037 remains authoritative for the generic caller boundary. This ADR
specializes it for a first-party caller in the same repository; it does not
supersede the Provider Calling Standard or move caller policy into Provider
packages.

### Required source boundaries

New product work will use the following logical roots. Later approved steps may
refine names below these roots, but changing their authority or dependency
direction requires another ADR.

| Root | Authority |
| --- | --- |
| `product/` | Product domain, application services, inward-facing ports, and product policy |
| `productapi/` | Product HTTP and streaming transport plus projection between Product Contract DTOs and product application inputs/outputs |
| `product/adapter/provider/` | Caller-side Provider client and translation from product intent to the locked Provider Contract |
| `product/adapter/postgres/` | Product business repositories, operation ledger, transactional outbox, and reconciliation checkpoints |
| `product/adapter/gateway/` | Product authorization and grant adapters for the Runtime Gateway; no Provider implementation imports |
| `guestagent/` | Future guest protocol and guest-local service, kept separate from Product and Provider transports |
| `gateway/` | Reusable caller-owned data-plane primitives and narrowly scoped adapters; no product business truth |
| `provider/`, `providerapi/`, `driver/` | Existing Provider domain, transport, repositories, runtime adapters, and backend actions |
| `instance/`, `server/api/` | Existing local development/management surface; never a Product or Provider wire model |
| `cmd/` | Composition roots only; allowed to depend on concrete implementations without transferring their authority |

The first product implementation remains in the root Go module so one toolchain
and repository-wide gate can enforce the dependency graph. A new Go module or
repository split requires a later ADR with migration, versioning, and release
evidence. The separate E2E module remains an evidence boundary, not a product
package.

No directory is created by this ADR other than this decision record. The
Product Contract step decides its own normative resource location before any
Product API transport is added.

### Dependency direction

Dependencies point inward within each authority and cross an authority only at
an explicit port or wire contract.

```text
productapi  -> product application -> product domain and ports
                                      ^
product adapters ---------------------+

product Provider adapter -> locked Provider Contract over network transport
providerapi -> Provider application -> Provider repository/runtime ports
Provider adapters --------------------+

Product Gateway adapter -> gateway core ports -> transport adapters
cmd composition roots -> all selected concrete implementations
```

The following rules are mandatory:

1. Product domain and application packages must not import `provider/`,
   `providerapi/`, `driver/`, `instance/`, concrete Gateway storage adapters,
   or transport frameworks.
2. Provider and Provider API packages must not import `product/`, `productapi/`,
   Product Contract packages, Product repositories, or Product Gateway policy.
3. `productapi/` projects Product Contract DTOs and calls product application
   ports. It must not proxy Provider DTOs or expose Provider routes as Product
   routes.
4. Only `product/adapter/provider/` may translate Product intent to Provider
   wire documents. It may depend on the stable Provider wire projection and
   generic transport/security libraries, but not Provider applications,
   repositories, runtime drivers, private references, or composition helpers.
5. Concrete Product repositories and infrastructure adapters implement ports
   owned by the product application boundary; the ports do not import their
   adapters.
6. `cmd/` may construct both sides, but it must not pass a Provider application,
   repository, driver, or private resolver into Product. Product-to-Provider
   execution still crosses the protected Provider listener and locked wire
   contract. There is no in-process fast path.
7. Web Console and MCP-facing integrations consume Product APIs only. They do
   not call Provider, backend engines, databases, or private Gateway endpoints
   directly.
8. Guest Agent does not import Product repositories or Provider runtime
   drivers and receives no long-lived user, database, Provider-controller, or
   infrastructure credentials.

The dependency policy will be enforced before the first product implementation
is merged by a repository test that evaluates non-test Go imports. Test and E2E
packages may cross boundaries only to construct black-box evidence; their
imports do not authorize production code to do so.

### Existing Gateway reference composition

The current `gateway` core expresses caller-owned authorization, capacity,
revocation, fencing, audit, and proxy ports. Some existing packages under
`gateway/adapter` and `gateway/composition` import Provider terminal, session,
Browser, or reference types for same-repository reference composition.

Those imports are a quarantined historical/reference exception. They may
continue to support their exact existing tests and evidence, but:

- Product composition must not import or instantiate them as its Provider
  boundary;
- new Product features must not extend the exception;
- production Product Gateway work requires a public, Contract-governed
  Provider data-plane adapter for each capability; and
- a capability with no sufficient public Provider data-plane contract remains
  blocked rather than falling back to an in-process resolver.

The Gateway/control/recording architecture step will decide whether neutral
Gateway primitives remain in `gateway/` or move behind a more explicit shared
boundary. This ADR does not reclassify existing reference evidence as product
evidence.

### API and contract separation

The Product API will have its own versioned Contract, namespaces, DTOs, errors,
idempotency rules, event model, compatibility policy, and conformance evidence.
It must be served on a separately configured transport boundary from both the
Provider listener and the local management API.

The following are prohibited:

- mounting `/instances` below a Product prefix or translating Product requests
  directly into `instance` service calls;
- exposing Provider OpenAPI objects as Product response models;
- adding Product-specific fields, error behavior, routes, or authorization to
  the Provider Contract;
- treating internal Provider DTOs, reserved operation names, or private driver
  methods as effective Provider capabilities; and
- allowing route presence to bypass capability discovery and exact profile
  selection.

The Product Contract step will choose exact paths and protocol versions. Until
then, no Product route name is authorized by this ADR.

### Persistence and transaction ownership

PostgreSQL is the authoritative store for Product business state. Its future
schema owns Workspace aggregates, named sandbox slots, Product operations,
idempotency records, control leases, event metadata, artifact and recording
catalogs, transactional outbox records, and reconciliation checkpoints as
defined by later architecture steps.

Provider file or memory repositories, local `/instances` repositories,
Gateway capacity/revocation state, and the Browser action-history witness must
never be queried as Product business truth. Product must not share their tables
or mutate their files.

There is no distributed transaction between Product PostgreSQL and a Provider.
Product persists intent and an outbox record atomically, calls Provider through
an idempotent adapter, and reconciles the retained Provider operation and
evidence into a new Product transaction. Exact schemas, isolation levels,
fencing columns, retry schedules, and recovery rules belong to the later
Workspace/storage and Product Contract decisions.

Redis-compatible storage may support bounded ephemeral coordination only. It
does not become the source of truth for Workspace desired state, Product
operations, control ownership, artifacts, recordings, or billing.

### Identity and control separation

Product end-user or Agent authorization terminates at Product API and public
Gateway boundaries. Provider mTLS/JWS admission authenticates an admitted
controller trust domain, not an end user.

The future Product control lease is a Product aggregate authority. It is not:

- a Provider sandbox lease;
- a Provider mutation fencing token;
- a Gateway connection-capacity lease;
- a Browser downstream action fence; or
- a Gateway revocation tombstone.

Later identity and Gateway steps must define explicit translations and fencing
checks without reusing one authority's token as another authority's proof.

### Recording and artifact separation

Metadata audit, terminal recording, media recording, Agent trace recording,
artifact staging evidence, artifact publication, and their catalogs are
separate data classes.

The existing Gateway `Recorder` remains a metadata-only audit port. It must not
be expanded to accept terminal bytes, Browser messages, display frames, Agent
reasoning, secrets, or artifact content. Later recording ports must define
their own retention, encryption, access-control, redaction, integrity, and
replay contracts.

Provider artifact staging and usage evidence remain provider-local evidence.
Product owns publication, user-visible metadata, retention, and aggregate
accounting after independently validating that evidence.

### External caller and evidence governance

The independently implemented `sandbox-runtime-external-caller` remains outside
this repository. Its source must not be copied, vendored, embedded, converted
into a Product adapter, or added as a workspace module.

Repository-local Product tests may prove that the Product adapter consumes the
locked Provider Contract, but they do not replace independent caller
qualification. Provider Contract, Product Contract, Product component, Gateway,
Guest Agent, deployment, and external-caller evidence remain separately named
and separately gated. Evidence from one track must not be aggregated into a
broader claim without a gate that actually composes the claimed topology.

### Change control

Changes are governed as follows:

- Provider Contract changes continue to update all locked normative resources
  together and run the Provider lock verifier and complete applicable Suite.
- Product Contract changes use their own future lock, schemas, semantic rules,
  fixtures, conformance cases, and compatibility policy.
- A Product feature that exposes a missing Provider capability must stop and
  request a separate Provider Contract slice; it cannot add consumer-specific
  behavior to Provider code in the same change.
- Cross-boundary imports, shared persistence, direct application calls, and
  public-route co-mingling require an ADR and cannot be introduced as local
  refactors.
- Production, HA, multi-controller, or hostile multi-tenant claims require
  their named deployment and evidence gates regardless of component test
  results.

## Sequencing gate

This ADR originally closed only the repository-governance decision and set the
following authorized order:

1. define and lock the Product Contract;
2. decide Workspace, slot, operation, and PostgreSQL ownership in detail;
3. decide identity, Agent delegation, control lease, and threat boundaries;
4. decide Runtime Gateway, session control, and recording protocols;
5. define deployment levels and operational gates; and
6. consolidate current-state and evidence documentation.

No Product API handler, Product database migration, Product Provider client,
public Gateway service, Guest Agent, or Web Console implementation is
authorized before its preceding decisions are accepted. ADRs 0043-0047 and the
Product v1 Phase 1 plan now record completion of those design decisions; they
do not themselves implement or qualify any of those services.

The separate overall Provider lifecycle Contract expansion remains a hard
dependency for a reconciled Product lifecycle. Reserved DTOs, protected route
matching, private driver cleanup, and qualification teardown do not satisfy
that dependency.

## Consequences

- Product implementation may live in this repository without making Product
  policy part of the Provider.
- Co-deployment is possible later, but it does not permit an in-process
  Product-to-Provider shortcut.
- Product gains an authoritative PostgreSQL boundary and asynchronous
  outbox/reconciliation model without making Provider storage globally
  authoritative.
- Existing Provider, local management, Gateway reference, and independent
  external-caller evidence retain their exact historical meaning.
- Initial implementation carries extra transport and operational cost because
  even co-located Product and Provider communicate through the protected wire
  boundary. That cost is accepted to preserve replaceability, black-box
  conformance, and honest failure semantics.
- A capability whose public Provider boundary is incomplete stays unavailable
  to Product until a Contract-first slice closes the gap.

## Rejected alternatives

### Convert `/instances` into the Product API

Rejected because its models, authentication, persistence, lifecycle, and error
semantics are development-oriented and are explicitly separate from both
Product and Provider contracts.

### Let Product call Provider applications or repositories directly

Rejected because it bypasses mTLS/JWS admission, capability negotiation,
idempotency, fencing, compatibility locks, and black-box reconciliation. It
would also make co-location a hidden correctness requirement.

### Add Product-specific behavior to the Provider surface

Rejected because Provider compatibility is repository-owned and generic.
Consumer fields and policy would make other callers depend on Product business
models.

### Use existing Gateway PostgreSQL or Redis-compatible state as Product truth

Rejected because those adapters protect specialized capacity, revocation, and
action-history authorities. Their schemas and failure semantics do not form a
Workspace or Product-operation aggregate.

### Move Product to a separate repository before defining its Contract

Rejected for the first delivery because it would add versioning and release
coordination before the boundaries are fully specified. The source boundary
can be split later without changing authority because Product-to-Provider calls
already use the public Contract.

### Treat same-repository Product tests as independent caller qualification

Rejected because source, build, deployment, and evidence independence are part
of the existing qualification claim.

## Non-goals

This ADR does not define Product API routes or DTOs, implement Product modules,
create database schemas, add Provider lifecycle methods, compose a public
Gateway, define a Guest Agent protocol, add recording, or establish deployment
or production readiness.
