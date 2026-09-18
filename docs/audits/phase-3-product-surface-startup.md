# Product Phase 3 Startup Audit

Date: 2026-09-18

Baseline: `477db77380708443917f6e6dea3555378fb3e39a`

Scope: Product Terminal, Files, Browser/Web, public Gateway, recording,
authentication, authorization, events, and frontend readiness

## Result

Phase 3 did not start from an existing Product service. The repository had a
content-locked Product Contract and extensive Provider/reference components,
but no Product API process, Product database, public Product Gateway, Guest
Agent, or frontend. Reusing the existing Provider/Gateway packages as if they
were Product implementations would cross the authority boundary defined by
ADRs 0042-0047.

The first implementation slice therefore establishes the trusted Product
kernel entry point: enforced Go import boundaries, executable Product Contract
content verification, and a real PostgreSQL transaction that accepts one
primary-code Workspace command and atomically records the Workspace, slot,
Product operation, first Product event, outbox intent, and scoped idempotency
result. It dispatches no Provider work and exposes no Product route.

## Evidence vocabulary

| Tier | Meaning in this audit |
| --- | --- |
| Contract-declared | A route, schema, profile, or semantic rule exists in a locked Contract. It proves design authority only. |
| Component | Code and focused tests demonstrate one in-process behavior. It does not prove a deployed surface or interoperability. |
| Independent-process | Separate processes exercised a fixed black-box topology with retained evidence. It remains bounded to that topology and authority. |
| Product-ready | An authenticated Product API, Product authority, Provider adapter, public data plane, recovery, client surface, and named integrated gate work together. This tier is absent at Phase 3 startup. |

## Inventory

| Area | Contract-declared | Existing component or prior evidence | Missing Product authority | Startup classification |
| --- | --- | --- | --- | --- |
| Product control plane | `product-contract/` declares 24 `/api/v1` paths and 27 operations, closed Product resources, errors, idempotency, events, sessions, artifacts, recordings, and Agent runs. | Before this slice there was no `product`, `productapi`, or Product database package. | Authenticated listener, DTO projection, authorization, persistence, reconciliation, and executable Product conformance. | Design only before Slice 1; Product-kernel component after Slice 1. |
| Terminal | Product Contract declares terminal session creation, read, close, resize, and connection grants. Provider packages implement terminal/session ports, durable Provider session and reference state, close/revocation, protected connect, and bounded byte proxy components. The Phase 2 repository-owned independent-process run covered its fixed Provider lifecycle topology. | `provider/terminal`, `provider/session`, `gateway`, and `gateway/adapter` have component evidence; the previous black-box run is Provider/reference evidence, not Product evidence. | Product session authority, control-lease/fence checks, Product-to-Provider adapter, one-use Product grant, public Product Gateway identity, resize support, Product audit/catalog integration, and Product E2E. | Reusable lower-level components; not a Product Terminal. |
| Files | Product Contract represents artifact metadata but does not yet define the full Guest Agent Files protocol. Provider runtime profiles provide stable guest mounts and Provider artifact staging components. | Stable `/inputs`, `/workspace`, `/outputs`, `/tmp` and Provider artifact staging have bounded Provider evidence. | Guest Agent, confined path model, list/stat/watch, digest transfer, resume/backpressure, revision staging, compare-and-swap commit, Product metadata, authorization, retention, and recovery. | No Product Files implementation. |
| Browser/Web | Product sessions can name browser/desktop profiles. Provider Browser packages, restricted egress, reference generation, Gateway composition, and several specialized reference E2E tracks exist. | Extensive Browser component and fixed-topology reference evidence exists, with explicit non-production limits. | Product capability resolver, Product browser session authority, Product public Gateway, Web application/control plane, deployment configuration, and Product-integrated evidence. | Provider/reference building blocks only. |
| Public Gateway | ADR 0046 defines the target Product Gateway. Existing `gateway` code has authorization/revocation/capacity/audit ports and Terminal/Browser reference composition. | Component tests and separately bounded caller/reference runs exercise those packages. | Product-owned grant issuance and validation, tenant/actor/session/fence binding, public listener identity and policy, Product revocation authority, deployable topology, and Product gate. | Not a public Product service. |
| Recording | Product Contract declares recording catalog resources. Existing Gateway `Recorder` records bounded metadata events and deliberately excludes frame payloads. | Metadata-only audit component evidence. | Content capture policy, consent, encryption, redaction, storage, retention/deletion, catalog publication, replay authorization, and integrity evidence. | Audit metadata only; no content recording. |
| Authentication and authorization | Product semantic rules require bearer authentication before authority and derive tenant/actor from authentication. | Provider mTLS/JWS admission is a separate Provider trust boundary. Existing Gateway authorizer interfaces are caller-owned component seams. | Product issuer/audience/key policy, tenant/actor principal, RBAC/ABAC, resource filters, cross-tenant nondisclosure, control leases, quotas, and audit ownership. | No Product authn/authz implementation. |
| Operations and events | Product Contract defines Product operations, contiguous Workspace events, polling and SSE. Provider lifecycle has Provider-local operations and finite event polling. | Provider lifecycle components and Phase 2 gates pass for their locked surface. Slice 1 now writes the first Product operation/event/outbox atomically. | Product reads, retention/cursor policy, SSE, outbox delivery, Provider evidence mapping, restart reconciliation, and terminal Product decisions. | Initial persistence component only after Slice 1. |
| Frontend | Product architecture calls for a Web client/control plane. | No frontend or UI root was present. | Authenticated application shell, API client, Workspace/Terminal/Files views, accessibility, CSP/CSRF/session policy, error/recovery UX, and deployable assets. | Absent. |

## First-slice authority and invariants

Slice 1 owns only Product command acceptance. `product` contains domain values,
application policy, and ports. `product/adapter/postgres` is the sole SQL
adapter. A production import-boundary test prevents Product domain/application
code from importing Provider, local management, Gateway implementation, Gin,
or PostgreSQL packages; it also prevents Provider/local/Gateway production
code from importing Product packages.

For one `CreateWorkspace` command, capability policy is checked before ID
allocation or persistence. PostgreSQL database time and one transaction commit:

1. the scoped idempotency reservation and semantic request digest;
2. one Workspace with exactly one `primary-code` slot;
3. one accepted Product operation;
4. sequence-one `workspace.create_accepted` evidence; and
5. one pending `workspace.reconcile` outbox message.

A same-scope/same-digest replay returns the retained operation. A different
digest conflicts. A failed insert rolls back all six authority records. An
ambiguous commit returns `ErrStoreOutcomeUnknown`; it is not reported as a
known failure. No external work occurs inside or before this transaction.

## Risks and non-claims

- PostgreSQL is currently component infrastructure, not a deployment or HA
  result. Migration ownership, runtime least privilege, backup/restore,
  failover, retention jobs, and multi-controller behavior remain open.
- The Product Contract remains Phase 1 design authority. Its new verifier
  proves locked bytes and document structure, not server compatibility.
- Capability policy is an injected port in Slice 1; Provider discovery and
  exact-revision admission do not exist yet.
- The outbox is retained but not dispatched. No Workspace reaches `active`, no
  runtime is allocated, and no Product operation reaches a terminal state.
- There is no Product HTTP listener, bearer authentication, authorization,
  public Gateway, Guest Agent, Files path, Browser Product path, recording
  content pipeline, frontend, deployment, SLO, or production-readiness claim.

The fixed remaining order and gates are in
[`product-v1-phase-3-product-kernel-terminal-files-web.md`](../plan/product-v1-phase-3-product-kernel-terminal-files-web.md).
