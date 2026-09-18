# Product v1 Architecture Phase 1

- Status: Complete as design and Contract-definition evidence
- Date: 2026-09-18
- Scope: Product architecture before implementation; this is separate from the
  historical Provider P1.x delivery labels

## Outcome

Phase 1 defines how this repository may grow from a Provider foundation into a
Product without weakening the locked Provider boundary. All eight steps are
complete. No Product service, database migration, public Gateway, Guest Agent,
or new Provider behavior is implemented or advertised by this phase.

The resulting authority order is:

1. the locked Provider Contract under `contract/` for Product-to-Provider wire
   behavior;
2. the independently versioned and content-locked Product Contract under
   `product-contract/` for client-to-Product control behavior;
3. accepted ADRs for repository, state, identity, data-plane, recording, and
   deployment decisions; and
4. this plan and the status/context documents for delivery order and evidence
   boundaries.

## Completed steps

| Step | Result | Authority |
| --- | --- | --- |
| 1. Baseline and contradiction audit | Separated facts, inferences, target design, evidence tiers, and ten concrete conflicts/gaps | [Current baseline and contradictions](../audits/phase-1-step-1-current-baseline-and-contradictions.md) |
| 2. Repository governance | Product may live in this repository only as a caller of the locked Provider Contract; package roots and dependency direction are fixed | [ADR 0042](../adr/0042-product-provider-repository-governance.md) |
| 3. Product Contract | Defined independent `v1alpha1` OpenAPI, closed JSON Schema, semantic rules, specification, manifest, and content lock | [ADR 0043](../adr/0043-product-contract-v1alpha1.md), [`product-contract/`](../../product-contract/) |
| 4. Workspace and storage | Defined composite Workspace, first-class slots, PostgreSQL authority, operations/attempts, outbox, reconciliation, revisions, artifacts, and recordings | [ADR 0044](../adr/0044-workspace-slot-and-product-storage-model.md) |
| 5. Identity and Agent authority | Defined principals, first-version roles, bounded Agent delegation, Product control leases, secret boundaries, and threat model | [ADR 0045](../adr/0045-product-identity-agent-delegation-and-threat-model.md) |
| 6. Gateway and recording | Separated Product control/data planes; defined target session protocols, one-use connection admission, Guest Agent boundary, and distinct audit/recording ports | [ADR 0046](../adr/0046-runtime-gateway-session-and-recording-architecture.md) |
| 7. Deployment and operations | Defined development, standalone, production, and future hostile-multitenant levels, production SLO targets, and release gates | [ADR 0047](../adr/0047-deployment-levels-slos-and-release-gates.md) |
| 8. Documentation consolidation | Made Product target and current Provider evidence adjacent, corrected stale status/future text, and retained historical evidence identities | This plan plus `README`, `STATUS`, `PROJECT_CONTEXT`, architecture, and development guidance |

## Locked decisions

### Repository and contracts

- Product modules remain separate from Provider, Gateway reference components,
  drivers, and the local `/instances` API.
- Every Product-to-Provider runtime call crosses the protected locked Provider
  Contract. Co-deployment does not create an in-process fast path.
- Product wire resources never reuse Provider, `instance`, repository, or
  backend-driver structures.
- Product and Provider have distinct namespaces, compatibility locks,
  authentication audiences, capability graphs, and release evidence.

### Product authority and persistence

- Product PostgreSQL owns tenant/actor authorization, Workspace aggregates,
  slots, desired state, Product operations, attempts, events, idempotency,
  control leases, sessions, Agent runs, catalogs, outbox, and reconciliation
  checkpoints.
- A Workspace contains one required `primary-code` slot and independently
  reconciled optional slots. Provider sandbox IDs and endpoints remain private
  adapter state.
- PostgreSQL commits intent before external work. Provider and Gateway changes
  are idempotent, level-triggered sagas; there is no distributed transaction.
- Durable Workspace content uses immutable content-addressed revisions and CAS
  heads in Product storage. A live Provider `/workspace` filesystem is not
  durable Product state.

### Identity and live control

- Product authenticates humans, delegated Agents, and services. Provider
  authenticates the Product calling service, never the Product end user.
- The first version has one human owner plus bounded Agents; collaboration
  vocabulary is reserved but invitations, shared control, chat, and rooms are
  not authorized.
- Product control lease, reconciler lease, Provider fencing, Gateway capacity,
  Browser action fencing, and connection grants are separate authorities.
- Public clients receive only Product Gateway coordinates and one-use tickets.
  Provider handoffs and private endpoints never leave Product adapters.

### Data plane, recording, and deployment

- Product API commits control intent; Runtime Gateway carries terminal,
  Browser, Desktop, HTTP-proxy, file, and MCP data under explicit profiles.
- Metadata audit, terminal content, media, Agent trace, and recording catalog
  are separate data classes and ports. Required recording fails closed.
- Current Docker, Apple Container, and Kubernetes smoke paths are development
  application-packaging evidence only.
- No standalone, production, hostile-multitenant, Product capability, or SLO
  attainment claim exists yet.

## Contradiction resolution

| Audit item | Phase 1 resolution |
| --- | --- |
| C-01 current verification drift | Current 53-case clean VCS-built core CI is recorded as passed; no fresh current remote or historical E2E bundle is inferred |
| C-02 terminal-connect status | ADR 0041 records that the candidate was selected by Provider Contract revision `22ba6987...`; later evidence remains bounded |
| C-03 Browser restore ledger drift | Newer successful main run `34069851741` at `838d3bb` is the canonical latest run; the inspected older artifact remains the detailed artifact authority until a newer artifact is independently inspected |
| C-04 completed work listed as future | P2.7 publication and qualification text is historical; the next gate is new Product/Provider scope, not repetition |
| C-05 baseline traceability | Current code snapshot and this uncommitted Phase 1 design set are identified separately; historical evidence baselines are preserved |
| C-06 target/effective API ambiguity | Architecture now places locked effective Provider surface next to the target lifecycle inventory |
| C-07 deployment claim hazard | ADR 0047 defines levels and keeps packaging, Provider deployment, Product deployment, and production qualification distinct |
| C-08 authority-name collision | ADRs 0044-0046 name and separate every lease/fence/grant authority |
| C-09 recording-name collision | ADR 0046 separates metadata audit from terminal, media, Agent trace, and catalog authority |
| C-10 persistence claim hazard | ADR 0044 assigns Product truth to new PostgreSQL relations and object storage; existing Browser/Gateway stores are not reused |

For C-03, successful run status and exact head were verified independently.
The older run's downloaded artifact identity and digest remain valid historical
evidence and are not silently attributed to the newer run.

## Next overall phase

Phase 2 is now fixed in the
[Provider lifecycle closure plan](product-v1-phase-2-provider-lifecycle.md).
It begins with Provider lifecycle Contract expansion, not Product UI or
database implementation. It must project, lock, implement, and test the
minimum Provider operations needed by a reconciled Product:

1. irreversible sandbox termination and its observation/cleanup evidence;
2. desired-state mutation and lease renewal or equivalent lifecycle authority;
3. resumable event/observation semantics for reconciliation;
4. terminal-session close where the runtime supports it.

ADR 0048 includes terminal close, excludes resize because no runtime port
exists, and excludes snapshot/restore from the minimum closure phase.

Only locked operations may be consumed by the Product adapter. Reserved Go
DTOs, semantic names, private driver methods, qualification cleanup, and
Browser-specific reference controls are not Contract authority.

After that Contract slice, implementation should proceed vertically: import
boundary guard, Product persistence and command transaction, outbox/reconciler,
one minimal Workspace/primary-code flow, then public Gateway/Guest Agent slices.
Each slice must declare its deployment level and capability/evidence gate.

## Phase 1 validation gate

Phase 1 is complete when:

- Product JSON parses, Product OpenAPI YAML parses, operation IDs are unique,
  and every external schema definition reference resolves;
- Product manifest/resource/tree digests match the compatibility lock;
- the unchanged Provider Contract lock verifier passes;
- modified documentation links resolve and whitespace/diff checks pass; and
- the final handoff records that the worktree changes are uncommitted and make
  no implementation or production-readiness claim.
