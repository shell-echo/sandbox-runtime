# Phase 1 Step 1: Current Baseline and Contradiction Audit

Status: completed audit input; non-normative

Audit date: 2026-09-18

Repository snapshot: `e5bc9bd7039e01a1898f90fbd77684a1cb6699ad`

## Purpose and limits

This document records the current repository baseline before any product-plane
architecture is authorized. It separates implemented and verified behavior
from reserved vocabulary, target architecture, historical evidence, and future
decisions.

This audit does not:

- change the Provider Contract, Provider behavior, or compatibility lock;
- authorize product modules inside this repository;
- turn the local `/instances` API into a Product API;
- treat a reference caller, test Gateway, or qualification harness as product
  implementation;
- import or copy the separately owned
  `sandbox-runtime-external-caller` implementation;
- establish production, deployment, high-availability, multi-controller, or
  hostile multi-tenant readiness; or
- settle the governance and architecture decisions assigned to later Phase 1
  steps.

The words **fact**, **inference**, and **decision required** have distinct
meanings below:

- **Fact** is directly supported by repository content or a reproduced local
  command result.
- **Inference** is a conclusion drawn from multiple facts and is not itself a
  normative decision.
- **Decision required** identifies work that must be made normative by a later
  approved step.

## Sources and authority order

The audit read the repository guidance and current planning baseline in full:

- [`AGENTS.md`](../../AGENTS.md)
- [`docs/PROJECT_CONTEXT.md`](../PROJECT_CONTEXT.md)
- [`README.md`](../../README.md) and
  [`README.zh-CN.md`](../../README.zh-CN.md)
- [`docs/architecture.md`](../architecture.md)
- [`docs/development.md`](../development.md)
- [`docs/STATUS.md`](../STATUS.md)
- [`docs/plan/README.md`](../plan/README.md)

It also inspected the applicable lifecycle, terminal, artifact, Browser,
calling-standard, issuer-trust, conformance, qualification, and optional-profile
ADRs and plans, the locked Contract resources, the application deployment
guides, the composition root, route dispatch, configuration, repositories, and
Gateway ports.

Primary evidence map:

| Boundary | Primary repository sources |
| --- | --- |
| Provider ownership | [ADR 0001](../adr/0001-agent-platform-provider-boundary.md), [ADR 0037](../adr/0037-sandbox-provider-calling-standard.md), and the [Provider Calling Standard](../../contract/specification/provider-calling-standard-v1.md) |
| Effective Provider wire surface | [OpenAPI](../../contract/openapi/sandbox-runtime-provider-v1.yaml), [Contract manifest](../../contract/compatibility/contract-manifest.json), [semantic rules](../../contract/semantic-rules/provider-v1.json), [local Suite](../../contract/conformance/provider-v1/suite.json), and [consumer lock](../../compatibility/sandbox-runtime/contract.lock.json) |
| Lifecycle and session bounds | [ADR 0004](../adr/0004-provider-lifecycle-contract.md), [P1.2 plan](../plan/p1.2-async-lifecycle.md), [ADR 0011](../adr/0011-terminal-session-contract-and-gateway-handoff.md), [ADR 0041](../adr/0041-provider-terminal-connect-contract.md), and [terminal/Gateway plan](../plan/p2.5f-terminal-gateway-vertical.md) |
| Artifact and usage boundary | [ADR 0012](../adr/0012-artifact-staging-and-usage-evidence.md) |
| Browser and Gateway boundary | [ADR 0017](../adr/0017-optional-profile-readiness.md), [ADR 0024](../adr/0024-browser-caller-gateway.md), [ADR 0030](../adr/0030-browser-authenticated-shared-capacity.md), [ADR 0032](../adr/0032-browser-durable-distributed-revocation.md), [ADR 0033](../adr/0033-browser-downstream-cdp-fencing.md), [ADR 0035](../adr/0035-browser-postgresql-action-history-witness.md), [ADR 0036](../adr/0036-browser-postgresql-controlled-restore-reference.md), and the [P4 plan](../plan/p4-optional-profiles.md) |
| Conformance and independent caller evidence | [ADR 0039](../adr/0039-content-addressed-and-portable-conformance.md), [ADR 0040](../adr/0040-independent-external-caller-qualification.md), and the [P2.7 plan](../plan/p2.7-independent-external-caller-qualification.md) |
| Current composition | [`cmd/serve.go`](../../cmd/serve.go), [`config/server.go`](../../config/server.go), [`providerapi/protected_handler.go`](../../providerapi/protected_handler.go), and [`gateway/port.go`](../../gateway/port.go) |
| Application packaging | [deployment overview](../deployment.md), [Docker guide](../docker.md), [Apple Container guide](../apple-container.md), and [Kubernetes guide](../kubernetes.md) |

For Provider compatibility claims, the repository-owned calling standard,
OpenAPI, JSON Schemas, semantic rules, fixtures, Conformance Suites, manifest,
and consumer lock outrank narrative documentation. Internal DTO vocabulary or
route matching does not authorize a public Provider operation absent from the
locked OpenAPI and semantic Contract.

## Reproduced baseline

The following checks passed from the clean audited snapshot before this file
was added:

| Check | Result |
| --- | --- |
| Toolchain | `go version go1.26.5 darwin/arm64` through `mise exec -- go` |
| Contract verifier | Passed for namespace `urn:shell-echo:sandbox-runtime:provider-v1`, version `1.0.0` |
| Contract revision/tree | `22ba6987ea5fbc37d53942720133c0acad199edd` / `c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38` |
| Local/remote Suite digests | `sha256:b40c932643f4a1e5fd6681e3abf9b64a607609866a6254456970f8b8034cf2a8` / `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0` |
| Root test gate | `go test -race -shuffle=on -count=1 ./...` passed |
| Static analysis | `go vet ./...` passed |

These are current component and Contract-integrity results. They do not replay
the separately recorded hosted qualification, remote discovery, real-backend
integration, Browser publication, specialized E2E, or deployment smoke gates.

## Current system baseline

### Process and API topology

**Fact.** The `serve` command composes two independent sibling listeners:

1. the local management API, including the unauthenticated `/instances`
   routes; and
2. the separately configured Provider HTTPS listener with frozen mTLS identity
   admission and optional protected-operation admission.

The local API uses the `instance` model and memory/file repositories. The
Provider listener uses Provider-specific DTOs, applications, repositories, and
runtime drivers. The two surfaces are not interchangeable.

**Fact.** Application mode currently has only `development` and `production`.
Production mode rejects every current Provider lifecycle, exec, terminal,
artifact, usage, and Browser driver because none has passed its production
adapter gate. Production mode also keeps the unauthenticated local API on a
loopback address.

**Inference.** The repository contains a strong Provider implementation and
development management shell, but not a deployable product control plane. A
new Product API cannot be obtained by renaming or exposing `/instances`.

### Effective Provider surface

The locked OpenAPI currently authorizes these paths:

| Family | Effective paths |
| --- | --- |
| Discovery | `GET /v1/capabilities` |
| Lifecycle subset | `POST /v1/sandboxes`; `GET /v1/sandboxes/{sandbox_id}`; `GET /v1/operations/{operation_id}` |
| Exec | `POST /v1/sandboxes/{sandbox_id}/exec`; `POST /v1/sandboxes/{sandbox_id}/exec:cancel`; result read |
| Terminal | runtime-session open and handoff read; optional controller-only `GET /v1/runtime-sessions:connect` |
| Browser | Browser-session open and handoff read |
| Artifact and usage evidence | artifact-stage accept/evidence read and usage-evidence read |

**Fact.** The OpenAPI does not authorize terminate, desired-state mutation,
lease renewal, snapshot, restore, event stream, runtime-session close, or
runtime-session resize routes.

**Fact.** The semantic rules and Go DTOs reserve operation names and document
shapes for several future lifecycle families. The protected transport also
recognizes those paths so admission can fail closed and the application layer
returns unavailable without starting repository or driver work. This is
intentional scaffolding, not an effective API.

**Inference.** A Product reconciler cannot safely close its lifecycle loop over
the present public Provider Contract. In particular, out-of-band cleanup used
by qualification is not a substitute for Contract-authorized termination.

### Provider implementations and evidence

| Area | Current fact | Evidence boundary | Product gap |
| --- | --- | --- | --- |
| Coding/shell | Protected create, status, exec/cancel/result, terminal open/handoff/connect, artifact staging, and usage evidence are composed for the exact default-disabled profile | Current 53-case local Suite and the named independent caller qualification pass their bounded gates | No Product API, durable product operation ledger, user auth, control lease, session close/resize, or Provider lifecycle closure |
| Independent caller | The separate caller passed 15 initial plus 5 reconstruction scenarios, 91 observations, and stable zero-resource cleanup for exact pinned identities | `qualified` applies only to the recorded caller, Provider revision, profile, topology, and scenarios | The caller remains outside this repository and is not a product implementation or aggregate conformance result |
| Browser Provider | Browser Contract/projection, signed runtime image, Docker adapter, provenance checks, restricted egress, durable Provider-local session/reference state, and usage evidence exist | Component, publication, command-graph, and separately named reference E2E tracks | The production command does not advertise Browser; no product-owned public Gateway or product authorization/control model is composed |
| Runtime Gateway | Backend-neutral terminal/Browser proxy ports, metadata-only audit, limits, revocation, capacity, and downstream fencing components exist | Process-local and specialized Redis-compatible/PostgreSQL-backed reference gates are separately recorded | No product Gateway service, Product API integration, public identity boundary, unified control lease, recording service, or production composition |
| PostgreSQL | A Browser action-history witness and controlled-restore reference exist | Component and same-runner reference evidence only | No product business-state schema, operation/outbox ledger, reconciliation authority, independent failure domain, or product backup/restore gate |
| Redis-compatible state | Shared Gateway capacity, revocation, and fencing adapters exist | Component and specialized caller evidence | This state is not product business truth and does not define human/Agent control ownership |
| Deployment | OCI, Apple Container, and development Kubernetes application packaging can start the local API and fake runtime | Local health/create/list smoke evidence only | No published general application image, protected Provider deployment, product services, production overlay, HA, or release gate |

### State and ownership boundaries

**Fact.** The calling standard assigns business truth, desired state, end-user
authorization, and the aggregate operation ledger to the caller. The Provider
owns provider-local execution state and evidence.

**Fact.** Current Provider persistence is predominantly single-controller
file-backed state. The local `/instances` persistence is separate. Gateway
PostgreSQL and Redis-compatible adapters serve specialized Browser authority,
not Product business state.

**Fact.** The current `gateway.Recorder` records bounded metadata-only audit
events and deliberately excludes stream payloads.

**Inference.** None of the following product authorities currently exists:

- Workspace and named slot aggregate state;
- user, Agent, viewer, or controller grants;
- one active control lease with fencing across humans and Agents;
- product operations, event timeline, transactional outbox, and reconciliation
  checkpoints;
- artifact catalog and product-owned artifact metadata;
- terminal, media, or Agent-trace recording catalogs and retention policy; or
- deployment-level product configuration, SLOs, backup, restore, and disaster
  recovery authority.

The existing Provider mutation fencing token, Browser capacity lease, Browser
downstream action fence, and Gateway revocation tombstone are separate
authorities. None is the product control lease.

### Workspace and capability model

**Fact.** Provider create requests carry `workspace_id` and
`sandbox_slot_key`, but the current coding/shell projection accepts only an
ephemeral, read-only workspace policy. A single create request creates one
Provider sandbox. The target architecture describes multiple named sandbox
slots, but no Product aggregate or orchestration model implements them.

**Fact.** There is no current Product API, Web Console, Guest Agent protocol,
file-watch service, Desktop implementation, editor/notebook integration, port
preview service, MCP tool surface, unified event timeline, or replay service.

**Inference.** Product work must first decide whether Workspace is a composite
aggregate of named sandbox slots or a primary sandbox with separately isolated
auxiliary sandboxes. The present Provider `workspace_id` field does not answer
that product-domain question.

## What “first version complete” currently means

**Fact.** The fixed P2.7 plan is 24/24 complete and its public-caller portion
is 13/13 complete. Hosted run `35203241121` qualified exact Provider revision
`170459266af5f4fad359ca8c63f2ae19741055c5` with exact external caller revision
`b3ebcc783e5db20395e29b029e0eb55f7819b49b` for the recorded coding/shell
profile and topology.

**Fact.** The same records explicitly exclude aggregate conformance,
multi-controller reliability, hostile multi-tenant isolation, HA, deployment,
and production readiness.

**Inference.** “First version complete” means the bounded Provider
coding/shell interoperability and evidence plan is complete. It does not mean
the intended multi-capability Agent workspace product exists or is ready to
operate.

## Contradiction and drift register

The severity below measures the risk of making a wrong architecture or release
claim, not runtime defect severity.

| ID | Severity | Classification | Finding | Required resolution |
| --- | --- | --- | --- | --- |
| C-01 | High | Direct contradiction | The top of `docs/STATUS.md` and the plan index record that core CI `35204434771` passed the clean VCS-built current 53-case Suite. The later “Current Verification” section says clean VCS-built Suite execution remains pending and that no current P2.6 pass is claimed. | Phase 1 step 8 must remove or clearly date the stale paragraph while preserving historical evidence boundaries. |
| C-02 | High | Stale decision status | ADR 0041 says terminal-connect is only a candidate and is ineffective until selected by a Contract lock. The current manifest, OpenAPI, schemas, fixtures, semantic rules, local Suite, lock, and command composition include terminal-connect. | Phase 1 step 8 must update ADR status/history without rewriting the locked Contract or inflating qualification claims. |
| C-03 | Medium | Evidence-ledger drift | `docs/plan/README.md` calls run `34069851741` at merge `838d3bb` the latest ADR 0036 main run. `docs/STATUS.md`, `docs/PROJECT_CONTEXT.md`, the detailed P4 plan, and ADR 0036 retain `34038556283` at `a0cddf4` as their recorded hosted run. Repository history shows the newer plan-index statement was intentional, but the repository alone does not contain the external artifact needed to reconcile both records. | Phase 1 step 8 must choose a canonical evidence record after verifying the newer run and artifact; until then both records remain bounded and no stronger claim follows. |
| C-04 | High | Completed work listed as future | `docs/PROJECT_CONTEXT.md` first records P2.7 as complete, then its “Completed Implementation History and Future Scope” list still instructs publication, execution, and qualification of that same caller as future work. | Phase 1 step 8 must replace the stale action with the actual next gate and retain the original execution record as history. |
| C-05 | Medium | Baseline traceability gap | `docs/PROJECT_CONTEXT.md` identifies documentation baseline `27081df`, while current `HEAD` is `e5bc9bd` and includes later application-deployment work. `docs/STATUS.md` includes that work, but the handoff index does not identify the current repository snapshot as one coherent baseline. | Phase 1 step 8 must publish one dated snapshot pointer and link each later evidence track without relabeling historical runs. |
| C-06 | High | Target/effective-surface ambiguity | Architecture tables name desired-state, lease, terminate, event, snapshot, and restore methods as target inventory. Internal admission and DTO code reserves them, while the locked OpenAPI omits them. The architecture does include caveats, but a route inventory can still be read as current capability. | The next overall Provider lifecycle Contract phase must define and lock the required subset. Phase 1 step 8 must label target and effective route inventories adjacent to each other. |
| C-07 | High | Deployment claim hazard | The repository now has three application-packaging profiles, but each smoke path uses the fake runtime and local API. “Application deployment support” can be mistaken for protected Provider or product deployment support. | Phase 1 step 7 must define deployment levels and gates; step 8 must keep packaging, Provider deployment, product deployment, and production qualification distinct. |
| C-08 | High | Authority-name collision | Provider fencing, Browser connection capacity, Browser action fencing, revocation, and future product control ownership all use lease/fence-like concepts. They protect different resources and have different authorities. | Phase 1 steps 5 and 6 must define separate names, state machines, fencing scopes, renewal rules, and failure semantics. |
| C-09 | Medium | Recording-name collision | `gateway.Recorder` is metadata audit only, while the product target requires terminal, media, and Agent-trace recording with catalogs, retention, access control, and replay. | Phase 1 step 6 must keep audit and content recording as separate ports and data classes. |
| C-10 | High | Persistence claim hazard | PostgreSQL exists only as a Browser action-history witness and Redis-compatible state exists for Gateway coordination. Neither is the requested product source of truth. | Phase 1 steps 3 and 4 must define product PostgreSQL ownership, schema, transaction boundaries, outbox, and reconciliation before implementation. |

## Missing decisions and blockers

These are not defects in the current bounded Provider. They are blockers for
starting the requested product implementation.

### Phase 1 step 2: repository governance and module boundary

Decision required before product code:

- whether this repository may contain Product API, Product application/domain,
  persistence, Gateway service, Guest Agent, recording, and Web Console
  modules;
- allowed dependency direction among Product, Provider, Gateway, and drivers;
- prohibition on Product code importing Provider repositories, backend IDs,
  host paths, or runtime-driver models;
- preservation of the separate external caller and of the Provider calling
  standard as the only cross-boundary contract; and
- migration and compatibility ownership for new product-facing APIs.

### Phase 1 step 3: Product Contract

Decision required:

- versioned Product API namespace and authentication/authorization boundary;
- Workspace, sandbox slot, session, operation, event, artifact, recording, and
  actor projections;
- strict request bounds, unknown-field rejection, error envelope, idempotency,
  optimistic concurrency, pagination, retention, and event-ordering rules;
- WebSocket or streaming upgrade contracts; and
- which data is stable public output versus internal evidence.

### Phase 1 step 4: Workspace, slots, and storage

Decision required:

- composite Workspace versus primary-plus-isolated sandbox model;
- names and invariants for primary code, Browser, Desktop, subagent, and other
  slots;
- workspace revision, branch, mount, artifact, and snapshot ownership;
- product PostgreSQL schema, aggregate transactions, operation ledger,
  transactional outbox, and reconciler checkpoints; and
- Provider ID mapping without leaking backend identity into product contracts.

### Phase 1 step 5: identity, Agent authority, and threat model

Decision required:

- user, tenant, Agent, viewer, controller, service, and Provider identities;
- short-lived credentials and delegation from a human to an Agent;
- one-controller lease and fencing semantics, including expiry, revocation,
  takeover, reconnect, and stale-actor rejection;
- secret references and guest-delivery boundaries; and
- single-user first-version simplifications that do not preclude later
  multi-actor collaboration.

### Phase 1 step 6: Gateway, session control, and recording

Decision required:

- public Gateway ownership and its interaction with Product API and Provider
  terminal/Browser handoffs;
- terminal close/resize, Browser live control, Desktop input/display, preview,
  editor/notebook, Files, and MCP session boundaries;
- explicit separation of metadata audit, terminal recording, media recording,
  Agent trace recording, and recording catalog; and
- backpressure, reconnect, revocation, retention, encryption, access control,
  and replay semantics.

### Phase 1 step 7: deployment levels and operational gates

Decision required:

- exact meanings of `development`, `standalone`, `production`, and
  `future-hostile-multitenant`;
- component topology, configuration, dependency health, readiness, metrics,
  tracing, SLOs, capacity, backup/restore, disaster recovery, and upgrade
  policy for each level;
- immutable image and platform release gates; and
- which claims require independent failure domains, multi-controller tests,
  security review, or hosted evidence.

### Phase 1 step 8: documentation consolidation

Decision required:

- one authoritative current-state page;
- explicit historical versus current evidence ledgers;
- adjacent target-versus-effective API inventories;
- correction of C-01 through C-07 after their facts are verified; and
- removal of stale future instructions without erasing evidence provenance.

## Entry criteria for the next overall phase

At the time of this audit, Product implementation was blocked until Phase 1
produced an accepted governance ADR and Product Contract. ADRs 0042-0047 and
the locked `product-contract/` design resources now satisfy that design entry
condition. The later Provider lifecycle expansion remains a hard dependency
for a reconciled Product control plane. At minimum, its Contract work must
decide and lock termination, desired-state mutation, lease renewal, event
observation, and session close/resize semantics. Snapshot and restore remain
separately capability-gated unless that phase explicitly brings them into
scope.

No implementation should infer these operations from reserved Go DTOs,
semantic operation names, private driver methods, or out-of-band qualification
cleanup.

## Audit conclusion

The repository is a credible, well-evidenced Provider foundation with strict
admission, bounded coding/shell interoperability, substantial Browser and
Gateway reference components, and clear non-claim discipline. It is not yet
the requested Agent workspace product.

The audit originally selected Phase 1 step 2 as the safest next action. Phase 1
is now complete as design and Product Contract-definition evidence. The next
overall action is the separately reviewed Provider lifecycle Contract
expansion recorded in the
[Product v1 Phase 1 plan](../plan/product-v1-phase-1.md), not Product UI,
database, or Gateway implementation that assumes missing Provider operations.

## Resolution addendum

The documentation-consolidation step resolved the register as follows:

- C-01: current clean VCS-built 53-case core CI is now stated consistently;
  no current remote/E2E bundle is inferred.
- C-02: ADR 0041 now records selection by the effective Provider Contract lock.
- C-03: main run `34069851741` at `838d3bb` and artifact `10000177842` were
  independently inspected and are the canonical latest ADR 0036 record.
- C-04: P2.7 publication and qualification are recorded as complete; the stale
  future instruction was replaced with the actual next Contract gate.
- C-05: current code snapshot `e5bc9bd` and the uncommitted Phase 1 design set
  are identified separately from historical evidence baselines.
- C-06: architecture now lists locked effective Provider routes immediately
  before the broader target lifecycle inventory.
- C-07: ADR 0047 separates development packaging, standalone, production, and
  future hostile-multitenant levels and evidence.
- C-08 through C-10: ADRs 0044-0046 separate control/fencing authorities,
  recording classes, and Product persistence from existing Provider/Gateway
  stores.
