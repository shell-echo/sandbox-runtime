# ADR 0047: Deployment Levels, SLOs, and Release Gates

- Status: Accepted for Phase 1 architecture; no level above development is
  currently qualified
- Date: 2026-09-18

## Context

The repository has local and hosted component, Contract, reference-caller, and
specialized Browser evidence. It also has Docker, Apple Container, and
Kubernetes application-packaging smoke paths that run the local `/instances`
API with the in-memory fake runtime. Those results are useful but do not prove
a protected Provider deployment, Product deployment, high availability, or
production readiness.

Terms such as “deployed,” “production,” and “multi-tenant” need explicit
topology, security, durability, observability, and evidence meanings. Without
deployment levels, a working container or a passing reference harness can be
mistaken for a release gate.

## Decision

### Deployment levels

Every build, guide, capability advertisement, and evidence record identifies
one of four levels. Passing one level never implies a higher level.

#### Development

Purpose: local coding, tests, demonstrations, and bounded reference evidence.

- Components may run in one process or host and may use in-memory/file stores,
  fake runtime, development Docker adapters, self-managed certificates, and an
  explicit local identity mode.
- One controller is the default. Restart, host, storage, and identity failure
  domains may be shared.
- Data may be disposable. Availability, RPO, RTO, and tenant-isolation SLOs do
  not apply.
- Product and Provider capabilities are unavailable unless their complete
  development graph is composed and advertised honestly.
- The current Docker, Apple Container, and Kubernetes application smoke paths
  belong here. They validate application packaging around the local API and
  fake runtime only.

#### Standalone

Purpose: one trusted owner on one installation, with durable Product state but
without high availability or hostile-workload claims.

- Product API, reconciler/workers, Provider, Runtime Gateway, Guest Agent where
  required, PostgreSQL, Redis-compatible coordination, object storage,
  identity, and telemetry are explicitly configured.
- Components may share one machine or cluster. A single failure domain and
  planned downtime are acceptable and disclosed.
- Production identity semantics, encrypted transport, secret references,
  durable migrations, bounded resources, backup/export, restore procedure,
  retention, and capability honesty are required. Development identity, fake
  runtime, and unreviewed default credentials are forbidden.
- One active Product controller is allowed. Recovery must reject stale
  generations and prove no duplicate current Provider binding.
- A successful backup and restore rehearsal is required before a standalone
  release, but no HA availability SLO is claimed.
- This level is for trusted single-user workloads; it is not a security
  boundary for mutually hostile tenants or guests.

#### Production

Purpose: supported service for authenticated tenants under the threat model in
ADR 0045, excluding the stronger future hostile-multitenant level.

- Product API, reconcilers, Gateway, Provider, identity, PostgreSQL,
  coordination, object storage, and telemetry use explicit service identities,
  least-privilege roles, independent health, rolling change procedures, and
  no development fallbacks.
- Control-plane replicas and reconcilers tolerate process/node replacement;
  durable authority remains in PostgreSQL. Gateway replicas use shared
  revocation/capacity authority where required.
- Critical stores have documented provenance, encryption, backup, restore,
  failover, monitoring, capacity, and operator quarantine procedures.
  Coordination state is not Product business truth.
- Public edges enforce authenticated TLS, bounded requests/streams, rate and
  capacity policy, revocation, safe errors, and recording policy. Provider,
  databases, Guest channels, and private runtime endpoints are not public.
- Runtime profiles use immutable verified images and reviewed isolation,
  filesystem, network, egress, secret, cleanup, and evidence policy.
- Multi-tenant authorization is required, but this level does not assert that
  a shared kernel/container boundary safely isolates determined hostile code.
  Profiles that accept untrusted code must explicitly document the isolation
  assumption and may remain unavailable.

#### Future hostile-multitenant

Purpose: mutually distrustful tenants and intentionally adversarial workloads.

- Requires a reviewed strong-isolation boundary such as dedicated VM or
  microVM-class isolation, tenant-separated control/data-plane policies,
  hardened image and device surface, strict network/metadata denial, host and
  kernel hardening, confidential secret delivery, forensic operations, and
  independent security assessment.
- Requires isolation escape, noisy-neighbor, side-channel, control-plane
  compromise, destructive restore, and incident-response exercises in addition
  to all production gates.
- It is a future research and qualification track. No current component,
  Docker hardening, reference E2E, or Product Contract design satisfies it.

### Required deployment graph

The logical graph is:

| Component | Authority |
| --- | --- |
| Product API | Public Product Contract, authentication, authorization, command transactions, reads, connection grants |
| Reconciler/workers | Outbox dispatch, Provider adaptation, sagas, evidence reconciliation, retention jobs |
| Provider | Locked Provider Contract and provider-local execution/evidence |
| Runtime Gateway | Public session data plane, live authority checks, limits, audit and recording adapters |
| Guest Agent | Slot-local mediated file/application/session operations over outbound authenticated channel |
| PostgreSQL | Product aggregate, operation, event, lease, session, catalog, and outbox authority |
| Redis-compatible coordination | Ephemeral/shared capacity, revocation acceleration, and profile-specific coordination; never Product truth |
| Object storage | Immutable Workspace blobs, artifacts, and recording segments/manifests |
| Identity and secrets | Human/workload identity, key rotation, scoped secret/grant exchange |
| Telemetry | Safe metrics, logs, traces, alerts, audit export, and SLO calculation |

Co-deployment may reduce operational cost at development or standalone level,
but it does not merge authorities or authorize in-process Product-to-Provider
bypass.

### Health, readiness, and capability

Liveness means a process can make progress and should not be restarted merely
because a dependency is temporarily unavailable. Readiness means the instance
can safely receive its class of traffic. Capability readiness is narrower: one
profile is advertised only when every required dependency and policy for that
profile is ready.

Product API readiness requires database connectivity, migrations at the exact
supported revision, identity policy, and ability to serve safe reads and
commit commands. A degraded optional profile removes or marks only that
capability unavailable. It does not make the whole API lie about readiness.

Gateway readiness requires current identity/grant validation, authority-watch
sources, capacity authority, audit sink, required recorders, and at least one
admissible advertised profile. Provider readiness follows the locked Provider
Contract and selected profile graph. Dependency health alone never advertises
a capability.

### Production service objectives

These are target objectives and release criteria for a future production
profile, not claims about the current repository. A release must publish the
exact measurement queries, exclusions, traffic threshold, observation window,
and error-budget policy.

| SLI | Initial production objective | Measurement boundary |
| --- | --- | --- |
| Product API availability | 99.9% per rolling calendar month | Eligible authenticated requests not returning server/dependency failure; client, authorization, conflict, and rate-limit outcomes are classified separately |
| Product read latency | p95 <= 300 ms | Server time for bounded metadata reads, excluding content transfer and client network |
| Product mutation acceptance | p95 <= 500 ms | Valid command receipt to durable operation acceptance, excluding asynchronous completion |
| Workspace event visibility | p99 <= 5 s | Transaction commit to authorized poll/SSE visibility |
| Gateway connection admission | p95 <= 2 s | Valid client handshake to upstream-ready or protocol-ready, excluding runtime provisioning |
| Established Gateway availability | 99.9% per month | Gateway-caused unexpected termination minutes for admitted sessions; client close, expiry, policy revocation, and runtime termination are separate causes |
| Control-plane backup recovery point | <= 5 minutes for regional disaster | Last recoverable Product PostgreSQL/object metadata state under the qualified backup profile |
| Control-plane disaster recovery time | <= 60 minutes | Declared disaster to safe read/write restoration under the qualified single-region recovery procedure |
| PostgreSQL instance failover | RPO 0 for committed transactions | Only for the exact synchronous high-availability topology and its tested failure set |

Workspace time-to-ready is profile- and capacity-dependent. No global number is
set in Phase 1. Before a profile can be advertised in production, it must
publish an SLI definition and load-tested p50/p95/p99 objective for supported
images, regions, warm/cold paths, and concurrency. Queue time, image pull,
runtime provision, Guest readiness, and required-slot readiness must be shown
separately so a fast cached path cannot hide cold-start behavior.

### Observability and privacy

Metrics use bounded labels. Tenant, Workspace, operation, session, Provider
correlations, URLs, filenames, command text, tokens, secrets, and recording
content are not metric labels. Logs and traces apply the safe-data rules from
the Product and Provider Contracts and carry opaque request/correlation IDs.

At minimum, production monitors API outcomes/latency, database pool and
transactions, outbox age, operation age/state, reconciliation lag, duplicate
or stale evidence, current binding conflicts, control-lease conflicts,
connection admissions/closures, authority-watch loss, recorder failure,
capacity, runtime provision/cleanup, object-store integrity, backup age,
restore/failover results, and capability readiness transitions.

### Release gates

#### Development gate

- locked Contract and schema/semantic verification;
- focused and full race/shuffle tests, vet, and applicable tagged runtime tests;
- bounded local smoke for the exact composed profile;
- explicit non-production configuration and claims.

#### Standalone gate

- all development gates on release artifacts;
- durable Product migrations and restart/reconciliation evidence;
- exact immutable images and configuration, production identity semantics, and
  no fake/runtime fallback;
- real PostgreSQL, coordination, object storage, Gateway, Provider, and Guest
  dependencies required by advertised capabilities;
- backup/restore rehearsal with integrity and cleanup evidence;
- single-controller failure/restart, storage-full, dependency-loss, and
  authority-expiry exercises; and
- operator guide, upgrade/rollback constraints, retention, and diagnostics.

#### Production gate

- all standalone gates, plus multi-replica and multi-controller behavior;
- independently exercised public Product/Gateway and protected Provider paths;
- load/soak/capacity and error-budget evidence against the declared SLOs;
- database, coordination, and object-store HA/failover plus backup/restore
  evidence in the exact deployment topology;
- security review and tests for tenant isolation, authorization, delegation,
  secrets, egress, replay, stale control, revocation, and safe telemetry;
- rolling upgrade, rollback or forward-fix, key rotation, certificate expiry,
  disaster recovery, quarantine, and incident-response exercises;
- signed immutable artifacts with verified provenance and dependency scanning;
  and
- one release evidence bundle that binds source, Contracts, images,
  configuration, topology, scenarios, observations, cleanup, and non-claims.

#### Future hostile-multitenant gate

- all production gates;
- approved strong-isolation design and implementation;
- independent penetration/isolation assessment and adversarial workload suite;
- host/kernel/device/network/metadata/side-channel hardening evidence; and
- tenant-compromise containment and forensic/incident exercises.

Local unit, component, reference-caller, or same-runner evidence can satisfy a
named prerequisite but cannot substitute for a higher-level release gate.

## Consequences

- Packaging and deployment readiness are no longer interchangeable terms.
- Standalone can become useful before HA without being mislabeled production.
- Production objectives are measurable, while profile startup objectives wait
  for representative baselines.
- Strong hostile-tenant isolation remains explicit future work rather than an
  implied property of containers.

## Rejected alternatives

### Call any containerized build a deployment

Rejected because packaging says nothing about protected interfaces, durable
authority, runtime composition, restore, HA, or security.

### Treat standalone as a small production topology

Rejected because it lacks HA and accepts one trusted owner and shared failure
domains. Its useful guarantees should be stated without stronger claims.

### Publish startup SLOs before measuring profiles

Rejected because image size, architecture, region, cache state, runtime,
network policy, and required slots materially change readiness time.

### Infer hostile multi-tenancy from container hardening

Rejected because process/container controls reduce risk but do not establish a
strong adversarial isolation boundary.

## Non-goals

This ADR does not supply deployment manifests, choose infrastructure vendors,
claim current SLO attainment, or authorize production capability
advertisement.
