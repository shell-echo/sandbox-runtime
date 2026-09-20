# Product v1 Phase 6 Production Hardening Plan

Date: 2026-09-20

Status: **1/15 complete**. The order is fixed by ADR 0051.

## Goal and claim boundary

Move from the bounded Phase 5 independent-process release topology to an
operator-deployable, observable, recoverable release candidate and then a
production release gate. Every result remains scoped to its exact deployment,
identities, artifacts, runtime profiles, scenarios, failure domains and SLO
window.

This plan does not change Provider Contract ownership, merge Product and
Provider truth, authorize consumer-specific Provider behavior, or imply
hostile-multitenant isolation. The future hostile-multitenant assurance level
remains a separate gate under ADR 0047.

## Permanent invariants

- Product, Provider, Gateway, Guest, Browser, Desktop, and the local
  `/instances` service retain separate process and authority boundaries.
- Product reaches runtime execution only through the locked network Provider
  Contract. Product code does not import Provider repositories or drivers.
- Configuration and readiness fail closed. A route, flag or successful process
  bind is not capability readiness.
- Secrets enter through bounded private references; stable APIs, logs, probes,
  events and evidence contain no credentials, private coordinates, host paths
  or backend diagnostics.
- Blocking and external work preserves cancellation and explicit deadlines.
- PostgreSQL, coordination and object storage are treated as independent
  production dependencies with explicit backup and failure domains.
- Immutable artifact identity, SBOM, signature and provenance are release
  inputs, not optional documentation.

## Fixed slices

### Slice 1 — independent Product process and strict development composition

Add `sandbox-runtime product serve`; an exact `product_process` configuration;
private bounded PostgreSQL and identity files; strict frozen development
identity decoding; real Product migrations/store; bounded HTTP transport; and
separate `/livez` and database-derived `/readyz`. Advertise no Product runtime
capability and deny all primary-slot mutations.

Gate: focused race/shuffle tests, full root race/shuffle and vet, both Contract
verifiers, retained Phase 3-5 evidence verifiers, and a disposable real
PostgreSQL process smoke. Standalone/production modes must fail at startup.

Status: complete within its development evidence boundary.

### Slice 2 — production Product kernel, identity and database roles

Compose the Product API and workers with production identity verification,
issuer/audience/key-rotation policy, TLS, distinct migration/runtime database
roles, schema-version compatibility, connection budgets and complete
dependency-derived capability snapshots. Remove static identity from every
standalone/production path.

Gate: key overlap/revocation, auth precedence, migration/runtime privilege
denial, pool exhaustion, database loss/recovery, restart and nondisclosure.

### Slice 3 — deployable Provider control plane

Create a role-specific Provider command and production configuration using
transactional state, exact protected admission, lifecycle/exec/terminal/
artifact/usage/Desktop readiness, bounded reconciliation and no local API.

Gate: real backend plus database restart/fault/concurrency tests, locked
Contract verification and exact capability advertisement.

### Slice 4 — deployable Gateway, Guest, Browser and Desktop roles

Create separate commands/configuration for public Gateway, outbound Guest,
private Browser and private Desktop roles. Freeze public/private TLS,
authorization, relay, capacity, revocation, recording and shutdown graphs.

Gate: independent process starts, dependency loss, reconnect, bounded drain,
least-authority credentials and no private-coordinate projection.

### Slice 5 — secret references, KMS and rotation

Introduce production secret-provider and envelope-key ports, KMS/HSM-backed
recording/ticket/data keys, scoped workload credentials, versioned rotation,
revocation and break-glass audit. No long-lived secret is accepted inline.

Gate: overlap rotation, stale-key rejection, KMS loss, cache expiry, restart,
revocation and plaintext-exclusion evidence.

### Slice 6 — TLS, network policy and least privilege

Close every service-to-service trust edge; automate certificate issuance and
rotation; enforce private ingress, restricted egress, metadata/DNS defenses,
role-specific service accounts, filesystem/capability/seccomp policy and
resource limits.

Gate: identity substitution, downgrade, cross-role/cross-tenant traffic,
metadata, DNS rebinding, policy outage and privilege-escalation denial.

### Slice 7 — application supply chain

Pin builder/runtime bases, produce reproducible multi-platform application
images, emit SBOMs, sign image indexes and attest source/build inputs. Enforce
digest-only deployment and verification before startup/admission.

Gate: independent signature/provenance/SBOM verification on every supported
architecture plus tamper and mutable-reference rejection.

### Slice 8 — production PostgreSQL, coordination and object storage adapters

Qualify role-separated PostgreSQL, Valkey-compatible coordination and external
object storage with bounded clients, TLS identity, ACLs, quotas, retention,
consistency semantics and distinct failure domains.

Gate: independent deployment/component tests, authorization denial, saturation,
partitions, stale fencing, corruption and exact cleanup.

### Slice 9 — backup, restore and data-integrity operations

Define backup/PITR schedules, object versioning, coordination reconstruction,
encryption-key recovery, restore ordering and reconciliation. Restore only into
an isolated target before controlled cutover.

Gate: independently timed backup/restore drills, stale/missing/corrupt backup
rejection, RPO/RTO measurement and post-restore authority verification.

### Slice 10 — observability and SLO control

Add bounded metrics, traces, structured safe logs, dashboards and alerts for
availability, latency, saturation, reconciliation, queue age, session health,
recording, storage and dependency failures. Freeze SLI definitions and budgets.

Gate: telemetry privacy/cardinality review, alert injection, trace continuity,
dashboard calculation tests and an initial non-claiming measurement window.

### Slice 11 — Docker, Apple Container and Kubernetes deployment profiles

Publish role-specific Docker-compatible images and deployment docs; add a
bounded standalone Apple Container profile where dependencies are supportable;
add Kubernetes production overlays with secrets, policies, storage, probes,
budgets, topology spread and disruption controls. Deployment environment and
Provider runtime backend remain independent.

Gate: immutable-image Docker smoke, Apple Container scope gate, Kubernetes
server-side validation and disposable-cluster role/dependency smoke.

### Slice 12 — upgrades, migrations, canary, rollback and disaster recovery

Define version skew, expand/migrate/contract database changes, key/protocol
compatibility, canary analysis, drain, rollback limits and regional disaster
recovery runbooks.

Gate: N/N-1 skew, interrupted migration, canary abort, rollback, forced drain,
regional dependency loss and recovery exercises.

### Slice 13 — hostile-input, tenant and resilience campaign

Exercise malformed/oversized inputs, auth confusion, resource exhaustion,
cross-tenant access, egress bypass, storage corruption, replay/fencing,
dependency partitions and cleanup under failure. This strengthens production
evidence but does not itself establish hostile-workload isolation.

Gate: fixed adversarial matrix with sanitizer review, quotas, cancellation,
leak checks and zero exact run-owned resources.

### Slice 14 — independent deployment release candidate

Build one immutable candidate and deploy the complete topology from published
artifacts in independently administered failure domains. Run black-box Product
and Provider clients, backup/restore, upgrade/canary/rollback, dependency loss,
SLO collection and cleanup without repository test-process composition.

Gate: strict signed evidence manifest binding artifacts, configuration digests,
identities, topology, scenarios, observations and non-claims.

### Slice 15 — final production release gate

Review the Slice 14 candidate, security/threat model, open risks, SLO window,
operations ownership, recovery drills and artifact provenance. Publish only an
accepted immutable candidate; otherwise record a blocked release without
weakening a gate.

Gate: independent evidence verification, all mandatory CI/deployment/security
checks, named operator acceptance and a precise supported-scope statement.

## Evidence ladder

Unit/component, real-adapter, same-repository composition, independent-process,
deployment, release-candidate and production-release evidence remain distinct.
Later evidence may depend on earlier identities but never retroactively widens
an earlier claim.

## Current stop point

Slice 1 is implemented. Slice 2 is next. No Phase 6 production, standalone,
HA, hostile-multitenant, SLO-attainment or deployment qualification is claimed.
