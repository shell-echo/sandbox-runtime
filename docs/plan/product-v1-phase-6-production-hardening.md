# Product v1 Phase 6 Production Hardening Plan

Date: 2026-09-22

Status: **5/15 complete**. Slices 4 and 5 passed their immutable real-process
gates and strict evidence verification. Repository-side hardening foundations
for Slices 6-10 and release-profile checks for Slices 7/11/14 are present, but
their deployment and independent-observation gates remain open. The order is
fixed by ADR 0051.

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

Status: complete within the production-kernel/process evidence boundary. The
Provider and public data-plane roles are deliberately absent, so the exact
capability snapshot reports `product.workspace` as unavailable and mutations
remain rejected before persistence.

### Slice 3 — deployable Provider control plane

Create a role-specific Provider command and production configuration using
transactional state, exact protected admission, lifecycle/exec/terminal/
artifact/usage/Desktop readiness, bounded reconciliation and no local API.

Gate: real backend plus database restart/fault/concurrency tests, locked
Contract verification and exact capability advertisement.

Status: complete as local role-process, transactional PostgreSQL, and real
Docker backend evidence. The production-only `provider serve` command selects
one exact coding-shell or Desktop Contract profile, retains Provider-local
state behind separated database roles, closes readiness on schema or bounded
reconciliation failure, and exposes no local API. See
[`product-phase-6-slice-3.md`](../audits/product-phase-6-slice-3.md).

### Slice 4 — deployable Gateway, Guest, Browser and Desktop roles

Create separate commands/configuration for public Gateway, outbound Guest,
private Browser and private Desktop roles. Freeze public/private TLS,
authorization, relay, capacity, revocation, recording and shutdown graphs.

Gate: independent process starts, dependency loss, reconnect, bounded drain,
least-authority credentials and no private-coordinate projection.

Status: complete within the bounded local independent-process scope. Separate
Gateway, Guest, Browser and Desktop commands enforce role-specific transport,
authority and readiness. Under ADR 0052, Provider remains the sole
Browser/Desktop handoff, PostgreSQL and Docker authority; independent
Browser/Desktop processes use `executor.v2`, and Desktop reaches only the
Provider-owned Unix broker mux using a signed short-lived capability. A strict
six-role/twelve-scenario gate passes real Chromium, real Desktop VP8/input,
dependency loss, reconnect, replay/capacity/drift denial, broker/executor/
Provider restart, bounded drain and exact zero-resource cleanup. The Desktop
OCI is a local non-release candidate, and public Product E2E, deployment and
production readiness remain unproved.
The accepted manifest binds runtime revision `78f5987fda45873e497bce6d336e29dd4a61dc74`,
evidence-tool revision `e2f4abacf03418c7b18f179c3e7459292d8626df`,
and manifest digest
`sha256:d01b3c41a0094657f18b4014b0649a799ea7fcf0e4ccaf07aa82cdd2052cc0d2`.
See [`product-phase-6-slice-4.md`](../audits/product-phase-6-slice-4.md) and the
[`strict evidence manifest`](../audits/product-phase-6-slice-4-evidence.json).

### Slice 5 — secret references, KMS and rotation

Introduce production secret-provider and envelope-key ports, KMS/HSM-backed
recording/ticket/data keys, scoped workload credentials, versioned rotation,
revocation and break-glass audit. No long-lived secret is accepted inline.

Gate: overlap rotation, stale-key rejection, KMS loss, cache expiry, restart,
revocation and plaintext-exclusion evidence.

Status: complete within the bounded local independent-process and real-adapter
scope. ADR 0054 and the Slice 5 audit freeze the work order. In addition to
canonical scoped bindings, the bounded cache and
opaque envelope-key port, Product now has a tenant-bound KMS recording adapter
and a strict Vault Transit client. A digest-pinned Vault TLS integration proves
recording round-trip, v1/v2 overlap rotation, restart reconstruction, KMS-loss
closure and cleanup. A second digest-pinned Vault KV/TLS gate proves the
versioned workload-material agent, certificate overlap, agent restart, Vault
loss and exact cleanup. Product production startup now uses an explicit v2
runtime schema and a role-owned registry for its TLS pair, runtime PostgreSQL
DSN and identity key ring. A separate no-cache `product migrate` process and
one-shot agent/socket are the only holders of the migration DSN; runtime config
cannot parse that authority. Its real PostgreSQL/TLS process gate proves
pre-migration bind denial, cross-purpose agent denial, exact bootstrap cleanup,
readiness closure on runtime-agent loss and recovery after agent restart. The
local gate records `distinct_os_uid_established=false`, so production service-
account isolation remains later deployment evidence. Provider, Gateway, Guest,
Browser and Desktop now use separate role-owned registries and agents;
Provider also has a separate one-shot migration process. An independent
credential controller issues six renewable short-lived runtime leases and two
non-renewable migration leases, while a separate persistent break-glass
controller enforces two distinct approvals, online single consumption and a
hash-chained metadata-only audit. Focused real-process gates pass, including
controller restart, Vault/agent loss, revocation, expiry and exact cleanup.

The immutable dual-evidence campaign passed. The real six-role
material/credential gate and the real Vault Transit plus PostgreSQL
recording-lifecycle gate bind runtime revision
`c189330c5ed0aa52c60b6b85c5cd9c6b59fbef10`, evidence-tool revision
`39fd1025f6fa838325aced711d8a024a9ce5d1b6`, Desktop candidate image digest
`sha256:669f3baff87ae5eda45e9957e6cf25804ad8ad95ef47bbe9b8f14a76e71fc5cb`
and manifest digest
`sha256:e6a6fdcc299c721e1fa2c48009d98a6ca4c52d59318c507af8b68fd8596e840c`.
Root race/vet, both Contract verifiers, retained Slice 4 verification and exact
zero-resource cleanup also passed. Product recording-content composition
remains explicitly false; Slice 8 must compose it with object storage, Slice 11
must reject premature deployment enablement, and Slice 14 must run
published-artifact black-box encrypted recording E2E before RC eligibility.
See the
[`strict Slice 5 evidence manifest`](../audits/product-phase-6-slice-5-evidence.json).

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

Slices 1-5 are implemented. Slice 6, TLS, network policy and least privilege,
is next. The current result is bounded local independent-process evidence using
a non-release Desktop candidate; no complete public Product recording-content
E2E, HSM, published application supply chain, deployment, HA,
hostile-multitenant, SLO-attainment or production qualification is claimed.
