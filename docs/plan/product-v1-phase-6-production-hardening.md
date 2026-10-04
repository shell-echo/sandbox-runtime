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

The Guest security-edge gate uses the actual independent Product and Guest
production commands. Product must own the PostgreSQL Guest binding and the
private `/agent` Hub; the wire must complete hello/challenge/signature/welcome
with nonce/replay, GuestID, tenant/workspace/slot, generation, capability and
expiry checks. Revoke the business binding, lose the database, revoke the TLS
peer or lose its CRL source, restart/reconnect both roles, and verify upgraded
WebSocket drain and exact cleanup. A run-owned fixture may prepare Product
binding rows, but it does not establish a formal public creation flow. The
Slice 6 manifest must distinguish `guest_security_edge_proven` from the
absent Files/Development public composition using the existing evidence
schema and non-claim mechanism. Hub/Guest-handler readiness never by itself
advertises user Files/Development readiness.

Status: underway. ADR 0055 and the Slice 6 startup audit freeze real Vault PKI,
live TLS rotation/revocation, role-isolated internal networks with alias-only
egress brokers, exact container least privilege and the complete privileged
principal inventory. Library checks or configuration text do not advance the
counter. The separate Slice 6 harness is still under construction: its
frozen 16-scenario routing plan and strict input preflight are not a successful
full-topology run, and no Slice 6 manifest may be issued from them.
The same-run component chain now also starts separate Product runtime and
Product material-agent TLS signer PID1 processes with managed leaves and
exact socket cleanup. Product material-agent configuration is preflighted
against both required bindings, and its separate PID1 opens both restricted
listeners, resolves the real KVv2 identity key-ring for a cross-UID/GID
Product owner, then drains with exact cleanup. At that earlier checkpoint,
its PostgreSQL runtime DSN and the Product/Guest production commands had not
yet run; this did not advance Slice 6.

The later E7 same-run component diagnostic at clean E
`34d72e05a115aa8fccbe5b9c0d94896c2ba26fb3` did run independent
Product and Guest PID1 processes against the locked PostgreSQL and Vault
inputs. It crossed the earlier durable-revocation readback failure, checked
the unexpired revoked binding with empty nonce in PostgreSQL, retained
Product/PostgreSQL/Guest-agent identities and Product SQL availability, and
cleaned exact run-owned resources to zero. The certificate controller still
reported a sticky local credential-revoke error; the independent terminal
operator separately confirmed remote revocation and a complete CRL. This
bounded component pass does **not** prove reconnect, peer TLS revocation,
CRL-source loss, the full frozen deployment inventory or the 16 scenarios,
and it does not produce a Slice 6 manifest. The detailed E6 failed and E7
passed records are in the
[Slice 6 startup audit](../audits/product-phase-6-slice-6-startup.md).
Phase 6 remains **5/15**.

A later separately reviewed clean E/R/F component at E
`f49ee748f5e8790cd58c62d04bc5304b1a363b49`, R/F
`c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635`, run
`20efb6c95a0fa39cb0441f580a86888f`, passed real Product runtime SQL
and Guest PID1 signed hello/welcome. An original upgraded connection drained
after same-PostgreSQL durable business-binding revocation; a new signed
attempt was rejected as revoked. Four private source/image/process/mutation-
bound receipt files passed independent reread, and exact run-owned Docker
cleanup passed. This closes only that component observation, not the full
Guest edge: database loss/recovery, TLS-peer revocation, CRL-source loss and
replacement restart/reconnect still require live proof. It is not a frozen
16-scenario/78-deployment gate or a Slice 6 manifest. Phase 6 remains **5/15**.

The initial external PostgreSQL leaf signing diagnostic is non-release:
its v1 terminal plan did not confirm revocation of that added serial. A
separate audit retains this exact gap. A later real same-run component gate
proved clean-source operator v2 capability *before* signing, observed the
actual non-root PostgreSQL-mounted leaf on nine isolated bridges with final
TLS/HBA and local SQL, stopped PostgreSQL, then confirmed all three serials
in the complete issuer CRL with two token accessors and operator self-revoke.
The [component audit](../audits/product-phase-6-slice-6-postgres-v2-component.md)
also retains three failed attempts whose third-leaf revocations were not
confirmed. That earlier component result did not supply a Product runtime
DSN or run nine SQL callers, the full 16-scenario gate or a release manifest.

A subsequent mutable-tree same-run component test started that PostgreSQL
server before Vault root revocation, created separate non-elevated Product
SCRAM logins and installed distinct migration/runtime DSNs into exact
create-only Vault KVv2 purpose bindings. Another run proved Product-owner
resolution through the live material-agent. Clean-source R3 component run
`50f6810acddb8bffd5ba4167b0e424e2` then completed an independent Product
`migrate v2` PID1 with exit 0 and read back the exact ledger, table ownership
and post-DDL grants from the same PostgreSQL process. Both controllers
quiesced; the certificate controller's known terminal failure remained
visible, and the approved independent operator confirmed revocation, complete
CRL and self-revocation before exact cleanup. See the
[component audit](../audits/product-phase-6-slice-6-postgres-v2-component.md)
for the frozen R3/E identities and failed historical runs. At that checkpoint
only the Product migration **component** had closed; the later separately
reviewed live-revoke component above adds bounded runtime SQL and one
Product/Guest edge observation. Neither proves nine live SQL callers, the
complete Guest security edge or the 16-scenario release gate. Phase 6
remains 5/15.

A subsequent no-issuer offline continuation admits
the Product v3 private inputs and stages an opt-in Product PID1 component
using the same PostgreSQL process, three private sockets and seven isolated
networks. Its restricted ingress-only TLS observer and SQL-connectivity-loss
path have not run against a new issuer; they are not relay, Guest, full gate
or readiness evidence. Sandbox accepted network disconnection only as this
component's database-connectivity-loss mechanism, not a PostgreSQL restart
or HA proof.

The Desktop Provider's Slice 6 proof uses the strict Phase 6
`local-candidate-non-release` executor-v2 image with a source-bound manifest,
`provider-process.v3` live TLS/CRL and `deployment_level=local_candidate`.
This is a local security-enforcement scope, not published-artifact or product
production readiness. The same protected application command is used; Desktop
v3 production artifact admission remains closed pending Slice 7 publication.

The same local-candidate-only exception applies to the other real
repository-owned role images in the complete Slice 6 inventory. The closed
security profile distinguishes local versus registry location from
`oci_manifest`/`oci_index` object kind and reserves `local_config` for an
actually proven config-addressable store. It pins platform and descriptor
chain, then independently observes Docker's runtime store ID, its descriptor,
the container's selected platform manifest and the separate OCI config. The
gate retains exact source/build inputs and a re-importable digest-checked OCI
archive, never pushes the candidate or substitutes Alpine/nc probes for real
role commands. Dirty-tree experiments remain component diagnostics; final
Slice 6 evidence needs an immutable source checkpoint and exact cleanup.

### Slice 7 — application supply chain

Pin builder/runtime bases, produce reproducible multi-platform application
images, emit SBOMs, sign image indexes and attest source/build inputs. Enforce
digest-only deployment and verification before startup/admission.

Gate: independent signature/provenance/SBOM verification on every supported
architecture plus tamper and mutable-reference rejection.

Before any external distribution, independently trace licenses for the actual
image contents, including the base, recursive APKs, Go modules, fonts and
codec libraries. Resolve `custom` and conflicting declarations from the exact
upstream version and build recipe, collect applicable copyright/license texts
and notices, and verify a concrete way to provide exact corresponding source,
distribution patches and build information where required. A scanner license
label, SBOM, signature or private registry alone does not satisfy this gate.
Unresolved license terms or required notices/source block publication, not
the bounded non-distributed Slice 6 local candidate.

Slice 7 must publish and independently verify the new executor-v2 Desktop
runtime, update its immutable lock and then enable exact Desktop v3 production
artifact admission. It must rerun security/runtime gates affected by the
artifact change; Slice 6 candidate evidence does not grant deployment status.
The final artifact profile rejects local/non-release images, verifies
index → platform manifest → config → running ImageID, and rechecks the full
inventory. Byte-identical unaffected observations may be reused only with an
explicit impact analysis; an altered image, entrypoint, base, dependency,
identity, network or configuration requires the affected real-role gate again.

### Slice 8 — production PostgreSQL, coordination and object storage adapters

Qualify role-separated PostgreSQL, Valkey-compatible coordination and external
object storage with bounded clients, TLS identity, ACLs, quotas, retention,
consistency semantics and distinct failure domains.

This slice also completes the production business graph, not just storage
connectors: wire the existing FileService/FileClient,
DevelopmentService/DevelopmentClient, transfer/revision/template and recording
services, actual Guest Files handlers, authenticated Product Web/BFF routes,
content sources and the required PostgreSQL/object-store ports into the
Product/Guest command lifecycles. Reuse existing `/web/data/.../files` and
`/web/transfers/...` rather than introducing a duplicate `/api/v1/files`.
Where a formal Development entry is missing, define the Product/data-plane
DTO, authorization, idempotency and quota boundary and review any Contract
impact before implementation; do not publish the Phase 5 test-only
`/gate/development` route. Explicitly requested but uncomposed production
capabilities fail startup; the default snapshot stays unavailable until all
dependencies and formal user paths are live. A new storage/egress edge must
update the same canonical security inventory and rerun affected Slice 6 gates.

Gate: independent deployment/component tests, authorization denial, saturation,
partitions, stale fencing, corruption and exact cleanup.
The mandatory formal-entry scenarios additionally cover authentication and
cross-tenant denial; Files list/stat/change authorization; transfer digest,
size, offset, quota and cancellation; Development prepare/write/commit/
finalize/rollback/restart; missing/tampered content and dependency loss; and
dynamic capability closure/recovery. Direct service calls, local blob
fixtures and test-only gate handlers cannot alone satisfy this entry gate.

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
Every full-product profile must fail startup/admission when a declared
Files/Development/transfer/recording business composition, dependency or
capability is missing; a kernel-only Product or connected Guest is not a
complete deployment.

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
From the published immutable artifacts and real public entry, run black-box
Files, Development, transfer and encrypted-recording E2E. The absence of
these scenarios blocks release-candidate acceptance, even if the Guest
private security edge and older component tests pass.

### Slice 15 — final production release gate

Review the Slice 14 candidate, security/threat model, open risks, SLO window,
operations ownership, recovery drills and artifact provenance. Publish only an
accepted immutable candidate; otherwise record a blocked release without
weakening a gate.

Gate: independent evidence verification, all mandatory CI/deployment/security
checks, named operator acceptance and a precise supported-scope statement.
The reviewer must explicitly verify the Slice 8 formal-entry and Slice 14
published-artifact Files/Development/transfer/recording evidence. Permanent
`unavailable` advertisement is not a way to satisfy the complete Product v1
target.

## Production composition inventory

This inventory separates existing implementations from their current
production command wiring. It assigns the promised public-entry-to-dependency
closure once, so each new TLS edge does not reveal an unowned business gap.

| Promised path | Existing code/authority | Current production-command gap and owner |
| --- | --- | --- |
| Workspace and Provider lifecycle | Product `Application`, Provider clients/dispatchers and locked Contract | Product kernel denies primary-slot mutation and has no Provider dispatch graph; complete Product-to-three-Provider production composition and dynamic readiness: Slice 8, then deployment/release gates 11/14/15. |
| Terminal, Browser and Desktop public sessions | Product control/session/grant/slot services, Gateway public handlers, Provider private handoffs, role executors | Product production handler passes nil control/session/grant/slot ports; bind formal public entry, role workers, exact Provider profile and Gateway dependency: Slice 8; preserve security-edge proof in Slice 6 and full E2E in Slice 14. |
| Guest private security edge | `guestagent.Hub`, Product PostgreSQL GuestBindingStore, Guest agent protocol | Separate Product `/agent` listener, live CRL, actual challenge/binding/revocation/reconnect and independent-process proof: Slice 6. This is not a user Files/Development route. |
| Files and transfers | `productweb.Options.Files/Transfers`, `FileService`, `FileClient`, `TransferService`, PostgreSQL and blob ports | Product command does not construct the BFF, Files/transfer services, content store or Guest Files handlers; formal route-to-Guest/storage closure: Slice 8; deployment and published-artifact gates: 11/14/15. |
| Development environments | `DevelopmentService`, `DevelopmentClient`, locked catalog, revision/content ports; Phase 5 `/gate/development` is test-only | Formal authenticated public entry/DTO is absent; define and implement it with real Guest materialization, persistence, content and restart/rollback under Slice 8, then 11/14/15. |
| Recording and catalog | `RecordingService`, KMS envelope adapter, Browser/Desktop live recorders, catalog and Product Web | Content/object-store and service lifecycles are not composed in Product production command; bind encrypted content/retention and formal replay in Slice 8, reject missing deployment in 11 and prove black-box published-artifact E2E in 14/15. |

The Product production `/readyz` signal reports dependencies of its actually
declared composition, not completion of this table. No row becomes ready
solely because a route binds, Guest transport connects, or a service unit
test passes.

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
