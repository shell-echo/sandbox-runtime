# Product v1 Phase 6 Production Startup Audit

Date: 2026-09-20

Status: startup authority and gap audit complete; implementation begins with
the fixed Phase 6 plan at **1/15**.

## Question audited

What is still missing between the accepted Product Phase 5 release topology
and a deployable, operable, production-qualified Product system?

The premise that Phase 5 already supplied a production deployment is false.
Its five roles are independent OS processes inside one strict, same-repository,
single-host release harness. The production command, operator configuration,
independent failure domains, HA, backup/restore, SLO evidence, and deployment
artifacts remain outside that result.

## Authority reviewed

This audit applies the Provider and Product Contracts, `AGENTS.md`,
`PROJECT_CONTEXT.md`, `README.md`, `architecture.md`, `development.md`, ADR
0047, the Phase 3-5 completion audits, and the Docker, Apple Container, and
Kubernetes application-deployment assets. Phase 6 ordering is fixed by
[`product-v1-phase-6-production-hardening.md`](../plan/product-v1-phase-6-production-hardening.md)
and ADR 0051.

## Capability and operations inventory

| Area | Fact at the Phase 5 baseline | Missing release authority |
| --- | --- | --- |
| Product | Domain, PostgreSQL adapter, authenticated transport components, workers, Web, recording, and Phase 5 release composition exist. There was no ordinary Product command or operator configuration. | Deployable command, production identity, role-separated migrations, complete dependency readiness, replicas, deployment and operations evidence. |
| Provider | `sandbox-runtime serve` can expose the local API and a default-disabled protected Provider listener. Current lifecycle, exec, terminal, artifact, usage, and Browser command adapters are development/single-controller compositions; Desktop is not production-composed. | Production persistence/reconciliation, Desktop graph, deployable topology, HA, deployment and operations gates. |
| Gateway | Terminal, Browser, and Desktop Gateway components plus strict release-harness compositions exist. | One deployable public process with production TLS/relay, distributed authority, rollout and SLO evidence. |
| Guest | Guest protocol, files, development materialization, restart behavior, and a release-harness role exist. | Published deployable agent, bootstrap/rotation, upgrade compatibility, least-privilege policy and independent deployment evidence. |
| Browser/Desktop runtime roles | Signed Browser and Desktop runtime authorities and bounded real-adapter evidence exist. | Operator-owned process configuration, private identity, independent lifecycle, media/relay sizing, upgrade and production evidence. |
| PostgreSQL | Thirteen Product migrations and real-adapter tests exist. | Migration/runtime role separation, HA, capacity, backup, restore, PITR, failure-domain and upgrade evidence. |
| Valkey-compatible coordination | Shared capacity, revocation and fencing adapters have real-backend component and bounded caller evidence. | Production ACL roles, HA/failover, persistence policy, independent failure domain, restore and operations evidence. |
| Recording/content storage | Encrypted local stores and cleanup/integrity tests exist. | External object-storage adapter, KMS-backed keys, retention/legal policy, backup/restore and failure-domain evidence. |
| Identity and secrets | Provider has one exact issuer-scoped mTLS/JWS trust domain. Phase 3-5 Product gates use frozen test identities and generated keys. | Production Product identity, workload identity, secret references, KMS/HSM envelope keys, rotation/revocation and break-glass evidence. |
| Network and transport | Component TLS, Origin, relay-only and private mTLS policies exist. | Complete service-to-service policy, certificate automation, private ingress/egress, DNS/metadata defenses and deployment enforcement evidence. |
| Supply chain | Exact runtime images are digest-bound and selected publications are signed/attested. The application Dockerfile uses mutable bases and no general application image is published. | Reproducible multi-platform application images, SBOM, signature/provenance policy and admission evidence. |
| Observability | Safe logs, audit records and evidence manifests exist. | Metrics/traces, alerting, RED/saturation signals, SLO calculations, privacy review and failure-injection correlation. |
| Deployment assets | Docker, Apple Container and Kubernetes development smokes exercise the fake local runtime. | Role-specific manifests/images, secrets, persistent state, probes, disruption/availability, upgrades and deployment release gates. |

## Conclusions

1. Phase 6 must not start by enabling every Phase 5 component in the existing
   root `serve` command. That would collapse Product/Provider/local API
   authority and turn test fixtures into operator configuration.
2. Process identity, strict configuration, health/readiness semantics, durable
   dependencies and deployment evidence must advance in dependency order.
3. PostgreSQL, coordination, and object storage need independently named
   failure and backup domains. Co-location in a test runner cannot establish
   those properties.
4. Production and future hostile-multitenant claims remain separate. A
   production release may still target trusted tenant workloads unless and
   until the hostile-input isolation gate passes.
5. Docker, Apple Container, and Kubernetes are application deployment
   environments, not implicit Provider runtime drivers.

## First slice selected

Phase 6 Slice 1 introduces an independent `product serve` command with a
strict development-only configuration section, private bounded secret files,
frozen development identity bindings, real PostgreSQL migration/storage, and
separate liveness/readiness probes. Runtime capability advertisement remains
empty and Workspace creation fails closed because no Provider policy is
composed. See
[`product-phase-6-slice-1.md`](product-phase-6-slice-1.md).

This is the smallest real process boundary that removes the earlier
"test-harness-only Product role" gap without claiming standalone or production
qualification.
