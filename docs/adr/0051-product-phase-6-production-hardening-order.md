# ADR 0051: Product Phase 6 Production Hardening Order

- Status: accepted
- Date: 2026-09-20

## Context

Product Phases 3-5 established bounded same-repository release topologies and
substantial Product, Provider, Gateway, Guest, Browser, Desktop, persistence,
and recording components. Phase 5 closes its exact 15-slice plan, but its
strict five-process gate remains single-host and test-harness owned. It does
not supply production commands, role-specific deployment assets, independent
failure domains, HA, backup/restore, SLOs, upgrade operations, or a production
release decision.

ADR 0047 defines assurance levels and prohibits deriving production readiness
from packaging or component tests. The Phase 6 startup audit also finds that
enabling the full Phase 5 graph in the existing root `serve` command would mix
the unauthenticated local API, Provider execution authority, and Product
business authority.

## Decision

Adopt the fixed 15-slice order in
[`product-v1-phase-6-production-hardening.md`](../plan/product-v1-phase-6-production-hardening.md).
The order begins with independent process/configuration boundaries, then adds
production identity and storage authority, deploys every runtime role, hardens
network/secrets/supply chain, proves data recovery and observability, and only
then runs upgrade, hostile-input, independent deployment, release-candidate,
and final release gates.

Each role is a separate process and configuration authority. Product remains a
caller of the locked Provider network Contract. The local `/instances` API,
Provider `/v1/*`, and Product `/api/v1/*` surfaces do not share wire DTOs,
identity, readiness, or durable truth.

Phase 6 Slice 1 is development-only. It may expose an independently deployable
Product API process backed by real PostgreSQL and frozen private identity
bindings, but it must advertise no runtime capability and reject Workspace
creation until a later slice composes exact Provider readiness. Standalone and
production configuration fail at startup.

Production readiness can be stated only after Slice 15 accepts an immutable
release candidate with reproducible evidence. Hostile-multitenant readiness is
not implied by that result and retains its separate gate.

## Consequences

- The first Product command is useful for process/deployment integration while
  remaining fail closed for runtime mutations.
- Production identity, KMS, external object storage, replicas and complete
  capability composition are deliberately later slices, not hidden defaults.
- Packaging smokes and same-runner tests remain lower evidence tiers.
- Any change in slice order, authority ownership, or a stable protocol requires
  an ADR update and the applicable Contract review.
