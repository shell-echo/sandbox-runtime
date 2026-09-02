# ADR 0017: Optional Profile Readiness and Contract-First Delivery

- Status: Accepted for P4 authority planning
- Date: 2026-09-02

## Context

The architecture lists browser, desktop, port-forward, snapshot/restore, GPU,
nested-container, and stronger-isolation profiles as optional capabilities. The
current repository-owned Provider Contract and implementation authorize only the
bounded coding/shell profile and terminal session behavior. The current
semantic rules explicitly forbid browser, desktop, and port-forward runtime
requests from the terminal-session route. No optional runtime image, guest
endpoint protocol, or deployable caller-owned Gateway policy is available.

The internal Block manifest foundation provides a validated description of a
future runnable block, but a manifest is not evidence that its image, driver,
session protocol, authorization, or isolation policy is ready. The real Agent
Platform caller and migration traffic harness are also still unavailable, so a
local profile test cannot close the P3 or production gates.

## Decision

P4 is delivered one optional profile at a time, with Contract authority decided
before Provider implementation. This planning slice changes no Provider route,
DTO, schema, semantic rule, capability advertisement, runtime image, or
production configuration.

Each profile must carry an explicit readiness record covering:

- locked capability and runtime-profile identifiers and versions;
- supported architectures, immutable image digest, image provenance, and
  reproducible build or publication source;
- stable guest mounts, entrypoint/argv, user identity, resource limits, and
  network policy;
- the provider-local session/endpoint boundary and caller-owned Gateway
  authorization, revocation, audit, and reconnect policy;
- operation, artifact, and usage evidence ownership and retention; and
- profile-specific security, fault, concurrency, restart, and expiry cases.

The delivery order is:

1. Browser authority audit and Contract gap inventory.
2. Desktop authority audit and Contract gap inventory.
3. Workspace snapshot/restore, only after its digest, secret-exclusion, and new
   identity semantics are authorized.
4. Port-forward, only after explicit egress, target, and caller authorization
   rules exist.
5. GPU, nested-container, and stronger-isolation profiles after their
   host/device security and deployment evidence is available.

The first implementation candidate is browser, but its first slice is an
authority audit and fixture design. It must not reuse terminal-session routes or
advertise `sandbox.browser` until the Contract, runtime, Gateway, usage, and
security gates are independently complete. Desktop follows the same boundary;
it is not a fallback implementation of browser behavior.

## Release gates

An optional profile may be advertised only after all of these named gates pass:

1. Contract/OpenAPI, schema, semantic-rule, fixture, DTO, projection, and
   Conformance Suite authority is locked.
2. Provider component ports, repositories, runtime adapter, and operation
   reconciliation pass focused success, rejection, cancellation, restart,
   expiry, and unknown-outcome tests.
3. The image is reproducibly built or published, pinned by digest, checked for
   architecture and provenance, and exercised with the declared mounts,
   identity, limits, and network policy.
4. Session and data-plane behavior uses a private endpoint and caller-owned
   Gateway authorization, revocation, recording, and reconnect controls.
5. Artifact and usage evidence is bounded, correlated to Provider operations,
   and explicitly separate from platform publication and billing truth.
6. Profile-specific fault, concurrency, cross-tenant, egress, privilege,
   secret-exclusion, and resource-boundary tests pass.
7. The independently owned reference/platform caller runs the locked scenarios
   over real process and network boundaries.

Aggregate conformance, multi-controller reliability, migration readiness,
deployment, and production readiness remain separate gates. A passing local
profile test or a valid Block manifest cannot substitute for them.

## Consequences

- The Block manifest can evolve as an internal composition input without
  silently becoming Provider protocol authority.
- Browser and desktop work can proceed through source-backed audits and
  reproducible image preparation while the real platform caller is blocked.
- Optional capability advertisement remains empty unless the complete profile
  dependency graph and its named gates pass.
- Any future Contract change must update the repository-owned lock, projections,
  fixtures, Conformance Suite, and the corresponding evidence ledger together.
