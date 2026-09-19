# ADR 0050: Product Desktop Phase 5 Boundary

- Status: Accepted for Product Phase 5 scope; Slices 1-2 are implemented
- Date: 2026-09-19

## Context

Product design already reserves a Desktop slot, Desktop session kind, and
`product-desktop.v1`, but those names are not an implementation or readiness
claim. At the Phase 5 baseline the locked Provider Contract did not authorize
Desktop. The repository also lacked a Desktop runtime image, display/input
broker, Provider application and adapter, Product persistence and
reconciliation, public data plane, recording composition, and unified Product
experience.

Starting with Product persistence would require Product code to invent a
Provider wire shape. Starting with a runtime image or driver would create an
unreviewed private protocol without stable lifecycle, security, cleanup, or
evidence semantics. Reusing Terminal or Browser routes would conflate distinct
session and data-plane authorities.

## Decision

Product Phase 5 follows the fixed 15-slice order in
`docs/plan/product-v1-phase-5-desktop-development-unified-product.md`.

The first slice is Provider Contract-first. Desktop has a separate capability,
capability profile, runtime profile, resource class, open/close lifecycle,
handoff document, operation family, usage meter, admission binding, and
Conformance cases. Terminal and Browser routes, DTOs, handoffs, profiles, and
runtime components cannot be used as Desktop substitutes.

Provider owns controller-to-Provider authentication and admission,
Provider-local execution, durable Provider operations, opaque handoff
resolution, generation and expiry enforcement, revocation, cleanup, and usage
evidence. Product owns business truth: users, tenants, Workspaces, slots,
sessions, desired state, aggregate operations, end-user grants, one-controller
leases, quotas, policy, audit, reconnect decisions, recording/catalog, and the
public Gateway.

The Provider handoff contains only an opaque `ref:desktop-session:*`, fixed
media/control profile identifiers, connection generation, and expiry. Public
signaling, relay credentials, session descriptions, candidates, and end-user
authorization belong outside the Provider control API. Raw addresses, ports,
backend identifiers, credentials, host paths, and diagnostics never enter the
stable Product or Provider DTOs.

The initial media authority is display video with optional audio output.
Keyboard, pointer, touch, clipboard, and transfer require explicit bounded
Product policy and current controller authority. Microphone input, camera
input, and host-device forwarding are denied. One session has at most one
controller; multi-user collaboration, controller queues, shared cursors, and
simultaneous control are deferred.

Desktop capability advertisement is the conjunction of the exact locked
Contract, Provider application/repository, verified immutable runtime image,
runtime adapter, broker, private resolver, revocation and cleanup, usage
evidence, and readiness graph. Product capability advertisement additionally
requires Product persistence/reconciliation, exact Provider adaptation,
public Gateway, grants/leases/policy, recovery, recording/catalog, Web
experience, and the final release gate. Until those dependencies pass,
advertisement remains empty.

## Slice 1 authority

Slice 1 authorizes and projects only the Provider Desktop wire behavior. The
locked authority includes exact open/read/handoff/close semantics,
revoke-before-cleanup expiry behavior, absorbing terminal states, strict
request digests and replay protection, safe errors, capacity signaling,
nondisclosure, and correlated duration usage evidence. Every new Suite case is
mapped to an executable repository test.

No runtime, driver, image, Guest protocol, public route composition, Product
state, or Web feature is enabled by this slice.

## Slice 2 Product authority

Product Desktop intent is now a separate durable authority. A Desktop slot has
the immutable exact shape `desktop` / `sandbox-runtime-desktop-v1` /
`sandbox.desktop@1.0.0` / `desktop-v1`. A Product Desktop session has the exact
kind/profile pair `desktop` / `product-desktop.v1`, is bound to one current
ready Desktop slot generation, and follows the Product-owned absorbing session
state machine.

The authenticated Product API remains generic at its Contract-authorized slot
and session routes, but strict application validation and PostgreSQL migration
8 reject every alternate Desktop shape. Expected versions, mutation digests,
tenant quotas, and database serialization resolve concurrent commands. One
transaction commits Product state, operation, event, security audit,
idempotency result, and external-work intent.

Desktop session intents use the separate `desktop_session.open` and
`desktop_session.close` outbox family. Existing Terminal and Browser workers
cannot lease them; Browser slot workers also filter `slot.reconcile` by slot
kind. There is deliberately no Desktop dispatcher until the Provider and
network adapter slices exist. Capability advertisement remains empty.

## Consequences

- Product Desktop persistence begins only after the Provider wire authority is
  immutable and selected by the repository lock.
- Provider and Product implementations can evolve behind explicit ports while
  preserving their separate sources of truth.
- Close and expiry cannot report success until the handoff is revoked, active
  media/control authority is terminated, owned runtime resources are cleaned,
  and exact absence is confirmed.
- Unknown outcomes are reconciled from retained evidence; they are never
  blindly redispatched.
- Historical qualification definitions retain dedicated immutable-revision
  locks; they are not silently rebound to the current Desktop-extended
  authority.
- Phase 5 completion requires the named independent-process Slice 15 gate.
  It still does not establish multi-user collaboration, HA, hostile
  multi-tenant isolation, production deployment, or general production
  readiness. Those remain later scopes.
