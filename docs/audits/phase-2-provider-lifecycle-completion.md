# Phase 2 Provider Lifecycle Completion

- Date: 2026-09-18
- Status: complete for the fixed nine-step Phase 2 scope
- Scope authority: ADR 0048 and the nine-step Phase 2 plan
- Implementation revision: `98995384c60a924f25ca58d3b7e561207bfa5be8`
- Lock-selection revision: `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`

## Result

Phase 2 completes the planned Provider lifecycle closure:

- reversible `ready`/`suspended` desired-state control;
- bounded lease renewal and reconciled expiry cleanup;
- irreversible explicit termination with exact-owned runtime absence proof;
- finite lifecycle-event pages with durable high-water cursors, bounded
  retention, explicit `409` ahead and `410` expired gaps;
- terminal-session close with durable intent, handoff revocation, exact
  allocation cleanup, absence confirmation, replay, restart recovery, and
  immutable unknown-attempt evidence; and
- optional all-or-nothing `sandbox.lifecycle-control@1.0.0` and
  `sandbox.terminal-control@1.0.0` capability composition.

Provider wire DTOs remain separate from lifecycle, repository, terminal, and
Docker types. The calling service continues to own business desired state,
end-user authorization, aggregate operations, public Gateway policy, and final
workflow decisions.

## Selected Contract authority

The exact lock selects Provider and Contract revision
`98995384c60a924f25ca58d3b7e561207bfa5be8` with Contract tree
`0a627baed11c8a6ddbe8a24bbc1869e4f85edc16`.

- manifest:
  `sha256:f1a4e787f5dc5fecc85c6f6ed54385925686dfc1ced749caca5522805320c799`
- OpenAPI:
  `sha256:f4301829d52969516d8551e14b7aee064628bec01e1d7d3613be3fa89579efdb`
- semantic rules:
  `sha256:0bf737c9dc242a0a7e32a1a86261fa1fc96b3124eeb2510738af274de53a2026`
- local Suite: 60 cases, digest
  `sha256:7db1d28d35ca193632c395247cc71eeaaff48b027964b9ea9da247eaad5e3991`
- remote Suite: unchanged 6 cases, digest
  `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0`

The coordinated authority includes five Provider operations, five closed
request/response schemas, fixtures, admission-operation bindings, semantic
rules, capability identities, operation types, Calling Standard choreography,
DTO projections, and seven additional local Suite cases.

## Implementation evidence

The selected implementation adds atomic durable mutation reservation; durable
event high-water marks and bounded retention; exact-owned fake and Docker
lifecycle controls; pending-operation and lease-expiry reconciliation; a
versioned terminal-close record family; protected strict transport; and
fail-closed readiness before capability advertisement.

The root and E2E modules pass full race/shuffle and vet. All eight E2E lock
checks pass. The Provider Contract and qualification-profile verifiers pass,
as do the qualification report/evidence tests. The clean VCS-built local
Conformance Runner executed all 60 cases with race detection and shuffle. The
tagged Docker lifecycle integration passes, including suspend/resume
observation, terminal and exec cleanup, exact removal, and mount-root cleanup.

## Independent-process lifecycle evidence

The repository-owned reference caller and reference stack ran as independent
OS processes through the protected Provider wire surface. Evidence directory
`e2e/evidence/20260918T074038.371995000Z` records:

- 15 initial coding/shell scenarios;
- 5 restart/reconstruction scenarios; and
- 9 lifecycle scenarios.

The lifecycle phase proves five-capability discovery, retained events after
restart, suspend and resume observation, cursor continuation, lease extension
without generation drift, durable terminal close, reconnect denial, explicit
termination, runtime absence, and final lifecycle events. The run used runtime
image digest
`sha256:9e99f925546b9acdaf858da4d11f162e0121e6d12cd2d52bde4c022ae1819dfc`.

This is independent-process black-box evidence from a repository-owned
reference caller. It is not evidence from a separately implemented external
caller and does not relabel the earlier independent external-caller
qualification.

## Claim boundary

Phase 2 remains single-controller development and reference evidence. It does
not establish independently implemented external-caller interoperability for
the new lifecycle operations, multi-controller storage, hostile-multitenant
isolation, HA, deployment qualification, or production readiness.

Phase 2 also excludes snapshot/restore, terminal resize, Browser-session close,
Product persistence and APIs, a public Gateway, Guest Agent work, and
deployment changes. Reserved names or existing runtime primitives do not
authorize any of those families.
