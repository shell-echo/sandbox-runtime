# Project Execution Status

Last updated: 2026-08-01

This document is the single local source of truth for current execution status:
what has landed, which release gates remain open, and which implementation
slice is next. It does not redefine protocol, architecture, engineering rules,
or release criteria.

When sources disagree, authority remains with the locked upstream Agent
Contract, followed by accepted ADRs and `docs/architecture.md`, then
`docs/development.md` and the applicable implementation plan. This document
reports progress against those authorities.

## Current snapshot

- Baseline branch: `main`
- Baseline revision: `255c927`
- Current phase: P1.1, Provider API admission
- Next planned slice: P1.1b, mTLS-only capability discovery
- P1.1 release gate: open
- Slice in progress: none recorded

## Delivery status

| Scope | Status | Evidence boundary |
| --- | --- | --- |
| P1.0: contract intake and ownership freeze | Closed | Contract identity and ownership-boundary evidence only. |
| P1.1a: wire DTO and Contract validation harness | Implemented and merged into `main` | Component and locked Contract projection evidence only. |
| P1.1b: mTLS-only capability discovery | Planned; not started | No implementation or validation evidence yet. |
| P1.1c: protected-operation admission | Not started | No implementation or validation evidence yet. |
| P1.1d: admission release gate | Not started | P1.1 remains open. |

P1.0 closed at revision `102f36a6240a4c33892b0ebc25232859b63e334c`.
P1.1a reached `main` through merge revision `255c927`.

## Recorded evidence

The P1.1a plan records validation on 2026-07-30 using the project Go 1.26
container toolchain:

- race-enabled, shuffled Go tests;
- `go vet ./...`;
- Agent Contract lock verification against a read-only checkout;
- Provider projection validation for the locked OpenAPI document schemas,
  operation body limits, upstream examples, and locally constructed response
  documents described in the plan;
- `git diff --check`.

The tagged Docker integration test was not required because P1.1a did not
change driver or lifecycle behavior. The authoritative command details and
evidence counts remain in the
[P1.1 implementation plan](plan/p1.1-provider-api-admission.md#p11a-validation-record).

## Open gate and unproven claims

P1.1 is not complete. Its architecture release gate still requires Schema and
fixture compatibility, mTLS discovery, token binding, digest substitution,
expiry, replay, and stale-fencing admission tests to pass.

The current revision does not prove or claim:

- HTTP Provider routing or mTLS capability discovery;
- JWS verification, digest binding, replay protection, or fencing admission;
- P1.2 lifecycle, durable operations, leases, events, or reconciliation;
- the aggregate `sandbox-core-v1` conformance profile;
- Agent Platform end-to-end compatibility or cross-provider interchangeability;
- multi-controller reliability, multi-tenant isolation, deployment readiness,
  or production readiness.

## Next implementation slice

P1.1b is the only next planned slice. Its scope is limited to a separate
Provider router and `GET /v1/capabilities`, with an admitted control-plane
client certificate, an immutable capability document supplied through an
application port, and response projection enforcement.

Mutation routes, operation bearer tokens, JWS admission, lifecycle dispatch,
and P1.2 work remain outside this slice. Completion requires the P1.1 plan's
P1.1b acceptance evidence; landing code alone does not close P1.1.

## Maintenance rule

Update this document whenever a slice starts, lands, is blocked, or changes the
evidence available for a release gate. Keep plans focused on intended scope and
acceptance criteria; keep current execution truth here.
