# Project Execution Status

Last updated: 2026-08-02

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
- Baseline revision: `6863429`
- Current phase: P1.1, Provider API admission
- Current slice: P1.1c planning, protected-operation admission
- P1.1 release gate: open
- Slices in progress: none; P1.1c planning is next

The implemented Provider discovery listener is separate from the local
management API and remains disabled by default. When enabled, it accepts TLS
1.2 or newer and requires both normal client certificate verification and an
exact URI SAN match from an operator-configured allowlist of fragment-free
absolute URI identities. No URI scheme is hard-coded. Failed certificate or
URI identity admission is rejected during the TLS handshake before HTTP routing.
The only registered Provider operation is `GET /v1/capabilities`; its immutable
raw v1 response contains empty `capabilities` and `runtime_profiles` arrays and
at least one required content-addressed compatibility profile. The profile is
descriptive metadata and does not advertise snapshot, restore, or another
runtime capability.

## Delivery status

| Scope | Status | Evidence boundary |
| --- | --- | --- |
| P1.0: contract intake and ownership freeze | Closed | Contract identity and ownership-boundary evidence only. |
| P1.1a: wire DTO and Contract validation harness | Implemented and merged into `main` | Component and locked Contract projection evidence only. |
| P1.1b: mTLS-only capability discovery | Implemented and verified on `main` | Application model, immutable source, response mapping, exact GET-only routing, mTLS identity admission, default-disabled configuration, composition, enabled-listener behavior, emitted-response projection, fail-together lifecycle, and tagged Docker integration evidence passed. |
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

P1.1b unit 1 was validated on 2026-08-01 with Go 1.26 in Apple Container:

- focused and full-repository race-enabled, shuffled Go tests;
- focused and full-repository `go vet`;
- Agent Contract lock verification against the locked read-only checkout;
- the existing P1.1a Provider projection regression;
- `git diff --check`.

P1.1b units 2-4 were then implemented and validated on 2026-08-01 with the
same toolchain and locked Contract checkout:

- full-repository race-enabled, shuffled Go tests;
- full-repository `go vet`;
- Agent Contract lock verification;
- the existing P1.1a Provider projection regression;
- validation of the actual emitted capability response against the locked
  capability Schema;
- `git diff --check`.

The final composition unit was implemented and validated on 2026-08-01. It
adds the separately named Provider HTTPS server at the composition root,
explicit configuration-to-application mapping, real mTLS listener evidence,
plaintext rejection, and cancellation-safe fail-together startup. Cross-review
identified and the implementation fixed an existing shutdown-before-bind race,
late signal registration, cancellation error misclassification, and test
listener TOCTOU.

The complete local validation passed:

- full-repository race-enabled, shuffled Go tests;
- full-repository `go vet`;
- Agent Contract lock verification at revision
  `0c91871fa469e951b8a508fe735a2a9a5797a67e`;
- the P1.1a locked Provider projection regression;
- the P1.1b emitted capability response Schema projection;
- `git diff --check`.

Because the composition unit hardens the shared server lifecycle, the tagged
Docker integration command became mandatory. It was executed in Apple
Container with `SANDBOX_RUNTIME_DOCKER_INTEGRATION=1`, but both integration
tests stopped before exercising the driver because no Docker Engine socket
exists at `/var/run/docker.sock`. This is recorded as an unavailable required
environment, not as a passing gate or a code failure. Apple Container is the Go
toolchain host here; it is not a Docker Engine API endpoint.

GitHub Actions CI run
[`30690971538`](https://github.com/shell-echo/sandbox-runtime/actions/runs/30690971538)
then validated revision `78bc9e27d1edbf39a982758c0c9b0f44a00477ba`
on 2026-08-01. All three jobs passed:

- `agent-contract-lock`, including both locked Provider projections;
- `test`, including full-repository race-enabled shuffled tests and `go vet`;
- `docker-integration`, including the required tagged Docker integration tests
  against the GitHub-hosted Docker Engine.

This closes P1.1b only. It does not close the P1.1 admission release gate.

## Open gate and unproven claims

P1.1 is not complete. Its architecture release gate still requires Schema and
fixture compatibility, mTLS discovery, token binding, digest substitution,
expiry, replay, and stale-fencing admission tests to pass.

The current revision does not prove or claim:

- JWS verification, digest binding, replay protection, or fencing admission;
- P1.2 lifecycle, durable operations, leases, events, or reconciliation;
- the aggregate `sandbox-core-v1` conformance profile;
- Agent Platform end-to-end compatibility or cross-provider interchangeability;
- multi-controller reliability, multi-tenant isolation, deployment readiness,
  or production readiness.

## Next implementation slice

The next action is to plan P1.1c protected-operation admission against the
locked Contract before changing behavior. That plan must decompose token
verification, request-digest substitution, expiry, replay protection, and
stale-fencing admission into independently reviewable units with explicit
Contract and security evidence.

Mutation routes, operation bearer tokens, JWS admission, lifecycle dispatch,
and P1.2 work remain outside the current slice. Landing code alone does not
close P1.1.

## Maintenance rule

Update this document whenever a slice starts, lands, is blocked, or changes the
evidence available for a release gate. Keep plans focused on intended scope and
acceptance criteria; keep current execution truth here.
