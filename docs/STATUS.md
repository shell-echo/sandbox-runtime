# Project Execution Status

Last updated: 2026-08-19

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
- Baseline revision: `c9cb48240fdcff472d6e594b70e6c36cb5147a6a`
- Current phase: P1.1, Provider API admission
- Current slice: P1.1c.4b.2b.3 protected transport composition
- P1.1 release gate: open
- Slices in progress: the P1.1c protected transport is blocked. The locked
  request/descriptor input cannot independently supply complete admitted
  operation context for post-create mutation or read binding, and P1.2 is the
  phase that owns durable SandboxOperation state. No route, listener setting,
  local context cache, or token-claim echo is permitted as a workaround.

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
| P1.1b: mTLS-only capability discovery | Implemented and verified on `main`; transport reconciliation merged through PR #9 | Application model, immutable source, response mapping, exact GET-only routing, mTLS identity admission, default-disabled configuration, composition, enabled-listener behavior, emitted-response projection, fail-together lifecycle, tagged Docker integration, strict query/body input evidence, and transport reconciliation CI passed. The `400`/`501` operation-level error-wire authority gap remains separately pending. |
| P1.1c: protected-operation admission | Blocked at protected transport composition; local components implemented | ADR 0002 defines local trust, caller binding, guard, response precedence, and the admitted-operation-context precondition. The pure key, clock, and mutation-guard ports, frozen static and bounded-file trusted public-key sources, bounded compact-JWS verification, strict bounded RFC 8785 request/descriptor digest verification, application gate, shared TLS/request identity extractor, and atomically persisted guard exist as component evidence. The locked route inputs do not independently supply the complete admitted operation context for post-create mutations and reads; P1.2 owns the durable state that would do so. No protected route, repository/driver dispatch, or P1.2 state has been implemented. |
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

Post-closure input-boundary hardening landed at revision `e85d2c2` on
2026-08-02. It rejects local API/Provider port reuse before startup, bounds TLS
material and CA count, rejects non-regular TLS material without blocking on a
FIFO, and centralizes bounded fragment-free URI identity validation. Apple
Container validation passed the full race-enabled shuffled test suite,
`go vet`, the locked Agent Contract verifier, and both mandatory Provider
projections. The tagged Docker integration test was not required because this
hardening changes neither a runtime driver nor lifecycle behavior. GitHub CI
evidence for this revision has not yet been recorded; the earlier P1.1b CI run
does not substitute for it.

Revision `fae94fd49a82d4a84092e3397d2b0a19f611d61c` records the resulting
Provider hardening evidence, and GitHub Actions run
[`30754320465`](https://github.com/shell-echo/sandbox-runtime/actions/runs/30754320465)
passed its Agent Contract lock/projections, race-enabled shuffled tests and
vet, and tagged Docker integration jobs. That CI proves only the tested main
revision, not the P1.1 release gate.

PR #8 merged strict capability-discovery input handling at
`7b0bd13803a1720859ad0c167627db5aca496261`. Its pull-request CI run
[`32209203243`](https://github.com/shell-echo/sandbox-runtime/actions/runs/32209203243)
passed for `87ed45c0b94c2ca6c7c10e22ed1b4eec182fc6a9`, and the post-merge main
CI run
[`32210577595`](https://github.com/shell-echo/sandbox-runtime/actions/runs/32210577595)
passed for that merge commit. Those runs close the previously pending PR/CI
evidence for strict query/body input handling. They do not close the P1.1
release gate or prove `sandbox-core-v1`, Agent Platform end-to-end behavior,
multi-controller or multi-tenant properties, deployment, or production
readiness.

For request metadata visible to the handler, the follow-on transport
reconciliation keeps query strings (including a bare trailing `?`), nonzero or
unknown `Content-Length`, and `chunked` transfer encoding fail closed with an
empty `400` before capability, application, repository, or driver dispatch.
The handler does not read or probe `Body`; this does not claim that the Go
server lifecycle never reads or drains framing. A real mTLS HTTP/1.1 test also
records that unsupported `Transfer-Encoding: gzip` is rejected by the Go parser
with its standard-library `501` before the handler. The test makes no claim for
HTTP/2 or other Go versions. The locked operation lists neither `400` nor `501`
in its response list, and its generic malformed-request component does not
grant operation-level wire authority. Upstream clarification remains pending;
no new error status or body is introduced here.

PR #9 merged that transport reconciliation at
`c9cb48240fdcff472d6e594b70e6c36cb5147a6a`. Its pull-request CI run
[`32228848484`](https://github.com/shell-echo/sandbox-runtime/actions/runs/32228848484)
and post-merge main CI run
[`32229889627`](https://github.com/shell-echo/sandbox-runtime/actions/runs/32229889627)
both passed `agent-contract-lock`, `test`, and `docker-integration`. This
closes only the transport-reconciliation evidence; it does not resolve the
separate discovery error-wire authority gap or close P1.1.

## Open gate and unproven claims

P1.1 is not complete. Its architecture release gate still requires Schema and
fixture compatibility, mTLS discovery, token binding, digest substitution,
expiry, replay, and stale-fencing admission tests to pass.

The current revision does not prove or claim:

- transport-wired mTLS caller admission, replay/fencing rejection before an
  actual Provider dispatch, or protected-route behavior;
- P1.2 lifecycle, durable operations, leases, events, or reconciliation;
- the aggregate `sandbox-core-v1` conformance profile;
- Agent Platform end-to-end compatibility or cross-provider interchangeability;
- multi-controller reliability, multi-tenant isolation, deployment readiness,
  or production readiness.

## Next implementation slice

P1.1c now has the accepted local trust and admission-state decision in
[ADR 0002](adr/0002-provider-operation-admission.md), a bounded compact-JWS
parser/verifier, strict canonical request/descriptor digest verification,
application-level context/time binding, a pure protected-operation gate, a
static/file trusted-key source, a shared TLS/request identity extractor, and a
durable single-controller guard. Protected transport composition is blocked on
an authoritative admitted-operation context that is not provided by the locked
route inputs and cannot be replaced by P1.2 state early. The detailed scope,
acceptance evidence, and stop conditions are in
[the P1.1c admission plan](plan/p1.1c-protected-operation-admission.md).

Mutation routes, full operation admission, lifecycle dispatch, and P1.2 work
remain outside the current planning unit. Landing future code alone does not
close P1.1.

## Maintenance rule

Update this document whenever a slice starts, lands, is blocked, or changes the
evidence available for a release gate. Keep plans focused on intended scope and
acceptance criteria; keep current execution truth here.
