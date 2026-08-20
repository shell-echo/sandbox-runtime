# Project Execution Status

Last updated: 2026-08-20

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
- Baseline revision: `203198e45ab7811cfc938be36816ba570ddd83ee`
- Locked Agent Contract revision: `cf623ac7b6c8730a0a609076adaefe5197488667`
- Locked Contract tree: `73cc7c6bbaf541991c7804bded6de22a7928b91b`
- Current phase: P1.1, Provider API admission
- Current slice: P1.1d admission release-gate evidence
- P1.1 release gate: open
- Slices in progress: PR #13 merged protected transport composition at
  `bbb2dc390c091a6b68a2ac67b673ac1effea6fb9`, and PR #14 merged the
  default-disabled operator key-file/guard-state configuration at
  `203198e45ab7811cfc938be36816ba570ddd83ee`. PR #14 CI run `32344672309`
  and post-merge run `32344913375` passed all required jobs. The current
  feature branch adds the P1.1d bearer-lifetime classification fix and the
  all-route admission evidence matrix; no P1.2 state or dispatch was added.

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
| P1.1c: protected-operation admission | Implemented and merged through PR #14; PR and post-merge CI passed | Locked Admission Context is decoded strictly and bound to the verified mTLS caller, protected route, JWS v2 claims, canonical request/read descriptor, and pure gate. All 14 protected paths are matched. Bearer authentication, including self-contained expiry/not-before validity, precedes Context/document validation; explicit configuration loads only frozen public-key files and an exclusive durable guard before it enables protected routes. Successful admission deliberately returns bounded unavailable/error and never calls repository/driver/lifecycle code. |
| P1.1d: admission release gate | In progress on the current feature branch | Local evidence covers all 14 protected paths, request/read-descriptor digest substitution, inactive bearer, replay, stale fencing, cancellation, and concurrent admission. The P1.1 gate remains open pending full local validation, review, PR CI, and any required Contract-owner clarification. |

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

PR #10 merged the P1.1c admission components at
`c107912fe0b7e4930bbd5a666650043d1c41b1ab`. Its pull-request CI run
[`32242490402`](https://github.com/shell-echo/sandbox-runtime/actions/runs/32242490402)
and post-merge main CI run
[`32242739010`](https://github.com/shell-echo/sandbox-runtime/actions/runs/32242739010)
both passed `agent-contract-lock`, `test`, and `docker-integration`. This
proves only the merged component and projection evidence; it did not expose a
protected route or close P1.1.

PR #13 merged protected transport composition at
`bbb2dc390c091a6b68a2ac67b673ac1effea6fb9`. Initial implementation `fdb3424`
passed its local validation. Automated review
then found bearer-authentication precedence, aggregate security-header budget,
closed GET query, trace-correlation, and retry-header gaps. Review-fix commit
`e697afc` addressed them, but its new PR CI merge candidate exposed an existing
Provider listener shutdown race: cancellation could close the listener before
`Shutdown`, which then returned `net.ErrClosed`. Commit `beee48b` makes that
completed close idempotent and passed five race/shuffle Provider API repetitions
plus complete local validation: race/shuffle tests, `go vet`, Contract
lock/projection checks, and tagged Docker integration. Pull-request CI run
[`32342795664`](https://github.com/shell-echo/sandbox-runtime/actions/runs/32342795664)
and post-merge main CI run
[`32343090796`](https://github.com/shell-echo/sandbox-runtime/actions/runs/32343090796)
both passed `agent-contract-lock`, `test`, and `docker-integration`. The command
composition root at that merge still
does not load operator trusted-key paths or instantiate `ProtectedTransportOptions`;
the listener remains discovery-only unless a caller explicitly supplies the
protected options. This is component/feature-branch evidence, not a merged or
production-ready claim.

The current P1.1c configuration-composition branch adds an independently
default-disabled `server.provider.protected_admission` section. Enabling it
requires 1..32 unique `EdDSA` or `ES256` public-key files plus a durable guard
state path. The command composition root reads and freezes the public keys,
retains the single-controller guard lock through service lifetime, passes the
resulting gate to the Provider listener, and releases the guard on later startup
failure or process exit. Partial configuration, a missing/malformed key file,
or unavailable/corrupt guard state fails closed before the listener starts.

Complete local validation for that feature branch passed on 2026-08-20:

- `AGENT_CONTRACT_SOURCE_ROOT=/tmp/agent-blueprints-cf623ac go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- `go run ./cmd/verify-agent-contract -source-root /tmp/agent-blueprints-cf623ac`;
- `SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 go test -tags=integration -count=1 ./driver/docker`; and
- `gofmt` plus `git diff --check`.

This is local component, composition, Contract projection, and Docker-driver
regression evidence only. PR CI, merge review, post-merge CI for the current
P1.1d branch, the P1.1 release gate, aggregate conformance, Platform end-to-end
compatibility,
multi-controller reliability, multi-tenant security, deployment readiness, and
production readiness remain unproven.

P1.1d local evidence then added the bearer-lifetime classification regression
and a generated test-local admission matrix for all 14 protected routes. The
focused race-enabled Provider API matrix passed on 2026-08-20. It proves only
the tested transport/gate boundary; it does not substitute for repository or
driver dispatch evidence, CI, or the P1.1 release gate.

## Open gate and unproven claims

P1.1 is not complete. Its architecture release gate still requires Schema and
fixture compatibility, mTLS discovery, token binding, digest substitution,
expiry, replay, stale-fencing admission tests, transport composition review,
and reproducible CI evidence to pass.

The current revision does not prove or claim:

- P1.1d PR review/CI or closure of the P1.1 release gate;
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
static/file trusted-key source, a shared TLS/request identity extractor, a
durable single-controller guard, and a merged protected transport adapter. The
immediate entry is completion of P1.1d full local validation, review, and CI
for the bounded admission matrix. No P1.2 lifecycle or repository/driver
dispatch may be added before the P1.1 release gate closes.
The detailed scope,
acceptance evidence, and stop conditions are in
[the P1.1c admission plan](plan/p1.1c-protected-operation-admission.md).

Mutation routes, full operation admission, lifecycle dispatch, and P1.2 work
remain outside the current planning unit. Landing future code alone does not
close P1.1.

## Maintenance rule

Update this document whenever a slice starts, lands, is blocked, or changes the
evidence available for a release gate. Keep plans focused on intended scope and
acceptance criteria; keep current execution truth here.
