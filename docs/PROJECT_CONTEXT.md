# Project Context

Updated: 2026-09-02

This is the stable entry point for a new developer, AI agent, development
device, or implementation session. It summarizes the system, engineering
constraints, current maturity, and next work. It is an index and verified
snapshot, not a second copy of the Contract or architecture.

## Start Here

Read this document after `AGENTS.md`, then verify the checkout before relying on
the snapshot:

```bash
git status --short --branch
git branch -vv
git rev-parse HEAD main origin/main
git log --oneline --decorate -8
```

Preserve uncommitted work. Do not reset, switch away from a dirty checkout, or
assume that a recorded evidence baseline is the current `HEAD`.

Use these sources in authority order:

1. The repository-owned MIT Provider Contract under `contract/`, including its
   OpenAPI, JSON Schemas, semantic rules, fixtures, Conformance Suite, and
   `compatibility/sandbox-runtime/contract.lock.json`, defines authorized wire
   behavior.
2. [`architecture.md`](architecture.md) and accepted
   [ADRs](adr/) define ownership, boundaries, delivery order, and release
   gates.
3. [`development.md`](development.md) and `AGENTS.md` define engineering and
   validation rules.
4. [Phase plans](plan/README.md) refine implementation slices without relaxing
   architecture gates.
5. [`STATUS.md`](STATUS.md) is the detailed evidence ledger. Code, Git state,
   and reproducible test or CI results must still support every status claim.

For a caller-facing summary of the locked Provider routes, ownership boundary,
admission rules, and integration checklist, read the
[`Provider Integration Profile`](platform-integration-profile.md). It is a
navigation guide only; the Contract resources and lock remain authoritative.

When sources disagree, do not silently blend them. Apply the higher-authority
source, verify the implementation, and update the stale narrative document.

## System in One Page

`sandbox-runtime` is a backend-independent sandbox Provider and local runtime
control plane. The first intended compatibility profile is coding and remote
shell. Browser, desktop, snapshots, GPU, and stronger isolation remain optional
until their own Contract and evidence gates pass.

Two API surfaces must remain separate:

| Surface | Purpose | Ownership boundary |
| --- | --- | --- |
| Local `/instances` API | Local instance management over fake or Docker drivers | Internal implementation; its DTOs and state are not Provider wire models |
| Provider API v1 | mTLS/JWS-protected asynchronous Provider protocol | Repository Contract controls routes, documents, semantics, and projection |

The calling Agent Platform owns WorkOrder, Run, desired business state,
tenant/user authorization, ProviderRevision selection, Artifact publication,
billing/accounting, its aggregate operation ledger, and public Gateway policy.
This repository owns provider-local execution, durable Provider operations,
runtime/session resources, and bounded evidence. Provider storage references
and backend endpoints are never public artifact URLs or client endpoints.

Dependencies point inward:

```text
Provider HTTP/mTLS/JWS transport
              |
              v
application policy and coordinators
              |
              v
repository and capability ports
              |
              v
runtime, persistence, session, and evidence adapters
```

Provider operations are asynchronous and preserve idempotency, attempts,
fencing, deadlines, cancellation, and unknown-outcome reconciliation. A
compatible coding/shell runtime must eventually expose stable guest paths
`/inputs`, `/workspace`, `/outputs`, and `/tmp`. Terminal clients receive only
an expiring opaque handoff; a Runtime Gateway resolves and proxies the internal
endpoint after its own authorization.

The default security posture is deny and fail closed. Do not expose backend
IDs, host paths, raw endpoints, daemon diagnostics, credentials, or secrets.
The existing Docker defaults and mTLS admission are useful component controls,
but they are not evidence of hostile multi-tenant isolation or production
readiness.

## Development Contract

- Keep transport, application policy, repositories, and runtime drivers in
  separate packages. Provider DTOs must not reuse local `instance` or backend
  engine structs.
- Preserve `context.Context` cancellation and deadlines for external work.
- Reject unknown, malformed, and oversized input before mutation when the
  Contract requires it. Unsafe production configuration must fail closed.
- Use narrow optional capability interfaces. Advertise a capability only when
  the complete configured dependency set and its named gate pass.
- Scope each change to one delivery slice. Ownership, public protocol,
  reliability, or security-boundary changes require an ADR and coordinated
  Contract review.
- Preserve unrelated worktree changes. Never turn local callbacks, fakes, or
  same-repository tests into external compatibility claims.

For Go changes, format with `gofmt` and run:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

For driver or lifecycle changes, also run the tagged Docker integration test in
an available Docker environment. For Contract metadata, DTO, Provider API, or
conformance changes, also run:

```bash
go run ./cmd/verify-contract -source-root .
go run ./cmd/run-conformance -source-root . -race -shuffle
```

Record an unavailable environment separately from a failed test. Keep these
evidence tiers distinct: component, Contract projection, CI, Provider
admission, external caller E2E, aggregate conformance, multi-controller,
multi-tenant, deployment, and production readiness.

## Current Snapshot

This snapshot was audited on 2026-09-02 against Provider implementation
baseline `e5d7324ef1d4508b8b0c474fe5ead47edd6f5146` and co-located E2E harness
baseline `2f165f9eb023392c1b6fb33845549f27e7364734`. Provider protocol behavior
remains unchanged from `d58497e5359056858564b9ac663178958cf5a6d6`; the new
commit adds only the internal Block manifest foundation and its documentation.
Provider fixes after
the previous documentation baseline bind create requirements to advertised
capabilities, preserve empty HTTP/2 reads, dispatch accepted lifecycle work,
aggregate terminal-session operations, and prevent a caller Gateway grant from
outliving its Provider endpoint.

The Provider full race/shuffle suite, vet, module verification, Contract lock
verifier, and unchanged locked 38-case Suite pass at the current implementation
baseline. The co-located
`e2e/` module then passed 15 initial and 5 process-reconstruction scenarios over
real mTLS/JWS HTTPS, WebSocket, separate caller/reference-stack processes, and
Docker. Its clean-run manifest is under ignored local evidence directory
`20260831T094209.963835000Z` and pins both commits, Contract identity,
configuration digests, and a temporary-registry tag plus immutable named
manifest digest for the `linux/amd64` runtime image. The harness starts and
cleans a uniquely labeled local `registry:2` container so the Provider sees a
real `name@sha256:<digest>` reference even when a Docker engine omits
`RepoDigests` for locally built images.
This is reference external-caller evidence only. The Provider implementation
baseline is covered by repository CI run `33379217795` at documentation/fix
commit `555436c`; its `provider-contract`, `test`, and `docker-integration`
jobs passed. Hosted Reference E2E run `33379217800` passed all 15 initial and 5
restart/resume scenarios after the bounded Gateway revocation drain fix. The
uploaded artifact is `reference-e2e-evidence-33379217800` with digest
`sha256:68250a85683dcbd8f01397d7373e98215382379ff895c0a58692de23c1880733`.

The co-located `e2e/` module also contains an explicitly named
`agent-platform-candidate` caller. Candidate implementation `47bd627` passed 15
initial and 5 resume scenarios over separate `platform-caller` and
`reference-stack` processes, with live capability/request shadow checks,
ProviderRevision selection, canary rollback/drain policy, state reconstruction,
mTLS/JWS, WebSocket, and Docker. The independent Hosted workflow run
`33460370618` passed the same candidate gate at baseline `c7ff5eb`; artifact
`platform-candidate-e2e-evidence-33460370618` has digest
`sha256:54f0aea847dcb0b1808c6c902f1465979a3ec4362d52ab8884187e85ea6343f7`.
This is candidate integration evidence only and does not represent real
Veronica, aggregate conformance, hostile multi-tenant security, deployment, or
production readiness.

On 2026-09-02 the current implementation and E2E lock were rechecked with
Provider race/shuffle, vet, Contract verifier, locked 38-case Suite, Block
component tests, and independent `e2e/` race/shuffle/vet/lock checks. The
reference run `20260902T035608.264731000Z` and candidate run
`20260902T035641.384559000Z` each passed 15 initial plus 5 reconstruction/
resume scenarios against the current lock. The checks passed with loopback
permission enabled; the unprivileged sandbox run could not bind local listeners
and is recorded as an environment limitation, not a code failure.

The internal Block manifest foundation is available under `blocks/` with ADR
0016 and plan `block-manifest-loader.md`. It is a strict, bounded local
configuration registry only; it does not advertise Provider capabilities,
execute blocks, or establish browser/desktop, deployment, or production
evidence.

P4 authority planning is recorded in ADR 0017 and
[`plan/p4-optional-profiles.md`](plan/p4-optional-profiles.md). Browser is the
first optional-profile candidate, and the plan records the 2026-09-02 browser
Contract gap inventory. Its first slice is Contract and image/security
authority audit only. No browser/desktop route, runtime image, capability
advertisement, or production configuration is enabled.

Contract identity:

- namespace: `urn:shell-echo:sandbox-runtime:provider-v1`
- version/license: `1.0.0` / MIT
- revision: `22a148e2898477790512d5bb742605654ff00ebf`
- Contract tree: `1a967c9c6ce9646c8431f6ee48699ec9f406a589`
- locked Conformance Suite: 38 cases

| Phase | Verified maturity | Open gate |
| --- | --- | --- |
| P0 | Passed: repository-owned MIT Contract migration and lock | Retain lock and projection regression |
| P1.1 | Passed for DTO, mTLS discovery, JWS/digest/replay/fencing admission | Production identity infrastructure remains unproven |
| P1.2 | Passed for the bounded Contract-authorized lifecycle subset and development composition | Reserved lifecycle families and production gates remain open |
| P2 components | P2.1-P2.5h local component, Contract projection, Docker, and recorded repository CI gates pass within their named boundaries | Retain single-controller/development constraints and exact Contract lock |
| P2.5i | Passed locally and hosted for the clean co-located independent reference caller: 15 initial plus 5 restart/resume scenarios against Provider `e5d7324` using harness `2f165f9` | Local evidence is `20260902T035608.264731000Z`; reference artifact is published in hosted run `33379217800`. Do not reinterpret this as Agent Platform or production evidence |
| P2 | Reference coding/shell caller release gate passed | Aggregate conformance, actual Agent Platform compatibility, multi-controller, hostile multi-tenant isolation, deployment, and production gates remain open |
| P3 | Local revision binding/shadow/metrics component evidence plus local candidate integration (`20260902T035641.384559000Z`) and Hosted candidate integration (`47bd627`/`c7ff5eb`, 15 initial + 5 resume) | Real platform traffic shadow parity, canary, rollback, old-run drain, metric parity, and unchanged platform contracts remain open |
| P4 | Authority/readiness planning accepted in ADR 0017; no optional profile implementation | Each browser/desktop/forwarding/snapshot/GPU/isolation profile needs independent Contract, security, and conformance gates |

Production readiness is not a numbered phase shortcut. Aggregate conformance,
multi-controller reliability, hostile multi-tenant security, deployment, and
production operations remain separate and unproven after the reference P2 gate
and require their own future evidence.

The latest verified repository CI for the pushed workflow baseline
`c7ff5eba6609bb0d047ab6d4cb1f6c53b09d27ed` is run `33460370563`; its
`provider-contract`, `test`, and `docker-integration` jobs passed. The
underlying P2.5g and P2.5h implementation gates remain run `33157119149` and
run `33159099578`, respectively. Repository CI remains distinct from
independent caller and production evidence.

## P2.5i Reference Result

The earlier audit correctly found no existing platform caller. A separately
versioned reference harness now exists as the `e2e/` Go module and process
boundary inside this Provider repository. Its caller module has an
import-boundary test that forbids Provider implementation imports; the separate
reference-stack process alone composes exported Provider/Gateway packages with
explicit caller-owned policy.

The clean `e329150` harness run against Provider `d58497e` verified exact
Contract/Suite identity, two ephemeral mTLS/JWS controller identities, locked
capability discovery, protected lifecycle, replay, exec/result/usage, stale
fencing, cancellation, opaque terminal handoff, Gateway bytes, wrong-caller and
cross-tenant denial, grant expiry, revocation, artifact staging/evidence,
process reconstruction, retained evidence, and same-shell reconnect. It
exposed no backend endpoint and left no managed container or new temporary run
directory.

This closes the reference external-caller P2.5i gate. It does not prove real
Veronica compatibility, aggregate conformance, distributed revocation,
multi-controller reliability, hostile multi-tenant isolation, deployment, or
production readiness.

The 2026-09-02 lock-refresh runs used harness `2f165f9eb023392c1b6fb33845549f27e7364734`
and Provider `e5d7324ef1d4508b8b0c474fe5ead47edd6f5146`. The reference evidence
`e2e/evidence/20260902T035608.264731000Z/manifest.json` and candidate evidence
`e2e/evidence/20260902T035641.384559000Z/manifest.json` each record 15 initial
plus 5 reconstruction/resume passes, Contract 38 cases, and a linux/amd64
named runtime digest. The candidate manifest remains explicitly bounded to
candidate integration and does not represent real Veronica or production
traffic.

## Platform Candidate Audit

The 2026-09-02 read-only re-audit found no independently runnable Agent
Platform caller or migration harness in the available adjacent projects:

- `/Users/echo/Projects/shell-echo/veronica` is a Blueprint/governance and TF00
  feasibility repository. Its local `main` is `17bb3855ba513b3a0e511f68f48c4e6aefbf265d`
  (90 commits ahead of `origin/main`
  `a758c219fd9f14a015368ab95914ed7386c05afc`); a live GitHub `ls-remote`
  confirmed that remote branch identity. Its working tree contains pre-existing
  user changes that were preserved. The audit covered tracked and visible
  untracked source plus build, deployment, and identity-material manifests. It
  found only Blueprint/governance and Temporal/PostgreSQL feasibility Python
  runners, with no Application service, Provider client, WorkOrder/AgentRun
  mapping, Gateway, mTLS/JWS identity configuration, Provider endpoint,
  shadow/canary traffic entrypoint, or rollback/drain harness. The bounded
  Temporal dev-server runner explicitly forbids workers, workflows, T2/T3, and
  external services, so it is not a platform caller.
- `/Users/echo/Projects/shell-echo/sandbox-runtime-e2e` is an older independent
  reference-caller checkout at `2981842` with no remote. Its README describes
  future remote-checkout preparation and the canonical reference harness is
  now the co-located `e2e/` module; it is not an Agent Platform caller.

Therefore P3 remains blocked for real platform evidence. The candidate result
is valid and complete within its named boundary, but it cannot establish real
platform request shadow parity, canary traffic, rollback, old-run drain, metric
parity, or unchanged platform-owned contracts. Resuming P3 requires a real
platform caller/service, the locked Contract/profile and ProviderRevision,
identity-bound mTLS/JWS PKI, reachable Provider/Gateway endpoints, and a
platform-owned shadow/canary/rollback/drain and metrics comparison entrypoint.

## Next Implementation Order

P2.5a established [ADR 0015](adr/0015-coding-shell-vertical-composition.md) and
the [vertical-composition plan](plan/p2.5-coding-shell-vertical-composition.md).
P2.5b then locked one atomic exec+terminal coding/shell profile in Contract
commit `22a148e` and projected it fail closed in `123d16a`. Its local gates and
repository CI `32924361132` pass. P2.5c commits `6c2962b` and `6340604` move
create/session bounded strict decode ahead of mutation guard reservation and
bind the regression into the locked Suite runner; local gates and CI
`32926181615` pass. P2.5d commit `de18787` adds the independent Provider Docker
lifecycle adapter and passes its local fault/restart, full Go, Contract/Suite,
and real Docker integration gates; CI `32929140044` passed all three jobs.
P2.5e commit `5917a57` locally composes strict protected exec/cancel/result and
operation projection, durable accept-before-dispatch and restart
reconciliation, bounded private output capture, real Docker execution and
cancellation, and fail-closed development composition. Full race/shuffle, vet,
Contract verification, the locked 38-case Suite, diff checks, focused race
matrices, and real Docker integration passed locally. CI `32937530059` passed
all three jobs. P2.5f0 then audited terminal/Gateway authority, data-plane,
recovery, persistence, cleanup, capacity, and deployment boundaries without
changing runtime behavior. P2.5f1 commit `6778d3c` adds the backend-neutral
terminal runtime port, a PTY-owning guest broker, adapter-private durable Docker
identity, bounded per-sandbox/per-controller capacity, identity-bound cleanup,
and fresh attach to the same shell after Provider driver reconstruction. Full
race/shuffle, vet, module verification, unchanged Contract verification, the
locked 38-case Suite, diff checks, focused terminal tests, and live Docker
integration passed locally. This is runtime-adapter evidence only; repository
CI `33033284420` subsequently passed all three jobs for evidence baseline
`66dd3d1`. P2.5f2 implementation `ccffd52` then adds the uncomposed durable
session vertical, provider-neutral allocation evidence, v1-to-v2 migration,
trusted lifecycle projection, exact-identity allocation recovery, observation,
expiry cleanup, and a success-commit hook that accepts but does not mint opaque
reference evidence. Full race/shuffle, vet, module and Contract verification,
the locked 38-case Suite, diff checks, focused fault/restart/migration matrices,
and live Docker integration passed locally. Repository CI `33045725476`
subsequently passed all three jobs for evidence baseline `3abefd4`. P2.5f3
implementation `b1acdd1` adds a durable opaque reference registry and resolver
in a separate repository. Registration mints a random 128-bit
`ref:session:*` value for a running allocation; resolution rechecks registry
expiry/revocation and exact committed-handoff identity, then constructs a fresh
adapter-private attach for each dial. File-backed restart, collision, expiry,
revocation, generation/reference mismatch, and concurrent resolve/revoke tests
pass locally. The registry/session repositories are intentionally non-atomic,
and no command composition or public backend endpoint is added. Repository CI
`33059304542` passed all three jobs for evidence baseline `7138a4c`. P2.5f4
implementation `14f14cc` adds `gateway/adapter`: a direct
`github.com/coder/websocket@v1.8.15` dependency (ISC-licensed, source-reviewed
for context reads/writes, message limits, control frames, and close behavior),
plus bounded adapters between the WebSocket/terminal byte surfaces and
`gateway.Stream`. It requires a caller-supplied pre-upgrade admission callback,
rejects wildcard origin patterns, retains the library's default same-origin
protection and disabled compression, accepts only text/binary data-plane
frames, and uses a 32 KiB default with a 64 KiB hard cap. Focused adapter
race/shuffle tests cover admission, origin rejection, binary flow, control
frames, over-limit `1009` close, cancellation, close, abrupt disconnect, and
partial terminal I/O. Full race/shuffle, vet, module verification, unchanged
Contract verification, the locked 38-case Suite, diff checks, and both Docker
regression packages passed locally. Repository CI `33064864447` then passed
`provider-contract`, `test`, and `docker-integration` for evidence baseline
`1d9da67`. `govulncheck` and an OSV scanner were not available, so no
vulnerability scan is claimed. P2.5f5 implementation `fdfc771` adds
`gateway/composition`, which requires caller-owned `Authorizer`,
`RevocationSource`, `Recorder`, and WebSocket handshake admission together with
a Provider reference resolver. It projects each freshly resolved Provider
terminal dial through the bounded f4 terminal adapter, rejects missing and
typed-nil dependencies and incomplete endpoint data fail closed, and closes the
caller stream on all connection exits. Focused and full race/shuffle, vet,
module verification, unchanged Contract verification, and the locked 38-case
Suite passed locally. This is a composition component, not Provider command
configuration, external-caller E2E, aggregate conformance, multi-controller,
multi-tenant, deployment, or production
evidence. Repository CI `33067526022` then passed all three required jobs for
evidence baseline `754c57d`; it is still not external-caller, aggregate,
multi-controller, multi-tenant, deployment, or production evidence. P2.5f6
commits `c4c7cbc` and `8a794c0` then add default-disabled development terminal
command composition with recovery before protected transport injection,
idempotent reference registration, file locking, bounded cleanup, and
production rejection. P2.5f7 test `0e8b284` then closes the local
single-controller terminal vertical gate with a real Docker session, durable
handoff, test-supplied Gateway policy, and same-shell reconnect after process
reconstruction. Their full local gates pass, and evidence baseline `cefbc74`
passed repository CI `33134521467`. P2.5g implementation `0e6e108` then adds
the default-disabled artifact/usage command vertical. It
binds staging to lifecycle readiness, tenant, generation, lease, and fencing;
reads only regular files beneath the owned Docker `/outputs`; runs injected
content scanners without shell interpolation; returns only opaque private
staging references; persists async artifact outcomes and partial exec-derived
usage across restart; and includes artifact operations in the family reader.
Its focused, full local, and Docker-tagged gates pass, and repository CI
`33157119149` passes all three jobs. P2.5h implementation `2c55173` and
repository CI `33159099578` also pass their bounded readiness/projection gates.
Reviewed documentation baseline `bba02a6` passes repository CI `33160646494`.

1. Preserve the clean reference and candidate harnesses and their named local
   evidence; the reference caller gate and candidate integration gate are
   complete within their separate boundaries.
2. Begin real P3 only against a platform migration target: lock the same
   Contract/profile, shadow capabilities and requests, canary only new runs,
   prove rollback and old-run drain, and compare the required metrics without
   changing platform-owned contracts.
3. Keep aggregate conformance, multi-controller, hostile multi-tenant,
   deployment, and production-readiness claims blocked until their separately
   named gates have reproducible evidence.

The detailed case-by-case evidence and exact open claims remain in
[`STATUS.md`](STATUS.md).

## Maintenance Rule

Update this document when architecture ownership, mandatory engineering gates,
phase maturity, Contract identity, primary blockers, or the next implementation
order changes. Put commit-by-commit evidence in `STATUS.md`, design rationale in
ADRs, and protocol details in `contract/`.

Use dated evidence baselines rather than statements such as `HEAD is <sha>`;
the latter becomes false as soon as a documentation update is committed. Every
handoff must leave facts, inference, and unproven claims visibly separate.
