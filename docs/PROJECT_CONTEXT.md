# Project Context

Updated: 2026-09-04

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

This snapshot was audited on 2026-09-04 against browser Contract authority
`5096e71fb84fbec22aa3487a0e55a1b49602ab8b`, Provider projection baseline
`24b2e36485c334634e561009850d1905ec3115d5`, browser session implementation
`9a5d225f793f37ccafdac31c276ccbcb1bc862ad`, sandbox/provenance implementation
`6e02f1c22f489802b0b2c9f06f4a807d2e7c36e5`, Browser Docker adapter
`cd33ba35c59bba62c48d13c0dcd08aeef5d9a434`, Browser provenance verifier
`939055475f73b0023b3946172a2c40750a99c7ea`, Browser restricted-egress and
create-policy implementation `7e60340`, protected Browser transport
implementation `b8423f5`, caller-owned Browser Gateway implementation
`5aae2810c4957ec7abad7de0e67f9507d9543c81`, and co-located E2E harness lock
`9eb32ba77d1b29767e5071f41f2264b7d1cc0d1d`. The Contract slice authorizes an
atomic browser-only capability shape, create/session/handoff schemas, protected
admission bindings, opaque reference security, operation/usage projection, and
10 new Suite cases. The browser image component is implemented under
`profiles/browser/image/`. The uncomposed Provider-local browser
session/application/reference/usage component is implemented under
`provider/browser/`. ADR 0020 and `provider/browser/driver/docker` add an
uncomposed fail-closed Docker adapter for that runtime port. ADR 0023 and
`b8423f5` add protected Browser open/handoff routing, admission correlation,
bounded error projection, and opaque response projection through a narrow
application port. ADR 0024 and `5aae281` add a separate caller-owned Browser
Gateway component with exclusive Browser identity/reference binding, explicit
authorization/revocation/audit/WebSocket-admission dependencies, bounded
reconnect, and RFC 6455 CDP framing. The command root still injects no Browser
application; no public Browser Gateway route, startup advertisement, or browser
caller scenario is included.

The Contract verifier and locked 48-case Suite pass against the current
projection. The `e2e/` module race/shuffle, vet, and lock checks also pass. A
clean reference run `20260904T013909.243838000Z` passed 15 initial and 5
process-reconstruction/resume coding/shell scenarios over real mTLS/JWS HTTPS,
WebSocket, separate caller/reference-stack processes, and Docker. Its manifest
pins Provider `5aae281`, harness `9eb32ba`, the Contract, and linux/amd64 runtime
image digest
`sha256:41c69ff79b9f895fa59e4a36d990993dffe0210b8b96df0bbf0647ae2ee651b4`.
This is reference coding/shell evidence only; it does not exercise browser.
Hosted Reference E2E run `33826813099` passed the same 15 initial and 5
reconstruction/resume coding/shell scenarios against harness/Provider lock
`9eb32ba`/`5aae281`. Its artifact `reference-e2e-evidence-33826813099` has
digest
`sha256:dbe54035cd65ce60dcb1a45254d394dc04b0e530907363ea167f8502fd91fd8e`.
This remains reference coding/shell evidence only and contains no browser
scenario.

The explicitly named `agent-platform-candidate` mode passed local run
`20260904T014037.825223000Z` against harness/Provider lock
`9eb32ba`/`5aae281`: 15 initial and 5 resume coding/shell scenarios over
separate `platform-caller` and `reference-stack` processes with candidate
shadow/selection/rollback/drain policy and state reconstruction. Hosted
workflow run `33826813100` passed the same scenario set
against harness/Provider lock `9eb32ba`/`5aae281`. Its artifact
`platform-candidate-e2e-evidence-33826813100` has digest
`sha256:f9a4f448e741c7945b225dd9dd1b72cf33d32745deb90a734b67fb41531f18bf`.
Local and hosted candidate results do not represent browser evidence, real
Veronica, aggregate conformance, hostile multi-tenant security, deployment, or
production readiness.

ADR 0018 records the original reproducible browser image component, while ADR
0019 requires the current `sandbox.runtime/browser-image/v2` sandbox posture
and signed publication. The image has no `--no-sandbox` path and binds a
fail-closed Chromium seccomp profile with digest
`sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`.
Local arm64 and amd64 integration runs returned Chromium `151.0.7922.109` over
loopback, found a sandboxed zygote, and retained the numeric user, read-only
root, drop-all, no-new-privileges, network-none, mount, and resource controls.
Manual publication run `33724368530` passed both native-architecture gates and
published
`ghcr.io/shell-echo/sandbox-runtime-browser@sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`
under tag `sha-58ed0093816d3daa3000750013b8e5991ef4bcf7`. Attestation `44912296`
binds the GitHub OIDC/Sigstore signer to this repository, workflow, source
commit, and hosted runner, and a constrained `gh attestation verify`
invocation succeeded independently. Independent registry inspection found
exactly `linux/amd64` and `linux/arm64/v8` descriptors and no extra manifest.
This closes the exact browser image sandbox/provenance publication gate. No
Provider route, Gateway composition, advertisement, or caller scenario is
implied by the publication evidence.

ADR 0020 and the Browser Docker adapter machine-bind that exact publication,
the checked-in seccomp profile, numeric identity, bounded stable guest mounts,
finite resources, durable private allocation state, and a fresh non-TTY relay
to container-loopback CDP. Focused/full race-shuffle, vet, Contract verification,
the unchanged 48-case Suite, and the tagged Docker driver matrix pass locally.
The live Browser case deliberately uses `network=none`; it proves private CDP
discovery, RFC 6455 upgrade, and `Browser.getVersion` only, not restricted
egress or complete runtime startup. The public adapter still requires
provenance verification and restricted-network implementations and fails
closed without them. ADR 0021 and `provider/browser/provenance/ghcli` now
provide the real, still-uncomposed provenance-verifier component. It pins and
rehashes an operator-supplied `gh` executable, verifies the immutable GHCR
bundle against exact GitHub OIDC/Sigstore identity and signed statement fields,
bounds output and environment inheritance, and preserves cancellation. Its
tagged live GHCR integration passes locally. It is not wired into a complete
Browser transport.

ADR 0022 and implementation `7e60340` add the still-uncomposed restricted-egress
Gateway process and Docker provisioner plus immutable lifecycle/create policy
binding. Each allocation receives an internal bridge; the Browser has only that
network and only the Gateway private IP as DNS, while the Gateway has that
bridge plus one explicitly owned uplink. DNS, HTTP Host, TLS SNI, resolved
public-address checks, image/container/network identity, policy digest, lease,
and restart state all fail closed. The combined tagged integration used the
real `gh` provenance verifier, the exact signed Browser image, and local Gateway
image `sha256:202bbf92fcbcce87e4b800f093d1df281125ab6fa43152906564cf8e0b7021d6`.
It passed allowed HTTP/HTTPS navigation, denied unlisted and metadata targets,
adapter/provisioner reconstruction, and exact cleanup with no managed resource
remaining. This is single-controller local Docker component/lifecycle-binding
evidence, not protected Provider transport, caller-owned Gateway, Browser
external-caller E2E, multi-controller, multi-tenant, deployment, or production
evidence. Separately, ADR 0023 and `b8423f5` compose the two protected Browser
handlers behind existing mTLS/JWS/admission controls. Local race/shuffle, vet,
Contract verification, and the unchanged 48-case Suite pass. This is
admission/transport component evidence only because command startup still has
no Browser application. ADR 0024 and `5aae281` then compose the caller-owned
Browser Gateway boundary without changing Provider startup. Requests and grants
bind exactly one terminal or Browser session namespace; resolved endpoints bind
the same sandbox/session/profile/reference/generation/expiry; and the Browser
adapter validates client-side RFC 6455 masking, fragmentation, control frames,
UTF-8, cancellation, partial writes, and the 64 KiB hard message limit. Caller
authorization, revocation, recording, WebSocket admission, and reconnect policy
remain explicit dependencies. This is Gateway component evidence only: no
public route, Browser runtime graph, advertisement, or Browser caller exists.

The two current coding/shell E2E runs and the Browser restricted-egress
integration left no managed Docker container or network. Their local evidence
is not a published CI artifact. The unprivileged sandbox
cannot bind the test listeners or access the Docker socket, so network/Docker
checks were run in the authorized local environment and the restriction is not
recorded as a code failure.

The internal Block manifest foundation is available under `blocks/` with ADR
0016 and plan `block-manifest-loader.md`. It is a strict, bounded local
configuration registry only; it does not advertise Provider capabilities,
execute blocks, or establish browser/desktop, deployment, or production
evidence.

P4 authority planning is recorded in ADR 0017 and
[`plan/p4-optional-profiles.md`](plan/p4-optional-profiles.md). Browser Contract
authority and Go projection are now locked, ADR 0018 records the reproducible
image foundation. ADR 0019 and run `33724368530` provide exact amd64/arm64/v8
sandbox and signed provenance evidence. ADR 0023 and `b8423f5` now add both
Browser routes to the protected router through a narrow injectable application
port, with nil application failing closed as retryable `503`.
The uncomposed-at-startup `provider/browser` session/application/reference/usage
components, Docker runtime adapter, provenance verifier, restricted-egress
provisioner, and create-policy binding pass their bounded local component gates.
ADR 0024 and `5aae281` add the separately injectable caller-owned Browser Gateway
component. No Browser command composition, public caller edge, capability
advertisement, or production configuration is enabled; the next slice is the
complete default-disabled command/runtime graph followed by independent Browser
caller evidence.

Contract identity:

- namespace: `urn:shell-echo:sandbox-runtime:provider-v1`
- version/license: `1.0.0` / MIT
- revision: `5096e71fb84fbec22aa3487a0e55a1b49602ab8b`
- Contract tree: `859f76dc0e855a0c8abdbbb5648df100dabb4328`
- locked Conformance Suite: 48 cases

| Phase | Verified maturity | Open gate |
| --- | --- | --- |
| P0 | Passed: repository-owned MIT Contract migration and lock | Retain lock and projection regression |
| P1.1 | Passed for DTO, mTLS discovery, JWS/digest/replay/fencing admission | Production identity infrastructure remains unproven |
| P1.2 | Passed for the bounded Contract-authorized lifecycle subset and development composition | Reserved lifecycle families and production gates remain open |
| P2 components | P2.1-P2.5h local component, Contract projection, Docker, and recorded repository CI gates pass within their named boundaries | Retain single-controller/development constraints and exact Contract lock |
| P2.5i | Latest local and hosted reference evidence passed 15 initial plus 5 restart/resume coding/shell scenarios against Provider `5aae281` using harness `9eb32ba`; hosted run `33826813099` passed | Local evidence is `20260904T013909.243838000Z`; neither run contains a browser scenario or implies Agent Platform or production properties |
| P2 | Reference coding/shell caller release gate passed | Aggregate conformance, actual Agent Platform compatibility, multi-controller, hostile multi-tenant isolation, deployment, and production gates remain open |
| P3 | Local revision binding/shadow/metrics component evidence plus latest local candidate integration (`20260904T014037.825223000Z`, `9eb32ba`/`5aae281`) and hosted candidate regression `33826813100` against the same lock | Real platform traffic shadow parity, canary, rollback, old-run drain, metric parity, and unchanged platform contracts remain open |
| P4 | Browser Contract authority/projection, exact sandboxed signed amd64/arm64/v8 publication, Provider-local session/application/reference/usage components, the fail-closed Docker/private-relay adapter, real provenance verifier, restricted-egress provisioner, create-policy binding, protected handlers, and caller-owned Gateway component have named evidence | Compose the complete command/runtime graph and public caller edge; browser advertisement, external Browser caller, multi-controller, multi-tenant, deployment, and production gates remain open |

Production readiness is not a numbered phase shortcut. Aggregate conformance,
multi-controller reliability, hostile multi-tenant security, deployment, and
production operations remain separate and unproven after the reference P2 gate
and require their own future evidence.

The Browser protected-transport implementation `b8423f5` and harness lock refresh
`a2721ad` are covered by repository CI run `33760609353`, which passed
`provider-contract`, `test`, `docker-integration`, and the separately named
`browser-provenance` job. Its Docker job does not execute the Browser
restricted-egress tagged integration; that live evidence remains local. Hosted
Reference and Candidate runs `33760609272` and `33760609231` passed their
separately named coding/shell scenarios. Repository CI remains distinct from
caller evidence, and neither hosted caller run contains a Browser scenario.
The Browser Gateway implementation `5aae281` and harness lock `9eb32ba` were
pushed together after all local gates and fresh 15+5 Reference/Candidate
coding/shell runs passed. Repository CI `33826813073` passed
`provider-contract`, `test`, `browser-provenance`, and `docker-integration`;
hosted Reference and Candidate runs `33826813099`/`33826813100` also passed their
separately named coding/shell scenarios. None of these hosted results contains a
Browser caller scenario.

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

The latest local lock-refresh runs use harness `9eb32ba77d1b29767e5071f41f2264b7d1cc0d1d`
and Provider `5aae2810c4957ec7abad7de0e67f9507d9543c81`. Reference evidence
`e2e/evidence/20260904T013909.243838000Z/manifest.json` and candidate evidence
`e2e/evidence/20260904T014037.825223000Z/manifest.json` each
record 15 initial plus 5 reconstruction/resume coding/shell passes, Contract 48
cases, and linux/amd64 runtime digest
`sha256:41c69ff79b9f895fa59e4a36d990993dffe0210b8b96df0bbf0647ae2ee651b4`.
Neither manifest contains a browser scenario; the candidate manifest also
remains explicitly bounded to candidate integration and does not represent real
Veronica or production traffic.

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

1. Add the complete default-disabled Browser command/runtime graph and integrate
   the Browser Gateway only behind an explicit caller-owned public edge. Keep
   `sandbox.browser` unadvertised until that graph and its external-caller gate
   pass.
2. Preserve the clean reference and candidate coding/shell harnesses and their
   named local evidence. Add Browser caller scenarios now that protected
   transport and caller-owned Gateway have their own component gates, but do not
   reuse the existing coding/shell results as Browser evidence.
3. Begin real P3 only against a platform migration target: lock the same
   Contract/profile, shadow capabilities and requests, canary only new runs,
   prove rollback and old-run drain, and compare the required metrics without
   changing platform-owned contracts.
4. Keep aggregate conformance, multi-controller, hostile multi-tenant,
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
