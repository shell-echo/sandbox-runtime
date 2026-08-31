# Project Status

Updated: 2026-08-31

This document is the implementation ledger for the repository-owned MIT
Provider Contract. It distinguishes local component evidence, Contract
projection evidence, CI, Conformance, external-caller compatibility,
multi-controller reliability, multi-tenant security, deployment, and
production readiness.

## Current Baseline

| Item | Evidence | Status |
| --- | --- | --- |
| Latest Provider implementation evidence | implementation `d58497e5359056858564b9ac663178958cf5a6d6` | Includes create capability binding, HTTP/2 empty-read admission, live lifecycle dispatch, terminal-session operation aggregation, and Gateway grant-to-endpoint expiry bounding. Full race/shuffle, vet, module verification, Contract verifier, locked 38-case Suite, and diff checks passed locally. This implementation is included in the descendant CI baseline `f509eca7a309cbecc4702c8a982189656ebd151b`, run `33348916594` |
| Latest repository CI evidence | Provider implementation `f509eca7a309cbecc4702c8a982189656ebd151b` | Repository CI run `33348916594` passed `provider-contract`, `test`, and `docker-integration` for the pushed Provider implementation. The earlier P2.5h and P2.5g documentation baselines passed in runs `33159099578` and `33157119149`. These are repository CI results only, not external-caller or production evidence |
| Latest reference external-caller evidence | independent harness `1d93722000056ddcf7dff41d2c633ee8f7b130db`; ignored evidence `20260830T073427.356961000Z` | Against Provider `d58497e`, all 15 initial and 5 process-reconstruction/resume scenarios passed over mTLS/JWS HTTPS, WebSocket, separate caller/reference-stack processes, and Docker. The manifest pins both commits, Contract revision/tree, 38-case Suite identity, configuration digests, and runtime image digest. This is P2.5i reference caller evidence only |
| Review | PR [#17](https://github.com/shell-echo/sandbox-runtime/pull/17) merged as `43ff3d7`; PR [#18](https://github.com/shell-echo/sandbox-runtime/pull/18) merged as `4774c3a`; PR [#19](https://github.com/shell-echo/sandbox-runtime/pull/19) merged as `e2755f5`; PR [#21](https://github.com/shell-echo/sandbox-runtime/pull/21) merged as `c5a4a65`; PR [#22](https://github.com/shell-echo/sandbox-runtime/pull/22) merged as `44f39ec`; PR [#23](https://github.com/shell-echo/sandbox-runtime/pull/23) merged as `ac72eab`; PR [#24](https://github.com/shell-echo/sandbox-runtime/pull/24) merged as `2e3dde6`; PR [#25](https://github.com/shell-echo/sandbox-runtime/pull/25) merged as `88506d1`; PR [#26](https://github.com/shell-echo/sandbox-runtime/pull/26) merged as `4ccb107`; PR [#27](https://github.com/shell-echo/sandbox-runtime/pull/27) merged as `28076a7`; PR [#28](https://github.com/shell-echo/sandbox-runtime/pull/28) merged as `2b25f76`; PR [#29](https://github.com/shell-echo/sandbox-runtime/pull/29) merged as `83965a2`; PR [#30](https://github.com/shell-echo/sandbox-runtime/pull/30) merged as `9d00212`; PR [#31](https://github.com/shell-echo/sandbox-runtime/pull/31) merged as `67b64a9`; PR [#32](https://github.com/shell-echo/sandbox-runtime/pull/32) merged as `5883da9`; PR [#33](https://github.com/shell-echo/sandbox-runtime/pull/33) merged as `ba39053`; PR [#35](https://github.com/shell-echo/sandbox-runtime/pull/35) merged as `c467cd4`; PR [#36](https://github.com/shell-echo/sandbox-runtime/pull/36) merged as `3a980bd`; PR [#37](https://github.com/shell-echo/sandbox-runtime/pull/37) merged as `f9cfbc3`; PR [#38](https://github.com/shell-echo/sandbox-runtime/pull/38) merged as `7ebcc8f`; PR [#39](https://github.com/shell-echo/sandbox-runtime/pull/39) merged as `17072e6`; PR [#40](https://github.com/shell-echo/sandbox-runtime/pull/40) merged as `65a9ba3`; PR [#41](https://github.com/shell-echo/sandbox-runtime/pull/41) merged as `ac555619`; PR [#42](https://github.com/shell-echo/sandbox-runtime/pull/42) merged as `97fb429` | PR #42 CI `32465114377` and post-merge CI `32465443385` provider-contract, test, and docker-integration passed |
| P2.2a release evidence | `2fa2e72` on PR #33, merged as `ba39053` | Local race/shuffle, vet, lock, Suite, PR CI, and post-merge CI passed |
| P2.2b release evidence | `e26bf2b` on PR #35, merged as `c467cd4` | Local race/shuffle, vet, lock, 19-case Suite, PR CI `32456100570`, and post-merge CI `32456279722` passed; no HTTP/dispatch composition |
| P2.2c release evidence | `275a9e9` on PR #39, merged as `17072e6` | Local race/shuffle, vet, lock, 19-case Suite, PR CI `32460695928`, and post-merge CI `32460914417` passed; no HTTP/Docker/automatic redispatch |
| P2.3a/b merge evidence | PR [#43](https://github.com/shell-echo/sandbox-runtime/pull/43) merged as `21f5236` | PR CI `32468912019` and post-merge CI `32469390678` provider-contract, test, and docker-integration passed; this proves resource/lock/projection evidence only |
| Contract namespace | `urn:shell-echo:sandbox-runtime:provider-v1` | Locked |
| Contract version/license | `1.0.0` / MIT | Locked |
| P2.3c0 local evidence | corrected resources `71fee34`; corrected projection and lock `ab9defc` | Full race/shuffle, vet, lock verifier, 26-case Conformance Suite, JSON parsing, and diff check passed locally against the final revision |
| P2.3c0 release evidence | PR [#44](https://github.com/shell-echo/sandbox-runtime/pull/44) head `16136d2`, merged as `6c1fc90` | Exact-head PR CI `32685685846` and post-merge CI `32686754674` passed `provider-contract`, `test`, and `docker-integration`; review findings were resolved before merge |
| P2.3c1 local evidence | independent `provider/session` domain and transactional `Authority` port | Focused and full race/shuffle, vet, lock verifier, 26-case Suite, JSON, dependency-boundary, and diff checks passed; no persistence or dispatch composition |
| P2.3c1 release evidence | PR [#45](https://github.com/shell-echo/sandbox-runtime/pull/45) merged as `4c37d8c` | PR CI `32696507856` and post-merge CI `32696727371` passed `provider-contract`, `test`, and `docker-integration`; Node.js 20 deprecation warnings remain |
| P2.3c2 local evidence | independent session memory/file repositories and transactional sandbox authority checks | Focused/full race/shuffle, vet, unchanged Contract lock, 26-case Suite, restart, expiry, idempotency, CAS generation/fencing, and diff checks passed; no transport or dispatch composition |
| P2.3c2 release evidence | direct `main` commit `e5c9dec` | Post-push CI #103 / run `32698606341` passed `provider-contract`, `test`, and `docker-integration`; Node.js 20 deprecation warnings remain |
| P2.3c3 local evidence | implementation commit `186190b` | Session application, protected POST/GET projection, admission binding, strict decode, status/expiry mapping, opaque endpoint non-disclosure, route coverage, full race/shuffle, vet, lock verifier, 26-case Conformance Suite, and diff checks passed; no Gateway/WebSocket composition |
| P2.3c4 local evidence | implementation commit `e675cb9` | Independent Gateway authorization binding, opaque reference resolution, bidirectional frame proxy, bounded reconnect, generation/expiry checks, revocation interruption, metadata-only audit, full race/shuffle, vet, dependency boundary, and diff checks passed; no real external caller or production wire claim |
| P2.3c4 release evidence | post-push CI run `32801539995` | `provider-contract`, `test`, and `docker-integration` all passed for the repository revision; this remains component/Gateway evidence, not external-caller or production readiness |
| P2.4 Contract authority | commits `4f3da4e` and `649c293` | Additive artifact staging request/evidence and usage evidence schemas, OpenAPI paths, semantic rules, fixtures, DTO projection, Suite cases, and ADR 0012; no runtime dispatch in the Contract step |
| P2.4 local evidence | commits `1ca700d` and `41225c0`, fix `3b94146` | Artifact/usage bounded domain, ports, memory staging/repository adapters, digest/MIME/size and check admission, idempotent replay/conflict, expiry, close, cancellation, and immutable evidence tests; component evidence only |
| P2.4 release evidence | post-push CI run `32804619553` | `provider-contract`, `test`, and `docker-integration` all passed for the final adapter revision; no Provider HTTP composition or external-caller claim |
| P2.4a0 admission authority | Contract commits `3a9d8b7` and `7e00715`; lock/admission commit `2aba87f` | Locks `stage_artifact`, `read_artifact_staging_evidence`, and `read_usage_evidence`; the stage mutation consumes replay/fencing guard state, reads do not; async outcomes, `400`/`503` error surface, descriptor JCS digests, unknown-operation rejection, and route absence are covered |
| P2.4a0 release evidence | post-push CI run `32819717542` | `provider-contract`, `test`, and `docker-integration` all passed; this proves Contract/admission authority only, not handler, application, staging dispatch, usage collection, or external-caller compatibility |
| P2.4a1 read authority | Contract commits `3846c9e` and `6f549c2`; lock/projection commit `dbea0e8`; ADR 0014 | Locks generic operation-family aggregation plus artifact pending/outcome-unknown/expired and usage unavailable/expired read states; no application, repository, aggregator, handler, router, or transport was added |
| P2.4a1 release evidence | post-push CI run `32823783136` | `provider-contract`, `test`, and `docker-integration` all passed; local race/shuffle, vet, lock verifier, projection/admission tests, and 35-case Suite also passed |
| P2.4a2 application component | commits `152033f`, `0440272`, and `4d0bb70` | Independent artifact accepted/running/terminal/outcome-unknown authority, explicit dispatch/reconcile boundary, memory/file adapters, expiry tombstones, usage operation-id index, lifecycle/artifact operation readers, and collision-safe aggregator; no handler/router/config change |
| P2.4a2 release evidence | post-push CI run `32827387303` | `provider-contract`, `test`, and `docker-integration` all passed; local authorized race/shuffle, vet, lock verifier, 35-case Suite, dependency-boundary tests, and `git diff --check` passed |
| P2.4a3 transport component evidence | commits `f5111a5`, `ce3c6e0`, `9a4bc71`, correction `c469337` | Three locked routes are admitted before application dispatch; artifact accept returns only `202` operation; evidence/usage state mappings and operation-family aggregation pass. Local race/shuffle, vet, lock verifier, 35-case Suite, focused projection tests, diff checks, and post-push CI `32838784395` (all three jobs) pass. This slice corrected artifact-stage preflight only; P2.5c later applies the ordering to create/session |
| Gateway clock correction | commit `0893ac3` | Grant-expiry timers now derive from the configured clock used by authorization and endpoint checks. Focused Gateway race/shuffle passed ten consecutive runs and the full race/shuffle suite passed. This is component regression evidence only |
| P2.5b Contract/projection evidence | Contract commit `22a148e`; projection/lock commit `123d16a`; status baseline `206caeb` | Locks one atomic `sandbox.exec@1.0.0` + `sandbox.terminal@1.0.0` coding/shell profile and retains terminal-only compatibility. Empty, terminal-only, and complete coding/shell advertisements are accepted; exec-only, missing/split mapping, and unknown-capability shapes fail closed. Full race/shuffle, vet, lock verification, 38-case Suite, diff checks, and post-push CI `32924361132` passed. No runtime behavior or nonempty startup advertisement was enabled |
| P2.5c admission-ordering evidence | transport commit `6c2962b`; Suite mapping `6340604`; status baseline `9b10abd` | Create and runtime-session bounded strict decode and Contract-safe `400` body-limit rejection precede digest/binding admission and mutation guard reservation. Digest-consistent unknown fields and oversized bodies consume no guard state; valid replay and stale fencing remain `409`. Full race/shuffle, vet, unchanged lock verification, mapped 38-case Suite, diff checks, and post-push CI `32926181615` passed. No dispatch or runtime behavior was added |
| P2.5d runtime evidence | implementation commit `de18787`; evidence baseline `e3a8265` | Provider-specific Docker lifecycle adapter, stable `/inputs` read-only, `/workspace` mutable, `/outputs` staging, bounded tmpfs `/tmp`, digest-pinned image, numeric non-root user, read-only root, resource/network bounds, ownership labels, idempotent create/remove, restart observation, unknown-outcome evidence, and explicit development composition passed focused/full race-shuffle, vet, unchanged Contract verification, 38-case Suite, diff checks, both real Docker integration packages, and post-push CI `32929140044`. This is single-controller development evidence only |
| P2.5e exec vertical evidence | implementation commit `5917a57`; evidence baseline `2f7a79b` | Protected exec/cancel/result/operation routes, strict preflight, durable accept-before-dispatch, independent exec persistence and migration, correlation/conflict checks, injected-clock ordering, retained terminal summary, restart/on-demand reconciliation, Docker execution/cancellation, private bounded capture, expiry, and unsupported-reference rejection passed focused/full race-shuffle, vet, unchanged Contract verification, the 38-case Suite, diff checks, and both live Docker integration packages. Post-push CI `32937530059` passed all three jobs; this is single-controller Provider/CI evidence only |
| P2.5f0 terminal/Gateway design evidence | source and Contract audit on 2026-08-27; `docs/plan/p2.5f-terminal-gateway-vertical.md` | Confirms that session authority and Gateway components are not command-composed and that the current non-TTY, no-stdin, one-shot Docker exec attach cannot prove terminal restart/reconnect. Locks ownership, provider-neutral/private persistence, cleanup, capacity, and f1-f7 delivery boundaries. No code, Contract, runtime, WebSocket, external-caller, or readiness evidence is claimed |
| P2.5f1 terminal runtime evidence | implementation commit `6778d3c`; evidence baseline `66dd3d1` | Backend-neutral allocate/observe/attach/cleanup ports, PTY-owning guest broker, adapter-private Docker identity, opaque `ref:terminal/*` receipt, lost-start recovery, capacity, expiry, identity conflict, process-group cleanup, sandbox removal, cancellation, and corrupt-state tests passed. Full local gates and repository CI `33033284420` passed all three jobs, including live Docker same-shell reattach after Provider driver reconstruction. No session coordinator, `ref:session:*` resolver, WebSocket/Gateway composition, external caller, or readiness evidence is claimed |
| P2.5f2 durable session coordination evidence | implementation commit `ccffd52`; evidence baseline `3abefd4` | Session repository v2, valid v1 migration, provider-neutral allocation receipt/observation evidence, trusted lifecycle projection, session-local fencing high-water, durable accept-before-allocation, exact-identity lost-attachment recovery, no replacement after uncertain outcomes, restart reconciliation, expiry/cleanup retry, corruption rejection, and registry-supplied success evidence passed focused/full race-shuffle, vet, module/Contract verification, the locked 38-case Suite, diff checks, and both live Docker integration packages. Post-push CI `33045725476` passed all three jobs. No `ref:session:*` registry/resolver, WebSocket/Gateway or command composition, external caller, multi-controller, tenancy, deployment, or readiness evidence is claimed |
| P2.5f3 opaque-reference evidence | implementation commit `b1acdd1`; evidence baseline `7138a4c` | A separate memory/file registry and resolver persist a random opaque `ref:session:*` binding for a running allocation. Resolution and every fresh `Dial` recheck active registry state plus exact committed session handoff identity before adapter attach. The file adapter has versioned JSON, atomic replacement, directory sync, and a single-controller lock; collision, restart, expiry, revocation, generation/reference mismatch, and concurrent resolve/revoke tests pass. Full race/shuffle, vet, module and unchanged Contract verification, the 38-case Suite, diff checks, and both live Docker integration packages passed locally. Repository CI `33059304542` passed all three jobs. No Contract, DTO, Provider transport, Gateway, command composition, external caller, aggregate conformance, multi-controller, tenancy, deployment, or production readiness evidence is claimed |
| P2.5f4 WebSocket/terminal adapter evidence | implementation `14f14cc`; evidence baseline `1d9da67`; CI `33064864447` | `gateway/adapter` keeps `github.com/coder/websocket@v1.8.15` and `provider/terminal.Stream` outside Gateway policy. Its WebSocket edge requires caller-owned admission before upgrade, rejects wildcard origin patterns, leaves compression disabled and same-origin enforcement on by default, and bounds messages to 32 KiB by default / 64 KiB maximum. It maps only text/binary data to `gateway.Stream`; WebSocket control frames are library-handled and never become terminal bytes. Focused race/shuffle tests cover admission, origin rejection, binary flow, ping/pong, normal/abrupt close, inbound `1009`, cancellation, terminal partial I/O, bounds, and idempotent close. Full local regression gates and repository CI `provider-contract`, `test`, and `docker-integration` passed. The dependency source/license/behavior review passed; `govulncheck` and OSV scanning were unavailable and are not claimed. No Gateway authorization/revocation/audit composition, Provider route/configuration, external caller, aggregate, multi-controller, tenancy, deployment, or production evidence is claimed |
| P2.5f5 Gateway composition evidence | implementation `fdfc771`; evidence baseline `754c57d`; CI `33067526022` | `gateway/composition` accepts only caller-supplied `Authorizer`, `RevocationSource`, `Recorder`, and WebSocket handshake admission plus a Provider reference resolver; no allow-all fallback exists. It resolves fresh opaque references on every Gateway attempt and wraps every Provider terminal dial in the f4 bounded adapter. Tests cover missing and typed-nil dependencies, incomplete endpoint rejection, grant binding, caller cross-tenant denial, endpoint expiry, revocation interruption, reconnect and exhaustion, bidirectional real-WebSocket flow, and metadata-only audit. Full race/shuffle, vet, module/Contract verification, the locked 38-case Suite, and diff checks passed locally; CI passed `provider-contract`, `test`, and `docker-integration`. No command/configuration composition, external caller, aggregate, multi-controller, tenancy, deployment, or production evidence is claimed |
| P2.5f6 command composition evidence | implementation `c4c7cbc`; startup/locking regression `8a794c0`; evidence baseline `cefbc74`; CI `33134521467` | The command root accepts an explicit default-disabled development terminal configuration only with protected admission plus Docker lifecycle/file persistence. It opens distinct session/reference single-controller files, constructs the reconnectable terminal runtime, recovers lifecycle then exec then terminal state before assigning `SessionApplication`, and keeps startup capability advertisement empty. Handoff registration is idempotent for an exact running allocation, avoiding an unbounded sequence of unresolvable references after a retry. After the Provider listener stops, bounded shutdown revokes and cleans still-running uncommitted allocations before repository release; successful unexpired handoffs retain their durable reattachment semantics. Config, disabled/incomplete/enabled startup/locking, recovery, shutdown order, route absence, full race/shuffle, vet, Contract verification, 38-case Suite, and Docker regressions pass locally. Repository CI passed all three required jobs. No public Gateway listener, caller authorization/revocation/recording default, Contract change, external caller, aggregate, multi-controller, tenancy, deployment, or production evidence is claimed |
| P2.5f7 terminal vertical evidence | implementation/test `0e8b284`; evidence baseline `cefbc74`; CI `33134521467` | The tagged `cmd` integration test uses the real Docker lifecycle and f6 terminal composition, obtains the durable opaque handoff, and injects f5 Gateway only with test-owned admission, authorization, revocation, and recorder ports. A first WebSocket connection sets shell state; after closing and reconstructing lifecycle, session/reference, terminal runtime, and resolver state, a fresh connection proves that state survives in the same shell. The CI Docker job includes `./cmd`, and repository CI passed `provider-contract`, `test`, and `docker-integration`. Focused race, full race/shuffle, vet, unchanged Contract/tree verification, the locked 38-case Suite, dependency checks, and the exact three-package Docker command pass locally. This does not add a public Gateway, real platform caller, production policy, capability advertisement, artifact/usage composition, aggregate conformance, multi-controller persistence, tenant isolation, deployment, or production readiness |
| P2.5h readiness-derived composition and advertisement | implementation `2c55173` | `ProviderCapabilityConfig.CodingShellEnabled` is an explicit opt-in. The command root constructs a deterministic dependency graph only after lifecycle, admission, exec, usage, terminal, artifact, and operation readers are composed. The source advertises exactly `sandbox.exec@1.0.0`/`exec-v1`, `sandbox.terminal@1.0.0`/`terminal-v1`, and `sandbox-runtime-coding-shell-v1` only when every graph node is ready; otherwise explicit enablement returns a startup error and disabled configuration returns non-nil empty arrays. Config and per-node dependency-absence matrices, immutable snapshot projection, canonical terminal IDs, full race/shuffle, vet, lock verification, the 38-case Suite, fixed-digest Docker integration, and diff checks pass. The command graph intentionally marks the concrete WebSocket and caller-owned Gateway boundary unavailable, so this slice does not produce a runnable nonempty-profile deployment or external-caller evidence |
| P3 local evidence | implementation commit `4212e88` | Revision identity validation, deterministic canary binding, rollback-only-new-run behavior, old-run draining, shadow validation bounds, and migration metric aggregation passed focused race/shuffle and vet; real platform traffic and migration evidence remain open |
| P3 component release evidence | post-push CI run `32805284762` | CI run concluded success for `4212e88`; this remains local migration component evidence, not external caller, canary traffic, rollback E2E, or production readiness |
| Historical external platform audit | 2026-08-30 review baseline `bba02a6`; platform checkout cached `origin/main@cf623ac` | The existing Agent Platform candidate still had no runnable sandbox caller, Gateway, lock, PKI/JWS, or scenario runner. This finding remains relevant to actual platform compatibility but no longer blocks the separately versioned reference P2.5i harness |
| P2.5i reference external caller | harness `1d93722000056ddcf7dff41d2c633ee8f7b130db`; Provider `d58497e5359056858564b9ac663178958cf5a6d6` | Clean local run passed 15 initial plus 5 restart/resume scenarios, including two controller contexts, endpoint non-disclosure, negative authorization, expiry/revocation, retained evidence, and same-shell reconnect. No Agent Platform, aggregate, multi-controller, hostile multi-tenant, deployment, or production claim |
| Contract resources | OpenAPI, admission, lifecycle, bounded exec, terminal-session, artifact-staging, usage-evidence schemas, fixtures, semantic rules, and Suite | Local Contract authority is locked; artifact publication, billing, and tenant authority remain outside the Provider |
| Contract lock | revision `22a148e2898477790512d5bb742605654ff00ebf`; tree `1a967c9c6ce9646c8431f6ee48699ec9f406a589`; manifest `sha256:52e47726556a35ae0f1d5867a2f744341efda15475141bed0a9f93a602c4f13c`; OpenAPI `sha256:93e9e0d4492db16fc75f3bfa08e2b7061b133638ff196c60aed45022421bda4f`; semantic rules `sha256:85e7955b18638183ee5295bd6be60b6f94aa0feeee0610cd20492fc0a3e7feb0` | Local verifier, 38-case Conformance, full race/shuffle, vet, projection tests, and post-push CI `32924361132` passed. Suite file SHA-256 is `b43c59ed10d3667223523d04470b52401dae240647228b0db305a1a88ba6bde0`, while the declared Suite digest remains the existing placeholder |
| External Agent Contract | no longer consumed; old compatibility evidence is historical only | Removed from implementation |

The lock verifier is intentionally bound to the repository-owned Contract tree.
It does not clone, mount, or read an external source repository.

## Plan Ledger

| Slice | Scope | Status | Required next evidence |
| --- | --- | --- | --- |
| P0.0 | Freeze local Contract ownership, namespace, version, license, resource layout, and lock | Passed and merged in PR #17 | Post-merge CI run `32360376058` passed |
| P0.1 | Replace external lock verifier with local tree/digest/semantic/fixture validation | Passed and merged in PR #17 | Current lock revalidation on this branch |
| P0.2 | Migrate DTO/projection tests and CI to local Contract | Passed and merged in PR #17 | Current projection regression |
| P0.3 | Rebase architecture, ADRs, README, plans, and status on local Contract | Passed and merged in PR #17 | Keep docs synchronized with follow-up Contract changes |
| P0.4 | Re-run P1.1 evidence against the repository-owned Contract | Passed through PR #19; post-merge run `32365284283` passed | Retain regression and lock evidence |
| P1.1a | Provider v1 DTOs and strict decoder | Passed under local Contract through PR #18; post-merge run `32363581638` passed | No new slice; retain regression coverage |
| P1.1b | mTLS-only capability discovery | Passed under local Contract through PR #18; post-merge run `32363581638` passed | No new slice; retain TLS/projection coverage |
| P1.1c | Protected-operation admission primitives and transport composition | Passed under local Contract through PR #18; post-merge run `32363581638` passed | P1.1d release-gate review |
| P1.1d | Admission release gate | Passed; Suite runner, race/shuffle matrix, PR CI, and post-merge CI all passed | Retain gate evidence; do not expand claim beyond P1.1 |
| P1.2.0 | Lifecycle Contract and authority inventory | Passed; PR #21 and post-merge CI run `32368734877` passed | Retain Contract lock and projection regression |
| P1.2.1 | Pure lifecycle domain | Passed; PR #22 and post-merge CI run `32370133083` passed | Retain domain transition regression |
| P1.2.2 | Atomic repository ports and development adapters | Passed; PR #23 merge `ac72eab`, post-merge CI `32372662597` passed | Retain repository fault/restart evidence; no multi-controller claim |
| P1.2.3 | Provider-local coordinator and reconciliation | Passed in PR #24 merge `2e3dde6`; post-merge CI reported successful | Retain coordinator fault/restart evidence; no multi-controller claim |
| P1.2.4 | Provider API lifecycle projection | Passed in PR #25 merge `88506d1`; PR CI run `32378782202` and post-merge CI run `32435540542` all required jobs successful | Retain projection/Schema/admission evidence; no runtime composition claim |
| P1.2.5 | Lifecycle release gate | Passed for the current Contract-authorized subset; local Suite behavior matrix and reserved-family boundary recorded | Retain no-claim boundary for terminate/lease/orphan families; no aggregate or production claim |
| P1.2.5a | Provider lifecycle composition | Passed in PR #27 merge `28076a7`; post-merge CI `32439289227` passed | Retain fake-driver and production-readiness boundaries |
| P1.2 | Async lifecycle, operation ledger, reconciliation, events | Passed for the bounded Contract-authorized subset; full architecture lifecycle families remain separately gated | P2.0 authority inventory; do not implement unauthorized lifecycle families |
| P2.0a | Coding/remote-shell authority inventory | Passed in PR #29 merge `83965a2`; post-merge CI `32440383198` passed | Retain ADR 0009 ownership boundary |
| P2.0b | Bounded exec Contract resources | Passed in PR #30 merge `9d00212`; no runtime dispatch | Retain lock source revision/tree and valid/rejection fixture evidence |
| P2.0c | Exec Contract lock/projection gate | Passed in PR #30; post-merge CI run `32444266288` passed | No runtime claim from the Contract gate |
| P2.1 | Bounded exec domain/application port | Passed in PR #31 merge `67b64a9`; post-merge CI `32445893337` passed; no public composition | Retain P2.2 non-goals and local-only evidence boundary |
| P2.2a | Exec result and cancellation-intent domain | Passed in PR #33 merge `ba39053`; post-merge CI `32454054853` passed; no persistence, dispatch, or HTTP composition | Retain local-only evidence boundary |
| P2.2b | Independent exec ledger persistence | Passed in PR #35 merge `c467cd4`; post-merge CI `32456279722` passed | Retain local-only evidence boundary; P2.2c design gate next |
| P2.2c | Bounded exec coordination and optional cancellation port | Passed in PR #39 merge `17072e6`; post-merge CI `32460914417` passed | Retain no-HTTP/no-Docker/no-auto-recovery boundaries |
| P2.2 | Retained result and cancellation behavior | Passed for P2.2a-c bounded provider-local subset | P2.3c0 Contract consistency gate and subsequent session evidence |
| P2.3a | Terminal session Contract resources | Passed as resource evidence in PR #43 merge `21f5236`; session behavior remains unimplemented | Retain resource projection regression |
| P2.3b | Terminal session lock and DTO/admission projection | Passed as lock/projection evidence in PR #43; the former capability consistency gap is addressed by P2.3c0 | Retain 24-case baseline and P2.3c0 review evidence |
| P2.3c0 | Terminal capability/profile Contract reconciliation | Passed in PR #44 merge `6c1fc90`; exact-head PR CI `32685685846` and post-merge CI `32686754674` passed | Retain 26-case Contract/projection regression and evidence boundaries |
| P2.3c1 | Provider-local terminal session domain and transactional authority port | Passed: PR #45 merged as `4c37d8c`; PR/post-merge CI passed | Retain no-persistence/no-transport boundary |
| P2.3c2 | Durable terminal session ledger and atomic sandbox authority check | Passed on `main@e5c9dec`; post-push CI #103 passed | Retain no-transport/no-dispatch/no-multi-controller boundary; P2.3c3 next |
| P2.3c3 | Protected transport projection and opaque handoff retrieval | Passed for bounded Provider transport evidence | Retain no-Gateway/no-WebSocket boundary; P2.3c4 requires independent Gateway evidence |
| P2.3c4 | Runtime Gateway integration | Passed for bounded Gateway component evidence | External caller E2E, real WebSocket adapter, distributed revocation, multi-controller reliability, and production deployment remain unproven |
| P2.4 | Artifact staging and usage evidence | Passed for bounded Provider Contract/domain/memory-adapter evidence; direct-main commits through `3b94146`, post-push CI `32804619553` | No HTTP composition, platform artifact publication, billing, distributed reconciliation, tenancy, deployment, or production claim |
| P2.4a0 | Artifact/usage protected-admission authority reconciliation | Passed in direct-main commits `3a9d8b7`, `7e00715`, and `2aba87f`; CI `32819717542` passed | Retain 33-case Suite, lock, guard classification, descriptor digest, async outcome, safe error, and route-absence regression |
| P2.4a1 | Operation aggregation and evidence-read authority reconciliation | Passed in direct-main commits `3846c9e`, `6f549c2`, and `dbea0e8`; CI `32823783136` passed | Retain 35-case Suite and locked pending/outcome-unknown/unavailable/expired state matrices; no runtime implementation claim |
| P2.4a2 | Artifact/usage Provider application and operation-family component | Passed for bounded provider-local application/repository/reader evidence in direct-main commits `152033f`, `0440272`, and `4d0bb70`; CI `32827387303` passed | Retain durable accept-before-dispatch, CAS/generation/fencing, restart/expiry/corruption, usage operation correlation, all-family aggregation, and duplicate-ID fail-closed evidence; no HTTP composition |
| P2.4a | Artifact/usage Provider transport composition | Passed for bounded component evidence; post-push CI `32838784395` passed | Retain the artifact-stage preflight evidence; create/session ordering is independently covered by P2.5c. Obtain separately supplied external-caller evidence; no aggregate, tenancy, deployment, or production claim |
| P2.5a | Coding/shell vertical-composition authority and delivery plan | Passed as design evidence in ADR 0015 and `docs/plan/p2.5-coding-shell-vertical-composition.md`; no Contract, config, runtime, route, or advertisement behavior changed | Retain the ownership and evidence boundaries through P2.5b-i |
| P2.5b | Coding/shell Contract profile reconciliation | Contract authority committed as `22a148e`; projection/lock committed as `123d16a`; full local gates and CI `32924361132` passed | Retain Contract/profile regression. Runtime composition and startup advertisement remain disabled |
| P2.5c | Create/session mutation preflight ordering | Transport correction `6c2962b`, Suite mapping `6340604`, and CI `32926181615` pass the slice gates | Retain admission-ordering regression through later verticals. This slice itself makes no dispatch, runtime, external-caller, or production claim |
| P2.5d | Provider runtime foundation | Passed for single-controller development evidence in `de18787`; evidence commit `e3a8265` and post-push CI `32929140044` passed | Retain Provider/local `/instances` separation, real Docker integration, restart/unknown/cleanup evidence, empty advertisement, and production rejection through P2.5e-h |
| P2.5e | Exec vertical composition | Passed in `5917a57`; evidence baseline `2f7a79b` and CI `32937530059` passed | Retain exec admission/runtime/recovery matrices and empty advertisement. Terminal runtime work continues under P2.5f; external caller, aggregate, reliability, tenancy, deployment, and production claims remain open |
| P2.5f0 | Terminal/Gateway authority, data-plane, recovery, and deployment audit | Complete as design evidence; no behavior or advertisement changed | Retain the reconnect and ownership boundaries through P2.5f1-f7 |
| P2.5f1 | Reconnectable terminal runtime port and Docker adapter | Passed local and repository CI gates in implementation `6778d3c`, evidence baseline `66dd3d1`, and CI `33033284420` | Retain the runtime identity/reconnect boundary; do not promote runtime-adapter evidence to a terminal/Gateway vertical claim |
| P2.5f2 | Durable session coordination and repository migration | Passed local and repository CI gates in implementation `ccffd52`, evidence baseline `3abefd4`, and CI `33045725476` | Retain the single-controller, separate-repository, no-command-composition boundary |
| P2.5f3 | Opaque reference registry and resolver | Passed local and repository CI gates in implementation `b1acdd1`, evidence baseline `7138a4c`, and CI `33059304542` | Retain the separate non-atomic session/reference stores and no-command-composition boundary through f4-f7 |
| P2.5f4 | WebSocket and terminal stream adapters | Local component/full regression gates and CI `33064864447` passed in implementation `14f14cc` and evidence baseline `1d9da67` | Compose f5 only with caller-owned authorization, revocation, and recorder ports. Retain no-command-composition/no-external-caller boundary |
| P2.5f5 | Gateway composition | Local composition gate and CI `33067526022` passed in implementation `fdfc771` and evidence baseline `754c57d` | Retain caller-owned policy and no-public-Gateway/no-external-caller boundary; f6 command composition does not weaken that boundary |
| P2.5f6 | Development terminal command configuration and process lifecycle | Local evidence passes in `c4c7cbc` and `8a794c0`; evidence baseline `cefbc74` passed repository CI `33134521467` | Retain default-disabled/single-controller/no-public-Gateway boundary; f7 and P2.5g evidence are recorded separately, while readiness-derived advertisement and independent caller E2E remain open |
| P2.5f7 | Terminal/Gateway vertical evidence gate | Local single-controller Docker/race/restart/reconnect gate passes in `0e8b284`; evidence baseline `cefbc74` passed repository CI `33134521467` | Retain same-repository test boundary and no-public-Gateway/no-external-caller claims; P2.5g artifact/usage evidence is recorded separately |
| P2.5g | Artifact and usage vertical | Local gate passes in implementation `0e6e108`: default-disabled development composition, durable artifact/usage repositories, async recovery/shutdown, real Docker output confinement and private staging, partial exec-derived usage, operation aggregation, and restart evidence. Repository CI `33157119149` passed all three jobs | Retain development-only/single-controller boundaries; publication, billing, external caller, aggregate, reliability, tenancy, deployment, and production claims remain open |
| P2.5h | Readiness-derived composition and exact advertisement | Local component/projection gate passes in implementation `2c55173`: explicit opt-in config, canonical IDs, complete dependency graph validation, empty-disabled behavior, and immutable exact Contract snapshot generation. Repository CI `33159099578` passed all three jobs. The Provider command graph still deliberately lacks caller-owned WebSocket/Gateway policy | Retain fail-closed Provider ownership. The reference stack supplies policy externally for P2.5i without adding an allow-all Provider default |
| P2.5i | Independent reference caller release gate | Passed locally with clean harness `1d93722` against Provider `d58497e`; evidence `20260830T073427.356961000Z` records 15 initial and 5 restart/resume passes, exact lock/config/image identities, separate processes, real sockets, and Docker | Publish/run this harness in CI separately. Do not promote it to Agent Platform, aggregate, multi-controller, hostile multi-tenant, deployment, or production evidence |
| P2 | Coding/remote-shell profile | Passed for the architecture's separately supplied reference caller gate. All earlier component/Contract gates retain their narrower evidence boundaries | Actual Agent Platform compatibility, aggregate conformance, multi-controller reliability, hostile multi-tenant security, deployment, and production gates remain open |
| P3 | Migration readiness and platform integration | Ready to begin from local binding/shadow/metrics component evidence (`4212e88`) now that the reference P2 caller gate passes | Supply a real platform migration target and prove locked-Suite/request shadow parity, new-run-only canary, rollback, old-run drain, metric parity, and unchanged platform-owned contracts |
| P4 | Optional capability profiles | Not started | Add browser, desktop, port forwarding, snapshots/restore, GPU, nested-container, and stronger-isolation profiles only through independent Contract, security, and conformance gates |
| Production readiness | Independent evidence tier, not a shortcut from P4 | Not established | Deployment, multi-controller reliability, multi-tenant security, operations, and production gates |

## Evidence Boundary

PR #17 merged the repository-owned Contract migration and its post-merge CI
run `32360376058` passed all required jobs. PR #18 then merged the protected-
admission Contract resources and bindings as `4774c3a`; post-merge run
`32363581638` passed `provider-contract`, `test`, and `docker-integration`.
PR #19 merged the local Suite runner and CI invocation as `e2755f5`; post-merge
run `32365284283` passed all required jobs.

- local Go tests are component evidence only;
- the local Contract verifier proves lock/resource identity, not protocol
  conformance;
- the local Suite runner executes 38 locked admission, lifecycle, exec,
  terminal-session, coding/shell capability, artifact-staging, and usage-evidence case IDs with the
  `providerapi`, `providerapi/v1`, and `provider/admission` test matrices; this remains Provider
  component/Contract-suite evidence, not aggregate lifecycle conformance;
- `suite_digest` is still a locked declared value and is not recomputed from
  Suite contents by the verifier; Git Contract-tree binding protects the
  consumed tree, but content-derived Suite digest remains an independent
  enhancement and is not claimed here;
- no aggregate lifecycle conformance, external-caller E2E,
  multi-controller reliability, multi-tenant safety, deployment readiness, or
  production readiness is claimed.

The final full race/shuffle run includes the discovery operation's bounded
handler `400` and parser-visible `501` transport tests under the corrected
projection.

## Current Verification

Passed locally (authorized test environment):

- JSON parsing of all newly added Contract resources;
- `git diff --check`;
- `internal/contractlock` unit tests;
- local Provider projection tests for `providerapi/v1` and `providerapi`;
- full `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- provider API socket/TLS tests;
- tagged Docker integration.
- P1.2.3 coordinator race/shuffle tests for idempotent accept, deadline
  pre-dispatch, known/unknown runtime outcomes, restart inspection, stale
  generation rejection, event replay, and concurrent reconciliation.
- P2.2b provider exec repository tests for idempotency and digest binding,
  cancellation target/generation binding, independent cancellation fencing, result
  retention and tombstones, immutable snapshots, concurrent memory access,
  file restart/lock/corruption handling, and cancelled contexts;
- P2.2b full race/shuffle test matrix, `go vet`, local Contract lock verifier,
  19-case local Conformance Suite, dependency-boundary check, and `git diff
  --check` passed in the authorized test environment.
- P2.2c focused repository/coordinator race/shuffle tests cover durable
  reservation before dispatch, attach identity and receipt conflicts, replay
  without redispatch, restart/query of unattached records and cancellation
  intents, cancellation confirmation gating, result/cancellation conflicts,
  context failures, deep copies, and file lock/corruption behavior.
- P2.3c0 full race/shuffle, vet, Contract lock verification, 26-case local
  Conformance Suite, JSON parsing, and diff checks passed against revision
  `71fee34380affcb46e1e1dce667475aa241048a4`.
- P2.3c1 focused and full race/shuffle, vet, unchanged Contract lock, 26-case
  Suite, JSON, dependency-boundary, and diff checks cover strict terminal-only
  requests, deadline/expiry bounds, immutable snapshots, transition rules,
  opaque handoff identity, and outcome-unknown non-reopening.
- P2.4 local verification covers JSON/YAML Contract resources, lock revision
  `7e00715e5e3583ec4f98eb25cfeab587638ac858`, 33-case Conformance, full
  race/shuffle, vet, artifact/usage domain bounds, memory adapter replay and
  conflict behavior, expiry, cancellation, immutable snapshots, and
  `git diff --check`. Post-push CI `32804619553` passed all three required
  jobs for `3b94146`. This remains provider-local evidence only: no HTTP route,
  artifact publication, billing truth, distributed reconciliation, external
  caller, tenancy, deployment, or production claim is made. P2.4a0 subsequently
  locked the three missing protected-admission operation bindings, async
  outcomes, safe pre-accept errors, and read descriptor digests. CI
  `32819717542` passed all required jobs for `2aba87f`, while route-absence tests
  confirm that no artifact/usage transport was composed. P2.4a1 then locked
  generic operation-family aggregation and the artifact/usage read-state
  matrices in `3846c9e`, `6f549c2`, and `dbea0e8`. Local race/shuffle, vet,
  lock verification, the 35-case Suite, projection/admission tests, and
  post-push CI `32823783136` passed. This adds no application, repository,
  aggregator, handler, router, transport, or external-caller evidence.
- P2.4a2 local verification covers durable artifact accept-before-dispatch,
  idempotent replay/conflict, generation/fencing checks, explicit dispatch and
  reconciliation, source-missing/content-rejected/outcome-unknown truth,
  no-duplicate dispatch, memory/file restart and lock/corruption/expiry
  behavior, operation-keyed usage evidence correlation, and operation-family
  aggregation with duplicate-ID fail-closed behavior. Authorized full
  race/shuffle, vet, Contract lock verification, 35-case Suite, and diff checks
  passed. CI `32827387303` passed all three required jobs. This remains
  provider-local component evidence: no handler, router, config, HTTP route,
  external caller, aggregate conformance, multi-controller reliability,
  multi-tenant security, deployment, or production claim is made.
- P2.4a3 local verification covers the three locked artifact/usage routes,
  strict admission and descriptor binding, artifact-stage schema preflight
  before mutation guard reservation, `202` accept-only staging, evidence/usage
  correlation, operation-family aggregation, bounded `400`/`403` mapping, and
  route nondisclosure. Full race/shuffle, vet, Contract lock verification,
  35-case Suite, projection tests, diff checks, and post-push CI
  `32838784395` passed. Create/session preflight is independently covered by
  P2.5c; external caller compatibility, aggregate conformance, multi-controller
  reliability, multi-tenant security, deployment, and production readiness
  remain unproven.
- Gateway clock correction `0893ac3` derives grant-expiry timers from the
  configured clock used by authorization and endpoint checks. The focused
  Gateway race/shuffle suite passed ten consecutive runs, and the full
  race/shuffle suite passed. This is deterministic component evidence only.
- P2.5b local verification covers Contract revision `22a148e2898477790512d5bb742605654ff00ebf`,
  tree `1a967c9c6ce9646c8431f6ee48699ec9f406a589`, the atomic coding/shell
  advertisement and rejection fixtures, exact create/session/evidence
  consistency, fail-closed application/wire projection, and three new Suite
  mappings. Full race/shuffle, vet, Contract lock verification, the 38-case
  Suite, diff checks, and post-push CI `32924361132` passed. Runtime dispatch,
  nonempty command advertisement, and external-caller evidence remain pending.
- P2.5c local verification covers create and runtime-session digest-consistent
  unknown-field rejection and encoded body limits before mutation guard
  reservation, plus unchanged valid replay and stale-fencing conflicts. The
  existing `protected-admission-replay-and-fencing` Suite case now selects
  these preflight regressions. Focused and full race/shuffle, vet, unchanged
  Contract lock verification, the mapped 38-case Suite, diff checks, and
  post-push CI `32926181615` passed. Application dispatch, runtime composition,
  and external-caller evidence remain pending.
- P2.5d local verification covers a Provider-specific Docker adapter without
  importing local `instance` models or repositories; exact ownership and
  immutable-spec digests; stable read-only `/inputs`, writable `/workspace`
  and `/outputs`, bounded tmpfs `/tmp`; digest-pinned image, numeric non-root
  identity, read-only root, disabled networking, dropped capabilities,
  no-new-privileges, resource/log bounds, idempotent create/remove, context
  cancellation, foreign-resource refusal, lost-response `outcome_unknown`,
  file-repository restart observation, and mount cleanup. Focused and full
  race/shuffle, vet, unchanged Contract verification, the 38-case Suite, diff
  checks, and live integration for both Docker packages passed at `de18787`;
  post-push CI `32929140044` passed all three jobs for evidence baseline
  `e3a8265`. This does not add exec/session/artifact/usage runtime
  dispatch, nonempty advertisement, external caller, multi-controller,
  multi-tenant, deployment, or production evidence.
- P2.5e local verification covers strict protected exec/cancel/result/operation
  projection; durable reservation before dispatch; independent file persistence
  and v1-to-v2 migration; execution/cancellation identity conflicts;
  sandbox/attempt/fence correlation; injected-clock temporal ordering; restart
  and on-demand reconciliation; terminal-summary retention after result expiry;
  real Docker exit handling, cancellation, private stdout/stderr capture,
  truncation, and idempotent identity-bound cleanup; and pre-accept rejection of
  unsupported environment, secret, and stdin references. Focused and full
  race/shuffle, vet, unchanged Contract verification, the 38-case Suite, diff
  checks, and live integration for both Docker packages passed at `5917a57`.
  Post-push CI `32937530059` passed `provider-contract`, `test`, and
  `docker-integration` for evidence baseline `2f7a79b`. At that baseline usage
  identity was bounded correlation only and the real collector was deferred to
  P2.5g; the later P2.5g local evidence is recorded separately. P2.5e does not
  prove external caller compatibility,
  aggregate conformance, multi-controller reliability, multi-tenant security,
  deployment, or production readiness.
- P2.5f1 local verification covers the backend-neutral terminal allocation,
  observation, attachment, cleanup, receipt, and stream boundaries; an
  in-sandbox broker that owns the PTY and shell; adapter-private container,
  broker-exec, and Unix-socket identity; opaque `ref:terminal/*` receipts;
  idempotent allocation, lost start responses, identity conflicts,
  per-sandbox/per-controller capacity, expiry, context cancellation, sandbox
  removal, corrupt state, and idempotent process-group cleanup. Full
  race/shuffle, vet, `go mod verify`, unchanged Contract verification, the
  locked 38-case Suite, diff checks, and both live Docker integration packages
  passed at `6778d3c`. The live test preserves a shell variable and broker exec
  identity across Provider driver reconstruction and a fresh attach. Building
  the broker into writable `/workspace` is test deployment only. Repository CI
  `33033284420` passed `provider-contract`, `test`, and `docker-integration` for
  evidence baseline `66dd3d1`. This does not prove durable session coordination,
  `ref:session:*` resolution, WebSocket or Gateway composition, external caller
  compatibility, aggregate conformance, multi-controller reliability,
  multi-tenant security, deployment, or production readiness.
- P2.5f2 local verification covers session repository v2 and valid v1
  migration; preservation of accepted operations and legacy successful
  handoffs; legacy running migration to `outcome_unknown`; immutable
  provider-neutral allocation receipts and observations; lifecycle
  ready/revision/generation/lease projection; session-local fencing high-water;
  accept-before-allocation; persisted acceptance-time allocation identity;
  idempotent replay/conflict; lost receipt attachment recovery without a second
  runtime allocation; no redispatch after an uncertain allocation or
  observation; restart reconciliation; expiry and identity-bound cleanup retry;
  corruption and duplicate-reference rejection; and lifecycle recheck before a
  registry-supplied success commit. Full race/shuffle, vet, `go mod verify`,
  unchanged Contract verification, the locked 38-case Suite, diff checks, and
  both live Docker integration packages passed at `ccffd52`. Post-push CI
  `33045725476` passed `provider-contract`, `test`, and `docker-integration` for
  evidence baseline `3abefd4`. This does not add a `ref:session:*`
  registry/resolver, WebSocket adapter, Gateway or command composition,
  nonempty advertisement, external caller, aggregate conformance,
  cross-repository atomicity, multi-controller reliability, multi-tenant
  security, deployment, or production readiness.
- P2.5g local verification covers artifact snapshot v2 with admission-derived
  tenant authority and explicit rejection of untrusted v1 state; durable
  accept-before-dispatch; lifecycle readiness, tenant, generation, lease, and
  fencing synchronization; request/retention deadlines; staged, rejected,
  missing, unknown, expired, recovery, and shutdown outcomes; and no swallowed
  reconciliation or persistence failures. The Docker output reader confines
  reads to an owned running generation and rejects links, directories, and
  non-regular files. The stager enforces digest/media/size, executes injected
  scanners by argv with bytes on stdin, writes private atomic content, and
  returns only `ref:staging/*`. Exec result observation derives only stable
  wall-time and exec-count evidence with `partial` reconciliation; it does not
  invent CPU, memory, network, price, or billing truth. Versioned locked file
  repositories, all-family operation reads, state-file separation, and
  default-disabled development composition pass focused and full race/shuffle,
  vet, `go mod verify`, unchanged Contract verification, the locked 38-case
  Suite, diff checks, and a Docker-tagged command-root vertical covering
  staged/rejected/missing evidence, operation aggregation, opaque-reference
  non-disclosure, and artifact/usage restart recovery. This reviewed worktree
  is based on implementation `0e6e108`; repository CI `33157119149` passes all
  three jobs. It proves no external caller,
  aggregate conformance, multi-controller reliability, multi-tenant security,
  deployment, publication, billing, or production readiness.
- P3 local component verification covers immutable ProviderRevision binding,
  deterministic canary selection, rollback isolation, drain state, shadow
  validation without dispatch, bounded metric aggregation, race/shuffle, vet,
  and `git diff --check`. This does not prove an external caller, traffic
  canary, rollback E2E, or platform-contract compatibility.

Pending:

- remote/CI publication of the independently versioned P2.5i reference harness;
  its clean local 15+5 scenario result is external-caller evidence, while the
  Provider command root correctly remains free of caller-owned authorization,
  revocation, recording, and public Gateway defaults;
- actual Agent Platform integration and P3 migration evidence. The separately
  inspected platform candidate still has no runnable sandbox caller/Gateway;
  the reference harness does not substitute for real request shadow parity,
  canary, rollback, old-run drain, metric parity, or unchanged platform
  contracts;
- optional content-derived Suite digest enhancement;
- aggregate lifecycle conformance, external-caller E2E, reliability, tenancy,
  deployment, and production gates.

## Next Entry

P1.1d is explicitly closed by the local Suite/security matrix, PR #19 CI, and
post-merge run `32365284283`. P1.2.0 is closed by PR #21, its three successful
PR checks, and post-merge run `32368734877`. P1.2.1 is closed by PR #22, its
three successful PR checks, and post-merge run `32370133083`. P1.2.2 is closed
as provider-local persistence only; the file adapter is single-controller
development evidence. P1.2.3 is closed as internal create dispatch and restart
reconciliation. P1.2.4 is closed as a projection/component slice; post-merge
CI run `32435540542` passed all required jobs. PR #26 merged the behavior-bound
Conformance mappings as `4ccb107`; post-merge run `32436541588` passed. PR #27
then composed the independent Provider lifecycle application and merged as
`28076a7`; post-merge run `32439289227` passed. It projects only `POST /v1/sandboxes`, `GET
/v1/sandboxes/{sandbox_id}`, and `GET /v1/operations/{operation_id}` after
protected admission. The command composition root now constructs an independent
Provider lifecycle application when explicitly enabled; disabled and
production-fake configurations remain fail-closed. Reserved
routes remain absent, and aggregate conformance, external-caller E2E,
multi-controller reliability, tenancy, deployment, and production claims
remain unproven. The P1.2.5 local Conformance mappings now exercise
coordinator idempotency, stale generation, concurrent reconciliation, deadlines,
cancellation, unknown outcomes, restart inspection, and locked DTO projection.
Terminate/lease/orphan cleanup are not authorized by the current Contract
revision. P1.2.5 is closed only for the current authorized subset. Terminate,
lease mutation, orphan cleanup, sessions, snapshots, runtime exec behavior,
and aggregate caller compatibility remain unproven or Contract-reserved. PR
#30 closed the bounded exec Contract gate only. P2.1 locally validates an
uncomposed Provider-local execution port with bounded input and opaque receipt
validation. PR #31 and post-merge CI close that local component slice. P2.2a
adds only result/intent domain validation; PR #33 and post-merge CI close that
domain slice. Neither slice exposes an exec route, durably accepts an operation,
retains a result, records cancellation intent in storage, reconciles an
outcome, selects a Docker/backend adapter, or proves runtime execution
behavior.

P2.2b is closed by PR #35 merge `c467cd4`, PR CI `32456100570`, and
post-merge CI `32456279722`. The next entry is P2.2c: define durable
pre-dispatch reservation/attach ordering, bounded coordination, pending
cancellation recovery/query boundaries, and an optional Canceler port. Do not
expose Provider HTTP, Docker/backend selection, or claim aggregate/runtime
execution compatibility from P2.2b.

P2.2c local implementation now provides durable reservation before executor
dispatch, exact opaque receipt attachment, bounded coordinator ordering, and
optional cancellation confirmation. Known non-context executor errors remain a
durable pending reservation rather than an inferred terminal failure; context
or receipt uncertainty is not redispatched on recovery. Cancellation intent
replay does not repeat external side effects, and current recovery exposes
query-only intent state rather than automatic Canceler retry. HTTP, Docker,
lifecycle-repository reuse, aggregate conformance, external E2E,
multi-controller, tenancy, deployment, and production claims remain unproven.

P2.2c is closed by PR #39 merge `17072e6`, PR CI `32460695928`, and post-merge
CI `32460914417`. PR #43 merged P2.3a/b as `21f5236`; PR CI `32468912019` and
post-merge CI `32469390678` passed. P2.3c0 correction `71fee34` makes the
terminal capability version `1.0.0`, aligns its capability profile with the
canonical `terminal-v1` session fixtures, and adds the 26th Suite case.
`ab9defc` binds revision `71fee34380affcb46e1e1dce667475aa241048a4` and tree
`4fafb742e40231cbf9fb957f5998bdce932fdb0d`, enforces terminal semver without
tightening the generic v1 Capability Schema, and verifies cross-resource
consistency. Full local race/shuffle, vet, lock verification, the 26-case Suite,
JSON parsing, and diff checks passed. Exact-head PR CI `32685685846` passed all
three jobs for head `16136d2`; PR #44 merged as `6c1fc90`, and post-merge CI
`32686754674` passed all three jobs. P2.3c0 is closed as Contract, capability
snapshot, DTO, handler projection, and local Suite evidence only. P2.3c1 now
locally defines a terminal-only request, accepted/running/terminal record state,
successful-only opaque WebSocket handoff derivation, and a transactional
authority port. PR #45 merged it as `4c37d8c`; PR CI `32696507856` and
post-merge CI `32696727371` passed all three jobs. P2.3c2 adds independent
provider/session memory and file persistence, idempotency replay, expiry
handling, compare-and-set generation/fencing, and same-transaction authority
rechecks. Direct main commit `e5c9dec` and post-push CI #103 / run
`32698606341` passed all three jobs. P2.3c3 now adds an independently
injectable session application boundary to the protected transport. POST
`/v1/sandboxes/{sandbox_id}/runtime-sessions` strictly decodes and projects an
accepted terminal operation after admission; GET
`/v1/operations/{operation_id}/runtime-session` projects only a successful,
unexpired opaque handoff. Pending, expired, failed, cancelled, and
`outcome_unknown` records map to stable errors; raw endpoints, addresses,
credentials, and provider tokens are rejected or omitted. The command
composition root still does not create an allocator, runtime driver, or
Provider WebSocket data plane. P2.3c3 is closed for bounded Provider transport
evidence by implementation commit `186190b` and post-push CI `32799871307`.
P2.3c4 then adds an independently composed Gateway boundary: caller/tenant/
session authorization binding, opaque reference resolution on every connect/
reconnect, bounded bidirectional frame proxying, revocation interruption,
expiry and generation fencing, and metadata-only recording. Commit `e675cb9`
and post-push CI `32801539995` close that slice as bounded component evidence.
A concrete WebSocket wire adapter, external caller E2E, distributed
revocation, multi-controller reliability, tenancy, deployment, and production
claims remain unproven. P2.4a0 then reconciled the artifact/usage protected-
admission vocabulary and lock in `3a9d8b7`, `7e00715`, and `2aba87f`; post-push
CI `32819717542` passed all three required jobs. P2.4a1 locked operation-family
aggregation and the evidence-read state matrices in `3846c9e`, `6f549c2`, and
`dbea0e8`; post-push CI `32823783136` passed all three required jobs and
executed the 35-case Suite. P2.4a2 then supplied the bounded application,
durable authority adapters, usage operation reader, and operation-family
aggregator in `152033f`, `0440272`, and `4d0bb70`; CI `32827387303` passed all
three required jobs. P2.4a3 now composes the three locked routes in commits
`f5111a5`, `ce3c6e0`, and `9a4bc71`, with the independent admission/error
correction in `c469337`: admission and descriptor binding complete before
application calls; stage returns only a `202` operation; artifact and usage
evidence projections enforce operation/sandbox/attempt/fencing correlation;
and the generic operation route uses composed family readers. Strict document
preflight rejects artifact-stage invalid documents before mutation guard
reservation; P2.5c commits `6c2962b` and `6340604` extend that ordering and
Suite mapping to create/session without adding dispatch.
Focused Provider tests and the local full race/shuffle, vet, lock, Suite, and
diff gates pass. Post-push CI `32838784395` passed all three jobs for
`1ca115b`. The command composition root injects
no synthetic artifact stager or usage collector; missing dependencies remain a
bounded `503` surface. Artifact publication, billing, aggregate conformance,
external-caller compatibility, multi-controller reliability, multi-tenant
safety, deployment, and production readiness are not claimed.

The first 2026-08-30 audit at documentation baseline `bba02a6` correctly found
no existing caller in the Provider repository or the separately inspected
Agent Platform candidate. That historical result is retained as the reason a
new independent harness was created; it is no longer the current P2.5i state.

`/Users/echo/Projects/shell-echo/sandbox-runtime-e2e` is now a separate Git
module. Its caller and command cannot import Provider implementation packages;
only its reference deployment process imports exported Provider/Gateway
composition. Full evidence runs reject a dirty or unversioned harness and a
Provider checkout with non-documentation changes after the locked baseline.

The final clean local run used:

| Input | Locked value |
| --- | --- |
| Caller harness | `1d93722000056ddcf7dff41d2c633ee8f7b130db` |
| Provider implementation | `d58497e5359056858564b9ac663178958cf5a6d6` |
| Contract revision/tree | `22a148e2898477790512d5bb742605654ff00ebf` / `1a967c9c6ce9646c8431f6ee48699ec9f406a589` |
| Suite identity | repository-owned Provider v1, 38 cases |
| Evidence directory | `20260830T073427.356961000Z` under the ignored E2E evidence root |

All 15 initial and 5 reconstruction/resume scenarios passed. The initial run
covered exact capability discovery, protected create, replay, lifecycle,
exec/result/usage, stale fencing, cancellation, terminal handoff/Gateway data,
two-context denial, expiry, revocation, artifact evidence, cross-tenant staging
denial, and mTLS caller binding. The reconstructed stack retained lifecycle,
exec/usage/artifact evidence, opaque handoff, and the same terminal shell.

This is sufficient for the reference P2.5i caller gate. It is not evidence that
the existing Agent Platform candidate is compatible, and it does not prove
aggregate conformance, distributed revocation, multi-controller reliability,
hostile multi-tenant isolation, deployment, or production readiness. P3 still
requires a real platform migration target and its separately named traffic
evidence.

The 2026-08-28 P2.5g review was based on implementation `0e6e108` from
`main@0e6e108`; its artifact/usage local and Docker gates pass, and repository
CI run `33157119149` passes all three jobs. The subsequent P2.5h implementation
`2c55173` is based on `main@0e6e108` and adds explicit canonical-profile opt-in,
dependency-absence validation, and readiness-derived immutable advertisement.
Full local Go, Contract/Suite, diff, and fixed-digest Docker gates pass without
changing Contract revision `22a148e2898477790512d5bb742605654ff00ebf` or its
38 cases. Repository CI run `33159099578` passes all three jobs for
documentation baseline `0ec712c`, and run `33160646494` passes all three jobs
for the reviewed documentation baseline `bba02a6`.
The Provider command root intentionally marks the concrete WebSocket and
caller-owned Gateway boundary unavailable, so explicit standalone profile
startup still fails closed. The reference stack supplies those caller-owned
dependencies externally for P2.5i without weakening the Provider default.
