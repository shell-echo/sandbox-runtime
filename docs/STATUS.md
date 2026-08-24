# Project Status

Updated: 2026-08-24

This document is the implementation ledger for the repository-owned MIT
Provider Contract. It distinguishes local component evidence, Contract
projection evidence, CI, Conformance, external-caller compatibility,
multi-controller reliability, multi-tenant security, deployment, and
production readiness.

## Current Baseline

| Item | Evidence | Status |
| --- | --- | --- |
| Checkout | `main@e5c9dec` | P2.3c2 implementation and post-push CI are passed; the implementation remains provider-local only |
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
| Contract resources | OpenAPI, admission, lifecycle, bounded exec, terminal-session schemas, terminal capability/profile fixture and mapping semantics, Suite | Local Contract consistency is restored; the terminal advertisement uses semver `1.0.0` and canonical profile `terminal-v1`; zero advertisement remains the default |
| Contract lock | revision `71fee34380affcb46e1e1dce667475aa241048a4`; tree `4fafb742e40231cbf9fb957f5998bdce932fdb0d`; semantic rules `sha256:1b07682a7c0398219b7d52c9283f78d520a81a36f77eb729bcff81dcd90671b9` | Local verifier, 26-case Conformance, exact-head PR CI, merge, and post-merge CI passed |
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
| P2.3c3 | Protected transport projection and opaque handoff retrieval | Blocked by P2.3c0-c2 | Route, admission, error projection, and endpoint non-disclosure evidence; no public Gateway claim |
| P2.3c4 | Runtime Gateway integration | Not started | Independently owned authorization, proxy, reconnect, revocation, recording, external caller, and end-to-end evidence |
| P2 | Coding/remote-shell profile | P2.1, P2.2a-c, and P2.3a-c0 closed for bounded Provider/Contract evidence | P2.3c1 provider-local session domain and authority port |
| P3 | Migration readiness and external-caller integration | Not started | External caller E2E, rollback and canary evidence |
| P4 | Production hardening | Not started | Deployment, multi-controller, multi-tenant, and production gates |

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
- the local Suite runner executes 26 locked admission, lifecycle, exec, and
  terminal-session case IDs with the `providerapi`, `providerapi/v1`, and
  `provider/admission` test matrices; this remains Provider
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

Pending:

- P2.3c3 transport projection and separate Gateway integration evidence;
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
`32698606341` passed all three jobs. No Provider HTTP route, allocator, runtime
driver, WebSocket data plane, or Gateway is composed. The next entry is
P2.3c3 protected transport projection.
