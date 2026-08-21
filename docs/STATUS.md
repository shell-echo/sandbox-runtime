# Project Status

Updated: 2026-08-21

This document is the implementation ledger for the repository-owned MIT
Provider Contract. It distinguishes local component evidence, Contract
projection evidence, CI, Conformance, external-caller compatibility,
multi-controller reliability, multi-tenant security, deployment, and
production readiness.

## Current Baseline

| Item | Evidence | Status |
| --- | --- | --- |
| Checkout | `codex/p1.2-lifecycle-next` at `297eeb6`, based on `origin/main@4ccb107` | P1.2.5a locally implemented; PR/CI pending |
| Review | PR [#17](https://github.com/shell-echo/sandbox-runtime/pull/17) merged as `43ff3d7`; PR [#18](https://github.com/shell-echo/sandbox-runtime/pull/18) merged as `4774c3a`; PR [#19](https://github.com/shell-echo/sandbox-runtime/pull/19) merged as `e2755f5`; PR [#21](https://github.com/shell-echo/sandbox-runtime/pull/21) merged as `c5a4a65`; PR [#22](https://github.com/shell-echo/sandbox-runtime/pull/22) merged as `44f39ec`; PR [#23](https://github.com/shell-echo/sandbox-runtime/pull/23) merged as `ac72eab`; PR [#24](https://github.com/shell-echo/sandbox-runtime/pull/24) merged as `2e3dde6`; PR [#25](https://github.com/shell-echo/sandbox-runtime/pull/25) merged as `88506d1`; PR [#26](https://github.com/shell-echo/sandbox-runtime/pull/26) merged as `4ccb107`; PR [#27](https://github.com/shell-echo/sandbox-runtime/pull/27) open at `f659789` | P1.2.4 passed; PR #26 post-merge CI待补证; PR #27 CI `32437596482` in progress |
| Worktree | Clean at `297eeb6` | Local composition evidence recorded; no remote PR claim |
| Contract namespace | `urn:shell-echo:sandbox-runtime:provider-v1` | Locked |
| Contract version/license | `1.0.0` / MIT | Locked |
| Contract resources | OpenAPI, admission and lifecycle schemas, semantic rules, fixtures, Suite | Locked and merged; P1.2.0 passed |
| Contract lock | revision `5fc9ce3`; tree `1a75340`; OpenAPI, manifest, semantic-rule, fixture, and Suite bindings | Locked locally |
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
| P1.2.5 | Lifecycle release gate | In progress; local Suite lifecycle IDs now execute coordinator/projection behavior matrices | Complete authorized fault/concurrency matrix, document unsupported/unproven families, PR/post-merge CI |
| P1.2.5a | Provider lifecycle composition | PR #27 open; CI run `32437596482` in progress | PR CI, review, post-merge CI, then retain fake-driver and production-readiness boundaries |
| P1.2 | Async lifecycle, operation ledger, reconciliation, events | P1.2.0-P1.2.4 passed; P1.2.5 release gate in progress; P1.2.5a next | Close P1.2.5 before P2 or production claims |
| P2 | Coding/remote-shell profile | Not started | P1.2 completion and profile-specific Conformance |
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
- the local Suite runner executes all 10 required case IDs with the
  `providerapi` and `provider/admission` test matrices; this remains Provider
  component/Contract-suite evidence, not aggregate lifecycle conformance;
- `suite_digest` is still a locked declared value and is not recomputed from
  Suite contents by the verifier; Git Contract-tree binding protects the
  consumed tree, but content-derived Suite digest remains an independent
  enhancement and is not claimed here;
- no aggregate lifecycle conformance, external-caller E2E,
  multi-controller reliability, multi-tenant safety, deployment readiness, or
  production readiness is claimed.

The local Contract explicitly authorizes the discovery operation's `400` and
parser-visible `501` outcomes, but implementation evidence for those outcomes
still needs to be re-run under the new projection.

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

Pending:

- P1.2.5 lifecycle release gate and fault/concurrency matrix;
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
Conformance mappings as `4ccb107`; its post-merge run `32436541588` remains
待补证 in this checkout because the GitHub Actions API was unavailable. It projects only `POST /v1/sandboxes`, `GET
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
revision. P1.2.5a is implemented locally; its focused acceptance and PR
post-merge evidence remain pending.
