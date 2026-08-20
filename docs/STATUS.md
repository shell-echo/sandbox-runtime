# Project Status

Updated: 2026-08-20

This document is the implementation ledger for the repository-owned MIT
Provider Contract. It distinguishes local component evidence, Contract
projection evidence, CI, Conformance, external-caller compatibility,
multi-controller reliability, multi-tenant security, deployment, and
production readiness.

## Current Baseline

| Item | Evidence | Status |
| --- | --- | --- |
| Checkout | `codex/p1.2-lifecycle-plan` from `e2755f5` | Planning |
| Review | PR [#17](https://github.com/shell-echo/sandbox-runtime/pull/17) merged as `43ff3d7`; PR [#18](https://github.com/shell-echo/sandbox-runtime/pull/18) merged as `4774c3a`; PR [#19](https://github.com/shell-echo/sandbox-runtime/pull/19) merged as `e2755f5` | P1.1d passed; P1.2 plan pending |
| Worktree | clean | Verified |
| Contract namespace | `urn:shell-echo:sandbox-runtime:provider-v1` | Locked |
| Contract version/license | `1.0.0` / MIT | Locked |
| Contract resources | OpenAPI, admission schemas, semantic rules, fixtures, Suite | Local tree updated through `72c2574` |
| Contract lock | revision `e0ed615`; tree `bb3fcd7`; OpenAPI, manifest, semantic-rule, fixture, and Suite bindings | Locked locally |
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
| P1.2 | Async lifecycle, operation ledger, reconciliation, events | Planning; now unblocked by P1.1d, no lifecycle behavior changed | Authority/Contract inventory and first bounded implementation slice |
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

Pending:

- P1.2 authority/Contract inventory and first bounded lifecycle plan;
- optional content-derived Suite digest enhancement;
- aggregate lifecycle conformance, external-caller E2E, reliability, tenancy,
  deployment, and production gates.

## Next Entry

P1.1d is explicitly closed by the local Suite/security matrix, PR #19 CI, and
post-merge run `32365284283`. The next entry is P1.2 planning; implementation
must remain bounded by the lifecycle Contract and this repository's ownership
boundary.
