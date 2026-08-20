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
| Checkout | `codex/p1.1-local-admission-contract@f9297c4` | In progress; PR pending |
| Review | PR [#17](https://github.com/shell-echo/sandbox-runtime/pull/17) merged as `43ff3d7`; current branch has no PR yet | Current slice pending review |
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
| P0.4 | Re-run P1.1 evidence against the repository-owned Contract | In progress; local validation passed on `f9297c4` | PR CI and post-merge evidence |
| P1.1a | Provider v1 DTOs and strict decoder | Local projection and decoder regression passed on `f9297c4` | PR CI and post-merge evidence |
| P1.1b | mTLS-only capability discovery | Local TLS matrix and locked response projection passed on `f9297c4` | PR CI and post-merge evidence |
| P1.1c | Protected-operation admission primitives and transport composition | Local Contract semantic binding matrix and admission regression passed on `f9297c4` | PR CI, review, and post-merge evidence |
| P1.1d | Admission release gate | In progress; not closed | Execute/approve local Suite and security matrix, then PR and post-merge CI |
| P1.2 | Async lifecycle, operation ledger, reconciliation, events | Not started; prohibited until P1.1d closes | New implementation slice only after gate closure |
| P2 | Coding/remote-shell profile | Not started | P1.2 completion and profile-specific Conformance |
| P3 | Migration readiness and external-caller integration | Not started | External caller E2E, rollback and canary evidence |
| P4 | Production hardening | Not started | Deployment, multi-controller, multi-tenant, and production gates |

## Evidence Boundary

PR #17 merged the repository-owned Contract migration and its post-merge CI
run `32360376058` passed `provider-contract`, `test`, and
`docker-integration`. The current branch adds protected-admission Contract
resources and bindings; those are not main-branch or release-gate evidence until
the follow-up review and merge complete.

- local Go tests are component evidence only;
- the local Contract verifier proves lock/resource identity, not protocol
  conformance;
- the local Suite is still a declaration until its cases are executed by a
  conformance runner; projection and semantic-binding tests are narrower
  evidence;
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

- PR for `codex/p1.1-local-admission-contract` and its PR CI;
- post-merge CI on the resulting main revision;
- execution of the declared local Conformance Suite beyond projection and
  semantic-binding tests;
- review of the P1.1d release-gate evidence.

## Next Entry

After the current branch is reviewed and merged, re-run the post-merge
admission matrix and decide whether P1.1d can close. P1.2 remains prohibited
until that release gate is explicitly closed.
