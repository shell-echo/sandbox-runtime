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
| Checkout | `codex/p1.1-release-gate-status@7b35a63` | In progress |
| Worktree | clean after the Contract migration changes are committed | Verified |
| Contract namespace | `urn:shell-echo:sandbox-runtime:provider-v1` | Locked |
| Contract version/license | `1.0.0` / MIT | Locked |
| Contract resources | OpenAPI, six JSON Schemas, semantic rules, two fixtures, Suite | Landed in `c0efc67` |
| Contract lock | local revision/tree and OpenAPI/manifest digests in `compatibility/sandbox-runtime/contract.lock.json` | Landed in `fb83eb5` |
| External Agent Contract | no longer consumed; old compatibility evidence is historical only | Removed from implementation |

The lock verifier is intentionally bound to the repository-owned Contract tree.
It does not clone, mount, or read an external source repository.

## Plan Ledger

| Slice | Scope | Status | Required next evidence |
| --- | --- | --- | --- |
| P0.0 | Freeze local Contract ownership, namespace, version, license, resource layout, and lock | Passed locally; commits `c0efc67`, `fb83eb5` | Full verifier and CI on the migration branch |
| P0.1 | Replace external lock verifier with local tree/digest/semantic/fixture validation | Passed locally in `6043236` | CI provider-contract job |
| P0.2 | Migrate DTO/projection tests and CI to local Contract | Passed locally in `6043236` | CI provider-contract job |
| P0.3 | Rebase architecture, ADRs, README, plans, and status on local Contract | Passed locally in `7b35a63` | Documentation review on PR |
| P1.1a | Provider v1 DTOs and strict decoder | Historical implementation exists; compatibility evidence reset by Contract change | Re-run local Contract projection and decoder matrix |
| P1.1b | mTLS-only capability discovery | Implementation exists; local Contract response authority now explicit | Real TLS matrix, local response projection, CI |
| P1.1c | Protected-operation admission primitives and transport composition | Implementation exists; local Contract semantic coverage is incomplete | Re-run admission matrix under local rules; do not claim lifecycle |
| P1.1d | Admission release gate | Not closed under the new Contract | Local Suite/security matrix, PR CI, review of semantic rules |
| P1.2 | Async lifecycle, operation ledger, reconciliation, events | Not started; prohibited until P1.1d closes | New implementation slice only after gate closure |
| P2 | Coding/remote-shell profile | Not started | P1.2 completion and profile-specific Conformance |
| P3 | Migration readiness and external-caller integration | Not started | External caller E2E, rollback and canary evidence |
| P4 | Production hardening | Not started | Deployment, multi-controller, multi-tenant, and production gates |

## Evidence Boundary

The previously merged P1.1 PRs and their green CI runs prove the old
implementation against the former external Contract only. They do not prove
the new local Contract. Until the migration is merged and revalidated:

- local Go tests are component evidence only;
- the local Contract verifier proves lock/resource identity, not protocol
  conformance;
- the local Suite is a declaration until its tests are executed;
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

- CI for the local `provider-contract` job;
- final documentation review on the PR.

## Next Entry

Open review for `7b35a63` and wait for the local `provider-contract` CI job. Only after the
new Contract projection, admission matrix, and CI are green may P1.1d be
reopened. P1.2 remains prohibited until that release gate is explicitly
closed.
