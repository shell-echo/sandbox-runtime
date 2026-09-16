# P3 Migration Readiness Plan

Status: **Retired / Superseded by ADR 0037.** The repository-local migration
component boundary remains implemented in commit `4212e88`; post-push CI run
`32805284762` concluded success. The separately versioned reference P2.5i
caller gate and all recorded P3 component evidence are retained at their
original boundaries. The concrete Agent Platform is no longer an integration
target, so there is no active P3 shadow-traffic, canary, rollback, drain, or
metric-parity release gate. A future generic caller adoption program requires
a new plan and evidence identity under ADR 0037.

## Authority and scope

This historical plan assumed that the calling platform owns WorkOrder, Run,
ProviderRevision selection policy,
Artifact metadata/publication, events, usage accounting, Gateway authorization,
and the external Conformance execution environment. This repository owns only
provider-independent readiness primitives that can be tested without changing
those contracts. ADR 0037 retains that generic caller/Provider ownership split
while superseding the binding to a specifically named Agent Platform.

The `migration` package provides:

- immutable `Revision` identity covering capability/runtime profile, Contract
  namespace/version, image digest, and security-policy digest;
- deterministic canary binding for new runs and immutable replay for existing
  run bindings;
- rollback that changes only future selections, with explicit draining and
  completed states for old bindings;
- shadow validation through an injected locked-Contract checker without
  serving traffic or dispatching a provider operation;
- bounded aggregation of lifecycle latency, exec success, orphan count,
  session stability, resource evidence, and reconciliation backlog.

## Non-goals

This slice does not implement an external caller, HTTP/WebSocket wire adapter,
production traffic routing, platform database/queue integration, deployment,
multi-controller coordination, cross-tenant authorization, or production
readiness. Local callbacks and metrics are component test seams, not external
compatibility evidence.

## Completed platform audit and identity check

The completed 2026-09-02 content audit observed the available
`/Users/echo/Projects/shell-echo/veronica` checkout at local
`main@17bb3855ba513b3a0e511f68f48c4e6aefbf265d`, 90 commits ahead of live
GitHub `origin/main@a758c219fd9f14a015368ab95914ed7386c05afc`. Its tracked and
visible untracked tree contained Blueprint/governance and TF00 feasibility
assets with Python runners, but no Application service, Provider client,
WorkOrder/AgentRun mapping, Gateway, mTLS/JWS PKI configuration, reachable
Provider endpoint, or migration traffic harness. The bounded Temporal
dev-server smoke explicitly forbade workers, workflows, T2/T3, and external
services and therefore could not serve as a platform caller.

A 2026-09-06 identity-only check found the dirty checkout at
`main@22343bb92b74e5d6e0aaf17d671344dd8c1bc7f9`, 110 commits ahead of unchanged
`origin/main`. Newer content was not re-audited, so this observation makes no
current capability claim. No runnable platform target has been independently
supplied to this repository; that environment gap historically kept the real
P3 gate open before ADR 0037 retired the target.
Pre-existing working-tree changes were left untouched. The older
`/Users/echo/Projects/shell-echo/sandbox-runtime-e2e` checkout is a reference
caller preparation tree with no remote, not an Agent Platform caller.

This was a blocking environment gap, not a failed Provider test. P3 is no
longer resumable as an Agent Platform migration. A future caller/service must
start a new adoption plan with the locked Contract/profile and
ProviderRevision, identity-bound mTLS/JWS credentials, Provider/Gateway
endpoints, and caller-owned rollout and evidence rules. Generic protected
admission additionally remains gated on ADR 0037's coordinated issuer protocol
slice.

## Acceptance evidence

- invalid revisions and profile-changing canaries fail closed;
- the same run remains bound to its original revision across replay and
  rollback;
- rollback changes only new run bindings and old runs can be marked draining;
- shadow validation bounds document size, copies the document, and suppresses
  checker error details;
- metric samples reject inconsistent dimensions and aggregate bounded counters;
- `go test -race -shuffle=on -count=1 ./...`, `go vet ./...`, the locked
  Contract verifier, Conformance Suite, and `git diff --check` pass.

## Historical release gate

The reference P2.5i harness closes the prerequisite caller gate without proving
platform migration. Before retirement, P3 would have required a real platform
target to lock the same Contract/profile, prove capability/request shadow
parity, canary only new runs, demonstrate rollback and old-run drain, and
compare lifecycle, exec, orphan, session, resource-evidence, and reconciliation
metrics without changing caller-owned contracts. That gate was never closed
and is no longer active. Its component and candidate results remain historical
evidence only.
