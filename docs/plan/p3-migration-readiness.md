# P3 Migration Readiness Plan

Status: the repository-local migration component boundary is implemented in
commit `4212e88`; post-push CI run `32805284762` concluded success. The
separately versioned reference P2.5i caller gate passes, so this slice is ready
to consume a real platform target. The 2026-09-01 read-only re-audit found no
runnable Agent Platform caller or migration harness in the available platform
candidate. P3 is therefore blocked for actual shadow traffic, canary, rollback,
drain, and metric-parity evidence.

## Authority and scope

The calling platform owns WorkOrder, Run, ProviderRevision selection policy,
Artifact metadata/publication, events, usage accounting, Gateway authorization,
and the external Conformance execution environment. This repository owns only
provider-independent readiness primitives that can be tested without changing
those contracts.

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

## Current platform audit

The available `/Users/echo/Projects/shell-echo/veronica` checkout is local
`main@4f812468e2827c86823490ce83e578ec4448cb3d`, 85 commits ahead of live
GitHub `origin/main@a758c219fd9f14a015368ab95914ed7386c05afc`. Its tracked
and visible untracked tree contains Blueprint/governance and TF00 feasibility
assets with Python runners, but no Application service, Provider client,
WorkOrder/AgentRun mapping, Gateway, mTLS/JWS PKI configuration, reachable
Provider endpoint, or migration traffic harness. The bounded Temporal
dev-server smoke explicitly forbids workers, workflows, T2/T3, and external
services and therefore cannot serve as a platform caller. Its pre-existing
working-tree changes were left untouched. The older
`/Users/echo/Projects/shell-echo/sandbox-runtime-e2e` checkout is a reference
caller preparation tree with no remote, not an Agent Platform caller.

This is a blocking environment gap, not a failed Provider test. The minimum
input to resume P3 is a real platform caller/service with the locked
Contract/profile and ProviderRevision, identity-bound mTLS/JWS credentials,
Provider/Gateway endpoints, and a platform-owned shadow/canary/rollback/drain
and metric-comparison harness.

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

## Release gate and next work

The reference P2.5i harness closes the prerequisite caller gate without proving
platform migration. P3 is not release-ready until a real platform target locks
the same Contract/profile, proves capability/request shadow parity, canaries
only new runs, demonstrates rollback and old-run drain, and compares lifecycle,
exec, orphan, session, resource-evidence, and reconciliation metrics without
changing WorkOrder, Artifact, event, usage, Gateway, or frontend contracts.
