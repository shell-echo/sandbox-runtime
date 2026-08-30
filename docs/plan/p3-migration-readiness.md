# P3 Migration Readiness Plan

Status: the repository-local migration component boundary is implemented in
commit `4212e88`; post-push CI run `32805284762` concluded success. P3 is
ready for real platform integration because the separately versioned reference
P2.5i caller gate now passes. No actual Agent Platform shadow traffic, canary,
rollback, drain, or metric-parity evidence exists yet.

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
