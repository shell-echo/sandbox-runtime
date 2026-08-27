# Project Context

Updated: 2026-08-27

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

This snapshot was audited on 2026-08-27 against P2.5f1 implementation commit
`6778d3c`. Its full local gates, including live Docker terminal reconnect,
passed. Evidence baseline `66dd3d1` then passed repository CI run `33033284420`
for P2.5f1. These baselines identify reviewed evidence; they are not
self-updating assertions about the checkout.

Contract identity:

- namespace: `urn:shell-echo:sandbox-runtime:provider-v1`
- version/license: `1.0.0` / MIT
- revision: `22a148e2898477790512d5bb742605654ff00ebf`
- Contract tree: `1a967c9c6ce9646c8431f6ee48699ec9f406a589`
- locked Conformance Suite: 38 cases

| Phase | Verified maturity | Open gate |
| --- | --- | --- |
| P0 | Passed: repository-owned MIT Contract migration and lock | Retain lock and projection regression |
| P1.1 | Passed for DTO, mTLS discovery, JWS/digest/replay/fencing admission | Does not prove runtime behavior or production identity infrastructure |
| P1.2 | Passed for the bounded Contract-authorized lifecycle subset and development composition | Provider lifecycle has fake and Docker development adapters; reserved lifecycle families and production gates remain open |
| P2.1-P2.4a3 | Bounded exec, result, terminal, Gateway, artifact, usage, admission, application, persistence, and transport components have local Contract/CI evidence | P2 is not vertically composed into a real coding/shell Provider and no independent caller E2E environment exists |
| P2.5a-e, P2.5f0-f1 | Plan, coding/shell Contract/profile, mutation preflight, Docker runtime foundation, and the exec vertical pass their local and CI gates; the terminal/Gateway audit and reconnectable terminal runtime/Docker adapter pass their respective design, local, and CI gates | Durable session coordination, opaque resolution, WebSocket/Gateway composition, artifact/usage, readiness-derived advertisement, and independent caller gates remain open |
| P3 | Local revision binding, shadow-validation, canary/rollback/drain, and metrics primitives passed component tests | P2 gate, external caller, real traffic parity, canary, rollback, and old-run drain E2E remain open |
| P4 | Optional capability profiles have not started | Each browser/desktop/forwarding/snapshot/GPU/isolation profile needs independent Contract, security, and conformance gates |

Production readiness is not a numbered phase shortcut. Aggregate conformance,
multi-controller reliability, hostile multi-tenant security, deployment, and
production operations remain separate and unproven even after a future P2/P3
E2E passes.

The latest verified repository CI for P2.5f1 evidence baseline `66dd3d1` is run
`33033284420`; its `provider-contract`, `test`, and `docker-integration` jobs
passed. This remains repository CI evidence, not independent caller or
production evidence.

## Current P2 Blockers

P2 has two independent blockers. Supplying an external caller alone would not
make the current Provider a usable coding/shell implementation.

1. Provider vertical composition is incomplete. P2.5e locally composes the
   protected exec/cancel/result/operation routes over durable acceptance, a
   separate file ledger, and the Provider Docker executor/canceler, but it is a
   development-only single-controller slice. P2.5f1 adds a separate
   backend-neutral terminal runtime, an in-sandbox PTY broker, and a Docker
   adapter that can attach to the same broker and shell after rebuilding the
   Provider driver. This runtime is not connected to the durable session
   application. Session coordination, opaque `ref:session:*` resolution,
   WebSocket/Gateway, artifact, and usage applications remain absent from
   command composition. Startup capability construction still advertises empty
   capability and runtime-profile arrays. No artifact staging or usage
   collection is yet composed.
2. No independently owned caller/platform E2E environment is runnable. The
   repository's 38-case runner maps to repository-local Go tests and CI has no
   external-platform job. The separately inspected platform candidate at
   `CelestialsGroup/agent-blueprints@cf623ac` still marks Sandbox Provider,
   Sandbox Controller, and Runtime Gateway unimplemented and has no executable
   E2E scenario.

No external E2E was run or claimed during the audit.

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
`66dd3d1`. The remaining terminal vertical is still open. Capability
advertisement remains empty. The next implementation slice is P2.5f2:

1. Implement durable session coordination, repository migration, and trusted
   lifecycle-authority synchronization, then complete opaque reference
   resolution, bounded WebSocket/Gateway composition, command recovery, and the
   local evidence gate through P2.5f7. The detailed order is in the
   [terminal/Gateway plan](plan/p2.5f-terminal-gateway-vertical.md).
2. Compose a real artifact stager and usage collector, then enable capability
   advertisement only when all required dependencies are present.
3. Supply an independently owned mTLS/JWS caller and reproducible deployment,
   run the locked Suite and coding/shell E2E, and only then evaluate P3 traffic
   shadowing, canary, rollback, and drain.

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
