# Implementation Plans

This directory indexes implementation plans that refine the authoritative
delivery order and release gates in [`docs/architecture.md`](../architecture.md).
Plans may narrow a phase into reviewable slices, but they do not replace the
locked repository-owned Provider Contract or relax an architecture release
gate.

Current execution state, landed slices, and the next planned slice are tracked
in [`docs/STATUS.md`](../STATUS.md).

| Phase | Plan | Status |
| --- | --- | --- |
| P0 | [Local Provider Contract migration](p0-local-provider-contract.md) | PR #17-#19 merged; post-merge CI passed; P0.4 closed |
| P1.1 | [Provider API admission](p1.1-provider-api-admission.md) | P1.1d release gate passed; lifecycle remains unclaimed |
| P1.1b | [mTLS capability discovery](p1.1b-capability-discovery.md) | Passed under local Contract with PR/post-merge evidence |
| P1.1c | [Protected-operation admission](p1.1c-protected-operation-admission.md) | Passed under local Contract with PR/post-merge evidence |
| P1.2 | [Async lifecycle](p1.2-async-lifecycle.md) | Bounded Contract-authorized subset passed through PR #27; reserved lifecycle families remain separately gated |
| P2 | [Coding/remote-shell authority inventory](p2-coding-remote-shell.md) | Bounded slices through P2.5h have component/Contract/CI evidence; the co-located reference caller gate passes, while Agent Platform E2E, aggregate conformance, reliability, tenancy, deployment, and production gates remain open |
| P2.5 | [Coding/shell vertical composition](p2.5-coding-shell-vertical-composition.md) | P2.5a-h retain their recorded local/CI gates; latest local and hosted P2.5i reference evidence `9eb32ba`/`5aae281` passed 15+5 scenarios in local run `20260904T013909.243838000Z` and hosted run `33826813099`; real Agent Platform E2E, aggregate conformance, reliability, tenancy, deployment, and production gates remain open |
| P2.5f | [Terminal and Gateway vertical](p2.5f-terminal-gateway-vertical.md) | f0 audit and f1-f7 terminal/Gateway slices pass their current local and repository CI gates; no public Gateway, independent caller, or capability advertisement was added |
| P3 | [Migration readiness](p3-migration-readiness.md) | Local binding/shadow/metrics component evidence and latest local/hosted candidate evidence `9eb32ba`/`5aae281` (15+5 scenarios; hosted run `33826813100`) exist; real platform shadow E2E, canary, rollback, drain, and migration gates remain blocked |
| P3 candidate | [Platform candidate caller](p3-platform-candidate-caller.md) | Candidate caller and Docker process harness passed locally at `9eb32ba`/`5aae281` and in hosted run `33826813100`; evidence remains distinct from real Veronica platform evidence |
| Internal foundation | [Internal Block Manifest Loader](block-manifest-loader.md) | Implemented as bounded component evidence; no Provider Contract or public API change |
| P4 Browser | [Optional Profiles](p4-optional-profiles.md) | Browser Contract/projection, exact sandboxed signed amd64/arm64/v8 image publication (`33724368530`), uncomposed session/reference/usage components, fail-closed Docker/private-relay, provenance, restricted-egress/create-policy, protected transport (`b8423f5`), and caller-owned Gateway (`5aae281`) components have named evidence; complete command/runtime composition, public caller edge, advertisement, and Browser caller remain open |
