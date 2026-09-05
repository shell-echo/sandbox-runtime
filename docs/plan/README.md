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
| P2.5 | [Coding/shell vertical composition](p2.5-coding-shell-vertical-composition.md) | P2.5a-h retain their recorded local/CI gates; hosted P2.5i run `33970773414` passed 15+5 scenarios against harness/Provider `17ed6ca`/`b4d41c9`, and the latest local pre-refresh run `20260905T080530.577843000Z` passes against `59e08d5`/`c0a55d1`; real Agent Platform E2E, aggregate conformance, reliability, tenancy, deployment, and production gates remain open |
| P2.5f | [Terminal and Gateway vertical](p2.5f-terminal-gateway-vertical.md) | f0 audit and f1-f7 terminal/Gateway slices pass their current local and repository CI gates; no public Gateway, independent caller, or capability advertisement was added |
| P3 | [Migration readiness](p3-migration-readiness.md) | Local binding/shadow/metrics evidence, hosted candidate run `33970773345` against harness/Provider `17ed6ca`/`b4d41c9`, and latest local pre-refresh candidate run `20260905T080623.861033000Z` against `59e08d5`/`c0a55d1` exist; real platform shadow E2E, canary, rollback, drain, and migration gates remain blocked |
| P3 candidate | [Platform candidate caller](p3-platform-candidate-caller.md) | Candidate caller and Docker process harness passed in hosted run `33970773345` against `17ed6ca`/`b4d41c9` and the latest local pre-refresh run `20260905T080623.861033000Z` against `59e08d5`/`c0a55d1`; evidence remains distinct from real Veronica platform evidence |
| Internal foundation | [Internal Block Manifest Loader](block-manifest-loader.md) | Implemented as bounded component evidence; no Provider Contract or public API change |
| P4 Browser | [Optional Profiles](p4-optional-profiles.md) | Browser Contract/projection, exact sandboxed signed amd64/arm64/v8 image publication (`33724368530`), Provider-local components, default-disabled command/runtime graph (`66183b1`), process-local Gateway limits, hosted Browser Reference E2E 13+5 run `33970773330`, Redis-compatible shared capacity `9434540`, local arm64 and hosted amd64 two-Gateway shared-capacity evidence including run `33970773388`, ADR 0032 component plus local/hosted caller evidence including run `33970773353`, and ADR 0033/`b4d41c9` downstream fencing component plus real-backend adapter integration pass their named gates; E2E lock `17ed6ca` only reruns existing scenarios. The independent ADR 0033 two-Gateway/unique-ingress/real-Chromium external-caller gate, private authenticated ingress topology, missing-high-water/restore controls, Valkey provenance/HA/failover, production storage/configuration/metrics/deployment, production advertisement/public Gateway, aggregate, multi-controller, multi-tenant, and production gates remain open |
