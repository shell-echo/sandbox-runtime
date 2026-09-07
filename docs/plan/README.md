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
| P2 | [Coding/remote-shell authority inventory](p2-coding-remote-shell.md) | Bounded slices through P2.5h have component/Contract/CI evidence and the co-located reference caller gate passes; aggregate conformance, reliability, tenancy, deployment, and production gates remain open |
| P2.6 | [Portable Provider conformance](p2.6-portable-provider-conformance.md) | Passed locally at implementation `3fe314a` and E2E lock refresh `ae476fe` under ADR 0039 for the content-derived 50-case local repository profile and separate 6-case read-only remote discovery profile. Independent-caller, protected/mutating remote, and broader readiness gates remain open |
| P2.7 | [Independent external caller qualification](p2.7-independent-external-caller-qualification.md) | P2.7a locks the verified definition profile `sandbox-runtime-external-caller-coding-shell-v1@1.0.0` at `sha256:baee769c0acc395448af61faef99cd97fbb63ccb83c70eb51915952be519991a`. Overall definition remains in progress: the closed report schema, report/evidence validator, adapter/harness, and external execution remain open, and no external caller has passed the gate |
| P2.5 | [Coding/shell vertical composition](p2.5-coding-shell-vertical-composition.md) | P2.5a-h retain their recorded local/CI gates; current local P2.5i run `20260907T044611.598221000Z` passed 15+5 scenarios against harness/Provider `b8d4829`/`af8a505`, while hosted run `33970773414` remains historical evidence against `17ed6ca`/`b4d41c9`; consumer-specific adaptation is out of scope, while independent-caller qualification, aggregate conformance, reliability, tenancy, deployment, and production gates remain open |
| P2.5f | [Terminal and Gateway vertical](p2.5f-terminal-gateway-vertical.md) | f0 audit and f1-f7 terminal/Gateway slices pass their current local and repository CI gates; no public Gateway, independent caller, or capability advertisement was added |
| P3 | [Migration readiness](p3-migration-readiness.md) | Retired by ADR 0037. Historical local component and candidate evidence remains valid only within its recorded harness boundary; no named-platform migration target remains |
| P3 candidate | [Platform candidate caller](p3-platform-candidate-caller.md) | Superseded as an active route by ADR 0037. Existing run and artifact identities remain historical; future consumers adapt to the locked Provider Contract |
| Internal foundation | [Internal Block Manifest Loader](block-manifest-loader.md) | Implemented as bounded component evidence; no Provider Contract or public API change |
| P4 Browser | [Optional Profiles](p4-optional-profiles.md) | Browser Contract/projection, exact sandboxed signed amd64/arm64/v8 image publication (`33724368530`), Provider-local components, default-disabled command/runtime graph (`66183b1`), process-local Gateway limits, Browser Reference E2E, Redis-compatible shared capacity, and ADR 0032 component plus caller evidence pass their named gates. ADR 0033/`b4d41c9` passes its component and platform-specific v1 caller gates. ADR 0034 separately passes its witnessed-v2 deletion/rollback-detection component, pinned-Valkey adapter, and local/hosted 18/18 caller gates at fixed harness `059357c`. ADR 0035/`3ff58dc` passes the PostgreSQL witness migration, least-privilege role, atomic-CAS, timeout, and strict restored-state component gate. ADR 0036 adds the separately locked same-runner controlled-restore profile; latest main run `34069851741` at merge `838d3bb` passes 18/18 with PostgreSQL and Valkey still sharing one runner, host, Docker engine, workflow, and operator. The ADR 0033, ADR 0034, and ADR 0036 caller profiles do not execute the Contract Suite. Production independent witness/storage and backup domains, both stores' provenance and HA/failover, operator controls, production configuration/metrics/deployment, production advertisement/public Gateway, aggregate, multi-controller, hostile multi-tenant, and production gates remain open |
