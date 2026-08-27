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
| P2 | [Coding/remote-shell authority inventory](p2-coding-remote-shell.md) | Bounded slices through P2.5e have component/Contract/CI evidence; P2.5f0 design and P2.5f1-f4 local/CI gates pass; Provider composition and independent caller E2E remain open |
| P2.5 | [Coding/shell vertical composition](p2.5-coding-shell-vertical-composition.md) | P2.5a-e pass through CI `32937530059`; P2.5f0-f2 pass through CI `33045725476`; P2.5f3 implementation `b1acdd1`, evidence baseline `7138a4c`, and CI `33059304542` pass; P2.5f4 implementation `14f14cc`, evidence baseline `1d9da67`, and CI `33064864447` pass, with f5 next |
| P2.5f | [Terminal and Gateway vertical](p2.5f-terminal-gateway-vertical.md) | f0 audit, f1 runtime/Docker adapter, f2 durable session coordination/migration, f3 opaque persistence/resolution, and f4 WebSocket/terminal adapters pass their current local and CI gates; Gateway, command composition, and advertisement remain open |
| P3 | [Migration readiness](p3-migration-readiness.md) | Local binding/shadow/metrics component evidence exists; P2 completion, external caller E2E, real canary, rollback, drain, and migration gates remain open |
