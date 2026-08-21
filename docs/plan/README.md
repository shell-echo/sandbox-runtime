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
| P2.0 | [Coding/remote-shell authority inventory](p2-coding-remote-shell.md) | Next; Contract/Schema/Suite work required before runtime implementation |
