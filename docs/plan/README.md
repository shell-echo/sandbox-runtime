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
| P0 | [Local Provider Contract migration](p0-local-provider-contract.md) | PR #17 merged; post-merge CI passed; P0.4 revalidation follow-up in progress |
| P1.1 | [Provider API admission](p1.1-provider-api-admission.md) | Local Contract revalidation passed on the current branch; release gate remains open |
| P1.1b | [mTLS capability discovery](p1.1b-capability-discovery.md) | Local TLS and response projection revalidation passed; PR evidence pending |
| P1.1c | [Protected-operation admission](p1.1c-protected-operation-admission.md) | Local semantic binding and admission matrix passed; PR evidence pending |
