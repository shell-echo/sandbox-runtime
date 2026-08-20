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
| P0 | [Local Provider Contract migration](p0-local-provider-contract.md) | PR #17 and PR #18 merged with post-merge CI passed; P0.4 Suite runner follow-up in progress |
| P1.1 | [Provider API admission](p1.1-provider-api-admission.md) | P1.1a-b-c passed under local Contract; P1.1d release gate remains open |
| P1.1b | [mTLS capability discovery](p1.1b-capability-discovery.md) | Local TLS and response projection revalidation passed; PR evidence pending |
| P1.1c | [Protected-operation admission](p1.1c-protected-operation-admission.md) | Local semantic binding, admission matrix, PR #18, and post-merge CI passed; gate review pending |
