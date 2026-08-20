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
| P0 | [Local Provider Contract migration](p0-local-provider-contract.md) | In progress: resources and lock landed; validator, CI, and documentation migration pending |
| P1.1 | [Provider API admission](p1.1-provider-api-admission.md) | Implementation exists, but compatibility evidence is reset until it passes the local Contract |
| P1.1b | [mTLS capability discovery](p1.1b-capability-discovery.md) | Implementation exists; local response projection and CI revalidation pending |
| P1.1c | [Protected-operation admission](p1.1c-protected-operation-admission.md) | Implementation exists; local semantic/admission revalidation pending |
