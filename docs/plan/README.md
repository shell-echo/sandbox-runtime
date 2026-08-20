# Implementation Plans

This directory indexes implementation plans that refine the authoritative
delivery order and release gates in [`docs/architecture.md`](../architecture.md).
Plans may narrow a phase into reviewable slices, but they do not replace the
locked Agent Contract or relax an architecture release gate.

Current execution state, landed slices, and the next planned slice are tracked
in [`docs/STATUS.md`](../STATUS.md).

| Phase | Plan | Status |
| --- | --- | --- |
| P1.1 | [Provider API admission](p1.1-provider-api-admission.md) | P1.1a-b verified; P1.1c merged through PR #14 with CI passed; P1.1d release-gate evidence in progress |
| P1.1b | [mTLS capability discovery](p1.1b-capability-discovery.md) | Implemented and verified on `main`; CI acceptance closed |
| P1.1c | [Protected-operation admission](p1.1c-protected-operation-admission.md) | Key, token/digest, application-gate, guard, protected transport, and configuration merged through PR #14; P1.1d gate remains open |
