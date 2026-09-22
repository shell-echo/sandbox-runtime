# ADR 0053: Phase 6 Evidence Closure Lifecycle

- Status: accepted
- Date: 2026-09-22

## Context

The Slice 4 finalization verifier correctly required every change after the
evidence-tool revision to be documentation-only. That rule proved the exact
closure HEAD, but applying it unchanged after Slice 5 source work would either
make retained Slice 4 verification permanently fail or require later runtime
code to be relabelled as Slice 4 evidence. Neither outcome is valid.

Phase 6 needs to retain an immutable historical conclusion while independently
requiring each successor slice to establish its own implementation, evidence
tool, finalization revision and gate. Historical evidence must never be an
implicit fallback for a current-source failure.

## Decision

The Phase 6 evidence verifier has two explicit modes:

1. `finalization` is the default and preserves the original behavior. The
   evidence-tool revision must be a current-history ancestor and every later
   path through HEAD must be exactly `README.md`, `README.zh-CN.md`, or
   `docs/**`. Any source, configuration, workflow or test change fails.
2. `retained` requires an explicit mode, slice ID, manifest path and closure
   record path. It validates an immutable historical closure and reports
   `claim_scope=historical_retained` and `current_head_covered=false`. It does
   not validate successor source or advance a later slice.

Every completed slice owns a canonical repository closure record. The record
binds the slice and manifest schema identities, runtime revision,
evidence-tool revision, finalization/closure revision, raw manifest SHA-256,
sealed manifest digest, artifact path and closure-record path. Retained
verification proves:

- runtime, evidence-tool, closure and current HEAD ancestry;
- the original closed runtime-to-evidence-tool file transition;
- the original documentation-only evidence-tool-to-closure transition;
- byte-exact manifest identity at the closure revision and in the current
  worktree;
- one-time closure-record introduction and no later manifest or record
  modification, deletion, replacement or move; and
- a clean current worktree.

The Slice 4 closure revision is
`9bb6a25860a038f1cc074dd0d3d6b6a5a4e9367b`. Its manifest remains unchanged;
the lifecycle record adds authority around that artifact without changing its
schema or claim.

CI and local acceptance must run every prior slice in retained mode and the
current slice through its development or finalization gate. Retained success
can never replace the current-slice gate.

## Consequences

- Later Phase 6 source work no longer rewrites or retroactively widens Slice 4
  evidence.
- Default verification remains strict enough to catch accidental source drift
  during finalization.
- Retained output is machine-readable and carries an explicit non-claim for
  current HEAD and successor slices.
- Every later slice must create its own closure record and strict evidence;
  the final release gate verifies each historical closure plus the current
  release candidate separately.
