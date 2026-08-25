# ADR 0014: Provider Operation and Evidence Read Authority

- Status: Accepted for P2.4a1 Contract authority reconciliation
- Date: 2026-08-25

## Context

ADR 0013 locked asynchronous artifact staging outcomes and the protected read
descriptors, but it did not uniquely define evidence-read behavior while an
operation was accepted, running, or outcome-unknown. It also did not state that
the generic Provider operation route must read artifact staging operations.
The current transport happens to delegate that route only to the lifecycle
application. Treating that implementation shape as protocol authority would
hide valid artifact operations and make `404` ambiguous between an unknown
operation, a pending operation, and a known failed operation with no evidence.

## Decision

`GET /v1/operations/{operation_id}` is an operation-family aggregation
boundary. A composed Provider must query the authority that owns the operation
family and must expose a known `artifact_stage` operation through the existing
Provider operation Schema. It returns `404` only when the operation is unknown
to every composed operation-family authority. A source-missing artifact stage
remains visible there as `failed` even though its evidence read is `404`.

Artifact evidence reads use the locked state matrix:

- unknown operations and source-missing operations return
  `404 SANDBOX_ARTIFACT_EVIDENCE_NOT_FOUND`, non-retryable;
- accepted and running operations return
  `503 SANDBOX_ARTIFACT_EVIDENCE_PENDING`, retryable, with a positive
  `Retry-After`;
- outcome-unknown operations return
  `503 SANDBOX_ARTIFACT_OUTCOME_UNKNOWN`, retryable, with a positive
  `Retry-After`, and remain subject to reconciliation;
- staged and content-rejected evidence returns `200`; and
- expired retained evidence returns
  `410 SANDBOX_ARTIFACT_EVIDENCE_EXPIRED`, non-retryable.

Usage evidence reads return `404 SANDBOX_USAGE_EVIDENCE_NOT_FOUND` when no
evidence is known, `503 SANDBOX_USAGE_EVIDENCE_UNAVAILABLE` with a positive
`Retry-After` when known evidence is not yet readable or temporarily
unavailable, `200` for an existing document with any Schema-authorized
reconciliation status, and `410 SANDBOX_USAGE_EVIDENCE_EXPIRED` after expiry.
Usage evidence remains provider-local observation and never becomes billing or
tenant authority.

Both evidence reads retain their exact protected descriptor digest and remain
side-effect-free admission reads that do not consume mutation guard state.

## Consequences

- A later application slice must supply operation-family readers and an
  aggregator without making the lifecycle repository own unrelated families.
- Artifact pending, unknown, source-missing, and expired states no longer rely
  on transport-local guesses.
- The outcome-unknown operation fixture proves that the existing Provider
  operation Schema can carry the required reconciliation state.
- This decision adds no application, repository, handler, router, staging
  dispatch, usage collection, publication, billing, or external integration.
- P2.4a transport and the Phase 2 external-caller release gate remain open.
