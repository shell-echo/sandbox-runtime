# ADR 0006: Provider-Local Lifecycle Coordinator Boundary

- Status: Accepted for P1.2.3 development implementation
- Date: 2026-08-20

## Context

P1.2.2 now provides atomic provider-local lifecycle persistence, but it does
not dispatch runtime work or reconcile a process restart. The Provider Contract
and its protected admission boundary remain the only public protocol authority;
the coordinator must therefore stay behind the transport boundary.

## Decision

The coordinator accepts a validated create request through the repository's
atomic `ReserveCreate` operation and only then dispatches a provider-local
driver. It records `provisioning` before dispatch, checks the operation deadline
before dispatch, and passes a child context bounded by that deadline to the
driver. A cancellation or timeout returned after dispatch is classified as
`outcome_unknown`; a bounded driver error that is known not to have taken effect
is classified as `known_failed`.

A running operation is inspected before any retry. A ready observation completes
the operation; an authoritative absent observation is a known failure; an
inspection failure remains unknown. An `outcome_unknown` operation is never
blindly retried or changed to a terminal success/failure state. Reconciliation
may still record a ready sandbox observation when the runtime proves that work
took effect.

All writes carry the operation fencing token and the sandbox expected
generation. Repository rejection is returned before driver dispatch, so stale
attempts cannot overwrite newer state or create duplicate runtime work. State
and event writes are intentionally separate; retries use deterministic event
IDs and repository idempotency. No public route, DTO projection, aggregate
operation ledger, multi-controller guarantee, or production claim is added.
Calls through one coordinator instance are serialized to prevent duplicate
dispatch from concurrent local workers; this mutex is not a distributed
controller lock and does not make the file adapter multi-controller safe.

## Consequences

- Driver adapters expose only bounded runtime observations and no backend
  identifiers, host paths, diagnostics, or credentials.
- A process restart can safely inspect a previously running operation instead
  of issuing a duplicate create blindly.
- Partial persistence between state and event writes is recoverable through the
  next reconciliation pass; the repository remains the source of local truth.
- P1.2.4 must add Contract-authorized HTTP projections before this behavior is
  externally callable.
