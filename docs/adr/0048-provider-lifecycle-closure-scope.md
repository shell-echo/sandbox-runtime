# ADR 0048: Provider Lifecycle Closure Scope

- Status: Accepted; implementation candidate complete, while the published
  exact Contract lock remains the authority until a later immutable refresh
- Date: 2026-09-18

## Context

The locked Provider Contract authorizes sandbox creation and status reads but
does not authorize sandbox termination, desired-state mutation, lease renewal,
or lifecycle event reads. It authorizes terminal-session open, handoff read,
and an optional protected connection route, but not session close or resize.

The implementation contains reserved admission names, route matchers, DTOs,
domain values, repository methods, and some runtime cleanup primitives for
parts of this surface. Those elements have different maturity and do not
override the lock-selected OpenAPI. The target Product needs a minimum
Provider lifecycle that can be retried and reconciled without importing
Provider packages or treating cleanup harnesses as API authority.

## Decision

### In-scope wire families

The Phase 2 candidate adds the following families through a coordinated
Provider Contract revision and implementation. They do not become selected
wire authority until the exact lock is refreshed to an immutable revision:

| Method and path | Decision |
| --- | --- |
| `POST /v1/sandboxes/{sandbox_id}:terminate` | The only irreversible sandbox termination command |
| `POST /v1/sandboxes/{sandbox_id}/desired-state` | Reversible `ready` and `suspended` requests only |
| `POST /v1/sandboxes/{sandbox_id}/lease` | Bounded renewal of the current sandbox execution lease |
| `GET /v1/sandboxes/{sandbox_id}/events` | Finite, paged reads after an exclusive sequence cursor |
| `POST /v1/sandboxes/{sandbox_id}/runtime-sessions/{runtime_session_id}:close` | Idempotent terminal-session close and cleanup |

The existing sandbox and operation reads are the result surfaces. No separate
termination-result route is added. A caller observes cleanup through the
retained termination operation, sandbox observation, and contiguous lifecycle
events. A termination operation may be `succeeded` only after the exact owned
runtime is confirmed absent and deterministic Provider-owned ephemeral state
has been removed. `terminated` is irreversible.

The desired-state request does not accept `terminated`; termination cannot be
smuggled through a reversible state mutation. A transition between `ready` and
`suspended` increments sandbox generation and is successful only after the
runtime observation reaches the requested state. Unsupported runtime profiles
reject the request before dispatch.

Lease renewal changes expiry under the exact current sandbox generation; it
does not itself increment desired generation. The new expiry must move
forward, be later than current Provider time, and stay within the advertised
`max_lease_seconds` horizon. Lease expiry revokes new work and invokes the same
reconciled cleanup engine used by explicit termination. It cannot merely mark
the record expired while leaving an untracked runtime behind.

### Capability honesty

The Contract change will define optional
`sandbox.lifecycle-control@1.0.0` with profile `lifecycle-control-v1`. It
authorizes the complete termination, desired-state, lease, and event family as
one all-or-nothing dependency graph. A runtime profile cannot advertise it
unless persistence, expiry processing, runtime terminate/suspend/resume,
reconciliation, event retention, transport, and evidence gates are all ready.

Terminal close is a separate optional capability,
`sandbox.terminal-control@1.0.0` with profile `terminal-control-v1`, and
requires `sandbox.terminal@1.0.0`/`terminal-v1` on the same runtime profile.
This avoids silently expanding the meaning of the existing terminal
capability. Closing first commits intent and revokes future handoff resolution,
then terminates active attachment authority and cleans the exact terminal
allocation. Success requires absence confirmation; ambiguous dispatch remains
reconcilable.

Route presence, reserved names, or partial composition never substitutes for
advertisement. An explicitly configured capability whose dependency graph is
incomplete makes startup fail closed.

### Event and gap semantics

Lifecycle events are safe Provider evidence, not the caller's aggregate event
ledger. Sequence is positive, monotonic, and contiguous per sandbox.
`after_sequence=N` means the caller has durably processed `N` and expects
`N+1`. Every page carries a next cursor and the observed latest sequence.

If the requested successor precedes the retained floor, the Provider returns
`410` with a closed safe cursor-expired detail containing the first available
and latest sequences. If the cursor is ahead of the latest sequence, the
Provider returns `409`; it never silently rewinds. The caller then reconciles
the sandbox and operation reads before choosing a new checkpoint. Phase 2 uses
bounded polling only; SSE and long polling are not added.

### Attempts, fencing, deadlines, and unknown outcomes

Every in-scope mutation uses the existing closed mutation envelope:
operation ID, attempt ID, positive fencing token, idempotency key, request
digest, and deadline. Sandbox mutations also bind the expected generation;
session close binds the exact sandbox generation, runtime-session identity,
and connection generation.

- Same idempotency scope and same canonical request digest return the same
  logical operation; a different digest is a conflict.
- Stale fencing, generation, or connection-generation input fails before any
  runtime dispatch.
- Deadlines and cancellation propagate to runtime work. They do not erase a
  dispatch that may already have taken effect.
- A timeout, cancellation, or lost response after possible dispatch produces
  `outcome_unknown` for that attempt. Reconciliation inspects the exact owned
  resource before any retry.
- `outcome_unknown` remains immutable attempt evidence. Later observation may
  advance sandbox or session cleanup evidence but does not relabel the attempt
  as known success.
- A higher-fenced attempt may continue the same desired outcome only after
  retained observation proves that it cannot overwrite newer authority or
  create a replacement resource.

### Compatibility

The intended change is additive inside the existing Provider v1 namespace and
version. Existing route and capability meanings must not change. Exact
revision/tree locking means callers opt into the new authority explicitly;
the current revision remains valid for its existing surface.

Phase 2 retains the v1 namespace because the candidate is additive and leaves
existing route and capability meanings intact. Any later discovery of a
breaking semantic requires this ADR and the versioning decision to be revisited
before lock selection.

### External caller boundary

This repository will define the exact qualification inputs for a future
external caller: Contract revision/tree and Suite identities, required
capabilities, protected routes, scenario IDs, independent observations,
restart/reconciliation cases, and zero-resource cleanup evidence. Phase 2 does
not import, modify, or claim results for an external caller. Repository-local
black-box evidence remains a lower evidence tier.

## Excluded from Phase 2

- Terminal resize: no terminal/session runtime port or adapter supports it.
- Snapshot and restore: reserved scaffolding is not minimum lifecycle closure.
- Browser-session close: it requires a separately scoped Browser control and
  usage-evidence decision.
- Product API, PostgreSQL, public Gateway, Guest Agent, Product UI, deployment,
  HA, hostile multi-tenant isolation, and production readiness.

Excluded operations remain absent from capability advertisement and locked
wire authority. No private endpoint, backend ID, host path, credential, or raw
daemon diagnostic may be added to stable responses or events.

## Dependency order

The fixed order is Contract authority, lifecycle persistence, runtime
capabilities, application reconciliation, event projection, terminal close,
transport/capability composition, and integrated evidence. Implementation may
not start from HTTP handlers or advertise a partial graph. The detailed nine
independently reviewable steps are authoritative in the Phase 2 plan.

## Consequences

- The caller retains business desired state, end-user authorization, aggregate
  operations, retry policy, and final Product decisions.
- The Provider owns only local execution, lease enforcement, retained attempts,
  cleanup, observation, and bounded evidence.
- The local `/instances` API, Provider DTOs, lifecycle domain, and runtime
  drivers remain separate types and packages.
- Accepting this ADR closes only scope ambiguity. It is not a Contract,
  implementation, compatibility, deployment, or production-readiness result.
