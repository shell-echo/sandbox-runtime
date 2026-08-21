# ADR 0010: Bounded Exec Contract Projection

- Status: Accepted for P2.0b/P2.0c
- Date: 2026-08-21

## Context

ADR 0009 established the ownership boundary for coding and remote-shell
behavior, but the repository-owned Provider Contract did not yet authorize an
exec request, cancellation intent, or retained result resource. Runtime code
must not be used to invent that wire authority.

## Decision

The additive Provider v1 Contract revision bound by the P2.0b resource commit
adds only these resources:

- `POST /v1/sandboxes/{sandbox_id}/exec` for a bounded asynchronous request;
- `POST /v1/sandboxes/{sandbox_id}/exec:cancel` for cancellation intent;
- `GET /v1/operations/{operation_id}/exec-result` for a retained result.

The exec request's `command` property is the structured argv vector. It is not
an arbitrary shell command string and has bounded item count and item size.
Working directories are restricted to `/workspace` or `/tmp` descendants with
no dot traversal. Environment values, secret grants, and stdin are opaque
references; plaintext secret values and inline stdin are not Contract-valid.
The request carries explicit deadline, output capture, and result-retention
bounds. Cancellation is an intent and never evidence of a cancelled process by
itself. A retained result includes an explicit `outcome_unknown` state and a
bounded `retained_until` expiry. Result and operation references use opaque
reference patterns and cannot expose container IDs, host paths, raw endpoints,
secrets, or credentials.

Usage evidence remains outside this slice and is reserved for P2.4. Terminal
sessions, artifacts, snapshot resources, public gateway behavior, and runtime
dispatch remain unauthorized.

The Contract lock binds the complete resource tree, including valid and
rejection fixtures and the executable Suite cases. Local projection tests
validate Schema fixtures, strict Provider wire DTO round trips, semantic rule
identities, and every rejection case. The Suite mappings execute those tests
only; they do not claim runtime or external-caller compatibility.

## Consequences

- P2.1 may implement provider-local exec ports only after this Contract lock
  and its release gate are accepted.
- Existing `/instances` and runtime driver models remain outside the Provider
  wire projection.
- Aggregate caller authorization, operation truth, artifacts, usage, public
  sessions, multi-controller reliability, multi-tenant safety, deployment, and
  production readiness remain unproven.
