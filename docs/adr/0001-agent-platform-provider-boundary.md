# ADR 0001: Agent Platform Provider Boundary

- Status: Accepted
- Date: 2026-07-30

## Context

The Agent Platform defines a stable Sandbox Provider API and also contains an
`application/provider/sandbox` implementation area. This repository is intended
to remain independently deployable and useful outside one Agent Platform
checkout. Implementing the same backend controller in both repositories would
duplicate operation handling, reconciliation, persistence, and security logic.

## Decision

`sandbox-runtime` is an independent implementation of Sandbox Provider API v1.
It owns:

- versioned Provider HTTP/SSE transport and provider-side admission;
- provider-local operation progress and reconciliation evidence;
- backend resource provisioning, observation, execution, and cleanup;
- internal runtime endpoints, retained results, and backend measurements.

The Agent Platform owns:

- `SandboxRegistry`, desired state, lease policy, and Provider Resolution;
- the authoritative `SandboxOperation` aggregate ledger, attempts, retries,
  manual review, and final platform decisions;
- Tenant, WorkOrder, Workspace, Artifact, Usage, and user authorization truth;
- public Runtime Gateway routes and RuntimeSession authorization.

The Agent Application's sandbox package is the platform-side client/adapter and
orchestration integration for this provider. It must not duplicate this
repository's Docker driver or provider-local controller.

The existing `/instances` API remains an internal development and management
surface. Its request, model, state machine, errors, and response envelope are not
the Provider API wire contract. Provider DTOs must be generated or validated
from the locked upstream Contract and translated at an explicit adapter boundary.

## Consequences

- Agent Blueprint and Application planning text must be coordinated before an
  end-to-end integration claim; this repository cannot change that authority.
- Both the Agent Platform and this service retain operation records, but for
  different authorities. Correlation IDs, attempts, and fencing tokens connect
  them without making provider-local state authoritative for platform outcomes.
- File persistence remains a single-controller development backend. A
  transactional repository and multi-controller evidence are required before
  advertising the core production profile.
- No compatibility claim is valid until the exact Provider revision and runtime
  profile pass the locked Sandbox Conformance Suite.

## Non-goals

This decision does not implement Provider API v1, modify the upstream Contract,
approve production multi-tenant Docker isolation, or adapt DeerFlow.
