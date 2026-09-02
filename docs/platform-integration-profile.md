# Provider Integration Profile

This document is the handoff point for a calling Agent Platform, service, or
integration adapter. It describes the stable boundary exposed by
`sandbox-runtime` and the responsibilities that remain with the caller.

It is not a second Contract. The repository-owned MIT Provider Contract is the
only wire authority. This document is a navigation and integration guide; the
OpenAPI document, JSON Schemas, semantic rules, fixtures, Conformance Suite, and
Contract lock take precedence over any summary here.

## Authority and identity

Use these files together:

| Input | Role |
| --- | --- |
| [`contract/openapi/sandbox-runtime-provider-v1.yaml`](../contract/openapi/sandbox-runtime-provider-v1.yaml) | Provider HTTP wire surface; terminal handoff is projected separately |
| [`contract/schemas/`](../contract/schemas/) | Closed request, response, operation, and evidence shapes |
| [`contract/semantic-rules/provider-v1.json`](../contract/semantic-rules/provider-v1.json) | Cross-field, ownership, admission, and lifecycle semantics |
| [`contract/fixtures/`](../contract/fixtures/) | Canonical examples and negative cases |
| [`contract/conformance/provider-v1/suite.json`](../contract/conformance/provider-v1/suite.json) | Locked 38-case Provider Suite |
| [`compatibility/sandbox-runtime/contract.lock.json`](../compatibility/sandbox-runtime/contract.lock.json) | Contract revision and resource lock |
| [`docs/architecture.md`](architecture.md) | Ownership boundaries and delivery gates |

The current Contract identity is:

| Field | Value |
| --- | --- |
| Namespace | `urn:shell-echo:sandbox-runtime:provider-v1` |
| Version | `1.0.0` |
| License | `MIT` |
| Revision | `22a148e2898477790512d5bb742605654ff00ebf` |
| Contract tree | `1a967c9c6ce9646c8431f6ee48699ec9f406a589` |
| Suite | Provider v1, 38 cases |

An integration must pin this identity, the selected Provider revision, the
runtime/profile identifiers, and the exact evidence or image digests it relies
on. A repository commit or a passing local test does not replace the Contract
lock.

## Ownership boundary

The Provider is a provider-local execution and evidence service. The caller is
the platform authority for business and end-user concerns.

| Concern | Provider owns | Calling platform owns |
| --- | --- | --- |
| Capability discovery | Immutable capability snapshot and limits | Selecting a compatible Provider revision/profile |
| Sandbox execution | Provider-local sandbox state, leases, runtime resources, operations, and bounded evidence | WorkOrder/Run business state and desired-state policy |
| Authorization | Protected admission checks for the caller-supplied request context | End-user identity, tenant policy, user authorization, and Gateway policy |
| Operations | Provider operation acceptance, idempotency, attempts, fencing, cancellation, and reconciliation | Aggregate operation ledger and product-level state transitions |
| Terminal access | Opaque session handoff and private provider-side resolver | Public Gateway, grant issuance, revocation policy, and audit sink |
| Artifacts and usage | Staging and provider-local evidence correlated to an operation | Artifact publication, metadata, billing, accounting, and retention policy |
| Secrets and endpoints | No stable exposure of backend IDs, host paths, daemon details, or raw endpoints | Public endpoint and credential lifecycle, if any |

The local `/instances` management API is an implementation surface. It is not a
substitute for the Provider API and its DTOs must not be used as Provider wire
models.

## Provider surface

The exact request and response fields are defined by OpenAPI and the schemas.
The route families are:

| Method and route | Purpose | Caller expectation |
| --- | --- | --- |
| `GET /v1/capabilities` | Read the immutable Provider capability snapshot | Use mTLS; do not send a body, query, or bearer token |
| `POST /v1/sandboxes` | Accept asynchronous sandbox creation | Bind the request to an admitted context and idempotency key |
| `GET /v1/sandboxes/{sandbox_id}` | Read provider-local sandbox state | Treat transitional and unknown outcomes according to the Contract |
| `POST /v1/sandboxes/{sandbox_id}/exec` | Accept bounded asynchronous execution | Preserve operation, attempt, generation, and fencing correlation |
| `POST /v1/sandboxes/{sandbox_id}/exec:cancel` | Accept an execution cancellation intent | Do not assume cancellation means the external process already stopped |
| `POST /v1/sandboxes/{sandbox_id}/runtime-sessions` | Accept a terminal-session open request | Require an exactly advertised terminal/runtime profile |
| `GET /v1/operations/{operation_id}` | Read the provider operation projection | Poll or reconcile without inventing a platform operation state |
| `GET /v1/operations/{operation_id}/exec-result` | Read an execution result projection | Keep result expiry and unknown outcomes explicit |
| `GET /v1/operations/{operation_id}/runtime-session` | Read a successful session handoff projection | Treat the handoff as opaque and expiring |
| `POST /v1/sandboxes/{sandbox_id}/artifacts:stage` | Accept provider-local artifact staging | Keep the returned reference private; publication remains platform-owned |
| `GET /v1/operations/{operation_id}/artifact-staging-evidence` | Read artifact staging evidence | Correlate it with the exact operation and sandbox attempt |
| `GET /v1/operations/{operation_id}/usage-evidence` | Read usage evidence | Use it as provider evidence, not as billing truth |

The Contract may reject unsupported profiles, stale generations, replayed or
conflicting attempts, invalid digests, expired leases, unavailable capacity,
and requests outside the advertised capability graph. A caller must handle
these as typed Provider outcomes rather than parse implementation diagnostics.

## Admission and operation rules

Protected operation routes require all of the following layers:

1. A mutually authenticated TLS connection with an admitted caller identity.
2. The Contract-defined bearer/JWS request metadata and descriptor digest.
3. Replay, idempotency, attempt, generation, lease, and fencing checks.
4. Strict schema and semantic validation before any mutation where the Contract
   requires preflight.

`GET /v1/capabilities` is mTLS-only and has its own empty-request rules. A
caller must not use bearer authentication as a replacement for the client
certificate identity.

Accepted mutating requests return an asynchronous Provider operation. The
caller must persist its own correlation between platform intent and Provider
operation, retry only according to the Contract and platform policy, and
reconcile unknown outcomes instead of issuing an unbounded duplicate request.
Provider-local operation records do not become the platform's aggregate ledger.

## Coding/shell profile

The current intended profile is coding and remote shell. A profile is usable
only when it is present in the immutable capability snapshot and the complete
configured dependency graph passes the named readiness checks. Empty or
default-disabled advertisements are intentional and mean that the caller must
not send operations for that capability.

For a terminal session, the caller receives an opaque, expiring handoff. It
must pass that handoff to a caller-owned Gateway composition that performs its
own authorization, revocation, connection admission, and recording. The
Provider does not expose a Docker socket, host path, internal endpoint, or
public Gateway URL through the handoff.

## Artifact and usage boundary

Artifact staging is provider-local evidence production. The Provider may
validate lifecycle readiness, tenant/generation/fencing bindings, output-file
confinement, scanning, and operation correlation. It returns only the Contract
defined private reference/evidence projection.

The caller remains authoritative for:

- public artifact naming and publication;
- user-visible artifact metadata and retention;
- billing, quotas, and accounting;
- aggregate usage semantics across Providers; and
- product-level success or failure decisions.

Do not treat a staging reference as a public download URL or a Provider usage
record as a billing invoice.

## Caller implementation checklist

A future platform caller should complete these items before claiming an
external integration:

- Pin the Contract namespace, revision, tree digest, Suite, and selected
  ProviderRevision/profile.
- Implement mTLS identity validation and JWS/digest admission using platform-
  owned credentials and key rotation policy.
- Map WorkOrder/Run intent to Provider requests without moving business truth
  into the Provider.
- Store Provider operation IDs, idempotency keys, attempts, generations, and
  fencing values in a platform-owned correlation record.
- Implement bounded polling/reconciliation for pending, unknown, expired,
  rejected, and unavailable outcomes.
- Supply Gateway authorization, revocation, recording, and public endpoint
  policy for terminal sessions.
- Keep artifact publication and billing outside the Provider evidence routes.
- Run the locked Contract verifier, Conformance Suite, and a black-box caller
  against a separately started Provider process.
- For migration, prove capability/request shadow parity, new-run-only canary
  selection, rollback, old-run drain, and metric parity without changing
  platform-owned contracts.

## Evidence boundary

The repository's `e2e/` module contains two deliberately separate harnesses:

- the independent reference caller, which proves the named Provider coding/shell
  scenarios over real processes, sockets, mTLS/JWS, WebSocket, and Docker; and
- the Agent Platform candidate caller, which models platform bindings and
  migration policy but is not a separately owned production platform.

These results are useful integration evidence, not proof of aggregate
conformance, multi-controller reliability, hostile multi-tenant isolation,
deployment qualification, or production readiness. Those gates require their
own environment and reproducible evidence.

To reproduce the repository-level checks:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go run ./cmd/verify-contract -source-root .
go run ./cmd/run-conformance -source-root . -race -shuffle
```

The reference and candidate E2E commands are documented in
[`e2e/README.md`](../e2e/README.md). Their evidence must retain its named
boundary and must not be relabeled as real Agent Platform or production
evidence.

## Change protocol

When the Provider wire behavior changes, update the Contract resources and
lock first, then update projections, fixtures, conformance cases, callers, and
this guide in one reviewed slice. When a platform needs a new business field,
first decide whether it belongs to the caller or to the Provider Contract; do
not add a platform-owned field to a Provider DTO merely to simplify mapping.

This document should be updated when the Contract identity, ownership boundary,
route family, caller checklist, or evidence boundary changes. Commit-level
evidence belongs in [`docs/STATUS.md`](STATUS.md); stable architecture belongs
in [`docs/PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) and
[`docs/architecture.md`](architecture.md).
