# ADR 0013: Artifact and Usage Protected Admission Bindings

- Status: Accepted for P2.4a0 Contract authority reconciliation
- Date: 2026-08-25

## Context

ADR 0012 added protected artifact staging and usage evidence resources, but the
closed admission operation vocabulary did not include their mutation and read
bindings. The OpenAPI paths therefore had no valid Admission Context and JWS
operation, Contract ID, or digest profile. Composing those routes would either
bypass protected admission or require implementation code to invent protocol
authority.

## Decision

The Provider v1 admission vocabulary adds exactly three operations:

- `stage_artifact` binds `POST .../artifacts:stage` to
  `urn:shell-echo:sandbox-runtime:request:stage-artifact:v1` using the
  request-excluding-`request_digest` profile;
- `read_artifact_staging_evidence` binds the artifact staging evidence GET to
  `urn:shell-echo:sandbox-runtime:descriptor:artifact-staging-evidence:v1`
  using the full-document descriptor profile; and
- `read_usage_evidence` binds the usage evidence GET to
  `urn:shell-echo:sandbox-runtime:descriptor:usage-evidence:v1` using the
  full-document descriptor profile.

The mutation name follows the `stageSandboxArtifact` OpenAPI operation verb and
the existing `cancel_exec` and `open_runtime_session` request-binding pattern.
The read names follow the closed `read_*` operation vocabulary and retain the
exact Contract resource in each descriptor ID. `artifact_stage` remains the
Provider operation result type and is deliberately not an admission operation.

Only `stage_artifact` is a protected mutation and consumes replay/fencing guard
state. Both evidence reads remain side-effect-free admission reads and do not
consume mutation JTI state. Unknown operations fail closed.

The staging accept boundary is asynchronous. A valid request is durably
accepted before staging or content-check dispatch and returns only a `202`
Provider operation. An oversized encoded request is the locked `400`; an
unsupported check capability is `422`; and a pre-accept internal condition that
cannot be projected safely fails closed as `503`. This Contract does not add
`413` or `500` to the stable response surface.

After acceptance, successful staging completes the operation as `succeeded`
and retains `staged` evidence. A content-check rejection completes it as
`failed` and retains immutable `rejected` evidence. A missing source completes
it as `failed` without manufacturing content evidence, so its evidence read is
`404`. These adapter outcomes are never returned synchronously from the accept
request.

Both evidence-read descriptors contain exactly `operation`, `sandbox_id`,
`operation_id`, `attempt_id`, and `fencing_token`; the path operation ID must
equal the Admission Context operation ID, and normalized query is empty. Their
request digest is RFC 8785 JCS over that complete descriptor document.

## Consequences

- A later transport slice can validate a caller-supplied Admission Context and
  bearer for each locked route without deriving authority from the token.
- The Contract fixture and Suite case bind each operation to its real method,
  concrete path shape, Contract ID, digest profile, and mutation classification.
- This decision adds no Provider route, handler, artifact dispatch, evidence
  application, usage collector, publication, billing, or external integration.
- Once a separately tested application boundary supplies the locked durable
  acceptance and operation-keyed reads, this decision authorizes the later
  P2.4a transport slice to compose only these three existing OpenAPI routes.
- P2.4a transport remains separately gated, and the Phase 2 external-caller
  release gate remains open.
