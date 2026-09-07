# External Caller Coding/Shell Qualification Profile v1

Profile ID: `sandbox-runtime-external-caller-coding-shell-v1`

Profile version: `1.0.0`

Profile digest:
`sha256:baee769c0acc395448af61faef99cd97fbb63ccb83c70eb51915952be519991a`

Status: P2.7a machine-readable definition authority locked. Overall P2.7
definition remains in progress because the report schema, report/evidence
validator, adapter protocol, harness, and external execution remain open. No
external caller has passed this profile.

## Purpose

This profile defines the evidence required to qualify a separately implemented
caller against the repository-owned Sandbox Provider Calling Standard. It is an
integration gate, not a Provider wire extension or a Provider Conformance Suite.

The locked Contract remains authoritative for every Provider HTTP document and
semantic rule. A caller adapts its private job, tenant, authorization, and
workflow models to that Contract. `sandbox-runtime` does not implement or
maintain the caller's adapter.

## Machine authority

[`profile.json`](../../qualification/external-caller-coding-shell-v1/profile.json)
is the ordered machine-readable authority for cases, interactions,
expected statuses and error-code policies, dependencies, observations, resource
bounds, cleanup, and non-claims. Its closed
[`profile.schema.json`](../../qualification/external-caller-coding-shell-v1/profile.schema.json)
has raw-byte digest
`sha256:2ad01731b69246399d6f04048593f31da9e4118b1dff99a81551b0c9b5972d77`.
The repository profile verifier validates the closed shape, semantic
cross-field rules, exact 15+5 case, 41-interaction, and 91-observation inventory,
schema digest, and content digest. This document explains the locked profile but
does not override it. A semantic change requires a new profile digest and
coordinated reference update.

The profile digest uses
`rfc8785-full-document-excluding-profile-digest-v1`: accept one bounded UTF-8
JSON object with closed, unique members and no trailing value; remove only the
top-level `profile_digest`; canonicalize the complete remaining object with RFC
8785 JCS; hash those UTF-8 bytes with SHA-256; and encode the result as lowercase
`sha256:<64 hexadecimal characters>`. The digest-profile member and every array
order remain in the input.

## Prerequisites

All prerequisites must be recorded before a mutating request is allowed:

1. The Contract namespace, version, revision, tree, manifest digest, OpenAPI
   digest, local Suite identity, and remote discovery Suite identity are exact.
2. The target advertises the expected Provider revision,
   `sandbox.exec@1.0.0`/`exec-v1`,
   `sandbox.terminal@1.0.0`/`terminal-v1`, and
   `sandbox-runtime-coding-shell-v1` as one atomic profile.
3. The actual executed Provider, external caller, qualification adapter,
   caller-owned Gateway, runtime image, qualification harness, Provider
   observer, Gateway observer, process supervisor, resource inspector, and
   teardown artifacts have observed immutable SHA-256 digests. Each requirement
   names the artifact role, owner, trust domain, digest subject, observing
   component, and whether an immutable source identity is mandatory. Raw
   executable bytes, an OCI image manifest or index, and a canonical
   configuration are different digest subjects. A process supervisor cannot be
   the sole observer of its own artifact. Source revisions alone are
   insufficient. The caller implementation and qualification adapter come from
   a source, owner, and release boundary outside the `sandbox-runtime` Git tree.
4. The caller has exactly two admitted controller identities belonging to two
   different tenants. A third same-CA URI-SAN identity is not admitted by the
   Provider listener.
5. The test target is dedicated and disposable. The operator has bounded
   run-namespace teardown within that target and can verify that no run-owned
   runtime resources remain.
6. Runtime image digest, architecture, resource ceiling, wall-clock deadline,
   process topology, persistent state locations, and a run-unique resource
   namespace are fixed before the run. Sanitized Provider, caller, adapter,
   Gateway, observer, inspector, teardown, topology, and architecture
   configuration snapshots have their own declared canonical digest profiles;
   executable identity does not substitute for configuration identity. An
   authoritative resource inspector captures the complete pre-run baseline for
   its declared query scope.

Generated code from the public Contract is permitted. The caller must not use
Provider implementation packages or the repository's `e2e/` request composer,
signer, workflow runner, or Gateway policy implementation.

## Required scenarios

The initial phase executes these scenarios in order:

1. `initial.locked-capability-discovery`;
2. `initial.protected-lifecycle-create`;
3. `initial.replay-semantics`;
4. `initial.lifecycle-completion-and-status`;
5. `initial.exec-result-and-usage-evidence`;
6. `initial.stale-fencing-rejection`;
7. `initial.exec-cancellation`;
8. `initial.terminal-session-and-opaque-handoff`;
9. `initial.gateway-terminal-byte-round-trip`;
10. `initial.gateway-wrong-caller-and-cross-tenant-rejection`;
11. `initial.gateway-grant-expiry`;
12. `initial.gateway-revocation`;
13. `initial.artifact-staging-and-evidence`;
14. `initial.provider-cross-tenant-artifact-rejection`; and
15. `initial.provider-mtls-caller-binding-rejection`.

`initial.replay-semantics` makes two different checks. Reusing the exact compact
JWS and JTI must fail with `409` before dispatch. Repeating the same logical
create with a new JTI but unchanged operation, idempotency, request digest, and
fencing bindings must return the same operation with no second runtime dispatch.
JTI rejection is not reported as idempotent replay.

Provider interactions lock HTTP route templates, statuses, and applicable stable
error codes. Caller-owned Gateway interactions lock only semantic outcomes. The
profile deliberately leaves their route as `consumer-defined` and their status
list empty; the future adapter protocol supplies the probe hook without turning
the caller's private Gateway API into a Provider standard.

The reconstruction phase restarts the Provider, external caller, qualification
adapter, and caller-owned Gateway processes while preserving only the state
declared by the run. It then executes:

1. `reconstruction.locked-capability-discovery`;
2. `reconstruction.durable-lifecycle`;
3. `reconstruction.retained-exec-usage-and-artifact-evidence`;
4. `reconstruction.durable-opaque-handoff`; and
5. `reconstruction.same-shell-reconnect`.

The Provider, external caller, adapter, and Gateway all receive new observed
process identities. Provider-local state, caller-owned correlation state, and
the runtime resource remain. The second invocation must not receive prior
sandbox, operation, attempt, idempotency, fencing, session, or handoff bindings
from the harness. The caller must recover them from its own durable store.

The process supervisor records a bounded sanitized invocation transcript for
both caller invocations. The transcript identifies the executable, process,
inherited-channel roles, configuration identities, and names of supplied fields,
but contains neither secret values nor forbidden correlation values. Its
canonical digest and field inventory must prove that reconstruction did not
receive a sandbox, operation, attempt, idempotency, fencing, runtime-session, or
handoff binding. Merely asserting that the harness did not re-inject state is not
an observation.

Before reconstruction, the Gateway observer creates a per-run unpredictable
shell-state challenge, sets it through the admitted terminal byte stream, and
observes confirmation. After all four processes have new identities, it opens a
fresh Gateway connection and verifies the same challenge in the same runtime
session. Evidence retains only bounded challenge and observation digests, not
the raw command or terminal output. A new shell that only completes another byte
round trip does not satisfy the same-shell case.

Each scenario is `passed`, `failed`, or `not_executed`. Skips and
not-applicable results are not accepted. A failed prerequisite marks every
dependent scenario `not_executed`. An executed mismatch is `failed`.
The separate run outcome is `passed`, `failed`, `incomplete`, or
`not_executed`, with `incomplete` taking precedence when cleanup, identity, or
required evidence is missing or unknown.

## Independent observations

Caller or adapter output alone cannot pass a case. Every interaction is bound to
one actor role, including the exact admitted controller and tenant or the
same-CA unadmitted identity. Every required observation names exactly one
oracle, subject, and correlation key. A case-level list of possible sources is
not sufficient. Caller-owner statements remain typed assertions and never count
as independent observations. The repository-owned harness correlates them with
four separately pinned observers:

- the Provider observer records bounded route templates, final status, stable
  error codes, mutation-write boundaries, dispatch counts, and selected stable
  Provider state without retaining raw protected documents;
- the Gateway observer actively probes authorization, byte forwarding, expiry,
  revocation, and reconnect behavior and consumes a bounded safe audit;
- the process supervisor records the actual executable or image digests and
  process replacement across reconstruction; and
- the authoritative resource inspector records the exact query scope, pre-run
  baseline, run ownership, and post-teardown inventory.

The observer implementations must be independent of the external caller and
adapter. One observer may supply several observations, but each observation has
one named oracle; an unrelated observation from the same case cannot
corroborate a caller assertion. Claims such as external ownership remain labeled
trusted inputs when no observer can establish them. The caller and adapter also
emit their embedded Contract revision, tree, profile ID, profile digest, and
release identities at startup. The harness compares those values with its
expectations; it must not supply the values that are presented as caller
self-identification.

Provider polling evidence distinguishes the terminal response from every
bounded transient response. A `404` or `503` is accepted only where the locked
Contract authorizes it for that state; required `Retry-After`, retryability,
deadline rechecks, and retry count are observed rather than collapsed into the
eventual `200`. Cancellation evidence reconciles the accepted `cancel_exec`
operation as well as the target operation and retained exec result. An accepted
cancel request alone is never a completed-cancellation observation.

## Caller Responsibilities

The external caller must construct and retain its own:

- exact Contract and Provider revision selection;
- mTLS client behavior, compact JWS, Admission Context, request/descriptor
  digests, and HTTP target binding;
- operation, attempt, fencing, idempotency, deadline, retry, and reconciliation
  state;
- tenant/work authorization decisions and negative cross-tenant requests;
- terminal Gateway authorization, revocation, recording, and reconnect policy;
  and
- artifact metadata and aggregate usage decisions outside Provider-local
  evidence.

The qualification operator may provision ephemeral trust material and invoke
the consumer-owned adapter. It must not generate protected Provider requests,
sign operations, choose retry outcomes, or proxy raw Provider responses into a
prewritten repository caller.

## Mutation and Cleanup

The profile performs Contract-authorized mutations. It must never run against
an arbitrary or production target. Operator-owned run-namespace teardown within
the disposable target is the v1 cleanup authority because the locked Contract
has no terminate or lease-control route.

The run is capped at one sandbox, three exec requests with at most two admitted
exec operations, one terminal session, two artifact requests with at most one
admitted artifact operation, eight distinct Provider mutations, twelve Provider
mutation write attempts, one Gateway control write, 512 Provider HTTP requests,
and eight Gateway connection attempts. The sandbox request is capped at 500
millicores, 256 MiB memory, 256 MiB ephemeral storage, and 64 PIDs.

Counters use observed transport boundaries. A Provider HTTP request is counted
once its request bytes may have been written; every mutating `POST`, including a
replay, counts once its request bytes may have been written; and a Gateway
attempt counts once connect or control bytes may have been written. Distinct
Provider mutations are unique interaction `logical_request_id` values marked
with that counter. Retries count as new attempts but not as new logical
operations when Contract idempotency returns the same operation. Global limits
preempt the smaller per-interaction wire-attempt limits.

Each case has at most 120 seconds from case dispatch until its terminal result,
further reduced by the remaining execution deadline. The 1,800-second execution
clock starts immediately before the first preflight read and ends after the last
scenario, including process reconstruction. The 2,100-second run clock has the
same start and ends after cleanup, reserving a separate cleanup context of at
most 300 seconds; case execution must stop early enough to preserve that cleanup
budget.
Post-run schema validation and receipt emission are not silently charged to a
different case clock and have their own validator deadline. Once any mutation
may have been written, cleanup is required even if the response is lost, the
caller exits, the run is cancelled, or the result is `outcome_unknown`.

The inspector query scope is a closed sanitized object binding the disposable
target, run namespace, ownership selector, resource kinds, inspector artifact,
and configuration identity while excluding the harness control plane. Its RFC
8785 full-document SHA-256 digest is recorded before mutation. A normalized
inventory is ordered lexicographically by resource type and stable observer ID;
entries expose no backend ID and the full document uses the same canonical
digest profile. The pre-run baseline contains zero run-owned resources. Cleanup
tears down the run namespace within the disposable target while the out-of-band
inspector remains available. Passing cleanup requires the post-teardown query
scope digest to match, three inventory samples one second apart to be stable and
equal the baseline, and the run-owned count to be zero. A vacuous,
changed-scope, unavailable, failed, or unknown inspection makes the run
`incomplete`, even if a behavioral mismatch also occurred.

This out-of-band teardown is qualification-harness behavior only. It is not a
Provider protocol operation and is not evidence that an external product can
terminate or renew a sandbox through v1.

## Required Evidence

One sanitized evidence payload records:

- profile ID and exact ordered scenario results for both phases;
- Contract, Suites, actual Provider, caller, adapter, Gateway, runtime image,
  observers, inspector, teardown, architecture, and configuration identities;
- which components and persistent stores were reconstructed;
- bounded route-template/status/error-code observations without request or
  response secrets;
- whether each Suite actually executed in this topology;
- mutation-write observation, cleanup obligation, cleanup attempts, cleanup
  completion, and zero remaining run-owned resources;
- exact payload-file inventory, raw file digests, sanitization result, start/end
  times, and evidence boundary; and
- observed facts separately from caller-owner assertions and trusted inputs.

The payload contains at most 16 regular non-symlink files, each at most 2 MiB
and together at most 8 MiB. Paths are unique relative POSIX paths under the
evidence root; path traversal and reopening a different file are rejected. The
16-file and 8-MiB limits apply to the final evidence root including
`report.json` and `receipt.json`; validation reserves one file slot and refuses
to emit a receipt when doing so would exceed either final bound.

`report.json` inventories and hashes only payload files other than itself and
`receipt.json`. Each inventory entry contains its relative POSIX path, byte
length, and raw-file SHA-256. Entries are ordered by the UTF-8 bytes of the path;
the complete closed inventory array is RFC 8785 canonicalized and SHA-256
hashed. After validation, the validator writes `receipt.json` with the SHA-256
of the exact raw `report.json` bytes, that canonical payload-inventory digest,
the profile identity, invocation identity, external artifact and process
identities, phase and ordered-result digest, completion state, and validation
outcome. The receipt does not hash itself. The final archive digest is recorded
by an external artifact envelope outside that payload. These exclusions avoid a
self-referential digest while still binding every file exactly once.

The evidence payload must not contain private keys, bearer tokens, encoded
Admission Contexts, certificate bodies, raw handoff or staging references, host
paths, credentials, secrets, backend IDs, daemon diagnostics, raw endpoints, or
captured command output.

## Passage and Claim Boundary

The profile passes only when all 20 scenarios execute and pass, caller and
adapter independence identities are present, every actual artifact and required
Contract/profile digest is exact, every required observation is produced by its
named independent oracle and correlated with separately labeled caller
assertions, cleanup completes, the resource inventory returns to baseline with
zero run-owned resources, and evidence sanitization succeeds.

A green result establishes interoperability only for the named external caller,
Provider revision, Contract identity, coding/shell profile, artifacts, topology,
and scenarios. It does not establish Provider Suite execution unless separately
recorded, nor aggregate conformance, multi-issuer admission, multi-controller
reliability, hostile multi-tenant isolation, HA, deployment, or production
readiness.
