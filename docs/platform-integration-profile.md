# Provider Integration Guide

This document is the non-normative handoff guide for any service or integration
adapter calling `sandbox-runtime`. Consumers adapt to the repository-owned
Provider Contract; this repository does not implement consumer-specific wire
adapters.

It is not a second Contract. The repository-owned MIT Provider Contract is the
only wire authority. Start with the normative
[`Sandbox Provider Calling Standard`](../contract/specification/provider-calling-standard-v1.md).
The calling standard, OpenAPI document, JSON Schemas, semantic rules, fixtures,
Conformance Suite, and Contract lock take precedence over any summary here.

## Authority and identity

Use these files together:

| Input | Role |
| --- | --- |
| [`contract/specification/provider-calling-standard-v1.md`](../contract/specification/provider-calling-standard-v1.md) | Normative caller sequence, ownership, and conformance obligations |
| [`contract/openapi/sandbox-runtime-provider-v1.yaml`](../contract/openapi/sandbox-runtime-provider-v1.yaml) | Provider HTTP wire surface; terminal and Browser handoffs are projected separately |
| [`contract/schemas/`](../contract/schemas/) | Closed request, response, operation, and evidence shapes |
| [`contract/semantic-rules/provider-v1.json`](../contract/semantic-rules/provider-v1.json) | Cross-field, ownership, admission, and lifecycle semantics |
| [`contract/fixtures/`](../contract/fixtures/) | Canonical examples and negative cases |
| [`contract/conformance/provider-v1/suite.json`](../contract/conformance/provider-v1/suite.json) | Locked 53-case Provider Suite |
| [`compatibility/sandbox-runtime/contract.lock.json`](../compatibility/sandbox-runtime/contract.lock.json) | Contract revision and resource lock |
| [`docs/architecture.md`](architecture.md) | Ownership boundaries and delivery gates |

The current Contract identity is:

| Field | Value |
| --- | --- |
| Namespace | `urn:shell-echo:sandbox-runtime:provider-v1` |
| Version | `1.0.0` |
| License | `MIT` |
| Revision | `22ba6987ea5fbc37d53942720133c0acad199edd` |
| Contract tree | `c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38` |
| Manifest digest | `sha256:1e17e0ef4f86e03be1dac22c48e7b556a8600a4baa6252f4514390d339b8ba3f` |
| Local Suite | `sandbox-provider@1.0.0` / `sandbox-runtime-provider-v1`; `repository-go-test`; 53 cases; `sha256:b40c932643f4a1e5fd6681e3abf9b64a607609866a6254456970f8b8034cf2a8` |
| Remote Suite | `sandbox-provider-remote@1.0.0` / `sandbox-runtime-provider-remote-discovery-v1`; `remote-http-black-box`; 6 cases; `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0` |

An integration must pin this identity, the selected Provider revision, the
runtime/profile identifiers, and the exact evidence or image digests it relies
on. A repository commit or a passing local test does not replace the Contract
lock. Both Suite digests use
`rfc8785-full-document-excluding-suite-digest-v1`: the complete Suite object is
RFC 8785 canonicalized after removing only its top-level `suite_digest`, then
hashed with SHA-256. The Git revision and tree remain the broader Contract
identity.

### Listener-local caller trust

The current ADR 0038 implementation assigns one caller trust domain to one
protected Provider listener. Enabling the listener requires all of these local
startup values:

- one exact issuer with no default, alias, fallback, or normalization;
- one Provider-instance audience and the immutable locally advertised Provider
  revision;
- the admitted mTLS URI SAN identities for that issuer; and
- 1..32 public verification keys with distinct `kid` values.

The Provider freezes those values before serving protected traffic. It never
uses the bearer `iss`, `aud`, `provider_revision_id`, `kid`, `sub`, or the
Admission Context to select a trust domain. The signed token and Admission
Context must independently match the Provider-local audience and revision. A
token from a trusted key but a different configured issuer is unauthenticated;
a verified token with the wrong local audience or revision is forbidden before
request digest verification or mutation reservation.

Rotate signing keys through explicit overlap and restart:

1. Install old and new public keys under distinct `kid` values, staying within
   the 32-key limit.
2. Restart the Provider listener so it freezes the overlap bundle.
3. Stop all old-key signing, move the caller to the new signing key, and wait
   300 seconds.
4. Remove the old key and restart the listener again.

There is no remote JWKS refresh or multi-issuer listener. A deployment that
needs multiple issuer-scoped caller trust domains must use separate listeners
or wait for a separately reviewed namespace design; it must not combine key or
identity bundles informally.

This implementation has passed its repository-local Contract, projection,
configuration, conformance, E2E lock, and same-repository reference gates. That
reference caller does not establish independently implemented external-caller
interoperability; each deployment and external caller still needs its own
pinned qualification evidence.

## Ownership boundary

The Provider is a provider-local execution and evidence service. The caller is
the authority for business and end-user concerns.

| Concern | Provider owns | Caller owns |
| --- | --- | --- |
| Capability discovery | Immutable capability snapshot and limits | Selecting a compatible Provider revision/profile |
| Sandbox execution | Provider-local sandbox state, leases, runtime resources, operations, and bounded evidence | WorkOrder/Run business state and desired-state policy |
| Authorization | Protected admission checks for the caller-supplied request context | End-user identity, tenant policy, user authorization, and Gateway policy |
| Operations | Provider operation acceptance, idempotency, attempts, fencing, cancellation, and reconciliation | Aggregate operation ledger and product-level state transitions |
| Terminal access | Opaque session handoff and private provider-side resolver | Public Gateway, grant issuance, revocation policy, and audit sink |
| Browser access | Opaque Browser-session handoff, private resolver, runtime resources, and restricted-egress binding | Public Gateway, end-user grants, revocation, abuse controls, and audit policy |
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
| `POST /v1/sandboxes/{sandbox_id}/browser-sessions` | Accept a Browser-session open request | Require the exact advertised Browser capability and runtime profile |
| `GET /v1/operations/{operation_id}` | Read the provider operation projection | Poll or reconcile without inventing a platform operation state |
| `GET /v1/operations/{operation_id}/exec-result` | Read an execution result projection | Keep result expiry and unknown outcomes explicit |
| `GET /v1/operations/{operation_id}/runtime-session` | Read a successful session handoff projection | Treat the handoff as opaque and expiring |
| `GET /v1/operations/{operation_id}/browser-session` | Read a successful Browser-session handoff projection | Pass the opaque, expiring handoff only to the caller-owned Browser Gateway |
| `POST /v1/sandboxes/{sandbox_id}/artifacts:stage` | Accept provider-local artifact staging | Keep the returned reference private; publication remains caller-owned |
| `GET /v1/operations/{operation_id}/artifact-staging-evidence` | Read artifact staging evidence | Correlate it with the exact operation and sandbox attempt |
| `GET /v1/operations/{operation_id}/usage-evidence` | Read usage evidence | Use it as provider evidence, not as billing truth |

The Contract may reject unsupported profiles, stale generations, replayed or
conflicting attempts, invalid digests, expired leases, unavailable capacity,
and requests outside the advertised capability graph. A caller must handle
these as typed Provider outcomes rather than parse implementation diagnostics.

## Admission and operation rules

Protected operation routes require all of the following layers:

1. A mutually authenticated TLS connection with an admitted caller identity.
2. Exact authentication against the listener's configured issuer and frozen
   verification-key bundle.
3. Authorization against the Provider-local audience/revision, mTLS subject,
   Admission Context, operation, request, and policy bindings.
4. The Contract-defined request metadata and descriptor digest.
5. Replay, idempotency, attempt, generation, lease, and fencing checks.
6. Strict schema and semantic validation before any mutation where the Contract
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

## Browser profile

Browser is an optional, atomic capability profile. A caller must not infer
support from route presence: it may open a Browser session only when the
immutable capability snapshot advertises the complete locked Browser shape and
the selected deployment passes its separate readiness gates.

A successful Browser-session operation returns only an opaque, expiring
handoff. The caller-owned Browser Gateway must bind that handoff to the exact
caller, tenant, Browser-session, grant, and freshly resolved endpoint; enforce
authorization, revocation, connection and request capacity, and audit policy;
and avoid recording CDP payloads. Provider responses expose no raw Chromium
endpoint, backend identifier, host path, or credential.

The reference profiles prove signed real-Chromium execution, restricted egress,
Gateway denial and recovery, shared capacity, durable exact-grant revocation,
downstream action fencing, and controlled-restore ordering within their named
topologies. The production command still exposes no public Browser Gateway and
does not advertise Browser. Independent PostgreSQL/Valkey failure and backup
domains, HA/failover, production operator controls, hostile-tenant evidence,
deployment, and production readiness remain separate gates.

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

Every external caller should complete these items before claiming an
integration:

- Pin the Contract namespace, revision, tree digest, Suite, and selected
  ProviderRevision/profile.
- Agree with the Provider operator on one exact issuer, Provider-instance
  audience, Provider revision, admitted URI SAN identity, and distinct key IDs;
  do not expect a default or fallback issuer.
- Implement mTLS identity validation and JWS/digest admission using caller-owned
  credentials and the overlap/restart key rotation procedure.
- Map caller intent to Provider requests without moving business truth
  into the Provider.
- Store Provider operation IDs, idempotency keys, attempts, generations, and
  fencing values in a caller-owned correlation record.
- Implement bounded polling/reconciliation for pending, unknown, expired,
  rejected, and unavailable outcomes.
- Supply Gateway authorization, revocation, recording, and public endpoint
  policy for terminal and Browser sessions.
- Before advertising Browser, supply deployment-owned shared capacity, durable
  revocation, downstream fencing, independently operated witness/restore
  domains, and fail-closed quarantine/resume controls.
- Keep artifact publication and billing outside the Provider evidence routes.
- Run the locked Contract verifier and the clean VCS-built 53-case local Suite
  Runner. Run the distinct six-case remote discovery profile against a
  separately started Provider, and qualify a separately implemented black-box
  caller as its own evidence gate.
- Own any consumer-side rollout, shadow, canary, rollback, drain, and metric
  comparison process. These are not Provider compatibility requirements.

## Evidence boundary

The repository's `e2e/` module keeps eight deliberately separate profiles:

- coding/shell Reference and historical Platform Candidate;
- Browser Reference;
- Browser shared capacity and durable exact-grant revocation; and
- Browser downstream fencing v1, witnessed v2, and PostgreSQL
  controlled-restore.

Reference and Candidate use real processes, sockets, mTLS/JWS, WebSocket, and
Docker; Candidate models platform bindings and migration policy but is not a
separately owned production platform. Browser Reference exercises the signed
real Browser path. Shared-capacity and durable-revocation use narrower fixtures
for their named distributed authority properties. The downstream-fencing and
controlled-restore profiles use real Chromium but record the Contract Suite as
unexercised (`suite_exercised=false`). The PostgreSQL witness workflow is a
separate component/integration track rather than a ninth E2E profile.

The generic reference caller in this repository remains reference evidence; it
does not establish independently implemented external-caller interoperability.
The historical P2.6 repository-owned 50-case local profile and six-case remote
discovery profile passed locally at implementation `3fe314a` and E2E lock
refresh `ae476fe`. The current local profile has 53 cases and requires a fresh
clean VCS-built run after the authority refresh is committed; no current P2.6
pass is claimed. Those profiles do not convert the existing E2E tracks into
aggregate evidence, and the remote profile does not cover protected or
mutating routes.
None of these results proves multi-issuer admission, aggregate conformance,
multi-controller reliability, multi-tenant isolation, HA, deployment
qualification, or production readiness. Those gates require their own
environment and reproducible evidence.

To reproduce the repository-level checks:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go run ./cmd/verify-contract -source-root .
runner_dir="$(mktemp -d)"
go build -buildvcs=true -o "$runner_dir/run-conformance" ./cmd/run-conformance
"$runner_dir/run-conformance" -source-root . -race -shuffle
```

The local Runner rejects missing or modified VCS build information and an
explicit `GOROOT`, then executes the exact Runner revision from a bounded
read-only Git archive. It resolves Git once to one absolute path reused for
verification and archive creation. Every case declares an exact mapped-test
count and requires all matching tests to be distinct, started, non-skipped
passes. The host OS, filesystem, initial Git selection, and Go and Git
executables remain trusted local inputs; path and self-reported version checks
do not attest their integrity. Do not replace the build with `go run
./cmd/run-conformance`; Go 1.26.5 does not record the required VCS settings for
that generated executable. The remote CLI requires an HTTPS Provider origin,
server CA, client CA, admitted client certificate/key, same-CA denied client
certificate/key, TLS server name, and expected Provider revision. Its unsafe
method flag becomes true only after a POST, PUT, PATCH, or DELETE discovery-path
probe is actually written. Its complete invocation is documented in
[`compatibility/sandbox-runtime/README.md`](../compatibility/sandbox-runtime/README.md).

All E2E commands are documented in [`e2e/README.md`](../e2e/README.md). Each
artifact must retain its named boundary; partial properties from separate
profiles must not be combined into aggregate conformance, independently
implemented external-caller interoperability, independent failure-domain,
deployment, or production evidence.

## Change protocol

When the Provider wire behavior changes, update the Contract resources and
lock first, then update projections, fixtures, conformance cases, callers, and
this guide in one reviewed slice. When a caller needs a new business field,
first decide whether it belongs to the caller or to the Provider Contract; do
not add a caller-owned field to a Provider DTO merely to simplify mapping.

This document should be updated when the Contract identity, ownership boundary,
route family, caller checklist, or evidence boundary changes. Commit-level
evidence belongs in [`docs/STATUS.md`](STATUS.md); stable architecture belongs
in [`docs/PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) and
[`docs/architecture.md`](architecture.md).
