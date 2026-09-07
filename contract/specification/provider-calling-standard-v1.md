# Sandbox Runtime Provider Calling Standard v1

## Status and scope

This specification is the human-readable calling choreography for the
repository-owned Sandbox Runtime Provider Contract. It applies to namespace
`urn:shell-echo:sandbox-runtime:provider-v1`, version `1.0.0`, only when this
resource is present in the Contract manifest and in the exact Contract tree
selected by a consumer's lock.

This specification composes requirements already defined by the Provider
Contract. It adds no route, field, status, capability, operation, or production
claim. The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and
**SHOULD NOT** describe an obligation only when the paragraph points to an
existing OpenAPI operation, JSON Schema, semantic rule, fixture, or Conformance
Suite case that supplies that obligation.

The local `/instances` management API is outside this standard. It is not an
alternative Provider wire surface, and its DTOs and backend state are not
Provider Contract documents.

## Contract authority

The Contract resources are cumulative constraints with distinct roles:

| Resource | Authority |
| --- | --- |
| [`contract-manifest.json`](../compatibility/contract-manifest.json) | Declares the Contract identity and resource inventory. It does not define wire behavior by itself. |
| [`sandbox-runtime-provider-v1.yaml`](../openapi/sandbox-runtime-provider-v1.yaml) | Defines the HTTP methods, paths, security schemes, media types, request limits, and response status surface. |
| [`schemas/`](../schemas/) | Defines the closed request, response, operation, handoff, capability, error, and evidence document shapes. |
| [`provider-v1.json`](../semantic-rules/provider-v1.json) | Defines cross-field, admission, ownership, lifecycle, profile, and evidence semantics that are not fully expressible in OpenAPI or JSON Schema. |
| [`fixtures/`](../fixtures/) | Supplies canonical accepted documents and rejection matrices for the named schemas and semantic rules. |
| [`suite.json`](../conformance/provider-v1/suite.json) | Names the executable Provider conformance cases for the required profile. Passing cases cannot authorize behavior absent from the other Contract resources. |
| This specification | Orders the existing resources into caller workflows and responsibility boundaries. |

No resource silently overrides another. An inconsistency between Contract
resources is a Contract defect: implementations fail closed and the revision is
corrected through the Contract change protocol before a compatibility claim is
made.

[`compatibility/sandbox-runtime/contract.lock.json`](../../compatibility/sandbox-runtime/contract.lock.json)
selects an immutable repository revision and Contract tree. The lock proves
resource identity and integrity; it does not by itself prove behavior,
conformance, deployment safety, or production readiness. Architecture and ADRs
define ownership and release gates outside the wire Contract. Narrative guides
under `docs/` are non-normative.

## Exact revision compatibility

Namespace `urn:shell-echo:sandbox-runtime:provider-v1` and semantic version
`1.0.0` identify the protocol family. They are not sufficient compatibility
coordinates. Every compatibility claim identifies all of:

- the exact Contract `source.revision` and `source.contract_tree` from the
  consumed lock;
- the selected immutable `provider_revision_id`;
- the exact capability versions, capability profile IDs, and runtime profile
  ID selected from one immutable capability snapshot; and
- any runtime image, policy, or evidence identities required by the selected
  deployment gate.

An additive v1 change may retain the namespace and semantic version while
producing a new exact revision and tree. A caller does not follow an implicit
"latest v1". It consumes a reviewed lock, verifies that lock, and switches to a
new revision deliberately. A breaking wire or semantic change requires a new
protocol version and namespace revision, as recorded by the architecture's
Contract versioning rules.

At the time this specification was introduced, the published lock still named
revision `5096e71fb84fbec22aa3487a0e55a1b49602ab8b` and Contract tree
`859f76dc0e855a0c8abdbbb5648df100dabb4328`. That tree predates this resource.
Consequently, this specification is not part of an effective locked Contract
until a later reviewed lock refresh names the commit and tree that contain it.
No compatibility or conformance result for the earlier tree may be relabeled as
evidence for the later exact Contract identity.

## Roles and responsibility boundaries

### Provider

The Provider owns provider-local execution and evidence:

- the immutable capability snapshot it returns;
- provider-local sandbox state, runtime resources, leases, operations,
  reconciliation, retained results, and bounded evidence;
- internal terminal and Browser endpoint resolution; and
- backend provisioning, observation, execution, and cleanup.

The Provider performs the protected admission checks bound by
`protected-admission-*` semantic rules. It does not become authoritative for
end-user identity, business workflow state, aggregate operation outcomes,
artifact publication, billing, or a public Gateway.

### Caller

The Caller owns business and end-user authority. It selects and durably binds a
Provider revision and an exactly advertised profile, authorizes tenant and user
intent, creates the Contract request and admission documents, and retains the
correlation needed to reconcile Provider operations. It remains authoritative
for product workflow state, aggregate operation decisions, artifact metadata
and publication, usage accounting, billing, and public endpoint policy.

Fields such as `tenant_id`, `work_order_id`, `workspace_id`, `branch_id`, and
`provider_resolution_id` are opaque Provider correlation bindings under v1.
They do not require a caller to adopt a particular external platform data model,
but the caller must supply stable values satisfying the locked schemas and keep
their business meaning outside Provider state.

The Caller treats Provider results as provider-local observations or evidence.
It does not infer a business-level success, billing total, or public artifact
URL from a Provider projection.

### Runtime Gateway

Terminal and Browser data planes are caller-owned Gateway responsibilities.
The Provider returns only an opaque, expiring handoff reference. The Gateway
performs its own user and tenant authorization, exact grant and session binding,
revocation, connection admission, reconnect policy, and metadata-only audit,
then resolves a fresh private endpoint through the Provider-owned resolver.

The Gateway does not expose or persist a Provider backend ID, host path,
container or Pod name, raw terminal endpoint, Chromium debugging endpoint,
backend token, or Provider credential. The Browser-specific boundary is further
defined by semantic rules `browser-session-gateway-handoff` and
`browser-session-security-boundary` and their named fixtures.

The Caller and Gateway may be implemented by the same product, but their
authority remains outside the Provider.

## Common calling flow

### 1. Verify and select inputs

Before sending Provider traffic, the Caller verifies the exact Contract lock
and retains the selected Contract and Provider revision identities. It does not
construct behavior from this specification without the rest of the locked
Contract resources.

### 2. Discover capabilities

The Caller invokes `GET /v1/capabilities` over mutually authenticated TLS. The
request has no query, body, bearer-token substitution, unsupported transfer
coding, or other request metadata forbidden by the OpenAPI operation and
semantic rules `capabilities-mtls-only`,
`capabilities-no-bearer-substitution`, and `capabilities-request-empty`.

The returned capability document is one immutable snapshot. The Caller selects
only an exact combination present in that snapshot and retains its
`provider_revision_id`. Route presence does not imply that a capability is
advertised or ready.

### 3. Construct a protected request

For a protected mutation, the Caller constructs a document accepted by the
route's referenced JSON Schema and within the OpenAPI encoded-body limit. It
uses the Contract-defined request digest profile and creates the admission
context and target documents required by the `protected-admission-*` rules.
The Caller serializes the complete Admission Context JSON document, computes
its required digest, encodes it as unpadded base64url, and sends it as exactly
one `X-Sandbox-Runtime-Admission-Context` header field value. Both the encoded
value and decoded document are bounded to 16,384 characters and 16,384 bytes,
respectively.

For a protected read, the Caller constructs the exact descriptor and digest
binding required for that operation. It does not substitute a mutation body,
path value, operation ID, attempt, generation, fencing value, or target from a
different request.

### 4. Send through protected admission

Protected routes require both the admitted mTLS identity and the short-lived
JWS bearer defined by the OpenAPI security declaration and semantic rules
`protected-admission-mtls-and-bearer`, `protected-admission-binding`,
`protected-admission-jws-profile`,
`protected-admission-issuer-local-authority-binding`,
`protected-admission-replay-fencing`, and
`protected-admission-contract-ids`.

The admission binding covers the configured issuer, selected mTLS caller,
Provider-local revision and audience, HTTP target, operation, request or
descriptor digest, policy decision, deadline, attempt, generation, fencing
token, and other fields required by the referenced schemas. Unknown, malformed,
oversized, expired, replayed, substituted, or stale input is rejected before
mutation where the Contract requires preflight.

### 5. Retain and reconcile the operation

An accepted mutation returns `202` with a Provider operation document. The
Caller durably retains its own correlation between business intent,
idempotency key, operation ID, attempt, generation, fencing value, request
digest, and Provider revision. Provider-local operation state does not replace
the Caller's aggregate ledger.

The Caller reads `GET /v1/operations/{operation_id}` and any operation-specific
result or evidence route using their protected descriptors. It preserves the
Contract distinction between accepted, running, terminal, expired,
temporarily unavailable, and outcome-unknown states. It reconciles an unknown
outcome instead of assuming failure or issuing an unbounded duplicate mutation.

### 6. Consume only the selected projection

The Caller consumes only fields authorized by the relevant response schema. A
successful runtime-session or Browser-session operation yields an opaque
handoff for the caller-owned Gateway. Artifact and usage routes yield bounded
Provider evidence, not public artifacts, prices, invoices, or final product
state.

## Authentication and admission

Capability discovery uses the admitted certificate identity and does not use a
bearer token as a replacement. Every protected route uses both mTLS and the
Contract-defined JWS carrier. The Caller validates and rotates its own identity
material according to its deployment policy; this Contract defines the wire
binding, not a production PKI service.

The bearer is a compact JWS with a closed
`protected-operation-jws-header.schema.json` header and closed
`protected-operation-jws-claims.schema.json` claims document. The protected
header uses `typ` `agent-sandbox-operation-admission+jwt`, an `EdDSA` or `ES256`
algorithm, and an issuer-scoped `kid`. Its `iss` claim is a 1-to-200-character
JWT StringOrURI and must exactly, case-sensitively equal the one issuer
configured for the Provider listener. A StringOrURI containing `:` is an
absolute URI and MUST NOT contain a fragment. There is no default, fallback,
alias, normalization, or bearer-led issuer discovery. The legacy opaque value
`agent-platform` is accepted only if the operator explicitly configures that
exact issuer.

The maximum bearer lifetime from `iat` through `exp` is 300 seconds. Key
rotation adds the new issuer-scoped public key and restarts the listener before
the caller switches signing keys. After old-key signing stops, the operator
waits 300 seconds, removes the old public key, and restarts the listener again.
This overlap is explicit; key removal does not rely on remote discovery or an
unbounded estimate of token expiry.

The listener's admitted URI SAN controller identities and frozen verification
keys all belong to that one issuer scope. The signed `sub` exactly equals the
one selected TLS-verified URI SAN. The signed `aud` and
`provider_revision_id`, and the corresponding Admission Context fields, each
independently equal the Provider-local audience and immutable capability
revision. Agreement between the two caller-supplied documents cannot replace
those local comparisons. This profile does not use a certificate thumbprint or
JWT `cnf` claim.

An unknown issuer, unknown key ID, invalid signature, malformed JWS, or inactive
token is an authentication failure represented by the operation's authorized
`401`. After successful signature verification under the configured issuer,
an incorrect mTLS subject, local audience, local Provider revision, or other
admission binding is an authorization failure represented by `403`. Responses
do not identify the failed issuer, key, certificate, or comparison.

Digest calculation follows the exact digest profile named by the operation
binding. Request mutations use
`rfc8785-request-excluding-request-digest-v1`; protected reads use
`rfc8785-full-document-v1` where specified. Admission context calculation uses
the profile declared by the admission-context schema and fixture. The Caller
does not invent an alternative canonicalization or omit a bound field.

Authentication failure, authorization failure, invalid input, conflict,
unsupported capability, capacity exhaustion, temporary unavailability, and
expiry are consumed through the OpenAPI status surface and closed standard
error schemas. Implementation diagnostics, daemon errors, addresses, paths,
tokens, or credentials are never a stable error API.

## Asynchrony, idempotency, retries, and cancellation

Provider mutations are asynchronous. Acceptance means that the Provider has
accepted the identified operation under the applicable semantic rule; it does
not mean the requested external effect has completed.

An idempotency replay retains the same logical operation identity and the same
bound request. A Caller does not reuse an idempotency key for changed input,
change attempt or fencing data without the Contract-defined transition, or
blindly create replacement work after an uncertain dispatch outcome.

Retries are bounded by caller policy and the Contract outcome. The Caller
retries only outcomes represented as retryable, observes `Retry-After` where
the OpenAPI operation or semantic rule requires it, and rechecks the request
deadline, lease, Provider revision, generation, attempt, and fencing binding.
Non-retryable rejection is not converted into a retry by parsing an internal
error string.

`POST /v1/sandboxes/{sandbox_id}/exec:cancel` records cancellation intent under
`exec-cancel-bounded`; acceptance is not confirmation that the external process
has already stopped. The Caller observes the retained operation and result
projections to reconcile the final outcome.

## Profiles and route families

The capability snapshot may be empty or may advertise only a Contract-valid
terminal, atomic coding/shell, or Browser profile shape. The exact shapes are
defined by the capability schemas, fixtures, and these semantic rules:

- `capabilities-terminal-profile-advertisement` binds
  `sandbox.terminal@1.0.0`, `terminal-v1`, and
  `sandbox-runtime-terminal-v1`;
- `capabilities-coding-shell-profile-advertisement` atomically binds
  `sandbox.exec@1.0.0`/`exec-v1` and
  `sandbox.terminal@1.0.0`/`terminal-v1` to
  `sandbox-runtime-coding-shell-v1`; and
- `capabilities-browser-profile-advertisement` binds
  `sandbox.browser@1.0.0`, `browser-v1`, and
  `sandbox-runtime-browser-v1` and forbids combining that profile with the
  coding/shell profile.

Coding/shell and Browser create requests retain stable guest paths `/inputs`,
`/workspace`, `/outputs`, and `/tmp` as defined by their semantic rules. A
snapshot/restore profile in capability metadata does not authorize an absent
snapshot or restore route.

The OpenAPI document currently authorizes these calling families:

- discovery: `GET /v1/capabilities`;
- lifecycle: `POST /v1/sandboxes` and
  `GET /v1/sandboxes/{sandbox_id}`;
- exec: `POST /v1/sandboxes/{sandbox_id}/exec`,
  `POST /v1/sandboxes/{sandbox_id}/exec:cancel`, and
  `GET /v1/operations/{operation_id}/exec-result`;
- terminal: `POST /v1/sandboxes/{sandbox_id}/runtime-sessions` and
  `GET /v1/operations/{operation_id}/runtime-session`;
- Browser: `POST /v1/sandboxes/{sandbox_id}/browser-sessions` and
  `GET /v1/operations/{operation_id}/browser-session`;
- operation reconciliation: `GET /v1/operations/{operation_id}`; and
- evidence: `POST /v1/sandboxes/{sandbox_id}/artifacts:stage`,
  `GET /v1/operations/{operation_id}/artifact-staging-evidence`, and
  `GET /v1/operations/{operation_id}/usage-evidence`.

Operation names reserved by an admission binding do not authorize a route that
is absent from OpenAPI. A Caller sends only operations in the selected locked
OpenAPI and only for capabilities advertised by the selected Provider
revision.

## Evidence and conformance

The Contract lock verifier establishes the identity and integrity of the
consumed resource tree. JSON Schema or projection tests establish selected
document behavior. The Conformance Suite maps every case ID in the required
profile to executable repository tests. These evidence tiers remain distinct.

A compatibility claim states the exact Contract revision/tree and Provider
revision exercised, the selected profile, the Suite case inventory, and whether
the Suite actually ran in that topology. Metadata that records
`suite_exercised=false` is not a Conformance Suite result. Separate component or
E2E profiles cannot be combined into an aggregate, multi-controller,
multi-tenant, deployment, or production claim without a separately named gate
and reproducible evidence.

The Suite's current declared `suite_digest` is a placeholder. The exact locked
Git Contract tree protects the Suite file at the selected revision, but the
declared value is not an independently content-derived Suite digest and is not
presented as one.

## Current implementation and deployment gaps

The following are non-normative maturity boundaries, not additions to Provider
wire behavior:

- the current OpenAPI authorizes sandbox create/read but not explicit
  terminate, desired-state, lease-renewal, snapshot, restore, or event routes;
  names reserved in admission documents do not close that lifecycle;
- terminal and Browser handoffs require a caller-owned Gateway, but v1 does not
  define public Gateway, close-session, resize, or revocation wire operations;
- capability discovery does not carry the full Contract revision/tree, so the
  caller obtains and verifies that identity out of band;
- the production command does not currently advertise Browser or expose a
  public Browser Gateway;
- current Browser controlled-restore evidence does not establish independent
  PostgreSQL and Valkey failure or backup domains, HA/failover, production
  operator controls, hostile-tenant isolation, or deployment readiness;
- file-backed Provider repositories remain single-controller development
  evidence rather than transactional multi-controller storage; and
- the repository-owned Suite maps case IDs to this repository's tests; it is not
  yet a language-neutral runner against an arbitrary remote Provider and does
  not by itself prove an external product's business workflow, authorization,
  aggregate ledger, Gateway, deployment, or production behavior.

These gaps do not weaken the locked wire Contract. They prevent broader
advertisement or readiness claims until their separately named gates pass.

## Non-goals

This specification does not:

- define the local `/instances` API;
- define WorkOrder, Run, user, tenant-policy, billing, or artifact-publication
  models for a particular calling product;
- define a multi-issuer listener, issuer selected by bearer input, remote JWKS
  discovery, or a multi-consumer trust namespace;
- expose a Provider-owned public terminal or Browser Gateway;
- standardize backend IDs, daemon APIs, host paths, raw endpoints, credentials,
  or implementation diagnostics;
- authorize desktop, GPU, port-forward, nested-container, snapshot, restore, or
  other operation families absent from the locked OpenAPI and advertised
  profile;
- establish a production PKI, storage topology, HA/failover procedure,
  deployment, hostile multi-tenant isolation, or production readiness; or
- replace the exact OpenAPI, schemas, semantic rules, fixtures, Suite, or lock.

## Contract change protocol

A wire or semantic change is made in the resource that owns that constraint,
with coordinated schema, semantic-rule, fixture, Suite, projection, caller, and
documentation changes where applicable. A requirement is not added only to
this Markdown document when it cannot be traced to an existing executable or
machine-readable Contract resource.

After the Contract resources are committed, the repository lock is refreshed
to the exact revision, Contract tree, manifest digest, and unchanged or updated
resource digests. Callers and evidence profiles opt in to that exact identity;
historical results retain the identity they actually exercised.
