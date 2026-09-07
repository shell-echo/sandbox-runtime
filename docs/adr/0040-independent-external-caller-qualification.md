# ADR 0040: Independent External Caller Qualification

- Status: Accepted
- Date: 2026-09-07

## Context

ADR 0037 makes the repository-owned Provider Contract the wire authority and
requires each external consumer to own its adapter. ADR 0038 makes protected
admission generic, while ADR 0039 provides content-addressed local and remote
discovery Suites. None of those results demonstrates that a separately owned
caller can construct and reconcile the complete coding/shell workflow.

The existing `e2e/` caller is valuable reference evidence, but it is developed,
reviewed, locked, and released with this repository. A separate Go module and
OS process do not make it independently implemented. Reusing that caller,
copying its request composer, or wrapping it in a product-specific launcher
would not close the external-caller gate.

There is also no Provider-authorized terminate, desired-state, or lease-renewal
route in the current locked OpenAPI. A qualification run that creates resources
therefore needs a disposable environment and operator-owned out-of-band cleanup.
That cleanup proves only that the test environment was restored; it does not
invent a Provider wire operation or close the lifecycle protocol gap.

## Decision

### Separate qualification profile

Define `sandbox-runtime-external-caller-coding-shell-v1` as a black-box evidence
profile outside the Provider Conformance Suites. Its exact requirements live in
the content-addressed
[`profile.json`](../../qualification/external-caller-coding-shell-v1/profile.json),
with explanatory text in
[`external-caller-coding-shell-v1.md`](../qualification/external-caller-coding-shell-v1.md).
It consumes the locked Provider Contract without changing Provider wire
behavior.

The profile digest removes only top-level `profile_digest`, RFC 8785 JCS
canonicalizes the complete remaining object, and hashes it with SHA-256. Closed
input, stable case IDs, dependencies, interactions, expected status and
error-code policies, observations, numeric limits, cleanup, and non-claims are
therefore one content-addressed identity.

The P2.7a repository verifier validates the closed schema, semantic cross-field
rules, exact 15+5 case, 41-interaction, and 91-observation inventory, schema
identity, and content digest. This locks the machine-readable definition
authority, not a report or qualification result. Overall P2.7 definition remains
in progress until the closed report schema and evidence validator exist.

The profile is not a new meaning for either
`sandbox-runtime-provider-v1` or
`sandbox-runtime-provider-remote-discovery-v1`. A report records local and
remote Suite execution independently and sets their exercised flags to false
unless those exact Suites actually ran in the recorded topology.

### Independence boundary

The caller implementation and its qualification adapter must be supplied from
an independently controlled source and release boundary outside the
`sandbox-runtime` Git tree. Evidence pins both the actual executed caller
artifact digest and its immutable source or release identity and identifies its
owner. Generated models from the
public OpenAPI or JSON Schemas are allowed. Importing, linking, invoking, or
copying Provider-side or `e2e/` request-signing and workflow code does not
establish independent implementation.

The caller runs in one or more processes separate from the Provider. It must
itself construct mTLS requests, compact JWS credentials, Admission Context
documents, request and descriptor digests, idempotency keys, attempts, fencing
values, and reconciliation decisions. The Provider test operator may provision
bounded ephemeral credentials and target configuration, but must not synthesize
Provider requests or sign protected operations on the caller's behalf.

The consumer owns any product-specific qualification adapter. This repository
defines the profile and evidence validator only; it does not acquire or maintain
consumer adapters.

### Exact run identity

Every run pins:

- the exact Provider Contract revision, tree, manifest digest, OpenAPI digest,
  capability versions, capability profiles, and runtime profile;
- the actual executed Provider, external caller, qualification adapter,
  caller-owned Gateway, runtime image, Provider observer, Gateway observer,
  process supervisor, resource inspector, and teardown artifact digests, plus
  their applicable source or release identities;
- the architecture, Provider, caller, adapter, Gateway, observer, inspector,
  teardown, and topology configuration digests and scenario inventory; and
- the execution environment, start and completion times, cleanup result, raw
  report digest, and externally recorded evidence-artifact digest.

Each executed-artifact requirement identifies the artifact role, owner, trust
domain, digest subject, observing component, and whether an immutable source or
release identity is mandatory. Raw executable bytes, an OCI manifest or index,
and a canonical configuration are distinct subjects. A process supervisor
cannot be the sole observer of its own artifact. Sanitized
architecture, Provider, caller, adapter, Gateway, observer, inspector, teardown,
and topology configurations have separate canonical identities; an executable
digest does not cover them implicitly.

Assertions supplied by the caller owner remain labeled as assertions. Each
interaction binds one actor role and authorization context, and each required
observation binds one named oracle, subject, and correlation key. A case-level
set of possible sources is not a substitute for that mapping. A pinned
repository-owned Provider observer, Gateway observer, process supervisor, and
authoritative resource inspector produce separate observations; caller output
never becomes independent merely because an unrelated observer also appears in
the case. The caller and adapter expose the Contract and
qualification-profile identities embedded in their actual artifacts at startup;
the harness compares them with expected values but must not inject the claimed
self-identity. Ownership and source-host statements that no observer can prove
remain explicit trusted inputs. A missing independence identity, unverifiable
artifact, or missing required observation makes the run incomplete rather than
silently turning a repository reference run into external evidence.

### Required topology and behavior

The coding/shell profile uses a dedicated, disposable target. It has exactly two
admitted controller identities belonging to different tenants plus one same-CA
but unadmitted mTLS identity. The external caller must exercise the
locked discovery, protected lifecycle, exec/cancel/result, terminal handoff,
caller-owned Gateway, artifact/usage, replay, stale-fence, caller-binding, and
negative cross-tenant scenarios declared by the profile.

The initial and reconstruction phases are distinct. The Provider, external
caller, adapter, and Gateway receive new observed process identities. Durable
reads and the same terminal allocation must survive. Correlation state remains
caller-owned: the harness must not re-inject prior sandbox, operation, attempt,
idempotency, fencing, session, or handoff bindings. A passed request before
reconstruction cannot substitute for the reconstruction phase.

The process supervisor records a bounded sanitized invocation transcript for
both caller invocations. It binds executable and process identity,
inherited-channel roles, configuration identities, and the names of supplied
fields while excluding secrets and raw correlation values. The transcript's
canonical digest and field inventory must show that the reconstructed invocation
did not receive a forbidden correlation binding. The Gateway observer also sets
and confirms a per-run unpredictable shell-state challenge before
reconstruction, then verifies the same challenge through a fresh connection
after process replacement. Evidence stores bounded hashes rather than terminal
commands or output. A newly allocated shell is not same-shell evidence.

Provider polling distinguishes terminal responses from bounded transient
responses and records Contract-authorized retryability, required `Retry-After`,
deadline checks, and attempt counts. Cancellation qualification reconciles the
accepted `cancel_exec` operation, the target operation, and the retained exec
result; acceptance alone is not final cancellation.

The two authorization contexts prove only the named binding and denial cases.
They do not establish hostile multi-tenant isolation, multi-controller
reliability, or a product's complete authorization policy.

### Cleanup and incomplete runs

Before any mutation, the operator verifies the exact disposable target,
credential scope, run-unique namespace, numeric resource and time budget,
authoritative inspector query scope, pre-run baseline, and cleanup mechanism.
The run may create at most the bounded resources declared by the profile. If a
mutating request may have been written, its cleanup obligation survives
cancellation, transport failure, and unknown outcome.

Request and mutation counters advance at observed transport boundaries: a
Provider request or mutating `POST` counts once its request bytes may have been
written, and a Gateway attempt counts once connect or control bytes may have
been written. A marked interaction's unique logical-request identity determines
distinct Provider mutations. Case time is the minimum of its own bound and the
remaining execution deadline. Execution time starts before the first preflight
read and includes reconstruction; total run time has the same start, ends after
cleanup, and excludes receipt validation. These clock and counting anchors are
evidence, not caller assertions.

Because the current Provider Contract has no cleanup route, the v1 profile uses
operator-owned run-namespace teardown within a dedicated disposable target. The
out-of-band authoritative inspector remains available across teardown. Its
closed sanitized query scope binds target, run namespace, ownership selector,
resource kinds, inspector artifact, and configuration, excludes the harness
control plane, and is content-addressed with RFC 8785 full-document JCS and
SHA-256. Inventory entries never expose a backend ID, are ordered by resource
type and stable observer ID, and are canonicalized with the same profile. Before
mutation, the baseline has zero run-owned resources. After teardown, the query
scope is unchanged, three samples one second apart are stable, the canonical
inventory digest equals the baseline, and the run-owned count is zero.
Changed-scope, vacuous, unavailable, failed, or unknown inspection makes the
qualification incomplete. Cleanup runs under a separate bounded context after
caller execution. Cleanup failure or an unknown cleanup outcome makes the
qualification incomplete whether behavioral scenarios failed or passed.

Prerequisite failures and unavailable environments are `not_executed`, not
Provider or caller failures. Cancellation stops further scenarios but still
enters cleanup. An executed mismatch is `failed`. A profile passes only when all
required scenarios executed and passed, cleanup completed, identity evidence is
complete, and the sanitized evidence set validates.

### Evidence safety

Evidence contains no private keys, bearer tokens, Admission Context bodies,
certificate bodies, raw endpoint references, host paths, command output,
credentials, secrets, backend identifiers, or daemon diagnostics. It may retain
bounded hashes, public certificate fingerprints, URI SAN identities approved
for publication, stable Provider error codes, route templates, status codes,
and timing summaries.

The report inventories payload files other than itself and the validator
receipt. Inventory entries contain relative POSIX path, byte length, and raw-file
SHA-256, are ordered by path UTF-8 bytes, and are RFC 8785 canonicalized before
SHA-256. The validator receipt records the exact raw report SHA-256, canonical
payload-inventory digest, profile and invocation identities, external artifact
and process identities, phase and ordered-result digest, completion state, and
validation outcome. The final file-count and byte bounds include both report and
receipt, so the validator reserves capacity before emitting the receipt. An
external artifact envelope records the final archive digest. No file hashes
itself. The evidence validator checks shape, exact scenario order, identities,
independent observations, cleanup, sanitization, and overclaim fields. It does
not attest the honesty of an
external owner, source host, build service, operating system, or network. Those
remain explicit trust inputs.

## Consequences

- External consumers have one repository-defined qualification target while
  retaining ownership of their adapters and business policy.
- The Provider does not gain a consumer registry, SDK dependency, or
  consumer-specific DTO.
- A caller can fail or leave a run incomplete independently of Provider
  conformance results.
- The existing same-repository reference evidence remains useful regression
  evidence but cannot satisfy the independence requirement.
- A future portable mutating Provider Suite still requires its own Contract
  resource and Provider-level cleanup authority; this ADR does not supply one.

## Non-goals

This decision does not qualify any current external caller, add Provider routes,
standardize a consumer's business API, require public source code, or establish
aggregate conformance, multi-issuer admission, multi-controller reliability,
hostile multi-tenant safety, HA, deployment, or production readiness.
