# ADR 0040: Independent External Caller Qualification

P2.7c.2 is implemented through c2b.7: the producer builds the closed sanitized
transcript and the report validator independently recomputes RFC 8785/SHA-256
from `process-supervisor.json`'s `adapter_transcript_projection`. It binds the
protocol, phases, invocations, processes, executables, configurations and field
inventory, and checks message order, derived counts and status consistency.
Physical byte counts, EOF/exit and process truth remain supervisor inputs, not
independent observations made by this validator. No independent external-caller
qualification result is claimed. c3.1 adds descriptor-backed, bounded executable
preflight and rechecking without launching a process. The fixed 24-step plan
has 21 completed and 3 unfinished steps. c3.2 implements the final static
configuration commitment, exclusive custody transfer and one-shot logical phase
admission with live descriptor rechecks. Reconstruction uses the existing
protocol completion gate; outer-harness evidence remains open.
c3.3 implements actual local spawn, endpoint handoff and bounded stop/reap.
c3.4 exclusively decodes and binds the first stdout startup identity before any
invocation or credential byte; Darwin/Linux tests execute repository helpers
only, not an independent caller, and release identities remain assertions. c3.5
validates the invocation against committed locations/startup requirements, then
concurrently delivers bounded stdin and inherited-pipe payloads with EOF. c3.6
starts one monotonic run budget before the first supervisor preflight read,
preserves it across reconstruction, clips every case and operation deadline,
drains bounded stderr concurrently, and accepts actual completion only after
ordered output, terminal, stdout EOF and a clean reaped exit. c3.7 publishes
sanitized evidence only after that completion, assigns opaque non-PID process
identities, prevents external inputs from overriding observed adapter facts,
and finalizes one canonical two-phase transcript. Real Darwin/arm64 and
Linux/arm64 Lima helper tests pass. d1 now freezes a sanitized target identity,
the exact profile-derived topology, 11 artifact requirements, all 10 ordered
configuration identities, the numeric runtime/cleanup budget, and the 15+5
scenario inventory before runtime setup. d2 now obtains target, artifact, and
configuration identities only through a read-only observer, creates three
descriptor-backed persistent stores, locks the authoritative inspector scope,
and requires a complete zero-resource baseline before exposing prepared state.
d3 releases mutation capability only after rechecking that state and baseline,
passes the executor a closed identity-and-case directive with no request,
endpoint, credential, correlation, or signing fields, and consumes exactly 15
ordered progress results under clipped per-case and execution deadlines. It
enforces dependencies, per-interaction wire-attempt bounds, and provisional
transport/request counters while retaining cleanup after an unknown start.
d4 admits reconstruction only after a terminal initial result and passes a
closed eight-field directive containing only identities, ordered case IDs, and
symbolic restart/preservation policy. It requires two distinct invocation IDs
and eight unique opaque non-PID labels across the four old/new process pairs,
rechecks persistent-store identity without reading entries, and consumes the
five ordered reconstruction results under the original execution deadline.
d5 adds four source-specific, read-only observer ports, binds their identities,
41 interaction results and exact 66/17/7/1 fact projections to the locked
profile and d2-d4 state, independently corroborates process replacement,
transcript, shell-challenge and resource-scope facts, and derives scenario
`passed`/`failed`/`incomplete`/`not_executed` plus conservative admission
counters. Repository fixtures prove this component logic only; they are not
independent caller evidence. d6 consumes the persistent cleanup obligation in a
separate bounded context, binds the operator-owned teardown identity, closes
local state descriptors, and requires exactly three same-scope, one-second-
spaced zero-resource samples equal to the baseline before declaring cleanup
successful. d7 now assembles and validates the closed evidence root as a local
component. A separate external-caller repository has completed 7 of its 13
local candidate checkpoints and has begun e1.7a: 8 of 15 initial cases are
locally composed in one Caller process through terminal handoff,
while the other 7 remain `not_executed`. It pins the refreshed authority. External
ownership/provenance, independent runtime interoperability and observations,
the actual 15+5 run, and a qualification result remain open. The main P2.7
plan therefore remains 21/24, with e1 in progress and e2/e3 pending.

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
authority, not a report or qualification result. P2.7b locks the closed report
schema at
`sha256:cd51ccf0aea0bc31b11ff4f288751fc7df0f0dd081860efc305182ea61f842e4`
and the separate validator semantics at
`sha256:c724eaa9f3b52e1a5ba4aa5aaeb5e8b61a744818b2f56fd8ff52dfa5e1e584df`,
and implements its bounded evidence-root validator. This locks the report,
payload-binding, and receipt evidence definition, not an external report or
qualification result.

P2.7c.1 locks the external adapter protocol schema at
`sha256:d12b477cd540e02c6a7e2f8eb77b0405b717c15e98a0f144b2d63f705ff95969`
and operational semantics at
`sha256:10cd42017aee60b620dbbb7394a20c2a387983468a865a8d12a572f861d07662`.
The report startup identity and process-supervisor payload preserve the exact
protocol ID, version, schema digest, and semantics digest. The validator checks
those values against independent trust anchors and emits the selected protocol
authority in its receipt. The protocol semantics require the process supervisor
to include the same identity in its sanitized transcript projection. P2.7c.2b.1
locks that closed projection Schema at
`sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293`
and fixes the per-process transition table plus cross-phase startup equality.
The definition verifier compiles these authorities but does not enforce state,
produce a projection, or recompute a transcript digest.
P2.7c.2b.2 separately implements the runtime-independent startup prefix: one
strictly decoded sequence-zero startup must precede the one-shot
invocation-input authorization, and the first sanitized failure is absorbing.
It does not launch or supervise a process or accept later protocol output.
P2.7c.2b.3 binds the subsequently recorded invocation to that startup Codec and
stdout stream, then admits only an unskipped sequence-one
`invocation_accepted` with matching invocation ID and phase. Package-private
raw-document integrity plus revalidation prevents mutable decoded projections
from changing the binding. P2.7c.2b.4 uses the exact order returned by the
verified profile authority and enforces the normal scenario branches:
`scenario_started` must immediately precede a same-case `completed` result,
while `not_executed` must arrive without a start. Each case advances once and
the final result reaches only `awaiting-terminal`. P2.7c.2b.5 enforces exactly
one normal/error terminal, completion/disposition consistency, no
post-terminal byte, stdout EOF, and then a supplied clean-process-exit event.
Early EOF, early or non-clean exit, and every undefined transition fail closed;
`complete` and the first failure are absorbing. c3.4 binds an actual local
child's first stdout record to this startup transition before any input, keeps
the decoder private, and reclaims the process on startup failure or cancellation.
The emitted release identities remain process assertions, not independent
artifact provenance. c3.5 then binds the validated invocation to the frozen
locations and exact startup requirements, enforces the credential/fd limits,
concurrently EOF-delivers stdin and fd 3-10, wipes private copies, and advances
state only after complete writes. Payload content provenance, bounded output
provenance remains a later harness/independent-evidence obligation. c3.6 starts
bounded stderr drainage with the process, consumes ordered post-invocation
stdout, and supplies the state machine's exit event only after terminal, stdout
EOF and an actual bounded reap. Its deadline authority is process-supervisor monotonic elapsed time: the run
execution budget starts once before first preflight and survives reconstruction,
case budgets are clipped by remaining execution and parent time without reset,
and timeout termination uses a separate five-second close/kill/reap context.
Events observed at or after an effective deadline lose to deadline expiry. The
definition verifier checks these anchors and budget examples, while c3.6 now
implements them locally; neither constitutes independent caller evidence.
P2.7c.2a implements the runtime-independent strict codec against that locked
authority. It fixes cross-language byte accounting and failure precedence,
requires strict UTF-8 JSON and the closed Schema, rejects wrong-direction
messages, and compares startup protocol digests with repository trust anchors.
It does not enforce message order, recompute the sanitized transcript, launch
an adapter, or establish execution evidence.
The report schema constrains digest shape rather than embedding the semantics
digest, avoiding a content-address cycle. This is a process-protocol definition
only. It does not execute an adapter, prove an independently implemented caller,
or change Provider wire behavior.

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

### External adapter process protocol

One qualification run has two one-shot adapter process invocations, first
`initial` and then `reconstruction`. Each fresh process must emit a combined
caller/adapter startup frame before the harness writes an invocation or any
credential byte. That frame exposes the embedded caller release, adapter
release, Contract revision/tree, profile ID/version/digest, and adapter protocol
schema/semantics digests. It is still a caller-owner assertion: the process
supervisor separately binds actual executable, process, and configuration
identities, and external ownership remains a trusted/provenance input.

The invocation has exactly seven harness-supplied fields: `invocation_id`,
`phase`, `profile_path`, `provider_origin`, `gateway_probe_endpoint`,
`credential_channel_descriptors`, and `caller_state_root`. Protocol envelope
fields are fixed metadata, not an extension mechanism. Secret bytes use only
dedicated inherited channels in the first Darwin/Linux transport profile and
never enter argv, environment, JSON messages, stdout, stderr, reports, or
evidence. The first transport profile fails closed on unsupported platforms;
only its JSON data model is language-neutral.

Reconstruction uses a distinct invocation ID and fresh Provider, caller,
adapter, and Gateway processes. The harness cannot supply a sandbox, operation,
attempt, idempotency, fencing, runtime-session, or handoff binding through any
invocation field, alias, nested payload, argv, environment, working directory,
credential channel, endpoint query, or state-root seed. The caller state root is
created empty before initial execution and remains unread and unmodified by the
harness through reconstruction.

Invocation location values use two closed lexical profiles. `profile_path` and
`caller_state_root` are non-root, absolute, lexically clean POSIX paths made
only from portable ASCII filename characters. `provider_origin` is a canonical
HTTPS origin without a path; `gateway_probe_endpoint` is canonical HTTPS or WSS
with a required clean static path. Both reject userinfo, query, fragment,
percent encoding, backslashes, non-printable or non-ASCII bytes, noncanonical
hosts and ports, DNS names ending in a WHATWG IPv4 number, IPv4-mapped IPv6,
and explicit default port `443`. IPv4 uses four shortest decimal octets and
IPv6 uses non-mapped RFC 5952 form. The four values come only from static operator and supervisor
preflight configuration. Their canonical `adapter_configuration` digest is
finalized before credential or forbidden-correlation material is acquired or
generated, before adapter process start, and before Provider or Gateway network
I/O; the values remain byte-identical across phase invocations. The process supervisor must
prove that derivation/order constraint and additionally
prove the locked regular profile file, private initially empty state directory,
no-symlink identity, and forbidden location overlap; the definition verifier
does not make those runtime claims. The supervisor proves only the values and
order after they enter its custody; operator-upstream non-derivation remains a
trusted input.

Every `invocation_accepted`, `scenario_started`, `scenario_result`, and
`invocation_finished` record binds its `invocation_id` byte-for-byte and its
phase exactly to the single validated inbound invocation for that process.
Scenario records additionally use a case-ID phase prefix equal to that
invocation phase. A mismatch is invalid adapter output and follows the locked
termination sequence. A `protocol_error` uses one of two disjoint branches
selected by `error_code`: `invalid_invocation` occurs before binding with
sequence 1 and both identity fields null; every other code occurs only after
`invocation_accepted`, uses the next contiguous sequence, and binds both fields
to the accepted invocation. The error is terminal and mutually exclusive with
`invocation_finished`. It remains a caller-owner assertion and assigns no
report status or run outcome. `output_failed` is valid only when no byte of the
failed normal record was written and a complete error record can still be
written; a partial record or write-channel failure is invalid/truncated output
observed by the supervisor, not a recoverable protocol error.

Adapter progress is a bounded caller-owner assertion, not independent evidence.
It reports only `completed` or `not_executed` dispositions and never assigns the
report's scenario status or run outcome. Final report status has four values:
`passed`, `failed`, `incomplete`, and `not_executed`. It is derived from adapter
claims and independent observations; missing required evidence without an
observed mismatch is `incomplete`, and only an observed mismatch establishes
`failed`. This explicitly separates adapter progress dispositions and the
profile's execution classifications from P2.7b's evidence-derived report state.

The protocol locks strict framing, sequence/order, message/byte/channel limits,
sanitized transcript projection, deadlines, and a fail-closed sequence of
closing supervisor-owned I/O, killing the process group, and bounded wait/reap.
The process implementation remains a later P2.7c slice. Even after it exists,
the boundary proves only that the harness did not construct/sign requests or
re-inject correlation values. It cannot alone prove source independence,
exclude copied code or a remote signer, or attribute every request to one PID.

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

The d1 harness freezes only sanitized digests and profile-derived inventory
before runtime setup. It derives the architecture digest from the closed
format-version/architecture object, the topology digest from the exact report
projection including the target identity, and the scenario-inventory digest
from the locked profile identity plus ordered phase/dependency/case IDs. Its
outer RFC 8785/SHA-256 commitment also binds the profile schema, eleven artifact
requirements, all ten configuration identities, every numeric runtime budget,
and the complete cleanup requirement snapshot. This static commitment is an
expectation for d2 observation, not proof that a target, process, artifact,
configuration, credential, or resource baseline exists.

The d2 preflight obtains the target, artifact, and configuration identities
through a read-only observer rather than through configuration input. It
requires the exact frozen bindings and complete immutable source/release
identity shapes, but repository fixtures remain component assertions rather
than independent provenance. Before returning prepared state it exclusively
creates and descriptor-rechecks three private persistent stores, recomputes the
closed resource-inspector query scope, and accepts only a complete, normalized,
zero-resource baseline. The sanitized d2 commitment contains store role names
but no raw path. A failure after state creation retains the root for separately
authorized operator teardown; close only releases descriptors. No scenario or
mutation API is part of d2.

The d3 initial orchestrator rechecks that prepared state before granting an
execution port access to mutation capability. Its entire outbound directive is
the runtime commitment, profile ID/version/digest, phase ID, and the exact 15
case IDs; request routes, methods, payloads, endpoints, credentials,
authorization, correlation, key, and signing fields are structurally absent.
The port owns those private inputs and returns one reduced progress record per
case plus a separate terminal/EOF/clean-exit gate. The harness enforces profile
order, dependencies, clipped case and execution deadlines, exact completed
interaction inventories, not-executed reason rules, per-interaction wire limits,
and counters derivable without outcome evidence. Those counters remain
provisional caller/adapter progress until d5 observer correlation. d3 does not
derive admitted resource counts or final scenario statuses. Mutation capability
release conservatively persists a cleanup obligation through start errors,
cancellation, protocol failure, and unknown outcomes.

The d4 reconstruction orchestrator is one-shot and is unavailable until d3 has
stored a terminal initial result. Its closed outbound directive contains the
same runtime/profile/phase/case identity fields plus only the four symbolic
restart components and three symbolic preserved stores. No state path or prior
correlation value crosses that boundary. The executor must return distinct
initial/reconstruction invocation IDs and exactly four ordered old/new opaque
non-PID process pairs before the harness consumes any of the five reconstruction
results. All eight labels must be unique. These remain provisional d4
assertions; d5 now requires a separately sourced process-supervisor snapshot to
corroborate them. The harness metadata-rechecks the
same store descriptors before and after restart and after terminal completion,
but never reads or seeds caller state. It evaluates the first reconstruction
dependency against the retained final initial disposition, preserves the d2
execution deadline, and fail-closed checks phase and cumulative attempt counts.
Neither this control flow nor the closed directive proves actual process
replacement, caller recovery, same-shell continuity, or final scenario status.

The d5 observation component has four source-specific read-only ports. Their
seven-field directive contains only the prepared-runtime/profile identities,
two opaque invocation labels, and resource-scope digest. It carries no concrete
request, endpoint, credential, signing input, host path, or caller correlation.
Provider/Gateway observations are bound to completed d3/d4 progress and exact
profile interaction order. Fact lists must match the exact profile-ordered
66 Provider, 17 Gateway, 7 process-supervisor, and 1 resource-inspector
bindings; a caller assertion is not an accepted source.

d5 derives scenario status only after matching outcomes and all bound facts:
all observed is `passed`, an outcome mismatch or contradiction is `failed`,
missing evidence without contradiction is `incomplete`, and an unexecuted case
has no interaction evidence and only missing facts. Because adapter `completed`
is progress rather than a pass, d3 may provisionally accept a dependent
`prerequisite_not_satisfied` stop after an executed predecessor. d5 accepts it
only when that predecessor is independently derived as `failed` or
`incomplete`; a caller-only stop after a derived pass fails closed. It also
cross-binds d2 artifact/configuration identities, d4 process replacement, the
sanitized adapter transcript, digest-only shell continuity, sandbox limits, and
the locked resource query scope. Admission counts use the P2.7b conservative
rule, including per-wire-attempt potential admissions when mutating evidence is
uncertain. Repository-local fakes test this logic but do not themselves prove
external observer process/control-domain independence. Cleanup and evidence
assembly are d6 and d7 responsibilities.

The d6 component consumes the persistent conservative cleanup obligation after
execution is idle, including after an unknown start, a canceled execution
context, or descriptor-only close. It closes local persistent-state descriptors
and invokes operator-owned teardown with only runtime/profile identities,
authority, and query-scope digest. The cleanup context is detached from
execution cancellation but cannot exceed either 300 seconds from cleanup start
or the original 2,100-second total deadline. A bound teardown receipt records
the observed teardown artifact/configuration identities and 1..32 internal
attempts.

Completed teardown becomes `succeeded` only after exactly three valid,
same-scope inspector samples at least one second apart are stable, equal to the
pre-run baseline, and contain zero run-owned resources. Residual or changing
inventory is `incomplete`, explicit teardown non-completion is `failed`, and
unavailable or invalid binding is `unknown` or `incomplete`. No mutation-
capability release yields `not_required` without a teardown call. The result
keeps its conservative obligation distinct from independently observed writes
and is not itself a report, evidence payload, final outcome, actual teardown,
or proof of observer independence.

The d7 component consumes the complete sanitized d1-d6 snapshot once and
accepts only a schema-valid transcript projection, 20 ordered supervisor
timings, 29 ordered caller-owner assertions, and five ordered digest-only
trusted-input statements. It does not accept arbitrary report JSON. The report,
all five payloads, and receipt bind the same d2 runtime commitment. A
descriptor-pinned empty evidence root receives exact exclusively created
`0600` files; the assembly writer is closed before the validator becomes the
only in-process receipt writer. Pre-handoff assembly failures remove only their
own publications, validator rejection preserves residue for diagnosis, and an
existing receipt is never overwritten. The report counters, cleanup
satisfaction, identity completeness, reason codes, and final four-state outcome
are derived rather than caller-selected. Repository synthetic tests establish
this local assembly boundary only; e1 still owns independent caller/adapter
identity and provenance, e2 the actual external run and teardown, and e3 the
archived receipt and bounded conclusion.

The report schema keeps run, phase, and scenario timestamps nullable so an
honest unavailable run can avoid invented timing evidence. The semantic rule is
not partially nullable: the six run timestamps are all null or all present, and
a present process-supervisor payload requires complete run, phase, and scenario
timings that it cross-binds. An absent process-supervisor payload suppresses all
such timings, requires every scenario to be `not_executed`, and also suppresses
the shell-continuity challenge.

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
A scenario cannot be `passed` unless every interaction declared by that
scenario and every required observation for those interactions is present,
observed, payload-digest-bound, and in the locked order.
An executed scenario with missing required evidence and no observed mismatch is
`incomplete`; an observed mismatch remains `failed`. The validator rejects use
of `incomplete` for either a complete pass or a proved behavioral mismatch.

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

Resource accounting fails closed when an interaction on a resource-bearing
mutation route does not match its locked outcomes or required observation
evidence. In that case every recorded wire attempt is counted as a distinct
potential unexpected admission. This may deliberately over-count sandboxes,
exec operations, terminal sessions, or artifact operations and reject the run
at a resource limit rather than assume that an uncertain attempt created
nothing.

The report's `sandbox_resources` object is a sanitized projection of exactly
four locked `create-sandbox` limits: CPU millicores, memory bytes, ephemeral
storage bytes, and PIDs. It is present exactly when the unique
`create-sandbox` interaction is present, regardless of that interaction's
reported outcome, and the Provider-observer payload must carry the identical
projection. This does not bind the complete request bytes or a digest of the
complete request; the external caller remains responsible for constructing the
Contract request.

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
type and stable observer ID, and are canonicalized with the same profile. The
`ownership_selector_digest` is bound into that scope digest and into the
resource-inspector payload's cleanup projection, but the validator has no
second independent fact source for the selector. The receipt therefore proves
binding consistency, not the selector content's independent truth or
completeness.
Before mutation, the baseline has zero run-owned resources. Its single sample
may equal `execution_started_at` or occur later, but it is strictly before the
start of the first scenario that contains a mutation-write interaction. After
teardown, the query scope is unchanged, exactly three samples at least one
second apart are within the cleanup window, stable, equal to the baseline, and
have a run-owned count of zero.
Changed-scope, vacuous, unavailable, failed, or unknown inspection makes the
qualification incomplete. Cleanup runs under a separate bounded context after
caller execution. Cleanup failure or an unknown cleanup outcome makes the
qualification incomplete whether behavioral scenarios failed or passed.
If mutation evidence exists but the resource-inspector payload is unavailable,
the report retains the cleanup obligation but records no inspector-owned scope,
baseline, samples, completion, or teardown-attempt evidence and uses cleanup
outcome `unknown` or `incomplete`. Acceptance records this uncertainty; it does
not claim that teardown was attempted or completed.

Prerequisite failures and unavailable environments are `not_executed`, not
Provider or caller failures. Cancellation stops further scenarios but still
enters cleanup. An executed mismatch is `failed`. A profile passes only when all
required scenarios executed and passed, cleanup completed, identity evidence is
complete, and the sanitized evidence set validates.

`passed` and behavioral `failed` reports require complete payload-backed identity.
Incomplete and not-executed reports may preserve a strict subset of the five
payloads and use `null` only for identity/evidence fields that the closed schema
marks nullable. Every present payload and non-null value remains subject to its
schema and semantic cross-file bindings; a null is an unknown fact, not positive
evidence.

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
itself, and the report does not claim the digest of that future envelope. The
evidence validator checks shape, exact scenario order, identities,
independent observations, cleanup, sanitization, and overclaim fields. It does
not attest the honesty of an
external owner, source host, build service, operating system, or network. Those
remain explicit trust inputs.

The five allowed payloads are the Provider observer, Gateway observer, process
supervisor, resource inspector, and trusted-input records. The evidence root is
pinned by one directory descriptor. Traversal and reopening use
descriptor-relative `openat`/`fstatat` with no-follow checks; payloads must be
regular, singly linked files; and receipt publication uses no-follow exclusive
creation with mode `0600`, synchronization, read-back, and identity checks.
Darwin/Linux provide this implementation and other platforms fail closed.
Context cancellation is checked at validator stage boundaries and immediately
before receipt commit, but it cannot interrupt a synchronous filesystem syscall
blocked in the kernel. The operator must place evidence on a healthy local
filesystem; the validator deadline is not a bound on a stuck FUSE or
network-filesystem operation.

These controls require an operator-enforced writer handoff. Before `Verify`
starts, all evidence producers must stop writing and the qualification operator
must give the validator exclusive write access to the root until it returns;
no other process, including one running under the same UID, may write, rename,
link, or remove its entries in that interval. Directory-FD pinning and the
TOCTOU, identity, digest, and inventory rechecks detect specified changes and
fail closed, but do not prove integrity against a process that retains
continuous write access. After successful return, an external packager may
archive the complete root and bind that archive digest in the separate artifact
envelope.

Receipt publication preserves that handoff boundary. After the schema,
semantic, sanitization, and capacity checks, the validator writes the candidate
under an exclusive random pending name. It then rechecks the final inventory,
raw report, and pending receipt, checks cancellation immediately before commit,
and only then commits the inode to `receipt.json` without overwrite. A failed
final check, pre-commit cancellation, or commit error triggers identity-aware
cleanup, and cleanup failures are returned. An entry replaced or created with a
different inode by a writer that violated the handoff is not overwritten or
deleted merely because it occupies the pending or destination name; such
residue is a failed-run operator condition and must not be packaged as accepted
evidence.

The validator semantics locks the report and payload marker set and requires
checks over raw bytes, normalized JSON, and decoded JSON strings. This remains a
supplemental rejection control for known obvious strings, not proof that
arbitrary unknown, encoded, encrypted, split, compressed, or disguised secrets
were detected. The validator-semantics digest binds the five payload mappings
and cross-file rules. It does not attest the
validator binary, repository revision, build, compiler, host filesystem, or
toolchain used for a particular run; those execution facts remain trusted
inputs unless separately attested.

The receipt uses RFC 8785 canonical JSON plus one LF byte, a fixed-width
lowercase hexadecimal receipt ID, and a UTC timestamp with exactly nine
fractional digits. The report can therefore reserve the exact future receipt
size, and the validator rechecks final count, byte length, raw report bytes, and
payload inventory after exclusive receipt creation. Caller ownership, source
hosting, build system, operating system, and network path are five ordered,
payload-bound trusted inputs rather than independent observations.

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
