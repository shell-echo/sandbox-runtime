# External Caller Coding/Shell Qualification Profile v1

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

Profile ID: `sandbox-runtime-external-caller-coding-shell-v1`

Profile version: `1.0.0`

Profile digest:
`sha256:ec113d31612dbb7cc0e9461925170f74f33722bb2efb237dbc68aa89f2d60231`

Status: P2.7a machine-readable definition authority, P2.7b closed report
schema/evidence validator, and P2.7c.1 content-addressed protocol definition are
locked; P2.7c.2a implements the runtime-independent strict codec, P2.7c.2b.1
locks the state/transcript definitions, and P2.7c.2b.2-.5 implement startup,
normal invocation acceptance, ordered scenario state, terminal, EOF, and a
supplied clean exit. Its authority is bound
through startup, process-supervisor,
validator, and receipt evidence. Its Schema compilers use one ECMA-262 regexp
engine and reject ASCII controls without POSIX-only classes. Invocation
path/endpoint profiles, cross-phase byte identity, output/error binding,
monotonic deadline anchors, the exact transition table, and the closed
transcript preimage shape are locked. Scenario/terminal state, two-phase binding
and transcript recomputation are implemented through c2b.7. c3.3 runs local
process probes, and c3.4 exclusively validates their first stdout startup frame
before any input. c3.5 validates the exact frozen locations/startup channel
requirements and performs bounded concurrent EOF delivery over stdin and fd
3-10. Release identities and payload policy are still external obligations; no
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
`sha256:c98f77473ff110fc54ef6a08f66bbe1b0a36c41ee71bcce8d68b9430d22a1798`.
The repository profile verifier validates the closed shape, semantic
cross-field rules, exact 15+5 case, 41-interaction, and 91-observation inventory,
schema digest, and content digest. This document explains the locked profile but
does not override it. A semantic change requires a new profile digest and
coordinated reference update.

The closed adapter process
[`schema`](../../qualification/external-caller-coding-shell-v1/adapter-protocol.schema.json)
has raw digest
`sha256:fdee270ca27003693b2ce504da769c9779825312e1dd4e06b5caf8578f5ee03c`.
Its locked
[`semantics`](../../qualification/external-caller-coding-shell-v1/adapter-protocol.semantics.json)
has raw digest
`sha256:997c49cd1a5b2c050d48333a973dd78b611221f869bf709cf6d1a8d771795a99`.
These files define only the harness-to-adapter process protocol. They neither
extend the Provider Contract nor show that any process executed it.
The report validator compares the protocol ID, version, schema digest, and
semantics digest against independent repository trust anchors. The
process-supervisor payload must match the report startup identity, and the
receipt explicitly records the validator-selected protocol authority. The
protocol semantics require the process supervisor to include the same
identity in its sanitized transcript projection. The closed
[`adapter-transcript.schema.json`](../../qualification/external-caller-coding-shell-v1/adapter-transcript.schema.json)
authority has raw digest
`sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293`.
It admits only exact two-phase protocol/process identities, field names,
credential roles, message-type/count summaries, bounded byte counts, and
terminal observations; raw values, credentials, endpoints, requests,
responses, correlations, and stderr are closed out. The current definition
verifier compiles this Schema and checks a locked example, but does not produce
or recompute a transcript digest.

The P2.7c.2a codec reads exactly one invocation document through EOF and counts
all input bytes, including legal JSON whitespace. Adapter output uses one LF
delimiter per record; the 64 KiB record ceiling excludes that delimiter, while
the 2 MiB stdout ceiling includes delimiters and all invalid or truncated
bytes. The codec accepts at most 33 output records, rejects CRLF and missing-LF
framing by forbidding raw carriage-return bytes, and validates strict UTF-8 JSON
with unique member names, valid Unicode surrogate escapes, one value, the closed
Schema, and the allowed message
direction. Startup digest values must equal the locked protocol authority.
Failures expose only stable sanitized kinds and the first failure is terminal.
The codec does not validate phase/case order, sequence or terminal state, and
does not launch or supervise a process. P2.7c.2b.1 separately locks the exact
transition table: a successful phase requires terminal output, stdout EOF, and
then a clean bounded-wait exit; undefined transitions, decode failure, early
EOF, post-terminal bytes, and non-clean exit fail. It also requires the two
fresh phase processes to emit canonically identical startup identities before
the report may project one startup identity. These are machine-verified
definitions. P2.7c.2b.2 now consumes one strictly decoded sequence-zero startup,
fails closed on empty/duplicate/out-of-order startup or decoder error, retains
the first sanitized failure, and grants one invocation-input authorization.
It does not accept subsequent output or perform process I/O.
P2.7c.2b.3 then requires the authorized invocation and the next output to share
the startup Codec and stdout stream, requires record count two and sequence one,
and binds `invocation_id` and `phase`. It defensively hashes and revalidates raw
decoded documents so mutable projections cannot change the state binding, then
retains only a sanitized invocation reference. This
implements only the normal `invocation_accepted` branch; pre-binding
`protocol_error` is added by P2.7c.2b.5.
P2.7c.2b.4 copies the exact phase order returned by the verified profile and
requires every scenario output to use the next case ID, same Codec/stdout
decoder, contiguous sequence, and cumulative wire count. A `completed` result
is legal only immediately after `scenario_started` for that case;
`not_executed` is legal only without a start. The final case reaches
`awaiting-terminal`. P2.7c.2b.5 then accepts exactly one completion-consistent
`invocation_finished` or branch-correct `protocol_error`, fails on any
post-terminal byte, requires stdout EOF, and accepts a clean-exit event only
after EOF. It does not launch or wait on a process, construct a
transcript, or provide execution evidence.

Deadline enforcement uses only process-supervisor monotonic elapsed time, never
reported wall-clock timestamps. The 1,800-second execution budget begins before
the first preflight and is shared across initial and reconstruction processes.
At each validated case boundary, the 120-second case budget is clipped by the
remaining execution and parent-context deadlines; scenario-start, retry, and
transient events cannot reset it. Failure termination receives a separate
five-second budget covering close-I/O, process-group kill, and bounded reap.
The definition lock alone is not runtime evidence; c3.6 enforces these anchors
for the local supervisor and observes ordered terminal, stdout EOF and the owned
process's real clean exit. c3.7 now publishes evidence only after that complete
path, binds non-overridable adapter facts into one canonical two-phase
projection, and runs the real helper matrix on Darwin/arm64 and Linux/arm64.
It still does not establish caller independence or scenario outcomes.

The invocation uses absolute, lexically clean POSIX paths made from portable
ASCII filename characters. It rejects root, empty or dot segments, repeated or
trailing separators, percent encoding, backslashes, whitespace, controls, and
Unicode normalization ambiguity. `provider_origin` is a canonical HTTPS origin
with no path, userinfo, query, fragment, percent encoding, or explicit default
port. `gateway_probe_endpoint` is canonical HTTPS or WSS with a required clean
static path and the same authority exclusions. Hosts are lowercase LDH DNS
names that do not end in a WHATWG IPv4 number, four-shortest-decimal-octet IPv4,
or non-IPv4-mapped RFC 5952 IPv6 literals; ports contain decimal digits only,
use shortest form in `1..65535`, and omit `443`.
The protocol requires these four values to come only from static operator and
supervisor preflight configuration and commits them under the canonical
`adapter_configuration` digest before any credential or forbidden-correlation
material is acquired or generated, any adapter process starts, or any Provider
or Gateway network I/O occurs. They remain byte-identical across phases. The
definition verifier locks this order but does not prove that a run followed it.
Runtime derivation/order evidence, regular-file and no-symlink identity,
private-empty-directory state, and location-overlap proof remain future
process-supervisor responsibilities. The supervisor can observe only the values
and order after they enter its custody; whether the operator derived its
upstream static configuration from other material remains a trusted input.
Every non-error output record binds its `invocation_id` byte-for-byte and its
phase exactly to the single validated inbound invocation for that process.
Scenario records also require a case-ID prefix equal to that phase. A mismatch
is invalid output and triggers the locked termination path. A `protocol_error`
uses one of two disjoint branches selected by `error_code`.
`invalid_invocation` is the only pre-binding code: it is the first and only
post-input output, has sequence 1, and sets both `invocation_id` and `phase` to
`null` rather than echoing an unaccepted identity. Every other error code is
post-binding: it follows `invocation_accepted`, uses the next contiguous
sequence, and binds both identity fields to the accepted invocation. Both
branches are terminal, mutually exclusive with `invocation_finished`, and
assign neither report status nor run outcome. `output_failed` is valid only
before any byte of the failed normal record is written and while a complete
error record remains writable. A partial record or output-channel failure is
invalid/truncated output observed by the supervisor, not a valid error record.
For an honest `not_executed` report, the receipt identifies only the validator's
selected authority; it does not claim that an adapter emitted startup identity.

The closed qualification report authority is
[`report.schema.json`](../../qualification/external-caller-coding-shell-v1/report.schema.json),
with raw-byte digest
`sha256:5d97e10c8b5b2f365e275e78868d5a35d78bbdffdec05ea2f18b5c947cd429f6`.
The separate closed
[`validator.semantics.json`](../../qualification/external-caller-coding-shell-v1/validator.semantics.json)
has raw-byte digest
`sha256:c724eaa9f3b52e1a5ba4aa5aaeb5e8b61a744818b2f56fd8ff52dfa5e1e584df`.
The standalone validator reads the complete evidence root, validates
`report.json` against that schema and the locked profile semantics, checks the
actual bounded payload inventory, stages a receipt candidate, and commits it as
`receipt.json` only after the final inventory and byte checks pass. The semantics
resource locks the five allowed payload paths,
their schema fragments and cross-file binding rules, the ordered trusted inputs,
and receipt authority identities. Its digest does not attest the validator
binary, repository revision, build, or host toolchain that performed a run;
those execution inputs remain outside the receipt's proof and must be trusted or
attested separately. The schema and semantics lock an evidence definition;
they are not an external execution result.

The operator must finish producer writes before validation and reserve the
evidence root for the validator's exclusive writes from `Verify` entry through
return. This excludes the producer and every other same-UID process. The fixed
directory descriptor and replacement, identity, digest, and inventory checks
fail closed on detected races; they are not an integrity guarantee against a
continuously writable attacker. After a successful return, the operator may
package the root, including `receipt.json`, and record the archive digest in the
external artifact envelope.
If a process violates that handoff by creating or replacing an entry, the
validator fails closed but deliberately does not overwrite or delete a
different inode it does not own. Such a replacement or destination may
therefore remain after the failed run; it is operator-visible handoff-violation
residue, not a receipt that may be packaged or accepted.

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

The d1 static harness freeze is a pre-runtime commitment, not observed runtime
evidence. Its input contains only the architecture label, canonical target and
run-namespace digests, and the seven Provider/caller/adapter/Gateway/observer/
inspector/teardown configuration digests. It rejects missing or non-lowercase
SHA-256 identities and path-like `.`/`..`/empty architecture segments. It never
accepts the raw target description, run namespace, path, endpoint, credential,
or caller correlation. The `architecture` configuration preimage is the closed
`{format_version, architecture}` object. The `topology` preimage is the exact
report topology derived from the verified profile plus its target identity. The
`scenario_inventory` preimage is the closed format/profile identity plus each
phase ID, dependency, and ordered case-ID array; the embedded profile digest
binds the complete interaction and observation definitions. All three and the
seven supplied component identities use RFC 8785 full-document SHA-256. The
outer internal commitment additionally binds the profile schema digest, all
eleven artifact requirements, the exact ordered ten-identity inventory, every
numeric runtime/resource/evidence limit, and the complete cleanup requirement
snapshot. The seven supplied component digests become evidence only after d2
observes and matches their actual configurations.

The d2 implementation accepts the target/artifact/configuration snapshot only
from a read-only observer port and verifies it against d1. It then creates the
three run-persistent state roles under one new private root using Darwin/Linux
no-follow directory descriptors. Production code never enumerates or opens
entries in those stores. The closed inspector scope binds the target, namespace,
ownership-selector digest, exact five resource kinds, and inspector artifact
and configuration. The harness recomputes the canonical scope and inventory
digests and accepts only a complete zero-resource baseline. This component
boundary does not make repository-owned fixtures independent evidence; actual
release provenance and observer payloads remain later gates.

The d3 initial orchestrator supplies an execution port only the sanitized
runtime commitment, profile identity, phase ID, and ordered 15 case IDs. The
port, not the harness, owns endpoints, credentials, request construction,
correlations, and signing. The harness consumes one reduced progress result per
case under the earlier execution/caller deadline and the 120-second case limit,
checks dependencies, exact interaction order and wire-attempt maxima, and
requires a terminal/EOF/clean-exit gate. It retains cleanup as soon as mutation
capability is released, including across unknown start or cancellation. Its
derived transport/request counters are provisional; d5 must correlate actual
outcomes and independent observations before resource admissions or any final
scenario status exists.

The d4 reconstruction orchestrator is admitted only after the stored initial
session reaches its terminal/EOF/clean-exit gate. It supplies the executor the
same identity/case boundary plus the exact symbolic restart-component and
preserved-store lists—never state paths or prior sandbox, operation, attempt,
idempotency, fencing, runtime-session, or handoff values. Before the first of the
five reconstruction results, it requires distinct initial/reconstruction
invocation IDs and ordered old/new opaque non-PID labels for Provider, external
caller, adapter, and caller Gateway, with all eight labels unique. These labels
remain provisional in d4; d5 now requires a separately sourced process snapshot
to corroborate them. The harness only rechecks persistent-store metadata; it does
not open, enumerate, read, seed, or modify caller-owned entries. Cross-phase
dependency propagation, the original execution deadline, per-case limits, exact
eight-interaction accounting, cumulative budgets, cancellation, and one-shot
semantics fail closed. The result contains no qualification status.

The d5 observation layer accepts no caller assertion as observer evidence. Its
four source-specific read-only ports own the `provider_observer`,
`gateway_observer`, `process_supervisor`, and `resource_inspector` projections.
A seven-field sanitized directive binds every port to the prepared runtime,
profile, two invocation labels, and resource query scope without supplying
routes, credentials, endpoints, request payloads, signing input, host paths, or
caller correlation values. Returned observations must match the exact 41
executed interaction identities and the profile-ordered 66/17/7/1 fact split.

Only d5 derives per-scenario four-state results. `completed` adapter progress is
`passed` only when the independently observed final/transient outcomes and all
required facts match. A closed-outcome mismatch or contradicted fact is
`failed`; missing evidence without a contradiction is `incomplete`; and
`not_executed` must contain no interaction evidence and only missing facts.
Because adapter `completed` is progress rather than a pass, d3 may
provisionally accept a dependent `prerequisite_not_satisfied` stop after an
executed predecessor. d5 accepts it only when that predecessor is independently
derived as `failed` or `incomplete`; a caller-only stop after a derived pass
fails closed. Other dependency violations also fail closed. Resource admissions
follow the report validator's conservative accounting so uncertain mutating
attempts cannot be undercounted. Process replacement, transcript, digest-only
shell challenge, artifact/configuration identities, sandbox limits, and current
resource inventory are cross-bound to d2-d4 state. This code path performs no
cleanup or evidence-root write. Repository fixtures validate the algorithm but
are not independent external-caller evidence or a qualification result.

The d6 cleanup layer consumes the persistent conservative obligation after
execution becomes idle, including after an unknown start or cancellation. It
closes local persistent-state descriptors and invokes the operator-owned
teardown through a six-field digest-only directive under a context detached
from execution cancellation and bounded by the 300-second cleanup limit plus
the original 2,100-second total deadline. The receipt must bind the observed
teardown artifact and configuration, runtime commitment, authority, unchanged
query scope, and 1..32 internal attempts.

After a completed teardown, d6 accepts only three valid inspector samples under
that same query scope, spaced at least one second apart. `succeeded` requires a
stable inventory equal to the pre-run zero-resource baseline. Residual or
changing inventories are `incomplete`, explicit teardown non-completion is
`failed`, unavailable or unbound evidence is `unknown` or `incomplete`, and a
run for which mutation capability was never released is `not_required` without
calling teardown. The conservative obligation and independently observed write
flag remain distinct. This is sanitized local component state for d7, not an
evidence payload, final run outcome, actual operator teardown, or independent
inspector proof.

The d7 local component accepts that complete state exactly once together with
only four closed supplemental projections: the schema-valid canonical adapter
transcript, 20 ordered process-supervisor scenario intervals, 29 ordered
caller-owner assertion results, and five ordered digest-only trusted-input
statements. It derives the report structure, counters, cleanup satisfaction,
identity completeness, reason codes, and final four-state result. It requires a
pre-existing empty evidence directory, exclusively creates the exact five
named payloads and `report.json` at mode `0600` through a pinned directory
descriptor, closes the assembly writer, and invokes the existing validator as
the only in-process writer allowed to publish `receipt.json`. The same runtime
commitment is required in the report, all payloads, and receipt. Repository
fixtures verify this seven-file pipeline but do not establish the provenance of
the caller, adapter, observations, trusted-input digests, or an external run.
Those remain e1-e3 gates.

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

The adapter protocol does not assign a qualification status. It emits only a
`completed` or `not_executed` progress disposition and caller-owned interaction
and assertion data. The harness combines those claims with independent
observations to derive the report's `passed`, `failed`, `incomplete`, or
`not_executed` status. Skips and not-applicable results are not accepted. A
failed prerequisite marks every dependent scenario `not_executed`. An executed
mismatch observed independently is `failed`; an executed scenario with missing
required evidence and no observed mismatch is `incomplete`. A scenario cannot
use `incomplete` to hide a complete pass or an observed failure.
The separate run outcome is `passed`, `failed`, `incomplete`, or
`not_executed`, with `incomplete` taking precedence when cleanup, identity, or
required evidence is missing or unknown.

`passed` and behavioral `failed` reports require complete payload-backed
identity. An `incomplete` or `not_executed` report may use `null` only in the
schema's explicitly nullable identity/evidence fields and may omit payloads that
could not be produced. This records unknown or unavailable facts without
inventing placeholder identities. Every payload that is present and every
non-null identity must still satisfy its closed schema and all applicable
cross-file bindings; null never means a fact was independently verified.

Timestamp nullability follows the same honesty rule but is all-or-nothing. The
six run timestamps are either all null or all present. If the
`process-supervisor.json` payload is present, run, phase, and scenario timings
must all be complete and must equal the supervisor payload's projections. If it
is absent, all timing evidence is null, every scenario is `not_executed`, and
the shell-continuity challenge is also null; a Gateway observation alone cannot
retain that execution challenge.

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

A scenario marked `passed` contains every interaction declared for that case and
every required observation in the locked order. Each required observation must
be `observed`, carry an evidence digest, and bind to the named observer payload;
missing, contradicted, or unbound evidence cannot be hidden behind a passing
scenario status.

Provider polling evidence distinguishes the terminal response from every
bounded intermediate response. A successful `200` operation or sandbox read
may be intermediate only when the observed document remains in a
Contract-defined nonterminal state; it is non-retryable at the HTTP layer even
though the caller must continue semantic polling. A `404` or `503` is accepted
only where the locked Contract authorizes it for that state; required
`Retry-After`, retryability, deadline rechecks, and retry count are observed
rather than collapsed into the eventual terminal `200`. Cancellation evidence
reconciles the accepted `cancel_exec`
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

For resource accounting, a resource-bearing mutation interaction whose final or
transient outcome or required observations do not match the locked profile is
treated conservatively. Every recorded wire attempt becomes a distinct
potential unexpected admission. The resulting sandbox, exec-operation,
terminal-session, or artifact-operation count may intentionally exceed the
real allocation count and fail the resource limit; uncertainty is never rounded
down to zero resources.

`sandbox_resources` records only the four sanitized locked limits for the
unique `create-sandbox` interaction: 500 millicores, 256 MiB memory, 256 MiB
ephemeral storage, and 64 PIDs. The field and identical Provider-observer
projection are required exactly when that interaction is recorded, including a
failed or unknown outcome. They do not bind the complete raw create request or
its digest.

Each case has at most 120 seconds from case dispatch until its terminal result,
further reduced by the remaining execution deadline. The 1,800-second execution
clock starts immediately before the first preflight read and ends after the last
scenario, including process reconstruction. The 2,100-second run clock has the
same start and ends after cleanup, reserving a separate cleanup context of at
most 300 seconds; case execution must stop early enough to preserve that cleanup
budget.
Post-run schema validation and receipt emission are not silently charged to a
different case clock and have their own validator deadline at validator stage
boundaries. The synchronous directory, read, synchronization, and publication
system calls are not interruptible through `context.Context`; the operator must
use a healthy local filesystem and must not treat the deadline as proof that a
stuck kernel, FUSE, or network-filesystem call will return. Once any mutation
may have been written, cleanup is required even if the response is lost, the
caller exits, the run is cancelled, or the result is `outcome_unknown`.

The inspector query scope is a closed sanitized object binding the disposable
target, run namespace, ownership selector, resource kinds, inspector artifact,
and configuration identity while excluding the harness control plane. Its RFC
8785 full-document SHA-256 digest is recorded before mutation.
The `ownership_selector_digest` is thereby bound into the scope digest and the
resource-inspector payload's cleanup projection, but the validator has no
second independent fact source for the selector itself. Acceptance proves those
bindings are internally consistent, not that the selector's underlying content
was independently observed or complete.

A normalized inventory is ordered lexicographically by resource type and stable
observer ID; entries expose no backend ID and the full document uses the same
canonical digest profile. The pre-run baseline contains zero run-owned resources and one
sample timestamp that may equal `execution_started_at` or occur later, but must
be strictly before the start of the first scenario containing a mutation-write
interaction. Cleanup
tears down the run namespace within the disposable target while the out-of-band
inspector remains available. Passing cleanup requires the post-teardown query
scope digest to match and exactly three inventory samples, each inside the
cleanup window and at least one second after the previous sample, to be stable,
equal to the baseline, and have a run-owned count of zero. A vacuous,
changed-scope, unavailable, failed, or unknown inspection makes the run
`incomplete`, even if a behavioral mismatch also occurred.
If mutation evidence exists but `resource-inspector.json` is unavailable, an
honest incomplete report keeps the cleanup obligation, records no inspector-
owned scope, baseline, samples, completion, or teardown-attempt evidence, and
uses cleanup outcome `unknown` or `incomplete`. Validator acceptance of that
report records missing cleanup evidence; it does not imply teardown occurred.

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

The only allowed payload files are `provider-observer.json`,
`gateway-observer.json`, `process-supervisor.json`,
`resource-inspector.json`, and `trusted-inputs.json`. They bind, respectively,
the Provider HTTP observer, caller-owned Gateway observer, process and startup
identity supervisor, authoritative cleanup/resource inspector, and the five
ordered trusted-input plus caller-assertion records. A complete identity
requires all five; incomplete and not-executed reports may contain a strict
subset, but no other payload path is accepted.

The payload contains at most 16 regular non-symlink, singly linked files, each
at most 2 MiB and together at most 8 MiB. The Darwin/Linux implementation opens
the evidence root once as a fixed directory descriptor, traverses and reopens
entries relative to that descriptor with `openat`/`fstatat` and no-follow flags,
and verifies directory-entry, inode, link-count, size, mode, and timestamp
stability. Paths are unique relative POSIX paths under the evidence root; path
traversal and root, directory, or file replacement are rejected. Receipt
publication uses no-follow exclusive creation at the root with mode `0600`,
then fsync, read-back, and identity revalidation; an existing entry is never
overwritten. Platforms without these descriptor-relative guarantees fail
closed. The 16-file and 8-MiB limits apply to the final evidence root including
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
self-referential digest while still binding every file exactly once. The report
does not contain the future envelope or its digest; the envelope is created only
after the validator has emitted and verified the receipt.

The validator serializes `receipt.json` as RFC 8785 canonical JSON followed by
one LF byte. Its `receipt_id` is `receipt-` plus 16 lowercase hexadecimal
characters and `validated_at` always has nine fractional UTC digits. These
fixed-width fields let a report producer determine the future receipt byte
length and declare the exact final byte count without knowing the validation
time. The declared final count and byte length are checked again after receipt
creation together with the unchanged raw report and payload inventory.

The candidate receipt is first published under an exclusive random
`.receipt.pending-*` name with mode `0600`, file and directory synchronization,
read-back, and inode checks. Only after that staging write does the validator
re-read the final payload inventory, exact raw `report.json`, and staged receipt
bytes. It checks context cancellation immediately before a no-overwrite commit
to `receipt.json`. Failure or cancellation removes only entries that still name
the validator-created inode and reports any unlink or synchronization failure;
it never treats an unowned writer replacement as successful cleanup.

The ordered trusted-input inventory is
`external-caller-ownership`, `source-hosting`, `build-system`,
`operating-system`, and `network-path`. Each item names its attesting source and
is bound to a sanitized payload-file digest. Validation proves that binding; it
does not turn any of those attestations into independently observed facts.

The evidence payload must not contain private keys, bearer tokens, encoded
Admission Contexts, certificate bodies, raw handoff or staging references, host
paths, credentials, secrets, backend IDs, daemon diagnostics, raw endpoints, or
captured command output.

The validator semantics locks a bounded forbidden-marker set. The validator
checks that set against each report and payload's raw bytes, normalized JSON,
and decoded JSON string values as supplementary fail-closed detection for
obvious material. It does not prove the absence of an arbitrary unknown,
encoded, encrypted, split, renamed, compressed, or otherwise disguised secret.
Evidence producers retain the sanitization obligation, and a validator receipt
must not be treated as a general secret-scan attestation.

Invoke the validator from a checkout containing the locked authorities:

```bash
go run ./cmd/verify-qualification-report \
  -source-root . \
  -evidence-root /absolute/path/to/evidence
```

The evidence root must not already contain `receipt.json`; the validator never
overwrites one. A successful command proves only that the exact sanitized
report and payload are internally consistent with the locked profile and report
schema. It cannot independently attest caller ownership, source hosting, build
systems, the operating system, or the network path. It also does not attest the
validator executable, repository checkout, compiler, or host-tool integrity;
those are execution trust inputs unless separately pinned and verified.

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
