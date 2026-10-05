# Phase 6 delivery priorities and machine handoff

Date: 2026-10-04

Status: coordination and delivery plan. Product positioning below is a
hypothesis to validate, not a comparative performance or production claim.

## Purpose and authority

Finish the existing Slice 6 acceptance scope without extending it into an
open-ended tooling project. Immediately after independent Slice 6 acceptance,
create a documented, committed, pushed and remotely verified checkpoint that
can be continued on another computer. Do not defer that checkpoint until
Slice 15. Authorization to continue Slices 7–15 remains in effect; the former
instruction to stop permanently after Slice 6 no longer applies.

This plan records the user's 2026-10-04 direction and the coordination
decisions below. It supplements the [Phase 6 plan](product-v1-phase-6-production-hardening.md)
and [ADR 0051](../adr/0051-product-phase-6-production-hardening-order.md),
without changing their order, Contract authority or release gates. It does not
authorize a new runtime backend, new paid infrastructure, credential access,
release publication or merge beyond existing approvals.

Use [STATUS](../STATUS.md) for current execution state, the
[startup audit](../audits/product-phase-6-slice-6-startup.md) for the fixed
open-item ledger and component receipts, and the
[scenario gap](../audits/product-phase-6-slice-6-scenario-gap.md) for the
final scenario queue. Update those records at substantive checkpoints rather
than creating competing status logs.

## Verified progress snapshot

Snapshot checked on 2026-10-04. These are acceptance counts, not estimates of
coding effort or remaining time.

| Item | Verified state |
| --- | --- |
| Phase 6 | 5 of 15 slices accepted; Slice 6 remains open |
| Slice 6 final topology | 0 of the fixed 16 complete-topology scenarios accepted; this does not mean no implementation exists |
| Final inventory | 78 deployments in the frozen gate inventory, not a claim of 78 containers per end-user sandbox |
| Accepted Guest business-revoke component | Evidence-tool revision `f49ee748f5e8790cd58c62d04bc5304b1a363b49`, runtime and fixture revision `c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635`, run `20efb6c95a0fa39cb0441f580a86888f` |
| Latest verified pushed implementation-branch checkpoint at this snapshot | `516861f7b5a08a1247c9d7890752ea04b30ebdf2` on `codex/product-v1-phase-6-hardening` |
| Work in progress | Guest PostgreSQL loss/recovery and replacement proof, helper cleanup and terminal ledger projection, then final component collection/binding; uncommitted work is not accepted or pushed evidence |

The accepted bounded component proves real Product/PostgreSQL/Guest signed
authentication, durable business-binding revoke, closure of the original
upgraded connection and fresh signed revoked-binding denial. Exact scoped
cleanup passed. The certificate controller's sticky credential-revoke failure
remains an explicit open issue: separately verified remote cleanup is not a
clean controller-drain result. Neither that component nor historical runs can
be spliced into the final fresh same-run topology.

The full-topology harness and live security edges still need work. Therefore
neither “only one final test remains” nor a numerical completion percentage
is supported. Existing component results reduce implementation uncertainty;
they do not advance the formal slice count.

## Comparator findings and product direction

The following is a documentation comparison checked on 2026-10-04, not a
head-to-head benchmark. The projects operate at different layers.

| Project | Documented strength | Implication for this project |
| --- | --- | --- |
| [Neko](https://github.com/m1k1o/neko) | WebRTC browser/Linux desktop streaming and multi-user collaboration, with [member permissions and authentication](https://neko.m1k1o.net/docs/v3/configuration/authentication) | Streaming, remote input and collaboration alone are not distinctive; do not claim Neko lacks authorization |
| [Agent Infra Sandbox](https://github.com/agent-infra/sandbox) | Integrated browser, shell, files, development tools and SDKs in a unified environment; [cloud deployment guidance](https://sandbox.agent-infra.com/guide/start/cloud-deployment) includes private exposure, TLS and authentication | A broad tool list or an all-in-one image is not enough; do not equate its quick start with its full security posture |
| [Microsoft NVX](https://github.com/microsoft/nvx) | OpenVMM hardware-isolated microVM execution and a [sandbox lifecycle service](https://github.com/microsoft/nvx/blob/dev/aci_edge_sandboxes/README.md) | Isolation infrastructure is a different layer from Product governance; Docker hardening must not be described as equivalent hostile-workload isolation |

**Positioning hypothesis:** prioritize teams delivering Agent capabilities to
their own users, where a human must be able to take over, permissions must
remain revocable during an active session, and faults must not create hidden
duplicate side effects or abandoned resources. The proposed advantage is
the combination of those properties across Terminal, Browser, Desktop,
Files and Development, with understandable operations and supported recovery.
It is not “more endpoints,” “more tests,” or “more evidence documents.”

There are existing components supporting this direction, but complete
production entry paths, deployment, recovery and independent acceptance are
still open. Distinctive architecture is not yet a demonstrated user advantage.
If the finished workflow is harder to deploy or operate without a measurable
benefit, this positioning must be revised rather than defended by sunk cost.

Validate this hypothesis through the already planned formal user paths and
deployment gates: an Agent task starts, a human observes/takes over, an active
permission is revoked, a dependency fails and recovers, and the task's files
and audit state remain coherent. Record setup effort, takeover/revocation
latency, recovery behavior and resource use with exact environment and
workload definitions. Slice 10 owns metric definitions; Slices 8/11/14 supply
the user paths and deployments. Do not add a new Slice 6 acceptance matrix,
invent performance targets, or claim superiority before comparable results.

## Architecture boundaries retained

Product owns business truth, desired state, end-user authorization and its
aggregate operation ledger. Provider owns provider-local execution and
evidence behind the locked repository-owned Contract. Gateway, Guest,
Browser and Desktop retain their approved process and trust boundaries.
The local `/instances` API remains separate from Provider APIs.

Reuse existing file, transfer, development and recording implementations and
formal routes; do not build parallel APIs just to demonstrate a feature.
Unknown external side effects remain unknown until existing reconciliation
or quiescence evidence resolves them; automatic retry is not proof of safety.

Neko and AIO Sandbox are workflow/component references. NVX is a possible
future isolation-layer evaluation, not a selected backend or a current
integration commitment. No NVX adapter, microVM rewrite, new identity system
or additional product surface is inserted into Slice 6 or the fixed Phase 6
order by this comparison. A concrete new requirement needs a separate
scope/architecture decision, dependency and license assessment, and rollback
plan before implementation.

Important changes to trust, identity/key ownership, topology, protocol,
Contract compatibility, production resource/time budgets, evidence reuse or
release boundaries still require coordination review before implementation.
Ordinary fixes within accepted ADRs and precise wiring do not require repeated
approval when their premises are unchanged. Independent operator acceptance
cannot be substituted by coordination review.

## Work reuse and stopping rules

The efficiency audit found an avoidable repeated full default race suite
after a tagged-only helper-test change that the default suite did not select.
That is concrete redundant work, but it does not explain every day spent on
Slice 6. Real cleanup ownership and security-edge failures are substantive
defects, not optional paperwork.

| Preserve | Stop or consolidate |
| --- | --- |
| Required race/shuffle/count, vet, applicable Docker and Contract gates at a stable implementation candidate | Repeating the entire root suite after every small tagged harness or documentation edit |
| Focused tagged tests for changed helper and failure paths | Treating another generic green suite as evidence for an unexecuted tagged path |
| Source-bound runtime builds under [ADR 0055](../adr/0055-phase-6-workload-tls-network-and-least-privilege-boundary.md) | Rebuilding frozen runtime R for evidence-tool E-only or documentation changes; do not evade the existing candidate C=R rule by relabeling |
| Existing unaffected component results, with explicit impact analysis | Re-running historical components merely because a new status document or helper exists |
| One fresh final run binding the entire required inventory and 16 scenarios | Combining old component receipts into a purported same-run final acceptance |
| Necessary bounded evidence of actual role behavior and cleanup | Adding a generic receipt framework, second observer or new helper for every wait/close operation |

Aggregate runtime changes into a clean source-bound candidate before expensive
builds. E-only changes still require the relevant evidence-tool tests and a
valid immutable E binding; reuse is not exemption from validation. A runtime,
image, entrypoint, dependency, identity, network or configuration change
invalidates affected observations, not automatically every unrelated result.

Record these coordination decisions once and cite them while their premises
remain unchanged:

- `S6-efficiency-and-component-boundary-20261004`: retain mandatory gates,
  batch candidate verification, reuse unaffected frozen runtime evidence and
  keep the component/full-Slice acceptance distinction explicit.
- `S6-A1-reuse-terminal-ledger-capture-20261004`: the terminal operator already
  reads and validates both ledgers at the correct lifecycle boundary. Add one
  closed, sanitized projection of that read for final review, not another
  reader or persistence of raw nonce/JTI/credential-bearing ledgers. Bind it
  to the existing raw length/hash and plan; do not claim that a projection can
  reconstruct discarded raw bytes. Evidence capture failure must not prevent
  otherwise authorized remote cleanup.
- The known sticky controller failure may remain explicit in a bounded
  component only when its exact typed failure, physical convergence and
  complete existing v3 remote cleanup evidence satisfy the reviewed boundary.
  Unknown/nonterminal active leases or missing observations still fail.
  Never relabel this as clean controller drain or full Slice 6 acceptance.

Use the existing fixed open-item ledger and scenario queue. A newly discovered
failure may block its affected acceptance condition; it does not automatically
authorize a new framework or a broader acceptance standard. Compare two
completed substantive attempts, not two polling snapshots: if neither closes
an acceptance result, resolves a blocker or narrows its cause, change the
diagnostic method, inspect related prerequisites together and aggregate the
fix. A running build/test is not stagnation. Do not raise timeouts, relax
security or retry indefinitely to manufacture a pass.

## Slice 6 step reporting

For each substantive, verifiable step in the fixed delivery sequence below,
report its stable number/name when starting, completing, failing, becoming
blocked or resuming. Include the observed result and evidence, the specific
open item closed or still missing, and the next step; report actual elapsed
time on completion when known, without inventing a percentage or ETA. Keep
code completion, component tests, real scenarios, formal acceptance and
commit/push state distinct. During a long build or test, report meaningful
phase changes and, after five minutes without one, the known running stage.
Do not rerun work merely to generate an update or turn individual commands
and documentation edits into new progress steps. The implementation session
also sends each compact step event to the coordination session so the user
receives it promptly; periodic checks only fill genuine reporting gaps.

## Next Slice 6 delivery sequence

1. Close the current bounded Guest recovery work: finish the already reviewed
   helper cleanup/ledger projection and final binding, freeze exact R/F/E,
   then obtain review for the applicable real-run boundary. Produce either
   directly verified PostgreSQL loss/recovery/replacement observations and
   exact cleanup, or a precise failed condition and narrowed cause. More
   helper tests alone are not this deliverable.
2. Close the remaining rows of the startup audit: Provider Browser crash and
   uncertain-outcome paths; three isolated Provider commands; complete live
   TLS/CRL and external-service edges; and actual network/UID/GID/privilege
   probes. Include Guest peer revoke, CRL-source loss and replacement behavior.
   Reuse unaffected components while completing the existing full harness.
3. Freeze and execute the complete 78-deployment/16-scenario gate with one
   fresh run ID, raw observations, source/image/config bindings and exact
   cleanup. Submit a compact evidence package for independent coordination
   review. Only formal acceptance changes the count from 5/15 to 6/15.
4. Synchronize STATUS, the plan/audit and handoff; commit and normally push the
   reviewed work, verify full local and live remote SHAs, and deliver the
   machine-handoff checkpoint below before advancing to Slice 7 work.

Current Slice 6 step 1 checkpoint (2026-10-05): the first separately
approved formal E attempt failed at old-client TLS-denial attribution. An
isolated no-issuer Vault replay supported a strict, E-only server-log
correlation fallback under Sandbox ruling
`S6-E-old-client-TLS-correlation-20261005`. A second separately approved
one-shot E attempt passed that probe but failed before the Product-A/Guest-A
private receipt chain; Product-A stdout was zero bytes and the original
container's start/exit state could not be recovered from Docker's short
event history. The v2 evidence remains `incomplete`. Sandbox ruling
`S6-E-start-observation-20261005` permits a bounded E-only correction for
the formal asynchronous Docker start observation, without changing receipt,
identity, terminal or release acceptance. A startup race is plausible but
not proven as the cause of the second failure. A third, separately approved
one-shot E attempt reached A's sealed Product/Guest streams and before-B
admission but failed when the formal B path passed the fixed Guest-B name to
an A-only network witness. The 107-file private root again retained only an
`incomplete` result and cleanup-only terminal evidence; exact run-owned
Docker objects were absent, but sticky controller revoke and formal terminal
confirmation remain open. Sandbox ruling
`S6-E-Guest-B-network-witness-20261005` permits an E-only closed-slot
correction while preserving the historical A-only component witness and
all identity/network checks. A fourth, separately approved one-shot E
attempt used clean E `fbd2502fc6e685cd2353d515f44d247e6da99763`
and failed after 505.56 seconds. Its 105-file private directory is
`incomplete`; the 29-event journal and zero-drop Product/Guest B streams
show substantially more of the replacement path, but no final binding,
119-file inventory or 14-slot convergence exists. Code-path review
supports, but the retained generic terminal error does not independently
prove, that formal precleanup replay succeeded before terminal v3 failed.
Precleanup is an in-memory digest and has no required same-named file.
Sandbox ruling `S6-E-terminal-first-failure-diagnostics-20261005` permits
only bounded E-side stage diagnosis and no-issuer regression checks; a
fifth issuer requires a newly frozen package and separate approval.
Further review found a deterministic E-side ledger identity mismatch:
the exact-issued-set expectation compared deployment labels to real PKI
authorization names. The reviewed desired-identity no-issuer test failed
before the correction and passes with exact authorization names/digests and
controller-policy state classification. This is component evidence, not a
proved cause of the fourth failure or the complete public R/E cross-package
chain. The old E571681 review-only script was never run and is obsolete;
a new clean E/review package and separate fifth one-shot approval are required.
None of these failed E runs counts
as one of the fixed 16 final scenarios; Phase 6 stays **5/15**.

Step 1 outcome (2026-10-05): Sandbox then approved one exact fifth run under
`S6-Ea065-single-run-approved-20261005`, and independently accepted only the
bounded Guest recovery component under
`S6-E550dba-bounded-recovery-accepted-20261005`. Run
`550dba360065dce4f46fa14476225ce5` passed in 533.78 seconds with clean
E `a065277e406bf09c4c22d4ce187e1d181e513316` and separate R/F
`e5816d0d3de0541bd9a677560096b3527f58f7b9`. Private root
`/Users/echo/.codex/phase6-slice6-run-evidence-Efix.GTGjew/550dba360065dce4f46fa14476225ce5`
retains final binding
`sha256:e66dc29a217c82e1ae9071b8046c33461afae8d216e488751c9a68e312549177`,
119-file inventory and 14-slot convergence; exact Docker/Vault/private cleanup
passed. Step 1 closes for real Guest PostgreSQL fault/recovery, A→B
replacement and recovered close, not the full topology. The certificate
controller remains `sticky_credential_revoke`/clean-drain OPEN, despite
independent terminal remote revoke and complete CRL. No sixth issuer is
authorized. Proceed to fixed step 2, starting with Provider Browser process
crash and unknown-result safety; Phase 6 remains **5/15**.

Step 2 bounded Browser checkpoint (2026-10-05): Sandbox ruling
`S6-Browser-process-crash-component-boundary-20261005` selected a test-only
independent-PID Browser application/identity-runtime crash component, not
production `provider serve v3` acceptance. The real PostgreSQL/high-UID
Browser/gateway Docker integration now kills a child after completed Docker
dispatch but before PostgreSQL `CompleteCreate`; a new PID recovers from the
finished proof with the same Docker IDs and no second dispatch, then exact
terminal cleanup. A second child is killed after actual restricted-network
acquire with no finished proof; the replacement retains Creating and the
finite UID, denies same-claim replay and a competitor, and does not redispatch.
Test-owned teardown of this unknown-result fixture is not an application
release. The opt-in tagged race integration passed (96.30 seconds on the
final test candidate), as did the ordinary repository race/shuffle suite,
vet, tagged package vet and Contract lock. This covers only the bounded
Browser crash component. Full `provider serve v3` replacement, other Docker
uncertainty cuts, the three Provider commands, remaining TLS/CRL/network/
privilege rows and one-run 78-deployment/16-scenario gate remain in step 2/3;
there is no Slice 6 manifest or release claim, and Phase 6 remains **5/15**.

Step 2 three-Provider source-difference checkpoint (2026-10-05): the existing
`provider serve` v3 entry selects coding-shell, Browser and Desktop with
mutually exclusive configurations; the remaining issue is real deployment
composition/observation, not a new Provider API. The [startup audit](../audits/product-phase-6-slice-6-startup.md)
now maps each PID's Profile, direct-versus-broker PostgreSQL signer path,
Contract/private/executor boundary, migration job, and missing final-topology
probe. Reuse one frozen Profile and its exact private-config archive contract
for all three; run the separate migration jobs before runtime admission and
start Browser/Desktop Provider mux and executor backend as a bounded
dependency group. The source audit alone does not close the three-command
row, authorize a sixth issuer, or alter the 5/15 count.

Sandbox review `S6-Provider-v3-wiring-scope-reviewed-20261005` keeps this
work gate-only: derive per-deployment startup and private-file inputs in the
existing `productphase6gate` helpers using exported final-Profile accessors,
not a new `internal/phase6security` production projection API or roster.
The first static draft was discarded after it incorrectly assumed that
Browser/Desktop Provider PIDs shared a direct PostgreSQL service bridge;
their paths are broker-only. Coding-shell remains direct. No new issuer,
runtime-source revision, release or push was authorized.

Subsequent prerequisite audit (2026-10-05) narrows that conclusion: the
three v3 command entries exist, but the frozen container Profile supplies no
approved Docker daemon/control channel or daemon-visible writable Provider
DataRoot/staging roots. Coding-shell also cannot honestly advertise its
mandatory artifact content checks with the older `/bin/true` test scanner.
These are open integration/architecture dependencies, not a request to
weaken the existing Profile or accept a static config as PID1 evidence.
The gate-only three migration input constructors and cross-job rejection
matrix remain component drafts pending a source-bound positive run; the
six-input 20-minute no-issuer rerun has not been spent. Sandbox was asked to decide
the scoped Docker/storage and fixed real-scanner approach. Phase 6 remains
**5/15**, with no Slice 6 manifest, push or release claim.

Sandbox subsequently selected one explicit operator-owned, daemon-facing
typed control principal, separate authenticated coding/Browser/Desktop
scopes, exact durable Provider state and coding staging volumes, confined
daemon-managed coding allocation volumes, and a real fixed-asset coding
scanner plus active-content policy. See ADR 0055 and the startup audit for
the source-to-input gap and current-daemon observations. This is a direction
for revising the old frozen inventory, not permission to add a hidden Docker
socket, start a privileged service, use a `true` scanner or relabel component
tests as a passing 78/16 topology. The next checkpoint is the concrete
closed-interface, principal/channel/volume/UID/resource, scanner and failure-
recovery boundary packet, with old→new inventory and R/F/E impact; the 16
scenario semantics remain fixed. Sandbox has since reviewed that packet:
three isolated control networks, direct mTLS without a second message-signing
key, per-allocation whole coding volumes, `passive-json-v1` content policy,
and a fixed ClamAV 1.4.6 LTS candidate with a 72-hour verified-rule freshness
bound and 4 GiB scanner cap. The standalone JSON policy/checker and private
scanner are source components, not yet wired to `provider serve`. One isolated
pinned-image ClamD/Unix-adapter probe has now passed real benign/EICAR scans
with exact cleanup, but its image-bundled rules are stale and it does not
establish the current-rule, v3 Profile/CRL or complete scanner service gate.
The current Docker VM has a known hard-cap lower-bound shortfall of
about 1,558 MiB even before all new roles and dynamic work are counted; no
full revised topology is admitted on it. The next result must be a source-
bound typed control/storage/scanner candidate with exact negative tests and
an updated complete Profile/resource envelope, then separately reviewed
daemon activation and fresh R/F/E. No full gate has passed, and **5/15** is
unchanged.
Sandbox has selected a distinct Security Profile v2 for that revised topology;
v1 keeps its historical digest and forbidden-Docker semantics. Provider
Process v3 coding must fail before side effects unless the complete v2
control/scanner/storage/rule/resource and guarded TLS/CRL bindings are
present. The accepted one-container ClamD adapter receipt is indexed in the
[Slice 6 startup audit](../audits/product-phase-6-slice-6-startup.md), not
promoted to an accepted 16-scenario run.
The reviewed four new security-principal tuples are now restricted to an
explicit v2-only registry and an offline provisional identity/TLS-delegation
fragment. This is not the final dynamic inventory or a complete v2 Profile.
Coding Provider v3 startup is held fail-closed ahead of material/PG/Docker
while its old command-scanner/daemon-facing composition remains; Browser,
Desktop and historical Provider v2 compatibility are unaffected. The hold
must be removed only after full v2 authority and guarded private composition
pass their named gates, never by relabelling the old checker path.
Sandbox has since selected two explicit coding allocation slots for the
current low-capacity local qualification candidate, with one no-network
workload and separate inputs/workspace/outputs whole volumes per slot. This
is not a production capacity default. Unknown create/cleanup outcomes keep
their slot reserved through recovery; reuse needs exact physical cleanup
evidence. The Profile v2 candidate and scenario budget must account for these
slots without interpreting the provisional 82-entry inventory as 82 steady
processes. Current VM resource shortfall and **5/15** status remain.
The coding allocation ID is now specified as a deterministic private digest
of the four persisted accepted-create origin fields, not a terminal SessionID
or SandboxSlotKey. Pure projection checks the unique existing idempotency
record for the original request digest and refuses a *new* allocation from
Running/Unknown/terminal create; the generation frozen at birth must retain
the same three volumes through later Suspend/Resume. A private same-row
PostgreSQL component now combines the Accepted-create projection, finite
reservation, first Creating permit and Running/Provisioning transitions; a
two-client concurrency/restart integration permits exactly one first dispatch
ticket. The optional Coding coordinator is now explicitly ticket-only and
keeps dispatch in Running/Creating until a real completed control receipt;
its tagged PostgreSQL component covers second-slot concurrency, third-slot
capacity, deadline/cancel row-lock waits, damaged documents and atomic event
rollback. This is not production composition, physical Docker dispatch,
control receipt or verified coding-volume cleanup. Coding v3 startup stays
fail-closed.

Step 2 Coding volume checkpoint (2026-10-05): a v2-only source-derived
runtime template and private Docker-control Unknown-intent ledger are
component-tested, but neither activates `provider serve v3`. The published
Coding image's named-volume root is `65532:65532 0770`, so the approved
distinct high-UID slot cannot write it unprepared. The first zero-data
`.` archive mechanism was disproved: Docker's pinned unpacker skips that
entry. Under a subsequent Sandbox ruling, one stopped, never-started
preparation carrier with an explicitly writable rootfs handled a two-
directory metadata archive; it was removed before a distinct read-only
runtime was created with `NoCopy=true` on the same three volumes. The one
real current-daemon probe passed actual slot-owner, high-UID workspace/
outputs/tmp writes, inputs/root denials and exact two-container/three-volume
cleanup. It reused the OCI index→selected manifest→config→layers and
Docker runtime-image checks. This is a bounded mechanism result, not a
production Control receipt, complete Profile v2, full gate or count change.
Sandbox subsequently accepted the probe as component evidence and approved
one-effect/one-Unknown-intent source work. The next acceptance target is a
bounded physical Completed observation plus an independently fenced durable
cleanup intent and exact whole-resource release proof; client timeout and
repeated absence alone cannot free a possibly late daemon effect. The
deterministic two-container/three-volume projection is underway, not an
activated Control service. No extra Slice 6 step is added.
Step 2 remains open and Phase 6 is **5/15**.

The later source-only Control observer now binds one test-scoped Unix client
to exact read-only v1.55 routes and pre-decode bounded responses. Its
SDK→inventory malformed-404/empty-list matrix and one specifically approved
nine-GET real empty-namespace component check passed on the current daemon.
This does not authenticate a production Profile/operator socket or prove
post-timeout daemon quiescence, complete runtime/metadata observation,
`Completed`, fenced deletion, `Released` or Provider PG release CAS.
The Coding v3 startup guard and **5/15** count remain unchanged.

The approved single retained Unknown effect subsequently passed a full
23-GET same-effect observation; its complete private proof was durably
saved before exact cleanup, followed by two zero-resource inventories.
Sandbox accepted that observation/cleanup as component evidence, not a
terminal receipt. The test receipt remains Unknown rev2 and must not be
retrofitted to Completed or Released after its runtime was removed. The
next source target is a generic *live* completion path: an unambiguously
returned create callback, current same-effect observation, bounded internal
exclusion, private proof persistence, and current-revision/authority CAS.
An Unknown effect after restart or ambiguous daemon work remains Unknown
without a separate quiescence producer; no historical proof import is
authorized. A separate Unknown-retirement recovery and the existing
fenced cleanup/Released/Provider-PG CAS remain open. This source progress
does not activate Coding v3 or advance **5/15**.

For the next normal cleanup leg, Sandbox ruled that a fresh legal terminate
can retire an allocation whose old create operation remains
`outcome_unknown` only when Control has a current, fully sealed Completed
receipt for that exact create effect. The old create outcome is immutable.
The accepted terminate and desired-state event are persisted first; a
single current PG transaction then binds its Running/Terminating/Cleaning
retirement identity before Control receives a short-lived cleanup permit.
Equal-to-birth fences may be legal when equal to the *current* PG highwater;
no synthetic fence increment is allowed. Control Unknown and unresolved
daemon effects stay occupied. Released proof and Provider PG exact release
CAS remain future gates; this is not permission to use the old cleaned
test effect or lift the Coding v3 guard.

The offline PG cleanup projection now records a current retirement binding
alongside the Cleaning slot, Running terminate, Terminating observation and
existing event in one candidate row mutation. It retains the exact
parent-deadline-clamped cleanup envelope for read-only response-loss
readback. Pure tests cover normal and historical-Unknown creates with
Control Completed, same-fence/repeated-generation terminate, competition
and identity/deadline drift. An approved single PostgreSQL-only component
batch now passes real two-client same-fence contention, transaction rollback,
row-lock deadline, exact readback and PG restart, with exact container and
anonymous-volume cleanup. Its synthetic Control receipt does not establish
cross-process attestation; SQL COMMIT response loss is not tested. The
subsequent approved, once-run final release-CAS PostgreSQL component batch
passed with race/shuffle: two PG clients contended with one winner, an actual
new occupant was admitted by normal first-create after release, and the old
proof could not release it. A transaction-local higher-fence drift, rollback,
row-lock deadline/cancel, lost-return readback and PG restart were covered;
this does not prove a persisted competing higher-fence operation. The Control
Released and Provider exact release sources remain unactivated: there is no
cross-process attestation, real Coding deletion or complete cleanup/release
gate. Coding v3 stays guarded and Phase 6 remains **5/15**.

Step 2 Provider↔Control integration decision (2026-10-05): Sandbox approved
the existing PG `Cleaning`+`Retirements` record as the durable barrier for
the original Coding allocation. A generic lifecycle writer must check it
under the same PG row transaction, not through a Coordinator pre-read or
an embedded repository escape. Conflicting new writes receive the existing
retryable 503; exact replay, reads and lawful same-attempt Unknown reporting
remain. This chooses the current PG barrier over a new supersession or
distributed abort protocol and does not hold a SQL lock across Docker or
network I/O. The companion typed Provider↔Control mTLS/CRL wire and full
Profile v2 source are authorized for source/component work only. Actual
physical Coding deletion, full-topology operation and gate acceptance are
separate. One approved bounded real-PG two-client barrier component batch
passed on 2026-10-05; it did not authenticate Control or perform Coding Docker
work. The fixed Step 2 remains open and Phase 6 stays **5/15**.

Next Step 2 source boundary: the reviewed authenticated Control observation
layer separates repository pre-read, dedicated mTLS/CRL transport, application
binding checks and the PG row-locked CAS. The transport cannot query PG, and
an ordinary wire response cannot construct the old local Control snapshot or
act as trusted release evidence. Begin checks the current original
create/accepted terminate binding; Finish uses the persisted retirement's
Control revision/state floor. Production composition must fix the real v2
adapter and cannot configure a fake/local-ledger fallback. These are design
constraints for the still-unimplemented vertical path, not acceptance of it.

An additional reviewed Step 2 recovery invariant requires the original
create-authority envelope to be minted and persisted in the same first-permit
PG transaction, indexed by allocation rather than recyclable slot. It must
survive final release and never be renewed for an expired status query. The
source now has a bounded original-record model, an atomic first-permit method,
read-only recovery and typed application/PG observation candidates; these are
not yet wired to the frozen v2 mTLS/CRL production client or gate. Legacy
unbound Creating slots remain occupied and cannot be silently repaired.

The follow-up source decision freezes an atomic-original authority mode and
Control policy digest in the existing Coding-specific PG marker at a separate
one-time v3 initialization. A legacy initialized marker is not upgraded in
place. Other repository instances, pools and restarts must see the same mode:
legacy first-create and local-snapshot cleanup/release wrappers reject v3,
while v3 entry points require the exact stored mode/policy and original
envelope. The v3 coordinator carries the same original bytes to a dedicated
dispatcher; a ticket-only or re-signed fallback is forbidden. Targeted source
tests and an authorized disposable two-pool PG component supplement now cover
the original/marker and queued retirement-first lease versus
higher-fence-first cleanup orderings, typed PG cleanup/release with a
synthetic Observer, slot reuse and restart. The first PG attempt failed on a
fixture conflict and its single approved repair supplement passed; both are
indexed in the [startup audit](../audits/product-phase-6-slice-6-startup.md).
This is still not cross-process Control mTLS/CRL, real Coding Docker absence
or the fixed topology gate. Step 2 and Phase 6 **5/15** remain unchanged.

Step 2 transport/CRL source checkpoint (2026-10-05): the Control status
server/client remain package-private and status-only. The server reads one
bound, ledger-locked receipt/state projection; a real localhost mutual-TLS
test passes `not_found` and denies a write action. Test handshake hooks are
not production CRL evidence. Sandbox selected explicit Profile-v2 CRL
validation/derivation/compilation entry points while preserving existing
CRL wire identifiers and digest domains. The source now calculates a complete
v2 mapping from the 82-static/two-Coding-slot synthetic graph, rejects
missing/extra/cross-purpose tuples and checks externally pinned canonical
source/role digests. Sandbox rejected the first synthetic mapping's
unapproved third PostgreSQL issuer; the revised source check enforces the
existing two `/pki` issuers and selects by the verified peer's fixed broker
group, with PostgreSQL on the general issuer. This has focused component
tests only; controller/agent source enforcement is still open. Every public
v2 entry remains closed behind the formal
`ProfileV2.Validate` source/image hold. Next is a real v2 TLS/CRL factory,
Control/Scanner role commands and source-bound images, then the fixed live
gate; none of these component checks advances **5/15**.

## Remaining Phase 6 order

These are summaries of the existing plan, not additional slices. Each slice
keeps its named formal gate and must be independently reviewed before closure.

| Slice | Required outcome | Reuse or boundary |
| --- | --- | --- |
| 7 | Application image pinning, SBOM, signatures, provenance, actual license/source obligations and executor-v2 Desktop publication | Recheck affected runtime gates; a local Slice 6 candidate is not a published release |
| 8 | Production PostgreSQL, coordination/object storage and complete Files/Development/transfer/recording business paths | Compose existing services and formal Web/BFF routes, not duplicate APIs or test-only routes |
| 9 | Backup, isolated restore, key recovery, integrity and measured RPO/RTO | Real restore drills, not backup configuration alone |
| 10 | Safe bounded telemetry, SLI/SLO definitions, dashboards and alerts | Measure user-visible behavior; an initial window is not a production SLO claim |
| 11 | Supported Docker, Apple Container and Kubernetes deployment profiles | Deployment packaging is not a new Provider backend; incomplete declared business capabilities fail closed |
| 12 | Upgrade/skew, migration, canary, rollback and disaster recovery | Real interruption/recovery exercises and explicit rollback limits |
| 13 | Fixed hostile-input, tenant and resilience campaign | Strengthens evidence but does not qualify hostile-workload isolation |
| 14 | Independent full deployment from published immutable artifacts with public-entry E2E | Include Files, Development, transfer and encrypted recording in independently administered failure domains |
| 15 | Final evidence/security/operations review and named operator acceptance | Precise supported scope; missing external conditions remain blockers, never fictional 15/15 |

Continue unaffected authorized work when a specific review or external input
is pending. Missing credentials, paid resources, independent infrastructure
or operator acceptance must be reported precisely. Do not treat an internal
technical review as a missing user decision, and do not fabricate external
conditions to avoid a blocker.

## Machine handoff checkpoint

The 2026-10-05 interim source checkpoint is permitted before formal Slice 6
step 3 because the operator is changing computers. It does not close step 2,
execute step 3, complete formal step 4, or advance the **5/15** count. Git
alone will not move ignored private evidence, local OCI candidates, Docker
state or credentials. The final acceptance/migration checkpoint remains open.

### Interim source checkpoint and restart boundary, 2026-10-05

- Fixed step 1: bounded Guest recovery E component accepted under its recorded
  source/run boundary; it is not the complete Guest security edge. Step 2 is
  still open for Provider Browser crash and uncertain outcomes, three isolated
  Provider commands, live TLS/CRL and external edges, actual least-privilege
  probes, and Guest peer-revoke/CRL-loss/replacement behavior. Step 3 is the
  fresh 78-deployment/16-scenario gate plus independent evidence review;
  step 4 is the post-acceptance documentation/source handoff. This interim
  commit/push is not a substitute for either step 3 or step 4.
- The accepted E private run is `550dba360065dce4f46fa14476225ce5` at
  clean E `a065277e406bf09c4c22d4ce187e1d181e513316` and clean R/F
  `e5816d0d3de0541bd9a677560096b3527f58f7b9`. Its private 0700
  evidence root under `~/.codex/phase6-slice6-run-evidence-Efix.GTGjew/`
  has 119 inventoried files (about 548 KiB). The final binding SHA256 is
  `e66dc29a217c82e1ae9071b8046c33461afae8d216e488751c9a68e312549177`;
  the 0600 gate log under `~/.codex/phase6-slice6-run-Efix.CQdy6i/` has
  SHA256 `44d2d3337d5893eba37db2658a0e3c366d92c8aa07e6eb660fc66fe208c2c084`.
  The exact run-label filtered Docker container/network/volume inventories
  were empty on the old host. These raw files are not in Git; preserve and
  transfer only through an approved private channel, verify hashes and
  restrictive permissions, and retain the original until recovery is proven.
- The separate Coding component's three retained 0600 receipts remain under
  `~/.codex/phase6-coding-control-3935310749/` (0700 directory), with SHA256
  `1df5dcb98ad3c5df3067691e149ef5a7a61b04a7da8b55c93faca7de15227cd6`,
  `6359f00fbcbb0d84e89fae72bbe947a7cf488048dd12fa023b5cdab61bf4292c`,
  and `0d8783b29f8b6a752dbb8a753affadd9db0f6645286d8e770a80d41f5409c81d`
  for completion, cleanup intent and cleanup result respectively. The
  recoverable published test OCI tar is in the old host's Trash. These are
  component observations, not a release artifact. The 54 ignored files in
  `e2e/evidence/` and older private runs are also not transferred by Git.
- Old R-bound local OCI candidate directories are about 133 MiB and 144 MiB
  (`~/.codex/phase6-slice6-candidates-Re581.CzaUL7/` and
  `~/.codex/phase6-desktop-Rc83fcbc.KTP1yl/`). They are not the new final
  source-bound candidate: rebuild from the eventual clean, locked source on
  the destination unless a particular old candidate must be independently
  audited and securely transferred. Never infer a signed release, deployment
  or current-source binding from their local presence. The runnable Slice 6
  deployment inventory is 78; the 82-static Profile-v2 synthetic fixture is
  provisional test data and cannot replace that topology.
- The corrected two-issuer Profile-v2 CRL source and package-private Control
  status transport passed focused race/shuffle/count-three checks. A parallel
  full `internal/phase6security` count-three run timed out at Go's ten-minute
  default in an existing large evidence-validation test; it is not a pass.
  The final source snapshot passed `go test -race -shuffle=on -count=1 ./...`
  (`internal/phase6security`: 383.709 seconds), `go vet ./...`, both Provider
  and Product Contract verifiers, and `git diff --check`. This is source
  quality only: public `ProfileV2.Validate` still has an unconditional
  source/image admission hold, `provider serve v3` is closed, and there is no
  live v2 CRL, Control/Scanner OS process, physical Coding Docker gate,
  16-scenario manifest, publication or production-readiness claim.
- Ruling `S6-ProfileV2-CRL-two-issuer-correction-reviewed-20261005` rejects
  a third PostgreSQL issuer: the existing `/pki` broker/general pair is
  exact, broker source is selected only by a verified broker peer, and
  PostgreSQL uses general. The first three-issuer fixture remains a failed
  review finding. The next substantive result is source-bound v2 TLS/CRL
  enforcement through Controller/agents and actual Control/Scanner commands,
  followed by the remaining step 2 live edges, not a synthetic gate receipt.

The old development host is macOS arm64 with a Linux/arm64 Docker daemon and
Go 1.26.8 selected through `mise`; the destination OS/chip/daemon are not yet
known. Re-establish Git/registry/Vault and other authorized credentials
securely on the destination; do not copy plaintext credentials or the old
Docker daemon state. For an empty destination checkout, after verifying the
normal push's exact full SHA from the handoff report:

```bash
git clone https://github.com/shell-echo/sandbox-runtime.git
cd sandbox-runtime
git fetch origin codex/product-v1-phase-6-hardening
git switch --track origin/codex/product-v1-phase-6-hardening
git rev-parse HEAD
git ls-remote --exit-code origin refs/heads/codex/product-v1-phase-6-hardening
mise exec go@1.26.8 -- env -u GOROOT GOFLAGS= GOTOOLCHAIN=local go version
```

Compare both full SHAs to the handoff report before work. Read
`docs/PROJECT_CONTEXT.md`, this plan, `docs/STATUS.md`, architecture,
development rules and ADR 0055. Verify the destination Docker architecture
and digest-pinned inputs before rebuilding or running tagged gates. If
private accepted observations are transferred, compare their SHA256 and
permissions to the audit; otherwise leave historical evidence on the old
host and rerun only what the next named gate actually requires. Start a new
session with: “Continue Product v1 Phase 6 Slice 6 from the verified
`codex/product-v1-phase-6-hardening` handoff SHA. Keep 5/15 and all v2/v3
admission holds. Read PROJECT_CONTEXT, STATUS, the Phase 6 delivery plan,
ADR 0055 and startup audit. Resume fixed step 2 at real v2 TLS/CRL
Controller/agent and Control/Scanner source-bound composition, then close
remaining live edges and the formal 78-deployment/16-scenario gate. Report
progress and coordinate architecture issues with pinned Sandbox. Do not
invent evidence or touch old-host private artifacts.”

Before declaring the **final post-acceptance** checkpoint ready (the interim
source handoff satisfies only the relevant inventory, safe commit/push and
single-writer parts, not item 1's missing release acceptance):

1. Finish the Slice 6 review and record accepted scope, remaining non-claims,
   exact R/F/E revisions, image identities, run ID, manifest/receipt hashes,
   verifier commands/results and the next Slice 7 outcome in the canonical
   documents. Keep secrets and private raw receipts out of Git.
2. Account for all changed/untracked files; commit only reviewed project work,
   preserve unrelated changes, and report anything intentionally left local.
   Use a normal push, never force-push. Record the final full commit SHA after
   the commit rather than trying to embed a commit's own SHA in its contents.
3. Compare full `git rev-parse HEAD`, the branch's upstream SHA and a fresh
   `git ls-remote --exit-code origin refs/heads/codex/product-v1-phase-6-hardening`
   result. All must match. A failed remote read or push means “local checkpoint,
   remote unverified,” not “pushed successfully.”
4. Inventory required non-Git artifacts and private evidence with hashes,
   ownership and access instructions: what is durably retrievable, what needs
   secure user-controlled transfer, and what can be rebuilt. Verify that local
   candidate images and accepted private receipts needed for continuation are
   actually recoverable. Do not silently publish them or commit credentials.
5. On the new computer, fetch the exact branch/commit into a clean checkout,
   read PROJECT_CONTEXT and this plan, provision the toolchain from repository
   and frozen build inputs, and re-establish authorized credentials securely.
   Verify retained evidence hashes and artifact access before deciding which
   environment-dependent checks are necessary. Reuse historical accepted
   evidence only within its recorded boundary; new-host execution is a new run.
6. Transfer the single-writer role and coordination context deliberately.
   Ensure the old machine has no owned run requiring cleanup and no automation
   still dispatching writes while the new machine starts. Do not delete old
   private evidence or the checkout until recoverability is confirmed.

The handoff report must contain the branch, full local/upstream/live remote
SHA comparison, acceptance/evidence summary, non-Git artifact availability,
credentials that require re-establishment, remaining blockers and one concrete
next deliverable. A pushed Git commit without those artifact prerequisites is
a source checkpoint, not a fully verified machine migration.
