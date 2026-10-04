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
not proven as the cause of the second failure. No third issuer is authorized.
Aggregate tagged validation, a fresh clean E freeze and separate one-run
review remain before any further real attempt. Neither failed run counts
as one of the fixed 16 final scenarios; Phase 6 stays **5/15**.

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

At this snapshot the implementation has uncommitted work and Slice 6 is open;
the final migration checkpoint has not been produced. Git alone will not move
ignored private evidence, local OCI candidates, Docker state or credentials.

Before declaring the checkpoint ready:

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
