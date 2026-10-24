# Project Status

The [whole-repository verification](audits/product-phase-6-slice-6-startup.md#2026-10-24-whole-repository-race-verification)
now passes at tested source d23a19ff3294bdc02843c2e106bb3bc96b9353e0.
The original `go test -race -shuffle=on -count=1 ./...` finishes naturally in
503.982350s/600s: 267 unique package lines, 229 passing test packages and38
packages without tests, empty stderr, no timeout/truncation/active signal.
Full2174 source/lock and direct/tool/Git checks match before/after. This is
one current root-module execution, not a repeatability or nested-module claim.

Separate `go vet ./...` passes naturally in67.234062s; its complete stage,
including bootstrap, inputs/Git pre/post and publication, finishes in
87.628873s/90s. miseGo1.26.8, GOMAXPROCS2, `-mod=readonly -p=2`, original
cache/module settings and all safety/refusal boundaries remain unchanged.
No repository Go or fixture change occurs in this verification stage.

The passive observer is explicitly incomplete: one valid process sample,
then an erroneous duplicate-FD-unregister marker stops further sampling.
Its failure does not interrupt Go. A separate private corrected copy passes
24 offline methods, including two positive multi-cycle/early-EOF tests;
no second full-race run occurs. Old failed preparations and the original
600.014672s timeout remain unchanged. This pass does not establish that
failure's unique cause, any individual optimization's savings or a stable
performance margin. Earlier entries below retain their then-current status.

Phase6 stays **5/15**, Slice6step2. Resume independently selected remaining
startup/safety audits; Docker management authority, step3 live inventory and
original16 scenarios/independent acceptance, and formalstep4 remain open.
Timers stay OFF; no gate, quota, timeout, old lock or evidence-reuse rule changes.
Private evidence: slice6-fullrace-observe-20261024-v1. This three-document
checkpoint's commit/push disposition is recorded separately.

The preceding [DNS lexical validation change](audits/product-phase-6-slice-6-startup.md#2026-10-24-dns-lexical-validation)
uses one bounded ASCII pass for the original lowercase/host/double-dot language.
Original size/edge/Unicode/IP rejection and permissive label behavior remain;
all TLS, external-service, egress, public-entry and snapshot checks remain.

A passes95 named results (70 new/25 original),7241 original-oracle comparisons
and package vet in16.701829s/90s. B passes the original73 PeerCRL results in
12.217274s/90s using unchanged A vet and the same2174 source/lock inputs.
Complete inputs/Git pre/post and publication are included in each batch.
One source-attribution preparation assertion failed by counting both hunk
markers; raw/failure retained. Independent offline review confirms the source
attribution without replay; the preparation failure stays FAILED.
No measured savings, new CPU profile, whole-repository pass or runtime admission.
Phase6 remains **5/15**, Slice6step2; fullrace **FAILED600.014672s** is unsatisfied.
miseGo1.26.8, original gates/locks/reuse and timers OFF remain. Private evidence:
slice6-dns-policy-scan-20261024-102141. Five-file commit/push disposition is separate.

The preceding [principal digest validation change](audits/product-phase-6-slice-6-startup.md#2026-10-24-principal-digest-validation)
removes one redundant outer-digest regexp after full Registry validation and
exact digest equality. Every rejection remains: malformed/forged identities,
wrong registry/authorization/TLS bindings and sandbox controlling digests still
fail closed. Public holds and separate snapshot validations remain.

A passes58 named results (33 new/25 original) plus package vet in14.408291s/90s;
B passes the original73 PeerCRL results in13.286053s/90s using unchanged A vet.
Complete2173 source/lock and inputs/Git pre/post plus publication are included.
No measured speedup, new CPU profile, whole-repository pass or runtime admission
is claimed. Phase6 remains **5/15**, Slice6step2; fullrace **FAILED600.014672s**
is unsatisfied, not rerun. Existing gates, miseGo1.26.8, old evidence/locks/reuse
rules and timers OFF remain. Private evidence:
slice6-principal-digest-guard-20261024-081613. The reviewed five-file checkpoint's
commit/push/live SHA disposition is recorded separately.

The preceding [Profile-v2 single-encoding change](audits/product-phase-6-slice-6-startup.md#2026-10-24-profile-v2-single-encoding)
replaces two full encodings in the private field-validator tail with one
root-digest-cleared encoding. Exact71-byte restoration keeps the original
signed JSON2MiB size limit; domain/error semantics and every earlier field
guard, public hold and independent validation boundary remain.

A passes44 named results (20 new/24 original) plus package vet in51.556528s/90s;
separate B passes the original73 PeerCRL results in15.635456s/90s. Both include
full2172 source/input/Git pre/post and publication; B reuses unchanged A vet.
This proves component behavior and the source-level two-to-one encoding change,
not measured savings, a new CPU profile, whole-repo or runtime acceptance.
Phase6 remains **5/15**, Slice6step2, fullrace **FAILED600.014672s** unsatisfied.
Next select another useful retained-profile or startup-audit target through
independent review. Existing gates/miseGo1.26.8/locks/reuse rules and timers OFF
remain. Private evidence: slice6-profile-v2-encoding-20261024-003430; six-file
commit/push/full SHA disposition follows separately.

The preceding [peer-CRL retained-profile source attribution](audits/product-phase-6-slice-6-startup.md#2026-10-23-peer-crl-recheck-source-attribution)
passes three local reports in3.208271s/90s including publication. Full2171
source/lock,74 tools and442 saved checkpoint files match before/after; unchanged
parser coverage reuses24 prior methods. No Go change/new test/profile/vet or
runtime admission. Source rows locate8.37s of requiredPeerCRLV2's overlapping
8.60s cumulative sampled weight at full Profile validation; sampled field
callees include validatePrincipal1.82s, Digest1.79s and json.Marshal1.58s.
These are not call counts, savings or a full-race timeout explanation.

Next independently inspect the two encodings' distinct ProfileDigest/size/error
semantics before proposing any equivalent change. Keep all public/final/snapshot
validation and refusal conditions. Earlier checkpoint792f5b9769a8422a36518560e4da3accd586564a
is normally pushed and verified local/upstream/live equal, clean0/0; the
officialSSH443 route preserves existing trust and original10/90s bounds.
The oldSSH22 failure remains. Phase6 stays **5/15**, Slice6step2; fullrace
**FAILED600.014672s** unchanged, timers OFF. Private evidence:
slice6-peercrl-checkpoint-ssh443-20261023-234529 and
slice6-peercrl-recheck-lines-20261023-235125. This new documentation checkpoint's
commit/push disposition follows separately.

The preceding [peer-CRL post-optimization CPU recheck](audits/product-phase-6-slice-6-startup.md#2026-10-23-peer-crl-post-optimization-cpu-recheck)
passes the unchanged TestPostgresPeerCRLV2OwnerIsolationAndPinnedDecode target:
73 named results, one package PASS and297 complete events. Target55.726909s,
flat pprof1.478675s and cumulative pprof0.396227s complete naturally in a
57.995788s/90s diagnostic batch. Complete input/Git/environment pre/post retain
their separate original bounds; this is not the entire operation elapsed.

New23 offline methods pass0.206235s/30s, preserving original refusals and adding
strict event/actual-retention-path refusal and old297-event compatibility.
The new real profile and binary are retained as exactly two private files,
with original FD/UID/GID/nlink/ACL/hash/mode guards and1MiB/16MiB observed
thresholds unchanged. Full137 direct/3helper/2module,2171 source and74 tool
checks pass before/after. Tested HEAD/upstreambf8a73d is clean0/0; no Go or
fixture code changes occur in this recheck, and no new vet/full-race pass.

The profile spans47.66s with28.35 sampled CPU seconds. Application cumulative
rows include ProfileV2.validateFields9.76s, requiredPeerCRLV2 8.60s,
Postgres role validation7.51s and pinned decode4.75s. Rows overlap and are
sampled, not call counts, savings, waits or the cause of the old600s timeout.
Old19.370434s versus new57.995788s comes from different contexts and is not a
controlled regression or benefit measurement. The source-level3-to-2 change
remains verified separately; absent samples cannot prove an edge disappeared.

Next independently inspect this new retained profile's source/caller/line
attribution before any further equivalent-change proposal. Keep full public
entry and snapshot validation, final role checks and every refusal. Phase6
remains **5/15**, Slice6 step2; step3 live inventory/original16/independent
acceptance and formalstep4 remain incomplete. Required full race remains
**FAILED600.014672s**, not rerun. miseGo1.26.8, all existing gates, timers OFF.
Private evidence: slice6-postgres-peercrl-cpu-recheck-20261023-230152.
This is the precommit source record; normal push/full SHA disposition follows.

The earlier [peer-CRL same-call graph reuse](audits/product-phase-6-slice-6-startup.md#2026-10-23-peer-crl-same-call-graph-reuse)
implements the independently reviewed private Postgres derive change from three
to two source-level full graph/field validations. One unchanged source-validator
body returns its required map only after every check succeeds; its existing
entry remains a full-check wrapper. Empty-owner ordering, nil graph on error,
all source/issuer/mapping refusals, fresh output and final complete role
validation remain. Public launch holds, separate entry validation and snapshot
boundaries remain; no cross-call cache or input-mutation reuse is introduced.

The first v3 test batch naturally FAILED in48.445792s/90 because one new
expected edge literal disagreed with the unchanged authoritative dependency:
provider-runtime uses provider-coding-postgres. The production implementation
was unchanged by that test correction. Independent review permits reuse of117
named passes in five unaffected complete parents. Fresh v5 passes the affected
13 named results and package vet in11.252236s/90, with complete input/source
checks before/after; this is not130 passes in one batch. Old failures remain.

A global filesystem device-number change was separately observed; hashes and
all other identity fields matched. Its cause is unknown. v4 was never run;
new v5 uses independently reviewed fresh full eight-field bindings without
editing old manifests or receipts. No measured performance benefit, whole-repo
pass or runtime acceptance is claimed. Full race remains **FAILED600.014672s**,
not rerun. Phase6 stays **5/15**, Slice6 step2; step3 and formal step4 remain
incomplete. mise Go1.26.8, all existing gates and timers OFF remain.
Private evidence: slice6-peercrl-graph-reuse-20261023-155048.
This is the precommit record; commit/push/live SHA disposition is separate.

The earlier [peer-CRL same-call validation analysis](audits/product-phase-6-slice-6-startup.md#2026-10-23-peer-crl-same-call-validation-proposal)
completes three read-only reports on the retained profile in 2.289901s under
the original shared 90s boundary. All exit0/reaped, empty stderr, no signal,
timeout or truncation; full source/lock, tool-source and old archive checks
pass before/after. New 24 parser/refusal methods pass in 0.074500s/30s.
No application test, new profile, Go optimization or runtime acceptance occurs.

Exact source and directed caller evidence identifies three full graph/field
validations on the private Postgres derive's complete source-level happy path.
Independent review accepts a minimal 3-to-2 design: one source-validator body
returns its required map only after all checks succeed; the existing validator
remains a full-check wrapper, and only this derive reuses the returned map.
Keep empty-owner ordering, nil graph on every error, all source/issuer/mapping
refusals, fresh output construction, and the final complete role validator.
Public launch holds, independent decode/file/compiler calls and snapshot
boundaries remain. No cross-call cache or input-mutation reuse is permitted.

The removable direct derive-to-required edge has only 120ms sampled weight.
That is not a call count or measured benefit; the overlapping 2.68s/3.03s totals
cannot be claimed as savings. Next review the concrete minimal implementation
and refusal tests before a new bounded execution identity. The required full
race remains **FAILED600.014672s** and was not rerun. Phase6 stays **5/15**,
Slice6 step2; step3 acceptance and formal step4 remain incomplete. All existing
security, evidence, resource and time gates hold; mise Go1.26.8, timers OFF.
Private evidence: slice6-peercrl-field-cpu-lines-20261023-144932.
This is the precommit record; commit/push/live SHA disposition is separate.

The earlier [PostgreSQL peer-CRL CPU diagnostic](audits/product-phase-6-slice-6-startup.md#2026-10-23-postgresql-peer-crl-targeted-cpu-diagnostic)
passes the exact TestPostgresPeerCRLV2OwnerIsolationAndPinnedDecode target:
73 named results, one package PASS and 297 complete JSON events. The unchanged
test retains additional owner, pin, encoding and public-hold assertions inside
those named cases. This is pure Go component evidence, not a live PostgreSQL run.

The original shared 90-second batch completes naturally in 19.370434s:
target command 18.317265s, flat pprof 0.661247s and cumulative pprof 0.146760s.
All three exit0/reaped with empty stderr and no signal, truncation or timeout.
New 21 offline refusal methods pass in 0.118586s/30s. Complete 2170 source/lock,
74 tool-source and frozen direct/helper/module checks pass before/after, with
local HEAD/upstream f98b8c522799d27345ddf28e549fe7b31234f7e7 clean0/0.
The earlier independent sync stage observed this same full live remote SHA.

The profile spans 13.22s with 12.12 sampled CPU seconds. Cumulative rows show
ProfileV2.validateFields 3.03s, requiredPeerCRLV2 2.71s,
PeerCRLRoleDocument.validatePostgresV2Fields 2.21s and
decodePostgresPeerCRLRoleDocumentV2Fields 1.46s. Rows overlap; they are not
exclusive cost, invocation counts, wait time, measured savings, host/build CPU
or the cause of the earlier full-race timeout. No Go source changes or
optimization are accepted. Next independently inspect those source/caller paths
using this saved profile, preserving full public-entry validation and all
owner, mapping, issuer, encoding and launch-hold refusals.

The required full race remains **FAILED600.014672s**; it was not rerun.
Phase6 remains **5/15**, Slice6 step2. Step1 historical bounded E is unchanged;
step3 live full Profile-v2/original16/independent acceptance is incomplete;
formal step4 has not started. mise Go1.26.8, existing resource/cache/proxy
settings and all security/evidence gates remain unchanged; timers OFF.
Private evidence: slice6-postgres-peercrl-cpu-20261023-141819.
This is the precommit source record; reviewed commit, push and final full
local/upstream/live disposition are recorded separately.

The earlier [bundle/canonical CPU attribution](audits/product-phase-6-slice-6-startup.md#2026-10-23-bundle-and-canonical-cpu-attribution)
naturally passes in4.441331s under the original shared90s, including full
input/Git/archive pre/post and three local reports. Those commands take
1.103288s/0.269843s/0.269676s, all exit0/reaped, empty stderr, no signal,
timeout or truncation. New18 parser/refusal methods pass0.308325s/30s.
Complete47 direct/2170 source-lock/74 tool-source and oldQ149-file archive
checks pass; local HEAD/upstreambfb8da325b654672f2359f34cb648da226a7fb9b
is clean0/0. No Go test, new profile, project build or host/Docker run occurs.

Old sampled bundle cumulative7.29s attributes3.72s to manifest-file verification,
2.60s to private reads and810ms to canonical receipt calls. Source rows split
private index/raw/envelope reads10ms/2.09s/500ms and canonical index/envelope
640/170ms. Canonical helper total890ms contains duplicate scan410ms,
typedDecode370ms and Marshal110ms; scenario validation contributes another
incoming80ms. Rows and graph weights overlap and round: they are not invocation
counts, waits, measured savings, host CPU or the cause of the old600s timeout.
Unsampled EOF/digest/identity/canonical checks remain necessary.

No production optimization is accepted. Keep early duplicate rejection,
typed unknown/type/trailing refusal, exact canonical bytes, run/config/content
digests, every public entry and dynamic filesystem checks. Current samples do
not justify custom decoding, reordered checks, new maps or caches. One stale
source-text mutation in an unexecuted fixture draft was corrected before final
review; old draft/plan bytes remain and no failed identity is replayed.
Next independently select another high-cost target from retained phase6security
evidence and require a discriminating bounded plan before new execution.
Do not keep replaying this completed diagnostic or the full repository blindly.
Private evidence: slice6-bundle-canonical-cpu-lines-20261023-124851.

The prior sync stage naturally pushesbfb8 and observes identical complete
local/upstream/final live SHA, clean0/0; old failures stay preserved. This
analysis freezes precommit source records; its later reviewed docs-only commit
and normalpush/full live disposition will be recorded separately.
Required fullrace remains **FAILED600.014672s**, Phase6 **5/15**/Slice6step2.
Step1 historical boundedE unchanged; step3 live fullProfileV2/original16/
independent acceptance incomplete; formalstep4 not started. Docker authority/
Linux/native/P2/publicProfileV2/provider-v3/twoissuer broker+general/
PostgreSQLgeneral/9bindings64barriers/oldlocks/reuse stay held. Existing
miseGo1.26.8/-p2/cache/publicproxy recipe remains, no kernelquota/networkexclusion
claim, globalinstall, unrelatedprocess intervention or quota/deadline expansion.
TimersOFF.

The earlier [receipt-file source CPU attribution](audits/product-phase-6-slice-6-startup.md#2026-10-23-receipt-file-source-cpu-attribution)
naturally passes the complete retained-profile operation in3.526027s/90s.
The three local reports take0.791644s,0.169803s and0.453769s; all exit0/reaped,
with empty stderr and no timeout/signal/truncation. Complete120 direct,
2170 source/locks,74 tool sources and the old149-file archive pass pre/post
checks. Local HEAD/upstream089eac50dc8a4a16c0aaa1b1a3eb85f86b384fe1 is clean0/0.
No Go test, new profile, project build, Docker or host observation runs.

Root cumulative1.67s resolves to Lstat1.65s and lexical/Clean20ms.
File cumulative2.60s receives a sample edge from VerifySlice6EvidenceBundle;
root-call1.67s, ancestor/file Lstat280/90ms,Open420ms,ReadAll100ms,
Dir10ms and graph Close30ms remain rounded overlapping CPU samples.
Graph weights are not invocation counts, wait time, measured savings or the
cause of the earlier full-race timeout. Unsampled checks remain necessary.
No production optimization is accepted: dynamic filesystem checks cannot
be cached as immutable computation; small lexical samples do not justify
extra code. Diagnostic artifact UID/GID/link checks are not invented as
existing application helper assertions.

Original lines-v1 remains FAILED2.666709s: its first pprof exits0/0.969017s
but the absolute-only parser refuses the correct repository-relative source
header; later reports do not run. A separate0.816133s after-failure closure
does not pass that identity. Independent correction review permits only the
two complete exact path spellings, with every source line still byte-matched.
Corrected18 parser/refusal methods pass0.048450s/30s; old16/failure originals
remain. An unexecuted draft with wrong branch/artifact names is blocked before
a precisely corrected executor and full new identity receive independent review.

Next independently inspect this same retained profile's bundle/canonical-decode
source and callers, preserving early duplicate/type/unknown/trailing/canonical/
digest/content and every public-entry refusal. No change is approved here.
Private evidence: slice6-receipt-file-cpu-lines-20261023-114816.
The required fullrace remains **FAILED600.014672s**; no rerun or fresh pass.
Phase6 stays **5/15**: step1 historical bounded E unchanged; step2 ongoing;
step3 live full Profile-v2/original16/independent acceptance incomplete;
formalstep4 not started. Docker authority/Linux/native/P2/publicProfileV2/
provider-v3/two-issuer broker/general/PostgreSQLgeneral/9bindings64barriers/
oldlocks/reuse stay held. Existing miseGo1.26.8/-p2/cache/public-proxy recipe
remains; no kernel-quota or network-exclusion claim, expanded quota/deadline,
installation or unrelated process intervention. TimersOFF.
This is the precommit source record; actual reviewed commit/push and full
local/upstream/live disposition will be recorded separately, not preclaimed.

The earlier [receipt-bundle targeted CPU diagnostic](audits/product-phase-6-slice-6-startup.md#2026-10-23-receipt-bundle-targeted-cpu-diagnostic)
naturally passes its original shared90s batch in40.124208s. The exact
TestSlice6ReceiptBundleRejectsCrossRunAndTampering parent and all seven children
pass, with37 complete JSON events, one package PASS and a new shuffle seed.
The parent also retains raw/index/path/permission/scenario/cleanup assertions;
eight outcomes do not mean only eight business checks. No fixture or Go source
changes. The old full-repository race remains **FAILED** at600.014672s.

The target command takes38.628149s, flat pprof0.989787s and cumulative pprof
0.220421s, all natural0/reaped with empty stderr and no signal, timeout or
truncation. Shared90s includes root preparation, test, complete artifact retention
and both local pprof commands. Full input/Git/environment pre/post checks keep
their original separate bounds; this is not a whole-operation90s guarantee.
Complete2170 source/lock,74 tool-source,105 direct,three helper and two module
pins and clean local HEAD1ca31bcea10e11bd350e77956a2d5443394f2565 checks pass.
Recorded upstream0154f0de708d35a49978858552c788432524a85a remains one commit behind;
that is frozen local identity, not proof of current remote synchronization.

Exactly two outputs remain: cpu.pprof40914B and phase6security.test16424322B.
Same held FDs bind root0700->02700->0700, generated0644/0755->retained0600,
unchanged full bytes/hashes, UID/GID/single-link identities and seven ACL checks.
The existing1MiB/16MiB thresholds are observed caps, not kernel quotas or proof
against a hostile same-UID writer. New18 offline refusal methods naturally pass
in0.159219s/30s, including old16 and actual old39-case stream refusal.
An initial preexecution plan was blocked for stale top-level bootstrap/root
metadata before any Go command; its original remains. Corrected v2 inputs
received independent approval, without code changes or replaying a failed run.

The profile spans33.60s with22.48 sampled CPU seconds (66.91% as reported by
pprof). It covers this test process including race/runtime, not builder or host
CPU. Global cumulative rows show VerifySlice6EvidenceBundle7.29s,
VerifySlice6Evidence3.71s, Decoder.Decode2.74s,
readPrivateSlice6ReceiptFile2.60s and absoluteSlice6ReceiptRoot1.67s.
Rows overlap: do not add them or call them caller-exclusive cost, measured saving,
CPU saturation, IO/swap cause or an explanation of the earlier600s failure.
The historical unprofiled27.21s is a different context, not a controlled comparison.

Next independently review bounded source-line/caller inspection of this retained
profile for private-file/root checks, without rerunning tests. Identify dynamic
filesystem checks versus repeated same-call computation before proposing any
equivalent change. Preserve every public entry, root/file identity, symlink,
ownership/mode/replacement, EOF/hash/canonical/content refusal; do not cache
evidence across calls or assume alias stability. No optimization is accepted here.
Private evidence: slice6-receipt-bundle-cpu-20261023-111347.

mise Go1.26.8/GOMAXPROCS2/-p2/umask022 and existing module/cache/index recipe
remain; concurrency flags are not kernel quotas. Public GOPROXY remains capable
of fetching missing modules; no network-exclusion or no-implicit-download claim.
No full-repository rerun, Docker/runtime scenario, global installation, unrelated
process intervention, quota/deadline expansion or reuse-rule change occurs.
Phase6 stays **5/15**: Slice6step1 historical bounded Guest E unchanged; step2
ongoing; step3 live full Profile-v2 inventory/original16/independent acceptance
incomplete; formalstep4 not started. Docker authority/Linux/native/P2, public
ProfileV2/provider-v3 holds, broker/general-only/PostgreSQL general,
nine bindings/64 barriers and old locks/evidence remain. TimersOFF.
This source record freezes the precommit checkpoint. Actual reviewed commit/push
and full local/upstream/live disposition will be recorded separately; no successful
remote synchronization is preclaimed.

The earlier [retained race-timeout analysis](audits/product-phase-6-slice-6-startup.md#2026-10-23-retained-race-timeout-action-analysis)
completes one independently reviewed offline operation naturally in10.902611s/90s,
including full input/local-Git pre/post checks and22 passing synthetic tests.
No Go test, build, Docker command, fresh host observation or network operation
runs in this analysis. The required full-repository race remains **FAILED** at
600.014672s; its213 received package records do not provide a causal timeline.

Original logs independently yield182 tested and31 no-test records, an exact
package/status prefix of the historical267-record success. On the recorded
two-action-worker model, conservatively subtracting1ms per displayed duration,
the received test-action intervals imply a necessary span of at least524.019s;
the same historical prefix gives330.2395s and the old complete run373.476s.
These are conditional action-span lower bounds, not CPU use, full-command elapsed,
remaining budget or proof of a cause. Never splice old suffix durations into
this run. Go's ordered/buffered output leaves54 historical names without received
results; none is thereby proved unstarted, hung or failed.

The largest displayed intervals include phase6security345.135s (old191.013s),
controlstorage56.678s (22.065s) and qualificationadapterprotocol47.310s
(19.987s). Multiple packages increased in different run contexts; no controlled
regression is established. No old process CPU/stacks/profile, actual PID timeline
or compile/queue timings exist in these records. Installed Go1.26.8 source ties
the displayed duration to the last test execution attempt through preformatting,
including post-Run buffer handling and rounding; it is not exact process CPU/wall.

Next prepare an independently reviewed exact-case CPU diagnostic for
TestSlice6ReceiptBundleRejectsCrossRunAndTampering, whose retained earlier
single-package trace reports27.21s. Current source repeats full bundle
verification across seven named envelope mutations and further raw/scenario/
cleanup refusal paths. Retain every assertion and fixture; collect complete
test events plus the existing exact-two-artifact CPU profile/binary under the
original90s batch and unchanged tool/cache/resource settings. This is a proposal,
not an executed or admitted diagnostic, and success would not explain the old
full-run timeout. New controller/target refusal tests, identity and complete
inputs require review before execution.

All2170 source/lock pins, three preanalysis progress docs,28 direct inputs,
three helpers and both sealed228/333-file checkpoints pass complete pre/post
checks. Content differences from the old successful source are only two added
and two changed phase6tls files; that does not establish build/runtime/environment
equivalence. The earlier focused93 outcomes and vet remain their recorded
same-Go-source evidence; no new full-suite pass is claimed. Private evidence:
`slice6-race-timeout-analysis-20261023-094817`.

Phase6 remains **5/15**: step1 historical bounded Guest E unchanged; step2
ongoing; step3 live full Profile-v2 inventory/original16/independent acceptance
incomplete; formalstep4 not started. Docker authority/Linux/native/P2,
public ProfileV2/provider-v3 holds, broker/general-only/PostgreSQL general,
nine bindings/64 barriers, old locks and reuse rules remain. mise/Docker only;
no quota/deadline expansion or unrelated process intervention. TimersOFF.
Prior0154 source push naturally succeeded and one postpush query observed it;
the later final live query and a separate readonly attempt failed. Do not claim
latest remote equality from local tracking alone. This document freezes the
precommit analysis checkpoint; a separately reviewed Git stage will record actual
commit/push and final local/upstream/live disposition.

The earlier [CRL drain source checkpoint with a full-race timeout](audits/product-phase-6-slice-6-startup.md#2026-10-23-crl-close-errors-and-single-budget-drain)
is an unaccepted intermediate source checkpoint. It fixes three independently
reproduced guard defects: discarded Close errors,
remaining peers omitted after a partial failure, and fresh authority restoring
readiness while an old socket is still closing. The old-source three-test command
naturally failed in2.751586s; its original failure remains preserved.

One guard-wide batch claims identities under the admission lock and runs Close
outside that lock with at most16 workers. The first real monotonic close deadline
is shared across the same call and concurrent joins; it may shorten, never renew.
A Close error or deadline permanently fails the guard and claims the remaining
peers within that batch. Pending closure refuses Ready/Track/fresh authority
commit; synchronous Registry.Forget cannot erase an uncertain closing identity.
Successful ordinary source-loss/expiry closure may recover only after a fresh
verified pull. Existing budget derivation and the8192 total identity cap remain.

Focused race naturally passes93 test outcomes (including children) and2 packages
in9.596221s/90s, with382 complete JSON events and no failure/skip.
The required final default-tag repository race **FAILED** at its original600s
limit (actual600.014672s, owned process group killed/reaped). Its16430B stdout
contains213 complete package records:182 ok and31 without tests, including
phase6tls5.488s, connectiondrain2.642s and phase6security345.135s. The remaining54
names in the old267-package list have no received result; this does not prove
which tests ran, stalled or failed. No cause is established and no full rerun occurs.
Final vet naturally passes in4.631769s. All2170 source/lock and direct/Git
pre/post checks pass. Focused/vet have no timeout, truncation or active signal;
the failed full race is neither a pass nor replaced by the old095 checkpoint. mise Go1.26.8,
GOMAXPROCS2/-p2 and childumask022 remain; concurrency flags are not kernel quotas.
These are component/development gates, not live Vault/Guest/Provider evidence.

If16 arbitrary Close calls never return, the17th stays queued: it is not proved
physically closed. The guard retains uncertainty and rejects admission; cleanup
may continue on the original pool after failure, without converting it to success.
New tests release their owned blockers and verify cleanup, no retry and bounded
concurrency. No old receipt, manifest, lock or reuse rule is overwritten.

Next independently analyze this full-race timeout's retained output and any
available process evidence, then propose a discriminating bounded diagnostic;
do not blindly replay the whole repository or reuse this failed identity. Private evidence:
`slice6-crl-close-budget-20261023-085001`.
Phase6 remains **5/15**: step1 historical bounded Guest E unchanged; step2
ongoing; step3 live full Profile-v2 inventory/original16/independent acceptance
incomplete; formalstep4 not started. Docker authority/Linux/native/P2, public
ProfileV2/provider-v3 holds, broker/general-only with PostgreSQL general, nine
bindings/64 barriers and old locks remain. mise/Docker only; no quota/deadline
expansion or unrelated process intervention. TimersOFF.
This source record freezes the precommit checkpoint. Stage commit/push and full
local/upstream/live SHA equality are recorded separately after actual
synchronization checks.

Historical same-call evidence checkpoint: [same-call evidence Profile validation checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-23-evidence-same-call-profile-validation)
passes the required default-tag repository race and vet on the final reduced
Go source. Slice6Evidence.Validate uses a private observation check immediately
after FinalGate fully validates the same unchanged Profile. Independent transitive
alias review found no intervening writes; every public observation, decode and
evidence entry retains complete validation. This is same-call validation, not
cross-call evidence reuse or protection against concurrent alias writers.

New tests preserve inputs, reject rehashed unsafe public reentry and retain eight
observation-domain refusals with an independently valid final Profile. Earlier
focused57 pass covers the same production/test logic; the final full race naturally
passes in407.273025s under600s with267 complete package records (229 ok,38 without
tests), including phase6security191.013s. Final vet naturally passes in4.932974s.
Full2168 source/lock and direct/Git pre/post checks pass; no timeout, truncation or
active signal. Final Go scope is two production files plus one test file.

The attempted old/new benchmark comparison remains **FAILED**: equal851443-byte
lengths had different corpus hashes. No measured latency/allocation benefit is
accepted; only one redundant Profile.Validate is structurally removed. Temporary
benchmark/fixture changes were withdrawn. Old failures, a blocked unexecuted
baseline wrapper and prelaunch preparation refusals remain private originals.
This success does not explain or retrospectively pass older timeout identities.

Next independently review CRL close-error/partial-drain handling under one existing
total budget. Private evidence: `slice6-evidence-profile-validation-once-20261022-125628`.
Phase6 stays **5/15**: Slice6step1 historical bounded Guest E unchanged; step2
ongoing; step3 live full Profile-v2 inventory/original16/independent acceptance
incomplete; formalstep4 not started. Docker authority/Linux/native/P2, public
ProfileV2/provider-v3 holds, broker/general-only with PostgreSQL general, nine
bindings/64 barriers, old locks and reuse rules remain. mise/Docker only;
no quota/deadline expansion or unrelated process intervention. TimersOFF.
At this precommit checkpoint, stage commit/push are pending. Record full
local/upstream/live SHA equality only after actual synchronization checks.

Historical evidence-decoder checkpoint: [Evidence-decoder optimization review](audits/product-phase-6-slice-6-startup.md#2026-10-22-evidence-decoder-optimization-review)
completes read-only pipeline analysis with **no accepted production change**.
Three local lists of the retained profile finish naturally in1.015508s under
the original shared90s; no test, benchmark, project build or new profile runs.
Exact VerifySlice6Evidence source rows attribute3.87s to duplicate scanning,
2.27s to typed Decode,0.47s to canonical Marshal and3.33s to equality/full
validation. These are old sampled CPU costs, not fresh wall-time or saved
budgets. Recursive scanner-list11.58s counts repeated frames and is not unique
CPU; global5.74s Decode/2.41s Marshal include other callers.

Independent review rejects moving duplicate scanning later because early
duplicate large inputs would incur extra decode/serialization work. A digest
copy change is deferred: the entire append+SHA line sampled20ms, with no measured
allocation benefit. Keep byte limit, early duplicate scan, unknown/type/trailing
refusal, exact canonical equality and every public semantic/digest check.
Complete2167 source/74 tool source and129-file retained archive pre/post
verification passes;77 old direct inputs remain current, while3 superseded
progress docs retain byte-matched old copies and separate current pins.

Next independently audit whether Slice6Evidence.Validate can avoid the second
same-call Profile.Validate in observation validation after FinalGate succeeds,
proving no intervening slice/map alias mutation and retaining full validation at
every public entry. No implementation of that candidate is approved here.
Prior full race stays **FAILED**; unchanged-source vet is historical and no
whole-suite run is repeated. Private evidence: `slice6-evidence-decode-analysis-20261022-122648`.
Phase6 remains **5/15**, Slice6step2ongoing, step3/formalstep4 incomplete; all
existing holds, locks, nine bindings/64 barriers and reuse rules remain. TimersOFF.
Stage Git synchronization is checked separately.

Historical inventory CPU checkpoint: [Evidence-inventory CPU attribution](audits/product-phase-6-slice-6-startup.md#2026-10-22-evidence-inventory-cpu-attribution)
completes one fresh exact-test CPU diagnostic in **51.520068s** under the
unchanged shared90s. TestSlice6EvidenceRequiresCompleteClosedInventory and all
38 children pass (39 test outcomes plus one package PASS); the natural test
command takes49.617583s and the two local pprof commands1.214565/0.300383s.
The complete stream has161 JSON events/42273B with no skipped/failed test,
truncation, active signal or timeout. Seventeen new synthetic parser/gate refusal
tests pass; old41 tests cover only unchanged generic guard behavior, not this
new target. Full2326 pin references (2325 distinct paths), including2167 original
source/locks and74 tool sources, and actual Git pre/post checks pass. No source,
assertion, module/cache/index or evidence-reuse rule changes.

The fresh held root stays02700 while producing exactly cpu.pprof/phase6security.test,
then changes through the same FD to0700 after natural complete test success;
both original files tighten to0600 with full bytes unchanged. Seven ACL checks
pass; final profile52335B/binary16387570B are below the unchanged1MiB/16MiB
observed thresholds. These are bounded observations under the private same-UID
premise, not kernel quotas, proof of no transient or production authority.
The profile covers43.87s with32.25 sampled CPU seconds. Flat race helpers lead:
__tsan_read6.28s/19.47%, racecall3.37s/10.45%, racecalladdr2.38s/7.38%.
Cumulative VerifySlice6Evidence is9.94s/30.82%; the global cumulative row for
rejectDuplicateMembers is3.87s/12.00%. Slice6Evidence.Validate3.32s/10.29% and
Profile.Validate2.65s/8.22% also overlap. Do not add cumulative rows or treat this
as compile/mise/host CPU, swap attribution or old full-race cause. New43.68s test
reporting versus prior28.09s is not a controlled regression/speed comparison.

Next read-only and independently examine duplicate scanning, typed decoding and
canonicalization in VerifySlice6Evidence for a provably equivalent optimization,
preserving duplicate/unknown/trailing/canonical and every public-entry rejection;
no optimization is implemented or accepted yet. The prior full race stays
**FAILED**, and prior same-source vet remains valid without another whole-suite
or vet run. Evidence: `slice6-evidence-inventory-cpu-20261022-112148`, private and
outside Git. Phase6 remains **5/15**, Slice6step2ongoing; step1 historical E unchanged,
step3 live inventory/original16/formal review incomplete, formalstep4 not started.
Docker authority/Linux/native/P2, public holds, two issuers/PostgreSQL general,
nine bindings/64 barriers and old locks remain. Timers stay off. Reviewed normal
progress-doc commit/push and fullSHA synchronization are recorded separately.

Historical race-frontier checkpoint: [Streamed race-frontier diagnostic](audits/product-phase-6-slice-6-startup.md#2026-10-22-streamed-race-frontier-diagnostic)
passes one fresh phase6security single-package race/shuffle/count1/-v identity
in 359.789372s under the unchanged 600s/1MiB bounds. Its 196771B stdout and
empty stderr contain 185 top-level outcomes: 179 PASS, 6 SKIP; including children,
1148 PASS and 6 SKIP, with one package ok at356.268s. No pending names or partial
line remains; natural0/reap, constant reception metadata and complete2167 source/
lock plus actual Git pre/post checks pass. Nineteen offline observation/parser
refusal tests pass; a separate pre-execution launcher SyntaxError remains recorded.
The first stdout receive bound is4.031167s, not exact startup/build time or CPU.
The prior full race remains **FAILED**. Its111 received outcomes exactly match
an older267-package success prefix, whose next historical item is phase6security;
156 historical entries were unreceived, not proved unrun or stuck, and the
current whole-repository package count was not newly enumerated. Fixed Go orders
plain multi-package summaries and buffers package output. New single-package
-v provides test-level evidence without replaying the old capped JSON identity.
Early received controlstorage/dockercontrol/desktopcandidate report114.529/
69.779/22.952s versus historical34.977/36.625/3.930s; these parallel package times
cannot be added as wall time or identify a host/source cause. Current slowest
tests report28.09s for complete evidence inventory,27.21s for receipt-bundle
cross-run/tamper refusal and25.31s for PostgreSQL peer-CRL owner/pinned decoding.
Next independently review exact-test CPU attribution for the28.09s case under
the existing90s diagnostic boundary, preserving all assertions and artifact guards.
This new run proves neither the old full-race cause nor absence of deadlock;
source, order and execution context must not be conflated. Evidence:
`slice6-race-frontier-20261022-102125`. No product Go, locks, cache/index or reuse
rules changed. Existing same-source vet remains valid; no whole-suite or vet
rerun is claimed. Phase6 stays **5/15**, Slice6 step2 ongoing; step1 historical
bounded E unchanged, step3 live inventory/original16/formal review incomplete,
formal step4 not started. Docker authority/Linux/native/P2, public holds,
two-issuer policy and nine bindings/64 barriers remain. Timers stay off; normal
progress-doc Git synchronization is checked separately.

Historical network-plan checkpoint: [Same-call network-plan validation](audits/product-phase-6-slice-6-startup.md#2026-10-22-network-plan-same-call-validation)
is an **unaccepted interim checkpoint: required full race remains FAILED**.
BindSlice6DesiredNetworkPlan now fully validates its input draft and rewritten
output once each, reducing successful top-level Profile.Validate calls from
18 to 2 while retaining every domain check and complete validation at every
public entry. New tests check full input preservation, unsafe reentry after
rehashing and rejection of a rewritten output that loses a reciprocal network
association. Identical race benchmark samples show median ns/op -84.02%,
allocated B/op -86.03% and allocs/op -77.81%; these are descriptive synthetic
results, not peak RAM, end-to-end latency or old-timeout causation.
A new informative JSON identity passes the same nine top-level/23 child tests
and one package PASS naturally in 14.860998s under 90s; its 18 private refusal
tests pass. The first focused run remains FAILED at 90.103202s, despite test
PASS lines without package completion. Full vet passes in 27.874392s. The new
full race reaches the unchanged 600s boundary (actual 600.672669s), is actively
terminated/reaped and fails; 111 received package outcomes do not establish
all-package success or identify the unfinished test. All 2167 fixed source/lock
pins match; mise Go1.26.8, GOMAXPROCS2/-p2, child umask022 and cache/index recipe
remain. No failed identity is rerun. Evidence:
`slice6-network-plan-validation-once-20261022-083637`. Next independently narrow
the unfinished full-suite work using existing receipts and an informative bounded
observation, without another blind full run. Close-error/partial-drain handling
remains open. No live Vault/Guest/three-Provider/final16 acceptance follows.
Docker authority/Linux/native/P2, public ProfileV2/provider-v3, two issuers,
PostgreSQL general, nine bindings/64 barriers, old locks and evidence-reuse
rules stay. Phase6 remains **5/15**, Slice6 step2 ongoing, step3 incomplete,
formal step4 not started; timers stay off. Normal interim Git synchronization
is recorded separately from validation.

Historical CPU diagnostic checkpoint: [Targeted CPU profile](audits/product-phase-6-slice-6-startup.md#2026-10-22-targeted-cpu-profile).

One independently reviewed exact-test diagnostic passes in **75.914772s**
under the unchanged shared 90s. Go naturally exits 0 in 71.236237s, all 16
test run/pass pairs and one package PASS are complete, and both local pprof
commands pass naturally. Runtime names stay restricted to the original two;
only after verified success does the held 02700 root tighten to 0700 and
the two held files to 0600, preserving bytes. Seven ACL checks and all
73 direct/3 helper/2 module plus 2166 source-lock/74 tool-source inputs pass.
The combined 41 refusal tests pass; the separate first startup-timeout
failure is preserved. No third-name refusal is observed, with the original
non-atomic observation limits intact. Sample duration is 52.38s with 32.09
sampled CPU seconds: race helpers lead flat cost, while Profile.Validate has
8.70s/27.11% cumulative cost. Cumulative paths overlap; this is not a wall-time
breakdown, improvement claim or explanation of the historical full-race
timeout. The full gate remains FAILED, without another whole-suite run.
Next independently audit same-call repeated validation in BindSlice6DesiredNetworkPlan,
preserving distinct snapshots and public-entry validation. No product code,
locks, cache/index or reuse rules changed. Phase6 stays **5/15**, Slice6 step2
ongoing, step3 incomplete, formal step4 not started; timers stay off. Normal
checkpoint Git synchronization is checked separately.

The earlier [private copy-root fixture](audits/product-phase-6-slice-6-startup.md#2026-10-22-private-copy-root-fixture)
passed its filesystem prerequisite without running Go:

One independently reviewed private filesystem fixture passes in 0.060627s.
The new root retains FD/path/device/inode/UID/GID while changing
0700 → 02700 → 0700; rwx permissions remain owner-only. Two tiny new files
have no privilege bits and retain bytes through root tightening, then tighten
0644/0755 → 0600. Eight bounded ACL observations and 35 direct plus three
helper input checks pass. All 24 offline refusal tests pass; a separate initial
zero-test discovery failure is retained. No Go or pprof ran. The fixed Go
CopyFile branch is supported by source, but its actual execution/I/O budget,
CPU hotspots and old full-race timeout cause remain unproved. Next integrate
this configuration into the private controller and independently review final
code/tests/fresh inputs, preserving runtime exact-two names and original
limits. No product code, lock, cache/index or reuse-rule change. This provides
neither hostile same-UID protection nor production authority. Phase6 remains
**5/15**, Slice6 step2 ongoing, step3 incomplete, formal step4 not started;
prior full-race failures remain FAILED and timers stay off. Git synchronization
is verified separately.

The earlier [artifact-refusal observation](audits/product-phase-6-slice-6-startup.md#2026-10-22-artifact-refusal-observation)
retains its failed Go result and original evidence:

This run's rejection is now tied to the actually observed extra name
`phase6security.test-go-tmp-umask`, absent after leader reap. Its listing inode
and bound root identity are retained privately. The scan was untruncated but non-atomic; it does not prove a creator,
refusal-time full metadata or the older failure's cause. The exact name matches
the fixed Go tool's umask probe. The diagnostic remains **FAILED** at19.196845s:
Go exit-9/active termination and reap, no timeout or stream truncation. There
are69 complete JSON events,16 test passes and one package PASS; command failure
still prevents pprof, and hotspots remain unknown. All21 private refusal tests
pass and2166 source/lock pins remain consistent with the clean f483 baseline.
Independent review blocks production-time third-name acceptance, so it is not
implemented. Next review the fixed tool's existing copy branch with a precise
private execution configuration preserving runtime exact-two names and access
permissions; that alternative is not implemented or admitted. No Go source, lock, quota, deadline, cache/index or reuse-rule change.
Phase6 stays **5/15**, Slice6 step2 ongoing, step3 incomplete, formal step4 not
started; old full race stays FAILED and timers stay off. Git synchronization
is separate from diagnostic/validation results.

The earlier [targeted synthetic-v2 CPU diagnostic](audits/product-phase-6-slice-6-startup.md#2026-10-22-targeted-synthetic-v2-cpu-diagnostic)
remains FAILED at25.428686s without a package terminal or saved refusal names;
this new run does not retrospectively supply those missing observations.

The earlier [bounded race-timeout investigation](audits/product-phase-6-slice-6-startup.md#2026-10-22-bounded-race-timeout-diagnosis)
remains FAILED at its1MiB stdout boundary, with151 top passes/5skips and no
package terminal. Its measured costs motivated this focused investigation;
neither failure has been retried or retrospectively converted to a pass.

The earlier [2026-10-22 same-call peer-CRL validation checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-22-peer-crl-same-call-validation)
is an **unaccepted interim checkpoint: full validation remains FAILED**.
PeerCRLSources now uses the existing private final-profile verifier after its
same-call entry Profile.Validate, removing one duplicate validation on the
unchanged snapshot. Complete final-graph/nine-owner, ordinary/DNS/purpose and
source checks remain; both public entries still revalidate every call. New
refusals rehash both Profile and Sources bindings before rejecting unsafe
root/privilege settings and accepting the original input again. Existing
race benchmark samples show median allocated bytes -43.95% and allocation
count -33.83%, but median ns/op is 29.1% slower with a wide range: no latency
improvement or previous-timeout cause is proved. Focused race passes in
84.742314s under 90s; full vet passes in 56.586027s. Required full race reaches
its unchanged 600s boundary (actual 600.034008s), is actively terminated/reaped
and **fails**. Its 111 received package outcomes do not establish full success
or identify a stuck test. All 2166 fixed source/lock pins match; existing
mise Go1.26.8, -p2/GOMAXPROCS2 and test umask022 remain. Evidence:
`slice6-peercrl-validation-once-20261022-032759`. Earlier f46 local/upstream/
live synchronization is confirmed separately; this checkpoint's normal Git
synchronization is checked separately from validation. No new runtime,
Vault/Guest/three-Provider or final 16-scenario gate runs, and old candidates do not
inherit changed source. Close-error/partial-drain handling remains open.
Docker authority/Linux/native/P2 and public ProfileV2/provider-v3 holds,
two-issuer policy, PostgreSQL general, old locks, reuse rules and budgets
remain. Phase 6 stays **5/15**: Slice 6 step 1 historical bounded E unchanged,
step 2 ongoing, step 3 incomplete, formal step 4 not started. Timers stay off.

The earlier [2026-10-22 observed CRL expiry checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-22-observed-crl-expiry-checkpoint)
implements a source-level fix independent of Docker management authority,
but full validation is **FAILED**, so this is an unaccepted interim checkpoint.
After a forward wall-clock jump, Ready/Track now invalidate expired evidence
and drain old connections under the original total close budget. They share
one locked transition, advance the first observed expiry watermark and stop
the old timer. Fresh signed pulls, including genuinely fresh in-flight pulls,
can recover ordinary expiry; clock rollback remains latched. Old-source
regressions fail; fixed phase6tls/connectiondrain race passes in 6.849086s and
full vet passes in 5.311936s. The required full race hits its original 600s
limit (actual 600.011412s), is actively terminated and fails. Its 111 completed
package results do not establish full success or locate the timeout cause.
No failed identity is retried. Tested Go/lock bytes match; existing mise
Go1.26.8, -p2/GOMAXPROCS2 and test umask022 remain. Evidence:
`slice6-crl-observed-expiry-20261022-093433`. Close-error/partial-drain handling
remains a separate open source gap requiring a single-budget design. No live
Vault/Guest/three-Provider or final16 gate runs; old candidates do not inherit
changed source. Docker authority/Linux/native/P2 and public admission holds
remain. Phase6 stays **5/15**: Slice6 step1 historical E unchanged, step2
ongoing, step3 incomplete, formal step4 not started. Guards, quotas, deadlines,
issuer policy and reuse rules stay fixed; timers remain off. Next independently
locate the full-race timeout before another justified validation identity.
Normal interim commit/push and full SHA synchronization are checked separately.

The earlier [2026-10-22 late-tracking revocation observation](audits/product-phase-6-slice-6-startup.md#2026-10-22-late-tracking-revocation-observation)
closes a source-level live-role CRL monotonicity gap independent of Docker
management authority. A zero-peer poll could install a revoked CRL between
a good handshake and Track; Track rejected that peer without retaining the
observation, allowing a later higher-number CRL to omit the unexpired serial.
Track now retains the verified revoked serial and certificate NotAfter through
one bounded helper shared with refresh and Poll, and advances the guard's
live clock watermark. The original 8192-entry
cap, including repeated-serial refusal at capacity, stays fixed; capacity
failure drains through existing Close after unlocking. Expired observations
can still retire, and ordinary source-loss recovery is unchanged. Old-source
regressions fail; fixed focused race passes. This stage's full race/shuffle/
count1 passes 267 package outcomes in 582.757202 seconds under the original
600 seconds; full vet passes in 3.901219 seconds. Tested Go/lock bytes match,
with existing mise Go1.26.8, -p2/GOMAXPROCS2 and test umask022. Evidence:
`slice6-crl-track-revocation-20261022-082700`. Test PKI, pipe EOF and synthetic
capacity fixtures are component evidence only; old candidates do not inherit
changed source. Docker authority/Linux/native/P2 and public admission holds
remain. Phase6 stays **5/15**: Slice6 step1 historical bounded E, step2 ongoing,
step3 incomplete, formal step4 not started. Guards, quotas, deadlines, issuer
policy and reuse rules stay fixed; timers remain off. Git sync is recorded
separately.

The earlier [2026-10-22 admission clock rollback](audits/product-phase-6-slice-6-startup.md#2026-10-22-admission-clock-rollback)
closes another source-level mTLS/CRL gap independent of Docker management
authority. Track previously rejected a backwards clock without latching the
failure, while Ready latched it without draining existing connections. Both
now latch under the admission mutex and reuse the existing Close after
unlocking, stopping the expiry timer and draining under the original budget.
Old-source regressions fail for both entry points; fixed focused race passes,
including unchanged/forward-clock controls. This stage's full race/shuffle/
count1 passes all 267 packages in 420.862909 seconds under 600 seconds, and
full vet passes in 3.627552 seconds. The two Go files and existing locks match
the tested snapshot. Development remains mise Go1.26.8 with -p2/GOMAXPROCS2
and test umask022. Evidence: `slice6-crl-track-clock-20261022-074336`.
These are component checks, not live Vault/Guest/three-Provider or final
16-scenario acceptance; old candidates do not inherit the changed source.
Docker authority and Linux/native/P2 remain HELD. Phase6 stays **5/15**:
Slice6 step1 historical bounded E, step2 ongoing, step3 incomplete, formal
step4 not started. Original guards, quotas, deadlines, issuer policy, public
holds and evidence-reuse rules remain; timers stay off. Stage Git sync is
verified separately.

The earlier [2026-10-21 CRL source-loss connection admission](audits/product-phase-6-slice-6-startup.md#2026-10-21-crl-source-loss-connection-admission)
closes a source-level TLS/CRL gap independent of Docker authority: a peer
whose handshake preceded source loss could register afterward using old CRL
evidence. Track now rejects unavailable state under its registration mutex.
Old-code regressions fail; fixed focused race and a real-TLS component pass.
The new full race/shuffle/count1 run completes all267 packages in564.207446s
under600s; full vet passes in53.924708s. Source/locks match, mise Go1.26.8,
-p2/GOMAXPROCS2 and test umask022 remain. A prior offline module-lookup failure
is preserved; normal official Go dependency restoration does not change the
final verifier's offline recipe or sealed caches. Evidence:
`slice6-crl-late-track-20261021-232634`. No real Vault/Guest/three-Provider,
Docker or final-topology gate follows. The earlier
[management-authority gap](plan/product-v1-phase-6-pbs-alternative-observation.md#2026-10-21-management-authority-evidence-paths)
and Linux/native/P2 holds remain. Phase6 stays **5/15**: Slice6 step1
historical bounded E, step2 ongoing, step3 incomplete, formal step4 not started.
Original guards/limits/reuse rules stay; timers remain off. Stage Git sync is
checked separately.

The earlier [2026-10-21 real Docker metadata screen](plan/product-v1-phase-6-pbs-alternative-observation.md#2026-10-21-real-docker-metadata-screen)
completes one reviewed read-only `/info` then `/version` identity. Both return
complete HTTP200 in0.043382/0.004288seconds under the unchanged3-second request,
64KiB wire and8KiB header bounds. All2875 input rows and old aliases match
before/after; the final pre-flush marker is1.950375seconds with outer natural0
under the original90-second parent. The actual Authorization value is **null**,
kept distinct from missing, empty and nonempty; it proves neither endpoint
identity nor management exclusivity. Raw HTTP is not retained and cannot be
independently reparsed. New26 execution-binding mocks pass; the earlier shell
redirection failure remains recorded, with no results attributed to that identity.
Evidence: `docker-metadata-readonly-20261021-191746`. The old reader bytes are
unchanged in a new bound location and both output roots are outside sealed
checkpoints. No Docker CLI, credential access, host admission, container,
build, scan, native observer or P2 runs. Next independently establish a concrete
management-authority/injection-control evidence path before any executor
qualification. Product code, old locks and all existing guards remain; no
Go/Contract rerun is claimed. Timers stay off. Phase6 remains **5/15**:
Slice6 step1 historical bounded E only, step2 ongoing, step3 incomplete,
formal step4 not started. Stage Git synchronization is checked separately.

The earlier [2026-10-21 metadata mock checkpoint](plan/product-v1-phase-6-pbs-alternative-observation.md#2026-10-21-bounded-mock-harness-checkpoint)
passes27 harness refusals and the unchanged17 original mock cases through new
reviewed identities, with complete35/53-row pre/post checks retaining the
original nine exact inputs. Both runs naturally exit0 under the same10-second
parent/64KiB bounds; final pre-flush markers are0.452756/0.379147seconds.
A class-shaped socket guard fixes an intervening `ssl` import failure, whose
raw failed identity remains unchanged. The earlier9.38-second delay is still
unexplained; these new timings do not attribute its cause. Evidence:
`metadata-unit-budget-20261021-100906`. This is private mock component evidence
only: no real daemon request, host admission, native observer, P2, build or
scan runs. A new complete metadata execution identity and actual inputs still
require review; never run a reader that writes into a sealed checkpoint.
Product code/old locks are unchanged; no Go/Contract rerun is claimed. Timers
stay off. Phase6 remains **5/15**, Slice6 step2 ongoing, step3 incomplete,
formal step4 not started. Stage Git synchronization is recorded separately;
these component results do not establish that local commits reached the remote.

The earlier [2026-10-21 alternative observation assessment](plan/product-v1-phase-6-pbs-alternative-observation.md)
rejects a direct Darwin-to-Docker substitution. A separately qualified Linux
prevention design is conditional only: daemon-side process injection, subsequent
exec, network rejection and full timing/identity proofs remain open. The new
private metadata probe is not executed. Its independently reviewed17-case mock
identity fails the original10-second parent, returning no test results or
complete post-input receipt; it is not retried or counted as passing. The
metadata screen and both real executor routes remain **HELD**. Evidence:
`pbs-linux-observation-feasibility-20261021-152922`. All old evidence and guards
remain; unchanged product component evidence is reused, with no Go/Contract
rerun. Reviewed design/progress documents follow normal commit/push; no native
observer, host admission, container, build, scan or real P2 starts. Timers stay
off. Phase6 stays **5/15**; Slice6 step2 ongoing, step3 incomplete, formal step4
not started.

The earlier [2026-10-21 immutable XNU discovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-xnu-immutable-discovery-held)
accepts official metadata only. The named `xnu-13432.` tag-prefix query is
empty; the observed `main` commit's unsigned API message names XNU12377.1.9,
which cannot substitute for the target13432.1.9. Six requests produce five200
responses and one complete404 for immutable `config/MasterVersion`; no source
is decoded. The complete nonrecursive root tree has21 entries and an unvisited
`config` subtree; it neither resolves that404 nor authenticates current ABI.
These routes do not establish global source absence. Actual dynamic pointers
are independently reviewed;10-second/1MiB request limits remain unchanged.
The new31+26+16 private reader tests pass, without product/formal acceptance.
Exact source, native census/ABI and P2 remain **HELD**; no host admission,
native call, build, scan or container starts. Evidence:
`xnu-immutable-discovery-20261021-123142`;17 old sealed checkpoints and1954
initial inputs remain preserved with explicit current-document overlays.
Only four progress documents change; unchanged product tests are reused by
impact, and no Go/Contract rerun is claimed. Normal reviewed commit/push,
original guards/budgets and disabled timers remain. Phase6 stays **5/15**;
Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 Apple release mapping check](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-apple-release-mapping-gap)
accepts four bounded official metadata responses, not exact current-platform
source provenance. Apple's HTML loads an embedded release catalog; its complete
script lacks macOS27.0.1/26A434/XNU13432.1.9 literals. Separately retrieved
distribution tag pages contain166 unique tags without macos27. This does not
prove global official-source absence; macOS26/XNU12377 cannot substitute.
Source-only parents naturally exit0 in3.045703/8.712990seconds, with complete
raw headers/bodies and1732/1763 full inputs exact before/after. The private
reader's27 plus11 focused tests pass. Exact source recovery, native/ABI/census
and P2 remain **HELD**; no host gate, build or scan starts. Evidence:
`xnu-release-mapping-20261021-103210`;16 prior sealed trees and1690 initial
rows remain preserved, with current document versions explicitly overlaid.
Four reviewed progress documents follow normal commit/push. Old failures,
guards, budgets and disabled timers remain. Phase6 stays **5/15**;
Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 native API source discovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-native-api-source-discovery-held)
records macOS27.0.1/26A434, arm64, Darwin27.0.0 and `xnu-13432.1.9~1` through
an independently reviewed0.093355-second metadata read. Two separately reviewed
official GitHub routes fail404: first exact-tag source0.715244seconds, then
distinct tag-root metadata2.123506seconds; the remaining3 source requests never
start. Failures are retained without retry, substitution or relaxed limits.
The error bodies are not captured by the unchanged reader; status/headers alone
do not prove global official-source absence. Native ABI/provenance/zombies/
coherent census remain **HELD**. Only the fixed `os.uname` platform read runs;
no libproc observer or process-group enumeration API, host gate, P2, build or
scan runs. Evidence: `pbs-native-api-evidence-20261021-095856`. All15 old sealed trees
and1552 prior inputs remain exact. This documentation checkpoint also records
the user's prelaunch policy: no redundant historical-code compatibility paths;
existing trust, Contract, review and evidence gates still apply. Private
evidence stays outside Git, unchanged tests are reused by impact and timers
stay off. Phase6 remains **5/15**; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-21 PBS source closure and observation review](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-pbs-source-closure-and-observation-review)
independently accepts all3 fixed missing source files and their raw HTTP/blob
proofs. Requests finish in0.781880/0.979875/1.100053seconds within the original10s
limits; parent naturally finishes in2.941195seconds and1520 input rows remain
exact before/after. This is source-only acceptance, not actual eight-case P2.
The [observation plan](plan/product-v1-phase-6-pbs-process-observation.md) has a
conditional CWD design; native group census remains **HELD**, requiring official
provenance/ABI/coherence and a corrected before-reap supervision chain.
No native API, host/Cosign case, build or scan starts; old prepared inputs and
failures remain unchanged. Evidence: `pbs-source-closure-20261021-092647`.
Four progress/readme updates and one new plan follow normal commit/push;
private evidence stays outside Git, unchanged code reuses49 component tests,
original gates stay and timers stay off. Phase6 stays **5/15**; Slice6 step2
ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 strict PBS diagnostic components](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-strict-pbs-diagnostic-components)
add strict original-bundle post-policy, complete candidate frames, no-follow
full-input guards and bounded sequential orchestration with refusal tests.
The final component suite passes49 tests. A separately reviewed0.079128-second
metadata-only read binds the retained certificate's SAN/issuer candidates;
neither it nor synthetic tests prove signatures or real eight-case acceptance.
The new prepared identity is **HELD**, pending three fixed-source edges and
concrete reviewed outer/host/boot/network/supply/group-census implementation.
No host/Cosign case, archive/SDK recovery, build or scan starts. Evidence:
`pbs-controller-20261021-082537`. All13 sealed checkpoints,1137 old rows/9aliases
and original limits are preserved; failures are not reclassified. Nine new
component/test/readme files and three progress documents follow normal
commit/push; private evidence stays outside Git and timers stay off.
Phase6 stays **5/15**; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 Cosign entry recovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-cosign-attestation-source-restored)
closes the missing source edge: the exact13636-byte entry is recovered through
one new reviewed Contents identity in1.335761seconds; nine direct dependencies
also match their fixed Git blobs. One intervening raw10-second failure is kept;
its separately reviewed new Contents identity succeeds within the original
bound. The source
path now connects local explicit root, keyless identity, digest/predicate checks
and refusal before legacy fallback. Independent review accepts an eight-case design that
retains25-second leaf/90-second total bounds, full source/input/provenance checks
and original fresh dual-host readiness. Design/source recovery is distinct from
implementation or actual verification: P2 remains unstarted pending strict
controller/refusal tests and new complete execution-input review. Evidence:
`cosign-attestation-entry-20261021-002703`. The prior10-second failures remain;
1061 input rows/9aliases and12 sealed checkpoints are exact. Only three progress
documents change and follow normal commit/push. No host/Cosign/archive/SDK/native
build/scan or timer starts. Phase6 stays **5/15**; Slice6 step2 ongoing,
step3 incomplete, step4 not started.

The earlier [2026-10-21 Python/SDK prerequisite review](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-python-sdk-authentication-prerequisites-held)
independently accepts 14 exact fixed-version source files and a conditional
authenticated-target-use analysis. Two source-only batches each finish 7/8;
the same missing Cosign attestation entry times out at the unchanged 10-second
limit through two official paths. Failures are retained without identity retry
or further endpoint requests. Actual verification remains **HELD** until that
entry and complete execution inputs are source-bound and independently reviewed.
All 27 selected compiler/ABI inputs and 264 Python headers/5 directories match;
retained bundles remain unverified, Python archives and the original signed
Apple SDK installer are absent from the inspected recovery materials. The
accepted good TUF target is pinned to its limited frozen-chain acceptance.
No host sample, Cosign/Python/SDK verification, build or scan starts. Evidence:
`python-sdk-auth-20261020-235600`. All 1031 old input rows, 9 aliases and 11
sealed checkpoints remain exact. Only three progress documents change and
follow normal commit/push; private evidence and disabled timers are preserved.
Phase6 stays **5/15**; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 frozen TUF four-case pass](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-frozen-top-tuf-four-case-chain-passes)
passes the original host gate at23:26:44/23:27:50 Asia/Shanghai: both base/Mach
samples pass,65.846674seconds has1253 swapin pages and zero swapout. Fixed
Cosign actually executes all four cases; independent joint review accepts
**4/4 only for this new frozen top chain**. Three exact mutations are rejected;
unchanged good authenticates four roles and all11 target bytes. All31 bounded
captures are natural/reaped,1031 complete input rows match before/after/current,
and eight old sealed checkpoints remain intact. Evidence:
`tuf-fourcase-resume-20261020-232404`. Old0/4 failures stay failed; strict parser
fields and modern partial root14 files do not become standalone authority.
No syscall-read13, official-latest/rollback/delegation, archive/SDK/native or
product acceptance is claimed. Next independently review downstream concrete
target consumption and candidate provenance with existing gates unchanged.
Only three reviewed progress documents follow normal commit/push; no source,
limit/cache/index/reuse change, new material, build/scan or timer starts.
Phase6 stays **5/15**; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 dual-host paging recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-dual-host-recheck-rejects-both-paging-deltas)
reviews a new928-input identity with all825 prior rows/9aliases and approved
implementation unchanged. At09:43:52/09:44:58 Asia/Shanghai, both base CPU/load/
memory-pressure samples and first Mach pass. Over65.930274seconds, swapin rises
71339 16KiB pages (1114.671875MiB), exceeding32pages/second, and swapout rises
95336 pages (1489.625MiB), exceeding zero. The second guard correctly rejects;
second Mach/readiness/TUF are unstarted, still0/4. All25 bounded captures are
natural/reaped, with928 input rows exact before/after/current and seven old
sealed checkpoints preserved. Future role expiry is time-only. Evidence:
`tuf-fourcase-resume-20261020-094023`. No retry, gate/limit/cache/index/reuse/
toolchain change, new material, build/scan or timer starts. Three reviewed
progress documents follow normal commit/push. Phase6 stays **5/15**; Slice6
step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 dual-host interval recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-dual-host-recheck-rejects-interval-swapin)
independently reviews a new identity with825 full inputs; prior722 rows/9aliases,
approved source and four mirrors remain unchanged. At09:29:40/09:30:46
Asia/Shanghai, load3.47/3.01, top idle79.37%/75.52% and free40%/33% pass;
the first Mach observation also passes. The65.817397second interval has6131
swapin pages (95.796875MiB), exceeding32pages/second, with zero swapout.
The second guard therefore rejects before Mach; no TUF case starts, still0/4.
All25 bounded receipts are natural/reaped without signal/truncation/timeout;
wrapper exit0 does not grant readiness. All825 input rows match before/after/
current and six old sealed checkpoints stay exact. Role freshness is time-only,
not cryptographic acceptance. Evidence: `tuf-fourcase-resume-20261020-092705`.
The failed identity is retained without retry; original complete dual readiness
and four-case unchanged-good joint review still precede TUF acceptance.
Three reviewed progress documents follow normal commit/push. No gate/limit/
cache/index/reuse/toolchain change, new external material, build/scan or timer
starts. Phase6 stays **5/15**; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-20 source-bound host recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-source-bound-host-recheck-stops-before-tuf)
uses a new independently reviewed identity and722 full inputs, retaining all610
old rows/9aliases/four mirrors and the unchanged approved implementation. Role
expiries remain future as a time check only. At08:58:05 Asia/Shanghai, load3.60
and free40% pass but top idle46.22%<60% rejects the first guard. No Mach check,
second sample, paging interval or TUF case starts. All13 bounded receipts are
natural/reaped without signal/truncation/timeout; the host wrapper's exit0 is
not a readiness pass. All722 input rows match before/after/current, and five
old sealed checkpoints remain exact. Evidence: `tuf-fourcase-resume-20261020-085244`.
Retain the failed identity without retry; original dual readiness and actual
four-case unchanged-good joint review still precede TUF acceptance. No new
external material, build/scan, gate/limit/cache/index/reuse/toolchain change or
timer starts. Three reviewed progress documents follow normal commit/push.
TUF stays0/4, Phase6 **5/15**; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-20 strict four-line capture policy](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-strict-four-line-capture-policy)
implements exact fixed-version warning/error frames and full target hash errors,
with strict bounded natural receipts and no negative stdout. New private caller
glue observes no-success facts before parsing and preserves target/post/good
authentication checks. Independent component verification passes96 repository
and18 adapter/unaffected tests, plus17 isolated historical baseline tests.
Old D4 raw is a format fixture only; its failure and TUF0/4 remain unchanged.
No new host/TUF case or execution lock is created; original fresh source/input,
host/supply/isolation gates and four-case unchanged-good joint review remain
required. All610 inputs/9aliases/four old checkpoints match. Evidence:
`tuf-fourline-policy-20261020-083751`. Three tool files and three progress
documents follow normal commit/push; private evidence remains outside Git,
limits/Go1.26.8/cache/index/reuse rules and disabled timers remain unchanged.
Phase6 stays **5/15**; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 util/log source correspondence](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-util-and-standard-log-source-correspondence)
closes the two source gaps: util confirms13.root.json and complete hash errors;
static inline metadata plus verified CUE0.16.1 source identifies init's global
log.SetFlags(0). Nineteen original10second-bounded requests restore18 source/module
files and one tree. The final private36 metadata/8 module tests pass; the static
observation takes1.323606seconds. Failed identities and drafts stay preserved.
Source correspondence is not D4 execution or mutation-versus-good proof; TUF
remains0/4. The conditional four-line repair includes full expected/got hashes;
concrete parser/refusal implementation and an original-gated new four-case run
remain pending. All610 inputs/9aliases/three sealed checkpoints match. Evidence:
`tuf-source-gap-20261019-151705`. No new Cosign/host/TUF/build/scan/container or
repository tests, toolchain/limit/cache/index/reuse changes or timer starts.
Phase6 remains **5/15**; Slice6 step2 ongoing, step3 incomplete, step4 not started.
Only reviewed progress documents follow the standing normal commit/push rule.

The earlier [2026-10-19 client/error source recovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-fixed-cosign-client-and-error-source-recovery)
verifies27 source/module files and two updater trees. The modern14 cache,
legacy12 memory/DB bootstrap, root-rotation thresholds, success-only disk sync
and two error emitters now have exact-version source support. Three original
10second-deadline requests fail and are preserved; util naming/hash-format
source and global log-flag attribution remain incomplete. D4 actual13 read
and mutation-versus-good causality are unproved, so its0/4 is unchanged.
The reviewed repair is conditional; no parser/fixture/root changes, host/TUF
execution, test/build/scan or timer follows. Evidence:
`tuf-source-recovery-20261019-133746`. Phase6 remains **5/15**; Slice6 step2
ongoing, step3 incomplete, step4 not started. Only reviewed progress documents
follow the standing normal commit/push checkpoint rule.

The earlier [2026-10-19 fixed Cosign static root investigation](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-fixed-cosign-roots-and-causality-held)
identifies legacy embedded root12 and modern embedded root14; D4's cached root
matches modern14 exactly. Initialization source calls modern then legacy, but
complete client/updater source and an accepted unchanged good remain missing:
D4 root13 consumption and mutation/refusal causality are unproved. Three
original10second source requests fail, are preserved, and network stops.
Independent review covers the static observation and conditional repair plan;
no implementation, new host/TUF run, test/build/scan or timer follows. Private
evidence: `tuf-bootstrap-readonly-20261019-130227`. TUF remains0/4, Phase6 **5/15**;
Slice6 step2 ongoing, step3 incomplete, step4 not started. Progress documents
follow the standing stage commit/push rule.

The earlier [2026-10-19 host pass and TUF diagnostic](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-host-gate-passes-tuf-root-attribution-held)
passes the original dual-host gate during20:45:13/20:46:18 Asia/Shanghai:
load2.01/1.85, top idle88.18%/77.96%, free38%/42%, both Mach checks and
65.717408seconds with105 swapin pages/zero swapout. Only TUF `bad-root13`
starts; CLI exit1 has four stderr lines rather than the parser's expected
three. That case fails the diagnostic, the other three do not start and the
accepted result is0/4. An unverified cached root v14 also leaves mutation-v13
causality unproved; error wording alone is not a cryptographic negative pass.
Next review the fixed CLI bootstrap/update paths and the strict parser/case
proposal before new execution. All610 inputs/9aliases/four mirrors remain
exact. No implementation change, retry, scan/build or timer occurs. Evidence:
`tuf-chain-resume-20261019-124329`. Phase6 stays **5/15**; Slice6 step2 ongoing,
step3 incomplete, step4 not started. Progress follows the stage commit/push rule.

The earlier [2026-10-19 two-sample recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-two-sample-recheck-refuses-interval-paging)
passes both base CPU/load/memory samples but fails original interval paging.
At19:57:03/19:58:09 Asia/Shanghai, load is1.02/1.36, top idle82.61%/87.99%
and memory free33%/33%. Over65.723560seconds, swapin+4112 pages (64.25MiB)
exceeds32pages/second and swapout+1456 pages (22.75MiB) exceeds zero. The first
Mach check passes; the second is not reached. No TUF case starts. All512
locked files,9aliases and four mirrors remain exact; independent identity/input
review precedes this one attempt, and the failed identity is retained without
retry. Private evidence: `tuf-chain-resume-20261019-115426`. This is a dated
observation, not a process attribution or current host guarantee. Frozen tests
are reused, no build/scan/new external material or timer runs. Phase6 remains
**5/15**; Slice6 step2 is ongoing, step3 incomplete and step4 not started.

The earlier [2026-10-19 local source checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-local-source-checkpoint-and-held-tuf-chain)
records three local batches: source/tests/tools/candidate records, design/audit
history, then that checkpoint's progress update. All2148 Go and2390 non-document
files match the previously validated source set and SHA256; the503.355-second
race `-p=6`, vet and two Contract passes are historical same-source evidence,
not new runs. No build or full test suite is started on the constrained host.
At that checkpoint's last actual sample,14:53:30 Asia/Shanghai, load5.15/free31% pass but
CPU idle35.65% fails the original60% floor. No second sample or TUF case starts.
The25 new same-boot tests pass only as component evidence; timestamp812 is
still unverified. Old locks, raw evidence, public holds, quotas/deadlines and
disabled automation remain intact. Local commits are not formal Slice6 step4
or remote publication. Phase6 remains **5/15**; Slice6 step2 is ongoing,
step3 is incomplete and step4 is not started.

The earlier [2026-10-15 interval readiness recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-interval-readiness-recheck-keeps-native-apk-held) confirms the original DB remains fresh at that dated observation and both37/19 raw scan reports match, reused without rescanning. Three manual samples87.190/78.641seconds apart retain the same Docker daemon and all27 calls pass, but continuing large swap deltas and load28.44→20.16→16.79 fail whole-host stability. Native Alpine APK execution remains unperformed in that checkpoint; no new container execution plan is admitted. Installation/GPG helpers remain separately held. Evidence: `gpg-native-recheck-20261015-102127`. Existing mise/Docker, limits and deleted automation remain unchanged. Phase6 remains5/15, Slice6 step2 ongoing; steps3/4 remain incomplete/not started. The dated DB freshness is not current supply admission.

The earlier [fresh DB and scan checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-fresh-vulnerability-db-and-scans-with-native-execution-held) restores and authenticates the complete official Trivy v2 DB layer. New scans recognize all37 Alpine proposal package/source/PURL records and all19 packages of the exact signed Wolfi carrier, with zero findings. The proposal result is metadata coverage, not installation or final GPG/Node admission. Six interval host samples retain the same Docker daemon, but swap activity continues; the final load is17.47 and the5second CPU sample fails. Native Alpine APK execution stays held. Installation and GPG helper paths require their own concrete independent review; existing RO/noexec/UID boundaries are unchanged. Earlier manifest/range/scan-precheck failures remain recorded. Private evidence: `gpg-db-native-20261015-094855`. Existing mise/Docker, quotas/deadlines, old locks/candidates and deleted automation remain unchanged. Phase6 remains5/15, Slice6 step2 ongoing;15 outputs and ENOSPC/OOM remain unverified.

The earlier [Docker/readiness checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-docker-restored-native-admission-still-held)
confirms the existing desktop-linux Docker daemon has returned: five interval
samples retain the same daemon/platform/version, with all15 ping/version/info
calls successful in13.14–34.17ms. Host load/CPU improve, but continuing swap
activity prevents accepting stable whole-host readiness. The previous DB
expired at2026-10-15T01:19:20Z; a reviewed new official metadata request fails
at the unchanged10second TLS connection bound. No DB layer/import/new scan or
native APK/install/GPG/container/compiler execution occurs. Original failures
are preserved without further retry, alternate source or relaxed limits. Independent
review also identifies an unresolved installation path under RO root/noexec
work/tmp: skipping scripts or adding an executable writable root is not
acceptance. Existing mise/Docker, old locks/candidates and deleted automation
remain unchanged. Evidence: `gpg-native-readiness-20261015-093139`. Phase6
remains5/15, Slice6 step2 ongoing;15 outputs and ENOSPC/OOM remain unverified.

The earlier [Alpine GPG dependency/prescan checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-alpine-gpg-dependency-materials-and-proposal-prescan)
restores the37 fixed-index proposed APK originals and passes their limited
signature/control/data correspondence (36 new OS crypto checks plus exact old
GPG evidence reuse). A full37-package/source/PURL metadata prescan reports zero
findings with the unchanged fresh DB. This is a proposal prescan, not actual
installed/full-image/embedded coverage or GPG/Node execution admission. Static
ELF audit visits133 regular files/55 ELF and152 edges, retaining one SQLite
RUNPATH as unresolved; installation/trigger/helper effects and mtab's runtime
mount remain open. The existing Docker context still names the missing same
socket; no container/candidate/compiler executes. Original transfer and v3
parser failures are preserved. Existing mise/Docker, quotas/deadlines, old
candidates/locks and deleted automation remain unchanged. Evidence:
`gpg-alpine-closure-20261014-1006`. Phase6 remains5/15, Slice6 step2 ongoing;
15 outputs,2637 exports and ENOSPC/OOM repair remain unverified.

The earlier [Alpine GPG key/source/data checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-alpine-gpg-key-source-and-signature-data-checkpoint)
binds the exact publisher key through official same-record pages and its fixed
mirror recipe, restores all12 GPG source originals with matching recipe SHA512,
and passes a reviewed9-process/2-datahash cryptographic data diagnostic using
the existing Apple-signed OS tool via mise Python. Original APK/index signatures
match; wrong-key/control/signature and data-only tampering reject. Full inputs
and tools match before/after. This is not native apk compatibility, full supply
or GPG/Node execution admission; no source/build reproduction is claimed. Host
load falls to2.53 in one sample, but the expected Docker socket is absent and
all three API calls fail. No container/compiler runs. Next review complete
dependencies/ELF/helpers and fresh coverage, then actual native/candidate gates
when the same daemon is ready. Evidence: `gpg-alpine-authority-20261014-0848`.
Old inputs/limits and deleted automation remain intact; Phase6 remains5/15,
Slice6 step2 ongoing, with15 outputs and ENOSPC/OOM repair still unverified.

The earlier [GPG replacement-material checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-gpg-replacement-materials-and-renewed-host-pressure)
retains an Alpine edge/aarch64 gpg2.5.22-r0 APK and the same declared commit's
official aports mirror recipe. All12 source tokens correspond to12 SHA512
declarations (GNU archive,10 patches,1 rules file); those12 originals are not
yet fetched or verified. The APK contains a signature member, but signing-key
authority, actual verification, index/dependency/source/ELF closure, fresh full
coverage and a qualified carrier remain open. The public wolfi2.4.9-r11 bytes
match the earlier authenticated CGR index, but lack a standalone signature;
the exact recipe is not yet obtained or verified, and that execution-candidate
route is stopped. No GPG,
Node, container or compiler executes. Host load again exceeds250 in a saved
read-only sample; a fast single Docker ping does not establish stable readiness.
Evidence: `gpg-verifier-candidate-20261014-0704`. Old candidates/locks and all
limits remain intact; automation remains deleted. Phase6 remains5/15, Slice6
step2 ongoing;15 outputs and ENOSPC/OOM repair remain unverified.

The earlier [APK verifier and GPG source checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-native-apk-index-verification-and-gpg-source-gaps)
restores the five missing wolfi layers and five GPG raw packages. The fixed
wolfi carrier has full signed-assembly correspondence,19/19 fresh APK scan
coverage with zero findings, and an independently reviewed narrow native APKINDEX
run: original signature passes; wrong-key and modified-index cases both reject
with BAD signature. Isolation, input checks and exact cleanup pass. Two earlier
runtime failures remain failures. A subsequent static31-package GPG proposal
records file overlaps, unresolved loader/installation semantics and missing
patch originals; its diagnostic completion is not GPG admission. Two anonymous
queries of the exact publisher source commit/recipe return404. GPG, Node and
compiler execution remain held; the previous Node HIGH rejection is unchanged.
Evidence: `gpg-supply-tls-recovery-20261014-0442`. Automation remains deleted;
Phase6 remains5/15, Slice6 step2 ongoing.

The earlier [vendor-signed Node/GPG checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-vendor-signed-node-and-gpg-chain-checks)
verifies eight new index/native signature and attestation checks for each of the
free Node and wolfi-base candidates. The smaller Node image has28 APKs with
zero findings, but complete161-package installed-JS coverage still reports the
same http-cache-semantics4.2.0 HIGH; it is rejected. Node embedded coverage
remains open. wolfi-base has five missing layers after a measured TLS handshake
timeout, so its full static/scan and APK-verifier admission are unperformed.
Gpgconf and five missing library APKs are now retained as unverified raw inputs;
npth transfer also fails at the unchanged TLS connection bound, and four further
packages are not attempted. APK/index signatures and the GPG verification chain
remain incomplete. No candidate/container/compiler executes. Old locks and
candidates stay intact; automation stays deleted. Evidence:
`node-minimal-gpg-chain-20261014-0343`. Phase6 remains5/15, Slice6 step2.

The earlier [Node/verifier alternative checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-node-and-verifier-alternative-candidates)
rechecks the fixed signed carrier and finds zero vulnerabilities in75 APKs, but
an independently reviewed supplementary scan recognizes all163 installed JS
packages and reports one HIGH in npm's http-cache-semantics4.2.0. The full
carrier remains rejected; upstream's dispute does not waive the current gate.
Node26 is investigated only for the generator controller, not the locked Node22
UI. Its18-node ELF closure and source-locator SBOM are bound, but embedded
component coverage remains incomplete. The replacement gpg2.4.9-r12 raw APK
and embedded recipe are available; gpgconf transfer fails at the original25s
bound, and index/APK signatures, dependency admission and source review remain
open. No candidate/container/compiler executes. Host samples also show continued
swap activity. Old candidates/locks remain intact; automation stays deleted.
Evidence: `node-tool-alternatives-20261014-0253`. Phase6 remains5/15, Slice6 step2.

The earlier Node tool supply checkpoint completes static source/archive/ELF
identity checks and a nine-package scan of the proposed OpenPGP verifier, but
admits neither the verifier nor Node22.23.3. The verifier registry check fails
on argon2id1.0.1's expired signing key; zero scanner findings do not replace it.
The actual Node release signature and complete core/native/bundled/dynamic
library vulnerability coverage remain open. Upstream OpenSSL3.5.8 additionally
matches a newly recorded HIGH advisory. Independent review finds DTLS is not
disabled in the saved arm64 configuration; JS API reachability is unproved,
which does not satisfy the existing zero-HIGH gate. No candidate
Node, compiler or container executes. The15 outputs and ENOSPC/OOM repair remain
unverified, with quotas/deadlines unchanged and automation deleted. Evidence:
`node-tool-supply-20261014-0207`. See the
[static supply checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-node-tool-static-supply-checkpoint).

The earlier2026-10-14 continuation prepares a reviewed three-stage cache
diagnostic and passes29 Node host fixtures plus9 Python decoder tests; no
container/compiler executes. Fresh Trivy DB data is recovered by validating31
saved ranges and fetching one missing4MiB range, but candidate scans remain
unperformed. Independent review identifies unresolved signed-release and
complete vulnerability coverage for the actual Node22.23.3 tool. Close that
supply boundary before constructing/reviewing the v10 controller. Final2637
exports,15 generated outputs and ENOSPC/OOM repair remain unverified; existing
quotas/deadlines and deleted automation are unchanged. Evidence:
`vault-generator-staged-cache-20261014-0128`. See the
[generator plan](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-staged-cache-preparation-execution-remains-held).

Historical generator evidence follows; its runtime successes do not admit v10.

The complete CE dry-run binds15 commands and offline module verification passes
after restoring467 authenticated graph metadata records. The first bounded
Docker attempt times out before actual generation; its input-postcheck timeout
and exact cleanup remain recorded. The complete986-module root scan retains
16 HIGH findings, and full UI remains blocked by an unfixed braces HIGH and
unsupported Ember5.8. The latest v3 run times out during OCI load in90.548seconds
without creating a container; exact cleanup passes, but the560-second wrapper
also interrupts final input checking. A separate full-input recheck passes
in248.239seconds; neither runtime failure is accepted. High post-failure host
load and a read-only Docker query timeout call for a lower-load diagnostic window.
The subsequent lower-load v4 OCI import succeeds in10.159seconds, but the
10-package Docker dry-run hits60.063seconds; no export/generation executes.
A v5 SIGQUIT diagnosis returns no stack at its60.029-second failure. Both
complete original full input pre/postchecks and exact cleanup. After the user's
manual readiness request, v6 captures17637 untruncated stack bytes and deliberately
interrupts dry-run at55.069seconds. Its171.237-second failure completes full
input pre/postchecking and precise cleanup; no export/enumer executes. The
single stack shows module-index directory traversal and package-load waiting,
not a proven complete timeout cause. The cancelled heartbeat remains off.
The reviewed private `goindex=0` follow-up passes exact15-directive dry-run in
15.938seconds, then fails real compiler exports with ENOSPC in76.486seconds.
Its separate2637-package metadata comparison matches, but clean exports and
generation remain unproved. No enumer executes; full input pre/postchecks and
exact cleanup pass. Next independently review the bounded scratch/cache storage
repair; do not enlarge quotas or repeat the same failure. The full158.554-second
failed run is retained in `vault-generator-index-fallback-20261013`.
A later v8 measurement locates1GiB /work byte exhaustion with plentiful
inodes. The reviewed v9 DWARF-off recipe still fails in172.604seconds, now with
475 direct ENOSPC and one compiler signal-killed error plus cgroup OOM kill.
Dry-run6.977seconds passes; real export109.725seconds is rejected, with0 actual
generated outputs. Complete inputs,15 old target bytes and exact cleanup pass.
Evidence is `vault-generator-scratch-20261013-1404` and
`vault-generator-scratch-recipe-20261013-1436`. Additional runtime attempts stop;
next review a concrete same-run cache/stage capacity and memory plan under the
original aggregate deadlines and final actual-export/output gates. No such
recipe is yet approved, and no automation is restored.
Vault15 output verification, full build and real issuance/
command composition remain open. Phase6 stays5/15; Slice6 steps1/2/3/4 remain
historical bounded E / ongoing / incomplete / not started. This is component
evidence, not acceptance.

The fixed first-version P2.7 plan is **24/24 complete**, and the public
independent external-caller plan is **13/13 complete**. There are no remaining
steps in either fixed plan.

Final hosted qualification run `35203241121` executed Provider revision
`170459266af5f4fad359ca8c63f2ae19741055c5` and caller revision
`b3ebcc783e5db20395e29b029e0eb55f7819b49b`. All 15 initial and 5
reconstruction scenarios passed, all 91 required observations matched, and
the exact run-owned resource scope returned to zero across three stable
samples.

Artifact `10488622806` binds checkpoint
`sha256:ce8394c3f0213f89bfb01be027016bcbeb272a24c014030a9bc8007d9ab7536f`,
seven-file archive
`sha256:ada1cae128a41e6b694ff413aab179c0eff94b42663ece8233dbb358e319e9bd`,
and result envelope
`sha256:d5e6fd528f2302252a38f49aa466c85767106a8bcef430120f230a8127f96758`.
The report is `passed`, validation is `accepted`, and the bounded disposition
is `qualified`.

Documentation baseline `27081dfde4dfc726ba4df06d1f3b50012a04d2f2` passed
core CI `35204434771`. The qualification and CI results apply only to their
recorded Contract/profile, revisions, artifacts, topology, and scenarios.
Aggregate conformance, other callers or profiles, multi-controller operation,
hostile multi-tenant isolation, HA, deployment, and production readiness
remain separate non-claims.

Product v1 architecture Phase 1 is separately complete as design and Product
Contract-definition evidence. It adds no implemented Product service,
persistence, public Gateway, Guest Agent, deployment, capability readiness, or
SLO-attainment claim.

Product v1 Phase 2 is complete for its fixed nine-step scope. Implementation
revision `98995384c60a924f25ca58d3b7e561207bfa5be8` is selected by
lock-selection revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`. The
clean-VCS 60-case local Suite, full root and E2E gates, tagged Docker lifecycle
integration, and repository-owned independent-process 15+5+9 reference run
pass. This does not add a separately implemented external-caller,
multi-controller, deployment, hostile-multitenant, or production-readiness
claim.

Product v1 Phase 3 is complete at **13/13** for its fixed standalone scope.
Slices 1-12 provide the Product authority, API, locked network-only Provider
adapter, control/Terminal/Gateway, Guest/Files, transfer/revision, secure Web,
catalog, and recording components. Slice 13 implementation
`04c2755bec125db7e2c04df3f4e2f8cfedb6ec1d` and run
`20260918T111903.806694000Z` compose four separate role processes with fresh
pinned PostgreSQL and pass the exact nine-scenario restart, fault, security,
data-plane, and cleanup matrix. The retained manifest is strict-valid. This is
same-repository standalone evidence with a locked-Contract Provider fixture,
not independently implemented caller, deployment, hostile-multitenant, HA, or
production evidence.

Product v1 Phase 4 Browser is complete at **13/13** for its bounded
same-repository separate-process scope. Run `20260918T152110.677058000Z` at
source baseline `322eb342650d2ade838f1b3a24e0d5bc0bfbb3e1` passed all 12
exact scenarios through separate Product, Gateway, Provider, and Browser OS
processes with fresh digest-pinned PostgreSQL and Valkey and fresh encrypted
recording storage. The retained manifest passes strict independent validation
and records exact row, object, coordination, process, and container cleanup.
This does not establish a deployable topology, independently implemented
caller, HA, hostile multi-tenant isolation, or production readiness.

Product v1 Phase 5 Desktop has completed **15/15** dependency-ordered slices
for its bounded same-repository independent-process topology.
Slice 1 establishes only the separate Provider Desktop Contract and Go
projection authority. It selects exact Contract revision
`720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`, and a content-derived 71-case
local Suite. Slice 2 implementation
`d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00` adds Product-owned Desktop
slot/session intent, exact profile constraints, PostgreSQL migration 8,
transactional audit/outbox persistence, quotas, race closure, nondisclosure,
and restart-safe reads. Slice 3 implementation
`f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5` adds Provider-local Desktop
domain/application policy, durable memory/file authority, restart-safe and
unknown-outcome reconciliation, operation aggregation, and optional protected
handlers. Slice 4 candidate implementation
`163dd8a258a24cf4727169b1cbd8ed7c0fe29292` adds a locked dual-architecture
image definition, fixed private broker, local reproducibility outputs, passing
native arm64 smoke, and a manual native publication/provenance workflow.
Publication run `35447651328` at source
`e4a940bda6c5172a78d0dbe40963ca1a99911976` passes native amd64/arm64/v8
gates, publishes exact signed index
`sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`,
and passes fresh independent provenance and platform-matrix verification.
Slice 5 implementation `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b`
adds the Provider-local Docker adapter, durable opaque resolver, fresh
attach/reconnect, lifecycle readiness, revoke/cleanup/absence composition, and
exact Desktop duration usage. Slice 6 implementation
`2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240` adds the exact network-only
Product adapter, isolated Desktop dispatch/observation workers, retained
operation recovery, separate Product/Provider generations, and
Desktop-specific close cleanup. The real-PostgreSQL plus HTTP Provider-fixture
gate passes. Slice 7 implementation
`0649d62911abb89229de40136347286736152ec6` adds exact Desktop-only
viewer/controller admission, encrypted one-use tickets, session-scoped
controller fencing, independent viewer/controller quotas, DB-time expiry and
revocation, full-binding continuous authority checks, and metadata-only audit.
At that boundary, production startup composition, public signaling/media/input,
policy, unified Web, capability advertisement, and release evidence remained
absent.

Slice 8 implementation `040c560f3701b7c972c25f05928dd435d9f55c20`
adds the separate bounded Desktop WebRTC handler with HTTPS ticket signaling,
exact Origin, relay-only production ICE, receive-only VP8/optional Opus,
viewer/controller separation, reliable ordered fenced input, continuous grant
checks, and slow-consumer closure. Durable Desktop policy, a real Provider
media bridge, recovery, recording, production startup composition, unified
Web, capability advertisement, and release evidence remain absent.

Slice 9 implementation `24f5c741eb605614f77f8d9d546708b9993e42dd`
adds immutable versioned Workspace Desktop policy, PostgreSQL migration 11,
deny-by-default input/clipboard/transfer gates, activation and consent,
bounded metadata and `/workspace/...` paths, exact Product transfer binding,
and continuous policy-revision revocation. A real Provider media/input bridge,
reconnect/recovery, recording, production startup composition, unified Web,
capability advertisement, and release evidence remain absent.

Slice 10 implementation `f23b16130c97e99d5d28008b01346779a0c681ee`
adds a database-time Desktop Gateway lease and fresh-grant crash recovery,
exact reconnect authority/generation checks, bounded visual/audio resync and
closed display/audio-output changes, connection-epoch stale-input rejection,
and transactional grant/handoff/session/binding cleanup with deterministic
single-generation slot replacement. A real Provider media/input bridge,
recording, production startup composition, unified Web, capability
advertisement, and release evidence remain absent.

Slice 11 implementation `c5b045abc5192b76b7d615ddbb0858b998ef98d5`
adds required Desktop recording with explicit consent and visible mode,
fail-closed initialization/live-loss behavior, bounded video/audio RTP and
minimized control events, encrypted integrity-linked segments, owner-authorized
replay, quota admission, and retention deletion. Clipboard content and transfer
paths/identities remain outside recording metadata, public catalog, and audit.
A real Provider media/input bridge, development templates, production startup
composition, unified Web, capability advertisement, and release evidence remain
absent.

Slice 12 implementation `490c2db96d6ba7a851d7846bc9e5f818dae2be77`
adds immutable coding-shell development-template selection, migration 13
validated revision/development persistence, exact Guest capability/generation/
health authority, bounded content-addressed workspace materialization, and
private two-phase rollback/restart recovery. The complete fresh tagged
PostgreSQL package and focused Guest/Product fault gates pass. Private paths,
credentials, Guest IDs, and runtime coordinates remain outside stable
projections. A real Provider media/input bridge, unified Web, production
startup composition, capability advertisement, and release evidence remain
absent.

Slice 13 implementation `84698c371d35edb862ffc81b484a3e31cc8120d9`
adds the capability-derived authenticated unified Product Web/BFF for
Workspace, Terminal, Files, Browser, Desktop, and recordings. Exact Desktop
slot/session/grant profiles, same-origin WebRTC, view/control UX, visible
recording state and consent, bounded reconnect/configuration, clipboard
consent, digest-checked transfers, accessible tabs/status, and strict
CSP/Origin/CSRF/nondisclosure pass the real headless-Chrome and full repository
gates. A real Provider media/input bridge, production composition and Desktop
advertisement, composed Slice 14 security/fault evidence, and the Slice 15
independent-process release gate remain absent.

Slice 14 implementation `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d`
adds the closed private Provider-to-Product-Gateway Desktop bridge, fresh and
continuous handoff authority checks, bounded VP8/optional-Opus and ordered
control transport, and strict tuple/input substitution rejection. The real
PostgreSQL composition gate joins one-use grants, durable policy, public
WebRTC, the private bridge, fenced input, required encrypted recording,
revocation, replay/cross-origin/cross-owner denial, capacity recovery,
retention object deletion, and exact tenant-row cleanup. Full race/shuffle,
vet, both Contract verifiers, and retained Phase 3/4 evidence verification
pass. The separate Product/Gateway/Provider/Desktop/Guest process topology,
real display/control and development scenarios, strict release evidence
bundle, exact release-topology advertisement, deployment, HA, hostile
multi-tenant isolation, and production readiness remain absent.

Product v1 Phase 6 production hardening is **5/15 complete**. ADR 0051 and
the fixed plan order deployable role boundaries, production identity/storage,
secrets/KMS, network, supply chain, recovery, observability, deployment,
upgrade, adversarial, independent deployment, release-candidate and final
release gates. Slice 1 adds the independent development-only `product serve`
command, strict private configuration, real PostgreSQL startup/storage, frozen
development identities and fail-closed liveness/readiness/capability behavior.
It is source/component evidence, not a published deployment, standalone or
production qualification.

Slice 2 adds the production Product kernel with TLS 1.3, strict rotating signed
identity, separated migration/runtime PostgreSQL roles, exact schema checks,
bounded connection budgets, dependency-loss/recovery monitoring, restart, and
nondisclosure evidence. Product-to-Provider/data-plane composition remains
absent, so
`product.workspace` is explicitly unavailable and mutation remains fail-closed.

Slice 3 adds the production-only independent `provider serve` role with TLS
1.3 mTLS, exact JWS admission, a transactional PostgreSQL mutation guard and
Provider-local repositories, separated database authority, bounded recovery,
loopback-only process probes, real coding-shell/Desktop backends, and exact
single-profile capability advertisement. Real database concurrency,
pause/recovery/restart, real-process restart, coding-shell lifecycle, and
Desktop broker gates pass. This remains local role-process/backend evidence;
public data planes, deployment, HA, operations qualification, and production
readiness remain absent.

Slice 4 adds separate Gateway, Guest, Browser and Desktop processes,
Browser/Desktop executor v2 backends, a Provider-owned signed Desktop broker
mux and sealed role-specific restricted egress. Its local six-role,
twelve-scenario gate passes real Chromium/Desktop media-input, dependency
loss, reconnect, replay/capacity/drift denial, broker/executor/Provider
restart, bounded drain and exact cleanup. The Desktop OCI remains a
non-release local candidate; public Product E2E, deployment and production
readiness remain open.

Slice 5 is complete within its bounded local evidence scope. ADR 0054 fixes
canonical scoped-secret bindings, separate one-shot migration authority,
runtime material agents, Vault Transit recording keys, and credential
rotation/revocation. The immutable six-role real Vault/PostgreSQL gate and its
strict manifest pass; its local process result explicitly records
`distinct_os_uid_established=false`. Runtime revision
`c189330c5ed0aa52c60b6b85c5cd9c6b59fbef10`, evidence tool
`39fd1025f6fa838325aced711d8a024a9ce5d1b6`, and manifest digest
`sha256:e6a6fdcc299c721e1fa2c48009d98a6ca4c52d59318c507af8b68fd8596e840c`
remain the bounded acceptance identities, not deployment or HSM evidence.

Slice 6 remains open at **5/15**. The clean checkpoint
`9511b44ad2b65421d78db239bad6309f85f9ad55` passes a real Docker
component gate twice: a source-bound Vault/PKI/controller chain, Guest TLS
signer and material-agent, signed two-approval capability issue, restricted
one-shot operator delivery, online Guest consume and exact Vault KVv2 use,
then before-expiry redelivery denial with unchanged persistent ledger and
exact container cleanup. Clean checkpoint
`f18c931d0652c5c5d2e61c5e0c42460420b317a3` additionally passes a third
real break-glass controller PID1: it recovers the consumed/one-use ledger
while Guest remains online and rejects the same capability before expiry,
with unchanged revision and audit head. At that earlier checkpoint this did
not prove the formal Guest production PID1/Product security edge, all 78 live
principals, 16 frozen
scenarios, or Slice 6 release evidence. The strict final manifest has not
been issued.

The next same-run real Docker component gate additionally starts distinct
`product-tls-agent` and `product-runtime-agent-tls-agent` PID1 processes under
the frozen 50m CPU/64 MiB/16-PID limits. Each obtains its own managed leaf,
opens its subject-only signer socket, and drains with exact socket cleanup.
The Product material agent's private Profile and two-material canonical
configuration are source-bound inputs. Its independent PID1 opened both the
owner-only material and break-glass sockets under its own Vault service
network while Guest stayed live; ordered drain removed those sockets and
both Product signer sockets, and exact Docker cleanup passed. Product KVv2
identity key-ring resolution now also passes through the live Product
material-agent to a cross-UID/GID Product owner observer, after exact scoped
Vault read, cross-Guest denial and token revocation. At that checkpoint the
PostgreSQL runtime DSN and Product runtime PID1 were not exercised. The
later reviewed component in the baseline table exercised bounded runtime SQL
and live business-binding revoke, but not the complete Product/Guest edge,
full topology or release manifest; these remain open,
so the counter stays **5/15**.

The later bounded Guest recovery E component is independently accepted under
`S6-E550dba-bounded-recovery-accepted-20261005`: run
`550dba360065dce4f46fa14476225ce5` at clean E
`a065277e406bf09c4c22d4ce187e1d181e513316` and separate R/F
`e5816d0d3de0541bd9a677560096b3527f58f7b9` passed the real
Product/PostgreSQL/Guest A→B replacement, PostgreSQL loss/recovery,
post-recovery close, terminal remote revoke/complete CRL and exact cleanup.
Its private final binding digest is
`sha256:e66dc29a217c82e1ae9071b8046c33461afae8d216e488751c9a68e312549177`;
119 source-bound files and 14 convergence slots were independently verified.
The controller still reports `sticky_credential_revoke` and has **not**
proved clean drain. This closes delivery step 1 only, not the revised
Profile-v2-inventory/16-scenario Slice 6 gate, a manifest, or any release
claim; Phase 6 stays **5/15**. The private evidence root and reuse boundary are indexed in the
[Slice 6 startup audit](audits/product-phase-6-slice-6-startup.md).

The next bounded Browser application/identity-runtime subprocess component
also passed with real PostgreSQL and high-UID Docker: a new PID recovered a
finished dispatch without a second create, while an unproved network-side
effect kept Creating capacity held and denied replay/competition. Both crash
points were observed before `SIGKILL`; test-owned cleanup left no matching
Docker resources. This is not production `provider serve v3` process recovery,
every uncertain Docker outcome, the three Provider commands, or a same-run
Slice 6 scenario receipt. The audit records its limits; Phase 6 stays
**5/15**.

The later Coding retirement-barrier source and one approved real PostgreSQL
component batch passed with two independent pools in the existing disposable
pinned-container harness. The batch checked a committed retirement against
subsequent generic higher-fence/lease/terminal writes, independent JTI
consumption, same-attempt Unknown/event handling, unrelated sandbox writes,
the opposite committed-fence ordering, restart retention and the existing
final-CAS/new-occupant path. These are ordered PG observations, not a new
simultaneous cleanup-versus-mutation race or an authenticated Control result;
malformed binding and low historical fence negative cases remain pure tests.
The [Slice 6 startup audit](audits/product-phase-6-slice-6-startup.md) records
the exact run and cleanup. Full Profile v2, Control mTLS/CRL and physical
Coding deletion remain open; v3 startup is guarded and Phase 6 stays
**5/15**.

Subsequent source-only v3 work adds a Coding-specific durable atomic-original
marker/policy, an exact original-create envelope saved in the first-permit PG
transaction, a ticket-free authority dispatcher interface, and typed
Completed/Released application-to-PG observation gates. Legacy create and
local-snapshot cleanup/release wrappers reject that v3 marker; the v3
coordinator now refuses legacy Inspect/Remove/Suspend/Resume reconciliation.
The Control ledger can project receipt/revision/state digest under one lock,
but no authenticated Control OS-process client/server or full Profile v2 is
composed. The new two-pool PG component extension has since passed one
authorized repair supplement after an initial failed fixture run: it checked
atomic original, legacy/mixed-mode denial, both observed row-lock orderings,
typed PG cleanup/release with a synthetic Observer, slot reuse, restart and
exact disposable PostgreSQL cleanup. Its scope and the failed first attempt
are recorded in the [Slice 6 startup audit](audits/product-phase-6-slice-6-startup.md).
This is not Control mTLS/CRL, Coding Docker physical absence or the fixed
16-scenario gate; no Slice 6 evidence manifest or acceptance count follows.

The next Profile-v2 source checkpoint tightens all 82 provisional static
identity/TLS-delegation records and checks both Coding slot IDs, UIDs/GIDs and
six whole-volume prefixes against that static roster plus Browser/Desktop
slots. It found the isolated Coding fixture's `58000/58001` GIDs collide with
existing PostgreSQL TLS agents; corrected IDs are test-only, not production
assignments. Conservative resource arithmetic now includes all static and
one-shot roles, both Coding workloads, all declared Browser/Desktop
workload/gateway slots, five external services and double-parse headroom.
Focused race tests pass. None of these fragments is a complete typed Profile
v2, authenticated Control transport, live resource observation or Slice 6
gate; v3 admission remains closed at **5/15**.

A subsequent draft provides an independent `ProfileV2` wire type, v2-only
canonical decoder/digest and explicit Control/Scanner private scope checks.
The old v1 golden sample is unchanged and cross-version decoding fails.
No complete positive v2 candidate, Control/Scanner source-bound image,
authenticated OS process or final gate exists yet; `DecodeV2` rejects the
partial sample and `Validate` keeps a final unconditional admission hold.
Targeted race tests, vet and both Contract locks pass, while
the whole-repository race/shuffle run now passes on the initial v2/status
source snapshot. Follow-on status tests changed after that run and have
their own focused race check. Phase 6 remains **5/15**.

The v2 draft now also has a same-package synthetic complete-field positive
path with self-consistent negative mutations; the public validator and
decoder retain their final source/image admission hold. Sandbox review
identified and closed an omitted restriction on the two new TLS agents:
both must be networkless and listenerless. This remains test-only field
evidence, not actual Control/Scanner process, PKI or profile admission.

A package-private read-only Control status HTTP server draft now bounds one
Coding status route and denies plaintext, unverified TLS and claimed-header
identity before any receipt projection. Its constructor is not exported;
the actual ledger-locked bound read returns `not_found` only for a missing
record and preserves ambiguous creates as `unknown`. A real localhost TLS
1.3 mutual-certificate HTTP test passes status and write-route denial, but
uses a test-only verification hook, not Profile-v2 CRL or a Control role
command. This is a transport component boundary only, with v3 and
Profile-v2 holds unchanged.

Sandbox's reviewed v2 CRL direction keeps the existing CRL wire/digest
formats while adding explicit Profile-v2-only source, role, canonical
decoder and exact tuple-index entry points. A complete synthetic field
fixture yields all required ordinary, DNS and nine PostgreSQL-purpose
edges; missing/extra/cross-profile/cross-purpose and Control/Scanner
broker-issuer mappings reject in focused race tests. All public v2 CRL
entry points still reject behind the Profile-v2 source/image hold. The
Control status client is also package-private, bounded and read-only; its
localhost TLS test is not a real Vault CRL or production Control process.
Sandbox found and rejected an initial v2 CRL fixture that invented a third
PostgreSQL issuer. The corrected source check requires exactly the two
existing `/pki` issuers and selects broker/general by the verified peer;
PostgreSQL uses general. Focused recomputed-digest negatives pass, but
controller policy, agent and live Vault enforcement remain open. On the
corrected source snapshot, the required whole-repository race/shuffle
count-one run, `go vet ./...`, both Contract locks and diff check pass;
these do not change the Slice 6 **5/15** release state.

The 2026-10-05 computer-change checkpoint is an **interim source handoff**,
not Slice 6 acceptance or the formal post-gate step 4. The fixed delivery
sequence remains: (1) the bounded Guest E component accepted, with the full
Guest edge open; (2) remaining Provider/Browser, isolated commands, live
TLS/CRL/external and privilege edges open; (3) freeze the complete revised
Profile-v2 inventory, including Control/Scanner, dedicated agents, dynamic
Coding allocations and peak resources, then run the original 16 scenarios
with strict independent evidence review; and (4) final post-acceptance
documentation/handoff open. The old 78-deployment baseline and 82-static
Profile-v2 synthetic fixture are neither a finalized revised live inventory
nor an acceptance result. Git does not contain accepted private E/Coding
receipts, ignored `e2e/evidence/`,
local OCI candidates or credentials. Their old-host locations, hashes,
transfer/rebuild rules, destination checkout commands and remaining holds
are in the [machine handoff plan](plan/product-v1-phase-6-delivery-and-handoff.md).
The normal-push SHA comparison belongs to the handoff report after the
checkpoint commit; no new manifest, production claim or **6/15** follows.

The 2026-10-08 new-host component checkpoint adds typed v2 CRL snapshot,
Controller policy/issuer preflight, agent/guard constructors and isolated
PostgreSQL-purpose role decoding. The restored baseline is
`91fe315641779e6ea640632538309d63ad1b303f`; the current patch is uncommitted.
The user confirmed new-host single-writer ownership and separate read-only
review. Focused and final whole-repository race/shuffle/count-one checks,
vet and both Contract locks pass; tagged Docker socket checks remain blocked
by their unrestored pinned fixture image. New-host validation, the repaired
legacy-constructor downgrade and preserved failures are tracked
in the [startup audit](audits/product-phase-6-slice-6-startup.md#2026-10-08-new-host-typed-v2-crl-component-checkpoint).
The subsequent [command checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-08-v2-controller-and-tls-agent-command-preflight)
adds explicit Controller v5 and TLS-agent v5/v6 config dispatch to their
actual startup paths. Private config/receipt mount checks, public identity
and policy preflight precede inherited key consumption. The final command
combination passed whole-repository race/shuffle/count-one in 437.982 seconds,
vet and both Contract locks with unchanged Go source hashes. Public Profile-v2
and Provider v3 admission remain closed. Actual Control/Scanner business
commands, consuming-role TLS/CRL composition, source-bound role images, the
revised live inventory and all 16 formal scenarios remain open; Phase 6
remains **5/15**.

The 2026-10-09 [Control/Scanner checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-control-status-and-scanner-command-components)
adds actual canonical-stdin command entry points behind the same public hold.
Control serves only Coding status from a pre-existing ledger and now rejects
cleanup-bound queries without the exact cleanup intent. Scanner composes
fixed ClamD process supervision, immutable rule-manifest bytes and private
mTLS/CRL service; Provider-side factories supply dedicated Scanner and typed
Control status clients. This is source/component progress, not complete
Control mutation handling, Provider v3/PG composition, current signed rules,
source-to-image proof or positive live command admission. Phase 6 stays
**5/15** and Slice 6 step 2 remains open. Final whole-repository race/shuffle/
count-one passed in 625.296 seconds, followed by vet; the two Contract locks
and Linux/arm64 command builds also pass on the unchanged production inputs.
The baseline DNS-dependent migration test failure, fixture-only repair and
missing pinned ClamAV integration input are recorded in the dated audit.

The following 2026-10-09 [held Provider dependency checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-provider-v3-dependency-composition)
separates Coding v3 from the old v1 Profile/daemon-driver composition. It
adds typed v2 PG and material constructors, freezes the existing nine-owner
PG graph in the field checker, and selects the PG policy-bound repository,
status Coordinator and dedicated Scanner in a candidate command path. Both
public holds precede effects; no lifecycle Application/lease sweep or
Control Begin/Finish worker runs. Private v3 inputs reject legacy Docker and
command-scanner overrides. This is source/component evidence, not positive
v3 startup or real PG/Control/Scanner operation. Full mutation/runtime ports,
images, credentials and original same-run gates remain open; Phase 6 is 5/15.
Independent read-only review found no blocker in this scope. Final root-module
race/shuffle/count-one passed in 496.298 seconds, with vet, both Contract locks
and Linux/arm64 core compilation also passing. The actual PG nine-source HBA
check failed before resource creation because the locked local PostgreSQL
image is missing; no real PG result is claimed.

The subsequent [held Coding Control executor checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-coding-control-executor)
adds the concrete source-bound create and Completed-only cleanup path plus an
explicit mutation config for the Control command. The original status config
stays read-only. Creation consumes eight fixed write requests after durable
Unknown; uncertain responses remain occupied without retry or cleanup. Both
public admission holds remain closed. This is component progress: no Provider
mutation client/runtime ports, live factory admission, new role image or real
create/cleanup gate is established. Docker's `desktop-linux` socket was
unavailable on this attempt, so current image availability could not be
rechecked. Original authority deadlines and Phase 6 **5/15** are unchanged.
The dated audit distinguishes final source checks from this Docker blocker.

The next [Provider original-authority dispatch checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-provider-original-authority-dispatch)
adds a dedicated typed Control mutation client and selects it in the held v3
command. The PG atomic create coordinator supplies the original envelope;
cleanup uses only a fresh permit from that call's explicit PG acknowledgement.
Neither uncertain responses nor stored historical envelopes grant a retry.
The client checks the peer before and after a bounded, non-replayed request.
Successful sends remain ACKs, not PG Ready/release evidence. Both public holds
remain closed and no Application/automatic lease worker starts. Atomic
Completed-to-Ready persistence and its generic-write guard are the next
separate implementation; remaining runtime ports and real gates stay open.
This is Slice 6 step 2 source/component progress, with Phase 6 still **5/15**.
Its final full race/shuffle/count-one run passed in 535.336 seconds, followed
by vet, both Contract locks and Linux/arm64 core compilation. Independent
review found no blocker in the eight Go files. Tagged Docker observation and
real PG transactional checks failed because the Docker socket is absent;
neither positive live admission nor real PG/physical acceptance is claimed.


The subsequent [Completed-to-Ready checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-provider-completed-to-ready-cas)
adds the typed status-only readback and atomic PG completion-history/Active/
Ready commit. Original authority, current generation/fence/lease and exact
Control evidence are rechecked under the row lock. Repeated identical Ready
reads do not increment PG revision. Late/cancelled Running becomes Unknown;
an existing Unknown remains unchanged. Generic lifecycle writers cannot
manufacture readiness, successful creation, termination progress, events or
lease replacements. Normal exact terminate/lease admission and direct
Creating-to-Cleaning remain available; non-create v3 reconciliation is still
held. Released allocation evidence survives slot reuse without authorizing
the next allocation. Independent read-only review closed the identified
admission/event bypasses in all 17 changed Go files. This remains Slice 6
step 2 source/component work, with both public holds closed and Phase 6 at
**5/15**. This final snapshot passed full race/shuffle/count-one in 514.886
seconds, vet, both Contract locks and Linux/arm64 compilation. Tagged Docker
observation and real PG integration failed at the absent Docker socket;
no real Ready/cleanup/concurrency result is claimed. Next connect the existing
typed cleanup Begin/Finish to lifecycle termination reconciliation. The dated
audit records the checks, preserved failures and remaining real gates.


The [typed termination checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-provider-typed-termination-reconciliation)
connects the existing cleanup admission/dispatch and Released CAS to the held
lifecycle coordinator. A single PG snapshot selects fresh Accepted admission,
Running/Unknown recovery or an already-released terminal read. A private
retirement ACK flag can only be set from the same fresh call's successful
Control dispatch. Recovery preserves unacknowledged Running as Unknown even
when Control is Pending/Unknown/NotFound; late ACK cannot upgrade it. Neither
lost PG/Control replies nor historical intents trigger a second dispatch.
Exact release after the operation deadline or cancellation now retains Unknown
while completing observed termination and slot release; existing Unknown
is unchanged. Public holds remain closed, no automatic worker starts, and
lease/suspend/resume execution is still held. This remains Slice 6 step 2,
with Phase 6 **5/15**. Independent read-only review matched all 16 changed
Go file hashes and found no definite remaining blocker. Full race/shuffle/
count-one passed in 430.728 seconds, along with vet, both Contract locks and
Linux/arm64 compilation. Docker was now reachable and both real read-only
observations passed. The initial real PG test failed because the pinned image
was absent. After downloading only that locked platform image and passing
the existing complete OCI descriptor/layer check, the real PG transactional
test passed in 4.896 seconds, including exact cleanup. Control remains
synthetic: physical termination, live TLS/CRL and complete supply/release
acceptance remain open. The dated audit preserves both attempts and the new
input's separate identity.

The [atomic lease checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-provider-atomic-lease-completion)
adds PG-only completion to the held Coding-v3 command. New lease admission,
expiry, Succeeded, idempotency and both events commit together. Lock-time
expiry/deadline checks prevent stale admission; exact replays and historical
successful reads do not write another revision. The original allocation and
current sandbox remain distinct from a historical success result. Older
Accepted records can be completed only while their current admission is
exact; superseded, cancelled, Running or Unknown historical records are not
upgraded. No Control call, public capability, automatic worker or mutation
window is added. Final focused race tests, the real PG transactional gate,
vet, both Contract locks and Linux/arm64 compilation pass. The first full race
invocation hit the unchanged security package's default ten-minute timeout;
one full retry with serialized package scheduling (`-p=1`) passed in
1,062.257 seconds, with no timeout extension or source change. Both results
remain recorded and the initial timeout cause is unproven. All eight changed
Go hashes match final independent review. Slice 6 step 2 remains in progress
and Phase 6 remains **5/15**; the dated audit records source, PG component and
formal-gate limits.

The following [runtime preflight checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-coding-runtime-preflight)
adds a single-snapshot, read-only PG current-state projection and explicitly
composes an exec support checker in the held v3 dependencies. It checks the
exact Active allocation and completed original create, desired/observed Ready,
current generation/lease/fence and frozen Profile/policy/peer. Request validation
and unsupported reference checks precede the read; cancellation, clock and
expiry checks follow it. Accepted termination closes eligibility before cleanup,
and a prospective higher fence changes no durable state. This is preflight
only, not an Executor or exec admission; no private wire action, public
capability or automatic worker is added. Final focused race, real PG,
full-repository race/shuffle/count-one with `-p=1` (1,022.115 seconds), vet,
both Contract locks and Linux/arm64 compilation pass on the same final source.
Seven file hashes match independent review; the audit retains the reproduced
inconsistent-state rejection and earlier failed fixtures. Physical runtime
ports and complete Slice 6 acceptance remain open; Phase 6 remains **5/15**.

The following [exec intent checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-coding-exec-intent-ledger)
adds a separate bounded no-permit ledger and explicit unused-state initialization.
Admission and complete-request conflict checks share the Coding lifecycle row
lock; historical replay has no write or dispatch effect. A high requested fence
is prospective only. The held command retains the focused recorder without an
Executor, public operation route or worker. The private Control wire remains
unchanged. Physical exec still requires a new atomic permit, generic-entry-point
isolation, Unknown-before-effect receipts, cleanup quiescence and result/cancel
closure. Final focused/real-PG checks, independent review, vet, both Contract
locks and Linux/arm64 build pass. This full-repository race run failed on the
unchanged phase6security package's default 600-second timeout; all other packages
passed. The standalone security package then passed with the original seed and
default timeout in 535.950 seconds; that does not replace the failed full
invocation. No full-run pass is claimed for this checkpoint. Phase 6 remains
**5/15**.

The 2026-10-10 [exec namespace isolation checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-exec-namespace-isolation)
closes the previous generic-exec and reverse operation-ID gaps. The enabled
Coding intent database now rejects all generic exec reads/writes; lifecycle
writers and typed unchanged replays check the intent namespace under the same
row lock. Damaged/orphan history cannot authorize reinitialization. Legacy
non-intent databases retain their prior behavior. This remains a no-permit
component; current-authority fencing, distinct Control receipts, quiescence,
observe/cancel/result and public command composition remain open. The real-PG gate, independent review, vet, both Contract locks and Linux/arm64
build pass. The full race invocation fails on a Controller TempDir cleanup
error and the security package default timeout; the unchanged Controller
same-seed diagnostic passes separately. That checkpoint left full validation
unresolved, as recorded in the dated audit; Phase 6 remains
**5/15**, Slice 6 step 2, and both public holds stay closed.

The subsequent [descriptor and validation-cost repair](audits/product-phase-6-slice-6-startup.md#2026-10-10-controller-descriptor-and-validation-cost-repair)
reproduces and fixes the Controller fixture's FD ownership defect, then removes
repeated whole-Profile checks inside the same validated call. All public entry
points revalidate current input; original receipt checks and rejection rules
remain. Independent review of sixteen Go files passes. The final combined
`go test -race -shuffle=on -count=1 ./...` passes in 625.022 seconds overall
(security package 580.323 seconds within its unchanged 600-second default),
as do vet, both Contract locks and Linux/arm64 compilation. Timeout headroom
is still limited; this result does not relabel the earlier failures or prove
future timing stability. No Docker topology gate ran in this increment.
Current exec authority/fencing, Control Unknown-before-effect receipts,
quiescence and observe/cancel/result recovery remain open. Phase 6 is still
**5/15**, Slice 6 step 2; there is no public admission, commit or push.

The later [held PG exec fence reservation](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-pg-exec-fence-reservation)
adds an explicitly bootstrapped, bounded reservation document without opening
an executor or public route. Same-row full-request/current-tuple admission
advances only the scope and lease fences. Independent review covers thirteen
Go files. The final real-PG component gate passes in 27.087 seconds, including
two-pool replay, competing typed lease/terminate, missing/corrupt document
rejection and historical reads after slot reuse. The receipt is history only;
Control Unknown-before-effect, physical quiescence and observe/cancel/result
recovery remain open. The first full race invocation failed when the unchanged
lifecycle repository test process reached the Go driver's fallback deadline,
without captured test startup output. Its focused three-run diagnostic and
vet/locks/build pass. The full same-source race/shuffle/count=1 recheck passes
in **355.541 seconds**, with only diagnostic verbosity added and the default
timeout/concurrency unchanged. All 2,015 Go/module hashes remain frozen. See
the dated audit for the distinct failed/passed invocations and unknown first
failure cause; the successful recheck is not a claimed root-cause fix. Phase 6
remains **5/15**, Slice 6 step 2.

The [exec containment mechanism probe](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-exec-containment-mechanism-probe)
now reproduces the legacy cancellation counterexample on local Docker:
successful direct-child TERM and a stopped wrapper leave a detached orphan
writing. Two independent command/PID 1 containers show stopped/Pid=0 and a
500 ms unchanged counter after exact SIGKILL or natural exit. The final
reviewed probe passes in **64.466 seconds**; the earlier archive-read failure
remains recorded. This is a locked PG process fixture, not a Coding/Profile-v2
gate or proof that late Docker calls cannot execute. Legacy production Cancel
is unchanged; distinct Control exec Unknown receipts are still unimplemented.
The independently reviewed containment/resource/dispatch design must precede
that wiring. Both public holds and formal **5/15** remain unchanged.

The next [resource/shared-scratch checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-exec-resource-and-shared-scratch-checkpoint)
implements checked resident/command limits within one slot's existing ceiling.
Its real Docker component test passes in **23.599 seconds**, inspecting the
actual limits and shared tmpfs type, 32 MiB data-block capacity, UID/GID/mode,
mount flags, cross-container visibility, noexec and ENOSPC. Command replacement
preserves scratch; full unmount/remount loses it. Exact fixture cleanup passes.
Independent review accepts only this resource arithmetic and local mechanism
scope. The [private exec protocol plan](plan/product-v1-phase-6-coding-exec-protocol.md)
specifies the new-mode adoption boundary, output/acceptance ordering and durable
Unknown/late-request/cleanup invariants. Actual Coding inputs, production
budgets, inode/metadata bounds, daemon restart and real PG-to-Control dispatch
remain open; no old resource/receipt bytes or public admission are changed.
Full race/shuffle/count=1 passes in **403.955 seconds** on the frozen 2,020
Go/module files, with default timeout/concurrency; vet and both Contract locks
also pass. Formal Phase 6 remains **5/15**, Slice 6 step 2.

The [execution template/storage candidate](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-execution-template-and-storage-budget-candidate)
now has a separate canonical mode, fixed candidate 1 GiB slot partition and
512 MiB Coding storage subquota. Output staging/sealing has 192 MiB; allocation
evidence, command evidence, double-state writing, closure and physical
headroom each have separate 64 MiB bounds. The real scratch probe passes in
**23.994 seconds**, proving the actual 4096-inode limit and file/directory
ENOSPC while data space remains, followed by inode reuse and exact cleanup.
The candidate and arithmetic have independent read-only review. The limits
are not yet consumed by durable PG/Control admission; full Profile/receipt
namespace, other-scope quotas and physical/runtime gates remain required.
All 2,024 Go/module hashes remain frozen through full race/shuffle/count=1
(**357.458 seconds**, default timeout/concurrency), vet and both Contract
locks. The initial live-remote timeout and successful bounded retry are
recorded separately. Phase 6 remains **5/15**, Slice 6 step 2.

The subsequent [private storage namespace checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-private-storage-namespace)
adds actual bounded file publication and restart inspection under one owner,
with immutable evidence, single-state replacement peak and independent close
space. Held execution template v2 binds the layout; other scopes' 512 MiB is
explicitly unallocated and cannot be consumed. Independent review accepts this
file-component scope. A fresh Linux/arm64 local-volume fixture passes in
**8.388 seconds** and removes its two containers/two volumes; the earlier
read-only-root copy setup failure is preserved, not counted as a test pass.
PG-to-Control dispatch, execution receipt semantics, source-verified physical
volume admission and cross-file recovery remain incomplete. The final 2,027 Go/module files pass full race/shuffle/count=1 in **553.057 seconds**
with default timeout/concurrency, vet and both Contract locks. Both public holds
and Phase 6 **5/15**, Slice 6 step 2 remain unchanged.

The next [common Control state checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-common-control-execution-state)
implements package-private new-protocol create/exec/retirement state on that
file store. All admission/closure decisions share the persistent owner and
manifest revision comparison. Unknown precedes bounded effect callbacks and
survives return, cancellation, retirement and restart; no release API exists.
Exact closure also advances the fence high-water mark. Independent review
found and closed that late-fence gap and required strictly newer retirement
generation with a distinct operation. The new typed four-volume completion
port has only synthetic test observations: actual source-bound collection,
complete Profile/physical-volume admission, atomic PG public acceptance/claim,
asynchronous private dispatch, terminal/cancel/cleanup and release remain open.
The dated audit separates component checks and preserved setup failures from
the still-unexecuted real Coding path. All 2,033 Go/module files remain frozen
through full race/shuffle/count=1 (**376.398 seconds**, default timeout/concurrency),
vet and both Contract locks. The tagged Linux local-volume component passes
separately, with synthetic observations/callbacks. Formal status remains
**5/15**, step 2.

The latest [four-volume observer checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-four-volume-completion-observer)
adds the package-private source-bound SDK collector and retained physical
projection recheck under receipt protocol v2. Legacy records cannot be upgraded
or reinterpreted. Exact four-volume inventory, image descriptor chain, runtime
limits/protections and empty-root metadata are checked before completion.
Independent review closed response-body socket drift and additional resource
and path-protection gaps. The real daemon check rejects a fresh empty scope
using only 11 bounded GETs; the Linux high-UID receipt fixture still uses
synthetic positive Docker responses. The Coding arm64 image is now downloaded,
not executed or freshly supply/attestation/vulnerability-qualified. Positive
four-volume workload/kernel gates, full Profile/physical namespace binding and
PG/async-mTLS admission remain open; formal status stays **5/15**, step 2.
The dated audit records final-source validation and private evidence.

The following [Coding supply revalidation](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-image-supply-revalidation)
passes original descriptor/layer checks and offline signed-provenance verification,
but its fresh arm64 Trivy report has **13 HIGH occurrences (12 distinct CVEs),
zero CRITICAL**. No Coding container is started. A new unsigned 23-component
CycloneDX inventory is available privately; this is not Slice 7 acceptance.
The historical Go1.26.5 broker and Alpine OpenSSL need repair; the user has now
approved Go1.26.9 only for the [new Coding candidate](plan/product-v1-phase-6-coding-image-candidate.md).
Its [separate recipe/locks](../profiles/coding-shell/candidate/README.md) use clean
91fe315 source and Alpine3.23.6. Both platform archives reproduce byte-for-byte
and scan with **0 HIGH/CRITICAL, 1 retained zlib MEDIUM** each. Native arm64
candidate diagnostic smoke passes in **5.077 seconds** with exact container
cleanup; amd64 runtime and formal four-volume gates remain unexecuted. Tools
now use mise (ordinary Go1.26.8, candidate-only Go1.26.9, Trivy0.74.0), with Docker
image builds and no global activation. The redundant hand-extracted Go copies
were removed after complete byte equality checks. Historical image locks and
all 2,040 Go/module files were unchanged at that build checkpoint. The [candidate audit](audits/product-phase-6-slice-6-startup.md#2026-10-10-repaired-coding-candidate-and-managed-tools)
records those checks, failures and limitations.

The subsequent [held binding component](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-candidate-template-and-receipt-binding)
adds source-owned candidate record identity, a distinct execution-template v3
and internal receipt v3, preserving old templates and rejecting v1/v2 state
without migration. Real archive/layer rechecks and bounded Docker image reads
pass; empty four-volume scope still cannot produce completion. Historical
scan metadata is not a fresh verdict or signature. The next
[Profile/kernel-root component](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-profile-mode-and-kernel-root)
adds a mutually exclusive candidate-v3 mode to the complete Profile field chain,
source-derived storage binding and declared eight-volume resource accounting.
Kernel-checked Store paths verify the actual root fd and live path mount ID;
a real ordinary Docker local volume is refused before writing a marker.
Positive Profile/kernel tests are synthetic. Docker volume identity, exclusive
ownership, stable hard quota, final live inventory and real four-volume
positive/failure scenarios still precede PG/mTLS composition. Formal status
remains **5/15**, Slice 6 step 2, both public holds closed; no publication or
production admission follows.

A separate same-run [PostgreSQL leaf component audit](audits/product-phase-6-slice-6-postgres-leaf-component-gap.md)
records successful fixed-identity Vault signing but no PostgreSQL launch and
no confirmed revocation of that extra leaf: the already-running diagnostic
used the v1 two-controller terminal plan. Its temporary Docker resources
and private key were removed exactly. The approved private v2 plan now
requires the third DER-bound target and complete-CRL confirmation, with a
pre-signing clean-binary capability check; implementation and real PG/v2
same-run gate are still in progress, not release evidence.

Updated: 2026-10-10

This document is the implementation ledger for the repository-owned MIT
Provider Contract. It distinguishes local component evidence, Contract
projection evidence, CI, Conformance, external-caller compatibility,
multi-controller reliability, multi-tenant security, deployment, and
production readiness.

## Current Baseline

| Item | Evidence | Status |
| --- | --- | --- |
| Product v1 architecture Phase 1 | [Phase plan](plan/product-v1-phase-1.md); ADRs 0042-0047; Product Contract namespace `urn:shell-echo:sandbox-runtime:product-v1alpha1`, version `0.1.0`, manifest `sha256:fa933c55b9025ba5d0d6661eb023d76de075676089342cab83bab9bacfbda007`, tree `sha256:3cbd422e7753768be6ed6510d62b0b78f63abd4c383179c91bd3a5ab73375562` | Complete as committed design and Contract-definition authority dated 2026-09-18. It defines repository governance, Product API authority, Workspace/slot persistence, Agent delegation/control, Runtime Gateway/recording, and deployment levels. Phase 3 implementation evidence is tracked separately |
| Product v1 Phase 2 Provider lifecycle closure | [Fixed nine-step plan](plan/product-v1-phase-2-provider-lifecycle.md); [Step 1 audit](audits/phase-2-step-1-provider-lifecycle-authority-gap.md); [completion record](audits/phase-2-provider-lifecycle-completion.md); ADR 0048; implementation `98995384c60a924f25ca58d3b7e561207bfa5be8`; lock selection `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1` | Complete for the fixed scope. Durable lifecycle mutations/events/expiry, exact-owned fake and Docker controls, terminal close/revocation/cleanup, protected transport, and fail-closed capability readiness are selected. Full root/E2E race and vet, eight E2E checks, Contract/profile verifiers, clean-VCS 60-case Suite, tagged Docker integration, and the repository-owned independent-process 15+5+9 black-box run pass. This does not prove separately implemented external-caller lifecycle interoperability, multi-controller operation, deployment, hostile-multitenant isolation, or production readiness |
| Product v1 Phase 3 Slice 1 | [Fixed 13-slice plan](plan/product-v1-phase-3-product-kernel-terminal-files-web.md); [startup audit](audits/phase-3-product-surface-startup.md); Product Contract manifest `sha256:fa933c55b9025ba5d0d6661eb023d76de075676089342cab83bab9bacfbda007`; tree `sha256:3cbd422e7753768be6ed6510d62b0b78f63abd4c383179c91bd3a5ab73375562` | Implemented as Product-kernel component evidence: import boundaries, content-lock/OpenAPI/JSON-Schema verification, migration ledger, and atomic Workspace/slot/operation/event/outbox/idempotency persistence. Focused and full repository gates plus disposable real PostgreSQL integration pass locally. At this slice boundary twelve slices remained and no Product-ready or production claim followed; current completion is recorded separately below |
| Product v1 Phase 3 Slice 2 | Product Contract manifest `sha256:7f7c5264693f4f01c47fcda6e27f0add609b4bec9549bc2a10338517dcef7cba`; tree `sha256:a5c9cfa4fdfcdb481336732b4b33de39b57ef6e30dc668b95a0cf524b143b4d1`; four fixtures; three conformance seed cases; `productapi` and `productapi/v1` | Strict bearer authentication, bounded closed JSON, duplicate-header/member rejection, auth precedence, tenant/actor nondisclosure, schema-valid DTO projection, PostgreSQL reads, and real-database HTTP create/read pass. At this slice boundary capabilities remained empty and no Provider dispatch, deployable listener, session/data plane, or readiness claim followed; current completion is recorded separately below |
| Product v1 Phase 3 completion | [Fixed 13-slice plan](plan/product-v1-phase-3-product-kernel-terminal-files-web.md); [completion audit](audits/product-phase-3-standalone-completion.md); [strict evidence manifest](audits/product-phase-3-standalone-evidence.json); implementation `04c2755bec125db7e2c04df3f4e2f8cfedb6ec1d`; run `20260918T111903.806694000Z` | Complete for the bounded standalone scope. Four separate Product/Gateway/Guest/Provider-fixture OS processes and fresh pinned PostgreSQL passed all nine exact capability, authentication, nondisclosure, restart, Guest Files, Terminal, ticket replay, Provider-fault, and cleanup scenarios. Independent validation confirms 4/4 processes, 9/9 scenarios, locked Provider/Product identities, fresh schema, row/process/container cleanup, and explicit non-claims. The Provider role is a locked-wire fixture and the topology is not deployment, independent-caller, HA, hostile-multitenant, or production evidence |
| Product v1 Phase 4 Browser Slice 1 | [Fixed 13-slice plan](plan/product-v1-phase-4-browser.md); [startup audit](audits/phase-4-product-browser-startup.md); ADR 0049 | Implemented locally as Product authority only. The strict authenticated generic session route accepts only exact Browser kind/profile pairs after injected readiness authorization; PostgreSQL additionally requires a ready `browser` slot with `sandbox.browser@1.0.0` / `browser-v1`, commits Browser-specific outbox work atomically, and prevents the Terminal worker from leasing it. Focused/full race-shuffle, vet, both Contract verifiers, retained Phase 3 evidence verification, migration replay, and the complete real-PostgreSQL tagged Product package pass against the pinned disposable image with cleanup. Provider Browser dispatch, public Browser data planes, capability advertisement, release evidence, deployment, HA, hostile-multitenant, collaboration, and production remain absent |
| Product v1 Phase 4 Browser Slice 2 | [Fixed 13-slice plan](plan/product-v1-phase-4-browser.md); ADR 0049; migration 4 | Strict Product API and PostgreSQL authority for auxiliary Browser slots: exact immutable Browser shape, expected Workspace version, mutation idempotency, bounded tenant quota, atomic operation/event/audit/`slot.reconcile` intent, and owner nondisclosure. Focused tests and fresh pinned-PostgreSQL race tests pass, including concurrent idempotent PUT and one-slot quota admission. Provider dispatch, observed readiness, public data planes, capability advertisement, and all release/deployment/production claims remain absent |
| Product v1 Phase 4 Browser Slice 3 | [Fixed 13-slice plan](plan/product-v1-phase-4-browser.md); ADR 0049; locked Provider revision/tree | Exact Browser-only Provider discovery, restricted-network sandbox create, Browser-specific slot/session dispatch, signed protected mutations/reads, and opaque Browser handoff observation are implemented through the Provider network Contract. Focused race tests and fresh pinned-PostgreSQL integration prove capability drift closure, stale-generation non-dispatch, Terminal/Browser worker isolation, atomic retained evidence, and no private endpoint projection. Provider Browser close is intentionally deferred to Slice 4 because the locked Contract has no close route. Public data planes, release evidence, advertisement, deployment, and production remain absent |
| Product v1 Phase 4 Browser completion | [Fixed 13-slice plan](plan/product-v1-phase-4-browser.md); [completion audit](audits/product-phase-4-browser-completion.md); [strict evidence manifest](audits/product-phase-4-browser-evidence.json); source baseline `322eb342650d2ade838f1b3a24e0d5bc0bfbb3e1`; run `20260918T152110.677058000Z` | Complete for the bounded same-repository separate-process scope. Four separate Product/Gateway/Provider/Browser OS processes, fresh pinned PostgreSQL and Valkey, and fresh encrypted recording storage passed all 12 exact identity, authentication, nondisclosure, lifecycle, automation, viewer/controller, real-WebRTC recording, restart, Provider-fault, backpressure, and cleanup scenarios. Strict validation confirms locked Provider/Product identities, 4/4 roles, 12/12 scenarios, executable digests, and complete cleanup. This is not deployment-qualified, independent-caller, HA, hostile-multitenant, or production evidence |
| Product v1 Phase 5 Desktop Slice 1 | [Fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); [startup audit](audits/product-phase-5-desktop-startup.md); ADR 0050; Contract revision `720ad15c343e71f36615dc4499edd5e764178bca`; tree `343ffde0819207cf99c005096c336735dd33a735` | Complete as Provider Contract and Go projection authority only. Separate Desktop capability/profile/runtime discovery, create binding, open/read/opaque-handoff/close, expiry/revocation, usage, admission, state, security, quota/error, and exact-cleanup semantics are locked. All 71 local Suite cases map to executable tests. No Desktop runtime, driver, image, protected route composition, Product authority, public Gateway, Guest protocol, Web experience, advertisement, deployment, HA, hostile-multitenant, or production claim follows |
| Product v1 Phase 5 Desktop Slice 2 | [Slice 2 evidence](audits/product-phase-5-desktop-slice-2.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`; migration 8 | Complete as Product intent and real-PostgreSQL component evidence. Strict authenticated routes accept only exact Desktop slot/session shapes; expected-version, idempotency, slot/session quota races, absorbing states, atomic operation/event/audit/outbox, worker isolation, nondisclosure, migration replay, and reconstructed-Store reads pass. No Desktop dispatcher, Provider implementation, runtime, public Gateway, Web UI, advertisement, independent-process, deployment, HA, hostile-multitenant, or production claim follows |
| Product v1 Phase 5 Desktop Slice 3 | [Slice 3 evidence](audits/product-phase-5-desktop-slice-3.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5` | Complete as Provider-local component and protected-handler evidence. Separate open/close authority, fences/replay/deadlines, memory and exclusive atomic-file persistence, restart at commit/effect boundaries, observation-only unknown reconciliation, revoke-before-exact-cleanup, retained operation reads, strict protected routes, safe errors, and nondisclosure pass. No runtime image, adapter, broker, private resolver, usage collector, production startup composition, Product dispatch, public Gateway, advertisement, independent-process, deployment, HA, hostile-multitenant, or production claim follows |
| Product v1 Phase 5 Desktop Slice 4 | [Candidate evidence](audits/product-phase-5-desktop-slice-4-candidate.md); [publication evidence](audits/product-phase-5-desktop-slice-4-publication.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `163dd8a258a24cf4727169b1cbd8ed7c0fe29292`; run `35447651328` | Exact dual-architecture source/package locks, scratch repack, numeric non-root security policy, bounded Unix-only broker, reproducible candidate outputs, and native arm64 component gate pass. Native hosted amd64/arm64/v8 publication, immutable index/platform manifests, GitHub OIDC/Sigstore attestation `48643717`, and fresh independent source/runner/matrix verification pass at source `e4a940b`. Slice 4 is complete at 4/15; no adapter composition or advertisement follows |
| Product v1 Phase 5 Desktop Slice 5 | [Slice 5 evidence](audits/product-phase-5-desktop-slice-5.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b` | Fail-closed locked-image Docker adapter, provenance and restricted-network dependencies, durable private state, opaque reference registry, fresh attach/reconnect checks, Desktop lifecycle readiness, revoke-before-cleanup/absence composition, exact duration usage, restart/fault matrices, and native arm64/v8 real-image broker/removal gate pass. Production startup, Product dispatch, public data planes, advertisement, deployment, and production readiness remain absent |
| Product v1 Phase 5 Desktop Slice 6 | [Slice 6 evidence](audits/product-phase-5-desktop-slice-6.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240`; migration 9 | Exact-revision/tree Product network adapter, signed-image/profile and readiness selection, protected Desktop create/lifecycle/open/close/observation/handoff requests, timeout/cancellation/replay/drift closure, isolated durable workers, retained recovery, Product/Provider generation separation, and Desktop-specific close cleanup pass focused and real-PostgreSQL gates. The Provider peer in the store gate is a same-repository HTTP fixture. Production startup, grants, public data planes, policy, recording, Web, advertisement, deployment, and production readiness remain absent |
| Product v1 Phase 5 Desktop Slice 7 | [Slice 7 evidence](audits/product-phase-5-desktop-slice-7.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `0649d62911abb89229de40136347286736152ec6`; migration 10 | Exact Desktop-only view/control admission, encrypted one-use tickets, session-scoped control fences, one controller, independent viewer/controller quotas, DB-time expiry/revocation, full-binding continuous checks, and metadata-only audit pass focused and real-PostgreSQL gates. No public signaling/media/input data plane, policy, recording, Web experience, production composition, advertisement, deployment, or production-readiness claim follows |
| Product v1 Phase 5 Desktop Slice 8 | [Slice 8 evidence](audits/product-phase-5-desktop-slice-8.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `040c560f3701b7c972c25f05928dd435d9f55c20` | Separate bounded Desktop WebRTC handler with HTTPS one-use-ticket signaling, exact Origin, relay-only production ICE, receive-only VP8 and optional Opus, viewer/controller separation, reliable ordered fenced input, continuous grant checks, peer/session/queue/bitrate bounds, slow-consumer closure, metadata-only audit, and handoff nondisclosure passes focused real-WebRTC and full repository gates. No durable Desktop policy, real Provider media bridge, recovery, recording, production composition, advertisement, deployment, or production-readiness claim follows |
| Product v1 Phase 5 Desktop Slice 9 | [Slice 9 evidence](audits/product-phase-5-desktop-slice-9.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `24f5c741eb605614f77f8d9d546708b9993e42dd`; migration 11 | Immutable Workspace policy revisions, owner/idempotency/expected-revision persistence, deny-by-default input/clipboard/transfer authorization, activation/consent and metadata/path bounds, exact complete Product transfer binding, continuous revision revocation, audit minimization, concurrency, restart, and real-PostgreSQL gates pass. No real Provider media/input bridge, reconnect/recovery, recording, production composition, advertisement, deployment, or production-readiness claim follows |
| Product v1 Phase 5 Desktop Slice 10 | [Slice 10 evidence](audits/product-phase-5-desktop-slice-10.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `f23b16130c97e99d5d28008b01346779a0c681ee`; migration 12 | Fresh-grant reconnect, exact generation/authority rebinding, database-time Gateway lease crash recovery, bounded visual/audio resynchronization, closed display/audio-output changes, stale-epoch/current-resolution input rejection, and deterministic transactional replacement cleanup pass focused WebRTC race and fresh real-PostgreSQL gates. No real Provider media/input bridge, recording, production composition, advertisement, deployment, or production-readiness claim follows |
| Product v1 Phase 5 Desktop Slice 11 | [Slice 11 evidence](audits/product-phase-5-desktop-slice-11.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADRs 0046/0050; implementation `c5b045abc5192b76b7d615ddbb0858b998ef98d5` | Explicit consent and visible mode, fail-closed required recorder, bounded Desktop RTP/control capture, encrypted immutable digest-linked segments, owner-only integrity replay, active-recording quota race closure, retention deletion/object cleanup, and catalog/audit content minimization pass focused Gateway and fresh real-PostgreSQL gates. No real Provider media/input bridge, development template, production composition, advertisement, deployment, or production-readiness claim follows |
| Product v1 Phase 5 Desktop Slice 12 | [Slice 12 evidence](audits/product-phase-5-desktop-slice-12.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `490c2db96d6ba7a851d7846bc9e5f818dae2be77`; migration 13 | Immutable signed-image template selection, validated revision manifests, exact primary-slot/Guest authority and health, bounded digest-checked workspace materialization, two-phase rollback/finalization, interrupted-swap recovery, idempotency, owner isolation, and nondisclosure pass focused and fresh full PostgreSQL gates. No real Provider media/input bridge, unified Web, production composition, advertisement, deployment, or production-readiness claim follows |
| Product v1 Phase 5 Desktop Slice 13 | [Slice 13 evidence](audits/product-phase-5-desktop-slice-13.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `84698c371d35edb862ffc81b484a3e31cc8120d9` | Capability-derived authenticated unified Product Web/BFF, exact Desktop public slot/session/grant profiles, same-origin WebRTC, viewer/controller UX, bounded reconnect/configuration, clipboard and recording consent, digest-checked shared transfers, accessible navigation, strict CSP/Origin/CSRF, and nondisclosure pass focused/full and real-headless-Chrome gates. No real Provider media bridge, production composition/advertisement, composed Slice 14 security/fault result, independent-process release, deployment, or production-readiness claim follows |
| Product v1 Phase 5 Desktop Slice 14 | [Slice 14 evidence](audits/product-phase-5-desktop-slice-14.md); [fixed 15-slice plan](plan/product-v1-phase-5-desktop-development-unified-product.md); ADR 0050; implementation `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d` | Closed private Provider/Gateway Desktop protocol, fresh and continuous handoff binding, bounded VP8/optional-Opus and ordered control transport, strict substitution/input rejection, and a real-PostgreSQL composition of grant, policy, public WebRTC, private bridge, recording, revocation, attack denial, capacity recovery, object deletion, and exact tenant-row cleanup pass focused/full gates. The independent-process Product/Gateway/Provider/Desktop/Guest release topology, real display/control and development scenarios, strict release evidence bundle, exact topology advertisement, deployment, HA, hostile multi-tenant isolation, and production readiness remain absent |
| Product v1 Phase 5 Desktop completion | [Completion audit](audits/product-phase-5-desktop-completion.md); [strict evidence manifest](audits/product-phase-5-desktop-evidence.json); implementation `024a768d51965f8949bacf3c97e499fb26a6e648`; shutdown-order fix `59de37d5ee22776305dfaab866c25ea6bd5406bc`; E2E lock `d5d6ed1a815b49625a054d9931a8cec2234d8e7e`; run `20260919T200125.484855000Z` | Complete at 15/15 for the bounded same-repository independent-process topology. Separate Product, Gateway, Provider, Desktop, and Guest OS processes pass 14 exact locked-identity, dependency-derived capability, real-display/control, development, restart/fault/security/recording, and cleanup scenarios. Strict validation confirms the exact roles/scenarios/runtime/platform/template identities and all cleanup/non-claim fields; the Provider media session closes before private WebSocket termination becomes observable; full E2E race/shuffle, vet, and all eight clean-checkout parent checks pass. The production command remains uncomposed; this is not deployment, HA, hostile-multitenant, independently implemented caller, or production-readiness evidence |
| Product v1 Phase 6 Slice 1 | [Startup audit](audits/product-phase-6-production-startup.md); [ADR 0051](adr/0051-product-phase-6-production-hardening-order.md); [fixed 15-slice plan](plan/product-v1-phase-6-production-hardening.md); [Slice 1 record](audits/product-phase-6-slice-1.md) | Phase 6 is 1/15 complete. The independent `product serve` command has strict development-only configuration, distinct bounded private PostgreSQL/identity files, closed frozen identity decoding, real migrations/store, bounded transport, separate liveness/database readiness, empty capability advertisement, and fail-closed primary-slot mutation. Root `serve` refuses Product composition. Focused race/shuffle tests pass. This is not TLS/production identity, role-separated database, Provider/Gateway/Guest/Browser/Desktop composition, deployment, HA, backup/restore, SLO, hostile-multitenant, or production evidence |
| Product v1 Phase 6 Slice 2 | [ADR 0051](adr/0051-product-phase-6-production-hardening-order.md); [fixed 15-slice plan](plan/product-v1-phase-6-production-hardening.md); [Slice 2 record](audits/product-phase-6-slice-2.md) | Phase 6 is 2/15 complete. Production `product serve` requires TLS 1.3, a closed Ed25519 JWT key ring with overlap/revocation, distinct exact migration/runtime PostgreSQL roles, exact schema compatibility and bounded pools. Migration authority closes before listener bind; a worker continuously closes/recovers readiness on database/schema state. The real-process gate passes auth precedence, privilege denial, pool exhaustion, database loss/recovery, restart and nondisclosure. Provider and public data planes remain absent; capability is unavailable and no deployment or production-readiness claim follows |
| Product v1 Phase 6 Slice 3 | [ADR 0051](adr/0051-product-phase-6-production-hardening-order.md); [fixed 15-slice plan](plan/product-v1-phase-6-production-hardening.md); [Slice 3 record](audits/product-phase-6-slice-3.md) | Phase 6 is 3/15 complete. Production-only `provider serve` keeps Product and `/instances` authority outside the process; requires TLS 1.3 mTLS, exact protected admission, separated PostgreSQL roles, transactional lifecycle/exec/Terminal/artifact/usage/Desktop state, exact schema checks, and bounded reconciliation; and advertises exactly one coding-shell or Desktop profile. Real PostgreSQL concurrency/fault/restart, real-process restart, coding-shell Docker lifecycle and signed Desktop broker gates pass. Product dispatch, public data planes, deployment, HA and production readiness remain later gates |
| Product v1 Phase 6 Slice 4 | [ADR 0052](adr/0052-phase-6-executor-role-boundary.md); [fixed plan](plan/product-v1-phase-6-production-hardening.md); [Slice 4 record](audits/product-phase-6-slice-4.md); [strict evidence manifest](audits/product-phase-6-slice-4-evidence.json); runtime `78f5987fda45873e497bce6d336e29dd4a61dc74`; evidence tool `e2f4abacf03418c7b18f179c3e7459292d8626df`; manifest `sha256:d01b3c41a0094657f18b4014b0649a799ea7fcf0e4ccaf07aa82cdd2052cc0d2` | Phase 6 is 4/15 complete within the bounded local independent-process scope. Product, Gateway, Provider, Guest, Browser and Desktop run as six separate OS processes and pass 12 strict scenarios with real Chromium, real Desktop VP8/input, dependency loss, bounded reconnect/drain, replay/capacity/drift denial, broker/executor/Provider restart and exact zero-resource cleanup. Executor v2 retains Provider authority and sealed Browser/Desktop egress identities. The Desktop OCI remains a `local-candidate-non-release`; no public Product E2E, published Phase 6 artifact, deployment, HA, SLO or production-readiness claim follows. Slice 5 secret references, KMS/HSM keys, scoped credentials, rotation/revocation and break-glass audit are next |
| Product v1 Phase 6 Slice 5 | [ADR 0054](adr/0054-phase-6-scoped-secret-and-envelope-key-boundary.md); [strict evidence manifest](audits/product-phase-6-slice-5-evidence.json); runtime `c189330c5ed0aa52c60b6b85c5cd9c6b59fbef10`; evidence tool `39fd1025f6fa838325aced711d8a024a9ce5d1b6`; manifest `sha256:e6a6fdcc299c721e1fa2c48009d98a6ca4c52d59318c507af8b68fd8596e840c` | Phase 6 is 5/15 complete for scoped material agents, one-shot migration authority, Vault Transit recording keys, credential rotation/revocation and bounded dual-control break-glass in a real six-role local gate. The gate explicitly reports `distinct_os_uid_established=false`; HSM, deployment and production readiness remain unproved. |
| Product v1 Phase 6 Slice 6 component checkpoint | [ADR 0055](adr/0055-phase-6-workload-tls-network-and-least-privilege-boundary.md); [external PostgreSQL/v2 audit](audits/product-phase-6-slice-6-postgres-v2-component.md); [startup and live-revoke audit](audits/product-phase-6-slice-6-startup.md); [scenario gap](audits/product-phase-6-slice-6-scenario-gap.md); Guest recovery E `a065277e406bf09c4c22d4ce187e1d181e513316`, R/F `e5816d0d3de0541bd9a677560096b3527f58f7b9`, run `550dba360065dce4f46fa14476225ce5`, final binding `sha256:e66dc29a217c82e1ae9071b8046c33461afae8d216e488751c9a68e312549177` | Earlier clean-source migration and live business-binding revoke components passed within their bounded scopes. The independently accepted Guest recovery E component proves real PostgreSQL loss/recovery, ordered Product/Guest A→B replacement, recovery close, terminal remote revoke/complete CRL, 119-file/14-slot binding and exact run-owned cleanup. This closes fixed delivery step 1 only. A separate test-only Browser application/identity-runtime PID-crash component passed finished-dispatch recovery and unproved network-side-effect capacity hold on real PostgreSQL/high-UID Docker, without second dispatch; it is not production Provider replacement. `sticky_credential_revoke` remains an open controller clean-drain failure despite independently confirmed remote cleanup. Three Provider commands, full TLS/CRL/network/privilege matrix and the revised complete Profile-v2-inventory/16-scenario gate remain open; there is no Slice 6 manifest, deployment or production readiness. Phase 6 stays 5/15. |
| Sandbox Provider Calling Standard decision | ADR 0037; `contract/specification/provider-calling-standard-v1.md`; repository-owned Contract manifest | External consumers adapt to the exact locked `sandbox-runtime` Provider Contract. The former named Agent Platform P3 migration route is retired, while caller/Provider ownership separation and historical candidate evidence remain. This standard slice adds no capability or production-readiness claim. ADR 0038 defines the generic issuer trust model; the named independent-caller qualification is recorded separately in P2.7 and deployment qualification remains open |
| Current Provider Contract authority | Revision `720ad15c343e71f36615dc4499edd5e764178bca`; tree `343ffde0819207cf99c005096c336735dd33a735`; manifest `sha256:483111511a588b41bd40d3fef686f0b21f465bb65d3215450ebb2ccf37a5de89`; OpenAPI `sha256:5a3da5d239f83e94eff09fc75438755f834e77bce8cd1c0f91c25055bf0cba2a`; semantic rules `sha256:7953d05e65f00c68e0428b6dd4fcebef1af103f2cab2fa6b214905b2496c8785`; 71-case local Suite `sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`; unchanged 6-case remote Suite | Product Phase 5 Slice 1 adds Desktop Contract/projection authority only. Exact lock verification, executable Suite mapping, race/shuffle, vet, retained Product evidence, and clean-VCS Conformance are the local acceptance gates. Historical Phase 2/3/4, hosted CI, external-caller, and remote-discovery evidence retains its recorded authority and is not relabeled |
| Application-container development deployment | Root `Dockerfile`; Docker, Apple Container, and Kubernetes bilingual guides; development Kustomize base; three smoke scripts; local runs on 2026-09-17 | Docker Engine 29.7.2 on Linux/arm64, Apple Container 1.4.1 on macOS/arm64, and kind 0.33.0 with Kubernetes 1.37.0 each passed the bounded health/create/list path with the in-memory fake runtime. Docker and Kubernetes additionally exercised numeric non-root and restricted filesystem/privilege settings; the Kubernetes run created and removed an isolated namespace, and its disposable kind cluster was removed. No application image was published. This is current-worktree application-packaging evidence only; hosted release gates, immutable multi-platform publication, protected Provider deployment, HA, hostile multi-tenancy, deployment qualification, and production readiness remain open |
| P2.7 independent external caller qualification | ADR 0040; profile `sandbox-runtime-external-caller-coding-shell-v1@1.0.0` at `sha256:ec113d31612dbb7cc0e9461925170f74f33722bb2efb237dbc68aa89f2d60231`; Provider/caller `170459266af5f4fad359ca8c63f2ae19741055c5`/`b3ebcc783e5db20395e29b029e0eb55f7819b49b`; hosted run `35203241121`; artifact `10488622806`; result envelope `sha256:d5e6fd528f2302252a38f49aa466c85767106a8bcef430120f230a8127f96758` | P2.7 is 24/24 and the public caller plan is 13/13. The run passed all 15+5 cases and 91 required observations, restored the zero-resource baseline across three stable samples, produced a seven-file accepted report/receipt archive, and passed a fresh-process verification after download. The bounded disposition is `qualified` only for the named caller, Provider revision, Contract/profile, artifacts, topology and scenarios. Aggregate conformance, multi-issuer, multi-controller, hostile multi-tenant isolation, HA, deployment and production readiness remain explicit non-claims |
| ADR 0038 caller issuer trust implementation | ADR 0038; implementation `034e647`; Contract lock `fd48de9`; projection regression fix `af8a505`; prior E2E lock `b8d4829`; local reference run `20260907T044611.598221000Z` | One protected listener has one explicit exact issuer with no default or fallback, Provider-local audience and revision anchors, issuer-scoped admitted URI SAN identities, and 1..32 frozen verification keys. Rotation overlaps distinct old/new `kid` values across a restart, stops old-key signing, waits 300 seconds, then removes the old key and restarts again. Issuer substitution remains an authentication failure; a verified wrong local audience or revision is forbidden before mutation reservation. Contract verification, 50-case conformance, root and E2E race/shuffle, vet, E2E lock checks, and the same-repository Docker reference run pass at their recorded identities. The run is 15 initial plus 5 reconstruction scenarios with manifest SHA-256 `60bda2dae83053db447417cea5c5e38d4798e1e90b91fbb5cfc75d2991c6993e`. It is reference evidence only; the named independent-caller result is recorded in P2.7, while multi-issuer admission, multi-tenant isolation, HA, deployment, and production readiness remain open |
| Historical P2.6 portable Provider conformance | ADR 0039; implementation `3fe314a012b808fe60dbd783d7c7c7121d3c548e`; E2E lock refresh `ae476fed12e82f472b19ff78fda633c8d702561d`; then-current 50-case local Suite and unchanged 6-case remote Suite | The historical clean local/remote Runners, root/E2E race and vet, parent-lock, and eight E2E checks passed for their recorded authority. The later 53-case local Suite passed clean VCS-built core CI `35204434771`; the subsequent 60-case local Suite passed the Phase 2 local release gate. No fresh remote run is claimed. Independent caller qualification is separately complete under P2.7. Protected/mutating remote, aggregate, hostile multi-tenant, HA, deployment, and production claims remain open |
| Latest downstream-fencing implementation and local/hosted caller evidence | Contract `5096e71`; projection/lock `24b2e36`; fencing component `b4d41c9`; Provider bootstrap `58488d7`; provisioning/process component `8a1049b`; historical run lock descriptor `b1d41f3`; historical metadata lock refresh `b8d4829`; active metadata lock `ae476fe`; local harness/run `550c785`/`20260906T050213.016063000Z`; hosted harness/run `2cadc53`/`34013982796` | The component and real-backend integration gates remain valid. The clean `linux/arm64` and hosted `linux/amd64` runs each pass all 13 scenarios through two independent mTLS/JWS caller processes, two Gateway processes, one authenticated unique ingress, retained Valkey state, and signed real Chromium. They exercise six protected Provider routes. The local run emits exactly five `0600` evidence files with all cleanup/sanitization checks true; the downloaded artifact contains evidence directory `20260906T052710.781616339Z` with exactly five sanitized files and pins the expected amd64 identities, topology, cleanup, and sanitization state. These close only the platform-specific ADR 0033 external-caller gates. Their historical Contract/tree/48-case identity is pinned but the Suite is not executed (`suite_exercised=false`); refreshing current lock metadata does not relabel those runs. These v1 runs do not exercise ADR 0034 deletion/restore behavior. Valkey provenance/HA/failover, production advertisement/public Gateway, independently implemented external-caller interoperability, aggregate, multi-controller, hostile multi-tenant, deployment, and production readiness remain open |
| ADR 0034 witnessed action-history component and local/hosted caller evidence | ADR 0034; witnessed v2 Redis adapter and Darwin/Linux file witness; pinned Valkey index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`; Contract `5096e71fb84fbec22aa3487a0e55a1b49602ab8b`; tree `859f76dc0e855a0c8abdbbb5648df100dabb4328`; fixed harness `059357c`; local run `20260906T100233.295973000Z`; hosted run `34026680591` | Local focused/full race-shuffle, vet, Contract lock verification, unchanged 48-case Suite, and tagged pinned-Valkey package integration pass. V2 retains at most 4,096 fingerprint-only session records in one permanent hash, rejects missing/malformed history, and compares its sequence/token with an independent monotonic witness; only an exact Redis-ahead-one interrupted commit may reconcile forward. The clean `linux/arm64` and hosted `linux/amd64` fixed-harness runners each pass 18/18 through two Gateways, two independent callers, one unique ingress, real Chromium, a separate orchestrator fault credential, and a file witness outside the logical Valkey restore set. They prove the named deletion, restored-old-snapshot, witness-reconstruction, and checkpoint-mismatch behaviors before rejected actions open a new upstream dial. The local exact five-file set is `0600`; the inspected hosted artifact contains directory `20260906T101111.796974798Z` with exactly five sanitized files. Artifact ID `9987350368` has digest `sha256:3e68f1c4b5bd74e0ae0ff0fde2c9ffefc63852cf9fc82b3019bedfb228bf2c9a`. These close only the platform-specific ADR 0034 caller gates; the Suite remains unexercised. The file witness remains single-process component infrastructure, not production storage. Production witness/storage, Valkey provenance/HA/failover, production ACL separation, configuration/advertisement/deployment, aggregate, multi-controller, hostile multi-tenant, and production-readiness results remain absent |
| ADR 0035 PostgreSQL witness candidate | ADR 0035; `PostgresActionHistoryWitness`; `pgx/v5 v5.9.2`; migration `gateway/capacity/redis/migrations/0001_action_history_witness.sql`; strict `VerifyRestoredState`; hosted workflow run `34031784793` at implementation `3ff58dc`; PostgreSQL digest `sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94` | Namespace/policy digest isolation, idempotent provision, atomic conditional CAS, primary-local synchronous commit, bounded contexts, error redaction, schema constraints, and least-privilege role shape are implemented. Local unit/full race-shuffle, vet, Contract lock, unchanged 48-case Suite, tagged-integration compilation, and the pinned-Valkey strict one-ahead non-mutation scenario pass. The hosted workflow passes the exact migration, role denial, concurrent CAS/reconnect, missing/malformed state, pool-starvation timeout, and combined real PostgreSQL/pinned-Valkey rollback cases. The initial tag pull resolved the digest now pinned by the workflow. The local PostgreSQL environment remained unavailable. Image provenance, independent failure/backup domains, deployment-owned controlled ingress operations, HA/failover, deployment, and production readiness remain unproved |
| ADR 0036 PostgreSQL controlled-restore reference | ADR 0036; profile `browser-postgres-controlled-restore-e2e-v1`; locked PostgreSQL index and exact migration; PostgreSQL witnessed-v2 Provider/private-ingress composition; orchestrator-only Redis restore control; strict restored-state startup; latest main revision/run `838d3bb`/`34069851741`; artifact `browser-postgres-controlled-restore-e2e-evidence-34069851741` | The inspected `linux/amd64` hosted run passes all 18 same-runner scenarios around two Gateways, two independent callers, one unique ingress, Valkey, PostgreSQL, and real Chromium. It quarantines both listeners before restore, rejects an older Redis snapshot without PostgreSQL advance or listener exposure, repairs the exact current state, and resumes only after strict verification. The artifact contains evidence directory `20260907T002737.609312407Z` with exactly five sanitized files; the report is 18/18, and the manifest pins `harness_commit=838d3bb2dea52c10fdc1ddf3136641709fedcb20`, records three ingress reconstructions, all cleanup/sanitization flags true, PostgreSQL restore evidence, `same_runner=true`, `independent_failure_domain=false`, and `suite_exercised=false`. Artifact ID `10000177842` has digest `sha256:96817b74f3faabb0226d7dee1f2ac8128901865a3834f9bcadcaae6459b76032`. This closes only the hosted ADR 0036 same-runner operational reference gate. PostgreSQL and Valkey still share the runner, host, Docker engine, workflow, and operator; provenance, HA, independent failure/backup domains, deployment, and production readiness remain unproved |
| Current hosted CI and evidence tracks | Documentation baseline `27081dfde4dfc726ba4df06d1f3b50012a04d2f2`; core CI `35204434771`; final qualification run `35203241121`; historical Browser and specialized E2E runs retain their recorded identities | Core CI passed all six jobs, including current Contract/local Suite, race/vet, Docker integration, browser provenance, and Ubuntu/macOS supervisor matrices. Final qualification separately passed its exact 15+5 scope. Historical Browser, capacity, revocation, fencing, witness, and restore workflows remain distinct evidence tracks and are not composed into aggregate, multi-controller, hostile multi-tenant, deployment, or production claims |
| GitHub Actions runtime | Node 24 migration `6c1ddde`; E2E lock `e75869d`; CI `33850219645`; Reference `33850219700`; Candidate `33850219664`; Browser `33850219667` | All four workflows passed without the previous Node 20 or `punycode` warnings. This is CI infrastructure evidence only and adds no Provider behavior, external-caller compatibility, deployment, or production-readiness claim |
| Browser-session release CI evidence | implementation/ledger baseline `df78739`; lock-refresh baseline `6163de1` | Repository CI runs `33712081491` and `33712412434` each passed `provider-contract`, `test`, and `docker-integration`. This is repository CI only, not browser external-caller or production evidence |
| Browser publication baseline CI evidence | hosted harness baseline `e7e4d57`; Provider lock `83a7884` | Repository CI run `33725664862` passed `provider-contract`, `test`, and `docker-integration`. This remains repository CI; exact Browser image publication is separately evidenced by run `33724368530`, and neither run is browser caller E2E |
| Prior inspected reference regression artifact | hosted harness/Provider `17ed6ca`/`b4d41c9`, run `33970773414`; latest local pre-refresh harness/Provider `59e08d5`/`c0a55d1`, run `20260905T080530.577843000Z` | Hosted and local Reference E2E each passed all 15 initial and 5 process-reconstruction/resume coding/shell scenarios. Hosted artifact `reference-e2e-evidence-33970773414` has digest `sha256:de2c6f2d31d9dd5a8323d82560bf0f314970c8e1825d815d224d48aac2dcba16`; the local run pins runtime digest `sha256:c1da999518ed8cf3c422142b705f3eeca5d60104be07bc28c15a7d527d2907fc`. This is coding/shell regression evidence, not Browser E2E or durable-revocation caller evidence |
| Prior inspected Agent Platform candidate artifact | hosted harness/Provider `17ed6ca`/`b4d41c9`, run `33970773345`; latest local pre-refresh harness/Provider `59e08d5`/`c0a55d1`, run `20260905T080623.861033000Z` | Hosted and local candidate E2E each passed all 15 initial plus 5 resume coding/shell scenarios, including candidate shadow/selection/rollback/drain policy and reconstruction. Hosted artifact `platform-candidate-e2e-evidence-33970773345` has digest `sha256:546c3ecd6f2cd23a629ab53eb61bbe23fa7361c8440297c0fb039886802d7bc0`; the local run pins runtime digest `sha256:c1da999518ed8cf3c422142b705f3eeca5d60104be07bc28c15a7d527d2907fc`. This is candidate integration only, not Browser evidence, real Veronica, durable-revocation caller evidence, or production evidence |
| Internal Block manifest foundation | implementation in `blocks/manifest.go`; ADR 0016 and plan `block-manifest-loader.md` | Strict `sandbox.runtime/v1alpha1` YAML/JSON parsing, digest-pinned images, bounded command/capability/path validation, symlink/nested-path rejection, duplicate detection, deterministic read-only registry, and defensive-copy tests pass. This is internal component evidence only; no Provider Contract, route, advertisement, runtime image, or production claim |
| P4 optional-profile authority | Contract `5096e71`; projection/lock `24b2e36`; 48-case Suite; command graph `66183b1`; Browser capacity `7b062e6`; Browser edge `44ea2ee`; Browser TLS edge `b8f8941`; authenticated capacity `997fb0d`; Redis-compatible capacity `9434540`; ADR 0032 revocation component `c0a55d1`; durable-revocation harness/Gateway `e952ef9`; ADR 0033 component `b4d41c9`; fixed v2 harness `059357c`; local v2 run `20260906T100233.295973000Z`; hosted v2 run `34026680591`; ADR 0035 witness component `3ff58dc`; latest ADR 0036 run `838d3bb`/`34069851741`; local downstream harness/run `550c785`/`20260906T050213.016063000Z`; hosted downstream harness/run `2cadc53`/`34013982796` | Browser authority and all named component/caller gates remain separate. ADR 0033 passes 13/13 on `linux/arm64` and `linux/amd64` for its locked v1 topology; its Contract Suite remains unexercised. ADR 0034 separately passes its witnessed-v2 component and pinned-Valkey adapter gates plus its `linux/arm64` and `linux/amd64` 18/18 caller/Chromium deletion-and-restore gates. ADR 0035 passes its real PostgreSQL component gate, and ADR 0036 passes its hosted same-runner 18/18 controlled-restore gate. Their Suites remain unexercised where recorded. Production independent witness/storage and restore operations, Valkey/PostgreSQL provenance/HA/failover, production configuration/metrics/deployment, aggregate, multi-controller, hostile multi-tenant, independently implemented external-caller interoperability, and production gates remain open |
| P4 browser image sandbox and provenance | ADR `0018`/`0019`; implementation `6e02f1c`; native-runner correction `99b8d36`; exact-index correction `494401a`; publication run `33724368530`; attestation `44912296` | Local arm64/amd64 integration passed with Chromium `151.0.7922.109`, a sandboxed zygote, no `--no-sandbox`, and seccomp digest `sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`. GHCR index `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f` has independently verified GitHub OIDC/Sigstore provenance for source `58ed009`. Independent inspection found only linux/amd64 and linux/arm64/v8 manifests. This closes the Browser image publication gate; command/caller evidence is recorded separately and production advertisement/deployment remains open |
| P4 browser session component | implementation `9a5d225`; lock/CI baseline `6163de1`; CI `33712412434` | Independent `provider/browser` domain and runtime ports, durable memory/file authority, accept-before-allocation coordinator, restart reconciliation, expiry/cancellation/unknown-outcome cleanup, separate opaque reference memory/file registry and resolver, browser operation-family projection, and bounded duration usage evidence pass focused and full-repository race/shuffle plus vet. This row remains Provider-local component evidence only; command/runtime and Browser external-caller evidence are recorded separately and do not convert it into aggregate, multi-controller, tenant, deployment, or production evidence |
| P4 browser Docker adapter component | implementation `cd33ba3`; E2E lock refresh `e1de512`; ADR 0020; CI `33731520938` and `33732133500` | The adapter requires injected provenance verification and restricted-egress provisioning, validates the exact signed image/seccomp/platform metadata, applies finite resources and four bounded stable guest mounts, persists private allocation/network identity, verifies owned restart state, and establishes a fresh non-TTY container-loopback CDP WebSocket relay. Focused/full race-shuffle, vet, the unchanged Contract verifier and 48-case Suite, the local tagged Docker driver matrix, and both three-job repository CI runs pass. The original live case used `network=none`, so this row is private-relay component evidence; complete composition and caller evidence are recorded separately and do not establish advertisement, aggregate, multi-controller, tenant, deployment, or production behavior |
| P4 browser provenance-verifier component | implementation `9390554`; E2E lock refresh `330f629`; ADR 0021; CI `33737531693` | The `provider/browser/provenance/ghcli` adapter rehashes a pinned absolute `gh` executable, fetches the bundle from the immutable GHCR artifact, enforces exact repository/workflow/source/GitHub OIDC/hosted-runner/SLSA identity, strictly rechecks one bounded verified statement, limits inherited environment, discards diagnostics, and preserves cancellation. Focused/full race-shuffle, vet, Contract verification, the unchanged 48-case Suite, real local GHCR/Sigstore integration, and the hosted `browser-provenance` job pass. Command/caller evidence is recorded separately; this component alone does not establish advertisement, aggregate, multi-controller, tenant, deployment, or production evidence |
| P4 browser restricted-egress component | implementation `7e60340`; E2E lock refresh `7f15628`; ADR 0022; CI `33747803509`; local Gateway image `sha256:202bbf92fcbcce87e4b800f093d1df281125ab6fa43152906564cf8e0b7021d6` | A strict local policy registry, DNS/HTTP/TLS Gateway, per-allocation internal Docker bridge, explicitly owned uplink, immutable lifecycle/create policy binding, Browser-only DNS/network projection, policy/lease/ownership recovery, and exact cleanup pass focused/full race-shuffle, vet, unchanged Contract verification and 48-case Suite. The original combined tagged integration proved allowed HTTP/HTTPS, denied unlisted/metadata targets, reconstruction, and cleanup. `f760369` adds bounded EDNS0 compatibility and hosted Browser run `33838215924` passes the complete path. This row remains component/lifecycle evidence; Gateway image publication, advertisement, aggregate, multi-controller, tenant, deployment, and production gates remain open |
| P4 browser protected transport component | implementation `b8423f5`; ADR 0023; harness lock `a2721ad`; CI `33760609353`; hosted regressions `33760609272`/`33760609231` | The two Contract-authorized Browser routes pass through mTLS/JWS/admission binding, bounded closed-JSON preflight, replay/fencing, application correlation, async operation projection, expiry, opaque handoff projection, and bounded error mapping. Nil application and malformed application identity fail closed; Browser operation-family aggregation is covered. Full race/shuffle, vet, Contract verification, and the 48-case Suite pass. This row remains Provider admission/transport component evidence; the default-disabled command and external Browser caller are recorded separately, while production advertisement, aggregate, multi-controller, tenant, deployment, and production gates remain open |
| P4 caller-owned Browser Gateway component | implementation `5aae281`; ADR 0024; E2E lock `9eb32ba`; CI `33826813073`; hosted regressions `33826813099`/`33826813100` | The shared Gateway policy state machine enforces exclusive terminal/Browser session identity and reference namespaces and exact resolved endpoint binding. The Browser composition requires caller authorization, revocation, recording, WebSocket admission, Provider resolution, and bounded reconnect settings; its private adapter validates RFC 6455 framing without auditing CDP payloads. Focused/full race-shuffle, vet, Contract verification, and the 48-case Suite pass. Its composition in the reference caller is recorded separately; no production public route, advertisement, aggregate, multi-controller, tenant, deployment, or production evidence is claimed |
| P4 initial browser command and external-caller evidence | ADR 0025/0026; command implementation `66183b1`; Provider DNS fix `f760369`; harness `79fee2b`; CI `33838215949`; hosted Browser run `33838215924` | The explicit default-disabled command graph binds the exact Browser runtime, provenance, restricted-egress/create-policy, durable session/reference, operation/usage, recovery, and shutdown dependencies without adding a public Gateway or production advertisement. Hosted `linux/amd64` Browser Reference E2E passed 10 initial plus 5 reconstruction scenarios over separate caller/reference processes, real mTLS/JWS HTTPS, WebSocket, signed-image provenance, Docker, CDP, allowed/denied egress, Gateway denial/expiry/revocation, partial/complete usage, mTLS caller rejection, recovery, and cleanup. Artifact `browser-reference-e2e-evidence-33838215924` has digest `sha256:4acfbc97c0c1f64e987b00870849a2244e33596918d08e659385c428310843ea`. This historical row closes only the Browser reference external-caller gate for its named lock; it contains no active capacity-rejection scenario and proves no production advertisement/public Gateway, independently implemented external-caller interoperability, aggregate, multi-controller, hostile multi-tenant, deployment, or production property |
| P4 Browser Gateway local-capacity component and caller evidence | ADR 0027; implementation `7b062e6`; E2E lock `a219d29`; harness `28a9a5e`; CI `33846603580`; hosted Browser run `33846603547` | Non-blocking total/per-session capacity is acquired after exact authorization binding and before revocation, the `authorized` audit event, Provider resolution, and backend dial, then released on every connection exit. Focused concurrency/revocation tests, full local gates, four-job repository CI, and hosted `linux/amd64` Browser Reference E2E pass. The caller holds an admitted CDP connection, observes rejection of a second same-session grant without disrupting the first, and connects a replacement after release. All 11 initial and 5 reconstruction scenarios pass; artifact `browser-reference-e2e-evidence-33846603547` has digest `sha256:b024225aa3545fa56a7cc5113f29c0817a86ebc70c3976e10d81bf3507546cba`. This is single-process capacity plus Browser reference external-caller evidence only; WebSocket pre-upgrade load, authorization load, distributed capacity/revocation, production advertisement/public Gateway, independently implemented external-caller interoperability, aggregate, multi-controller, hostile multi-tenant, deployment, and production gates remain open |
| P4 Browser pre-upgrade edge component and caller evidence | ADR 0028; implementation `44ea2ee`; E2E lock `3b63c76`; local harness/run `249cdd4`/`20260904T080946.250607000Z`; hosted harness/run `e7e7f03`/`33854020809`; CI `33854020951` | Browser composition requires a process-local global connection/fixed-window request gate before WebSocket admission and upgrade. Focused/full race-shuffle, vet, Contract verification, the unchanged 48-case Suite, independent E2E module gates, clean local `linux/arm64`, and hosted `linux/amd64` Browser runs pass. The added 16-request authenticated wrong-Origin burst observes ordinary `403`, generic pre-upgrade `429` with bounded `Retry-After`, and recovery. Hosted artifact `browser-reference-e2e-evidence-33854020809` has digest `sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`. All 12 initial and 5 reconstruction scenarios pass; the 20-record Gateway audit contains six `authorized`, six `connected`, four `client_closed`, and one each `capacity_rejected`, `denied`, `expired`, and `revoked`, with no `grant-browser-edge-*` identity. This is a process-local Browser service plus reference external-caller result only; listener/TLS/HTTP limits, partition-aware shared capacity, distributed durable revocation, production advertisement/public Gateway, independently implemented external-caller interoperability, aggregate, multi-controller, hostile multi-tenant, deployment, and production gates remain open |
| P4 Browser listener/TLS/HTTP component and caller evidence | ADR 0029; implementation `b8f8941`; local harness/run `35cf068`/`20260904T091156.303717000Z`; hosted harness/run `7a20d9d`/`33857739150`; CI `33857739103` | The caller-owned reference edge loads bounded regular-file server-auth material before bind, freezes TLS 1.3 plus HTTP/1.1, caps accepted connections, and requires explicit header/read/write/idle limits with context-aware startup/shutdown. Focused/full race-shuffle, vet, Contract verification, the unchanged 48-case Suite, independent E2E module gates, clean local `linux/arm64`, and hosted `linux/amd64` Browser runs pass. The black-box caller rejects TLS 1.2, proves TLS 1.3/HTTP/1.1, rejects slow and oversized headers before the handler, saturates the accepted-connection limit, and observes recovery. All 13 initial and 5 reconstruction scenarios pass. Hosted artifact `browser-reference-e2e-evidence-33857739150` has digest `sha256:94bcdfa53b667d4a6bc17fd6714cc9895e8402b830b8c6425c604c835f9228f`; inspected directory `20260904T091942.992885726Z` pins Provider/Contract/tree/Suite/image/platform. Its 20-record Gateway audit preserves the previous type counts with no edge grant, endpoint, token, credential, CDP, or payload field. This is a process-local listener/TLS/HTTP component plus Browser reference external-caller result only; partition-aware shared/distributed capacity, durable distributed revocation, production storage/configuration and metrics, production advertisement/public Gateway, independently implemented external-caller interoperability, aggregate, multi-controller, hostile multi-tenant, deployment, and production gates remain open |
| P4 Browser authenticated-capacity port, memory component, and reference regression | ADR 0030; implementation `997fb0d`; E2E lock `49d1c20`; harness `6b01b75`; CI `33940332882`; hosted Browser run `33940332911` | Browser composition now requires a caller-owned capacity authority after exact grant binding and before revocation, authorized audit, Provider resolution, or dial. Typed loss/unavailability terminates both streams without reconnect; release uses an independent bounded context; simultaneous causes resolve as revocation, expiry, capacity, then transport. The memory reference atomically enforces global, tenant, and exact tenant/sandbox/session limits without storing caller, grant, credential, handoff, endpoint, or backend identity. Local and hosted component/lock gates pass. Hosted `linux/amd64` Browser Reference E2E passed 13 initial plus 5 reconstruction scenarios against Provider `997fb0d`; artifact `browser-reference-e2e-evidence-33940332911` has digest `sha256:f4133967b6e573c701b82c72dc4d101febd4e6b28199e188fa0c8db049bff9ae`. Its active contention path uses the authenticated memory authority. This remains process-local reference external-caller evidence; no shared-store TTL/renewal, ownership, crash reclamation, stale-owner fencing, two-Gateway-process, distributed revocation, deployment, or production evidence is claimed |
| P4 Browser Redis-compatible shared capacity and local two-Gateway evidence | ADR 0031; implementation `9434540`; Provider baseline `2ed5e68`; harness/Gateway source `ddbb2c4`; local run `20260905T061037.558537000Z` | The adapter verifies immutable policy, uses one bounded sorted-set record per lease, and implements atomic Lua acquire/renew/release, Redis server-time expiry, conservative renewal, TTL crash reclamation, and opaque-owner monotonic fencing. All 10 scenarios pass on `linux/arm64` through two independent Gateway OS processes and pinned Valkey. Rejection is post-`101` normal `1000` close, not HTTP `429`. The manifest pins Contract/tree/48-case metadata with `contract.exercised=false`, and pins Valkey index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd` with `provenance_not_established=true`. This is local Gateway shared-capacity evidence only, not hosted, Provider Contract E2E, Browser/CDP, HA/failover, durable distributed revocation, downstream fencing, Provider multi-controller, hostile multi-tenant, independently implemented external-caller interoperability, deployment, or production evidence |
| P4 Browser shared capacity hosted two-Gateway evidence | workflow/run `Browser Shared Capacity E2E`/`33949577876`; harness/Gateway source `de297e7`; Provider baseline `2ed5e68`; artifact `browser-shared-capacity-e2e-evidence-33949577876` | The hosted `linux/amd64` run independently passes all 10 scenarios. GitHub artifact digest is `sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`; downloaded run `20260905T062246.271594332Z` contains exactly six sanitized files. Audits contain 22 `authorized`, 22 `connected`, 18 `client_closed`, five `capacity_rejected`, two `capacity_lost`, and two `capacity_unavailable`; observations contain 22 `resolve` and 22 `dial`. The manifest pins Valkey index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`, amd64 child `sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478`, Contract/tree/48-case metadata with `exercised=false`, and `provenance_not_established=true`. This is hosted Gateway/Valkey shared-capacity evidence only, not Provider Contract E2E, Browser/CDP, image provenance, restricted egress, Provider artifact/usage, Valkey provenance, HA/failover, durable distributed revocation, downstream fencing, Provider multi-controller, hostile multi-tenant, independently implemented external-caller interoperability, aggregate, deployment, or production evidence |
| P4 Browser exact-grant durable revocation component | ADR 0032; implementation `c0a55d1`; E2E lock `59e08d5`; hosted evidence `c7fe24d`; pinned Valkey index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd` | The Gateway now requires one atomic, level-triggered exact-grant revocation watch; nil, malformed, conflicting, or unavailable watches fail closed; revocation cancels blocked resolution/dial work and wins the documented stable termination priority. The memory adapter and Redis-compatible retained-tombstone source/writer pass focused/full race-shuffle, vet, Contract verification, the unchanged 48-case Suite, and tagged real-Valkey component integration. The Redis adapter verifies immutable policy, hashes namespace/grant identities, uses server time and bounded grant lifetime, retains the maximum tombstone expiry, bounds operations/polling, and rejects malformed or unavailable state. Pre-ADR0033 local and hosted Browser `13+5`, Reference/Candidate `15+5`, and shared-capacity `10/10` regressions pass; hosted run IDs are `33955436984`, `33955436969`/`33955437046`, and `33955436968`. This row is component and regression evidence only: those runners do not exercise the separately required two-Gateway/independent-revoker retained-backend scenario, downstream fencing, Valkey provenance/HA, multi-controller, multi-tenant, deployment, or production behavior |
| P4 Browser durable-revocation local and hosted caller evidence | ADR 0032; harness/Gateway `e952ef9`; Provider `c0a55d1`; local `linux/arm64` run `20260905T095109.569973000Z`; hosted `linux/amd64` run `33959122456`; artifact `browser-durable-revocation-e2e-evidence-33959122456` | Both runs passed all seven locked scenarios through two independent Gateway OS processes, two independent black-box caller processes, one independent revoker process, and one pinned retained Valkey authority. Local A/B revoke-to-close propagation was 72/72 ms and hosted was 97/99 ms, below the 2-second bound. The runs prove active and pre-resolution exact-grant revocation on both Gateways, retained rejection after two Gateway reconstructions, unaffected same-session/other-tenant grants, outage failure closure, recovery without resurrection, and exactly seven sanitized evidence files. Hosted artifact digest is `sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`; its audit totals are nine each `authorized`/`connected`/`revoked`, four each `revocation_unavailable`/`client_closed`, nine each `resolve`/`dial`, and three `revoke_committed`. Contract/tree/48 cases are metadata with `exercised=false`; Valkey provenance is not established and `acl_role_separation_established=false`. This closes only the ADR 0032 caller-owned durable exact-grant revocation gate, not Provider API/Contract conformance, real Browser/CDP or downstream fencing, independently implemented external-caller interoperability, multi-controller, hostile multi-tenant, deployment, or production readiness |
| P4 Browser downstream CDP fencing component and local/hosted external-caller evidence | ADR 0033; fencing implementation `b4d41c9`; Provider bootstrap `58488d7`; provisioning/process implementation `8a1049b`; lock descriptor `b1d41f3`; local harness/run `550c785`/`20260906T050213.016063000Z`; hosted harness/run `2cadc53`/`34013982796`; pinned Valkey index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd` | The action-fence/private-ingress/Redis adapter passes its component plus real-backend integration gate. The local arm64 and hosted amd64 runs each pass 13/13 through two independent mTLS/JWS callers, two Gateways, one authenticated unique ingress, retained Valkey, and signed real Chromium. They prove ordinary/replacement mutations, stale and pre-action lease-loss rejection before Chromium, terminal lower-fence closure without reconnect, unaffected scopes, outage recovery, retained high-water across ingress reconstruction, bypass exclusion, and cleanup/sanitization. The local run retains exactly five `0600` files; the downloaded artifact contains evidence directory `20260906T052710.781616339Z` with exactly five sanitized files. Manifest cleanup and sanitization booleans are all true. Six protected Provider routes are exercised, but the 48-case Suite is not (`suite_exercised=false`). These close only the platform-specific ADR 0033 caller gates. Deleted/restore-missing high-water detection, restored-snapshot consistency, Valkey provenance/HA/failover, production metrics/configuration/deployment, Provider multi-controller reliability, hostile multi-tenant isolation, independently implemented external-caller interoperability, aggregate conformance, and production readiness are not proved |
| P4 Browser witnessed action-history component and local/hosted caller evidence | ADR 0034; witnessed v2 implementation; pinned Valkey index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`; fixed harness `059357c`; local run `20260906T100233.295973000Z`; hosted run `34026680591` | The explicit v2 successor adds permanent bounded fingerprint-only history, strict whole-hash validation, an independent monotonic checkpoint witness, exact one-step interrupted-CAS recovery, and stable fail-closed errors. Focused/full race-shuffle, vet, Contract verification, the unchanged 48-case Suite, and tagged real-Valkey adapter integration pass. It does not rewrite v1 or alter default composition. The separately locked real-Chromium caller harness passes 18/18 locally on `linux/arm64` and hosted on `linux/amd64`; the local set has exactly five `0600` evidence files, and the inspected hosted artifact has exactly five sanitized files with all cleanup/sanitization checks true. These close the platform-specific deletion/restore caller gates only; the Suite is not executed. The included file witness is local single-process infrastructure, not HA or production storage. Production witness, deployment-owned operational restore, deployment, and production gates remain open |
| Review | PR [#17](https://github.com/shell-echo/sandbox-runtime/pull/17) merged as `43ff3d7`; PR [#18](https://github.com/shell-echo/sandbox-runtime/pull/18) merged as `4774c3a`; PR [#19](https://github.com/shell-echo/sandbox-runtime/pull/19) merged as `e2755f5`; PR [#21](https://github.com/shell-echo/sandbox-runtime/pull/21) merged as `c5a4a65`; PR [#22](https://github.com/shell-echo/sandbox-runtime/pull/22) merged as `44f39ec`; PR [#23](https://github.com/shell-echo/sandbox-runtime/pull/23) merged as `ac72eab`; PR [#24](https://github.com/shell-echo/sandbox-runtime/pull/24) merged as `2e3dde6`; PR [#25](https://github.com/shell-echo/sandbox-runtime/pull/25) merged as `88506d1`; PR [#26](https://github.com/shell-echo/sandbox-runtime/pull/26) merged as `4ccb107`; PR [#27](https://github.com/shell-echo/sandbox-runtime/pull/27) merged as `28076a7`; PR [#28](https://github.com/shell-echo/sandbox-runtime/pull/28) merged as `2b25f76`; PR [#29](https://github.com/shell-echo/sandbox-runtime/pull/29) merged as `83965a2`; PR [#30](https://github.com/shell-echo/sandbox-runtime/pull/30) merged as `9d00212`; PR [#31](https://github.com/shell-echo/sandbox-runtime/pull/31) merged as `67b64a9`; PR [#32](https://github.com/shell-echo/sandbox-runtime/pull/32) merged as `5883da9`; PR [#33](https://github.com/shell-echo/sandbox-runtime/pull/33) merged as `ba39053`; PR [#35](https://github.com/shell-echo/sandbox-runtime/pull/35) merged as `c467cd4`; PR [#36](https://github.com/shell-echo/sandbox-runtime/pull/36) merged as `3a980bd`; PR [#37](https://github.com/shell-echo/sandbox-runtime/pull/37) merged as `f9cfbc3`; PR [#38](https://github.com/shell-echo/sandbox-runtime/pull/38) merged as `7ebcc8f`; PR [#39](https://github.com/shell-echo/sandbox-runtime/pull/39) merged as `17072e6`; PR [#40](https://github.com/shell-echo/sandbox-runtime/pull/40) merged as `65a9ba3`; PR [#41](https://github.com/shell-echo/sandbox-runtime/pull/41) merged as `ac555619`; PR [#42](https://github.com/shell-echo/sandbox-runtime/pull/42) merged as `97fb429` | PR #42 CI `32465114377` and post-merge CI `32465443385` provider-contract, test, and docker-integration passed |
| P2.2a release evidence | `2fa2e72` on PR #33, merged as `ba39053` | Local race/shuffle, vet, lock, Suite, PR CI, and post-merge CI passed |
| P2.2b release evidence | `e26bf2b` on PR #35, merged as `c467cd4` | Local race/shuffle, vet, lock, 19-case Suite, PR CI `32456100570`, and post-merge CI `32456279722` passed; no HTTP/dispatch composition |
| P2.2c release evidence | `275a9e9` on PR #39, merged as `17072e6` | Local race/shuffle, vet, lock, 19-case Suite, PR CI `32460695928`, and post-merge CI `32460914417` passed; no HTTP/Docker/automatic redispatch |
| P2.3a/b merge evidence | PR [#43](https://github.com/shell-echo/sandbox-runtime/pull/43) merged as `21f5236` | PR CI `32468912019` and post-merge CI `32469390678` provider-contract, test, and docker-integration passed; this proves resource/lock/projection evidence only |
| Contract namespace | `urn:shell-echo:sandbox-runtime:provider-v1` | Locked |
| Contract version/license | `1.0.0` / MIT | Locked |
| P2.3c0 local evidence | corrected resources `71fee34`; corrected projection and lock `ab9defc` | Full race/shuffle, vet, lock verifier, 26-case Conformance Suite, JSON parsing, and diff check passed locally against the final revision |
| P2.3c0 release evidence | PR [#44](https://github.com/shell-echo/sandbox-runtime/pull/44) head `16136d2`, merged as `6c1fc90` | Exact-head PR CI `32685685846` and post-merge CI `32686754674` passed `provider-contract`, `test`, and `docker-integration`; review findings were resolved before merge |
| P2.3c1 local evidence | independent `provider/session` domain and transactional `Authority` port | Focused and full race/shuffle, vet, lock verifier, 26-case Suite, JSON, dependency-boundary, and diff checks passed; no persistence or dispatch composition |
| P2.3c1 release evidence | PR [#45](https://github.com/shell-echo/sandbox-runtime/pull/45) merged as `4c37d8c` | PR CI `32696507856` and post-merge CI `32696727371` passed `provider-contract`, `test`, and `docker-integration`; Node.js 20 deprecation warnings remain |
| P2.3c2 local evidence | independent session memory/file repositories and transactional sandbox authority checks | Focused/full race/shuffle, vet, unchanged Contract lock, 26-case Suite, restart, expiry, idempotency, CAS generation/fencing, and diff checks passed; no transport or dispatch composition |
| P2.3c2 release evidence | direct `main` commit `e5c9dec` | Post-push CI #103 / run `32698606341` passed `provider-contract`, `test`, and `docker-integration`; Node.js 20 deprecation warnings remain |
| P2.3c3 local evidence | implementation commit `186190b` | Session application, protected POST/GET projection, admission binding, strict decode, status/expiry mapping, opaque endpoint non-disclosure, route coverage, full race/shuffle, vet, lock verifier, 26-case Conformance Suite, and diff checks passed; no Gateway/WebSocket composition |
| P2.3c4 local evidence | implementation commit `e675cb9` | Independent Gateway authorization binding, opaque reference resolution, bidirectional frame proxy, bounded reconnect, generation/expiry checks, revocation interruption, metadata-only audit, full race/shuffle, vet, dependency boundary, and diff checks passed; no real external caller or production wire claim |
| P2.3c4 release evidence | post-push CI run `32801539995` | `provider-contract`, `test`, and `docker-integration` all passed for the repository revision; this remains component/Gateway evidence, not external-caller or production readiness |
| P2.4 Contract authority | commits `4f3da4e` and `649c293` | Additive artifact staging request/evidence and usage evidence schemas, OpenAPI paths, semantic rules, fixtures, DTO projection, Suite cases, and ADR 0012; no runtime dispatch in the Contract step |
| P2.4 local evidence | commits `1ca700d` and `41225c0`, fix `3b94146` | Artifact/usage bounded domain, ports, memory staging/repository adapters, digest/MIME/size and check admission, idempotent replay/conflict, expiry, close, cancellation, and immutable evidence tests; component evidence only |
| P2.4 release evidence | post-push CI run `32804619553` | `provider-contract`, `test`, and `docker-integration` all passed for the final adapter revision; no Provider HTTP composition or external-caller claim |
| P2.4a0 admission authority | Contract commits `3a9d8b7` and `7e00715`; lock/admission commit `2aba87f` | Locks `stage_artifact`, `read_artifact_staging_evidence`, and `read_usage_evidence`; the stage mutation consumes replay/fencing guard state, reads do not; async outcomes, `400`/`503` error surface, descriptor JCS digests, unknown-operation rejection, and route absence are covered |
| P2.4a0 release evidence | post-push CI run `32819717542` | `provider-contract`, `test`, and `docker-integration` all passed; this proves Contract/admission authority only, not handler, application, staging dispatch, usage collection, or external-caller compatibility |
| P2.4a1 read authority | Contract commits `3846c9e` and `6f549c2`; lock/projection commit `dbea0e8`; ADR 0014 | Locks generic operation-family aggregation plus artifact pending/outcome-unknown/expired and usage unavailable/expired read states; no application, repository, aggregator, handler, router, or transport was added |
| P2.4a1 release evidence | post-push CI run `32823783136` | `provider-contract`, `test`, and `docker-integration` all passed; local race/shuffle, vet, lock verifier, projection/admission tests, and 35-case Suite also passed |
| P2.4a2 application component | commits `152033f`, `0440272`, and `4d0bb70` | Independent artifact accepted/running/terminal/outcome-unknown authority, explicit dispatch/reconcile boundary, memory/file adapters, expiry tombstones, usage operation-id index, lifecycle/artifact operation readers, and collision-safe aggregator; no handler/router/config change |
| P2.4a2 release evidence | post-push CI run `32827387303` | `provider-contract`, `test`, and `docker-integration` all passed; local authorized race/shuffle, vet, lock verifier, 35-case Suite, dependency-boundary tests, and `git diff --check` passed |
| P2.4a3 transport component evidence | commits `f5111a5`, `ce3c6e0`, `9a4bc71`, correction `c469337` | Three locked routes are admitted before application dispatch; artifact accept returns only `202` operation; evidence/usage state mappings and operation-family aggregation pass. Local race/shuffle, vet, lock verifier, 35-case Suite, focused projection tests, diff checks, and post-push CI `32838784395` (all three jobs) pass. This slice corrected artifact-stage preflight only; P2.5c later applies the ordering to create/session |
| Gateway clock correction | commit `0893ac3` | Grant-expiry timers now derive from the configured clock used by authorization and endpoint checks. Focused Gateway race/shuffle passed ten consecutive runs and the full race/shuffle suite passed. This is component regression evidence only |
| P2.5b Contract/projection evidence | Contract commit `22a148e`; projection/lock commit `123d16a`; status baseline `206caeb` | Locks one atomic `sandbox.exec@1.0.0` + `sandbox.terminal@1.0.0` coding/shell profile and retains terminal-only compatibility. Empty, terminal-only, and complete coding/shell advertisements are accepted; exec-only, missing/split mapping, and unknown-capability shapes fail closed. Full race/shuffle, vet, lock verification, 38-case Suite, diff checks, and post-push CI `32924361132` passed. No runtime behavior or nonempty startup advertisement was enabled |
| P2.5c admission-ordering evidence | transport commit `6c2962b`; Suite mapping `6340604`; status baseline `9b10abd` | Create and runtime-session bounded strict decode and Contract-safe `400` body-limit rejection precede digest/binding admission and mutation guard reservation. Digest-consistent unknown fields and oversized bodies consume no guard state; valid replay and stale fencing remain `409`. Full race/shuffle, vet, unchanged lock verification, mapped 38-case Suite, diff checks, and post-push CI `32926181615` passed. No dispatch or runtime behavior was added |
| P2.5d runtime evidence | implementation commit `de18787`; evidence baseline `e3a8265` | Provider-specific Docker lifecycle adapter, stable `/inputs` read-only, `/workspace` mutable, `/outputs` staging, bounded tmpfs `/tmp`, digest-pinned image, numeric non-root user, read-only root, resource/network bounds, ownership labels, idempotent create/remove, restart observation, unknown-outcome evidence, and explicit development composition passed focused/full race-shuffle, vet, unchanged Contract verification, 38-case Suite, diff checks, both real Docker integration packages, and post-push CI `32929140044`. This is single-controller development evidence only |
| P2.5e exec vertical evidence | implementation commit `5917a57`; evidence baseline `2f7a79b` | Protected exec/cancel/result/operation routes, strict preflight, durable accept-before-dispatch, independent exec persistence and migration, correlation/conflict checks, injected-clock ordering, retained terminal summary, restart/on-demand reconciliation, Docker execution/cancellation, private bounded capture, expiry, and unsupported-reference rejection passed focused/full race-shuffle, vet, unchanged Contract verification, the 38-case Suite, diff checks, and both live Docker integration packages. Post-push CI `32937530059` passed all three jobs; this is single-controller Provider/CI evidence only |
| P2.5f0 terminal/Gateway design evidence | source and Contract audit on 2026-08-27; `docs/plan/p2.5f-terminal-gateway-vertical.md` | Confirms that session authority and Gateway components are not command-composed and that the current non-TTY, no-stdin, one-shot Docker exec attach cannot prove terminal restart/reconnect. Locks ownership, provider-neutral/private persistence, cleanup, capacity, and f1-f7 delivery boundaries. No code, Contract, runtime, WebSocket, external-caller, or readiness evidence is claimed |
| P2.5f1 terminal runtime evidence | implementation commit `6778d3c`; evidence baseline `66dd3d1` | Backend-neutral allocate/observe/attach/cleanup ports, PTY-owning guest broker, adapter-private Docker identity, opaque `ref:terminal/*` receipt, lost-start recovery, capacity, expiry, identity conflict, process-group cleanup, sandbox removal, cancellation, and corrupt-state tests passed. Full local gates and repository CI `33033284420` passed all three jobs, including live Docker same-shell reattach after Provider driver reconstruction. No session coordinator, `ref:session:*` resolver, WebSocket/Gateway composition, external caller, or readiness evidence is claimed |
| P2.5f2 durable session coordination evidence | implementation commit `ccffd52`; evidence baseline `3abefd4` | Session repository v2, valid v1 migration, provider-neutral allocation receipt/observation evidence, trusted lifecycle projection, session-local fencing high-water, durable accept-before-allocation, exact-identity lost-attachment recovery, no replacement after uncertain outcomes, restart reconciliation, expiry/cleanup retry, corruption rejection, and registry-supplied success evidence passed focused/full race-shuffle, vet, module/Contract verification, the locked 38-case Suite, diff checks, and both live Docker integration packages. Post-push CI `33045725476` passed all three jobs. No `ref:session:*` registry/resolver, WebSocket/Gateway or command composition, external caller, multi-controller, tenancy, deployment, or readiness evidence is claimed |
| P2.5f3 opaque-reference evidence | implementation commit `b1acdd1`; evidence baseline `7138a4c` | A separate memory/file registry and resolver persist a random opaque `ref:session:*` binding for a running allocation. Resolution and every fresh `Dial` recheck active registry state plus exact committed session handoff identity before adapter attach. The file adapter has versioned JSON, atomic replacement, directory sync, and a single-controller lock; collision, restart, expiry, revocation, generation/reference mismatch, and concurrent resolve/revoke tests pass. Full race/shuffle, vet, module and unchanged Contract verification, the 38-case Suite, diff checks, and both live Docker integration packages passed locally. Repository CI `33059304542` passed all three jobs. No Contract, DTO, Provider transport, Gateway, command composition, external caller, aggregate conformance, multi-controller, tenancy, deployment, or production readiness evidence is claimed |
| P2.5f4 WebSocket/terminal adapter evidence | implementation `14f14cc`; evidence baseline `1d9da67`; CI `33064864447` | `gateway/adapter` keeps `github.com/coder/websocket@v1.8.15` and `provider/terminal.Stream` outside Gateway policy. Its WebSocket edge requires caller-owned admission before upgrade, rejects wildcard origin patterns, leaves compression disabled and same-origin enforcement on by default, and bounds messages to 32 KiB by default / 64 KiB maximum. It maps only text/binary data to `gateway.Stream`; WebSocket control frames are library-handled and never become terminal bytes. Focused race/shuffle tests cover admission, origin rejection, binary flow, ping/pong, normal/abrupt close, inbound `1009`, cancellation, terminal partial I/O, bounds, and idempotent close. Full local regression gates and repository CI `provider-contract`, `test`, and `docker-integration` passed. The dependency source/license/behavior review passed; `govulncheck` and OSV scanning were unavailable and are not claimed. No Gateway authorization/revocation/audit composition, Provider route/configuration, external caller, aggregate, multi-controller, tenancy, deployment, or production evidence is claimed |
| P2.5f5 Gateway composition evidence | implementation `fdfc771`; evidence baseline `754c57d`; CI `33067526022` | `gateway/composition` accepts only caller-supplied `Authorizer`, `RevocationSource`, `Recorder`, and WebSocket handshake admission plus a Provider reference resolver; no allow-all fallback exists. It resolves fresh opaque references on every Gateway attempt and wraps every Provider terminal dial in the f4 bounded adapter. Tests cover missing and typed-nil dependencies, incomplete endpoint rejection, grant binding, caller cross-tenant denial, endpoint expiry, revocation interruption, reconnect and exhaustion, bidirectional real-WebSocket flow, and metadata-only audit. Full race/shuffle, vet, module/Contract verification, the locked 38-case Suite, and diff checks passed locally; CI passed `provider-contract`, `test`, and `docker-integration`. No command/configuration composition, external caller, aggregate, multi-controller, tenancy, deployment, or production evidence is claimed |
| P2.5f6 command composition evidence | implementation `c4c7cbc`; startup/locking regression `8a794c0`; evidence baseline `cefbc74`; CI `33134521467` | The command root accepts an explicit default-disabled development terminal configuration only with protected admission plus Docker lifecycle/file persistence. It opens distinct session/reference single-controller files, constructs the reconnectable terminal runtime, recovers lifecycle then exec then terminal state before assigning `SessionApplication`, and keeps startup capability advertisement empty. Handoff registration is idempotent for an exact running allocation, avoiding an unbounded sequence of unresolvable references after a retry. After the Provider listener stops, bounded shutdown revokes and cleans still-running uncommitted allocations before repository release; successful unexpired handoffs retain their durable reattachment semantics. Config, disabled/incomplete/enabled startup/locking, recovery, shutdown order, route absence, full race/shuffle, vet, Contract verification, 38-case Suite, and Docker regressions pass locally. Repository CI passed all three required jobs. No public Gateway listener, caller authorization/revocation/recording default, Contract change, external caller, aggregate, multi-controller, tenancy, deployment, or production evidence is claimed |
| P2.5f7 terminal vertical evidence | implementation/test `0e8b284`; evidence baseline `cefbc74`; CI `33134521467` | The tagged `cmd` integration test uses the real Docker lifecycle and f6 terminal composition, obtains the durable opaque handoff, and injects f5 Gateway only with test-owned admission, authorization, revocation, and recorder ports. A first WebSocket connection sets shell state; after closing and reconstructing lifecycle, session/reference, terminal runtime, and resolver state, a fresh connection proves that state survives in the same shell. The CI Docker job includes `./cmd`, and repository CI passed `provider-contract`, `test`, and `docker-integration`. Focused race, full race/shuffle, vet, unchanged Contract/tree verification, the locked 38-case Suite, dependency checks, and the exact three-package Docker command pass locally. This does not add a public Gateway, real platform caller, production policy, capability advertisement, artifact/usage composition, aggregate conformance, multi-controller persistence, tenant isolation, deployment, or production readiness |
| P2.5h readiness-derived composition and advertisement | implementation `2c55173` | `ProviderCapabilityConfig.CodingShellEnabled` is an explicit opt-in. The command root constructs a deterministic dependency graph only after lifecycle, admission, exec, usage, terminal, artifact, and operation readers are composed. The source advertises exactly `sandbox.exec@1.0.0`/`exec-v1`, `sandbox.terminal@1.0.0`/`terminal-v1`, and `sandbox-runtime-coding-shell-v1` only when every graph node is ready; otherwise explicit enablement returns a startup error and disabled configuration returns non-nil empty arrays. Config and per-node dependency-absence matrices, immutable snapshot projection, canonical terminal IDs, full race/shuffle, vet, lock verification, the 38-case Suite, fixed-digest Docker integration, and diff checks pass. The command graph intentionally marks the concrete WebSocket and caller-owned Gateway boundary unavailable, so this slice does not produce a runnable nonempty-profile deployment or external-caller evidence |
| P2.7 e2 terminal-connect prerequisite | current 2026-09-16 worktree; locked Contract remains `22ba6987` | Adds default-disabled `provider.terminal.connect_enabled`, requires exact agreement between immutable `sandbox.terminal-connect@1.0.0` advertisement and a composed connector, consumes the bounded base64url retained-handoff descriptor only after mTLS/JWS admission, rechecks exact durable session/reference/generation/expiry authority before every fresh attach, negotiates only `sandbox-runtime-terminal.v1`, disables compression, permits only binary messages up to 65,536 bytes, and closes the stream no later than handoff expiry. Positive full protected WebSocket byte round-trip plus malformed carrier, authority mismatch, composition/advertisement mismatch, capability projection, config, full race/shuffle, vet, locked Contract verification, diff checks, and the exact three-package Docker integration command with locally cached digest-pinned Alpine pass. The first Docker attempt was environmentally unavailable because Docker Hub token/manifest requests timed out; it made no code-failure claim. This closes one e2 prerequisite only: it is not an external run, does not supply the missing runtime image, does not refresh candidate provenance, and does not establish Gateway end-user policy, multi-controller, deployment, or production readiness |
| P2.7 coding/shell runtime-image publication | source `cf1830e9bbfcd08d6f171e60f67d949d839e1069`; run `35171475925`; attestation `48073123`; index `sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1` | The strict repository-owned image retains locked amd64/arm64/v8 Alpine inputs, `go1.26.5`, the image-baked terminal broker, fixed `65532:65532` identity and bounded shell/mount/network policy. Native hosted integration passed for both architectures. Independent inspection confirmed exactly linux/amd64 `sha256:a3559ade39fd86c9bb04f69a111d8da4e2f31951333b48bf6d59bd752c95aa4e` and linux/arm64/v8 `sha256:a3d9567ee49482582baff67cc3b8679bbe08b79909f7375145004f1c92b4d5f3`; independent attestation verification bound the repository, workflow, source, main ref, GitHub-hosted runner, SLSA predicate and Rekor timestamp. This closes the image publication gate only. The external caller still pins its synthetic image until its separate provenance refresh, and no e2 qualification or production-readiness result is claimed |
| P3 local evidence | implementation commit `4212e88` | Revision identity validation, deterministic canary binding, rollback-only-new-run behavior, old-run draining, shadow validation bounds, and migration metric aggregation passed focused race/shuffle and vet. At that baseline, real-platform traffic and migration evidence remained open; ADR 0037 later retired the named P3 migration target |
| P3 component release evidence | post-push CI run `32805284762` | CI run concluded success for `4212e88`; this remains local migration component evidence, not external caller, canary traffic, rollback E2E, or production readiness |
| Historical external platform audit | 2026-08-30 review baseline `bba02a6`; platform checkout cached `origin/main@cf623ac` | The existing Agent Platform candidate then had no runnable sandbox caller, Gateway, lock, PKI/JWS, or scenario runner. This finding explains why the co-located candidate harness was added; it is not evidence about the real platform |
| Latest completed real-platform content audit and later identity check | 2026-09-02 read-only content audit at `veronica` local `main@17bb3855ba513b3a0e511f68f48c4e6aefbf265d`, 90 commits ahead of live GitHub `origin/main@a758c219fd9f14a015368ab95914ed7386c05afc`; 2026-09-06 identity-only check at dirty local `main@22343bb92b74e5d6e0aaf17d671344dd8c1bc7f9`, 110 commits ahead of unchanged `origin/main`; old `sandbox-runtime-e2e@2981842` | The completed 2026-09-02 content audit found Blueprint/governance and Temporal/PostgreSQL TF00 feasibility material plus Python runners, but no runnable Application service, Provider client, WorkOrder/AgentRun mapping, Gateway, mTLS/JWS PKI, Provider endpoint, or migration traffic harness. Its bounded Temporal dev-server smoke explicitly forbade workers, workflows, T2/T3, and external services. The 2026-09-06 check did not inspect newer content and therefore made no claim about later external-platform capabilities. No runnable platform target had been independently supplied to this repository, so the then-defined real P3 gate was not closed. The old checkout had no remote and was reference-caller preparation only; pre-existing `veronica` changes were preserved. The co-located candidate harness was separate and did not close real-platform evidence. ADR 0037 later retired that named migration target |
| P3 candidate integration evidence | hosted harness/Provider `17ed6ca`/`b4d41c9`, run `33970773345`; latest local pre-refresh harness/Provider `59e08d5`/`c0a55d1`, evidence `e2e/evidence/platform-candidate/20260905T080623.861033000Z` | Hosted and local candidate regressions passed 15+5 coding/shell scenarios against Contract 48 cases. Hosted artifact digest is `sha256:546c3ecd6f2cd23a629ab53eb61bbe23fa7361c8440297c0fb039886802d7bc0`; local runtime digest is `sha256:c1da999518ed8cf3c422142b705f3eeca5d60104be07bc28c15a7d527d2907fc`. Its recorded boundary is `Agent Platform candidate integration only`; real-platform shadow parity, canary traffic, rollback/drain, and platform-contract ownership were not established. ADR 0037 later retired the named P3 migration target without reclassifying this historical evidence |
| P2.5i reference external caller | current local harness/Provider `b8d4829`/`af8a505`, run `20260907T044611.598221000Z`; historical hosted harness/Provider `17ed6ca`/`b4d41c9`, run `33970773414` | The current local run and historical hosted run each passed 15 initial plus 5 restart/resume coding/shell scenarios. The current manifest SHA-256 is `60bda2dae83053db447417cea5c5e38d4798e1e90b91fbb5cfc75d2991c6993e`; the hosted artifact digest is `sha256:de2c6f2d31d9dd5a8323d82560bf0f314970c8e1825d815d224d48aac2dcba16`. Neither contains a Browser scenario or proves independently implemented external-caller interoperability, durable-revocation caller behavior, aggregate, multi-controller, hostile multi-tenant, deployment, or production properties |
| P4 browser Contract authority and reference callers | Contract `5096e71`; projection/lock `24b2e36`; command `66183b1`; downstream component `b4d41c9`; fixed v2 harness `059357c`; local v2 run `20260906T100233.295973000Z`; hosted v2 run `34026680591`; ADR 0035 witness component `3ff58dc`; latest ADR 0036 run `838d3bb`/`34069851741`; local downstream harness/run `550c785`/`20260906T050213.016063000Z`; hosted checkout/downstream run `2cadc53`/`34013982796` | Browser authority and the Browser reference, shared-capacity, durable-revocation, downstream-fencing, witnessed-v2, PostgreSQL witness, and controlled-restore tracks remain separate. The downstream track passes its 13-scenario v1 caller gate on local arm64 and hosted amd64; its 48-case Suite remains unexercised. ADR 0034 passes its deletion/rollback-detection component and pinned-Valkey adapter gates plus its locked 18-scenario local arm64 and hosted amd64 caller runners. ADR 0035 passes its PostgreSQL component gate, and ADR 0036 passes its hosted same-runner 18-scenario controlled-restore gate. Their Suites remain unexercised where recorded. Production independent witness/storage and restore operations, Valkey/PostgreSQL provenance/HA/failover, production configuration/metrics/deployment and topology, independently implemented external-caller interoperability, aggregate, multi-controller, hostile multi-tenant, and production evidence remain absent |
| Contract resources | OpenAPI, admission, lifecycle, bounded exec, terminal-session, browser-session, desktop-session, artifact-staging, usage-evidence schemas, fixtures, semantic rules, and Suite | Local Contract authority is locked; Browser/Desktop end-user and tenant Gateway policy, artifact publication, billing, and tenant authority remain outside the Provider |
| Contract lock | format 2; revision `720ad15c343e71f36615dc4499edd5e764178bca`; tree `343ffde0819207cf99c005096c336735dd33a735`; manifest `sha256:483111511a588b41bd40d3fef686f0b21f465bb65d3215450ebb2ccf37a5de89`; OpenAPI `sha256:5a3da5d239f83e94eff09fc75438755f834e77bce8cd1c0f91c25055bf0cba2a`; semantic rules `sha256:7953d05e65f00c68e0428b6dd4fcebef1af103f2cab2fa6b214905b2496c8785` | The Provider Calling Standard is a manifest resource. Both Suite digests are content-derived with `rfc8785-full-document-excluding-suite-digest-v1`. Local `sandbox-provider@1.0.0` / `sandbox-runtime-provider-v1` has 71 cases and digest `sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`; remote `sandbox-provider-remote@1.0.0` / `sandbox-runtime-provider-remote-discovery-v1` has six cases and digest `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0` |
| External Agent Contract | no longer consumed; old compatibility evidence is historical only | Removed from implementation |

The lock verifier is intentionally bound to the repository-owned Contract tree.
It does not clone, mount, or read an external source repository.

## Plan Ledger

| Slice | Scope | Status | Required next evidence |
| --- | --- | --- | --- |
| P0.0 | Freeze local Contract ownership, namespace, version, license, resource layout, and lock | Passed and merged in PR #17 | Post-merge CI run `32360376058` passed |
| P0.1 | Replace external lock verifier with local tree/digest/semantic/fixture validation | Passed and merged in PR #17 | Current lock revalidation on this branch |
| P0.2 | Migrate DTO/projection tests and CI to local Contract | Passed and merged in PR #17 | Current projection regression |
| P0.3 | Rebase architecture, ADRs, README, plans, and status on local Contract | Passed and merged in PR #17 | Keep docs synchronized with follow-up Contract changes |
| P0.4 | Re-run P1.1 evidence against the repository-owned Contract | Passed through PR #19; post-merge run `32365284283` passed | Retain regression and lock evidence |
| P1.1a | Provider v1 DTOs and strict decoder | Passed under local Contract through PR #18; post-merge run `32363581638` passed | No new slice; retain regression coverage |
| P1.1b | mTLS-only capability discovery | Passed under local Contract through PR #18; post-merge run `32363581638` passed | No new slice; retain TLS/projection coverage |
| P1.1c | Protected-operation admission primitives and transport composition | Passed under local Contract through PR #18; post-merge run `32363581638` passed | P1.1d release-gate review |
| P1.1d | Admission release gate | Passed; Suite runner, race/shuffle matrix, PR CI, and post-merge CI all passed | Retain gate evidence; do not expand claim beyond P1.1 |
| P1.1e | ADR 0038 listener-local caller trust domain | Passed the repository-local coordinated Contract, projection, configuration, Provider, conformance, E2E lock, and same-repository reference gates with explicit no-default issuer configuration, Provider-local audience/revision anchors, a maximum 32-key frozen bundle, and overlap rotation coverage | Qualify an independently implemented external caller separately. Do not claim multi-issuer, multi-tenant, HA, deployment, or production properties |
| P1.2.0 | Lifecycle Contract and authority inventory | Passed; PR #21 and post-merge CI run `32368734877` passed | Retain Contract lock and projection regression |
| P1.2.1 | Pure lifecycle domain | Passed; PR #22 and post-merge CI run `32370133083` passed | Retain domain transition regression |
| P1.2.2 | Atomic repository ports and development adapters | Passed; PR #23 merge `ac72eab`, post-merge CI `32372662597` passed | Retain repository fault/restart evidence; no multi-controller claim |
| P1.2.3 | Provider-local coordinator and reconciliation | Passed in PR #24 merge `2e3dde6`; post-merge CI reported successful | Retain coordinator fault/restart evidence; no multi-controller claim |
| P1.2.4 | Provider API lifecycle projection | Passed in PR #25 merge `88506d1`; PR CI run `32378782202` and post-merge CI run `32435540542` all required jobs successful | Retain projection/Schema/admission evidence; no runtime composition claim |
| P1.2.5 | Lifecycle release gate | Passed for the current Contract-authorized subset; local Suite behavior matrix and reserved-family boundary recorded | Retain no-claim boundary for terminate/lease/orphan families; no aggregate or production claim |
| P1.2.5a | Provider lifecycle composition | Passed in PR #27 merge `28076a7`; post-merge CI `32439289227` passed | Retain fake-driver and production-readiness boundaries |
| P1.2 | Async lifecycle, operation ledger, reconciliation, events | Passed for the bounded Contract-authorized subset; full architecture lifecycle families remain separately gated | P2.0 authority inventory; do not implement unauthorized lifecycle families |
| P2.0a | Coding/remote-shell authority inventory | Passed in PR #29 merge `83965a2`; post-merge CI `32440383198` passed | Retain ADR 0009 ownership boundary |
| P2.0b | Bounded exec Contract resources | Passed in PR #30 merge `9d00212`; no runtime dispatch | Retain lock source revision/tree and valid/rejection fixture evidence |
| P2.0c | Exec Contract lock/projection gate | Passed in PR #30; post-merge CI run `32444266288` passed | No runtime claim from the Contract gate |
| P2.1 | Bounded exec domain/application port | Passed in PR #31 merge `67b64a9`; post-merge CI `32445893337` passed; no public composition | Retain P2.2 non-goals and local-only evidence boundary |
| P2.2a | Exec result and cancellation-intent domain | Passed in PR #33 merge `ba39053`; post-merge CI `32454054853` passed; no persistence, dispatch, or HTTP composition | Retain local-only evidence boundary |
| P2.2b | Independent exec ledger persistence | Passed in PR #35 merge `c467cd4`; post-merge CI `32456279722` passed | Retain local-only evidence boundary; P2.2c design gate next |
| P2.2c | Bounded exec coordination and optional cancellation port | Passed in PR #39 merge `17072e6`; post-merge CI `32460914417` passed | Retain no-HTTP/no-Docker/no-auto-recovery boundaries |
| P2.2 | Retained result and cancellation behavior | Passed for P2.2a-c bounded provider-local subset | P2.3c0 Contract consistency gate and subsequent session evidence |
| P2.3a | Terminal session Contract resources | Passed as resource evidence in PR #43 merge `21f5236`; session behavior remains unimplemented | Retain resource projection regression |
| P2.3b | Terminal session lock and DTO/admission projection | Passed as lock/projection evidence in PR #43; the former capability consistency gap is addressed by P2.3c0 | Retain 24-case baseline and P2.3c0 review evidence |
| P2.3c0 | Terminal capability/profile Contract reconciliation | Passed in PR #44 merge `6c1fc90`; exact-head PR CI `32685685846` and post-merge CI `32686754674` passed | Retain 26-case Contract/projection regression and evidence boundaries |
| P2.3c1 | Provider-local terminal session domain and transactional authority port | Passed: PR #45 merged as `4c37d8c`; PR/post-merge CI passed | Retain no-persistence/no-transport boundary |
| P2.3c2 | Durable terminal session ledger and atomic sandbox authority check | Passed on `main@e5c9dec`; post-push CI #103 passed | Retain no-transport/no-dispatch/no-multi-controller boundary; P2.3c3 next |
| P2.3c3 | Protected transport projection and opaque handoff retrieval | Passed for bounded Provider transport evidence | Retain no-Gateway/no-WebSocket boundary; P2.3c4 requires independent Gateway evidence |
| P2.3c4 | Runtime Gateway integration | Passed for bounded Gateway component evidence | External caller E2E, real WebSocket adapter, distributed revocation, multi-controller reliability, and production deployment remain unproven |
| P2.4 | Artifact staging and usage evidence | Passed for bounded Provider Contract/domain/memory-adapter evidence; direct-main commits through `3b94146`, post-push CI `32804619553` | No HTTP composition, platform artifact publication, billing, distributed reconciliation, tenancy, deployment, or production claim |
| P2.4a0 | Artifact/usage protected-admission authority reconciliation | Passed in direct-main commits `3a9d8b7`, `7e00715`, and `2aba87f`; CI `32819717542` passed | Retain 33-case Suite, lock, guard classification, descriptor digest, async outcome, safe error, and route-absence regression |
| P2.4a1 | Operation aggregation and evidence-read authority reconciliation | Passed in direct-main commits `3846c9e`, `6f549c2`, and `dbea0e8`; CI `32823783136` passed | Retain 35-case Suite and locked pending/outcome-unknown/unavailable/expired state matrices; no runtime implementation claim |
| P2.4a2 | Artifact/usage Provider application and operation-family component | Passed for bounded provider-local application/repository/reader evidence in direct-main commits `152033f`, `0440272`, and `4d0bb70`; CI `32827387303` passed | Retain durable accept-before-dispatch, CAS/generation/fencing, restart/expiry/corruption, usage operation correlation, all-family aggregation, and duplicate-ID fail-closed evidence; no HTTP composition |
| P2.4a | Artifact/usage Provider transport composition | Passed for bounded component evidence; post-push CI `32838784395` passed | Retain artifact-stage preflight and create/session ordering regressions. The exact independently supplied caller result is recorded separately under P2.7; this slice makes no aggregate, tenancy, deployment, or production claim |
| P2.5a | Coding/shell vertical-composition authority and delivery plan | Passed as design evidence in ADR 0015 and `docs/plan/p2.5-coding-shell-vertical-composition.md`; no Contract, config, runtime, route, or advertisement behavior changed | Retain the ownership and evidence boundaries through P2.5b-i |
| P2.5b | Coding/shell Contract profile reconciliation | Contract authority committed as `22a148e`; projection/lock committed as `123d16a`; full local gates and CI `32924361132` passed | Retain Contract/profile regression. Runtime composition and startup advertisement remain disabled |
| P2.5c | Create/session mutation preflight ordering | Transport correction `6c2962b`, Suite mapping `6340604`, and CI `32926181615` pass the slice gates | Retain admission-ordering regression through later verticals. This slice itself makes no dispatch, runtime, external-caller, or production claim |
| P2.5d | Provider runtime foundation | Passed for single-controller development evidence in `de18787`; evidence commit `e3a8265` and post-push CI `32929140044` passed | Retain Provider/local `/instances` separation, real Docker integration, restart/unknown/cleanup evidence, empty advertisement, and production rejection through P2.5e-h |
| P2.5e | Exec vertical composition | Passed in `5917a57`; evidence baseline `2f7a79b` and CI `32937530059` passed | Retain exec admission/runtime/recovery matrices and the slice's empty-advertisement boundary. P2.7 later exercised the exact external flow separately; aggregate, reliability, tenancy, deployment, and production claims remain open |
| P2.5f0 | Terminal/Gateway authority, data-plane, recovery, and deployment audit | Complete as design evidence; no behavior or advertisement changed | Retain the reconnect and ownership boundaries through P2.5f1-f7 |
| P2.5f1 | Reconnectable terminal runtime port and Docker adapter | Passed local and repository CI gates in implementation `6778d3c`, evidence baseline `66dd3d1`, and CI `33033284420` | Retain the runtime identity/reconnect boundary; do not promote runtime-adapter evidence to a terminal/Gateway vertical claim |
| P2.5f2 | Durable session coordination and repository migration | Passed local and repository CI gates in implementation `ccffd52`, evidence baseline `3abefd4`, and CI `33045725476` | Retain the single-controller, separate-repository, no-command-composition boundary |
| P2.5f3 | Opaque reference registry and resolver | Passed local and repository CI gates in implementation `b1acdd1`, evidence baseline `7138a4c`, and CI `33059304542` | Retain the separate non-atomic session/reference stores and no-command-composition boundary through f4-f7 |
| P2.5f4 | WebSocket and terminal stream adapters | Local component/full regression gates and CI `33064864447` passed in implementation `14f14cc` and evidence baseline `1d9da67` | Compose f5 only with caller-owned authorization, revocation, and recorder ports. Retain no-command-composition/no-external-caller boundary |
| P2.5f5 | Gateway composition | Local composition gate and CI `33067526022` passed in implementation `fdfc771` and evidence baseline `754c57d` | Retain caller-owned policy and no-public-Gateway/no-external-caller boundary; f6 command composition does not weaken that boundary |
| P2.5f6 | Development terminal command configuration and process lifecycle | Local evidence passes in `c4c7cbc` and `8a794c0`; evidence baseline `cefbc74` passed repository CI `33134521467` | Retain default-disabled/single-controller/no-public-Gateway boundary. Later readiness and independent caller evidence are separate P2.5h/P2.7 results and do not broaden this slice |
| P2.5f7 | Terminal/Gateway vertical evidence gate | Local single-controller Docker/race/restart/reconnect gate passes in `0e8b284`; evidence baseline `cefbc74` passed repository CI `33134521467` | Retain same-repository test boundary and no-public-Gateway/no-external-caller claims; P2.5g artifact/usage evidence is recorded separately |
| P2.5g | Artifact and usage vertical | Local gate passes in implementation `0e6e108`: default-disabled development composition, durable artifact/usage repositories, async recovery/shutdown, real Docker output confinement and private staging, partial exec-derived usage, operation aggregation, and restart evidence. Repository CI `33157119149` passed all three jobs | Retain development-only/single-controller boundaries. Exact external-caller evidence is recorded separately under P2.7; publication, billing, aggregate, reliability, tenancy, deployment, and production claims remain open |
| P2.5h | Readiness-derived composition and exact advertisement | Local component/projection gate passes in implementation `2c55173`: explicit opt-in config, canonical IDs, complete dependency graph validation, empty-disabled behavior, and immutable exact Contract snapshot generation. Repository CI `33159099578` passed all three jobs. The Provider command graph still deliberately lacks caller-owned WebSocket/Gateway policy | Retain fail-closed Provider ownership. The reference stack supplies policy externally for P2.5i without adding an allow-all Provider default |
| P2.5i | Independent reference caller release gate | Current local run `20260907T044611.598221000Z` with harness/Provider `b8d4829`/`af8a505` passed 15 initial and 5 restart/resume coding/shell scenarios; hosted run `33970773414` remains historical evidence against `17ed6ca`/`b4d41c9` | Current manifest SHA-256 is `60bda2dae83053db447417cea5c5e38d4798e1e90b91fbb5cfc75d2991c6993e`; hosted artifact digest is `sha256:de2c6f2d31d9dd5a8323d82560bf0f314970c8e1825d815d224d48aac2dcba16`. Neither run contains a Browser scenario, and neither is evidence of independently implemented external-caller interoperability, durable-revocation caller behavior, aggregate conformance, multi-controller reliability, hostile multi-tenant isolation, deployment qualification, or production readiness |
| P2.6 | Content-derived and portable Provider conformance | Historical 50-case local and six-case remote profiles passed at `3fe314a`/`ae476fe`; the later 53-case local Suite passed core CI `35204434771`; the current clean VCS-built 60-case local Suite passes at lock-selection revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1` | No fresh current remote run is claimed. Independent caller qualification is separately complete under P2.7; protected/mutating remote and broader gates remain open |
| P2 | Coding/remote-shell profile | The component/Contract/reference gates retain their exact boundaries, and the separately supplied independent P2.7 caller qualification is complete for its recorded scope | Other callers/profiles, aggregate conformance, multi-controller reliability, hostile multi-tenant security, deployment, and production gates remain open |
| P3 | Named-platform migration | Retired by ADR 0037. Historical component evidence (`4212e88`), local candidate integration, and hosted candidate run `33970773345` remain under their original evidence identities | No release gate remains. Consumers adapt to the exact locked Provider Contract and own any shadow, canary, rollback, drain, and metric-comparison process |
| Internal Block manifest | Declarative block configuration foundation | Passed as component evidence; no public API or runtime execution | Add a separately reviewed browser/desktop manifest and runtime image before enabling any optional capability |
| P4 | Optional capability profiles | Browser Contract authority/projection, signed image publication, Provider-local components, separately named Browser/shared-capacity/durable-revocation caller gates, ADR 0033 component/caller evidence, ADR 0034 witnessed-v2 local/hosted caller evidence, the ADR 0035 PostgreSQL component gate, and the ADR 0036 hosted same-runner controlled-restore gate have passed within their tiers. Neither downstream profile nor the controlled-restore profile executes the Contract Suite | Production independent witness/storage and restore operations, Valkey/PostgreSQL provenance/HA, production configuration/metrics, hostile-tenant/operational evidence, deployment, and production advertisement remain later gates |
| Product Phase 5 Slice 1 | Provider Desktop Contract and Go projection authority | Passed for exact revision `720ad15c343e71f36615dc4499edd5e764178bca`, tree `343ffde0819207cf99c005096c336735dd33a735`, and 71-case local Suite | Retain exact Contract projection and historical-evidence separation |
| Product Phase 5 Slice 2 | Product Desktop slot/session and PostgreSQL intent authority | Passed at implementation `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`, including fresh pinned-PostgreSQL migration replay and concurrent race cases | Retain Product intent/worker isolation while later slices add dispatch; no runtime, public route, advertisement, or release claim follows |
| Product Phase 5 Slice 3 | Provider Desktop domain, application, persistence, reconciliation, operation aggregation, and optional protected handlers | Passed at implementation `f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5`, including focused/full race-shuffle, vet, Contract/evidence verifiers, tagged existing-lifecycle Docker integration, restart-boundary and unknown-outcome matrices, exact cleanup, safe errors, and nondisclosure | Continue with the immutable Desktop runtime image and broker protocol in Slice 4; no runtime adapter, production composition, dispatch, advertisement, or release claim |
| Product Phase 5 Slice 4 | Reproducible immutable Desktop runtime image, private broker, and provenance | Passed: local candidate `163dd8a258a24cf4727169b1cbd8ed7c0fe29292`; publication run `35447651328` at source `e4a940b`; index `sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`; attestation `48643717`; exact native platform and independent verification gates pass | Slice 5 may select only `profiles/desktop/image.LockedPublication`; no adapter, production composition, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 5 | Provider Desktop runtime adapter, private resolver, lifecycle, usage, revocation, and cleanup composition | Passed at implementation `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b`: focused/full race-shuffle, vet, lock/evidence regressions, restart/fault/generation matrices, and native arm64/v8 immutable-image broker attach/reconnect/removal pass | Continue with the Product network-only Provider adapter in Slice 6; no production startup composition, public data plane, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 6 | Product network-only Provider adapter, isolated Desktop dispatch/observation, retained recovery, and close cleanup | Passed at implementation `2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240`: focused/full race-shuffle, vet, Contract/evidence verifiers, tagged Docker lifecycle regression, and fresh real-PostgreSQL network-adapter recovery pass | Continue with Product Desktop view/control grants in Slice 7; no production startup composition, public data plane, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 7 | Product-owned Desktop viewer/controller grant authority, one-use tickets, fencing, quotas, revocation, and continuous checks | Passed at implementation `0649d62911abb89229de40136347286736152ec6`: focused/full race-shuffle, vet, Contract/evidence verifiers, and fresh real-PostgreSQL concurrency, replay, tamper, expiry, revocation, and audit pass | Continue with the public Desktop data plane in Slice 8; no production startup composition, signaling/media/input route, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 8 | Bounded public Desktop WebRTC handler, display/optional-audio, ordered fenced input, continuous authority, and backpressure closure | Passed at implementation `040c560f3701b7c972c25f05928dd435d9f55c20`: focused ten-run Desktop race, real in-process WebRTC viewer/controller/media/input cases, full race-shuffle, vet, Contract/evidence verifiers, and nondisclosure/security bounds | Continue with durable Desktop input/clipboard/transfer policy in Slice 9; no real Provider media bridge, production startup composition, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 9 | Durable versioned Desktop input/clipboard/transfer policy and exact Product transfer binding | Passed at implementation `24f5c741eb605614f77f8d9d546708b9993e42dd`: focused ten-run Desktop race, full race-shuffle, vet, Contract/evidence verifiers, and fresh real-PostgreSQL migration/replay/concurrency/restart/isolation gates | Continue with reconnect, resynchronization, and replacement recovery in Slice 10; no real Provider media/input bridge, production startup composition, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 10 | Fresh-grant reconnect, resynchronization, restart lease recovery, and deterministic replacement cleanup | Passed at implementation `f23b16130c97e99d5d28008b01346779a0c681ee`: focused ten-run Gateway/repository race, real WebRTC reconnect/control cases, full race/shuffle, vet, Contract/evidence verifiers, and fresh real-PostgreSQL migration/recovery/replacement gates | Continue with Desktop recording in Slice 11; no real Provider media/input bridge, production startup composition, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 11 | Required Desktop recording, replay, catalog, retention, quota, and integrity composition | Passed at implementation `c5b045abc5192b76b7d615ddbb0858b998ef98d5`: consent/mode and fail-closed Gateway cases, ten-run Gateway race, full race/shuffle, vet, Contract/evidence verifiers, and fresh full tagged PostgreSQL quota/encryption/integrity/authorization/retention gates | Continue with Desktop development-environment templates in Slice 12; no real Provider media/input bridge, production startup composition, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 12 | Immutable development templates, exact Guest workspace materialization, health, rollback, and restart persistence | Passed at implementation `490c2db96d6ba7a851d7846bc9e5f818dae2be77`: focused race/shuffle and vet, exact Guest transport/materialization/fault/restart tests, fresh complete tagged PostgreSQL migration/replay/authority/isolation package, and clean E2E parent lock | Continue with unified Product Web in Slice 13; no real Provider media/input bridge, production startup composition, advertisement, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 13 | Unified capability-derived authenticated Product Web/BFF for Workspace, Terminal, Files, Browser, Desktop, and recordings | Passed at implementation `84698c371d35edb862ffc81b484a3e31cc8120d9` and E2E lock `25283420377baebd9aaac8c1199068fb90735403`: generated-client regeneration, focused/full race-shuffle, vet, real headless Chrome authentication/capability navigation, both Contract verifiers, retained Phase 3/4 evidence verification, and all eight parent-lock checks | Continue with the composed cleanup/quota/fault/security regression gate in Slice 14; no real Provider media bridge, production startup composition/advertisement, independent-process release, deployment, or production-readiness claim follows |
| Product Phase 5 Slice 14 | Private Provider/Gateway Desktop bridge and composed cleanup/quota/fault/security regression gate | Passed at implementation `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d` and E2E lock `65d514622405e69f9accfc50d09d207263c961cb`: focused/full race-shuffle, vet, fresh full tagged PostgreSQL composition/cleanup, both Contract verifiers, retained Phase 3/4 evidence verification, and all eight parent-lock checks | Continue with the independent-process release topology in Slice 15; no exact release-topology advertisement, deployment, HA, hostile multi-tenant, or production-readiness claim follows |
| Product Phase 5 Slice 15 | Five-role independent-process release gate and strict evidence bundle | Passed at implementation `024a768d51965f8949bacf3c97e499fb26a6e648`, run `20260919T200125.484855000Z`: 14 exact scenarios cover locked identities, dependency-derived capability readiness, real display/control, Guest development materialization, Product/Gateway/Guest restart, Provider fault closure, security, encrypted recording, and exact cleanup; the retained manifest passes strict validation | Phase 5 is complete only for this same-repository single-host/single-controller topology. Production command composition, deployment, HA, hostile multi-tenant isolation, independently implemented caller interoperability, and production readiness remain open |
| Production readiness | Independent evidence tier, not a shortcut from P4 | Not established | Deployment, multi-controller reliability, multi-tenant security, operations, and production gates |

## Evidence Boundary

PR #17 merged the repository-owned Contract migration and its post-merge CI
run `32360376058` passed all required jobs. PR #18 then merged the protected-
admission Contract resources and bindings as `4774c3a`; post-merge run
`32363581638` passed `provider-contract`, `test`, and `docker-integration`.
PR #19 merged the local Suite runner and CI invocation as `e2755f5`; post-merge
run `32365284283` passed all required jobs.

- local Go tests are component evidence only;
- the local Contract verifier proves lock/resource identity, not protocol
  conformance;
- the historical P2.6 local Suite runner executed the verifier's immutable
  50-case snapshot
  from a bounded read-only archive of its exact clean Runner revision. It
  requires each case to declare an exact mapped-test count and all matching
  tests to appear as distinct, started, non-skipped passes in `go test -json`.
  It rejects explicit `GOROOT`, resolves and reuses one absolute Git path, and
  records the host OS, filesystem, initial Git selection, and Go and Git
  executables as trusted local inputs. This remains Provider
  repository/Contract-suite evidence, not aggregate lifecycle conformance;
- both Suite digests are recomputed from RFC 8785 canonical content excluding
  only the top-level `suite_digest`; the separate six-case remote profile is
  black-box discovery evidence only and does not execute the local profile. Its
  unsafe-method flag becomes true only after a POST, PUT, PATCH, or DELETE probe
  is actually written;
- Contract/Suite component evidence alone establishes no external-caller E2E or
  aggregate lifecycle conformance. Separately named Reference, Candidate,
  Browser, shared-capacity, and durable-revocation caller evidence is recorded
  below without establishing multi-controller reliability, multi-tenant safety,
  deployment readiness, or production readiness.

The full race/shuffle gate includes the discovery operation's bounded handler
`400` and parser-visible `501` transport tests under the corrected projection.

## Current Verification

For the historical 60-case authority, the Phase 2 local release gate passed the
Contract and profile/protocol verification, clean VCS-built race-enabled and
shuffled local Suite, DTO projections, full root and E2E race/shuffle tests,
vet, tagged Docker lifecycle integration, and all eight E2E checks. Core CI
`35204434771` remains evidence for the earlier 53-case authority and its named
Browser provenance and Ubuntu/macOS supervisor matrices. No hosted result or
fresh current six-case remote discovery run is relabeled by the local Phase 2
release gate.

For the current 71-case authority, Product Phase 5 Slice 1 adds exact Desktop
Contract schemas, semantic rules, fixtures, admission bindings, projection,
and executable Suite mappings. Its local gate runs Contract/profile
verification, full race/shuffle, vet, Product Contract verification, retained
Phase 3/4 evidence validation, structured-data parsing, and a clean VCS-built
race-enabled shuffled Suite. This remains Contract/projection evidence only;
no Desktop runtime or advertisement is exercised.

Product Phase 5 Slice 2 adds Product Desktop intent at implementation
`d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`. Focused tests, full repository
race/shuffle, vet, both Contract verifiers, retained evidence verifiers, and
the complete tagged PostgreSQL package pass. The real-adapter run uses fresh
PostgreSQL 16 pinned to
`sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
and removes its disposable container. This is persistence/component evidence;
it does not dispatch Desktop work or establish runtime or release readiness.

Product Phase 5 Slice 3 adds Provider-local Desktop authority at implementation
`f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5`. Focused and full repository
race/shuffle, vet, both Contract verifiers, historical qualification-profile
verification, retained Product Phase 3/4 evidence verification, and the tagged
existing-lifecycle Docker integration pass.
Tests cover replay/fencing/deadline/cancellation, every open commit/effect
restart boundary, file restart and corruption, close/expiry ordering,
observation-only unknown outcomes, exact-owned cleanup, transport strictness,
safe errors, and nondisclosure. This is in-process component evidence with
injected runtime/handoff ports; no runtime, production composition, capability
advertisement, independent process, or release readiness is established.

Product Phase 5 Slice 4 candidate implementation
`163dd8a258a24cf4727169b1cbd8ed7c0fe29292` passes focused and full repository
race/shuffle, vet, Contract/profile/evidence verification, Shell/YAML parsing,
and the native linux/arm64/v8 image integration. The tagged image gate performs
two identical builds and exercises the numeric non-root, read-only, drop-all,
`no-new-privileges`, private-IPC, no-network, no-device, bounded-resource
runtime; strict broker probe/describe; `xdpyinfo`; nonempty `xwd` capture;
process/image/container policy; and cleanup. The amd64 candidate was reproduced
by cross-build only and is not a native smoke. Manual publication run
`35447651328` at main source `e4a940bda6c5172a78d0dbe40963ca1a99911976`
subsequently passed the native amd64 and arm64/v8 gates. It published platform
manifests `sha256:ae1b71855f879066caf73f1056039d52b796d936a19f4b34a58a5565dd89609b`
and `sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505`
under index `sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`.
Attestation `48643717`, registry object
`sha256:2abf3a1c0304bac70f3118d4b16c193cc1cf2abaa83c144efdd15a365998faf8`,
Rekor index `2892645362`, and the fresh independent job verify repository,
workflow, source, hosted runner, and exact matrix. This closes Slice 4 only and
advanced the phase count to 4/15.

Product Phase 5 Slice 5 implementation
`0c30d6f5e6e0c6227069b8689668a1a0dcfb940b` passes focused/full repository
race/shuffle, vet, Contract/evidence regressions, restart/fault/generation
matrices, and the native linux/arm64/v8 real-image broker transport gate. The
runtime adapter selects only the locked publication, requires provenance and
restricted-network dependencies, persists private ownership state, and exposes
only a bounded private attachment after fresh resolver checks. The composed
close path durably revokes, cleans the exact receipt, and confirms absence;
usage stops at the earliest revocation. The transport gate deliberately uses
`network=none`, so it is not deployed restricted-egress evidence. This closes
Slice 5 at 5/15 without enabling production composition or advertisement.

Product Phase 5 Slice 6 implementation
`2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240` passes focused/full repository
race/shuffle, vet, Provider/Product Contract and retained Product evidence
verification, existing tagged Docker lifecycle integration, and the full
tagged real-PostgreSQL Product store gate. The adapter selects the exact
Desktop Contract, signed image/profile, architecture, runtime class, limits,
and restricted-network policy; protected mutations and retained reads preserve
timeout, cancellation, replay, ambiguity, and correlation semantics. A
reconstructed Store/client recovers slot and session operations, persists only
the opaque handoff, carries Provider generation separately from Product slot
fencing, and closes the Desktop session without replacing its slot. The
database gate used fresh native arm64 PostgreSQL image
`postgres@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
and removed the temporary container. This closes Slice 6 at 6/15 without
enabling production composition, grants, public data planes, or advertisement.

Product Phase 5 Slice 7 implementation
`0649d62911abb89229de40136347286736152ec6` passes focused/full repository
race/shuffle, vet, Provider/Product Contract and retained Product evidence
verification, and the complete tagged real-PostgreSQL Product package gate.
Migration 10 gives Desktop grants independent viewer/controller limits while
the existing session-scoped unique controller fence applies to Desktop. The
database cases prove encrypted exact-replay/one-use tickets, owner
nondisclosure, full-binding tamper rejection, explicit close and release
revocation, monotonically replaced control fences, concurrent quota admission,
DB-time lease expiry, and metadata-only audit. The gate used fresh native arm64
PostgreSQL image
`postgres@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
and removed the temporary container. This closes Slice 7 at 7/15 without a
public signaling/media/input data plane, production composition, or
advertisement.

Product Phase 5 Slice 8 implementation
`040c560f3701b7c972c25f05928dd435d9f55c20` passes ten consecutive focused
Desktop race runs, full repository race/shuffle and vet, Provider/Product
Contract verification, and retained Phase 3/4 evidence verification. Real
in-process WebRTC peers carry VP8 display RTP, optional Opus output RTP, and
one reliable ordered fenced input for both viewer and controller bindings.
Negative cases prove exact Origin/TLS/ticket precedence, receive-only media,
codec/resolution/bitrate bounds, viewer/control separation, closed input
shapes, grant and injected-policy rechecks, revocation, single control channel,
queue/backpressure closure, required-recording denial, and no opaque handoff in
the public response or audit. This closes Slice 8 at 8/15 as same-process
handler/component evidence without durable Desktop policy, a real Provider
media bridge, recovery, recording, production composition, or advertisement.

Product Phase 5 Slice 9 implementation
`24f5c741eb605614f77f8d9d546708b9993e42dd` passes focused ten-run Desktop
race tests, full repository race/shuffle and vet, Provider/Product Contract
verification, retained Phase 3/4 evidence verification, and the fresh real-
PostgreSQL tagged gate. Migration 11 replay, concurrent expected-revision
updates, historical idempotency replay, cross-owner nondisclosure, metadata-
only audit, and reconstructed-Store reads pass. Gateway cases prove the closed
keyboard/pointer/touch/clipboard/transfer matrix, activation/consent and
clipboard/count/size/type/digest/path bounds, exact Product transfer identity,
policy-source failure/revision closure, and unconditional microphone/camera/
device denial. This closes Slice 9 at 9/15 as Product policy, PostgreSQL, and
same-process Gateway component evidence without a real Provider media/input
bridge, reconnect/recovery, recording, production composition, or
advertisement.

Product Phase 5 Slice 10 implementation
`f23b16130c97e99d5d28008b01346779a0c681ee` passes focused ten-run Desktop
Gateway and repository race tests, full repository race/shuffle and vet,
Provider/Product Contract verification, retained Phase 3/4 evidence
verification, and the fresh full tagged PostgreSQL gate. Migration 12 replay,
database-time expired-Gateway reclamation, reconstructed-repository
fresh-grant reconnect, generation substitution denial, and exact deterministic
replacement cleanup pass. WebRTC cases prove in-grace recovery, visual/audio
resynchronization and keyframe bounds, closed resolution/audio-output changes,
stale timer and connection-epoch behavior, and current-resolution input
validation. This closes Slice 10 at 10/15 as Product PostgreSQL and
same-process Gateway component evidence without a real Provider media/input
bridge, recording, production composition, or advertisement.

Product Phase 5 Slice 11 implementation
`c5b045abc5192b76b7d615ddbb0858b998ef98d5` passes explicit consent/mode,
pre-media initialization failure, live recorder-loss closure, the ten-run
Desktop Gateway race gate, full repository race/shuffle and vet,
Provider/Product Contract verification, retained Phase 3/4 evidence
verification, and the fresh full tagged PostgreSQL gate. The real-store case
proves one-winner active-recording quota admission, encrypted-at-rest Desktop
video/audio and minimized control segments, digest linkage, tamper rejection,
owner-only replay, catalog/audit content minimization, expiry, row transition,
and exact encrypted-object deletion. This closes Slice 11 at 11/15 as Product
recording/local-encrypted-store/PostgreSQL and same-process Gateway component
evidence without a real Provider media/input bridge, development templates,
production composition, or advertisement.

Product Phase 5 Slice 12 implementation
`490c2db96d6ba7a851d7846bc9e5f818dae2be77` passes focused race/shuffle and
vet, immutable catalog and private blob-source checks, exact Guest protocol and
authority projection, unsafe-path/offset/digest failure closure, pre-finalize
rollback, interrupted-swap reconstruction, and the complete fresh tagged
PostgreSQL package. Migration 13 replay, revision-manifest persistence, current
primary-slot and Guest-generation binding, idempotency conflict, restart-safe
ready reads, cross-owner nondisclosure, and minimized event/audit projections
pass. This closes Slice 12 at 12/15 as Product/Guest/local-content-store and
real-PostgreSQL component evidence without a real Provider media/input bridge,
unified Web, production composition, or advertisement.

Product Phase 5 Slice 13 implementation
`84698c371d35edb862ffc81b484a3e31cc8120d9` passes generated-client
regeneration, Node 24 syntax validation, focused and full repository
race/shuffle, vet, real headless Chrome authenticated capability navigation,
Product and Provider Contract verification, and retained Phase 3/4 evidence
verification. The BFF keeps encrypted server-side bearer custody, strict
Origin/CSRF/CSP, shared digest-checked transfer projection, and no private
Provider coordinates. This closes Slice 13 at 13/15 as Product Web/BFF and
real-headless-browser component evidence without a real Provider media/input
bridge, production composition/advertisement, composed Slice 14 evidence, or
the independent-process Slice 15 release result.

Product Phase 5 Slice 14 implementation
`13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d` passes focused private-bridge
race/shuffle, the full repository race/shuffle and vet gates, both Contract
verifiers, retained Phase 3/4 evidence verification, and the complete fresh
tagged PostgreSQL package. The composed gate proves the one-use control grant,
durable policy, public WebRTC, private Provider bridge, VP8/optional-Opus RTP,
ordered fenced input, required encrypted recording, continuous revocation,
replay/origin/owner denial, private capacity recovery, retention deletion, and
exact tenant-row cleanup. This closes Slice 14 at 14/15 as same-repository
bridge, same-process composition, and real-store evidence without the separate
Product/Gateway/Provider/Desktop/Guest release topology, real display/control
and development scenarios, strict Slice 15 evidence bundle, deployment, or
production-readiness result. Desktop capability advertisement remains off.

Product Phase 5 Slice 15 implementation
`024a768d51965f8949bacf3c97e499fb26a6e648` adds the strict final tagged
release gate and evidence verifier. Run `20260919T200125.484855000Z` passes
all 14 required scenarios through separate Product, Gateway, Provider,
Desktop, and Guest OS processes with fresh digest-pinned PostgreSQL, fresh
recording/content/Guest state, the exact signed Desktop runtime, real X11
capture and fenced pointer input, public WebRTC/private mTLS, encrypted
recording replay, actual Guest development materialization before and after
restart, Product/Gateway/Guest restart recovery, Provider dependency-loss
closure, dependency-derived exact-topology advertisement, and exact cleanup.
The strict retained manifest verifies both Provider Contract identities, the
Product Contract identity, runtime/platform/template locks, the exact role and
scenario sets, every cleanup flag, and explicit non-claims while rejecting
unknown/private/secret material. This closes Phase 5 only for the recorded
same-repository single-host/single-controller topology. The production command
remains uncomposed; deployment, HA, hostile multi-tenant, independently
implemented caller, and production-readiness evidence remain open.

E2E baseline lock `d5d6ed1a815b49625a054d9931a8cec2234d8e7e`
advances the reference, candidate, Browser, shared-capacity, durable-revocation,
downstream-fencing v1/v2, and PostgreSQL controlled-restore parent checks to
the Phase 5 evidence/CI baseline
`59de37d5ee22776305dfaab866c25ea6bd5406bc`; E2E race/shuffle, vet, and all
eight local `-check` commands pass.

Historical P2.6 evidence remains at implementation
`3fe314a012b808fe60dbd783d7c7c7121d3c548e` and E2E lock refresh
`ae476fed12e82f472b19ff78fda633c8d702561d`: the then-current 50-case local
Runner, six-case remote Runner, root/E2E race and vet, Contract lock,
parent-lock, and all eight E2E checks passed from a clean checkout.

Previously passed locally at their recorded identities (authorized test
environment):

- ADR 0038 implementation `034e647`, Contract lock `fd48de9`, projection
  regression fix `af8a505`, and then-active E2E lock `b8d4829`; Contract revision
  `034e6476ff508a0571e64de9ce923799717b902b`, tree
  `33f1926feb8e12f24a8f92b9e6879102e19c2173`, and all 50 Suite cases;
- root and E2E-module full race/shuffle tests and vet, the Contract verifier,
  the race/shuffle conformance runner, and all eight E2E `-check` commands,
  including the retained historical Candidate check;
- same-repository Docker reference run `20260907T044611.598221000Z`, with all
  15 initial and 5 reconstruction scenarios passing, zero retained managed
  containers, and manifest SHA-256
  `60bda2dae83053db447417cea5c5e38d4798e1e90b91fbb5cfc75d2991c6993e`;
- JSON parsing of all newly added Contract resources;
- `git diff --check`;
- `internal/contractlock` unit tests;
- local Provider projection tests for `providerapi/v1` and `providerapi`;
- full `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- provider API socket/TLS tests;
- tagged Docker integration.
- P4 browser Contract verification, exact capability/create/session/handoff/
  usage projection, admission digest bindings, security/rejection fixtures,
  operation/meter component validation, protected handlers with fail-closed
  absent-application behavior, and the locked 50-case Suite. The reference and
  candidate 15+5 runs are coding/shell regression only and do not add browser
  E2E evidence.
- P1.2.3 coordinator race/shuffle tests for idempotent accept, deadline
  pre-dispatch, known/unknown runtime outcomes, restart inspection, stale
  generation rejection, event replay, and concurrent reconciliation.
- P2.2b provider exec repository tests for idempotency and digest binding,
  cancellation target/generation binding, independent cancellation fencing, result
  retention and tombstones, immutable snapshots, concurrent memory access,
  file restart/lock/corruption handling, and cancelled contexts;
- P2.2b full race/shuffle test matrix, `go vet`, local Contract lock verifier,
  19-case local Conformance Suite, dependency-boundary check, and `git diff
  --check` passed in the authorized test environment.
- P2.2c focused repository/coordinator race/shuffle tests cover durable
  reservation before dispatch, attach identity and receipt conflicts, replay
  without redispatch, restart/query of unattached records and cancellation
  intents, cancellation confirmation gating, result/cancellation conflicts,
  context failures, deep copies, and file lock/corruption behavior.
- P2.3c0 full race/shuffle, vet, Contract lock verification, 26-case local
  Conformance Suite, JSON parsing, and diff checks passed against revision
  `71fee34380affcb46e1e1dce667475aa241048a4`.
- P2.3c1 focused and full race/shuffle, vet, unchanged Contract lock, 26-case
  Suite, JSON, dependency-boundary, and diff checks cover strict terminal-only
  requests, deadline/expiry bounds, immutable snapshots, transition rules,
  opaque handoff identity, and outcome-unknown non-reopening.
- P2.4 local verification covers JSON/YAML Contract resources, lock revision
  `7e00715e5e3583ec4f98eb25cfeab587638ac858`, 33-case Conformance, full
  race/shuffle, vet, artifact/usage domain bounds, memory adapter replay and
  conflict behavior, expiry, cancellation, immutable snapshots, and
  `git diff --check`. Post-push CI `32804619553` passed all three required
  jobs for `3b94146`. This remains provider-local evidence only: no HTTP route,
  artifact publication, billing truth, distributed reconciliation, external
  caller, tenancy, deployment, or production claim is made. P2.4a0 subsequently
  locked the three missing protected-admission operation bindings, async
  outcomes, safe pre-accept errors, and read descriptor digests. CI
  `32819717542` passed all required jobs for `2aba87f`, while route-absence tests
  confirm that no artifact/usage transport was composed. P2.4a1 then locked
  generic operation-family aggregation and the artifact/usage read-state
  matrices in `3846c9e`, `6f549c2`, and `dbea0e8`. Local race/shuffle, vet,
  lock verification, the 35-case Suite, projection/admission tests, and
  post-push CI `32823783136` passed. This adds no application, repository,
  aggregator, handler, router, transport, or external-caller evidence.
- P2.4a2 local verification covers durable artifact accept-before-dispatch,
  idempotent replay/conflict, generation/fencing checks, explicit dispatch and
  reconciliation, source-missing/content-rejected/outcome-unknown truth,
  no-duplicate dispatch, memory/file restart and lock/corruption/expiry
  behavior, operation-keyed usage evidence correlation, and operation-family
  aggregation with duplicate-ID fail-closed behavior. Authorized full
  race/shuffle, vet, Contract lock verification, 35-case Suite, and diff checks
  passed. CI `32827387303` passed all three required jobs. This remains
  provider-local component evidence: no handler, router, config, HTTP route,
  external caller, aggregate conformance, multi-controller reliability,
  multi-tenant security, deployment, or production claim is made.
- P2.4a3 local verification covers the three locked artifact/usage routes,
  strict admission and descriptor binding, artifact-stage schema preflight
  before mutation guard reservation, `202` accept-only staging, evidence/usage
  correlation, operation-family aggregation, bounded `400`/`403` mapping, and
  route nondisclosure. Full race/shuffle, vet, Contract lock verification,
  35-case Suite, projection tests, diff checks, and post-push CI
  `32838784395` passed. Create/session preflight is independently covered by
  P2.5c; external caller compatibility, aggregate conformance, multi-controller
  reliability, multi-tenant security, deployment, and production readiness
  remain unproven.
- Gateway clock correction `0893ac3` derives grant-expiry timers from the
  configured clock used by authorization and endpoint checks. The focused
  Gateway race/shuffle suite passed ten consecutive runs, and the full
  race/shuffle suite passed. This is deterministic component evidence only.
- P2.5b local verification covers Contract revision `22a148e2898477790512d5bb742605654ff00ebf`,
  tree `1a967c9c6ce9646c8431f6ee48699ec9f406a589`, the atomic coding/shell
  advertisement and rejection fixtures, exact create/session/evidence
  consistency, fail-closed application/wire projection, and three new Suite
  mappings. Full race/shuffle, vet, Contract lock verification, the 38-case
  Suite, diff checks, and post-push CI `32924361132` passed. Runtime dispatch,
  nonempty command advertisement, and external-caller evidence were not
  established by that slice; the exact independent result was later recorded
  separately under P2.7.
- P2.5c local verification covers create and runtime-session digest-consistent
  unknown-field rejection and encoded body limits before mutation guard
  reservation, plus unchanged valid replay and stale-fencing conflicts. The
  existing `protected-admission-replay-and-fencing` Suite case now selects
  these preflight regressions. Focused and full race/shuffle, vet, unchanged
  Contract lock verification, the mapped 38-case Suite, diff checks, and
  post-push CI `32926181615` passed. Application dispatch, runtime composition,
  and external-caller evidence were not established by that slice; later P2.7
  evidence remains a separate result.
- P2.5d local verification covers a Provider-specific Docker adapter without
  importing local `instance` models or repositories; exact ownership and
  immutable-spec digests; stable read-only `/inputs`, writable `/workspace`
  and `/outputs`, bounded tmpfs `/tmp`; digest-pinned image, numeric non-root
  identity, read-only root, disabled networking, dropped capabilities,
  no-new-privileges, resource/log bounds, idempotent create/remove, context
  cancellation, foreign-resource refusal, lost-response `outcome_unknown`,
  file-repository restart observation, and mount cleanup. Focused and full
  race/shuffle, vet, unchanged Contract verification, the 38-case Suite, diff
  checks, and live integration for both Docker packages passed at `de18787`;
  post-push CI `32929140044` passed all three jobs for evidence baseline
  `e3a8265`. This does not add exec/session/artifact/usage runtime
  dispatch, nonempty advertisement, external caller, multi-controller,
  multi-tenant, deployment, or production evidence.
- P2.5e local verification covers strict protected exec/cancel/result/operation
  projection; durable reservation before dispatch; independent file persistence
  and v1-to-v2 migration; execution/cancellation identity conflicts;
  sandbox/attempt/fence correlation; injected-clock temporal ordering; restart
  and on-demand reconciliation; terminal-summary retention after result expiry;
  real Docker exit handling, cancellation, private stdout/stderr capture,
  truncation, and idempotent identity-bound cleanup; and pre-accept rejection of
  unsupported environment, secret, and stdin references. Focused and full
  race/shuffle, vet, unchanged Contract verification, the 38-case Suite, diff
  checks, and live integration for both Docker packages passed at `5917a57`.
  Post-push CI `32937530059` passed `provider-contract`, `test`, and
  `docker-integration` for evidence baseline `2f7a79b`. At that baseline usage
  identity was bounded correlation only and the real collector was deferred to
  P2.5g; the later P2.5g local evidence is recorded separately. P2.5e does not
  prove external caller compatibility,
  aggregate conformance, multi-controller reliability, multi-tenant security,
  deployment, or production readiness.
- P2.5f1 local verification covers the backend-neutral terminal allocation,
  observation, attachment, cleanup, receipt, and stream boundaries; an
  in-sandbox broker that owns the PTY and shell; adapter-private container,
  broker-exec, and Unix-socket identity; opaque `ref:terminal/*` receipts;
  idempotent allocation, lost start responses, identity conflicts,
  per-sandbox/per-controller capacity, expiry, context cancellation, sandbox
  removal, corrupt state, and idempotent process-group cleanup. Full
  race/shuffle, vet, `go mod verify`, unchanged Contract verification, the
  locked 38-case Suite, diff checks, and both live Docker integration packages
  passed at `6778d3c`. The live test preserves a shell variable and broker exec
  identity across Provider driver reconstruction and a fresh attach. Building
  the broker into writable `/workspace` is test deployment only. Repository CI
  `33033284420` passed `provider-contract`, `test`, and `docker-integration` for
  evidence baseline `66dd3d1`. This does not prove durable session coordination,
  `ref:session:*` resolution, WebSocket or Gateway composition, external caller
  compatibility, aggregate conformance, multi-controller reliability,
  multi-tenant security, deployment, or production readiness.
- P2.5f2 local verification covers session repository v2 and valid v1
  migration; preservation of accepted operations and legacy successful
  handoffs; legacy running migration to `outcome_unknown`; immutable
  provider-neutral allocation receipts and observations; lifecycle
  ready/revision/generation/lease projection; session-local fencing high-water;
  accept-before-allocation; persisted acceptance-time allocation identity;
  idempotent replay/conflict; lost receipt attachment recovery without a second
  runtime allocation; no redispatch after an uncertain allocation or
  observation; restart reconciliation; expiry and identity-bound cleanup retry;
  corruption and duplicate-reference rejection; and lifecycle recheck before a
  registry-supplied success commit. Full race/shuffle, vet, `go mod verify`,
  unchanged Contract verification, the locked 38-case Suite, diff checks, and
  both live Docker integration packages passed at `ccffd52`. Post-push CI
  `33045725476` passed `provider-contract`, `test`, and `docker-integration` for
  evidence baseline `3abefd4`. This does not add a `ref:session:*`
  registry/resolver, WebSocket adapter, Gateway or command composition,
  nonempty advertisement, external caller, aggregate conformance,
  cross-repository atomicity, multi-controller reliability, multi-tenant
  security, deployment, or production readiness.
- P2.5g local verification covers artifact snapshot v2 with admission-derived
  tenant authority and explicit rejection of untrusted v1 state; durable
  accept-before-dispatch; lifecycle readiness, tenant, generation, lease, and
  fencing synchronization; request/retention deadlines; staged, rejected,
  missing, unknown, expired, recovery, and shutdown outcomes; and no swallowed
  reconciliation or persistence failures. The Docker output reader confines
  reads to an owned running generation and rejects links, directories, and
  non-regular files. The stager enforces digest/media/size, executes injected
  scanners by argv with bytes on stdin, writes private atomic content, and
  returns only `ref:staging/*`. Exec result observation derives only stable
  wall-time and exec-count evidence with `partial` reconciliation; it does not
  invent CPU, memory, network, price, or billing truth. Versioned locked file
  repositories, all-family operation reads, state-file separation, and
  default-disabled development composition pass focused and full race/shuffle,
  vet, `go mod verify`, unchanged Contract verification, the locked 38-case
  Suite, diff checks, and a Docker-tagged command-root vertical covering
  staged/rejected/missing evidence, operation aggregation, opaque-reference
  non-disclosure, and artifact/usage restart recovery. This reviewed worktree
  is based on implementation `0e6e108`; repository CI `33157119149` passes all
  three jobs. It proves no external caller,
  aggregate conformance, multi-controller reliability, multi-tenant security,
  deployment, publication, billing, or production readiness.
- P3 local component verification covers immutable ProviderRevision binding,
  deterministic canary selection, rollback isolation, drain state, shadow
  validation without dispatch, bounded metric aggregation, race/shuffle, vet,
  and `git diff --check`. This does not prove an external caller, traffic
  canary, rollback E2E, or platform-contract compatibility.
- Internal Block manifest verification covers strict YAML/JSON decoding,
  bounded digest-pinned image and path validation, symlink/nested-path refusal,
  duplicate detection, deterministic registry ordering, defensive copies, and
  cancellation. The root full race/shuffle, vet, Contract verifier, locked
  50-case Suite, and independent E2E module race/shuffle/vet/lock checks pass.
  The current local reference Docker run passes against harness/Provider lock
  `b8d4829`/`af8a505`; the latest local Candidate run remains historical
  pre-refresh evidence against `59e08d5`/`c0a55d1`.
  This is component, reference-caller, and candidate evidence only; it does not
  establish independently implemented external-caller interoperability or any
  production gate.
- P4 browser image verification covers immutable per-platform source pins,
  scratch repack, fixed loopback CDP, rejected argv overrides, numeric user,
  read-only root, stable `/workspace` and `/tmp` mounts, resource bounds, and
  the fail-closed Chromium seccomp profile. Local arm64 and amd64 integration
  observed Chromium `151.0.7922.109` and a sandboxed zygote under
  `network=none`, `cap-drop=ALL`, and `no-new-privileges`, with no
  `--no-sandbox` process. Manual publication run `33724368530` passed the same
  gate on native hosted runners and published GHCR index
  `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`
  for source `58ed009`, tag `sha-58ed0093816d3daa3000750013b8e5991ef4bcf7`,
  and attestation `44912296`. Independent `docker buildx imagetools inspect`
  found exactly linux/amd64 and linux/arm64/v8 manifests; independent
  `gh attestation verify` passed with the repository, signer workflow, source
  digest, and hosted-runner constraints. The exact image publication gate is
  closed for this immutable digest.
  Provider runtime/transport/Gateway composition, browser caller, deployment,
  and production gates remain open.

- P4 uncomposed browser session component verification covers the independent
  browser domain and runtime ports, durable memory/file authority, lifecycle
  coordination with accept-before-allocation, exact receipt identity,
  restart/reconciliation, expiry, cancellation, unknown-outcome handling,
  cleanup, separate opaque-reference memory/file registry and per-connect
  revalidation, browser operation-family projection, and bounded duration usage
  evidence. Focused and full-repository race/shuffle plus vet pass. This is
  Provider-local component evidence only; it does not compose HTTP, Gateway,
  startup advertisement, the
  browser image runtime, an external caller, aggregate
  conformance, multi-controller reliability, tenant isolation, deployment, or
  production readiness.

- P4 Browser Docker adapter verification covers exact publication and seccomp
  binding, startup dependency refusal, image/platform/ownership drift,
  cancellation/deadline propagation, deterministic capacity, durable replay
  and restart observation, cleanup and unknown outcomes, four bounded stable
  guest tmpfs mounts, non-TTY stdout-only relay, private version discovery, and
  RFC 6455 handshake validation. Focused/full race-shuffle, vet, Contract
  verification, the unchanged 48-case Suite, and all three tagged Docker driver
  packages pass locally. The Browser live case uses `network=none` and proves
  only the exact image controls plus private CDP transport; restricted-egress
  evidence is recorded separately below.

- P4 Browser provenance-verifier verification covers the independent
  `provider/browser/provenance/ghcli` adapter. It rehashes a configured absolute
  executable, invokes `gh attestation verify` without a shell, reads the bundle
  from the immutable GHCR artifact, pins GitHub OIDC/Sigstore and SLSA identity,
  rechecks the signed statement, bounds output and environment inheritance, and
  preserves cancellation. Focused/full race-shuffle, vet, the tagged real GHCR
  integration, and repository CI `33737531693` pass; that CI has four separately
  named jobs including `browser-provenance`. This is an uncomposed component: it
  does not prove complete Browser startup, restricted egress, create-policy
  binding, protected transport, Gateway behavior, or Browser caller E2E.

- P4 restricted-egress/create-policy verification covers strict policy/config
  parsing, special/private/metadata address denial, bounded DNS, exact HTTP Host
  and TLS SNI enforcement, per-allocation internal networking, fixed private
  Gateway DNS, exact Browser/Gateway image and container drift checks, durable
  policy identity, restart recovery, rollback, and cleanup. Implementation
  `7e60340` passes focused/full race-shuffle, vet, unchanged Contract verification
  and 48-case Suite, existing Docker regressions, and a combined tagged Docker
  integration using the real provenance verifier and signed Browser image. The
  integration passed allowed HTTP/HTTPS, denied unlisted and metadata targets,
  reconstructed both adapters, and left no managed container/network. This is
  single-controller local component/lifecycle-binding evidence only. Repository
  CI `33747803509` passes `provider-contract`, `test`, `docker-integration`, and
  `browser-provenance`; its Docker job does not execute the Browser tagged case.

- P4 Browser protected-transport verification covers the two locked route
  bindings, mTLS/JWS/admission ordering, closed-JSON and size preflight before
  mutation state, application request/response correlation, async operation
  projection, pending/expired/unavailable/conflict errors, opaque handoff
  projection, forbidden endpoint-detail absence, nil-application failure,
  concurrency, cancellation, and Browser operation-family aggregation. ADR 0023
  and implementation `b8423f5` pass focused/full race-shuffle, vet, Contract
  verification, and the unchanged 48-case Suite locally. Harness lock
  `a2721ad` then passed repository CI `33760609353` plus hosted Reference and
  Candidate coding/shell regressions `33760609272` and `33760609231`. The caller
  runs contain no Browser scenario. This component commit alone does not compose
  the Browser command/runtime graph and is not Browser
  external-caller, aggregate, multi-controller, tenant, deployment, or
  production evidence.

- P4 caller-owned Browser Gateway verification covers exact exclusive
  terminal/Browser request and grant identities, strict opaque-reference
  namespaces, endpoint sandbox/session/profile/generation/expiry binding,
  denial before resolution, active revocation, reconnect resolution, and
  metadata-only audit. ADR 0024 and implementation `5aae281` add a distinct
  private Chromium RFC 6455 adapter with server/client masking rules,
  text/binary fragmentation, ping/pong/close, UTF-8, partial-write,
  cancellation, and 64 KiB hard-limit tests. Full root and `e2e/` race/shuffle,
  vet, Contract verification, the unchanged 48-case Suite, and local Reference
  and Candidate runs `20260904T013909.243838000Z` and
  `20260904T014037.825223000Z` pass against harness/Provider lock
  `9eb32ba`/`5aae281`. Those 15+5 runs contain no Browser scenario. Hosted
  CI `33826813073` and Reference/Candidate workflows
  `33826813099`/`33826813100` pass against the same lock. Their caller runs still
  contain no Browser scenario.

- P4 Browser command/reference-caller verification covers the default-disabled
  Provider graph in ADR 0025/`66183b1`, bounded EDNS0 correction `f760369`, and
  ADR 0026 harness `79fee2b`. Repository CI `33838215949` passes all four jobs.
  Hosted Browser Reference E2E `33838215924` passes 10 initial and 5 reconstructed
  scenarios, including protected lifecycle, opaque handoff, CDP, restricted
  egress, denial/expiry/revocation, partial/complete usage, mTLS binding,
  recovery, and cleanup. Its sanitized artifact digest is
  `sha256:4acfbc97c0c1f64e987b00870849a2244e33596918d08e659385c428310843ea`.
  This is reference Browser external-caller evidence only.

- P4 Browser Gateway local-capacity verification covers explicit valid total
  and per-session configuration, non-blocking acquisition after exact grant
  binding and before revocation/Provider resolution, concurrent contention,
  metadata-only rejection audit, idempotent release on failure/close/revocation,
  and slot reuse. ADR 0027 and implementation `7b062e6` pass focused contention
  and revocation tests for 20 shuffled race runs, plus full repository
  race/shuffle, vet, Contract verification, and the unchanged 48-case Suite.
  E2E lock `a219d29` and harness `28a9a5e` pass the independent module's full
  race/shuffle, vet, and three check modes. Repository CI `33846603580` passes
  `provider-contract`, `test`, `browser-provenance`, and `docker-integration`.
  Hosted Browser Reference E2E `33846603547` passes 11 initial and 5
  reconstruction scenarios. Its added black-box scenario holds an admitted CDP
  connection, observes capacity rejection for a second same-session grant
  without disrupting the first, then reconnects after release. Artifact
  `browser-reference-e2e-evidence-33846603547` has digest
  `sha256:b024225aa3545fa56a7cc5113f29c0817a86ebc70c3976e10d81bf3507546cba`;
  inspected run directory `20260904T065835.995038539Z` has 11+5 passing reports
  and a 20-record Gateway audit with exactly one `capacity_rejected` event and
  no payload, secret, token, or endpoint field. Reference/Candidate coding/shell
  runs `33846603323`/`33846603454` also pass 15+5 against that historical lock;
  their artifact digests are
  `sha256:333be42b84c1d2ebfff86bae7d619348e84d13fe29b6f15975b587c2d38447c3`
  and `sha256:d3148037292f4e883dc96a1e224294f5841a4ae838bc1c8e2fe5e67455d39f95`.
  Those two runs contain no Browser scenario. The capacity result remains
  process-local and post-WebSocket-upgrade; it is not pre-upgrade edge,
  distributed, multi-controller, hostile-tenant, deployment, or production
  evidence.

- P4 Browser pre-upgrade edge verification covers explicit bounded
  configuration, non-queueing global concurrency, fixed-window request rate,
  rate-before-capacity accounting, cancellation, zero/backwards clock failure,
  typed-nil dependencies, idempotent release, generic `429` with bounded
  `Retry-After`, generic `503`, and lease release after failed or successful
  WebSocket handling. ADR 0028 and implementation `44ea2ee` pass focused and
  full repository race/shuffle, vet, Contract verification, and the unchanged
  48-case Suite. E2E lock `3b63c76` and harness `249cdd4` pass the independent
  module race/shuffle, vet, and all three check modes. Clean Browser run
  `20260904T080946.250607000Z` passed 12 initial and 5 reconstruction scenarios
  on `linux/arm64`, with the exact signed Browser image digest
  `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`.
  Its 16 authenticated wrong-Origin requests observe both ordinary `403` and
  pre-upgrade `429`, validate `Retry-After`, and recover to ordinary `403` after
  the window. The structured 20-record Gateway audit has the expected six
  `authorized`, six `connected`, four `client_closed`, and one each
  `capacity_rejected`, `denied`, `expired`, and `revoked`, and no
  `grant-browser-edge-*` identity. Clean Reference run
  `20260904T081521.464863000Z` and Candidate run
  `20260904T081706.648122000Z` separately pass their 15+5 coding/shell
  regressions against the same local harness/Provider lock and runtime digest
  `sha256:bcd5dbff8b2d108ee7dab464a85ee7d39ef74a8616a6af73a94ebb10ff8eaf75`.
  Repository CI `33854020951` passes all four jobs. Hosted Reference run
  `33854020874` and Candidate run `33854020947` pass their separate 15+5 sets;
  artifact digests are
  `sha256:220650f1b61b0297ec445ded03bf3a15870514a9482c9e55012ddfba8ae0da2d`
  and `sha256:48cbe44c433e5b3a858a2691fe1f736469b2e8d71228541f2bdfcc4aab1c15b1`.
  Hosted Browser run `33854020809` passes 12+5 on `linux/amd64`; artifact
  `browser-reference-e2e-evidence-33854020809` has digest
  `sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`.
  Its inspected run directory `20260904T083407.182245415Z` binds harness
  `e7e7f03`, Provider `44ea2ee`, the Contract/tree, 48-case Suite, and exact
  signed Browser image. Both reports pass and the 20-record audit preserves the
  expected type counts with no `grant-browser-edge-*`. The Browser result is
  process-local edge plus Browser reference external-caller evidence,
  not listener/TLS/HTTP, tenant-partitioned/shared capacity, distributed
  revocation, production advertisement/public Gateway, independently
  implemented external-caller interoperability,
  aggregate, multi-controller, hostile multi-tenant, deployment, or production
  evidence. The Reference and Candidate runs retain their coding/shell and
  candidate-only boundaries.

- P4 Browser listener/TLS/HTTP verification covers bounded accepted
  connections before TLS, bounded regular-file certificate/private-key reads,
  explicit server-auth validity, frozen TLS 1.3 and HTTP/1.1-only policy,
  explicit HTTP header/read/write/idle limits, cancellation before bind, and
  graceful shutdown. ADR 0029 and implementation `b8f8941` pass focused/full
  race-shuffle, vet, Contract verification, and the unchanged 48-case Suite.
  Harness `7a20d9d` passes the independent module race/shuffle, vet, and all
  three check modes. Clean local Browser run
  `20260904T091156.303717000Z` passed 13 initial and 5 reconstruction scenarios
  on `linux/arm64` against harness `35cf068`; repository CI `33857739103`
  passed all four jobs. Hosted Browser run `33857739150` passed the same 13+5
  set on `linux/amd64`. Its black-box transport scenario rejects TLS 1.2,
  negotiates TLS 1.3 with HTTP/1.1, rejects slow and oversized headers before
  the handler, saturates the configured accepted-connection limit, and proves
  recovery. Artifact `browser-reference-e2e-evidence-33857739150` has digest
  `sha256:94bcdfa53b667d4a6bc17fd6714cc9895e8402b830b8c6425c604c835f9228f`;
  inspected directory `20260904T091942.992885726Z` pins harness `7a20d9d`,
  Provider `b8f8941`, Contract/tree, 48-case Suite, exact signed image, and
  `linux/amd64`. Both reports pass. The 20-record audit preserves six
  `authorized`, six `connected`, four `client_closed`, and one each
  `capacity_rejected`, `denied`, `expired`, and `revoked`, with no edge grant,
  endpoint, token, credential, CDP, or payload field. Hosted Reference and
  Candidate regressions `33857739105`/`33857739189` separately pass their 15+5
  coding/shell scenario sets; they are not Browser evidence. The Browser result
  is listener/TLS/HTTP component plus reference-caller evidence only, not
  authenticated partition-aware shared/distributed capacity, durable
  distributed revocation, production configuration, deployment, or production
  evidence.

- P4 Browser authenticated-capacity verification covers explicit dependency
  and ordered limits, authorization and exact grant binding before acquisition,
  atomic global/tenant/session contention with no partial reservation,
  cross-caller/grant same-session enforcement, tenant independence,
  cancellation, typed loss/unavailability, idempotent independently bounded
  release, release-failure audit, stable revocation/expiry/capacity/transport
  priority, reconnect suppression, and concurrent acquisition/release. ADR 0030
  and implementation `997fb0d` pass focused/full race-shuffle, vet, Contract
  verification, and the unchanged 48-case Suite. E2E lock `49d1c20` passes the
  independent module race/shuffle, vet, and Reference, Candidate, and Browser
  lock checks. Repository CI `33940332882` passes all four jobs. Hosted Browser
  run `33940332911` passes 13+5 against harness/Provider `6b01b75`/`997fb0d`;
  artifact digest is
  `sha256:f4133967b6e573c701b82c72dc4d101febd4e6b28199e188fa0c8db049bff9ae`.
  Its inspected directory `20260905T025344.457525674Z` pins the Contract/tree,
  48 cases, signed Browser image, and `linux/amd64`; both reports pass. The
  20-record Gateway audit retains six `authorized`, six `connected`, four
  `client_closed`, and one each `capacity_rejected`, `denied`, `expired`, and
  `revoked`, with no edge grant, endpoint, token, credential, CDP, or payload
  field. This is single-process authenticated-memory reference evidence. A real
  shared backend, two independent Gateway processes, TTL/renewal, crash
  reclamation, stale-owner fencing, distributed revocation, deployment, and
  production evidence remain absent.

- P4 pre-upgrade edge correction `2ed5e68` serializes `Clock.Now` observation
  and fixed-window state updates under the same mutex. A prior full-repository
  race/shuffle run exposed a false `ErrUnavailable`/HTTP `503`; the new
  deterministic regression covers that ordering. HTTP `429` remains only the
  intended pre-upgrade fixed-window rate rejection. This path is separate from
  the authenticated shared-capacity rejection after WebSocket `101`, which is
  observed as a normal `1000` close.

- P4 Browser Redis-compatible shared-capacity verification covers immutable
  policy provisioning and startup checks, bounded atomic global/tenant/session
  contention, renewal beyond three lease TTLs, confirmed lease loss, Gateway
  crash reclamation, stale-owner fencing, renew/release cleanup, retained-store
  outage failure closure and recovery, and sensitive-data absence. ADR 0031 and
  implementation `9434540` add the adapter. Clean local run
  `e2e/evidence/shared-capacity/20260905T061037.558537000Z` passes all 10
  black-box scenarios on `linux/arm64` through two independent Gateway OS
  processes and one real pinned Valkey authority, against Provider baseline
  `2ed5e68` and harness/Gateway source `ddbb2c4`. Rejection occurs after
  WebSocket `101` and is observed as a normal `1000` close, not HTTP `429`.
  The manifest pins policy fingerprint
  `1b29321807530907a8407cd6d33bdefbbb980fd7cb0b297592181a2333a8bacd`,
  Valkey index
  `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`,
  arm64 child
  `sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e`,
  and Contract/tree/48-case metadata with `contract.exercised=false`; Valkey
  provenance is explicitly not established. The private echo fixture does not
  exercise Provider API, real Browser/CDP, image provenance, restricted egress,
  artifact/usage, HA/failover, durable distributed revocation, downstream
  fencing, Provider multi-controller, hostile multi-tenant, independently
  implemented external-caller interoperability,
  aggregate conformance, deployment, or production behavior. This is local,
  not hosted, evidence.

- Hosted Browser Shared Capacity E2E run `33949577876` passes the same 10
  scenarios on `linux/amd64` against harness/Gateway source `de297e7` and
  Provider `2ed5e68`. Artifact
  `browser-shared-capacity-e2e-evidence-33949577876` has GitHub digest
  `sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`.
  Downloaded run `20260905T062246.271594332Z` contains exactly six sanitized
  files and all 10 report entries pass. Its audits contain 22 `authorized`, 22
  `connected`, 18 `client_closed`, five `capacity_rejected`, two
  `capacity_lost`, and two `capacity_unavailable`; observations contain 22
  `resolve` and 22 `dial`. The same private echo and Gateway/Valkey-only
  boundary applies: Contract/tree/48 cases are metadata with
  `contract.exercised=false`, Valkey provenance is not established, and the run
  does not exercise Provider API, real Browser/CDP, image provenance,
  restricted egress, Provider artifact/usage, HA/failover, durable distributed
  revocation, downstream fencing, Provider multi-controller, hostile
  multi-tenant, independently implemented external-caller interoperability,
  aggregate, deployment, or production behavior.

- P4 Browser exact-grant revocation verification covers the atomic
  level-triggered watch contract, invalid and unavailable watch closure,
  pre-resolution rejection, cancellation during blocked resolve/dial, active
  disconnect, reconnect suppression, stable termination priority across
  revocation, expiry, capacity, and unavailability, and bounded audit reasons.
  ADR 0032 and implementation `c0a55d1` add the port, memory adapter changes,
  and the Redis-compatible retained-tombstone source/writer. The Redis adapter
  verifies immutable policy and uses hashed namespace/grant keys. It uses Redis
  server time and enforces a 1-second to 24-hour maximum grant-lifetime policy
  range. It preserves the maximum expiry with `PEXPIREAT` and bounds polling
  and operations.
  Focused/full race-shuffle, vet, Contract verification, the unchanged 48-case
  Suite, and tagged integration against pinned Valkey index
  `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
  pass locally. E2E lock `59e08d5` pins Provider `c0a55d1`; local Browser run
  `20260905T080015.795386000Z` passes 13+5, Reference
  `20260905T080530.577843000Z` and Candidate
  `20260905T080623.861033000Z` each pass 15+5, and shared-capacity
  `20260905T080725.227680000Z` passes 10/10 on arm64. These are pre-ADR0033
  regressions only. Browser still uses one process-local memory revocation
  authority, while shared capacity does not exercise revocation. These
  component and regression results alone provide no independent
  two-Gateway/independent-revoker caller, downstream-fencing, Valkey
  provenance/HA, multi-controller, multi-tenant, deployment, or production
  evidence.

- Hosted pre-ADR0033 repository CI `33955437033` passes `provider-contract`,
  `test`, `browser-provenance`, and `docker-integration`. Reference run
  `33955436969`, Candidate `33955437046`, Browser `33955436984`, and shared
  capacity `33955436968` pass against harness `c7fe24d` and Provider `c0a55d1`.
  Downloaded reports contain only passing 15+5, 15+5, 13+5, and 10/10 scenario
  sets. Their respective artifact digests are
  `sha256:68642bb9810b397fada89bdb2666c11d46ddc0961eec6d6fd7d5e826e7336a70`,
  `sha256:2b745f256e4a0e1bdfa46c5129b1d92548a6f7afd2630a0c0720eb552ed35147`,
  `sha256:a5b0be338190b39f16c27e2a7b31ba983022fc8da8f60fa23c9d4fdce1834173`,
  and `sha256:d99d76374c745fb9a7adcc9b7e09e1f24963641e7d86b277a9a0647b870acdc2`.
  This is repository CI plus separately named pre-ADR0033 regression evidence,
  not the ADR 0032 two-Gateway/independent-revoker caller gate, real Agent
  Platform, aggregate, multi-controller, multi-tenant, deployment, or
  production evidence.

- Harness/Gateway `e952ef9` adds the separately locked ADR 0032
  durable-revocation runner. Clean local run
  `20260905T095109.569973000Z` passes 7/7 on `linux/arm64`; hosted workflow run
  `33959122456` passes 7/7 on `linux/amd64`. Both use two independent Gateway OS
  processes, two independent black-box caller processes, one independent
  revoker process, and one pinned retained Valkey authority. Local A/B
  revoke-acknowledgement-to-close was 72/72 ms and hosted was 97/99 ms, below
  the 2-second bound. The hosted artifact
  `browser-durable-revocation-e2e-evidence-33959122456` has GitHub digest
  `sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`;
  downloaded run `20260905T095228.504289461Z` contains exactly seven sanitized
  files. Contract/tree/48 cases are metadata with `exercised=false`, Valkey
  provenance is unestablished, and ACL role separation is false. This closes
  only the caller-owned durable exact-grant revocation gate, not Provider API,
  real Browser/CDP or downstream fencing, independently implemented
  external-caller interoperability,
  multi-controller, hostile multi-tenant, deployment, or production readiness.

- ADR 0033 and implementation `b4d41c9` add narrow downstream action-fence and
  fenced-resolver ports, Redis-compatible exact-member/session-high-water
  authorization, a complete-message private ingress state machine, and
  fail-closed Browser composition. Targeted and full race/shuffle tests, vet,
  Contract verification, the unchanged locked 48-case Suite, and tagged
  integration against pinned Valkey index
  `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
  pass. This closes the component plus real-backend adapter integration gate.
- Local harness/run `550c785`/`20260906T050213.016063000Z` and hosted
  harness/run `2cadc53`/`34013982796` each pass all 13 ADR 0033 scenarios on
  `linux/arm64` and `linux/amd64`, respectively, through two independent
  callers, two Gateways, one authenticated unique ingress, retained Valkey,
  and signed real Chromium. The five retained local evidence files are `0600`;
  the downloaded hosted artifact contains evidence directory
  `20260906T052710.781616339Z` with exactly five sanitized files. All manifest
  cleanup and sanitization checks pass. The
  hosted artifact digest is
  `sha256:9c00f3ba184e82d7eff661b831c05c1bdf331fa41caf2d8bbb3353168ab155b0`.
  Contract/tree/48-case identity is pinned, six protected Provider routes are
  exercised, and the Suite is explicitly not executed
  (`suite_exercised=false`). These close only the platform-specific named
  caller gates and do not exercise deleted history or restored snapshots.
  Valkey provenance/HA/failover, production metrics/configuration/deployment,
  Provider multi-controller, hostile multi-tenant, independently implemented
  external-caller interoperability,
  aggregate conformance, and production readiness remain unproved.
- ADR 0034 adds an explicitly selected v2 successor without changing those v1
  identities or results. Its permanent Redis hash retains eight fixed
  checkpoint fields and at most 4,096 canonical fingerprint-only session
  records; every verify/action validates the complete bounded shape. A separate
  sequence/token witness rejects missing, divergent, behind, or more-than-one-
  ahead Redis state and durably confirms admission; exact one-ahead recovery is
  limited to an interrupted witness CAS. The Darwin/Linux file witness rejects
  unsafe file shapes and reconstructs under a lifetime exclusive lock. Focused
  and full race/shuffle, vet, Contract verification, the unchanged 48-case
  Suite, and tagged integration against the pinned Valkey index pass. A
  separately locked
  18-scenario v2 caller harness is implemented with two Gateways, two callers,
  real Chromium, an independent file witness, and an orchestrator-only Redis
  fault identity. Clean local run `20260906T100233.295973000Z` at fixed harness
  `059357c` passes 18/18 on `linux/arm64`; its exact five-file `0600` evidence
  set passes cleanup and sanitization. This closes only the local ADR 0034
  Chromium deletion/restore caller gate. Hosted run `34026680591` at the same
  checkout passes 18/18 on `linux/amd64`; its inspected artifact contains
  evidence directory `20260906T101111.796974798Z` with exactly five sanitized
  files. Artifact ID `9987350368` has digest
  `sha256:3e68f1c4b5bd74e0ae0ff0fde2c9ffefc63852cf9fc82b3019bedfb228bf2c9a`.
  This closes only the hosted ADR 0034 caller gate. The Suite remains
  unexercised, and production witness, HA/failover, production ACL, deployment,
  and production evidence remain open.
- Intermediate hosted run `34025787520` at `ef63be4` failed the retained-field
  scenario only in the post-fault restore-control verifier. That helper required
  the restored hash's `DUMP` bytes to equal the earlier dump, although the binary
  representation is not canonical logical hash state. Fix `059357c` retains the
  real `DUMP`/`RESTORE` fault and validates Redis type, logical string/hash/zset
  content, missing-key state, and persistent/temporary TTL semantics. Focused,
  full E2E-module race/shuffle and vet gates plus both fresh caller runs pass.
  Earlier successful hosted run `34025141624` at `05b3b46` and artifact digest
  `sha256:55991ec39138183cefecab9cdfb5b23d4bada9b6b96286655cd9b8899a022203`
  remain historical pre-fix evidence; they are not relabeled as `059357c` runs.

Open:

- retain regression coverage for the exact independently qualified caller and
  require a fresh bounded qualification for any different caller, Provider
  revision, Contract/profile, artifact set, topology, or scenario inventory;
- define explicit cleanup authority, prerequisites, and evidence semantics
  before adding protected or mutating remote conformance profiles;
- complete the Provider lifecycle and session-management surface required by a
  deployable consumer, including explicit resource termination/lease control and
  standard Gateway lifecycle behavior; these routes remain unauthorized today;
- Browser production advertisement and deployable
  authenticated unique-ingress/public caller-owned Gateway; a production
  independent witness and restore procedure; Valkey provenance and HA/failover
  consistency; production storage/configuration, ACLs, metrics, hostile-tenant,
  and operational evidence;
- additional caller/profile qualifications, multi-issuer admission, aggregate
  lifecycle conformance, multi-controller
  reliability, multi-tenant isolation, HA, deployment, and production gates.

## Retired Platform Integration Track

P3 is retired rather than blocked. The former platform audit and candidate
harness remain historical evidence only. No missing named-platform repository,
credential, endpoint, or migration harness is an input to future
`sandbox-runtime` work. External consumers must conform to the exact locked
Contract and own their adapter, business state, authorization, Gateway policy,
and rollout process.

## Next Entry

P2.6's local release gate is complete. ADR 0040 defines the independently
implemented caller boundary, and P2.7a locks its verified machine-readable
definition authority at
`sha256:ec113d31612dbb7cc0e9461925170f74f33722bb2efb237dbc68aa89f2d60231`.
Overall P2.7 is complete for its named coding/shell caller qualification; the
result is bounded to the revisions and non-claims recorded above. P2.7b locks
the closed report schema at
`sha256:5d97e10c8b5b2f365e275e78868d5a35d78bbdffdec05ea2f18b5c947cd429f6`
and validator semantics at
`sha256:bc0b5be7aefcebb6a71871d9724cd671235b6ef2bf453a1954313547ad379ed9`,
plus the bounded report/evidence validator. It rejects retained timing or owned
positive evidence when its producer payload is absent; requires complete
payload-backed execution timing when present; caps each interaction at 64 wire
attempts; and counts every wire attempt as a potential resource when the
interaction evidence is inconsistent. Cleanup rejects partial query-scope
identities, digest-binds complete scopes, and enforces the baseline before first
mutation, exact post-teardown samples, and authoritative-inspector bindings.
Create-sandbox resources must be
present exactly when observed and must match both observer evidence and the
locked profile. Receipt bytes are staged and committed only after final checks,
with cancellation and competing-destination races rejected. These are
validator-component guarantees; they do not attest producer truthfulness,
original request bodies, or an external caller result. Validation requires the
qualification operator to stop
producers and keep the validator as the evidence root's exclusive writer from
`Verify` entry through return, including against other same-UID processes. The
dirfd and TOCTOU checks detect changes and fail closed; they do not prove
integrity against a continuously writable attacker. Only after a successful
return may the external operator package the root and record its archive
digest.

P2.7c.1 locks the adapter protocol schema at
`sha256:fdee270ca27003693b2ce504da769c9779825312e1dd4e06b5caf8578f5ee03c`
and operational semantics at
`sha256:997c49cd1a5b2c050d48333a973dd78b611221f869bf709cf6d1a8d771795a99`.
The protocol authority is bound through startup, process-supervisor, validator,
and receipt evidence. All qualification Schema compilers use one ECMA-262
regexp engine and reject ASCII controls without POSIX-only classes. Invocation
paths/endpoints now use closed canonical profiles. The definition requires a
digest-bound preflight freeze before the supervisor or harness acquires or
generates credential or forbidden-correlation material, plus cross-phase byte
identity; runtime proof awaits the supervisor and operator-upstream
non-derivation remains trusted. Non-error output invocation IDs and phases bind
to the single validated inbound invocation, including scenario case-ID phase
prefixes. Protocol errors now use disjoint pre-binding and post-binding terminal
branches with atomic identity nullability. The monotonic deadline model starts
once before first preflight, never resets across phase reconstruction, clips
case budgets to the remaining run and parent deadlines, and gives failure
termination a separate bounded five-second context. P2.7c.2a now enforces the
locked EOF/LF framing and exact byte/record limits, strict UTF-8/JSON/Schema and
direction rules, startup protocol-authority equality, and stable sanitized
decode failures. It intentionally does not enforce message order or deadlines,
recompute transcripts, or execute a process. P2.7c.2b.1 locks the complete
transition table, terminal/EOF/clean-exit rules, cross-phase startup equality,
and the closed transcript preimage Schema at
`sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293`.
P2.7c.2b.2 now enforces only the startup boundary: one validated first record,
one post-startup invocation-input authorization, and first-failure absorption.
It creates no transcript and launches no process. The subsequent work is
P2.7c.2b.3 binds the one authorized, validated invocation to the same Codec
and stdout stream, then accepts only the next sequence-one
`invocation_accepted` with matching invocation ID and phase. It also rejects
skipped records and mutated decoded projections/documents. P2.7c.2b.4 now
loads the exact ordered 15+5 case IDs from the verified profile and enforces one
result for each phase case: `completed` requires a same-case start, while
`not_executed` forbids one. Every scenario record remains bound to the same
Codec, stdout stream, invocation, phase, contiguous sequence, and observed wire
count. It ends at the terminal boundary and claims no execution. The subsequent
P2.7c.2b.5 now requires exactly one normal or error terminal. Normal completion
must match the observed dispositions; protocol errors obey the disjoint
pre-binding `invalid_invocation` and bound post-acceptance branches. Any
post-terminal byte, early EOF, or non-clean/early process-exit event fails
closed. Only terminal, EOF, then a supplied clean-exit event reaches `complete`.
P2.7c.2b.6 gates fresh reconstruction and canonical startup equality; c2b.7
produces and validates the sanitized transcript binding. c3.3 owns actual local
process start/stop and c3.4 binds the first stdout startup record before input.
c3.5 validates frozen locations and startup requirements, then concurrently
EOF-delivers bounded stdin and inherited-pipe credential streams. c3.6 binds the
shared monotonic run budget before the first supervisor preflight read, clips
case and operation waits, drains bounded stderr concurrently, consumes ordered
post-invocation stdout, and supplies the clean-exit event only after terminal,
stdout EOF and actual zero-exit reap. c3.7 publishes defensive sanitized phase
evidence only after that path, binds non-overridable adapter facts into one
canonical two-phase transcript, and passes real Darwin/arm64 and Linux/arm64
helper tests. d1 freezes the static target/topology, identity inventories,
numeric budgets, cleanup policy, and 15+5 scenario order. d2 obtains identities
through a read-only observer, creates and descriptor-rechecks the three private
persistent stores, recomputes the closed inspector scope and inventory digests,
and requires a complete zero-resource baseline before returning prepared state.
d3 adds a one-shot initial execution port whose only harness directive is the
runtime commitment, profile identity, phase ID, and ordered 15 case IDs. It
rechecks persistent state before releasing mutation capability, retains a
cleanup obligation across unknown start/cancellation/failure, clips each case
to 120 seconds and the earlier caller/execution deadline, enforces dependencies
and exact completed/not-executed progress, and derives fail-closed provisional
attempt/request counters from the profile's minimal accounting projection. It
does not expose request-construction fields, derive admission/resource truth,
or assign final scenario status.
d4 adds a separate one-shot reconstruction port that is unavailable until the
initial session reaches terminal/EOF/clean-exit completion. Its closed directive
adds only the four symbolic restart components and three symbolic preserved
stores to the d3 identity/case fields; it contains no prior correlation value or
state path. The executor supplies two distinct invocation IDs and exact ordered
old/new opaque identities for Provider, external caller, adapter, and caller
Gateway before any reconstruction result is accepted. All eight process labels
must be unique and non-PID-shaped, but remain provisional within d4. d5 now
requires a separately sourced process snapshot to corroborate them. The harness metadata-rechecks state before/after restart
and after the terminal gate without reading caller-owned entries, seeds the
five-case dependency chain from the stored initial dispositions, preserves the
original execution deadline, and checks cumulative provisional usage. Active
reconstruction blocks close; cancellation, malformed receipts, process reuse,
state replacement, invalid progress, or terminal/close failures fail closed and
retain cleanup. No final status or state-recovery/same-shell claim is produced.
Darwin race tests, native Linux/arm64 package tests, and guest-local tagged
Docker lifecycle/terminal/artifact integrations pass in the no-host-mount Lima
environment. The tests still use repository-owned identity/inspector fixtures
and mutable environment bootstrap inputs, so independent provenance and a
qualification result remain absent.

d5 now consumes separate Provider, Gateway, process-supervisor, and resource-
inspector snapshots under the existing execution deadline. It requires exact
observer artifact/configuration identity, completed-progress interaction order,
91 ordered profile fact bindings split 66/17/7/1 by source, four initial plus
four reconstructed process identities, a sanitized transcript, a digest-only
shell challenge, and the locked resource query scope. It derives the four
scenario states and conservative admission/resource counters without treating
caller progress as independent truth. Focused race tests cover success,
missing/contradicted evidence, outcome mismatch, not-executed propagation,
identity/order/scope/process/transcript failures, one-shot behavior, and
potential unexpected admissions. This remains repository-local component
evidence; real independent observer provenance and actual external execution
remain absent.

d6 consumes that conservative obligation after idle, unknown-start, canceled,
or descriptor-closed execution state. It detaches from execution cancellation,
clips cleanup to both the 300-second budget and original total deadline, closes
local state descriptors, and sends only six sanitized identity fields to the
operator-owned teardown port. A bound receipt permits 1..32 internal attempts;
success additionally requires exactly three unchanged-scope inspector samples
at least one second apart, stable and equal to the zero-resource baseline.
Residual/drifting resources, teardown non-completion, unavailable evidence,
identity drift, and exhausted budgets remain `incomplete`, `failed`, or
`unknown`. Focused race tests use repository fakes, so no actual operator
teardown or independent inspector result is claimed. d7 now adds typed one-shot
assembly, exact five-payload inventory binding, descriptor-pinned exclusive
`0600` publication, assembly-writer closure, and validator-only receipt
publication. Its synthetic seven-file test is local component evidence only.
The public separate e1 candidate has completed 13/13 checkpoints through e1.8c:
all 15 locked initial and all 5 reconstruction cases are locally composed from durable
`initial_complete` state without private correlation reinjection. Retained
handoff validation and a bounded reconstructed-Gateway byte connection are
included. Candidate-owned process cleanup, sanitized failure mapping and output
ordering/limits are locally closed. Public hosted run `35068957048`
builds source commit `58a211f0c167af3ec117c8cb8247bfe268bbae40`
from its content-addressed source archive, reproduces byte-identical Linux/amd64
artifacts, verifies the pinned authority, and publishes strict manifest digest
`sha256:468b0f7bfd7e835ba5464033994739c28cec3b9985fbd24fb3ae375b8e7fb33b`.
The downloaded bundle and all five subjects in Sigstore attestation `47846951`
verify. Final hosted run `35203241121` separately closes the supervised 15+5
execution, exact observations, operator cleanup, report, receipt, archive and
bounded disposition for the named revisions. It does not establish any of the
recorded aggregate, reliability, tenant, deployment or production non-claims.
Any protected or mutating remote Suite profile must first define
cleanup authority, prerequisites, case-specific evidence, and incomplete-run
semantics; the six-case discovery profile must not be stretched to cover it.
The same-repository reference and P2.6 profiles are not that external
qualification. Multi-issuer design, lifecycle-closure gaps, aggregate
conformance, multi-controller, multi-tenant, HA, deployment, and production
gates remain separate work before broad interoperability is claimed.

P4 Browser authority is complete in Contract `5096e71` and projection
`24b2e36`. ADR 0019 and publication run `33724368530` establish the exact
sandboxed, signed amd64/arm64/v8 image at
`sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`.
ADRs 0020 through 0024 and their named commits establish the Provider-local
session/application/reference/usage, Docker/private-relay, real provenance,
restricted-egress/create-policy, protected-transport, and caller-owned Gateway
components. ADR 0025 and `66183b1` compose those dependencies in an explicit,
default-disabled Browser command graph.

ADR 0026 and historical harness/Provider lock `79fee2b`/`f760369` establish the
separate Browser reference caller. Hosted Browser Reference E2E run
`33838215924` passed all 10 initial and 5 process-reconstruction scenarios on
`linux/amd64`; artifact `browser-reference-e2e-evidence-33838215924` has digest
`sha256:4acfbc97c0c1f64e987b00870849a2244e33596918d08e659385c428310843ea`.
Repository CI `33838215949` passed all four named jobs. This remains historical
evidence for its lock and contains no active capacity-rejection scenario.

ADR 0027 and implementation `7b062e6` add explicit process-local total and
per-session Browser Gateway connection capacity. Capacity harness `28a9a5e`
actively exercises that boundary. Hosted Browser Reference E2E run
`33846603547` passed all 11 initial and 5 process-reconstruction scenarios on
`linux/amd64`; artifact `browser-reference-e2e-evidence-33846603547` has digest
`sha256:b024225aa3545fa56a7cc5113f29c0817a86ebc70c3976e10d81bf3507546cba`.
The inspected manifest pins Provider `7b062e6`, the Contract/tree, 48-case
Suite, signed Browser image, verifier and configuration digests, reports, and
evidence boundary. Its reports contain only passing scenarios. The added caller
scenario proves same-session contention does not disrupt the admitted CDP
connection and that the slot is reusable after release; the 20-record Gateway
audit contains exactly one metadata-only `capacity_rejected` event. Repository
CI `33846603580` passed all four named jobs. Hosted Reference and Candidate
coding/shell regressions `33846603323`/`33846603454` passed their separate 15+5
scenario sets against the same lock and do not add Browser or real-platform
evidence.

ADR 0028 and implementation `44ea2ee` add a required process-local global
connection and fixed-window request limiter before Browser WebSocket admission
and upgrade. Harness `249cdd4` first exercises that boundary locally. Clean
local Browser run `20260904T080946.250607000Z` passed all 12 initial and 5
process-reconstruction scenarios on `linux/arm64`. The added caller scenario
observes ordinary wrong-Origin `403`, generic pre-upgrade `429` with bounded
`Retry-After`, and recovery, while the structured 20-record Gateway audit
contains no `grant-browser-edge-*` identity. Clean local Reference and Candidate
runs `20260904T081521.464863000Z` and `20260904T081706.648122000Z` pass their
separate 15+5 coding/shell regressions against the same lock. Repository CI
`33854020951` then passed all four jobs. Hosted Reference `33854020874`,
Candidate `33854020947`, and Browser `33854020809` passed their separately
named 15+5, 15+5, and 12+5 scenario sets against harness `e7e7f03` and Provider
`44ea2ee`; artifact digests are recorded above.

At that ADR 0029 evidence baseline, the local restricted-egress tagged rerun
built Gateway image
`sha256:7dd335db916005fb84154fb17b4a7e293df2e4a1e742d9492104472159f8ff60`
but timed out after 120 seconds in external GitHub provenance verification
before reaching a network scenario. It was recorded as unavailable external
provenance, not as a local pass or code failure. Hosted run
`33857739150` provides the complete Browser reference path, process-local
post-authorization capacity, pre-upgrade service-edge evidence, and bounded
listener/TLS/HTTP evidence. At that baseline, durable distributed revocation,
downstream fencing,
Valkey provenance, HA/failover consistency, production storage/configuration
and metrics, production Browser advertisement and deployable caller-owned
Gateway, independently implemented external-caller interoperability, aggregate
conformance, multi-controller reliability, hostile multi-tenant security,
deployment, and production
readiness remained independent open gates; later named evidence is recorded
above.

ADR 0030 and implementation `997fb0d` now establish only the
authenticated-capacity port and process-local memory reference. E2E lock
`49d1c20` pins the co-located Reference, Candidate, and Browser checks to that
Provider revision; their lock/regression checks pass locally. Hosted CI
`33940332882`, Reference `33940332897`, Candidate `33940332881`, and Browser
`33940332911` all pass against harness `6b01b75` and Provider `997fb0d`.
Reference and Candidate pass their separately named 15+5 coding/shell sets;
Browser passes 13+5 and its authenticated-memory contention path.

ADR 0031 and `9434540` then add the Redis-compatible shared-capacity adapter.
Clean local run `20260905T061037.558537000Z` passes all 10 independently named
`Browser Gateway shared-capacity black-box evidence` scenarios on `linux/arm64`
through two independent Gateway OS processes and one pinned Valkey authority,
against Provider baseline `2ed5e68` and harness/Gateway source `ddbb2c4`. The
Contract revision/tree and 48-case Suite are metadata only and were not
exercised. The private echo fixture also does not exercise Provider API, real
Browser/CDP, image provenance, restricted egress, artifact, or usage paths.
Hosted run `33949577876` independently passes the same 10 scenarios on
`linux/amd64` against harness/Gateway source `de297e7` and the same Provider
baseline. Its artifact digest is
`sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`.
This closes the separately named local arm64 and hosted amd64 shared-capacity
gates only.

ADR 0032 and implementation `c0a55d1` then close the caller-owned exact-grant
level-triggered revocation port and real Redis-compatible retained-tombstone
adapter component slice. E2E lock `59e08d5` pins that Provider revision and the
pre-ADR0033 local Browser 13+5, Reference/Candidate 15+5, and shared-capacity 10/10
regressions pass. Hosted CI `33955437033` also passes at repository revision
`c7fe24d`. Four pre-ADR0033 regressions pass with harness `c7fe24d` locked to
Provider `c0a55d1`: Reference `33955436969`, Candidate `33955437046`, Browser
`33955436984`, and shared capacity `33955436968`.
Those existing modes do not exercise two Gateways with an independent revoker
against the retained backend. Harness/Gateway `e952ef9` supplies that separate
runner: local run `20260905T095109.569973000Z` and hosted run `33959122456`
pass all seven scenarios on arm64 and amd64. The hosted artifact digest is
`sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`.
This closes only ADR 0032's durable exact-grant caller gate. ADR 0033
implementation `b4d41c9` subsequently passes targeted/full race-shuffle, vet,
Contract verification, the unchanged locked 48-case Suite, and tagged
integration against pinned Valkey index
`sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`.
This closes its component plus real-backend adapter integration gate.
Implementation `58488d7` adds the next process/component slice: two independent
downstream caller OS processes each use a distinct mTLS/JWS Controller identity,
perform their own Provider Browser bootstrap, bind the returned handoff only in
private state, and stay alive in the JSONL control loop. Implementation
`8a1049b` and historical provisioning lock `fb1b2b0` add strict
bounded EOF-framed FD 3/4/5 provisioning, exact final-config correlation,
failure kill plus bounded wait and natural-exit cleanup, a parent process manager, and the full
Contract handoff grammar in `gatewaystack`. FD5 proves at-most-once delivery,
not child acceptance; readiness requires a correlated JSONL response. FIFO
validation does not prove an anonymous pipe, so the `os.Pipe` launcher is
trusted. Contract Browser-session termination is absent, so a failed handshake
does not prove Provider resource cleanup. These remain process/component
constraints. Runner implementation `a2b82b0` and corrections through harness
`550c785` compose the full local topology. Run
`20260906T050213.016063000Z` passes all 13 scenarios on `linux/arm64`. The
manifest pins Provider `58488d7`, harness baseline `8a1049b`, component
`b4d41c9`, caller substrate `074a9d4`, signed Browser and Valkey identities, and
the Contract/tree/48-case identity. It exercises six Provider routes but not the
Suite (`suite_exercised=false`). Its exact five-file `0600` evidence set passes
all cleanup and sanitization checks.

Hosted checkout/harness `2cadc53` independently passes repository CI
`34013982778` and Reference, Candidate, Browser, shared-capacity,
durable-revocation, and downstream-fencing runs `34013982794`, `34013982784`,
`34013982785`, `34013982786`, `34013982798`, and `34013982796`. The last run
passes the same 13 ADR 0033 scenarios on `linux/amd64`. Downloaded artifact
`browser-downstream-fencing-e2e-evidence-34013982796` contains evidence
directory `20260906T052710.781616339Z` with exactly five sanitized files and
pins the expected identities, topology, cleanup, and sanitization state. The
GitHub artifact has digest
`sha256:9c00f3ba184e82d7eff661b831c05c1bdf331fa41caf2d8bbb3353168ab155b0`.
These CI and six E2E tracks remain separate evidence; the downstream runner
does not execute the Contract Suite.

Local ADR 0034 harness/run `059357c`/`20260906T100233.295973000Z` passes all 18
v2 scenarios on `linux/arm64`. It uses two independent callers, two Gateways,
one authenticated unique ingress, retained Valkey, an independently retained
file witness, and signed real Chromium. Retained-field deletion, complete-state
deletion, and restored-old snapshot cases reject before a new upstream dial;
ingress/witness reconstruction, exact Redis-ahead-one recovery, and other
checkpoint mismatch rejection also pass. The exact five-file `0600` evidence
set passes cleanup and sanitization. Contract/tree/48-case identity is pinned,
but the Suite is not executed (`suite_exercised=false`). This closes only the
local ADR 0034 external-caller gate.

Hosted checkout/run `059357c`/`34026680591` passes the same 18 v2 scenarios
on `linux/amd64`. Downloaded artifact
`browser-downstream-fencing-v2-e2e-evidence-34026680591` contains evidence
directory `20260906T101111.796974798Z` with exactly five sanitized files. Its
manifest records five ingress reconstructions, all cleanup and sanitization
booleans true, no top-level v1 `adapters` field, and
`suite_exercised=false`; the report records 18/18 with no failures. The GitHub
artifact ID is `9987350368`; its digest is
`sha256:3e68f1c4b5bd74e0ae0ff0fde2c9ffefc63852cf9fc82b3019bedfb228bf2c9a`.
This closes only the hosted ADR 0034 external-caller gate.

Checkout `059357c` also passes repository CI `34026680576`, Reference
`34026680567`, Platform Candidate `34026680617`, Browser Reference
`34026680597`, shared capacity `34026680568`, durable revocation `34026680592`,
and downstream-fencing v1 `34026680577`. These eight workflows and seven E2E
profiles remain distinct evidence tracks.

Merge commit `a0cddf4` and its workflow set remain historical evidence. The
newer canonical PostgreSQL controlled-restore run is `34069851741` at main
revision `838d3bb2dea52c10fdc1ddf3136641709fedcb20`. It passes all 18 scenarios
on `linux/amd64`. Downloaded artifact
`browser-postgres-controlled-restore-e2e-evidence-34069851741` contains evidence
directory `20260907T002737.609312407Z` with exactly five sanitized files. Its
report records 18/18; its manifest pins that exact harness commit, three ingress
reconstructions, all cleanup and sanitization booleans true, PostgreSQL restore
evidence, `same_runner=true`, `independent_failure_domain=false`, and
`suite_exercised=false`. Artifact ID `10000177842` has digest
`sha256:96817b74f3faabb0226d7dee1f2ac8128901865a3834f9bcadcaae6459b76032`.
This closes only the hosted ADR 0036 same-runner operational reference gate.

Earlier hosted run `34025787520` at `ef63be4` exposed a verifier false negative:
the restore-control helper compared raw Redis/Valkey `DUMP` bytes after
`RESTORE`, not logical restored state. `059357c` compares the restored key type,
logical string/hash/zset content, missing-key state, and TTL semantics while
retaining real `DUMP`/`RESTORE` injection. It adds regression tests for hash
iteration order, equal-cardinality field replacement, and string/zset changes.

Valkey provenance and HA/failover, a production witness and restore procedure,
production storage/configuration, ACLs and metrics, hostile-tenant and
operational evidence, production Browser advertisement and deployable
unique-ingress/public Gateway, independently implemented external-caller
interoperability, aggregate, multi-controller, multi-tenant, deployment, and
production gates remain separate.

P1.1d is explicitly closed by the local Suite/security matrix, PR #19 CI, and
post-merge run `32365284283`. P1.2.0 is closed by PR #21, its three successful
PR checks, and post-merge run `32368734877`. P1.2.1 is closed by PR #22, its
three successful PR checks, and post-merge run `32370133083`. P1.2.2 is closed
as provider-local persistence only; the file adapter is single-controller
development evidence. P1.2.3 is closed as internal create dispatch and restart
reconciliation. P1.2.4 is closed as a projection/component slice; post-merge
CI run `32435540542` passed all required jobs. PR #26 merged the behavior-bound
Conformance mappings as `4ccb107`; post-merge run `32436541588` passed. PR #27
then composed the independent Provider lifecycle application and merged as
`28076a7`; post-merge run `32439289227` passed. It projects only `POST /v1/sandboxes`, `GET
/v1/sandboxes/{sandbox_id}`, and `GET /v1/operations/{operation_id}` after
protected admission. The command composition root now constructs an independent
Provider lifecycle application when explicitly enabled; disabled and
production-fake configurations remain fail-closed. Reserved
routes remain absent, and aggregate conformance, external-caller E2E,
multi-controller reliability, tenancy, deployment, and production claims
remain unproven. The P1.2.5 local Conformance mappings now exercise
coordinator idempotency, stale generation, concurrent reconciliation, deadlines,
cancellation, unknown outcomes, restart inspection, and locked DTO projection.
Terminate/lease/orphan cleanup are not authorized by the current Contract
revision. P1.2.5 is closed only for the current authorized subset. Terminate,
lease mutation, orphan cleanup, sessions, snapshots, runtime exec behavior,
and aggregate caller compatibility remain unproven or Contract-reserved. PR
#30 closed the bounded exec Contract gate only. P2.1 locally validates an
uncomposed Provider-local execution port with bounded input and opaque receipt
validation. PR #31 and post-merge CI close that local component slice. P2.2a
adds only result/intent domain validation; PR #33 and post-merge CI close that
domain slice. Neither slice exposes an exec route, durably accepts an operation,
retains a result, records cancellation intent in storage, reconciles an
outcome, selects a Docker/backend adapter, or proves runtime execution
behavior.

P2.2b is closed by PR #35 merge `c467cd4`, PR CI `32456100570`, and
post-merge CI `32456279722`. The next entry is P2.2c: define durable
pre-dispatch reservation/attach ordering, bounded coordination, pending
cancellation recovery/query boundaries, and an optional Canceler port. Do not
expose Provider HTTP, Docker/backend selection, or claim aggregate/runtime
execution compatibility from P2.2b.

P2.2c local implementation now provides durable reservation before executor
dispatch, exact opaque receipt attachment, bounded coordinator ordering, and
optional cancellation confirmation. Known non-context executor errors remain a
durable pending reservation rather than an inferred terminal failure; context
or receipt uncertainty is not redispatched on recovery. Cancellation intent
replay does not repeat external side effects, and current recovery exposes
query-only intent state rather than automatic Canceler retry. HTTP, Docker,
lifecycle-repository reuse, aggregate conformance, external E2E,
multi-controller, tenancy, deployment, and production claims remain unproven.

P2.2c is closed by PR #39 merge `17072e6`, PR CI `32460695928`, and post-merge
CI `32460914417`. PR #43 merged P2.3a/b as `21f5236`; PR CI `32468912019` and
post-merge CI `32469390678` passed. P2.3c0 correction `71fee34` makes the
terminal capability version `1.0.0`, aligns its capability profile with the
canonical `terminal-v1` session fixtures, and adds the 26th Suite case.
`ab9defc` binds revision `71fee34380affcb46e1e1dce667475aa241048a4` and tree
`4fafb742e40231cbf9fb957f5998bdce932fdb0d`, enforces terminal semver without
tightening the generic v1 Capability Schema, and verifies cross-resource
consistency. Full local race/shuffle, vet, lock verification, the 26-case Suite,
JSON parsing, and diff checks passed. Exact-head PR CI `32685685846` passed all
three jobs for head `16136d2`; PR #44 merged as `6c1fc90`, and post-merge CI
`32686754674` passed all three jobs. P2.3c0 is closed as Contract, capability
snapshot, DTO, handler projection, and local Suite evidence only. P2.3c1 now
locally defines a terminal-only request, accepted/running/terminal record state,
successful-only opaque WebSocket handoff derivation, and a transactional
authority port. PR #45 merged it as `4c37d8c`; PR CI `32696507856` and
post-merge CI `32696727371` passed all three jobs. P2.3c2 adds independent
provider/session memory and file persistence, idempotency replay, expiry
handling, compare-and-set generation/fencing, and same-transaction authority
rechecks. Direct main commit `e5c9dec` and post-push CI #103 / run
`32698606341` passed all three jobs. P2.3c3 now adds an independently
injectable session application boundary to the protected transport. POST
`/v1/sandboxes/{sandbox_id}/runtime-sessions` strictly decodes and projects an
accepted terminal operation after admission; GET
`/v1/operations/{operation_id}/runtime-session` projects only a successful,
unexpired opaque handoff. Pending, expired, failed, cancelled, and
`outcome_unknown` records map to stable errors; raw endpoints, addresses,
credentials, and provider tokens are rejected or omitted. The command
composition root still does not create an allocator, runtime driver, or
Provider WebSocket data plane. P2.3c3 is closed for bounded Provider transport
evidence by implementation commit `186190b` and post-push CI `32799871307`.
P2.3c4 then adds an independently composed Gateway boundary: caller/tenant/
session authorization binding, opaque reference resolution on every connect/
reconnect, bounded bidirectional frame proxying, revocation interruption,
expiry and generation fencing, and metadata-only recording. Commit `e675cb9`
and post-push CI `32801539995` close that slice as bounded component evidence.
A concrete WebSocket wire adapter, external caller E2E, distributed
revocation, multi-controller reliability, tenancy, deployment, and production
claims remain unproven. P2.4a0 then reconciled the artifact/usage protected-
admission vocabulary and lock in `3a9d8b7`, `7e00715`, and `2aba87f`; post-push
CI `32819717542` passed all three required jobs. P2.4a1 locked operation-family
aggregation and the evidence-read state matrices in `3846c9e`, `6f549c2`, and
`dbea0e8`; post-push CI `32823783136` passed all three required jobs and
executed the 35-case Suite. P2.4a2 then supplied the bounded application,
durable authority adapters, usage operation reader, and operation-family
aggregator in `152033f`, `0440272`, and `4d0bb70`; CI `32827387303` passed all
three required jobs. P2.4a3 now composes the three locked routes in commits
`f5111a5`, `ce3c6e0`, and `9a4bc71`, with the independent admission/error
correction in `c469337`: admission and descriptor binding complete before
application calls; stage returns only a `202` operation; artifact and usage
evidence projections enforce operation/sandbox/attempt/fencing correlation;
and the generic operation route uses composed family readers. Strict document
preflight rejects artifact-stage invalid documents before mutation guard
reservation; P2.5c commits `6c2962b` and `6340604` extend that ordering and
Suite mapping to create/session without adding dispatch.
Focused Provider tests and the local full race/shuffle, vet, lock, Suite, and
diff gates pass. Post-push CI `32838784395` passed all three jobs for
`1ca115b`. The command composition root injects
no synthetic artifact stager or usage collector; missing dependencies remain a
bounded `503` surface. Artifact publication, billing, aggregate conformance,
external-caller compatibility, multi-controller reliability, multi-tenant
safety, deployment, and production readiness are not claimed.

The first 2026-08-30 audit at documentation baseline `bba02a6` correctly found
no existing caller in the Provider repository or the separately inspected
Agent Platform candidate. That historical result is retained as the reason a
new independent harness was created; it is no longer the current P2.5i state.

`e2e/` is a separately runnable Go module and process boundary co-located in this
Provider repository. Its caller and command cannot import Provider
implementation packages; only its reference deployment process imports
exported Provider/Gateway composition. Full evidence runs reject a dirty or
unversioned harness and a Provider checkout with non-documentation changes after
the locked baseline. The root workflow is tracked in
`.github/workflows/reference-e2e.yml`; hosted run `33379217800` passed all 15
initial and 5 reconstruction/resume scenarios on commit `555436c`. Its uploaded
artifact digest is `sha256:68250a85683dcbd8f01397d7373e98215382379ff895c0a58692de23c1880733`.

The candidate integration run used implementation commit `47bd627` and clean
evidence harness commit `9e5f546`, with the same locked Provider/Contract
identities. `cmd/platform-e2e` launched a separate
`platform-caller` process, performed live capability and create-request shadow
checks, exercised candidate ProviderRevision selection plus canary rollback and
old-run drain policy, and persisted candidate state across Provider process
reconstruction. The ignored manifest is
`e2e/evidence/20260831T104115.065616000Z/manifest.json`; it records 15 initial
and 5 resume scenarios, runtime digest
`sha256:3932dd52da715306f5e4ce8c0719a9d4ca854110bb91d51be21a12582d1d9332`, and
the boundary `Agent Platform candidate integration only`. Docker resources were
cleaned after the run.

The final clean local run used:

| Input | Locked value |
| --- | --- |
| Caller harness | `e329150df3d33a21ba30c1f616a94246b4ff8804` |
| Provider implementation | `d58497e5359056858564b9ac663178958cf5a6d6` |
| Contract revision/tree | `22a148e2898477790512d5bb742605654ff00ebf` / `1a967c9c6ce9646c8431f6ee48699ec9f406a589` |
| Suite identity | repository-owned Provider v1, 38 cases |
| Evidence directory | `20260831T094209.963835000Z` under `e2e/evidence/` (ignored) |

All 15 initial and 5 reconstruction/resume scenarios passed. The initial run
covered exact capability discovery, protected create, replay, lifecycle,
exec/result/usage, stale fencing, cancellation, terminal handoff/Gateway data,
two-context denial, expiry, revocation, artifact evidence, cross-tenant staging
denial, and mTLS caller binding. The reconstructed stack retained lifecycle,
exec/usage/artifact evidence, opaque handoff, and the same terminal shell.

This is sufficient for the local and hosted reference P2.5i caller gate. The
hosted artifact is recorded above. It does not prove interoperability with an
independently implemented external caller, aggregate conformance, distributed
revocation, multi-controller reliability, hostile multi-tenant isolation,
deployment, or production readiness. ADR 0037 later retired the named P3
migration target without changing this historical evidence boundary.

The 2026-08-28 P2.5g review was based on implementation `0e6e108` from
`main@0e6e108`; its artifact/usage local and Docker gates pass, and repository
CI run `33157119149` passes all three jobs. The subsequent P2.5h implementation
`2c55173` is based on `main@0e6e108` and adds explicit canonical-profile opt-in,
dependency-absence validation, and readiness-derived immutable advertisement.
Full local Go, Contract/Suite, diff, and fixed-digest Docker gates pass without
changing Contract revision `22a148e2898477790512d5bb742605654ff00ebf` or its
38 cases. Repository CI run `33159099578` passes all three jobs for
documentation baseline `0ec712c`, and run `33160646494` passes all three jobs
for the reviewed documentation baseline `bba02a6`.
The Provider command root intentionally marks the concrete WebSocket and
caller-owned Gateway boundary unavailable, so explicit standalone profile
startup still fails closed. The reference stack supplies those caller-owned
dependencies externally for P2.5i without weakening the Provider default.


### 2026-10-10 held Docker consumer observation and dedicated backend

The [Control storage backend component](plan/product-v1-phase-6-control-storage-backend.md)
adds a separate bounded global Docker observer and a fresh dedicated Store
mode. It checks stopped consumers, exact volume/Control mounts, unsafe aliases
and device authority, live root-fd facts and fixed loop geometry. A Linux
operator-only helper prepares and seals a one-GiB ext4 image offline, with
source inode and initial-byte binding. This does not yet prove physical admission:
shared-VM loop/device operations await explicit scope authorization, complete
source-inode/volume composition and real positive/failure gates. Current real
Docker evidence covers ordinary-volume and stopped-consumer refusal only.
The new offline image is not an attached quota backend, a release image or an
old receipt upgrade. Public Profile/provider v3 holds and Phase 6 **5/15** remain.


### 2026-10-11 authorized real backend diagnostic; admission remains blocked

The user authorized the exact shared-VM loop7 diagnostic. Fresh census, original
image hash/dev/inode checks and atomic attach passed. High-UID raw ext4 writes
survived two container replacements; physical ENOSPC and ELF noexec refusal
passed. The mounted-device O_EXCL test returned EBUSY, and the helper refused
detach while preserving the exact backing inode. These are separate component
facts, not Store quota or full Control acceptance.

The positive Store admission test **failed**: actual mountinfo carried
`master:5`, and sysfs exposed `/receipt.ext4` instead of the required absolute
backing path. No Store namespace was initialized; both strict checks remain.
The next step is independent review of a source-inode/volume observation
composition and an actually private mount, then fresh Store positive gates.
The high-UID Store and root-owned Docker socket are not yet one composed
observer authority. Details and evidence boundaries are in the
[Control storage backend plan](plan/product-v1-phase-6-control-storage-backend.md).

Slice 6 step **1** retains only its historical bounded evidence; step **2**
continues with these real diagnostic results and explicit admission blockers;
step **3** full live inventory/original sixteen scenarios/independent acceptance
is incomplete; step **4** has not begun. Phase 6 remains **5/15** and public
Profile/provider v3 stay closed. No commit, push or release is authorized here.

Validation for this checkpoint: mise Go1.26.8 full Darwin race/shuffle/count=1
suite passed in **440.344 seconds**, `go vet ./...` in **7.430 seconds**, and
Provider/Product Contract verification in **0.496 / 0.130 seconds**. The two new
Linux integration test binaries executed in restricted arm64 Docker; their
Linux integration-tag vet passed in **0.917 seconds**. Production Go files and
locks were unchanged in this turn. The positive Store test remains a recorded
FAIL; raw and mounted-refusal PASS results do not convert it to acceptance.

Exact cleanup completed: owned consumers and ext4 volume removed, helper
observed ENXIO after detach, all eight granted loop nodes were unconfigured,
offline fsck passed, then the backing volume was removed. No run-owned
containers or volumes remained; both new diagnostic image tags were removed.
Retained pre-removal and fresh post-removal inventories also show no mount
source overlapping either owned volume path or its ancestors/children. This
relies on the coordinated sole operator and does not fence daemon-external
writers. The unrelated existing containers and prior diagnostic utility image
were preserved. Private commands/results, image/binary identities, both the
executed and reviewed-follow-up cleanup scripts, and exact source delta are in
`coding-persistent-backend-live-20261011` outside Git and the migration package.


### 2026-10-11 source observer and private-mount follow-up

A fresh independently reviewed diagnostic used local-driver
`o=rw,nosuid,nodev,noexec,private`. The actual mount no longer contained
`master`, and the unchanged strict kernel-root check passed. This corrects
the earlier review's conflation of container bind propagation with the local
driver's underlying mount options. The held Docker observer now requires
this exact option set and still checks the live Store fd separately.

The helper's new `observe` action uses a read-only backing mount and only
read-only pinned file/loop descriptors, canonical seal and before/after
statx/census/ioctl checks. Actual observation passed, including with an active
filesystem consumer; wrong mount access, absent device and wrong namespace
were refused without output. It emits diagnostic identity fields, not a
Store capability or signed receipt. The positive Store test still fails on
its unchanged exact backing-path check; the private-mount blocker alone is
closed for this observed configuration. See the [backend plan](plan/product-v1-phase-6-control-storage-backend.md).

Next: independently select the live source-capability/Store-root/Docker-volume
composition. Do not turn serialized helper JSON into caller authority. ADR
0055's existing high-UID Control plus fixed supplementary GID 0 candidate
remains the separate Docker-socket direction, with access/denial gates pending.
Phase 6 stays **5/15**; Slice 6 steps **1/2/3/4** remain historical bounded
evidence / in progress / incomplete / not begun. Public Profile/provider v3
admission stays closed, and no commit, push or release occurs.


### 2026-10-11 live source/Store/Docker composition checkpoint

The independently reviewed held component now admits one actual high-UID
Control only after composing retained source FDs/inode and original seal,
strict private whole-ext4 Store root, exact Docker volumes and complete current
consumer inventories. The new source-provision.v2 mode has no legacy receipt
upgrade; its root-owned group-readable source, exact RO loop nodes and fixed
socket group are restricted to that candidate. Both original sysfs-path and
Desktop representation failures remain recorded. See the
[reviewed design](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-live-source-store-and-docker-composition)
for the capability and timeout boundaries.

The final fresh Linux/arm64 fixture passes initialization, persisted state/CAS,
64-object allocation quota refusal, replacement-Control reopening, stopped
receipt/backing/socket consumer refusal, cooperative helper exclusion and
same-byte source seal inode-replacement refusal. Its exact containers, volumes
and new image were removed; loop7 ENXIO and offline fsck passed. Logs, binaries,
source hashes and failed attempts are outside Git in
`control-storage-composition-20261011`, with the final run in `v4-budget-final`.
Development stayed in mise Go1.26.8 and Docker. The worktree remains uncommitted.

Next complete the held Store's physical ENOSPC/uncertain-write/recovery and
wrong-principal denial gates, then integrate the composed lifetime with the
source-derived Coding ledger and complete Profile/operator command admission.
A private fixture with synthetic Profile/principal digests is not that full
admission. The complete four-volume Coding scenarios and original sixteen-
scenario/topology acceptance remain open. Slice 6: **1** historical bounded
Guest E; **2** ongoing, this component passes; **3** incomplete; **4** not begun.
Phase 6 remains **5/15** and both public holds remain closed.


### 2026-10-11 Store fault and wrong-principal checkpoint

The [held Store fault gates](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-store-fault-and-principal-gate-design)
now have independent review and ten fresh Linux/arm64 real fixtures: actual
pending-object Write ENOSPC, no-effect space preflight, two cancellation points,
five process-exit points, and wrong UID/GID/missing-socket-group denial. Incomplete
state remains preserved and refuses reopen/reinitialization; complete canonical
state may be revalidated in a new process, without a success receipt or dispatch
permit. Socket denial is actual connect EACCES, not a permission-mode inference.
This does not prove power-loss durability. All exact fixture resources and the
new diagnostic image were reclaimed; private evidence lives outside Git in
`control-storage-fault-gates-20261011`. mise Go1.26.8/Docker remain the only
selected development toolchain/runtime; source remains uncommitted.

Next bind the composed Store lifetime to the source-derived Coding ledger and
full Profile/operator command path, then run the four-volume physical scenarios
and the still-open Slice6 security/topology gates. Step **1** retains historical
bounded E; **2** continues with these Store gates passing; **3** complete live
topology/original16 and independent acceptance remain incomplete; **4** has not
begun. Phase6 remains **5/15**, with both public admission holds closed.

The same final Go snapshot passes full race/shuffle/count=1 in 524.358 seconds,
full vet in 8.867 seconds, Linux tagged vet and all ten real fixtures.


### 2026-10-11 source-owned Coding ledger checkpoint

The ledger now owns the composed source/Store/Docker lifetime through a private
marked port. Ordinary-directory constructors compile only in tests; the held
constructor checks the storage/template/daemon/endpoint/platform join before
I/O. Failed loading retains markers, while missing state never triggers repair.
Cancellation while draining callbacks keeps the owner locked and closed to new
work until a later Close completes.

Six fresh Linux/arm64 fixtures pass durable Unknown before an effect probe,
replacement-process refusal of replay/Completed/exec, canceled Close and lock
retention until drain, before/after-state interruption without dispatch, missing
state refusal without reset, and a stopped second consumer causing an absorbing
source-owner failure. Removing that peer does not revive the old owner; a new
owner reopens the unchanged empty ledger. All six namespaces, loop mappings and
the new diagnostic image were reclaimed exactly. The raw evidence and one
preserved outer snapshot-comparison failure are outside Git in
`control-storage-ledger-20261011`. The failure compared the replacement container's
parent-directory mtime; independent review restricted comparison to the Store
root/entries, with all original files retained and no scenario rerun.

This is a held source-storage/ledger component using explicit fixture Profile,
principal and policy digests plus bounded callbacks. Full source-derived
Profile/operator and four-volume effects remain unproved. Independent review
found the current complete Profile cannot represent the diagnostic candidate's
RO backing, exact eight RO loop devices and different socket target, and its
required service networks/mounts differ. Next introduce and independently review
an exact source-access mode and operator binding without widening generic
HostDevices/mount rules; then wire the complete command and PG/mTLS paths.
See the [backend design](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-source-owned-execution-ledger-lifetime).

Slice6 remains **1** historical bounded E, **2** in progress with this component
passing, **3** full live topology/original16 and independent acceptance incomplete,
**4** not begun. Phase6 stays **5/15**; public Profile/provider v3 holds, two issuers,
frozen-R reuse and old locks stay unchanged. Development uses mise Go1.26.8 and
Docker; no staging, commit, push or release occurred.


Final validation for the unchanged Go snapshot passed: full
`go test -race -shuffle=on -count=1 ./...` in **474.875 seconds**, full
`go vet ./...` in **18.48 seconds**, the focused ledger/source-owner race tests
in 15.317 seconds, and final Linux tagged vet in 0.516 seconds. Six real fixtures
and independent evidence/documentation review passed within the stated scope.
The existing 600-second full-suite runner limit was not changed. No Go byte
changed after the real-fixture snapshot; subsequent edits only record results.
Contract inputs, Go module/toolchain locks and AGENTS remain unchanged.


## 2026-10-11 complete-Profile source-access permission checkpoint

An independently reviewed optional source-access v1 mode now represents the
exact source-v2 backing, eight RO loop devices, canonical Docker socket, owner
UID/GID/groups and new Control image identity inside the complete declared
Profile v2. A pre-seal source-intent digest breaks the backing-label/Profile/seal
cycle; the final Profile then binds the original seal. Read-only operator review
checks either canonical stage and never grants runtime admission. Legacy wire
encoding and the public Profile/provider v3 holds remain unchanged.

The real Docker fixture passes source Store initialization, replacement reopen,
a create-only positive baseline, eight stopped permission/configuration
refusals and a stopped unauthorized private-config consumer refusal followed by
successful reopen. Exact loop/volume/container/network/image cleanup passes.
The actual observer checks seven mounts and three internal isolated networks,
but this is **Control-only staging**: other role supply identities are synthetic,
and live Provider/TLS peers, CA/CRL content, service readiness and release supply
are not proved. Two failed preparation attempts remain preserved outside Git;
neither is counted as acceptance. Evidence: `control-profile-source-access-20261011`.

Next establish separately reviewed operator admission and exact legitimate
Provider/TLS/CA consumer identities, then connect the source-owned ledger and
complete Control/PG/mTLS command path and four-volume effects. See the
[permission-mode design and evidence boundary](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-complete-profile-source-access-declaration).

Slice6: **1** historical bounded E accepted in its original scope; **2** ongoing,
with this permission component passing; **3** full live topology/original16 and
independent formal acceptance incomplete; **4** not begun. Phase6 remains5/15.
Development remains mise Go1.26.8 and Docker. No commit, push or release.


Final checkpoint validation passed on the unchanged Go snapshot: full
`go test -race -shuffle=on -count=1 ./...` in **340.282 seconds**, full
`go vet ./...` in **8.66 seconds**, both Contract lock verifiers and Linux tagged
vet. Independent design/code/raw-evidence/documentation review accepted the
stated held Control-only component scope. All 237 commands in the final physical
fixture completed successfully; the two earlier failed attempts remain retained
and excluded. No Go source changed after the final real-fixture image build.
The original 600-second suite limit, public admission holds and Phase6 5/15
status remain unchanged. This completes this permission component checkpoint,
not Slice6 formal acceptance or its step4 handoff.


## 2026-10-11 operator and consumer observation checkpoint

Independent design/code review added a held operator-signature and consumer
observation component. Admission re-derives the complete canonical Profile,
then binds a fresh single-use challenge to actual source/root, original seal,
Docker volume and consumer graph observations before Store initialization.
Signatures use a separate test-key commitment, expire within120seconds and do
not create production authority. Every subsequent Store operation rechecks the
approved graph. The old Control-only staging branch remains unchanged.

Real Docker checks passed for the Profile-derived19 diagnostic containers and
three isolated Control/Provider networks: initialize/reopen, signature/review
forgery and graph-drift refusals, stopped/missing consumers, extra endpoint, and
same-name/label wrong UID/image/command/group/config/CA mount permission/source
refusals. Legitimate replacement required a fresh signature. These are fixed
sleep-process permission/session observations, **not real Provider/TLS identity
or readiness**. No CA/CRL bytes or production operator credential are accepted
by this evidence. The test pipe is not an added private-config file. One private
harness preparation failure remains preserved and excluded from acceptance.

Evidence: `control-operator-consumers-20261011`; see the
[operator/consumer component boundary](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-operator-and-consumer-observation-component).
Next establish the production bootstrap and real role launch/service identity,
then the source-owned Control/PG/mTLS command path and four-volume effects.
Slice6: **1** historical bounded E; **2** ongoing; **3** final live topology,
original16 and independent formal acceptance incomplete; **4** not started.
Phase6 remains **5/15**. Development uses mise Go1.26.8 and Docker, with no
commit, push, merge or release. Public admission holds remain closed.


Final validation on the unchanged Go snapshot passed: full
`go test -race -shuffle=on -count=1 ./...` in **260.098 seconds**, full
`go vet ./...` in **3.184 seconds**, both Contract lock verifiers and Linux
tagged vet. Independent review matched all2091Go files to the frozen snapshot
and accepted only the stated held diagnostic scope. Exact cleanup removed all
19 remaining diagnostic containers, six volumes, three networks and the new
image tag; all eight loop nodes were unconfigured and offline fsck passed.
The original600-second suite limit was unchanged. No Go byte changed after the
real fixture binary build. This is a Slice6 step2 component checkpoint, not
formal acceptance or step4 handoff.


## 2026-10-12 held bootstrap and actual process evidence

The [bootstrap/process checkpoint](plan/product-v1-phase-6-control-operator-bootstrap.md) adds a canonical
operator public-key declaration, independent empty-by-default executable pin,
fixed sealed Control FD3 and an explicitly held Control config protocol.
Eight launch declarations bind original OCI role/loader bytes. A trusted
operator probe distinguishes actual PID1 executable/credentials/argv from
container labels and distinguishes the loader from the role.

Real Linux checks passed for sealed-FD positive/negative cases, eight OCI byte
bindings, five direct-entry Control/TLS process-byte observations, two loader
observations and identity/environment/mount refusals. Direct-entry observations
are diagnostic overrides, not approved startup or service readiness. Three
actual Provider commands still reject v2 at the core v1 startup reader; actual
Control/TLS commands remain held. Production pin/probe delivery, operator
challenge transport, Store dispatch and full consumer readiness remain open.
The five private config volumes, all owned containers and three new diagnostic
image tags were reclaimed. Failed fixture attempts and the first600-second
full-race timeout remain evidence, never passes. See the private checkpoint
`control-production-bootstrap-20261012` for final validation and raw logs.

Next independently review the production delivery and post-observation
challenge/signature composition. Public holds, two issuers and frozen-R rules
are unchanged. Phase6 remains5/15; Slice6 steps1/2/3/4 are historical bounded E /
ongoing / incomplete / not started. Development remains mise Go1.26.8 and Docker;
no commit, push, merge or release.


Final checkpoint validation passed on the final Go combination: full
`go test -race -shuffle=on -count=1 -json ./...` in **582.294seconds**, full
`go vet ./...` in **6.491seconds**, both Contract lock verifiers and Linux
tagged vet. The first600.019-second timeout is retained as failed, not erased
by the later pass; no timeout limit was extended. Only the opt-in test fixture
generator changed after the real binary build (it rebinds the selected image
into its synthetic source intent); production Go inputs and real image bytes
were unchanged. The final whole-repository run includes that correction. This
is held Slice6 step2 component evidence, not production acceptance or step4.


## 2026-10-12 held process-delivery continuation

The [versioned pin/probe and post-observation signature component](plan/product-v1-phase-6-control-process-delivery.md)
adds an independent build-time public pin, the fixed image probe, real loader
and Control PID1 observation, sealed loader-generated binding, and a one-use
host-signature reply. The signature scope is only `held-control-process-delivery`;
it cannot open Store or authorize the earlier diagnostic consumer graph.
The host observes twice before signing; Control re-observes after signing.
The selected Unix Docker endpoint remains an operator-controlled trust premise.

Final source and original OCI inputs, actual positive/negative transcripts,
required verification and exact cleanup are indexed in private checkpoint
`control-production-delivery-20261012`; older failed attempts remain retained.
These are dirty-source diagnostic images with a test key, not clean release
or independent production operator acceptance. The next result is separately
reviewed source/root/volume/full-consumer and actual service composition.

Phase6 remains **5/15**. Slice6 **1** historical bounded E / **2** ongoing /
**3** final topology, original16 and independent formal review incomplete /
**4** not started. Public holds, issuer policy, old release/toolchain locks and
frozen-R reuse rules remain unchanged. No Git submission or release occurred.


## 2026-10-12 held Control source-observation continuation

The [source-observation component](plan/product-v1-phase-6-control-source-observation.md) binds the same real Control process
and retained source/root FDs to backing/filesystem volumes, fixed socket,
eight read-only loop grants and three isolated Control networks. It introduces
an explicit v3 target/bootstrap/startup tuple, v5 config and the distinct
`held-control-source-observation` signature scope. Host probes compare actual
source evidence twice before signing; Control rechecks its retained session
behind the signature. No Store is initialized or opened.

The real CLI positive passed in35.622seconds; the tagged Docker integration with
race passed in33.869seconds. Seven actual refusal cases cover old startup,
wrong key/signature, replay, stopped second consumer, source record inode
replacement and deadline. Both physical drift cases carried a valid test
signature and failed at source re-observation. Fifteen host projection cases
plus wrong backing-volume options reject unsafe inputs. Empty-root assertions,
original seal preservation, exact loop7 detach/ENXIO and eight-device census
are separate private fixture evidence. These facts do not prove Store contents
or full consumer/service readiness. Logs and prior failed attempts are retained
in private checkpoint `control-source-process-composition-20261012`.

Independent review required fixed daemon logging/resource settings and exact
four-label checks in original OCI, selected image and container metadata; both
repairs are applied. Image labels do not attest clean source or provenance.
The new operator key is recorded as local development only, with no independent
production approval. The GET-only collector does not make the mounted Docker
socket a kernel-enforced read-only capability.

The next reviewable result is production operator/Store admission composed with
the actual Provider/TLS/CA consumer graph, retaining the public holds until its
named gate is met. Phase6 remains **5/15**: Slice6 step1 historical bounded Guest
E; step2 ongoing; step3 final live topology, original16 scenarios and formal
independent review incomplete; step4 documentation/submission/push handoff not
started. Existing two-issuer, PostgreSQL general, frozen-R, Go1.26.8/release-lock
rules remain unchanged. Development uses mise and Docker; no Git submission.

## 2026-10-12 held CA directory prerequisite

The [trust-v4 component](plan/product-v1-phase-6-control-trust-observation.md) addresses the reproduced named-volume-at-PEM mismatch. It binds the two exact read-only CA directories, retained file identities and bytes to the existing source/process signature. Public and old Store admission remain held. This advances Slice6 step2 only; actual Provider/TLS consumers, production operator authority, final live topology/original 16 scenarios and formal handoff remain open. Phase6 stays **5/15**.

Actual v4 positive, three signed physical drift refusals, bounded initial-input refusals, Linux reader execution and the same new binaries on legacy v3 are recorded in private `control-real-consumers-20261012`. Full race (462.510s), vet, both Contract locks and tagged Docker race passed. Exact cleanup passed after the first attempt safely refused an in-use network; the wrong-owner wrapper assertion failure is also retained. See the component document for evidence limits.


## 2026-10-12 held Provider / Control TLS peer

The [real-process peer component](plan/product-v1-phase-6-provider-tls-peer.md)
connects one fixed Coding control edge through separate Linux role/agent test
processes using production TLS, Unix signing, retained CA FDs and source-bound
CRL enforcement. The selected 20-case matrix covers a real TLS1.3/mTLS POST,
nine initial refusals and ten active-fault closures plus fresh-client refusals.
The closures take 1.142–3.462 seconds within the unchanged 10-second bound.
Original fixture failures are retained and excluded from negative passes.

This is integration-only dirty-source component evidence with diagnostic X.509
issuers, not actual production Provider/Control commands, Vault/controller
issuance, operator approval, Store or full-topology admission. Public holds,
the broker/general issuer rule, old receipts and frozen-R reuse remain intact.
Private inputs, logs and exact resource receipts are in
`provider-tls-peer-20261012`; see the component document for failure stages,
verification and next work. Phase6 stays **5/15**: Slice6 step1 historical
bounded E; step2 ongoing; step3 final live topology/original16/formal independent
acceptance incomplete; step4 not started. No staging, commit, push or release.


At the peer checkpoint, implementation and real component cases were recorded, but
whole-repository code acceptance was **blocked**: three full race/shuffle/count1
runs exited124 at the unchanged 600-second bound, including the process-local
GOMAXPROCS=4 scheduling experiment. The phase6security package passed separately
in492.302s; full vet, both Contract locks, Linux tagged vet/package execution
and exact resource cleanup passed. These do not substitute for the incomplete
full race gate. Resolve that bounded verification issue before broader command
composition or any acceptance claim; no timeout, assertion or public hold is
relaxed. Original failures and final source/evidence hashes are preserved in
private `provider-tls-peer-20261012`.


## 2026-10-12 bounded full-repository race follow-up

The [verification follow-up](plan/product-v1-phase-6-provider-tls-peer.md#repository-verification-status)
passes the complete race/shuffle/count1 suite with `-p=6` in **510.429 seconds**
under the unchanged 600-second bound (phase6security 475.785 seconds). All 267
packages have final outcomes. The Go/module source, tests and assertions are
unchanged; only package scheduling differed, with no `GOMAXPROCS` override.
The three prior timeouts remain failed evidence, not default-concurrency or CI
passes. Independent review accepts this local gate result within that scope.
Prior vet, Contract and Linux component results are reused on matching source;
no new Docker execution or production acceptance is claimed. Evidence is in
private `race-gate-diagnosis-20261012`, outside the migration package and Git.

This removes the missing local full-race result as the immediate blocker.
Phase6 remains **5/15**: Slice6 step1 retains bounded historical Guest E;
step2 continues with production operator/Store, actual Provider/Control/Scanner
commands and source-bound Vault/controller/agent composition; step3 final live
topology, original16 and independent formal acceptance remain incomplete;
step4 post-acceptance handoff is not started. Public holds and the two-issuer
rule remain unchanged. No staging, commit, push, merge or release occurred.


## 2026-10-13 Vault two-issuer continuation

The [reviewed component and evidence boundary](plan/product-v1-phase-6-vault-two-issuer.md) fixes a reproduced
duplicate-source/omitted-issuer acceptance in VaultClient and prepares an
opt-in real broker/general test for Control, Scanner, broker and PostgreSQL
client policies. PostgreSQL stays on general. The exact pinned Vault archive
has been restored and verified, but cryptographic image signature/provenance
is unverified; the required supply gates block starting the real service.
Neither ordinary skipped tests nor archive verification are real two-issuer
execution or Controller/agent/command acceptance. See the component document
and private `vault-controller-continuation-20261013` checkpoint for final
verification results, failed attempts and next evidence.

Phase6 remains **5/15**. Slice6 step1 retains historical bounded Guest E; step2
continues with supply resolution, actual issuer/source binding and the complete
operator/Store/Provider/Control/Scanner/Controller/agent composition. Step3
final live topology, original16 and independent formal acceptance remain open;
step4 post-acceptance handoff is not started. Public holds and frozen-R reuse
remain unchanged. No Git staging, commit, push, merge or release occurred.

Final bounded verification: workloadpki tagged race/shuffle/count1, full vet,
tagged vet and both Contract verifiers pass. The new whole-repository race
run timed out at 600.297 seconds (exit124), with phase6security unfinished; it
is not replaced by the historical 510.429-second result. The fresh exact-input
Trivy scan has 6 HIGH findings (4 unique CVEs), and image signature/provenance
remains unverified. No Vault service or real two-issuer scenario ran. Both the
full-race and supply blockers remain open; all original failure records are
preserved.


## 2026-10-13 race diagnosis and Vault supply proposal

The [reviewed diagnosis](plan/product-v1-phase-6-race-budget-diagnosis.md)
identified redundant desired-topology construction inside each nine-rule HBA
call. Fresh plans are now reused only within that call, preserving all original
validation, per-owner checks and output bytes. New characterization and
mutation-isolation tests passed before and after the change. The final full
`go test -race -shuffle=on -count=1 -p=6 -json ./...` passed in **503.355 seconds**
under the unchanged 600-second limit; all267 packages ended. Full vet and both
Contract lock verifiers passed. All2148 Go files match the pre-run snapshot.
This supplies the missing local full-race result for this source; previous
timeouts remain failed evidence and single profile samples are not a stable
performance guarantee or proof of the sole historical timeout cause.

The independently reviewed [Vault supply proposal](plan/product-v1-phase-6-vault-supply-remediation.md)
keeps image authenticity/provenance and the six HIGH findings as independent
blockers. No Vault lock, trust root or toolchain lock changed; no new candidate
was fetched or Vault service started. Next produce an exact candidate dossier,
verify all supply gates, and independently review candidate-specific consumption
before running the new two-issuer matrix and complete command composition.
Private evidence: `race-vault-remediation-20261013`, outside Git and migration.

Phase6 remains **5/15**. Slice6 steps1/2/3/4 remain historical bounded Guest E /
startup and real-boundary work ongoing / final live topology, original16 and
independent formal acceptance incomplete / post-acceptance handoff not started.
Public holds, broker/general issuers, PostgreSQL general and frozen-R reuse
remain unchanged. Development stays mise Go1.26.8 or Docker. No staging, commit,
push, merge or release.


## 2026-10-13 Vault 2.1.2 candidate supply result

The [candidate investigation](plan/product-v1-phase-6-vault-candidate-supply.md) restores and verifies the exact new
index, arm64 manifest, config and seven original layers, including ordered
diff IDs and wrong-identity refusals. Its private repository-validator race
check passed in **24.044 seconds**. Trivy0.74.0 completed the fresh full-image
report in **1.853 seconds**, bound to the actual config and unchanged scan/DB
bytes, but the existing vulnerability gate **fails: 4 HIGH, 0 CRITICAL**.
The actual binary contains Go1.26.8 and x/net v0.59.0; all lower/unknown
findings remain recorded. Image signature and build provenance also remain
unverified. Independent review confirmed rejection, not runtime qualification.

No Vault service ran. Exact new ECR Docker references were removed without
force/prune, preserving the historical image. Failed transfers and incomplete
Docker exports remain in private `vault-candidate-supply-20261013`; the accepted
locks and receipts are unchanged. All2148 repository Go files match the prior
503.355-second full-race snapshot, so that same-source evidence is reused.
Next review a replacement/build proposal covering fixed embedded inputs and
independent publisher/builder authority. Vault compiler selection is a separate
decision; the existing Go1.26.9 exception remains Coding-only.

Slice6 step1 retains historical bounded Guest E; step2 remains ongoing and
blocked on these Vault supply inputs for the real issuer/command composition;
step3 final live inventory, original16 and independent formal acceptance remain
incomplete; step4 post-acceptance handoff is not started. Phase6 remains **5/15**.
Broker/general, PostgreSQL general, public holds and frozen-R reuse are unchanged.
Development uses mise/Docker. No staging, commit, push, merge or release.

## 2026-10-13 Vault rebuild decision package

The independently reviewed [isolated rebuild proposal](plan/product-v1-phase-6-vault-rebuild-proposal.md)
binds the exact clean upstream tree and an unapplied three-file patch for a
Vault-specific Go1.26.9/root x/net0.60.0 candidate. Strict object verification
and patch applicability passed; source scripts, build and Vault execution were
not run. UI inclusion, derived-source metadata and offline generator/package
execution are explicit fail-closed requirements. Full build inputs and
publisher/builder authority remain unresolved. The next decision is the
Vault-only compiler exception; existing permission is still Coding-only.

All2148 repository Go files remain bound to the prior passing full-race/vet/
Contract snapshot; this documentation checkpoint does not rerun or extend those
results. Phase6 remains **5/15**. Slice6 steps1/2/3/4 remain historical bounded
Guest E / ongoing, with real Vault supply blocked / final live inventory,
original16 and independent acceptance incomplete / post-acceptance handoff not
started. Private evidence: `vault-rebuild-proposal-20261013`. No accepted locks,
trust roots or receipts changed; no commit, push, publication or release.


## 2026-10-13 approved Vault diagnostic input preparation

The user confirmed the private Vault-only Go1.26.9/root x/net v0.60.0 build
exception. The [input checkpoint](plan/product-v1-phase-6-vault-build-inputs.md) records a new
uncommitted source copy, an actual module graph with only that x/net version
delta, exact compiler materials, 1,852 compatible registry UI archives and
four Git-package source correspondences. Node22 is a separately reviewed
private UI tool delta; the dependency lock is unchanged. Source-bound download
recovery, 15 enumer outputs and UI lifecycle conditions have read-only
independent review; actual source/generator/UI execution has not occurred.

Incomplete builder/module transfers remain failed evidence. Final runtime
identity, Ember5.8 support, publisher/builder approval and all downstream
candidate/runtime results remain unresolved. No accepted lock, trust root,
ordinary repository toolchain, public Profile/provider hold or frozen-R rule
changed. No commit, push, publication or Vault service execution occurred.
Private evidence: `vault-rebuild-inputs-20261013`.

Phase6 remains **5/15**. Slice6 step1 retains historical bounded Guest E;
step2 is ongoing; step3 final live inventory/original16/independent acceptance
is incomplete; step4 has not started. The next acceptable result is complete
checked inputs and a reviewed isolated build recipe, followed by a genuinely
new diagnostic output and scan; this checkpoint is not formal acceptance.

## 2026-10-13 Vault builder material closure and rejection

The [builder checkpoint](plan/product-v1-phase-6-vault-builder-admission.md)
restores the remaining24 Go requests and three Node layers. All987 ZIP/mod
pairs and actual offline root go mod verify pass; the exact native OCI chain,
diff IDs and Node binary correspondence pass. The complete builder scan
**fails with4 CRITICAL/65 HIGH**, and image signature/build-source admission
is still unverified. No Docker import, source build or Vault service occurred.
The conditional isolation plan preserves all gates; it is not approval to
execute this image. Private evidence: `vault-isolated-build-20261013`.

Next establish a viable independently admitted builder and frozen generator/
pnpm store recipes. Repository Go and accepted locks are unchanged. Phase6 is
still **5/15**: Slice6 step1 historical bounded E; step2 ongoing with builder
admission failed; step3 final inventory/original16/independent acceptance
incomplete; step4 not started. This is no formal Slice completion or release.

## 2026-10-13 Vault builder selection and dependency gate rejection

The [new builder/recipe checkpoint](plan/product-v1-phase-6-vault-builder-selection.md)
selects an exact Chainguard arm64 carrier with eight verified signature/attestation
checks, a signed apko/75-package source correspondence and a zero-finding full
image scan. A separately reviewed Docker init-layer reconciliation accounts
for the saved export without rewriting its original strict failure. Node22.23.3
and authenticated pnpm10.34.7 are the selected private tools; builtin Node26 is
covered by the read-only exact Node mount. The new private enumer graph closes
all9 archive/mod checksum inputs. Historical Vault source and accepted locks
remain unchanged.

Complete material inventories now recognize all9 enumer dependencies and1852
compatible registry packages. They report8 HIGH and51 HIGH/4 CRITICAL respectively;
the separate admission command exits1. Four Git sources have separate bindings,
not coverage by those scans. Generator and complete UI/Vault build execution
remain rejected; offline transport/store probes cannot waive these findings.
Next review scoped repair inputs, unresolved advisories and the complete offline
graph. No Vault service or new candidate binary/image is claimed. Private evidence:
`vault-builder-candidate-20261013`. Phase6 stays5/15; Slice6 steps1/2/3/4 remain
historical bounded E / ongoing / incomplete / not started.
