# Project Context

Updated: 2026-10-21

This is the stable handoff index for a new developer, AI agent, development
device, or implementation session. It summarizes the system, engineering
constraints, verified maturity, and evidence boundary; it does not override
the Provider Contract, architecture, accepted ADRs, or reproducible evidence.

## Stage checkpoint workflow

User direction, 2026-10-19: after each completed small stage with repository
changes, check tracked and untracked files for omissions, commit the coherent
reviewed changes and normally push the current implementation branch. This is
standing authorization for those stage commits and pushes; do not wait for a
separate request each time or accumulate several finished stages locally.
Verify the full local HEAD, upstream reference and live remote SHA after each
push. If authentication, divergence or another failure blocks the push, retain
the local commits and report the exact unsynchronized state; never force-push.
No-change stages need no empty commit. Keep private evidence outside Git and
preserve the existing validation/review gates. Intermediate checkpoints do not
constitute formal Slice acceptance, merge, release or publication authority.

## Active Phase 6 delivery and machine handoff

The [delivery priorities and handoff plan](plan/product-v1-phase-6-delivery-and-handoff.md)
records the 2026-10-04 comparator findings, product-positioning hypothesis,
architecture boundaries, evidence-reuse decisions and next work. Phase 6
remains **5/15**, with Slice 6 open; component results are not full-topology
acceptance. The 2026-10-05 interim source checkpoint is for changing
computers, not completion of the formal Slice 6 step 4: commit and normally
push reviewed source, compare full local/upstream/live remote SHAs, and
inventory private evidence and local artifacts separately from Git. Resume
Slice 6 step 2 on the new computer; only independent acceptance of step 3
permits 6/15, and formal step 4 still follows that acceptance. The existing
authorization and fixed order for Slices 7–15 remain unchanged.

The latest [2026-10-21 Python/SDK authentication prerequisite review](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-python-sdk-authentication-prerequisites-held)
confirms the retained Python candidate metadata/bundles, the authenticated good
TUF target, all 27 selected compiler/ABI inputs and the complete 264-file,
5-directory Python header tree. Two separately reviewed source-only batches
each verify 7/8 fixed source files. The same missing Cosign attestation entry
times out at the original 10-second boundary through raw and immutable blob
paths; both failures remain, with no identity retry or further endpoint loop.
Independent review accepts 14 source files and the conditional target-use
analysis, while actual Python verification remains **HELD**: helper/library
behavior cannot prove the missing entry's real wiring. Python archive bytes
and the exact original signed Apple SDK package remain absent from the inspected
recovery materials. No host sampling, Cosign verification, build or scan starts.
Evidence: `python-sdk-auth-20261020-235600`. Next close that exact source edge,
then independently review complete execution inputs, strict provenance/refusal
checks and fresh original host readiness. Existing TUF 4/4 remains limited to
its frozen top chain. Three progress documents follow normal commit/push;
private evidence, original limits/guards/reuse rules and disabled timers stay.
Phase6 remains 5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 frozen TUF four-case pass](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-frozen-top-tuf-four-case-chain-passes)
passes the original dual-host gate and independently accepts **4/4** only for
this new identity's frozen top metadata/target chain. At23:26:44/23:27:50
Asia/Shanghai, load4.37/2.65, top idle81.57%/80.31%, free42%/41% and both Mach
checks pass;65.846674seconds has1253 swapin pages (19.578125MiB) and zero
swapout. The unchanged fixed Cosign then naturally rejects root13, timestamp
and target mutations, while the same-base unchanged good authenticates all
four top roles and11 cached target files. Joint review binds exact variants,
empty isolated caches, strict complete error frames, actual bytes/receipts
and post-state. All31 bounded captures are natural/reaped;1031 input rows and
eight old sealed checkpoints remain exact. Evidence:
`tuf-fourcase-resume-20261020-232404`. Old failures are not reclassified;
raw provisional parser fields remain unchanged, and modern partial root14
files are not authority. This does not prove syscall reads of13, official latest,
inherited rollback/delegation, Python archive/SDK/native or product acceptance.
Next independently review concrete authenticated-target use and provenance for
existing archive/SDK candidate records with all downstream gates intact. Three
reviewed progress documents follow normal commit/push; no implementation,
limit/cache/index/reuse changes, build/scan/new material or timer follows.
Phase6 remains5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 dual-host paging recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-dual-host-recheck-rejects-both-paging-deltas)
uses a new independently reviewed identity with928 complete inputs, preserving
all825 prior rows/9aliases and unchanged approved source. At09:43:52/09:44:58
Asia/Shanghai, load4.41/4.86, top idle64.82%/60.38% and memory-pressure free31%/
31% pass, with first Mach76.902174%. Over65.930274seconds, swapin increases71339
16KiB pages (1114.671875MiB), above32pages/second, and swapout increases95336
pages (1489.625MiB), above zero. Both original paging predicates fail; second
Mach and TUF never start. All25 bounded receipts are natural/reaped without
signal/truncation/timeout; wrapper exit0 is not readiness. All928 before/after/
current input rows and seven old sealed checkpoints remain exact. Role expiry
is still future as a time check only. Evidence: `tuf-fourcase-resume-20261020-094023`.
The failed identity is retained without retry; no gate/limit/tool/cache/index/
reuse changes, build/scan/new material or timer follows. Three reviewed progress
documents follow normal commit/push. A new independently reviewed identity must
pass the complete original dual gate before four-case unchanged-good joint
review. TUF stays0/4, Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-20 dual-host interval recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-dual-host-recheck-rejects-interval-swapin)
uses a separately reviewed new identity with825 complete inputs, retaining all722
prior rows/9aliases and the unchanged approved implementation. Final role
expiries remain future as a time check only. At09:29:40/09:30:46 Asia/Shanghai,
load3.47/3.01, top idle79.37%/75.52% and free40%/33% pass both base samples;
first Mach idle84.791252% also passes. Over65.817397seconds, swapin rises6131
16KiB pages (95.796875MiB), exceeding the original32pages/second bound;
swapout stays zero. The second guard stops before its Mach check and no TUF
case starts. All25 bounded receipts naturally finish/reap without signal,
truncation or timeout; wrapper exit0 is not readiness. All825 before/after/
current rows match, and six old sealed checkpoints remain exact. Evidence:
`tuf-fourcase-resume-20261020-092705`. This failed identity is not retried.
Next a new independently reviewed identity must pass the complete original
dual gate before the frozen four-case batch and joint causal review. Only three
progress documents follow normal commit/push; no gate/limit/tool/cache/index/
reuse changes, external material, build/scan or timer follows. TUF stays0/4,
Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 source-bound host recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-source-bound-host-recheck-stops-before-tuf)
independently reviews a new true execution identity with722 complete inputs,
preserving all610 old rows/9aliases and four17-file mirrors. The approved
four-line implementation is unchanged; final role expiries are still future,
which is only a time check. At08:58:05 Asia/Shanghai, load3.60 and free40% pass,
but top idle46.22% fails the original60% floor. The first guard stops before
Mach, the second sample or any TUF case; no paging interval is measured.
All13 bounded receipts naturally finish without signal/truncation/timeout and
are reaped; host wrapper exit0 does not override its false readiness result.
All722 before/after/current inputs match; five old sealed checkpoints remain
exact. Evidence: `tuf-fourcase-resume-20261020-085244`. The failed identity is
retained without retry. Next use a separately reviewed new identity and the
original dual gate before the frozen four-case batch and joint causal review.
Only three progress documents follow normal commit/push; no tool/limit/supply/
cache/index/reuse changes, new external material, build/scan or timer follows.
TUF stays0/4, Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-20 strict four-line capture policy](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-strict-four-line-capture-policy)
adds a reusable pure-Python fixed-Cosign3.1.3 parser and independent synthetic
tests in tools/tuf-diagnostic-policy. It exactly matches both distinct warnings,
case-specific full duplicated payloads and complete target expected/got hashes;
strict natural receipt, original25second/1MiB bounds and empty negative stdout
are required. New private caller glue records target/no-success facts before
parsing, rejects broken symlinks/unknown errors and retains all good/post/input
checks. Independently reviewed component suites pass96 repository tests and18
adapter/unaffected regression tests;17 unchanged old tests pass separately as a
historical baseline. D4 raw matches only as a format fixture, without changing
its failed result. No actual execution lock, host sample or Cosign/TUF case is
started. Fresh source-bound execution inputs, original host/supply/isolation
gates and unchanged-good joint causal review still precede any TUF acceptance.
All610 inputs/9aliases/four old sealed checkpoints are preserved. Evidence:
`tuf-fourline-policy-20261020-083751`. Only three tool files and three progress
documents follow normal commit/push; private data stays outside Git, original
limits/toolchain/cache/index/reuse rules and disabled timers remain unchanged.
TUF stays0/4, Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-20 util and standard-log source closure](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-util-and-standard-log-source-correspondence)
verifies18 new fixed-version source/module files and one complete tree through
19 successful original10second-bounded requests. Legacy util confirms
13.root.json naming and the complete expected/got hash error. A new independently
reviewed read-only static observation passes in1.323606seconds after36 synthetic
tests, locating global log.SetFlags at CUE0.16.1 adt/log.go:54; verified source
sets0 in init, consistent with D4's untimestamped final line. Eight module-identity
byte tests pass before strict CUE decoding. Failed diagnostic/fixture/invocation
identities and unexecuted drafts remain preserved. Static metadata uses pinned
Go intervals within participating Mach-O sections;15988 text suffix bytes stay
unexplained. This closes the two source-correspondence gaps, not actual13 reads,
cryptographic mutation-versus-good causality or TUF acceptance. The conditional
strict-four-line repair now requires the full target hash payload and concrete
parser/refusal review before any new original-gated four-case run. All610 inputs,
9aliases and three old sealed checkpoints remain exact. Private evidence:
`tuf-source-gap-20261019-151705`. No Cosign/host/TUF/build/scan/container or repository
test runs; no TUF parser/root/cache/index/reuse/limit/toolchain change or timer starts.
TUF stays0/4, Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete,
step4 not started. Only reviewed progress documents follow normal commit/push.

The earlier [2026-10-19 fixed Cosign client/error source recovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-fixed-cosign-client-and-error-source-recovery)
verifies27 source/module files and two complete updater trees in a new
independently reviewed identity. Source explains modern14 persistence before
Refresh, legacy's separate memory/DB and embedded12 selection, old/new root
threshold checks, success-only disk synchronization, and Cobra/main's two
error emissions matching D4's four lines. Three10second-deadline requests
fail and remain recorded; util VersionedPath/hash-format source and global
logger-flag attribution are still missing. Core paths are source-supported,
but the complete helper chain, actual13 read and mutation-versus-good
causality are not proved. Root/timestamp and target failures also have different
wrappers; predicted unexecuted cases are not actual results. The conditional
repair keeps root13, nil external root, exact case-specific error frames,
all refusal checks and the original four-case order/bounds. No implementation,
new host/TUF run, test/build/scan/container or timer starts. Private evidence:
`tuf-source-recovery-20261019-133746`. Old evidence stays exact; TUF remains0/4,
Phase6 stays5/15, Slice6 step2 ongoing, steps3/4 incomplete/not started.

The earlier [2026-10-19 fixed Cosign root investigation](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-fixed-cosign-roots-and-causality-held)
identifies static legacy root12 and modern root14 in the exact Cosign3.1.3
binary; D4's cached root exactly matches the modern root's5491 bytes. Exact
initialization source calls modern first and falls back to legacy with nil
external root. These distinct paths do not make cached14 proof of a legacy14
bootstrap, and do not establish that D4 read13 or rejected its mutation.
Three official source requests fail at the unchanged10second deadline;
network stops and complete client/updater source remains missing. A strictly
reviewed local FS observer maps all11 embedded file blobs to official tag
objects; its earlier failed plain-hash hypothesis is preserved. This is static
storage evidence, not actual TUF execution or acceptance. The conditional
repair proposal first requires complete source review, then strict error-frame
and refusal tests and a new original-gated four-case run including unchanged
good. No parser, fixture, root, old cache/evidence, quota or timeout changes.
Private evidence: `tuf-bootstrap-readonly-20261019-130227`. No new host sample,
CLI/test/build/scan/container or timer starts; TUF stays0/4 and Phase6 stays5/15,
Slice6 step2 ongoing, steps3/4 incomplete/not started.

The earlier [2026-10-19 host pass and held TUF root attribution](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-host-gate-passes-tuf-root-attribution-held)
passes the original dual-host gate in its actual20:45:13/20:46:18 Asia/Shanghai
window: load2.01/1.85, top idle88.18%/77.96%, free38%/42%, both Mach checks,
and65.717408seconds with105 swapin pages (1.640625MiB) and zero swapout.
The existing TUF batch then starts only `bad-root13`. Its CLI naturally exits1,
but four actual stderr lines fail the parser's strict three-line expectation;
the case is not accepted and the remaining three do not start (0/4 accepted).
The cache also contains unverified root v14 while the mutation targets v13;
the rejection's causal link to that mutation is unproved. Do not clear this
by only accepting another error format. Next independently review the fixed
tool's bootstrap/update paths, mutation causality and any strict parser/case
correction before another identity. All610 inputs/9aliases/four mirrors remain
exact; old evidence is preserved, no implementation or limit changes and no
retry or timer follows. Private evidence: `tuf-chain-resume-20261019-124329`.
Phase6 remains5/15, Slice6 step2 ongoing, steps3/4 incomplete/not started.

The earlier [2026-10-19 two-sample recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-two-sample-recheck-refuses-interval-paging)
uses a new independently reviewed identity and the unchanged implementation.
At19:57:03/19:58:09 Asia/Shanghai, both base samples pass load, top CPU idle and
memory floors; the first Mach observer also passes. Over65.723560seconds,
swapin rises4112 pages (64.25MiB) and swapout1456 pages (22.75MiB), violating
both original interval predicates. The second guard stops before its Mach
observer, so original dual readiness fails and TUF four cases remain unstarted.
All512 locked inputs,9aliases and four17-file mirrors match before/after;
the previous184-file/19-directory checkpoint and seal remain exact. Frozen
tests are reused without rerunning them. Evidence:
`tuf-chain-resume-20261019-115426`. This dated observation does not establish
ongoing host performance or attribute paging to a process. No retry, new
external material, scanner/build or timer is started. The progress update
follows the standing stage-checkpoint commit/push direction;
Phase6 stays5/15 and Slice6 step2 remains ongoing, with steps3/4 incomplete/not started.

The earlier [2026-10-19 local source checkpoint and held TUF chain](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-local-source-checkpoint-and-held-tuf-chain)
preserves the existing implementation in local commits and updates this handoff.
All2148 Go files and all2390 Git-visible non-document files exactly match the
2026-10-13 validated snapshot by file set and SHA256. Its503.355-second full
race run with `-p=6`, vet and both Contract results are same-source historical
evidence; none was rerun during this resource-constrained checkpoint. Its last
actual host attempt at14:53:30 Asia/Shanghai has load5.15/free31% but CPU idle
35.65%<60%, so it stops at the first sample; no second sample or TUF case starts.
The added same-boot guard has25 passing tests, but supplies no host or TUF
admission. Timestamp812 remains an unverified candidate. Private evidence stays
outside Git, automation stays off, and all existing supply/isolation gates and
public holds remain. This is an intermediate local source checkpoint, not
Slice6 step4, a new scan, remote synchronization or release. Phase6 remains5/15;
Slice6 step2 is ongoing and steps3/4 remain incomplete/not started.

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

Prior Slice6 step2 work: [held Provider / Control TLS peer](plan/product-v1-phase-6-provider-tls-peer.md), following the source/process and CA directory observation components. It connects separate Linux role/agent test processes through the production TLS, signer and source-bound CRL machinery; production Provider/Control commands, Vault/controller issuance, operator/Store and full-graph admission remain open. The follow-up local full-repository race/shuffle/count1 run passed with package concurrency `-p=6` in 510.429 seconds under the unchanged 600-second bound, on the same Go source. The three earlier timeouts remain failed evidence; this is not a default-concurrency or CI result. See the peer document for diagnosis and unchanged production gates.

The [2026-10-13 Vault continuation](plan/product-v1-phase-6-vault-two-issuer.md)
fixes a reproduced duplicate-source/omitted-issuer acceptance in VaultClient
and prepares an opt-in real broker/general component. The exact locked Vault
archive has been restored and verified; image signature/provenance remains
unverified and the fresh scan reports HIGH findings, so real Vault execution
is blocked by the required supply gates. The new full race run also timed out
at the unchanged 600-second bound; component tests, vet and Contract checks
do not substitute for it.
No real two-issuer result or Controller/agent/command composition is claimed.
The private checkpoint is `vault-controller-continuation-20261013`.

The subsequent [race budget diagnosis](plan/product-v1-phase-6-race-budget-diagnosis.md)
removes repeated desired-graph construction within one HBA call while retaining
every validation and per-call freshness. The final full race/shuffle/count1
run with existing `-p=6` passed in **503.355 seconds** under the unchanged
600-second limit; full vet and both Contract locks passed on matching source.
Earlier timeouts remain failed evidence. The independently reviewed
[Vault supply proposal](plan/product-v1-phase-6-vault-supply-remediation.md)
keeps the six HIGH findings and unverified image signature/provenance as
separate unresolved blockers; no candidate lock or trust root was changed and
no Vault service started. Next establish an exact, independently reviewed
candidate dossier before actual two-issuer/command work. Evidence is private
checkpoint `race-vault-remediation-20261013`; Phase6 remains5/15 and Slice6
steps1/2/3/4 remain historical bounded E / ongoing / incomplete / not started.

The [Vault2.1.2 candidate investigation](plan/product-v1-phase-6-vault-candidate-supply.md)
completed original-byte index/platform/config/seven-layer verification and a
fresh full-image scan. The archive race diagnostic passed in24.044 seconds;
scan report generation took1.853 seconds, but the vulnerability gate **fails**
with4 HIGH findings in the actual Go1.26.8/x/net v0.59.0 binary. Image signature
and build provenance remain unverified. Independent review confirmed this
bounded rejection. No Vault service ran and no accepted lock changed; both
new ECR Docker references were precisely removed, retaining historical inputs.
Private evidence: `vault-candidate-supply-20261013`. All2148 Go files still match
the503.355-second full-race snapshot. Next review a replacement/build proposal
with fixed embedded inputs and independently established supply authority;
the Coding-only Go1.26.9 permission does not authorize a Vault toolchain change.
Phase6 remains5/15 and Slice6 step2 remains open.

The subsequent [Vault isolated rebuild proposal](plan/product-v1-phase-6-vault-rebuild-proposal.md)
was independently reviewed, and the user confirmed the Vault-only private
diagnostic Go1.26.9/x/net v0.60.0 exception. The
[input checkpoint](plan/product-v1-phase-6-vault-build-inputs.md) records the
private source patch, unchanged other module selections, full compatible UI
archive checks and reviewed generator/lifecycle boundaries. Ordinary repository
work remains Go1.26.8. The subsequent
[builder admission checkpoint](plan/product-v1-phase-6-vault-builder-admission.md)
closes all24 remaining Go materials, verifies987/987 archive/mod pairs and an
actual offline root go mod verify, and restores all missing Node layers.
However, the complete Node builder scan **fails with4 CRITICAL/65 HIGH** and
signature/build-source admission remains unverified. The held isolation plan
does not authorize that image. No builder/source execution, new Vault binary
or service has run. Next admit an exact viable builder and close the generator
and pnpm store recipes before execution; unsupported Ember5.8, runtime UID/GID
and candidate supply remain unresolved. New private evidence is
`vault-isolated-build-20261013`; previous checkpoints are preserved. Phase6
remains5/15, with Slice6 step2 ongoing and steps3/4 uncompleted/not started.

The subsequent [builder selection and offline recipe checkpoint](plan/product-v1-phase-6-vault-builder-selection.md)
verifies an exact signed Chainguard/apko carrier, its75-package closure and
zero-finding full-image scan, plus a reviewed source-accounted Docker export.
Authenticated pnpm10.34.7 and fixed Node22.23.3 are the private selected tools;
all9 enumer dependency materials now close. The bounded Docker environment and
one-package two-stage offline store probe pass; full UI is not qualified.
Full material inventories expose
8 HIGH generator findings and51 HIGH/4 CRITICAL UI registry findings, so the
separate execution gate rejects complete builds. Historical source/locks stay
unchanged. Next review scoped dependency repairs and unresolved advisories,
then complete the full offline graph and source-build gates. Private evidence:
`vault-builder-candidate-20261013`; Phase6 stays5/15, Slice6 step2 remains open.

The [generator dependency remediation checkpoint](plan/product-v1-phase-6-vault-dependency-remediation.md)
derives only private enumer go.mod/sum, verifies12 module pairs and removes the
old8 HIGH findings. One OpenPGP UNKNOWN stays in the material inventory;
independent exact-package/subprocess review permits only the generator scope.
The reviewed offline Docker run passes original tests and builds the new ELF
in45.290seconds; its actual output scan recognizes all embedded modules and
has no findings. The EXDEV fixture failure and zero-recognition first scan are
retained, not passes. Complete UI remains blocked by the unfixed braces HIGH
and Ember5.8 support boundary. Next verify the fixed15 Vault generation outputs
and independently review a supported UI repair graph. Private evidence is
`vault-dependency-remediation-20261013`; Phase6 remains5/15, Slice6 step2 open.

The [Vault generator output checkpoint](plan/product-v1-phase-6-vault-generator-output.md)
binds the unchanged9090-file private source, exact15 CE root commands and
authenticated offline module graph. The host full-CE dry-run passes; the
original enterprise-tagged selection and first Docker full-root dry-run fail
and remain recorded. A complete986-module root inventory exposes16 HIGH
findings, so the independently reviewed diagnostic scope cannot grant full
Vault build, supply or service admission. The latest v3 attempt reaches the
90-second OCI load limit before container creation; exact cleanup succeeds
and the wrapper later interrupts input postchecking. A separate full-input
check passes in248.239seconds without accepting either failed run. A later
lower-load v4 run imports the same OCI archive in10.159seconds but still hits
the10-package dry-run60-second bound. Its176.071-second failure completes full
input pre/postchecking and precise cleanup. A separate v5 SIGQUIT diagnostic
also times out without returning a stack; its271.977-second failure is retained.
Neither executes compiler exports or enumer. After the user's manual readiness
request, separated samples show61–65%CPU idle and same-daemon info below0.8s.
The reviewed v6 asynchronous observer captures17637 untruncated Go stack bytes
and deliberately interrupts dry-run at55.069s; its171.237s failure is not a
natural60s timeout or a generation pass. At that instant two workers traverse
module-index directories while the main goroutine waits for package loading.
This supports a targeted hypothesis, not a unique root cause. Full input
pre/postchecking and exact cleanup complete; no export/enumer executes. The
heartbeat was deleted at the user's request and remains off. Current evidence is
`vault-generator-resume-20261013-115951` and `vault-generator-stack-probe-20261013`;
older `vault-generator-output-20261013` is preserved. Actual15-output byte
verification and supported UI remediation remain open. Phase6 remains5/15 and
Slice6 step2 ongoing.

The independently reviewed, one-shot `goindex=0` private Go1.26.9 fallback
then passes the same10-package dry-run in15.938seconds with all15 exact
directives. Real compiler export runs for76.486seconds but the gate rejects
534 direct ENOSPC errors and1741 erroneous/incomplete package rows. The2637
package/module/selected-file identities match in a separate post-failure
metadata comparison; clean exports and actual generation do not pass. No
enumer executes. Full input before/after receipts,15 source-target checks
and exact cleanup complete; the run fails in158.554seconds. Evidence is
`vault-generator-index-fallback-20261013`. Next investigate bounded compiler
scratch/cache storage and independently review a concrete repair before any
new attempt; do not enlarge limits, import unknown cache or repeat this failure.
The undocumented index switch is private diagnostic scope only. Phase6 remains5/15.

The subsequent v8 measurement establishes `/work` byte exhaustion rather than
inode exhaustion: free bytes0 with at least45905 inodes available, and nearly
1GiB of combined cache/work allocations. Its119.142-second failure preserves
full inputs and exact cleanup. The reviewed v9 DWARF-off candidate also fails
in172.604seconds:475 direct ENOSPC plus one compiler signal-killed error,
with cgroup oom2/oom_kill1 and Docker OOMKilled=true. Dry-run passes, but actual
exports fail and generated outputs remain0/15. Full input checks,15 old target
bytes and exact cleanup pass; post-failure2637 metadata identity is not export
acceptance. Evidence is `vault-generator-scratch-20261013-1404` and
`vault-generator-scratch-recipe-20261013-1436`. No further runtime attempt or
automation is started. Next independently review a same-run cache/stage design
that addresses both capacity and peak memory within one300-second aggregate
compiler budget/390-second container budget, retaining final simultaneous2637
real exports and15 original output bytes. Feasibility remains unknown; no new
cache policy, `-l`, quota/time increase or production admission is approved.

## Current verified state

- the fixed P2.7 independent external-caller qualification plan is **24/24**;
- the public `sandbox-runtime-external-caller` plan is **13/13**;
- hosted run `35203241121` executed all 15 initial and 5 reconstruction
  scenarios, matched all 91 required observations, and restored the exact
  run-owned resource scope to zero across three stable samples;
- artifact `10488622806` contains the accepted seven-file evidence archive,
  validator receipt, and bounded `qualified` result envelope; and
- post-documentation core CI run `35204434771` passed every required job; and
- Product v1 architecture Phase 1 is complete as committed design and
  Product Contract-definition authority; and
- Product v1 Phase 2 is complete for its fixed nine-step scope: implementation
  revision `98995384c60a924f25ca58d3b7e561207bfa5be8` is selected by lock
  revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`, the clean-VCS 60-case
  Suite and all required release gates pass, and the repository-owned
  independent-process reference run passes 15+5+9 scenarios; and
- Product v1 Phase 3 is complete at **13/13** for its bounded standalone scope.
  In addition to the Product authority, authenticated API, locked Provider
  reconciliation, control, Terminal/Gateway, Guest/Files, transfer/revision,
  Web, catalog, and recording components, run
  `20260918T111903.806694000Z` at implementation
  `04c2755bec125db7e2c04df3f4e2f8cfedb6ec1d` passed nine black-box scenarios
  through four separate role processes and fresh pinned PostgreSQL. Its strict
  evidence manifest records complete process, schema, and container cleanup.
  This same-repository Provider-fixture topology is not deployment, HA,
  hostile-multitenant, independently implemented caller, or production
  evidence; and
- Product v1 Phase 4 Browser is complete at **13/13** for its bounded
  same-repository separate-process scope. Run
  `20260918T152110.677058000Z` at source baseline
  `322eb342650d2ade838f1b3a24e0d5bc0bfbb3e1` passed 12 exact scenarios
  through separate Product, Gateway, Provider, and Browser OS processes with
  fresh digest-pinned PostgreSQL and Valkey plus fresh encrypted recording
  storage. Strict evidence validation confirms the locked Contract identities,
  four roles, scenario set, and cleanup. Deployment, HA, hostile multi-tenant,
  independently implemented caller, and production readiness remain explicit
  non-claims; and
- Product v1 Phase 5 Desktop is **15/15 complete** for its bounded
  same-repository independent-process topology. Slice 1 establishes the
  separate Provider Desktop Contract and Go projection authority at revision
  `720ad15c343e71f36615dc4499edd5e764178bca`, tree
  `343ffde0819207cf99c005096c336735dd33a735`, with a content-derived 71-case
  local Suite. Slice 2 implementation
  `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00` adds exact Product Desktop
  slot/session intent, PostgreSQL migration 8, atomic audit/outbox persistence,
  quotas, concurrency closure, nondisclosure, and restart-safe reads. Slice 3
  implementation `f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5` adds the separate
  Provider Desktop domain, application policy, memory/atomic-file authority,
  restart and unknown-outcome reconciliation, operation projection, and
  optional protected handlers. Slice 4 candidate implementation
  `163dd8a258a24cf4727169b1cbd8ed7c0fe29292` adds the locked Desktop image
  inputs, fixed Unix-only broker, reproducible local outputs, passing native
  arm64 smoke, and a manual native publication/provenance workflow. Run
  `35447651328` at source `e4a940bda6c5172a78d0dbe40963ca1a99911976`
  passes native amd64/arm64/v8 gates, publishes exact signed index
  `sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`,
  and passes fresh independent provenance and architecture verification.
  Slice 5 implementation `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b`
  adds the Provider-local Docker adapter, durable opaque reference authority,
  fresh attach/reconnect checks, lifecycle readiness, exact duration usage,
  and revoke/cleanup/absence composition. Slice 6 implementation
  `2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240` adds the locked network-only
  Product adapter, isolated Desktop slot/lifecycle/session/observation workers,
  retained operation recovery, separate Product/Provider generations, and
  Desktop-specific close cleanup with a real-PostgreSQL gate. Slice 7
  implementation `0649d62911abb89229de40136347286736152ec6` adds exact
  Desktop-only viewer/controller grants, encrypted one-use tickets,
  session-scoped controller fencing, independent viewer/controller quotas,
  revocation, continuous authority checks, and metadata-only audit. At that
  boundary, production startup composition, public signaling/media/input,
  policy, unified Web, capability advertisement, and release evidence remained
  absent.

  Slice 8 implementation `040c560f3701b7c972c25f05928dd435d9f55c20`
  adds a separate bounded Desktop WebRTC handler with authenticated encrypted
  signaling, exact Origin, receive-only VP8/optional Opus, viewer/controller
  separation, ordered fenced input, continuous authority, and backpressure
  closure. Durable Desktop policy, a real Provider media bridge, recovery,
  recording, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 9 implementation `24f5c741eb605614f77f8d9d546708b9993e42dd`
  adds immutable versioned Workspace policy, PostgreSQL migration 11,
  deny-by-default keyboard/pointer/touch/clipboard/transfer authorization,
  activation and consent, bounded clipboard/media/digest/count/size/path
  rules, exact Product transfer binding, and continuous policy-revision
  revocation. A real Provider media/input bridge, reconnect/recovery,
  recording, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 10 implementation `f23b16130c97e99d5d28008b01346779a0c681ee`
  adds database-time Desktop Gateway leases for bounded crash recovery,
  fresh-grant reconnect with exact authority/generation rebinding, visual and
  audio resynchronization with rate bounds, closed display/audio-output
  changes, connection-epoch stale-input rejection, and transactional cleanup
  plus one-generation replacement for a replaced Desktop slot. A real Provider
  media/input bridge, recording, production composition, unified Web,
  capability advertisement, and release evidence remain absent.

  Slice 11 implementation `c5b045abc5192b76b7d615ddbb0858b998ef98d5`
  composes required Desktop content recording into the public Gateway. The
  client supplies an explicit bounded consent reference and receives the exact
  selected recording mode; missing initialization or live recorder loss closes
  admission/connection. Encrypted immutable segments retain bounded VP8/Opus
  RTP plus minimized control/synchronization metadata, monotonic timestamps,
  and digest linkage. Existing Product authorization, quotas, integrity replay,
  retention, and deletion apply to Desktop media. Clipboard text, transfer
  paths/identities, private coordinates, and content are absent from public
  catalog and metadata audit. A real Provider media/input bridge, development
  templates, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 12 implementation `490c2db96d6ba7a851d7846bc9e5f818dae2be77`
  adds the immutable development template catalog, validated revision-manifest
  persistence, exact Guest generation/capability/health authority, bounded
  content-addressed workspace materialization, and private two-phase
  rollback/restart recovery. Migration 13 and the complete fresh PostgreSQL
  package pass. Host paths, object paths, credentials, Guest IDs, and runtime
  coordinates remain outside stable health, event, and audit projections. A
  real Provider media/input bridge, unified Web, production composition,
  capability advertisement, and release evidence remain absent.

  Slice 13 implementation `84698c371d35edb862ffc81b484a3e31cc8120d9`
  adds the capability-derived authenticated unified Product Web/BFF for
  Workspace, Terminal, Files, Browser, Desktop, and recordings. Exact public
  Desktop slot/session shapes, fresh grants and controller leases,
  same-origin WebRTC, bounded recovery/configuration, explicit clipboard and
  recording consent, digest-checked transfers, keyboard-accessible tabs, and
  strict browser security/nondisclosure pass focused, full repository, and
  real headless-Chrome gates. Desktop advertisement remains off pending the
  real Provider media/input bridge, production startup composition, Slice 14
  composed security/fault cleanup, and Slice 15 independent-process release.

  Slice 14 implementation `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d`
  adds the closed neutral private Desktop media/control protocol, Product
  network source, Provider trusted-peer handler, fresh attach and continuous
  handoff authority, capacity/backpressure bounds, and a real-PostgreSQL
  composed public-WebRTC/private-bridge/recording/security/cleanup gate. Full
  race/vet, tagged store, Contract, and retained Phase 3/4 evidence regressions
  pass. This is same-repository same-process composition evidence with a
  reference media executor.

  Slice 15 implementation `024a768d51965f8949bacf3c97e499fb26a6e648`
  adds the strict independent-process release gate. Run
  `20260919T200125.484855000Z` passes 14 exact scenarios through separate
  Product, Gateway, Provider, Desktop, and Guest OS processes with fresh
  pinned PostgreSQL, the exact signed Desktop runtime, real X11 capture and
  fenced pointer control over public WebRTC/private mTLS, encrypted recording
  replay, actual Guest development materialization, Product/Gateway/Guest
  restart recovery, Provider-dependency fault closure, and exact cleanup. The
  exact gate topology derives Desktop/development capability readiness from
  live dependencies. The strict manifest rejects identity/scenario drift,
  incomplete cleanup, secrets, private coordinates, and host paths. This does
  not compose the production command or establish deployment, HA, hostile
  multi-tenant, independently implemented caller, or production readiness.
  Corrective commit `59de37d5ee22776305dfaab866c25ea6bd5406bc`
  deterministically closes the Provider media session before its private
  WebSocket closure becomes observable. E2E lock
  `d5d6ed1a815b49625a054d9931a8cec2234d8e7e` binds all eight
  parent checks to evidence/CI baseline
  `59de37d5ee22776305dfaab866c25ea6bd5406bc`; full E2E race/shuffle, vet,
  and all eight clean-checkout checks pass; and
- Product v1 Phase 6 production hardening is **5/15 complete** under ADR 0051
  and the fixed Phase 6 plan. The startup audit distinguishes existing
  components and same-repository gates from deployable/operable/production
  authority. Slice 1 adds `sandbox-runtime product serve`, strict
  development-only `product_process` configuration, bounded private
  PostgreSQL and frozen identity files, real Product migrations/store,
  independent liveness/readiness, empty capability advertisement, and
  fail-closed primary-slot authorization. The root `serve` command refuses an
  enabled Product section, so the Product, Provider, and local API roles remain
  separate. This is source/component evidence for a runnable development
  Product process, not a published deployment, standalone/production
  qualification, HA, hostile-multitenant safety, SLO attainment, or production
  readiness. Slice 2 adds production-kernel configuration, TLS 1.3, a closed
  Ed25519 Product access-token key ring with overlap/revocation, distinct
  migration/runtime PostgreSQL roles, exact read-only schema compatibility,
  and a fail-closed recovery monitor. Slice 3 adds the independent
  production-only `provider serve` role with TLS 1.3 mTLS, exact protected
  admission, separate PostgreSQL migration/runtime authority, transactional
  lifecycle/exec/Terminal/artifact/usage/Desktop state, bounded recovery and
  loopback probes, and exact single-profile coding-shell or Desktop
  advertisement. Real PostgreSQL concurrency/fault/restart, process restart,
  coding-shell Docker lifecycle, and signed Desktop broker gates pass locally.
  Product dispatch remains uncomposed, so `product.workspace` is still
  explicitly unavailable. Slice 4 adds separate Gateway/Guest/Browser/Desktop
  roles, restricted executor v2 backends, sealed Browser/Desktop egress
  identity, and a Provider-owned signed Desktop broker mux. Its corrective
  immutable candidate passes the six-role/twelve-scenario gate and strict
  evidence verification. Runtime revision
  `78f5987fda45873e497bce6d336e29dd4a61dc74`, evidence-tool revision
  `e2f4abacf03418c7b18f179c3e7459292d8626df`, manifest digest
  `sha256:d01b3c41a0094657f18b4014b0649a799ea7fcf0e4ccaf07aa82cdd2052cc0d2`,
  and candidate image digest
  `sha256:0592a69e8f85125360eb6805132b3654324ab9a56c0ea019ea3dc7aade103d4e`
  are fixed by the accepted evidence. The Desktop OCI remains a non-release
  local candidate; public Product E2E, publication, deployment and production
  readiness remain open. Slice 5 is complete within its bounded local
  independent-process and real-adapter evidence scope:
  ADR 0054 adds a repository-private canonical purpose/tenant/role/version
  secret binding, an exact adapter over the existing secret provider, a
  bounded invalidation-safe cache and an opaque envelope-key port. The existing
  Product recording port now carries explicit tenant scope; a tenant-bound KMS
  store wraps one random DEK per recording and a strict Vault Transit adapter
  passes a digest-pinned TLS integration with overlap rotation, restart,
  dependency loss and cleanup. Product's no-cache one-shot migration
  command/agent is physically separate from
  the v2 runtime registry for the TLS pair, runtime PostgreSQL DSN and identity
  key ring. A real Vault KV/TLS gate and real Product/PostgreSQL process gate
  prove pre-migration bind denial, cross-purpose denial, exact bootstrap
  cleanup, agent restart/loss and readiness closure/recovery. All six runtime
  roles use separate material agents; six renewable runtime and two one-shot
  migration credentials, controller restart, Vault/agent loss, revocation,
  expiry, dual-control break-glass, plaintext exclusion and exact cleanup pass
  the immutable gate. Runtime revision
  `c189330c5ed0aa52c60b6b85c5cd9c6b59fbef10`, evidence-tool revision
  `39fd1025f6fa838325aced711d8a024a9ce5d1b6` and manifest digest
  `sha256:e6a6fdcc299c721e1fa2c48009d98a6ca4c52d59318c507af8b68fd8596e840c`
  are retained. The local gate records `distinct_os_uid_established=false`;
  Product recording-content composition, HSM, deployment and production
  readiness remain false. Slice 6 is underway under ADR 0055 with real Vault
  PKI, live TLS rotation/revocation, role-isolated egress enforcement and exact
  container least privilege as its frozen order. Current source-level work
  closed the historical pre-v2 desired inventory of 78 deployments, 30 isolated
  external paths, 35 external edge IDs, 11 actual material agents, 12
  credential issuer sockets, 9 PostgreSQL-purpose signers and one ordered
  nine-role shared-service HBA. Four unconsumed V2 Browser/Desktop material
  deployments were removed without renumbering surviving identities or
  networks. The earlier 82-deployment source-bound candidate is historical
  component evidence and must be rebuilt before use with this topology.
  Real same-run Vault ACL/issuer installation, two controller PID1 processes,
  distinct Product/Guest TLS and material agents, and a source-bound pinned
  PostgreSQL PID1 have now passed a composed component gate. PostgreSQL used
  its Vault-issued server leaf, exact final HBA and nine isolated bridges;
  after mounted-leaf verification and shutdown, an independent one-shot v2
  operator confirmed three certificate serials, two token accessors, complete
  CRL and self-revocation, followed by zero run-labeled Docker resources.
  The separate no-secret provisioner probe and strict PEM/mount-order tests
  also pass. A further mutable-tree component run started PostgreSQL before
  Vault root revocation, used client-side encrypted native role creation to
  establish separate non-elevated Product migration/runtime SCRAM logins,
  precreated only the operator-owned database/schema, and stored their real
  DSNs in separate create-only KVv2 version-1 purpose bindings. Scoped
  readback, cross-purpose/cross-owner denial, token revocation, controller
  quiesce, v2 terminal PKI cleanup and exact Docker cleanup passed. A second
  same-run component test proved distinct-owner runtime DSN resolution. The
  clean-source R3 run `50f6810acddb8bffd5ba4167b0e424e2` additionally
  completed independent Product `migrate v2` PID1 with exit 0 and exact
  same-PostgreSQL migration-ledger, table-owner and grant readback. The known
  certificate-controller terminal failure remained recorded; the accepted
  independent one-shot operator confirmed revocation, complete CRL and
  self-revocation, followed by exact resource cleanup. Earlier failures remain
  historical. A later clean E `f49ee748f5e8790cd58c62d04bc5304b1a363b49`
  with clean R/F `c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635` passed one
  independently reviewed Product/PostgreSQL/Guest runtime component: a signed
  hello/welcome installed an upgraded connection, a same-PostgreSQL durable
  business-binding revoke drained it, and a fresh signed attempt was rejected
  as revoked. Run `20efb6c95a0fa39cb0441f580a86888f` retains four private
  source/image/process/mutation-bound zero-drop receipt files and exact
  zero-resource cleanup. The two earlier receipt attempts remain failed and
  incomplete; the certificate controller's sticky local terminal failure
  remains despite independent operator cleanup. This is not the complete
  Guest security edge: PostgreSQL loss/recovery, peer TLS revocation, CRL-source
  loss and replacement restart/reconnect remain unproved. Nine live SQL callers,
  the revised complete Profile-v2 inventory and its full 16-scenario Slice 6
  gate, formal signed evidence and deployment also remain unproved. The
  historical 78-deployment baseline and provisional 82-static-principal
  fixture do not establish the revised live topology. Phase 6 stays 5/15.

  The 2026-10-08 new-host uncommitted component checkpoint adds explicit
  typed v2 CRL Controller policy/issuer preflight, agent/guard constructors
  and single-owner PostgreSQL role decoding. Its follow-up wires explicit
  Controller config v5 and TLS-agent config v5/v6 into the actual commands,
  with typed Profile/source/policy/process checks before private key FDs.
  Public Profile-v2 validation and Provider v3 admission remain held.
  The 2026-10-09 continuation adds held Control Coding status and Scanner
  command entry points, scoped consuming-role TLS/CRL factories, a typed
  status Observer and dedicated Scanner client. The Control command only
  opens an existing receipt ledger; that original status-only config remains
  read-only.
  Scanner owns its fixed ClamD child and private 256 MiB runtime tmpfs.
  The next 2026-10-09 checkpoint explicitly selects a separate held Coding
  v3 dependency path: typed v2 PG/materials, PG lifecycle repository, status
  Coordinator, passive JSON checker and private Scanner. No Application or
  automatic lease worker is started. The subsequent held Control checkpoint
  adds a concrete Coding create/Completed-only cleanup executor and explicit
  `sandbox-runtime.provider-docker-control-coding-config.v2` command input.
  It preserves Unknown-before-write, single-use physical requests, same-process
  completion, original daemon binding and both public admission holds. It
  does not initialize a ledger or retire historical Unknowns. The following
  Provider dispatch checkpoint adds the typed original-authority mutation
  client and candidate command composition. Create uses the PG atomic first
  permit; cleanup sends only the original create and fresh cleanup returned
  by that same explicitly successful PG admission. Historical reads, lost
  replies and uncertain commits do not authorize another send. ACKs never
  publish Ready or release a slot; separate authenticated observations and
  typed PG commits remain required. No Application/automatic worker starts.
  The following Ready checkpoint adds a separate authenticated Completed
  readback and one PG transaction for allocation-bound completion history,
  Active and Ready. Exact repeats do not write another revision. Late or
  cancelled Running becomes OutcomeUnknown; existing Unknown is retained.
  A generic-writer guard protects the full sandbox projection, including
  after release and slot reuse, while allowing exact terminate/lease
  admission and the existing direct Creating-to-Cleaning path. The command
  composes this readback without an Application or automatic worker.
  This continuation connects typed cleanup Begin/Finish to lifecycle
  termination, including already-terminal reads before any generic shortcut.
  One read-only PG SELECT validates marker, allocation/retirement and the
  operation/sandbox tuple from the same snapshot. Accepted may attempt one
  fresh admission/send. Only that send's typed successful result may record
  a durable ACK in the existing retirement. Recovery preserves unacknowledged
  Running as Unknown before observing; Released cannot upgrade it. ACK plus
  independent exact Released, an unexpired operation and no cancellation are
  required for Running to succeed. Uncertain replies cannot grant another
  send, and late ACK cannot upgrade Unknown or a released allocation.
  Already-released Succeeded/Unknown reads leave the new slot occupant alone.
  Late/cancelled Running finishes as Unknown while observed termination and
  slot release commit together. New-host full race/vet, both Contract locks,
  read-only Docker observation and the real PG transactional component now
  pass; the PG run uses only a newly recovered locked image and synthetic
  Control, not physical execution or complete supply/release acceptance.
  The following lease continuation commits new Coding-v3 lease admission,
  Succeeded, idempotency and both events in one PG transaction. It rechecks
  deadline and the old lease under the row lock; replay adds no revision and
  never invokes Control. The locked Contract permits a 202 response carrying
  an already-completed operation. Typed historical readback runs before the
  generic terminal shortcut. Only an exact current older Accepted admission
  can be completed; superseded or unsupported old states stay unchanged.
  This does not renew runtime mutation authority or start an expiry worker.
  The next runtime-preflight checkpoint adds one read-only PG snapshot of
  marker, allocation/completion and lifecycle/lease state, with an explicit
  exec support checker in the held command. A higher prospective fence cannot
  advance PG state, and accepted termination immediately closes eligibility.
  This snapshot is not physical authority: exec still needs atomic current
  admission and its own closed Control protocol, receipts and recovery.
  The following no-permit exec-intent checkpoint adds a separate bounded PG
  ledger with same-row current-state checks and complete-request replay. Explicit
  initialization requires an unused atomic namespace; no startup upgrades it.
  Its history receipt cannot execute work or advance a fence. Physical exec still
  needs a new current-authority CAS, distinct Control permit/Unknown receipts,
  cleanup quiescence and observation/cancellation/result handling. This run's
  full race invocation failed on phase6security's unchanged default timeout;
  component/PG checks, review, vet, locks and compilation passed. The audit
  retains that failure separately from the passing same-seed standalone
  diagnostic; a passing full invocation for this checkpoint is not claimed.
  The 2026-10-10 [exec isolation checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-exec-namespace-isolation)
  closes the generic-exec bypass and reverse lifecycle operation-ID collision:
  enabled intent mode rejects generic exec reads/writes, and the same PG row
  lock protects both admission orders and typed read-only replay callbacks.
  It adds no physical authority or fence reservation. See the dated audit for
  this combination's validation, independently reviewed scope and remaining work.
  The following [descriptor and validation-cost repair](audits/product-phase-6-slice-6-startup.md#2026-10-10-controller-descriptor-and-validation-cost-repair)
  fixes the Controller test's duplicated FD ownership and removes redundant
  whole-Profile validation within a single unchanged-input call. Public
  entry points still fully revalidate each input. Independent review, the full
  default race run, vet, both Contract locks and Linux/arm64 compilation pass
  on the combined new-host source. The security package took 580.323 seconds,
  so default-timeout headroom remains limited; older failed runs stay recorded.
  This restores a passing source checkpoint, not physical exec authority or
  formal Slice 6 acceptance.
  The subsequent [PG exec fence reservation](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-pg-exec-fence-reservation)
  adds a reviewed, explicitly initialized unused-state-only ledger. Same-row
  admission requires the intent's complete request and current runtime tuple,
  then advances only the scope/lease fence pair. Two-pool lease/terminate races,
  corruption rejection and historical reads after slot reuse pass the real-PG
  component gate. These receipts grant no execution authority; a future
  physical dispatch still needs a fresh CAS. Distinct Control Unknown receipts,
  execution/cleanup quiescence and observe/cancel/result recovery remain the
  next complete source boundary. Full race/shuffle, vet, both locks and
  Linux/arm64 compilation pass on the frozen source. The audit separately
  preserves the first full invocation's unexplained test-process fallback
  timeout and the successful diagnostic/full recheck; no root-cause fix is
  claimed.
  The following [exec containment probe](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-exec-containment-mechanism-probe)
  reproduces detached descendants writing after the legacy direct-child TERM
  and wrapper exit. Separate PID 1 containers stop writing in the bounded
  observed window after SIGKILL/natural exit, using a locked PG process fixture,
  not a Coding candidate. No production architecture or exec authority is
  adopted by this experiment. Distinct Unknown receipts remain pending the
  reviewed containment/dispatch/cleanup design; the old canceller is unchanged.
  The next [resource and shared-scratch checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-exec-resource-and-shared-scratch-checkpoint)
  adds a prospective resident/command partition within one slot ceiling and a
  passing real Docker 32 MiB shared-tmpfs component test. The [private protocol
  plan](plan/product-v1-phase-6-coding-exec-protocol.md) preserves shared `/tmp`,
  requires a new resource/Profile mode, and specifies PG acceptance/occupancy
  plus Control Unknown, late-request closure and allocation cleanup ordering.
  This is still no physical dispatch: production partition/storage caps,
  inode/metadata bounds, locked Coding inputs and restart/cancel/release gates
  must be frozen and validated before adoption. Legacy plans/receipts and both
  public holds remain unchanged.
  The subsequent [execution-budget checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-execution-template-and-storage-budget-candidate)
  freezes an independently reviewed new template **candidate**, with separate
  resident/command/data/metadata allowances, 4096 scratch inodes and a 512 MiB
  Coding child storage budget inside the shared 1 GiB Control volume. The
  updated real scratch probe proves inode exhaustion/reuse on the local daemon.
  PG/Control durable quota consumers, new receipt namespace, other-scope
  allocation, actual Coding workload sizing and restart/release gates remain
  open. Arithmetic reservation is not dispatch permission.
  The next [private storage checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-private-storage-namespace)
  implements a new exclusive file namespace, class byte/object limits, exact
  restart inventory, state replacement peak and independent closure space.
  The held execution template is now explicitly v2 and includes its layout;
  the other 512 MiB remains unallocated with no write entry point. Darwin and
  Linux file-component checks and independent review do not prove a physical
  volume admission, new execution receipt, or PG-to-Control dispatch. A partial
  state/manifest commit stops rather than reconstructing authority. Complete
  new Profile/receipt/atomic claim composition and real workload gates remain
  the next boundary; both public holds remain closed.
  The [common Control state checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-common-control-execution-state)
  now consumes that file store with a held, package-private create/exec/retirement
  state machine. Durable Unknown, exact claim closure, monotonic fences and
  retirement share one state/owner; callbacks cannot clear occupancy. Typed
  four-volume completion uses current-state comparison. The subsequent
  [four-volume observer checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-four-volume-completion-observer)
  supplies a separate bounded read-only SDK collector with retained physical
  projections rechecked on receipt-v2 reopen. Synthetic positive observations,
  real Docker empty-scope rejection and Linux file-component checks do not
  prove a positive Coding workload or kernel scratch gate. The pinned arm64
  Coding image has been downloaded but not executed. The next
  [supply revalidation](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-image-supply-revalidation)
  verifies its original archive and signed provenance, but the fresh arm64 scan
  fails with 13 HIGH occurrences. The positive Coding gate remains held. A
  [separate candidate proposal](plan/product-v1-phase-6-coding-image-candidate.md)
  now has the user's candidate-only Go1.26.9 approval. Its separate clean-source
  Alpine3.23.6 candidates reproduce byte-for-byte on both platforms and scan
  with zero HIGH/CRITICAL, retaining one zlib MEDIUM each. Native arm64 diagnostic
  smoke and exact container cleanup pass, without formal four-volume admission.
  Development tools now use mise, with ordinary Go1.26.8 retained; image builds
  use Docker. Historical locks and production templates remain unchanged.
  See the [candidate audit](audits/product-phase-6-slice-6-startup.md#2026-10-10-repaired-coding-candidate-and-managed-tools).
  The subsequent [held binding component](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-candidate-template-and-receipt-binding)
  connects source-owned candidate records to a separate execution-template v3,
  internal receipt v3 and read-only observer; old v1/v2 state is not migrated.
  A historical scan hash is not current supply admission. The subsequent
  [candidate Profile/kernel-root component](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-profile-mode-and-kernel-root)
  adds an explicit v3 alternative to the full Profile field chain, derived
  storage binding and revised declared resource accounting. Mixed old/new modes
  reject. The Store checks its actual Linux root fd and live pathname mount ID;
  an ordinary unbounded Docker local volume is rejected without a marker.
  This is not physical admission: exact Docker volume/consumer identity,
  external exclusivity, stable hard quota, a final live inventory and positive
  four-volume scenarios remain required, followed by atomic PG claim and
  asynchronous mTLS dispatch. Both public holds remain closed.
  Remaining daemon-free runtime ports, source-bound images and real same-run gates
  are still open. These command paths are not live admission. See the dated
  [startup audit](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-coding-runtime-preflight)
  for new-host validation, limitations and preserved failures. See also the
  [exec intent checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-coding-exec-intent-ledger).

The qualification applies only to Provider revision
`170459266af5f4fad359ca8c63f2ae19741055c5`, external-caller revision
`b3ebcc783e5db20395e29b029e0eb55f7819b49b`, and the recorded Contract,
profile, artifacts, topology, and scenarios. Aggregate conformance,
multi-controller reliability, hostile multi-tenant isolation, HA, deployment,
and production readiness remain separate non-claims.

The Product Phase 1 result adds no implemented Product API, database migration,
public Gateway, Guest Agent, capability advertisement, deployment, or SLO
attainment claim. See
[`plan/product-v1-phase-1.md`](plan/product-v1-phase-1.md) for its exact output
and [`plan/product-v1-phase-2-provider-lifecycle.md`](plan/product-v1-phase-2-provider-lifecycle.md)
for the fixed nine-step Provider lifecycle closure plan. ADR 0048 and the
Step 1 audit and completion record include termination, reversible desired
state, lease renewal/expiry, resumable events, and terminal-session close; they
exclude resize and snapshot/restore from Phase 2. See
[`audits/phase-2-provider-lifecycle-completion.md`](audits/phase-2-provider-lifecycle-completion.md)
for the selected authority, release evidence, and exact non-claims.
The Phase 3 startup inventory, fixed slice order, and completion evidence are
recorded in
[`audits/phase-3-product-surface-startup.md`](audits/phase-3-product-surface-startup.md)
[`plan/product-v1-phase-3-product-kernel-terminal-files-web.md`](plan/product-v1-phase-3-product-kernel-terminal-files-web.md),
with the accepted standalone run in
[`audits/product-phase-3-standalone-completion.md`](audits/product-phase-3-standalone-completion.md).
Product Phase 4 startup scope and slice order are recorded in
[`audits/phase-4-product-browser-startup.md`](audits/phase-4-product-browser-startup.md)
and [`plan/product-v1-phase-4-browser.md`](plan/product-v1-phase-4-browser.md),
with the bounded release result in
[`audits/product-phase-4-browser-completion.md`](audits/product-phase-4-browser-completion.md).
Product Phase 5 startup findings, boundary decision, and fixed slice order are
recorded in
[`audits/product-phase-5-desktop-startup.md`](audits/product-phase-5-desktop-startup.md),
[`audits/product-phase-5-desktop-slice-2.md`](audits/product-phase-5-desktop-slice-2.md),
[`audits/product-phase-5-desktop-slice-3.md`](audits/product-phase-5-desktop-slice-3.md),
[`audits/product-phase-5-desktop-slice-4-candidate.md`](audits/product-phase-5-desktop-slice-4-candidate.md),
[`audits/product-phase-5-desktop-slice-4-publication.md`](audits/product-phase-5-desktop-slice-4-publication.md),
[`audits/product-phase-5-desktop-slice-5.md`](audits/product-phase-5-desktop-slice-5.md),
[`audits/product-phase-5-desktop-slice-6.md`](audits/product-phase-5-desktop-slice-6.md),
[`audits/product-phase-5-desktop-slice-7.md`](audits/product-phase-5-desktop-slice-7.md),
[`audits/product-phase-5-desktop-slice-8.md`](audits/product-phase-5-desktop-slice-8.md),
[`audits/product-phase-5-desktop-slice-9.md`](audits/product-phase-5-desktop-slice-9.md),
[`audits/product-phase-5-desktop-slice-10.md`](audits/product-phase-5-desktop-slice-10.md),
[`audits/product-phase-5-desktop-slice-11.md`](audits/product-phase-5-desktop-slice-11.md),
[`audits/product-phase-5-desktop-slice-12.md`](audits/product-phase-5-desktop-slice-12.md),
[`audits/product-phase-5-desktop-completion.md`](audits/product-phase-5-desktop-completion.md),
[`adr/0050-product-desktop-phase-5-boundary.md`](adr/0050-product-desktop-phase-5-boundary.md),
and
[`plan/product-v1-phase-5-desktop-development-unified-product.md`](plan/product-v1-phase-5-desktop-development-unified-product.md).
Product Phase 6 authority, ordering, startup gaps, and the first four slices are in
[`adr/0051-product-phase-6-production-hardening-order.md`](adr/0051-product-phase-6-production-hardening-order.md),
[`plan/product-v1-phase-6-production-hardening.md`](plan/product-v1-phase-6-production-hardening.md),
[`audits/product-phase-6-production-startup.md`](audits/product-phase-6-production-startup.md),
[`audits/product-phase-6-slice-1.md`](audits/product-phase-6-slice-1.md),
[`audits/product-phase-6-slice-2.md`](audits/product-phase-6-slice-2.md),
[`audits/product-phase-6-slice-3.md`](audits/product-phase-6-slice-3.md),
[`adr/0052-phase-6-executor-role-boundary.md`](adr/0052-phase-6-executor-role-boundary.md),
[`audits/product-phase-6-slice-4.md`](audits/product-phase-6-slice-4.md), and the
[`strict Slice 4 evidence manifest`](audits/product-phase-6-slice-4-evidence.json).
ADR 0053 defines default finalization versus explicit historical retained
verification, with Slice 4's immutable
[`closure record`](audits/product-phase-6-slice-4-closure.json).

See [`STATUS.md`](STATUS.md) for the complete evidence ledger and
[`qualification/external-caller-coding-shell-v1.md`](qualification/external-caller-coding-shell-v1.md)
for the exact qualification boundary.

## Start Here

Read this document after `AGENTS.md`, then verify the checkout before relying on
the snapshot:

```bash
git status --short --branch
git branch -vv
git rev-parse HEAD main origin/main
git log --oneline --decorate -8
```

Preserve uncommitted work. Do not reset, switch away from a dirty checkout, or
assume that a recorded evidence baseline is the current `HEAD`.

Use these sources in authority order:

1. The repository-owned MIT Provider Contract under `contract/`, including its
   Provider Calling Standard, OpenAPI, JSON Schemas, semantic rules, fixtures,
   Conformance Suite, and
   `compatibility/sandbox-runtime/contract.lock.json`, defines authorized wire
   behavior and caller obligations.
2. The independent Product Contract under `product-contract/` defines the
   target client-to-Product control protocol. It is Phase 1 design authority,
   not implementation or readiness evidence.
3. [`architecture.md`](architecture.md) and accepted
   [ADRs](adr/) define ownership, boundaries, delivery order, and release
   gates.
4. [`development.md`](development.md) and `AGENTS.md` define engineering and
   validation rules.
5. [Phase plans](plan/README.md) refine implementation slices without relaxing
   architecture gates.
6. [`STATUS.md`](STATUS.md) is the detailed evidence ledger. Code, Git state,
   and reproducible test or CI results must still support every status claim.

Start external integrations with the normative
[`Sandbox Provider Calling Standard`](../contract/specification/provider-calling-standard-v1.md).
The [`Provider Integration Guide`](platform-integration-profile.md) is a
non-normative implementation summary; the Contract resources and lock remain
authoritative.

When sources disagree, do not silently blend them. Apply the higher-authority
source, verify the implementation, and update the stale narrative document.

## System in One Page

`sandbox-runtime` is a backend-independent sandbox Provider and local runtime
control plane. The first intended compatibility profile is coding and remote
shell. Browser, desktop, snapshots, GPU, and stronger isolation remain optional
until their own Contract and evidence gates pass.

Three API surfaces must remain separate:

| Surface | Purpose | Ownership boundary |
| --- | --- | --- |
| Local `/instances` API | Local instance management over fake or Docker drivers | Internal implementation; its DTOs and state are not Provider wire models |
| Provider API v1 | mTLS/JWS-protected asynchronous Provider protocol | Repository Contract controls routes, documents, semantics, and projection |
| Product API v1alpha1 | End-user Workspace control plane | Independent Product Contract; Phase 6 Slices 1-2 add development and production-kernel listeners with real PostgreSQL, TLS 1.3 signed identity, separated database authority, empty/unavailable capability projection, and fail-closed runtime mutation; Slice 3 adds a separate Provider process, while Slice 4 adds bounded independent data-plane roles without yet composing public Product dispatch |

The calling service owns its business correlation records, desired business
state, tenant/user authorization, ProviderRevision selection, Artifact
publication, billing/accounting, aggregate operation ledger, and public Gateway
policy. It adapts to this repository's Contract; the Provider does not carry a
consumer-specific adapter.
The target Product is the calling service defined by ADRs 0042-0047. It owns
Workspace aggregates, user/Agent authorization, Product operations, outbox,
reconciliation, sessions, public Gateway policy, and catalogs. This repository
owns provider-local execution, durable Provider operations,
runtime/session resources, and bounded evidence. Provider storage references
and backend endpoints are never public artifact URLs or client endpoints.

Protected admission uses one caller trust domain per listener. The issuer is an
explicit exact value with no default or fallback; the Provider-instance
audience and Provider revision are local startup anchors rather than facts
accepted from the bearer or Admission Context. The listener freezes 1..32
issuer-scoped verification keys and its admitted URI SAN identities. One
listener does not currently support multiple issuers or consumers.

Dependencies point inward:

```text
Provider HTTP/mTLS/JWS transport
              |
              v
application policy and coordinators
              |
              v
repository and capability ports
              |
              v
runtime, persistence, session, and evidence adapters
```

Provider operations are asynchronous and preserve idempotency, attempts,
fencing, deadlines, cancellation, and unknown-outcome reconciliation. A
compatible coding/shell runtime must eventually expose stable guest paths
`/inputs`, `/workspace`, `/outputs`, and `/tmp`. Terminal clients receive only
an expiring opaque handoff; a Runtime Gateway resolves and proxies the internal
endpoint after its own authorization.

The default security posture is deny and fail closed. Do not expose backend
IDs, host paths, raw endpoints, daemon diagnostics, credentials, or secrets.
The existing Docker defaults and mTLS admission are useful component controls,
but they are not evidence of hostile multi-tenant isolation or production
readiness.

## Development Contract

- Keep transport, application policy, repositories, and runtime drivers in
  separate packages. Provider DTOs must not reuse local `instance` or backend
  engine structs.
- Preserve `context.Context` cancellation and deadlines for external work.
- Reject unknown, malformed, and oversized input before mutation when the
  Contract requires it. Unsafe production configuration must fail closed.
- Use narrow optional capability interfaces. Advertise a capability only when
  the complete configured dependency set and its named gate pass.
- Scope each change to one delivery slice. Ownership, public protocol,
  reliability, or security-boundary changes require an ADR and coordinated
  Contract review.
- Preserve unrelated worktree changes. Never turn local callbacks, fakes, or
  same-repository tests into external compatibility claims.

For Go changes, format with `gofmt` and run:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

For driver or lifecycle changes, also run the tagged Docker integration test in
an available Docker environment. For Contract metadata, DTO, Provider API, or
conformance changes, also run:

```bash
go run ./cmd/verify-contract -source-root .
runner_dir="$(mktemp -d)"
go build -buildvcs=true -o "$runner_dir/run-conformance" ./cmd/run-conformance
"$runner_dir/run-conformance" -source-root . -race -shuffle
```

The local Suite runner requires a clean VCS-built binary, records its revision
and Go version from build information, and executes a bounded read-only archive
of that revision. Every case declares an exact mapped-test count and requires
all matching tests to appear as distinct, started, non-skipped passes in `go
test -json`. The Runner rejects an explicit `GOROOT`, resolves Git once to a
single absolute executable path reused for verification and archive creation,
and records that the host OS, filesystem, initial Git selection, and Go and Git
executables remain trusted local inputs. `go run ./cmd/run-conformance` lacks
the required VCS settings under Go 1.26.5 and correctly fails. The separate
remote discovery prerequisites and command are documented in
[`compatibility/sandbox-runtime/README.md`](../compatibility/sandbox-runtime/README.md).

Record an unavailable environment separately from a failed test. Keep these
evidence tiers distinct: component, Contract projection, CI, Provider
admission, external caller E2E, aggregate conformance, multi-controller,
multi-tenant, deployment, and production readiness.

## Current Snapshot

The selected Product Phase 2 implementation snapshot is
`98995384c60a924f25ca58d3b7e561207bfa5be8`; lock-selection revision
`3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1` binds its exact Provider Contract
tree and E2E metadata. No remote CI result is assigned to these local release
revisions.

The latest remotely verified documentation baseline remains
`27081dfde4dfc726ba4df06d1f3b50012a04d2f2`. Core CI run `35204434771`
passed all six jobs, including the current Contract and clean VCS-built local
Suite, full race tests, vet, Docker integration, Browser provenance, and the
Ubuntu/macOS qualification-supervisor matrix. The detailed component ledger
below retains older per-gate commits and run IDs because those identify exact
historical evidence rather than the newest documentation commit.

The ADR 0038 calling-standard slice remains implemented. The current Contract
authority is revision `720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`, and a content-derived 71-case
local Suite. Product Phase 5 Slice 1 maps every case to executable repository
tests and keeps Desktop advertisement disabled. The historical Phase 2
60-case Runner, remote Runner, hosted CI, Product Phase 3/4, and external-caller
results retain their recorded identities and are not relabeled as current
runs. Product Phase 5 Slice 2 separately adds Product Desktop intent at
implementation `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`. Slice 3 adds
Provider-local Desktop authority and optional protected handlers at
`f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5`; neither slice changes the
Provider Contract identity or any historical result, and Slice 3 is not
production startup composition or capability advertisement.
The independently implemented caller result is instead the separate bounded
P2.7 qualification recorded above. Rotation remains operator-driven, and
protected/mutating remote conformance, aggregate conformance, multi-controller,
hostile multi-tenant safety, HA, deployment, and production readiness remain
outside the completed first-version claim.

This snapshot was audited on 2026-09-06 against browser Contract authority
`5096e71fb84fbec22aa3487a0e55a1b49602ab8b`, Provider projection baseline
`24b2e36485c334634e561009850d1905ec3115d5`, browser session implementation
`9a5d225f793f37ccafdac31c276ccbcb1bc862ad`, sandbox/provenance implementation
`6e02f1c22f489802b0b2c9f06f4a807d2e7c36e5`, Browser Docker adapter
`cd33ba35c59bba62c48d13c0dcd08aeef5d9a434`, Browser provenance verifier
`939055475f73b0023b3946172a2c40750a99c7ea`, Browser restricted-egress and
create-policy implementation `7e60340`, protected Browser transport
implementation `b8423f5`, caller-owned Browser Gateway implementation
`5aae2810c4957ec7abad7de0e67f9507d9543c81`, default-disabled Browser command
composition `66183b1f49b22c211e43c841d15383b745e89967`, Browser DNS compatibility
implementation `f760369dd4b71f507b15a2aecf988e98ca74854b`, Browser Gateway local
capacity implementation `7b062e6511f73b916dd18977041d83732e590088`, Browser
pre-upgrade edge implementation `44ea2eecc75752870d4e8580a75be26578dcd63a`,
Browser listener/TLS/HTTP implementation
`b8f89413cb34110793fa552ba1620f1529f6f416`,
Browser authenticated-capacity implementation
`997fb0db9d3517cf1c3e153217b1ac7305b4ebfd`, its co-located E2E lock
`49d1c20`, and hosted harness/evidence baseline
`6b01b75f0e1f6ca1c60f033f8d5bab3898720a3b`, plus Redis-compatible shared
capacity implementation `94345407c149eb095f27ac1c51f60fa38a16a4af`,
shared-capacity Provider baseline
`2ed5e689f68627c2d7c8e96cf903fc001ea4a546`, and local evidence
harness/Gateway source `ddbb2c4771a356bc3ab66295c93bef3b749e2c09`, plus hosted
shared-capacity harness/Gateway source
`de297e7d951881f8ed3792b4c3dd0553be87284c` and run `33949577876`, plus
durable exact-grant revocation component implementation
`c0a55d1e0a862f9e5a592abd27b1e25be3c85b3e` and earlier regression E2E
lock/harness baseline `59e08d542b05ad1a047f439f4ea72e82c8c37404`, plus durable-revocation
harness/Gateway source `e952ef9dabf4e9e6f2a984ce0c7944cb2bc569c7`, local run
`20260905T095109.569973000Z`, and hosted run `33959122456`, plus downstream CDP
fencing component and real-backend adapter integration implementation
`b4d41c9a32b4ccf39edaba3fb8bf5ad239c1f945`, downstream caller bootstrap
implementation `58488d70c0a43d68747ca6e14f81c56f1e23237a`, caller provisioning/process
implementation `8a1049bfa1d68bdd88c9df3ebd02c2c9ac0434b5`, local downstream-fencing
harness/run `550c7855704f22809e989ede0f67240033f320ba`/
`20260906T050213.016063000Z`, and hosted downstream-fencing harness/run
`2cadc534e54c6eacd37497887820a157a89585f5`/`34013982796`, plus fixed witnessed
v2 harness `059357cdd1f6f4ecd78ccbbaf9923add0fcd2230`, local run
`20260906T100233.295973000Z`, and hosted run `34026680591`, plus PostgreSQL
controlled-restore implementation `ffa40d643605e51d4ea1baebab1bd3f8bd710b5f`,
PR #47 merge `a0cddf40d07f9ad81b02d3eb028f141aeb424228`, and post-merge run
`34038556283`. The later main run `34069851741` at
`838d3bb2dea52c10fdc1ddf3136641709fedcb20` is the current canonical ADR 0036
run and passes the same 18/18 profile. Its independently inspected artifact is
`browser-postgres-controlled-restore-e2e-evidence-34069851741`, ID
`10000177842`, digest
`sha256:96817b74f3faabb0226d7dee1f2ac8128901865a3834f9bcadcaae6459b76032`.
Merge commit `a0cddf4` also passes repository CI `34038556281`,
Reference `34038556295`, Candidate `34038556284`, Browser `34038556297`,
shared-capacity `34038556314`, durable-revocation `34038556293`,
downstream-fencing v1 `34038556291`, downstream-fencing v2 `34038556299`, and
PostgreSQL witness `34038556301`. These remain distinct evidence tracks.
The Contract slice authorizes an atomic browser-only capability shape,
create/session/handoff schemas, protected admission bindings, opaque reference
security, operation/usage projection, and 10 new Suite cases. The browser image
component is implemented under
`profiles/browser/image/`. The Provider-local browser
session/application/reference/usage component is implemented under
`provider/browser/`. ADR 0020 and `provider/browser/driver/docker` add a
fail-closed Docker adapter for that runtime port. ADR 0023 and
`b8423f5` add protected Browser open/handoff routing, admission correlation,
bounded error projection, and opaque response projection through a narrow
application port. ADR 0024 and `5aae281` add a separate caller-owned Browser
Gateway component with exclusive Browser identity/reference binding, explicit
authorization/revocation/audit/WebSocket-admission dependencies, bounded
reconnect, and RFC 6455 CDP framing. ADR 0025 and `66183b1` add an explicit,
default-disabled Browser Provider graph. ADR 0026 and the co-located harness add
a separate Browser-only reference stack and black-box caller. ADR 0027 and
`7b062e6` add non-blocking process-local total/per-session connection capacity
before revocation and Provider resolution. ADR 0028 and `44ea2ee` add
process-local global connection/fixed-window request control before Browser
WebSocket admission and upgrade. ADR 0029 and `b8f8941` add a separate bounded
accepted-connection listener, frozen server-auth certificate, TLS
1.3/HTTP/1.1-only policy, header/time limits, and context-aware lifecycle for
the reference Gateway. ADR 0030 and `997fb0d` add an authenticated-capacity
port after exact grant binding, typed loss/unavailability events, bounded
release, stable revocation/expiry/capacity termination priority, and a
process-local memory reference with atomic global, tenant, and session
accounting. Browser composition requires the port. ADR 0031 and `9434540` add
a Redis-compatible implementation with one bounded atomic capacity record,
server-time leases, renewal, TTL reclamation, and stale-owner fencing. The
production command still exposes no public Browser Gateway route and does not
advertise Browser; only the reference stack advertises the exact locked Browser
profile.

The Contract verifier and root race/shuffle and vet gates pass against the
current projection. E2E race/shuffle passes except for its intentional clean
parent-checkout test, and E2E vet and all other lock tests pass. Clean Docker
reference run `20260907T044611.598221000Z` at harness
`b8d4829` and Provider baseline `af8a505` passed 15 initial and 5
process-reconstruction/resume coding/shell scenarios over real mTLS/JWS HTTPS,
WebSocket, separate caller/reference-stack processes, and Docker. Its manifest
SHA-256 is `60bda2dae83053db447417cea5c5e38d4798e1e90b91fbb5cfc75d2991c6993e`
and it pins locally built linux/amd64 runtime digest
`sha256:60baefac927a0a77743aeca268b271b62b07079f31521f98fd3a4cb33474a999`.
This is same-repository reference evidence; it does not execute the then-current
50-case
Suite or qualify an independently implemented caller. An earlier clean
reference run `20260904T081521.464863000Z` passed 15 initial and 5
process-reconstruction/resume coding/shell scenarios over real mTLS/JWS HTTPS,
WebSocket, separate caller/reference-stack processes, and Docker. Its manifest
pins Provider `44ea2ee`, harness `249cdd4`, the Contract, and linux/amd64 runtime
image digest
`sha256:bcd5dbff8b2d108ee7dab464a85ee7d39ef74a8616a6af73a94ebb10ff8eaf75`.
This is reference coding/shell evidence only; it does not exercise browser.
Hosted Reference E2E run `33854020874` passed the same 15 initial and 5
reconstruction/resume coding/shell scenarios against harness/Provider lock
`e7e7f03`/`44ea2ee`. Its artifact
`reference-e2e-evidence-33854020874` has digest
`sha256:220650f1b61b0297ec445ded03bf3a15870514a9482c9e55012ddfba8ae0da2d`.
This remains reference coding/shell evidence only and contains no browser
scenario.

The explicitly named `agent-platform-candidate` mode passed local run
`20260904T081706.648122000Z` against harness/Provider lock
`249cdd4`/`44ea2ee`: 15 initial and 5 resume coding/shell scenarios over
separate `platform-caller` and `reference-stack` processes with candidate
shadow/selection/rollback/drain policy and state reconstruction. Hosted
workflow run `33854020947` passed the same scenario set against
harness/Provider lock `e7e7f03`/`44ea2ee`. Its artifact
`platform-candidate-e2e-evidence-33854020947` has digest
`sha256:48cbe44c433e5b3a858a2691fe1f736469b2e8d71228541f2bdfcc4aab1c15b1`.
Local and hosted candidate results do not represent browser evidence, real
Veronica, aggregate conformance, hostile multi-tenant security, deployment, or
production readiness.

Hosted Browser Reference E2E run `33854020809` passed all 12 initial and 5
process-reconstruction scenarios against harness/Provider lock
`e7e7f03`/`44ea2ee`. The path uses separate reference-stack and black-box caller
processes over mTLS/JWS HTTPS and a caller-owned WebSocket Gateway, the exact
signed `linux/amd64` Browser image, real GitHub OIDC/Sigstore provenance,
restricted egress, durable state, duration usage evidence, and exact resource
cleanup. The capacity scenario holds one CDP connection, rejects a second
same-session grant without disrupting the first, and connects a replacement
after release. The edge scenario sends 16 authenticated wrong-Origin requests,
observes ordinary `403` plus generic pre-upgrade `429` with bounded
`Retry-After`, and recovers. Artifact
`browser-reference-e2e-evidence-33854020809` has digest
`sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`.
Its inspected run directory `20260904T083407.182245415Z` pins the Contract/tree,
48-case Suite, signed Browser image, and `linux/amd64`. Both reports contain
only passing scenarios. The 20-record metadata-only Gateway audit has six
`authorized`, six `connected`, four `client_closed`, and one each
`capacity_rejected`, `denied`, `expired`, and `revoked`; it contains no
`grant-browser-edge-*` identity, endpoint, token, or CDP payload. This closes
the process-local post-authorization capacity and pre-upgrade Browser service
scenarios within the Browser reference external-caller gate only.

Clean local Browser run `20260904T080946.250607000Z` then passed 12 initial and
5 process-reconstruction scenarios against harness/Provider lock
`249cdd4`/`44ea2ee` on `linux/arm64`. ADR 0028 adds a process-local global
connection and fixed-window request gate before Browser WebSocket admission and
upgrade. The added black-box scenario sends 16 authenticated wrong-Origin
requests, observes ordinary `403` plus generic pre-upgrade `429` with bounded
`Retry-After`, and observes ordinary `403` again after the window. The
20-record Gateway audit retains the six `authorized`, six `connected`, four
`client_closed`, and one each `capacity_rejected`, `denied`, `expired`, and
`revoked` events, with no `grant-browser-edge-*` identity.
At that baseline, listener/TLS/HTTP-layer limits remained open, together with
partition-aware shared or distributed capacity, durable distributed revocation,
production advertisement, generic-consumer interoperability, aggregate, multi-controller,
hostile multi-tenant, deployment, and production gates.

ADR 0029 and implementation `b8f8941` then add the bounded public TLS edge.
Clean local Browser run `20260904T091156.303717000Z` passed 13 initial and 5
process-reconstruction scenarios against harness/Provider lock
`35cf068`/`b8f8941` on `linux/arm64`. Hosted Browser run `33857739150` passed
the same 13+5 set against harness/Provider `7a20d9d`/`b8f8941` on
`linux/amd64`. The new black-box scenario rejects TLS 1.2, negotiates TLS 1.3
with HTTP/1.1, rejects slow and oversized request headers before the handler,
holds the configured accepted-connection limit, and recovers after release.
Artifact `browser-reference-e2e-evidence-33857739150` has digest
`sha256:94bcdfa53b667d4a6bc17fd6714cc9895e8402b830b8c6425c604c835f9228f`;
its inspected run directory is `20260904T091942.992885726Z`. Its 20-record
Gateway audit retains the prior type counts and contains no edge grant, token,
endpoint, credential, CDP, or payload field. This closes the listener/TLS/HTTP
component and Browser reference-caller scenario only. Authenticated
partition-aware shared or distributed capacity, durable distributed
revocation, production storage/configuration and metrics, production
advertisement, generic-consumer interoperability, aggregate, multi-controller, hostile
multi-tenant, deployment, and production gates remain open.

ADR 0030 and implementation `997fb0d` then add the post-binding
authenticated-capacity port and process-local global/tenant/session memory
reference. Hosted repository CI `33940332882` passes `provider-contract`,
`test`, `browser-provenance`, and `docker-integration`. Hosted Reference,
Candidate, and Browser runs `33940332897`/`33940332881`/`33940332911` all pin
harness `6b01b75`, Provider `997fb0d`, the Contract/tree, and 48 cases.
Reference and Candidate pass their separately named 15+5 coding/shell sets;
their artifacts have digests
`sha256:c5294520236200c06597bcc383455b9a74cb3668557cce313ab7e4dab0af0537`
and
`sha256:5fad63cd7dfc863af83faf2e5324529852cc8b741deeac5414f12d5fd0dd26f5`.
Browser passes 13+5 on `linux/amd64`; artifact
`browser-reference-e2e-evidence-33940332911` has digest
`sha256:f4133967b6e573c701b82c72dc4d101febd4e6b28199e188fa0c8db049bff9ae`.
Its active contention scenario reaches the authenticated memory authority, and
the 20-record metadata-only Gateway audit retains six `authorized`, six
`connected`, four `client_closed`, and one each `capacity_rejected`, `denied`,
`expired`, and `revoked`. This is a single reference Gateway process, not a
shared backend or two-Gateway-process capacity result. TTL/renewal, crash
reclamation, stale-owner fencing, durable distributed revocation, real Agent
Platform, aggregate, multi-controller, hostile multi-tenant, deployment, and
production gates remain open.

ADR 0031 and implementation `9434540` then add the Redis-compatible shared
capacity adapter, followed by the WebSocket close and deterministic stale-lease
harness and edge-timing corrections through `ddbb2c4`. Clean local evidence
`e2e/evidence/shared-capacity/20260905T061037.558537000Z` passes all 10 scenarios
on `linux/arm64` through two independent Gateway OS processes and a real pinned
Valkey authority. It covers cross-process global/tenant/session contention,
unaffected-tenant service, renewal beyond three lease TTLs, confirmed loss,
Gateway crash reclamation, stale-owner fencing, renew/release cleanup,
retained-store outage failure closure and recovery, and evidence sanitization.
Shared-capacity rejection occurs after WebSocket `101` and is observed as a
normal `1000` close, not the pre-upgrade limiter's HTTP `429`. The manifest pins
harness/Gateway source `ddbb2c4`, Provider baseline `2ed5e68`, policy fingerprint
`1b29321807530907a8407cd6d33bdefbbb980fd7cb0b297592181a2333a8bacd`, Valkey
index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`,
and arm64 child
`sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e`.
Valkey provenance is explicitly not established. The Contract revision/tree
and 48-case Suite are pinned as metadata with `exercised=false`; Provider API,
real Browser/CDP, image provenance, restricted egress, artifact/usage, HA,
durable distributed revocation, downstream fencing, Provider multi-controller,
hostile multi-tenant, generic-consumer interoperability, deployment, and production gates are
not established by this local run.

Hosted Browser Shared Capacity E2E run `33949577876` independently passes the
same 10 scenarios on `linux/amd64` against harness/Gateway source `de297e7` and
Provider baseline `2ed5e68`. Artifact
`browser-shared-capacity-e2e-evidence-33949577876` has GitHub digest
`sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`;
its downloaded run directory `20260905T062246.271594332Z` contains exactly the
manifest, report, two audit logs, and two observation logs. All 10 report
entries pass. The combined audits contain 22 `authorized`, 22 `connected`, 18
`client_closed`, five `capacity_rejected`, two `capacity_lost`, and two
`capacity_unavailable` records; the observations contain 22 `resolve` and 22
`dial` records. The manifest pins the same Contract/tree/48-case metadata with
`exercised=false`, the same Valkey index, amd64 child
`sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478`,
and `provenance_not_established=true`. This is hosted Gateway/Valkey
shared-capacity evidence only; it does not exercise Provider API, real
Browser/CDP, image provenance, restricted egress, Provider artifact/usage,
HA/failover, durable distributed revocation, downstream fencing, Provider
multi-controller, hostile multi-tenant, generic-consumer interoperability, aggregate,
deployment, or production behavior.

ADR 0032 and implementation `c0a55d1` then replace the split revocation
check/watch with one exact-grant level-triggered watch, cancel blocked Provider
resolution and dial work when the authority terminates, and add a
Redis-compatible retained-tombstone source/writer. The adapter verifies an
immutable policy, hashes namespace and grant identities, uses Redis server time
to bound grant lifetime and tombstone expiry, preserves the greatest expiry
under duplicate or out-of-order revoke, polls within bounded operations, and
fails closed on malformed state or authority loss. Focused/full race-shuffle,
vet, Contract verification, the unchanged 48-case Suite, and the tagged real
pinned-Valkey component integration pass locally. This establishes Gateway
revocation port semantics plus one retained-backend adapter component only.

Historical E2E lock `59e08d5` pins Provider `c0a55d1`. Its local Browser run
`20260905T080015.795386000Z` passes 13+5 scenarios, Reference run
`20260905T080530.577843000Z` and Platform Candidate run
`20260905T080623.861033000Z` each pass 15+5, and shared-capacity run
`20260905T080725.227680000Z` passes 10/10 on `linux/arm64`. These are regression
evidence within their existing names: Browser still uses one process-local
memory revocation authority, and shared capacity does not exercise revocation.
Harness/Gateway source `e952ef9` now supplies the separate durable-revocation
runner. Local `linux/arm64` run `20260905T095109.569973000Z` and hosted
`linux/amd64` run `33959122456` each pass all seven locked scenarios through
two independent Gateway OS processes, two independent black-box caller
processes, an independent revoker/control process, and the same retained Valkey
authority. They prove active and pre-resolution revocation, restart retention,
exact-grant scope, outage failure closure, recovery without resurrection,
bounded propagation, and sanitized evidence. The hosted artifact has digest
`sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`.
Contract/tree/48 cases are metadata with `exercised=false`; the fixture is not
a real Browser/CDP path, and downstream CDP fencing remains a separate later
ADR and gate.

Hosted pre-ADR0033 repository CI `33955437033` passes at repository revision
`c7fe24d`. Reference, Candidate, Browser, and shared-capacity runs
`33955436969`, `33955437046`, `33955436984`, and `33955436968` pass with harness
`c7fe24d` locked to Provider `c0a55d1`.
Downloaded artifacts pin the unchanged Contract/tree/48 cases and contain only
passing 15+5 Reference, 15+5 Candidate, 13+5 Browser, and 10/10 shared-capacity
reports. Their GitHub digests are recorded in `STATUS.md`. Browser still uses
the process-local memory revocation authority, while shared capacity still does
not exercise revocation, so these hosted runs also do not close ADR 0032's
independent caller gate.

The later dedicated hosted run `33959122456` is the separately named ADR 0032
caller gate; it must not be conflated with those four regression tracks.

ADR 0033 and implementation `b4d41c9` then add narrow downstream action-fence
ports, a Redis-compatible exact-member/session-high-water authority adapter, a
private ingress component that serializes complete CDP actions, and explicit
fail-closed Browser composition. Targeted and full race/shuffle tests, vet,
Contract verification, the unchanged locked 48-case Suite, and tagged real
integration against pinned Valkey index
`sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
pass. Local run `20260906T050213.016063000Z` at harness `550c785` additionally
passes all 13 ADR 0033 external-caller scenarios on `linux/arm64` through two
Gateway processes, two independent mTLS/JWS caller processes, one authenticated
unique ingress, retained Valkey state, and signed real Chromium. This closes
the local named caller gate; hosted run `34013982796` passes the same 13
scenarios on `linux/amd64` and closes that platform-specific caller gate. Its
artifact digest is
`sha256:9c00f3ba184e82d7eff661b831c05c1bdf331fa41caf2d8bbb3353168ab155b0`.
The Contract/tree/48-case identity is pinned, but the Suite is not exercised.

ADR 0034 then adds a separately selected v2 action-fencing component. One
bounded permanent Redis hash detects missing or malformed retained session
history, and an independent sequence/token witness rejects a Redis action state
restored behind it. The included Darwin/Linux `0600` file witness is
single-process component evidence and is valid only outside the Redis
snapshot/restore domain. Local focused/full race-shuffle, vet, Contract
verification, the unchanged 48-case Suite, and tagged integration against the
same pinned Valkey index pass. The existing downstream caller results still use
ADR 0033 v1, so neither prior run is deletion/restore evidence. A separately
locked 18-scenario v2 real-Chromium runner is implemented with an independent
file witness and orchestrator-only Redis fault credential. Clean local run
`20260906T100233.295973000Z` at fixed harness `059357c` passes all 18 scenarios
on `linux/arm64`, including retained-field and complete-state deletion,
restored-old snapshot rejection with the same numerical capacity fence, witness-adapter
reconstruction, exact one-ahead recovery, other checkpoint mismatch rejection,
and proof of no new upstream dial before the rejected actions. Its exact five
`0600` files pass cleanup and sanitization. This closes only the local ADR 0034
caller gate. Hosted run `34026680591` at the same checkout independently
passes the same 18 scenarios on `linux/amd64`. Its inspected artifact contains
evidence directory `20260906T101111.796974798Z` with exactly five sanitized
files; artifact ID `9987350368` has digest
`sha256:3e68f1c4b5bd74e0ae0ff0fde2c9ffefc63852cf9fc82b3019bedfb228bf2c9a`.
This closes only the hosted ADR 0034 caller gate; the Suite remains unexercised.
Production witness/storage, Valkey provenance/HA/failover, production
metrics/configuration and topology, deployment, multi-controller, hostile
multi-tenant, generic-consumer interoperability, aggregate conformance, and production
readiness remain unproved.

ADR 0035 now adds a PostgreSQL production-candidate witness adapter and strict
read-only `VerifyRestoredState`. Rows are isolated by both the private capacity
namespace digest and witnessed-v2 policy digest; mutations use atomic
conditional updates, force primary-local synchronous commit, preserve bounded
contexts, and redact database detail. The repository includes an explicit
migration, column-scoped runtime grants, real PostgreSQL/Redis integration
tests, and a separate workflow. Local full race/shuffle, vet, Contract
verification, the unchanged 48-case Suite, and the pinned-Valkey strict
one-ahead non-mutation case pass. Hosted workflow run `34031784793` at
implementation `3ff58dc` passes the exact migration, runtime and denied roles,
concurrent CAS/reconnect, missing and malformed state, bounded pool starvation,
and combined pinned-Valkey rollback cases against real PostgreSQL. Its initial
tag pull resolved PostgreSQL digest
`sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`,
which the workflow now pins. The local service remained unavailable. This is
not production or HA evidence; independent failure and backup domains, server
provenance, both stores' HA/failover, deployment, correlated rollback, and
deployment-owned controlled ingress operations remain open.

ADR 0036 now implements a separately locked same-runner operational reference
for the controlled ingress sequence. Its 18-scenario runner retains the first
ten real-Chromium fencing scenarios, stops both Provider/private-ingress
listeners, proves the live Gateways have no alternate downstream path, restores
an older Redis snapshot, and requires strict `VerifyRestoredState` to reject it
without advancing PostgreSQL or opening a listener. It then restores the exact
current Redis state, verifies without mutation, resumes the listeners, and
performs a real-CDP read and write. The runner uses an orchestrator-only Redis
restore credential and a PostgreSQL runtime role available only to the
orchestrator and Provider/private-ingress process. The latest canonical
`linux/amd64` main run is `34069851741` at
`838d3bb2dea52c10fdc1ddf3136641709fedcb20`; all 18 scenarios pass. Its
independently inspected artifact
`browser-postgres-controlled-restore-e2e-evidence-34069851741` contains
evidence directory `20260907T002737.609312407Z` with exactly five sanitized
files; the report is 18/18, and the manifest records three ingress
reconstructions, every cleanup and sanitization flag true, no file-witness v2
field, PostgreSQL restore evidence, and an unexercised Contract Suite. Artifact
ID `10000177842` has GitHub digest
`sha256:96817b74f3faabb0226d7dee1f2ac8128901865a3834f9bcadcaae6459b76032`.
This closes only the hosted same-runner ADR 0036 operational reference gate.
The lock and manifest record `same_runner=true` and
`independent_failure_domain=false`; this adds no independent host, storage,
backup, operator, HA, deployment, or production evidence.

Intermediate hosted run `34025787520` at documentation checkout `ef63be4`
failed in the restore-control verification rather than the fencing behavior.
The helper compared post-`RESTORE` hash `DUMP` bytes with the original dump,
although that binary encoding is not a canonical logical hash representation.
Fix `059357c` keeps real `DUMP`/`RESTORE` injection and instead compares Redis
type, logical string/hash/zset content, missing-key state, and TTL semantics.
The fresh local and hosted runs above establish the fixed-harness evidence.

ADR 0018 records the original reproducible browser image component, while ADR
0019 requires the current `sandbox.runtime/browser-image/v2` sandbox posture
and signed publication. The image has no `--no-sandbox` path and binds a
fail-closed Chromium seccomp profile with digest
`sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`.
Local arm64 and amd64 integration runs returned Chromium `151.0.7922.109` over
loopback, found a sandboxed zygote, and retained the numeric user, read-only
root, drop-all, no-new-privileges, network-none, mount, and resource controls.
Manual publication run `33724368530` passed both native-architecture gates and
published
`ghcr.io/shell-echo/sandbox-runtime-browser@sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`
under tag `sha-58ed0093816d3daa3000750013b8e5991ef4bcf7`. Attestation `44912296`
binds the GitHub OIDC/Sigstore signer to this repository, workflow, source
commit, and hosted runner, and a constrained `gh attestation verify`
invocation succeeded independently. Independent registry inspection found
exactly `linux/amd64` and `linux/arm64/v8` descriptors and no extra manifest.
This closes the exact browser image sandbox/provenance publication gate. No
Provider route, Gateway composition, advertisement, or caller scenario is
implied by the publication evidence.

ADR 0020 and the Browser Docker adapter machine-bind that exact publication,
the checked-in seccomp profile, numeric identity, bounded stable guest mounts,
finite resources, durable private allocation state, and a fresh non-TTY relay
to container-loopback CDP. Focused/full race-shuffle, vet, Contract verification,
the unchanged 48-case Suite, and the tagged Docker driver matrix pass locally.
The live Browser case deliberately uses `network=none`; it proves private CDP
discovery, RFC 6455 upgrade, and `Browser.getVersion` only, not restricted
egress or complete runtime startup. The public adapter still requires
provenance verification and restricted-network implementations and fails
closed without them. ADR 0021 and `provider/browser/provenance/ghcli` provide
the real provenance-verifier component. It pins and
rehashes an operator-supplied `gh` executable, verifies the immutable GHCR
bundle against exact GitHub OIDC/Sigstore identity and signed statement fields,
bounds output and environment inheritance, and preserves cancellation. Its
tagged live GHCR integration passes locally. ADR 0025 wires the exact verifier
only inside the default-disabled Browser graph.

ADR 0022 and implementation `7e60340` add the restricted-egress Gateway process,
Docker provisioner, and immutable lifecycle/create-policy binding. Each
allocation receives an internal bridge; the Browser has only that network and
the Gateway private IP as DNS, while the Gateway has that bridge plus one
explicitly owned uplink. DNS, HTTP Host, TLS SNI, resolved public-address,
image/container/network identity, policy digest, lease, and restart checks fail
closed. The original combined local tagged integration passed allowed
HTTP/HTTPS navigation, denied unlisted and metadata targets, reconstruction,
and exact cleanup. Implementation `f760369` additionally accepts only zero
additional DNS records or one bounded RFC 6891 EDNS0 OPT record; malformed,
repeated, non-OPT, wrong-version, unsafe-flag, and oversized forms remain
rejected. The current local tagged rerun reached the real provenance verifier
but timed out there after 120 seconds, so it is recorded as unavailable external
provenance rather than a passing or failing network scenario. Hosted Browser
run `33838215924` independently passes the complete restricted-egress scenario
on `linux/amd64` with this fix.

ADR 0023 and `b8423f5` compose the two protected Browser handlers behind
existing mTLS/JWS/admission controls. ADR 0024 and `5aae281` compose the
caller-owned Browser Gateway boundary with exclusive terminal/Browser identity,
exact endpoint binding, metadata-only audit, bounded reconnect/revocation, and
RFC 6455 validation. Caller authorization, revocation, recording, WebSocket
admission, and reconnect policy remain explicit dependencies. ADR 0025 and
`66183b1` bind those Provider-local runtime dependencies into a fail-closed,
default-disabled command graph with durable recovery and cleanup. It still adds
no Provider-owned user authorization, production Browser advertisement, or
public Browser Gateway. ADR 0026 and `79fee2b` supply those caller-owned policies
only in a separate reference deployment and first proved the complete 10+5
Browser external-caller path in hosted run `33838215924`. ADR 0027 and
`7b062e6` add process-local connection capacity; capacity harness `28a9a5e` and
hosted run `33846603547` add its active rejection/release scenario without
changing the production advertisement boundary. ADR 0028 and `44ea2ee` add the
process-local pre-upgrade connection/rate gate, and harness `249cdd4` proves its
rejection, recovery, and Gateway-audit exclusion locally; hosted run
`33854020809` passes that 12+5 baseline. ADR 0029 and `b8f8941` add the bounded
TLS listener/HTTP component; harness `7a20d9d` and hosted run `33857739150`
pass its 13+5 Browser reference scenarios.

The internal Block manifest foundation is available under `blocks/` with ADR
0016 and plan `block-manifest-loader.md`. It is a strict, bounded local
configuration registry only; it does not advertise Provider capabilities,
execute blocks, or establish browser/desktop, deployment, or production
evidence.

P4 authority planning is recorded in ADR 0017 and
[`plan/p4-optional-profiles.md`](plan/p4-optional-profiles.md). Browser Contract
authority and Go projection are locked; ADR 0018/0019 and run `33724368530`
provide exact amd64/arm64/v8 sandbox and signed publication evidence. ADRs 0020
through 0024 cover the Provider-local runtime, provenance, restricted egress,
protected transport, and caller-owned Browser Gateway components. ADR 0025 and
`66183b1` compose the default-disabled Provider graph; ADR 0026 defines the
independent reference caller. ADR 0027 and `7b062e6` add process-local Gateway
capacity, and harness `28a9a5e` exercises its original 11+5 hosted scenario.
ADR 0030 and `997fb0d` add the authenticated-capacity port and process-local
global/tenant/session memory component. E2E lock `49d1c20` passes all three
clean lock checks. Hosted CI `33940332882` and Reference/Candidate/Browser runs
`33940332897`/`33940332881`/`33940332911` pass against harness `6b01b75` and
Provider `997fb0d`. ADR 0031 and `9434540` add the Redis-compatible adapter;
local run `20260905T061037.558537000Z` passes its separate 10-scenario
real-Valkey, two-independent-Gateway black-box gate against harness/Gateway
source `ddbb2c4` and Provider baseline `2ed5e68`. Hosted run `33949577876`
passes the same 10-scenario gate on `linux/amd64` against harness/Gateway source
`de297e7` and the same Provider baseline.
ADR 0032 and `c0a55d1` add exact-grant level-triggered revocation port and
real-Valkey adapter component evidence. Historical E2E lock `59e08d5` passes local
Browser 13+5, Reference/Candidate 15+5, and shared-capacity 10/10 regressions;
none is the separately required two-Gateway/independent-revoker revocation
caller gate. Pre-ADR0033 hosted CI `33955437033` and four regressions also pass
against harness `c7fe24d` and Provider `c0a55d1`: Reference `33955436969`,
Candidate `33955437046`, Browser `33955436984`, and shared capacity
`33955436968`. They do not expand those boundaries.
Separate harness/Gateway `e952ef9`, local run
`20260905T095109.569973000Z`, and hosted run `33959122456` pass the seven-case
durable-revocation caller gate on arm64 and amd64. Its Contract identity is
unexercised metadata and its private echo path is not Browser/CDP.
ADR 0033/`b4d41c9` subsequently passes targeted/full race-shuffle, vet, Contract
verification, the unchanged locked 48-case Suite, and tagged pinned-Valkey
integration for its downstream CDP fencing component and real-backend adapter.
Implementation `58488d7` then wires Provider bootstrap into each persistent
downstream caller OS process. The dual-process test gives each caller a distinct
mTLS/JWS Controller identity, reconciles its own capability/create/operation/
sandbox/Browser-session/handoff chain, binds the opaque handoff only in private
process state, and confirms both processes remain in the JSONL control loop.
Implementation `8a1049b` adds the correlated FD 3/4/5 request, private endpoint
envelope, and exact final-configuration handoff; strict bounded EOF-framed JSON;
fixed direction validation and close-on-exec setup; canonical live expiry checks;
at-most-once delivery; cancellation, failure, and natural-exit cleanup; a
fail-closed parent process manager with kill plus bounded wait; and the full Contract handoff-reference
grammar in `gatewaystack`. FD5 delivery is not child acceptance; a correlated
JSONL response establishes readiness. FIFO type validation cannot distinguish a
named FIFO from an anonymous pipe, so the `os.Pipe` launcher is trusted. The
Contract has no Browser-session termination mutation, so handshake failure does
not prove Provider resource cleanup. These remain process/component boundaries.
Runner implementation `a2b82b0` and corrections through harness `550c785` then
compose the complete local topology. Clean run
`20260906T050213.016063000Z` passes 13/13 on `linux/arm64`, including stale
action rejection, higher-fence replacement, terminal closure without
reconnect, outage recovery, unaffected scopes, retained high-water across
ingress reconstruction, bypass exclusion, cleanup, and sanitization. The
Contract identity is pinned and six Provider routes are exercised, but the
48-case Suite remains unexercised (`suite_exercised=false`).
Hosted checkout `2cadc53` passes repository CI `34013982778`, Reference
`34013982794`, Candidate `34013982784`, Browser `34013982785`, shared-capacity
`34013982786`, durable-revocation `34013982798`, and downstream-fencing
`34013982796`. Downloaded downstream artifact
`browser-downstream-fencing-e2e-evidence-34013982796` contains evidence
directory `20260906T052710.781616339Z` with exactly five sanitized files; its
report passes 13/13 and its manifest pins the required amd64 image identities,
topology, and cleanup state.
ADR 0028 and `44ea2ee` add process-local pre-upgrade connection/rate control;
hosted run `33854020809` passes the combined 12+5 Browser caller against harness
`e7e7f03`. ADR 0029 and `b8f8941` add listener/TLS/HTTP bounds; hosted run
`33857739150` passes the 13+5 Browser caller against harness `7a20d9d`.
ADR 0034 separately passes its witnessed v2 deletion/rollback-detection
component and pinned-Valkey adapter gates. It is not selected by this v1 caller
topology. The separately locked v2 caller topology passes its 18-scenario local
`linux/arm64` gate in run `20260906T100233.295973000Z` at harness `059357c`;
hosted run `34026680591` passes the same 18 scenarios on `linux/amd64` at the
same checkout. Its Contract identity is pinned while the Suite remains
unexercised. Production Browser advertisement/public Gateway and v2
private-ingress deployment, a production independent witness, controlled
restore operations, Valkey provenance and HA/failover consistency, remaining
profile-specific security and concurrency, aggregate, multi-controller,
multi-tenant, deployment, and production gates remain separate and open.

Contract identity:

- namespace: `urn:shell-echo:sandbox-runtime:provider-v1`
- version/license: `1.0.0` / MIT
- revision: `720ad15c343e71f36615dc4499edd5e764178bca`
- Contract tree: `343ffde0819207cf99c005096c336735dd33a735`
- manifest digest:
  `sha256:483111511a588b41bd40d3fef686f0b21f465bb65d3215450ebb2ccf37a5de89`
- OpenAPI digest:
  `sha256:5a3da5d239f83e94eff09fc75438755f834e77bce8cd1c0f91c25055bf0cba2a`
- semantic-rules digest:
  `sha256:7953d05e65f00c68e0428b6dd4fcebef1af103f2cab2fa6b214905b2496c8785`
- local Suite: `sandbox-provider@1.0.0`, profile
  `sandbox-runtime-provider-v1`, `repository-go-test`, 71 cases, digest
  `sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`
- remote Suite: `sandbox-provider-remote@1.0.0`, profile
  `sandbox-runtime-provider-remote-discovery-v1`, `remote-http-black-box`, 6
  cases, digest
  `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0`

| Phase | Verified maturity | Open gate |
| --- | --- | --- |
| P0 | Passed: repository-owned MIT Contract migration and lock | Retain lock and projection regression |
| P1.1 | The DTO, mTLS discovery, JWS/digest/replay/fencing admission, ADR 0038 repository-local gates, and the exact P2.7 independent external-caller qualification pass. The listener has one explicit caller trust domain, Provider-local audience/revision anchors, and up to 32 frozen keys | Production identity infrastructure, multi-issuer admission, deployment-owned rotation, and qualification of other callers remain unproven |
| P1.2 | Passed for the selected Contract-authorized lifecycle subset and development composition | Snapshot/restore, resize, and production gates remain open |
| P2 components | P2.1-P2.5h local component, Contract projection, Docker, and recorded repository CI gates pass within their named boundaries | Retain single-controller/development constraints and exact Contract lock |
| P2.5i | Latest completed local run `20260907T044611.598221000Z` passed 15 initial plus 5 restart/resume coding/shell scenarios against historical harness/Provider lock `b8d4829`/`af8a505`; hosted regression `33970773414` remains historical evidence against `17ed6ca`/`b4d41c9` | Neither run contains a Browser scenario or proves interoperability with an independently implemented external caller, durable-revocation caller behavior, or production properties |
| P2.6 | The historical 50-case local and separate 6-case remote profiles passed at `3fe314a`/`ae476fe`. The later content-derived 60-case local Suite passed from a clean VCS-built Runner at lock-selection revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`; Product Phase 5 separately selects the current 71-case authority | Protected or mutating remote profiles and broader aggregate/reliability/deployment gates remain separate |
| P2.7 | Complete at **24/24**; the public independent caller is **13/13**. Hosted run `35203241121` executed all 15+5 cases against Provider `170459266af5f4fad359ca8c63f2ae19741055c5` and caller `b3ebcc783e5db20395e29b029e0eb55f7819b49b`, matched all 91 required observations, completed stable zero-resource teardown, and produced accepted seven-file artifact `10488622806` with result-envelope digest `sha256:d5e6fd528f2302252a38f49aa466c85767106a8bcef430120f230a8127f96758` | No step remains in the fixed first-version plan. Other callers/profiles, aggregate conformance, multi-controller, hostile multi-tenant, HA, deployment, and production readiness require new scopes and evidence |
| P2 | Reference coding/shell caller and Product Phase 2 lifecycle release gates passed; the latter includes a repository-owned independent-process 15+5+9 black-box run | Independently implemented external-caller lifecycle interoperability, aggregate conformance, multi-controller, hostile multi-tenant isolation, deployment, and production gates remain open |
| P3 | Retired by ADR 0037. Historical revision binding/shadow/metrics components and candidate runs retain their recorded evidence boundaries | No named-platform migration gate remains; external consumers adapt to the exact locked Provider Contract |
| P4 | Browser Contract authority/projection, exact sandboxed signed amd64/arm64/v8 publication, Provider-local components, default-disabled command/runtime composition, process-local Gateway limits, the separately recorded Browser/shared-capacity/durable-revocation caller gates, ADR 0033 component/caller evidence, the ADR 0034 v2 local/hosted deletion and rollback-detection gates, the ADR 0035 PostgreSQL component gate, and the ADR 0036 hosted same-runner controlled-restore gate pass within their named boundaries | Production independent witness/storage and restore operations, production Browser advertisement/public Gateway, Valkey/PostgreSQL provenance and HA, production configuration/metrics, aggregate, multi-controller, multi-tenant, deployment, and production gates remain open |
| Product Phase 5 | **15/15 complete** for the bounded same-repository independent-process topology. The exact Product/Gateway/Provider/Desktop/Guest process graph passes 14 strict scenarios with fresh pinned PostgreSQL, signed runtime, real display/control, Guest development materialization, restart/fault/security/recording checks, dependency-derived exact-topology advertisement, strict evidence validation, and exact cleanup | Production command composition and deployment qualification, HA, hostile multi-tenant isolation, independently implemented caller interoperability, and general production readiness remain later gates |

Production readiness is not a numbered phase shortcut. Aggregate conformance,
multi-controller reliability, hostile multi-tenant security, deployment, and
production operations remain separate and unproven after the reference P2 gate
and require their own future evidence.

The Browser protected-transport implementation `b8423f5` and harness lock refresh
`a2721ad` are covered by repository CI run `33760609353`, which passed
`provider-contract`, `test`, `docker-integration`, and the separately named
`browser-provenance` job. Its Docker job does not execute the Browser
restricted-egress tagged integration; that live evidence remains local. Hosted
Reference and Candidate runs `33760609272` and `33760609231` passed their
separately named coding/shell scenarios. Repository CI remains distinct from
caller evidence, and neither hosted caller run contains a Browser scenario.
The Browser Gateway implementation `5aae281` and harness lock `9eb32ba` were
pushed together after all local gates and fresh 15+5 Reference/Candidate
coding/shell runs passed. Repository CI `33826813073` passed
`provider-contract`, `test`, `browser-provenance`, and `docker-integration`;
hosted Reference and Candidate runs `33826813099`/`33826813100` also passed their
separately named coding/shell scenarios. None of these hosted results contains a
Browser caller scenario.
Previous implementation `f760369` and harness lock `79fee2b` are covered by
repository CI `33838215949`; all four `provider-contract`, `test`,
`browser-provenance`, and `docker-integration` jobs passed. Hosted coding/shell
Reference/Candidate regressions `33838215917`/`33838215882` also passed their
separate 15+5 scenarios, while hosted Browser Reference E2E `33838215924`
passed its separate 10+5 Browser scenarios. ADR 0027 capacity implementation
`7b062e6` and harness `28a9a5e` are covered by repository CI `33846603580`;
all four jobs passed. Hosted Reference/Candidate regressions
`33846603323`/`33846603454` pass 15+5 coding/shell scenarios, while Browser
Reference E2E `33846603547` passes its separate 11+5 scenarios including active
same-session capacity rejection/release. These three caller modes retain their
distinct evidence boundaries.

The GitHub Actions Node 24 migration `6c1ddde` and lock refresh `e75869d` are
covered by repository CI `33850219645`, Reference `33850219700`, Candidate
`33850219664`, and Browser `33850219667`; all passed without the previous Node
20 or `punycode` warnings. This is CI runtime maintenance only. The subsequent
Browser edge implementation `44ea2ee` and harness `249cdd4` pass all required
local Go/Contract/E2E gates and the clean local Browser 12+5 run described
above. Repository CI `33854020951` passes all four jobs. Hosted Reference
`33854020874`, Candidate `33854020947`, and Browser `33854020809` pass their
separate 15+5, 15+5, and 12+5 scenario sets against harness `e7e7f03` and
Provider `44ea2ee`; their artifact digests are
`sha256:220650f1b61b0297ec445ded03bf3a15870514a9482c9e55012ddfba8ae0da2d`,
`sha256:48cbe44c433e5b3a858a2691fe1f736469b2e8d71228541f2bdfcc4aab1c15b1`,
and `sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`,
respectively. The three caller modes retain distinct evidence boundaries.

## P2.5i Reference Result

The earlier audit correctly found no existing platform caller. A separately
versioned reference harness now exists as the `e2e/` Go module and process
boundary inside this Provider repository. Its caller module has an
import-boundary test that forbids Provider implementation imports; the separate
reference-stack process alone composes exported Provider/Gateway packages with
explicit caller-owned policy.

The clean `e329150` harness run against Provider `d58497e` verified exact
Contract/Suite identity, two ephemeral mTLS/JWS controller identities, locked
capability discovery, protected lifecycle, replay, exec/result/usage, stale
fencing, cancellation, opaque terminal handoff, Gateway bytes, wrong-caller and
cross-tenant denial, grant expiry, revocation, artifact staging/evidence,
process reconstruction, retained evidence, and same-shell reconnect. It
exposed no backend endpoint and left no managed container or new temporary run
directory.

This closes the reference external-caller P2.5i gate. It does not prove real
Veronica compatibility, aggregate conformance, distributed revocation caller behavior,
multi-controller reliability, hostile multi-tenant isolation, deployment, or
production readiness.

The latest local pre-ADR0033 coding/shell lock-refresh runs use harness
`59e08d542b05ad1a047f439f4ea72e82c8c37404` and Provider
`c0a55d1e0a862f9e5a592abd27b1e25be3c85b3e`. Reference evidence
`e2e/evidence/20260905T080530.577843000Z/manifest.json` and candidate evidence
`e2e/evidence/platform-candidate/20260905T080623.861033000Z/manifest.json` each
record 15 initial plus 5 reconstruction/resume coding/shell passes, Contract 48
cases, and linux/amd64 runtime digest
`sha256:c1da999518ed8cf3c422142b705f3eeca5d60104be07bc28c15a7d527d2907fc`.
Neither manifest contains a browser scenario; the candidate manifest also
remains explicitly bounded to candidate integration and does not represent real
Veronica or production traffic.

## Retired Platform Candidate Track

ADR 0037 retires the former named Agent Platform migration target. Earlier
audits correctly established that no runnable platform caller or migration
harness had been supplied, but that absence is no longer an active project
blocker because this repository will not implement or wait for a
consumer-specific adapter.

The historical `agent-platform-candidate` harness, commits, runs, and artifacts
remain valid only within their recorded revision-binding, shadow, canary,
rollback, drain, and metric-component boundaries. Their names and evidence are
not rewritten. A future consumer owns its integration and rollout evidence and
must conform to the exact locked Provider Contract.

## Completed Implementation History and Future Scope

The fixed first-version plan is complete; there is no remaining numbered P2.7
implementation step. The material below records the completed dependency order.
Any further multi-controller, HA, hostile multi-tenant, deployment, production,
or additional-profile work is a new scope with its own authority and gates.

P2.5a established [ADR 0015](adr/0015-coding-shell-vertical-composition.md) and
the [vertical-composition plan](plan/p2.5-coding-shell-vertical-composition.md).
P2.5b then locked one atomic exec+terminal coding/shell profile in Contract
commit `22a148e` and projected it fail closed in `123d16a`. Its local gates and
repository CI `32924361132` pass. P2.5c commits `6c2962b` and `6340604` move
create/session bounded strict decode ahead of mutation guard reservation and
bind the regression into the locked Suite runner; local gates and CI
`32926181615` pass. P2.5d commit `de18787` adds the independent Provider Docker
lifecycle adapter and passes its local fault/restart, full Go, Contract/Suite,
and real Docker integration gates; CI `32929140044` passed all three jobs.
P2.5e commit `5917a57` locally composes strict protected exec/cancel/result and
operation projection, durable accept-before-dispatch and restart
reconciliation, bounded private output capture, real Docker execution and
cancellation, and fail-closed development composition. Full race/shuffle, vet,
Contract verification, the locked 38-case Suite, diff checks, focused race
matrices, and real Docker integration passed locally. CI `32937530059` passed
all three jobs. P2.5f0 then audited terminal/Gateway authority, data-plane,
recovery, persistence, cleanup, capacity, and deployment boundaries without
changing runtime behavior. P2.5f1 commit `6778d3c` adds the backend-neutral
terminal runtime port, a PTY-owning guest broker, adapter-private durable Docker
identity, bounded per-sandbox/per-controller capacity, identity-bound cleanup,
and fresh attach to the same shell after Provider driver reconstruction. Full
race/shuffle, vet, module verification, unchanged Contract verification, the
locked 38-case Suite, diff checks, focused terminal tests, and live Docker
integration passed locally. This is runtime-adapter evidence only; repository
CI `33033284420` subsequently passed all three jobs for evidence baseline
`66dd3d1`. P2.5f2 implementation `ccffd52` then adds the uncomposed durable
session vertical, provider-neutral allocation evidence, v1-to-v2 migration,
trusted lifecycle projection, exact-identity allocation recovery, observation,
expiry cleanup, and a success-commit hook that accepts but does not mint opaque
reference evidence. Full race/shuffle, vet, module and Contract verification,
the locked 38-case Suite, diff checks, focused fault/restart/migration matrices,
and live Docker integration passed locally. Repository CI `33045725476`
subsequently passed all three jobs for evidence baseline `3abefd4`. P2.5f3
implementation `b1acdd1` adds a durable opaque reference registry and resolver
in a separate repository. Registration mints a random 128-bit
`ref:session:*` value for a running allocation; resolution rechecks registry
expiry/revocation and exact committed-handoff identity, then constructs a fresh
adapter-private attach for each dial. File-backed restart, collision, expiry,
revocation, generation/reference mismatch, and concurrent resolve/revoke tests
pass locally. The registry/session repositories are intentionally non-atomic,
and no command composition or public backend endpoint is added. Repository CI
`33059304542` passed all three jobs for evidence baseline `7138a4c`. P2.5f4
implementation `14f14cc` adds `gateway/adapter`: a direct
`github.com/coder/websocket@v1.8.15` dependency (ISC-licensed, source-reviewed
for context reads/writes, message limits, control frames, and close behavior),
plus bounded adapters between the WebSocket/terminal byte surfaces and
`gateway.Stream`. It requires a caller-supplied pre-upgrade admission callback,
rejects wildcard origin patterns, retains the library's default same-origin
protection and disabled compression, accepts only text/binary data-plane
frames, and uses a 32 KiB default with a 64 KiB hard cap. Focused adapter
race/shuffle tests cover admission, origin rejection, binary flow, control
frames, over-limit `1009` close, cancellation, close, abrupt disconnect, and
partial terminal I/O. Full race/shuffle, vet, module verification, unchanged
Contract verification, the locked 38-case Suite, diff checks, and both Docker
regression packages passed locally. Repository CI `33064864447` then passed
`provider-contract`, `test`, and `docker-integration` for evidence baseline
`1d9da67`. `govulncheck` and an OSV scanner were not available, so no
vulnerability scan is claimed. P2.5f5 implementation `fdfc771` adds
`gateway/composition`, which requires caller-owned `Authorizer`,
`RevocationSource`, `Recorder`, and WebSocket handshake admission together with
a Provider reference resolver. It projects each freshly resolved Provider
terminal dial through the bounded f4 terminal adapter, rejects missing and
typed-nil dependencies and incomplete endpoint data fail closed, and closes the
caller stream on all connection exits. Focused and full race/shuffle, vet,
module verification, unchanged Contract verification, and the locked 38-case
Suite passed locally. This is a composition component, not Provider command
configuration, external-caller E2E, aggregate conformance, multi-controller,
multi-tenant, deployment, or production
evidence. Repository CI `33067526022` then passed all three required jobs for
evidence baseline `754c57d`; it is still not external-caller, aggregate,
multi-controller, multi-tenant, deployment, or production evidence. P2.5f6
commits `c4c7cbc` and `8a794c0` then add default-disabled development terminal
command composition with recovery before protected transport injection,
idempotent reference registration, file locking, bounded cleanup, and
production rejection. P2.5f7 test `0e8b284` then closes the local
single-controller terminal vertical gate with a real Docker session, durable
handoff, test-supplied Gateway policy, and same-shell reconnect after process
reconstruction. Their full local gates pass, and evidence baseline `cefbc74`
passed repository CI `33134521467`. P2.5g implementation `0e6e108` then adds
the default-disabled artifact/usage command vertical. It
binds staging to lifecycle readiness, tenant, generation, lease, and fencing;
reads only regular files beneath the owned Docker `/outputs`; runs injected
content scanners without shell interpolation; returns only opaque private
staging references; persists async artifact outcomes and partial exec-derived
usage across restart; and includes artifact operations in the family reader.
Its focused, full local, and Docker-tagged gates pass, and repository CI
`33157119149` passes all three jobs. P2.5h implementation `2c55173` and
repository CI `33159099578` also pass their bounded readiness/projection gates.
Reviewed documentation baseline `bba02a6` passes repository CI `33160646494`.

The private FD 3/4/5 provisioning protocol, parent process manager, and
Contract-wide `gatewaystack` handoff validation are implemented at `8a1049b`.
Harness `550c785` composes them into the complete local ADR 0033 topology, and
run `20260906T050213.016063000Z` passes all 13 scenarios on `linux/arm64`.
Hosted harness `2cadc53` run `34013982796` passes the same scenarios on
`linux/amd64`; the downloaded artifact contains evidence directory
`20260906T052710.781616339Z` with exactly five sanitized files and has been
inspected.

P2.7b validation requires an operator-enforced writer handoff: the validator is
the evidence root's exclusive writer from `Verify` entry through return,
including against producers and other processes with the same UID. Its dirfd
and TOCTOU checks fail closed on detected changes; they do not prove integrity
against a continuously writable attacker. The validator stages its owned
receipt, repeats the final evidence checks, and commits only if cancellation or
a competing destination has not won; publication does not attest that reported
interactions correspond to original request bodies. External packaging and
archive digesting happen only after a successful return.

P2.7c.1 locks the language-neutral adapter JSON schema and its
first Darwin/Linux inherited-pipe transport semantics. Its protocol authority is
bound through startup, process-supervisor, validator, and receipt evidence.
All qualification Schema compilers use one ECMA-262 regexp engine and reject
ASCII controls without POSIX-only classes. Invocation paths/endpoints now use
closed canonical profiles. The definition requires digest-bound preflight
commitment before the supervisor or harness acquires or generates credential or
forbidden-correlation material, plus cross-phase byte identity; runtime proof
awaits the supervisor and operator-upstream non-derivation remains trusted.
Non-error output invocation IDs and phases now bind to the single validated
inbound invocation, including scenario case-ID phase prefixes. Protocol-error
branches now distinguish unbound `invalid_invocation` from
bound post-acceptance terminal failures. Its monotonic deadline anchors retain
one execution budget across reconstruction, clip each case to remaining global
and parent time, prevent resets, and bound failure termination separately.
P2.7c.2a adds the runtime-independent strict codec. Invocation bytes are counted
through EOF; output record limits exclude the LF delimiter while the stdout
total includes delimiters and invalid or truncated bytes. The codec rejects
invalid UTF-8, duplicate members, invalid surrogate escapes, multiple values,
unknown fields, wrong-direction messages, and mismatched startup protocol
authority with stable sanitized failures. It deliberately does not validate
message order, recompute transcripts, enforce deadlines, or launch a process.
P2.7c.2b.1 now locks the exact transition table, terminal-to-EOF-to-clean-exit
completion, cross-phase canonical startup equality, and the closed sanitized
transcript preimage Schema at
`sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293`.
This is definition evidence only, not runtime state or transcript evidence.
P2.7c.2b.2 adds the runtime-independent startup gate: it consumes the first
strictly decoded adapter record, requires `startup_identity` sequence zero,
rejects empty, duplicate, and out-of-order startup, preserves the first
sanitized failure, and grants invocation-input authorization once. It neither
performs I/O against a process nor advances into invocation acceptance.
P2.7c.2b.3 records the invocation only after the startup gate authorized input,
requires the invocation and output to originate from the same verified Codec
and stdout decoder, rejects skipped output records, and accepts only sequence
one with matching invocation ID and phase. A package-private document digest
and revalidation prevent mutable decoded fields from changing the bound
message; only a sanitized invocation reference is retained. P2.7c.2b.5 adds
the valid pre-binding error branch.
P2.7c.2b.4 obtains both phase case orders from that same verified profile
result, copies them into the per-phase machine, and accepts exactly one result
per case in order. `completed` requires an immediately preceding
`scenario_started` for the same case; `not_executed` forbids a preceding start.
Sequence, invocation, phase, Codec, stdout-stream, wire-byte, and decoded-record
integrity remain bound for every accepted scenario message. The machine stops
at `awaiting-terminal`. P2.7c.2b.5 accepts exactly one normal
`invocation_finished` whose completion matches all observed dispositions, or
the exact pre-/post-binding `protocol_error` branch. It rejects output after
terminal, requires EOF on the bound decoder, and accepts a clean-exit event only
after EOF. The pure state-machine slice neither launches nor waits on a process;
c3.6 now supplies this event from the owned child's bounded real exit observation.
A process boundary alone cannot prove caller source independence or exact
PID-level request attribution.

1. Retain the completed P2.7 publication, 24/24 qualification, and public
   caller 13/13 evidence at their exact recorded identities. Retain the
   completed Product Phase 2, Phase 3, and Phase 4 results at their exact
   historical Contract and topology identities; the current Desktop-extended
   Contract lock does not relabel them.
2. Before adding protected or mutating remote profiles, define their explicit
   cleanup authority, prerequisites, case-specific evidence, and incomplete-run
   semantics; do not reinterpret the discovery profile.
3. Preserve the Browser, coding/shell Reference, and historical Platform
   Candidate harnesses as separately named evidence modes. The candidate mode
   is historical and P3 is retired; future consumers own their adapters and
   rollout evidence.
4. Prove independent PostgreSQL/Valkey failure and backup domains, HA, and
   operator controls only in a deployment-owned environment. Retain hosted ADR
   0036 evidence as same-runner reference evidence.
5. Retain the completed Product Phase 5 15/15 evidence at its exact Contract,
   runtime, template, process, and scenario identities. Define a separate
   Phase 6 or deployment plan before enabling production command composition,
   production advertisement, collaboration, HA, hostile-tenant, or operational
   readiness claims.
6. Keep multi-issuer admission, aggregate conformance, multi-controller,
   multi-tenant, HA, independent external-caller interoperability, deployment,
   and production-readiness claims blocked until their separately named gates
   have reproducible evidence.

The detailed case-by-case evidence and exact open claims remain in
[`STATUS.md`](STATUS.md).

## Maintenance Rule

Update this document when architecture ownership, mandatory engineering gates,
phase maturity, Contract identity, primary blockers, or the next implementation
order changes. Put commit-by-commit evidence in `STATUS.md`, design rationale in
ADRs, and protocol details in `contract/`.

Use dated evidence baselines rather than statements such as `HEAD is <sha>`;
the latter becomes false as soon as a documentation update is committed. Every
handoff must leave facts, inference, and unproven claims visibly separate.


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
