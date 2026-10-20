# Phase6 Vault generator output verification

Date: 2026-10-13. This follows the [generator dependency remediation](product-v1-phase-6-vault-dependency-remediation.md).
Private evidence is `vault-generator-output-20261013`, outside Git and the
migration package. The active branch remains `codex/product-v1-phase-6-hardening`
at `91fe315641779e6ea640632538309d63ad1b303f`; inherited changes are preserved.
Phase6 remains **5/15**, with Slice6 step2 ongoing.

Latest continuation: [2026-10-20 frozen TUF four-case pass](#2026-10-20-frozen-top-tuf-four-case-chain-passes).
The source HEAD and supply observations below are dated historical records,
not the current Git HEAD or current vulnerability-database freshness.

## Source and command scope

The private Vault2.1.2 source has9090 files and39559500 bytes, identical to the
previous approved input snapshot. The Vault-only Go1.26.9/x/net0.60/Node22
candidate changes remain confined to private inputs. Ordinary repository
Go1.26.8, historical source and release locks are unchanged.

The root contains15 enumer commands in14 source files and10 packages. A
sixteenth literal directive in tools/tools.go invokes install-tools and has
the tools build tag; the default CE traversal excludes it. Eleven nested
api/sdk directives are outside this root-module scope. The unfiltered host
CE `go generate -n -x ./...` reports exactly the fixed15 commands in9.424seconds.
Metadata recognizes278 root packages and2826 total packages, with2637 packages
and482 external module versions in the selected generator package closure.
No directive or lifecycle script is executed by that dry-run.

The original Makefile's enterprise-tagged package selection fails on this CE
snapshot because cacheutil and vault/replication have only excluded CE files.
That failure remains in the raw evidence; this checkpoint does not establish
equivalence to the complete original Makefile preparation path.

The source-bound recipe uses the prior new enumer ELF, SHA256
`13952c5207471be30579af8534b1a9dea4486f9ab3d4bede19936dcf8b17906e`.
Independent source review confirms its generated header uses the literal
enumer command name, so the required result is exact byte equality with all15
original outputs. Every target must match immediately after generation and
again in the final source tree. All non-target contents, file/directory sets
and declared working modes must remain unchanged. Compiler export metadata
must contain all10 packages and reject Error, DepsErrors or Incomplete rows.

## Offline inputs and unresolved findings

All987 archive/mod pairs are rechecked against prior raw hashes and h1 sums.
The first offline `go mod verify` fails because an older testify1.7.0 graph
go.mod is absent. The repair adds467 go.mod-only graph records from existing
private materials, each checked against the locked go.sum; it changes no
selected version and fetches nothing. The next actual `go mod verify` passes
in36.215seconds. The initial failure is retained.

The complete root inventory scan covers exactly986 external module versions,
excluding the root and five local replacements. It reports16 HIGH,0 CRITICAL,
18 MEDIUM,7 LOW and2 UNKNOWN with no severity/unfixed suppression. Among the
482 selected generator-closure versions, one MEDIUM gosnowflake finding and
one UNKNOWN OpenPGP finding remain. Module presence is not call reachability,
and this narrower view does not clear the complete root inventory. The
independently reviewed permission is for isolated compiler analysis and
generator diagnostics only. Complete Vault build, supply and service gates
remain open; the full UI also retains its previously reported51 HIGH/
4 CRITICAL, unfixed braces advisory and Ember5.8 support boundary.

Host metadata uses the existing mise-managed Go1.26.9 installation, whose
15045 files are checked against the official archive. No global tool activation
or installation occurs. Actual generator execution is confined to Docker with
the previously admitted carrier, fixed Node22.23.3 and Linux Go1.26.9.

## Bounded execution and retained failures

The diagnostic uses read-only inputs/root, none networking, UID501:GID20,
no capabilities, no-new-privileges, private namespaces,2 CPUs,2GiB memory and
128 PIDs. Only noexec tmpfs is writable: /work1GiB/65536inodes and /tmp64MiB/
32768inodes. There is no executable output tmpfs and no Vault service or
application init execution. Effective environment, all requested/observed
mounts, kernel network state, privileges and cgroups are checked. The controller,
wrapper and outer limits remain450/560/600seconds respectively.

The first Docker run reaches Go1.26.9 but its full-root unfiltered dry-run
times out in60.642seconds, before compiler exports or any enumer command.
The container is not OOM-killed, and exact owned container/image cleanup
succeeds. Subsequent full input verification outlasts the wrapper; the overall
560.715-second result is a failure, not an input-integrity pass. Raw output,
controller binding and cleanup receipts are retained.

The independently reviewed second recipe carries the complete source as a
new read-only compressed data capsule, SHA256
`95929248e5c200c38b8c2a73e4f5740b7033fed98b1a5c735ec21a126b52815e`.
It checks every original source byte, directory, canonical path and output size
before exclusive creation in tmpfs. The9090-file capsule is15706116 bytes;
original host source modes remain fixed, while working files/directories are
normalized to0644/0700. The original source tree remains in the full execution
input lock. Exact-set/content/mode and file-descriptor identity checks reject
symlinks, FIFOs, added empty directories and changed modes/content. No sampled
or cached hash substitutes for a complete check.

The revised Docker recipe is configured to dry-run the fixed10 packages,
without a directive filter. Such a result could be combined only with the host
full-CE traversal to describe the15-command scope; it cannot retroactively
pass the first Docker full-root command. The recipe can retain available raw
compiler metadata after an export failure within existing output bounds;
process termination or excessive output can prevent collection. Export was
not executed in either Docker run. A four-worker input-hash preparation is
interrupted after340.830seconds
before creating any lock or container. A one-second sample shows frequent
Python lock scheduling, which is a performance clue, not a whole-run diagnosis.
Independent review confirms that returning to serial file-descriptor traversal
retains all checks. A167-file diagnostic produces identical serial/parallel
results, with differing cache conditions; it does not prove full-tree speed.
The new v3 lock preparation actually passes in247.901seconds, binding185291
files and21283 directories. It also completes a new full check that v1 inputs
remain unchanged, without retroactively accepting v1.

The v3 execution passes its initial exact-input checks but local OCI load
exceeds the existing90-second command bound in90.548seconds. No container is
created and no compiler export or generator runs. Reconciliation finds the
exact expected native image, verifies its sole tag and absence of consumers,
then removes it without force; subsequent image and container absence checks
pass. Client timeout alone does not show that the OCI bytes are corrupt or
that the daemon rejected the import. The load/performance cause remains
unresolved. No additional bulk execution is started to obtain a green result.
The560-second wrapper then interrupts the final complete input check; its
observed duration is562.427seconds and the outer command returns failure in
569.495seconds. Controller bytes still match before and after. That is not a
successful post-input verification. A separate complete integrity check then
passes in248.239seconds, comparing all four locked trees and29 individual
inputs. This establishes unchanged retained inputs, not runtime acceptance.

The subsequent read-only host observation records16GiB RAM,26097.12MiB used
swap,1/5/15-minute load93.62/97.69/127.04 and3% idle CPU in the one-second
sample. A separate Docker info query also times out at10seconds. This was
sampled after the failed import, during the separate input check; it shows
contemporaneous pressure, not the import's proven cause. The same OCI archive
loaded successfully in77.779seconds in v1, whereas v3 hit its90-second limit.

Next wait for a lower-load window and verify bounded read-only responsiveness
and identity of the same daemon before another controlled attempt. Do not
introduce a new delivery architecture merely to compensate for an unmeasured
environment problem. If a smaller delivery or pre-positioning proposal is
needed, independently review exact source/artifact binding, resource ownership
and cleanup before execution. Do not
extend90/450/560/600-second bounds, omit hashes, accept an unidentified cached
image or disturb unrelated Docker workloads. The acceptance target remains
all15 byte-identical outputs with clean compiler exports and exact cleanup.

## Lower-load continuation and stack diagnostic

On the new-machine continuation, three separated samples report load1 of
5.33/5.64/5.68, CPU idle57/61/53 percent and same-daemon Docker info responses
of0.771/1.084/1.249seconds. This is a lower-load observation, not a guarantee
that host pressure remains low during subsequent commands. The reviewed v4
run preserves the old input lock and creates a fresh private output/resource
identity. Its OCI load succeeds in10.159seconds, but the10-package Docker
`go generate -n -x` still times out at60.063seconds with empty output. No
compiler export or enumer executes. The complete run fails in176.071seconds;
exact container/image cleanup and full input pre/postchecking complete.
The latter is supported by the reviewed controller control flow and retained
tracebacks, not by a separate postcheck receipt. Kernel observations report no
OOM event and ample free tmpfs blocks; they do not establish a unique cause.

A separately reviewed v5 dry-only diagnostic uses SIGQUIT at the same60-second
limit. It fails in60.029seconds, returning Go status2 but no stdout/stderr
bytes, so it supplies no Go stack and does not explain the original timeout.
The full run fails in271.977seconds with complete input pre/postchecking,
all15 working target hashes/sizes/modes retained, and precise cleanup.
Both failures remain immutable private evidence in
`vault-generator-resume-20261013-115951`; prior checkpoints are preserved.

Actual Go1.26.9 source shows module-graph/package discovery before directive
printing, including cold module-index work despite `IgnoreImports:true`.
This is a possible area to investigate, not a measured bottleneck. Neither
file arguments, a directive filter nor omission of the Docker dry-run is
accepted as a replacement gate. No cache or indexing flag has been changed.

A new dry-only asynchronous observer was prepared in private checkpoint
`vault-generator-stack-probe-20261013`. It retains bounded stdout/stderr while
requesting SIGQUIT at55seconds, SIGKILL at59seconds if necessary, and a failure
at the unchanged60-second deadline if close is unobserved. Signal delivery
is an active diagnostic interruption and can never produce a passing dry-run.
JavaScript timer scheduling can drift under load; actual durations and close
state must be retained, with original outer limits still in force. Every
stream is limited to1MiB of retained bytes, truncation is explicit, and
existing-child errors must not cancel the hard-stop timers. It does not run
exports or generators. Original185291-file input checks, the new six-file
probe identity, source-target byte/mode checks and exact cleanup remain
required. Host mise Node helper fixtures are component evidence only; actual
Docker evidence from the subsequent manual continuation is recorded below.

Host pressure rose again during continuation; a later sample reports load1
13.74 and CPU idle13 percent even though Docker info returns in1.391seconds.
No unrelated process was stopped. The user subsequently cancelled the heartbeat
and requested a manual check after other heavy builds stopped. The heartbeat
was deleted and remains off; old-machine automation is not restored. The acceptance target remains clean
compiler exports and all15 actual byte-identical outputs, which remain open.

## Manual recovery and actual v6 stack evidence

Three separated manual samples show load1 8.762/7.739/6.528, CPU idle61/65/61
percent and same-daemon info0.728/0.683/0.711seconds. Swap use decreases; these
observations permit a bounded attempt but do not guarantee its success. The
existing admitted carrier/compiler/enumer scans remain within their database
NextUpdate of2026-10-14T01:09:18Z. This is evidence reuse under the existing
freshness rule, not a new scan or full Vault supply acceptance.

V6 loads the exact OCI archive in7.315seconds and captures the actual Go stack.
The predetermined SIGQUIT is accepted at55.037seconds; dry-run closes at
55.068589seconds with status2. All17637 stderr bytes are retained in both raw
and base64 form, with no truncation; stdout is empty. The active diagnostic
interruption is a failure and cannot be called a natural60-second timeout or
spontaneous Go crash. The full wrapper fails in171.237seconds.

At that instant, the main goroutine waits in `modload.loadFromRoots` and two
workers are in `modindex.indexModule/importRaw` through `ReadDir/Getdents`.
This identifies the observed stage; it does not establish the earlier elapsed
time distribution, a particular module, virtiofs causality, a deadlock or a
guaranteed repair. There are zero compiler-export or enumer commands. The
9090-file source check and all15 original target hashes/sizes/0644 modes pass;
memory peak is1163284480 bytes with no OOM event. Exact container and sole-tag
image cleanup completes without force.

The original185291-file/21283-directory inputs and new six-file probe complete
pre/postchecking. As in v4/v5, this claim rests on the unchanged reviewed
controller's `finally` control flow and retained original failure traceback,
not a standalone per-phase hash receipt. All27 prepared files still match the
immutable preparation index. Independent read-only outcome review accepts
these limited claims. Actual evidence is `vault-generator-stack-probe-20261013`;
manual observations are `manual-readiness-20261013-130826`.

## Reviewed v7 index fallback and compiler scratch rejection

An independent fixed-Go1.26.9 source review confirms that the undocumented
`GODEBUG=goindex=0` uses the existing direct-directory scanning fallback. The
v6 stack supports testing that hypothesis, without proving it accounts for
all historical elapsed time. A second independent review of the concrete v7
scripts permits one private diagnostic with the same ten dry-run targets,
fifteen generator argv vectors, empty cache, original185291-file input lock,
time limits,2CPU/2GiB/128PIDs, none network, RO inputs and noexec tmpfs. This
does not change a production gate, toolchain lock or cache-reuse policy.

The only Go environment change is that index flag. The actual export command
keeps `-e -deps -export` and adds JSON observation fields for selected compile
and embedded files, Imports, Name and Standard. Before any generator, a new
comparator requires2637 unique package paths with exact module identities,
recursive replacements and selected files against authenticated Linuxarm64/
CGO0 CE metadata. Every non-unsafe package must have a nonempty regular Export
inside the run's fresh `/work/cache`, with no indirect path. Thirteen host
fixtures exercise accepted metadata and missing/duplicate/drifted/error/export
rejections; these fixtures are component evidence only.

The v7 OCI load passes in3.340seconds. The same ten-package dry-run exits0 in
15.938129seconds and exactly matches all15 directives. Actual compiler export
runs for76.485729seconds; `go list -e` exits0 but returns1741 package rows with
Error/DepsErrors/Incomplete state. All534 direct Error rows report
`no space left on device`, including compiler archives and assembler objects
under `$WORK`. The unchanged error gate fails before enumer. There are895
rows with an Export field, but no complete successful export validation.
A separate post-failure comparison matches the2637 package/module/selected
file/Imports metadata; it does not establish typecheck or generation success.
No enumer command runs and outputs remain0.

The full attempt fails in158.554seconds. All15 source targets retain original
bytes/sizes/0644 modes, and non-target source checks pass. New explicit full
input receipts pass before in26.322seconds and after in30.223seconds, including
the original185291 files/21283 directories, new seven-file probe and original
CE metadata bytes. The exact stopped container and its sole-tag image are
removed without force; final absence checks pass. Wrapper/controller identities
remain unchanged. Independent read-only outcome review confirms this failure.

Memory peak reaches2147483648 bytes with448 max events, no OOM and no OOM kill.
The post-command `/work` sample has122399 free4096-byte blocks and49973 free
inodes; this occurs after compiler cleanup. The evidence directly establishes
bounded compiler-scratch ENOSPC, not failure-time byte/inode peaks, the precise
interaction with memory pressure or a full host disk. Stop repeated execution
of the same recipe. Next measure scratch/cache occupancy and independently
review a concrete storage/execution layout that retains the original limits,
complete exports, exact command set and actual generated-byte comparison.
Do not increase quotas/timeouts, import unidentified cache, omit exports or
relabel this partial progress as all15 output verification. Private evidence:
`vault-generator-index-fallback-20261013`; the cancelled heartbeat remains off.

## Measured scratch exhaustion and rejected v9 recipe

The separately reviewed v8 observer keeps all original execution gates and
records194 bounded statfs/cgroup samples plus two bounded non-atomic metadata
snapshots. Host and Linux observer fixtures each pass11 cases, including
unresponsive worker finalization. The119.142-second real run fails: dry-run
passes in10.196seconds, but export48.863seconds returns510 direct ENOSPC and
1710 erroneous/incomplete package rows. No enumer executes. `/work` free bytes
reach0 while at least45905 inodes remain. Near failure, cache and temporary
allocated bytes are507559936 and497942528 in a121.173ms snapshot. Pinned Go
source retains work archives and copied cache archives until Builder.Close;
this measured byte exhaustion agrees with that behavior. Samples are not a
guaranteed peak detector and directory attribution is not atomic. Memory
reaches2GiB with max314 but no OOM/kill in v8.

Independent source/design and concrete reviews then permit one v9 diagnostic
adding only `-gcflags=all=-dwarf=false` to the private generator GOFLAGS. This
suppresses compiler-generated DWARF while retaining real typing and exports;
it changes cache/archive identity and is not a release-build recipe. Go and
enumer inherit the same flag; other arguments can still affect action IDs.
Cache starts empty, stays run-owned, and no active archive is purged, patched
or deduplicated. The1GiB /work,64MiB /tmp,2CPU/2GiB/128PIDs and original command,
aggregate and outer deadlines are unchanged.

V9 fails in172.604seconds. Dry-run6.977seconds passes the15 directives; export
109.725seconds returns1549 erroneous/incomplete rows. Its476 direct errors
include475 ENOSPC and one compile signal-killed error for
`google.golang.org/api/compute/v1`. Cgroup events record oom2/oom_kill1/max707997,
and Docker final OOMKilled is true. The observed memory peak is2147733504
bytes, with the configured cap still2147483648. Thus the candidate fails both
storage and memory boundaries; it is not merely another space-only failure.
Free bytes again reach0, with at least44726 inodes available; near-full cache
and temporary allocations are506138624 and494759936 bytes. The1087 rows with
Export fields are not complete accepted exports. The error gate stops before
all15 enumer commands, leaving0 generated outputs.

Both runs preserve15 old target bytes and0644 modes, all non-targets and source
sets. They complete original185291-file/21283-directory input checks plus their
new9-file probes before/after, and exact container/sole-tag image cleanup.
Separate post-failure comparisons match2637 package/module/selected-file/Imports
metadata only. Independent outcome reviews accept these bounded failure claims,
not real export or generated-output acceptance. Private evidence is
`vault-generator-scratch-20261013-1404` and
`vault-generator-scratch-recipe-20261013-1436`; the heartbeat stays deleted.

Further runtime attempts stop at this new combined blocker. The next design
must consider a same-run, source-bound, initially empty cache with deterministic
stages and normal Go temporary cleanup, while retaining one300-second aggregate
compiler budget inside390 seconds and the final simultaneous2637 actual export
checks plus all15 original output bytes. Complete-cache size, largest-package
memory and total duration remain unknown. No staged cache recipe, new memory
setting or `-l` flag is implemented or approved for execution. Neither quota
expansion nor relaxed exports/byte comparisons are authorized. The next
reviewable deliverable is the concrete capacity/stage/budget design.

## 2026-10-14 staged-cache preparation; execution remains held

The source-bound2637-package dependency graph is complete and independently
reviewed. The proposed26-stage sequence is a design artifact, not an approved
complete execution. Source size does not establish archive capacity or peak
memory. A narrower v10 diagnostic has been implemented privately: three stages
with256,426 and427-package closures, ending in the previously killed
`google.golang.org/api/compute/v1`. It changes scheduling to `-p=1`, retains
`-gcflags=all=-dwarf=false`, GOMAXPROCS2 and all other selected inputs, and starts
with an empty cache. Each natural Go invocation must leave its work directory
empty; no live temporary/archive deletion or external cache is allowed.

All stages, metadata/real Export checks, observations and observer finalization
share one300-second compiler deadline inside the original390-second total.
The2CPU/2GiB/128PIDs,1GiB /work,64MiB /tmp and other outer limits remain fixed.
Reject every OOM-class event increment, including after final source checking;
record `max` pressure separately. Each stage preserves raw stdout/stderr bytes,
hashes and completeness. The64MiB combined capture and15MiB JSON transport
ceilings reject overflow and mark obtainable evidence partial; these are
userspace capture/acceptance limits, not kernel memory limits. Host gzip decoding
is bounded during decompression. No enumer command is in this diagnostic;
`diagnosticPassed` can never substitute for final2637 exports or15 byte-identical
generator outputs.

Independent concrete review accepts the12-file probe and decoder as preparation
only. Existing mise Node24.21.0 passes29 host control fixtures; existing mise
Python3.13.16 passes9 bounded-decoder tests, and probe syntax passes. These use
fixture archives and are not Linux execution or Go compilation. The future
controller/wrapper has deliberately not been created: complete input pins,
390-second integration, independent concrete execution review and runtime
supply admission remain necessary.

The previous Trivy DB expired at2026-10-14T01:09:18Z. Initial token TLS failure
and a second incomplete range acquisition remain preserved. After independent
review,31 successful ranges were revalidated and only the missing4MiB range
retrieved once; the complete133530205-byte OCI layer matches its descriptor.
New raw DB metadata is Version2, UpdatedAt2026-10-14T01:19:20.78149892Z and
NextUpdate2026-10-15T01:19:20.78149865Z. Recovery/import take5.519/2.071seconds.
This restores DB data only: no fresh candidate scan or image admission occurred.

An independent supply review identified a separate unresolved boundary in the
actually mounted official Node22.23.3 ELF. Local unsigned SHASUMS authenticate
neither the release signer nor complete current core/native/bundled dependency
vulnerability coverage. The carrier signature and the rejected Debian image
report do not substitute. Before any v10 execution, verify the official signed
release checksums with independently authenticated release keys, bind the exact
archive/ELF and complete source-derived dependency coverage, then perform the
required fresh scoped supply checks and review. A zero-recognized scan is never
a zero-vulnerability pass. Do not silently replace Node or weaken coverage.

Private evidence: `vault-generator-staged-cache-20261014-0128`. No container,
compiler, enumer, Vault/UI service, commit or push ran in this checkpoint; the
heartbeat remains deleted. ENOSPC/OOM repair and all15 generated outputs remain
unverified. The next acceptable deliverable is the Node tool supply closure and
fresh scoped admission, followed by a reviewed controller and one bounded
three-stage diagnostic. Phase6 stays5/15; Slice6 step2 continues.

## Validation and Slice6 ledger

Repository changes in this checkpoint are documentation only. Exact comparison
with the previous2148-Go-file503.355-second passing snapshot permits reuse of
the prior full race, vet and both Contract checks; these are not new executions.
Private generator checks
are separate component evidence, not compatibility or production acceptance.
Public ProfileV2/provider serve v3 holds, broker/general as the only issuers,
PostgreSQL using general, and frozen-R reuse rules remain unchanged.

1. Bounded Guest E: historical acceptance retained, not replayed.
2. Startup audit and real security boundary: ongoing; source-generation
   verification and complete Vault/UI supply remain open.
3. Final live topology, original16 scenarios and independent formal acceptance:
   incomplete.
4. Post-acceptance documentation/commit/push handoff: not started.

## 2026-10-14 Node tool static supply checkpoint

Private checkpoint `node-tool-supply-20261014-0207` preserves the full previous
source and evidence baseline. Official Node22.23.3 SHASUMS, detached signature,
release key at a fixed official release-keys commit and annotated tag data are
available. The 50,447,060-byte source archive matches its checksum row; this is
byte consistency, not a completed cryptographic release verification.

An independently reviewed static pass takes8.441seconds and inventories all32,585
source archive members and5,866 binary archive members, hashing all29,186/4,750
regular files respectively. The actual mounted ELF
matches the archive member; Node/V8 distributed headers match source bytes.
There are388 selected source markers, including a bounded four-line simdjson
version excerpt with the entire7,643,098-byte header hash. The original4MiB
selection-limit failure is preserved. ELF inspection records7 dynamic SONAMEs
and no RPATH/RUNPATH. Configuration and version headers are static release
claims, not a reproducible source-to-binary build or runtime observation.

The proposed OpenPGP.js6.3.2 verifier is also not admitted. Its nine-package
current registry-signature check fails in0.078seconds on argon2id1.0.1's key,
which expired2025-01-29. The failed run has no complete verification output;
do not claim all other eight packages passed. Independent review keeps that
failure: the top-level bundle signature is not substituted after failure for
the previously reviewed nine-package rule. No OpenPGP library is loaded.
Separate static correspondence passes124/124 source-map bytes against fixed
source and eight dependency archives in0.131seconds. A fresh Trivy scan takes
0.626seconds, recognizes exactly9 packages and finds zero vulnerabilities at
all severities. This is verifier-constituent coverage only, not Node coverage
or execution admission; raw DB NextUpdate is2026-10-15T01:19:20.78149865Z.

Node coverage still needs an authenticated release, actual embedded-component
mapping, current core/upstream advisories including version/patch applicability,
and fresh package/byte binding for the carrier libraries behind all7 SONAMEs.
Do not include unmounted npm/Corepack as substitutes for the actual Node ELF,
or call a bare-ELF scan with zero recognized packages a pass. The official
[OpenSSL September29 advisory](https://openssl-library.org/news/secadv/20260929.txt)
includes CVE-2026-84782 (HIGH), whose affected3.5 range includes this source's
OpenSSL3.5.8. Independent source review finds no OPENSSL_NO_DTLS in either
arm64 asm/no-asm configuration; build.info includes statem_dtls.c and the
retransmission implementation retains the described unfixed state. No DTLS
entry point was found in the733 reviewed Node src/lib code files; this is not
proof of binary non-reachability. Record the upstream HIGH version hit with
actual exploitability unproved, and keep the zero-HIGH admission gate blocked.
A network-none diagnostic does not waive supply requirements.

Next independently review viable Node and OpenPGP candidates under unchanged
supply gates; retain this Node candidate and historical locks. Select a
supply-qualified OpenPGP verification path without erasing the
failed candidate, verify exact signed SHASUMS/tag/key validity, and finish the
Node coverage ledger before refreshed scoped supply admission and a reviewed
v10 controller. No new compiler/container/enumer result exists;15 outputs,
2637 final exports and ENOSPC/OOM repair remain unverified. No quota, timeout,
Go toolchain, historical lock, public Profile hold or frozen-R rule changes.
Automation remains deleted; no commit or push occurs. Repository changes in
this checkpoint are documentation only; prior matching Go/Contract evidence
is reused, not rerun or described as newly executed.

Slice6 remains: step1 historical bounded Guest E acceptance; step2 ongoing and
execution held at the Node supply boundary; step3 final topology/original16
scenarios incomplete; step4 formal post-acceptance handoff not started.
Phase6 remains5/15.

## 2026-10-14 Node and verifier alternative candidates

Private evidence: `node-tool-alternatives-20261014-0253`. Root remains the sole
writer; two read-only implementation_agent reviewers cover the candidate design,
concrete bounded checks and actual results. The starting branch/HEAD remains
`codex/product-v1-phase-6-hardening` at
`91fe315641779e6ea640632538309d63ad1b303f`, with inherited uncommitted work
preserved. Neither a qualified replacement nor a new generator result is claimed.

The first alternative is the fixed carrier's original `nodejs-26=26.11.1-r0`
for generator-controller diagnostics only. It does not replace the UI's Node22
engine constraint and does not mount the rejected official Node22 ELF. Static
inspection of the retained, reconciled image export binds18 ELF nodes (including
Node),60 dependency edges, their exact file hashes and unique APK owners. No
RPATH/RUNPATH is present; actual libcrypto/libssl are OpenSSL4.0.3-r6. These are
static loader relationships, not runtime observations or complete non-ELF inputs.

The original index/native signatures and SLSA/apko/SPDX verification bytes are
rechecked against their retained hashes; no new Cosign execution is claimed.
All13 OCI descriptors and the exact75-package signed/actual sets match. A fresh
full-image Trivy scan completes in15.529seconds and recognizes75/75 Wolfi APK
packages with zero findings. The unchanged DB NextUpdate is
2026-10-15T01:19:20.78149865Z. This APK-layer result alone is insufficient for
Node admission: it has no installed-JS result and does not separately establish
the embedded Node/V8/llhttp/undici/native component coverage.

An independently reviewed supplementary collection takes7.955seconds and binds
all217 actual package.json files and7 Node header/debug files to original image
bytes and unique APK owners. Of the217,163 have package name/version and54 are
auxiliary manifests. The metadata-only rootfs scan takes0.812seconds and matches
all163 exact FilePath/Name/Version triples. It reports **one HIGH**:
`CVE-2026-93748` / `GHSA-ch52-4w7c-c8xp`,
`http-cache-semantics@4.2.0`, under npm12.2.0-r2. The scanner exits0 to generate
its report; the separate admission check correctly exits1. No fixed version is
listed by the saved DB or current [reviewed advisory](https://github.com/advisories/GHSA-ch52-4w7c-c8xp).
The [upstream maintainer disputes the advisory](https://github.com/kornelski/http-cache-semantics/issues/56);
that dispute is recorded and is not an approved exclusion. The complete carrier
remains rejected, including use merely to bootstrap an APK verifier. This does
not rewrite its historical APK-only scan, or permit a purpose/network waiver.

The image's Node and apk-tools package SPDX files also match original hashes.
They identify publisher recipe locators in `chainguard-dev/stereo` and Node
source commit `364593d0631def13e3043dd84f77ebca2c767ce5`. These are statements
inside the previously signed image, not separately signed SPDX files, an
independently retrieved recipe, or a reproduced build. Public recipe lookup was
unsuccessful; Node embedded component and current advisory coverage remain open.

For an OpenPGP verifier, the alternative is the actual `gpg` subpackage at
2.4.9-r12 rather than the gnupg metapackage or gpgv alone. The fixed carrier's
repository file and three key files are byte-bound. Its live aarch64 APKINDEX
is saved as8,060,313 bytes and statically bounded to43,333,632 expanded bytes,
five members and122,188 records. A19-package candidate closure consists of
eight additions and11 carrier packages; this is not authenticated APK solver
acceptance. Index `C` denotes control metadata hash, not whole-APK SHA256.

The first raw APK fetch rejects HTTP303 under its original no-redirect rule.
Independent review then permits only one manually validated redirect to the
observed exact CDN host/object path, without forwarding credentials or exposing
the signed URL. Per-package transfer25s, wrapper30s and8MiB remain fixed. The
811,162-byte gpg APK is acquired in3.556seconds (wrapper elapsed), SHA256
`66435b649c2868277487ca357163583b69c706df6120c3446a3ac90fe3cc77b7`.
Static inspection finds13 members, an expanded72,068-byte `.melange.yaml`,
`.PKGINFO`, SPDX and the gpg/keyboxd ELFs. The recipe declares both GnuPG and
FreePG patch inputs plus distribution patches; it must be authenticated and
reviewed as that exact candidate. No recipe command or candidate binary runs.

The gpgconf request first fails the exact redirect-path check because its
control hash contains a slash. A separately reviewed request accepts only the
observed literal path but then reaches the25s transfer bound with zero response
bytes; worker elapsed is25.143seconds. All failures remain preserved; no timeout
is extended and no repeated request follows. Remaining requirements include
index/APK signature checks with tamper/wrong-key negatives, the six other new
library materials, solver/file closure, authenticated recipe/patch review and
fresh complete scans before any verifier execution. The raw APK and recipe do
not close official Node release/tag signature verification.

Separated host samples at03:11:48/03:12:19UTC show CPU idle15.40/43.26percent and
same-daemon info2.297/0.964seconds, but swap-in/out increase72,410/89,792 pages.
These samples do not establish stable readiness. No image is loaded, container
created, candidate executed or unrelated process stopped. Automation remains
deleted; no global environment is installed. Development tools used are the
existing mise Python/Trivy with read-only Docker observations.

Next investigate a vendor-signed free smaller Node image under a fresh exact
digest and the same supply gates; do not assume it omits npm. Independent design
review does not authorize a selective-file derivative to inherit an old image
signature. Avoid a new assembly pipeline until its source/publisher authority,
full runtime data and complete coverage can be established. The present full
carrier failure remains an execution blocker. Preserve the gpg bytes and resolve
the exact missing material/verification path without repeating completed work.
Any concrete runtime plan still requires independent review and stable readiness.

Repository changes are documentation only; matching Go sources and Contract
inputs retain earlier full-race/vet/lock evidence, not newly executed tests.
Old candidates, release locks, Go1.26.8, frozen-R reuse and public Profile holds
remain unchanged. No commit, push or publication occurs. Compiler300/container390/
controller450/wrapper560/outer600, load90,2CPU/2GiB/128PIDs and existing tmpfs limits
are unchanged. Final2637 exports,15 generated outputs and ENOSPC/OOM repair remain
unverified. Slice6 steps1/2/3/4 remain historical bounded E / ongoing / incomplete /
post-acceptance handoff not started; formal Phase6 remains5/15.

## 2026-10-14 vendor-signed Node and GPG chain checks

Private evidence: `node-minimal-gpg-chain-20261014-0343`. Main remains the sole
writer; two read-only implementation_agent reviewers review design, concrete
scripts and actual outcomes. The previous362-file/309-directory private index,
all2557 nonignored workspace files, branch and full HEAD match the prior sealed
checkpoint at start. All old artifacts are preserved. The cancelled automation
remains deleted. No global tool or candidate is installed.

The free standard `cgr.dev/chainguard/node:latest` is fixed to index
`sha256:51042bb0c3f282bc5694e8c9b3a06847ef847d566115f91dee6ad2cd88a7d26e`,
arm64 manifest
`sha256:f99475923192f82504a29552820f26e4bb96dbf2bfdce4569e5962cd75ac055a`,
and config
`sha256:9ca78e5b942477a92e39f4360d5d3ee9591bd7879e9cc8b7bc7dadb6fe8ebef8`.
This is the smaller free standard variant, not a purchased `*-slim` product.
The official tag catalog does not establish a free slim-only candidate; no new
account, paid access or selective-file derivative is used.

All eight new Cosign checks (index/native image signatures and SLSA v1/apko/SPDX)
pass under the exact official GitHub issuer/workflow identity and normal
transparency verification. The Node verification wrapper takes190.737seconds.
Raw upstream index/native descriptors remain separate from the locally created
single-platform OCI scan index. All13 native manifest/config/layer descriptors
match their exact bytes; every layer diffID is verified. Three exact-digest
blobs are reused only as bytes, without inheriting old signatures or scans.

Static correspondence passes in1.013seconds:3197 rootfs entries,28 APKs,215 actual
package.json files,161 named/versioned installed JS packages and54 auxiliary
manifests. Actual APK DB and signed native apko/SLSA/SPDX package sets match;
config architecture, run-as, working directory and entrypoint also match the
signed assembly. This proves the publisher's declarative assembly statements,
not recursive OS reproducibility. Five ordinary apko character-device entries
are recorded as metadata under exact path/device/owner constraints; no device
is created. Canonical paths, final directory ancestry and incremental resource
bounds remain enforced, and metadata links are rejected.

The fresh complete OCI scan recognizes28/28 Wolfi packages in1.097seconds with
zero findings. The separate original-byte rootfs JS scan recognizes161/161 exact
path/name/version tuples in0.082seconds and reports one HIGH,
`CVE-2026-93748`, in npm12.2.0-r2's `http-cache-semantics@4.2.0`. Its actual
package.json hash equals the rejected prior carrier's file. No fixed version is
listed; the previously recorded upstream dispute is not an approved exclusion.
The admission wrapper correctly exits1 after4.732seconds, retaining reports.
All severities and empty ignore/configuration are preserved; DB NextUpdate is
2026-10-15T01:19:20.78149865Z and full inputs/DB match before and after. The new
Node image is rejected. Node embedded/native coverage also remains incomplete;
Node26 is not a replacement for the locked Node22 UI or an execution permission.

An independent authentic APK-verifier carrier is investigated at
`cgr.dev/chainguard/wolfi-base`, index
`sha256:256c88bb066424045021090932d50be93c8e3f2ce3586707702a401b146f3e43`,
arm64 manifest
`sha256:e02c7a98dc477e32e2f04ea2e827a132baace0fbeccb3781aa9c64ffc7982774`,
config
`sha256:e155f0caf849076e20b844e6e2633c767f3bc11836e2571c443b3ee483db83d8`.
Its eight new signature/attestation checks pass in201.844seconds. The signed
recipe lists19 packages including apk-tools2.14.10-r17, without Node/npm.
Only config and six of11 layers have been acquired; a later cgr.dev blob request
fails at the original10-second TLS connection bound. Its timing records DNS and
TCP completion, no completed TLS handshake and no response/body; the cause
beyond that observed phase is unknown. The88.095-second material run fails,
leaving five layers missing. No full static correspondence, image scan, Docker
load or APK-verifier execution is claimed. No repeated failed request follows.

The separately reviewed fresh-link gpgconf diagnostic succeeds in9.755seconds
at182609 bytes, SHA256
`656fe831cf7e933a89d8a8c49055a2e53e4e2fb591ce3ec6493d34b65b8f616c`.
It preserves the old25-second zero-byte failure, without proving its cause.
Five more raw APKs (libassuan, libbz2-1, libgcrypt, libgpg-error and libksba) are
acquired. npth-libs fails on the CDN TLS handshake at the original10-second
connection limit; the next four packages (readline, sqlite-libs, ncurses and
ncurses-terminfo-base) are not attempted. Each item retains25-second aggregate
transfer/30-second worker and8MiB limits, one exact HTTPS redirect, no transferred
authorization and no signed URL in public output. The19-package prior candidate
closure is still not an authenticated solver result; wolfi-base would need12
additions, seven of which now have raw bytes including retained gpg. Signatures,
complete dependencies, GnuPG/FreePG/patch-source review, exact solver/ELF/runtime
closure and complete scans remain prerequisites for GPG execution. The official
Node release and annotated-tag signatures are therefore still unverified.

Preparation failures are retained separately: both first token requests were
HTTP200 JSON labeled text/plain and rejected by the initial parser; the reviewed
fix accepts that exact type only at the token endpoint, keeping token bytes in
memory. The initial Node blob request rejects the newly observed exact CDN
host; a reviewed fixed-host/digest-path correction is used. The first wolfi
material attempt times out at token TLS. The Node material wrapper then fails
to create its receipt because the child's material JSON already has that name;
exclusive creation prevents overwrite. A separate complete13-descriptor check
proves acquired bytes, not success or an elapsed time for that wrapper. The
initial static check rejects five standard character-device members; the
reviewed metadata-only handling above preserves that failure.

Next restore only the five missing wolfi blobs and five missing GPG additions
through a reviewed bounded transport plan after the handshake problem is
resolved; do not re-fetch intact artifacts or loop the same failure. Then verify
full carrier supply, actual APKINDEX/APK signatures with wrong-key/tamper
negatives, authenticated recipe/dependency and fresh-scan admission, before any
GPG operation. The rejected Node candidate needs a distinct qualified vendor
replacement; signatures alone and a disputed advisory do not waive its HIGH.
No free alternative is assumed to exist, and no paid source is authorized.

This turn changes documentation only in the repository. All2148 Go files and
other non-documentation inputs retain their matching prior test evidence; no
new Go/race/vet/Contract or Docker test is claimed. There is no compiler export,
enumer, full Vault/UI build, candidate execution, commit, push or publication.
Load90/compiler300/container390/controller450/wrapper560/outer600,2CPU/2GiB/
128PIDs,/work1GiB and /tmp64MiB noexec remain unchanged. No new host/Docker
readiness is asserted because supply admission prevents runtime work. Final2637
exports,15 outputs and ENOSPC/OOM repair remain unverified. Slice6 steps1/2/3/4
remain historical bounded E / ongoing / final topology and16 scenarios incomplete /
post-acceptance handoff not started; formal Phase6 remains5/15.

## 2026-10-14 native APK index verification and GPG source gaps

Private evidence: `gpg-supply-tls-recovery-20261014-0442`. This is a narrow
Slice6 step2 supply diagnostic, not a15-output run or Slice6 closure. Root
remains the sole writer; implementation_agent reviewers independently examine
the plans, exact scripts and raw results. Automation remains deleted.

Four anonymous cgr/CDN TLS probes complete with normal TLS verification. They
do not establish the cause of the earlier timeouts or future availability.
Only the five missing wolfi layers are fetched (35.557seconds) and five missing
GPG dependency APKs are restored (38.913seconds), under unchanged transfer
bounds. The previous failures, candidates, locks and sealed checkpoint remain
byte-identical. The fixed wolfi native manifest is
`sha256:e02c7a98dc477e32e2f04ea2e827a132baace0fbeccb3781aa9c64ffc7982774`;
config is `sha256:e155f0caf849076e20b844e6e2633c767f3bc11836e2571c443b3ee483db83d8`.

All13 native descriptors,11 diffIDs,416 root entries and19 APK identities match
the original signed apko/SLSA/SPDX assembly. The earlier eight exact-digest
Cosign receipts are reused, not newly executed. Fresh Trivy coverage recognizes
19/19 packages with zero findings in1.141seconds. DB NextUpdate remains
2026-10-15T01:19:20.78149865Z. Complete static inspection accounts for104 regular
files,33 ELF files,71 loader edges,54 ld.so.cache entries,13 generated non-APK
files and four public keys. Sixteen packages declare source locators; the three
without them (wolfi-base/baselayout/keys) contain metadata/configuration/public
keys, not ELF. The existing authenticated declarative assembly policy applies;
no recursive OS rebuild, standalone APK signatures or GPG admission is claimed.

Three host samples show52.18/63.42/58.8% CPU idle, load1 of6.335/8.150/7.691,
no swap-out increment and continuing swap-in. All nine same-daemon bounded
ping/version/info responses succeed in6.7–54.3ms. These support only the light
diagnostic, not stable readiness for compiler/build work.

The first native attempt fails before start because unset Docker HostConfig.Init
is omitted; the container remains created/Pid0. Its4.435-second outer failure
and exact cleanup are retained. The second adds explicit --init=false and
starts only the observation shell, but exits74 at busybox ip before any APK
CASE (outer2.047seconds). The temporary command error was not emitted before
cleanup, so its cause is not asserted. Static Busybox bytes are consistent with
an absent ip applet. A reviewed third attempt uses directly observed fib_trie
and if_inet6 with a strict parser limited to this fixed Docker-none diagnostic;
it is not a general ip-address equivalence claim. Fixed
[Linux loopback route construction](https://raw.githubusercontent.com/gregkh/linux/v7.0.14/net/ipv4/fib_frontend.c)
supports host LOCAL; the initial reviewer's speculative UNICAST objection was
withdrawn without expanding the parser. One positive and11 negative address
fixtures pass before execution.

The third native run passes in4.683seconds outer/2.005seconds attached-runtime
measurement. Exact cases are version0/help1/original0/wrong-key1/changed-index1.
Raw original-index output is `0 - OK`; both negative outputs are
`-129 - BAD signature`, not UNTRUSTED. All three cases also retain a repository
cache-missing warning; neither repository availability nor installation is
claimed. Actual UID501:GID20, no capabilities, NoNewPrivs, read-only root and
inputs, network-none addresses/routes/zero traffic and resource limits pass.
All97 fixed inputs pass before/after checks. The full-ID/nonce container and
sole-tag/descriptor image are precisely removed without force; no consumers
remain. The raw original index, wrong-key and valid-structure one-byte tamper
fixtures remain available. The index contains122188 package records.

All12 raw GPG additions match exact signed-index P/V/A/S and the distribution's
Q1/SHA1 compressed-control checksum, then the control's SHA256 compressed-data
hash. They have no individual APK signature segment; locally frozen whole-file
SHA256 values do not become publisher whole-APK signatures. Separate valid
gzip/tar control/data tamper fixtures fail their respective bindings. The395
APK PAX checksums match370 regular files and25 symlink targets. Unknown PAX
fields remain rejected.

A first static proposal inspection fails in0.076seconds on a loader search
override. A reviewed diagnostic-only successor completes in0.186seconds and
records31 declared packages,828 proposed entries,370 new regular files and68
ELF files. It records200 default loader edges, but explicitly leaves three
RPATH=/usr/lib objects unresolved (libhistory, libreadline and libsqlite3),
including all their outgoing edges. ncurses overlaps the base clear/reset
entries. The simple dependency parser also leaves glibc's !musl constraint
uninterpreted and reports etc/mtab and usr/lib/terminfo as unresolved static
paths. These observations are not proof of unsafe packages or real solver
failure. All12 additions are reached from the19-package GPG dependency graph;
gpgconf's declared self-dependency is recorded. This JSON tree retains original
base entries on overlap and is neither an installed filesystem nor a signed
derivative. SONAME/version-symbol, dynamic-helper/dlopen, installation/trigger
semantics, complete31-package fresh scan and embedded/source coverage remain
open. No GPG binary or installation script executes.

The GPG recipe additionally names five local patches whose bytes are absent:
libassun-version.patch,0010-avoid-beta-warning.patch,
0210-dirmngr-hkp-avoid-potential-race-condition-when-some-host-die.patch,
fix-i18n.patch and make-aes-default-for-fips.patch. SPDX locates gnupg.yaml in
chainguard-dev/stereo at c9565b7e28626f669c1d4357026519657002181e, but two bounded
anonymous official GitHub commit/recipe queries return404 (1.916/1.752seconds,
TLS verification successful). This establishes present anonymous retrieval
failure, not whether the repository is private or permanently unavailable.
GnuPG/FreePG upstream originals and the exact applied patch sequence also remain
unverified. Source references and zero package findings cannot replace them.
The current GPG candidate remains held; next obtain authentic exact missing
materials or independently review a candidate with obtainable complete sources,
then resolve the proposed installation/ELF graph and full fresh coverage before
release/tag verification. No paid access or new trust root is assumed.

The earlier standard Node image stays rejected for http-cache-semantics4.2.0
HIGH, with embedded coverage incomplete. This turn does not repeat that scan
or run Node/compiler/Vault/UI. All existing quotas/deadlines are retained:
load90/compiler300/container390/controller450/wrapper560/outer600,2CPU/2GiB/
128PIDs, /work1GiB and /tmp64MiB noexec. Existing mise Python/Trivy and Docker
are used without global installation. Only six repository documents change;
all2148 Go files retain matching earlier test evidence, with no new Go/race/vet/
Contract result claimed. No commit/push/publication occurs. Final2637 exports,
15 generated outputs and ENOSPC/OOM repair remain unverified. Slice6 step1
historical bounded E is retained, step2 remains ongoing, step3 full topology
and original16 scenarios are incomplete, step4 post-acceptance handoff is not
started; formal Phase6 remains5/15.

## 2026-10-14 GPG replacement materials and renewed host pressure

Private evidence: `gpg-verifier-candidate-20261014-0704`. This is a materials
and static-correspondence checkpoint, not tool admission or15-output execution.
The sole-writer arrangement remains human-confirmed. The existing
implementation_agent independently reviews the bounded plans, frozen request
scripts, raw results and final documentation; it does not write shared files.

The established builder-selection policy permits authenticated declarative apko
assembly with fixed packages, signed provenance and full fresh coverage. The
old raw-APK patch gap does not impose recursive OS rebuilds on a whole signed
vendor image. Two anonymous GPG-image inquiries yield HTTP403 and a10.043-second
TLS connection timeout, respectively; neither obtains an image index. These
failures do not prove permanent unavailability or authorize paid access. The
public Wolfi index declares10,520,005 bytes and exceeds the fixed8MiB cap;
curl rejects it without acquiring the body. The first GitHub query fails415
because the shared helper used OCI Accept. A reviewed JSON-accept successor
obtains the public Wolfi head, but does not authenticate a package recipe.
All prior failures remain intact; no size/time limit is enlarged.

The newly retained public gpg2.4.9-r11 APK is810214 bytes, SHA256
`80314c8f7de7e09ca53db01dcb722ece2e6358f0b9cd15db0a2da482ef7872b4`.
P/V/A/S, Q1 compressed-control SHA1 and control SHA256 datahash correspond to
the earlier authenticated **CGR** index. This is not verification of the new
public Wolfi index or an individual APK signature: the package has only two
gzip members, without .SIGN. Its source still locates chainguard-dev/stereo
at5033e0e7cbec14193af5e776dc244cd102cf3fbf. A different public main recipe
cannot replace that exact original. [GNU's download page](https://www.gnupg.org/download/index.html)
records2.4 end-of-life on2026-06-30; distribution backport support for this exact
package is unknown. Independent review stops this execution-candidate route,
retaining its bytes. [gpgv's official semantics](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html)
omit expiration/revocation checks, so it is not directly substituted for the
strict verification policy. No custom validity shortcut or self-authenticating
unadmitted GPG source-build path is adopted.

The new official Alpine edge/main/aarch64 inquiry fails to acquire APKINDEX at
the unchanged TLS bound (10.264541seconds), and GitLab's exact source URL
returns403. It does retain gpg2.5.22-r0,488130 bytes, SHA256
`ae20333e20e2c2b5991db635ee3342d801d8e1ddcbf7c019232db58fd3e1942a`.
Static parsing identifies three gzip members, a512-byte signature member named
alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub, matching internal datahash,
and11 direct dependencies: same-version dirmngr/gpgconf/keyboxd plus eight so
dependencies. Signature presence and its filename do not establish validity or
key authority; the package's commit declaration remains unauthenticated.

A separately reviewed single GET to the [official aports mirror](https://github.com/alpinelinux/aports)
obtains the [same fixed commit's APKBUILD](https://raw.githubusercontent.com/alpinelinux/aports/b2ea575329d2d0abb0aebe51c6a03773c493b02e/main/gnupg/APKBUILD)
in1.948176seconds:7959 bytes, SHA256
`fb91c0be1fea959b3edc82d1e145bd08debbc98ea82831a83838eebfbdf6a489`.
The earlier403 is preserved. Static gnupg/2.5.22/r0 and gpg's three same-version
dependencies agree with PKGINFO. All12 source tokens match12 unique SHA512
declarations: GNU archive,10 patches and one rules file. There is no shell
evaluation, no12 source-original retrieval/content verification, and no recipe
commit signature or reproduced-build proof. The retained JSON states all
execution/signature/source-closure admission flags false.

Existing Alpine3.23.6 utility, Coding candidate and Desktop locks do not
automatically delegate an edge signing key or new carrier. No edge package is
mixed into a stable Alpine/Wolfi root. Next independently review the exact key
authority and collection plan; then close actual index/APK signature positive
and negative cases, full recursive dependency/source/ELF/helper and fresh
vulnerability coverage, and applicable carrier signature/assembly provenance.
Only an admitted candidate and stable host permit actual GPG good/wrong-key/
tamper/expired/revoked cases, followed by Node supply and original15 outputs.

The new read-only host sample records load252.39/110.67/59.90; top tool output
also shows1.21% idle. One same-socket Docker ping succeeds in0.176848seconds,
but no stable interval version/info chain is established. No unrelated process,
container or VM is stopped, restarted or throttled. No candidate, container,
GPG, Node, compiler or full Vault/UI executes this turn. Four bounded receipt
programs finish in17.217046/10.160780/20.619781/4.002344seconds; their exit0
means receipts were preserved, not that all inquiries or gates passed.

Only six repository handoff documents change. Existing mise Python is used;
no global environment is installed, no new scan/Go/race/vet/Contract result is
claimed, and all2148 Go files retain matching prior evidence. Old candidates,
locks and raw evidence remain intact. All quotas/deadlines remain unchanged:
load90/compiler300/container390/controller450/wrapper560/outer600,2CPU/2GiB/
128PIDs,/work1GiB,/tmp64MiB noexec,RO inputs/root and none network. Automation
remains deleted; there is no commit/push/publication. Final2637 exports,15
outputs and ENOSPC/OOM repair remain unverified. Slice6 steps1/2/3/4 remain
historical bounded E / ongoing / final topology and original16 scenarios
incomplete / post-acceptance handoff not started. Formal Phase6 remains5/15.

## 2026-10-14 Alpine GPG key source and signature data checkpoint

Private evidence: `gpg-alpine-authority-20261014-0848`. This closes limited
publisher-key correspondence,12 original source identities and actual signature
data diagnostics. It does not admit GPG/Node, a new carrier or15-output execution.
Root remains the human-confirmed sole writer; implementation_agent independently
reviews bounded plans, frozen scripts, raw outcomes and final documentation.

Five fixed HTTPS requests complete in8.112630seconds: official alpine-keys
recipe/key, official package/contents pages and a new532333-byte edge/main/aarch64
APKINDEX. The index SHA256 is
`707b409e234df3177af451f92f64a00424b750e4d17c6261275a38f648b928a0`.
The800-byte alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub key SHA256 is
`d11f6b21c61b4274e182eb888883a8ba8acdbf820dcc7a6d82a7d9fc2fd2836d`;
its full SHA512 matches the fixed official mirror alpine-keys2.6-r0 recipe at
b9f23becced4d7b3ccc0fa0f28530243ccd314a0, including aarch64 mapping. The
[official package record](https://pkgs.alpinelinux.org/package/edge/main/aarch64/alpine-keys)
has all six identity fields in one table; the contents page's exact key/package/
branch/repository/architecture relation is in one row. An initial global-substring
authority check is rejected before execution. Revised acquisition saves HTML
with correspondence false; a separate strict table/row parser and independent
raw review establish only the specified data-diagnostic publisher-key basis.
These are same-publisher channels, not independent cryptographic roots; no
global keyring or production operator authority changes. Prior TLS/403 failures
remain unchanged; the new index is one request, with no retry or enlarged limit.

All12 GPG original files then match the fixed b2ea575329d2d0abb0aebe51c6a03773c493b02e
recipe SHA512 declarations in24.186408seconds. This includes10 patches, one
rules file and the8,363,854-byte GNU2.5.22 tar within8MiB, SHA256
`96e27b020ad26510388e06f5f07f3f70a4ed8916ee995f1b72b7a024e6d9d87e`.
Independent review recomputes all12 original/receipt/recipe bindings. No GNU
detached signature, recipe commit signature, patch application or reproduced
build is claimed. The authenticated apko declarative-assembly policy remains
unchanged; this does not add recursive OS source rebuilds.

Existing mise Python invokes the existing macOS OpenSSL tool without installing
an environment. A0.078545-second bounded identity probe passes strict Apple
codesign and records actual LibreSSL3.3.6, com.apple.openssl and the Apple
certificate chain. Exact tool SHA256 is
`49db04c17e3a8c169ebc48a1149d78c165a86c04913203f46b2a14ce7f4a14fc`.
This is an OS cryptographic data tool, not newly admitted candidate supply.
An earlier buffered-output draft is rejected without execution; a reviewed
streaming successor persists at most64KiB per stream, records overlimit/signal/
timeout as failure and stops only its own child. Each command remains within5s;
the2s reap cleanup is separately recorded, not a success extension. Received
bytes can include one additional64KiB read block; only persisted bytes are capped.

The frozen C2 data run completes in0.072955seconds:9 cryptographic process cases
and2 SHA256 datahash cases all match. Two valid public-key parses exit0. Original
APK/index signatures exit0 with exact `Verified OK`; APK wrong-key/control/signature
tamper and index wrong-key/control tamper exit1 with exact `Verification Failure`.
Original datahash matches; a data-only change rejects by datahash while reusing
the exact already-verified control/signature. All tampered control/data/index
fixtures remain valid gzip/tar with one content byte changed. No format failure
substitutes for the cryptographic negative. Eighteen raw stdout/stderr streams
remain, stderr empty; no timeout/truncation/active signal occurs. All11 inputs,
four original sources and the tool match before/after. Independent review
accepts actual receipts without replaying the diagnostic. The6034-record index
binds gpg P/V/A/S/C to the exact488130-byte APK from the earlier checkpoint.

The [official v2 format](https://wiki.alpinelinux.org/wiki/Apk_spec) uses
RSA-PKCS1v1.5/SHA1 over compressed control and SHA256 compressed-data binding.
The legacy SHA1 algorithm is recorded; no explicit prohibition was found in
the applicable repository supply policy, and no general approval or waiver is
inferred from this limited mathematical result. Native apk verification of this
Alpine package remains unperformed, along with full recursive dependencies,
ELF/helpers/installation semantics, fresh complete scans, carrier signature/
assembly provenance, actual GPG expiration/revocation and Node release/tag checks.
The rejected Node HIGH and incomplete embedded coverage remain open.

The host's new sample shows load2.53/4.75/17.78 and current69.1% CPU idle, but
the expected Docker socket is absent and ping/version/info all fail with curl7.
A later metadata-only check still finds no socket. This is not a stable same-
daemon readiness chain; no daemon switch/start/restart or unrelated process
stop occurs. Next independently review the index-bound dependency/helper/ELF
materials and full fresh scan plan, then actual native/carrier gates once the
same Docker runtime is ready. No native apk, GPG, Node, container, compiler or
full Vault/UI runs this turn.

Only six repository handoff documents change; all2148 Go files and other inputs
retain matching previous evidence. No new Go/race/vet/Contract scan or runtime
gate is claimed. Old locks/candidates/raw failures, connect10/request25 material
bounds and load90/compiler300/container390/controller450/wrapper560/outer600,
2CPU/2GiB/128PIDs,/work1GiB,/tmp64MiB noexec,RO inputs/root and none network
remain unchanged. Automation remains deleted; no commit/push/merge/publication.
Final2637 exports,15 outputs and ENOSPC/OOM repair remain unverified. Slice6
steps1/2/3/4 remain historical bounded E / ongoing / final topology and original16
scenarios incomplete / post-acceptance handoff not started; Phase6 remains5/15.

## 2026-10-14 Alpine GPG dependency materials and proposal prescan

Private evidence: `gpg-alpine-closure-20261014-1006`; separate new checkpoint,
with previous164 files/25 directories and all2557 worktree files verified at
entry. Root remains the human-confirmed sole writer; implementation_agent
independently reviews frozen plans/scripts and actual data results. No old
checkpoint, migration inventory, candidate, lock or automation is rewritten.

The exact signed-index proposal has37 records/10,697,458 compressed bytes.
Explicit roots are gpg2.5.22-r0, optional gpg-agent2.5.22-r0 and carrier-layout
alpine-baselayout3.7.2-r1. The agent is not a declared gpg dependency. Explicit
/bin/sh selects priority100 busybox-binsh, retaining all four providers;
ssl_client is included as possible install-if, not a claimed solver/install
result. Unknown constraints/providers reject. The original parser failure on
literal coreutils cmd:[ is preserved; only that literal syntax is corrected.
The proposal is neither native SAT nor a final installed package inventory.

The first CDN batch saves12 new APK originals in14.119395seconds, then fails
on libassuan3.0.2-r0 with curl35 Connection reset by peer in1.154191seconds.
Original batch b is unattempted. A reviewed fixed TUNA transport selected from
[Alpine's official current mirror list](https://mirrors.alpinelinux.org/)
initially stops before any APK request: the official HTML gives HTTP200 but
exceeds the unchanged1MiB cap (curl56,1.798321seconds,zero retained body).
Its outer1.905517second failure remains false. The independent official web
observation is transport evidence, not saved original HTML or new key authority.
A separately reviewed caller pins18 inputs, keeps all previous failures and
only requests the24 still-missing originals once in12+12. Those two batches
complete in13.771977/5.505275seconds, with all HTTP200/S/SHA receipts retained.
All36 new originals plus old gpg are independently checked; no new index,
versions, signing roots, proxy, redirect, retry or enlarged cap is introduced.

Static v3 fails in0.142653seconds on architecture comparison and its partial
output remains untouched. Actual signed controls have exactly four noarch
packages (alpine-baselayout/-data, busybox-binsh, ncurses-terminfo-base), while
repository index A is aarch64. The official abuild update_abuildrepo_index
explains this CARCH directory/--rewrite-arch format. Reviewed v4 permits only
those fixed P/V mappings, confirms each regular noarch payload lacks ELF magic,
and requires exact aarch64 in the other33 controls. No raw index/control is
modified; this is format correspondence, not native architecture proof.
Index m is maintainer, not control packager: it is explicitly unmapped, while
I/T/U/L/t/k and P/V/A correspondence/o/c/D/p/i/S/C are checked as applicable.

The0.196689second v4 data parse binds37 packages,356 payload entries and
25,799,680 expanded bytes. Three gzip segments, signed-index Q1 compressed
control identity, control datahash SHA256, regular/symlink PAX checksums,
UID/GID/mode, all control scripts/triggers and original byte CAS are retained.
Conflicts/PAX metadata overlaps/hardlink failures are0;42 links include
etc/mtab->proc/mounts as dangling, so complete_virtual_tree_identity is false.
No extractall, host symlink/chown, script execution or fabricated installed DB
occurs. Every owner entry is preserved. Source/report pins match before/after.

New36 signature data processes complete in0.289436seconds with exact Verified
OK/empty stderr, no timeout, truncation or signal; each remains5s/64KiB per
stream. All124 source/control/tool/context pins match before/after. Old gpg's
exact signature/control/key match the prior successful actual apk-original
case, independently verified before reusing it; lock booleans are not proof.
All37 limited APK v2 RSA-PKCS1v1.5/SHA1 control and SHA256-data bindings pass.
This is mathematical OS-tool diagnosis, not native apk interoperability,
source reproduction, full carrier supply or GPG policy/execution admission.

The0.380952second static ELF data audit visits all133 regular files and55 ELF,
records152 declared edges and version chains with0 parse failures, and retains
one unresolved usr/lib/libsqlite3.so.3.54.0 RUNPATH=/usr/lib. Declared graph
complete is false; musl default paths are static candidates only. VERNEED
libraries absent from NEEDED cannot be silently ignored. Helper/dlopen strings
are observations, not runtime coverage. Three payload scripts and control
scripts from alpine-baselayout/busybox/pinentry remain original CAS bytes.
Busybox applet links, pinentry's post-install pinentry-curses link, UID/GID,
installation/trigger effects and actual GPG helper selection remain unexecuted.
No additional language payload candidates are found in this static scope.

The reviewed third-party CycloneDX proposal preserves actual P/V/origin/control
architecture/raw SHA and37 source-aware PURLs; it honestly names its collector,
not Trivy. Existing mise Trivy0.74.0 runs offline with the original fixed DB,
no updates/ignore/filter, all severities/list-all, GOMAXPROCS2,300second process/
600second outer limits and1MiB per stream. The outer program takes3.386599seconds
including full hashes/COW DB preparation; scanner timing is in its raw receipt.
Actual report SHA256 is
`faf59739496e3c25a54a25d7de383cdf0c11034147ce438bfdcc5ac3848a9859`.
It recognizes exactly37 package/source four-tuples and37 PURLs, no missing/
extra rows, OS Alpine/edge, zero findings at every severity. Source/tool/DB and
COW copy hashes plus DB freshness match before/after; NextUpdate is
2026-10-15T01:19:20.78149865Z, and must be checked anew on continuation.
The actual third-party SBOM accuracy warning remains in stderr. EOSL is omitted;
[exact Trivy0.74.0's OS type](https://pkg.go.dev/github.com/aquasecurity/trivy@v0.74.0/pkg/fanal/types#OS)
uses bool/omitempty, so false can be omitted; the
[matching Alpine detector](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/detector/ospkg/alpine/alpine.go)
supports edge and queries its advisory stream. No JSON explicit false or final
installed/full-image/embedded component coverage is claimed. Earlier pre-scan
drafts are held without execution, including a corrected strict-presence
interpretation that would have falsely rejected valid omitted-false reports.

Current read-only Docker context is desktop-linux with the same expected Unix
socket, no DOCKER_HOST/DOCKER_CONTEXT override; the socket is still absent.
One host sample load5.76/6.06/5.04 is not a stable native readiness chain.
No unrelated process/container/VM is stopped/restarted/throttled and no daemon
is switched or started. Next close remaining static/helper/installation
observations, then independently review narrow native APK verification and
actual carrier/install/full-image/helper/expired/revoked gates when this same
Docker runtime is ready. Node HIGH/embedded coverage remains open; only an
admitted Node/verifier and stable runtime permit original15-output/ENOSPC/OOM
work. The metadata prescan cannot admit those executions.

Only six repository documents change; all2148 Go files retain matching earlier
race/vet/Contract evidence, without reruns for reporting. Existing mise/Docker,
Go1.26.8/old locks, E-only frozen-R policy and load90/compiler300/container390/
controller450/wrapper560/outer600,2CPU/2GiB/128PIDs,/work1GiB,/tmp64MiB noexec,
RO inputs/root and none network remain unchanged. Automation remains deleted;
no candidate/container/compiler/full Vault/UI or GPG/Node executes, and no
commit/push/merge/publication occurs. Phase6 remains5/15. Slice6 steps1/2/3/4
remain historical bounded E / ongoing / final topology and original16 scenarios
incomplete / post-acceptance handoff not started.15 outputs,2637 exports and
ENOSPC/OOM repair remain unverified.

## 2026-10-15 Docker restored native admission still held

Private evidence: `gpg-native-readiness-20261015-093139`. At entry, the previous
sealed579-file/55-directory checkpoint passes exact-set/SHA/size/600-file and
700-directory checks. All2557 worktree files match its final map. Actual branch
is codex/product-v1-phase-6-hardening, full HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, with263 inherited porcelain rows and
empty staging. Root remains the user-confirmed sole writer. The previous
reviewer is no longer live after an interrupted turn; a newly invoked read-only
implementation_agent reviews this continuation using the unchanged configured
role, with the same previously accepted runtime-metadata observation limit.
No old checkpoint, migration inventory, candidate/lock or automation is changed.

Five interval samples around09:33–09:40 on2026-10-15 (Asia/Shanghai) confirm
existing Docker context desktop-linux, its same Unix endpoint and daemon ID,
Docker29.8.2/Engine commit8af9fe3/Linux arm64. No DOCKER_HOST/DOCKER_CONTEXT
override is present. All15 bounded ping/version/info calls succeed,13.14–34.17ms.
Load moves8.39/5.36/3.53 to2.61/3.30/3.14; observed CPU idle moves55.41% to76.65%.
This establishes API recovery, not complete native execution admission. Across
four intervals vm_stat records112382 swap-in and145600 swap-out pages at16KiB
(1,841,266,688 and2,385,510,400 bytes). Later swapouts increase; whole-host
stability is conservatively unaccepted. memory_pressure -Q reports36% system
memory free; that single percentage does not override interval evidence.
No unrelated process/container/VM is stopped, throttled or restarted. No daemon
is switched, started or restarted. The read-only container inventory sees two
existing entries and changes neither. A whole-process comm inventory hits its
64KiB cap and its own child is killed; its partial output is failure evidence,
not a complete process inventory. Completed owned calls retain reap receipts.

The old Trivy DB expires at2026-10-15T01:19:20.78149865Z (09:19 Asia/Shanghai).
Yesterday's37-proposal and19-carrier zero-finding results remain historical;
copying files or editing metadata does not renew coverage. A new DB discovery
plan uses only the existing mise Python and reviewed bounded HTTPS helper:
official ghcr.io anonymous repository token and trivy-db:2 manifest, connect10/
request25,64KiB token in memory,4MiB manifest, no proxy/redirect/retry. The
subprocess has90seconds/64KiB per stream, within600second outer containment.
Optimized Python is explicitly refused before IO. Manifest status/header/body
SHA, OCI kind/artifact/config/one-layer descriptors and original512MiB layer
bound are checked before any further stage; this is data supply, not execution.

The first guarded discovery fails in0.965923seconds after token HTTP200/73-byte
response and before any manifest request. Caller/helper's legacy token grammar
excluded RFC6750-valid plus/slash/trailing padding. The token original was not
persisted, so its exact character is not claimed. A separately reviewed new
caller/helper admit only the RFC6750 bounded ASCII grammar,<=4096characters,
while still rejecting whitespace/quote/backslash and retaining all limits.
The held draft and first failure remain untouched; a new output directory is
used. This corrects protocol parsing without adding a trust root or credentials.

The single revised discovery completes its failed outer program in11.818996
seconds. Token HTTP200 succeeds in1.678874seconds; the fixed official manifest
request then returns curl28 SSL connection timeout in10.026526seconds, no HTTP
status and zero body. discovery_passed remains false. Raw stdout/stderr,
headers and receipts are retained; no further retry after this failure, alternate source,
longer connection budget, layer download, import, metadata modification or new
scan follows. Native candidate admission remains false.

Independent design review permits reuse of old narrow Wolfi carrier isolation,
identity checks, exact input hashing and precise container/image cleanup only
as a new run's reviewed design. Old one-time controllers are not replayed;
Wolfi APKINDEX success does not prove Alpine index/APK compatibility or an
Alpine installed root. A fresh scan of the exact authenticated carrier and
37-proposal/source identities must precede new native Alpine verification,
including fixed key, original index/all37 originals and valid-structure
wrong-key/tamper negatives with exact specific errors.

Installation/helper execution has an additional unresolved plan boundary:
37 proposal records do not include apk-tools and are not native SAT/install-if
results. Installing under the existing noexec /work with an RO container root
can block the installed shell/busybox, postinstall/trigger and GPG/helper
executions; non-root/zero-cap identity also cannot be silently promoted into an
installer. This is a conflict in the currently described execution path, not
proof that every possible compliant design is impossible. No executable writable
root, extra privilege/mount, --no-scripts workaround or fabricated installed DB
is introduced. Before actual installation, independently review a concrete
path preserving the existing trust/resource boundaries and verify actual DB/
file/owner/UID/GID/busybox links/pinentry-curses, SQLite RUNPATH, runtime mount
and helper effects. Good/wrong-key/tamper/expired/revoked GPG cases follow only
after that path, complete installed/carrier/embedded fresh coverage and runtime
readiness pass. No GPG/Node/compiler/Vault/UI or native APK/container executes.

Next continuation: check whole-host stability with bounded interval samples,
then independently review a new fresh official DB supply attempt and actual
complete-image/proposal scans. Preserve this TLS failure; do not loop it or
infer future registry availability. Review/freeze a new Alpine native verification
run only after all supply/runtime prerequisites pass. Keep installer/helper
path work separate and unaccepted until its constraints are actually resolved.
Automation remains deleted; no observation or retry is scheduled. Existing
mise/Docker, Go1.26.8/old locks, frozen-R reuse policy and load90/compiler300/
container390/controller450/wrapper560/outer600,2CPU/2GiB/128PIDs,RO inputs/root,
none network,/work1GiB and/tmp64MiB noexec remain unchanged. No commit/push/
merge/publication occurs. Only six handoff documents change; prior matching
Go/race/vet/Contract evidence is retained, with no new Go gate claim. Phase6
remains5/15. Slice6 steps1/2/3/4 remain historical bounded E / step2 ongoing /
final topology and original16 scenarios incomplete / post-acceptance handoff
not started.15 outputs,2637 exports and ENOSPC/OOM repair remain unverified.

## 2026-10-15 fresh vulnerability DB and scans with native execution held

Private evidence: `gpg-db-native-20261015-094855`. Entry checks confirm the
previous122-file/13-directory checkpoint's exact set, SHA, size and permissions,
all2557 worktree file hashes, branch codex/product-v1-phase-6-hardening and full
HEAD `91fe315641779e6ea640632538309d63ad1b303f`. The263 inherited porcelain rows
and empty staging are preserved. Root remains the user-confirmed sole writer;
the existing implementation_agent provides read-only independent reviews with
the unchanged configured role and previously accepted runtime-metadata limit.

The old DB stays expired. A new reviewed transport uses the official Trivy0.74
GCR default, `mirror.gcr.io/aquasec/trivy-db:2`; it is an official transport for
the same publisher, not a new key/trust root or a claim of byte identity with
GHCR. See [the fixed Trivy source](https://raw.githubusercontent.com/aquasecurity/trivy/v0.74.0/pkg/db/db.go)
and [official DB configuration](https://trivy.dev/docs/latest/configuration/db/).
The new raw616-byte HTTP200 manifest SHA is
e933e44d86a54b50a1b29be576796ef1e4977d6c8c7ecf67da2399535b2a6bc2.
The first validator fails on the standard empty config descriptor. A reviewed
offline correction checks its exact mediaType/size2/{} bytes/base64/SHA and
artifactType; it makes no second network request and preserves the failure.

The first exact blob range returns302 and is preserved as a failed206 check.
No automatic redirect is enabled. Its unique relative same-origin Location is
frozen and independently reviewed before one explicit request obtains the first
4MiB with206/exact Content-Range. The remaining31 ranges are fetched once, at
most two in flight, under the unchanged connect10/request25second bounds and a
narrower450second download stage. The complete133783650-byte layer SHA
f00c72cd10fe9462c58047756db3ed2429581e88c032512ec15293ecc1076e3f
passes in89.419seconds (outer89.511). No automatic proxy/retry/fallback occurs.
The process-group wrapper's ESRCH race is reviewed and repaired before use.

The separately reviewed import completes in3.939seconds (outer4.051), inside
90seconds. It validates single-gzip CRC/end/no extra member, expansion bounds,
strict tar checksums/names/type/size/zero padding, and exactly two unique regular
files into a new private directory. trivy.db is1624571904bytes, SHA
e149e60746d0b26ba2e92e27c96eb60d219c220a2183bb307679b8e09da681e5;
original143-byte metadata SHA is
670c9e2a119b98d161fa8c952dbbe25cc1fd9ecc141bcdc030b7d45e2338ffd1.
Version2/UTC UpdatedAt<=now<NextUpdate/age<=24hours and full input/output hashes
pass. UpdatedAt is2026-10-14T19:14:58.511503573Z and NextUpdate is
2026-10-15T19:14:58.511503003Z (2026-10-16 03:14:58 Asia/Shanghai). DownloadedAt
is the original year1 value; metadata is not edited to renew freshness.

Two independently reviewed scans execute sequentially with the existing mise
Trivy0.74.0, private cloned caches, offline/skip-update flags, all severities,
empty ignore input, GOMAXPROCS2,300seconds and1MiB per process stream inside
560/600second wrappers. Full inputs/tools/DB hashes and freshness pass before
and after each scan. UNKNOWN/HIGH/CRITICAL gate policy is unchanged.

- Alpine proposal:37/37 name/version/source-name/source-version and PURL records,
  Alpine edge, supported EOSL interpretation, zero findings; scanner0.674656s,
  outer6.937782s. The Third-party SBOM warning remains. This is a proposal
  metadata prescan, not actual installed/full-image/embedded coverage.
- Wolfi carrier: native manifest e02c7a98dc477e32e2f04ea2e827a132baace0fbeccb3781aa9c64ffc7982774,
  scanned config e155f0caf849076e20b844e6e2633c767f3bc11836e2571c443b3ee483db83d8;
  all19 actual installed package/source/PURL records match, zero findings;
  scanner1.640162s, outer13.242265s. All OCI descriptors/layout/index are pinned
  before/after. Exact prior eight signature/attestation receipts and source-bound
  33ELF/71edge/13generated-file audit are reused; they are not new signature or
  rebuild runs. No package.json occurs in the pinned full root/metadata.

Wolfi v1 fails in1.654895seconds before scanner/output-directory creation because
it wrongly requires an empty JS extraction directory to exist. The sealed old
checkpoint never contained that directory. Independently reviewed v2 requires
its absence/non-symlink and checks no package.json in both original full root
and metadata. It writes a new output directory; the first failure remains.
`embedded_node_coverage_complete` remains null in the original inventory. No
final Node embedded coverage, GPG execution or installation is claimed.

Six interval read-only host samples around09:50–10:13 retain desktop-linux,
the original Unix endpoint and daemon ID, Docker29.8.2/8af9fe3/Linux arm64.
All18 ping/version/info calls succeed in13.407–180.426ms. Initial load2.40 and
idle76.62% do not establish stable readiness. Across five intervals swapins
increase1312960 and swapouts1457260 pages (16KiB each). The last interval alone
adds221501in/339584out. Final load is17.47/8.33/5.16. The final top CPU call
hits5.002693seconds, its own child is killed/reaped, and current CPU is unknown.
This is failed sampling evidence, not a CPU/readiness pass. No unrelated
process/container/VM is stopped, throttled, restarted or inspected beyond the
bounded observations; no daemon is switched/started/restarted. Native admission
stays false. No native APK, installer, GPG, Node, container or compiler executes.

Installation/GPG-helper paths are independently reviewed as a separate boundary,
not admitted by these scans. No concrete compliant new installation topology is
frozen here. The old RO root/noexec work/tmp/non-root zero-cap path still cannot
be assumed to run postinstall/triggers, installed shells, pinentry or helpers.
The37 proposals do not include apk-tools and do not prove native SAT/install-if,
installed DB/file/owner/UID/GID semantics, busybox links, pinentry-curses, SQLite
RUNPATH or runtime mtab. No extra privilege/executable writable root, --no-scripts,
fabricated installed DB or acceptance claim is introduced. Independently review
a concrete installation/helper execution plan before that work; original/wrong
key/tamper/expired/revoked GPG cases and complete installed/embedded coverage
remain future gates. This held path is not proof that every compliant design is
impossible.

Next: after the user resumes, recheck interval host stability and DB/scan freshness;
freeze and independently review a new native Alpine APK-only diagnostic with the
original index/all37 originals, fixed trusted key and valid-structure wrong-key/
tamper negatives. Do not replay old one-time controllers or broaden that check
into installation/helper execution. No further sampling or retry is scheduled.
The deleted automation remains off. Existing mise/Docker, Go1.26.8/old locks,
old candidates, two issuers, frozen-R reuse and load90/compiler300/container390/
controller450/wrapper560/outer600,2CPU/2GiB/128PIDs,RO inputs/root,none network,
/work1GiB and/tmp64MiB noexec remain unchanged. Only six handoff documents change;
no Go/race/vet/Contract run is claimed for this data/doc continuation, and no
commit/push/merge/release occurs. Phase6 remains5/15. Slice6 steps1/2/3/4 remain
historical bounded E / step2 ongoing with fresh supply scans passed and native
execution held / final live topology and original16 scenarios incomplete /
post-acceptance handoff not started.15 outputs,2637 exports and ENOSPC/OOM repair
remain unverified.

## 2026-10-15 interval readiness recheck keeps native APK held

Private evidence: `gpg-native-recheck-20261015-102127`. The previous381-file/
53-directory checkpoint passes full exact-set/SHA/size/mode checks at entry;
all2557 worktree files match its final map. Actual branch remains
codex/product-v1-phase-6-hardening, full HEAD
`91fe315641779e6ea640632538309d63ad1b303f`,263 inherited porcelain rows, empty
staging. Existing human-confirmed sole writing and read-only implementation_agent
review arrangements remain. No old material, lock or automation is rewritten.

Independent review first approves only three manual bounded read-only samples,
not native execution. Actual completion times are10:23:32,10:24:59 and10:26:18
Asia/Shanghai, intervals87.190238 and78.641069seconds. Each uses the unchanged
5second/64KiB per-command bound; Docker Unix HTTP keeps connect2/total3seconds.
All27 calls exit0 and reap, with no timeout, signal or truncation. The original
desktop-linux context/Unix endpoint/daemon ID and29.8.2/8af9fe3/Linux arm64
remain exact. All9 ping/version/info calls pass in0.030789–0.529273seconds.

Load moves28.44/22.90/14.41 to20.16/21.67/14.79 then16.79/20.44/14.95.
Observed top CPU idle is8.19%,6.22%,33.65%. These improvements do not establish
whole-host stability: vm_stat16KiB-page swapin/out deltas are
+872005/+909586 and+272658/+164312. Both intervals retain substantial swapout.
Independent actual-result review confirms native_readiness_pass=false; successful
API calls and lower final load do not override that boundary. No native APK
run is frozen or executed, no image is loaded and no container is created.
No unrelated process/container/VM is stopped, throttled or restarted; no Docker
daemon switch/start/restart occurs. All tracked owned sampling processes reap;
no complete whole-host process inventory is claimed. No further sample is scheduled.

At10:26:49, the unchanged original DB metadata SHA670c9e2a119b98d161fa8c952dbbe25cc1fd9ecc141bcdc030b7d45e2338ffd1
passes Version2/UTC UpdatedAt<=now<NextUpdate/age<=24h (age25911.256seconds).
NextUpdate remains2026-10-15T19:14:58.511503003Z (Oct16 03:14:58 Asia/Shanghai).
The37-proposal raw report SHA0a63870ad450a1d5fc1eedc7e98571202d0cce9c8c44c45415d0bd701609f967
and19-Wolfi raw report SHA6ead85b71f90ef4a3bc52bff883c67a66692c876bc2052d60cee7d9598d7e1c5
match. Their actual37/19 package counts and zero findings are reused as the
same-byte supply evidence, not new scans, installed GPG/Node coverage or native
execution admission. The complete original checkpoint is read-only; metadata
is not edited, and no fresh DB acquisition/import/scanner/build runs.

Next manual continuation must recheck host intervals and actual DB/scan freshness.
Only after stability and supply prerequisites pass should a new native APK-only
run be frozen and independently reviewed: exact original Alpine index/all37 APKs,
fixed key, valid-structure wrong-key/tamper negatives, full inputs pre/post and
precise owned cleanup under original limits. Old one-time controllers remain
read-only references. Installation and GPG-helper execution need their own
concrete reviewed path; scans or eventual APK verification cannot admit them.
No privilege, quota, executable writable root, timeout or evidence gate changes.
Existing mise/Docker, Go1.26.8/old locks/candidates, two issuers, frozen-R rules,
load90/compiler300/container390/controller450/wrapper560/outer600,2CPU/2GiB/
128PIDs,none network,RO root/inputs,/work1GiB and/tmp64MiB noexec remain unchanged.
Automation remains deleted; no new task or recurring observation is created.
Only six handoff documents change. No Go source/test/Contract, staging, commit,
push, merge or release occurs. Phase6 remains5/15; Slice6 steps1/2/3/4 remain
historical bounded E / step2 ongoing with native admission held / final topology,
original16 and formal independent acceptance incomplete / post-acceptance
handoff not started.15 outputs,2637 exports and ENOSPC/OOM remain unverified.

## 2026-10-19 local source checkpoint and held TUF chain

The user requests a local source checkpoint while the host is resource
constrained. This continuation starts from the fixed handoff commit
`91fe315641779e6ea640632538309d63ad1b303f` on
`codex/product-v1-phase-6-hardening`. Independent read-only review approves
three dependency-preserving batches: the complete coupled source/tests/tools
and candidate metadata; design and audit history; then the current progress
update. The first two commits are
`9de98bb8f6af191c2318d05babde1608d1bba2ae` and
`c3ddabae420d332b97ffb5386d031ffe04c2d7ef`; the following progress commit
completes the local checkpoint. Git history records the new HEAD. Historical
candidate source pins, old receipts and locks retain their original values.
This is neither final Slice6 step4 nor a push, merge, publication or release.

### Preserved implementation and validation scope

The source batch includes the held source-bound v2 Controller/agent TLS and
CRL components, Coding execution/lease/fence/observation work, dedicated
Control storage and exact source identity, operator bootstrap/process
observation/post-observation delivery, their command wiring, tests and local
tools. Separate Coding candidate JSON/recipe records remain unsigned and
not admitted; metadata is not restored OCI payloads or live supply evidence.
No source behavior is changed during this checkpoint. `ProfileV2.Validate`
and the production Provider v3 startup path remain fail-closed. There are still
only broker/general issuers, with PostgreSQL using general; no old identity
count or deployment list becomes the final live topology.

Lightweight full comparisons show that all2148 Git-visible Go files match
`race-vault-remediation-20261013/gate-go-snapshot.json`, with no additions,
deletions or SHA256 differences. All2390 Git-visible non-document files also
match that checkpoint's `final-files.json` by exact set and SHA256, including
the non-Go inputs. Thus the already recorded full race/shuffle/count1 run
with `-p=6` remains applicable in its original scope: exit0 in503.355seconds
under the unchanged600second bound. Full vet and both Contract lock checks
also passed on that source. None is rerun now. These are not default package
concurrency, CI, a fresh Docker integration run or production acceptance;
earlier timeouts and scoped integration failures remain failed evidence.
Existing Docker/Linux records retain their own original inputs and limits.

The sole writer explicitly stages only reviewed repository paths. Private
recovery directories, migration packages, raw logs/receipts, OCI payloads,
tool binaries and credentials stay outside these commits. The transaction
has a separate private record, `source-commit-checkpoint-20261019-092639`.
No new dependency, global environment, compiler, container, scanner or build
is started. Existing mise/Docker, ordinary Go1.26.8, candidate-only exceptions,
9bindings,64barriers, frozen-R reuse and all resource/time bounds are unchanged.
Automation remains off; no recurring observation is restored.

### Latest actual diagnostic result

The independently reviewed private continuation
`tuf-chain-resume-20261019-062739` reuses the fixed four-case TUF implementation
and frozen root/role/target inputs. It preserves four17-file mirrors and adds
a stronger same-boot refusal before reusing the prior limited N4 socket
boundary proof. Its25 new tests actually pass; this is component evidence,
not host readiness or TUF authentication. The same-boot predicate consumes
bounded original uptime receipts under a normal UTC-clock premise and grants
no admission by itself. A reboot or relevant tool/profile/execution-chain
change prevents silently inheriting the old N4 observation.

The last actual host sample is2026-10-19 14:53:30 Asia/Shanghai:

| Original first-sample check | Observed | Result |
| --- | --- | --- |
| Load1 at most6 | 5.15 | Pass |
| CPU idle at least60% | 35.65% | Fail |
| Memory free at least30% | 31% | Pass |

All nine base observation commands complete naturally. Fast Docker responses
do not substitute for the missing stable interval. The first CPU refusal
stops the controller; the outer recorder's exit0 only records that failure.
No second sample, Mach auxiliary sample, interval swap conclusion or TUF case
starts. All414 locked input files,9aliases and the four mirrors remain exact
before/after; the original failure identity is retained without retry. The
whole new evidence directory is sealed and independently reviewed, solely
as evidence preservation. No ongoing host-performance conclusion is implied
by the dated first sample, and no additional sample is taken for this commit.

Timestamp812 remains a retained449-byte, unverified candidate. Matching its
declared snapshot version166 does not authenticate that snapshot, complete
the root chain or establish an official latest state. The intended three
cryptographic rejection cases and one positive case have **zero actual
starts** in this attempt. No fresh vulnerability scan, Python archive/SDK
authentication, whole-chain90/120second benefit result,15 generated-output
acceptance or ENOSPC/OOM repair is claimed. Earlier DB/37/19 scan results keep
their original dates and scope; they do not establish freshness on October19.

### Fixed Slice6 steps and next acceptable result

| Step | Status at this checkpoint |
| --- | --- |
| 1. Bounded Guest E evidence | Historical acceptance only within its original scope |
| 2. Remaining startup audit and real security boundaries | Ongoing; latest host CPU prerequisite failed, TUF four cases not started |
| 3. Complete Profile-v2 live inventory, original16 scenarios and independent formal review | Incomplete |
| 4. Post-acceptance documentation/commit/push handoff | Not started; these intermediate local commits are not that acceptance |

Phase6 remains **5/15**. On a later manual continuation, use a new identity,
independently review identity/inputs, and apply the original two-sample host
and same-boot conditions. Only a full pass permits the reviewed four-case
cryptographic run under its original per-case/parent/output bounds, followed
by independent actual-result review. Dynamic external inputs and subsequent
recovery/import/real metadata/37/19 scans remain separately reviewed stages.
APK, installation/GPG helpers and complete Node supply admission retain
their own gates; one passing component cannot replace them. Preserve every
old failure and lock, and do not widen cache/index/evidence reuse, quotas,
timeouts or public admission to clear this checkpoint.

## 2026-10-19 two-sample recheck refuses interval paging

The user authorizes one new identity after independent identity/input review,
the original two-sample host gate, and only on a complete pass the existing
four-case TUF implementation. New private evidence is
`tuf-chain-resume-20261019-115426`; its source workspace starts clean at
`6368a344f26c88ad4a3a54cfad80e91c1abeea3b` on the same implementation branch.
No source behavior, old lock, old receipt or failed identity is changed.

Independent review checks the new512-file lock and all9 original tool aliases.
All414 previous input rows remain present;98 added rows are96 original-byte
copies, one new path-rebound mirror manifest and the old input lock itself.
The copies contain the same15 Python modules including the frozen guard test,
13 host source/lock files and68 mirror files. All four trees retain17 files
each, exact directories/modes, role/target originals, case order and negative
mutations. Only owned mirror paths/file URIs and explicit provenance metadata
change. Old failed host/controller outputs are not runtime inputs. The old25
guard tests are reused in their unchanged-source scope, not rerun. Full original
tool/source/SDK checks pass; metadata time fields remain in the future without
conferring signature authentication. No dynamic external material is acquired.

The one actual attempt observes:

| Base observation | First sample | Second sample | Original condition |
| --- | --- | --- | --- |
| Time, Asia/Shanghai | 19:57:03 | 19:58:09 | Same attempt |
| Load1 | 1.02 | 1.36 | At most6; both pass |
| Top CPU idle | 82.61% | 87.99% | At least60%; both pass |
| Memory free | 33% | 33% | At least30%; both pass |
| Swapin pages | 262110085 | 262114197 | Delta4112 |
| Swapout pages | 286929986 | 286931442 | Delta1456 |

The monotonic base interval is65.723560041seconds. The actual16KiB-page deltas
are64.25MiB swapin and22.75MiB swapout. The original upper bounds are
32pages/second for swapin (about2103.154 pages in this interval) and zero
swapout. Both fail. The first guard passes naturally in2.090067seconds and
includes the additional Mach CPU check, idle95.351137%. The second guard
returns1 naturally in0.719497seconds with `interval paging bounds`, before
starting its Mach observer or creating a readiness result. The positive
first-state receipt is not a complete dual-host admission.

All18 base commands complete naturally with their original5second/64KiB
bounds, no timeout, signal or truncation, and all children reaped. Both samples
retain the original desktop-linux context/Unix endpoint/daemon identity and
29.8.2/8af9fe3/Linux arm64 version. All six Docker ping/version/info calls pass
in10.464–42.978ms. Those responses and good CPU scalars do not override the
paging refusal. The600second host recorder exits0 in66.824462seconds solely
to record the failed summary; the controller exits1 for `host runner result`.
No TUF claim,90second parent, case state or four-case result exists. **TUF
actual cases started:0.** Timestamp812 and the frozen top chain remain unverified.

Both same-boot predicates pass within their normal-UTC-clock and limited old
N4 socket-proof scope; they do not grant host, general network or TUF admission.
All512 locked inputs match completely before/after and on final readback,
along with9aliases and four17-file mirrors; post_error is null. The previous
sealed184-file/19-directory evidence set, index and seal remain exact. Every
old failure is retained; this identity is not retried and no further sample
is scheduled. The observation does not identify a responsible process or
describe host performance after these two dated samples. No unrelated process,
container or VM is stopped, limited or restarted.

This stage changes only the three progress documents under the standing
commit/push direction. No new Go/unit/race/vet/Contract test, scanner, compiler,
container, build, native APK/GPG execution or tool installation runs; previously
matching source evidence remains limited to its original scope. Existing mise,
two issuers, public holds,9bindings/64barriers, quotas/deadlines and evidence-reuse
rules are unchanged. Automation stays off. Recording this stage checkpoint
does not complete Slice6 step4 or authenticate any new supply input.

Phase6 remains **5/15**. Slice6 step1 retains bounded historical E acceptance;
step2 is ongoing with the interval paging prerequisite failed; step3 complete
live topology/original16/independent formal acceptance is incomplete; step4
post-acceptance handoff is not started. Next manual continuation requires a
new identity/input review and a complete original dual-host and same-boot pass
before the reviewed four cryptographic cases. Subsequent external recovery,
real metadata and37/19 scans remain separately reviewed. No gate, resource
quota, timeout, cache/index rule or evidence-reuse standard is relaxed.

## 2026-10-19 host gate passes, TUF root attribution held

New private identity: `tuf-chain-resume-20261019-124329`, with the workspace
starting clean at`36e81a705b336033d3a2258baaec4e839e148a7d`. Independent
review approves only this exclusive identity once, with the same controller,
runner, host source lock and original resource/time boundaries. All512 previous
input rows remain;98 additional rows are96 same-byte source/host/mirror copies,
the path-rebound manifest and the previous input lock. The610-file table,
9 tool aliases and four17-file mirrors are fully checked. No previous failed
host/controller output is a runtime input. The frozen25 guard tests are reused
only for the unchanged source; no test or implementation is modified or rerun.

The original host gate actually passes in this bounded window:

| Observation | First sample | Second sample |
| --- | --- | --- |
| Time, Asia/Shanghai | 20:45:13 | 20:46:18 |
| Load1 | 2.01 | 1.85 |
| Top CPU idle | 88.18% | 77.96% |
| Mach idle, display value | 89.61039% | 70.987039% |
| Memory free | 38% | 42% |
| Swapin pages | 262161297 | 262161402 |
| Swapout pages | 287017966 | 287017966 |

The monotonic interval is65.717408167seconds. Swapin+105 16KiB pages is
1.640625MiB, below the original32pages/second limit (about2102.957 pages);
swapout is zero. Both base/Mach/source/SDK and same-daemon checks pass without
changing a threshold. HOST600 exits0 in67.450473seconds and the controller
immediately starts the separately bounded TUF parent. Original age120 checks
pass during that execution; later report readback is not a new readiness grant.
Same-boot checks retain only the normal UTC-clock/old N4 limited-socket scope.
No ongoing-performance or production-readiness conclusion follows.

### First actual TUF case and two distinct unresolved checks

Only `bad-root13` starts, under the original pinned Cosign3.1.3, deny-network
profile, empty private state and unchanged argv/environment. Its one mutation
changes `13.root.json`'s signed expiry while preserving original signatures.
The CLI naturally exits1 in0.795449seconds; stdout is empty, stderr1232bytes,
no active signal, timeout or truncation, and the process is reaped. Actual
stderr contains four lines: the two known modern-client file-URI warnings,
then `Error: P` and an untimestamped `error during command execution: P`.
Both complete payloads are identical and contain the expected signature-
threshold error text. The frozen parser instead requires three lines and a
timestamp on its final line, so it fails first with
`exact expected warning/error line count`. The subsequent no-success/target
assertions in the case body are not reached; no case acceptance is recorded.

Independent raw-state review also finds one cached, unverified `root.json`
with signed version14, JSON-equal to the frozen mirror's `14.root.json`
(its serialized bytes differ). The modern warnings request `15.root.json`,
whereas the selected mutation is in13. This does not by itself identify the
modern versus legacy root consumption path or prove that13 was never read.
It does mean existing evidence does not establish that the13 mutation caused
the threshold refusal. The unchanged good case was not run, so failure of the
unmodified frozen chain has not been excluded. Treating this as only a logging
format problem would leave an unproved security negative.

The parent's original sequential stop-on-failure rule prevents the timestamp,
target and good cases from starting. The90second parent exits1 naturally in
1.311914seconds; the controller exits1 with post_error null. **One case starts,
zero cases are accepted; the four-case result is0/4.** Captured partial cache
metadata and a later observation of no trusted-root target cannot substitute
for the skipped assertions or an authenticated positive. Timestamp812, the
frozen target chain, Python archive/SDK and downstream supply remain unqualified.

### Preservation and next reviewed result

All610 input rows match before/after/current,9aliases and four17-file mirrors
remain exact, and the old204-file/19-directory checkpoint/index/seal is unchanged.
All28 bounded original receipts are natural, without flags, with their children
reaped. The actual attempt leaves the four Git start/post-run raw outputs equal;
only the subsequent three progress documents change under the standing
commit/push direction. No failed identity, old metadata, receipt or manifest
is overwritten; no additional sample, test, scanner/build/container/compiler,
external input, credential change or timer is introduced. Mise/Docker, ordinary
Go1.26.8, two issuers, public holds, quotas/deadlines and reuse rules remain.

Next independently review a read-only investigation of the pinned CLI's actual
bootstrap root and modern/legacy cache/update paths, then establish mutation
causality relative to the unchanged good input. Any parser proposal must be
separately reviewed with real-format and refusal fixtures, retaining the
strict warning origin, complete matching error payload, specific refusal,
exit/no-success/target/state/closure and original bounds. Do not automatically
accept four lines, override the trusted initial root, relabel this failed
case or run a new identity on the strength of an error substring. No parser,
fixture, case order or trust-root change is made in this checkpoint.

Phase6 remains **5/15**. Slice6 step1 retains its bounded historical Guest E
acceptance; step2 continues with this actual host pass and an unaccepted TUF
diagnostic; step3 complete live inventory/original16/formal independent review
is incomplete; step4 post-acceptance handoff has not started. This progress
commit/push is an intermediate checkpoint, not formal Slice acceptance.


## 2026-10-19 fixed Cosign roots and causality held

Private read-only identity: `tuf-bootstrap-readonly-20261019-130227`, starting
from clean`acfcdeac1731d55888c7294987293db8b3729cae`. The new checkpoint does
not execute Cosign, TUF cases, host sampling, tests, a compiler, scanner or
container. Independent review precedes the static plan, each exact official
source-input batch and the FS observation hypotheses. Existing mise Python
only reads files/binary data; local mise Go source is a layout reference,
not an executed or newly installed environment. Timers stay off.

### Exact tool, entry source and separate embedded roots

The fixed139618946-byte Cosign3.1.3 retains SHA256
`5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76`.
Its embedded build info names sigstore1.10.8, sigstore-go1.2.2, legacy
go-tuf0.7.0 and go-tuf/v2 2.4.2, matching the retrieved exact-tag Cosign go.mod.
Its recorded build Go1.26.4 describes that artifact; ordinary repository
Go1.26.8 and all historical locks remain unchanged. Build info is not proof
of an independently reproducible build.

Three complete official tag trees and five source/module blobs are retrieved
with public credential-free HTTPS and checked against exact Git blob SHA1
and size, with retained SHA256. The authenticated
[initialize entry](https://github.com/sigstore/cosign/blob/v3.1.3/cmd/cosign/cli/initialize/init.go)
leaves rootFileBytes nil without`--root`, tries modern signing config and
live trusted root first, and calls legacy.Initialize with that nil external
root if the modern result remains nil. Its two warnings are separate from
legacy's subsequent failure. The
[later TUF helper](https://github.com/sigstore/cosign/blob/v3.1.3/pkg/cosign/tuf.go)
can read CachePath/URLToPath(mirror)/root.json for subsequent operations;
that helper is not initialize's bootstrap entry.

A reviewed static Mach-O/FS mapping checks file-backed VM ranges, exact
variable/table references, slice bounds, all14 records including directories,
file paths, content ranges and the exact compiler checksum. All11 embedded
file blobs also match official tag-tree path/size/Git blob SHA1. Three root
files are extracted without executing the artifact:

| Static module file | Signed version | Bytes including LF | SHA256 |
| --- | --- | --- | --- |
| legacy sigstore repository/root.json | 12 | 5414 | `874bcce852d0eb8346bcc7fc1816fddd9cb4a8664ba6a43c1101834cea6ba2a4` |
| modern sigstore-go repository/root.json | 14 | 5491 | `a0dfcc5d51c1ce4a66b541a3fff0afa97225ccc40456b21140bb2e2f113122e2` |
| modern staging_root.json | 13 | 4220 | `f0a8b825e7e504c36d2f4bac2c97b7a78b2abb152f3fd3b017496c20e031468e` |

D4's cached URL-directory root equals the modern14 file byte for byte.
The staging13 is a different file from the production mirror's13.root.json.
These are static module-storage associations, not proof of which file D4
consumed, authenticated or rejected. Local Go1.26.8 layout against the
artifact's Go1.26.4 remains a bounded self-consistency hypothesis, not a
whole-ABI claim. The first observer's plain SHA256-prefix assumption fails
and stays recorded as failure. Exact local compiler source instead defines
size-dependent toolchain checksums; separately reviewed V2 passes those
checks plus all original structural and independent blob checks. This
corrects a new observation hypothesis; no host/TUF guard is changed.

### Causality still held and conditional correction

D4 also has a separate tuf.db directory. Its sealed000001.log is0 bytes;
a no-write read cannot establish legacy initialization or a root13 read.
Complete good/bad-root13 mirror comparison confirms only13.root.json changes,
with signed.expires the sole JSON difference and signatures unchanged.
Signature-key-ID overlap is metadata evidence only, not cryptographic
verification. Cached modern14 cannot establish that legacy starts at14;
legacy's static12 makes a12-to13 rotation candidate consistent. Actual
legacy selection/update stages and mutation/refusal causality remain unproved.
The unchanged good was never run, so an unrelated broken base is not excluded.

The legacy client raw request fails at10.008622seconds; one separately reviewed
immutable official blob API request fails at10.008472seconds; a previously
unattempted legacy root-file request fails at10.010188seconds. Each triggers
the original whole-request10second deadline with zero body, is retained as
failure, and is not relabelled by later static extraction. Network stops after
the third failure; no endpoint loop or additional unattempted request follows.
Complete legacy/modern client and updater source remains missing. Historical
web summaries are historical design evidence, not newly authenticated source.

The independently reviewed proposal remains conditional: first complete the
exact client/updater/error-emission source chain; then review a strict fixed-
version four-line negative frame and refusal fixtures. Preserve both warning
origins, complete equal error payloads and the specific case refusal, natural
exit, no-success/target, state identity, full input closure and all existing
bounds. Do not accept error substrings or a broad three/four-line union,
replace the initial root or automatically retarget root13 to15. Wrong lines,
foreign origin, unmatched payload, wrong-case refusal, success target/output,
exit/flag/post-identity failures and a broken good must remain refusals.

Only a new reviewed identity with fresh original dual-host/supply/isolation
admission may execute the unchanged four-case order and25/90second limits.
Negative acceptance remains provisional until the same frozen-base unchanged
good fully authenticates and the entire four-case result passes independent
actual review. No fifth case, order change, cache/index/reuse change, third
executor, larger quota or longer timeout is proposed. No implementation or
refusal tests are executed in this checkpoint; old D4 stays **0/4**.

D4's229-file/26-directory checkpoint, its index/seal, the frozen input rows
and all earlier failure records are preserved. Only three progress documents
change for the standing normal commit/push checkpoint. Phase6 remains **5/15**;
Slice6 step1 keeps bounded historical Guest E, step2 continues with full
source/actual causality held, step3 final topology/original16/formal independent
review incomplete, step4 post-acceptance handoff not started.


## 2026-10-19 fixed Cosign client and error source recovery

New private identity: `tuf-source-recovery-20261019-133746`, from clean
`733ffa878dc5a74bdde32a7f729bb002c7278084`. Independent identity/input review
precedes each exact source batch and the separate Cobra candidate consumption.
No failed source/D4 identity is rerun, and none of its original receipts is
rewritten. Existing mise Python reads source/data only; no global environment,
CLI/TUF/host test, compiler, scanner, container or timer is started.

### Retrieved source and remaining input failures

There are32 actual public credential-free HTTPS requests:29 succeed, three
fail at the original whole-request10second deadline. Twenty-seven source/module
files are verified, including the separately reviewed61142-byte Cobra source,
and two complete go-tuf trees are retained. Exact known blobs match approved
path/size/Git blob SHA1, with raw HTTP bodies, status/headers and SHA256 retained.
Cobra Contents metadata is independently reviewed before strict LF/base64,
roundtrip, size and blob-SHA decoding into a new private file; that does not
relabel the earlier failed Cobra recursive-tree request.

The three failures take10.012913,10.656768 and10.012695seconds respectively.
The util raw request recordsHTTP200 but captures zero body and fails its
10second deadline; one reviewed immutable official blob API also fails.
Both stay failures, and no further util endpoint is tried. The exact
VersionedPath/hash-error helper source remains missing. UI env/common/sign
candidate sources do not locate a global standard-log flag setter. These
are retained gaps, not a complete-source or reproducible-binary claim.

Before F2, independent review holds a fetcher draft that would classify TLS
certificate/protocol errors as continuable OSError and allow empty candidate
content. The unexecuted draft is retained; SSL errors are changed to stop
before OSError handling, and candidate content must be nonempty. Only after
reviewing the corrected SHA does F2 execute. F1 has no observed SSL error;
its actual timeout and successful TLS/blob evidence are preserved. All source
requests retain the original1MiB cap, no authentication/redirect/retry, and
stop the batch on non-transport integrity/status/TLS/size failures.

### Source-supported cache and refusal paths

The recovered exact-version sources now distinguish the two clients:

| Path | Source-supported behavior | Evidence limit |
| --- | --- | --- |
| modern sigstore-go1.2.2 / go-tuf2.4.2 | DefaultRoot is embedded14; New uses CachePath/URLToPath(mirror), persists the input root before Refresh, then begins online root loading at version+1 via HTTP fetcher | Explains partial14 and file-URI15 warnings; not remote authentication |
| legacy sigstore1.10.8 / go-tuf0.7.0 | MemoryLocalStore is seeded only from TUF_ROOT/tuf.db; nil external root and absent local root select embedded12; Init checks signatures while ignoring initial expiry | Source selection rule, not a new replay or crypto verdict |
| legacy UpdateRoots | Calls VersionedPath(root.json,13), reads through FileRemoteStore, verifies old-root threshold and new self-signatures, exact+1, then final-root expiry | util helper body and actual D4 read trace remain missing |
| legacy disk state | updateClient synchronizes memory to disk only after Update succeeds | Empty D4 LevelDB log does not prove absence of initialization or reads |

See the exact [legacy client](https://github.com/sigstore/sigstore/blob/v1.10.8/pkg/tuf/client.go),
[legacy updater](https://github.com/theupdateframework/go-tuf/blob/v0.7.0/client/client.go)
and [modern updater](https://github.com/theupdateframework/go-tuf/blob/v2.4.2/metadata/updater/updater.go).
The canonical signature verifier covers the whole signed object, including
expires. The unchanged signature list and sole expiry mutation therefore
fit the root-threshold refusal mechanism. They do not replace the unexecuted
unchanged good comparison or prove D4 actually read13. Modern14's URL cache
is not imported as legacy's initial root.

The D4 complete error payload matches the recovered legacy Update wrapper
chain; an Init failure would use a different wrapper, while modern failures
are the preceding warnings. [Cobra ExecuteC](https://github.com/spf13/cobra/blob/v1.10.2/command.go)
prints Error:P and [Cosign main](https://github.com/sigstore/cosign/blob/v3.1.3/cmd/cosign/main.go)
prints error during command execution:P after Execute returns. This explains
the two matching payload lines in the four-line raw stderr. Their observed
lack of a timestamp is retained; the global flag initializer was not found
in the selected sources and is not claimed to be closed.

Root/timestamp errors pass the error-updating-mirror wrapper; target download
has a different downloading-target wrapper. The proposal separates these
case payloads. Only the root payload was actually observed; timestamp/target
full messages remain predictions, and target's wrong-sha256 leaf still relies
on the frozen expectation with the util formatter source missing. The old
embedded trusted-root target also differs in size/hash from the frozen target;
it cannot be treated as an already authenticated new target or an actual
download observation.

### Conditional correction and retained acceptance boundary

First resolve the util source gap under independent input review and review
the logger-attribution limit against the fixed tool's actual raw output.
Then independently review a strict fixed-version four-line negative parser:
two original-origin warnings, Error:P and the untimestamped final P, with
complete identical, case-specific payloads. Preserve all original receipt,
exit, stdout/no-success/target, state identity, full input closure and bounded
execution checks. Keep frozen tests and add refusal fixtures for wrong lines,
origins, payloads/cases, success artifacts, exit/flags and post-state failures.
No broad three/four-line union, generic substring, changed trust root or
root13-to15 retargeting is proposed. Old D4 raw may test format only; it stays
a failed case rather than gaining retroactive acceptance.

Implementation and tests are not performed here. A later new reviewed identity
must pass fresh original dual-host/same-boot/supply/isolation gates before the
unchanged four-case order and25second children/90second parent/1MiB bounds.
Negative verdicts remain provisional until the same frozen-base unchanged
good authenticates all required roles/targets and all four pass joint actual
independent review. Current TUF result remains **0/4**.

All old evidence,9 bindings,64 barriers, cache/index/reuse standards, resource
limits, Go1.26.8 and historical locks remain unchanged. Only three progress
documents change for the standing normal commit/push checkpoint. Phase6 stays
**5/15**; Slice6 step1 is bounded historical Guest E, step2 ongoing with source
helper and actual causality gaps, step3 final inventory/original16/formal review
incomplete, step4 post-acceptance handoff not started.

## 2026-10-20 util and standard-log source correspondence

New private identity: `tuf-source-gap-20261019-151705`, from clean
`3039aadec98427b51bb26b870cc36f3b86a070bf`. Source observations use UTC19;
this checkpoint uses Asia/Shanghai20. Identity/input/source paths, private
static readers and dynamic candidate decoding receive independent review before
execution. Existing mise Python reads data only; no downloaded source, Cosign,
Go toolchain, host/TUF gate, build, scanner, container or repository test runs.

### Restored helpers and standard-log attribution

All19 public credential-free requests succeed within the original10second
whole-request/1MiB bounds, with no redirect/retry. Eighteen fixed-version
source/module files and one complete2138-entry containerregistry tree are
verified by complete sizes/hashes/Git blobs and strict Contents decoding.
Raw responses and original failure records remain private outside Git.

The exact [go-tuf0.7.0 util source](https://github.com/theupdateframework/go-tuf/blob/v0.7.0/util/util.go)
confirms VersionedPath(root.json,13) produces13.root.json, and ErrWrongHash
includes full lowercase expected/got hex values. This uses a new reviewed
Contents input; the old failed raw/blob identities remain failed.

Three containerregistry sources distinguish their own loggers from standard
global log. Twelve Go1.26.4 runtime/ABI/linker/arm64/log files then support
bounded static metadata reading of the exact Cosign binary; they are source
inputs, not an installed toolchain or reproducible-build result. The final
reader verifies122694 functions,78571 unique FD offsets,213649 PC offsets and
192288 inline records, passing in1.323605958seconds after36 frozen synthetic
tests. Its sole global log.SetFlags metadata candidate is CUE's adt.init.0,
`cuelang.org/go@v0.16.1/internal/core/adt/log.go:54`, parentPC20.

Fixed binary buildinfo and verified Cosign go.mod both select cuelang.org/go
v0.16.1. Strictly decoded [CUE go.mod](https://github.com/cue-lang/cue/blob/v0.16.1/go.mod)
confirms that module before the [CUE log source](https://github.com/cue-lang/cue/blob/v0.16.1/internal/core/adt/log.go)
is decoded: its init imports standard log and calls log.SetFlags(0). The exact
[Go1.26.4 wrapper](https://github.com/golang/go/blob/go1.26.4/src/log/log.go)
delegates to std.SetFlags. This source/static correspondence explains a
configuration consistent with D4's untimestamped final line; it is not an
actual D4 call trace, argument observation or proof of all setter absence.
The complete module zip h1 and whole Cosign source-to-binary reproducibility
are not established. Eight module-identity byte tests pass before decoding.

### Preserved diagnostic failures and conservative read boundary

An initial reader rejects its incorrect DWARF mapping assumption. Later drafts
are held before execution for format/fixture issues. An actual synthetic run
fails on bytearray-versus-bytes fixture semantics; a new33-test run passes,
then a relative-plan invocation is rejected before binary open. A new absolute
invocation fails in0.419675875seconds on its etext/section-end assumption.
Every failed identity remains preserved without rerun or retrospective pass.

A separately reviewed narrow nlist observation passes in0.457751875seconds:
Go's runtime.etext is15988B before the final Mach-O text section end. The
internal-linker MinLC relation cannot be treated as that final-file equality.
The new reader pins all five observed nlist type/section/VA values and reads
only the Go text/metadata intervals within their participating file-backed
section indices. Uninterpreted suffix bytes remain of unknown origin;
CGO_ENABLED=1 is not causal proof. It does not reconstruct textsectmap or prove
global uniqueness of same-named Mach-O sections. Its text+offset bounds are
conservative refusal conditions, not a general external-linking theorem.
Full pre/post binary SHA/FD identity, all function/FD/PC/CU checks, the original
10second read window and1MiB result bounds remain. This is a private static
diagnostic correction, with no change to product, host or TUF gates.

Before CUE decoding, independent review also holds a module-space-only check
that could miss a second TAB-separated module directive. The unexecuted draft
is retained. Complete token collection, exactly one two-token module line
and conservative block-comment refusal pass the8 new frozen byte cases;
all original FD/JSON/base64/blob/readback checks remain.

### Source-supported conditional repair and remaining actual gate

The source chain is now complete for these two helper gaps: legacy embedded12
selection with nil external root, versioned13 lookup, old/new root thresholds,
exact+1, final expiry and success-only disk synchronization. Modern's partial14
cache remains separate. The sole signed.expires mutation with identical
signatures fits the canonical signed-object rejection mechanism, but actual13
consumption, cryptographic mutation causality and unchanged good are unproved.

The target error prediction must include both full hashes:
expected `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`,
got `89798404182843a00037e10a50ba95597b4d66c78b921f90909d2ce1a620fab0`.
It follows the downloading-target wrapper, unlike root/timestamp Update
errors. The old short target leaf and proposal remain unchanged historical
records; the corrected full message is a source prediction, not CLI output.

Next independently review concrete strict-four-line negative parsing and
refusal fixtures: two original-mirror constrained warnings, Error:P and the
untimestamped final P, with identical complete case-specific payloads.
Keep all original origin/role/UTF8/line/order/exit/no-success/target/state/input
refusals; add full-hash and wrong-case tests. Do not use a three/four-line
union, generic substring, root retargeting or old-D4 retroactive acceptance.
No such parser or real four-case run is implemented in this checkpoint.

A later new reviewed identity still needs fresh original dual-host/same-boot,
supply and isolation gates, unchanged four-case order,25second children,
90second parent and1MiB streams. Keep root13, nil external root and separate
cache state. Negative verdicts stay provisional until the same frozen-base
unchanged good authenticates all roles/targets and all four pass joint actual
independent review. TUF remains **0/4**.

All610 original input rows,9aliases and three old sealed checkpoints match
complete sets/hashes/modes; old locks/evidence,9 bindings,64 barriers,
cache/index/reuse rules, quotas/deadlines and repository Go1.26.8 remain intact.
Only three progress documents change for the standing normal commit/push
checkpoint, with private evidence and source retained outside Git. Timers
remain off. Phase6 stays **5/15**; Slice6 step1 historical bounded Guest E,
step2 ongoing with source gaps closed but actual gates pending, step3 final
inventory/original16/formal review incomplete, step4 post-acceptance handoff
not started. This checkpoint commit is not formal step4.

## 2026-10-20 strict four-line capture policy

New private identity: `tuf-fourline-policy-20261020-083751`, from clean
`0a86d7e57add4650e2f9e6b7c8aefcbc358af9c9`. Design/input review precedes
implementation, then a second concrete implementation/caller/test review
precedes one component-test driver. Existing mise Python3.13.16 reads data
and runs synthetic tests only; no network, Cosign, host/TUF gate, Go/Docker,
build, scan, global environment or timer change occurs.

### Implementation and preserved caller checks

The new repository [capture policy](../../tools/tuf-diagnostic-policy/README.md)
is pure Python with no CLI/process/network/filesystem behavior. Each negative
requires exactly two distinct full modern warnings, Error:P and the
untimestamped final error-during-command-execution:P. Both complete payloads
must equal the fixed case-specific expectation. The target payload includes
both full lowercase64-hex expected/got values from the prior source checkpoint.
Warning roles, their different wrappers, exact original mirror plus15.root.json
and file transport reason are fixed; good retains exactly two warnings only.
No trimming, URL normalization, substring/three-line/timestamp alternative,
partial hash or arbitrary caller-supplied error template is accepted.

The capture checker requires a closed13-field receipt, precise integer/bool
types, reviewed seven-argument invocation, natural expected exit, reaping,
original25seconds/1MiB, finite nonnegative elapsed, full received/stored/actual
byte equality, no signal/truncation/timeout, and empty negative stdout. Its
result explicitly remains format-only and unauthenticated; it cannot bind the
producer, prove signatures or supply a case/batch pass by itself.

New private copied policy/caller versions preserve all seven non-frame policy
function bodies, CASES/TOOL/target locks, fullinput/expiry/current-host checks,
good's full Root status/roles/target bytes, post identity/tree bounds and
sequential failure-stop. No-success stdout/Root-status/target-lstat facts are
recorded before parsing, including unknown errors; a broken target symlink is
present and refused. Parser failure still preserves facts, while any parser
or post error keeps the case false. The new runner is an unexecuted template:
no actual execution lock, claim, fixture mirror or cache is created here.

### Actual component results and retained evidence boundary

All three isolated child suites pass naturally under25seconds/1MiB, with
unchanged25-file implementation rows before and after:

| Suite | Actual test count | Captured elapsed seconds | Meaning |
| --- | ---: | ---: | --- |
| repository | 96 | 0.044517041 | Independent literal frames, complete hash, URI, receipt and output refusals |
| baseline | 17 | 0.043199209 | Exact old source/test copies in new isolated paths; historical baseline only |
| adapter | 18 | 0.075657375 | Nine new caller checks plus nine unaffected frozen regressions against new policy |

The old three-line positive examples remain historical baseline tests; they
are explicitly refused by the new parser and do not count as its correctness
proof. New fixtures reject altered warning role/source/wrapper/URL/version,
wrong line counts/order/duplicates/extra text, CRLF/missing-LF/invalid-UTF8/NUL,
wrong/unequal case payloads, omitted/truncated/changed/uppercase/swapped hashes,
signal/timeout/truncation, false numeric types/counts/limits/argv and nonempty
negative stdout. Caller tests exercise target presence, broken symlink,
unknown lstat, parse-failure facts, post failure and original sequence stop.

The exact old D4 raw stderr is consumed read-only as a source-bound **format
fixture only** and matches the new four-line function. No old receipt is
accepted as a new capture, no old case is reclassified and no failure identity
is rerun. The original failed run and actual TUF result stay **0/4**.

All610 original rows/9aliases and four sealed checkpoints627 files/55
directories outside their indices remain exact. Old failed receipts, recovery
sources, migration material,9 bindings,64 barriers,402 files/33 components and
cache/index/reuse standards are retained. Repository changes are three pure
tool files plus three progress documents, reviewed before normal commit/push;
raw/private adapter material remains outside Git. No Go/Provider/Contract
behavior changes, full Go rerun, larger allocation or extended deadline occurs.

Next review a new real execution identity and complete input lock binding
these exact code bytes, dynamic metadata freshness and supply evidence. Only
fresh original dual-host/same-boot/supply/isolation gates permit the original
four-case order,25second children/90second parent/1MiB execution. Keep root13,
nil external root and separate cache state; any failure preserves and stops.
Negatives remain provisional until the same frozen-base unchanged good
authenticates all roles/targets and all four pass joint actual review. No such
new run is admitted or performed here, and actual13 reads/mutation causality
remain unproved. Timers remain off. Phase6 stays **5/15**; Slice6 step1 historical
bounded Guest E, step2 ongoing, step3 final inventory/original16/formal review
incomplete, step4 post-acceptance handoff not started.

## 2026-10-20 source-bound host recheck stops before TUF

New private identity `tuf-fourcase-resume-20261020-085244` receives independent
read-only identity/input/freshness review before one original host attempt.
The722-file lock SHA256 is
`e7a1bcc9d6b8103042f281263eaa9fcbb77baed1c65ddf9f6091b5481ba11f92`.
All610 old rows and9aliases remain;112 new rows bind the owned copied sources,
mirrors and external source/evidence references. The97 byte/mode-identical
copies comprise16 modules,13 host sources/lock and68 mirror files. The four
case trees each have17 files, validated against all18 original sources and
11 target declarations; manifest changes are owned mirror/URI paths and
path_rebind provenance only. The controller changes only the invoked runner
filename to the already reviewed v3; no tool implementation changes here.
New claims, output and cache are exclusive; no old run state is copied.

A source-only preparation draft fails before creating the execution directory
because a historical resumed fixture's relative inventory entry is absent.
Its script and failure record are preserved. A new preparation script loads
the exact old-lock-bound original SOURCE module and its actual inventory,
checks the complete18-input closure, regenerates variants in memory and
compares every old/new mirror byte. It does not rerun a failed host/TUF
identity or rewrite an old inventory. The final independent review confirms
the complete import closure, all722 physical rows, aliases, copied host lock,
exclusive identity, manifest path-only diff and original bounds.

The same frozen root15/timestamp812/snapshot166/targets14 have future expiry
at pre-execution and post checks:2026-11-20T13:58:18Z,
2026-10-26T01:39:45Z,2036-10-04T08:51:19Z and2036-05-09T09:00:52Z respectively.
This is a time check, not cryptographic authentication or official-latest
admission. No new external input is fetched; native APK/image/DB/scanner
admission is outside this run. Existing fixed-tool, deny-network and same-boot
refusal checks remain; the old proof never supplies current host readiness.

The original first base sample completes at2026-10-20T00:58:05.009927Z
(08:58:05 Asia/Shanghai). Uptime load1 **3.60** and memory free **40%** pass,
but top CPU idle **46.22%** fails the original60% floor. The first90-second
guard naturally exits1 in1.246702083seconds with `stable sample bounds`.
Mach, second sample and host-first/readiness are not reached. There is no
dual-sample interval or paging-delta conclusion and no process attribution.
The three Docker ping/version/info calls complete in25.795/18.549/27.364ms,
retaining the exact daemon/version; that single window does not grant admission.

All13 bounded receipts (nine leaves and four outer/negative captures) are
natural, reaped and within their original time/byte bounds, without signal,
truncation or timeout. The host wrapper exits0 in1.349223625seconds but its
summary explicitly says readiness=false; controller correctly rejects
`host runner result`, naturally exits1 and records post_error=null. No
parent90, case claim, chain-runs/cache or TUF case starts: **0/4**, unchanged.
The actual raw result and absent stages receive independent read-only review;
the failure identity is retained without retry.

All722 input rows match before/after/current;9aliases and four mirrors stay
exact. Five old sealed checkpoints retain all679 files excluding five indices,
59 directories and exact indices/external seals. The original9 bindings,
64 barriers, old402 files/33 components and all failed evidence remain intact.
Frozen96 parser and18 adapter/unaffected tests are reused within unchanged
source scope;17 old baseline tests remain separate. No unit/Go/race/vet/Contract
rerun, build, scan or container is started, and no Go1.26.8/release lock,
cache/index/reuse/guard/timeout/quota change occurs. Existing mise Python3.13.16
`-B` supplies this run without a global install. Timers remain off.

Only three reviewed progress documents follow the standing normal commit/push
workflow, with private raw evidence outside Git. Next use a separately reviewed
new identity; original complete dual readiness must pass before unchanged TUF
four cases, and negative acceptance still requires same-base good all-role/
all11-target authentication and actual joint causal review. Dynamic inputs,
if introduced, need their own stage review. Phase6 stays **5/15**; Slice6 step1
historical bounded Guest E, step2 ongoing, step3 final inventory/original16/
formal review incomplete, step4 post-acceptance handoff not started.

## 2026-10-20 dual-host recheck rejects interval swapin

New private identity `tuf-fourcase-resume-20261020-092705` receives independent
identity/complete-input/expiry review before one original dual-host attempt.
Its825-file lock SHA256 is
`1d06c46a5ee608a9c119393b23515699a0d02f9dd7726c9be11075f2d6269a4b`.
All722 prior rows, including the original610, and9aliases remain unchanged.
The103 new rows bind99 owned C inputs and four source/preparation references;
98 exact copies comprise17 modules including the unchanged v3 controller,
13 host sources/lock and68 mirror files. New manifest changes only owned
mirror/URI and three path_rebind provenance values. All18 original sources,
11 target declarations and four17-file variants match their frozen bytes.
No old failed output, host admission or cache is copied. The unchanged-source
96 parser/18 adapter tests are reused;17 historical baseline tests stay separate.
No test or tool implementation is changed or rerun.

Frozen root15/timestamp812/snapshot166/targets14 remain before their original
2026-11-20/2026-10-26/2036-10-04/2036-05-09 expiries at actual pre/post checks.
This is a time check, not signature authentication or official-latest proof.
No new external input, DB, image or native/scanner admission is introduced.
The complete import closure, fixed tools, sandbox profile and same-boot refusal
are independently checked. Original host5/70/90/600, gap65/age120,
load6/topidle60/free30/Mach/paging/daemon and TUF25/90/1MiB/GOMAXPROCS2
bounds remain unchanged. Any unfrozen dynamic input still needs stage review.

Actual base samples, Asia/Shanghai on2026-10-20:

| Measurement | 09:29:40 | 09:30:46 |
| --- | --- | --- |
| load1 | 3.47 | 3.01 |
| top CPU idle | 79.37% | 75.52% |
| memory free | 40% | 33% |
| Mach idle display | 84.791252%, passes | not reached |
| swapin cumulative16KiB pages | 262287091 | 262293222 |
| swapout cumulative16KiB pages | 287207766 | 287207766 |

Both base samples pass scalar floors, and the first Mach observation passes.
The base monotonic interval is65.817397042seconds; swapin increases6131 pages
(95.796875MiB), exceeding the original32*gap=2106.156705pages limit, while
swapout remains zero. The second guard naturally exits1 in0.819408875seconds
with `interval paging bounds`, before its Mach observation. This identifies
the failed interval predicate, not any process responsible or later readiness.
The first guard naturally exits0 in1.827086375seconds. All six Docker
ping/version/info calls pass in15.237–58.874ms with the same fixed daemon;
fast Docker and both CPU scalars do not override interval paging.

All25 bounded receipts (18 leaves, six outer/negative captures and one Mach)
are natural/reaped, within original time/byte bounds, without signal,
truncation or timeout. The host wrapper naturally exits0 in66.666006458seconds,
but summary readiness is false; controller correctly refuses `host runner result`,
exits1 and records post_error=null. No host-readiness, second Mach, parent90,
case claim, chain-runs/cache or TUF case is produced. **Zero cases start and
TUF remains0/4**; the failed identity is preserved without retry. Dynamic raw
results and the stopping path receive independent read-only review.

All825 complete input rows match before/after/current;9aliases and four mirrors
remain exact. All six earlier sealed checkpoints retain846 files excluding
their indices,77 directories and exact index/seal bytes. Prior failures,
9 bindings,64 barriers, old402 files/33 components and cache/index/reuse rules
are retained. No allocation/deadline/guard relaxation, Go1.26.8/release-lock
change, global install, unrelated-process intervention, build/scan/container
or new timer occurs. This run uses existing mise Python3.13.16 `-B`.

Only three reviewed progress documents follow the standing normal commit/push
workflow; private raw evidence stays outside Git. Next a separately reviewed
new identity must pass the complete original dual gate before the same frozen
four TUF cases and unchanged-good all-role/all11-target joint causal review.
Timers remain off. Phase6 stays **5/15**; Slice6 step1 historical bounded Guest E,
step2 ongoing, step3 final inventory/original16/formal review incomplete,
step4 post-acceptance handoff not started.

## 2026-10-20 dual-host recheck rejects both paging deltas

New private identity `tuf-fourcase-resume-20261020-094023` receives independent
identity/complete-input/expiry review before one original dual-host attempt.
Its928-file lock SHA256 is
`417e98d9fa3532749684c7d618348127d04896f03963de1c4fa3c07bb144e325`.
All825 prior rows and9aliases remain;103 new rows bind the same owned source/
mirror/preparation scope as the preceding run. The98 copies (17 modules,
13 host sources/lock and68 mirrors) are byte/mode-identical. Manifest changes
only owned mirror/URI and three provenance values. All18 original sources,
11 target declarations, four17-file variants and the import closure match.
Old failed outputs, host admission and cache are never copied. The fixed
four-role metadata remains before expiry in actual pre/post checks, which
is only time freshness, not cryptographic authentication or official-latest
admission. No new external input or native/DB/image/scanner gate is introduced.

Actual samples on2026-10-20, Asia/Shanghai:

| Measurement | 09:43:52 | 09:44:58 |
| --- | --- | --- |
| load1 | 4.41 | 4.86 |
| top CPU idle | 64.82% | 60.38% |
| memory-pressure free | 31% | 31% |
| Mach idle display | 76.902174%, passes | not reached |
| swapin cumulative16KiB pages | 263130187 | 263201526 |
| swapout cumulative16KiB pages | 288104217 | 288199553 |

Both base scalar samples and first Mach pass. The base monotonic interval is
65.930274167seconds: swapin+71339 pages (1114.671875MiB) exceeds the original
32*gap=2109.768773pages, and swapout+95336 pages (1489.625MiB) exceeds zero.
Both paging predicates fail. The second guard naturally exits1 in0.934319291
seconds with `interval paging bounds`, before its Mach observation. The first
guard naturally exits0 in2.148300333seconds. Six Docker ping/version/info calls
pass in21.249–48.242ms on the same fixed daemon; scalar or Docker success does
not override paging and does not attribute the paging to a specific process.

All25 bounded receipts are natural/reaped without signal/truncation/timeout,
within original time/byte bounds. The wrapper naturally exits0 in67.118760833
seconds but readiness is false; controller correctly refuses `host runner result`,
exits1 and records post_error=null. Second Mach, readiness, parent90, case claim,
chain-runs/cache and TUF cases never start, **0/4**. Raw results and stopping
behavior receive independent read-only review; this failed identity is not retried.

All928 complete input rows match before/after/current;9aliases and four mirrors
stay exact. Seven earlier sealed checkpoints retain1041 files excluding their
indices,96 directories and exact index/seal bytes. Original9 bindings,
64 barriers,402 files/33 components and all failed evidence remain preserved.
Runtime code, dependencies and fixtures are unchanged, so prior96 parser/
18 adapter component coverage is reused;17 historical baseline tests remain
separate. No tests are rerun because of the new identity. Original5/70/90/600,
gap65/age120, scalar/Mach/paging/daemon/sameboot and25/90/1MiB/sandbox/
GOMAXPROCS2 remain unchanged, as do repository Go1.26.8/old locks, cache/index/
reuse and quotas. Existing mise Python3.13.16 `-B` is used without global
installation or unrelated-process intervention; no build/scan/container or
timer starts. Only three reviewed progress documents follow normal commit/push.

Next a separately reviewed new identity must pass the complete original dual
gate before the same frozen four TUF cases and unchanged-good all-role/all11-
target joint causal review; unfrozen dynamic inputs still need stage review.
Private raw evidence stays outside Git. Phase6 remains **5/15**; Slice6 step1
historical bounded Guest E, step2 ongoing, step3 final inventory/original16/
formal review incomplete, step4 post-acceptance handoff not started.

## 2026-10-20 frozen top TUF four-case chain passes

New private identity `tuf-fourcase-resume-20261020-232404` receives independent
identity/complete-input/expiry review before its one actual execution. The
1031-file lock SHA256 is
`48a5cd6f64a81af0e77ba7026ba4ea33269cbf2fde23185dabe4b8196ac2b9bf`.
All928 prior rows and9aliases remain;103 new rows,98 byte/mode-identical
copies and the same17-module/13-host/68-mirror scope follow the reviewed
preparation. All18 origin inputs,11 targets, four17-file variants and the
import closure match; controller, host lock and runtime behavior are unchanged.
No old failed output, cache or host admission is copied. The frozen four-role
metadata passes its actual pre/post expiry checks, without claiming latest.

Actual host samples on2026-10-20, Asia/Shanghai:

| Measurement | 23:26:44 | 23:27:50 |
| --- | --- | --- |
| load1 | 4.37 | 2.65 |
| top CPU idle | 81.57% | 80.31% |
| memory-pressure free | 42% | 41% |
| Mach idle display | 91.053678%, passes | 89.669007%, passes |
| swapin cumulative16KiB pages | 282058136 | 282059389 |
| swapout cumulative16KiB pages | 309264430 | 309264430 |

The original host gate passes in this actual window:65.846674375seconds,
swapin+1253 pages (19.578125MiB), below32*gap=2107.09358pages, and swapout0.
The bound remains **32 pages/second**, each16KiB (512KiB/second), unchanged.
Both base/Mach samples, original deadlines/freshness/SDK/source/same-boot and
daemon checks pass. Six Docker ping/version/info calls take12.205–30.190ms
on the fixed daemon. Host outer600 naturally exits0 in67.738222167seconds;
the chain starts about1.62seconds after the last base sample. This dated window
does not grant continuing host readiness to later stages.

Actual frozen case order and results:

| Case | Mutation | CLI exit | CLI seconds |
| --- | --- | --- | --- |
| bad-root13 | signed.expires only; signatures retained | 1, expected refusal | 0.094406083 |
| bad-timestamp | signed.version812→813 only; signatures retained | 1, expected refusal | 0.058061125 |
| bad-target | trusted_root.json offset0 xor1 only | 1, expected refusal | 0.087567083 |
| good | all17 delivered files unchanged | 0, accepted top chain | 0.087503625 |

All four actual captures meet original25second/1MiB limits and exact argv;
parent90 naturally exits0 in1.723590250seconds. Each negative has empty stdout,
no Root status or trusted target, two exact case-URI warnings followed by two
identical full error payloads; target expected/got64hex values match actual
good/bad bytes. Good has only the two known warnings, reports root15,
snapshot166, targets14 and timestamp812 without errors, and caches all11 target
files with exact original bytes/hash/size/mode. Four new caches start empty,
parents have distinct stable inodes, full post-state trees match records and
all post_errors are empty. All31 bounded captures are natural/reaped without
signal/truncation/timeout; controller host/batch flags are true, exit0,
post_error=null. All1031 before/after/current rows,9aliases and four mirrors match.

Independent actual joint review accepts **4/4 only for this new frozen top
metadata/target chain**. Same-base unchanged-good success and single-file
variants support bounded refusal attribution. Raw parser fields remain
format-only/provisional; acceptance is recorded separately, not rewritten into
old receipts. Modern root14 partial artifacts in all four states are not
authority. This is not syscall evidence of reading13.root, official-latest,
inherited rollback/delegated-role, Python-archive/SDK/native/operator or product
acceptance. Old failed runs retain their original0/4 and are never retried or
reclassified. Eight old sealed checkpoints retain1241 files excluding indices,
115 directories and exact index/seal bytes.

Runtime/tool/dependency/fixture bytes are unchanged;96parser/18adapter component
coverage is reused by impact,17historical baseline tests stay separate, and
no unit/Go/Contract/build/scan/container is rerun. Original9 bindings,
64 barriers,402 files/33 components, all limits/quotas/guard/cache/index/reuse,
Go1.26.8 and old release locks remain. Existing mise Python3.13.16 `-B`, fixed
Cosign and sandbox are used without global installs or unrelated-process
intervention. No new external material or timer starts. Only three reviewed
progress documents follow normal commit/push; private raw evidence stays outside Git.

Next independently review the concrete use of these authenticated targets and
source provenance for existing Python archive/SDK candidate records. Their actual
signature/byte correspondence, new identities, freshness/supply/host/isolation
and downstream reviews remain required; this4/4 does not inherit those gates.
Phase6 remains **5/15**; Slice6 step1 historical bounded Guest E, step2 ongoing,
step3 final inventory/original16/formal review incomplete, step4 post-acceptance
handoff not started.

## 2026-10-21 Python SDK authentication prerequisites held

Private checkpoint `python-sdk-auth-20261020-235600` starts on October 20 and
closes on October 21, Asia/Shanghai. It inventories the retained normal and
stripped Python 3.13.16+20261003 Darwin arm64 candidates and index-0 SLSA v1
bundles. These are metadata and unverified proof bytes; neither archive is
present in the inspected recovery tree. Current hashes, sizes and modes match
all 27 selected compiler/ABI inputs, all 264 Python headers and all 5 header
directories, with the SDK alias unchanged. The exact original signed Apple
CLT/SDK installer still lacks a qualified locator, size, digest and payload.
Receipt/BOM observations do not close its source authentication.

Independent review approves two distinct source-only retrieval identities with
the unchanged fixed fetcher and existing mise Python 3.13.16 `-B`. Each request
has its original whole 10-second/1MiB boundary, each parent 90 seconds/1MiB,
with no credentials, proxy, redirect following or retry. Each batch verifies
7/8 source files against the retained complete upstream Git trees; parents
naturally exit 1 in 18.194320 and 18.175151 seconds, without timeout, active
signal, truncation or unreaped child. The missing Cosign 3.1.3
`cmd/cosign/cli/verify/verify_blob_attestation.go` request fails twice: the raw
path takes 10.012599 seconds and the separately reviewed immutable blob API
path 10.012831 seconds, both with zero body bytes. Those leaf deadlines are
failures despite natural parent completion. Both original identities and
partial responses remain; no further endpoint request is made this stage.

Independent source/result review accepts the 14 successful fixed source files.
The fixed CLI spells the digest algorithm flag `--digestAlg`. Its command
constructs the expected verification options, but the actual attestation
`Exec` source is still absent. The recovered trusted-material helper reads an
explicit root locally and returns before default TUF fallback; the recovered
Cosign/sigstore-go libraries conditionally configure and enforce certificate,
CT, transparency-log, time, digest and identity policies. Their presence alone
does not establish how the missing entry uses them, parses bundles or handles
network fallback. The source-supported plan therefore remains **HELD before
actual Cosign verification**.

The proposed explicit root is only the accepted good target's 6787-byte
`trusted_root.json`, SHA256
`6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`,
bound to the separate frozen-chain 4/4 acceptance. Modern partial root14 files
and old default caches are not authority. Frozen role expiries are still in
the future at this observation; future consumption must recheck freshness and
all inputs. Strict future policy must retain issuer and exact workflow identity,
SCT/tlog/time checks, each expected digest's unique matching build subject,
workflow/ref/source-commit provenance and negative cases. Library digest
membership among 896 subjects does not prove a unique expected subject.
Even a future digest-only verification would authenticate the statement binding,
not archive presence, installed-byte correspondence, SDK provenance or ABI.

All 1031 prior input rows, 9 aliases and 11 sealed checkpoints (1734 files
excluding their indices, 166 directories) remain exact. The analysis input lock
is explicitly not a complete future execution lock. Original 9 binding positions,
64 barriers, old 402 files/33 components, guard/cache/index/evidence-reuse,
time/resource bounds and Go1.26.8 remain. No new host sampling, Cosign/TUF case,
archive download/extraction, SDK execution, native build, scan, container or
timer starts. Existing 96 parser/18 adapter component results are unaffected;
no tests are rerun for this documentation/source-data stage. Only three reviewed
progress documents follow normal commit/push; private sources/raw failures stay
outside Git.

Next close the exact missing entry with a separately reviewed source path and
new identity, then review the concrete verifier/post-policy/refusal design and
complete execution inputs before fresh original dual-host admission. Archive
delivery/Location and original SDK package/payload correspondence remain
separate reviewed stages. Phase6 stays **5/15**; Slice6 step1 historical bounded
Guest E, step2 ongoing, step3 final inventory/original16/formal review incomplete,
step4 post-acceptance handoff not started.
