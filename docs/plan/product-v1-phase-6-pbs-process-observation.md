# PBS diagnostic process and working-directory observation

Status: CWD design conditionally accepted; native group census held. No
implementation, native observation or real P2 is admitted by this checkpoint.
This plan concerns the private diagnostic launcher, not a Provider protocol or
Product release gate. Phase6 remains5/15 and Slice6 step2 remains open.

## Recovered source prerequisites

Private checkpoint `pbs-source-closure-20261021-092647` restores three fixed
sigstore-go v1.2.2 files from independently reviewed official GitHub blob URLs:

| Source | Git blob | Bytes | Request seconds |
| --- | --- | ---: | ---: |
| `pkg/fulcio/certificate/summarize.go` | `da9a6661a90ee5925573286505c32732333800d6` | 2646 | 0.781880 |
| `pkg/fulcio/certificate/extensions.go` | `e9a0680d1620a81204a97977baaf518b93c27206` | 11081 | 0.979875 |
| `pkg/tlog/entry.go` | `45b0182287ef454e395be324ee208102385501be` | 18333 | 1.100053 |

All three match the retained complete official tree and original10-second/
1MiB request bounds. The90-second parent naturally exits0 in2.941195seconds;
full1520 input rows match before/after. Actual source/result review verifies
1539 rows. Five previously indirect tree/request/module records now have direct
input rows; the prior manifests are preserved. No failed identity is retried.

The selected source supports first-URI SAN selection, raw V1 versus complete
DER V2 OIDC issuer decoding, and the first Rekor-v1 DSSE signature extraction.
The retained canonicalized Rekor body has one signature equal to the original
DSSE signature. This supports static branch correspondence. It does not prove
actual Go parsing, branch order or complete stderr from a real verification.
All eight frames remain candidates requiring actual unchanged-good joint
review. Historical metadata flags and the old prepared identity remain intact.

## Invariants

- Keep the original25-second leaves,90-second complete batch,1MiB stream caps,
 120-second host age, original dual-host gate and supplier/network/boot rules.
 All observation and postcheck work must fit their existing timing domains.
- Use existing mise Python; add no verification worker or subprocess observer.
 Do not compile, install packages, load a native library or run P2 as part of
 this design checkpoint. Existing Docker quotas stay unchanged.
- A successful attempt uses no active signal. Cleanup after a failed capture
 cannot make it pass. Missing, partial, stale or uncertain observations refuse.
- Reserve the owned session/group leader PID until ownership-safe inspection
 completes. Never inspect or signal unrelated process scopes.
- Preserve raw outputs, all failures, old manifests and the unexecuted16-file
 prepared identity. A future admitted attempt needs a new complete reviewed
 identity. Do not change cache/index, evidence reuse or the deny-network profile.

## Working-directory binding

Select an exclusive empty `state/cwd` per case, owned by the actual operator
UID/GID with0700 mode and an exact symlink-free parent chain. Walk each component
using `openat`/`dir_fd` and `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`, holding directory
FDs rather than checking an ancestor and reopening an entire path. Retain the
selected FD throughout the case. Require `FD_CLOEXEC` and explicit non-inheritance;
`Popen(cwd=None, close_fds=True)` inherits the cwd vnode, not these FDs.

The fresh single-threaded batch process uses `fchdir` on that held FD before
each sequential `Popen`; the leaf inherits the actual kernel cwd vnode. This
changes only that process's cwd, never the user's shell or app. Avoid a
`preexec_fn`, extra helper or a second path-based cwd lookup. Original host
sampling runs separately with its original environment/cwd. Input, executable,
capture and log paths remain absolute.

After initialization, bind held FD, `.`, canonical path and parents before spawn
and after the leaf. The cwd equality includes device/inode, mode, UID/GID,
positive `nlink`, `mtime_ns` and `ctime_ns`. Retain parent FD anchors. Prepare
capture/log directories before the baseline and keep writes off this chain.
Include a create-then-delete refusal fixture; an empty tree alone misses it.
These checks do not claim a universal filesystem-operation audit.
Retain the complete bounded cwd/state tree and reject unexpected files,
including hidden cache files, replacement, deletion, rename, symlink, permission
or ownership changes. A natural command receipt never overrides a failed
binding or postcheck. All work remains inside the existing total budget.

This binds the selected working directory. It is not filesystem confinement:
the existing sandbox profile restricts networking and is unchanged.

## Conditional native group protocol

The candidate observer uses the existing Python process and a native group
enumeration API, potentially `libproc`'s `proc_listpids(PROC_PGRP_ONLY)` and
`proc_pidinfo(PROC_PIDTBSDINFO)`. This choice is **not admitted** by the local
header declarations. The local `libproc.h` itself warns that these private
interfaces can change. Official API/ABI/library/kernel provenance and coherent
complete membership semantics must first be established independently.

The intended lifecycle is:

1. The outer starts a new session/group and binds the batch PID birth, session,
   PGID and current boot. Its unreaped leader reserves that identity.
2. Capture the leaf's raw streams, then observe natural exit using `waitid`
   with `WNOWAIT`. No preceding `poll`, `wait` or reap may release its PID.
   The current `capture.run` waits/reaps before `group_check`; that real calling
   chain must change and be tested, not merely gain an observer callback.
3. Before reaping the leaf, require the qualified API's exact expected members:
   batch plus known defunct leaf if that API includes zombies. Prove its zombie
   behavior before implementation; do not guess or switch at runtime.
4. Exclude every other live/forking member with a source-supported coherent
   complete set observation. Two matching snapshots alone are insufficient.
   Only then reap the leaf and require a singleton batch before another case
   and final closure.
5. The outer likewise holds its batch leader unreaped, proves only that known
   defunct batch remains, then reaps it. A defunct sole member cannot fork;
   the reserved private session/group cannot be silently replaced by PID reuse.
6. Any missing/unknown member, race, failed syscall or binding failure preserves
   raw evidence and fails. Signal only the previously bound owned group during
   failure cleanup; never derive a signal target from untrusted census output.

An initial candidate buffer has129 PID slots for a maximum128 observed owned
members. A full buffer, zero/negative/short/nonmultiple count, duplicate,
sentinel, overflow or uncertain return refuses. This is a read bound, not a
new runtime resource allowance. Record raw bytes/counts/errno and each PID's
birth/parent/group/UID tuple; qualify actual layout and return conventions.
Do not add an out-of-budget timeout or a subprocess fallback for a blocked API.
In particular, census inserted before leaf reap cannot be relabelled as work
outside its original25-second envelope. Prove the earlier leaf/total hard-stop
path and measured elapsed bounds before implementation/admission; whole90 alone
does not justify accepting an over25-second leaf. That supervision path remains
part of the native hold, not an approved new timeout or control protocol.

The selected launcher/tool no-escape premise also needs source closure. A PGID
snapshot cannot establish cleanup of descendants that call `setsid`/`setpgid`
and leave it. If this premise or coherent snapshot semantics cannot be proved,
the native route stays held; do not relabel it hostile-process containment or
substitute repeated observations for the missing proof.

## Evidence still required

Local `libproc.h`, `sys/proc_info.h` and `sys/event.h` are frozen as metadata
only. They do not authenticate the signed SDK installer, actual loaded image,
ABI or kernel behavior. The old SDK/ABI qualification and Python archive gates
are unchanged. A library in the dyld shared cache cannot be assigned a fictional
regular-file hash; its actual platform/image identity needs a reviewed source
and verification path.

The local event header says `NOTE_TRACK`, `NOTE_TRACKERR` and `NOTE_CHILD` are
unsupported since macOS10.5. They are not a usable fork-tracking shortcut.
Direct-child reap, EOF, `killpg(PGID,0)`, `waitid` alone and equal snapshots are
also insufficient membership evidence.

Before implementation/admission, independently close native provenance,
coherence, zombie semantics, PID/session races, exact ABI and no-escape inputs.
Then review bounded tests for held/closed-pipe descendants, nondirect members,
zombies, identity substitution, partial/overflow/errno results, forced membership
races, premature-reap regression, FD non-inheritance, unsupported APIs and cwd
substitution/rename/deletion/transient-create-delete/writes. Missing
evidence must cause refusal. Existing49 component tests cover unchanged code
only; they do not qualify this native observer or future lifecycle changes.

The exact-platform evidence stage below implements only source discovery from
the separately reviewed bounded read-only plan. It does not authorize a native call, real host gate, new P2
execution, build, scan, profile change or timer. Concrete implementation and
fresh dynamic-input/original-host review still precede any actual eight-case
run and its independent joint acceptance.

## 2026-10-21 exact-platform source evidence

Private checkpoint `pbs-native-api-evidence-20261021-095856` preserves all15 prior
sealed trees (2141 files excluding indices,201 directories) and1552 old direct
input rows. Initial review holds an unexecuted metadata draft because private
modules import before runtime byte pins. The revised wrapper pins imports
first, rejects unpinned bytecode and uses the reviewed minimal `env -i` outer
environment; the child is standard-library-only. These private readers are
source/metadata tools, not changes to the P2 controller or its timing domains.

The single platform read naturally exits0 in0.093354542seconds under10s/1MiB,
with1568 full inputs exact before/after. It records macOS27.0.1, build26A434,
arm64, Darwin27.0.0 and `root:xnu-13432.1.9~1/RELEASE_ARM64_T8132`.
`xnu-13432.1.9` is only the resulting official-source tag candidate. Neither
uname/plist metadata nor the existing SDK27 headers authenticate the running
kernel or actual dyld image and ABI.

An independently reviewed source-discovery identity requests
`apple-oss-distributions/xnu` Contents for `bsd/kern/proc_info.c` at that exact
tag. It returns HTTP404 in0.715243750seconds, stopping the four-file batch after
one request. `bsd/sys/proc_info.h`, `libsyscall/wrappers/libproc/libproc.c` and
`bsd/kern/kern_proc.c` are not requested. The90-second parent naturally exits1
in0.914159084seconds, with1580 full rows exact before/after.

A separately reviewed new identity asks a distinct metadata question: whether
`/git/trees/xnu-13432.1.9` resolves in the same official repository. This also
returns404 in2.123505792seconds; parent naturally exits1 in3.123951708seconds,
with1591 full rows exact before/after. It does not retry the failed file URL,
change source version or enumerate fallback endpoints. Both captures retain
raw stdout/receipts and HTTP status/headers, without signal, truncation or
timeout. The existing reader rejects non200 before reading the response body:
the stored0-byte bodies are not complete error responses (advertised135/110
bytes), and no error-message text is inferred.

The checked routes are unavailable for this exact label at those request
times. This does not establish global absence from Apple release channels or
prove any libproc locking, zombies, return/errno semantics or ABI layout.
No source is decoded or accepted. Beyond the fixed `os.uname` metadata read,
no libproc observer is explicitly loaded or process-group enumeration API called. The
candidate remains held for source/platform correspondence, complete coherent
membership, no-escape and before-reap budget evidence. Next independently
review an official publication/platform mapping path; do not silently substitute
another XNU version or rely on equal observed PID lists. Original9 bindings,
64 barriers, guards, resource/timeout limits and all old evidence remain.

## 2026-10-21 Apple release mapping gap

Private checkpoint `xnu-release-mapping-20261021-103210` independently reviews
new source-only identities. A fresh platform capture naturally exits0 in
0.108581834seconds with1705 complete inputs exact before/after; the recorded
platform remains macOS27.0.1/26A434, Darwin27.0.0, arm64 and
`xnu-13432.1.9~1`. This is metadata, not authentication of the kernel or ABI.

The [Apple release page](https://opensource.apple.com/releases/) returns a
10947-byte loading shell in1.545086541seconds. The official distribution's
[first tag page](https://api.github.com/repos/apple-oss-distributions/distribution-macOS/tags?per_page=100&page=1)
returns100 entries in1.430195333seconds and an explicit next/last page2 link.
The90-second parent naturally exits0 in3.045702542seconds;1732 full inputs stay
exact before/after. Neither shell text nor page1 alone proves source absence.

After separate review of these actual inputs, the exact
[script named by the page](https://opensource.apple.com/scripts/main.built.6a507df9.js)
returns916699 bytes in6.283076291seconds, and the exact
[next tag page](https://api.github.com/repositories/413590264/tags?per_page=100&page=2)
returns66 entries/33978 bytes in2.323428958seconds. Parent naturally exits0 in
8.712989666seconds with1763 full inputs exact before/after. All four requests
return200 with complete raw headers/bodies, within10seconds and1MiB combined
header/body each; no retry, redirect, authentication or script execution occurs.

Nonexecuting static inspection binds module1's embedded catalog to module172's
`../../data/unlocalized/releases.json` dependency. The complete script has no
`macOS 27`, `27.0.1`, `26A434` or `13432.1.9` literal. Its observed macOS26.0
and26.5 entries name XNU12377.1.9 and12377.121.6 respectively; neither is used
as current-platform source. Both tag pages total166 unique names without
macos27. Page2 has only prev/first links, but the pages were retrieved at
different times; this is not an atomic listing or proof about all Apple channels.

Independent result review accepts only this bounded discovery result. Exact
source/platform correspondence remains unavailable from the checked materials;
source recovery, native provenance/ABI, complete coherent census, zombies,
no-escape and before-reap supervision remain **HELD**. Do not substitute an older
version or launch native/P2 work. Next require an authenticated exact official
source pointer and separately review its immutable recovery inputs.

Private reader tests pass27 transport/JSON cases plus11 focused followup-policy
cases; no product acceptance follows. Held reader drafts and an offline analysis
preparation failure remain recorded. All16 old sealed trees,1690 initial rows,
9 bindings,64 barriers and existing guards remain; only explicit current-doc
versions change. No libproc observer/group API, host gate, Cosign case, build,
scan, container or global installation runs. Timers stay off and original
budgets, supply/cache/index/reuse rules remain. This is Slice6 step2, not step4.

## 2026-10-21 XNU immutable discovery held

Private checkpoint: `xnu-immutable-discovery-20261021-123142`. Independently
reviewed source-only discovery preserves the prior platform metadata target
`xnu-13432.1.9`; this stage does not recapture or authenticate the running kernel.

The [official XNU repository](https://api.github.com/repos/apple-oss-distributions/xnu)
returns its own owner/URLs and default branch `main` in5.595381333seconds.
The [named tag-prefix query](https://api.github.com/repos/apple-oss-distributions/xnu/git/matching-refs/tags/xnu-13432.)
returns the complete empty array in1.898287750seconds without pagination.
The source-only parent naturally exits0 in22.137423083seconds under90seconds,
with1969 full inputs exact before/after. This bounded prefix result does not
prove absence from all official channels.

After actual-input review, the [main ref](https://api.github.com/repos/apple-oss-distributions/xnu/git/ref/heads/main)
returns commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` in3.979094166seconds;
parent naturally exits0 in4.123652125seconds with1997 inputs exact. A separately
reviewed immutable Contents query for `config/MasterVersion` returns404 in
4.014177792seconds: complete127-byte body and1141-byte headers are retained,
no decoded source is produced, parent naturally exits1 in4.187303333seconds,
and2010 inputs remain exact. This failed identity is not rerun. A404 alone is
not version-mismatch evidence or proof that no official source exists.

The separately reviewed [actual commit object](https://api.github.com/repos/apple-oss-distributions/xnu/git/commits/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea)
returns200 in1.188105209seconds. Its unsigned API message names
`xnu-12377.1.9`; it points to root tree
`7cb04f5def354255785e3cb0e06d496dc918ebea`. Parent naturally exits0 in
1.255732208seconds with2036 exact inputs. The message is nominal metadata,
not cryptographic version authentication and not current13432 source.

The [actual nonrecursive root tree](https://api.github.com/repos/apple-oss-distributions/xnu/git/trees/7cb04f5def354255785e3cb0e06d496dc918ebea)
returns200 in2.937365208seconds with4749-byte body,1340-byte headers,
`truncated:false` and all21 entries checked. Parent naturally exits0 in
3.023432208seconds with2049 inputs exact. `config` is a tree with SHA
`13260f6a35e496d864ed1135ab0bf92185bed68a`; no child pointer is followed.
The root does not establish whether `MasterVersion` exists inside it or why
the Contents route failed. API objects are not recomputed Git-object proofs.

All six HTTP calls retain the original10-second whole-request/1MiB combined
header/body bounds, raw bytes and failure records. No retry, redirect,
authentication or automatic follow occurs. Full input checks sit outside
source-only capture timing and do not close P2 leaf25/whole90/host-age120
budgets. Three new private-reader suites pass31,26 and16 tests under their
original10-second parents (7.104490875,0.752199750,0.103549417seconds); these
are73 metadata-tool checks, not product or formal acceptance.

Independent result review accepts bounded discovery only. Exact current
source recovery, provenance/ABI, coherent census, zombies, no-escape and
before-reap supervision remain **HELD**. Next require an authenticated exact
current-platform source pointer; do not substitute12377 or repeat the404.
No native observer/group API, host admission, P2, build, scan, container or
global installation runs. All17 old sealed checkpoints,1954 initial rows,
9 bindings,64 barriers,402 files,33 components and existing guards remain.
Prior16 sealed-tree checks are retained; the latest prior tree is freshly
checked in full here. Only four current-document rows receive explicit version
overlays. Product Python code stays at its earlier49-test state, without a
rerun; no Go/Contract rerun is claimed. Original time/resource/supply/cache/
index/reuse boundaries remain and timers stay off. This is Slice6 step2.

## 2026-10-21 alternative observation assessment

The [alternative feasibility assessment](product-v1-phase-6-pbs-alternative-observation.md)
rejects a direct platform substitution and records a conditional Linux-only
construction, with management injection, subsequent exec, network and complete
budget/identity obligations still open. Neither route is admitted. A new
private metadata probe's17-case mock identity fails its original10-second
parent without test results or a complete post-input receipt; no real daemon
query is made. Preserve that failure and require a new reviewed identity for
any later attempt. Existing runtime code and49-test evidence are unchanged.
No native/host/container/build/scan/P2 work starts; original guards, quotas and
budgets remain, timers stay off and Phase6 stays5/15, Slice6 step2 ongoing.
