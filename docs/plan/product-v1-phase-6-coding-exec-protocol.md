# Phase 6 Coding exec containment and private handoff

Date: 2026-10-10. Status: independently reviewed, constrained implementation
direction; **not runtime admission**. Phase 6 remains 5/15, Slice 6 step 2. The locked Provider Contract,
architecture and ADRs 0052/0054/0055 remain authoritative. No public Contract,
issuer topology, old receipt, frozen-R reuse rule or existing populated
namespace is changed by this proposal.

## Why the existing execution path cannot be composed

The retained real-daemon probe reproduces a detached orphan writing after the
legacy direct-child TERM succeeds and the wrapping Docker exec stops. Neither
that algorithm, capture EOF, callback drain nor a finite quiet window proves
the attached execution's descendants stopped. The legacy development driver
is unchanged; it cannot supply v3's required confirmation by delegation.

Adding a command container alongside today's full-limit Coding runtime also
violates its resource accounting. The current source binds preparation and
runtime containers plus three whole volumes, with one complete resource limit
per slot. A separate full-limit command doubles its declared peak and escapes
the exact inventory/cleanup set.

The locked calling standard promises stable `/inputs`, `/workspace`, `/outputs`
and `/tmp` guest paths. It does not explicitly specify `/tmp` persistence
between individual execs, but the existing single-container exec and Terminal
implementation shares it. Preserve that observed behavior rather than silently
changing to private per-command tmpfs. Exec POST explicitly permits capacity
exhaustion (429 with positive Retry-After); it does not promise multiple
simultaneous commands per sandbox. Original request replay must still return
its historical operation instead of being treated as new capacity demand.

## Selected candidate and explicit adoption boundary

Use a persistent resident container for the sandbox and a separate private-PID
container for each command. The command itself is namespace PID 1: no shell
wrapping it, no Docker init shim that can outlive it, no restart policy. Its
argv and working directory come from the strictly validated Provider request.
The fixed published/source-bound image, user, environment, network none,
read-only root, no-new-privileges, capability drop, seccomp and named mounts
come only from a newly frozen private template. Environment/secret/stdin
references remain unsupported before durable acceptance until their real
resolver is composed; they are not interpreted as inline values.

Preserve three generation-scoped whole data volumes, including read-only
inputs. Add one separate allocation/generation/Profile-scoped **whole shared
scratch volume** at `/tmp`. The candidate mechanism is Docker's local volume
driver with exactly type/device `tmpfs` and source-derived fixed size,
uid/gid, `0700`, nosuid/nodev/noexec options. It is not an arbitrary driver
options API, ordinary disk volume, subdirectory, host bind or daemon socket
mount. Resident and command share the allocation UID/GID and scratch. Other
allocations have different identities and all four names.

Adoption needs a new explicit Profile/template and resource/receipt mode in a
new empty namespace. Do not add optional fields to legacy receipt-v2 bytes,
reinterpret `CodingRuntimeTemplateV2`, upgrade populated ledgers or make the
existing Profile-v2 validator accept this incomplete projection. Both public
holds stay closed. New source/image/inventory candidates require their own
frozen inputs and gate evidence. Shared scratch must pass real mount/type,
capacity, flags, identity, visibility, retention, failure and cleanup tests on
each admitted platform. If the mechanism does not meet these conditions, reject
this candidate; no disk or host-bind fallback is permitted.

The admitted maximum is one possible command per allocation, not just one
locally running goroutine. With two slots, account for at most four running
containers, six possible named container objects (including never-started
preparation carriers), and eight whole volumes. Completed command tombstones
remain in the ledger after exact command-container removal. Inventory scans
the allocation's complete label/name scope, not only previously known IDs;
an extra labelled container or mount prevents cleanup acceptance.

## Resource and retained-output accounting

`codingidentity.ExecutionResources` checks a prospective split of one existing
slot ceiling; it is not physical authority. `ExecutionScratch.BindResources`
adds the separate metadata allowance check. Freeze resident R, command E and
32 MiB shared scratch data S and a separate metadata reserve M. Each container
has independently valid nonzero limits. Require R.memory + E.memory + S + M <= slot.memory,
R.cpu + E.cpu <= slot.cpu, R.pids + E.pids <= slot.pids, and exactly one
possible command. Do not reduce the accounting when an RPC times out. The
shared scratch is conservatively counted in addition to both container limits,
without assuming which cgroup gets charged for shared pages. Private `/dev/shm`
and private tmpfs must be explicitly bounded within their container memory
limits. Docker/kernel overhead, Control buffers and other role processes
retain separately validated topology headroom.

The 32 MiB constant bounds scratch **data blocks**, not all tmpfs inode or
kernel metadata memory. The updated mechanism fixture uses the new template's
`ExecutionScratch` policy: `nr_inodes=4096`, with 32 MiB separately reserved for
metadata. Real `statfs` and exhaustion verify the inode limit: while data
blocks remain free, both file and directory creation fail with ENOSPC; a freed
file inode can be reused by a directory. The recorded cgroup memory/shmem/slab
samples do not establish a kernel upper bound or complete charging attribution.
Production pressure and topology headroom remain unproved.

For the first local mechanism test only, the 256 MiB/500 milliCPU/64 PID
ceiling split into R=64 MiB/100/16, E=160 MiB/400/48, S=32 MiB. Its updated
inode test uses E=128 MiB and adds M=32 MiB within the same ceiling. These
values actually feed Docker create and are independently inspected. The
distinct held `CodingExecutionTemplate` freezes a **candidate** slot split
of 1 GiB/1000 milliCPU/64 PIDs: R=128 MiB/100/16, E=832 MiB/900/48, S=32 MiB,
M=32 MiB. Real resident, Terminal broker and command stress must still validate
these candidate values before production admission. Neither fixture uses the
missing locked Coding image or establishes that workload's capacity.

The new canonical template has its own protocol and resource mode, locked
image/index/platform/config/manifest, source command/environment, distinct
scratch prefix per slot, private PID/IPC, no init shim/restart, disabled daemon
logging and 16 MiB private shared memory. Unknown/duplicate/noncanonical fields
and old/new template interchange reject. It copies source identity from a
validated old template without inheriting its runtime admission or changing
its bytes. The complete new Profile must additionally bind the new empty
receipt mode/namespace, private authority and all physical resource names;
this template does not yet define that receipt schema or activate dispatch.
The subsequent held template **v2** adds the complete `controlstorage.Layout`
value to its canonical bytes and uses a new digest domain. Its layout has no
template/Profile back-reference, so there is no digest cycle. Previous v1
candidate bytes reject; saved candidates and legacy template-v2 receipts are
not rewritten or silently upgraded.

One live command does not bound retained outputs. The existing request model
and legacy driver can capture up to 8 MiB **per stream**; do not silently
redefine `capture.max_bytes` as a combined maximum. Reserve each enabled
stream's effective cap (default included) plus atomic staging/sealing peak
before dispatch. The new source-bound Control storage allocation must cover
all live reservations, retained results, uncertainty holds, immutable
tombstones, create/release evidence, ledger replacement and fixed headroom
within the existing bounded Control volume. Byte and object-count exhaustion
rejects new admission; it never drops an accepted result or deletes history
to make room. Candidate aggregate caps are now fixed below, rather than
inferred from 4096 legacy receipt slots or the shared 1 GiB Control volume.
The new file component below enforces a bounded Coding filesystem namespace.
The execution state schema, all-scope allocation and runtime gates remain
prerequisites to dispatch wiring.

| New Coding candidate partition | MiB | Bound |
| --- | ---: | --- |
| Output including staging/sealed peak | 192 | At most six full two-stream results at 8 MiB/stream with two copies; smaller captures remain subject to record/file/byte caps |
| Allocation completion/release evidence | 64 | At most 32 allocation histories, two 1 MiB documents each |
| Execution terminal/no-effect evidence | 64 | At most 64 command histories, one 1 MiB document each |
| State and atomic replacement | 64 | Single canonical state at most 32 MiB, plus one replacement copy |
| Dedicated close/cleanup reserve | 64 | Kept separate from output and terminal evidence; worst-case 1 MiB per execution |
| Physical/transient headroom | 64 | Separate positive margin, not a measured filesystem bound |
| Total Coding child quota | 512 | The remaining 512 MiB is not free Coding space: complete Profile allocation for other Control scopes remains required |

`ExecutionStorage.Charge` preserves the default 8 MiB per enabled stream,
reserves two file copies and rounds each possible allocation upward to 64 KiB.
Internal canonical request bytes are charged at actual length (up to 2 MiB),
plus a 32 KiB transition envelope, against the **single** state limit; its
replacement copy is already a separate partition. The independent full-state
encoding check rejects bytes beyond the reservation or 32 MiB. The public
encoded request limit remains 256 KiB; an internal JSON-expansion test is not
an exception to that wire limit. A count limit of 64 never promises capacity
for 64 maximum-sized internal requests. Expired outputs may be released only
by a future durable closure/expiry transition; this arithmetic component has
no expiry/release API and cannot grant dispatch permission.

The template also fixes a 1024-object Coding storage ceiling. A future Control
observer must count **all** evidence, state/lock, output, staging and directory
objects and reject unexplained files, not just use the helper's OutputFiles
count. It must verify filesystem allocation units, actual allocated bytes,
per-class limits, replacement/temporary peaks and closure writability. Old
ledger namespaces and unrelated Control scopes cannot share this child quota.
These are required physical/durable consumers, not capabilities implemented
by the arithmetic helpers. The new file boundary implements the subset below;
it does not infer execution relationships or authority from file counts.

### Private storage namespace component

`internal/controlstorage` consumes the fixed layout: Coding 512 MiB, including
448 MiB of classified files and 64 MiB physical/metadata headroom; the other
512 MiB stays explicitly unallocated and has no writer API. The current
Control program has no Browser/Desktop receipt consumer to justify assigning
those scopes a sufficient runtime allowance. Complete Profile allocation is
still required. The layout is part of held template v2; a separate runtime
binding records its value, fresh namespace/storage ID, candidate Profile and
template digests, Control principal and UID/GID. Binding format validation
does not validate those source documents or admit a Profile.

Initialization requires an existing private empty root and a separate trusted
physical-namespace check after durable creation of the permanent lock marker.
Only the exact new storage ID/physical mount may eventually supply this root;
an empty child directory in an old shared volume is insufficient. The current
library cannot derive Docker volume identity from a path or prove the callback's
claim. Opening never initializes or repairs. The owner pins the directory and
lock identities, holds a lifetime flock, and performs relative no-follow I/O.
Every write/reopen checks the complete root-level set, canonical manifest,
each file's bytes/hash, owner/mode/device/link count, and source/root identity.
No other scope, old ledger, unknown directory/file or temporary residue is
allowed. This excludes cooperating second owners, not malicious same-UID
bypass writers; the physical volume/subject isolation gate remains necessary.

Each class has a fixed total, per-file and count bound. Charges use the larger
of logical bytes and observed allocated blocks, rounded up to 64 KiB; filesystem
block size must divide that unit. Root, lock, manifest and replacement metadata
are counted against headroom, and the full object budget includes transient
files; unfinished transient files always reject on reopen. A single state may be replaced only under the same ID, with old and
replacement copies both charged. Immutable output/evidence uses exclusive
link publication, so a same-name entrant is never overwritten. There is no
delete, expiry or capacity-release API. Ordinary writes also check currently
available filesystem space while retaining the full close/headroom allowance.
These observations are not a kernel quota or a guarantee against writers
outside the admitted volume/owner boundary.

Object and manifest commits are sequential, individually synchronized file
operations, **not a two-file transaction**. Once writing begins, any error
poisons that owner; no residue is deleted or uncertain result retried. A crash
after object publication but before its manifest update leaves an inconsistency
and reopening rejects. If the fully committed state is readable, a later owner
can check its bytes, without reconstructing any dispatch ticket. No automatic
repair exists; actual receipt/dispatch composition must retain the hold or
provide a separately reviewed recovery protocol. Opaque `Closure` bytes are
storage, not a sealed no-effect observation, and `State` bytes alone cannot
establish Unknown/Completed. The final Darwin race and Linux local-volume
tests are file-component evidence, not a complete physical-volume admission,
power-loss durability, PG claim, execution result or cleanup gate.

PG is the sole logical authority for the aggregate byte/object reservations:
reserve their complete frozen worst-case cost atomically with the fresh claim
and public operation acceptance. Before that commit, exhaustion may return
the locked 429 with positive Retry-After and create no accepted operation.
The successful commit is the acceptance linearization point; an uncertain
reply is reconciled by the original operation, never a fresh dispatch ticket.
Control independently enforces the same source-bound hard caps against its
actual durable reservations before Docker effects. A later Control capacity
or readiness rejection cannot turn an already accepted POST into 429. It must
durably close the exact claim before any effect, retain a sealed no-effect
tombstone, and yield an existing public `failed` / `known_failed` outcome with
a bounded safe error, no exit code or invented execution. PG may then release
only the physical/output reservations proved absent by the matching closure;
retained result/history costs remain reserved for their own lifetimes. If
closure cannot be persisted or its reply is uncertain, hold the claim and
reconcile it; never infer no-effect from an error or `NotFound`. The concrete
storage partition must reserve enough non-output ledger headroom to persist
these closures even when the output budget is exhausted.
For an accepted operation that never physically started, the required result
`started_at` is the operation's logical acceptance/start time. It must not be
presented as an observed container start; physical start remains a separate
private fact that may be absent.

Disable unbounded daemon logging for command containers. Capture is bounded
and private; draining/truncation must retain context/deadline and memory
bounds. Lost capture after a Control crash cannot be reconstructed from a
Docker exec ID or labelled complete. Result outcome, result-file expiry and
physical execution occupancy are separate facts. Expiring a result never
authorizes removal of a possible execution or cancellation of its capacity
reservation; output deletion must exclude in-flight writers and record its
own durable state.

## PG to Control: one fresh dispatch, durable occupancy

The existing intent and fence receipts are immutable history, never permits.
The complete eventual path is:

1. Under the PG `control_state FOR UPDATE` transaction, revalidate the full
   request, current Active/Ready allocation, lease/deadline, generation/fence,
   original completion, tenant and frozen new resource/Profile bindings.
   Atomically reserve the sole possible-exec slot and create a fresh immutable
   dispatch claim with bounded expiry, aggregate output/metadata reservation
   and accepted public operation in that same transaction. Only the initial successful commit
   may yield a process-local one-use dispatch ticket. Commit uncertainty and
   historical reads/replays never yield a replacement ticket.
2. Use a new explicitly versioned, mTLS/Profile/peer-bound asynchronous private
   Control action. The existing create/cleanup/status protocol and its 30s
   Completed/Released response expectation are not an exec protocol. The
   Provider supplies no Docker IDs, mount paths, raw endpoint or options.
3. Under the same Control lifetime owner and allocation transaction/lock domain
   used by create/retirement, validate the claim and frozen sources, reserve
   output bytes and commit `Unknown` durably **before the first Docker effect**.
   In that transaction, require the original create to be `Completed`, with
   the exact completion seal and slot/Profile/image/UID/GID/four-volume mapping,
   and no cleanup intent, closed admission or `Released` state. A PG claim
   alone never establishes physical readiness. These checks and the new
   occupancy record must share the original allocation's ledger authority.
   Admission and cleanup therefore cannot miss a separate file's occupancy.
   Unknown counts even if no callback ran. Release the state lock for bounded
   I/O; never hold it for the command's lifetime and block cancellation.
4. Derive one unique command name from immutable claim/allocation identity.
   Create/inspect/attach/start only this exact source-derived object, once.
   Retain the physical ID in Control-private evidence. Return the durable
   acknowledgement promptly; independently observe later. POST success is
   not terminal evidence, and a transport timeout never causes replay.

The first dispatch implementation must consume this claim all the way through
private Control admission. Another readable, no-permit reservation ledger by
itself would not close this boundary. The current resource component is only
the first physical prerequisite and does not implement these four steps.

## Cancellation, late requests, and cleanup

Persist cancellation intent before any stop. Stop only the exact command
container under the frozen allocation/claim/image/daemon binding. Cancellation
confirmation requires fresh trusted evidence of that execution and descendants
stopping in response to the bounded stop, with no uncertain daemon mutation
that may later create/start work. If natural exit wins, retain its real exit;
do not infer cancelled solely because a cancellation request was accepted.
PID 1/container observations and command output sealing must close together;
the 500 ms mechanism probe is not a release rule.

After known terminal execution, seal bounded output, remove the exact command
container, and obtain independent exact inventory evidence before releasing
the possible-exec slot. Keep the original result/tombstone until its specified
retention or longer required authority lifetime. Unknown, CancelPending and
CleanupPending retain physical capacity. Missing containers, elapsed leases,
local callback drain and result expiry do not clear them.

The PG-to-Control gap needs an explicit closure handshake. If a committed PG
claim appears absent at Control, Control must first durably close **that exact
claim** against future arrival under the same allocation lock. Only a new
sealed closed-before-any-effect observation can represent known non-dispatch
to the PG CAS. A read-only `NotFound` followed by release leaves a late-request
race and is forbidden. If an Unknown already exists, closure cannot turn it
into no-effect; retain it until the actual effect is resolved. An uncertain
Docker create/start/kill/delete remains held unless a separately reviewed,
source-bound quiescence protocol proves no late effect; there is currently no
automatic repair/timeout override for that case.

Termination first records PG retirement and rejects new exec claims, then
durably closes allocation admission at Control. Resolve or retain all possible
commands before stopping/removing resident and preparation objects and all
four volumes. PG slot release consumes only a fresh matching sealed Control
cleanup observation under a current CAS. Lease renewal never extends a running
command deadline or reauthorizes a previous claim. Control restart restores all
occupancy/byte reservations before serving any request; no sender ticket is
reconstructed. Resident/scratch loss cannot continue as Ready on an old
completion seal or silently rematerialize `/tmp` as an empty successful state.

For a claim already committed when termination wins the PG row lock, PG keeps
that possible-exec occupancy. Control's allocation-close and exec admission
linearize under the same durable allocation gate: close first rejects the
late ticket even if it was valid when issued; `Unknown` first requires
termination to cancel/resolve that entry or remain held. A momentary absence
of containers never substitutes for closing all outstanding admission paths.

## Evidence required before adoption

### Held common Control state checkpoint, 2026-10-10

The package-private `executionLedger` consumes `controlstorage` under one
lifetime owner for create, execution and retirement. The separate protocol
`sandbox-runtime.coding-isolated-receipts.v2` binds the held template/layout,
fresh storage namespace, Profile/principal/daemon/environment/endpoint/policy
digests, and source-derived allocation/generation/slot resources. These digest
bindings do not by themselves prove the complete Profile or actual mounts.

Locked `ReadState` returns checked bytes and a whole-manifest revision;
`CompareState` atomically checks that revision and state digest under the same
store mutex before publication. Reopen requires the existing canonical state
and recomputes retained metadata/output reservations. It never initializes a
missing receipt, upgrades old bytes, repairs an interrupted two-file commit,
or reconstructs an outbound ticket. All slots remain retained because this
component has no Released/terminal/output-expiry transition yet.

Create and execute publish Unknown before invoking bounded callbacks outside
the state mutex. Completion needs the same process's successful create return
and a new typed four-volume observation bound to the current state revision
and digest; a retirement or other intervening mutation rejects that observation.
The separate `executionUnixObserver` now implements the collection port using
bounded exact Docker reads. Its own four-volume inventory and runtime policy,
raw locked OCI descriptor chain, and strict empty-root archive checks produce
retained physical projections for canonical-state reopen validation. Protocol
v2 rejects previous candidate v1 bytes; only a fresh empty namespace initializes
it. Old three-volume observations cannot satisfy this port. Positive SDK tests
remain synthetic, while the real daemon test only proves empty-scope rejection.
Docker Options/archives do not prove actual kernel scratch flags, capacity,
inodes or noexec, and a successful callback never implies completion or release.

An exact closed-before-effect claim is a local tombstone, not cross-service
sealed no-effect evidence or a PG release CAS input. It advances the highest
observed fence and cannot overwrite an Unknown. Retirement requires a strictly
newer generation and distinct operation, closes admission in the same state,
and retains all possible executions. Cleanup cannot enter while any execution
is Unknown or a callback is in flight; admitted cleanup first persists its own
Unknown and cannot mark Released on return. A bounded owner-close that times
out retains the lifetime flock until callbacks actually drain.

Independent read-only review and Darwin/Linux component checks cover this
scope. There is no command/PG/transport caller yet. Full new Profile/physical
namespace observation, atomic PG accepted-operation/claim/ticket, asynchronous
mTLS admission and actual Coding workload/terminal/cancel/quiescence/release
remain required; the four production dispatch steps above are still open.

| Boundary | Required evidence |
| --- | --- |
| Resource split | Positive bounds, exact/over-limit arithmetic, no overflow; actual source-derived container limits; realistic resident/command stress and full topology headroom |
| Scratch | Actual tmpfs mount type/flags/data and inode capacity, metadata memory headroom, UID/GID/mode, bidirectional shared visibility, noexec and ENOSPC; command replacement continuity; full unmount and admitted daemon/restart failure behavior |
| Authority | PG two-pool claim/lease/retirement races; initial ticket once; commit lost reply; full binding/tamper/expiry rejection |
| Control | Durable Unknown before effect; same allocation gate against cleanup; fsync/rename/crash and close-before-late-arrival tests; no ticket from replay |
| Execution | Real locked Coding image; exact isolated command/descendants; cancellation/natural-exit races; no shared PID/IPC; timeout/disconnect/late daemon effects retain occupancy |
| Results | Per-stream cap/default, bounded drain, PG aggregate reservations and independent Control hard caps, pre/post-acceptance exhaustion, closure headroom, aggregate storage/metadata peak, crash-safe sealing and expiration without clearing execution state |
| Cleanup | Complete new resource set, extra-object rejection, exact stop/remove and inventory, PG release CAS and slot reuse with old claims rejected |

The existing two-issuer decision and remaining Slice 6 Provider/Browser,
TLS/CRL, network/UID/GID/permission and Guest scenarios are unchanged. Only
the full live v2 inventory, original sixteen scenarios and independent formal
acceptance allow step 3 to close; step 4 follows that acceptance.

### 2026-10-10 prerequisite failure

The [new-host supply check](../audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-image-supply-revalidation)
verifies the old index provenance and original arm64 archive, but its fresh
scan has 13 HIGH occurrences. Static template identity validation does not
consume that report or override the failed gate. Do not start the positive
four-volume scenario from this old image. The [separate candidate proposal](product-v1-phase-6-coding-image-candidate.md)
keeps historical identity untouched. The user has approved candidate-only
Go1.26.9; the new Alpine3.23.6 candidates pass reproducible build, descriptor
and HIGH/CRITICAL checks, with one retained zlib MEDIUM per platform. Native
arm64 diagnostic smoke passes, but its tmpfs layout is not the four-volume
protocol. Independently reviewed new image/template/Profile/receipt binding
and affected real gates remain next. No runtime or receipt protocol change
or production admission follows from candidate build evidence.

### 2026-10-10 subsequent held candidate binding

The separate reviewed [candidate binding design](product-v1-phase-6-coding-image-candidate.md#reviewed-held-binding-component-2026-10-10)
now supplies a source-owned unsigned candidate record, execution-template v3
and internal receipt v3. The common ledger now requires v3; the v2 checkpoint
above describes historical component evidence, not a migration path. Reopen
rejects both v1 and v2 state and preserves the old bytes. Neither legacy template
changes. Real original archive/layer rechecks and bounded Docker image queries
are narrower than the still-required four-volume runtime gate.

Complete Profile adoption remains unresolved: the full typed Profile still
contains the old Coding runtime template, while private storage only checks
`ProfileDigest` syntax. Candidate record equality or local slot uniqueness
cannot replace complete topology/resource/principal and physical namespace
validation. No public Profile hold, dispatch authority, vulnerability exception,
publication or evidence-reuse rule changes in this component.


### 2026-10-10 subsequent Profile mode and kernel-root checks

The [next candidate component](product-v1-phase-6-coding-image-candidate.md#held-complete-field-candidate-mode-and-kernel-root-2026-10-10)
adds an explicit mutually exclusive candidate-v3 mode to the complete Profile
field chain and derives storage Binding only from that checked source. This
closes the pure field-binding gap described above; public admission stays
closed. Declared slot/resource accounting includes eight Coding volumes and
retains other Control scopes as unallocated. It is not a final live inventory.

The Store's separate kernel-checked APIs reject ordinary directories and
unbounded Docker local volumes using their actual root fd/mount facts. They
have no caller-supplied successful physical callback, and cannot reopen or
rewrite a legacy namespace as kernel-checked. Both path/fd mount ID and stable
filesystem/root geometry are rechecked; mount ID is only a session anchor.
These APIs do not prove Docker volume identity, external exclusivity or stable
hard quota. Their name, tests and retained record deliberately make that limit
explicit. No production dispatch may use a kernel check as physical admission;
the closed Docker observer, dedicated capacity backend and real positive/failure
four-volume chain still precede PG acceptance/claim and mTLS composition.


### 2026-10-10 held Docker consumer observation and dedicated backend

The [Control storage backend component](product-v1-phase-6-control-storage-backend.md)
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
