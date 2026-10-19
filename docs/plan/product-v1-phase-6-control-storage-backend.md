# Held Control storage backend, 2026-10-11

This is Slice 6 step 2 component work. Phase 6 remains **5/15**. Public
`ProfileV2.Validate`, Provider v3 admission and new execution dispatch remain
closed. This document does not change either issuer, historical evidence,
the frozen-R reuse policy, or the final sixteen-scenario gate.

## Implemented observation boundary

The private Control storage observer has a separate read-only Docker API
allowlist. It brackets complete bounded inventories (128 containers and 256
volumes maximum, one MiB per response) with daemon and live Store-fd checks.
All containers, including stopped ones, are inspected. The exact Control
container, principal labels, high UID/GID, immutable image identity and whole
receipt mount must match. Another consumer, an intersecting bind path,
backing-volume exposure, device alias, unexplained mount, shared PID namespace, or known container
authority capable of changing mounts/devices rejects the observation. HostConfig
mounts, legacy binds, tmpfs overlays and volumes-from are checked as well as
the current Mounts projection. Socket identity is checked after response-body
read and close, not just connection establishment. Duplicate/case-alias JSON,
oversize responses, warnings, cancellation and list/inspect drift fail closed.

Two matching inventories describe current Docker objects. They do not fence
future daemon requests, prove every filesystem alias, enumerate external VM
writers, or attest a source-bound complete running Profile. The observer is
private and has no runtime admission constructor. Its positive pure tests use
synthetic requirements; a real ordinary-volume fixture only checks the current
mount projection and rejection of stopped extra consumers/unbounded storage.

## Dedicated filesystem candidate

The new `controlstorage` dedicated mode requires a fresh namespace and the
existing kernel-root checks, plus actual loop sysfs facts from its root fd's
device: ext4, exactly one GiB block-device capacity and nonzero sizelimit,
offset zero, writable, no autoclear/partscan/direct-I/O flags, exact source
device and backing path. Kernel/file/backend facts are checked on each Store
anchor. The persistent manifest distinguishes file-only, kernel-only and
dedicated modes; none can reopen or promote another mode. These observations
still do not prove the backing inode, global exclusivity or operational trust.

`tools/control-storage-backend` is a Linux-only operator diagnostic, built with
mise Go1.26.8. It is not a new runtime role, deployment daemon or automatic
recovery service. The helper allocates a fresh regular one-GiB file with
fallocate and fsync. A separate pinned e2fsprogs image formats it offline with
discard and lazy initialization disabled, a private high-UID root and no
lost+found entry. Offline e2fsck and root-inode inspection precede sealing.
The helper fsyncs the image before hashing and durably publishing its original
hash, length, device and inode. A seal is local diagnostic metadata, not an
independent operator signature or a filesystem-validation replacement.

The prepare/format/seal stages need no device access or SYS_ADMIN. The local
diagnostic image pins Alpine3.23.6 arm64, e2fsprogs1.47.3-r0 and the downloaded
APK hashes, installs with APK signature verification and no network during
image build, and retains its exact local image identity outside Git. This is
not a published or release-qualified role image. Old image locks are unchanged.

## Device ceremony and exact ownership

The user explicitly authorized the proposed local diagnostic scope on
2026-10-11. This permits the bounded loop7 ceremony below; it does not authorize
a production mount manager, privileged container or relaxed admission policy.

Docker Desktop's loop devices belong to its shared Linux VM. The initial
read-only sysfs view showed loop0–loop7 without backing mappings; that view is
not a current allocation reservation. Before any device operation, a fresh
bounded census must inspect every visible loop's kernel device/inode mapping.
Only explicitly passed read-only nodes are used for the census; a missing node,
new device, inaccessible status, duplicate backing inode or uncertain result
refuses the operation. No loop-control, wildcard device rule, mknod, privileged
container, host directory mount, host PID namespace or automatic alternate
device selection is permitted by this proposal.

The proposed diagnostic reserves only the explicitly authorized loop7 for
writes; other observed loop nodes would be passed read-only. The helper takes
`O_RDWR|O_EXCL` for attach/detach, verifies the exact block rdev, and atomically
configures offset zero and a fixed one-GiB sizelimit. It compares backing
dev/inode with `LOOP_GET_STATUS64`, rather than trusting a pathname. An occupied
device or race fails without detaching someone else's mapping. The mapping
census is repeated around the operation. A trusted VM operator must exclude
competing privileged management; a census is not a fence against that operator.

The real gate must then create an exact run-owned Docker local ext4 volume,
observe the high-UID Control filesystem and unique consumer, exercise durable
write/reopen and capacity exhaustion, and reject a second/stopped consumer,
mount replacement, wrong mapping, extra loop alias and capacity/flag drift.
The expected sysfs backing path must be tested as-is. If it differs between
namespaces, redesign the source-inode/volume binding under review rather than
accepting arbitrary paths. A caller-provided success flag cannot supply this
missing composition. No physical Store observation is a dispatch permit.

Cleanup first removes exact run-owned consumers and the filesystem volume.
The helper's exclusive block-device fd must reject a mounted/claimed device
before any detach ioctl. Only a subsequent ENXIO proves that exact mapping was
detached; lazy autoclear or any uncertainty retains the backing and evidence.
The helper never removes backing files. Docker object ownership and absence
must be independently rechecked before any fixture cleanup. The 2026-10-11
diagnostic below now supplies actual device and exclusive-open failure evidence.
It does not supply successful Store admission.

The one-GiB image bounds the complete filesystem including metadata, so usable
payload is smaller. Coding's 512 MiB remains the only allocated storage scope;
the other 512 MiB remains unallocated, and the full topology capacity gate is
still open. This backend does not protect against a trusted administrator,
underlying Docker VM disk exhaustion, or VM loss. Restart must reobserve and
fail closed; the helper refuses to reattach used image bytes using a changed
initial seal. Automatic recovery, production provisioning and four-volume
Coding scenarios remain subsequent work.

The device assumptions follow the [Docker block-volume documentation](https://docs.docker.com/engine/storage/volumes/#block-storage-devices)
and [Linux block-device exclusive-open semantics](https://man7.org/linux/man-pages/man2/open.2.html).

## 2026-10-11 actual diagnostic: raw filesystem passes, Store admission fails

The fresh census found every explicitly granted loop0–loop7 unconfigured.
The existing offline image's original hash, one-GiB allocation, private owner,
device and inode matched its immutable seal. The helper atomically attached
only loop7 and verified the exact backing dev/inode and size through the kernel.
No original seal, image lock or historical receipt was rewritten.

The real Docker Desktop Linux/arm64 mount exposed two independent blockers:

- The whole ext4 mount at `/receipt` had `master:5` in actual mountinfo. It
  receives upstream propagation and fails the existing private-mount check,
  even though rw/nosuid/nodev/noexec and high UID/GID were correct.
- Actual loop sysfs exposed `/receipt.ext4`, not the Docker volume's absolute
  mountpoint plus filename. The exact backing-path check also failed. Linux
  obtains this display using [`file_path`](https://raw.githubusercontent.com/torvalds/linux/master/drivers/block/loop.c);
  a namespace-dependent pathname must not replace a backing inode proof.

`TestDedicatedStorageRealAdmission` therefore **failed** as a positive gate.
The root remained empty; the following raw-write phase independently required
that emptiness. No Store namespace or receipt was initialized. The implementation
still rejects both conditions, and no caller boolean, basename fallback, Docker
inspect propagation string or unreviewed `o=private` change can override them.

Separate Linux integration diagnostics passed with the exact run-owned ext4
volume and UID/GID 57010:57011, no capabilities/network, read-only root and fixed
resource limits. They wrote and synced one MiB, reopened and compared bytes in
a second container, and verified again in a third. Executing a copied valid ELF
on the volume returned EACCES. Physical stress wrote **1,002,438,656 bytes** before
ENOSPC; no EIO was accepted. The original payload remained readable. Removing
only the verified stress inode and syncing restored **1,002,602,496 available
bytes**. Payload capacity was **1,020,702,720 bytes**, below the one-GiB device
size because filesystem metadata consumes space. These are raw filesystem
facts, not Store logical-quota, Store ENOSPC-branch or complete Profile evidence.
Stress-file identity checking assumes the explicitly coordinated sole writer;
the check and unlink are not an atomic defense against a same-UID attacker.

While a separately inspected high-UID holder kept that volume mounted,
`TestMountedBackendExclusiveDetachRefusal` observed EBUSY from O_RDWR|O_EXCL,
verified that the production helper refused detach, and reobserved the same
backing inode. This uses only the already authorized exact loop7 write access
and temporary SYS_ADMIN. Subsequent cleanup removes the exact consumers and
filesystem volume before detach, requires ENXIO plus a fresh all-loop census,
and checks offline e2fsck before removing the backing volume. Raw logs, both
test binaries, source hashes and cleanup results remain outside Git under
`coding-persistent-backend-live-20261011`.

The next acceptable result requires a reviewed source-inode/volume observation
composition and an actually private mount, followed by a fresh Store namespace
and the positive persistence/logical-quota gates. The high-UID Store process also
cannot directly access the observer's current root:root 0660 Docker socket;
separate raw filesystem and root-side Docker inventories do not prove one
composed Control authority. No new privileged role or socket permission is
implicitly approved. The existing closed Profile/provider entry points remain.

## 2026-10-11 follow-up: private mount and read-only source observation

The next independently reviewed diagnostic corrected an assumption from the
earlier review: a Docker volume's container bind propagation and the local
driver's underlying filesystem mount are separate layers. The
[Moby local driver](https://raw.githubusercontent.com/moby/moby/master/daemon/volume/local/local_unix.go)
passes its `o` options to the [mount implementation](https://raw.githubusercontent.com/moby/sys/main/mount/mounter_linux.go),
which handles MS_PRIVATE as a separate operation after mounting the filesystem.
Those upstream sources suggested a test; they were not proof of the installed
daemon binary or permission to ignore a failed kernel check.

A fresh loop7 image/namespace on the same Docker Desktop daemon used exact
local options `rw,nosuid,nodev,noexec,private`. Its actual high-UID whole ext4
mount had **no optional propagation fields**, and the unchanged strict
`readKernelRoot` check passed. The held Docker volume observer now requires
that exact private option, rejects the earlier option set and slave propagation,
and still requires the separate live Store-fd check. This closes the observed
private-mount problem for this diagnostic configuration, not for all daemons.

The helper's new `observe` action is separate from the older ceremony path.
It requires a read-only backing mount; opens only read-only, no-follow,
close-on-exec descriptors; takes a shared lock on an **existing** ceremony lock;
and never creates a missing file. It retains the backing directory, image,
canonical original seal and exact loop fd. Statx compares each fd with its live
name, including mount ID, inode, owner, permissions and link count. The three
backing files must belong to that same directory mount. The loop's actual
backing dev/inode, offset, fixed size and flags match the retained image and
seal before and after a complete bounded census. Writable mount, absent device,
wrong namespace and detached source fail without emitting an observation.

The private JSON reports only explicit identity fields and hashes. It does not
serialize the loop filename, encryption key/name or reserved arrays. The seal's
hash remains the **initial** image hash; mounted writes can change image bytes.
The observer neither rehashes those live bytes as an immutable snapshot nor
grants a Store token, operator signature, lease or execution permit. A shared
lock coordinates cooperating helper ceremonies only. It cannot fence a VM
administrator or prevent a change after the final check.

Actual read-only observation passed both without a mounted consumer and while
a separately inspected high-UID consumer held the filesystem mounted. The
helper had no added capabilities or network, a read-only root/backing mount,
and only explicitly granted read-only loop nodes. Negative cases above passed.
The positive Store test still **failed**: kernel-root validation now succeeds,
but sysfs still displays `/receipt.ext4`, which does not satisfy the unchanged
backing-path requirement. No namespace was initialized and this observer output
is not consumed by Store admission. Evidence is outside Git under
`coding-backend-source-observer-20261011`; the preceding run is retained as-is.

The next design must combine a live source capability with the actual Store
root and Docker volume identity, without accepting caller-decoded diagnostic
JSON. How to provide that capability to the high-UID Control remains unselected;
no read-only device or backing descriptor is implicitly granted to that role.
For its separate Docker endpoint, ADR 0055 already defines the preferred
unique high UID/primary GID plus fixed supplementary GID 0 candidate, subject
to real access and wrong-principal denial gates. Lack of that currently
configured group is not evidence that a new runtime principal is required.

This diagnostic's exact cleanup passed: no remaining consumer or mount-source
alias, filesystem volume removed before exact loop7 detach, ENXIO and all eight
loop nodes unconfigured, offline e2fsck clean, original seal unchanged, and both
owned volumes, all owned containers and the new diagnostic image tag removed.
The existing base utility image and unrelated Docker resources were retained.
Independent read-only review checked these records and the final option guard.

Validation used mise Go 1.26.8 and restricted Linux/arm64 Docker containers.
The full race/shuffle/count=1 run passed in 326.442 seconds and full vet passed
in 2.649 seconds, before the final Docker option guard edit. That final affected
package separately passed race/shuffle/count=1 in 39.107 seconds, vet in 0.515
seconds, and the real ordinary-volume/stopped-consumer integration in 5.395
seconds. Linux helper tests, the strict private-mount diagnostic, source
observations/refusals and tagged Linux vet also passed. These are complementary
results, not a claim that the full suite ran against the final identical bytes.
The positive Store admission test remains a recorded failure; persistence,
logical quota and Store-level ENOSPC acceptance remain pending.


## 2026-10-11 reviewed live source, Store and Docker composition

The next explicitly authorized, independently reviewed candidate provides the
missing live composition in one high-UID Control process. A new
`source-provision.v2` namespace uses root-owned backing directories with GID
57011/mode 0750 and root-owned regular files with GID 57011/mode 0640. Legacy
root:root 0700/0600 mode remains separate and is not upgraded. The Control runs
as 57010:57011 with fixed supplementary GID 0, no capabilities or network, a
read-only root, and exactly three mounts: its private receipt filesystem RW,
its backing volume RO and the root:root 0660 Docker socket RO. Exactly
loop0–loop7 are granted read-only; only the separate operator attach/detach
helper can write the explicitly authorized loop7. No wildcard devices,
loop-control, MKNOD, privileged container or host-directory access is added.

The Linux source session retains read-only, no-follow FDs for the directory,
existing ceremony lock, image, canonical original seal and selected loop for
the complete Store lifetime. It holds a shared flock, checks actual UID/GID
and supplementary groups, and compares each name with its retained FD through
statx, including mount ID, inode, type, owner, mode and link count. The image
remains fully allocated at exactly one GiB. The actual original seal bytes
must match the expected digest and the separate v2 protocol, namespace,
Control GID and image identity. The original image hash remains historical;
current mounted image bytes are never resealed to obtain acceptance.

The Store's existing private whole-ext4-root checks remain mandatory. Its
root device must equal the selected block FD's rdev. Before and after checks,
all eight visible loops are read through exact RO nodes; missing, added,
inaccessible or aliased mappings reject. Actual LOOP_GET_STATUS64 binds the
selected loop to the held image dev/inode, zero offset, exact sizelimit and
flags; bounded sysfs geometry reads corroborate device capacity and writability.
This separate mode no longer uses a namespace-dependent backing filename as
inode proof. The old dedicated mode's strict pathname check is unchanged.

The private composed constructor reads two matching complete Docker inventories
before initializing or reopening the Store, then brackets Store operations with
fresh source/root and Docker checks. It derives a persistent volume binding
from actual inspected volume records, daemon identity/environment, endpoint
scope and the expected socket source. It does not accept decoded observer JSON
or a caller boolean as proof. The Store manifest persists this binding and
stable source/root identities; session mount IDs are checked live rather than
persisted across containers. Changes in inspected volume metadata, including the creation timestamp,
change the binding. Docker local volumes do not provide an unforgeable generation
token: this does not detect all same-metadata recreations by a trusted daemon.
The separate source-directory, image and Store inode checks remain mandatory.
Optional changes in a full Docker Volume record may also conservatively refuse
reopening; there is no automatic manifest repair.

Only the exact inventoried Control may hold these source/device/socket rights.
Stopped second consumers, named-volume or bind aliases, other known socket
holders and other container device authority reject. The actual Docker Desktop
socket mount source is explicitly pinned as `/run/host-services/docker.proxy.sock`
in this fixture; `/var/run/docker.sock` is a distinct selectable expected source,
not a fallback. For this proxy candidate only, unrelated macOS binds may have
exact `/host_mnt` + `/Users/...` list representation and `/Users/...` inspect
representation. All other MountPoint fields must match. Owned mounts, volumes
and sockets are never normalized; the raw list projection is safety-checked
and retained in both inventory digests. This records the observed daemon
behavior without weakening source alias checks or changing unrelated services.

Construction and each composed operation have a shared maximum ten-second
request context, including gate wait, initial external reads, both observations
and the Store write context. Individual Docker requests retain their existing
five-second cap, and shorter caller deadlines win. Failure after a potentially
written mutation yields uncertainty and poisons the live wrapper; a failed
post-initialization observation leaves the marker for investigation. Close
releases held local FDs even after request cancellation. These contexts cannot
interrupt a kernel syscall already blocked in filesystem I/O and are not a
physical ten-second disk-I/O guarantee.

The composed type and its Store are private to this component. There is still
no public production constructor, full source/operator admission or Coding
ledger/dispatch permit from a successful observation. A read-only Docker socket
mount does not constrain daemon API authority: Control, the daemon and host/VM
administrators remain trusted. Snapshot checks and advisory flock do not fence
an uncooperative administrator or a future daemon request.

Private commands, failed attempts, binaries, source hashes and new receipts are
stored outside Git under `control-storage-composition-20261011`. The old
migration package, seals, helper authorization and previous acceptance evidence
are unchanged. This work closes the previously missing component composition;
full Profile admission, Store ENOSPC/recovery branches, actual wrong-principal
socket denial, complete four-volume Coding scenarios and the final topology
and sixteen-scenario gate remain separate work.


The final fresh Linux/arm64 fixture (`v4-budget-final`) passes composed
initialization and a 102,400-byte persisted state, successful/stale CAS,
64 one-byte allocation objects followed by ErrCapacity on object 65, and
reopening in a replacement Control container. Wrong expected seal, stopped
receipt consumer, stopped backing consumer and stopped socket peer each reject;
removing each extra consumer restores valid reopening. A held source session
blocks the cooperating helper's exclusive maintenance lock. Replacing only
the seal filename with a new inode containing identical bytes is detected by
both the retained Store and composed wrapper. The original seal bytes are
preserved; this does not stand in for an image-inode or mount replacement test.

Both new fixture namespaces were reclaimed exactly: no owned containers or
volumes remain, filesystem removal preceded exact loop7 detach/ENXIO, all eight
loops were unconfigured, offline fsck passed, and only the new image tags were
removed. The preexisting utility image and unrelated services were retained.
All original failed attempts remain alongside final evidence.

Validation: the full race/shuffle/count=1 suite passed in 256.398 seconds and
full vet in 5.495 seconds before the final Docker mapping and shared-deadline
edits. The final affected Docker package passed race/shuffle/count=1 in 34.723
seconds, native vet in 0.427 seconds and Linux tagged vet in 0.492 seconds.
Linux helper/source FD tests and the final real composition above also pass.
The ordinary-volume/stopped-consumer Docker test passed in 5.044 seconds before
the last shared-deadline edit; final real fixtures cover the changed composed
path. These are complementary snapshot-scoped results, not a claim that the
full suite ran on the final identical bytes. Contract inputs and locks did not
change and their earlier unchanged-source evidence was not rerun for narration.


## 2026-10-11 Store fault and principal gate design

The next independently reviewed gate keeps the existing Store recovery policy:
there is no reset, residue deletion, automatic repair or new recovery API.
Initialization is refused on an existing marker. A fresh process may reopen
only a fully canonical, source/root/volume-bound namespace; that observation
is not a success receipt or dispatch permission. Mid-publication residue
remains closed. A readable namespace after process exit is not proof of
power-loss durability, especially at the pre-directory-fsync manifest-rename
stage.

A private, unset-by-production test observer records `writeNew`'s actual
syscall stage and underlying error before the existing outward ErrUncertain
mapping. It does not inject errno or provide authority. The implementation
also now treats file Close errors as write failure; previously they were
ignored. Raw syscall errors are not added to stable API messages.

The Linux tagged fixture uses only the already reviewed exact high-UID Control,
source-provision.v2 backing, private whole ext4 filesystem and bounded loop7
ceremony. Ten fresh namespaces separate low-space preflight, actual write
ENOSPC, two cancellation points, five process-exit points and wrong-principal
probes. The helper and pinned base image are reused unchanged; only the affected
test binaries and one local diagnostic image are rebuilt. mise Go1.26.8 remains
the repository toolchain; no global development installation is involved.

Test-only pressure is an actual high-UID file created and then unlinked inside
this run's ext4, retained by fd. Allocation is bounded by the one-GiB backend
and the existing ten-second request context. It grants no storage to the
unallocated half or any other runtime scope. With only 32 MiB available,
ordinary Store preflight must return ErrCapacity before the write hook or any
namespace change; releasing the exact pressure fd restores healthy writes.
For the actual ENOSPC case, a `before-object` test hook runs only after the
Store space check has passed, allocates real blocks down to eight free blocks,
and returns nil. Acceptance requires the real pending.object Write/Sync to
return ENOSPC, not the hook returning a synthetic error. If pressure cannot be
created within its bounds, or Openat fails without residue, that is a different
recorded result and cannot be relabeled as the pending-write gate.

After an uncertain write, the live owner stays poisoned even when pressure is
released. A replacement Control process independently checks the exact
residue and attempts both Store reopening and the private composed constructor.
Reopen refusal must leave every retained file's inode, permissions, length and
hash unchanged. An incomplete namespace must also reject InitializeSourceBound
without deleting or replacing its marker.

Five controlled process exits skip Go defers at before-object, after-object-
sync, after-object-rename, after-manifest-sync and after-manifest-rename. The
first and last allow a consistent independent reopen; the three middle stages
retain their specific pending/object/manifest inconsistencies and reject.
Caller cancellation before Put is a no-effect refusal; cancellation after
object sync remains uncertain with a pending object. Complete original state
and any published test evidence are checked against their expected bytes.

Wrong-principal checks use separately created candidates after the accepted
Control has been stopped and removed. They do not assume `docker exec --user`
removes supplemental groups. Actual UID/GID/groups are checked for wrong UID
57012:57012, wrong primary GID 57010:57012 and correct 57010:57011 without socket
GID0. Tests separately probe expected source/root file DAC and require actual
Unix socket connect to return EACCES, then require source-Store admission to
reject. The original exact owner is recreated and must reopen successfully
after each probe. A correct UID may still read its own 0700 Store files; that
is not a failed wrong-GID test. Likewise the correct primary GID may read the
RO source, while missing GID0 must still deny socket access and source mode.

Faults are exercised through the private Store test hook inside the same
inventoried Control. Docker composition is checked during initial admission and
again on independent reopening; a fixture input or decoded diagnostic JSON is
not promoted into continuous production admission. Full source Profile/operator
commands, Coding ledger/PG/dispatch integration and the four-volume Coding
scenarios remain later gates. Public holds, issuers and evidence-reuse rules
are unchanged.


### Actual fault and principal results

All ten fresh Linux/arm64 namespaces passed their selected gates and exact
cleanup. Actual pressure reduced available blocks from 1,003,548,672 bytes to
32 MiB for the no-effect preflight, and to 32,768 bytes after the Store's
preflight for the write fault. The latter observed **pending.object Write
ENOSPC** from the real syscall and retained an empty pending file. It was not
an injected errno. Original manifest/state hashes remained unchanged; release
of pressure did not unpoison the owner or repair the incomplete namespace.

| Boundary | Observed result after independent process/Control replacement |
| --- | --- |
| Low-space preflight | ErrCapacity before write; files unchanged; releasing only the pressure fd restored valid writes and later composed reopen |
| Actual Write ENOSPC | ErrUncertain, poisoned owner, pending object retained; Store reopen, reinitialize and composed reopen refused |
| Cancel before call | No effect; original state revalidated and reopened |
| Cancel after object sync | ErrUncertain and pending object; independent reopen refused |
| Exit before object write | Original consistent namespace reopened |
| Exit after object sync | Pending object preserved; reopen refused |
| Exit after object rename | Published object with old manifest preserved; reopen refused |
| Exit after manifest sync | Published object and pending manifest preserved; reopen refused |
| Exit after manifest rename | Currently consistent files revalidated and reopened; no caller success receipt or power-loss claim |
| Wrong principals | Actual file DAC and socket connect EACCES; source Store refused; original owner restored and composed reopen passed after every probe |

For the eight fault/cancel/exit cases requiring separate reopen classification,
name/hash/inode/size/mode snapshots before and after the recovery attempt match
exactly. The three wrong-principal groups were actually `[57012]`, `[57012]`
and `[57011]`; GID0 was absent. Correct-owner positive reopen is a separate
result, not inferred from a failed wrong-owner attempt.

Each case removed its exact consumers and filesystem volume before exclusive
loop7 detach, confirmed ENXIO and all eight nodes unconfigured, passed offline
fsck, and removed its backing volume. Original seals were byte-checked. The
single new diagnostic image was removed after all cases; the base utility
image and unrelated services/volumes were retained. All binaries, commands,
raw stdout/stderr, observed metadata, review record and exact source hashes
remain outside Git in `control-storage-fault-gates-20261011`. These tests close
the bounded Store fault/principal gaps, not the complete Profile, Coding
ledger/PG dispatch, four-volume runtime or original sixteen-scenario gate.


Final validation for these same Go bytes passed: `go test -race -shuffle=on
-count=1 ./...` in **524.358 seconds**, full `go vet ./...` in **8.867 seconds**,
focused Store/Docker race tests in 27.622 seconds, and Linux tagged vet in
1.622 seconds. The full race run retained its existing 600-second runner limit;
no timeout was extended. The ten actual Linux fixtures used the frozen final
Go snapshot; subsequent changes only record results in documentation. Contract
inputs, Go module/toolchain locks and AGENTS are unchanged, so their unchanged
historical checks were not rerun for narration.


## 2026-10-11 reviewed source-owned execution ledger lifetime

Independent review identified a concrete gap between the admitted diagnostic
mechanism and the held complete Profile. The real candidate needs a RO source
volume, eight exact RO loop nodes, `/run/control-storage-docker.sock`, no network
and exactly three mounts. The current complete Profile instead forbids host
devices, fixes the daemon target at `/var/run/docker.sock`, and requires three
Control ingress networks/listeners plus its private TLS/configuration inputs.
A valid-looking Profile digest cannot authorize those different rights. The
existing three-volume command also cannot consume the new four-volume mode by
stripping fields or casting templates. Neither policy is relaxed here.

This continuation closes the separate ledger-lifetime dependency. Its only
non-test constructor first joins the complete storage binding/layout/template,
actual daemon identity/environment, endpoint scope and platform. It refuses
caller-prepopulated derived volume identity before opening anything. It then
owns the previously reviewed composed source/Docker Store, with one shared
maximum ten-second constructor context. A package-private marker and narrow
Check/ReadState/CompareState/Close port exclude a raw file Store. The ordinary
directory constructors and their adapter now compile only in tests.

The common loader checks and reads the owned Store, then either initializes one
new state by CAS or strictly decodes existing state. Missing state on reopen is
an error, never an invitation to initialize. Every failure closes only its held
FDs and retains the permanent marker and any state/residue. Every subsequent
ledger read/CAS passes through the actual source/root/Docker observations.
Unknown is still durable before a callback; callback return, expiry, reopen
and cancellation do not make it Completed, replayable or releasable.

Close marks the ledger closing before draining callbacks. Cancellation while
waiting leaves the source, Store flock and Docker sessions owned, and further
work closed; the caller must later finish Close. Only after callbacks return
are the sessions released. The observations and advisory locks do not fence
future daemon calls or an uncooperative host/VM administrator. No public
constructor, command admission, authenticated PG claim or production callback
is introduced by this private composition.

The new real fixtures use the source-owned Coding candidate template and actual
observed daemon, but explicitly synthetic Profile/principal/policy digests and
bounded effect probes. They are source-storage/ledger component evidence, not
full source-derived Profile/operator or four-volume workload evidence. The two
ledger interruption hooks bracket a real durable state CAS; they are not new
physical ENOSPC or power-loss experiments. Previous physical Store fault results
remain tied to their own unchanged source and fresh namespaces.

Next define and independently review an exact, separately versioned Control
source-access mode in the complete Profile and operator provisioning path. It
must bind the named backing volume, eight explicit RO devices, original seal,
canonical socket source/target, source owner UID/GID/groups and deployment image
without widening generic HostDevices or mount-kind rules. It must compose the
real service networks and TLS/private-config mounts one-to-one, account for
resources and distinguish mutable deployment/session facts from the acyclic
source preimage. Only then can the command and source-derived ledger binding
be wired, followed by PG/mTLS and four-volume physical gates. Public Profile
and Provider v3 holds, two issuers, frozen-R reuse and Phase6 5/15 remain intact.


### Actual source-owned ledger results

Six fresh source-v2 namespaces on the exact loop7/ext4 backend pass:

| Case | Observed result |
| --- | --- |
| durable-unknown | A real CAS is readable as Unknown before the bounded effect probe; replacement-process reopen refuses create replay, exec and completion collection. |
| close-drain | Canceled Close keeps an actually checkable source owner and prevents a second owner; after callback drain and completed Close a new owner reopens Unknown. |
| uncertain-before | The before-state ledger interruption invokes no effect, poisons the ledger, and leaves the original empty state available for independent revalidation. |
| uncertain-after | The after-state ledger interruption follows real publication, invokes no effect, and retains Unknown across a replacement process. |
| missing-state | An initialized Store with no ledger refuses both ledger reopen and reinitialization; failed load releases its FDs without adding state. |
| consumer-drift | A stopped second receipt-volume consumer is inserted before the held owner checks; source-owner poison is asserted, and after peer removal a fresh valid request still refuses with no state change. A replacement owner reopens the empty state. |

Each completed fixture removed exact owners/consumers, removed its filesystem
volume, detached the original loop7 with ENXIO, checked all eight loops empty,
passed offline fsck, compared the original seal's canonical bytes and hash,
and removed the exact backing volume. Zero owned containers/volumes remain.
The one new shared diagnostic image was removed only after all six fixtures;
the original utility base and unrelated services remained.

The uncertain-after command tests both passed, but an outer raw `ls -la`
comparison failed because it included `..`, the replacement container's parent
directory. Independent review confirmed that this was the sole differing line;
Store root, entries and all content digests were equal. The failed comparison,
raw snapshots and corrected scope decision remain recorded, and the scenario
was not rerun. Later snapshots use only Store root/entries and explicit
name/inode/size/mode/owner/link-count plus SHA256. No Store assertion, recovery
policy or original evidence was weakened or overwritten.

Evidence is outside Git under `control-storage-ledger-20261011`. All actual
fixtures use the final Go snapshot in its `validation-start-files.json`.
Final validation results are recorded below; earlier Store fault checks are
not presented as a new run of their unchanged source.


Final validation for the unchanged Go snapshot passed: full
`go test -race -shuffle=on -count=1 ./...` in **474.875 seconds**, full
`go vet ./...` in **18.48 seconds**, the focused ledger/source-owner race tests
in 15.317 seconds, and final Linux tagged vet in 0.516 seconds. Six real fixtures
and independent evidence/documentation review passed within the stated scope.
The existing 600-second full-suite runner limit was not changed. No Go byte
changed after the real-fixture snapshot; subsequent edits only record results.
Contract inputs, Go module/toolchain locks and AGENTS remain unchanged.

## 2026-10-11 reviewed complete-Profile source-access declaration

The independently reviewed `sandbox-runtime.phase6-control-source-access.v1`
mode adds an optional `DockerControl.SourceAccess` to the held Profile v2.
It is restricted to the candidate Coding execution v3 mode and the unique
Control UID57010/GID57011 with supplementary group0. Legacy encoding omits the
new field and retains the old socket/device rules. Only this exact Control
branch declares HostDevices; other principals still cannot borrow it.

Provisioning has two digest domains. Before sealing, the independently canonical
`source-intent.v1` includes a fresh namespace, Control principal and OCI image
identity/platform, fixed UID/GID/groups, root:57011 source directory0750 and
files0640, the RO backing mount, exact1GiB sealed image, loop0–7 at their same
paths with `r` permissions and selected loop7, and one explicit supported daemon
socket source mounted RO at `/run/control-storage-docker.sock`. The backing
label binds this intent and the exact backend; it does not contain the future
Profile digest. After the original seal exists, the full Profile recomputes the
intent and includes the original seal digest. Only the filesystem/Control labels
and Store binding add the final Profile digest. Old labels and seals are never
rewritten. The RO backing mount has MaxBytes0: the image is exactly1GiB, but the
backing volume itself is not claimed to have a hard quota.

`tools/control-source-review` reads bounded canonical stdin. With `-intent`, it
checks the independent pre-seal document without a placeholder seal or full
Profile. Without that flag, it checks the **complete declared** Profile chain,
including the existing static registry, candidate template/budget, three Control
networks/listeners, TLS agents, CRL/private configuration, trust edges and PG
bindings. Both outputs explicitly say `held-not-a-permit`; neither is consumed
as a production Store/ledger/execution capability. Public `ProfileV2.Validate`,
`DecodeV2`, storage binding and provider v3 admission remain closed. The old
Control command is not silently adapted by stripping the source mode.

The new private observer branch checks all seven Control mounts, exact groups,
devices, socket source/target, memory/CPU/PIDs, seccomp policy digest, OCI index
and selected manifest/platform, and the three named internal isolated networks
and addresses. Each auxiliary VolumeInspect must match the unfiltered
VolumeList. All containers, including stopped ones, are checked for receipt,
backing, socket and auxiliary-input consumers or aliases. Input-volume creation
metadata and network IDs are observed inside the stability bracket; mutable
session identities are not inserted into the pre-seal intent.

This runtime branch is **Control-only staging**, with no production constructor:
only explicitly enabled integration tests compose it with a Store. Each network
has only the Control endpoint in this fixture. Legitimate Provider/TLS-agent
peers will need an independently reviewed exact identity/consumer allowlist
before full-topology admission. The actual input mounts do not prove live CA,
private CRL content, TLS-agent socket availability or service readiness. A RO
Docker socket mount does not restrict Docker API authority; daemon/operator
remain trusted. The existing three-mount/no-network diagnostic branch is not
widened.

The current test fixture derives the final Profile digest from complete
canonical Profile bytes and the new original seal. Its Control image is a new
local diagnostic candidate with verified local index→arm64 manifest→config
hashes; other role supply identities remain explicitly synthetic. This is not
release supply/provenance admission, a final live inventory, or original16
acceptance. Two preliminary attempts are preserved outside Git: one corrected
an OCI index misclassified as config identity before Control launch; the other
failed on Docker's explicit IPv4 network option before Store initialization.
Both were reclaimed through the original seal and exact namespace, with no
receipt edits or failure removal.

Next establish reviewed operator admission and the complete command's trusted
source inputs, including exact identities of allowed Provider/TLS/CA consumers.
Then connect the source-owned ledger to the real Control/PG/mTLS command path
and prove four-volume effects. No descriptive review output may bypass that
admission. Phase6 remains5/15; Slice6 step2 remains open, step3 full topology and
original16 remain unaccepted, and step4 has not begun.

### Actual bounded source-access results

The final fresh Linux/arm64 namespace passes Store initialization/write/read,
replacement-container reopen, and reopen after all permission refusals. The
same daemon first accepts the create-only configured baseline, then rejects
**eight never-started** variants: RW socket, RW loop7, missing loop0, extra group,
RW backing, wrong socket target, missing private configuration mount and missing
network. A stopped second private-config-volume consumer is refused; after its
exact removal a fresh owner reads the unchanged state. These are daemon-object
configuration and source-storage checks, not execution of unsafe permissions.

Exact cleanup retains the original seal, removes run-owned containers/volumes
and three networks, observes loop7 detach with ENXIO and all eight loops clear,
and passes offline fsck before removing the backing volume and new image tag.
No global prune is used. The operator binary also passes independent pre-seal
intent and complete canonical Profile review from stdin, producing held output.
Evidence is private and outside Git in `control-profile-source-access-20261011`,
with `final-fixture` holding the accepted component run and both preliminary
attempts retained. Whole-repository validation and final independent evidence
review are recorded separately; this subsection alone is not their result.


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

## 2026-10-11 reviewed operator and consumer observation component

The new held boundary is derived from the complete canonical Profile inside the
admission constructor. The exported source review and consumer review remain
modifiable descriptions: neither can supply authority. Admission re-decodes the
original bytes, runs the complete static field chain and compares the derived
projection before reading an operator bootstrap key. The previous Control-only
staging branch still rejects all peer consumers; it is not relaxed in place.

This boundary consists of Control, the consumers of its `internal-server-ca`
and `internal-client-ca`, the three endpoint Providers, and its unique TLS
agent, derived and deduplicated from the Profile. The current fixture contains
19 principals. Other anchors (`external-server-ca`, `postgres-client-ca`,
`vault-client-ca`) and their consumers remain outside this observation. Each
peer receives exactly its two relevant RO CA mounts or, for the TLS agent,
its single declared RW socket volume. Every unrelated role mount/network is
rejected in this diagnostic projection. Control retains its seven exact mounts
and eight RO loop mappings. Each of its three isolated internal networks has
exactly Control and the corresponding Provider endpoint. No public uplink is
created for this fixture.

Container names/labels locate candidates but cannot authorize them. The
observer checks the actual full ID, creation/start times, OCI index and selected
platform manifest, numeric UID/GID/groups, resource/security settings, actual
and configured mounts, volume roots, and network IDs/IPs/endpoints. Stopped and
unrelated containers participate in the full bounded census; extra consumers,
source aliases, stopped required consumers and replacement drift fail closed.
This is a fixed `/bin/sleep 1800` **diagnostic carrier** mode with exact command,
entrypoint, environment and working directory. It is not a real Provider/TLS
process identity or complete-role deployment. Signing arbitrary observed
commands is not accepted as legitimate service identity.

Operator observation v1 signs the canonical Profile byte hash and logical
digest, fresh process run/challenge, namespace, original intent/seal, actual
source/root session, Docker graph and volume binding with a maximum 120-second
lifetime. The verifier generates both random values; every signature attempt
consumes that session. Restart/reopen requires a new signature. Wall time and a
local monotonic deadline are enforced. Every Store operation rechecks the
approved root/graph and expiry, with post-write drift retaining uncertain state.
A read-only `SourceProbe` holds the source FDs/ceremony lock and actual Store
root before authorization. Signature failure never initializes a Store marker.
All failed admission paths release owned FDs, lock and Docker client.

The test bootstrap is an owned read-only pipe: exact 32 public-key bytes, EOF,
bounded Poll/read, context cancellation and descriptor closure. It is explicitly
**not** a new file in the closed Profile private-config directory and not a
production credential channel. The key commitment is fixed independently in
the diagnostic binary; normal builds have an empty commitment and fail closed.
The test private key remains on the operator host. That signer independently
re-derives the Profile, re-reads the daemon graph and compares a separate physical
source/root probe. This proves local test-key verification, not an independent
production operator's approval. No production constructor or dispatch grant is
introduced. The Store's existing source-v2 format does not acquire a persistent
operator-mode marker; this run uses a fresh namespace and establishes no legacy
migration or byte-level no-upgrade guarantee.

Real evidence is retained outside Git as `control-operator-consumers-20261011`:
canonical-review tampering and bad signature refusals without Store changes;
signed graph drift and live graph drift refusals; initialize/reopen; stopped TLS
writer, extra stopped CA reader, third endpoint, same-name/label wrong UID,
command, image, extra group/config, writable CA and swapped CA source refusals;
and fresh signing/reopen after legitimate replacement. One private Python
harness assignment failed before creating the first replacement; it is retained
and excluded from acceptance, then the remaining scenarios were resumed without
changing Go bytes, image, Profile or original seal.

Remaining work is the production bootstrap declaration/operator identity,
source-bound real role launch configuration and actual Provider/TLS/CA/CRL
service chain, followed by Control/PG dispatch and four-volume effects. CA bytes,
TLS socket contents, certificate/CRL readiness, the other anchor graph and final
82-principal live inventory are not proved by the diagnostic volumes. The public
Profile/provider-v3 holds, two issuers, frozen-R rule and Phase6 5/15 remain.


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
