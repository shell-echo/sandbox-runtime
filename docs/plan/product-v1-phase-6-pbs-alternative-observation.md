# PBS alternative observation feasibility

Date: 2026-10-21. Status: independently reviewed design candidate only;
**no replacement executor or real P2 is admitted**. This continues the
[process/cwd observation plan](product-v1-phase-6-pbs-process-observation.md).
Phase6 remains **5/15**, Slice6 step2 ongoing. This is not formal step4.

Current continuation: [real Docker metadata screen](#2026-10-21-real-docker-metadata-screen).
The earlier unavailable17-case result below remains historical and failed;
the new mock result does not qualify a real endpoint or replacement executor.

## Decision and current evidence

Keep the fixed Darwin diagnostic held. Its current capture reaps the child
before the group check; neither that check's interface nor matching snapshots
proves coherent complete membership, zombies or no escape. The checked Apple
publication paths have not established exact current-platform XNU provenance.
This does not prove that no official source exists.

A plain switch to Docker is not equivalent. The existing fixed executable is
Darwin arm64; Linux would change its bytes, ABI, invocation, filesystem and
execution evidence. mise manages the installed tool; it supplies no process
confinement. A Linux path must be a separately qualified new execution target,
with original locks, failures and the held Darwin identity preserved. Do not
inherit old acceptance or keep redundant implementations for compatibility.

Independent review conditionally accepts investigation of prevention in a new
Linux target. It does **not** accept a concrete seccomp policy, runtime,
management-authority premise, budget or verification result. Existing component
evidence and old seccomp A/B results do not qualify this new target.

Private checkpoint: `pbs-linux-observation-feasibility-20261021-152922`.
The latest prior sealed checkpoint is freshly verified in full:130 files
excluding its index and9 directories. The18-tree historical evidence chain,
2379 initial direct inputs, nine aliases,64 barriers,402 old files and33
qualified components remain retained; older full-check records are not
represented as new executions. Mutable official documentation below is design
discovery, not authenticated exact source, ABI or runtime input.

## Proof obligations for a possible Linux target

| Obligation | Candidate approach | Evidence still missing |
| --- | --- | --- |
| Tool and execution identity | Authenticated Linux-arm64 ELF, OCI/runtime/kernel and policy inputs; new argv and run binding | Exact candidate bytes, source/supply qualification and complete reviewed input graph |
| No extra user processes | Fixed verifier as sole PID1; no init, helper, health, restart or lifecycle command; arch-bound seccomp permits only proven Go thread creation | Exact clone flags/ABI and effective enforcement; retain every applicable baseline deny; reject new processes and escape attempts with process termination |
| No daemon-side injection | Bind approved management authority throughout the case | `docker exec` can insert another process without verifier fork/clone; project single-writer confirmation is not enforced exclusive Docker API access |
| Executable surface | Bind initial OCI executable and all later executable paths/FDs | Stateless seccomp does not distinguish first `execve` from later calls; `execveat`, memfd and alternate executables need closure |
| Network rejection | At least the original deny-network semantics | `network=none` alone does not close loopback, Unix sockets or inherited FDs |
| Filesystem and input identity | Preserve original host input identities and bind derived container copies separately | Container device/inode identities cannot be relabelled as original host identities; cwd/state/mount/UID/GID and noexec checks remain |
| Natural result and closure | Complete raw output, natural expected exit and exact cleanup | Start/attach/log framing, signals, OOM and namespace cleanup must be distinguished; stopped state/exit code alone is insufficient |
| Timing and resources | Same two executors at most,2CPU/2GiB/128PIDs; leaf25s, whole90s, host age120s | Measured full chain including create/start/attach/wait/inspect, all input/host checks, observation and cleanup; no independent extra budget |

The [Linux seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
supports argument filtering and process-terminating actions; it also describes
limits of the mechanism. The [clone reference](https://man7.org/linux/man-pages/man2/clone.2.html)
distinguishes thread-group creation. These facts support a hypothesis, not
the exact flags or permitted syscalls of this verifier.

The [PID-namespace reference](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
states that termination of namespace PID1 kills remaining processes. Therefore
a stopped container cannot prove that no process was left behind. The
[Docker exec command](https://docs.docker.com/reference/cli/docker/container/exec/)
starts another command in a running container, independently of PID1's fork
policy. The [OCI Linux configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
and [Docker seccomp documentation](https://docs.docker.com/engine/security/seccomp/)
describe policy inputs, not proof of a concrete profile's behavior.

The existing trusted daemon/operator boundary remains. Docker socket access
is powerful administrative access, as documented by
[Docker](https://docs.docker.com/engine/install/linux-postinstall/).
Do not silently turn that trust boundary into an assertion that every socket
client is excluded during this run. A new claim requires an explicit reviewed
authority model and evidence; it is not established by a run label, advisory
lock, read-only socket mount, before/after daemon ID or endpoint path.
Existing ADR0055 endpoint/ID drift checks do not authenticate an endpoint or
establish quiescence of other callers.

## Narrow management-metadata screen and actual outcome

The reviewed private probe proposes only two direct requests to the frozen
existing Unix socket: `/info`, then `/version`. It executes no Docker CLI,
credential helper, login, container operation, host-admission gate, build or
scan. Each complete request has an absolute3-second bound,64KiB complete wire
and8KiB headers. It rejects redirects, authentication/fallback/retry paths,
non200, compression, ambiguous framing, incomplete or oversized responses.

Only whitelisted metadata and byte counts/hashes would be persisted. Raw HTTP
is intentionally not retained, so no independent raw-response reparse is
possible. Error records omit exception details and ignored proxy/registry
fields. Allowed printable kernel/security metadata is not a general detector
of secrets deliberately placed in those fields by a malicious endpoint.
The four authorization states—missing, null, empty and nonempty—remain
distinct. None proves management exclusivity; a plugin name would only identify
a policy-source investigation. Socket/parent identity checks do not authenticate
the daemon or eliminate a connect-time race.

Independent implementation review permits one17-case mock-only test identity,
not the real requests. The exact focused unit graph contains nine rows: all
new code/tests/runners, capture/files/policy helpers, execution plan and existing
managed Python binary. This scope is limited to those tests; it does not remove
the2379 historical inputs or their required checks from a real operation.

That identity **fails the original10-second whole-parent limit**. Its capture
has only0.619251583seconds remaining and reports0.625471042seconds elapsed,
`TimeoutError`, no child exit code, no confirmed owned-child reap and zero
captured bytes. The outer rejects whole-parent elapsed time and has no complete
post-input receipt. The pre-capture work consumed approximately9.38seconds;
there is no internal timing evidence attributing it to a specific file, CPU
load or syscall. Seventeen test results are **unavailable**, not passed.
A later read-only process snapshot finds no matching diagnostic command; that
does not repair the missing run-time ownership/closure evidence.

The original failure and own outer logs are retained outside Git. A tooling
store reset caused only those three shell outer logs to land in the default
checkout; their exact own bytes were verified and moved to the private
checkpoint, with a relocation record. Internal paths and captures were always
absolute in the checkpoint. No product source was affected.

No real `/info` or `/version` request is executed, and there is no observation
of actual authorization-plugin state. No endpoint or runtime conclusion follows
from an unexecuted probe. The failed identity must not be rerun or reclassified;
any later attempt needs new reviewed inputs and the unchanged original bounds.

## Continuation boundary

Current result: direct platform substitution is rejected; the separate Linux
construction remains a conditional design candidate with the obligations above
open. The Darwin native route remains held for exact provenance/ABI, coherent
census, no escape and before-reap supervision. Neither route is qualified for
implementation or real P2 by this checkpoint.

Next close the metadata instrument's actual test/budget evidence under a new
reviewed identity before querying the daemon. Independently qualify the chosen
route's authority, executable and network premises before changing the real
controller. Do not repeatedly run the same failed identity or infer feasibility
from mutable documentation. If those premises cannot be established within the
existing environment and boundaries, retain the hold rather than install a
new daemon, change shared settings or substitute weaker observations.

No new executable, image, native observer, SDK recovery, verifier case or supply
scan runs here. Existing49 diagnostic component tests cover unchanged product
code and are reused by impact; no product, Go or Contract suite is claimed as
rerun. Timers stay off. Original guards, nine bindings,64 barriers, quotas,
timeouts, cache/index and evidence-reuse rules stay unchanged. Slice6 step1's
historical bounded Guest evidence is unchanged; step2 continues, step3's final
topology/original16 scenarios and independent acceptance remain incomplete,
and formal step4 has not started.

## 2026-10-21 bounded mock harness checkpoint

Private checkpoint: `metadata-unit-budget-20261021-100906`. The previous181-file/
4-directory sealed tree is freshly checked in full. Previous reports and
failed identities are preserved; no old manifest is regenerated to clear a
failure. An input-preparation helper initially compared whole stat results,
including access time; its failure is retained. The corrected preparation
uses the existing identity fields and the prior sealed graph's expected pin,
with no change to the actual binding standard.

The new private harness streams every complete input twice, retaining exact
bytes/EOF, device/inode, UID/GID, mode, modification/change times and real
parent-chain checks. Its raw-byte loader executes only the checked private
modules. The original nine focused inputs, reader and17-case suite remain
exact. Timer and handler preparation uses existing builtin modules; the first
time sample immediately arms the remaining10-second budget before subsequent
imports/definitions. Capture reserves its existing2-second cleanup and a
0.25-second closure margin from that same budget; insufficient time prevents
spawn. Known-handle deadline exceptions enter the unchanged capture cleanup.
A missing receipt or interrupted Popen does not prove ownership or reap.
Neither cleanup after a deadline nor a late marker can make an overrun pass.

One revised identity fails during `unittest.mock` → `asyncio` → `ssl` import:
replacing `socket.socket` with a function breaks `SSLSocket` inheritance.
The child naturally exits1 in0.971716958seconds, within its7.427096292-second
capture allowance, with1578-byte raw stderr, no output, no timeout/truncation/
active signal and a recorded reap. It supplies no25-case test results or
complete postcheck. This is a new concrete code failure, not proof about the
older unexplained9.38-second delay. The failed identity is not repeated.

The final class-shaped guard denies construction in `__new__` before the base
constructor, preserving the interface required by `ssl`. It is installed
before the mock module loads. It covers `socket.socket`, including the tested
Unix/Internet constructors; it is not a general OS, `_socket` or `socketpair`
sandbox. Frozen source review and the mock scope remain necessary.

| New identity | Test result | Complete input rows before/after | Final marker before flush | Captured child time |
| --- | --- | ---: | ---: | ---: |
| v4 refusal | 27/27 | 35 | 0.452756s | 0.271438s |
| v4 frozen original suite | 17/17 | 53 | 0.379147s | 0.197998s |

Both have raw complete streams, capture natural0/owned reap/no flags,
RESULT/SUMMARY, seven phase records and outer natural0. The original nine
rows remain exact in both full checks. Each retains whole-parent10 seconds
and64KiB per stream; marker timestamps precede their final flush, whose success
also requires natural process exit. Refusal cases cover input/parent drift,
symlinks/FIFO/EOF, module substitution, count/result failures, missing PID,
time/stream boundaries and capture cleanup models. The models use no third
process or real signal. No general process-containment or native-ABI proof
follows. Measured phase costs cannot explain the old run under other conditions.

No real `/info` or `/version` request runs. Next independently review a new
complete metadata identity, fresh socket/daemon inputs and exact output root.
Do not call the old reader's main entry with a path that writes into its now
sealed checkpoint; new source copies need explicit new location/identity
bindings. Preserve3-second request/64KiB wire/8KiB header bounds, redacted
projection limitations and all existing authority/host/runtime gates.
Darwin native and new Linux executor qualification remain held. Product code
and prior49 component coverage are unchanged, with no Go/Contract rerun.
Timers remain off; original9 bindings,64 barriers,402 old files,33 components,
quotas, timeouts and cache/index/reuse rules remain. Phase6 stays5/15,
Slice6 step2 ongoing, step3 incomplete, formal step4 not started.

## 2026-10-21 real Docker metadata screen

Private checkpoint: `docker-metadata-readonly-20261021-191746`. Independent
review accepts a new complete2875-row identity: all previous2832 rows remain
verbatim, with43 new source, seal, preparation and actual mock-evidence rows.
The old282-file/7-directory checkpoint's complete external inventory and seal
are checked before preparation. No old manifest or sealed directory is written.

The original reader is copied byte-for-byte to the fresh private `reader-run`
directory; its explicit new `__file__` derives a new `daemon-metadata-v1` output.
The parent has its own separate `real-stage-v1` capture root. Both must be
absent initially; root ownership,0700 permissions and real parent identities,
the copied source, socket inode/metadata and helper bindings are checked.
The new wrapper loads only exact checked private bytes, reusing the reviewed
streaming primitives and capture rather than the old path-import wrapper.

A new26-case execution-binding mock suite passes, with complete25-row pre/post
checks retaining the original nine inputs, natural captured/outer0 and a
0.177062-second pre-flush marker under the unchanged10-second/64KiB bounds.
It covers source/root/output drift, preexisting outputs, unknown ownership,
time/stream refusal and joint output consistency. The old27/17 suites are not
rerun for reporting. One earlier shell launch fails on a misspelled stderr
parent path and supplies no test result; its empty stdout, exit1 and error
record remain. A separately reviewed v2 plan and new outer streams execute
once; no failed plan is rerun or reclassified.

Only the child invokes the original reader. Its per-request3-second alarms
cannot cancel the parent's single early90-second deadline. Capture, the
existing2-second cleanup and0.25-second closure reserve share that same budget.
All2875 complete input rows, nine old aliases, SDK alias, root and socket
bindings are checked before/after within it. Three generated JSON files are
checked separately for exact set, private modes and consistency with the full
captured stdout/stderr; generated outputs are not invented pre-inputs.

| Actual request | HTTP / EOF | Seconds | Complete wire bytes |
| --- | --- | ---: | ---: |
| `/info` | 200 / complete | 0.043382041 | 10182 |
| `/version` | 200 / complete | 0.004287875 | 1132 |

Both preserve3-second/64KiB wire/8KiB header limits. The child naturally exits0
and is reaped in0.090972seconds without timeout, truncation or signal; capture
has86.402912seconds from the same remaining parent budget. Final marker time
is1.950375seconds **before its flush**; outer natural0 and empty stderr jointly
confirm this bounded identity. No exact full-process wall time is claimed.
The version projection matches the fixed expected Linux/arm64 metadata.

Actual `/info` Authorization is **null**, not missing, empty or nonempty.
Its policy meaning and exclusive management access remain unknown. Projection
flags for management exclusivity and independent endpoint authentication stay
false. Only whitelisted projection and counts/hashes are saved: raw HTTP is
not retained, so independent raw reparse and raw-response authentication are
not proved. Fixed socket/parent identity does not close the connect-time race,
and printable metadata is not a general secret detector for a malicious peer.

This closes the narrow real metadata-instrument observation only. It does not
qualify the proposed Linux executor or Darwin native route, prove management
exclusivity, prevent daemon-side exec injection, authenticate the endpoint,
prove executable/network isolation, or admit P2. Next independently select a
concrete trusted management-authority/injection-control evidence path; the
observed null cannot substitute for it. No daemon configuration, permission,
credential or shared runtime setting is changed. There is no Docker CLI,
container, host admission, native/P2, build, scan or SDK/archive recovery.

Product code and old locks remain unchanged. Prior unaffected49 component
coverage and the frozen original17 reader cases are reused by actual impact
and byte equality, without a new Go/race/vet/Contract claim. Original9 bindings,
64 barriers,402 old files,33 components, resource/time/cache/index/reuse gates
remain. Four progress documents follow normal reviewed commit/push; private
evidence stays outside Git. Timers remain off. Phase6 stays5/15; Slice6 step1
retains historical bounded E, step2 ongoing, step3's final live topology and
original16/independent acceptance incomplete, formal step4 not started.
