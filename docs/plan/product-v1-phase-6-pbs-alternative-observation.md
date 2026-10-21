# PBS alternative observation feasibility

Date: 2026-10-21. Status: independently reviewed design candidate only;
**no replacement executor or real P2 is admitted**. This continues the
[process/cwd observation plan](product-v1-phase-6-pbs-process-observation.md).
Phase6 remains **5/15**, Slice6 step2 ongoing. This is not formal step4.

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
