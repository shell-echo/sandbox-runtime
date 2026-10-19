# Full race budget diagnosis and local planning correction

2026-10-13. This is Slice6 step2 verification work. Phase6 remains **5/15**;
it does not qualify the final topology or open production admission.

## Evidence behind the change

The preceding full command, `go test -race -shuffle=on -count=1 -p=6 -json
./...`, reached the unchanged 600-second wrapper limit and exited124 after
600.297 seconds. The phase6security package had not ended. The last reported
PostgreSQL peer-source test was unfinished, but that does not identify it as
the cause. Across 146 completed phase6security top-level tests shared with
the earlier 510.429-second passing run, summed reported durations increased
from 402.99 to 535.94 seconds. The increase was distributed. A final test name
and the absence of an emitted FAIL event are not deadlock diagnostics.

Current read-only host observations found ten logical CPUs, 16GiB memory and
substantial compressed memory. Load averages and swap-in deltas varied during
the diagnostic period. Those are possible contributors to runtime variability;
they do not establish the cause of the previous timeout. No unrelated process
was stopped, host setting changed or GOMAXPROCS override added.

After independent review, one focused race-enabled CPU/allocation profile used
`TestCompiledPeerCRLAuthorizerMatchesClosedSources`. The original test and all
its full Profile/source validation and legacy comparison calls were retained.
The profile identified repeated desired-network construction inside
`Slice6DesiredFinalSharedPostgresHBARules`: every one of nine SQL rules rebuilt
the same transport and service-bridge plans. In that sample the HBA function
accounted for 1.30 seconds of 15.06 seconds sampled CPU; it was a concrete
avoidable cost, not the entire runtime.

## Reviewed equivalent implementation

Each HBA call now creates fresh targets, transports and bridges once. It still
runs the original target/graph verifiers, matches each owner uniquely, checks
the actual dialer, parses the IPv4 address and emits the same nine /32 rules.
A private endpoint projection uses those local bridges. The public endpoint
function still builds its own fresh repository-owned desired graph on every
call. There is no global cache, cross-call reuse, cached authorization result
or caller-supplied graph admission.

Characterization captured the original HBA bytes before the change. Added
tests passed against the old implementation first, then the new one: all nine
HBA rows including broker-owned dialers, both endpoint addresses on each of
30 dedicated bridges, unknown/member rejection and caller mutation isolation.
The existing graph and HBA tests remain intact. The current-turn delta touches
two existing Go files and adds one test file; older dirty-worktree changes
remain separate. In-memory reversal of only the two local edits reproduces
both starting file hashes, without reverting the repository.

## Focused observations

| Same focused race test | Before | After |
| --- | --- | --- |
| Wrapper elapsed seconds | 22.837 | 14.364 |
| Sampled CPU seconds | 15.06 | 8.15 |
| Profile alloc_space, MB | 1842.80 | 1480.99 |
| Final service-bridge cumulative alloc_space, MB | 379.62 | 95.53 |

Both commands exited0. Allocation profiles are sampled and these are single
runs, not a controlled performance benchmark or an SLA. The cost reduction is
consistent with the removed repeated construction; elapsed-time changes also
include host variability. Full Profile validation and JSON/regexp/network
costs remain. The focused result alone does not establish that the complete
suite fits within 600 seconds.

## Validation and evidence boundary

The final full run **passed in 503.355 seconds**, exit0, with all 267 packages
ending: 229 passed and 38 had no tests. It recorded 8,785 test/subtest starts,
8,765 passes and 20 skips, with no unfinished test or FAIL event. The
phase6security package passed in 448.941 seconds. All 2,148 Go files match the
pre-run snapshot. Full `go vet ./...` passed in 5.370 seconds; both Provider
and Product Contract lock verifiers passed. Skipped real gates are not actual
service evidence. Independent review accepted the local code and focused
evidence; final evidence review is recorded in the private checkpoint.

The final full run used the original 600-second wrapper and existing `-p=6`
package bound, race detection, shuffle and count1. No test timeout is extended,
assertion removed, validation bypassed or workload split to fabricate an
aggregate pass. The pre-run Go file set is frozen separately from the Git
HEAD; final results must match that set. Development uses mise Go1.26.8 with
the existing isolated caches. No dependency or repository toolchain lock is
changed. This pure desired-plan change does not alter a Docker driver or
lifecycle; no new real Docker/production gate is implied by ordinary tests.
This closes the missing local full-race result for this source combination,
not the separate Vault supply blocker or a guarantee about CI/default
concurrency. The previous 600.297-second timeout remains a failed result.

Raw before/after profiles, commands, characterization, scope proofs and the
final run are retained privately in `race-vault-remediation-20261013`, outside
Git and the migration package. Previous failed runs remain untouched. The
[Vault supply proposal](product-v1-phase-6-vault-supply-remediation.md) records
the separate blocker before any new two-issuer service execution. No staged
change, commit, push, merge, release or Slice6 step4 handoff is part of this work.
