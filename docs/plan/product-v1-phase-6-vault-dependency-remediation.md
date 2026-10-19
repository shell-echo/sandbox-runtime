# Phase6 Vault generator dependency remediation

Date: 2026-10-13. This follows the [builder and offline recipe checkpoint](product-v1-phase-6-vault-builder-selection.md).
Private evidence is `vault-dependency-remediation-20261013`, outside Git and
the migration package. The active branch remains
`codex/product-v1-phase-6-hardening` at
`91fe315641779e6ea640632538309d63ad1b303f`, with inherited modifications preserved.
This advances Slice6 step2; Phase6 remains **5/15**.

## New generator inputs

The original enumer pseudo-version
`v0.0.0-20250122154818-a42b666c3cd3` remains the source origin. A separate
24-file candidate changes only `go.mod` and `go.sum`; implementation and
original tests are unchanged. Its private Go floor is1.26.0 and compiler is
the previously authorized Vault-only Go1.26.9. Ordinary repository Go1.26.8
and all historical source, release locks, manifests and receipts stay fixed.

Explicit x/mod0.40 and x/net0.60 repair seeds produce an actual12-module
selection, including x/tools0.49, x/sync0.22, x/crypto0.57, x/sys0.48,
x/term0.46, x/text0.42 and telemetry at
`v0.0.0-20260811182544-a038080d80e5`. The first independent estimate of
x/mod0.41/x/sync0.23 was corrected against the actual pruned Go module graph;
it is not an executed result. No blanket dependency upgrade or tidy was used.
All12 ZIP/go.mod pairs match their authenticated sums and independently
recomputed h1 values. Actual offline `go mod verify` passes, and only the two
declared candidate files differ. Material closure took46.409seconds.

The complete, locally derived inventory scan recognizes exactly12 modules:
**0 HIGH,0 CRITICAL,1 UNKNOWN**, compared with the old graph's8 HIGH.
The UNKNOWN is [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), which
affects the seven unmaintained `x/crypto/openpgp` packages. It remains in the
raw inventory report. An actual Linux/arm64 CGO0 metadata traversal covers184
generator/test packages and imports none of them or any other x/crypto package.
Independent source review also checks the TestEndToEnd subprocess inputs:
13 testdata programs, with the existing CGO case skipped under CGO0, use
standard-library imports. This supports only the named generator build/test
scope; it does not make the complete x/crypto inventory finding-free or grant
Vault/UI execution.

The official Linux arm64 Go1.26.9 archive matches SHA256
`4a97373d49fcacdcf3694fea368a500b00ee3e963974f3e7514132717632f052` from
[Go release metadata](https://go.dev/dl/). Its15045 original files are retained
as private inputs. A full extracted-root scan recognizes all10 actual Go tool
executables as stdlib1.26.9, with no findings. Historical ELF/syso test fixtures
inside the Go source tree are not additional tools selected for execution.
The scanner and fresh DB are unchanged from the preceding checkpoint; reports
contain no severity or unfixed suppression.

## Reviewed execution boundary

The prior admitted Chainguard manifest and Node22 observer are reused with
read-only compiler, module and source inputs. Docker uses `none` networking,
read-only root, UID501:GID20, no capabilities, no-new-privileges, private
namespaces,2 CPUs,2GiB memory,128 PIDs and fixed file-descriptor/core limits.
Writable storage is only bounded tmpfs: `/work`1GiB/65536inodes and `/tmp`
64MiB/32768inodes are noexec; `/exec`512MiB/32768inodes permits the generated
test programs. Network, mount, capability and cgroup observations precede Go
execution. The controller450-second deadline and outer600-second limit remain.

Independent review caught omitted empty directories/special files and an
unlocked source-hash comparison file before execution. The revised lock records
all directory paths/modes and regular-file identities, rejects other types,
includes the comparison file and is itself pinned. Negative checks reject
an added empty directory, symlink and FIFO. An external wrapper binds the
reviewed controller before and after execution. JSON output is capped before
emission while retaining the existing16MiB Docker transport limit.

The first real run fails in102.398seconds, including37.294seconds for the Go
test command. Original `stringer.go` creates its temporary output in the current
directory, then renames it to the requested target. The fixture initially put
these on `/work` and `/exec`, causing EXDEV in TestEndToEnd. The failure and
exact container/image cleanup are retained. Independent review approves moving
only the source copy and Go cwd to `/exec/source`, alongside `/exec/tmp`.
That source copy is now on the existing executable mount; copied files must
remain0644 and directories0700. No new executable mount, source patch, test
omission, quota increase or timeout extension is used.

The final v3 run passes in45.290seconds. Original TestGolden, TestSplitIntoRuns
and TestEndToEnd all pass; the test command takes15.455seconds and the final
build6.637seconds. All12 non-CGO testdata programs are actually generated,
compiled and run; the existing `cgo.go` skip is observed. The earlier review's
14-input estimate is corrected to the actual13-file set, without editing the
old lock/receipt wording or removing any test.

The new Linux arm64 ELF is7306974bytes, SHA256
`13952c5207471be30579af8534b1a9dea4486f9ab3d4bede19936dcf8b17906e`.
Its actual build metadata binds Go1.26.9, CGO0, name1.0.1, x/mod0.40,
x/sync0.22 and x/tools0.49. This is a new derived artifact, not the historical
enumer binary. The accepted output scan recognizes the derived main module,
all four embedded dependencies and stdlib1.26.9, with no findings. An earlier
scan of the0444 data file recognized no packages and is not accepted as clean.
A scan-only0555 copy of exactly the same bytes provides the required coverage;
neither copy was executed on the host. Input identities,
controller hash and before/after network observations remain consistent;
exact owned-container and sole-reference image removal pass. The ELF is
stored as0444 private data and was not executed on the host. No Vault generator
directive, UI build, Vault ELF/image or Vault service was produced or run.

## UI repair proposal remains blocked

Exact npm metadata is retained for20 proposed fixed package versions and
compared with original package manifests. This is a proposal only: new archives,
their signatures, a resolved new lock and full graph have not been accepted.
Four targets also change dependency declarations, so replacing20 version labels
would not prove closure. The original1852-package report still has51 HIGH and
4 CRITICAL; no original UI source/lock or lifecycle script was changed/executed.

The [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
still marks3.0.3 affected with no patched version. Official registry metadata
still selects3.0.3; [upstream PR72](https://github.com/micromatch/braces/pull/72)
is closed and unmerged. Maintainer disagreement does not withdraw the advisory
or waive the zero-HIGH gate. Separately,
[Ember's support table](https://emberjs.com/releases/lts/) ends security support
for `ember-source`5.8 on2025-06-16. A supported major-version migration needs
plugin, API, build and test compatibility review, and does not automatically
remove braces. That EOL date is not asserted for ember-cli independently.

Next validate the fixed15 Vault generator commands and their outputs against
the new exact generator artifact under a separately reviewed source/input and
write-budget recipe. The complete UI requires a supported, repaired dependency
graph or a separately reviewed source-remediation candidate before offline
installation/build. No HIGH exception, unpublished patch-as-release claim,
partial UI or headless Vault substitution is authorized by this checkpoint.

## Validation and Slice6 ledger

Repository changes are documentation only. Exact source matching permits reuse
of the prior2148-Go-file503.355-second race, vet and both Contract-lock results;
they are not new executions. The new private generator checks are separate
component evidence. Production UID/GID, clean release identity, full Vault ELF
and image supply/consumption, broker/general real issuance and command
composition remain open. Public ProfileV2/provider serve v3 holds, the two
issuers and frozen-R rules remain unchanged. No Git staging, commit, push,
publication, production process or automation restoration occurred.

1. Bounded Guest E: historical acceptance retained, not replayed.
2. Startup audit and real security boundary: ongoing; generator dependency
   remediation is bounded component work, and complete UI execution is blocked.
3. Final live topology, original16 scenarios and independent formal acceptance:
   incomplete.
4. Post-acceptance documentation/commit/push handoff: not started.

Follow-up: the [source-generation checkpoint](product-v1-phase-6-vault-generator-output.md)
records the fixed15 CE directive scope, offline graph repair and actual bounded
execution outcomes separately from this generator ELF's original tests/build.
