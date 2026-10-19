# Vault private diagnostic build inputs

2026-10-13. Phase6 **5/15**, Slice6 step2. The user confirmed the
[reviewed proposal](product-v1-phase-6-vault-rebuild-proposal.md): only the new
private Vault diagnostic candidate may use Go1.26.9 and root x/net v0.60.0
through mise/Docker for input preparation, build and scanning. This grants no
publisher/builder authority, production identity, Vault execution, publication,
commit or push. Ordinary sandbox-runtime remains Go1.26.8.

Private evidence is `vault-rebuild-inputs-20261013`, outside Git and the
migration package. The active branch remains
`codex/product-v1-phase-6-hardening` at
`91fe315641779e6ea640632538309d63ad1b303f`, with inherited work preserved.
The separate main checkout is unchanged.

## Verified preparation

- The complete 9,090-file upstream current tree is copied from the retained
  verified archive. The original three-file patch is applied only to this
  uncommitted private copy. The pristine upstream checkout remains unchanged.
- Existing mise Go1.26.9 has 15,045 files byte-identical to its previously
  verified official Darwin archive. The separately pinned Linux arm64 compiler
  archive is also present and hash-verified. No global tool activation occurred.
- Actual root-module selection contains 992 modules including the root and five
  local replacements. Before/after comparison changes only x/net v0.59.0 to
  v0.60.0; the highest selected language floor is Go1.26.4. This graph result
  does not establish availability of every module archive.
- A read-only independent review accepted Node22.23.3 with the unchanged
  pnpm10.22.0 for this diagnostic preparation. The separate `ui/package.json`
  Node20-to-22 engine patch is recorded; dependencies and pnpm lock are unchanged.
  Official Node archive SHA-256 and pnpm's source-pinned SHA-512 match. Ember5.8
  is outside its LTS security support window, which remains an unresolved
  supply concern, not an accepted risk.
- The four commit-pinned Git package archives match every current-tree Git blob.
  This is content/source correspondence, not independent publisher approval.
- All 1,852 Linux arm64/glibc-compatible registry archives match their exact
  locked SHA-512, package name and version; four Git entries and 13 incompatible
  platform entries account for the complete 1,869-entry literal lock inventory.
  The successful retry took 469.424 seconds. This is archive availability,
  not a pnpm-parsed/frozen installed dependency graph or a successful UI build.
- Alpine3.23.6's raw index, selected native manifest, config, compressed layer,
  diff ID and actual Docker rootfs match. A fresh complete base scan reports
  zero HIGH/CRITICAL and one MEDIUM. This is base evidence, not a Vault scan or
  inherited Coding acceptance.

## Execution conditions retained

The root Linux CE generator inventory is exactly 15 `enumer` directives with
15 corresponding committed outputs. Nested modules and the `tools`-tagged
installer are excluded. The exact generator is
`github.com/stevendpclark/enumer@v0.0.0-20250122154818-a42b666c3cd3`.
Before execution, close its dependencies and run `go generate -n ./...` in the
isolated offline builder, requiring that exact command set. Limit the actual
write set to the reviewed 15 outputs; static inventory is not a generator pass.

The UI workspace's `verifyDepsBeforeRun: install` can make `pnpm run` or
`pnpm exec` install again. After a proven offline frozen install with scripts
disabled, use the direct locked webpack and Ember executables and the existing
metadata copy operation. Do not invoke the upstream UI helper unchanged.
All local Ember engines and the complete UI remain required.

The pinned vault-client-typescript Git archive lacks its declared `dist` files.
Review identified a bounded explicit compilation path for the retained TypeScript using
the UI-locked TypeScript5.6.3 and its two existing configs, in a private isolated
install tree. This compilation has not run. A failure requires a reviewed
follow-up; do not enable all lifecycle scripts, run OpenAPI generation or
silently substitute TypeScript5.9.3. Registry and Git broccoli-sri-hash packages
remain distinct identities. The stale node-sass rebuild command is not evidence
of a present dependency; retain actual absence proof and require the full UI
build instead.

The compatible registry inventory contains 171 lifecycle declarations. A
separate read-only review of the seven install/postinstall hooks found none
requires execution for this frozen UI path: two core-js hooks only print
messages; the three Carbon hooks and Scarf collect installation telemetry;
Parcel's hook builds from source only when explicitly configured. The locked
`@parcel/watcher-linux-arm64-glibc@2.5.6` archive contains a 469,976-byte
AArch64 ELF. Keep compatible optional dependencies enabled and install scripts disabled, and
later verify its actual Node22/glibc load in the final builder. This narrow
review does not authorize all 171 scripts or eliminate the explicit TypeScript
client build above.

Read-only tracing found no independently approved Vault numeric runtime UID/GID.
The fixture's `100:1000`, implicit upstream allocation, DNS identity policy and
Control/operator source-access declarations do not supply that approval.
Source/material work and a separately reviewed offline binary build can proceed
without it. Final runtime ownership/configuration must await the real input.

## Current boundary

Module archives and the pinned Docker builder are checked separately from the
completed UI archive checks. Network timeouts and the first overly narrow npm tar-root
parser are retained as failed attempts. A new parser accepts one canonical
top-level package manifest under an arbitrary single directory prefix, while
still requiring the exact locked SHA-512, package name and version. Verified
archives are reused; failures are never removed by regenerating a lock.
The fixed Node22.23.3-bookworm-slim index is
`sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392`,
with native manifest
`sha256:b20fe038d9592822dd534600a1ddf467e985178aa3fed60ec441a056c2cc45bd`.
Docker pulls failed or timed out, and raw-layer retrieval also failed with a
read timeout. Its incomplete bytes do not establish builder availability,
rootfs correspondence, a complete scan or permission to execute it.

The independently reviewed Go download recovery uses a new private download
module (`module-recovery-cwd`, distinct from the earlier empty download cwd)
with only relevant, conflict-checked sums from the fixed source and
previous successful checksum-DB downloads. Recomputed archive `h1` and go.mod
`h1` matched all 746 modules obtained before that recovery. Keep GOSUMDB enabled
for missing entries. Sums supplied by the source are source-pinned integrity,
not a claim of new per-module online checksum-DB verification. Neither source
module files nor cache trust markers are rewritten to suppress a failure.

The downloaded-receipt check recomputed and matched both hashes for **934
of 987** fixed requests (root graph external modules plus the explicit
generator). An additional cache reconciliation verified 29 interrupted-download
archives against the already frozen checksum authorities, producing **963/987**
verified materials. **24 remain unclosed**: nine lack archive/mod bytes and 15
have bytes but lack a complete frozen checksum authority. Those 15 are not
accepted merely because they exist in a cache. Both original and reconciliation
receipts are retained. The source-pinned transfer stopped at the
unchanged 600-second material-runner bound. Earlier timeouts are retained.
Range probes for the three missing Node layers returned exact HTTP206 ranges;
the following range-fetch attempt failed while obtaining the anonymous registry
token. This is still unavailable complete builder input, not a successful
resumable download. All these child commands have ended.

No upstream source, dependency lifecycle, generator, UI builder or Vault process
has executed. No candidate ELF/image, generated UI, candidate scan, signed
provenance or runtime result exists. Full input closure and an independently
reviewed execution recipe still precede the diagnostic build.

Slice6's formal ledger remains: step1 historical bounded Guest E; step2 ongoing;
step3 final live inventory/original16/independent acceptance incomplete; step4
not started. This private input checkpoint is not Slice6 acceptance or handoff.

## Follow-up material and builder result

The [subsequent checkpoint](product-v1-phase-6-vault-builder-admission.md) closes
the24 outstanding Go requests and three missing Node layers. It preserves this
checkpoint's963/987 and failed-transfer evidence. Full Node builder admission
now fails on4 CRITICAL/65 HIGH findings and unresolved signature/build-source
authority; material restoration does not authorize source execution.
