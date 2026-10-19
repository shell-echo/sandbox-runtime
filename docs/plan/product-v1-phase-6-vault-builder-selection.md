# Vault builder selection and offline recipe checkpoint

2026-10-13. Phase6 remains **5/15**, Slice6 step2. This continues the
[rejected builder checkpoint](product-v1-phase-6-vault-builder-admission.md).
Private materials and original logs stay outside Git in
`vault-builder-candidate-20261013`. Root is the sole writer; read-only
implementation_agent reviews cover the authority model, observation changes,
package transport and failure boundaries. Their reviews are not operator signatures.

## Selected private builder carrier

| Identity | Fixed value |
| --- | --- |
| Repository | cgr.dev/chainguard/node |
| Original index | sha256:df7376d245b4a242d38e9289d265e6124a21217dea665001a0058960367fae46 |
| Native linux/arm64 manifest | sha256:0754d2c98d57b04fbf67be92bb4d5bcfa62bd4cb26f51063f177ba0cf24e78af |
| Config | sha256:224026b08e684601954160bc27b12c01096fcd9244c333a19ae28af531483e76 |

All11 compressed layers and diffIDs match. Eight actual Cosign verifications
pass: index/native image signatures plus SLSA, apko and SPDX attestations,
using the exact GitHub Actions issuer and publisher workflow identity.
The independently accepted source model is authenticated declarative apko
assembly with75 fixed APK packages. Those packages match signed SLSA, signed
apko, signed SPDX, the actual layered APK database and the complete current
Trivy scan. The latter reports zero findings. No recipe Git commit or recursive
source rebuild of all OS packages is claimed; the certificate's workflow SHA
is signing context. This private builder authority does not approve a Vault
artifact, production signer or historical lock change.

The distroless alternative has verified image signatures and zero HIGH/CRITICAL,
but complete-image build-source admission remains unresolved. It was not run.
The previous Debian Node builder remains rejected with4 CRITICAL/65 HIGH.
Neither rejection is rewritten by this new selection.

Docker29.8.2/containerd identifies this imported image by native manifest ID;
its descriptor/config/diffIDs are checked separately. The full unstarted export
completed in46.922 seconds. Its strict pristine-image comparison failed because
Docker's init layer replaces2 entries and adds5. A separate17.646-second offline
reconciliation pins the actual Engine commit, five official source files, raw
OCI chain and saved847,430,656-byte tar. All10 init rules match; the other8030
entries match in recorded fields/file bytes, including device metadata and
absence of PAX attributes. Timestamps are not claimed. The original strict
failure and earlier120-second export timeout remain failures. See
[Moby's fixed init implementation](https://github.com/moby/moby/blob/8af9fe3a36bab3e039862a2ab1cef1880c9b4d03/daemon/initlayer/setup_unix.go).

## Tools, generator materials and offline installation

Only the exact official Node22.23.3 ELF is selected, mounted read-only over the
carrier's Node26 path and at an absolute tool path. pnpm10.34.7 has verified
registry ECDSA and tag-specific SLSA authority; all1072 extracted files match.
Its recognized98-package rootfs scan has zero findings. The earlier filesystem
scan recognizing zero packages is not acceptance. Old pnpm10.22.0 has current
HIGH advisories and is not selected. The private packageManager-only10.34.7
proposal was reviewed, but the historical9090-file Vault snapshots remain unchanged.
No automatic Corepack/package-manager switching or global installation is used.

The fixed enumer source and all9 standalone dependency archive/go.mod h1 values
now match the selected graph. Eight newly verified checksum lines are recorded
only in a new private enumer go.sum; source/go.mod versions are unchanged.
Actual offline module verification passes. This closes dependency materials,
not generator vulnerability admission or execution.

The private `offline-build-recipe.md` records the two-stage frozen/offline
transport/store design. Registry entries preserve original IDs/SRI and use
relative digest-named tarballs with a private file: registry. Git entries retain
original keys/importers/snapshots/peer suffixes but use separately verified
file: tarballs. Their packlists must follow the actual pinned pnpm GitFetcher
branch and retain original Git bytes/modes/package.json; publish-manifest
rewriting and blanket prepare hooks are prohibited. Four Git inputs remain
commit-bound, and13 incompatible platform entries remain in the original lock.
The compatible arm64/glibc Parcel input is retained. A store mechanism test does
not prove a full frozen UI graph, Git repacker, TypeScript client or Ember build.

## Actual bounded Docker probes

The final environment probe passes in6.950 seconds: Linux arm64, Node22.23.3,
pnpm10.34.7, diagnostic501:20, read-only mounts/root, no effective or bounding
capabilities, no privilege gain, actual2-CPU/1GiB/128-PID limits and bounded
byte/inode tmpfs all match. The initial network observer rejected the kernel's
nine default tunnel devices; a second attempt exposed the separate empty
bonding_masters sysfs control file. Both failures remain. Independently reviewed
new observation requires the exact interface/control sets, all non-loopback
interfaces down without addresses or external routes, zero before/after traffic,
and Docker's empty none-network endpoints. Only loopback and IPv6 reject routes
are accepted; no active outbound connection was attempted.

The final single-package offline probe passes in8.398 seconds. Both frozen-lock
installs preserve their original mini-lock bytes and match all1051 lodash4.18.1
file bytes; the second reports reused1/downloaded0. The first uses only the
bound local file transport (pnpm's generic counter calls this downloaded1),
with actual network counters remaining zero. The original SRI/pkgID selects
one exact v10 CAFS index; all1051 indexed file sizes/SHA512 values match.
The only store symlinks are pnpm's two source-defined project registrations,
with exact hashed names and relative targets inside this run. Two earlier
whole-store-no-symlink failures remain; the final observer does not skip
unexpected links or relax input integrity. The archive stays mounted read-only
in both stages, so this proves a store hit, not material withdrawal or full UI.
No dependency lifecycle script, generator, UI compiler or Vault code ran.
Every probe container was precisely removed. The final private image cleanup
uses the full manifest identity, its sole owned tag and no consumers, without
force; the final checkpoint records absence and the unchanged unrelated services.

## Dependency execution remains rejected

The first direct scans recognize5 generator modules and1144 UI lock packages;
they report2 HIGH and30 HIGH/2 CRITICAL respectively. Those counts do not cover
all versions in the restored materials. A new, locally derived scan inventory
rechecks all1852 registry archives against original size/SHA/SRI and actual
package.json identity, and binds the9 generator dependencies to the frozen
graph. Trivy's recognized name/version sets exactly match those inventories.
They are local scan inputs, not upstream signed SBOMs.

| Complete inventory scan | HIGH | CRITICAL | Other |
| --- | --- | --- | --- |
| Nine enumer dependencies | 8 | 0 | 9 MEDIUM,3 UNKNOWN |
| 1852 compatible registry packages | 51 | 4 | 22 MEDIUM,9 LOW |

All scans use the pinned Trivy0.74.0 and unchanged official DB updated
2026-10-13T01:09:18Z before expiry, without severity/unfixed suppression.
Report generation succeeds; the separate dependency-admission command correctly
exits1. The4 Git inputs have separate source identities and are not covered by
these registry/module vulnerability scans. Generator findings include x/mod0.22
and x/net0.34; the UI inventory includes a braces3.0.3 HIGH with no fixed version
in this DB. No waiver or unreachable-code claim is applied.

Consequently, no generator execution, full UI installation/compilation or new
Vault binary/image is admitted. Next independently review scoped repair inputs
and unresolved advisories, preserving the old locks; then recheck full coverage
and the actual offline graph before executing affected tools. Unsupported
Ember5.8, complete build write limits, production UID/GID, final candidate
supply/consumption and clean-source release identity remain open.

## Validation and fixed Slice6 ledger

This checkpoint changes repository documentation and private evidence only.
Ordinary repository Go1.26.8, accepted release/Contract locks, frozen-R reuse,
broker/general issuer topology and ProfileV2/provider serve v3 holds stay fixed.
The matching2148 Go files retain the earlier503.355-second full-race, vet and
two Contract-lock evidence; these are not new executions. No staging, commit,
push, publication, production process or automation resumption is authorized.

1. Historical bounded Guest E: retained, not replayed.
2. Startup audit/real security boundary: ongoing. Builder supply and generator
   material closure advanced; dependency vulnerability gates still reject builds.
3. Final live inventory, original16 scenarios and independent acceptance: incomplete.
4. Post-acceptance documentation/commit/push handoff: not started.

The later [generator remediation checkpoint](product-v1-phase-6-vault-dependency-remediation.md)
retains these historical failures and derives new private enumer module inputs.
Its reviewed generator-only tests/build and actual ELF scan pass; the new
full module inventory still records one non-imported OpenPGP UNKNOWN. Complete
UI installation/build remains blocked. This does not retroactively approve
the old dependency graph, source lock, scan or full-build recipe above.
