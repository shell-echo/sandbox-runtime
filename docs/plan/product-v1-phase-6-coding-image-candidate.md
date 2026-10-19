# Phase 6 Coding image candidate repair proposal

Date: 2026-10-10

Status: the user explicitly approved Go 1.26.9 for this new Coding candidate
on 2026-10-10. Repository-wide and other-candidate Go 1.26.8 pins remain
unchanged. Development tools now use mise and image builds use Docker, per
the user's environment preference. Candidate build evidence does not establish
production image admission, publication or formal Slice 6 acceptance.

## Trigger and preserved authority

The restored historical Coding publication remains exactly source
`cf1830e9bbfcd08d6f171e60f67d949d839e1069`, index
`sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1`.
New-host cryptographic provenance verification and the original arm64
descriptor/layer chain pass. A fresh Trivy 0.74.0 DB dated 2026-10-10 identifies
13 HIGH occurrences (12 distinct CVEs), zero CRITICAL, 12 MEDIUM, 13 LOW and
5 UNKNOWN. Two HIGH occurrences are Alpine OpenSSL packages; eleven are in
the Go 1.26.5 broker. These findings are package/version observations, not
proof that the broker exposes every vulnerable function.

The current template's identity checks do not consume a vulnerability verdict.
The old image therefore remains excluded from this turn's required positive
four-volume gate. No temporary CVE exception, signature-only acceptance or
historical pass can close that gate. The historical manifest, publication
constants, image, original receipts and old three-volume behavior remain
unchanged. See the [supply audit](../audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-image-supply-revalidation).

## Proposed smallest change

1. Introduce a separate local Coding candidate recipe, lock and inventory;
   keep `profiles/coding-shell/image` historical inputs intact. Its identity
   must never reuse the old published index, attestation or qualification.
2. Select clean broker source commit
   `91fe315641779e6ea640632538309d63ad1b303f`, tree
   `15070834772f766c46a62a61a7aaa8c5afd5411b`, through a new private `git archive`.
   Do not label the cumulative dirty implementation checkout as that source.
   Candidate recipe/lock bytes need their own hashes; if broker behavior must
   change, select and review a new clean source instead of mislabeling it.
3. Apply the user-approved exception **only for this new Coding candidate**
   to use Go **1.26.9** through `mise exec go@1.26.9 -- ...`. Keep the repository's and other candidates' Go 1.26.8 pins
   unchanged until separately addressed. The official darwin/arm64 archive
   `go1.26.9.darwin-arm64.tar.gz` is published with SHA-256
   `f9bb7c0a02506c5d9bf0d1eb1f7ee6c7684f844ae49558308a0427b830e022cc`;
   the downloaded input was verified before use. The mise-managed toolchain
   was subsequently compared byte-for-byte with that extraction; redundant
   hand-extracted Go directories were removed, with archives/records retained.
   No global activation, PATH or shell configuration change.
4. Resolve and freeze a repaired Alpine 3.23 base as exact index and
   amd64/arm64 manifests before pulling/building. The separate
   [candidate input lock](../../profiles/coding-shell/candidate/inputs.lock.json)
   now selects Alpine 3.23.6 and its exact descriptors. `libcrypto3` and `libssl3` must at least contain the
   upstream 3.5.8-r0 fix, but actual new-image scans remain decisive. Preserve
   the repack model without mutable `apk add`. If additional APKs are required,
   first lock their entire signed byte/dependency closure and install offline.
5. Preserve shell, broker protocol, UID/GID/slot, mount, resource and network
   boundaries. Build only affected Coding candidates, recording source,
   toolchain, recipe, dependency and output identities. Do not rebuild the
   unrelated role/Desktop set for this change.

Go's official records place the following affected standard-library versions
before 1.26.9: [GO-2026-6609](https://pkg.go.dev/vuln/GO-2026-6609),
[GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611), and
[GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607). Thus the original 1.26.8
candidate pin cannot be assumed to fix these new scanner findings. Alpine's
[v3.23 security database](https://secdb.alpinelinux.org/v3.23/main.json) records
the OpenSSL CVE-2026-14456 correction at 3.5.8-r0. Neither source supplies
application reachability analysis or a future clean-scan guarantee.

## Evidence and admission sequence

- Verify the chosen clean source, official toolchain bytes, immutable base
  descriptors and exact dependency inputs. Rebuild deterministically and
  inspect the actual broker metadata; retain failed attempts without replacing
  previous manifests or receipts.
- Generate a new SBOM, scan all OS and Go components with a recorded current
  scanner/database and explicit empty exception set, and evaluate all
  HIGH/CRITICAL findings. Fixing only the three new Go CVEs is insufficient.
  Do not claim amd64 from arm64 scans or cross-builds.
- Record a new bounded local candidate identity and source/build evidence.
  Independently review the candidate trust/admission protocol before connecting
  it to a new execution template, receipt protocol and complete Profile.
  A local hash or unsigned SBOM is not a published signature or operator seal.
  Registry publication/signing, if required by that reviewed path, remains a
  separate authorized step; this proposal does not publish anything or waive it.
- Run the new four-volume source-bound positive and failure scenarios with a
  fresh run ID, physical receipt-volume admission, real scratch/statfs/inode/
  noexec and UID/GID evidence. Then continue the existing atomic PG claim and
  asynchronous mTLS Control composition. A private fixture never opens
  `ProfileV2.Validate` or `provider serve v3`.

The new image changes runtime inputs: affected runtime evidence must be new.
Unchanged E-only/document work may reuse the existing frozen R under its
original rule; absence of old local R does not authorize C=R or broader reuse.
Any reuse-policy change needs separate independent review.

## Approved scope and remaining admission

The user explicitly approved candidate-only Go 1.26.9, repaired base, build and
verification. `mise install` manages explicit Go versions without activating a
global default: ordinary source work remains `mise exec go@1.26.8 -- ...`, and
only this candidate uses `mise exec go@1.26.9 -- ...`. Trivy is also mise-managed;
Docker builds have disabled build-step network and no mutable package installs.

Complete Profile and physical namespace admission still need their concrete
independent review and real gates. The held v3 identity/template/receipt
component reviewed below does not supply that authority. The existing
`CodingRuntimeTemplateV2` and `CodingExecutionTemplate` still bind the historical
published image and are not changed to accept this candidate. A diagnostic
smoke may prove bounded image behavior; it cannot stand in for the held four-volume
positive gate or published signature. Phase 6 remains 5/15, Slice 6 step 2 active.

## Reviewed held binding component, 2026-10-10

The concrete next component uses a separate `CodingCandidateExecutionTemplate`
with execution-template protocol v3 and held internal receipt protocol v3.
Independent design review permits this bounded identity/observation path; it
does not accept a runnable Profile or authorize a supply-chain exception.

`profiles/coding-shell/candidate` now embeds the original input/artifact locks,
recipe, sanitized historical evidence index and both platforms' original OCI
manifest/config bytes. Source-owned exact hashes freeze these records. The
identity explicitly binds clean broker commit/tree/archive, separate recipe,
candidate-only toolchain, base, selected output, broker and historical scan/SBOM
records. The recipe is not attributed to the clean broker tree. Metadata
availability does not prove layer availability; matching a historical scan hash
does not produce a current scan verdict or independent operator signature.

The new canonical template selects only these two local OCI manifests. Its
reference/store identity is the manifest digest; its selected-manifest field
is empty, as required by the existing manifest identity rules. Container
selected-descriptor comparisons use the actual manifest digest. Docker can
omit the image descriptor platform; the collector still requires matching
Docker OS/architecture, original config platform and container selected
descriptor platform, rejecting any conflicting optional platform. It retains
the existing resource split, four mounts, scratch/storage bounds, slot policy
and read-only Docker request boundary. Old runtime-v2 and execution-v2 templates
remain byte-compatible with their historical image and cannot decode v3.

The package-private common ledger now binds this new template and candidate
record into every v3 binding/resource/claim/observation digest. Reopening v1/v2
state fails; initialization requires a fresh empty physical namespace and never
rewrites an old receipt. There is no new public constructor for dispatch,
Profile override, auto-migration or released-state transition.

Complete Profile binding is deliberately still unresolved: its current typed
Coding field binds the old runtime template, and `controlstorage.Binding` checks
only the syntax of `ProfileDigest`. A made-up replacement digest, local slot
uniqueness, or passing component test cannot close that gap. The new complete
topology must freeze the candidate, revised resources and physical namespace,
and cross-check all principals and slot identities before adoption. Both public
admission holds stay closed.

Next establish that full Profile/physical namespace binding and the original
four-volume positive/failure scenarios with fresh run identities and independent
review. Actual kernel flags/capacity/inodes, noexec, UID/GID, workload resource
headroom, replacement and cleanup remain required. Follow with the planned PG
accepted-operation/claim and asynchronous mTLS Control path. See the
[binding audit](../audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-candidate-template-and-receipt-binding).


## Held complete-field candidate mode and kernel root, 2026-10-10

The next independently reviewed component adds `ProfileV2.CodingExecution`, an
explicit `sandbox-runtime.phase6-coding-execution-profile.v3` alternative. New
mode requires the historical `CodingTemplate` and `ResourceBudget` to be fully
zero; old mode omits the new field. No old template is converted, no v1 Profile
is stripped to manufacture v2 authority, and old canonical encoding is retained
when the optional field is absent. Both modes run the same complete v2 field
chain, with separate Coding slot and budget checks. Public `Validate`, decoding,
storage-binding derivation and `provider serve v3` remain closed.

The new mode binds the exact candidate template and Provider/Control platform,
full declared static and Browser/Desktop UID/GID inventory, all declared static
StorageIDs and eight Coding volume prefixes. Browser/Desktop dynamic volume
prefixes are not present in the current `SandboxIdentitySlot` schema, so this
cannot establish their final live inventory. The new capacity record counts
both resident and command limits, stopped preparation carriers, four volumes
per slot, scratch data plus metadata within the original slot ceilings, all
other declared roles/services and existing double-parse headroom. It explicitly
retains 512 MiB for Coding and 512 MiB unallocated/no-writer; no Browser/Desktop
receipt capacity is invented. Host/kernel/workload headroom remains unproved.

The Profile owns a fresh namespace/storage ID and fixed Control mount policy;
the derived storage Binding then carries the final Profile digest, template,
layout and actual declared Control principal/UID/GID, avoiding a hash cycle.
The pure derivation rechecks the complete field chain, including the final
Profile digest. Its public entry first requires full admission and remains
closed. An arbitrary digest string or a complete synthetic fixture grants no
Store or execution permit.

`InitializeKernelChecked` and `OpenKernelChecked` have no success callback.
They inspect the actual Store root fd on Linux using stat/statfs/statx and
bounded mountinfo: the exact private mount must be the filesystem root of a
persistent ext4/XFS filesystem, with high owner IDs, nosuid/nodev/noexec and
bounded observed data capacity. An ordinary shared local-volume subdirectory,
tmpfs/overlay, aliases, missing flags and unbounded filesystems reject. Live
pathname and pinned fd must agree on mount ID as well as device/inode. The
session mount ID is checked on operations; the separately retained stable root,
filesystem/source identity and geometry are checked on reopening. Legacy
manifests cannot be upgraded or used to strip kernel mode. Darwin refuses this
Linux-only path. Existing file-only APIs keep their bounded component semantics.

These are kernel/file checks, not physical namespace admission. Mountinfo sees
one namespace; a momentary statfs size does not prove a stable hard quota,
exclusive Docker ownership, absence of host writers or exclusion of resizing.
A closed source-bound Docker volume/Control mount/sole-consumer observer and a
reviewed persistent capacity backend remain blockers. The new high-UID Linux
fixture proves ordinary local-volume refusal with no marker and exact cleanup;
positive kernel facts and complete Profile fixtures remain synthetic. No
four-volume workload or PG/mTLS dispatch is enabled.


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
