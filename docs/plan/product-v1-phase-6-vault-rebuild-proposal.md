# Vault isolated rebuild proposal

2026-10-13. Slice6 step2, Phase6 **5/15**. This is a decision package for a
new private Vault candidate, following the [failed official 2.1.2 candidate](product-v1-phase-6-vault-candidate-supply.md).
It does not select a replacement image, approve a signer, or permit Vault
service execution. The user subsequently confirmed the bounded compiler
exception below; the [input checkpoint](product-v1-phase-6-vault-build-inputs.md)
records its application. Historical proposal evidence remains unchanged.

## Proposed bounded decision

Permit **only the new Vault candidate** to use Go1.26.9 and root-module
`golang.org/x/net v0.60.0`, under mise or Docker, for isolated preparation,
build and scanning. Preserve the sandbox-runtime Go1.26.8 toolchain, old image
locks, frozen-R reuse rules and historical receipts. Do not execute this
candidate as a Vault service until its separate supply and consumption reviews
pass. No publishing, paid infrastructure, deployment or new trust root is part
of this decision. User confirmation has now been received for this compiler scope.

The [Go advisories](https://pkg.go.dev/vuln/GO-2026-6611) identify Go1.26.9 and
x/net v0.60.0 as the fixes for the shared HTTP/2 finding. The other two HIGH
standard-library findings are covered by [GO-2026-6609](https://pkg.go.dev/vuln/GO-2026-6609)
and [GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607). These versions are
proposed repair inputs, not a promise that a newly built image will pass a
fresh scan. All findings, including newly published ones, remain in scope.

## Exact source and proposed dependency delta

The official `v2.1.2` ref resolves to commit
`76fdd6587523c4c6cb079635075e019714d23470`, root tree
`6704d399e391f48f64ec66ac7ec2dcc6b03b6841`. The fixed source's root `.go-version`,
`go.mod`, `go.sum`, `Makefile` and `Dockerfile` were fetched and their Git blob
hashes independently compared with that root tree. GitHub reports a verified
commit; that API assertion is not independent approval of a publisher key or
proof of a resulting image. A separate shallow checkout now has the exact
commit/tree, a clean status and passing `git fsck --full --strict`. Its current
tree contains 9,090 files and no submodules; this is complete current-tree
source, not complete upstream history. The pristine 47,636,480-byte Git archive
has SHA-256 `fd648a579e2d717734742a256da4e62e58a6c53d976f646673d0d3d368ec68e3`.
No upstream source or build script has been executed.

The draft source delta is limited to:

| File in the separate Vault source | Proposed change |
| --- | --- |
| `.go-version` | 1.26.8 to 1.26.9 |
| root `go.mod` | x/net v0.59.0 to v0.60.0; retain `go 1.26.4` |
| root `go.sum` | Add the two independently checksum-verified v0.60.0 entries; retain old entries |

The retained three-file patch has SHA-256
`195da8c9559463c52659232575bf8dfe7834ccdb6cf503d0b5beb837ae6602fc`.
`git apply --check` passes against the clean checkout; the patch remains an
external proposal in the historical checkpoint. It has subsequently been
applied only to a new private diagnostic source copy. The pristine and proposed file
hashes are recorded in private `proposed-patch.json`.

The proposed module was downloaded with existing mise Go1.26.8, public Go
proxy and checksum-database verification, into a new private module cache.
Its archive checksum is `h1:79p50tfZlm0J9YfoDsSi639qSXNGVwEzOPLCxM2FsYU=`;
its go.mod checksum is `h1:2DA/G1UfVbCpQPeWTmMPGY7Cs2PkBkwu743bVX5PIVg=`.
Its reported source is `https://go.googlesource.com/net`, commit
`18ece0ce30bc35fa81fe72028bf309bb3ff3f4a5`.

[x/net's fixed go.mod](https://raw.githubusercontent.com/golang/net/v0.60.0/go.mod)
requires Go1.26.0 and crypto0.57.0/sys0.48.0/term0.46.0/text0.42.0. Vault's
root already requires those four versions and Go1.26.4. Therefore the direct
requirements do not force another upgrade; full minimal-version selection
and the complete module graph still require actual verification.

The root replaces five modules with local source: `api`, `sdk`, and
`api/auth/{approle,kubernetes,userpass}`. Some retain older x/net requirements.
The candidate is built and tested through the **root module graph**; the final
build-info/package manifest must show x/net v0.60.0 everywhere relevant.
Do not claim those nested modules are separately patched or publish them.
If a standalone nested-module test is needed, first define its explicit
candidate module graph; silently changing its language floor or testing an
old graph does not validate the candidate. Unexpected transitive changes
require a new reviewed delta, not unrestricted `go get -u` or blanket tidy.

A source patch and derived snapshot are new materials. Record base commit/tree,
patch SHA-256, all modified file hashes, complete post-patch tree/content digest
and source archive digest. Do not label patched bytes as the pristine upstream
commit or as clean committed release evidence. No commit is authorized here.
An immutable candidate requiring a clean committed derivative remains pending
that separate source-selection step; an uncommitted build is only diagnostic.

## Compiler, generated code and UI closure

The official Go download metadata gives these proposed compiler archives:

| Compiler material | SHA-256 |
| --- | --- |
| go1.26.9.darwin-arm64.tar.gz | `f9bb7c0a02506c5d9bf0d1eb1f7ee6c7684f844ae49558308a0427b830e022cc` |
| go1.26.9.linux-arm64.tar.gz | `4a97373d49fcacdcf3694fea368a500b00ee3e963974f3e7514132717632f052` |

Select exactly one controlled builder path per receipt. A mise invocation may
use the existing isolated Darwin installation after verifying its material;
a Docker builder must separately bind its own image, Linux compiler archive,
tool binaries and configuration. Native runtime qualification is Linux arm64;
a Darwin cross-build is not native runtime evidence. No global activation,
shell-profile edit or system package installation is needed.

The fixed upstream Makefile defaults to development targets that add
`testonly`; its preparation invokes generators, and it has hook-copy behavior.
Do not use those defaults on the host. The official CE build path uses
`CGO_ENABLED=0`; its CI helper runs `go generate` and then builds with supplied
tags and version linker metadata. Audit the complete generator/tool inventory
before execution. Generators and dependency-install scripts are code execution:
run them only in the controlled Docker build environment, with bounded output,
no host credentials or Docker socket, and record their output hashes. The
current-tree inventory finds 27 generator directives across 26 Go files,
including local nested modules; that is an inventory, not an approved execution
list. Resolve the actual selected packages/tags, every generator binary and
its dependencies, permitted arguments, outputs and writable paths first.

Retain the full CE feature set and UI assets. Do not use `minimal`, `testonly`,
enterprise/HSM tags, substitute plugins or omit UI to obtain a smaller or green
image. The fixed UI package declares Node20 and pnpm10.22.0 with a package-manager
integrity string; its pnpm lock is retained as a source material. That declaration
does not establish an acceptable current UI toolchain. Exact Node/pnpm artifacts,
their security/support assessment, dependency integrity and built assets must
be closed first. A necessary Node/lock change is an additional reviewed delta.
No UI tool has been installed or invoked by this proposal.

The following conditions fail preparation or qualification:

- UI omitted: `scripts/ci-helper.sh build` defaults to empty `GO_TAGS`; only
  Makefile `bin` supplies `ui`. Set an explicit CE tag set containing `ui`, and
  prove package selection includes `http/assets.go` and excludes
  `http/assets_stub.go`. The former embeds `web_ui/*`; retain a complete hashed
  generated-asset manifest and verify the actual Go embed file list against it,
  including required entry/assets. Missing or extra/unbound assets fail. A tag
  alone does not prove UI delivery. After supply admission, verify the built
  binary actually serves the bound UI; no service execution is authorized now.
- Stale source identity: the CI helper derives `version.GitCommit` from
  `git rev-parse HEAD` and sets `-buildvcs=false`. An uncommitted patch would
  therefore keep the pristine upstream revision. A reviewed candidate wrapper
  must explicitly bind `GitCommit` to a named local-candidate content digest,
  covering the complete patched/generated build source, and preserve upstream
  commit/tree and patch separately. The field must carry a clearly labelled
  value such as `upstream.<full-git-sha>.localcandidate.sha256.<content-digest>`;
  do not describe a content SHA-256 as a Git commit. Preserve base version
  `2.1.2`, add a distinct
  local-candidate metadata suffix, and retain linker/build metadata. Compare
  actual ELF Go build-info/linker settings with the build record; after supply
  admission also compare the binary's reported version/revision. An upstream-only
  revision, missing derived identity or mismatch rejects the candidate; an
  external manifest cannot compensate for a falsely pristine embedded identity.
- Unbounded generators or package scripts: the UI helper runs bare `pnpm
  install`, `npm rebuild node-sass` and `pnpm run build`. Do not execute it
  unchanged. Resolve and verify exact Node/pnpm/package archives and native
  build/download inputs, use a frozen lock and offline dependency store, and
  disable install scripts until each required lifecycle script has an explicit
  reviewed execution list. Run approved generator/UI commands without network
  in the bounded Docker environment. Undeclared scripts, a requested download,
  lock mutation or an output outside the declared set fails that stage. Do not
  silently omit a required script or generator to make it pass.

Verify generated-source and UI manifests, compile through the frozen root graph with
`GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`, `-mod=readonly`, and disable network
after the complete checked materials are staged. Keep all caches private to the
candidate. A missing locked input stops that stage.

## Runtime image and reproducible materials

Build a new image, not a retag of the failed official archive. A candidate
runtime base must bind its real index, native platform manifest, config,
compressed layers and diff IDs. The already recorded Alpine3.23.6 descriptor
from the Coding investigation is a possible **input to evaluate**, not an
approved Vault base and not inherited Coding acceptance. Resolve the exact
selected base before build; no mutable `alpine:3` or future tag refresh.

The upstream Dockerfile uses mutable APK operations and allocates a user/group
implicitly. Replace those mechanisms in the candidate recipe with explicit
approved material inputs: all required APK packages and transitive dependencies,
versions, repository-signing keys, archive hashes and install order, plus exact
numeric UID/GID from the private approved deployment input. No online APK update
or install remains in the frozen build. Preserve and verify the required
dumb-init/su-exec/tzdata/certificate material, entrypoint bytes and behavior,
Vault binary path, signals, volumes, configuration permissions and non-root
execution. The existing two-issuer fixture's numeric owner is not a production
owner authorization. Changes to any of these behaviors require affected tests.

Record recipe/context hashes, compiler and dependency locks, build parameters,
builder identity, all generated outputs and output OCI descriptors. Produce a
re-importable original-byte archive and SBOM. Repeat one build from those exact
inputs to compare output bytes; report any difference rather than promising
historical tar/binary equality. The new image identity cannot inherit an old
manifest, operator receipt, Guest binding or frozen-R qualification.

## Supply authority and consumption boundaries

`internal/phase6profilebuilder/external_images.go` and the phase6security OCI
readers provide reusable descriptor/layer checks. They do not verify image
publisher identity, controlled builder provenance or vulnerability policy.
`internal/artifactverify` verifies local files under a caller-provided key;
`phase6rolecandidate` declares non-release repository-owned roles. Neither
approves a third-party Vault publisher. Control observation pins and operator
keys also have a different purpose and must not be reused as image authority.

Before supply acceptance, an independently approved trust declaration must
identify the image publisher public-key fingerprint or certificate issuer and
exact subject, builder identity and authority, permitted source/recipe/materials,
proof format, and revocation/validity policy. Do not generate a new key and treat
it as approved merely because a signature verifies. Do not claim HashiCorp
authorship for a locally patched image. Secrets stay outside build contexts.

Verify actual signatures and build statements against the final OCI subjects,
and bind index to the selected platform manifest, config and layers. A signed
statement must cover the patched source, compiler, UI/generator inputs, APK/base,
recipe and actual outputs. An unsigned locally written provenance JSON is an
audit draft only. Publisher/builder identities and proof delivery are still
unresolved; this proposal grants none. No CI dispatch, upload or publication is
authorized, including use of an existing workflow under a different identity.

After supply acceptance, add a narrowly scoped candidate-specific loader/test
path under independent review. Keep `slice6VaultImage`, shared integration
constants, Slice5 manifests and evidence verifiers unchanged. Do not accept an
arbitrary environment-supplied digest or relabel a local artifact as a registry
publication. The candidate loader must reopen approved archive/proof/scan bytes,
reject missing/extra/wrong source and platform identities, and recheck actual
Docker config/rootfs and ownership before every use. No Profile/provider v3
hold is opened by this work. Whether a local third-party candidate may enter a
later bounded gate remains an explicit boundary decision, not automatic use of
ADR0055's repository-owned-role allowance. Slice7 still owns publication gates.

## Validation order and acceptance evidence

1. Before build: verify a clean upstream source, the exact patch, full dependency
   graph and sums, generated-code/UI inputs, base/APKs, private ownership inputs,
   and isolated builder. Missing or inconsistent material rejects preparation.
2. After an authorized diagnostic build: verify raw OCI chain/diff IDs and actual
   binary build metadata; scan the **complete new image** with a fresh database,
   explicit empty ignore configuration and all severities retained. Any HIGH or
   CRITICAL fails. Test wrong archive/platform/config/source and changed inputs.
   Neither scanner exit0 nor fewer findings is supply acceptance.
3. Before consumption: independently verify the publisher/builder proofs and
   review the exact new loader and compatibility delta. No Vault process starts
   before this boundary. Existing sandbox-runtime Go changes require its full
   race/shuffle/count1, vet, applicable Docker and Contract gates at unchanged
   limits; unrelated already-passing source evidence is not rerun for reporting.
4. Then run fresh broker/general issuer, exact role/source/DER, CRL readiness,
   revoke/cross-issuer isolation, mutable-default drift, wrong-role/issuer,
   publication/CRL denial and sealed-backend scenarios. Verify injected state and
   exact failure stage, then bind Controller/agent/Provider/Control/Scanner.
   PostgreSQL remains on general. Prove exact container/volume/network cleanup.

## Review result and current evidence

Read-only independent `implementation_agent` review accepted this as a bounded
**decision package**, after the UI, derived-source identity and generator/UI
script conditions above were made explicit. It did not approve a build input,
publisher, trust root, candidate image or runtime gate. Source checkout and
patch applicability are actual passing checks; full module resolution, build,
fresh candidate scan and Vault execution have not happened. Failed source
fetch attempts remain in the private evidence alongside the successful fetch.

Private `vault-rebuild-proposal-20261013` contains the clean-source receipt,
original archive, source/blob comparisons, proposed patch and file hashes,
checksum-verified x/net material, compiler/advisory metadata, build-source
inventory and independent-review record. Its `proposed-inputs.json` leaves
unresolved inputs and all candidate outputs explicitly empty. The next decision
was the narrowly scoped Vault compiler exception at the top of this document;
the earlier permission was explicitly Coding-only. That new exception is now
confirmed. Close the listed build inputs before executing an isolated
diagnostic build; see the subsequent input checkpoint for actual results.

This list is the candidate work sequence, not Slice6's formal four-step ledger.
Slice6 step1 retains historical bounded Guest E; step2 is ongoing; step3 final
live inventory/original16/independent acceptance is incomplete; step4 has not
started. This proposal and its private `vault-rebuild-proposal-20261013` evidence
do not change Phase6's **5/15** result. No runtime repair or candidate pass is
claimed until its named evidence actually exists.
