# Phase 6 local Coding candidate

This is a separate, unsigned, non-release candidate. It does not replace or
inherit `../image` and is not admitted by the existing Coding templates,
Provider startup, full Profile-v2 gate or historical publication.

`inputs.lock.json` selects clean broker source, its archive and module hashes,
the candidate-only Go 1.26.9 toolchain, exact Alpine 3.23.6 index/platform/config/
layer inputs, and this Dockerfile. Both platforms contain OpenSSL 3.5.8-r0.
The recipe repacks the selected base without `apk add`; build steps use
`--network=none`, `SOURCE_DATE_EPOCH=0`, no generated SBOM/attestation and no push.
Labels explicitly identify the result as a local candidate. The historical
profile label describes behavior; it does not grant admission.

Use mise-managed tools, without changing global activation or shell config:

```sh
mise install go@1.26.9 trivy@0.74.0
mise exec go@1.26.9 -- go version
```

Only this candidate uses Go 1.26.9. Ordinary repository work retains
`mise exec go@1.26.8 -- ...`. Do not run the historical image build script or
its integration test against this candidate; they select different inputs.

To reproduce, start a new private evidence directory outside the migration
package and Git checkout. Export the locked commit with `git archive`, verify
its exact tree/archive/module hashes, and verify the cached modules before an
offline build. Use a fresh build cache and explicit `GOENV=off`,
`GOTOOLCHAIN=local`, `GOWORK=off`, `GOPROXY=off`, `GOSUMDB=off`,
`GOFLAGS=-mod=readonly`, `CGO_ENABLED=0`, `GOOS=linux` and selected `GOARCH`.
The broker command under `mise exec go@1.26.9 --` is:

```sh
go build -trimpath -buildvcs=false -ldflags=-buildid= \
  -o "$build_context/terminal-broker" ./cmd/terminal-broker
```

Normalize the binary mode to 0555 and mtime to zero, copy this exact Dockerfile
into the private context, and build the selected platform with the locked
`BASE_IMAGE_DIGEST`, clean `VCS_REF`, `SOURCE_DATE_EPOCH=0`, `--no-cache`,
`--provenance=false`, `--sbom=false`, `--network=none`, OCI export and a private
metadata file. Never use the mutable tag as the build argument. Retain each
attempt separately; compare full archives and descriptor/layer/broker bytes.

Verify actual output descriptors/diffIDs, image policy and broker metadata,
then scan the exact output with the recorded full-package Trivy database and
empty config/ignore set. Trivy 0.74.0 accepts the extracted OCI layout directory
for these exports; verify every extracted byte against the archive. It does
not accept this pure OCI tar directly as a Docker-save archive. A completed
scanner process is not itself vulnerability acceptance. Convert the same
report to SBOM without a duplicate scan; a local SBOM is unsigned.

The 2026-10-10 arm64 and amd64 builds are separately byte-reproducible and
scan with zero HIGH/CRITICAL. Each retains one MEDIUM in zlib 1.3.2-r0,
CVE-2026-85091, with upstream fix 1.3.2-r1. No finding is suppressed or waived;
this is not a zero-vulnerability statement. The amd64 build ran via Docker's
emulated build support on the arm64 host, not a native amd64 runtime gate.

Raw source/toolchain/base/build/scan records, failures and unsigned SBOMs are
retained outside Git in the private `coding-image-candidate-20261010`
checkpoint. See the [candidate plan](../../../docs/plan/product-v1-phase-6-coding-image-candidate.md)
and [startup audit](../../../docs/audits/product-phase-6-slice-6-startup.md).
A diagnostic smoke is not the four-volume source-bound positive scenario.
New template/receipt/Profile trust binding and independent operator acceptance
must precede production admission; publication remains separately authorized.

The subsequent held binding component adds `LockedIdentity`, original raw OCI
descriptor metadata and `evidence.lock.json`. Exact source-owned hashes bind
these historical records, including the separate candidate recipe. They are
not live supply checks, downloaded image layers or an operator signature.
`CodingCandidateExecutionTemplate` v3 and internal receipt v3 consume this
identity without changing either old v2 template or publication. Complete
Profile, physical namespace and real four-volume admission remain held. See the
[reviewed binding design](../../../docs/plan/product-v1-phase-6-coding-image-candidate.md#reviewed-held-binding-component-2026-10-10).
