# Coding/Shell Runtime Image

This directory defines the repository-owned guest image for the locked
`sandbox-runtime-coding-shell-v1` Provider profile. It is not a caller, a
Provider route, a public Gateway, or qualification evidence by itself.

The image repacks an exact per-platform Alpine manifest and adds only the
terminal broker built from this repository. It does not run `apk add` or use a
mutable base at build time. The manifest locks the amd64 and arm64/v8 inputs,
numeric runtime identity, stable mount boundary, shell and broker paths,
network-none policy, and the requirement for release attestation before the
image can be used in qualification.

Build one native platform from the repository root:

```bash
profiles/coding-shell/image/build.sh \
  linux/arm64/v8 \
  sandbox-runtime-coding-shell:dev-arm64 \
  "$(git rev-parse HEAD)"
```

Use `linux/amd64` on amd64. The script builds the Linux terminal broker with the
manifest-locked `go1.26.5` toolchain, `CGO_ENABLED=0`, `-trimpath`, no VCS
stamping and no Go build ID, normalizes its timestamp, and invokes BuildKit
with the matching locked base manifest,
`SOURCE_DATE_EPOCH=0`, and provenance disabled for the local image. It accepts
only the two platforms declared in `manifest.json`.

Run the native integration gate with Docker available:

```bash
SANDBOX_RUNTIME_CODING_SHELL_IMAGE_INTEGRATION=1 \
  mise exec -- go test -tags=integration -count=1 \
  ./profiles/coding-shell/image
```

The gate builds identical inputs twice and compares local image IDs, then runs
the guest with a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, no network, bounded resources, read-only `/inputs`,
writable `/workspace` and `/outputs`, and tmpfs `/tmp`. It exercises `/bin/sh`,
`printf`, `sleep`, artifact output, and an actual terminal-broker PTY round trip
as UID/GID `65532:65532`, then removes its container and image tags.

Passing this local gate establishes component behavior on the tested platform.
It does not establish a published OCI index, hosted cross-platform build,
signature, source attestation, external-caller provenance, or an accepted P2.7
qualification result. Those remain separate release and qualification gates.

The manual-only `Coding Shell Image Publication` workflow runs the same gate on
native GitHub-hosted amd64 and arm64 runners, pushes content-addressed platform
manifests, creates an immutable `sha-<source-commit>` two-platform index, and
signs and verifies its provenance with GitHub OIDC. Checking in the workflow is
not publication evidence; its exact run, source, digest, descriptors and
attestation must be recorded only after a successful invocation.
