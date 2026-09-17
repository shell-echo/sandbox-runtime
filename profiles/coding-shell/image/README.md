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
signs and verifies its provenance with GitHub OIDC.

The first accepted publication is source
`cf1830e9bbfcd08d6f171e60f67d949d839e1069`, workflow run `35171475925`, and
attestation `48073123`:

- image: `ghcr.io/shell-echo/sandbox-runtime-coding-shell@sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1`;
- linux/amd64: `sha256:a3559ade39fd86c9bb04f69a111d8da4e2f31951333b48bf6d59bd752c95aa4e`;
- linux/arm64/v8: `sha256:a3d9567ee49482582baff67cc3b8679bbe08b79909f7375145004f1c92b4d5f3`;
- registry attestation object: `sha256:bf31ce86deb5b7f6d2ba374753042e1e2a95c299bb5e6e025976249ddd4536a0`;
- Sigstore transparency-log index: `2870923506`.

Independent inspection confirmed an exact two-entry OCI index, and independent
`gh attestation verify` enforcement confirmed the repository, workflow,
source digest, `main` ref, GitHub-hosted runner, SLSA predicate and Rekor
timestamp. `publication.go` is the machine-checked local authority for this
exact evidence. This closes image publication only; it is not external-caller
qualification or production-readiness evidence.
