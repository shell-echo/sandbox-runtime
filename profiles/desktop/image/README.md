# Desktop Runtime Image

This directory defines the Product Phase 5 Slice 4 Desktop image component.
It is not a Provider adapter, private resolver, public Gateway, Product
dispatcher, or capability advertisement.

The image uses the same immutable Alpine 3.23 source index selected by the
qualified coding/shell image, but Desktop has its own per-platform source
manifest and package-archive locks. `build.sh` fetches exact package versions,
hashes the complete recursive APK archive set before installation, installs
without further network access, and verifies the complete installed-package
set. Any repository drift fails the build instead of selecting new packages.

Supported native platforms are exactly `linux/amd64` and `linux/arm64/v8`.
Build one with:

```bash
./build.sh linux/arm64/v8 sandbox-runtime-desktop:dev "$(git rev-parse HEAD)"
```

The build compiles the broker with Go 1.26.5, `CGO_ENABLED=0`, `-trimpath`, no
VCS stamping, and no build ID. The final scratch repack normalizes build-owned
timestamps and contains no inherited port metadata. The runtime entrypoint
rejects arguments and starts only the fixed Desktop broker.

The broker owns one `1280x720x24` Xvfb display and Openbox session. X11 TCP is
disabled. Its `0600` Unix socket accepts only strict, single-object `probe` and
`describe` messages under protocol `sandbox.runtime/desktop-broker/v1`.
Requests are limited to 4 KiB, responses to 8 KiB, and concurrent connections
to 16. The description exposes the fixed profiles and
`ref:desktop-display:primary`, never the X11 socket, process IDs, ports, host
paths, or credentials. Input execution, clipboard, file transfer, media
transport, public signaling, and end-user authorization are deliberately not
part of this slice.

The native smoke builds twice and requires identical image IDs. It runs the
image as `1000:1000` with a read-only root filesystem, all capabilities
dropped, `no-new-privileges`, private IPC, no network, no device requests,
finite CPU/memory/PID limits, exact mounts, and writable `/tmp` only. It probes
the broker, validates its bounded descriptor, captures the native X root
window with `xwd`, inspects the process and container policies, and removes all
test resources:

```bash
SANDBOX_RUNTIME_DESKTOP_IMAGE_INTEGRATION=1 \
SANDBOX_RUNTIME_DESKTOP_PLATFORM=linux/arm64/v8 \
go test -tags=integration -count=1 -run '^TestDesktopImageNativeIntegration$' \
  ./profiles/desktop/image
```

Use `linux/amd64` only on an amd64 host; the native gate rejects emulation.

The manifest records reproducibility outputs built with the fixed label input
`VCS_REF=slice4-output`: `sha256:ec8da6b3e48d145a960d1faa3a5a7202c43221de0f3a7d73e6f62783cc92efe6`
for native arm64/v8 and
`sha256:47999b3fb061fee77a1d1ab53d8bc9045d5082dc00cc6e9626ff6e0e113721d6`
for amd64. The amd64 value was reproduced twice by cross-build on the arm64
development host; it is not an amd64 native runtime smoke or publication
digest. Publication uses the exact source commit as its VCS label and therefore
has distinct content digests that must be recorded after the hosted run.

The manual-only `Desktop Image Publication` workflow builds and smokes both
architectures on native GitHub-hosted runners, publishes only an immutable
`sha-<source-commit>` index, creates a GitHub OIDC/Sigstore SLSA provenance
attestation, and passes its digest to a separate fresh verification job. That
job verifies repository, signer workflow, source commit, hosted-runner policy,
and the exact two-platform matrix. A checked-in workflow is not publication
evidence: Slice 5 must not accept this image until a named workflow run and its
immutable index/platform/attestation identities are recorded in repository
authority. Mutable tags are never runtime inputs.

The local image and protocol gates are component evidence only. They do not
establish a WebRTC media path, control authorization, audio, GPU acceleration,
runtime adapter, restricted-egress deployment, hostile-multitenant isolation,
HA, deployment, or production readiness.
