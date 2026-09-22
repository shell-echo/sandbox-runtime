# Desktop Runtime Image

This directory defines the Product Phase 5 Slice 4 Desktop image component.
It is not a Provider adapter, private resolver, public Gateway, Product
dispatcher, or capability advertisement.

Two immutable-purpose manifests are intentionally separate:

- `phase5-production-release-manifest.json` is the byte-exact build identity
  for signed publication
  `sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`.
  Its file digest is
  `sha256:a03c1426058ef6fe18a70329610d0495d267cd1aa9513e650367e3f9a8857887`;
  the production adapter accepts no other manifest for that lock.
- `phase6-local-candidate-manifest.json` contains the newer session/media
  inputs used to build the Phase 6 executor-v2 local candidate. It is not a
  publication manifest and the production adapter rejects it.

Neither path is auto-selected from image labels. The Provider deployment level
chooses one closed constructor, and the constructor verifies the corresponding
manifest, image digest and labels without fallback.

The Phase 5 build checked
`sha256:6b5fc1ece685456ed20f474c9af9547c597210f9105f7f12e9cf21d8377db4b5`
as its installed-package-set input but did not publish that value as an OCI
label. The Phase 5 runtime schema requires the label to be absent and does not
claim startup-time installed-set attestation. The Phase 6 candidate schema is
separate and requires its per-platform installed-set label.

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
attestation, and passes its digest to a separate fresh verification job. The
first accepted publication is source
`e4a940bda6c5172a78d0dbe40963ca1a99911976`, workflow run `35447651328`, and
attestation `48643717`:

- image: `ghcr.io/shell-echo/sandbox-runtime-desktop@sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`;
- linux/amd64: `sha256:ae1b71855f879066caf73f1056039d52b796d936a19f4b34a58a5565dd89609b`;
- linux/arm64/v8: `sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505`;
- registry attestation object: `sha256:2abf3a1c0304bac70f3118d4b16c193cc1cf2abaa83c144efdd15a365998faf8`;
- Sigstore transparency-log index: `2892645362`.

Independent verification enforced the repository, signer workflow, source
commit, `main` ref, GitHub-hosted runner, SLSA predicate, and the exact
linux/amd64 plus linux/arm64/v8 matrix. `publication.go` is the machine-checked
authority for this exact immutable evidence. Mutable tags are never runtime
inputs.

The local image and protocol gates are component evidence only. They do not
establish a WebRTC media path, control authorization, audio, GPU acceleration,
runtime adapter, restricted-egress deployment, hostile-multitenant isolation,
HA, deployment, or production readiness.
