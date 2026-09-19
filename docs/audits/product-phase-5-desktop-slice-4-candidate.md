# Product v1 Phase 5 Desktop Slice 4 Candidate Evidence

Date: 2026-09-19

Implementation: `163dd8a258a24cf4727169b1cbd8ed7c0fe29292`

Provider Contract authority: revision
`720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`

Status: historical local-candidate checkpoint; subsequently closed by
[`product-phase-5-desktop-slice-4-publication.md`](product-phase-5-desktop-slice-4-publication.md)

## Result

At this checkpoint the repository contained a reproducible Desktop
runtime-image candidate and a private display/session broker. The required
native amd64/arm64 publication had not yet run. Publication run `35447651328`
subsequently closed that gate; its immutable identities and independent
verification are recorded in the separate publication evidence document.

Desktop capability advertisement and production command composition remain
unchanged. The image, broker, and publication workflow are not wired to the
Slice 3 Provider application.

## Locked image authority

The strict manifest locks:

- Alpine 3.23 index
  `sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40`;
- linux/amd64 source manifest
  `sha256:1beb0dc0a51de7ff38e3b5274078a2e0b81113ba5c7535e1a03d5913a5edbda3`;
- linux/arm64/v8 source manifest
  `sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c`;
- exact versions of Xvfb, Openbox, xterm, xdotool, xdpyinfo, xset, xwd, and
  DejaVu fonts;
- architecture-specific recursive APK archive-set digests and the exact
  122-package installed-set digest; and
- the fixed Go 1.26.5 broker build, build context, security policy, mount
  matrix, broker protocol, and output-evidence classification.

The build fetches exact recursive APK archives, validates the complete archive
set before offline installation, validates the installed package set, removes
nondeterministic caches/logs, normalizes build-owned timestamps and symlink
timestamps, and repacks from scratch. The final image has no exposed ports and
runs as fixed `1000:1000`. Runtime policy requires a read-only root filesystem,
all Linux capabilities dropped, `no-new-privileges`, runtime-default seccomp,
private IPC, no host devices or device requests, finite resource limits, exact
mounts, and a restricted network when a later adapter composes the image.

With the fixed local label input `VCS_REF=slice4-output`, repeated candidate
builds recorded:

- linux/amd64 image ID
  `sha256:47999b3fb061fee77a1d1ab53d8bc9045d5082dc00cc6e9626ff6e0e113721d6`;
  reproduced twice by cross-build on the arm64 development host, not a native
  amd64 smoke or a registry manifest digest; and
- linux/arm64/v8 image ID
  `sha256:ec8da6b3e48d145a960d1faa3a5a7202c43221de0f3a7d73e6f62783cc92efe6`;
  produced after the native double-build and smoke gate.

Hosted publication uses the exact source commit as its revision label, so its
content and index digests are intentionally distinct from these candidate
image IDs. The subsequently accepted identities are not retroactively treated
as local candidate outputs.

## Broker boundary

The broker owns only one fixed `:99` Xvfb `1280x720x24` display, Openbox, and
the fixed development xterm. It disables X11 TCP and accepts no executable,
display, geometry, workspace, stop, or user overrides. Its `0600` Unix socket
uses protocol `sandbox.runtime/desktop-broker/v1` and accepts only strict
single-object `probe` and `describe` requests.

Requests are limited to 4 KiB, responses to 8 KiB, concurrent connections to
16, and per-request work to two seconds. The descriptor exposes fixed media
and control profile identifiers plus opaque
`ref:desktop-display:primary`; it does not expose the X11 socket, PIDs, ports,
backend IDs, host paths, credentials, or diagnostics. Input execution, media
transport, signaling, public authorization, clipboard, and file transfer are
not part of this protocol.

Tests cover unknown, trailing, malformed, and oversized input; method and
protocol rejection; response bounds; descriptor nondisclosure; socket mode;
concurrency; cancellation; stale-socket behavior; and command-line override
rejection.

## Local verification

The following local gates pass:

- native linux/arm64/v8 tagged image integration, including two identical
  builds, fixed non-root/read-only/drop-all/no-new-privileges/private-IPC/no-
  network/no-device execution, broker probe/describe, `xdpyinfo`, nonempty
  `xwd` capture, fixed process-tree inspection, container/image-policy
  inspection, and exact cleanup;
- focused broker/image tests with race detection, shuffle, and count one;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- Provider and Product Contract verifiers;
- historical qualification-profile verification;
- retained Product Phase 3 and Phase 4 evidence verification;
- Shell and workflow YAML parsing; and
- repository diff checks.

The native amd64 gate is not claimed locally. The Docker integration removes
its test containers and images. The retained candidate image IDs are evidence
values, not selected runtime inputs.

## Hosted publication gate at this checkpoint

The manual-only `Desktop Image Publication` workflow is defined to:

1. build and smoke amd64 and arm64/v8 on separate native GitHub-hosted runners;
2. validate the exact source and package-archive labels;
3. push platform manifests without a mutable `latest` tag;
4. publish exactly one `sha-<source-commit>` two-platform OCI index;
5. create GitHub OIDC/Sigstore build provenance for that index; and
6. pass the immutable index digest to a fresh job that verifies repository,
   signer workflow, source commit, hosted-runner policy, and the exact
   architecture matrix.

Checking in this workflow was component evidence only. The gate remained open
at this checkpoint until the later named successful run, source revision,
immutable index digest, both platform-manifest digests, attestation identity,
and independent verification result were recorded in repository authority.

## Non-claims

This candidate does not establish a Provider runtime adapter, private resolver,
real open/attach/reconnect/close/expiry composition, usage collection, Product
dispatch, public signaling/media/control, audio, GPU acceleration, end-user
authorization, input or transfer policy, recording, unified Web, capability
advertisement, independently implemented caller, deployment, HA, hostile-
multitenant isolation, or production readiness. The later publication evidence
closes only Slice 4 and advances Phase 5 to **4/15 complete**; all of these
non-claims remain.
