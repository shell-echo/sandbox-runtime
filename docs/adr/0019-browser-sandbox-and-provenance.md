# ADR 0019: Browser Sandbox and Provenance Publication

- Status: Accepted for the P4 browser image hardening slice
- Date: 2026-09-03

## Context

ADR 0018 established a reproducible browser image component, but its pinned
`chromedp/headless-shell` rootfs had no setuid sandbox helper and Docker's
default seccomp policy blocked the unprivileged user-namespace operations used
by Chromium. Removing `--no-sandbox` under the declared non-root,
`cap-drop=ALL`, `no-new-privileges`, read-only-root, and network-none controls
therefore failed with `No usable sandbox`. Running with `seccomp=unconfined`
proved that the browser build could use its user-namespace sandbox, but that
setting removes an independent container boundary and is not acceptable.

The previous local image digests also had no externally verifiable signer.
BuildKit's local attestation index was deliberately excluded from the
reproducibility digest because it carried invocation-time metadata. A local
self-signed file would not establish a useful trust root and cannot close the
provenance gate.

## Decision

The internal browser image manifest advances to
`sandbox.runtime/browser-image/v2`. This is not a Provider wire version. The
browser entrypoint requires Chromium's user-namespace sandbox. It does not
contain `--no-sandbox` and has no environment-variable escape hatch. User
arguments remain rejected, and CDP remains fixed to `127.0.0.1:9222`.

The runtime must apply `profiles/browser/image/chromium-seccomp.json`. It is a
fail-closed `SCMP_ACT_ERRNO` profile derived from the Playwright Chromium
profile at commit `ae935a43d9e376e4759548f6b3c6905c7b282333`, limited to the
supported amd64 and arm64 architecture maps. In addition to its ordinary
default allowlist, the only explicit sandbox setup syscalls are `chroot`,
`clone`, `setns`, and `unshare`. The exact profile digest is bound in the image
manifest and OCI labels. The Apache-2.0 license and modification notice travel
with the derived file.

Applying the profile does not relax the other runtime controls: UID/GID
`1000:1000`, read-only root, writable `/tmp` and `/workspace` tmpfs mounts,
`cap-drop=ALL`, `no-new-privileges`, finite memory/CPU/PID limits, and a
non-public network remain required. This is container-plus-browser component
hardening, not hostile multi-tenant isolation evidence.

The repository owns a manual-only `Browser Image Publication` workflow. It:

1. runs only from `main` and pins every third-party action by commit;
2. uses native `ubuntu-24.04` amd64 and `ubuntu-24.04-arm` runners, selecting
   the locked upstream digest independently for each architecture;
3. runs the sandboxed image integration gate before publication;
4. pushes content-addressed platform manifests to GHCR and combines them under
   the immutable `sha-<source-commit>` tag, never `latest`; and
5. signs the final multi-platform digest with GitHub Actions OIDC/Sigstore
   SLSA provenance, then verifies repository, signer workflow, source commit,
   and hosted-runner identity in the same job.

Normal pushes do not publish images. A checked-in workflow is design and CI
component evidence only until a named run succeeds and its immutable image and
attestation identities are recorded.

## Evidence

The tagged integration test rebuilds one locked platform at a time and runs it
with the declared identity, mounts, limits, network, and seccomp profile. It
requires a live loopback CDP `200` response with the exact browser version and
a sandboxed zygote process, while rejecting any process tree containing
`--no-sandbox`. Local arm64 and emulated amd64 runs passed on Docker Desktop
with the checked-in source. The implementation commit, published digest,
workflow run, and attestation verification remain separate release evidence to
be recorded after publication.

## Consequences

- The earlier ADR 0018 unsandboxed image digests remain historical component
  evidence and are not valid inputs for Provider browser composition.
- A future Browser runtime adapter must supply the exact seccomp profile and
  all declared HostConfig controls; startup must fail closed if any dependency
  or attestation identity is absent or mismatched.
- Provider routes, Gateway composition, capability advertisement, browser
  external-caller E2E, multi-controller reliability, hostile multi-tenant
  security, deployment, and production readiness remain open gates.
