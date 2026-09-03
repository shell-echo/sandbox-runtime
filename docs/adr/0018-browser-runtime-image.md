# ADR 0018: Browser Runtime Image Boundary

- Status: Accepted for the P4 browser image component
- Date: 2026-09-03

## Context

The browser Contract and Provider projection authorize a browser capability and
session resources, but they do not make a runtime image, endpoint, Gateway, or
capability advertisement available. The first implementation slice needs a
bounded image artifact whose source, architecture matrix, launch behavior, and
container assumptions can be checked independently of Provider route
composition.

The selected `docker.io/chromedp/headless-shell:latest` index is recorded by
immutable digest in `profiles/browser/image/manifest.json`:

- index: `sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04`;
- `linux/amd64`: `sha256:5f877a2a559dea1a99fb750da695d28a020cdd49db660aead6c78a46e3c7dd50`;
- `linux/arm64/v8`: `sha256:2fc473f3f926ccae8dbfedf60897937dece94ff7bbdfab20457ebfc732c2b162`.

The upstream image's default entrypoint uses a wildcard endpoint forwarder
and declares ports that are not part of the Provider boundary. Its current
Chromium build also requires `--no-sandbox` on hosts without usable user
namespaces. That is acceptable only as an explicit development smoke override,
not as a production security posture.

## Decision

Build one platform at a time from the matching immutable upstream manifest and
repack the rootfs into a `scratch` final stage. The repack supplies a fixed
entrypoint, removes inherited port metadata and the upstream forwarder, and
keeps CDP on `127.0.0.1:9222`.

The image declares the following runtime contract for a future Provider
composition:

- numeric user and group `1000:1000`;
- read-only root filesystem with writable `/workspace` and `/tmp` mounts;
- `cap-drop=ALL`, `no-new-privileges`, and restricted egress selected by the
  container runtime;
- no user-supplied command-line arguments; and
- no public endpoint or image-level port publication.

The Dockerfile normalizes all rootfs directory mtimes outside mounted kernel
filesystems and requires `SOURCE_DATE_EPOCH=0` for a reproducible locally
loaded platform image. Local verification uses `--provenance=false` because
BuildKit's default attestation index includes invocation time metadata. This
does not waive provenance: a signed external attestation remains mandatory
before any browser capability advertisement.

The development-only escape hatch is enabled only by the explicit
`BROWSER_RUNTIME_ALLOW_UNSANDBOXED=1` environment variable. The default exits
without starting Chromium. The image is therefore component evidence only and
must not be enabled by Provider startup configuration.

## Evidence

With the checked-in Dockerfile and `SOURCE_DATE_EPOCH=0`, two no-cache builds
per platform produced identical locally loaded platform digests:

| Platform | Platform image digest |
| --- | --- |
| `linux/amd64` | `sha256:38ff93f17e372560506f41b8ef77f43e06b0f37a04df17ce15d87297a1b97f83` |
| `linux/arm64/v8` | `sha256:6f2372feb2808b9de666138c6eed5e62b033c467114eed689d100f61f2a8009c` |

Both images were run with the declared user, read-only rootfs, tmpfs mounts,
all capabilities dropped, `no-new-privileges`, and `network=none`. Each kept
the CDP listener on loopback and returned an HTTP/1.1 200 response for
`/json/version`, reporting Chromium `151.0.7922.109`. The default entrypoint
returned exit status `78` without the development override and status `64` for
a command-line endpoint override. No smoke container was retained.

## Consequences

- The image can be reviewed and rebuilt without adding browser routes,
  application state, Gateway policy, or capability advertisement.
- A stable platform image digest is available for later runtime composition,
  while signed provenance, sandbox support, and deployment policy remain open
  gates.
- The retained upstream `socat` binary is inert image content; no entrypoint or
  network forwarder invokes it. Future hardening may remove unused packages,
  but that is a separate image change requiring fresh evidence.
- Browser session recovery, opaque reference resolution, usage evidence,
  caller-owned Gateway authorization, external caller E2E, multi-controller,
  multi-tenant, deployment, and production readiness remain unproven.
