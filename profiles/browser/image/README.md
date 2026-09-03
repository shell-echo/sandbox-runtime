# Browser Runtime Image

This directory contains the first P4 browser image component. It is not a
Provider route, capability advertisement, public Gateway, or browser caller.

The image is rebuilt from the immutable per-platform manifests of
`docker.io/chromedp/headless-shell` and repacked as a `scratch` image. Repacking
removes the upstream image's default `socat` forwarder, `0.0.0.0` binding, and
exposed-port metadata. The checked-in [manifest](manifest.json) is the source
and security authority for the build inputs and declared guest boundary.

Build one platform at a time with the matching manifest digest:

```bash
docker build \
  --no-cache \
  --provenance=false \
  --platform linux/arm64/v8 \
  --build-arg BASE_IMAGE_DIGEST=sha256:2fc473f3f926ccae8dbfedf60897937dece94ff7bbdfab20457ebfc732c2b162 \
  --build-arg SOURCE_DATE_EPOCH=0 \
  --build-arg VCS_REF=$(git rev-parse HEAD) \
  --tag sandbox-runtime-browser:dev-arm64 \
  .
```

Use the `linux/amd64` digest from `manifest.json` for an amd64 build. The
platform must be checked after build; a tag or an index digest alone is not
evidence of the selected platform. `SOURCE_DATE_EPOCH=0` fixes the image
config/history clock and `--provenance=false` makes the locally loaded platform
manifest digest stable; run the same command twice and compare `docker image
inspect --format '{{.Id}}'`. BuildKit's default provenance attestation embeds
the invocation clock in its index wrapper, so its index digest is not used for
this component reproducibility check. A signed provenance attestation remains a
separate required gate before capability advertisement.

The selected headless-shell build uses Chromium's user-namespace sandbox. The
runtime must supply the checked-in `chromium-seccomp.json`: Docker's default
profile blocks the required namespace operations, while `seccomp=unconfined`
is explicitly forbidden. The profile remains fail closed by default and binds
the four sandbox setup syscalls `chroot`, `clone`, `setns`, and `unshare`. Its
exact digest and upstream derivation are recorded in `manifest.json`; the
Apache-2.0 license and modification notice are included alongside it.

```bash
docker run --rm \
  --platform linux/arm64/v8 \
  --user 1000:1000 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp="$(pwd)/chromium-seccomp.json" \
  --network none \
  --memory 1g \
  --cpus 1 \
  --pids-limit 256 \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --tmpfs /workspace:rw,noexec,nosuid,size=1g \
  sandbox-runtime-browser:dev-arm64
```

The guest CDP endpoint is fixed to `127.0.0.1:9222` and is never published by
the image or smoke command. The entrypoint rejects all user arguments and has
no unsandboxed override. Run the reproducible integration gate for either
locked platform with:

```bash
SANDBOX_RUNTIME_BROWSER_IMAGE_INTEGRATION=1 \
SANDBOX_RUNTIME_BROWSER_PLATFORM=linux/arm64/v8 \
go test -tags=integration -count=1 -run '^TestBrowserImageSandboxIntegration$' \
  ./profiles/browser/image
```

Use `linux/amd64` for the other platform. The test rebuilds the image, applies
the exact seccomp policy and declared container controls, queries the private
CDP endpoint from inside the network-none container, verifies the browser
version and sandboxed zygote process, and cleans up its tagged resources.

The reproducible platform image digests recorded by ADR 0018 are historical
unsandboxed component evidence:

| Platform | Source manifest | Platform image digest |
| --- | --- | --- |
| `linux/amd64` | `sha256:5f877a2a559dea1a99fb750da695d28a020cdd49db660aead6c78a46e3c7dd50` | `sha256:38ff93f17e372560506f41b8ef77f43e06b0f37a04df17ce15d87297a1b97f83` |
| `linux/arm64/v8` | `sha256:2fc473f3f926ccae8dbfedf60897937dece94ff7bbdfab20457ebfc732c2b162` | `sha256:6f2372feb2808b9de666138c6eed5e62b033c467114eed689d100f61f2a8009c` |

They must not be used for Provider browser composition. The manual-only
`Browser Image Publication` workflow rebuilds and smoke-tests both current
platforms, publishes an immutable `sha-<source-commit>` GHCR index, signs its
digest with GitHub Actions OIDC/Sigstore SLSA provenance, and verifies the
repository, signer workflow, source commit, and hosted-runner identity. Merely
checking in that workflow is not provenance evidence: a named successful run,
immutable digest, and verified attestation must be recorded separately.

The sandbox and provenance gates do not by themselves authorize Provider
routes or capability advertisement. Restricted egress policy, a private
endpoint resolver, caller-owned Gateway authorization/revocation/audit/
reconnect controls, browser external-caller E2E, and the later reliability,
tenancy, deployment, and production gates remain independent.
