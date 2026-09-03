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

The smoke command below is deliberately explicit because the selected
headless-shell build cannot use Chromium's user-namespace sandbox on hosts
where unprivileged user namespaces are disabled. The default entrypoint exits
without this override. This is development component evidence only and is not
an advertisement or production security approval.

```bash
docker run --rm \
  --platform linux/arm64/v8 \
  --user 1000:1000 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --network none \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --tmpfs /workspace:rw,noexec,nosuid,size=1g \
  --env BROWSER_RUNTIME_ALLOW_UNSANDBOXED=1 \
  sandbox-runtime-browser:dev-arm64
```

The guest CDP endpoint is fixed to `127.0.0.1:9222` and is never published by
the image or smoke command. A future Provider composition must replace the
development override with a verified browser sandbox, restricted egress
policy, private endpoint resolver, caller-owned Gateway authorization,
revocation, audit, and reconnect controls before any browser advertisement.

The reproducible platform image digests recorded for this slice are:

| Platform | Source manifest | Platform image digest |
| --- | --- | --- |
| `linux/amd64` | `sha256:5f877a2a559dea1a99fb750da695d28a020cdd49db660aead6c78a46e3c7dd50` | `sha256:38ff93f17e372560506f41b8ef77f43e06b0f37a04df17ce15d87297a1b97f83` |
| `linux/arm64/v8` | `sha256:2fc473f3f926ccae8dbfedf60897937dece94ff7bbdfab20457ebfc732c2b162` | `sha256:6f2372feb2808b9de666138c6eed5e62b033c467114eed689d100f61f2a8009c` |

These are local component-evidence digests, not published Provider image
authority. The checked-in manifest still requires an external provenance
attestation and verified browser sandbox before advertisement.
