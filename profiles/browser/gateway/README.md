# Browser Egress Gateway Image

This image contains the Provider-local process that enforces one Browser
allocation's restricted HTTP/HTTPS egress policy. It is not the caller-facing
Runtime Gateway.

Build from the repository root so the pinned Go builder and the exact gateway
sources are the only inputs copied into the build stage:

```bash
docker build \
  --provenance=false \
  --file profiles/browser/gateway/Dockerfile \
  --tag sandbox-runtime-browser-egress-gateway:dev \
  .
```

The final image is `scratch`, runs as `65532:65532`, exposes no port, accepts no
weaker mode, and has fixed `serve` and `healthcheck` commands. The Docker
restricted-network provisioner still requires an immutable local image ID or
repository digest and re-inspects all image and container controls before use.

The complete local component integration uses the immutable ID printed by
`docker image inspect`:

```bash
SANDBOX_RUNTIME_BROWSER_NETWORK_INTEGRATION=1 \
SANDBOX_RUNTIME_BROWSER_GATEWAY_IMAGE=sha256:<local-image-id> \
go test -tags=integration -count=1 \
  -run '^TestBrowserRestrictedEgressIntegration$' \
  ./provider/browser/driver/docker
```

This source-pinned local build is component input only. No published digest,
signature, deployment distribution, multi-tenant isolation, or production
readiness is claimed until those gates have separate evidence.
