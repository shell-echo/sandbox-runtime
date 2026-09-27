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

For the Phase 6 candidate path, the restricted-network Docker core can
override this image default with a high numeric gateway UID/GID from a
Provider-private reserved identity slot. It binds that slot to the owned
network/container and rechecks the effective Docker user on inspection. This
capability alone does not prove that a Provider acquired the slot from its
durable PostgreSQL ledger. The opt-in Docker component test is:

```bash
SANDBOX_RUNTIME_GATEWAY_SLOT_INTEGRATION=1 \
SANDBOX_RUNTIME_GATEWAY_SLOT_IMAGE=sha256:<actual-local-image-id> \
go test -tags=integration -race -count=1 \
  -run '^TestGatewayReservedSlotDocker$' \
  ./provider/network/restricted/docker
```
