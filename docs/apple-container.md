# Apple Container

[简体中文](apple-container.zh-CN.md)

This document describes how to build and run the `sandbox-runtime` application
itself with Apple Container. It does not describe an Apple Container sandbox
backend and does not authorize one.

See [Application Deployment](deployment.md) for the cross-platform deployment
boundary and current support matrix.

## Supported scope

The repository Dockerfile builds a Linux OCI image containing the
`sandbox-runtime` service. The local smoke test verifies that Apple Container
can:

1. build that Dockerfile as a Linux `arm64` OCI image;
2. start the image as a non-root container;
3. publish the local management API to a host loopback port;
4. receive a successful `/health` response; and
5. create and list one instance through the default in-memory fake runtime.

This is local application-packaging evidence. It is not evidence for the
protected Provider surface, Docker-backed exec, terminal, artifact, Browser,
multi-controller, Kubernetes, production deployment, or hostile multi-tenant
isolation.

## Prerequisites

- Apple silicon;
- a supported macOS release;
- Apple Container installed and running;
- `curl`; and
- network access for the first image and kernel downloads.

Check the installation:

```bash
container --version
container system status
```

If Apple Container reports that no default `arm64` kernel is configured,
install its recommended kernel once:

```bash
container system kernel set --recommended
```

That command changes the user's Apple Container installation and downloads a
large external kernel archive. It is intentionally not run automatically by
the repository smoke test.

## Automated smoke test

From the repository root, run:

```bash
./scripts/apple-container-smoke.sh
```

The script uses host port `18080` by default. Select another port when it is
already occupied:

```bash
SANDBOX_RUNTIME_APPLE_SMOKE_PORT=28080 \
./scripts/apple-container-smoke.sh
```

The container and its uniquely tagged smoke-test image are removed on exit.
Retain the image for inspection by setting:

```bash
SANDBOX_RUNTIME_APPLE_SMOKE_KEEP_IMAGE=1 \
./scripts/apple-container-smoke.sh
```

## Manual run

Build the existing Dockerfile:

```bash
container build --progress plain \
  --tag sandbox-runtime:apple-local \
  .
```

Start the service:

```bash
container run \
  --detach \
  --remove \
  --name sandbox-runtime-apple \
  --publish 127.0.0.1:18080:8080 \
  --env SANDBOX_RUNTIME_APPLICATION_MODE=development \
  --env SANDBOX_RUNTIME_SERVER_API_HOST=0.0.0.0 \
  sandbox-runtime:apple-local
```

Then check it from the host:

```bash
curl --fail http://127.0.0.1:18080/health
container stop sandbox-runtime-apple
```

The explicit `0.0.0.0` container-side listen address is required for the
published port. Host exposure remains bound to `127.0.0.1` because the local
management API has no end-user authentication.

## Current limitations

- The Dockerfile currently uses mutable base-image tags. A release workflow
  must pin reviewed base-image digests and publish an immutable multi-platform
  OCI image index.
- The smoke test uses the in-memory fake runtime. Full coding/shell Provider
  composition currently requires Docker-specific runtime dependencies and is
  outside this Apple Container application smoke test.
- No Apple Container CI runner or release gate is configured yet.
- This workflow does not establish deployment or production readiness.

The deployment target and sandbox execution backend are separate concerns:
running the service under Apple Container does not make Apple Container a
Provider runtime driver, and this smoke test does not attempt to create nested
Apple Container services.
