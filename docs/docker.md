# Docker Application Deployment

[简体中文](docker.zh-CN.md)

This guide builds and runs the `sandbox-runtime` application itself with
Docker. It does not make Docker the sandbox execution backend. The commands
below deliberately use the in-memory fake runtime and expose only the local
management API.

See [Application Deployment](deployment.md) for the cross-platform boundary
and support matrix.

## Verified scope

The repository smoke test verifies:

1. the root `Dockerfile` builds a Linux application image;
2. the image declares numeric user and group `1000:1000`;
3. the container runs with a read-only root filesystem, all Linux capabilities
   dropped, and privilege escalation disabled;
4. port `8080` is published only on host loopback;
5. `/health` succeeds; and
6. one local fake instance can be created and listed.

It does not verify the protected Provider API, Docker-backed sandbox execution,
multi-controller operation, hostile multi-tenant isolation, or production
readiness.

## Prerequisites

- Docker CLI and a reachable Linux Docker Engine;
- `curl`; and
- an unused loopback TCP port, `18081` by default.

## Run the smoke test

```bash
./scripts/docker-smoke.sh
```

The script uses a unique image tag and container name. It removes both on
success and failure. To retain the image for inspection:

```bash
SANDBOX_RUNTIME_DOCKER_SMOKE_KEEP_IMAGE=1 \
  ./scripts/docker-smoke.sh
```

To choose another loopback port:

```bash
SANDBOX_RUNTIME_DOCKER_SMOKE_PORT=28081 \
  ./scripts/docker-smoke.sh
```

## Manual development run

```bash
docker build --tag sandbox-runtime:local .

docker run --rm \
  --name sandbox-runtime \
  --publish 127.0.0.1:8080:8080 \
  --env SANDBOX_RUNTIME_APPLICATION_MODE=development \
  --env SANDBOX_RUNTIME_SERVER_API_HOST=0.0.0.0 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  sandbox-runtime:local
```

In another shell:

```bash
curl --fail http://127.0.0.1:8080/health
```

The local `/instances` API has no end-user authentication. Do not publish this
port on an untrusted network. A protected Provider deployment requires its own
configuration, credentials, durable state, caller identity, and Gateway
composition.

## Docker-backed sandboxes are separate

The container above has no Docker socket. Mounting a host Docker socket would
grant the application substantial control over the host daemon and is not part
of this application-deployment smoke test. Docker-backed Provider capabilities
must use their separately reviewed configuration and integration tests.
