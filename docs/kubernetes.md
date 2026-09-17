# Kubernetes Application Deployment

[简体中文](kubernetes.zh-CN.md)

This guide deploys the `sandbox-runtime` application itself to Kubernetes. It
does not implement Kubernetes as a sandbox execution backend.

The repository assets under `deploy/kubernetes/development` intentionally form
a development profile. They use the in-memory fake runtime and the local
management API. They are not a production Provider deployment.

See [Application Deployment](deployment.md) for the cross-platform boundary.

## Included resources

The Kustomize base contains:

- a `ConfigMap` selecting development mode and port `8080`;
- a single-replica `Deployment` with startup, readiness, and liveness probes;
- a `ClusterIP` `Service`;
- a default-deny-style ingress `NetworkPolicy` that permits port `8080` only
  from same-namespace Pods labelled
  `sandbox-runtime.shell-echo.dev/client=true`;
- numeric non-root identity, default seccomp, no service-account token,
  read-only root filesystem, no privilege escalation, and no Linux
  capabilities;
- explicit CPU/memory bounds; and
- a bounded `emptyDir` mounted only at `/tmp`.

The `Recreate` strategy and one replica are deliberate because the development
fake runtime is process-local and non-durable.

## Offline validation

No cluster is needed to render the Kustomize base and check its required
security invariants:

```bash
./scripts/kubernetes-smoke.sh
```

This is structural evidence only. It does not prove that a Kubernetes API,
scheduler, CNI, kubelet, or container runtime accepted and ran the resources.

## Live smoke test

The live mode requires:

- a reachable current `kubectl` context;
- an unused local port, `18082` by default; and
- `sandbox-runtime:local` already available to every target node. The checked-in
  development Deployment uses `imagePullPolicy: Never` because no application
  image is published yet.

Run:

```bash
SANDBOX_RUNTIME_KUBERNETES_LIVE=1 \
  ./scripts/kubernetes-smoke.sh
```

The script creates a uniquely named namespace, deploys the resources, waits for
rollout, port-forwards the Service, verifies health/create/list, and deletes the
namespace. Set `SANDBOX_RUNTIME_KUBERNETES_KEEP_NAMESPACE=1` to retain it.

For another preloaded image tag:

```bash
SANDBOX_RUNTIME_KUBERNETES_LIVE=1 \
SANDBOX_RUNTIME_KUBERNETES_IMAGE=sandbox-runtime:test \
  ./scripts/kubernetes-smoke.sh
```

## Local kind example

With Docker and kind available:

```bash
kind create cluster --name sandbox-runtime
docker build --tag sandbox-runtime:local .
kind load docker-image sandbox-runtime:local --name sandbox-runtime
SANDBOX_RUNTIME_KUBERNETES_LIVE=1 ./scripts/kubernetes-smoke.sh
kind delete cluster --name sandbox-runtime
```

The smoke script owns only its unique namespace. Cluster creation, image
loading, and cluster deletion stay explicit operator actions.

## Manual deployment

Create a namespace and apply the development base:

```bash
kubectl create namespace sandbox-runtime
kubectl apply --namespace sandbox-runtime \
  --kustomize deploy/kubernetes/development
kubectl rollout status --namespace sandbox-runtime \
  deployment/sandbox-runtime --timeout=180s
```

Before using a remote registry, replace `sandbox-runtime:local` with an
immutable digest and change the pull policy in an operator-owned overlay. Do
not put credentials in the `ConfigMap`; use a separate Secret and the protected
Provider configuration model.

## Security and production boundary

The local management API is unauthenticated. A `ClusterIP` plus NetworkPolicy
reduces exposure but is not authentication, and NetworkPolicy enforcement
depends on the cluster CNI. Do not add an Ingress or public LoadBalancer for
this development profile.

Production use still requires separately reviewed identity, mTLS/JWS admission,
durable repositories, capability dependencies, Gateway, secret delivery,
observability, disruption/availability design, backup/restore, and an immutable
published image. These development manifests establish none of those claims.
