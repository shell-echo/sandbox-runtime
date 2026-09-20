# Application Deployment

[简体中文](deployment.zh-CN.md)

This document defines the deployment boundary for the `sandbox-runtime`
application. It deliberately separates the environment that runs the service
from the backend that the service uses to execute sandbox workloads.

[ADR 0047](adr/0047-deployment-levels-slos-and-release-gates.md) additionally
defines the `development`, `standalone`, `production`, and future
`hostile-multitenant` assurance levels. Every current asset and result in this
document is `development` packaging evidence only.

## Two independent concerns

| Concern | Question | Current examples |
| --- | --- | --- |
| Application deployment environment | Where does the `sandbox-runtime` service process run? | Docker, Apple Container, or a Kubernetes Pod |
| Sandbox execution backend | Where and how does the Provider execute a requested sandbox? | In-memory fake adapters or the current Docker development adapters |

Running the service image with Apple Container or Kubernetes does not make
either platform a sandbox execution backend. Conversely, selecting the Docker
sandbox backend does not require the service process itself to be launched by
Docker, provided it can reach the explicitly configured and authorized Docker
Engine endpoint.

The public Provider Contract must not expose either deployment-platform
identity or backend implementation identity.

## Current support matrix

| Deployment environment | Repository assets | Verified scope | Missing work |
| --- | --- | --- | --- |
| Docker-compatible OCI runtime | Root `Dockerfile`, `.dockerignore`, bilingual guide, and `scripts/docker-smoke.sh` | Local Linux `arm64` image build; numeric non-root identity; restricted container start; health, create, and list with the fake runtime | Hosted multi-architecture CI and a release gate |
| Apple Container | Root `Dockerfile`, bilingual guide, and `scripts/apple-container-smoke.sh` | Local Apple silicon build, non-root start, loopback port publication, health, create, and list with the fake runtime | Hosted CI and a release gate |
| Kubernetes | Development Kustomize base, bilingual guide, and `scripts/kubernetes-smoke.sh` | Offline rendering/security checks and a local-cluster health, create, and list path with the fake runtime | Hosted cluster CI, immutable registry image, production overlay, and a release gate |

There is currently no published general-purpose `sandbox-runtime` application
image. The repository-specific coding/shell and Browser runtime images are
different artifacts and must not be used as the application image.

Phase 6 Slice 1 adds an independently runnable `product serve` development
process, but no Docker, Apple Container, or Kubernetes role-specific Product
deployment asset or qualification. The existing image can execute a different
subcommand only as local operator experimentation; that does not widen the
support matrix below or make the default `serve` packaging smoke a Product
deployment result.

Local development evidence on 2026-09-17 passed the Docker smoke path with
Docker Engine 29.7.2 on Linux/arm64, the Apple Container path with Apple
Container 1.4.1 on macOS/arm64, and the Kubernetes live path with kind 0.33.0
and Kubernetes 1.37.0. These are current-worktree application-packaging checks,
not hosted release or production-deployment evidence.

## Portable application-container contract

Every supported deployment environment should preserve these properties:

- execute the repository-built `sandbox-runtime serve` process as a numeric
  non-root user;
- select a Linux image matching the target architecture;
- set `SANDBOX_RUNTIME_SERVER_API_HOST=0.0.0.0` only inside the container when
  the local API must be reached through a published port or Service;
- keep the unauthenticated local API on a host loopback address or behind an
  authenticated trusted boundary;
- inject configuration and credentials rather than embedding them in the
  image;
- mount only explicitly required writable state and keep secrets separate from
  ordinary configuration;
- retain process signals and bounded shutdown behavior; and
- use `/health` only for the local application health check, not as proof that
  protected Provider capabilities or external dependencies are ready.

Production Provider deployment additionally requires the complete protected
listener, identity, durable-state, capability, Gateway, and operational
dependencies described by the architecture and Provider Contract. Merely
starting the application container is not that deployment gate.

## Platform guides

- [Docker](docker.md): local application smoke path.
- [Apple Container](apple-container.md): locally verified application smoke
  path.
- [Kubernetes](kubernetes.md): development Kustomize base with offline and live
  smoke paths.

## Known gaps

- The root Dockerfile currently refers to mutable base-image tags.
- No immutable multi-platform application image is published.
- Kubernetes has no production overlay, Helm chart, hosted cluster gate, or
  availability evidence.
- The current Apple Container evidence uses the in-memory fake runtime.
- The Docker and Kubernetes application smoke paths also use that fake runtime.
- The Phase 6 Product process has no role-specific published image or
  deployment profile yet.
- Multi-controller, high availability, hostile multi-tenant isolation,
  deployment qualification, and production readiness remain separate open
  gates.
