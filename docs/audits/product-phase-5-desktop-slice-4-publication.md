# Product v1 Phase 5 Desktop Slice 4 Publication Evidence

Date: 2026-09-19

Publication source: `e4a940bda6c5172a78d0dbe40963ca1a99911976`

Workflow run: `35447651328`

GitHub attestation: `48643717`

Status: passed; Slice 4 is complete within its image-publication boundary

## Result

The manual-only `Desktop Image Publication` workflow ran from `main` at the
exact source commit above. Separate native GitHub-hosted amd64 and arm64/v8
runners passed the tagged Desktop image integration gate, built and pushed
content-addressed platform manifests, and produced exactly one immutable
two-platform OCI index.

The publish job created GitHub OIDC/Sigstore SLSA provenance for that index.
A fresh independent job then verified the repository, signer workflow, source
commit, `main` ref, GitHub-hosted runner policy, and exact architecture matrix.
An additional constrained `gh attestation verify` from the development host
returned the same source, workflow, runner environment, subject, and Rekor
timestamp.

## Immutable identities

| Item | Accepted identity |
| --- | --- |
| Repository | `ghcr.io/shell-echo/sandbox-runtime-desktop` |
| Immutable tag | `sha-e4a940bda6c5172a78d0dbe40963ca1a99911976` |
| OCI index | `sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300` |
| linux/amd64 manifest | `sha256:ae1b71855f879066caf73f1056039d52b796d936a19f4b34a58a5565dd89609b` |
| linux/arm64/v8 manifest | `sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505` |
| Registry attestation object | `sha256:2abf3a1c0304bac70f3118d4b16c193cc1cf2abaa83c144efdd15a365998faf8` |
| GitHub attestation | `48643717` |
| Rekor log index | `2892645362` |

The source certificate and SLSA statement bind workflow
`github.com/shell-echo/sandbox-runtime/.github/workflows/desktop-image.yml`,
repository `shell-echo/sandbox-runtime`, source and build-config digest
`e4a940bda6c5172a78d0dbe40963ca1a99911976`, `refs/heads/main`,
`workflow_dispatch`, and `github-hosted` runner environment.

## Acceptance boundary

`profiles/desktop/image/publication.go` fails closed on drift in the index,
platform manifests, source, workflow, repository, runner policy, attestation,
registry object, Rekor index, or runtime profile. This closes only Slice 4's
immutable image and provenance gate and permits Slice 5 to select that exact
digest.

It does not establish a Provider runtime adapter, private resolver,
open/attach/reconnect/close/expiry behavior, usage collection, Product
dispatch, public signaling/media/control, end-user policy, recording, unified
Web, capability advertisement, independently implemented caller, deployment,
HA, hostile-multitenant isolation, or production readiness.
