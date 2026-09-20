# Product v1 Phase 6 Local Verification — 2026-09-20

Date: 2026-09-20

Status: **passed local verification; no Phase 6 completion-counter advance**.

This record captures reproducible checks performed on the Phase 6 hardening
branch after the dependency refresh and digest-pinned image-base change in
commit `15d7314`. It is repository-side evidence only. It does not establish
an independently administered deployment, production availability, HA,
hostile multi-tenant isolation, or operator acceptance.

## Source and dependency checks

- `go mod verify` passed.
- `go vet ./...` passed.
- `go test -race -shuffle=on -count=1 ./...` passed.
- Focused Phase 6 packages passed with shuffled tests:
  `./cmd ./config ./roleprocess ./internal/phase6profile
  ./internal/secretref ./internal/netpolicy ./internal/artifactverify
  ./internal/backup ./internal/telemetry`.
- Provider production-process integration passed with a fresh PostgreSQL
  container, separated migration/runtime roles, TLS 1.3 mTLS, dependency loss,
  restart, capability projection, and protected-material log checks.
- Product development and production process integration passed with fresh
  PostgreSQL, readiness loss/recovery, separated migration/runtime roles,
  restart, authentication, capability-unavailable mutation rejection, and
  protected-material log checks.

## Image and deployment checks

- Dockerfile builder and runtime bases are digest pinned.
- The local multi-platform OCI index is
  `localhost:5001/sandbox-runtime:phase6-multi@sha256:7c8b7f6aaf2ee45bf45e015c008c2bf5fd25137c2c89e595adbfb94431631987`.
- Platform manifests are `linux/amd64@sha256:3ea02e68ff2908f24139675f8d0121d52edc8d5731f1b8a6f0eeec0defde589c` and
  `linux/arm64@sha256:d80a788215a3df64cc66917eca25ad096934a6de4dcd7491ef8cdf26969d3021`.
- A local cosign key verified the image-index signature and CycloneDX
  attestation. The key is temporary local evidence, not a production trust
  anchor or Sigstore/OIDC publication.
- Trivy HIGH/CRITICAL scan counts were zero for both the Alpine image and the
  Go binary.
- Kubernetes Kustomize security-invariant rendering passed.
- A disposable kind cluster (`sandbox-runtime-phase6`) passed the live
  development Kubernetes smoke using image `sandbox-runtime:phase6-local`:
  health, create-instance, list-instance, rollout, and cleanup checks passed.
- Apple Container 1.4.1 passed the local arm64 application smoke with the
  digest-pinned Dockerfile. Docker Engine 29.7.2 passed the non-root,
  read-only-root, capability-drop application smoke after the smoke harness
  was hardened to retry transient startup `curl` errors.

## Boundary and remaining gates

The role transport boundary remains fail-closed. `gateway serve`, `guest
serve`, `browser serve`, and `desktop serve` do not become ready until their
role-specific application graphs are explicitly composed. This is intentional:
the current configuration contains opaque authority references but does not
define safe factories for caller authorization, revocation, recording,
Provider handoff resolution, Guest identity, or private media/input bridges.

The Phase 6 plan therefore remains **3/15**. Open gates include the complete
four-role application graph and independent-process gate, KMS/HSM and
certificate rotation, independent PostgreSQL/coordination/object-store
failure domains, backup/PITR drills, SLO measurement and alerting, production
role manifests, canary/rollback/disaster recovery, hostile-input and tenant
campaigns, and independently administered release-candidate/operator
acceptance evidence.
