# Phase 6 Release Profile and Evidence

The repository has a strict release-profile verifier:

```bash
go run ./cmd/verify-product-phase6-profile \
  -profile /absolute/path/to/phase6-release-profile.json
```

The profile is a mode-0600 JSON document. It binds one source revision and
configuration digest to exactly four independent data-plane roles:
`gateway`, `guest`, `browser`, and `desktop`. Each role declares a
digest-only OCI image reference, matching image digest, independent SBOM,
provenance and signature digests, supported architecture, service account,
probe paths, and the role-specific ingress boundary.

The verifier is a repository-side input check. It does not claim that a
registry signature, SBOM, provenance statement, cluster policy, certificate
issuer, KMS/HSM, or dependency failure domain was independently observed.
Those facts must be recorded in external release-candidate evidence before
Slices 14 or 15 can pass.

## Required external evidence

The operator must attach immutable observations for every supported
architecture, including image-index signature verification, source/build
provenance, SBOM inspection, certificate rotation, KMS/HSM behavior,
PostgreSQL/coordination/object-store isolation, backup/PITR RPO/RTO, cluster
deployment, version-skew rollback, hostile-input coverage, and named operator
acceptance. A passing profile check alone cannot advance the Phase 6 counter.
