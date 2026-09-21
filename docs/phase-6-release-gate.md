# Phase 6 Release Profile and Evidence

The repository has a strict release-profile verifier:

```bash
go run ./cmd/verify-product-phase6-profile \
  -profile /absolute/path/to/phase6-release-profile.json
```

The four-role release profile (`gateway`, `guest`, `browser`, `desktop`) is an
artifact/ingress profile. It is deliberately distinct from the Slice 4
six-process gate, whose observed process set is `product`, `gateway`,
`provider`, `guest`, `browser`, and `desktop`. The latter is verified only by
the strict evidence manifest command:

```bash
go run ./cmd/verify-product-phase6-evidence \
  -source-root /absolute/path/to/sandbox-runtime \
  -manifest /absolute/path/to/observed-phase6-slice-4-evidence.json
```

That manifest must be produced by an actual six-process run and binds source,
configuration, role commands, the exact `local-candidate-non-release` Desktop
manifest/image/platform identity, scenario observations (including broker,
executor and Provider restart), and exact cleanup. The
verifier does not synthesize a manifest or convert a profile check into a
release claim. Slice 4 evidence must state that the local OCI candidate is not
published or signed and is not production-release qualification. Slice 7 owns
the later immutable multi-platform publication, SBOM, signature, provenance,
and production driver-lock update.

Final repository verification additionally requires a clean working tree,
proves that the manifest's implementation revision is an ancestor of `HEAD`,
reconstructs the recorded source-tree digest from that immutable revision, and
allows only `README.md` or `docs/` evidence/documentation changes afterward.
Any post-evidence source, configuration, workflow or test change requires a
new implementation commit, candidate build and six-process run.

The profile is a mode-0600 JSON document. It binds one source revision,
source-tree digest, and configuration digest to exactly four independent
data-plane roles. `profile_digest` is the canonical SHA-256 summary of that
closed projection (excluding the `profile_digest` member itself), so any
post-publication role, artifact, or configuration mutation is rejected:
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
