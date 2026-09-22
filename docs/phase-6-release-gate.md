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

That default behavior is the `finalization` mode. After a slice is closed,
[ADR 0053](adr/0053-phase-6-evidence-closure-lifecycle.md) permits only an
explicit historical check:

```bash
go run ./cmd/verify-product-phase6-evidence \
  -mode retained \
  -slice product-v1-phase-6-slice-4 \
  -source-root "$PWD" \
  -manifest "$PWD/docs/audits/product-phase-6-slice-4-evidence.json" \
  -closure-record "$PWD/docs/audits/product-phase-6-slice-4-closure.json"
```

Retained mode validates the immutable runtime, evidence-tool and closure
ancestry, the original closed diffs, the byte-exact manifest, and the one-time
closure record. Its machine-readable result always states
`claim_scope=historical_retained` and `current_head_covered=false`. It does not
verify later source, approve a successor slice, or replace that slice's current
development/finalization gate. There is no automatic mode fallback.

Slice 4's accepted canonical manifest is checked in at
[`audits/product-phase-6-slice-4-evidence.json`](audits/product-phase-6-slice-4-evidence.json).
Its immutable closure record is
[`audits/product-phase-6-slice-4-closure.json`](audits/product-phase-6-slice-4-closure.json).
It binds runtime revision `78f5987fda45873e497bce6d336e29dd4a61dc74`,
evidence-tool revision `e2f4abacf03418c7b18f179c3e7459292d8626df`,
the `linux/arm64/v8` candidate image digest
`sha256:0592a69e8f85125360eb6805132b3654324ab9a56c0ea019ea3dc7aade103d4e`,
and manifest digest
`sha256:d01b3c41a0094657f18b4014b0649a799ea7fcf0e4ccaf07aa82cdd2052cc0d2`.
This advances Phase 6 only to 4/15 within the bounded local
independent-process scope; it is not the Slice 7 publication gate or a
production-release claim.

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
