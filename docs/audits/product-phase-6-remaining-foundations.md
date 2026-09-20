# Product v1 Phase 6 Remaining Foundations

Date: 2026-09-20

This record separates repository-owned implementation foundations from the
external evidence still required by Slices 4–15. It does not advance the
Phase 6 completion counter.

## Repository-owned foundations added in this continuation

- Slice 4: separate Gateway/Guest/Browser/Desktop production commands,
  role-specific configuration, public/private TLS constraints, outbound-only
  Guest validation, loopback-only probes, and mixed-authority rejection.
- Slice 5: `internal/secretref` reference parsing, bounded file resolution,
  versioned key material, rotation windows, expiry, and revocation.
- Slice 6: `internal/netpolicy` exact-host/port egress policy with DNS
  rebinding protection and metadata/private/link-local address denial.
- Slice 7: `internal/artifactverify` private-file mode checks, SHA-256 digest
  verification, and Ed25519 manifest signature verification.
- Slice 8: strict configuration for coordination, object storage, and KMS
  dependency references using opaque `secret://`/`kms://` values only.
- Slice 9: `internal/backup` immutable manifest and isolated-target restore
  ordering.
- Slice 10: `internal/telemetry` fixed low-cardinality metric registration.
- Slice 7/11/14: `internal/phase6profile` and
  `cmd/verify-product-phase6-profile` bind digest-only images, SBOM,
  provenance, signatures, supported architectures, service accounts, probe
  paths, and role ingress boundaries. A configured role checks this profile
  before readiness.

The role probe validates its three private authority files, recording-key
reference, optional release profile, and typed Phase 6 dependency
configuration. It still returns not-ready until the owning
Gateway/Guest/Browser/Desktop application graph is composed; binding a
listener is not treated as capability readiness.

## Gates that remain open

These foundations do not establish real KMS/HSM behavior, certificate
issuance/rotation, Valkey/object-store independent failure domains, signed
multi-platform application publication, backup/PITR RPO/RTO, dashboards or an
SLO measurement window, Kubernetes/Apple Container role deployment, version
skew/canary/rollback, hostile multi-tenant isolation, or an independently
administered release candidate. Slice 4 still needs its complete application
graph behind the role transports. Slices 14 and 15 cannot be marked complete
without externally observed topology and operator acceptance evidence.
