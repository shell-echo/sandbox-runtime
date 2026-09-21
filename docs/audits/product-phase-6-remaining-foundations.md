# Product v1 Phase 6 Remaining Foundations

Date: 2026-09-20

This record separates repository-owned implementation foundations from the
external evidence still required after Slice 4. Foundation packages alone do
not advance the Phase 6 completion counter.

## Repository-owned foundations added in this continuation

- Slice 4: separate Gateway/Guest/Browser/Desktop production commands,
  role-specific configuration, public/private TLS constraints, outbound-only
  Guest validation, loopback-only probes, mixed-authority rejection, and the
  versioned opaque-only Provider-to-executor Browser/Desktop relay graph. The
  Provider remains the sole handoff/runtime authority; the independent roles
  do not own Provider state or Docker control.
- Slice 4 Browser runtime: an operator-owned mTLS CDP relay is available as
  `cmd/browser-executor-backend`; its tagged integration test has completed a
  real `Browser.getVersion` exchange against the locked Chromium image.
- Slice 4 Desktop runtime: `executor.v2`, the signed `desktop-bridge.v2`
  capability, Provider-owned Unix broker mux, replay ledger, Desktop-specific
  sealed restricted-egress identity and local candidate path pass the strict
  six-role/twelve-scenario gate. Slice 4 is complete only for that bounded
  local independent-process scope.
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
configuration. Browser/Desktop readiness additionally probes the configured
executor backend through the private mTLS relay; binding a listener is not
treated as capability readiness.

## Gates that remain open

The remaining foundations do not establish real KMS/HSM behavior, certificate
issuance/rotation, Valkey/object-store independent failure domains, signed
multi-platform application publication, backup/PITR RPO/RTO, dashboards or an
SLO measurement window, Kubernetes/Apple Container role deployment, version
skew/canary/rollback, hostile multi-tenant isolation, or an independently
administered release candidate. Slice 4's local six-process evidence does not
establish complete public Product E2E or widen its explicit non-claims. Slices
5-15 retain their own gates, and Slices 14-15 cannot be marked complete without
externally observed topology and operator acceptance evidence.
