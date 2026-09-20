# Phase 6 Operations Runbook Skeleton

This runbook is intentionally a skeleton until an operator supplies the
deployment-specific identities, secret references, artifacts, and dependency
owners. It is not a production-readiness claim.

## Startup order

1. Verify the immutable application manifest and every role artifact with
   `internal/artifactverify` before binding a listener. For a complete
   release candidate, also run `go run ./cmd/verify-product-phase6-profile`
   against the mode-0600 profile and bind that file through each role's
   `authority.release_profile_file`.
2. Resolve KMS, coordination, object-store, PostgreSQL, and certificate
   references through the configured secret provider. Never place their bytes
   or endpoint credentials in TOML, environment variables, logs, or probes.
3. Start migration authorities and record the exact schema digest. Close DDL
   connections before starting runtime roles.
4. Start Provider, Guest, private Browser/Desktop, Gateway, and Product roles
   independently. Readiness is valid only after each role's dependency graph
   has passed its bounded checks.

## Drain and restart

- Mark the role unavailable to new admissions before sending termination.
- Stop accepting public connections, then wait only for the configured drain
  budget. Revoke or fence every still-open handoff before cleanup.
- Reconcile retained operations after restart. An unknown external outcome is
  never replayed blindly; it must be observed or terminally failed.
- Confirm the loopback probe is ready again and that no migration authority,
  private endpoint, credential, host path, or backend diagnostic appears in
  logs or public responses.

## Restore and rollback

- Restore into an isolated target using the fixed backup order: manifest,
  database base, WAL, object versions, coordination reconstruction, encryption
  keys, authority reconciliation, then controlled cutover.
- Do not cut over from an unverified or same-identity target. Reject missing,
  stale, corrupt, unsigned, or digest-mismatched artifacts.
- Rollback is bounded by the supported version-skew policy and must not reuse
  revoked credentials, stale fencing tokens, or pre-restore capability state.

The current role transport intentionally keeps `/readyz` closed while the
role-specific application graph is absent. Do not override that state with a
probe-only deployment or use it as a production SLO observation.
