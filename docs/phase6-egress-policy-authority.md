# Phase 6 egress policy-state authority: operator checkpoint

This is a Slice 6 implementation runbook, **not** a production deployment
approval. The full Slice 6 gate and evidence are outstanding; Phase 6 remains
5/15.

One authority process owns exactly one immutable profile policy. Its UID/GID,
signing-public-key digest, broker UID/GID, private Unix socket directory,
managed persistent ledger volume and Current poll/timeout bounds must match
the canonical `phase6-security-profile.v1`. The signing private key enters
only as a mode-0600, authority-owned regular descriptor 3. It must not appear
in stdin JSON, environment, arguments, logs or the broker container. The
broker mounts only its policy's socket directory read-only and holds only the
public key. The ledger volume is mounted only into its authority.

The `egress-policy-state-authority` command accepts one bounded canonical JSON
configuration on stdin. Its `mode` is exactly `initialize`, `serve` or
`inspect`. No mode falls back to another:

1. An operator explicitly runs `initialize` once for an empty managed ledger
   volume. Normal `serve` fails if that ledger is absent or corrupt.
2. `serve` recovers the durable CAS high-water, refreshes active state with a
   higher generation, and answers fresh broker challenges. A revoked ledger
   cannot become active on restart. The broker refuses to listen before its
   first valid Current and polls thereafter; one failed poll drains it.
   The profile pins the maximum age of an active ledger commit. If the
   authority's refresh loop stalls but its socket still answers, it must
   refuse to sign Current once that age is exceeded.
3. To **permanently revoke**, the operator sends SIGUSR1 to this exact
   authority process, waits for a successful exit, then runs `inspect` as the
   authority UID/GID with read-only access to the exact ledger and no signing
   descriptor. Only a successful receipt with the expected policy/profile/
   principal/broker binding, a greater generation, `status=revoked`, committed
   UTC time and ledger digest confirms success. Save that non-secret receipt
   with the operator incident record.

Signal delivery alone is not a receipt. SIGTERM, SIGKILL, authority outage,
failed ledger fsync or a broker that stopped because Current became unavailable
are **not** permanent revocation. `inspect` must fail for an active, absent,
corrupt, swapped or unreadable ledger. After a confirmed revoked receipt,
restarting the authority cannot sign active Current, even if a legacy signed
active state file is present. Restoration of both a trusted ledger and signing
key by a privileged operator is outside this local anti-rollback claim and
requires the independent Slice 14 recovery procedure.

If the SIGUSR1-run process exits nonzero, do not automatically report success
even if a revoked ledger file is visible: a failed directory fsync can leave
visible but unproven durable bytes. Preserve the failure and receipt for an
operator-led recovery decision. Conversely, a zero exit after SIGTERM is not
revocation; the independent revoked receipt remains mandatory.

The tagged Docker checkpoint
`SANDBOX_RUNTIME_PHASE6_POLICY_AUTHORITY_DOCKER=1 go test -tags=integration -run '^TestDockerDistinctUIDPolicyAuthorityAndRevocation$' -count=1 -v ./internal/egresspolicystate`
tests the protocol with distinct UIDs, read-only broker view, wrong-peer
rejection, crash/restart, persistent revoked receipt and exact fixture cleanup.
It uses a deterministic fixture key and a protocol probe, not the production
broker/authority pair, real DNS, all declared principals or retained Slice 6
release evidence.
