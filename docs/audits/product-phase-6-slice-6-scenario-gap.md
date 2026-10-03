# Phase 6 Slice 6 frozen scenario gap (2026-10-04)

This is a work queue against `phase6security.RequiredSlice6Scenarios()` and
`productphase6gate/slice6_plan_test.go`, not a scenario receipt or acceptance
manifest. E7's same-run Product/Guest component pass used a clean E34d72/R884/F884
source trio and exact cleanup. Its 0600 log and limitations are in the
[startup audit](product-phase-6-slice-6-startup.md). No frozen scenario has a
same-run raw receipt from a complete deployment inventory; Phase 6 remains
**5/15**. Every future receipt must bind one new run ID, source/profile,
actual source and target instances, raw probes and cleanup. E7 cannot be
spliced into that new run.

| Frozen scenario | Three required assertions | Existing real signal or scaffold | Missing direct same-run probe |
| --- | --- | --- | --- |
| `browser_cdp_and_capacity_replay` | `real_cdp_version`; `finite_capacity`; `same_authority_replay_denied` | Browser backend real-CDP component; frozen route | CDP command, capacity denial and authority replay on the final Browser/executor edge |
| `browser_external_witness_isolation` | `distinct_external_identities`; `grant_isolation`; `restore_domain_isolation` | Source-bound PostgreSQL/Valkey image supply and role policies | Separate Browser witness SQL and Valkey roles, negative grants and independent restore domains |
| `cross_role_and_tenant_denial` | `wrong_peer_denied`; `wrong_route_denied`; `cross_tenant_denied` | Frozen trust-edge mapping | Actual mTLS/route/tenant substitution attempts against final Provider edges |
| `desktop_media_input_and_cleanup` | `broker_in_parent_observed`; `real_rtp_and_input`; `exact_dynamic_cleanup` | Earlier signed-broker/real Desktop component gates | Parent broker identity, RTP/input and dynamic cleanup within the final deployment run |
| `direct_egress_and_metadata_denial` | `role_direct_ip_denied`; `metadata_denied`; `alias_only_egress` | Egress-broker and policy components | Real Product role direct-IP, metadata and allowed-alias probes under final network policy |
| `dns_rebinding_and_alternate_path_denial` | `rebinding_denied`; `alternate_path_denied`; `dns_receipt_observed` | Pinned CoreDNS archive and DNS checker components | Actual rebinding and alternate-path attempts with DNS receipt on the final egress edge |
| `external_dependency_loss` | `witness_loss_closes_admission`; `capacity_loss_closes_admission`; `bounded_recovery` | E7 Product SQL loss/recovery is a different edge | Browser action-history PostgreSQL and capacity-Valkey loss/recovery while Browser ingress lives |
| `guest_auth_and_reconnect` | `signed_challenge_welcome`; `binding_revoke_denied`; `upgraded_socket_drain` | E7 Guest ready, durable revoked/empty-nonce readback and 503/exit-1; no direct lifecycle receipt | Bind accepted signed hello/welcome, original upgraded socket closure, and a fresh old-identity attempt rejected *because of* revoked binding, with Product/PG/agents healthy |
| `least_privilege_active_probes` | `complete_container_inventory`; `effective_uid_gid`; `seccomp_capability_mount_limits` | E7 inspects a subset of actual containers | Complete frozen inventory and active UID/GID/seccomp/capability/mount checks for every deployment |
| `mtls_identity_and_downgrade_denial` | `wrong_certificate_denied`; `plaintext_denied`; `legacy_downgrade_denied` | Real managed mTLS component paths | Three negative client attempts on the final Gateway/Provider private edge |
| `policy_authority_loss_and_revocation` | `authority_loss_closes_egress`; `revoked_policy_denied`; `fresh_state_required` | Policy-authority/broker components | Live Product egress authority-loss, revoke and stale-state denial |
| `provider_and_executor_restart` | `distinct_process_instances`; `retained_authority`; `stale_admission_denied` | Earlier independent role/backend components | Actual Provider and executor replacement, retained authority readback and stale admission denial |
| `resource_exhaustion_denial` | `bounded_product_requests`; `bounded_gateway_connections`; `bounded_workers` | E7 host/Docker capacity interlock is test safety, not role saturation | Finite Product/Gateway/worker saturation and recovery on final roles |
| `revoked_leaf_and_crl_rollback_denial` | `vault_revoked_leaf_denied`; `active_socket_drain`; `crl_rollback_denied` | E7 terminal revokes at shutdown, not an active peer test | Live Vault leaf revoke, timed upgraded-socket drain and stale/rollback CRL rejection |
| `role_and_controller_drain` | `bounded_sigterm`; `active_socket_close`; `exact_lease_socket_cleanup` | E7 controller quiesce plus exact component cleanup; sticky local revoke failure remains | Timed Browser/Desktop role drain, active socket closure and complete lease/socket cleanup |
| `vault_pki_rotation_and_loss` | `fresh_issue_and_overlap`; `live_rotation`; `loss_closes_admission` | E7 root trust cutover and managed leaf issuance | Concurrent old/new leaf overlap, live rotation and Vault-source-loss admission denial |

## Guest-edge observability and remaining live proof

`guestagent.Agent.Ready` is true only after a signed hello and validated
welcome, so E7's connected Guest `/readyz` is useful client success evidence.
But the role readiness also depends on material and CRL health. Before the
optional receipt change, every welcome-read error became `ErrUnauthorized`,
the Hub's `CloseNow` had no lifecycle receipt, and the PostgreSQL store
returned the same `ErrForbidden` for revoked state and invalid signature.
E7's 503/exit 1 and durable SQL row therefore remain insufficient to prove
the cause or the original upgraded WebSocket's closure. The new hooks address
those ambiguities only when captured from a newly built and independently
verified Product/Guest PID1 pair in the same run.

E-only networkless Docker probes confirm `docker start -a` can capture bounded
canonical receipts with `--log-driver=none` and classify exact container exit
0/3 independently; the disposable non-root, read-only, no-network Alpine
containers clean by exact label. This proves the collector carrier and exit
classification, not a Product/Guest lifecycle signal or production evidence.

The current E-only collector additionally requires an explicit private,
persistent root and an exclusive run-ID subdirectory. Its read-only verifier
reopens bounded Product/Guest raw files, the canonical fixture mutation
receipt and source/image/config binding; a disposable test directory is not
durable component evidence.

The options considered with Sandbox were:

1. Existing `/readyz`, PostgreSQL row, container/agent fingerprints and
   read-only `/proc/net/tcp` or Docker inspect: no R rebuild, but cannot
   distinguish business denial from transport/CRL loss or tie an original
   upgraded connection to a fresh denied attempt. Reject as final proof.
2. Sandbox-approved **minimal closed lifecycle receipt** from the existing
   Product Hub/Authenticator and Guest Agent, captured from each exact PID1
   by an E-only bounded `docker start -a` collector while keeping Docker
   `log-driver=none`. Correlate both sides by a domain-separated SHA-256 of
   validated canonical `AuthRequest.SigningBytes()`, which includes both
   challenge and client nonce; neither nonce nor signed bytes are emitted.
   Product separates signed authentication, welcome write, peer installation,
   authority-stale observation, actual first `CloseNow` completion and a
   fresh same-transaction signature-validated revoked-row rejection. Guest
   separates hello write, welcome validation and read-loop/transport
   termination. Every event has a closed protocol, sequence, event kind,
   attempt digest, binding generation and bounded in-process elapsed/wall
   time. The Gate
   binds the stream to its exact Docker container ID and run ID; it retains
   no raw frames, keys, tokens, signatures or addresses. The exact fixture
   receipt, including its private Guest/container identifiers, stays only in
   the operator-owned 0700 evidence run for independent verification; it is
   not a stable API, runtime mount or routine diagnostic output.
   `product/adapter/postgres/guest.go` must distinguish a validated signature
   on a revoked row from invalid signature and store unavailability without
   changing admission. `guestagent/hub.go` and `guestagent/agent.go` provide
   lifecycle hooks; Product/Guest production composition supplies a bounded,
   nonblocking writer. The E collector rejects gaps, duplicates, overflow,
   timeout, source/instance drift and missing healthy controls. The callback
   must never block the Hub or change handshake timing; lost receipt makes
   evidence unavailable, not admission success. No new network principal,
   credential, socket, mount, TTL or Provider Contract field is needed.
3. A dedicated private Unix receipt socket or writable evidence volume could
   persist events without attaching stdout, but adds a mount, protocol,
   reader authority and cleanup surface to the frozen profile; it is not a
   smaller first change. A new public/private HTTP diagnostic endpoint would
   be a larger security boundary and is rejected here.

Option 2 changes runtime R, even though no wire API changes. It requires a
new clean R/F checkpoint and rebuilding/rechecking the source-bound twelve
role candidates and Desktop candidate (and any changed fixture digest), not
relabeling R884 images. Production stdout exposure depends on deployment
logging policy, so the event schema must be metadata-only and opt-in under a
closed private profile, with strict line/count ceilings and no arbitrary
logging fallback. Attached collectors can lag, disconnect or cancel; the
nonblocking bounded queue must fail closed for evidence and be joined on
role drain, never hold connection callbacks or retain secret buffers. Rollback
is to remove the optional receipt emission/collector and keep the existing
runtime behavior and E7 component boundary, with no schema or Provider
Contract migration. Sandbox has since authorized this exact bounded runtime
implementation and no-issuer component verification, but **not** another
issuer run. The optional v3 config switch, both process hooks, same-transaction
PostgreSQL classification, closed receipt writer and strict stream verifier
now exist. The E-only `docker start -a` collector opens 0600 bounded captures
under the persistent 0700 run root before Product/Guest PID1 startup, waits
for exact Guest running PID1 within the existing 45-second budget, checks
stopped/exit/OOM/image identity, verifies both closed streams against
source-derived config/Profile digests, and joins accepted/closed and fresh
validated-revoked signed attempt digests. It stores E/R/F source, candidate
image, fixture mutation and raw-byte bindings only after both streams pass.
This path has passed no-issuer Docker and causal-drift tests but has
**not** run with the real Product/Guest pair. Pinned arm64 Docker proves normal non-TTY attach and a deliberately
unread attached-output writer cancellation/join; real isolated PostgreSQL
proves the signed revoked positive and wrong-signature/capability/generation/
expiry negatives. A separate no-issuer real PostgreSQL + Hub + Agent component
test passes ten consecutive race/shuffle iterations: one accepted signed
attempt is installed, a real `RevokeGuest` closes that connection, and a new
signed retry is rejected by the original joined-row transaction with the
same attempt digest observed on both sides. Its isolated PostgreSQL container
was removed by exact ID with zero matching labels. This is not an actual
source-bound Product/Guest PID1 run. The new R/F candidate still must be built and audited; the
E collector must then observe actual source-bound Product/Guest PID1 streams,
and the full run must pass all 16 scenarios with a strict manifest.
None of these component results advances Phase 6 beyond **5/15**.

Sandbox rejected the first `72ffa6d` R checkpoint for an unjoined-producer
`seal` race and E's disposable raw capture. R now joins Product's actual Hub
handler/monitor/auth paths and Guest's Agent lifecycle before sealing under
the inherited shutdown context, aborting on cancellation or timeout. E
requires `SANDBOX_RUNTIME_PHASE6_SLICE6_RUN_EVIDENCE_ROOT` before issuer
allocation; failure retains bounded raw files plus `incomplete.json`, never
an accepted disposition. Deterministic handler/monitor/writer tests, a real
Linux Docker abort probe, directory/file replacement, tamper, identity,
overflow and sync-failure negatives, and the no-issuer attached Docker probe
pass locally. The `72ffa6d` role/Desktop images are preserved only as
**unaccepted diagnostic** artifacts. A clean corrected R/E checkpoint, fresh
R/F rebuild, independent review and newly authorized same-run gate are still
required. Phase 6 remains **5/15**.
