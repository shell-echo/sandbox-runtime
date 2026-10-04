# Phase 6 Slice 6 frozen scenario gap (2026-10-04)

This is a work queue against `phase6security.RequiredSlice6Scenarios()` and
`productphase6gate/slice6_plan_test.go`, not a scenario receipt or acceptance
manifest. Historical E7 used clean E34d72/R884/F884. A later independently
reviewed component at clean E `f49ee748f5e8790cd58c62d04bc5304b1a363b49`
and R/F `c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635` passed the bounded
real Product/PostgreSQL/Guest business-binding revoke path in run
`20efb6c95a0fa39cb0441f580a86888f`. Its private receipts and limits are in
the [startup audit](product-phase-6-slice-6-startup.md). No frozen scenario has a
same-run raw receipt from a complete deployment inventory; Phase 6 remains
**5/15**. Every future receipt must bind one new run ID, source/profile,
actual source and target instances, raw probes and cleanup. Neither E7 nor
either accepted bounded component can be spliced into that new run.

Update 2026-10-05: fixed delivery step 1 is now closed by the independently
accepted bounded Guest recovery E component, run
`550dba360065dce4f46fa14476225ce5`, clean E
`a065277e406bf09c4c22d4ce187e1d181e513316`, R/F
`e5816d0d3de0541bd9a677560096b3527f58f7b9`, private final binding
`sha256:e66dc29a217c82e1ae9071b8046c33461afae8d216e488751c9a68e312549177`.
It proves the real Product/PostgreSQL/Guest loss/recovery and ordered A→B
replacement with a 119-file/14-slot terminal/cleanup binding. It does not
alter any row's missing *direct same-run final-topology probe* below. The
certificate controller's `sticky_credential_revoke` remains an explicit
clean-drain gap; the full 78-deployment/16-scenario run has not occurred.

| Frozen scenario | Three required assertions | Existing real signal or scaffold | Missing direct same-run probe |
| --- | --- | --- | --- |
| `browser_cdp_and_capacity_replay` | `real_cdp_version`; `finite_capacity`; `same_authority_replay_denied` | Browser backend real-CDP component; frozen route | CDP command, capacity denial and authority replay on the final Browser/executor edge |
| `browser_external_witness_isolation` | `distinct_external_identities`; `grant_isolation`; `restore_domain_isolation` | Source-bound PostgreSQL/Valkey image supply and role policies | Separate Browser witness SQL and Valkey roles, negative grants and independent restore domains |
| `cross_role_and_tenant_denial` | `wrong_peer_denied`; `wrong_route_denied`; `cross_tenant_denied` | Frozen trust-edge mapping | Actual mTLS/route/tenant substitution attempts against final Provider edges |
| `desktop_media_input_and_cleanup` | `broker_in_parent_observed`; `real_rtp_and_input`; `exact_dynamic_cleanup` | Earlier signed-broker/real Desktop component gates | Parent broker identity, RTP/input and dynamic cleanup within the final deployment run |
| `direct_egress_and_metadata_denial` | `role_direct_ip_denied`; `metadata_denied`; `alias_only_egress` | Egress-broker and policy components | Real Product role direct-IP, metadata and allowed-alias probes under final network policy |
| `dns_rebinding_and_alternate_path_denial` | `rebinding_denied`; `alternate_path_denied`; `dns_receipt_observed` | Pinned CoreDNS archive and DNS checker components | Actual rebinding and alternate-path attempts with DNS receipt on the final egress edge |
| `external_dependency_loss` | `witness_loss_closes_admission`; `capacity_loss_closes_admission`; `bounded_recovery` | E7 Product SQL loss/recovery is a different edge | Browser action-history PostgreSQL and capacity-Valkey loss/recovery while Browser ingress lives |
| `guest_auth_and_reconnect` | `signed_challenge_welcome`; `binding_revoke_denied`; `upgraded_socket_drain` | Run `20efb6c95a0fa39cb0441f580a86888f` proves the bounded live business revoke; accepted bounded E run `550dba360065dce4f46fa14476225ce5` also proves real PostgreSQL loss/recovery and ordered A→B replacement/close with terminal binding | Repeat the three fixed assertions in the final 78-deployment/16-scenario run and bind that run's raw receipt; independently prove peer TLS revoke and CRL-source loss in the complete Guest edge |
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
Before the third issuer attempt, this path had passed no-issuer Docker and
causal-drift tests but had **not** run with the real Product/Guest pair. Pinned
arm64 Docker proves normal non-TTY attach and a deliberately unread
attached-output writer cancellation/join; real isolated PostgreSQL
proves the signed revoked positive and wrong-signature/capability/generation/
expiry negatives. A separate no-issuer real PostgreSQL + Hub + Agent component
test passes ten consecutive race/shuffle iterations: one accepted signed
attempt is installed, a real `RevokeGuest` closes that connection, and a new
signed retry is rejected by the original joined-row transaction with the
same attempt digest observed on both sides. Its isolated PostgreSQL container
was removed by exact ID with zero matching labels. That no-issuer test was not
an actual source-bound Product/Guest PID1 run. The later clean R/F candidates
were rebuilt and audited, and the E collector observed actual source-bound
Product/Guest PID1 streams in accepted component run
`20efb6c95a0fa39cb0441f580a86888f`. The full deployment run must still
pass all 16 scenarios with a strict manifest.
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
**unaccepted diagnostic** artifacts. The subsequent corrected clean R/F and E
checkpoint and source-bound rebuild passed independent review; first E491 and
then E5a real receipt attempts failed, each retaining only incomplete files.
The third, separately authorized E
`f49ee748f5e8790cd58c62d04bc5304b1a363b49` and R/F
`c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635` attempt passed only the
bounded live business-binding revoke component with four independently reread
private files and exact cleanup. Neither failed run is relabeled, and no
release scenario receipt or manifest was issued. Phase 6 remains **5/15**.

## Guest PostgreSQL-loss/replacement A′ candidate (unaccepted)

Sandbox approved a narrower Product-alive PostgreSQL-loss/recovery path and
ordered replacement only after exact old PID1 stop and nonce release. It did
not approve a durable owner/epoch takeover or a crash-plus-database-outage HA
claim. The current uncommitted runtime candidate pre-reserves the configured
Guest connection capacity before authentication can commit, retains a
process-local old-owner pin across a signed connected-row query, and sends a
fixed empty-reason WebSocket 1013 only for definite pre-commit dependency
unavailability or a fully validated `connected_busy` row with that exact local
owner. Unknown commit, orphan ownership, invalid signature, revoked binding,
generation/expiry drift, and protocol denial stay fail-closed.

After an authenticated transport is marked pending in memory, the candidate
closes it before one bounded worker attempts an exact old-nonce PostgreSQL
retirement. An unknown write response switches to readback-first
reconciliation; a disconnected readback is only `already_inactive`, not proof
of an exact `released` CAS. The worker uses the existing Product pool, one
connection at most, a one-second attempt budget, finite retry/backoff and a
terminal red hold on exhaustion, supersession or failed close. Product private
admission and public readiness combine the original dependency status with
the cleanup/capacity state. This cleanup also runs with private receipts off.

New candidate-only private receipts use the separate closed
`sandbox-runtime.phase6-guest-receipt.v2` protocol. The v1 writer/verifier and
historical receipts are not broadened or relabeled. V2 records actual 1013
retries, authority-query loss, pending-before-close, completed close and
retirement disposition; its strict per-stream and Product/Guest pair verifiers
reject missing, reordered, unmatched or wrong-generation events. A local
source-bound E-only multi-PID1 collector and its fault/restart/process/raw
evidence binder are **not yet complete**. The earlier v1 E reader correctly
rejects new v2 streams; it is not a fallback.

The subsequent runtime correction also binds failed 1013/1008 closes to the
remaining original handshake deadline and actual hijacked-transport close,
without adding a fresh close budget. Receipt-off Product shutdown closes
admission and joins Hub handlers and the retirement worker even when the
underlying transport shutdown reports an error. A controlled welcome-write
failure proves pending-before-close, actual close confirmation, exact nonce
retirement and no peer installation. A separate E-only no-issuer Docker drill
captures four real PID1s into four bounded 0600 v2 files under one 0700 run,
then checks actual container/PID/start/finish/image/exit identity and exact
run-label cleanup. Its v2 marker remains `incomplete`; synthetic begin/seal
streams are collector-mechanism evidence only, not Product/Guest recovery or
replacement evidence. The same-run PostgreSQL fault, authoritative old-nonce
readback, ordered stop/start, source-bound raw pair verification and persistent
v2 binding remain open.

Sandbox also approved a narrow E/operator read-only PostgreSQL readback using
the existing local `postgres` peer account, without adding a runtime SQL
principal, network, DSN, grant or HBA change. The current fixed-query helper
checks the exact run-owned PostgreSQL ID, image, UID 70, live PID/start time,
config/data mounts and unchanged process fingerprint; it reads only the exact
Guest row's state, nonce-nullness and DB-time expiry, and confirms the named
SQL backend exited. A real disposable no-issuer PostgreSQL drill passes
connected, disconnected/null and missing/duplicate/expired-row cases. This is
operator-superuser observation, not least-privilege evidence. The disposable
`network=none` drill does not validate the source-derived nine-network map or
mounted HBA, so it cannot bind the formal E run or prove CAS release.
The observer now creates two individual Docker execs per readback, requires
each exact ID to be stopped with exit code zero, uses a fresh bounded
operation name and fail-stops the run on an uncertain exec. This closes the
component's CLI-return ambiguity but does not replace the missing formal
source/network/HBA and recovery ordering proof. A separate formal-only
constructor now rejects a missing Profile/graph and demands the nine
source-derived isolated networks, stage-specific dialer membership and PG
endpoint IDs/IPs, mounted HBA, final PostgreSQL PID1 and effective TLS/HBA
settings. Bounded A′ has one live Product dialer, one successfully exited
Product migration job with exact ledger and original-ID removal, and seven
not-started PG dialers;
it does not pretend all nine are running. The formal reader also demands
unchanged process/HBA, an effective-settings/postmaster recheck and four
distinct SQL states with original expiry. The source collector now persists
bounded same-run network/HBA/settings, PostgreSQL PID1/volume/map, Product
PID1 and full Product network projection, container inventory, migration exit/removal, and before/after ledger
bytes with whitelisted SQL exec terminal observations. The validator
reconstructs the nine-edge proof from those files and the frozen source.
A synthetic positive and self-consistent-but-wrong ledger/network/PG
fingerprint negatives pass; a real same-run positive remains open.
An E-only no-issuer Docker drill now exercises the bounded Guest–Product
isolation action with two independent live PID1 containers: it checks the
original run-owned isolated Product and Guest-runtime network IDs/IPs,
detaches only the Guest–Product edge, retains both PIDs and Guest's runtime
edge, then reconnects that same edge at its original IP. Wrong edge,
duplicate detach and duplicate restore are rejected, and exact run-labeled
cleanup succeeds. This tests the approved intervention's mechanics only;
it does not supply the prerequisite Product/Guest PostgreSQL-loss close
receipts, SQL release observation or signed same-Guest recovery.
The live attached v2 collector can now take an inode-checked bounded prefix
snapshot while PID1 is running, reject partial/invalid lines, and trigger
only after the same initial attempt has Product's actual dependency-loss
close and Guest's read termination. A two-PID1 no-issuer Docker drill passes
this trigger without sealing or publishing evidence; a controlled partial
write and wrong-event negatives pass. The final closed raw streams must
still be reread and verified, and the trigger must still be joined to the
actual PG fault and the approved network action in one E run.
The SQL observer now persists each stage's bounded row/backend/settings stdout
and read/check/settings Docker API terminal projection under fixed 0600 names
in the same 0700 v2 run. Duplicate stage, tamper, backend replay and timing
negatives pass. A structural four-stage checker includes a separate final
old-nonce release and rejects different source, PG, target, expiry, execution
order or replayed exec/operation identities. Product migration ledger reads
share the single-worker/same-run-uncertain admission and retain an unknown
exec ID for cleanup.
Both exact network actions now classify lost Docker responses and a failed
first post-action inspect under one non-renewable deadline capped by the
caller's remaining budget and five seconds. A proved
detach is restored at its original IP and never becomes success evidence;
unclassifiable graph outcomes remain incomplete and require exact stop/cleanup.
Real no-issuer Docker injections for both fault edges pass. A sealed-prefix
checker binds the live trigger's byte counts/hashes to the final v2 PID1
files, with synthetic splice, partial and PID-drift negatives. A precleanup
E merger now rereads all four sealed PID1 files, four SQL stages, 23 bounded
source-raw classes and a private E event journal. It checks both v2 causal
pairs, frozen common-core image, distinct role startup configs, source-bound
Product/PG PID/network/retained-edge facts, and the explicit old-nonce final
NULL stage **after A seal and before B start**. The synthetic journal requires
strict event sequence, increasing same-base monotonic elapsed time and exact
source/action/SQL/PID1 references; UTC alone is not its order evidence.
Paired self-consistent wrong PG network/PID or Guest IP, B-stop-only NULL,
event replay/reorder, stage, source, image and config negatives pass. The
derived action before/after projections are persisted as eight fixed private
raw files alongside 32 bounded, whitelisted original Docker process, network,
and PostgreSQL-identity projections. The merger independently replays all
eight action states from those original projections against the frozen source;
same-inode tampering of either derived or original network raw fails. E
call/observed references bind the corresponding original snapshot digest.
No-issuer real Docker drills
now write monotonic call/observed events at the two actual network action
sites; an uncertain CLI response leaves only `call`. The fixed SQL reader
records its operation-specific call before Docker exec, and its formal wrapper
can emit `observed` only after terminal SQL/settings raw is persisted.
The Product/Guest PID1 capture can record B start-call before Docker start,
persist and reread its bounded live-start inspect, then record start-observed
without using the future seal SHA. A no-issuer real Docker drill stops Guest-A
and records exact stop-call, exit-observed and zero-drop-sealed events; it now
checks that normal Product-A stop is refused without the recovered live close.
The E journal now has 29 ordered events: after Guest-A seal and before
Product-A stop, `recovered_close_observed` binds a still-live Product-A v2
open prefix, already sealed Guest-A raw, recovered attempt/generation, and
both exact process identities. Normal Product-A stop rereads the receipt and
both raws; pre-B and final replay require the observed Product prefix in the
final sealed original. Missing close, non-`released` resolution, wrong attempt
or stale prefix fail closed.
The guarded order has also passed a no-issuer real Docker drill using synthetic
v2 PID1 emitters: Guest-A seals first, Product-A emits the recovered close
while still running, the observation is recorded, Product-A then stops, and
final originals replay. Wrong process/attempt and same-inode prefix tamper
are rejected. These emitters are not the real Product/Guest commands and
do not establish the formal same-run E chain. A pre-B admission helper rejects B bindings
before the first B start, rereads frozen A source/action/SQL/PID1, checks
recovered close/release and final NULL, and requires exactly the first 25
monotonic events; its private digest is required again by the eventual
four-PID1 merger. A formal B-start wrapper refuses a missing admission file and wrong 25/27-event
boundary. The admission has only synthetic positive coverage and neither
helper is yet called by a formal same-run launcher. A separate original-resource
receipt saves the two Guest network IDs and empty-network Docker projections
from the full network allocator before members join. Pre-B and final merger
compare those IDs with later source/actions and reopen the original Vault
mount/anonymous-volume identity. A no-issuer Docker drill created the full
network inventory and a Vault-image container, then proved the exact two
original network IDs, Vault ID and both anonymous volumes absent after cleanup.
A private exact-origin-zero receipt additionally binds those original-ID
absence responses to precleanup and Docker-zero digests; its positive and
wrong-ID negative are synthetic so far. These separated mechanisms are not a complete real
E orchestration; the whitelisted Docker projections have not yet been
collected and replayed in the required one-run source→action→SQL→PID1 chain.
The separate Docker-zero component now binds both exact absent anonymous
volumes to bounded original Vault mount and anonymous-label projections;
a no-issuer real Docker create/remove/recheck passes. This is not terminal
zero across non-Docker resources or an accepted E disposition. The real
same-run merger, terminal cleanup binding, E/R/F freeze and authorized issuer
run remain open.
The Product receipt, actual close and source-bound PostgreSQL fault/recovery
must still be observed together. The v2 pair verifier now permits exactly two
signed attempts when pending capacity returns HTTP 503 before WebSocket
Accept; any observed 1013 still needs its own exact two-sided match. None of
these component results changes the **5/15** count.

The terminal-zero gap is now explicit: a summary-only v2 receipt cannot be
independently replayed once the one-shot operator revokes itself. Sandbox
approved private input/evidence v3 over the same exact v2 three-certificate,
two-accessor plan. The operator's existing Vault exchanges now have a
whitelisted bounded response collector and a single canonical stdout line;
the host's optional v3 runner captures stdout separately from fixed-stage
stderr and can persist an inode-checked private plan, raw line and source
binary/container binding. Offline replay verifies token lookup and exact
absence responses, certificate revoke state/time, issuer DER, complete signed
CRL DER and three serials, CRL config, 204 empty-body revocations and receipt
order. Synthetic response and rejection tests pass, including oversized
transport and nonempty 204 rejection. The v3 diagnostic sink has **no E
precleanup digest** and is rejected by the formal binding verifier; the
existing clean source binary is v2-only. A new source-bound real Vault v3
observation, formal same-run E binding and terminal-zero evidence remain open.
The v3 opt-in is named `SANDBOX_RUNTIME_PHASE6_SLICE6_TERMINAL_V3_DIAGNOSTIC`:
despite the capability preflight, that full harness may create a Vault issuer;
it is **not** a no-issuer drill and was not enabled here.
No new issuer/signing run or count increment is authorized by these component
tests.

The formal terminal-v3 sink now has a separate constructor that first replays
the same run's sealed E precleanup source/action/SQL/PID1 chain; an arbitrary
digest or the temporary diagnostic sink cannot set its verified-precleanup
state. A terminal-zero **preflight**, not a release disposition, joins that
digest to the independently reopened v3 line/plan/operator binary and
container ID, Docker-zero receipt and exact original network/Vault absence.
It enforces operator exit before Docker-zero and Docker-zero completion before
exact-origin checks, and all four Product/Guest PID1 exits and PostgreSQL
readbacks before operator start. The full E launcher does not yet call this
preflight, and non-Docker terminal classes still need an accepted same-run
merger. At this checkpoint the Go 1.26.8 full repository race/shuffle, tagged
Slice 6 race/shuffle, tagged vet, untagged vet, Product Contract verifier and
diff check passed. The no-issuer recovered-close Docker drill passed again
and left no run-labeled container. These are candidate checks, not a formal
issuer run or accepted E evidence.

The E-only Product and Guest process handles now reuse the component runners'
reviewed create-argument and one-time Guest resource-preparation primitives,
but not their hidden fault, v1 receipt or stop callbacks. They bind A/B to
the first allocator's 78 original network IDs, exact role names, the same
config/socket/storage/anchor identities and the 25-event pre-B admission.
The original-network mapping passed a real no-issuer Docker allocation and
exact cleanup drill. A separate real no-issuer Docker B-PID1 drill confirmed
normal v2 seal, rejection of a mismatched cleanup binding, exact ID removal
and absence, without appending any B-stop event to the frozen 29-event E
journal. These are lifecycle primitives, not the single source-to-terminal E
launcher. That launcher, its same-run formal Vault v3 observation and the
non-Docker terminal-zero merger remain open; the phase count stays **5/15**.

Shared Vault/Controller/PostgreSQL/agent bootstrap network creation sites now
call a typed run-scoped resolver. The legacy source still invokes the strict
create primitive and rejects a pre-existing name; the E source uses only the
first allocator's original manifest, checks frozen spec plus live exact ID,
and never creates a replacement. A disposable no-issuer Docker negative
removes one exact original empty bridge, creates a same-name/same-spec new
bridge, and confirms the E source rejects the new ID before run-owned cleanup.
This is preparatory injection, not a new E
bootstrap test entry: no same-run issuer/bootstrap/29-event sequence has yet
used the E source end to end. The original empty observations are allocation
identities, not later member-state evidence.
The E Product and Guest entry checks now start their existing readiness
budgets before PID1 capture preflight, running inspection and network checks;
the shorter startup context is not the parent of the long-lived attached
stdout collector. A real no-issuer B drill cancels that startup context and
still observes the live collector before sealed shutdown.
An E-only 29-event procedure now calls the formal PG fault wrappers and
recorded SQL/network actions in one fixed order, checks event count and kind
after each live action, derives each accepted attempt digest from both
canonical live v2 PID1 prefixes only after Product peer installation, admits
B only after the 25-event frozen
predecessor, and verifies four sealed PID1 files before exact B removal.
Its order-boundary and missing-source negatives pass, but the procedure has
not yet been invoked by a shared-bootstrap E entry or exercised in a real
issuer run. It is therefore orchestration code, not formal E evidence.
A typed post-bootstrap E entry now validates that the passed original
network map equals the injected bootstrap map, prepares Guest config/storage
once, starts Product-A and Guest-A under v2 attached capture, reconstructs
the nine PostgreSQL service endpoints from original IDs, proves the frozen
A-stage migration/PG source, and calls that 29-event procedure. It rejects
missing original-source authority before Docker. The E-only top-level entry
now calls this procedure inside the shared Vault/Controller/PKI/PostgreSQL
bootstrap and live signer window. It checks capacity and v3 operator capability
before creating the original complete network inventory, switches away from
the old Product/Guest component callback, and wires replayed E precleanup to
the formal one-shot v3 terminal and post-cleanup Docker/original-ID preflight.
A failed E business sequence can only attempt a single v3 cleanup-only
revocation with an incomplete marker, not an accepted terminal receipt. The
arming environment variable is not issuer approval. The host temporary
resource owner now has an explicit seven-directory inode-pinned finish and a
private original-name absence receipt, with real-file replacement negatives.
Attach/writer joins, retained-file verification and external E/R/F freeze
binding remain open; the top-level test deliberately fails closed
after its present terminal preflight. No same-run issuer execution or accepted
source-to-terminal E receipt is claimed.

Reproduce the no-issuer network identity/replacement and B-seal/cleanup
drills from the repository root with local pinned images already loaded:

```bash
SANDBOX_RUNTIME_PHASE6_SLICE6_CREATED_NETWORKS_NO_ISSUER=1 \
  mise exec go@1.26.8 -- go test -tags=phase6slice6gate -race -count=1 \
  -run '^TestSlice6GuestRecoveryOriginalNetworkCreationNoIssuerDocker$' ./productphase6gate
SANDBOX_RUNTIME_PHASE6_SLICE6_B_STOP_NO_ISSUER=1 \
  mise exec go@1.26.8 -- go test -tags=phase6slice6gate -race -count=1 \
  -run '^TestSlice6GuestRecoveryBStopAndRemovalNoIssuerDocker$' ./productphase6gate
```

Both tests use disposable run labels and exact cleanup; neither mints an
issuer, signs a workload certificate or produces accepted E evidence.

Focused race/shuffle tests cover capacity, single-worker/timeout/drain,
post-commit welcome-write failure, local-owner 1013, mixed old/new endpoint
failure, unknown-write readback-first, event order and v1/v2 separation.
The full tagged Product PostgreSQL package passed against a fresh pinned
`postgres:16-alpine` process, including signed busy negatives, exact nonce
release/readback and fresh signed reconnect; its disposable container was
removed. The required full repository race/shuffle passed on a second run,
`go vet ./...` and the Product Contract verifier passed. The first full race
run failed only during one temporary Git fixture's `.git/info` directory
cleanup; its fixed failing shuffle seed then passed 20 isolated package runs.
The writer of that transient file is not established, so the first failure
remains recorded rather than erased. Final source validation must rerun after
the remaining E and runtime edits. No new R/F/E freeze, issuer run, manifest,
release assertion or count increment follows from this candidate work.
