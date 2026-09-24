# Product v1 Phase 6 Slice 6 Startup Audit

Date: 2026-09-23

Status: implementation underway. Product Phase 6 remains **5/15**.

Checkpoint 2026-09-23: a distinct signed controller peer-CRL v2 protocol now
binds policy identity, security profile, edge, local principal, direction,
anchor, full issuer DER digest and operator-selected source. The controller
re-authorizes that tuple and persists a shared replay nonce before Vault
access; the agent's v2 adapter resolves only its role's source ID and checks
the signed complete CRL. Both commands now have explicit peer-CRL configuration
versions and private canonical source-file loading; old configurations cannot
silently enable this capability. Canonical-wire, mutation, Unix signed
round-trip and fixed-source Vault component tests pass. This is not yet a
live role handshake/drain or full-inventory gate, so the counter does not move.
Sandbox's follow-up ruling fixes restart semantics: live roles must detect
CRL rollback and revoked-leaf resurrection in memory; a restarted role starts
unknown and must make a fresh online read from the fixed Vault source before
admission. Agent/controller restarts may not reset a still-running role's
watermark. A historical rollback of trusted Vault itself is explicitly outside
this single-cluster Slice 6 claim. No local peer-CRL observation ledger or
extra role-writable volume is authorized.

Checkpoint: signed controller and agent v2 snapshots now carry canonical
collection time; role-side `PeerCRLGuard` checks the actual TLS-verified
leaf/issuer, re-verifies the complete CRL, bounds source age, detects process-
local CRL/source/clock rollback and revoked-to-good resurrection, and starts
not-ready with no inherited good state. The Provider and Gateway private mTLS
handshake callbacks now invoke it after identity verification. A real TLS 1.3
handshake component test admits a good leaf and rejects a revoked leaf.
At that checkpoint, per-connection poll/drain, pre-handshake readiness
bootstrap, all-role wiring and distinct-process evidence remained open.

Checkpoint: Sandbox required zero-peer readiness with an operator-pinned
issuer, not first-peer discovery. The agent v2 snapshot now carries bounded
full issuer DER and signed-source collection time. A private role derivative
of the canonical source mapping binds each required mTLS edge to the complete
issuer digest and the full mapping digest; production Provider/Gateway configs
pin that document and digest. Agent/controller peer-CRL commands pin their
full source-document digest, and agent v2 requests/responses bind it. The
role guard bootstraps a complete signed CRL before any peer, then still checks
the actual TLS-verified immediate issuer and leaf on every handshake.
Provider Contract/private HTTP transports now track active and hijacked
sockets, poll the source and drain on revocation/loss with an exact close
hook; Gateway's outbound Provider transport uses a context-bound TLS dial
and guarded active-connection registry. Readiness invokes an online bootstrap
for both Provider edges and the Gateway outbound edge. Focused race tests pass.
This is component evidence only: full-role rollout, root-only/multi-CA anchor
negatives, real restart/source-loss gate, all-principal network/privilege
observations and the immutable Slice 6 manifest are still open. The counter
remains **5/15**.
An operator-only derivation command now writes the minimal role document as a
new mode-0600 canonical file from independently pinned profile/source inputs;
it refuses to overwrite an existing file. Its subprocess test validates the
generated artifact and absence of Vault locators. This does not create a
production deployment or an all-role configuration gate.

The accepted runtime edge matrix exposed a second configuration omission:
Guest-to-Product, Provider-to-Browser and Provider-to-Desktop were named in
ADR 0055 but absent from the test profile and production v3 composition.
Sandbox ruled that the simultaneous target needs three distinct Provider
process profiles (coding-shell, Browser-only and Desktop-only), not one
aggregate Provider identity. The canonical profile component validator now
requires the separate Product/Gateway Contract/private edges for each exact
Provider instance, the Browser/desktop attach directions only from their
matching Provider instances, Guest-to-Product, and both role-to-backend
edges. It checks the fixed listener, route, tenant scope, private target IP,
isolated two-member network and two CA purposes, and rejects missing or
aliased runtime edges. The test fixture gives each Provider instance a
distinct principal/UID/GID, TLS agent and socket; race-enabled negatives
reject coding-to-Browser attach, Browser-to-Desktop attach, route/target drift
and duplicate aliases. This is still profile/component evidence. Browser-only
Provider production composition, Desktop v3, Product's Guest receiver and
per-instance database/material/admission/cleanup isolation are absent, so
the full graph and Slice 6 evidence remain open at **5/15**.

Checkpoint 2026-09-24: Browser/Desktop role v3 configuration now refuses raw
TLS files and static material selections. Their candidate application graph
resolves only the matching Provider-instance attach edge and the separate
role-to-backend edge from the complete profile, requires a remote signer,
fresh inbound/outbound peer-CRL guards and bounded WebSocket lifetimes, and
tracks upgraded attach sockets through revocation/shutdown. A real TLS/WebSocket
component test verifies hijacked-socket drain. Sandbox resolved a backend
identity omission: each backend server now requires exactly one canonical
profile DNS SAN in addition to the URI and `server_auth` EKU. Profile and
edge-boundary negatives reject missing, multiple, wildcard and IP names;
numeric dialing with pinned TLS ServerName and wrong DNS/URI negatives are
covered by the shared live TLS tests. Agent/controller policy validation
already binds issuance DNS to the profile. This remains code and component
evidence; the complete distinct-process Vault/Docker gate and immutable Slice
6 manifest are absent, so Phase 6 stays **5/15**.

Checkpoint: the 10-second profile drain claim exposed a real scheduling
contradiction: 30-second CRL staleness had produced a 15-second poll interval.
The common guard now derives one total pull deadline and poll interval from
the exact local principal's drain bound; the 10-second candidate caps them at
2 seconds each and budgets the entire connection collection at 1 second.
Provider/role server polling and outbound-client polling share that result.
Permit waits consume the same pull deadline, and an independent expiry timer
closes tracked sockets at the earlier of freshness or CRL validity loss.
Fixed-width parallel closure prevents one slow `Close` from serially blocking
all other sockets, while an over-budget close fails readiness. Component
budget, timeout, early-expiry and slow-close tests pass. This is not measured
Vault publication, scheduler jitter or full-capacity real-process drain
evidence; 10 seconds remains an unproved candidate until the named gate passes.
Guest v3 configuration now also rejects static TLS material and retains one
role-owned Guest signing-key binding. Its candidate outbound client selects
only the canonical Guest→Product `/agent` edge, live signer and peer-CRL
source, with numeric dialing, pinned Product DNS/URI and a bounded WebSocket
lifetime. This does not imply that Product's production private Guest Hub is
composed; that receiver and the complete process graph remain open.

## Corrected premises

The repository does not already enforce Slice 6 merely because TLS 1.3,
`internal/netpolicy`, seccomp files and hardened Browser/Desktop container
options exist. Current production role TLS identities are parsed and frozen at
startup. The generic network-policy library is not the mandatory path for all
role traffic and cannot prevent a process from opening a direct socket. The
Slice 5 process gate intentionally records one host UID. Those facts are
component foundations, not certificate-rotation, network-enforcement or
least-privilege evidence.

The opposite shortcut is also rejected: moving the complete production system
into Kubernetes or platform-specific manifests now would consume Slice 11
without first freezing the portable security contract.

## Reused foundations and open gaps

| Area | Reused authority | Gap that Slice 6 must close |
| --- | --- | --- |
| TLS parsing | `internal/tlsmaterial`, TLS 1.3 transports, exact SAN/EKU and role material registries | Real Vault PKI issuance, role-local key generation, atomic live swap, bounded overlap, CRL/revocation-driven connection drain, outage and clock-rollback closure. |
| Workload credentials | Slice 5 credential controller, renewable leases and agent identities | A separate certificate-controller identity and least-scope Vault PKI policy; no workload may hold CA or arbitrary PKI-role authority. |
| Network policy | `internal/netpolicy` and Browser/Desktop restricted-network provisioner/gateway | Mandatory alias-based broker path for every declared egress edge, role-isolated internal networks and topology proof that direct/raw-IP/DNS/proxy bypasses fail. |
| Runtime hardening | Existing runtime read-only rootfs, drop-all, no-new-privileges, resource bounds and selected seccomp checks | A closed all-principal profile, unique container UID/GID, role-specific seccomp and exact drift/privilege/resource negative tests. |
| Evidence | Slice 4 and 5 immutable/retained verifiers | A Slice 6 manifest binding the full principal/edge/profile inventory to real PKI, Docker network, Browser/Desktop smoke and cleanup observations. |

## Frozen order

1. Add the closed security profile and inventory validator.
2. Add the independent certificate controller, closed signed CSR protocol,
   real Vault PKI adapter, role-local key generation and atomic live TLS
   rotation/revocation path.
3. Add the alias-only egress broker and prove role-isolated Docker topology,
   DNS/metadata/rebinding/direct-socket denial and policy-revocation drain.
4. Enforce unique container UID/GID, read-only filesystem, mounts, capabilities,
   seccomp and resource limits for the complete repository-owned principal set.
5. Run the immutable full-inventory gate, real Browser CDP and Desktop
   media/input smokes, exact cleanup, strict evidence verifier, root race/vet,
   both Contract verifiers, and retained Slice 4/5 verifiers.

The order is fixed by ADR 0055. Focused component checks may establish a
checkpoint but cannot advance the Phase 6 counter.

## Implemented checkpoint: principal-bound PKI and local signers

The repository now has the shared closed `securityprincipal.v1` registry, a
separate `workload-credential.v2` lease/ledger protocol, the signed
principal-bound certificate protocol and a real Vault PKI adapter. Version 2
cannot reinterpret a Slice 5 v1 request or lease. Certificate-controller Vault
credentials are exact-policy scoped; substitution, delegation, mixed-version,
replay, restart, expiry and revocation tests fail closed.

`workload-tls-agent` generates P-256 keys locally, obtains an exact CSR-bound
certificate and exposes only a peer-credential-bound Unix snapshot/signing
capability. Its rotation, overlap, CRL staleness, issuer outage, clock rollback,
replay, capacity, cancellation and exact socket/key cleanup tests pass under
the race detector. A real TLS 1.3 handshake succeeds through the remote signer
without exporting a private key.

The certificate controller now requires a private regular descriptor-5 key
and strictly validates its operator bootstrap certificate before first Vault
use. A tagged real integration starts the fixed-digest Vault image with TLS 1.3
and mandatory client certificates, proves certificate-less denial, performs
the initial PKI operation, closes the bootstrap transport, switches to the
locally generated managed certificate, performs a post-switch CRL operation,
revokes the managed certificate and observes its serial in the authoritative
Vault CRL before exact container cleanup.

The alias-only egress broker is now implemented as an independent principal-
bound process with a closed target protocol, broker-side bounded DNS resolution,
address validation, checked-IP dialing, replay/capacity limits and policy-
revocation drain. Its focused tests use controlled resolvers and dialers; they
do not establish the real topology gate.

A tagged Docker topology checkpoint now starts two distinct-UID/GID Alpine
probe containers on an actual `isolated` internal bridge network, adds the
broker probe alone to a separate uplink and starts a fixture on that uplink.
Docker inspect
and in-container `/proc` probes verify read-only roots, zero effective
capabilities, `no-new-privileges`, active seccomp, configured PID/memory/CPU
bounds confirmed in the live cgroup, exact network membership and broker-only
uplink. Direct connections from the protected probe to the fixture IP and a
public IP fail, while the dual-homed probe reaches the fixture; exact run-owned
containers and networks
are removed and checked absent. The fixture and broker probe are **not** the
real egress-broker binary or the complete role inventory. The test does not
prove role-specific seccomp, resource exhaustion, DNS rebinding, authenticated
broker transport or all-principal enforcement.

An additional real negative probe exposed a host-gateway bypass:
Docker 29.7.2 allowed a container attached **only** to a `--internal` bridge to
connect to that bridge's gateway (`172.20.0.1`) where a disposable host-network
fixture listened on port 18080. Thus the internal bridge alone does not enforce
the ADR's no-direct-socket claim against host services. The exact probe
containers and network were removed and checked absent. Sandbox ruled that
every role/trust-edge network must use the Docker `isolated` IPv4 gateway mode,
with IPv6 disabled until separately proven. The updated tagged test now
reproduces the ordinary-bridge bypass with the same host fixture, then proves
the fixture is reachable from the uplink but not from the isolated role via
the former internal gateway, another bridge gateway, Docker host aliases,
public IP or metadata IP. It also proves the role can reach its declared
broker probe. Network inspect confirms `isolated`, no host gateway, exact
members and disabled IPv6; live probes confirm no default route/IPv6 address.
This remains a topology checkpoint using probe processes, **not** the real
egress-broker binary or all-principal network-complete evidence.

The closed observation validator rejects principal/image/UID/GID/seccomp,
resource, network and cleanup drift, including resource-controller digest
substitution and container-ID reuse. A bounded Docker-network-inspect importer
now extracts exact driver, gateway mode, subnet, host-gateway absence, IPv6
state and member container IDs and binds the raw inspect document by digest;
the tagged topology checkpoint exercises that importer against the live
daemon. Unit fixtures remain synthetic, and the active probes do not yet
produce retained raw receipts tied to every repository principal. This is not
the full Docker collector or release evidence. The complete least-privilege
inventory and immutable Slice 6 evidence gate remain open, so Phase 6 remains
**5/15**.

The policy-revocation component now has a closed Ed25519 state protocol,
operator-owned single-writer atomic/fsynced CAS ledger, independent authority
command, challenge/response Unix Current protocol and production broker
startup/continuous polling path. The broker does **not** read a state file:
it refuses to listen before a fresh signed online
Current, then polls at a profile-bound interval and revokes/drains on the
first invalid, unavailable, rolled-back or revoked response. Each policy is
bound to a distinct controller principal, key digest, socket and managed
persistent ledger volume in the canonical security profile. Component tests
cover replay, restart high-water, old active versus committed revoked state,
peer credentials, stale active-ledger refusal, failed revocation commit without
a receipt, healthy refresh, online revocation and live TLS tunnel
drain. A tagged Docker checkpoint runs the authority protocol in a real
container under UID/GID 20001:30001 and its client under 20002:30000 with
only a read-only managed-volume view. It observes active Current, abrupt
authority death, SIGTERM/SIGKILL without false permanent revocation,
safe same-owner stale-socket recovery on restart, signed
revocation, revoked restart despite restoration of an old audit snapshot,
authority outage denial, wrong-UID peer rejection, broker denial on reading
the private ledger and exact fixture container/volume cleanup. A separate
read-only authority-UID process verifies the committed revoked generation,
binding, timestamp and ledger digest; a crash with active ledger fails that
inspection. The fixture
embeds a deterministic test key in a shared test binary; it does **not** prove
production signing-key isolation. It calls the protocol package directly and
is **not** the production
broker/authority pair or a full Slice 6 gate. The obsolete file monitor and
snapshot-file publication path were removed; a legacy signed active file is
ignored in the restart test. The profile
exception for one authority-private
managed persistent volume is explicit; broker and business roles have no
ledger access or host-path bind mount.

This is still **not** an independent authority/broker OS-process or Docker
gate. Distinct UID/GID socket directory/mount behavior, real broker and
authority restart/failure isolation, all-principal hardening, retained raw
topology receipts, full DNS/egress negative matrix and strict Slice 6 evidence
are outstanding. Privileged operator restoration of both key and ledger is
outside this local trust claim. Phase 6 therefore remains **5/15**.

A subsequent tagged Docker checkpoint builds and runs the actual
`egress-policy-state-authority` command under its profile-bound UID/GID,
with a private descriptor-3 signing key and managed ledger/socket volumes.
It proves explicit initialization, fresh signed Current to a distinct-UID
client, wrong-UID and private-ledger denial, SIGTERM and SIGKILL recovery
without a false revocation receipt, safe stale-socket recovery, SIGUSR1
successful exit, a separate read-only `inspect` receipt, revoked restart
rejection and exact run-owned cleanup. This test exposed and fixed a
production public-key type comparison that had rejected a valid signing key.
The client is a Current-protocol probe, **not** the production broker; this
checkpoint does not establish the full Slice 6 gate. The next production
broker test exposed the role-local TLS agent's old 0700 parent and 0600
socket permissions: distinct agent and broker UIDs could not traverse or
connect. Sandbox ruled a closed v2 production layout.

Sandbox retained `workload-tls-agent.v1` wire messages but mandated a closed
production config/socket layout v2. The shared implementation now creates an
agent-UID-owned, role-GID 0710 parent with an agent-UID-owned 0666 socket,
checks exact ownership/modes and stable path inode, verifies peer UID/GID
before reading, and actively closes accepted connections on cancellation.
Half-frame read timeout, replay/capacity and permission-drift tests pass under
the race detector. A tagged Docker test starts the real signing listener
and client package code in separate agent/role processes with different
UID/GID, verifies certificate snapshot and ECDSA remote signature, denies a
wrong UID, wrong GID and extra role, then proves agent-loss denial and exact
container/volume cleanup. Its issuer is a test fixture and its client is not
the production egress broker. Profile-bound socket mounts/trust edges for
every role and executor, full production broker TLS/DNS mTLS, and the Slice 6
gate remain outstanding. Phase 6 remains **5/15**.

The key-owner audit found a second independent gap: the existing eight
`material_agent` identities are Vault KV/credential processes, not separate
TLS-agent processes. The private principal registry now has a distinct
`tls_agent` kind, and the certificate delegation matrix permits only one
exact TLS agent per runtime/executor/registered broker subject plus the
certificate controller's internal managed-signer exception. TLS agents are
denied by the v2 Vault-credential issuance matrix even when a backend policy
is configured. This is a registry/PKI component checkpoint, not a complete
profile inventory or a migrated runtime TLS path. The detailed ownership
inventory is in `product-phase-6-tls-key-ownership.md`.

A full race/shuffle run also exposed a real authority timing race in the
online revocation test: the socket handler sampled time before waiting for
the ledger lock, then compared that old instant with a just-committed revoked
record. The live Current path now samples its clock while holding the same
lock as the ledger read; a deterministic pre/post-commit regression and 100
repeated race-enabled broker revocation tests pass. Unbounded package
parallelism on this host repeatedly delayed local WebRTC ICE/media assertions
and exposed a separate Close/Recover test that incorrectly equated one CAS
effect owner with one observer of the final durable state. The data-path
tests now have test-only admission/event budgets; the CAS test checks exact
effect counts and permits both callers to observe the committed outcome.
The root `go test -race -shuffle=on -count=1 ./...` completed with exit 0
under `GOFLAGS=-p=4`, without concurrent Docker tests. This is a reproducible
host-concurrency condition, not a default-parallelism claim or the Slice 6
release gate.

The earlier single-Provider profile checkpoint required eight static TLS-agent deployments
and one additional agent for each registered egress broker. Each binding
checks both principal digests, separate process UID/GID, the exclusive
private socket storage and read-only subject mount, 0710/0666 socket layout,
one subject-to-agent Unix edge, issuer policy/Vault role and cleanup class.
Agent/subject substitution, mode/path drift, missing binding and third-party
mount sharing fail closed in race-enabled profile tests. The production TLS
agent now reads that profile before its signing key and rejects a self-
submitted requester, subject, issuer or socket mapping; the egress broker
checks the same subject binding before opening its TLS-agent client. This is
configuration/component evidence only. Other runtime and executor commands
still use local TLS key material, and there is not yet a real production
broker→agent→controller→Vault→DNS/mTLS gate. Phase 6 remains **5/15**.

Sandbox then identified the reverse trust edge that the first binding did
not close: TLS-agent configs could independently select the certificate-
controller endpoint, peer and response key. The profile now declares one
controller authority and an exclusive agent→controller Unix endpoint per TLS
agent, plus an explicitly separate managed-TLS self endpoint. It binds the
controller response key and each agent's CSR request key by purpose-separated
public-key digests. The TLS-agent command checks these fields before opening
its client; the certificate-controller command uses the same validated
profile-derived registry (including dynamic broker agents) and rejects a
missing/extra/substituted listener or policy set. Its production config is
v2, with no v1 production fallback. The shared Unix inode/ownership and
connection tracker replaced the old PKI socket `chown` and unbounded first-
frame/close behavior. Targeted race tests pass. A tagged Docker gate now runs
one controller and two agents under three distinct UID/GID pairs, with
separate controller-owned/agent-group 0710 directories and read-only agent
mounts. Both agents issue and renew strict CSR certificates, revoke and read
CRLs; cross-agent, wrong UID/GID and wrong controller-response key are denied;
a half-frame peer times out; cancellation and exact run-owned container/volume
cleanup are observed. This gate uses a repository-private test CA rather than
the production certificate-controller command or Vault. The full
broker→agent→controller→Vault→DNS/mTLS process graph is still outstanding, so
this is not a Slice 6 release gate and the count remains **5/15**.

The Browser/Desktop executor production TLS constructor now uses a neutral
live TLS 1.3 signer builder instead of the Provider transport helper. It binds
both directional CA pools to the same validated profile, checks the exact
profile URI/DNS/EKU/TTL and P-256 signer proof for each new handshake, disables
server session tickets, and refuses a missing or failed signer. Focused
race-enabled handshakes prove generation swap, signer loss, issuer/identity/
usage drift, extra peer SAN/EKU, expired leaf, and public versus mutual TLS
semantics. These are component tests, not the production distinct-UID graph.
The same unpublished backend authority v2 is now tightened with pinned
peer-CRL role/source digests in both real command entrypoints. Each command
verifies the derivative role document before constructing a live signer and
inbound peer-CRL guard; remote-signer backend constructors reject a missing
guard, signer probe or bounded connection lifetime. The shared connection
registry retains hijacked WebSockets, polls revocation, drains them on source
loss or revocation, and forgets the exact socket on close. Browser and Desktop
component race tests observe that an accepted mTLS WebSocket closes and the
CDP upstream or Unix broker session closes too, with zero tracked sockets.
Each new `/executor` upgrade also performs a bounded fresh signer/CRL check,
including when HTTP reuses a prior TLS connection; a cached handshake alone
does not admit a new WebSocket after source loss.
This checkpoint also reruns the real pinned Chromium `Browser.getVersion`
integration and the native arm64 Desktop image/X11/RTP broker integration;
both pass and their run-owned containers are removed. These exercise the
backend compatibility path and the Desktop image respectively, not the
unreleased production command/agent/CRL graph.
The static constructor still imports the Provider mTLS file loader for
historical component compatibility; the production remote branch never calls
that loader. These tests do not substitute for the distinct-UID commands,
real Vault CRL and full principal/network inventory gate; the counter remains
**5/15**.
Product now also has an explicit v3 public-listener command path: its material
registry contains only runtime DSN and identity key ring, while the validated
profile, exact public listener, pinned issuer anchor and separate agent
provide TLS identity. The Product transport now accepts an exclusive live
certificate callback instead of requiring a static certificate array; a
mixed callback/static configuration is rejected. Its dependency monitor
rechecks the signer. The v2 path
remains explicit historical compatibility, not an automatic v3 fallback.
At that checkpoint Provider/Gateway/Guest/Browser/Desktop and Product's
internal edges still needed live-signer migration; all existing-connection revocation drain remains
mandatory. No Slice 6 evidence manifest is issued.

The canonical profile now has exactly two closed `public_listeners` bindings:
Product API and Gateway signaling. Each binds the runtime principal digest,
specific TCP listener/port, server issuer anchor and explicit `none` client
certificate policy. The validator rejects a third public listener, an
unbound listener, an optional-client-certificate mode, a client-verification
anchor, or a role lacking server-auth usage. This is profile component
evidence only; Product v3 command composition has not passed a real
distinct-UID process gate, and the public listener's
user/grant authorization remains application-owned.

The profile's earlier global `SeccompDigest` uniqueness check was not a
least-privilege requirement: two separate TLS agents with the same reviewed
syscall needs can use the same digest without sharing UID, GID, key, mount or
network authority. The check was removed while each principal still binds an
exact digest and runtime observation still rejects per-principal drift. A
positive equal-policy regression and the retained seccomp-drift negative
test cover the distinction. The final gate must still inspect actual policy
bytes and denial behavior, not merely a digest-shaped string.

Sandbox resolved the public ingress topology as one operator-owned fixed
TCP relay: it alone joins `public_ingress` NAT and the two separate isolated
Product/Gateway trust networks; the roles have no host publication. The
relay owns no TLS signer, material agent or business secret and cannot select
targets through HTTP, CONNECT, SOCKS, DNS or SNI. The canonical profile now
requires its own principal/UID/GID/image/resource identity and two exact
digest-bound mappings, including frontend and target IPs, networks, host
bindings, ports and per-route limits. Non-relay `ingress_frontend` listeners,
extra relay listeners, role host publication and endpoint drift are rejected.
Every profile network now binds a canonical non-overlapping IPv4 CIDR;
frontend and target IPs must belong to their declared networks, and Docker
inspect must report that exact subnet. The Docker-network importer records
exact member IPv4 addresses, and
the observation validator binds the two relay publications and destination
IPs to the profile. A tagged Docker checkpoint built and ran the actual
`phase6-ingress-relay` command as a distinct non-root process; it exercised
host-published routing through a NAT frontend to two `isolated` networks,
inspected exact relay-only publication/network membership and UID/capability
bounds, observed upstream loss and restart, and verified exact run-owned
container/network/volume cleanup. The upstreams were fixed-response Alpine
`nc` probes, not the Product/Gateway commands. This proves neither TLS/user
or grant authorization through ingress nor WebRTC ICE/UDP/media delivery,
all-principal seccomp/resource enforcement, or the final release graph.
Phase 6 remains **5/15**.

A further component checkpoint imports raw `docker inspect` port mappings and
requires the relay to be the sole host-published principal, with exactly two
configured and active TCP bindings; Product/Gateway probes must have none.
The real relay Docker test now verifies this observation and disabled kernel
forwarding as well as isolated networks, upstream restart and exact cleanup.
The canonical local mTLS anchor rule now binds each caller and server to both
read-only CA artifacts for distinct own-leaf and peer-verification purposes.
A two-issuer handshake test rejects swapped roots and mismatched signers. The
profile adds an isolated Product→Provider Contract edge and a separate
Gateway→Provider private Terminal edge, each with a numeric target, canonical
route, exact listener, identities and two CA purposes.

Gateway v3 now uses an exclusive live public signer and a separate live
private Provider client; its material registry contains only Product DSN and
grant key. Provider coding-shell v3 now selects two distinct profile-bound
live mTLS listeners: Contract admits Product, private Terminal admits Gateway
and only the exact `/private/terminal` path. Provider v3 runtime material
contains only DSN and admission verification keys; Desktop v3 is explicitly
rejected. Provider transport constructors reject static/live mixing, TLS
downgrade, optional client certificates, session-resumption bypass and
client-hello configuration replacement. Real TLS handshake tests show that
the listener-specific client URI allowlist rejects a wrong role even under a
trusted client CA. Targeted race tests, root race/vet and both locked Contract
verifiers pass for this code checkpoint. These are not the actual three-role
command, cert-rotation, revocation-drain or full-inventory gates. No Slice 6
manifest or count change follows.

The next Provider transport checkpoint tracks accepted Contract and private
Terminal sockets beneath `net/http`, including hijacked Terminal connections.
V3 binds their maximum lifetime to each exact profile trust edge; shutdown
drains accepted sockets rather than relying on `http.Server.Shutdown`, which
does not own hijacked sessions. A real mTLS private-listener test upgrades a
connection and verifies the socket is closed and the registry reaches zero;
the Contract test verifies an idle keep-alive socket is also drained. This
does not yet wire authoritative revocation notifications or prove the
profile's revocation drain bound during a live process gate.

Sandbox selected a versioned read-only pull from the existing Vault PKI →
certificate-controller → role TLS agent chain for peer revocation; v1 Unix
snapshot/sign semantics remain closed. The first code prerequisite verifies a
complete CRL against the exact CA DER identity, signature, issuer, AKI,
number and validity window, then checks a peer leaf under that same issuer.
Its test rejects a same-serial/different-issuer substitution. This helper is
not yet wired to the v2 Unix protocol or live TLS admission. The remaining
gate requires fixed-version Vault publication-policy observation, exact
profile source mapping, freshness/rollback protections, budgeted polling,
new-handshake denial and existing-connection drain across roles.
The tagged PKI integration used the pinned Vault image (reporting v2.1.1)
and observed `disable=false`, `auto_rebuild=false`, `enable_delta=false`;
after a real revoke, the complete CRL number advanced and the CRL verified
under the actual issuing CA. This establishes that fixture's publication
behavior only, not a production Vault configuration or end-to-end latency
bound.
The Vault PKI client now has an explicit `RequireImmediateCompleteCRL` mode:
before reading a CRL it uses the same scoped credential to read `config/crl`
and rejects missing, disabled, auto-rebuild or delta policy. Unit negatives
and the fixed-image integration pass with a read-only config ACL. Existing
v1 controller composition does not silently enable this option; the future
v2 peer-revocation path must opt in and bind the policy to its exact issuer
source before it can claim enforcement.
The next component now rejects delta, distribution-point-scoped, indirect or
unknown-critical CRL semantics even when a CRL signature is valid. A fixed
Vault source lookup accepts only an operator-supplied immutable issuer UUID,
mount and full issuer DER digest; it reads that issuer's CA and complete CRL,
checks both against the pinned DER and never falls back to `/pki/crl`.
Wrong/missing issuer, wrong signed CRL, alias/path injection and a disabled
complete-CRL policy fail closed in unit tests. The pinned real Vault image
also passed the exact issuer endpoint read after a real revoke. This is
component evidence only: the mapping is not yet bound to the profile's edge
authorization, controller/agent v2 wire path or live handshake/drain, and
there is no current Slice 6 manifest.
A separate `workload-tls-agent.v2` peer-CRL wire codec is now drafted beside
the frozen v1 snapshot/sign codec. Its canonical bounded request binds the
profile digest, exact edge, local principal, direction, peer anchor and full
issuer digest without accepting a caller-selected Vault path; its response
binds those fields and a source ID, complete CRL bytes, digest, number and
times. Decoding re-verifies the signed CRL against the caller's exact issuer
DER and rejects a v1 fallback. This codec is not yet an agent socket service
or controller authorization path, so no live handshake/drain claim follows.
An additional closed canonical operator source document is bound to the
existing security profile digest and Vault external identity. It maps fixed
issuer sources separately from exact local-principal/edge/direction/peer-
anchor authorizations; unknown edge, role, direction, anchor or actual issuer
DER cannot select a source. It allows two directions to reference one actual
issuer without implying separate CAs from differing anchor names. This
document is not yet loaded by production controller/agent commands and does
not establish source caching, least-privilege ACLs or full edge coverage.
The existing restricted Unix signer socket can now accept the distinct v2
peer-CRL request only when an explicit provider capability is configured;
the v1 snapshot/sign decoder and client remain intact. A real Unix socket
round trip verifies the returned issuer-bound signed CRL, while replay,
capacity, wrong-edge, v1-only fallback, cancellation and upstream-cancel
tests pass. This provider is still a test fixture, not the production
controller-backed authorization path; the role commands do not require v2
yet, and no live mTLS admission or existing-connection drain is proven.
The operator binding now exposes an agent-facing authorization lookup that
returns only a source ID for the exact role/edge/anchor/issuer digest; the
full Vault mount and immutable issuer ID stay in the controller-side source
record. The production controller must independently reauthorize the same
tuple before reading Vault; this is not yet wired.

## Exact final inventory

The gate covers six logical runtime roles instantiated as eight processes
(including separate coding, Browser and Desktop Providers), two executor
backends, their ten distinct TLS agents, one TLS agent per egress broker,
ten declared Vault material agents,
workload-credential/break-glass/certificate controllers, two one-shot
migration jobs, all egress brokers and their one-to-one policy-state
authorities, and the existing Desktop broker/Browser
runtime enforcement observations, plus the public ingress relay and its two
exact published paths. Vault, PostgreSQL and DNS are external
dependencies whose digest, identity, ingress and authorized-client edges are
bound; their deployment and HA remain non-claims.

## Required negative matrix

- substituted role, agent, tenant, trust domain, SAN or EKU;
- TLS 1.2/downgrade, expired certificate, revoked serial, stale CRL, issuer
  restart, Vault/controller loss and clock rollback;
- cross-role and cross-tenant service traffic;
- undeclared target alias, port or protocol, raw IP, alternate DNS, proxy
  environment, redirect, metadata/private/link-local/loopback/reserved answer
  and DNS rebinding;
- broker/DNS/policy loss and policy revision drift/revocation;
- root execution, UID/GID reuse, writable root, undeclared mount/tmpfs,
  capability addition, disabled no-new-privileges, seccomp drift, extra
  listener/network/device/daemon socket and PID/memory/CPU exhaustion; and
- process, connection, socket, file, container and network cleanup to the exact
  declared zero-resource boundary.

## Non-claims

Until the final gate passes, Phase 6 stays 5/15. Even after Slice 6 closure,
the result remains a same-host local-container gate. HSM-backed CA authority,
published/signed application images, platform service accounts, Kubernetes or
Apple Container deployment qualification, HA, independently administered
failure domains, hostile-multitenant safety and production readiness remain
later gates.
