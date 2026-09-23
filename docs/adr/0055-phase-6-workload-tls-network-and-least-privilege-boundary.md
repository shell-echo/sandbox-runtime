# ADR 0055: Phase 6 Workload TLS, Network and Least-Privilege Boundary

- Status: accepted
- Date: 2026-09-22

## Context

Phase 6 Slice 5 establishes role-owned secret registries, short-lived Vault
credentials, real Vault Transit recording encryption and bounded break-glass
authority. It does not automate workload-certificate issuance, replace a live
TLS identity without restart, close existing connections after revocation, or
make network and operating-system policy independently enforceable.

The repository already contains strict TLS material parsing, TLS 1.3 role
transports, a DNS-rebinding-aware `internal/netpolicy` library and hardened
Browser/Desktop runtime containers. Those are foundations only. Most TLS
configurations are frozen at process startup, `internal/netpolicy` is not the
mandatory dial path for every role, and the Slice 5 local gate runs repository
processes under one host UID. Configuration text and library unit tests cannot
establish the Slice 6 enforcement claim.

Slice 11 owns platform deployment profiles. Slice 6 must therefore define and
prove one portable security contract without claiming that a local Docker gate
is Kubernetes, Apple Container, cloud service-account or independent-deployment
evidence.

## Decision

### Certificate authority and live rotation

Use real, digest-pinned Vault PKI as the Slice 6 production issuer and
revocation authority. A repository-private CA may appear only in unit tests.
An independent operator-owned certificate-controller process receives its
least-scope, short-lived Vault credential through the Slice 5 workload-
credential controller. It never exposes a Vault token, CA private key or
arbitrary Vault PKI role to a workload.

Each role-owned TLS agent generates its TLS private key locally and sends
a closed, signed CSR request to the certificate controller. The controller
maps the authenticated peer and agent identity to one exact trust domain,
principal URI SAN, optional DNS SAN set, EKU set, Vault role and TTL ceiling.
It rejects caller-selected SANs, wildcard identities, extra usages and an
unconfigured role. The private key never leaves that separate TLS-agent process.

Certificates have a repository hard maximum lifetime of one hour. The closed
security profile fixes a shorter or equal lifetime, a rotation window no later
than two thirds of that lifetime, and a bounded overlap. A role atomically
validates and swaps a complete certificate/key/CA revision through live TLS
callbacks. A failed refresh retains an unexpired previous revision only until
the safety deadline; readiness then closes and new handshakes fail closed.
Resolved PEM is cleared after parsing.

The controller and agents continuously observe authoritative Vault
revocation state. A revoked serial is rejected on a new handshake immediately,
and connection registries drain existing connections within the profile's
bound. Stale revocation state, controller or Vault outage, clock rollback and
issuer restart fail closed. Waiting only for certificate expiry is forbidden.

The runtime peer-revocation feed is a pull through the existing Vault PKI →
certificate-controller → role-owned TLS agent path, never a controller push,
new revocation authority, runtime Vault token or arbitrary AIA/CDP lookup.
The agent's current v1 Unix snapshot/sign protocol stays frozen. A distinct
`workload-tls-agent.v2` must bind a read-only complete CRL request/response to
the profile, exact trust edge, local principal, direction, peer-verification
anchor and full issuer certificate DER digest; production roles requiring
peer revocation must reject v1/no-capability fallback. The agent validates
the controller signature; the role validates the agent response binding,
CRL signature, issuer/AKI, serial, sequence,
time and source freshness against its own pinned peer CA before permitting a
new handshake or retaining an existing connection. An actual TLS-verified
peer leaf/issuer, not a header or claimed serial, keys the connection registry.
The combined Vault publication, controller/agent collection, role polling and
socket cleanup delay must fit the profile's end-to-end revocation bound;
individual poll and staleness limits alone do not prove it. Missing issuer
source, stale/rolled-back CRL, authority loss, or revoked-to-good resurrection
of an unexpired observed peer fail closed. Same-issuer reads may be shared,
but an agent cannot substitute its own issuer's CRL for a different peer CA.
Different server/client anchor IDs or purposes do not themselves prove
different issuers: compare the actual issuing CA's full DER SHA-256 first.
The canonical profile/operator source mapping fixes the existing Vault
backend/endpoint, mount, immutable Vault issuer UUID and complete issuer DER
digest for each actual peer CA, then authorizes that source only for the
requesting agent's declared mTLS edges. A mutable `default` issuer alias,
caller-supplied URL/path/issuer reference and `/pki/crl` fallback are
forbidden. The controller verifies the selected issuer certificate against
the pinned DER and re-verifies every complete CRL's signature and scope;
cache identity includes source, profile revision and issuer, while edge
authorization remains separate. Issuer replacement requires a new explicit
profile and controlled transition, not implicit rollover.
The source/edge mapping may be a separate closed canonical operator document
only when it is pinned to the exact security-profile digest and Vault
external identity. Its source set and per-edge authorization set remain
distinct; a source's presence never grants every role permission to read it.

The single-cluster complete-CRL path requires an observed Vault PKI CRL
configuration with building enabled, `auto_rebuild=false` and
`enable_delta=false`, plus a bounded refresh before `NextUpdate`; a contrary
configuration is unavailable, not a reason to poll faster or grant runtime
rotate authority. HashiCorp documents that a successful revoke rotates the
complete CRL unless `auto_rebuild=true`, and that expired complete CRLs may
otherwise need operator rotation
([PKI API: revoke/config/rotate](https://developer.hashicorp.com/vault/api-docs/secret/pki)).
This does not claim multi-cluster/unified CRL or automatic CA rotation.

Every runtime role, Browser/Desktop executor backend, material agent,
credential controller, break-glass controller, certificate controller and
migration job has a distinct URI SAN and exact server/client EKUs for its
declared trust edges. Shared identities and wildcard SANs are forbidden.

The Browser and Desktop executor backend production commands use version-2
authority files and the validated Phase 6 profile's sole role-to-executor
`wss` trust edge. They reject version-1 local server-key authority. Each new
handshake obtains a generation-bound certificate from its separate TLS agent
and verifies the pinned issuer, exact URI/DNS/EKU, lifetime and public signer
key before serving. Static-file backend constructors remain only component
compatibility paths; they are not a production fallback. Existing-connection
revocation drain and the distinct-UID command-level graph remain named gates,
not conclusions from these callbacks.

The private identity vocabulary is the closed, versioned
`securityprincipal.v1` registry. Its kinds are `runtime_role`,
`material_agent`, `tls_agent`, `migration_job`, `controller`, `executor_backend` and
`egress_broker`; every name-to-kind-to-role mapping is explicit. The
`workload-credential.v2` protocol binds the complete principal and its digest
to a separate v2 lease namespace and ledger. Version 1 remains frozen as Slice
5 evidence only: a production Slice 6 caller cannot downgrade to v1 or renew a
v1 lease through v2. Certificate-controller credential issuance is separately
allowlisted to exactly the `certificate-controller-pki` backend policy;
migration credentials are nonrenewable, while runtime roles, migration jobs,
executor backends, egress brokers and the credential controller are denied
direct issuance by default.

The certificate controller's own first Vault connection is the sole bounded
bootstrap exception. An operator-provisioned client private key is inherited
only through descriptor 5 as a private regular file; it is never present in
JSON, environment, arguments, logs, evidence or the repository. The matching
certificate must chain to the configured Vault client trust bundle and carry
the exact certificate-controller URI/DNS identity, empty subject, P-256 key,
digital-signature usage, client-auth EKU, valid time and at most one-hour
lifetime. The scoped Vault token and mTLS identity are both required; static
tokens, anonymous access, server-only TLS and a v1 credential fallback are
forbidden.

The bootstrap identity may perform only the first controlled issuance and CRL
read. The controller then atomically selects its locally generated managed
certificate, closes the old transport connections, destroys the bootstrap
key, and uses the managed signer for subsequent Vault handshakes. Shutdown
revokes overlap material before the current identity, destroys both keys and
closes every connection. Missing, wrong, nonregular, public-permission,
offset, oversized or mismatched descriptor material; wrong SAN/EKU/CA/time;
token-policy mismatch; Vault denial; failed first switch; stale old
connections; and leaked key material all fail closed.

Every role TLS agent exposes only the closed
`workload-tls-agent.v1` Unix signing protocol. It authenticates the role by
socket UID/GID, bounds connections and global nonce replay state, and returns
only the certificate chain, public key and generation-pinned ECDSA signature.
The TLS private key remains inside the agent. Rotation preserves the previous
generation only for the declared overlap, while CRL staleness, missed rotation,
issuer outage, clock rollback or revocation closes signing at the earliest
safety deadline.

The wire protocol remains v1, but the production socket layout and command
configuration are `workload-tls-agent-config.v2`. Version 1's agent-owned
0700 parent and 0600 socket cannot be reached by a role with its required
distinct UID. Each agent/role pair instead gets one private mount directory:
agent UID owner, role GID group, mode 0710; its Unix socket is agent-UID-owned,
mode 0666, with no socket `chown` or dependence on inode group inheritance.
Directory group permits path traversal only, not writes. The agent and role
verify the exact parent owner/group/mode, socket type/owner/mode, no symlinks,
stable socket inode and exact peer UID/GID before any protocol frame. The
agent rejects supplementary groups outside its own GID, and the deployment
drops all capabilities including `CAP_CHOWN`. The role mounts only its own
agent directory read-only; no other role mounts it. An authorized peer that
sends no frame or only half a frame has a bounded initial read deadline;
cancel/close actively closes accepted connections before waiting for handlers.
The v2 layout does not change the v1 message schema or create another
certificate/signing state machine. Production commands do not select the
old layout. The complete profile-to-mount/edge binding and real broker mTLS
gate remain mandatory before Slice 6 is counted.

A TLS agent is a separate OS process and a distinct private
`securityprincipal.KindTLSAgent` identity, not an alias of the existing
`KindMaterialAgent` Vault KV/credential process. TLS agent identities are
ineligible for `workload-credential.v2` token issuance even if an operator
mistakenly configures a backend policy. The PKI delegation relation is one
TLS agent to one exact subject (including separate Browser/Desktop executor
agents and a distinct agent per registered egress broker); the old
material-agent and shared Browser/Desktop role/executor delegation is not a
production authorization path. The certificate controller's own managed
Vault TLS key remains its explicitly audited internal-signer exception.
The private principal vocabulary was extended before a Slice 6 lock or
release evidence was created; Provider Contract is unchanged. The canonical
profile and process gate must inventory every actual key owner and must not
create empty agent principals for processes that do not use one.

The still-unlocked `phase6-security-profile.v1` now binds all eight static
runtime/executor TLS agents and exactly one additional agent per registered
egress broker. Every canonical `tls_agent_bindings` entry fixes the agent and
subject deployment/principal digests, distinct UID/GID pairs, one private
socket storage ID and `/run/tls/<agent>/signer.sock` path, 0710 directory and
0666 socket modes, the exact subject-to-agent Unix peer edge, issuer policy
and Vault role, and socket cleanup class. The profile rejects omissions,
duplicates, cross-subject substitution, extra mounts/edges and sharing with
the policy-authority socket. The production TLS-agent command checks its
config against this profile; the egress broker checks its signer endpoint
against its bound agent before connecting. These checks are configuration
authority only: Product now has an explicit v3 live-signer public listener;
Gateway has an explicit v3 live-signer public listener and a profile-bound
Gateway→Provider private client with separate own-client and peer-server CA
roots. Gateway v3 admits only Product database and grant-key material, not
static TLS material. Its private route is a numeric address on the isolated
Gateway/Provider trust network, bound to the Provider private listener and
canonical path. Provider coding-shell now has an explicit v3 profile-bound
Contract listener for Product and a separate private Terminal listener for
Gateway, each with an exclusive live signer, direction-specific CA pools and
distinct client allowlists; v3 Desktop is rejected. The two Provider listeners
use the same role-owned signer but do not merge route or peer admission. This
remains component evidence: no actual v3 Product/Gateway/Provider command
graph, certificate-rotation, revocation-drain or cleanup gate has passed.
Product's private edges and the other three runtime commands still need
migration, and
a real broker/controller/Vault/DNS mTLS process gate is required before Slice
6 can close.

The same canonical profile, not a second signed document, owns the closed
`trust_anchors` registry. Each anchor records its original bundle-byte SHA-256,
server- or client-verification purpose, trust domain, artifact/storage ID,
read-only target path, operator writer, owner UID/GID and exact consumers.
An `mtls` trust edge references its server-verification anchor and, when the
server is repository-owned, its client-verification anchor. Unix signing
edges cannot cite CA anchors. A bundle can be read-only shared by declared
consumers, but equal bytes do not merge distinct purposes or trust domains.
For a repository-owned internal mTLS edge, both exact endpoint principals
consume both anchors read-only: the caller uses the client anchor to verify
its own agent-issued client leaf and the server anchor to verify its peer;
the server uses the server anchor to verify its own agent-issued server leaf
and the client anchor to verify its peer. The two root pools remain separate;
CA readability grants neither signing authority nor a reverse dial. This
does not invent an external-service mount or change the public server-only
listener into mTLS. Missing or extra consumers/mounts fail closed.
The common loader verifies one stable opened file's owner, non-writable
source, SHA-256 and strict CA-only PEM records before the bytes reach a TLS
config. The controller bootstrap client certificate has a separate
`client_verification` anchor; its local chain check must not reuse the Vault
server-verification root. The CA revision remains frozen for that process; anchor changes
require a new canonical profile and controlled process replacement, not a
new CA rotation control plane. Executor, controller→Vault and broker→DNS/inbound
commands consume this registry now; other production TLS commands and full
trust-edge binding still need the same loader before release.

The production runtime TLS configuration advances explicitly to v3. V3 uses
only a profile-bound live signer and direction-specific pinned anchors; the
v2 material-registry certificate/private-key path is retained solely for its
historical candidate evidence and cannot be an automatic production fallback.
New handshakes must fetch and verify a fresh certificate/signing capability,
and TLS session resumption cannot bypass that check. Existing HTTP, WebSocket
and media connections must separately drain within the profile's revocation
bound. The live TLS 1.3 builder and Browser/Desktop backend hookup are
component checkpoints, not that six-role command gate.

Provider Contract and private Terminal listeners track accepted sockets below
`net/http`, enforce the exact trust edge's maximum connection lifetime, and
close both keep-alive and hijacked sockets on shutdown. That transport
registry is a prerequisite, not a revocation feed: the authoritative
controller/agent revocation signal, live drain timing and corresponding
cross-process failure gate remain required before a Slice 6 closure claim.

The canonical profile declares only these runtime dialing authorities:
Product→Provider locked Contract listener; Gateway→Provider separate private
handoff/media listener; Provider→Browser and Provider→Desktop private executor
listeners; Browser→its Browser backend; Desktop→its Desktop backend; and
Guest→Product's separate private Guest-control listener. Each internal edge
binds the exact listener and route, protocol, both deployment/principal
digests, URI/DNS/EKU, distinct server/client CA anchors, connection lifetime
and revocation drain. A response on an authorized connection does not grant a
reverse dial. Browser/Desktop credential fields named `ProviderOrigin` are
SPIFFE peer identities, not outbound Provider URLs; no such reverse edge is
inferred. Gateway's committed Product database reads do not invent a
Gateway→Product HTTP edge. Provider coding and Desktop instances cannot share
one identity that masks their different capabilities.

Only exact Product and Gateway public listener bindings use TLS 1.3
server-authentication without a workload client certificate. Product user
authentication and Gateway ticket/grant, Origin, session and fence checks
remain required. These bindings do not create a wildcard external principal
or grant the same optional-client-cert policy to a private listener. WebRTC
media retains its authenticated signaling and DTLS/SRTP binding rather than
being misclassified as a generic mTLS HTTP edge. The Guest remains outbound
only; its private Product receiver must compose the existing Guest Hub,
binding store, challenge authentication and Files/Development adapters under
the Product identity. A fixture-only Guest peer is not production composition.
Database, coordination, object storage, egress broker, agent/controller Unix,
Vault and DNS dependencies each retain their own actual-consumer bindings and
cannot be hidden under the runtime mTLS matrix.

The certificate controller is one logical process, not one controller per
agent. Its production command configuration is v3 and receives the same
validated profile/registry as its TLS-agent clients, including registered
broker agents; the old nil-broker registry is not a production fallback.
The profile fixes the controller principal/UID/GID and its response-signing
key ID/public-key digest separately from Vault CA and mTLS trust material.
Each TLS agent gets a distinct controller Unix endpoint, storage ID, 0710
controller-owned/agent-group directory, 0666 controller-owned socket, exact
agent-to-controller peer edge, and CSR request key ID/digest. The controller
owns each directory read-write and only its corresponding agent mounts it
read-only. The controller command checks its complete listener and policy
sets against the profile, including the managed Vault TLS self-policy. The
agent checks its controller endpoint, peer UID/GID, response key, CSR key and
issuer policy before opening the socket.

The controller's own managed Vault TLS renewal uses a separately declared
internal self endpoint with 0700 directory and 0600 socket; it is not an
extra TLS agent and never shares an external agent endpoint. Both Unix paths
use common no-symlink, stable-inode, owner/mode, stale-socket and active-
connection cleanup checks. External agent endpoints never use `chown`,
supplementary groups or CAP_CHOWN, and a half-sent first frame is bounded.
A two-agent distinct-UID Docker test now proves this Unix/CSR component with a
private test CA; full production broker/controller/Vault/DNS integration is
still required before Slice 6 closure.

### Enforced egress and ingress

Use role-isolated Docker internal networks in `isolated` IPv4 gateway mode and
independent egress-policy broker identities for the portable Slice 6 local
gate. Every protected role and trust-edge bridge must be created with
`--internal --opt com.docker.network.bridge.gateway_mode_ipv4=isolated`.
IPv6 is disabled and verified in this profile; a future IPv6-enabled profile
must also use and prove `gateway_mode_ipv6=isolated`. A protected process has
no host network, Docker socket, host bridge address, default external route or
alternate Docker network. It joins only its own isolated network and explicitly
declared isolated trust-edge networks. Its corresponding broker alone joins a
separate external-uplink bridge and holds no Product/Provider business secret,
database authority or runtime-engine authority.

The stronger mode is mandatory, not an optimization. On Docker 29.7.2 a real
`--internal`-only container reached a disposable host-network service through
the bridge gateway, despite failing an external-network direct-socket probe.
The same host fixture must be a positive control in the gate: ordinary
`--internal` reproduces the bypass, while `isolated` denies that gateway,
other Docker gateways, resolved `host.docker.internal` and
`gateway.docker.internal` numeric addresses, public and metadata addresses.
The protected role must still reach its declared broker and the broker must
reach an allowed uplink fixture. Network inspect verifies exact members,
`Internal`, `bridge`, `isolated`, disabled IPv6 and absent host gateway address;
live route/address probes verify no default route or IPv6 address. A failed
network option, missing positive control or unexpected reachability fails the
gate. [Docker documents why ordinary internal bridge gateways remain host-
reachable and why `isolated` omits the bridge address](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).

Product and Gateway public TCP entry uses one operator-owned, fixed-target
ingress relay process. It alone joins the `public_ingress` NAT network and
two separate `isolated` trust-edge networks; Product and Gateway join only
their respective isolated networks and have no host-published ports. The
relay binds only one explicitly declared frontend IPv4 address and forwards
two exact port mappings to profile-pinned numeric upstream addresses. TLS
terminates in Product/Gateway, not the relay. The relay has its own UID/GID,
image, seccomp and resource bounds, no TLS/material-agent identity, no
business credential, no Docker socket, no HTTP parser, CONNECT/SOCKS,
dynamic DNS/SNI upstream or proxy-header authority. The canonical profile
binds its principal digest, exact frontend/target network membership,
non-overlapping canonical IPv4 CIDRs, listener, host publication, endpoint,
port, per-route limits and mapping
digest. Unknown frontend listeners, role-owned ingress listeners and role
host publication are rejected. The Docker gate must independently inspect
the actual network IPs, port bindings, routes and disabled forwarding,
exercise Product/Gateway TLS and application authorization through those
published ports, test relay/target failure and drain, and prove exact
cleanup. A raw TCP relay does not solve WebRTC ICE/UDP/media reachability;
that remains a separate release gate, not an inferred consequence.

A role can request only a closed target alias, port and protocol. The broker
maps that alias to the immutable security profile, performs DNS itself, checks
every A/AAAA result through `internal/netpolicy`, rejects raw IPs,
redirect-based authority changes, alternate DNS, proxy-environment bypasses,
metadata, loopback, private, link-local, multicast and reserved addresses, and
dials only a checked address. The policy revision and lease bind every
connection; lifetime is bounded and policy revocation closes existing
connections. The external DNS service's exact certificate DNS SAN is part of
the digest-bound profile; broker startup accepts only that SAN and a numeric
DNS endpoint on the declared trust-edge port, never an operator-selected
hostname that would invoke ambient DNS. DNS, policy or broker outage fails
closed.

Each egress policy has exactly one independent operator-owned authority
process, controller principal, UID/GID, signing key, persistent CAS ledger
and restricted Unix socket; no process signs another policy. A one-time
explicit initialization commits generation one. Later starts recover the
ledger and cannot silently initialize a missing/corrupt record or reactivate
a revoked policy. Every active refresh and revocation commits the atomic,
fsynced ledger; the authority signs Current from that ledger's in-memory
state digest. It does **not** publish a separate state file: distinct broker
and authority UIDs cannot safely share a 0600 file, and file-plus-online
comparison would still have only one underlying trust source while adding
publication races, write load and failure modes. A legacy file, if present,
has no authorization effect.

Before listening, and then at a profile-bound interval no longer than one
second, the broker sends a new random challenge to the live authority over a
per-broker Unix socket. A canonical signed Current response binds that
challenge, exact environment/profile/policy/principal/broker digests,
generation, active/revoked status, committed state digest and short validity.
The authority signs from a linearizable read of its durable ledger. Broker
checks exact peer UID/GID, signature/key, nonce, freshness, monotonic
generation and same-generation immutability. A missing/late/invalid response,
clock rollback, authority loss or revoked status immediately revokes the
broker revision, drains existing sessions and stops admission; it cannot
continue on the previous active response until its nominal expiry. A new
policy revision requires a separate broker and authority instance.

The socket directory is authority-owned, broker-group, mode 0710 and mounted
only into those two containers. On platforms where Unix socket inode group
cannot reliably be assigned, its mode is 0666 **only inside that protected
directory**; exact parent ownership/mode, no symlinks, broker/authority peer
credentials and the signed policy binding remain mandatory. The authority
signing key never enters the broker or repository. Local gates do not prove
independent production operator administration or trusted recovery from a
privileged operator restoring both ledger and key; Slice 14 must explicitly
state that boundary.

An operator SIGUSR1 is only a revocation trigger, not proof of completion.
The operator waits for a successful authority exit, then runs an independent
read-only inspection of the exact private ledger. A successful canonical
receipt must bind the expected environment, profile, policy, principal,
broker, generation, committed time and ledger digest with `status=revoked`.
SIGTERM, SIGKILL, signal delivery, transport loss and nonzero process exit
must never be reported as permanent policy revocation; a visible receipt after
a failed fsync/exit is escalated rather than treated as proven durable.

Equivalent policies may share implementation but not a higher-authority
global broker identity. Negative network-topology tests, rather than an
in-process dialer assertion, prove that direct sockets and alternate paths do
not bypass the broker. Linux host enforcement may strengthen a platform
profile but is not the cross-platform Slice 6 requirement.

### Least privilege and evidence semantics

Every repository-owned container in the Slice 6 gate uses a unique numeric
UID/GID, non-root execution, a read-only root filesystem, only declared tmpfs
and role-private sockets, plus one narrowly scoped managed persistent ledger
volume per policy-state authority. Its ledger volume is writable only by that
authority, never by its broker or another role; arbitrary volumes, host-path
bind mounts and shared business storage remain forbidden. All Linux
capabilities are dropped,
`no-new-privileges`, a role-specific seccomp policy, bounded PIDs/memory/CPU,
no host devices, host mounts, daemon sockets or extra listeners. The gate
rejects drift and exercises privilege escalation and resource exhaustion.
Each principal binds its reviewed policy by exact digest and the gate checks
that binding against the running container. Equivalent least-privilege
syscall needs may share one policy artifact and digest; forcing unique bytes
per principal is not an isolation control. UID/GID, credential, network and
mount separation remains per principal, and a shared policy must not include
the union of unrelated roles' extra syscalls merely for convenience.

Evidence records the exact observed layer:

- `distinct_container_uid_gid_established=true`;
- `container_namespace_isolation_established=true`;
- `host_user_namespace_mapping_established` only from an actual mapping check;
- `platform_service_account_established=false`; and
- `same_host_local_container_gate=true`.

It must not collapse these facts into an unqualified
`distinct_os_uid_established=true` statement.

### Closed security profile and inventory

Add a closed, canonical, versioned Phase 6 security profile. It binds every
process principal, digest-only image identity, UID/GID, filesystem, capability,
seccomp and resource rule, listener/ingress edge, TLS trust domain/SAN/EKU,
allowed service and egress edge, policy digest, DNS/metadata rule, secret
purpose, certificate timing/revocation policy and cleanup class. Missing,
unknown or duplicate principals/edges, mutable images, extra ports, mounts,
capabilities or networks fail validation.

The final immutable gate covers:

- Product, Gateway, Provider, Guest, Browser and Desktop runtime roles;
- Browser and Desktop executor backends;
- six runtime plus Product/Provider migration material agents;
- workload-credential, break-glass and certificate controllers;
- Product and Provider one-shot migration jobs;
- every egress broker and its one-to-one operator-owned policy-state authority;
- the public ingress relay and its two exact published Product/Gateway paths; and
- the existing Desktop broker and Browser runtime security assertions.

External Vault, PostgreSQL and DNS remain outside the repository-owned role
set, but their digest/identity/ingress edges and exact reachable clients are
bound. The gate covers identity substitution, downgrade, wrong SAN/EKU,
expiry/revocation, cross-role/tenant traffic, direct/raw-IP/alternate-DNS/
metadata/rebinding attempts, policy outage, privilege escalation, resource
exhaustion and exact cleanup. Real Browser CDP and Desktop media/input smokes
run under the profile. Slice 4's 50/100 stress matrix is repeated only if its
media/broker timing changes.

## Consequences

- Slice 6 proves local enforcement with real Vault PKI and Docker, not an HSM
  CA, cloud identity, published/signed application image, platform service
  account, deployment, HA or production readiness.
- The descriptor-5 first-operation bootstrap is an operator runbook boundary,
  not automatic HSM, cert-manager, cloud workload identity or platform
  bootstrap. Slices 11 and 14 must replace or explicitly revalidate it in each
  deployment and independently administered environment.
- Slice 7 owns SBOM, signature, provenance and publication for all images.
- Slice 11 translates this frozen contract into Docker, Apple Container and
  Kubernetes profiles and validates platform ServiceAccount, NetworkPolicy,
  PodSecurity and user-namespace behavior. It may not weaken the contract.
- Slice 14 repeats the security contract from published artifacts in an
  independently administered environment.
- Slice 6 remains open and Phase 6 remains 5/15 until the real PKI, network,
  least-privilege, full-inventory and strict evidence gates all pass.
