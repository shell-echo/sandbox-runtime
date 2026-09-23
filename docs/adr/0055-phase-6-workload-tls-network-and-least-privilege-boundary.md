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

Each role-owned material agent generates its TLS private key locally and sends
a closed, signed CSR request to the certificate controller. The controller
maps the authenticated peer and agent identity to one exact trust domain,
principal URI SAN, optional DNS SAN set, EKU set, Vault role and TTL ceiling.
It rejects caller-selected SANs, wildcard identities, extra usages and an
unconfigured role. The private key never leaves the material agent.

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

Every runtime role, Browser/Desktop executor backend, material agent,
credential controller, break-glass controller, certificate controller and
migration job has a distinct URI SAN and exact server/client EKUs for its
declared trust edges. Shared identities and wildcard SANs are forbidden.

The private identity vocabulary is the closed, versioned
`securityprincipal.v1` registry. Its kinds are `runtime_role`,
`material_agent`, `migration_job`, `controller`, `executor_backend` and
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

Every role material agent exposes only the closed
`workload-tls-agent.v1` Unix signing protocol. It authenticates the role by
socket UID/GID, bounds connections and global nonce replay state, and returns
only the certificate chain, public key and generation-pinned ECDSA signature.
The TLS private key remains inside the agent. Rotation preserves the previous
generation only for the declared overlap, while CRL staleness, missed rotation,
issuer outage, clock rollback or revocation closes signing at the earliest
safety deadline.

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
- every egress broker and its one-to-one operator-owned policy-state authority; and
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
