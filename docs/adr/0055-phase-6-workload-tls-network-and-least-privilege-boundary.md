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

### Enforced egress and ingress

Use role-isolated Docker internal networks and independent egress-policy broker
identities for the portable Slice 6 local gate. A protected process has no host
network, Docker socket or default external route. It joins only its own
internal network and explicitly declared trust-edge networks. Its corresponding
broker is the sole external uplink and holds no Product/Provider business
secret, database authority or runtime-engine authority.

A role can request only a closed target alias, port and protocol. The broker
maps that alias to the immutable security profile, performs DNS itself, checks
every A/AAAA result through `internal/netpolicy`, rejects raw IPs,
redirect-based authority changes, alternate DNS, proxy-environment bypasses,
metadata, loopback, private, link-local, multicast and reserved addresses, and
dials only a checked address. The policy revision and lease bind every
connection; lifetime is bounded and policy revocation closes existing
connections. DNS, policy or broker outage fails closed.

Equivalent policies may share implementation but not a higher-authority
global broker identity. Negative network-topology tests, rather than an
in-process dialer assertion, prove that direct sockets and alternate paths do
not bypass the broker. Linux host enforcement may strengthen a platform
profile but is not the cross-platform Slice 6 requirement.

### Least privilege and evidence semantics

Every repository-owned container in the Slice 6 gate uses a unique numeric
UID/GID, non-root execution, a read-only root filesystem, only declared tmpfs
and role-private sockets, all Linux capabilities dropped,
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
- every egress broker; and
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
- Slice 7 owns SBOM, signature, provenance and publication for all images.
- Slice 11 translates this frozen contract into Docker, Apple Container and
  Kubernetes profiles and validates platform ServiceAccount, NetworkPolicy,
  PodSecurity and user-namespace behavior. It may not weaken the contract.
- Slice 14 repeats the security contract from published artifacts in an
  independently administered environment.
- Slice 6 remains open and Phase 6 remains 5/15 until the real PKI, network,
  least-privilege, full-inventory and strict evidence gates all pass.
