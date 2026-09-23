# Product v1 Phase 6 Slice 6 Startup Audit

Date: 2026-09-22

Status: implementation underway. Product Phase 6 remains **5/15**.

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

The production egress broker still lacks a policy-revocation event source:
`Server.RevokePolicy` is implemented and component-tested, but the current
command only reads its profile at startup and waits for termination. Sandbox
ruled that an operator-signed, short-lived, generation-monotonic policy-state
snapshot must be polled with a hard bound and that revocation, outage, expiry,
bad signature or rollback must drain the old broker and stop new admission.
That monitor and its real-process gate remain to be implemented; a manual
SIGTERM is not accepted as the sole revocation mechanism.

## Exact final inventory

The gate covers six runtime roles, two executor backends, eight material
agents, workload-credential/break-glass/certificate controllers, two one-shot
migration jobs, all egress brokers, and the existing Desktop broker/Browser
runtime enforcement observations. Vault, PostgreSQL and DNS are external
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
