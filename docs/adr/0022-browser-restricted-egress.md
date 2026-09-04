# ADR 0022: Browser Restricted-Egress Network

- Status: Accepted for the uncomposed P4 Browser restricted-egress component
- Date: 2026-09-03

## Context

The Browser Docker adapter requires a `RestrictedNetwork`, but its existing
tests use a fake or `network=none`. A normal Docker bridge, a pre-created
network name, or a static success callback does not enforce the Contract's
create-time restricted policy. The locked Browser image also rejects command
overrides and exposes CDP only on loopback, so the runtime cannot inject a
weaker proxy flag after publication.

The Provider Contract carries an opaque `policy_reference`, not an egress
allowlist. The platform owns policy selection; a Provider deployment must map
that reference to reviewed local enforcement configuration. Session requests
must never replace or relax the create-time choice.

## Decision

Add a Provider-local policy registry and Docker restricted-network adapter.
Each configured policy has one bounded reference and an exact/suffix hostname
allowlist. Configuration is normalized, deduplicated, hashed, and fail-closed;
IP literals, wildcard-only entries, user information, ports, and malformed
names are rejected.

Each Browser allocation receives a dedicated internal Docker bridge. The
Browser container is attached only to that bridge and uses the gateway's fixed
private address as its only configured DNS resolver. A dedicated gateway
container is attached to both the internal bridge and an explicitly configured,
operator-owned uplink. The default Docker bridge, host networking, published
ports, privileged mode, and an absent or internal uplink are forbidden. Network,
gateway, policy, namespace, controller, sandbox, session, and lease identities
are bound through deterministic names and labels and re-inspected after process
reconstruction. Release removes only exact owned resources.

The gateway listens only on its internal address. It returns that address for
allowed A queries and rejects other names; AAAA does not expose a bypass. DNS
queries may contain at most one bounded RFC 6891 EDNS0 OPT additional record
with a root name, a 512-to-4096-byte UDP payload size, version zero, and only
the DNSSEC OK flag. The gateway ignores its options and still rejects answer,
authority, non-OPT, or repeated additional records. HTTP port 80 requires an
allowed Host header. TLS port 443 uses Go's TLS parser to read a bounded
ClientHello and requires an allowed SNI before forwarding the original bytes.
For every upstream connection, the gateway independently resolves the
hostname, rejects loopback, unspecified, multicast, private, link-local,
carrier-grade NAT, documentation, benchmark, reserved, and other non-public
address ranges, and dials one validated address directly without an environment
proxy. This closes direct-IP, redirect-to-private-address, Docker
service-discovery, and DNS-rebinding paths for the supported HTTP/HTTPS Browser
egress profile. Other ports and protocols have no route through the internal
network.

The gateway image is a separate trust input. The Docker adapter requires an
immutable image ID or digest and validates its fixed user, entrypoint, labels,
and absence of exposed ports. This slice may build that image locally for a
tagged integration test; publication provenance and deployment distribution of
the gateway image remain separate gates.

The lifecycle model persists the create-time network mode, policy reference,
and gateway requirement. Browser session coordination accepts only a ready
Browser sandbox with the exact restricted policy and passes that immutable
reference into the runtime allocation. The Docker runtime rejects any mismatch
with its configured policy registry.

## Release boundary

Unit and race tests cover policy normalization, hostname matching, unsafe
address denial, DNS answers, HTTP Host and TLS SNI enforcement, context
cancellation, Docker ownership drift, idempotent acquisition, restart
inspection, rollback, and cleanup. A tagged Docker integration must create the
real internal network and gateway, start the exact Browser image with gateway
DNS, prove allowed HTTP/HTTPS navigation and denied unlisted/private targets,
reconstruct the adapters, and remove all owned resources.

This remains single-controller Docker component and lifecycle-binding evidence.
It does not compose protected Browser handlers or a caller-owned Gateway,
advertise `sandbox.browser`, establish Browser external-caller E2E, prove
hostile multi-tenant isolation, or establish deployment or production
readiness.

## Consequences

- Deployments must provide a reviewed local policy registry, an explicitly
  owned uplink, and a separately pinned gateway image.
- Policy changes produce a new digest and cannot mutate an existing lease.
- The uncomposed Browser adapter's private state advances from version 1 to
  version 2 and rejects old experimental state instead of guessing a missing
  resolver or policy digest. No deployed migration is claimed.
- A policy, image, network, gateway, DNS, Host, SNI, or resolved-address mismatch
  fails closed.
- Complete Browser transport composition remains blocked until this component
  and the existing provenance verifier pass together with the Browser runtime.
