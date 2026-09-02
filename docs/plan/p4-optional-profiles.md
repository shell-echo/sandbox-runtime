# P4 Optional Profiles

Status: browser Contract authority and Go projection are locked. No browser
runtime, image, application, handler, route composition, or advertisement is
implemented. This work does not close P3, browser external-caller, aggregate
conformance, multi-controller, multi-tenant, deployment, or production gates.

## Objective

Add optional runtime profiles one at a time while preserving the Provider and
Agent Platform ownership boundary. Every profile must have an explicit
Contract, image, runtime, session, usage, security, and independent-caller
evidence chain before it can be advertised.

## Current facts

- The locked Provider Contract now authorizes an atomic `sandbox.browser@1.0.0`
  / `browser-v1` shape, `sandbox-runtime-browser-v1`, a browser create fixture,
  separate browser session open/handoff resources, protected-admission
  bindings, and browser duration usage evidence.
- Browser authority does not reuse the terminal-session route. The Provider
  router intentionally does not match either browser route, and startup does
  not advertise the browser capability.
- The repository has no browser or desktop runtime image, guest endpoint
  protocol, or deployable public Gateway composition.
- `blocks/` can validate an internal digest-pinned Block manifest, but it does
  not authorize a Provider capability or establish image provenance.
- A real Agent Platform caller and migration traffic harness remain unavailable;
  the co-located candidate harness is evidence only within its named boundary.

## Profile order and gates

| Order | Profile | First slice | Required gates before advertisement |
| --- | --- | --- | --- |
| 1 | Browser | Contract authority complete; image/provenance and uncomposed runtime components next | Image and guest tests, runtime/session recovery, Gateway policy, usage evidence, security/concurrency matrix, independent browser caller |
| 2 | Desktop | Contract and authority audit; display/input/session boundary design | Desktop protocol and image, display/input security, Gateway/reconnect, usage, fault and caller evidence |
| 3 | Workspace snapshot/restore | Digest and compatibility audit | Secret exclusion, digest verification, new sandbox identity, restore fault/recovery, Contract and caller evidence |
| 4 | Port-forward | Target and egress authority audit | Explicit target allowlist, network isolation, expiry/revocation, cross-tenant and caller evidence |
| 5 | GPU | Device and scheduler authority audit | Device isolation, scheduling, image/driver matrix, accounting, hostile security and deployment evidence |
| 6 | Nested-container / stronger isolation | Host boundary and deployment audit | Privilege, namespace, daemon, kernel, multi-controller, deployment, and production gates |

## Browser authority slice

The completed authority slice locks:

- capability/version/profile: `sandbox.browser` / `1.0.0` / `browser-v1`;
- runtime profile: `sandbox-runtime-browser-v1`;
- `POST /v1/sandboxes/{sandbox_id}/browser-sessions` and
  `GET /v1/operations/{operation_id}/browser-session`;
- operation/admission values `open_browser_session` and
  `read_browser_session` with exact JCS digest bindings;
- opaque `ref:browser-session:*` handoff, connection generation, and expiry;
- `sandbox.browser_session_milliseconds` usage with `milliseconds`; and
- caller-owned Gateway user/tenant authorization, revocation, audit, and
  reconnect policy, with URL/IP/port/CDP/backend-token disclosure forbidden.

These are wire and projection authorities, not runnable routes. Route-absence
tests require both browser paths to return `404` without consuming the mutation
guard. No runtime image, public endpoint, or advertisement is part of this
slice.

## Browser authority result

The 2026-09-02 audit inspected the locked Contract resources rather than
inferring support from generic schema vocabulary:

| Contract surface | Locked result | Remaining implementation gate |
| --- | --- | --- |
| Capability snapshot | Browser-only `1.0.0`/`browser-v1` maps to `sandbox-runtime-browser-v1`; mixed, wrong-version, wrong-profile, and wrong-runtime shapes fail closed | Derive advertisement only from a complete browser dependency graph |
| Create request | Browser fixture binds exact capability/runtime, digest-pinned amd64 image authority, restricted network policy, stable workspace, and unprivileged security fields | Supply a real reproducible image digest and validate its declared runtime behavior |
| Session and handoff | Separate schemas and routes bind session/operation/attempt/fence identity and expose only an expiring opaque reference | Implement durable browser session application/repository/runtime ports without composing transport yet |
| Gateway security | Semantic rules and security matrix leave user/tenant authorization, revocation, audit, reconnect, and fresh reference resolution with the caller | Implement and fault-test private endpoint resolution and caller-owned policy composition |
| Usage | Browser duration meter and operation/sandbox correlation are locked under the shared usage route | Implement bounded collection, reconciliation, expiry, and restart behavior |
| Fixtures and Suite | Success/rejection/security/admission fixtures and 10 new Suite cases raise the locked Suite from 38 to 48 cases | Add runtime fault/concurrency/image cases in later slices; current Suite is Contract projection evidence only |
| Runtime image | No browser image, digest, provenance attestation, architecture matrix, or guest endpoint is present | Build or publish a reproducible image and verify mounts, user, limits, network, and endpoint behavior before Provider composition |

This result is Contract/projection authority only. It does not make the
internal Block manifest a wire resource or establish browser runtime evidence.

## Acceptance evidence

- Contract authority commit `5096e71` and projection/lock commit `24b2e36`;
- Contract revision `5096e71fb84fbec22aa3487a0e55a1b49602ab8b`, tree
  `859f76dc0e855a0c8abdbbb5648df100dabb4328`, and 48-case Suite;
- Contract verifier, browser projection/admission/security/route-absence tests,
  and the locked 48-case Conformance Suite pass locally;
- E2E harness lock commit `75e5725` plus reference and candidate 15+5
  coding/shell regression runs; these runs contain no browser scenario; and
- runtime/image/handler/advertisement, real platform, multi-controller,
  multi-tenant, deployment, and production evidence remain explicitly open.

## Next work

Build and verify a reproducible digest-pinned browser image first: source,
supported architectures, provenance, numeric user, read-only root, stable
mounts, limits, restricted egress, and a private guest endpoint. Then implement
uncomposed provider-local browser session ports, durable operation/session
state, reconciliation, expiry, cleanup, usage, and opaque resolution. Do not
add handler routes or enable advertisement until those component gates and the
caller-owned Gateway boundary pass; browser external-caller E2E follows after
composition and remains separate from the existing coding/shell harness runs.
