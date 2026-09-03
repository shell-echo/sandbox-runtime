# P4 Optional Profiles

Status: browser Contract/Go projection, exact sandboxed signed amd64/arm64/v8
image publication, and uncomposed Provider-local
session/application/reference/usage components have named evidence. No Browser
runtime adapter, handler, route composition, or advertisement is implemented.
This work does not close P3, browser external-caller, aggregate conformance,
multi-controller, multi-tenant, deployment, or production gates.

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
- The repository has a browser image component under
  `profiles/browser/image/`, with immutable amd64/arm64 upstream pins,
  a fixed private guest endpoint, a fail-closed Chromium seccomp profile, and
  no unsandboxed launch path. Manual run `33724368530` published the signed
  two-architecture GHCR index
  `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`
  from source `58ed009`. Its workflow assertion and an independent registry
  inspection found exactly linux/amd64 and linux/arm64/v8. The image is not a
  composed browser runtime, session service, or deployable public Gateway.
- The uncomposed `provider/browser` component supplies browser-specific domain
  types, runtime ports, durable memory/file authority, restart reconciliation,
  expiry/cancellation/unknown-outcome cleanup, opaque reference registry and
  resolver, operation projection, and bounded duration usage evidence. It is a
  single-controller Provider-local component and has no transport composition.
- `blocks/` can validate an internal digest-pinned Block manifest, but it does
  not authorize a Provider capability or establish image provenance.
- A real Agent Platform caller and migration traffic harness remain unavailable;
  the co-located candidate harness is evidence only within its named boundary.

## Profile order and gates

| Order | Profile | First slice | Required gates before advertisement |
| --- | --- | --- | --- |
| 1 | Browser | Contract authority and exact signed amd64/arm64/v8 sandbox publication are complete | Runtime/session recovery, Gateway policy, usage evidence, security/concurrency matrix, independent browser caller |
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
| Create request | Browser fixture binds exact capability/runtime, digest-pinned amd64 image authority, restricted network policy, stable workspace, and unprivileged security fields; ADR 0019 plus publication run `33724368530` establish exact amd64/arm64/v8 sandbox and signed provenance evidence | Bind the immutable digest and exact seccomp policy in a fail-closed runtime adapter before composition |
| Session and handoff | Separate schemas and routes bind session/operation/attempt/fence identity and expose only an expiring opaque reference; uncomposed browser authority, coordinator, registry, and resolver now pass focused lifecycle/restart/expiry tests | Compose transport only after exact image publication, Gateway policy, and caller evidence pass |
| Gateway security | Semantic rules and security matrix leave user/tenant authorization, revocation, audit, reconnect, and fresh reference resolution with the caller; the Provider-local registry/resolver rechecks opaque state and committed handoff on every dial | Compose only with caller-owned authorization/revocation/audit/reconnect ports and fault-test the combined Gateway |
| Usage | Browser duration meter and operation/sandbox correlation are locked under the shared usage route; the uncomposed component derives bounded duration evidence from successful handoff and earliest trusted stop/expiry | Add runtime termination/reconciliation integration and route projection after composition |
| Fixtures and Suite | Success/rejection/security/admission fixtures and 10 new Suite cases raise the locked Suite from 38 to 48 cases | Add runtime fault/concurrency/image cases in later slices; current Suite is Contract projection evidence only |
| Runtime image | ADR 0019 removes every `--no-sandbox` path, binds seccomp digest `sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`, and passes local/native amd64 and arm64 sandbox gates. Run `33724368530` publishes exact signed index `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`; attestation `44912296` and independent platform inspection verify | Implement an adapter that supplies the exact image and runtime controls |

This result is Contract/projection authority only. It does not make the
internal Block manifest a wire resource or establish browser runtime evidence.

## Acceptance evidence

- Contract authority commit `5096e71` and projection/lock commit `24b2e36`;
- Contract revision `5096e71fb84fbec22aa3487a0e55a1b49602ab8b`, tree
  `859f76dc0e855a0c8abdbbb5648df100dabb4328`, and 48-case Suite;
- Contract verifier, browser projection/admission/security/route-absence tests,
  and the locked 48-case Conformance Suite pass locally;
- ADR 0018/0019 browser image evidence: local arm64 and amd64 integration runs
  report Chromium `151.0.7922.109`, a sandboxed zygote, and no `--no-sandbox`
  process under the exact declared container controls. Native-runner
  publication run `33724368530` publishes exactly linux/amd64 and linux/arm64/v8
  under immutable digest
  `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`;
  GitHub OIDC/Sigstore attestation `44912296`, an independent constrained
  `gh attestation verify`, and independent registry inspection pass;
- Browser session component commit `9a5d225`, current E2E harness lock
  `58ed009`, and Provider lock `c91d83f`; reference and candidate 15+5
  coding/shell regression runs pass locally and in hosted runs `33724009124`
  and `33724009180`; these runs contain no browser scenario; and
- runtime adapter/handler/Gateway/advertisement, real platform, multi-controller,
  multi-tenant, deployment, and production evidence remain explicitly open.

## Next work

The digest-pinned browser image passes the ADR 0019 sandbox, exact platform,
and signed provenance checks for both supported architectures. The uncomposed
Provider-local browser session/application/reference/usage components pass
their focused lifecycle, restart, expiry, cleanup, opaque-resolution, and
duration evidence tests. Next, implement the Browser runtime adapter with the
immutable digest, seccomp policy, identity, mounts, limits, private endpoint,
and network controls before composing protected handlers and the caller-owned
Gateway boundary. Do not enable advertisement until that complete graph passes
its fault/security gates; browser external-caller E2E follows after composition
and remains separate from coding/shell harness runs.
