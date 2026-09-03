# P4 Optional Profiles

Status: browser Contract/Go projection, exact sandboxed signed amd64/arm64/v8
image publication, and uncomposed Provider-local
session/application/reference/usage components have named evidence. ADR 0020
and `provider/browser/driver/docker` add a fail-closed, still-uncomposed Docker
adapter and private relay component. ADR 0021 and
`provider/browser/provenance/ghcli` add a real, still-uncomposed provenance
verifier. No real restricted-egress implementation, create-policy binding,
handler, route composition, Gateway, or advertisement exists.
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
- The uncomposed Browser Docker adapter binds the exact published image and
  seccomp policy, numeric identity, read-only root, drop-all and
  no-new-privileges controls, finite resources, four bounded stable guest
  mounts, deterministic ownership, durable allocation evidence, and a fresh
  non-TTY `socat` relay to container-loopback CDP. It requires injected
  provenance verification and restricted-egress provisioning with no weaker
  fallback. Focused race/shuffle and a real Docker `network=none` relay test
  pass; the latter is private-transport component evidence only.
- The uncomposed GitHub CLI provenance adapter rehashes a pinned absolute
  executable, fetches the bundle from the immutable GHCR artifact, verifies
  exact GitHub OIDC/Sigstore and SLSA identity, strictly rechecks one bounded
  signed statement, limits inherited environment, and preserves cancellation.
  Its focused/full tests and tagged live GHCR integration pass locally; hosted
  CI run `33737531693` passes its separate `browser-provenance` job. This is
  provenance-verifier component evidence, not complete Browser startup.
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
| Create request | Browser fixture binds exact capability/runtime, digest-pinned amd64 image authority, restricted network policy, stable workspace, and unprivileged security fields; ADR 0019 plus publication run `33724368530` establish exact amd64/arm64/v8 sandbox and signed provenance evidence; ADR 0021 supplies a real uncomposed verifier for that publication | Bind create-time network policy to a real restricted-egress provisioner and compose it with the provenance verifier; the adapter rejects absent dependencies |
| Session and handoff | Separate schemas and routes bind session/operation/attempt/fence identity and expose only an expiring opaque reference; uncomposed browser authority, coordinator, registry, resolver, and Docker adapter now pass focused lifecycle/restart/expiry/private-attach tests | Compose protected transport and the caller-owned Gateway only after real runtime dependencies and their security tests pass |
| Gateway security | Semantic rules and security matrix leave user/tenant authorization, revocation, audit, reconnect, and fresh reference resolution with the caller; the Provider-local registry/resolver rechecks opaque state and committed handoff on every dial | Compose only with caller-owned authorization/revocation/audit/reconnect ports and fault-test the combined Gateway |
| Usage | Browser duration meter and operation/sandbox correlation are locked under the shared usage route; the uncomposed component derives bounded duration evidence from successful handoff and earliest trusted stop/expiry | Add runtime termination/reconciliation integration and route projection after composition |
| Fixtures and Suite | Success/rejection/security/admission fixtures and 10 new Suite cases raise the locked Suite from 38 to 48 cases | Add runtime fault/concurrency/image cases in later slices; current Suite is Contract projection evidence only |
| Runtime image | ADR 0019 removes every `--no-sandbox` path, binds seccomp digest `sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`, and passes local/native amd64 and arm64 sandbox gates. Run `33724368530` publishes exact signed index `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`; attestation `44912296` and independent platform inspection verify. ADR 0020 and the Docker adapter machine-bind that publication, validate local image metadata, apply the exact runtime controls, and establish the private CDP WebSocket stream. ADR 0021 and implementation `9390554` verify the immutable publication through the real GitHub CLI/Sigstore path as an uncomposed component | Supply the real restricted-egress implementation, bind create policy, and validate complete startup with both dependencies without the relay test's deliberate `network=none` boundary |

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
- Browser session component commit `9a5d225`; latest hosted E2E harness/Provider
  evidence `330f629`/`9390554`; reference and candidate 15+5 coding/shell
  regression runs pass in hosted runs `33737531617` and `33737531705`; these
  runs contain no browser scenario; and
- ADR 0020 and Browser adapter implementation `cd33ba3` pass focused and full
  race/shuffle, vet, exact Contract verification, the unchanged 48-case Suite,
  and the tagged Docker driver matrix. Repository CI `33731520938` and lock
  refresh CI `33732133500` pass all three jobs. The Browser tagged case
  exercises the exact published image, four guest mounts, sandbox controls,
  non-TTY relay, private version discovery, RFC 6455 upgrade, and
  `Browser.getVersion` over `network=none`; it does not test restricted egress
  or runtime startup with real dependency implementations; and
- ADR 0021 and provenance verifier implementation `9390554` pass focused/full
  race-shuffle, vet, real local GHCR/Sigstore integration, and repository CI
  `33737531693`, including the separately named `browser-provenance` job. The
  component is not wired into complete Browser startup; and
- real restricted-egress provisioning and create-policy binding, handler/Gateway/
  advertisement, real platform, multi-controller, multi-tenant, deployment,
  and production evidence remain explicitly open.

## Next work

The image, session/application/reference/usage components, fail-closed Docker
adapter, and real provenance verifier now have evidence within their named
boundaries. Next, implement the real restricted-egress provisioner, bind the
create-time policy reference through lifecycle composition, and run the full
adapter with it and the existing provenance verifier. Only then compose
protected Browser handlers and the caller-owned Gateway boundary. Do not enable
advertisement until that complete graph passes its fault/security gates;
browser external-caller E2E follows after composition and remains separate from
coding/shell harness runs.
