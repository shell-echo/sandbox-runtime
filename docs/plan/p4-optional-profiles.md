# P4 Optional Profiles

Status: browser Contract/Go projection, exact sandboxed signed amd64/arm64/v8
image publication, and uncomposed Provider-local
session/application/reference/usage components have named evidence. ADR 0020
and `provider/browser/driver/docker` add a fail-closed, still-uncomposed Docker
adapter and private relay component. ADR 0021 and
`provider/browser/provenance/ghcli` add a real, still-uncomposed provenance
verifier. ADR 0022 and implementation `7e60340` add a real, still-uncomposed
restricted-egress provisioner and immutable create-policy binding. ADR 0023 and
implementation `b8423f5` add protected Browser open/handoff handler component
evidence. ADR 0024 and implementation `5aae281` add the uncomposed caller-owned
Browser Gateway component. No Browser command/runtime composition, public
Gateway route, or advertisement exists.
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
- Browser authority does not reuse the terminal-session route. The protected
  router now matches both Browser routes and fails closed when no Browser
  application is injected. Command startup injects none and does not advertise
  the browser capability.
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
- The uncomposed restricted-egress component maps an opaque create-time policy
  reference to a normalized local hostname allowlist and a per-allocation
  internal bridge. The Browser has one network and one private DNS resolver;
  the fixed gateway has the internal bridge plus an explicitly owned uplink and
  permits only validated DNS A, HTTP Host, TLS SNI, and public resolved
  addresses. Implementation `7e60340` passes focused/full race-shuffle, vet,
  the unchanged Contract verifier and 48-case Suite, and a real local Docker
  composition with the existing `gh` verifier and signed Browser image.
  Repository CI `33747803509` passes its four named jobs but does not execute
  the Browser restricted-egress tagged case. This is single-controller local
  component/lifecycle-binding evidence only.
- ADR 0023 and `b8423f5` add a narrow protected-transport application port and
  the two Contract-authorized Browser handlers. They apply the existing
  mTLS/JWS/admission gate, reject unknown/oversized input before mutation state,
  correlate admitted and application identities, project Browser operations,
  enforce handoff expiry, and return only `ref:browser-session:*`. Full local
  race/shuffle, vet, Contract verification, and the unchanged 48-case Suite
  pass. This is not command/runtime composition or Browser caller evidence.
- ADR 0024 and `5aae281` extend the existing caller-owned Gateway policy state
  machine with an exclusive Browser session identity and
  `ref:browser-session:*` namespace, exact resolved-endpoint binding,
  metadata-only audit, reconnect/revocation handling, and a separate RFC 6455
  adapter for Chromium CDP. Composition requires explicit caller authorization,
  revocation, recording, WebSocket admission, and Provider Browser resolver
  ports. Focused and full race/shuffle, vet, Contract verification, and the
  unchanged 48-case Suite pass locally. This is an uncomposed component, not a
  public route, Browser command graph, advertisement, or Browser caller result.
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

These began as wire and projection authorities. ADR 0023 now gives both routes
bounded protected-handler component evidence while keeping absent application
composition fail closed. ADR 0024 separately supplies the caller-owned Browser
Gateway component. No public endpoint, startup composition, advertisement, or
external Browser caller is part of those slices.

## Browser authority result

The 2026-09-02 audit inspected the locked Contract resources rather than
inferring support from generic schema vocabulary:

| Contract surface | Locked result | Remaining implementation gate |
| --- | --- | --- |
| Capability snapshot | Browser-only `1.0.0`/`browser-v1` maps to `sandbox-runtime-browser-v1`; mixed, wrong-version, wrong-profile, and wrong-runtime shapes fail closed | Derive advertisement only from a complete browser dependency graph |
| Create request | Browser fixture binds exact capability/runtime, digest-pinned amd64 image authority, restricted network policy, stable workspace, and unprivileged security fields; ADR 0019 plus publication run `33724368530` establish exact amd64/arm64/v8 sandbox and signed provenance evidence; ADR 0021 supplies a real uncomposed verifier, while ADR 0022 and `7e60340` bind the create policy to a real restricted-egress provisioner and validate full runtime dependency startup locally | Preserve this policy through command/runtime composition; do not allow session-time substitution or advertise before the complete graph passes |
| Session and handoff | Separate schemas and routes bind session/operation/attempt/fence identity and expose only an expiring opaque reference; browser authority, coordinator, registry, resolver, Docker adapter, protected handlers, and caller-owned Gateway now pass their separately bounded component gates | Compose the complete command/runtime graph and explicit caller edge, then prove the combined path through a Browser caller |
| Gateway security | Semantic rules and security matrix leave user/tenant authorization, revocation, audit, reconnect, and fresh reference resolution with the caller; the Provider-local registry/resolver rechecks opaque state and committed handoff on every dial. ADR 0024 composes these explicit ports with Browser-only identity/reference checks and RFC 6455 framing | Add a caller-owned public route only through explicit configuration and fault-test it with the complete runtime graph and independent Browser caller |
| Usage | Browser duration meter and operation/sandbox correlation are locked under the shared usage route; the uncomposed component derives bounded duration evidence from successful handoff and earliest trusted stop/expiry | Add runtime termination/reconciliation integration and route projection after composition |
| Fixtures and Suite | Success/rejection/security/admission fixtures and 10 new Suite cases raise the locked Suite from 38 to 48 cases | Add runtime fault/concurrency/image cases in later slices; current Suite is Contract projection evidence only |
| Runtime image | ADR 0019 removes every `--no-sandbox` path, binds seccomp digest `sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`, and passes local/native amd64 and arm64 sandbox gates. Run `33724368530` publishes exact signed index `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`; attestation `44912296` and independent platform inspection verify. ADR 0020 and the Docker adapter machine-bind that publication, validate local image metadata, apply the exact runtime controls, and establish the private CDP WebSocket stream. ADR 0021 and implementation `9390554` verify the immutable publication through the real GitHub CLI/Sigstore path. ADR 0022 and `7e60340` validate complete local runtime dependency startup with the real verifier and restricted egress | Compose the Browser command/runtime graph and caller edge without weakening the verified transport and runtime graph |

This result is Contract/projection authority only. It does not make the
internal Block manifest a wire resource or establish browser runtime evidence.

## Acceptance evidence

- Contract authority commit `5096e71` and projection/lock commit `24b2e36`;
- Contract revision `5096e71fb84fbec22aa3487a0e55a1b49602ab8b`, tree
  `859f76dc0e855a0c8abdbbb5648df100dabb4328`, and 48-case Suite;
- Contract verifier, browser projection/admission/security/protected-transport
  tests, and the locked 48-case Conformance Suite pass locally;
- ADR 0018/0019 browser image evidence: local arm64 and amd64 integration runs
  report Chromium `151.0.7922.109`, a sandboxed zygote, and no `--no-sandbox`
  process under the exact declared container controls. Native-runner
  publication run `33724368530` publishes exactly linux/amd64 and linux/arm64/v8
  under immutable digest
  `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`;
  GitHub OIDC/Sigstore attestation `44912296`, an independent constrained
  `gh attestation verify`, and independent registry inspection pass;
- Browser session component commit `9a5d225`; latest hosted E2E harness/Provider
  evidence `9eb32ba`/`5aae281`; reference and candidate 15+5 coding/shell
  regression runs pass in hosted runs `33826813099` and `33826813100`; these
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
  component is exercised by the local restricted-egress composition; and
- ADR 0022 and restricted-egress/create-policy implementation `7e60340` pass
  focused/full race-shuffle, vet, the unchanged Contract verifier and 48-case
  Suite, existing Docker driver/lifecycle regressions, and the combined tagged
  Browser integration. The local Gateway image ID is
  `sha256:202bbf92fcbcce87e4b800f093d1df281125ab6fa43152906564cf8e0b7021d6`;
  repository CI `33747803509` passes, but its Docker job does not execute this
  Browser tagged case. This is not published Gateway provenance or deployment
  evidence; and
- ADR 0023 and protected transport implementation `b8423f5` pass route,
  preflight/admission ordering, correlation, operation/handoff projection,
  expiry, opaque-reference security, failure, concurrency, aggregation, full
  race/shuffle, vet, Contract verifier, and unchanged 48-case Suite gates.
  Harness lock `a2721ad` passes repository CI `33760609353` and hosted
  Reference/Candidate coding/shell regressions `33760609272`/`33760609231`;
  those caller runs contain no Browser scenario; and
- ADR 0024 and caller-owned Browser Gateway implementation `5aae281` pass
  focused/full race-shuffle, vet, Contract verification, and the unchanged
  48-case Suite. E2E lock `9eb32ba` passes independent-module race/shuffle and
  vet plus clean local Reference and Candidate runs
  `20260904T013909.243838000Z`/`20260904T014037.825223000Z`, each with 15+5
  coding/shell scenarios against Provider `5aae281`. These are regression
  evidence only and contain no Browser scenario. Repository CI `33826813073`
  and hosted Reference/Candidate regressions `33826813099`/`33826813100` also
  pass the same lock; their caller runs still contain no Browser scenario.
  Browser command/runtime composition, public Gateway integration, advertisement,
  Browser caller, real platform, multi-controller, multi-tenant, deployment,
  and production evidence remain explicitly open.

## Next work

The image, session/application/reference/usage components, fail-closed Docker
adapter, real provenance verifier, restricted-egress provisioner, create-time
policy binding, protected handlers, and caller-owned Gateway now have evidence
within their named boundaries. Next, add the complete default-disabled Browser
command/runtime graph and integrate the Browser Gateway only behind an explicit
caller-owned public edge without weakening those bindings. Then add independent
Browser caller scenarios. Do not enable advertisement until that graph passes
its fault/security and external-caller gates; Browser E2E remains separate from
coding/shell harness runs.
