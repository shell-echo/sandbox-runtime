# P4 Optional Profiles

Status: Browser Contract/Go projection, exact sandboxed signed amd64/arm64/v8
image publication, Provider-local session/application/reference/usage, Docker
runtime/private relay, provenance, restricted egress/create policy, protected
transport, and caller-owned Gateway components have named evidence. ADR 0025
and implementation `66183b1` compose the default-disabled Browser Provider
graph. ADR 0026 and harness `79fee2b` add the separate reference deployment and
black-box caller; hosted run `33838215924` passes all 10 initial and 5
process-reconstruction Browser scenarios against Provider `f760369`. ADR 0027,
capacity implementation `7b062e6`, and capacity harness `28a9a5e` extend that
path with process-local Browser Gateway connection capacity; hosted run
`33846603547` passes 11 initial and 5 reconstruction scenarios against Provider
`7b062e6`, including active same-session contention and release. Production
Browser advertisement and public Gateway deployment remain absent. ADR 0028,
implementation `44ea2ee`, and harness `249cdd4` add a process-local global
connection/fixed-window request gate before Browser WebSocket admission and
upgrade. Clean local run `20260904T080946.250607000Z` passes 12+5 scenarios,
including authenticated wrong-Origin edge rejection and recovery without
Gateway audit identity. Hosted run `33854020809` passes the same 12+5 set
against harness/Provider `e7e7f03`/`44ea2ee`; artifact
`browser-reference-e2e-evidence-33854020809` has digest
`sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`.
This work does not close
listener/TLS/HTTP limits, partition-aware shared capacity, distributed durable
revocation, P3, real Agent Platform, aggregate conformance, multi-controller,
multi-tenant, deployment, or production gates.

ADR 0029 and implementation `b8f8941` subsequently add a bounded
accepted-connection listener, frozen server-auth certificate, TLS
1.3/HTTP/1.1-only policy, explicit HTTP header/time limits, and context-aware
lifecycle. Local Browser run `20260904T091156.303717000Z` passes 13+5 on
`linux/arm64` against harness `35cf068`; hosted run `33857739150` passes 13+5
on `linux/amd64` against harness `7a20d9d`. Its inspected artifact
`browser-reference-e2e-evidence-33857739150` has digest
`sha256:94bcdfa53b667d4a6bc17fd6714cc9895e8402b830b8c6425c604c835f9228f`.
This closes only the listener/TLS/HTTP component and Browser reference-caller
scenario. Partition-aware shared or distributed capacity, durable distributed
revocation, production storage/configuration and metrics, P3, real Agent
Platform, aggregate, multi-controller, multi-tenant, deployment, and
production gates remain open.

ADR 0030 and implementation `997fb0d` now add the required
authenticated-capacity port after exact grant binding, typed lease-loss and
unavailability handling, bounded release, deterministic
revocation/expiry/capacity termination priority, and a process-local memory
reference with atomic global, tenant, and session accounting. E2E lock
`49d1c20` passes the independent module race/shuffle, vet, and all three lock
checks. Repository CI `33940332882` and hosted Reference/Candidate/Browser runs
`33940332897`/`33940332881`/`33940332911` pass against harness `6b01b75` and
Provider `997fb0d`. Browser passes 13+5 on `linux/amd64`; artifact digest is
`sha256:f4133967b6e573c701b82c72dc4d101febd4e6b28199e188fa0c8db049bff9ae`.
This is port, memory-component, and single-process reference regression evidence
only. No real shared store, two-Gateway-process run, TTL/renewal, crash
reclamation, stale-owner fencing, distributed revocation, deployment, or
production gate is claimed.

ADR 0031 and implementation `9434540` subsequently add the Redis-compatible
shared-capacity adapter. Clean local evidence
`e2e/evidence/shared-capacity/20260905T061037.558537000Z` passes all 10 black-box
scenarios on `linux/arm64` through two independent Gateway OS processes and one
pinned Valkey authority, against harness/Gateway source `ddbb2c4` and Provider
baseline `2ed5e68`. The run covers atomic cross-process global/tenant/session
contention, unaffected-tenant service, renewal, confirmed loss, crash
reclamation, stale-owner fencing, renew/release cleanup, retained-store outage
failure closure and recovery, and evidence sanitization. It is local Gateway
shared-capacity evidence only: Contract metadata is pinned but not exercised,
and Valkey provenance, HA/failover consistency, durable distributed revocation,
downstream fencing, real Browser/CDP, Provider multi-controller, hostile
multi-tenant, real Agent Platform, deployment, and production gates remain
open.

Hosted Browser Shared Capacity E2E run `33949577876` independently passes the
same 10 scenarios on `linux/amd64` against harness/Gateway source `de297e7` and
Provider baseline `2ed5e68`. Artifact
`browser-shared-capacity-e2e-evidence-33949577876` has GitHub digest
`sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`;
downloaded run `20260905T062246.271594332Z` contains exactly six sanitized
manifest/report/audit/observation files. The audits contain 22 `authorized`, 22
`connected`, 18 `client_closed`, five `capacity_rejected`, two `capacity_lost`,
and two `capacity_unavailable` records; observations contain 22 `resolve` and
22 `dial` records. The manifest pins Contract/tree/48-case metadata with
`exercised=false`, Valkey amd64 child
`sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478`,
and `provenance_not_established=true`. This remains Gateway/Valkey-only
evidence and does not add Provider API, Browser/CDP, image provenance,
restricted-egress, Provider artifact/usage, HA, revocation, downstream fencing,
multi-controller, multi-tenant, real-platform, aggregate, deployment, or
production evidence.

ADR 0032 and implementation `c0a55d1` add an atomic exact-grant,
level-triggered revocation watch plus a Redis-compatible retained-tombstone
source/writer. Focused/full race-shuffle, vet, Contract verification, the
unchanged 48-case Suite, and tagged integration against the same pinned Valkey
index pass locally. Current E2E lock `59e08d5` passes local Browser 13+5,
Reference/Candidate 15+5, and shared-capacity 10/10 regressions. Those existing
modes do not execute a two-Gateway/independent-revoker retained-backend
scenario. Harness/Gateway source `e952ef9` adds the separate locked runner;
local `linux/arm64` run `20260905T095109.569973000Z` and hosted `linux/amd64`
run `33959122456` each pass all seven scenarios through two Gateways, two
black-box callers, one independent revoker, and one retained Valkey authority.
Contract identity remains metadata with `exercised=false`, the echo fixture is
not Browser/CDP, and downstream fencing plus all production gates remain open.

Hosted current-lock repository CI `33955437033` passes at repository revision
`c7fe24d`. Reference `33955436969` (15+5), Candidate `33955437046` (15+5),
Browser `33955436984` (13+5), and shared capacity `33955436968` (10/10 on
`linux/amd64`) pass with harness `c7fe24d` locked to Provider `c0a55d1`. Their
artifacts were inspected and retain their separately named boundaries; none
adds the missing independent revoker scenario.

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
  router matches both Browser routes and fails closed when no Browser
  application is injected. The default-disabled Browser command graph injects
  the application only after every exact dependency is validated; production
  startup still does not advertise the Browser capability.
- The repository has a browser image component under
  `profiles/browser/image/`, with immutable amd64/arm64 upstream pins,
  a fixed private guest endpoint, a fail-closed Chromium seccomp profile, and
  no unsandboxed launch path. Manual run `33724368530` published the signed
  two-architecture GHCR index
  `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`
  from source `58ed009`. Its workflow assertion and an independent registry
  inspection found exactly linux/amd64 and linux/arm64/v8. The image is not a
  composed browser runtime, session service, or deployable public Gateway.
- The `provider/browser` component supplies browser-specific domain
  types, runtime ports, durable memory/file authority, restart reconciliation,
  expiry/cancellation/unknown-outcome cleanup, opaque reference registry and
  resolver, operation projection, and bounded duration usage evidence. It is a
  single-controller Provider-local component.
- The Browser Docker adapter binds the exact published image and
  seccomp policy, numeric identity, read-only root, drop-all and
  no-new-privileges controls, finite resources, four bounded stable guest
  mounts, deterministic ownership, durable allocation evidence, and a fresh
  non-TTY `socat` relay to container-loopback CDP. It requires injected
  provenance verification and restricted-egress provisioning with no weaker
  fallback. Focused race/shuffle and a real Docker `network=none` relay test
  pass; the latter is private-transport component evidence only.
- The GitHub CLI provenance adapter rehashes a pinned absolute
  executable, fetches the bundle from the immutable GHCR artifact, verifies
  exact GitHub OIDC/Sigstore and SLSA identity, strictly rechecks one bounded
  signed statement, limits inherited environment, and preserves cancellation.
  Its focused/full tests and tagged live GHCR integration pass locally; hosted
  CI run `33737531693` passes its separate `browser-provenance` job. This is
  provenance-verifier component evidence, not complete Browser startup.
- The restricted-egress component maps an opaque create-time policy
  reference to a normalized local hostname allowlist and a per-allocation
  internal bridge. The Browser has one network and one private DNS resolver;
  the fixed gateway has the internal bridge plus an explicitly owned uplink and
  permits only validated DNS A, HTTP Host, TLS SNI, and public resolved
  addresses. Implementation `7e60340` passes focused/full race-shuffle, vet,
  the unchanged Contract verifier and 48-case Suite, and a real local Docker
  composition with the existing `gh` verifier and signed Browser image.
  Repository CI `33747803509` passes its four named jobs but does not execute
  the Browser restricted-egress tagged case. Implementation `f760369` adds
  bounded RFC 6891 EDNS0 compatibility without broadening hostname, address, or
  port policy; hosted Browser run `33838215924` passes the complete egress
  scenario with that fix. The current local tagged rerun was unavailable after
  its real provenance check timed out, so it is not counted as a local pass.
- ADR 0023 and `b8423f5` add a narrow protected-transport application port and
  the two Contract-authorized Browser handlers. They apply the existing
  mTLS/JWS/admission gate, reject unknown/oversized input before mutation state,
  correlate admitted and application identities, project Browser operations,
  enforce handoff expiry, and return only `ref:browser-session:*`. Full local
  race/shuffle, vet, Contract verification, and the unchanged 48-case Suite
  pass as transport component evidence.
- ADR 0024 and `5aae281` extend the existing caller-owned Gateway policy state
  machine with an exclusive Browser session identity and
  `ref:browser-session:*` namespace, exact resolved-endpoint binding,
  metadata-only audit, reconnect/revocation handling, and a separate RFC 6455
  adapter for Chromium CDP. Composition requires explicit caller authorization,
  revocation, recording, WebSocket admission, and Provider Browser resolver
  ports. Focused and full race/shuffle, vet, Contract verification, and the
  unchanged 48-case Suite pass locally.
- ADR 0025 and `66183b1` compose an explicit, default-disabled Browser command
  graph with exact image/provenance/network/create-policy, durable session and
  reference stores, operation/usage aggregation, recovery, and bounded reverse
  shutdown. It exposes only the protected Provider routes and adds neither a
  public Browser Gateway nor production Browser advertisement.
- ADR 0026 and capacity harness `28a9a5e` compose caller-owned authorization,
  revocation, recording, WebSocket admission, and reference resolution in a
  separate Browser-only reference deployment. Hosted run `33846603547` passes
  11 initial and 5 reconstructed-process scenarios against Provider `7b062e6`;
  artifact `browser-reference-e2e-evidence-33846603547` has digest
  `sha256:b024225aa3545fa56a7cc5113f29c0817a86ebc70c3976e10d81bf3507546cba`.
- ADR 0027 requires explicit total and per-session Browser Gateway connection
  limits. The single-process ledger rejects without queueing before revocation
  access or Provider resolution and releases on every exit path. It does not
  limit WebSocket upgrade or authorization work and is not distributed. The
  current black-box caller holds one CDP connection, observes one metadata-only
  capacity rejection without disrupting that connection, and reconnects after
  release.
- ADR 0028 and implementation `44ea2ee` require a separate process-local edge
  lease before Browser WebSocket admission and upgrade. The implementation
  combines non-queueing global connection capacity with a bounded fixed-window
  request rate, projects only generic `429`/bounded `Retry-After` or generic
  `503`, and holds the lease across the complete public connection. Local
  harness `249cdd4` passes 12+5 Browser scenarios; its 16-request authenticated
  wrong-Origin burst observes ordinary `403`, pre-upgrade `429`, and recovery,
  while the 20-record Gateway audit contains no `grant-browser-edge-*` identity.
  Hosted run `33854020809` passes the same 12+5 scenario set on `linux/amd64`
  against harness `e7e7f03`. This does not bound listener/TLS/HTTP work,
  partition by authenticated tenant, share capacity across processes, or make
  revocation durable or distributed.
- ADR 0029 and implementation `b8f8941` add a separate caller-owned TLS server
  that bounds accepted connections before TLS, freezes bounded regular-file
  certificate/key material before bind, allows only TLS 1.3 plus HTTP/1.1, and
  requires explicit header/read/write/idle limits. Harness `7a20d9d` and hosted
  run `33857739150` prove TLS downgrade rejection, slow and oversized header
  rejection before the handler, listener saturation, and recovery. This remains
  one-process reference evidence, not partitioned/shared capacity, distributed
  revocation, production configuration, deployment, or production readiness.
- ADR 0030 and implementation `997fb0d` require a separate caller-owned
  authenticated-capacity authority after exact request/grant binding and before
  revocation, authorized audit, Provider resolution, or dial. The Gateway
  terminates an active connection on typed lease loss/unavailability, does not
  reconnect, releases with an independent bounded context, and resolves
  simultaneous termination causes as revocation, then expiry, then capacity,
  then transport. The memory reference atomically enforces global, tenant, and
  exact tenant/sandbox/session limits and excludes caller, grant, credentials,
  handoff reference, and endpoint data from its subject. E2E lock `49d1c20`
  binds the co-located harness to Provider `997fb0d` and passes all three check
  modes locally. Hosted Browser run `33940332911` passes 13+5 and its active
  contention path reaches the authenticated memory authority. It does not
  implement shared-store TTL/renewal, ownership, crash reclamation,
  stale-owner fencing, or cross-process coordination.
- ADR 0031 and implementation `9434540` provide the Redis-compatible adapter;
  the shared-capacity lock pins Provider baseline `2ed5e68`, the exact Valkey
  index and native manifests, immutable policy fingerprint, Lua identities,
  and ten scenarios. Clean local run
  `20260905T061037.558537000Z` passes 10/10 on `linux/arm64` through two
  independent Gateway OS processes and the real pinned Valkey backend.
  Rejection occurs after WebSocket `101` and appears as a normal `1000` close,
  not HTTP `429`. The fixture uses a private echo resolver and does not exercise
  Provider routes, Contract cases, Browser/CDP, image provenance, restricted
  egress, artifacts, or usage. The Valkey digest is pinned, but provenance is
  explicitly not established; HA/failover, durable distributed revocation,
  downstream fencing, deployment, and production evidence remain open.
- Hosted run `33949577876` passes the same 10 shared-capacity scenarios on
  `linux/amd64` against harness/Gateway source `de297e7` and Provider `2ed5e68`.
  Its six-file sanitized artifact
  `browser-shared-capacity-e2e-evidence-33949577876` has GitHub digest
  `sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`.
  This is a second architecture and hosted execution result for the same narrow
  Gateway/Valkey boundary, not a Provider Contract or Browser runtime result.
- ADR 0032 and implementation `c0a55d1` replace the split revocation check/watch
  with one exact-grant level-triggered watch, cancel blocked resolve/dial work,
  and add a Redis-compatible retained-tombstone source/writer. The adapter
  verifies immutable policy, hashes namespace/grant identities, uses Redis
  server time for bounded lifetime and expiry, retains the greatest expiry,
  and fails closed on malformed state or authority loss. The real-Valkey
  component integration passes. E2E lock `59e08d5` pins Provider `c0a55d1`, and
  current local Browser, Reference, Candidate, and shared-capacity regressions
  pass without exercising the independent durable-revocation caller gate.
- Hosted current-lock repository CI `33955437033` passes at repository revision
  `c7fe24d`. Four regressions pass with harness `c7fe24d` locked to Provider
  `c0a55d1`: Reference `33955436969`, Candidate `33955437046`, Browser
  `33955436984`, and shared capacity `33955436968`. Their respective artifact
  digests are
  `sha256:68642bb9810b397fada89bdb2666c11d46ddc0961eec6d6fd7d5e826e7336a70`,
  `sha256:2b745f256e4a0e1bdfa46c5129b1d92548a6f7afd2630a0c0720eb552ed35147`,
  `sha256:a5b0be338190b39f16c27e2a7b31ba983022fc8da8f60fa23c9d4fdce1834173`,
  and `sha256:d99d76374c745fb9a7adcc9b7e09e1f24963641e7d86b277a9a0647b870acdc2`.
  Downloaded manifests and reports preserve 15+5 Reference, 15+5 Candidate,
  13+5 Browser, and 10/10 shared-capacity results. Browser still uses the memory
  revocation authority and shared capacity does not exercise revocation.
- Harness/Gateway `e952ef9` passes the separate durable-revocation caller gate
  locally in `20260905T095109.569973000Z` on `linux/arm64` and in hosted run
  `33959122456` on `linux/amd64`. Each run passes 7/7 scenarios with two Gateway
  processes, two black-box caller processes, one independent revoker process,
  and pinned retained Valkey. Local A/B propagation is 72/72 ms and hosted is
  97/99 ms, all under the 2-second bound. Hosted artifact
  `browser-durable-revocation-e2e-evidence-33959122456` has digest
  `sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`.
  This closes only ADR 0032's durable exact-grant caller gate; Contract is
  metadata with `exercised=false`, ACL role separation and Valkey provenance
  are not established, and the fixture proves no Browser/CDP, downstream
  fencing, real platform, multi-controller, hostile multi-tenant, deployment,
  or production behavior.
- `blocks/` can validate an internal digest-pinned Block manifest, but it does
  not authorize a Provider capability or establish image provenance.
- A real Agent Platform caller and migration traffic harness remain unavailable;
  the co-located candidate harness is evidence only within its named boundary.

## Profile order and gates

| Order | Profile | First slice | Required gates before advertisement |
| --- | --- | --- | --- |
| 1 | Browser | Contract authority, exact signed amd64/arm64/v8 sandbox publication, default-disabled runtime composition, independent Browser reference caller, process-local Gateway and pre-upgrade limits, bounded listener/TLS/HTTP behavior, the ADR 0030 authenticated-capacity port/memory reference, ADR 0031 local arm64 plus hosted amd64 real-Valkey two-Gateway shared-capacity evidence, ADR 0032 exact-grant revocation port/Redis-compatible adapter component, and local plus hosted seven-scenario two-Gateway/independent-revoker caller evidence are complete within their named boundaries | Downstream fencing, Valkey provenance, HA/failover consistency, production storage/configuration and metrics, remaining hostile-tenant and operational evidence, production advertisement, and deployable caller-owned Gateway |
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

These began as wire and projection authorities. ADR 0023 gives both routes
bounded protected-handler component evidence; ADR 0024 supplies the
caller-owned Browser Gateway component; and ADRs 0025/0026 compose and exercise
the complete reference path. Production advertisement and a deployable public
Gateway remain outside those reference-only slices.

## Browser authority result

The 2026-09-02 audit inspected the locked Contract resources rather than
inferring support from generic schema vocabulary:

| Contract surface | Locked result | Remaining implementation gate |
| --- | --- | --- |
| Capability snapshot | Browser-only `1.0.0`/`browser-v1` maps to `sandbox-runtime-browser-v1`; mixed, wrong-version, wrong-profile, and wrong-runtime shapes fail closed. The reference deployment advertises only this shape | Keep production advertisement disabled until the remaining profile-specific security, concurrency, deployment, and operational gates pass |
| Create request | Browser fixture binds exact capability/runtime, digest-pinned amd64 image authority, restricted network policy, stable workspace, and unprivileged security fields. The default-disabled command graph preserves these bindings and the hosted caller proves lifecycle creation | Replace development/single-controller dependencies with reviewed production configuration before deployment |
| Session and handoff | Separate schemas and routes bind session/operation/attempt/fence identity and expose only an expiring opaque reference. Hosted initial and reconstructed-process scenarios prove the combined Provider and caller-owned Gateway path | Add distributed reliability and production deployment evidence without exposing backend identity |
| Gateway security | Semantic rules leave user/tenant authorization, revocation, audit, reconnect, and fresh reference resolution with the caller. Hosted reference scenarios prove wrong-caller/cross-tenant denial, expiry, active revocation, metadata-only audit, and reconnect. ADR 0027 adds non-blocking single-process total/per-session connection capacity before revocation and Provider resolution; run `33846603547` actively proves same-session rejection and slot reuse. ADR 0028 adds a process-local global connection/rate gate before Browser WebSocket admission and upgrade; hosted run `33854020809` proves rejection/recovery and Gateway-audit exclusion. ADR 0029 adds process-local listener/TLS/HTTP bounds; hosted run `33857739150` proves downgrade/slow-header/oversized-header rejection and capacity recovery. ADR 0030/`997fb0d` add the post-binding authenticated-capacity port, lease-loss semantics, and a global/tenant/session memory component; `49d1c20` locks the co-located harness. ADR 0031/`9434540`, local run `20260905T061037.558537000Z`, and hosted run `33949577876` add Redis-compatible atomic leases plus 10/10 arm64 and amd64 two-Gateway real-Valkey shared-capacity evidence. ADR 0032/`c0a55d1` add exact-grant level-triggered revocation and a Redis-compatible retained-tombstone adapter; harness `e952ef9`, local run `20260905T095109.569973000Z`, and hosted run `33959122456` pass its separate two-Gateway/independent-revoker seven-scenario caller gate | Add downstream fencing, establish Valkey provenance and HA/failover consistency, then add hostile multi-tenant, abuse, metrics, production configuration, and deployable public-edge evidence |
| Usage | Browser duration meter and operation/sandbox correlation are locked under the shared usage route; hosted initial/resume scenarios prove partial and complete duration evidence | Keep platform publication and billing truth outside the Provider; add production retention and reconciliation evidence |
| Fixtures and Suite | Success/rejection/security/admission fixtures and 10 new Suite cases raise the locked Suite from 38 to 48 cases | Add runtime fault/concurrency/image cases in later slices; current Suite is Contract projection evidence only |
| Runtime image | ADR 0019 removes every `--no-sandbox` path, binds seccomp digest `sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`, and passes local/native amd64 and arm64 sandbox gates. Run `33724368530` publishes exact signed index `sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`; attestation `44912296` and independent platform inspection verify. The Docker adapter, provenance verifier, restricted egress, default-disabled command graph, and hosted `linux/amd64` reference caller machine-bind and exercise that publication | Publish and review the restricted-egress Gateway image and production deployment configuration separately |

The Contract rows remain authority evidence; component, command-composition,
and external-caller results are recorded separately below. None makes the
internal Block manifest a wire resource or establishes production readiness.

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
- Browser session component commit `9a5d225`; preceding hosted E2E harness/Provider
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
  pass the same lock; their caller runs still contain no Browser scenario; and
- ADR 0025 and command/runtime implementation `66183b1` pass configuration,
  exact dependency binding, lifecycle readiness, operation/usage aggregation,
  recovery, cleanup ordering, focused/full race-shuffle, vet, Contract, and
  48-case Suite gates. ADR 0026 and harness lock `79fee2b` then pass hosted
  Browser Reference E2E run `33838215924` against Provider `f760369`: 10 initial
  and 5 process-reconstruction scenarios on `linux/amd64`, including CDP,
  allowed/denied egress, wrong-caller/cross-tenant denial, grant expiry,
  revocation, partial/complete usage, mTLS binding rejection, reconnect, and
  cleanup. Artifact digest is
  `sha256:4acfbc97c0c1f64e987b00870849a2244e33596918d08e659385c428310843ea`.
  Repository CI `33838215949` passes `provider-contract`, `test`,
  `browser-provenance`, and `docker-integration`. Production advertisement,
  deployable public Gateway, real platform, aggregate conformance,
  multi-controller, hostile multi-tenant, deployment, and production evidence
  remain explicitly open.
- ADR 0027 and its Browser Gateway capacity implementation pass focused
  concurrent race/shuffle tests for explicit configuration, total and
  per-session rejection, pre-resolver enforcement, metadata-only rejection
  audit, stream closure, revocation release, and slot reuse. Implementation
  `7b062e6`, harness `28a9a5e`, and repository CI `33846603580` pass the full
  local/hosted gates. Hosted Browser Reference E2E `33846603547` passes 11+5
  scenarios and actively verifies that a second same-session grant is rejected,
  the admitted CDP connection remains usable, and a replacement connects after
  release. Artifact digest is
  `sha256:b024225aa3545fa56a7cc5113f29c0817a86ebc70c3976e10d81bf3507546cba`.
  Hosted Reference/Candidate coding/shell regressions
  `33846603323`/`33846603454` also pass 15+5 against the same lock, but contain
  no Browser scenario and do not add Browser or real-platform evidence. This is
  single-process capacity plus Browser reference external-caller evidence, not
  a distributed, hostile-tenant, deployment, or production result.
- ADR 0028 and implementation `44ea2ee` add a required process-local global
  connection/fixed-window request limiter before Browser WebSocket admission
  and upgrade. Focused race/shuffle tests cover invalid configuration,
  contention, recovery, rate/capacity ordering, cancellation, clock failure,
  typed-nil dependencies, generic HTTP projection, and release paths. Full
  repository race/shuffle, vet, Contract verification, and the unchanged
  48-case Suite pass. E2E lock `3b63c76` and harness `249cdd4` pass the
  independent module gates and a clean local 12+5 Browser run. The added caller
  burst proves pre-upgrade `429` plus recovery, and the structured audit check
  proves no `grant-browser-edge-*` request reached the Gateway audit. Repository
  CI `33854020951` passes all four jobs. Hosted Browser run `33854020809` passes
  the same 12+5 set against harness/Provider `e7e7f03`/`44ea2ee`; inspected
  artifact `browser-reference-e2e-evidence-33854020809` has digest
  `sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`.
  Hosted Reference/Candidate `33854020874`/`33854020947` separately pass 15+5
  coding/shell scenarios. This is a process-local Browser service and Browser
  reference external-caller result, not listener/TLS/HTTP,
  tenant-partitioned/shared, distributed revocation/capacity, deployment, or
  production evidence.
- ADR 0029 and implementation `b8f8941` pass focused/full race-shuffle, vet,
  Contract verification, and the unchanged 48-case Suite. E2E harness
  `7a20d9d` passes its full race/shuffle, vet, and three check modes. Clean local
  Browser run `20260904T091156.303717000Z` passes 13+5 on `linux/arm64`;
  repository CI `33857739103` passes all four jobs; hosted Browser run
  `33857739150` passes 13+5 on `linux/amd64`. The inspected artifact digest is
  `sha256:94bcdfa53b667d4a6bc17fd6714cc9895e8402b830b8c6425c604c835f9228f`.
  Hosted Reference/Candidate regressions `33857739105`/`33857739189` separately
  pass their 15+5 coding/shell sets. This is listener/TLS/HTTP component and
  Browser reference evidence only, not shared/distributed capacity, durable
  distributed revocation, hostile-tenant, deployment, or production evidence.
- ADR 0030 and implementation `997fb0d` pass focused and full repository
  race/shuffle, vet, Contract verification, and the unchanged 48-case Suite.
  Tests cover dependency and limit validation, authorization/acquisition
  ordering, exact grant binding, atomic global/tenant/session contention,
  no-partial reservation, cross-caller/grant same-session enforcement, tenant
  independence, cancellation, loss/unavailability, idempotent bounded release,
  release-failure audit, stable termination priority, reconnect suppression,
  and concurrent acquisition/release. E2E lock `49d1c20` passes the independent
  module race/shuffle, vet, and Reference, Candidate, and Browser lock checks
  against Provider `997fb0d`. Repository CI `33940332882` passes all four jobs.
  Hosted Reference/Candidate `33940332897`/`33940332881` pass their separately
  named 15+5 coding/shell sets. Hosted Browser `33940332911` passes 13+5 on
  `linux/amd64`; inspected artifact
  `browser-reference-e2e-evidence-33940332911` has digest
  `sha256:f4133967b6e573c701b82c72dc4d101febd4e6b28199e188fa0c8db049bff9ae`.
  Its 20-record metadata-only audit has six `authorized`, six `connected`, four
  `client_closed`, and one each `capacity_rejected`, `denied`, `expired`, and
  `revoked`, with no edge grant, endpoint, token, credential, CDP, or payload
  field. These results remain single-process reference regressions, not real
  shared-capacity evidence.
- ADR 0031 and implementation `9434540` add a Redis-compatible capacity adapter
  with immutable policy verification, one bounded sorted-set record per lease,
  atomic Lua acquisition/renewal/release, server-time expiry, conservative
  renewal, TTL crash reclamation, and opaque owner plus monotonic fencing.
  Shared-capacity Provider baseline `2ed5e68` and clean harness/Gateway source
  `ddbb2c4` pass the locked local run
  `20260905T061037.558537000Z`: all 10 scenarios pass on `linux/arm64` through
  two independent Gateway OS processes and Valkey index
  `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
  with arm64 child
  `sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e`.
  The policy fingerprint is
  `1b29321807530907a8407cd6d33bdefbbb980fd7cb0b297592181a2333a8bacd`.
  The manifest sets `contract.exercised=false` and
  `provenance_not_established=true`; this local result is not hosted evidence or
  a Provider Contract, Browser/CDP, HA, durable-revocation, downstream-fencing,
  multi-controller, multi-tenant, platform, deployment, or production result.
- Hosted Browser Shared Capacity E2E run `33949577876` passes the same 10 cases
  on `linux/amd64` against harness/Gateway `de297e7` and Provider `2ed5e68`.
  Downloaded run `20260905T062246.271594332Z` contains exactly six sanitized
  files; artifact
  `browser-shared-capacity-e2e-evidence-33949577876` has GitHub digest
  `sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`.
  Its metadata remains `contract.exercised=false` and Valkey
  `provenance_not_established=true`, so the local evidence boundaries still
  apply unchanged.
- ADR 0032 and implementation `c0a55d1` add the exact-grant level-triggered
  revocation port, fail-closed memory behavior, and Redis-compatible
  retained-tombstone source/writer. Focused/full race-shuffle, vet, Contract verification,
  the unchanged 48-case Suite, and tagged integration against pinned Valkey
  index
  `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
  pass locally. E2E lock `59e08d5` pins Provider `c0a55d1`. Current local Browser
  `20260905T080015.795386000Z` passes 13+5, Reference
  `20260905T080530.577843000Z` and Candidate
  `20260905T080623.861033000Z` each pass 15+5, and shared-capacity
  `20260905T080725.227680000Z` passes 10/10 on arm64. Browser still uses one
  process-local memory revocation authority and shared capacity does not execute
  revocation, so none closes the independent durable-revocation caller gate.
- Harness/Gateway `e952ef9` adds the separately locked durable-revocation
  runner. Clean local run `20260905T095109.569973000Z` and hosted run
  `33959122456` each pass all seven scenarios on `linux/arm64` and
  `linux/amd64`, respectively. The downloaded hosted artifact contains exactly
  seven sanitized files and has GitHub digest
  `sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`.
  This is exact-grant Gateway/Valkey caller evidence only; Contract is metadata
  with `exercised=false`, and no Browser/CDP, downstream-fencing, Valkey
  provenance/HA, ACL role separation, platform, tenant-security, deployment,
  or production claim is added.

## Next work

The Browser authority, image, Provider-local components, default-disabled
command/runtime graph, independent reference-caller chain, process-local
Gateway connection capacity, process-local pre-upgrade Browser service gate,
bounded listener/TLS/HTTP component, and authenticated-capacity port/memory
reference now pass their named evidence gates. The ADR 0031 adapter and local
arm64 plus hosted amd64 two-Gateway real-Valkey shared-capacity gates also pass.
ADR 0032 now passes its exact-grant revocation port and real Redis-compatible
adapter component gate plus its separately locked local and hosted
two-Gateway/independent-revoker caller gate. Next, define downstream CDP fencing
as an independent ADR/gate, then establish Valkey provenance and HA/failover
consistency and add metrics, production storage/configuration, hostile-tenant,
and operational evidence before reviewing production advertisement.
Keep Browser Reference E2E separate from coding/shell, real Agent Platform,
aggregate conformance, multi-controller, multi-tenant, deployment, and
production evidence. After the Browser readiness record is complete, begin the
Desktop Contract/authority audit as the next optional profile rather than
reusing Browser or terminal routes.
