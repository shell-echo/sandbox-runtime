# sandbox-runtime

P2.7c.2 is implemented through c2b.7: the producer builds the closed sanitized
transcript and the report validator independently recomputes RFC 8785/SHA-256
from `process-supervisor.json`'s `adapter_transcript_projection`. It binds the
protocol, phases, invocations, processes, executables, configurations and field
inventory, and checks message order, derived counts and status consistency.
Physical byte counts, EOF/exit and process truth remain supervisor inputs, not
independent observations made by this validator. No independent external-caller
qualification result is claimed. c3.1 adds descriptor-backed, bounded executable
preflight and rechecking without launching a process. The fixed 24-step plan
has 21 completed and 3 unfinished steps. c3.2 implements the final static
configuration commitment, exclusive custody transfer and one-shot logical phase
admission with live descriptor rechecks. Reconstruction uses the existing
protocol completion gate; outer-harness evidence remains open.
c3.3 implements actual local spawn, endpoint handoff and bounded stop/reap.
c3.4 exclusively decodes and binds the first stdout startup identity before any
invocation or credential byte; Darwin/Linux tests execute repository helpers
only, not an independent caller, and release identities remain assertions. c3.5
validates the invocation against committed locations/startup requirements, then
concurrently delivers bounded stdin and inherited-pipe payloads with EOF. c3.6
starts one monotonic run budget before the first supervisor preflight read,
preserves it across reconstruction, clips every case and operation deadline,
drains bounded stderr concurrently, and accepts actual completion only after
ordered output, terminal, stdout EOF and a clean reaped exit. c3.7 publishes
sanitized evidence only after that completion, assigns opaque non-PID process
identities, prevents external inputs from overriding observed adapter facts,
and finalizes one canonical two-phase transcript. Real Darwin/arm64 and
Linux/arm64 Lima helper tests pass. d1 now freezes a sanitized target identity,
the exact profile-derived topology, 11 artifact requirements, all 10 ordered
configuration identities, the numeric runtime/cleanup budget, and the 15+5
scenario inventory before runtime setup. d2 now obtains target, artifact, and
configuration identities only through a read-only observer, creates three
descriptor-backed persistent stores, locks the authoritative inspector scope,
and requires a complete zero-resource baseline before exposing prepared state.
d3 releases mutation capability only after rechecking that state and baseline,
passes the executor a closed identity-and-case directive with no request,
endpoint, credential, correlation, or signing fields, and consumes exactly 15
ordered progress results under clipped per-case and execution deadlines. It
enforces dependencies, per-interaction wire-attempt bounds, and provisional
transport/request counters while retaining cleanup after an unknown start.
d4 admits reconstruction only after a terminal initial result and passes a
closed eight-field directive containing only identities, ordered case IDs, and
symbolic restart/preservation policy. It requires two distinct invocation IDs
and eight unique opaque non-PID labels across the four old/new process pairs,
rechecks persistent-store identity without reading entries, and consumes the
five ordered reconstruction results under the original execution deadline.
d5 adds four source-specific, read-only observer ports, binds their identities,
41 interaction results and exact 66/17/7/1 fact projections to the locked
profile and d2-d4 state, independently corroborates process replacement,
transcript, shell-challenge and resource-scope facts, and derives scenario
`passed`/`failed`/`incomplete`/`not_executed` plus conservative admission
counters. Repository fixtures prove this component logic only; they are not
independent caller evidence. d6 consumes the persistent cleanup obligation in a
separate bounded context, binds the operator-owned teardown identity, closes
local state descriptors, and requires exactly three same-scope, one-second-
spaced zero-resource samples equal to the baseline before declaring cleanup
successful. d7 now assembles and validates the closed evidence root as a local
component. A separate external-caller repository has completed 10 of its 13
local candidate checkpoints through e1.7c: all 15 initial and all 5
reconstruction cases are locally composed from durable `initial_complete`
state without private correlation reinjection, and its candidate-owned process
cleanup, failure mapping and output ordering/limits are locally closed. It pins
the refreshed authority. Its e1.8a local builder now produces a deterministic
source archive, archive-derived immutable startup identity, byte-identical
double builds and a strict three-artifact manifest, but the manifest honestly
records no independent source hosting or build attestation. Operator-owned resource teardown and stable
zero-resource inspection remain unexecuted. External
ownership/provenance, independent runtime interoperability and observations,
the actual 15+5 run, and a qualification result remain open. The main P2.7
plan therefore remains 21/24, with e1 in progress and e2/e3 pending.

Composable Linux sandbox runtime for remote shells, desktops, browsers, and applications.

`sandbox-runtime` is an early-stage runtime project for launching, accessing, and controlling remote workloads inside isolated Linux sandbox instances. It is designed to become a reusable foundation for products such as remote shells, cloud browsers, remote desktops, browser automation workers, AI-operated sandboxes, and embedded remote application environments.

The project is intentionally **runtime-first**. It is not just a cloud browser UI, a room/session collaboration product, or a single-purpose remote desktop application. The goal is to define a composable runtime layer where display, audio, input, streaming, clipboard, storage, networking, automation, and application blocks can be combined according to the needs of the product built on top.

## Status

This repository is in active implementation. The coding/shell and Browser
reference-caller gates and the local plus hosted two-Gateway shared-capacity
gates pass within their separately named evidence boundaries. ADR 0032 also
passes its caller-owned exact-grant revocation port and real-Valkey adapter
component gate plus its separate local and hosted two-Gateway,
independent-revoker black-box gate. ADR 0033 passes its downstream CDP fencing
component and real-backend adapter integration gate. Local run
`20260906T050213.016063000Z` at harness `550c785` and hosted run `34013982796`
at harness `2cadc53` each pass all 13 downstream-fencing scenarios on
`linux/arm64` and `linux/amd64`, respectively. The runs use two independent
mTLS/JWS caller processes, two Gateway processes, one authenticated unique
ingress, retained Valkey state, and the exact signed Browser image running real
Chromium. They close only the platform-specific ADR 0033 external-caller gates.
ADR 0034 adds an explicitly selected v2 component with a bounded permanent
session-history hash and an independent monotonic restore witness. Its local
race/shuffle, vet, Contract verifier, unchanged 48-case Suite, and pinned-Valkey
adapter gates pass. The existing reference stack and both ADR 0033 caller runs
still use v1; they are not v2 deletion/restore evidence. The separately locked
v2 runner passes all 18 scenarios locally on `linux/arm64` in run
`20260906T100233.295973000Z` and in hosted `linux/amd64` run `34026680591`, both
at fixed harness `059357c`. It uses two Gateways, two independent
mTLS/JWS callers, one unique ingress, signed real Chromium, an orchestrator-only
Redis fault credential, and an independent file witness. The local exact
five-file set is `0600`; both runs pass cleanup and sanitization. These close
only the platform-specific ADR 0034 external-caller gates. ADR 0035 now adds a
PostgreSQL production-candidate witness adapter, explicit least-privilege
migration, and a strict read-only controlled-restore check. Its local unit,
full-repository, Contract, Suite, and pinned-Valkey strict-recovery checks pass;
hosted workflow run `34031784793` at implementation `3ff58dc` passes the real
PostgreSQL migration, role, concurrency, timeout, and combined pinned-Valkey
rollback gate. That run resolved and the workflow now pins PostgreSQL digest
`sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`.
This is not a production witness. ADR 0036 now implements a separately locked
same-runner controlled-restore reference: PostgreSQL-backed witnessed fencing,
Provider/private-ingress quarantine, older-Redis rejection through strict
read-only verification, exact-state repair, and post-resume real CDP. PR #47
merged as `a0cddf4`; post-merge `linux/amd64` run `34038556283` passes all 18
scenarios. Its independently inspected artifact contains exactly five sanitized
files, pins `harness_commit=a0cddf4`, and records all cleanup and sanitization
checks as true. PostgreSQL and Valkey still share one host, Docker engine,
operator, and workflow, so this profile cannot establish independent failure or
backup domains.
Valkey provenance and HA/failover, production Browser
advertisement/public Gateway composition, aggregate conformance,
multi-controller, hostile multi-tenant, deployment, and production gates remain
open. The former named Agent Platform migration track is retired; external
consumers must implement the repository-owned Provider calling standard. The
ADR 0033, v2, and controlled-restore profiles
pin Contract identity but do not execute the Suite (`suite_exercised=false`).

ADR 0038's listener-local caller trust domain remains implemented. The current
Contract authority is revision `22ba6987ea5fbc37d53942720133c0acad199edd`,
tree `c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38`, and manifest
`sha256:1e17e0ef4f86e03be1dac22c48e7b556a8600a4baa6252f4514390d339b8ba3f`.
It contains a content-derived 53-case local `repository-go-test` Suite at
`sha256:b40c932643f4a1e5fd6681e3abf9b64a607609866a6254456970f8b8034cf2a8`
and the unchanged 6-case `remote-http-black-box` discovery Suite. The refreshed
Contract verifier, root tests/vet, and E2E lock logic pass in the current
worktree. A clean VCS-built 53-case Runner, the E2E parent-lock gate, and all
eight E2E `-check` commands remain pending until the refresh is committed and
run from a clean checkout; no new P2.6 pass is claimed. The prior P2.6 release
gate remains historical evidence at implementation `3fe314a` and E2E lock
refresh `ae476fed12e82f472b19ff78fda633c8d702561d`. Docker
reference run `20260907T044611.598221000Z`
remains historical 15+5 evidence against its recorded `b8d4829`/`af8a505`
harness/Provider identity; it is not relabeled as P2.6 evidence. Neither Suite
proves interoperability with an independently implemented external caller,
protected or mutating remote conformance, aggregate conformance, hostile
multi-tenant safety, HA, deployment, or production readiness.

Merge commit `a0cddf4` passes repository CI `34038556281`, Reference
`34038556295`, Candidate `34038556284`, Browser `34038556297`, shared-capacity
`34038556314`, durable-revocation `34038556293`, downstream-fencing v1
`34038556291`, downstream-fencing v2 `34038556299`, PostgreSQL witness
`34038556301`, and PostgreSQL controlled restore `34038556283`. The independently
inspected controlled-restore artifact
`browser-postgres-controlled-restore-e2e-evidence-34038556283` has ID
`9991028239` and GitHub digest
`sha256:72d822c44c2ab5e91ed500f5ef549d8ec1c63268443a48fa293c93a3d24ca14e`.
These remain ten distinct workflows and eight separate E2E tracks, not
aggregate conformance.

An intermediate v2 workflow `34025787520` at `ef63be4` exposed a verifier
false negative: Redis/Valkey `DUMP` bytes for a restored hash were treated as a
canonical logical representation. Fix `059357c` retains real `DUMP`/`RESTORE`
fault injection but verifies restored string/hash/zset content and TTL semantics
instead; both fresh platform-specific runs above use that fix.

Start a new development session with
[`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md). It summarizes the current
architecture, engineering rules, verified maturity, blockers, and next work;
the detailed implementation evidence ledger remains in
[`docs/STATUS.md`](docs/STATUS.md). For normative caller obligations and the
Provider call sequence, see the
[`Sandbox Provider Calling Standard`](contract/specification/provider-calling-standard-v1.md).
The [`Provider Integration Profile`](docs/platform-integration-profile.md)
remains a non-normative implementation guide.

Currently implemented:

- Go control-plane service
- Cobra-based CLI
- TOML configuration loader
- environment-variable overrides with the `SANDBOX_RUNTIME_` prefix
- structured logging with optional file rotation
- Gin-based HTTP API server
- uniform JSON response envelope
- `/health` endpoint
- graceful multi-server lifecycle management
- Dockerfile for packaging the control-plane binary
- backend-independent instance model and lifecycle state machine
- concurrency-safe fake driver for lifecycle validation
- configurable fake and Docker runtime drivers
- instance lifecycle HTTP API backed by the selected driver
- separate Provider API v1 wire DTOs and locked Contract projection validation
- Provider-specific fake and Docker lifecycle adapters kept separate from local
  `/instances`, with stable coding/shell mounts in the Docker development adapter
- default-disabled Provider capability discovery on a separate mTLS-only HTTPS
  listener
- default-disabled protected-operation admission with one explicit
  listener-local caller issuer, a Provider-local instance audience and
  revision, 1..32 frozen public-key files, and a single-controller
  replay/fencing guard; the repository-local coordinated calling-standard gate
  passes
- default-disabled, development-only Provider exec composition over the Docker
  lifecycle runtime, a separate durable ledger, bounded private output capture,
  cancellation, result expiry, and restart reconciliation
- bounded `gateway.Stream` adapters for an admitted WebSocket edge and private
  terminal byte stream, plus a local composition that requires caller-owned
  authorization, revocation, recording, and a Provider reference resolver; no
  public Gateway route, command composition, or capability advertisement is
  enabled
- strict internal Block manifest parsing and a bounded read-only registry;
  this configuration format is not Provider wire behavior
- an optional Browser image component with native amd64/arm64 sandbox tests,
  a fixed fail-closed seccomp profile, an immutable GHCR index containing
  exactly linux/amd64 and linux/arm64/v8, and independently verified GitHub
  OIDC/Sigstore provenance; this image evidence does not by itself enable a
  Provider route
- Provider-local Browser session, opaque-reference, operation,
  duration-evidence, and fail-closed Docker runtime-adapter components; the
  adapter binds the exact signed image, private non-TTY CDP relay, stable guest
  mounts, and runtime limits
- a real GitHub CLI/Sigstore Browser provenance verifier and a real Docker
  restricted-egress provisioner. Browser lifecycle authority
  persists the create-time restricted policy; the adapter binds it to a
  per-allocation internal network, pinned private DNS/HTTP/TLS gateway, and
  exact hostname policy
- protected Browser open/handoff transport handlers that preserve admission
  correlation and project only an expiring opaque reference
- a caller-owned Browser Gateway boundary with separate
  `browser_session_id`/`ref:browser-session:*` identity, exact endpoint binding,
  metadata-only audit, bounded reconnect/revocation, RFC 6455 CDP framing, and
  explicit process-local total/per-session connection capacity. Its public
  Browser service also requires a process-local global connection/fixed-window
  request limiter before WebSocket admission and upgrade. A separate bounded
  TLS edge freezes server-auth material before bind, accepts only TLS 1.3 and
  HTTP/1.1, and limits accepted connections, header size, and HTTP timeouts.
  ADR 0030 also makes an authenticated-capacity authority explicit after exact
  grant binding; its memory reference atomically accounts for global, tenant,
  and session partitions and terminates an active connection if its lease is
  lost. ADR 0031 adds a Redis-compatible implementation with atomic shared
  global/tenant/session leases, renewal, TTL reclamation, and stale-owner
  fencing. A clean local `linux/arm64` black-box run passed all 10 scenarios
  through two independent Gateway OS processes and one pinned Valkey authority.
  Hosted workflow run `33970773388` separately passed the same 10 scenarios on
  `linux/amd64`; its GitHub Actions artifact digest is
  `sha256:2350e3fbed3801366ade3bb4ed204545c1b0f55037a2dc7148de2ef4952e4216`.
  Its private echo fixture does not call the Provider API or a real Browser/CDP;
  capacity rejection is a post-WebSocket-`101` normal `1000` close, not the
  pre-upgrade limiter's HTTP `429`. Contract/Suite identity is metadata only
  (`exercised=false`), and neither run covers Browser image provenance,
  restricted egress, or Provider artifact/usage behavior.
  Those shared-capacity runs do not establish Valkey provenance, HA/failover
  consistency, durable distributed revocation, downstream fencing, or
  production deployment. ADR 0032 and `c0a55d1` replace the split revocation
  check/watch with an exact-grant level-triggered watch, cancel blocked
  resolution/dial work on authority termination, and add a Redis-compatible
  retained-tombstone source/writer with immutable policy, server-time lifetime
  bounds, monotonic expiry retention, bounded polling, and fail-closed outage
  behavior. A separate clean `linux/arm64` run and prior inspected hosted
  `linux/amd64` run `33970773353` pass all seven retained-backend caller
  scenarios through two Gateway processes, two black-box caller processes, and
  one independent revoker process. The private echo fixture does not exercise
  Provider routes,
  the Contract, or a real Browser/CDP path, and the runs do not establish
  downstream fencing, Valkey provenance/HA, ACL role isolation, real Agent
  Platform compatibility, multi-controller, hostile multi-tenant, deployment,
  or production readiness
- ADR 0033 downstream CDP fencing ports, a Redis-compatible exact-member and
  retained session-high-water adapter, a private ingress component, and
  fail-closed Browser composition. Targeted and full race/shuffle tests, vet,
  the Contract verifier, the unchanged locked 48-case Suite, and tagged
  integration against pinned Valkey index
  `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
  pass at implementation `b4d41c9`. This remains component plus real-backend
  adapter integration evidence; the separately recorded local caller run below
  establishes only its named topology and scenarios
- ADR 0034 witnessed downstream-action successor component. One bounded
  permanent Redis hash retains exact session fingerprints and checkpoint state;
  a separate monotonic witness detects a retained Redis state restored behind
  it. The Darwin/Linux file witness is single-process component evidence and is
  independent only when deployed outside the Redis snapshot/restore domain.
  Focused and full race/shuffle tests, vet, Contract verification, the unchanged
  48-case Suite, and tagged integration against the same pinned Valkey index
  pass. The separate v2 caller harness passes 18/18 locally on `linux/arm64` in
  run `20260906T100233.295973000Z` and hosted on `linux/amd64` in run
  `34026680591`, both at fixed harness `059357c`; the Suite is not executed. No
  default composition or production advertisement selects v2
- ADR 0035 PostgreSQL action-history witness candidate. It binds rows to both
  private capacity-namespace and witnessed-v2 policy fingerprints, performs
  bounded durable conditional updates with `pgx/v5`, ships an explicit schema
  migration and least-privilege role guidance, redacts backend errors, and adds
  strict read-only `VerifyRestoredState` semantics. Local unit/full gates and a
  pinned-Valkey one-ahead non-mutation check pass. Hosted workflow run
  `34031784793` at `3ff58dc` passes the PostgreSQL and combined rollback tests;
  the workflow now pins the exact PostgreSQL digest resolved by that run. No
  provenance, HA, deployment, or production claim follows
- ADR 0036 PostgreSQL controlled-restore reference. The separately named
  18-scenario runner composes the ADR 0035 witness into the two-Gateway,
  two-independent-caller, unique-ingress, real-Chromium harness. It quarantines
  both Provider/private-ingress listeners before Redis restore, requires an
  older snapshot to fail strict `VerifyRestoredState` without advancing
  PostgreSQL, restores the exact current Redis state, and resumes real CDP only
  after an exact match. Post-merge `linux/amd64` run `34038556283` for merge
  `a0cddf4` passes 18/18; its inspected five-file artifact pins that exact
  harness commit and records all cleanup and sanitization checks as true.
  The profile records `same_runner=true` and `independent_failure_domain=false`
- downstream caller bootstrap implementation `58488d7`: two independently
  identified mTLS/JWS caller OS processes each perform Provider capability,
  create, operation, sandbox, Browser-session, and handoff reconciliation, bind
  the resulting opaque handoff only in private process state, and remain alive
  in the existing JSONL loop. The dual-process test is process/component
  evidence only; the downstream lock records `suite_exercised=false`
- downstream caller provisioning implementation `8a1049b` and lock foundation
  `fb1b2b0`:
  a trusted launcher passes one correlated request, private endpoint envelope,
  and exact final caller configuration over fixed FD 3/4/5 pipes. Strict
  bounded EOF-framed JSON, direction validation and close-on-exec setup, canonical live
  expiry, at-most-once delivery, cancellation/failure kill plus bounded wait, natural-exit
  cleanup, and Contract-wide handoff-reference validation pass process/component
  tests. FD5 delivery alone is not child acceptance; readiness requires a
  correlated JSONL response. `S_IFIFO` does not independently prove an
  anonymous pipe, so the launcher remains trusted
- downstream-fencing local harness/run `550c785`/
  `20260906T050213.016063000Z` and hosted harness/run `2cadc53`/`34013982796`:
  all 13 locked scenarios pass on `linux/arm64` and `linux/amd64`, respectively,
  through two Gateway processes, two independent caller processes, one
  authenticated unique ingress, retained Valkey, and signed real Chromium.
  The five local `0600` evidence files pass exact-set, private-material, audit,
  and cleanup checks. Downloaded GitHub artifact
  `browser-downstream-fencing-e2e-evidence-34013982796` contains evidence
  directory `20260906T052710.781616339Z` with exactly five sanitized files and
  has digest
  `sha256:9c00f3ba184e82d7eff661b831c05c1bdf331fa41caf2d8bbb3353168ab155b0`.
  These are ADR 0033 external-caller results only; the Contract Suite is not
  executed and no real-platform, aggregate, multi-controller, multi-tenant,
  deployment, or production claim is added
- a default-disabled Browser Provider command/runtime graph and a separate
  Browser-only reference stack plus black-box caller. Hosted Browser Reference
  E2E run `33970773330` passes 13 initial and 5 process-reconstruction
  scenarios through real mTLS/JWS HTTPS, WebSocket, signed-image provenance,
  Docker, restricted egress, concurrent same-session capacity rejection and
  release, authenticated wrong-Origin pre-upgrade rate rejection and recovery,
  TLS downgrade rejection, slow/oversized HTTP input rejection, listener
  saturation/recovery, usage evidence, and cleanup. The production command
  still exposes no public Browser Gateway and does not advertise Browser

Planned but not yet implemented:

- multi-issuer or multi-consumer admission on one protected listener; this
  requires separate identity, key-ID, replay, fencing, and policy namespaces
- independently implemented external-caller interoperability evidence beyond
  the same-repository generic reference caller
- use a deployment-owned environment to prove independent PostgreSQL/Valkey
  failure and backup domains, HA/failover, operator authorization, metrics, and
  rollback controls without promoting the passed same-runner reference to
  deployment evidence
- production Browser advertisement and deployable caller-owned Gateway
  integration only after those independent readiness gates pass
- runtime images for desktop workloads
- display, audio, input, streaming, clipboard, and file-transfer modules
- deployable WebRTC / VNC / public WebSocket Gateway composition
- web viewer and management console
- SDKs for embedding and automation

## What this project is for

`sandbox-runtime` is meant to provide a lower-level runtime foundation for systems that need to run GUI workloads remotely.

Example use cases:

- remote shell and terminal environments
- cloud browser infrastructure
- remote desktop environments
- isolated browser sessions for automation
- AI agents operating real GUI applications
- browser-based access to Linux desktop applications
- ephemeral GUI sandboxes for testing, demos, support, or education
- managed runtime backends for products that need streamed application UI

The long-term direction is to make GUI runtime capabilities composable rather than hard-coded into one product shape.

## Core ideas

### Control plane

The Go service is the control plane. It owns configuration, APIs, runtime orchestration, lifecycle management, policy, and driver integration.

### Runtime instance

A runtime instance is a sandbox environment with a backend-independent lifecycle. An instance may host a shell, browser, desktop, or application using a container or another isolation backend.

### Workload

A workload identifies what an instance hosts. The core model currently supports shell workloads without coupling them to a concrete driver or access protocol. Desktop and browser workloads will be added when their runtime behavior is implemented.

### Block

A block describes a runnable capability or application, such as `browser-chrome`, `browser-firefox`, `desktop-xfce`, or `app-vscode`. Blocks should eventually be defined by manifests rather than hard-coded Go code.

### Module

A module represents a runtime capability used by one or more blocks, such as display, audio, input, streaming, clipboard, file transfer, storage, networking, or automation.

### Driver

A driver is responsible only for creating, inspecting, starting, stopping, and removing the underlying runtime resource. Instance identity, lifecycle policy, and metadata persistence remain in the control plane. Driver removal is idempotent so interrupted cleanup can be retried safely. The Docker driver uses the official Moby Engine client with API-version negotiation, resource limits, restricted networking and capabilities, ownership labels, and retry-safe removal. The fake driver remains available for local control-plane development without a container engine.

### Instance service and repository

The instance service owns IDs, validation, lifecycle transitions, and coordination
with runtime drivers. API reads reconcile stable and transitional states against
the runtime; successful mutations are confirmed before their terminal state is
persisted. Repository implementations remain replaceable: fake development uses
memory, while Docker uses an atomically replaced, versioned state file and runs
startup recovery before accepting requests.

### Connector

A connector exposes access to a running instance. Examples include HTTP, WebRTC, WebSocket control channels, VNC, HLS, or automation protocols.

### Policy

Policy defines what an instance is allowed to do: resource limits, network access, filesystem mounts, clipboard permissions, automation access, and other runtime constraints.

## Architecture direction

The provider boundary, repository-owned Contract, security baseline, and
authoritative phased delivery plan are defined in
[the architecture document](docs/architecture.md). The independent-provider
ownership decision is recorded in historical
[ADR 0001](docs/adr/0001-agent-platform-provider-boundary.md) and its
generic-caller successor,
[ADR 0037](docs/adr/0037-sandbox-provider-calling-standard.md).

The intended long-term architecture is:

```text
sandbox-runtime/
├── cmd/            # CLI entrypoints and commands
├── config/         # typed configuration loading and validation
├── logger/         # structured logging abstraction
├── server/         # HTTP API server and lifecycle management
├── internal/       # internal error types and shared internals
├── option/         # reusable option/value objects
├── instance/       # instance model, service, repository contract and memory store
├── driver/         # runtime backends (fake and Docker)
│
├── blocks/         # future block manifests
├── runtime/        # future runtime images and guest scripts
├── webapp/         # future viewer and management console
├── docs/           # architecture, specs, and ADRs
└── deploy/         # deployment examples
```

The current repository starts with the Go control-plane foundation. Runtime images, block manifests, and web UI will be added as the project matures.

## Current HTTP API

The local management API and Provider API use separate listeners and wire
formats. Provider capability discovery is default-disabled. When explicitly
configured, its dedicated listener requires TLS 1.2 or newer, normal client
certificate chain verification, and an exact URI SAN match from an
operator-supplied allowlist of fragment-free absolute URI identities. No URI
scheme is hard-coded, and clients that fail certificate or URI identity
admission are rejected during the TLS handshake before HTTP routing.

With the default configuration, the admitted Provider surface contains only:

```http
GET /v1/capabilities
```

It returns a raw Provider API v1 document rather than the local management API
envelope. The immutable startup document intentionally advertises empty
`capabilities` and `runtime_profiles` arrays, plus at least one required,
content-addressed snapshot/restore compatibility profile. That compatibility
metadata does not advertise or authorize snapshot, restore, or another runtime
capability. The `protected_admission` configuration is independently disabled
by default. When explicitly enabled with an immutable public-key bundle and a
durable guard state file, it adds the protected-operation admission boundary.
Startup also requires one exact issuer, one Provider-instance audience, and the
same Provider revision used by the immutable capability snapshot. No issuer is
defaulted from legacy behavior or selected from the bearer. The listener
freezes 1..32 distinct verification keys and its admitted URI SAN identities
inside that one caller trust domain.

Rotation is an explicit restart procedure: install old and new public keys
under distinct `kid` values, restart, move the caller to the new signing key,
wait until every token accepted under the old key has expired, remove the old
key, and restart again. There is no remote JWKS refresh or simultaneous
multi-issuer listener. The component, Contract, conformance, and same-repository
reference gates for these implementation properties pass; deployment-owned key
rotation and independently implemented caller qualification remain separate.

Individually enabled Provider lifecycle and exec applications may then compose
only their locked routes. Exec requires the Provider Docker lifecycle runtime
and its own file ledger; the development adapters remain rejected in production.
A reconnectable terminal runtime/broker, Docker adapter, durable session
coordination application, and private opaque `ref:session:*` registry/resolver
now exist as development components. The file-backed registry reconstructs a
fresh terminal attach after restart and rechecks expiry, revocation, committed
session handoff, and identity bindings before each dial; it does not expose
backend data. A local Gateway composition requires caller-owned authorization,
revocation, recording, and WebSocket admission before it can proxy that fresh
attach. The Provider command root includes default-disabled development
artifact/usage composition but deliberately does not supply caller-owned public
Gateway policy. Default standalone startup therefore still advertises no
runtime capability. The separately versioned reference E2E stack in
 [`e2e/`](e2e/) supplies those caller-owned dependencies as an independent Go
 module and process boundary, and its exact atomic coding/shell advertisement
 and full reference caller scenarios pass locally; this does not turn the
 Provider default into a deployable production Gateway.

Capability discovery has no query parameters or request document. For request
metadata visible to the handler, a query string (including a bare trailing
`?`), nonzero or unknown `Content-Length`, and `chunked` transfer encoding are
rejected with an empty `400` before capability, application, repository, or
driver dispatch. The handler does not read or probe `Body`; this does not claim
that the Go server lifecycle never reads or drains request framing. Unsupported
transfer codings can instead be rejected by the Go `net/http` parser before the
handler with its standard-library `501` response. The repository-owned OpenAPI
authorizes both `400` and `501` for this operation; the implementation still
returns the bounded empty `400` handler response and observes the parser-level
`501` without claiming a Provider error document for either case until the
corresponding response projection tests pass.

### Health check

```http
GET /health
```

Example response:

```json
{
  "code": "ok",
  "message": "success",
  "success": true,
  "data": {
    "status": "ok"
  },
  "time": "2026-01-01T00:00:00Z",
  "latency": 0
}
```

All local management API handlers are expected to return the same response
envelope:

```json
{
  "code": "ok",
  "message": "success",
  "success": true,
  "data": {},
  "time": "...",
  "latency": 0
}
```

Typed errors are mapped to structured failure envelopes. Unexpected errors are hidden in production mode and only exposed in development mode.

### Instance lifecycle

The instance API uses the configured runtime driver. The default fake driver
validates the control-plane contract without creating containers. Selecting the
Docker driver creates real stopped containers that can be controlled through
the lifecycle API; interactive shell sessions are a later milestone.

```http
POST   /instances
GET    /instances
GET    /instances/:id
POST   /instances/:id/start
POST   /instances/:id/stop
DELETE /instances/:id
```

List instances:

```http
GET /instances
```

The response is an array sorted by instance ID. The service-level instance
quota bounds the size of this response.

Create a shell instance:

```json
{
  "name": "my-shell",
  "workload": "shell"
}
```

Instance names are limited to 128 characters. Request bodies are limited to
64 KiB, and the in-process service allows at most 1,000 instances by default.

### Docker runtime

The safe development default is the in-memory `fake` driver. Production mode
rejects that driver; to use Docker Engine, configure:

```toml
[runtime]
driver = "docker"

[repository]
driver = "file"

[repository.file]
path = "data/instances.json"

[runtime.docker]
host = ""                       # DOCKER_HOST or the default Docker socket
image = "alpine:3.23"
pull_policy = "if_not_present"  # never | if_not_present | always
memory_bytes = 536870912
nano_cpus = 1000000000
pids_limit = 256
operation_timeout_seconds = 30
pull_timeout_seconds = 300
stop_timeout_seconds = 10
user = "65532:65532"
namespace = "default"
controller_id = "runtime-dev-01"
command = ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]
```

The server checks Docker connectivity at startup when this backend is selected.
Containers have networking disabled, all Linux capabilities dropped,
`no-new-privileges` enabled, a read-only root filesystem, a bounded `/tmp`
tmpfs, bounded logs, a numeric non-root user, and CPU, memory, and PID limits.
Driver operations verify ownership labels before mutating a container. The
configured image must contain the configured command and allow it to run as the
configured user; override both values together for custom images. Give each
control-plane deployment a stable, unique controller ID when sharing a Docker
daemon. Namespace groups related resources, while controller ID establishes
ownership and must remain unchanged across restarts.
`controller_id` is required whenever the Docker driver is selected and is never
generated automatically. Changing it makes existing containers invisible to the
new controller; containers without the controller label are deliberately not
adopted.

Until an authentication layer is implemented, production mode accepts only a
loopback API listener. It also requires an image pinned by `@sha256:...` and
rejects plaintext remote Docker endpoints. Explicit Docker hosts continue to
honor the standard `DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH` settings.

Instance metadata is atomically persisted at `repository.file.path`. On startup
the service reconciles every persisted record with Docker, adopts correctly
labelled resources missing from the repository, rejects ownership metadata
conflicts, and finishes interrupted removals. Mount the parent directory on
durable storage when running the control plane itself in a container.
Only one process may open a repository path at a time; a stable `.lock`
companion file prevents two controllers from overwriting each other's snapshot.
The locked file repository currently supports Darwin and Linux.

The live Docker integration test is opt-in:

```bash
SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 go test -tags=integration ./driver/docker
```

## Quick start

### Requirements

- Go 1.26+
- Docker, optional

### Run locally

```bash
git clone https://github.com/shell-echo/sandbox-runtime.git
cd sandbox-runtime

go test ./...
go run . serve
```

The API server listens on `127.0.0.1:8080` by default. There is no application
authentication in v1. Production mode therefore rejects non-loopback listeners;
development deployments that override the bind address must provide their own
authenticated network boundary.

Test the health endpoint:

```bash
curl http://127.0.0.1:8080/health
```

### Run with a config file

A template config is provided at `config.tpl.toml`.

```bash
cp config.tpl.toml config.toml
go run . serve -c config.toml
```

`config.toml` is intended for local runtime configuration and should not be committed.

### Run with environment variables

Configuration values can be overridden with the `SANDBOX_RUNTIME_` prefix. Dotted config keys are converted to uppercase environment variables with `_` separators.

Examples:

```bash
SANDBOX_RUNTIME_APPLICATION_MODE=development \
SANDBOX_RUNTIME_LOGGER_LEVEL=debug \
SANDBOX_RUNTIME_SERVER_API_PORT=8081 \
go run . serve
```

## Docker

Build the image:

```bash
docker build -t sandbox-runtime .
```

Run it:

```bash
docker run --rm \
  -p 127.0.0.1:8080:8080 \
  -v sandbox-runtime-data:/app/data \
  sandbox-runtime
```

Then check:

```bash
curl http://127.0.0.1:8080/health
```

The current Docker image packages only the control-plane service. It does not yet include browser, desktop, or GUI runtime images.

## Configuration

The configuration system uses three sources, in increasing precedence:

1. built-in defaults
2. optional TOML config file
3. environment variables

Default config path:

```text
config.toml
```

Template config path:

```text
config.tpl.toml
```

Environment variable prefix:

```text
SANDBOX_RUNTIME_
```

Example config:

```toml
[application]
name = 'sandbox-runtime'
mode = 'development'

[application.timezone]
name = 'Asia/Shanghai'

[logger]
level = 'info'
add_source = false

[logger.file]
name = ''
max_size = 100
max_backups = 7
max_age = 30
compress = true

[server.api]
host = '127.0.0.1'
port = 8080
```

By default, file logging is disabled. Set `logger.file.name` to a non-empty path to enable rotated file output.

## CLI

```bash
sandbox-runtime --help
sandbox-runtime serve
sandbox-runtime serve -c config.toml
```

Current command:

| Command | Description |
| --- | --- |
| `serve` | Start the configured long-running servers. |

Future commands may include:

| Command | Purpose |
| --- | --- |
| `manifest validate` | Validate block manifests. |
| `block list` | List available runtime blocks. |
| `instance create` | Create a runtime instance. |
| `instance inspect` | Inspect a runtime instance. |
| `instance stop` | Stop a runtime instance. |

## Roadmap

The delivery phases and their release gates in
[the architecture document](docs/architecture.md#delivery-plan-and-release-gates)
are authoritative. Items below are ordered by dependency, not by product
visibility.

### Foundation

- [x] CLI skeleton
- [x] typed config loader
- [x] structured logger
- [x] HTTP API server
- [x] health endpoint
- [x] Docker packaging for the control plane

### Provider Contract and admission

- [x] define the independent Sandbox Provider ownership boundary
- [x] establish the MIT Provider Contract, namespace, schemas, semantic rules, fixtures, and Suite
- [x] add local Contract lock verification
- [x] define Provider DTOs separately from local instance and driver models
- [x] validate Provider DTOs and fixtures against the locked local Contract
- [x] implement mTLS-only capability discovery
- [x] implement per-operation JWS and request/descriptor digest admission
  boundary across the individually composed Provider routes
- [x] implement one explicit issuer-scoped caller trust domain per protected
  listener, with Provider-local audience/revision anchors and bounded frozen
  rotation keys, and pass its repository-local coordinated gate
- [ ] qualify an independently implemented external caller; the
  same-repository generic reference caller remains reference evidence only.
  ADR 0040 defines the boundary, and P2.7a locks the verified coding/shell
  machine-readable definition authority at
  `sha256:4effea27fd3d7668b88eeb95c69e19b51556914b7949b1a39ce522b2aec46c14`.
  P2.7b locks the closed report schema at
  `sha256:cd51ccf0aea0bc31b11ff4f288751fc7df0f0dd081860efc305182ea61f842e4`
  and its validator semantics at
  `sha256:c724eaa9f3b52e1a5ba4aa5aaeb5e8b61a744818b2f56fd8ff52dfa5e1e584df`,
  and adds the bounded evidence-root validator and sanitized receipt. The
  validator enforces payload-owned nullable evidence and complete execution
  timing, a 64-wire-attempt ceiling with fail-closed potential-resource
  accounting, bound cleanup scope/baseline/stability samples, exact
  create-sandbox resource projection, and receipt publication only after final
  rechecks. This locks report-validation components only; it does not attest
  producer truthfulness, original request bodies, or an external compatibility
  result. P2.7c.1 locks the adapter protocol schema at
  `sha256:d12b477cd540e02c6a7e2f8eb77b0405b717c15e98a0f144b2d63f705ff95969`
  and operational semantics at
  `sha256:10cd42017aee60b620dbbb7394a20c2a387983468a865a8d12a572f861d07662`.
  P2.7c.2b.1 also locks the closed sanitized-transcript projection Schema at
  `sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293`.
  The identity-first, bounded protocol allows only the seven profile-owned
  harness fields, keeps credentials on dedicated inherited channels, and treats
  adapter progress as caller-owner assertions rather than final evidence. The
  report startup identity, process-supervisor projection, validator semantics,
  and receipt now bind the same exact protocol authority. P2.7c.2a implements a
  runtime-independent strict codec for EOF-framed invocation input and
  LF-delimited adapter output. It locks exact byte/record accounting, strict
  UTF-8/JSON/Schema and message-direction checks, startup protocol-authority
  matching, and sanitized terminal decode failures. The operational-semantics
  digest was refreshed to bind those previously implicit count and precedence
  rules. P2.7c.2b.1 machine-locks the complete per-process transition table,
  terminal-to-EOF-to-clean-exit sequence, cross-phase startup equality, and
  exact private-material-free transcript preimage shape. P2.7c.2b.2 implements
  the first runtime-independent state gate: it consumes exactly one valid
  sequence-zero startup record, rejects missing/duplicate/out-of-order startup,
  retains the first sanitized failure, and grants invocation-input authorization
  only once.
  P2.7c.2b.3 binds the authorized, validated invocation to that same Codec and
  stdout decoder, rejects skipped records or modified decoded envelopes, and
  accepts only the next sequence-one `invocation_accepted` with byte-identical
  invocation ID and exact phase. P2.7c.2b.4 then reads the exact ordered case
  IDs from the verified profile, requires `scenario_started` before a
  `completed` result, forbids it before `not_executed`, and advances to the
  terminal boundary only after every phase case has one result. P2.7c.2b.5
  enforces the disjoint normal/error terminal branches, rejects any
  post-terminal byte, requires stdout EOF, and reaches `complete` only from a
  clean-exit event after EOF. Actual bounded process
  waiting, and process-execution enforcement remain later gates.
  All qualification Schema compilers now use one ECMA-262 regexp engine, and
  the locked text patterns reject ASCII controls without POSIX-only classes.
  Invocation paths/endpoints now use closed canonical profiles, and the
  definition requires a digest-bound preflight freeze before the supervisor or
  harness acquires or generates credential or forbidden-correlation material,
  plus byte identity across phases. Runtime proof awaits the process supervisor;
  operator-upstream non-derivation remains trusted. Non-error output records now
  bind their invocation ID and phase to the single validated inbound invocation,
  and scenario case IDs bind to that phase. Protocol errors now have disjoint
  pre-binding and post-binding branches with atomic nullable identity, contiguous
  sequence, and terminal exclusivity. Monotonic deadline anchors now preserve one
  shared 1,800-second execution budget across both phases, clip each case to the
  remaining execution and parent deadline, forbid timer resets, and reserve a
  separate five-second failure-termination budget. P2.7c.2a does not validate
  phase/case order, enforce deadlines, launch an adapter, or recompute a
  transcript; P2.7c.2b.1 defines those state and transcript rules, while
  P2.7c.2b.2-.5 enforce startup, normal invocation acceptance, exact ordered
  scenario state, terminal exclusivity, EOF, and supplied clean-exit state
  without launching or waiting on a process. The c3.3 supervisor separately runs
  local process probes. c3.4 binds the actual child's first stdout record to the
  locked startup gate before any input, retains exclusive decoder ownership, and
  fail-closes with process reclamation. c3.5 then verifies the private invocation
  against the committed locations and exact startup channel requirements,
  enforces channel/fd uniqueness plus per-channel/aggregate credential limits,
  concurrently writes stdin and fd 3-10, closes every input for EOF, and advances
  state only after exact byte completion. c3.6 then enforces the shared run/case
  deadlines, bounded stderr, terminal-to-EOF order, and actual zero-exit reap.
  c3.7 publishes defensive phase evidence only after that complete path and
  binds its non-overridable adapter facts into one canonical two-phase
  transcript. d1-d6 freeze and execute the request-free harness through
  independently observed results and bounded cleanup. d7 now consumes that
  sanitized state once, accepts only the closed transcript/timing/assertion/
  trusted-digest projections, and creates the exact five payloads plus report
  at `0600` through a pinned directory descriptor. It closes the assembly
  writer before the validator alone publishes the receipt, with the same
  runtime commitment bound across all seven files. Real Darwin/arm64 and
  Linux/arm64 helpers pass. These repository probes do not establish release,
  payload, caller, adapter, trusted-input, or observer provenance, and no
  independent external caller has passed the gate.

### Provider lifecycle

- [x] add durable Provider sandbox, operation, lease, and event models
- [x] add idempotency, generation, fencing, deadlines, and reconciliation
- [x] compose the authorized Provider lifecycle application for development (production driver and readiness remain gated)
- [x] add an independent Provider Docker lifecycle adapter with stable mounts,
  restart observation, unknown-outcome evidence, and cleanup
- [x] compose development exec/cancel/result routes over durable acceptance,
  Docker execution, bounded private capture, expiry, and reconciliation
- [x] add a reconnectable Provider terminal runtime/broker and Docker adapter
  with private backend identity and restart-reattach evidence
- [x] pass the locked local lifecycle/security Suite mappings (component evidence only)
- [x] compose durable terminal sessions and artifact/usage development verticals
- [x] derive the exact nonempty advertisement from a complete externally supplied readiness graph
- [x] pass the independent reference caller release gate (generic-consumer and production gates remain separate)

### Manifest and blocks

- [x] define internal block manifest format
- [x] load block manifests from disk
- [x] validate manifests
- [x] expose internal block registry APIs (no public route)
- [ ] add `browser-chrome` manifest prototype

### Instance lifecycle

- [x] define instance model
- [x] define lifecycle state machine
- [x] add fake driver
- [x] expose instance CRUD APIs

### Docker runtime

- [x] implement Docker driver
- [ ] create base runtime image
- [x] create and publish the exact sandboxed, signed amd64/arm64/v8 browser
  image component (Provider runtime composition remains open)
- [x] support container create/start/stop/inspect/remove
- [ ] support container logs
- [x] define runtime resource limits

### Remote GUI capabilities

- [ ] display module
- [ ] audio module
- [ ] input module
- [ ] streaming module
- [ ] clipboard module
- [ ] file-transfer module
- [ ] network policy module
- [ ] automation connector

### Product layer

- [ ] web viewer
- [ ] management console
- [ ] SDK
- [ ] examples
- [ ] deployment templates

## Non-goals for the first stage

The first stage is focused on runtime foundations. It intentionally does not prioritize:

- multi-user rooms
- chat
- billing
- team management
- collaboration UX
- full cloud-browser product features
- production-grade sandbox hardening guarantees

Those can be built on top later, but they should not shape the core runtime prematurely.

## Security note

`sandbox-runtime` applies conservative Docker defaults, but Docker Engine access
and container isolation alone are not a hardened multi-tenant security boundary.
The v1 API also has no built-in authentication. Keep it on loopback or behind an
authenticated trusted proxy in development; production mode currently enforces
loopback. Do not run hostile workloads in production
until the threat model, filesystem policy, seccomp/AppArmor profile, user
namespaces, secrets handling, and host isolation have been explicitly reviewed.

## Development

See [the development standards](docs/development.md) for package boundaries,
security rules, required gates, and Contract change discipline.

Run tests:

```bash
go test ./...
```

Build binary:

```bash
go build -o dist/sandbox-runtime .
```

Run server:

```bash
go run . serve
```

## License

MIT License.
