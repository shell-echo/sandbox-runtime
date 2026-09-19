# Development Standards

The first-version P2.7 plan is complete at **24/24**, and the public
independent external-caller plan is complete at **13/13**. Hosted
qualification run `35203241121` produced an accepted report, receipt,
seven-file archive, and bounded `qualified` disposition for the exact recorded
coding/shell scope. Core CI run `35204434771` passed after documentation
closure.

These results do not relax the engineering rules below. Every future behavior,
Contract, security, deployment, or compatibility change must pass its own
named gates and must preserve the distinction between component evidence,
Conformance evidence, external-caller qualification, and production readiness.

## Toolchain and commands

Use the Go version declared in `go.mod`. Docker is optional for ordinary unit
tests and required for the tagged Docker integration test.

Apple Container is an optional application-packaging test environment. On a
supported Apple silicon host, run `./scripts/apple-container-smoke.sh` to build
the repository Dockerfile and exercise the local health/create/list path with
the in-memory fake runtime. See [`apple-container.md`](apple-container.md) for
kernel setup and the exact non-production evidence boundary. This is distinct
from a Provider runtime driver or Docker-backed capability test.

Run `./scripts/docker-smoke.sh` for the equivalent restricted Docker application
path. Run `./scripts/kubernetes-smoke.sh` for offline Kustomize/security checks;
set `SANDBOX_RUNTIME_KUBERNETES_LIVE=1` only after the selected image is
available on every node of the current test cluster. These application smoke
tests use the fake runtime and are not substitutes for Provider, backend, or
deployment qualification gates. See [`deployment.md`](deployment.md).

When Docker Desktop is unavailable, a Lima Docker VM may supply the daemon and
mise may supply the exact Go version. If that VM deliberately has no host
mounts, tests that create Docker bind mounts must execute inside the guest so
their generated paths exist in the daemon's filesystem; pointing a macOS test
process at the mountless guest socket is an invalid topology for those tests.
Such a VM remains local component infrastructure unless its mutable bootstrap
and artifact provenance are separately pinned.

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go run ./cmd/verify-product-contract -source-root .
go test -race -v -tags=phase3gate -count=1 -run '^TestStandalonePhase3ReleaseGate$' ./productphase3gate
go run ./cmd/verify-product-phase3-evidence -manifest docs/audits/product-phase-3-standalone-evidence.json
go test -v -count=1 -tags=phase4browsergate ./productphase4gate
go run ./cmd/verify-product-phase4-evidence -manifest docs/audits/product-phase-4-browser-evidence.json
SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 go test -tags=integration -count=1 ./driver/docker ./provider/lifecycle/driver/docker
SANDBOX_RUNTIME_BROWSER_ADAPTER_INTEGRATION=1 go test -tags=integration -count=1 ./provider/browser/driver/docker
SANDBOX_RUNTIME_BROWSER_PROVENANCE_INTEGRATION=1 go test -tags=integration -count=1 ./provider/browser/provenance/ghcli
SANDBOX_RUNTIME_BROWSER_NETWORK_INTEGRATION=1 SANDBOX_RUNTIME_BROWSER_GATEWAY_IMAGE=sha256:<local-gateway-image-id> SANDBOX_RUNTIME_BROWSER_FIXTURE_IMAGE=sha256:<local-fixture-image-id> go test -tags=integration -count=1 -run '^TestBrowserRestrictedEgressIntegration$' ./provider/browser/driver/docker
SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_ADMIN_URL=postgres://<migration-owner>@127.0.0.1/witness SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_URL=postgres://<runtime-role>@127.0.0.1/witness SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_DENIED_URL=postgres://<denied-role>@127.0.0.1/witness SANDBOX_RUNTIME_SHARED_CAPACITY_REDIS_URL=redis://127.0.0.1:6379/0 go test -tags=integration -race -shuffle=on -count=1 ./gateway/capacity/redis
go run ./cmd/verify-contract -source-root .
go run ./cmd/verify-qualification-profile -source-root .
go test -count=1 ./cmd/verify-qualification-report ./internal/evidencefiles ./internal/qualificationreport
runner_dir="$(mktemp -d)"
go build -buildvcs=true -o "$runner_dir/run-conformance" ./cmd/run-conformance
"$runner_dir/run-conformance" -source-root . -race -shuffle
```

Format changed Go files with `gofmt`. Do not weaken or skip a gate to make a
change pass. Record an unavailable integration environment separately from a
code failure.

The Product Phase 3 tagged gate requires Docker. It creates and removes one
exact disposable PostgreSQL container and starts four child OS processes from
the tagged test executable. Its checked-in manifest is historical evidence for
the recorded source revision; a new run does not overwrite it automatically.
Validate a newly selected manifest independently before updating the audit.

The local Suite command requires a clean checkout and a clean VCS-built Runner.
It reads the Runner revision and Go version from `debug.ReadBuildInfo`, rejects
missing revision data and `vcs.modified=true`, and tests a bounded read-only
`git archive` of that exact revision rather than mutable worktree source. `go
run ./cmd/run-conformance` lacks the required VCS settings under Go 1.26.5 and
correctly fails.

The qualification-profile verifier separately checks the P2.7a coding/shell
definition's repository trust anchors, closed schema, semantic invariants, and
exact historical Provider Contract projection selected by
`qualification/external-caller-coding-shell-v1/contract.lock.json`. That
retained lock is verified from its immutable Git revision and must not be
replaced by the current Provider lock or used for a new compatibility claim.
Its success proves only that the historical profile definition is locked; it
does not validate a qualification report or claim that an external caller
executed or passed the profile. P2.7b separately locks the
closed report schema at
`sha256:9e9d75c021534d1b0ad49ad230031bad8cc578c163ac7f5626471899b0991c7c`
and the validator semantics at
`sha256:dd15969eb171575db0dd3883701c1f788ed338bdffcbec343a6455b00ed2c227`,
and tests the evidence-root, report validator, and command components. CI runs
those component tests but does not fabricate an external qualification run.
P2.7c.1 locks the adapter protocol schema at
`sha256:7948265be2f90f8c695c62340ab57f451b0771c104e9505d01d778063fca23a6`
and operational semantics at
`sha256:5e0521ff6df2451384c717fd62c0335d3e726164f7488ac191430b263affe82c`.
Its startup/process-supervisor/validator/receipt authority binding is complete;
all qualification Schema compilers use one ECMA-262 regexp engine and reject
ASCII controls without POSIX-only classes. Invocation paths/endpoints use closed
canonical profiles. The definition requires digest-bound preflight commitment
before the supervisor or harness acquires or generates credential or
forbidden-correlation material, plus cross-phase byte identity; c3.1-.7 now
enforce the local supervisor boundary while operator-upstream non-derivation
remains trusted.
Non-error output invocation IDs and phases now bind to the single validated
inbound invocation, including scenario case-ID phase prefixes. Protocol-error
branches now distinguish unbound `invalid_invocation` from
bound post-acceptance failures. Monotonic anchors share the run execution
deadline across both phases, clip case budgets, forbid resets, and separate the
bounded failure-termination context. P2.7c.2a adds the pure strict codec: the
invocation ceiling counts all bytes through EOF; an output record ceiling
excludes its LF delimiter; the stdout ceiling includes delimiters plus invalid
or truncated bytes. It rejects invalid UTF-8, duplicate members, invalid
surrogate escapes, multiple JSON values, Schema/unknown-field violations,
wrong-direction messages, and startup authority mismatches using sanitized
terminal error kinds. P2.7c.2b.1 additionally compiles the closed transcript
projection Schema at
`sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293`
and checks the exact state-transition authority, including terminal, EOF, and
clean-exit completion. P2.7c.2b.2 implements its startup-only prefix: consume
one validated sequence-zero startup record before granting one invocation-input
authorization, with stable first-failure absorption. Runtime invocation
acceptance is extended by P2.7c.2b.3: one authorized and validated invocation
is recorded, then only the next unskipped sequence-one acceptance from the same
Codec/stdout stream with matching ID and phase is accepted. Package-private raw
document digests and revalidation reject mutated decoded envelopes; the state
retains only a sanitized invocation reference. P2.7c.2b.4 reads the exact case
order from the verified profile and enforces same-case
`scenario_started`/`completed` pairing plus start-free `not_executed` results,
with contiguous stream and byte binding through the final phase case.
P2.7c.2b.5 enforces one normal/error terminal, completion/disposition
consistency, no output after terminal, stdout EOF, and a supplied clean-exit
event after EOF. It performs no process wait. c3.4 exclusively decodes the
actual child's first stdout record through that same state machine, exposes
only a defensive structured startup identity, and reclaims the process on
invalid/absent startup or cancellation. c3.5 validates invocation locations and
descriptor requirements before concurrently writing bounded stdin/credential
streams and closing all input fds for EOF. It wipes its private payload copies,
records only bounded counts, and reclaims ambiguous delivery. Deadlines,
post-invocation drainage, exit observation, and sanitized transcript binding
are implemented by c3.6-.7. Real Darwin/arm64 and Linux/arm64 helpers cover the
complete two-phase local path. The configured CI matrix reruns the package on
Ubuntu and macOS, but release/payload provenance, independent observation, and
external-caller qualification remain separate evidence gates.

The d7 assembly API accepts no caller-built report document. It consumes the
one-shot sanitized d1-d6 snapshot and only the closed transcript projection,
20 ordered supervisor timings, 29 ordered caller assertions, and five ordered
trusted-input subject digests. `RootAssembler` requires an already-created
empty evidence directory, publishes the five locked payload names and
`report.json` exclusively at `0600` through the pinned directory descriptor,
then closes that writer before `Verify` becomes the only in-process writer for
`receipt.json`. Report state, counters, cleanup satisfaction, identity
completeness, reasons, and outcome are derived. The runtime commitment is
cross-bound through report, payloads, and receipt. Local synthetic tests are
component evidence; e1 still requires separately supplied immutable caller and
adapter provenance.

Verify them with:

```bash
go run ./cmd/verify-qualification-adapter-protocol -source-root .
```

That command compiles the closed protocol and transcript projection schemas
against the locked report definitions, checks their trust anchors and
operational invariants, and validates bounded examples. It launches no process
and provides no external-caller
evidence. Adapter progress is caller-owner input; only a later harness combining
it with independent observers may derive the report's four-state outcome.

The validator semantics allows exactly five payload files:
`provider-observer.json`, `gateway-observer.json`,
`process-supervisor.json`, `resource-inspector.json`, and
`trusted-inputs.json`. `passed` and `failed` require all five and complete
payload-backed identity. `incomplete` and `not_executed` may retain a strict
subset and use only the schema's explicitly nullable identity fields; every
present payload and non-null identity must still validate and cross-bind.
An executed scenario with missing required evidence and no observed mismatch is
`incomplete`; a proved mismatch remains `failed`. If mutation evidence exists
without `resource-inspector.json`, retain the cleanup obligation, clear all
inspector-owned positive evidence, use zero teardown attempts, and record
cleanup as `unknown` or `incomplete`.
The Provider observer also binds the report's fixed sandbox-resource projection
to the observed `create-sandbox` interaction. The projection is absent exactly
when that interaction is absent and otherwise must equal the locked profile.
It records observed create-request values; it is not evidence that the runtime
allocated or enforced those limits. If the process-supervisor payload is absent,
all scenarios must be `not_executed` and execution, cleanup, scenario, and shell
continuity timings remain absent. If it is present, its complete run and
scenario timing projections must bind the report, even when the run is not a
pass.

Validate a supplied evidence root only after it contains the external
operator's complete sanitized `report.json` and payload files:

```bash
go run ./cmd/verify-qualification-report \
  -source-root . \
  -evidence-root /absolute/path/to/evidence
```

Before invoking the validator, the qualification operator must stop every
producer and grant the validator exclusive write access to the evidence root
until `Verify` returns. No producer or other process with the same UID may
write, rename, link, or remove entries during that interval. Directory-FD,
no-follow, identity, digest, and inventory rechecks detect named races and fail
closed; they do not establish integrity against an attacker that retains
continuous write access. Only after a successful return may the external
operator package the complete root, including `receipt.json`, and record the
archive digest in its separate artifact envelope.

The validator rejects an existing `receipt.json`; on success it creates that
file without overwriting another result. On Darwin and Linux, the root is held
as one fixed directory descriptor; traversal and reads use descriptor-relative
`openat`/`fstatat` with no-follow checks, regular files must have one link, and
receipt publication is exclusive, no-follow, mode `0600`, synchronized, read
back, and identity-checked. Unsupported platforms fail closed rather than use a
weaker path implementation.
Use a healthy local filesystem for the evidence root. Cancellation is checked
at validator stage boundaries and immediately before commit, but Go context
cancellation cannot interrupt a synchronous filesystem syscall blocked in the
kernel. A deadline therefore does not guarantee timely return from a stuck FUSE
or network-filesystem operation.

Acceptance proves schema, semantic, inventory, size, path, and the defined
sanitization checks for the exact evidence root. The semantics-locked marker set
is checked against raw bytes, normalized JSON, and decoded JSON strings, but
still catches only known obvious material; it cannot prove discovery of every
unknown, encoded, or disguised secret. External ownership and source/release
statements remain trusted inputs. The semantics digest binds data rules, not the
validator binary, repository revision, build, compiler, operating system,
filesystem, or host toolchain; those execution inputs require separate trust or
provenance.
Validator acceptance is not by itself interoperability, Suite execution,
deployment, or production evidence.

Run the local runner with `GOROOT` unset. It rejects any explicit `GOROOT`, uses
the default `runtime.GOROOT()/bin/go`, and checks `go env GOVERSION` against the
build identity. It resolves Git once from the initial `PATH` to an absolute,
symlink-resolved, regular executable, reuses that path for Contract verification
and the runner-revision archive, and records Git's self-reported version. It
also clears Go path overrides, sets `GOWORK=off`, `GOENV=off`,
`GOTOOLCHAIN=local`, and an empty `GOFLAGS`, and passes `-mod=readonly`.

The host OS, filesystem, initial Git selection, and Go and Git executables are
trusted local inputs. Absolute-path, file-type, and self-reported version
checks prevent specific environment substitution and resolution drift; they
do not attest host-tool integrity. The runner prints this evidence boundary.
Every Contract case mapping declares an exact expected pass count. The `go test
-json` stream must show all matching tests as distinct, started, non-skipped
passes and the observed count must equal that declaration. Zero or unexpected
extra matches, a parent-only scaffold pass, skip, failure, malformed evidence,
or cancellation fails closed.

The separate remote discovery CLI also requires a clean VCS-built binary. Its
inputs are an HTTPS Provider origin, server CA, client CA, admitted client
certificate/key, denied client certificate/key rooted in the same client CA,
TLS server name, and expected Provider revision. Build it with:

```bash
go build -buildvcs=true -o "$runner_dir/run-remote-conformance" ./cmd/run-remote-conformance
```

Pass those inputs with `-target`, `-ca`, `-client-ca`, `-client-cert`,
`-client-key`, `-denied-client-cert`, `-denied-client-key`, `-server-name`, and
`-provider-revision`, respectively. See
[`compatibility/sandbox-runtime/README.md`](../compatibility/sandbox-runtime/README.md)
for the complete command and exact local/remote Suite identities. The remote
profile covers only six read-only discovery cases; it is not the local 71-case
Suite, protected or mutating remote conformance, independent-caller
interoperability, aggregate conformance, or production-readiness evidence. The
report sets `unsafe_method_probes_sent=true` only after a POST, PUT, PATCH, or
DELETE discovery-path probe is actually written; a written probe prevents a
zero-side-effect claim for an arbitrary non-conforming target.

The historical P2.6 release gate passed locally at implementation `3fe314a` and
E2E lock refresh `ae476fe`, including both clean VCS-built Runners, the root and
E2E race/shuffle and vet gates, Contract verification, parent-lock verification,
and all eight E2E `-check` commands. The later 53-case local authority passed as
a clean VCS-built Runner in core CI `35204434771`. The Phase 2 60-case authority
passes from a clean VCS-built, race-enabled, shuffled Runner at lock-selection
revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`. Product Phase 5 Slice 1
selects the current 71-case Desktop-extended authority and requires the same
clean VCS-built, race-enabled, shuffled local Runner. No fresh remote Runner or
relabeled historical hosted result follows from either local release gate.
Keep those checks separate from external caller, deployment, and production
qualification.

## Package boundaries

- `server` and future `providerapi` packages own transport only.
- application services own lifecycle and coordination, without Gin or Docker
  types.
- repository and driver interfaces are ports; concrete implementations stay in
  their adapter packages.
- `driver/*` owns backend actions and observations, not public policy or durable
  platform truth.
- Provider wire DTOs must remain separate from `instance` models and backend
  engine types.
- optional capabilities such as exec, terminal, and snapshot use focused ports;
  do not grow one mandatory driver interface for unsupported features.

Dependencies point inward. Export the minimum surface and keep cross-package
calls on public contracts rather than implementation structs.

For Product persistence changes, run a disposable PostgreSQL instance and then:

```bash
SANDBOX_RUNTIME_PRODUCT_POSTGRES_URL=postgres://<user>:<password>@127.0.0.1:<port>/<database>?sslmode=disable \
  go test -tags=integration -race -shuffle=on -count=1 ./product/adapter/postgres
```

This is real-adapter component evidence. It does not establish database image
provenance, least-privilege deployment roles, backup/restore, HA, or production
readiness.

## Product package and import boundaries

The accepted Product architecture is being implemented through the fixed Phase
3 slices. Slice 1 adds only the Product domain/application port, PostgreSQL
adapter, import guard, and Contract verifier. Use these roots and directions:

- `productapi` owns Product HTTP/SSE transport and Product wire DTOs only;
- `product` owns Product domain/application policy and ports;
- `product/adapter/postgres`, `product/adapter/gateway`, and
  `product/adapter/provider` implement those ports;
- `guestagent` is a separate guest-side protocol and process boundary;
- existing `provider`, `providerapi`, `gateway`, `instance`, `driver`, and
  backend packages remain separate authorities.

Product application/domain packages must not import `provider`, `providerapi`,
`instance`, `driver`, backend adapters, or existing Gateway implementation
packages. `product/adapter/provider` may consume generated or neutral DTOs for
the locked Provider Contract and translate them into Product port values; it
must not import Provider repositories, services, command composition, private
references, or backend identities. All Product runtime operations cross the
protected Provider network Contract even when processes are co-deployed.

Product transport DTOs must be generated from or checked against
`product-contract/` and cannot reuse PostgreSQL rows, Product aggregates,
Provider DTOs, or driver structs. The first Product implementation change must
add a non-test Go import-boundary check before adding behavior. That guard now
runs in `internal/productboundary`; extend it whenever a new Product or Guest
Agent root is added. ADR 0042 owns the complete dependency decision; local
convenience is not an exception.

## Product Phase 4 Browser discipline

Follow the fixed order in
[`plan/product-v1-phase-4-browser.md`](plan/product-v1-phase-4-browser.md) and
the authority boundary in ADR 0049. The historical Provider "P4 Browser"
packages and evidence are not Product Phase 4 composition or release evidence.

Product Browser sessions must bind to a Product slot of kind `browser`; never
reuse `primary-code` or a Terminal handoff. The Product control lease,
Provider mutation fence, Browser connection generation, Gateway capacity
lease, and downstream action fence are independent authorities. Browser
outbox work uses a Browser-specific type and must not be leased by Terminal
workers.

Product Browser capability readiness may be derived only when the exact
Provider adapter, public automation/live Gateway, viewer/controller policy,
revocation, network isolation, recording mode, recovery, and cleanup graph is
ready. The Phase 4 release gate proves that graph only in its bounded
same-repository separate-process topology; it does not authorize production
advertisement or deployment claims. Missing clipboard, upload, download,
permission, recording, or egress policy denies the feature. A disconnected
client is not proof that the durable session or Provider allocation is closed.

For Slice 1-2 persistence changes, run the ordinary Product PostgreSQL command
above. Slice 2 additionally requires the concurrent idempotency and one-slot
tenant-quota cases. That result is real-adapter authority evidence only; it is
not Browser runtime, public data-plane, independent-process, deployment, or
production evidence.

Slice 3 Browser Provider tests must use a network server boundary and the
locked Provider DTOs. Require a fresh exact Browser-only capability snapshot
for every authorization/dispatch, restricted network plus an explicit egress
policy reference for sandbox create, and an opaque Browser handoff reference
for session observation. Run the tagged PostgreSQL package to prove Browser
and Terminal workers cannot lease each other's outbox work.

The final Phase 4 tagged gate requires Docker. It creates and removes exact
fresh PostgreSQL and Valkey containers, starts four child OS processes, and
uses fresh encrypted local recording storage. The checked-in evidence manifest
is historical evidence for its recorded source baseline; validate it with the
separate verifier before selecting it. Passing this gate is not deployment,
independent-caller, HA, hostile-multitenant, or production evidence.

## Product Phase 5 Desktop discipline

Follow the fixed order in
[`plan/product-v1-phase-5-desktop-development-unified-product.md`](plan/product-v1-phase-5-desktop-development-unified-product.md)
and ADR 0050. Desktop must not reuse Terminal or Browser slot profiles,
session profiles, outbox families, Provider routes, handoffs, runtime
repositories, or release evidence.

The Product Desktop slot shape is exactly `desktop` /
`sandbox-runtime-desktop-v1` / `sandbox.desktop@1.0.0` / `desktop-v1`. The
Product session shape is exactly `desktop` / `product-desktop.v1`. Keep both
application validation and PostgreSQL constraints aligned. A Product command
must commit state, operation, contiguous event, security audit, idempotency
result, and outbox intent atomically before external work.

Run the ordinary tagged Product PostgreSQL gate for every Desktop persistence
change. Preserve concurrent same-key idempotency, expected-version, Desktop
slot quota, and Desktop session quota cases; migration replay; terminal-state
absorption; cross-tenant nondisclosure; and fresh-Store reads. Desktop session
outbox types are `desktop_session.open` and `desktop_session.close`. Until the
later adapter slice provides a dedicated consumer, no existing worker may
lease them and capability advertisement remains empty.

Provider Desktop Slice 3 changes must preserve the separate `provider/desktop`
domain and coordination authority. Commit open intent before allocating;
persist the immutable allocation receipt before publishing an opaque handoff.
After a restart, an already-running or outcome-unknown open is observation
only: never blindly allocate again. Close and expiry durably revoke the source
handoff before external effects, then revoke, clean only the exact retained
allocation receipt, and observe absence. An outcome-unknown close may only
observe revocation and allocation state; it must not repeat cleanup. Keep
memory and atomic-file adapters behaviorally equivalent, retain operation
records after handoff expiry, reject stale fencing/generation/revision, and
map internal failures to safe transport errors.

The Slice 3 protected handlers are optional application injection only. Do not
compose them into production startup or advertise Desktop until the later
runtime, adapter, resolver, readiness, and release slices pass. Run focused
Desktop domain/application/repository/transport race-shuffle tests in addition
to the full repository race/shuffle and vet gates. Provider API or compatibility
changes also require the Provider Contract verifier.

The Slice 4 image/broker publication is locked by
`profiles/desktop/image.LockedPublication`. Manual run `35447651328` passes on
native amd64 and arm64/v8 GitHub-hosted runners, publishes exact immutable
index and platform manifests, and passes attestation plus independent
verification. A local cross-build is not a native architecture smoke, and a
checked-in workflow is not provenance evidence. Runtime adapters must select
only this fail-closed publication authority; any replacement requires a new
named publication and repository-authority update.

For image/broker changes, keep `profiles/desktop/image/manifest.json`, its Go
validator, the Dockerfile, build script, broker constants, integration policy,
and publication matrix aligned. Run the focused race/shuffle tests plus the
full repository gates. On each native architecture, run:

```bash
SANDBOX_RUNTIME_DESKTOP_IMAGE_INTEGRATION=1 \
SANDBOX_RUNTIME_DESKTOP_PLATFORM=linux/arm64/v8 \
go test -v -tags=integration -count=1 \
  -run '^TestDesktopImageNativeIntegration$' ./profiles/desktop/image
```

Use `linux/amd64` on a native amd64 runner. Never substitute emulation, a
mutable tag, or an image config ID for the required native runtime and
published OCI manifest/index identities. The broker is private Unix-only
observation at this slice: adding input execution, media, public signaling,
authorization, or arbitrary process control requires its later owning slice.

Slice 5 runtime changes must keep `provider/desktop/driver`, `reference`,
`lifecycle`, `usage`, and application policy separate. The driver may persist
backend identity only in its private state. Every attach/reconnect must resolve
the durable opaque reference again; never retain a closure that bypasses
revocation, expiry, source-operation, receipt, or generation checks. Close and
expiry order is durable revoke, exact receipt cleanup, then absence
confirmation. Usage starts at successful handoff commit and stops at the
earliest revocation, endpoint/sandbox termination, or expiry.

Run the real private-broker adapter gate on a native Docker host:

```bash
SANDBOX_RUNTIME_DESKTOP_ADAPTER_INTEGRATION=1 \
go test -tags=integration -count=1 \
  -run '^TestDesktopBrokerTransportIntegration$' \
  ./provider/desktop/driver/docker
```

This gate uses `network=none` to isolate real image/broker/container behavior;
it is not restricted-egress deployment evidence. The production driver still
requires a fail-closed restricted-network provisioner. Do not weaken that port
or advertise Desktop because the transport-focused gate passes.

Slice 6 Product adapter changes must use `product/adapter/provider.NewDesktop`
and select only the current Desktop Contract revision/tree, the locked signed
image, one exact runtime profile, bounded resources, and an explicit
restricted-network policy. Do not change the legacy Product Provider lock to
retroactively relabel Phase 3 or Phase 4 evidence. Product slot generation is
the Product fence; `provider_bindings.provider_generation` is the independent
Provider expected generation.

Keep Desktop slot, lifecycle, session, expiry, and observation leases separate
from generic, Terminal, and Browser workers. Desktop close clears the Product
handoff and terminalizes the session while retaining the slot; never reuse the
Browser terminate-and-replace path. Dispatch close/expiry only with a retained
positive connection generation. Preserve accepted and outcome-unknown attempts
for observation after Store/client reconstruction.

For Product Desktop adapter or migration changes, run the focused adapter
tests, full repository gates, Contract/evidence verifiers, existing tagged
Docker lifecycle regression, and the real PostgreSQL gate:

```bash
SANDBOX_RUNTIME_PRODUCT_POSTGRES_URL=postgres://<user>:<password>@127.0.0.1:<port>/<database>?sslmode=disable \
  go test -tags=integration -race -shuffle=on -count=1 \
  ./product/adapter/postgres
```

This proves the Product network adapter and real Store boundary against the
test Provider peer. It is not production process composition, an independently
implemented Provider deployment, a public Desktop Gateway, or advertisement
evidence.

Slice 7 Product grant changes may authorize `view` and `control` only for an
exact ready `desktop` / `product-desktop.v1` session. Viewer grants have no
control lease or fence. Controller grants require the current actor-bound,
session-scoped lease and fence. Keep Desktop viewer/controller quotas separate
from Browser quotas and preserve the one-live-controller index for every
session family. Quota admission, expiry, consume, and continuous authority
must use PostgreSQL time and the complete retained binding tuple.

Public grant responses and security audit rows must not contain a Provider
handoff, endpoint, backend identity, connection ticket, or payload. A ticket is
stored only as its lookup digest plus authenticated ciphertext for exact
idempotent replay, and first consumption makes it unusable. Run the complete
tagged Product PostgreSQL race/shuffle gate above for every Desktop grant,
control, quota, audit, or migration change. This slice does not authorize a
public Desktop signaling/media/input handler; that begins in Slice 8.

Slice 8 Desktop data-plane changes must keep a distinct Desktop signaling DTO
and control protocol. Production construction requires HTTPS, an exact HTTPS
Origin allowlist, password-authenticated `turns:` relays, a bounded closed JSON
offer, and the consumed `product-desktop.v1` grant. Accept exactly one
receive-only VP8 video section and optional receive-only Opus audio section;
never accept upstream microphone/camera media.

Viewer bindings must not create a control channel. Controller bindings require
the current lease and fence plus one reliable ordered
`product-desktop-control.v1` channel. Decode only bounded keyboard, pointer,
and touch shapes, require sequence `n+1`, recheck continuous grant authority,
and call the injected Product input-authority port before private execution.
Keep signaling, peer, per-session, RTP, bitrate, input, and control-output
queues bounded and close on overflow or slow consumption. Public responses and
audit remain metadata-only and exclude tickets, Provider handoffs, media, and
input. Required recording fails closed until the recording slice is composed.

For each Desktop signaling/media/input change, run focused Desktop WebRTC race
tests plus the full repository gates and Contract/evidence verifiers. This
handler-level result is not a real Provider media bridge, durable policy,
production startup, advertisement, deployment, or production evidence.

Slice 9 Desktop policy changes must use `product.DesktopPolicy`; do not reuse
Browser actions or persistence. Policies are immutable positive revisions
scoped to the Product Workspace. Updates require owner authority, one exact
expected revision, idempotency, metadata-only audit, and retained historical
results. Absence, corruption, store failure, or a revision change fails closed
and terminates an established Desktop peer.

Keep the action matrix deny by default. Independently gate keyboard, pointer,
touch, clipboard read/write, Product-bound upload/download, activation, and
consent. Enforce clipboard, count, per-file, aggregate-size, canonical media
type, SHA-256 digest, and confined `/workspace/...` path bounds. Match every
transfer to the exact Product tenant, actor, Workspace, ID, direction,
completed state, digest, and byte count. Never project object references.
Microphone, camera, and host-device forwarding remain denied.

For Desktop policy or migration changes run focused Desktop policy/Gateway
race tests, the full repository gates and Contract/evidence verifiers, plus the
complete tagged Product PostgreSQL race/shuffle gate. This is policy and
same-process Gateway component evidence, not a real Provider media/input
bridge, recovery, production startup, advertisement, deployment, or production
evidence.

## Go and API rules

- accept `context.Context` on blocking or external operations and preserve
  cancellation and deadlines;
- wrap errors with operation context and map them to stable public codes only at
  the transport boundary;
- reject unknown JSON fields, multiple JSON values, oversized bodies, invalid
  identifiers, and unsafe defaults;
- return caller-safe snapshots from repositories and services;
- protect shared state explicitly and test races and cancellation paths;
- use injected clocks, ID generators, engines, and repositories where
  deterministic fault tests need them.

Never expose container IDs, host paths, daemon errors, raw endpoints, secrets,
or credentials through a stable API. Production configuration must fail closed
when authentication, persistence, image pinning, or transport safety is absent.

## Provider Contract discipline

The repository-owned MIT Contract under `contract/` defines wire behavior and
caller obligations through its locked Provider Calling Standard, OpenAPI, JSON
Schemas, semantic rules, fixtures, and Conformance Suite. Update
`compatibility/sandbox-runtime/contract.lock.json` only as a reviewed protocol
change, then update DTOs, mappings, fixtures, tests, and documentation together.
Do not claim compatibility with an external Contract or add consumer-specific
wire behavior.

For v1, compatibility requires the exact Contract revision/tree and selected
capability/runtime profile; the `/v1` path alone is insufficient. Contract
lock verification proves only the identity of consumed inputs. Unit
tests prove components. Conformance, multi-controller reliability, security,
deployment, and production readiness remain separate evidence tiers.

## Protected admission trust discipline

Treat one protected Provider listener as one caller trust domain. Enabled
startup must require one exact issuer with no default, alias, or fallback; one
Provider-instance audience; the immutable locally advertised Provider
revision; the admitted URI SAN identities; and 1..32 frozen verification keys.
Do not select issuer, audience, revision, identity allowlist, or key bundle from
the bearer or Admission Context. The bearer and Admission Context must each
match the Provider-local audience and revision rather than merely agree with
one another.

Key rotation is configuration plus restart, not dynamic discovery. Add old and
new public keys under distinct `kid` values, restart, move the caller to the new
key, wait for all accepted old-key tokens to expire, remove the old key, and
restart again. Do not add remote JWKS refresh, an implicit key, or a second
issuer to the listener without a separate design for key-ID, URI-SAN, replay,
fencing, and policy namespaces.

Tests for this boundary must cover exact generic issuer success, issuer
substitution as authentication failure, Provider-local audience/revision
rejection as authorization failure before mutation reservation, invalid startup
configuration, and overlapping rotation keys. Passing these component and
same-repository reference tests does not establish interoperability with an
independently implemented external caller. The repository-local
calling-standard Contract, projection, configuration, conformance, E2E lock,
and reference gates pass; multi-issuer, multi-tenant, HA, deployment,
independent-caller qualification, and production gates remain separate.

## Composition and advertisement discipline

Provider lifecycle, exec, terminal/Gateway, artifact/usage, and capability
advertisement are separate readiness boundaries. Development exec composition
requires the Provider Docker lifecycle runtime and its own durable file ledger;
it must not reuse local `/instances` persistence. Production continues to
reject the development Provider lifecycle and exec adapters.

Keep startup advertisement empty until the complete P2.5h dependency graph and
its named gates pass. A composed route, a Contract projection, a local Suite
mapping, and CI are distinct evidence and none substitutes for the independent
P2.5i reference-caller E2E gate. That same-repository reference gate is itself
distinct from independently implemented external-caller interoperability.

## Terminal and Gateway discipline

A terminal runtime must be independently reattachable after Provider restart;
do not present a retained in-memory stream, one-shot Docker exec attach, or a
replacement shell as reconnect evidence. Persist provider-neutral allocation
receipts and opaque `ref:session:*` references separately from adapter-private
backend identity. Reconstruct a fresh dial operation through the resolver on
every Gateway connect or reconnect; never persist a Go closure.

The P2.5f1 Docker development adapter uses an in-sandbox PTY broker and keeps
its container, broker-exec, and Unix-socket identity in adapter-private state.
Its integration test builds the broker into the test sandbox's writable
`/workspace`; that is test deployment evidence only. A real deployment must
ship the broker at a fixed read-only image path before the adapter can be
considered for production configuration.

Gateway user and tenant authorization, revocation policy, and audit sinks are
caller-owned ports. Enabled composition must require them explicitly and fail
closed when any is absent. Do not add a static or allow-all authorizer. The
current Provider Contract does not authorize resize or explicit close-session
mutations, so either feature requires a coordinated protocol decision before
implementation.

## Change and review discipline

Keep changes scoped to one delivery slice and state its non-goals. New behavior
requires success, rejection, cancellation, and recovery tests proportional to
its failure modes. Changes to ownership, public protocol, reliability semantics,
or security boundaries require an ADR and coordinated compatibility review.
