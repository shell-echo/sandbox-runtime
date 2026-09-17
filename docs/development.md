# Development Standards

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
component. A separate external-caller repository has completed 7 of its 13
local candidate checkpoints and has begun e1.7a: 10 of 15 initial cases are
locally composed in one Caller process through acknowledged active Gateway
revocation, while the other 3 remain `not_executed`. It pins the refreshed authority. External
ownership/provenance, independent runtime interoperability and observations,
the actual 15+5 run, and a qualification result remain open. The main P2.7
plan therefore remains 21/24, with e1 in progress and e2/e3 pending.

## Toolchain and commands

Use the Go version declared in `go.mod`. Docker is optional for ordinary unit
tests and required for the tagged Docker integration test.

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
SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 go test -tags=integration -count=1 ./driver/docker ./provider/lifecycle/driver/docker
SANDBOX_RUNTIME_BROWSER_ADAPTER_INTEGRATION=1 go test -tags=integration -count=1 ./provider/browser/driver/docker
SANDBOX_RUNTIME_BROWSER_PROVENANCE_INTEGRATION=1 go test -tags=integration -count=1 ./provider/browser/provenance/ghcli
SANDBOX_RUNTIME_BROWSER_NETWORK_INTEGRATION=1 SANDBOX_RUNTIME_BROWSER_GATEWAY_IMAGE=sha256:<local-image-id> go test -tags=integration -count=1 -run '^TestBrowserRestrictedEgressIntegration$' ./provider/browser/driver/docker
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

The local Suite command requires a clean checkout and a clean VCS-built Runner.
It reads the Runner revision and Go version from `debug.ReadBuildInfo`, rejects
missing revision data and `vcs.modified=true`, and tests a bounded read-only
`git archive` of that exact revision rather than mutable worktree source. `go
run ./cmd/run-conformance` lacks the required VCS settings under Go 1.26.5 and
correctly fails.

The qualification-profile verifier separately checks the P2.7a coding/shell
definition's repository trust anchors, closed schema, semantic invariants, and
exact Provider Contract projection. Its success proves only that the profile
definition is locked; it does not validate a qualification report or claim that
an external caller executed or passed the profile. P2.7b separately locks the
closed report schema at
`sha256:5d97e10c8b5b2f365e275e78868d5a35d78bbdffdec05ea2f18b5c947cd429f6`
and the validator semantics at
`sha256:c724eaa9f3b52e1a5ba4aa5aaeb5e8b61a744818b2f56fd8ff52dfa5e1e584df`,
and tests the evidence-root, report validator, and command components. CI runs
those component tests but does not fabricate an external qualification run.
P2.7c.1 locks the adapter protocol schema at
`sha256:fdee270ca27003693b2ce504da769c9779825312e1dd4e06b5caf8578f5ee03c`
and operational semantics at
`sha256:997c49cd1a5b2c050d48333a973dd78b611221f869bf709cf6d1a8d771795a99`.
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
profile covers only six read-only discovery cases; it is not the local 53-case
Suite, protected or mutating remote conformance, independent-caller
interoperability, aggregate conformance, or production-readiness evidence. The
report sets `unsafe_method_probes_sent=true` only after a POST, PUT, PATCH, or
DELETE discovery-path probe is actually written; a written probe prevents a
zero-side-effect claim for an arbitrary non-conforming target.

The historical P2.6 release gate passed locally at implementation `3fe314a` and
E2E lock refresh `ae476fe`, including both clean VCS-built Runners, the root and
E2E race/shuffle and vet gates, Contract verification, parent-lock verification,
and all eight E2E `-check` commands. The current 53-case authority requires a
fresh clean-checkout run after the refresh is committed. Keep those checks
separate from external caller, deployment, and production qualification.

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
