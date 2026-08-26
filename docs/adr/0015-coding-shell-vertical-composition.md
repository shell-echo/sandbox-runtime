# ADR 0015: Coding/Shell Vertical Composition and Honest Advertisement

- Status: Accepted for P2.5a authority and composition planning
- Date: 2026-08-26

## Context

P2.1 through P2.4a3 produced bounded Contract, domain, application,
persistence, admission, transport, and Gateway components. Those results do not
form a runnable coding/shell Provider.

The current command composition root injects only the Provider lifecycle
application. That application selects only a fake lifecycle driver. Exec routes
pass protected admission but have no application dispatch. Runtime-session,
artifact, and usage applications are not injected by the command root. The
startup capability source uses the default constructor and therefore advertises
empty `capabilities` and `runtime_profiles` arrays.

The locked Contract is also intentionally narrower than the target P2 profile.
Its capability semantics permit only an empty snapshot or a terminal-only
snapshot and explicitly forbid non-terminal capability advertisement. The
create fixture names a default runtime profile that is not an advertised
coding/shell profile. Consequently, implementation code cannot honestly
advertise `sandbox.exec` or infer a composite runtime profile from existing
DTOs, ports, or architecture prose.

No independently owned caller/platform E2E environment is currently runnable.
That external absence is a separate blocker; supplying a caller would not make
the incomplete Provider vertical usable.

## Decision

P2 vertical composition is a new sequence of separately gated slices. The
Contract authority slice must pass before runtime behavior or advertisement is
added.

The Contract slice will define one canonical coding/shell runtime profile that:

- advertises the existing `sandbox.exec` and `sandbox.terminal` capabilities at
  explicitly locked versions and capability-profile IDs;
- maps those capability profiles to one explicit runtime profile;
- binds create admission to the advertised Provider revision and runtime
  profile, with both required capabilities represented consistently;
- retains terminal-session admission against the exact advertised terminal
  capability profile;
- requires stable `/inputs`, `/workspace`, `/outputs`, and `/tmp` runtime
  semantics plus provider-local usage evidence; and
- preserves an empty advertisement when coding/shell composition is disabled.

The exact profile identifiers and any retained terminal-only compatibility mode
must be decided and locked in OpenAPI/Schemas, semantic rules, fixtures, Suite
cases, lock metadata, DTO projection, and cross-resource tests together. This
ADR does not invent those wire identifiers by itself.

Capability advertisement is derived from the successfully composed dependency
graph, not from arbitrary operator-provided strings. If an operator explicitly
enables the coding/shell profile and any mandatory dependency is absent or
invalid, startup fails. If the profile is not enabled, the Provider retains an
honest zero-capability snapshot. It must never silently advertise a partial
profile or degrade an explicitly enabled profile to empty advertisement.

The mandatory dependency set includes:

- protected mTLS/JWS admission and durable mutation-guard state;
- Provider-local lifecycle persistence and a real runtime lifecycle adapter;
- stable mount preparation and cleanup;
- durable exec acceptance, executor, cancellation, result retention,
  reconciliation, and usage collection;
- terminal authority, allocator, opaque handoff resolution, concrete WebSocket
  transport, and the trusted Gateway boundary; and
- artifact acceptance, real output staging, bounded content checks, retained
  evidence, and operation-family aggregation.

Transport schema validation for create and runtime-session mutations must be
audited and corrected before those routes are composed. A schema-invalid
document must not consume replay or fencing state merely because its digest is
internally consistent.

Provider runtime state and wire models remain independent from the local
`/instances` API. Low-level backend engine code may be reused only behind a
Provider-specific adapter that preserves Provider ownership labels, stable
mount semantics, opaque projections, and asynchronous operation authority. The
local instance DTO, repository, and lifecycle state machine do not become
Provider models.

## Release Evidence

Each implementation slice requires focused success, rejection, cancellation,
unknown-outcome, restart, cleanup, and dependency-absence evidence proportional
to its scope, plus the repository-wide Go gates. Contract-facing slices also
require the lock verifier and complete locked Suite.

The P2 release gate additionally requires an independently owned caller using
the exact locked Contract, mTLS/JWS material, and a reproducible Provider plus
Gateway deployment. It must cover lifecycle, exec/cancel/result, terminal
handoff and data plane, artifact/usage reads, endpoint non-disclosure, negative
authorization and cross-tenant attempts, restart/reconciliation, and expiry.
Repository-local test mappings do not satisfy this gate.

## Consequences

- P2.5a changes design authority and delivery order only; it adds no Contract,
  config, runtime, route, or advertisement behavior.
- P3 remains blocked until both Provider vertical composition and independent
  caller E2E pass.
- A real Docker-backed development profile will still not prove hostile
  multi-tenant isolation, multi-controller reliability, deployment, or
  production readiness.
- Browser, desktop, port forwarding, snapshots/restore, GPU, nested containers,
  and stronger isolation remain P4 optional profiles with independent gates.
