# ADR 0052: Phase 6 Provider-Owned Handoff and Executor Role Boundary

- Status: accepted
- Date: 2026-09-21

## Decision

The Provider remains the sole owner of Browser and Desktop handoff authority.
It owns the PostgreSQL session/reference truth, tenant binding digest,
generation/fence/expiry/revocation/recovery state, and the concrete runtime
resolver and attach/cleanup implementation. The public locked Provider
Contract listener and the Provider-private handoff listener remain separate
from the executor protocol.

The independent Browser and Desktop processes are restricted media/input
executors. They do not copy Provider session truth, write Provider state, hold
Docker control authority, or become a second owner. They receive only a
short-lived opaque capability through a versioned internal mTLS protocol.

The executor protocol uses closed schemas with strict unknown/duplicate/missing
field rejection, bounded request/response sizes, deadlines and cancellation,
replay rejection, generic-safe errors, and binding of the tenant digest,
opaque sandbox/session identity, generation, fence, handoff/reference digest,
expiry, media/codec profile, Provider revision, and connection epoch. Provider
rechecks this authority on resolve, attach, reconnect, close, revoke,
recovery, and cleanup. Executors cannot extend expiry, change tenant binding,
or mutate session truth.

Production Desktop uses `sandbox-runtime.executor.v2` only. The earlier v1
executor path is retired from production and may remain only in compatibility
tests. A Desktop v2 capability carries an opaque allocation reference and a
complete normalized `desktopmedia.MediaPolicy`. Provider also signs a separate
`desktop-bridge.v2` statement that binds the executor authority digests to the
broker's independent digest domain, allocation, policy, runtime session,
generation, fence, epoch, expiry, executor identity, and one-use nonce. The
Desktop backend may only relay this statement; it cannot recalculate or sign
one.

The Desktop executor reaches the runtime through a Provider-owned host Unix
broker mux. The mux socket lives in an operator-precreated mode-0700 directory,
has a provider-instance-random basename and mode 0600, admits only same-UID
peers, rejects unsafe or active stale nodes, and is removed only when the path
still names the inode it created. The executor backend receives this socket as
its only runtime coordinate; it still has no Provider database or Docker
authority.

The mux accepts only canonical `desktop-session.v2` opens or `probe.v2`. It
verifies the Provider bridge signature and then re-resolves the current durable
handoff before and after selecting a runtime. The opaque allocation reference
is resolved only inside the Provider Docker adapter, which rechecks the owned
state record, exact candidate image/spec labels, runtime security policy and
running state before executing one fixed `desktop-broker session` argv. The
mux has no generic exec operation and never projects the container ID, host
path, raw runtime endpoint, credential, or daemon diagnostic.

Browser and Desktop restricted egress share only neutral Docker primitives.
Their thin provisioners receive sealed typed identities (`browser` or
`desktop`); no caller may provide an arbitrary role, workload name or label
namespace. Initial allocation admits only the exact owned Gateway. Fresh
attach/recovery additionally requires one unique expected workload name and
matching role, namespace, controller, sandbox, session, generation, fence,
identity digest, network mode and private endpoint. An opposite-role label,
drifted identity, missing workload or any extra network endpoint fails closed,
and release removes only the exact owned empty allocation.

Inside the candidate container, the broker pins Provider Ed25519 verification
keys, verifies the bridge signature and broker digest, rejects replay and
drift, and keeps its v2 route separate from the legacy `desktophandoff.v1`
route. The broker has no Provider database or Docker authority; the backend has
no broker signing key.

Accepted bridge statements are recorded before admission in a bounded,
mode-0600, atomically replaced broker-local replay ledger. The ledger survives
broker process restart, rejects malformed or noncanonical recovery state,
prunes expired claims, and fails closed at capacity or on persistence failure.
Desktop readiness uses an explicit `probe.v2` broker request. The Provider mux
can mint that one-use signed probe only after a real candidate allocation has
successfully passed current handoff and runtime validation, and proxies it
through the actual container broker before returning ready. A socket, legacy
broker, or pre-allocation process alone is therefore insufficient for v2
readiness.

Slice 4 uses a separate `local-candidate-non-release` runtime identity. It
binds the exact source tree, build scripts and arguments, base/package inputs,
platform, OCI config digest, and locally loaded image digest. Provider may
select it only with `deployment_level=local_candidate`, `pull_policy=never`,
and a strict candidate manifest. The production profile continues to select
only the Phase 5 signed lock and rejects the v2 executor until Slice 7 publishes
and verifies a new multi-platform runtime. Local candidate evidence is never a
production artifact, signature, provenance, or release claim.

Business tenant authorization remains caller-owned. Provider performs only the
irreversible opaque binding-digest consistency checks defined by the private
handoff contract.

## Consequences

Provider production composition remains the only place that constructs the
Docker runtime and private handoff listener. Browser/Desktop role commands
construct only executor listeners and bounded protocol handlers. A role probe
is not ready until its executor graph and its Provider dependency are healthy.
Independent-process evidence must observe both the Provider authority process
and the executor process; a probe-only or copied handler is insufficient for
Slice 4 completion.
