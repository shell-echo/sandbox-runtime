# ADR 0052: Phase 6 Provider-Owned Handoff and Executor Role Boundary

- Status: accepted
- Date: 2026-09-21

## Decision

The Provider remains the sole owner of Browser and Desktop handoff authority.
It owns the PostgreSQL session/reference truth, the persisted opaque tenant
binding and Provider-local generation/fence/expiry/revocation/recovery state,
and the concrete runtime resolver and attach/cleanup implementation. Product
retains business grant, control-lease fence, tenant and end-user authority;
the Gateway capacity adapter retains its own action-fence claim and high-water
authority. These values are not interchangeable. The public locked Provider
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

The Browser-only Provider remains a separate production-v3 process from the
coding and Desktop Providers. Its session and reference documents must use the
Provider PostgreSQL authority; the older Browser file registries and static
executor TLS are not a production fallback. On the authenticated independent
action-ingress→Provider private edge, the Provider may atomically bind one previously unbound Browser
handoff reference to a caller-derived tenant digest after exact resource,
session, Provider revision, generation, fence and expiry checks. The same
binding is idempotent, while another digest, stale authority, revocation or
expiry is rejected. Binding is never a substitute for Gateway's actual
tenant/grant authorization. The Browser role/backend may not read that
PostgreSQL state or obtain Docker authority.

Browser production uses an explicit closed `browser-handoff.v2`, not a silent
extension or fallback to v1, a static CDP URL, or header-only attach. The
authenticated private edge admits only the exact action-ingress principal,
instance, audience, route and Browser Provider profile. Product/Gateway must
atomically consume a one-use grant and verify the committed tenant, actor,
session, slot/generation/profile, active control lease, revocation and expiry
before deriving a scoped stable tenant/resource digest. A Redis capacity claim
is not a grant or control lease; it remains opaque and is interpreted only by
the caller-owned capacity authority. Connection epoch, authority expiry and
request digest are separately bound and cannot be folded into the stable
tenant digest. The Provider verifies the delegated caller and exact local
resource/connection tuple, not the caller's end-user eligibility algorithm.
This boundary does not claim resistance to a compromised authorized Gateway.

`browser-handoff.v2` adds a new tenant/resource digest definition; v1 fixed
only a `sha256:v1:` syntax and is not retroactively assigned this algorithm.
The v2 value is `hmac-sha256:v2:` followed by lowercase HMAC-SHA-256 hex.
The caller-only key is a dedicated, random 32-byte
`browser_tenant_binding_key` secret, distinct from TLS, admission, tickets,
recording and Desktop bridge keys. The HMAC input is the ASCII domain
`sandbox-runtime/browser-handoff-tenant-binding/v2`, one NUL byte, then
compact `encoding/json.Marshal` of a closed ordered struct containing exactly
`caller_authority_scope`, `provider_instance_audience`, `tenant_id`,
`sandbox_id`, `browser_session_id`, `provider_revision_id`,
`capability_profile_id`, `connection_generation`, `handoff_reference`.
Identifiers are validated as bounded ASCII without normalization; generation
is a positive bounded integer. These fields come from committed Product
binding and validated stable caller/Provider configuration, never an end-user
supplied payload. One-use grant ID, raw/digested Redis claim, expiry,
connection epoch and control lease/fence are excluded. Thus an exact handoff
keeps its digest across reconnects, while a new reference, Provider revision,
generation or audience has a new digest. The HMAC is privacy-preserving
consistency evidence, not a Product grant attestation.

Product binding metadata must atomically fix caller scope and key version at
first selection. The role material registry resolves only that exact version;
rotation affects new handoffs, not active bindings. Loss or revocation of an
active key fails closed and requires affected handoffs to be revoked and
recreated, never guessed with a new active key or downgraded to plain SHA-256.
Provider and executors receive neither key nor tenant plaintext: they validate
the v2 format and match the first durable reference binding. The locked
Provider Contract is unchanged.

The Product persistence shape is an additive, immutable row per exact
`(tenant_id, product_session_id, provider_instance_audience,
handoff_reference)`. It holds the nine-field derivation projection, exact
secret binding ID, reference, purpose, role, version and canonical binding
digest alongside the derived tenant digest, not key bytes, tickets or Redis
claims. PostgreSQL rejects updates to an established metadata row; only a
new exact handoff can select a new key. The existing `runtime_sessions`
handoff pointer remains the sole current selector; an old metadata row is
never itself an active authorization.
The first selection and a newly observed handoff should commit in the same
Product transaction under the existing session/slot/Provider binding locks.
Independent Gateway replicas must agree on the entire immutable row or reject
a conflict; they never overwrite it with their locally active key. A grant
must retain this exact row identity when issued and refuse consumption after
the current handoff changes. Historical grants without that binding are not
silently upgraded in the v3 path. Cleanup may remove a row only after its
handoff, grants, connections and replay window are all inactive; missing
metadata for an established handoff is a failure, not permission to reselect
a key. This is Product caller metadata, not a second Provider session truth.

The Desktop private transport needs an explicit v2 prepare/start boundary.
The v1 `accepted` response remains a historical streaming protocol, never a
production v3 fallback. A v2 `prepared` response reserves capacity and
validates the current authority without opening the executor media reader.
Product sends one start bound to the exact handoff, generation, connection
epoch, fence and authority/request digests only after the public WebRTC sender
and private demultiplexer are armed, recording is ready, and authority remains
valid. Provider rechecks the same authority before opening media, then sends
`started` before forwarding packets. Prepare-to-start consumes the original
connection and first-media deadlines; expiry, cancellation, missing start or
broker loss close and release the reservation. Runtime queue overflow after
activation remains fail-closed. The implemented v2 path remains a component
candidate until a decodable first frame and failure matrix pass the real
Product PostgreSQL/WebRTC and Docker gates. The current internal first-frame
signal measures the first successful RTP write, not a client-decoded display
frame; the latter requires separate real-media evidence.

ADR 0033's unique, separately scheduled Browser CDP action ingress remains
mandatory. The Gateway's raw capacity claim travels only on that protected
private path. The ingress serializes activation, closure of a replaced old
stream, exact-member/high-water verification and each *complete* CDP write
under one execution gate. The Provider private attach and typed Docker mux are
downstream of that ingress; they cannot be exposed as a Gateway-to-CDP bypass.
Provider PostgreSQL connection evidence and periodic handoff re-resolution
cannot replace per-action capacity verification or its restart-retained
high-water witness. Product grant revocation/control-lease loss and capacity
member/witness failure are separate fail-closed gates.

A static CDP upstream is not an allocation binding. Browser production attach
must select the current Provider-owned allocation behind one opaque reference,
verify it against the durable handoff and Docker runtime state, and only then
relay CDP frames. Different sessions or tenants must never share a fixed
prestarted Chromium merely because the backend capacity is one. This requires
a typed Provider-owned runtime bridge with bounded socket/cleanup semantics;
it cannot expose arbitrary URL or command selection to the Browser backend.
The previous static-upstream Browser backend is component compatibility
evidence only, not a passing full-system gate.
One-use Browser executor request IDs and request digests are committed to the
Provider reference record under the same PostgreSQL sandbox-authority check
before Docker attach. The local mux/backend caches are bounded defense in
depth, not restart-retained authority. A successful claim is consumed even if
the subsequent attach fails; retry requires a fresh, newly authorized request.
This replay ledger never contains the caller's raw Redis capacity claim and
does not replace the independent per-action ingress high-water check.
The Browser allocation mux is a Provider-owned Unix socket under the exact
`/run/browser-mux` directory. The canonical profile binds one Provider writer
mount, one read-only Browser backend consumer mount, a distinct-UID Unix peer
edge and the Provider's Unix listener; no Gateway or ingress process may mount
it. Operator-provisioned mode 0710 directory ownership is Provider UID plus
backend GID, and the mode 0666 socket is reachable only through that
directory. The mux still validates the backend peer UID and one-use executor
capability before resolving Docker state. Profile declarations alone do not
prove the mount or filesystem policy was enforced in a process gate.

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

Phase 6 local integration and Slice 6 security-enforcement gates use a separate
`local-candidate-non-release` runtime identity. It
binds the exact source tree, build scripts and arguments, base/package inputs,
platform, OCI config digest, and locally loaded image digest. Provider may
select it only with `deployment_level=local_candidate`, `pull_policy=never`,
and a strict candidate manifest. The production profile continues to select
only the Phase 5 signed lock and rejects the v2 executor until Slice 7 publishes
and verifies a new multi-platform runtime. Local candidate evidence is never a
production artifact, signature, provenance, or release claim.

The Slice 6 Desktop Provider uses the same independent command, PostgreSQL
authority, material registry, broker and executor-v2 runtime composition with
`provider-process.v3` live TLS/CRL wiring and
`deployment_level=local_candidate`. In this exact combination, the Contract
listener, private `/desktop` listener and outbound Desktop attach use three
separate profile-bound edges and the Desktop Provider principal. The candidate
manifest is checked against the configured local source tree at startup and
the loaded image is inspected against its exact content identity. Candidate
mode cannot select raw/static TLS keys or a production manifest. An
`application.mode=production` command selects the protected process path; it
does not certify that the candidate artifact is released. Desktop v3 with
`deployment_level=production` remains rejected until Slice 7 publishes and
independently verifies the matching executor-v2 native multi-platform image,
SBOM, signature and provenance, then binds a new immutable lock. Phase 5's
signed older runtime is not a substitute. The affected security and runtime
gates must be repeated with the published artifact; Slice 6 local-candidate
evidence does not upgrade automatically.

The two Desktop image identities use separate closed types and paths. The
Phase 5 production adapter accepts only
`phase5-production-release-manifest.json`, whose original publication bytes
are fixed at
`sha256:a03c1426058ef6fe18a70329610d0495d267cd1aa9513e650367e3f9a8857887`
from source `e4a940bda6c5172a78d0dbe40963ca1a99911976`, together with the existing
signed index lock. The Phase 6 local candidate accepts only
`phase6-local-candidate-manifest.json` plus its generated mode-0600 candidate
identity. Production and local-candidate configuration select exactly one of
these paths according to the closed deployment level; missing, unknown,
crossed, label-drifted, or digest-drifted identities fail closed. Image labels
never choose or downgrade the validation rule.

For current local-candidate admission the generated identity is v2, accompanied
by a private, digest-bound OCI archive sidecar. It separates the Docker store
descriptor, container-selected platform manifest and true OCI config digest;
raw index/manifest/config/layer bytes and ordered diff IDs are verified. The
historical v1 identity remains readable only for historical evidence and is
not automatically admitted or upgraded. A local tag or Docker `.Id` is not a
config digest or a substitute for the selected-manifest chain. Omitted ARM64
variant is compared as baseline v8 only for this repository's locked
`linux/arm64/v8` profile; descriptor bytes and hashes are never normalized.

During Slice 4 development the evolving candidate package manifest had
temporarily replaced the production adapter's verification input. That was a
repository identity-selection regression, not evidence that the signed Phase
5 artifact was unavailable. Restoring the immutable Phase 5 manifest preserves
that artifact's bounded production-adapter availability. Enabling executor v2
in the production profile still requires the Slice 7 multi-platform
publication, signature, provenance and lock update.

The historical Phase 5 image verified its installed package set while building
but did not emit an `installed-set-digest` OCI label. Its versioned production
schema therefore requires that label to be absent and rejects unexpected
presence, while requiring the exact historical custom-label set, package
archive digest, signed index/platform lock, source revision and provenance.
The top-level installed-set digest remains immutable build-input evidence; the
runtime does not claim to re-attest it from an image label or infer it from any
other label. The Phase 6 candidate schema separately requires its
per-platform installed-set label. Slice 7 must publish the stronger Phase 6
multi-platform supply-chain identity.

Slice 6 isolates the package drift discovered in the historical recursive
fetch: only the candidate recipe has new closed per-architecture APK locks.
The lock binds every archive's name, version, architecture, source repository,
SHA-256, size and declared license; local staging verifies the entire set
before a network-disabled Docker build, and the Dockerfile independently
checks archive and installed-set digests. Candidate identity and OCI labels
also bind the exact lock file digest. The old Phase 5 Dockerfile/build script,
signed manifest and publication workflow are unchanged. The candidate broker
is built with Go 1.26.8 after a Go 1.26.5 image scan reported eight high-
severity standard-library findings; a new scan reported zero high/critical
findings in the arm64 OS packages and broker. This scan is point-in-time
component evidence, not a standing security or release guarantee.

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
