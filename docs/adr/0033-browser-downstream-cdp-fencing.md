# ADR 0033: Browser Downstream CDP Action Fencing

- Status: Accepted for the P4 Browser downstream CDP fencing component slice
- Date: 2026-09-05

## Context

ADR 0031 assigns every authenticated Browser connection-capacity lease an
opaque owner and a monotonically increasing fence. That fence prevents a stale
owner from renewing or releasing a replacement owner's shared-capacity record.
The current `gateway.ConnectionLease` does not expose the fence to the Browser
data path, however, and Chromium does not understand it.

ADR 0032 closes the separate exact-grant durable-revocation caller gate. A
Gateway process observes capacity and revocation events and closes its public
and private streams when either authority terminates. Closing a stream is not a
downstream action fence. A Gateway can be suspended after it has established a
CDP stream, remain suspended while its capacity lease expires and another
Gateway acquires a higher fence, and resume before its local renewal observer
runs. The resumed process can then write an old-owner CDP message to the
already established Chromium connection.

Checking Redis again inside the Gateway immediately before `Stream.Send` does
not close this gap. The Gateway can be suspended between the check and the
write. A process-local lock, timer, or cancellation observer has the same
failure mode. The resource boundary that serializes ownership changes and CDP
actions must therefore be outside the Gateway process and in front of the only
Chromium connection that can accept those actions.

Three existing values remain distinct:

- the Provider operation fencing token orders Provider-local sandbox and
  Browser-session mutations;
- the Browser connection generation binds an opaque Provider handoff to one
  committed runtime allocation; and
- the ADR 0031 owner and fence order caller-owned connection-capacity
  ownership.

None may be substituted for another. This decision adds no Provider route,
DTO, Schema, capability, operation, or public endpoint.

## Decision

Add a private Browser CDP ingress and an action-fencing capability for the
caller-owned authenticated-capacity authority. The ingress is a separate
enforcement component. The Provider continues to own Browser allocation,
opaque handoff, runtime attachment, and cleanup. The calling platform continues
to own users, tenants, grants, revocation, public Gateway policy, and public
connection capacity.

The Provider does not become the capacity or grant authority by supplying a
private runtime stream to the ingress. The ingress enforces evidence issued and
verified by the caller-owned capacity authority; it does not mint grants,
select tenant limits, mutate Provider operations, or interpret Provider
business state.

### Opaque action-fence claim

A fencing-enabled Browser capacity lease supplies one bounded, versioned,
opaque action-fence claim through a new narrow capability. The ordinary
`ConnectionLease` event and release contract remains unchanged. Browser
composition that enables downstream fencing requires the narrow capability
explicitly and rejects a lease that does not implement it. Terminal composition
does not acquire Browser action-fencing semantics implicitly.

The claim is private connection material. Its canonical encoding carries only
the exact active ADR 0031 capacity member, including that member's opaque owner,
monotonic fence, tenant/session fingerprints, and authorization expiry. The
configured verifier, rather than the claim bytes alone, additionally binds:

- the exact immutable capacity-policy and namespace fingerprints;
- the claim format and action-admission program identity;
- the exact tenant, sandbox, Browser session, session kind, and authorization
  expiry represented by the capacity member; and
- at the first successful activation for that fence, an action-subject
  fingerprint that also includes the capability profile and Browser connection
  generation supplied by the already-authorized Gateway.

The Gateway treats the claim as opaque. It may transport it only over the
private ingress channel for the exact Browser connection that acquired the
lease. It must not place the claim, owner, fence, member, namespace, Redis key,
or subject fingerprint in a URL, public response, ordinary Gateway audit,
caller report, log, metric label, or Provider handoff record.

A claim is not a bearer grant and cannot establish authority by itself. The
ingress validates it against the retained shared-capacity state before it can
admit an action. Replaying a claim after its exact member is absent, expired,
released, or replaced fails closed.

### Unique private ingress

Each exact tenant, sandbox, and Browser session has one logical private ingress
and one ingress-owned Chromium upstream. The ingress terminates the private
Gateway channel, reconstructs complete bounded CDP data messages, and owns the
only path that may write those messages to Chromium. The direct
Gateway-to-Chromium and Gateway-to-raw-Provider-attacher paths are unavailable
in fencing-enabled composition.

The ingress may be implemented as a separately started process or behind an
equivalent independently scheduled service boundary, but the release evidence
requires a separate OS process. Deployment routing, credentials, and runtime
composition must prevent a Gateway from bypassing it. Supplying two ingress
instances that can independently write to the same Chromium endpoint is invalid
because their process-local critical sections cannot order downstream writes.

The ingress serializes these operations under one per-session execution gate:

1. exact-member and session-high-water validation for an activation;
2. closure of the previously active private stream when the activation carries
   a higher fence;
3. lazy establishment of the replacement's unique Chromium upstream; and
4. for each action, exact-member/high-water revalidation followed by complete
   forwarding while the same gate remains held.

The fencing-enabled profile requires authenticated capacity policy to set the
exact Browser-session limit to one. Multiple simultaneous owners for one CDP
session conflict with a highest-fence single-writer invariant and are rejected
as invalid configuration, even if a more permissive generic capacity policy
would otherwise be valid.

Browser-to-caller responses and events are delivered only to the currently
active ingress connection. Control frames are handled by the private transport
and are not CDP actions. A client-to-Chromium text or binary data message is one
action for this boundary. The complete message must fit the already reviewed
hard bound and be buffered before action admission; no fragment or partial
payload may be written to Chromium first.

### Redis exact-member and high-water authority

The Redis-compatible action-fencing adapter uses a newly provisioned,
fencing-enabled capacity namespace. It does not rewrite an existing ADR 0031
policy in place. Its action policy pins the format, the inherited capacity
policy fingerprint, the action-admission script hash, bounds, and retention
rules. Runtime startup is verify-only and never recreates missing policy or
high-water history transparently.

An action-admission script atomically:

1. validates the capacity and action policies, key types, argument shape, and
   bounded encodings;
2. reads Redis server time and validates the complete exact capacity member and
   the requested bounded action window;
3. proves that the member is still active, is not past authorization expiry,
   and matches the claim's owner, fence, tenant, sandbox, Browser session-kind,
   and Browser-session fingerprints;
4. validates that the capacity fencing counter is canonical and is not behind
   the claimed or retained fence;
5. reads the exact Browser session's retained action high-water record;
6. rejects a lower fence, or treats the same fence with a different owner,
   action subject, policy, or bound expiry as unavailable; and
7. compare-and-advances the high-water record for a higher valid fence, without
   shortening the previous record's safe retention.

All keys used by this atomic decision share the capacity namespace's Redis
Cluster hash tag. Raw tenant, sandbox, Browser-session, grant, handoff,
endpoint, credential, or backend identifiers are not key components. A
per-session high-water key uses only the fixed namespace tag and the exact
session fingerprint. Claims are limited to 24 hours and the key is retained at
least until no previously activated claim can remain valid, without shortening
an older retention deadline. Missing history is treated as a first activation;
the adapter cannot distinguish a legitimate first/post-retention activation
from administrative early deletion of that one key. Detecting such deletion
requires stronger retained-store controls and is part of the later HA/restore
gate. Malformed, wrong-type, or internally inconsistent state is unavailable,
never a fresh authority. A capacity fence counter behind the exact active
member or an existing retained high-water record is a detectable rollback and
is also unavailable. A syntactically valid older snapshot, or deletion of the
retained high-water key, is not detectable by this component.

The script returns bounded status and conservative server-relative timing only.
Raw Redis diagnostics and shared-state values remain private. Redis client
retries are disabled; context cancellation and bounded dial, command, read,
write, and pool timeouts follow the ADR 0031 discipline.

### Action admission linearization

For this ADR, an action means one complete client-to-Chromium CDP data message.
Its admission linearization point is the successful atomic exact-member and
session-high-water decision in the authoritative Redis-compatible store while
the unique ingress holds the per-session execution gate. The ingress retains
that gate until it has either written the complete admitted message to its
unique Chromium upstream or failed the write and closed the connection.

This definition avoids a Gateway-side check-to-write race. If a replacement
lease or its higher-fence ingress activation is ordered before the old action's
authority decision, the old exact-member or high-water check fails before any
of that action is written to Chromium. If the old action's authority decision
is ordered first, that action was admitted before the replacement for this
boundary and may be forwarded before the ingress admits a higher-fence action.
The unique ingress prevents a second process from overtaking the retained
per-session execution gate and reversing that order at Chromium.

The ingress passes its complete bounded operation budget to the authority. The
atomic decision rejects a capacity member whose Redis-server-time lifetime
cannot cover that budget. This safety window bounds work but is not the
linearization mechanism. If the authority result is unavailable or ambiguous,
the action is not admitted. If
the authority decision succeeds but the downstream write or response becomes
uncertain, the outcome is unknown: the ingress closes the connection and does
not replay the action automatically.

The linearization point orders action admission and forwarding. It does not
identify when Chromium executes the command or when an external side effect
becomes visible. A command admitted before a higher fence, expiry, or
revocation may complete afterward. This component cannot undo a command that
Chromium already accepted.

### Gateway ordering, termination, and priority

The Browser connection ordering becomes:

1. validate the public request;
2. authorize and exactly bind the caller grant;
3. acquire process-local and authenticated capacity, including the opaque
   action-fence claim;
4. establish and validate the exact-grant revocation watch;
5. record the authorized event;
6. resolve the opaque Provider Browser handoff;
7. connect only to the private ingress, which validates/activates the exact
   claim before lazily dialing Chromium;
8. record the connected event; and
9. proxy complete messages through per-action ingress admission.

A missing, nil, typed-nil, malformed, expired, mismatched, stale, or
unverifiable claim must not reach Chromium through the reviewed ingress.
Neither may a wrong namespace or policy, zero or exhausted fence, owner
collision, wrong capacity subject or session kind, same-fence action-subject
drift (including profile or connection generation), absent/expired/replaced capacity member,
lower-than-high-water fence, same-fence different owner, direct attachment, or
non-unique ingress topology. Store outage, timeout, malformed state, detectable
counter/state inconsistency, and an ambiguous authority result fail closed.

Loss before private connection establishment does not record a connected event
or dial Chromium. Loss during an active connection closes the public stream,
private ingress stream, and Chromium upstream without reconnect. A later
reconnect requires a newly resolved Provider handoff and the same still-active
claim; a stale or replaced claim cannot reconnect.

Stable simultaneous-cause priority remains:

1. confirmed exact-grant revocation;
2. grant expiry;
3. confirmed capacity or downstream-fence loss;
4. capacity or downstream-fence authority unavailability;
5. revocation-authority unavailability; and
6. transport failure or caller cancellation.

Downstream-fence loss and unavailability use fixed, bounded, metadata-only
reasons. A higher capacity fence is not reported as grant revocation. ADR 0032
revocation remains an independent exact-grant authority and is not stored in or
inferred from the action high-water record. This slice does not establish
downstream revocation fencing.

## Release Boundary

The component slice includes the ADR, narrow claim and verifier ports, the
Redis-compatible exact-member/high-water adapter, the private ingress state
machine with lazy upstream dial, and explicit fail-closed Browser composition.
The composition rejects simultaneous raw and fenced resolvers, but an interface
implementation alone cannot prove private peer identity or a unique deployment
topology. Those remain named requirements of the independent multi-process
release gate.

Focused race/shuffle and real pinned-Redis-compatible integration tests must
cover:

- missing, nil, typed-nil, malformed, oversized, wrong-version, wrong-policy,
  wrong-namespace, and expired claims;
- exact tenant, sandbox, Browser-session, session-kind, authorization-expiry,
  owner, fence, and capacity-member binding, plus same-fence rejection when the
  activated profile or connection generation changes;
- a virgin high-water record, same-owner idempotent validation, a higher-fence
  advance, lower-fence rejection, and same-fence owner or subject conflict;
- one per-session execution gate across claim activation, action admission,
  complete downstream write, replacement, and stream closure;
- complete-message buffering with no pre-admission partial write, bounded
  text/binary messages, cancellation, deadlines, and downstream write failure;
- exact-member expiry, release, replacement, renewal, capacity-policy mismatch,
  fence exhaustion or detectable capacity-counter rollback, wrong Redis types,
  malformed history, store timeout or outage, and ambiguous results;
- ingress and adapter reconstruction against retained high-water state;
- rejection of raw/fenced resolver coexistence and configurations with a
  session limit other than one; unique authenticated ingress routing remains a
  deployment and caller-gate requirement;
- fixed audit reasons and absence of claims, owners, fences, members, keys,
  subject fingerprints, handoff references, endpoints, credentials, backend
  identifiers, and CDP payloads from public errors, logs, metrics, and audit;
  and
- stable priority against revocation, grant expiry, capacity events,
  revocation-authority loss, transport failure, and cancellation.

Full repository race/shuffle, vet, Contract verification, and the unchanged
locked 48-case Conformance Suite remain required. Passing these gates
establishes downstream CDP fencing ports, one Redis-compatible authority
adapter, the private ingress component, and Browser composition behavior only.
It is component and real-backend integration evidence, not external-caller E2E.

Closing the downstream CDP fencing caller gate requires a separately locked
black-box run with at least two independently started Gateway OS processes, an
independent private ingress OS process, independent black-box callers, one real
retained Redis-compatible authority, and the exact signed Browser image running
real Chromium. An echo stream, two service objects in one process, a mocked CDP
server, or a Gateway-local ingress does not qualify.

The run must:

- establish an exact Browser session and prove an ordinary bounded CDP action;
- suspend the owning Gateway process past its confirmed capacity lease, acquire
  a replacement for the same session through another Gateway, and activate the
  higher fence;
- use distinct observable real-CDP mutations to prove that a message queued to
  the suspended old Gateway after its lease loss is rejected before Chromium,
  while the replacement owner's mutation succeeds;
- prove pre-action loss, active-stream replacement, lower-fence reconnect
  rejection, unaffected Browser sessions and tenants, and no partial old action
  forwarded at the ingress;
- prove store-outage failure closure and recovery against retained state;
- reconstruct the ingress while retained high-water state is present and prove
  stale rejection; a gate that removes or restores away that state must add an
  independent virgin-state marker or remain open;
- leave no direct route from either Gateway to Chromium and clean every owned
  runtime resource; and
- produce sanitized evidence pinning clean Gateway, ingress, caller/harness,
  Provider, Contract/tree/Suite, Browser image and provenance, Redis-compatible
  image and configuration, policy and script fingerprints, architecture, and
  scenario report identities.

The Contract identity and any Provider or Browser scenarios exercised by that
run must be reported explicitly. They must not be inferred from component
tests or from the earlier shared-capacity and durable-revocation echo fixtures.

Passing the component slice or the later caller gate does not establish CDP
exactly-once behavior, transparent replay or reconnect safety, command-result
certainty after disconnect, revocation of an already admitted or executed
action, arbitrary suspension safety for the ingress itself, downstream grant-
revocation fencing, Redis or Valkey provenance, HA/failover or restored-snapshot
consistency, Provider multi-controller reliability, hostile multi-tenant
isolation, real Agent Platform compatibility, aggregate conformance,
production advertisement, deployment readiness, or production readiness.

## Consequences

- ADR 0031's capacity fence becomes usable as private downstream ownership
  evidence without becoming a Provider fencing token or a public credential.
- A unique serialized ingress, rather than the potentially suspended Gateway,
  decides which complete CDP action may enter Chromium.
- Fencing-enabled Browser composition is intentionally single-writer per
  Browser session and fails closed on malformed or internally inconsistent
  retained authority. A missing high-water key is treated as first activation,
  subject to the separately stated deletion/restore limitation.
- Complete-message admission adds one shared-authority decision and buffering
  cost to each client-to-Chromium CDP action. Throughput, latency, and store load
  require measurement before deployment sizing.
- The first successful activation freezes the full action subject for that
  fence. The existing capacity member does not itself encode capability profile
  or connection generation, so correct authenticated Gateway-to-ingress peer
  identity remains an explicit topology requirement.
- Retention TTL prevents unbounded action-history growth but cannot detect an
  administrator or failed restore deleting one high-water key early. Restored-
  snapshot consistency remains outside this component evidence.
- Previously admitted commands and unknown outcomes remain explicit. Stronger
  execution or side-effect semantics would require cooperation from Chromium or
  a different downstream protocol and a separate decision.
- Durable exact-grant revocation, shared capacity, and downstream action
  fencing remain three separately named authorities and evidence gates.
