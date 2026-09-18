# ADR 0045: Product Identity, Agent Delegation, and Threat Model

- Status: Accepted for Phase 1 architecture; implementation and security
  qualification are not yet authorized
- Date: 2026-09-18

## Context

The Product Contract admits human, Agent, and service actors and introduces
Workspace- and session-scoped control leases. The Provider Contract has a
different trust boundary: it authenticates calling services and protects
provider-local execution. Neither Provider admission nor a Provider fencing
token is end-user authorization.

The first product version is intended for one human owner and their delegated
Agents. Later collaboration must not require replacing resource identities,
events, or authorization records. The design therefore retains tenant, actor,
role, and control-scope fields while deliberately withholding multi-human
collaboration until its own policy and concurrency gates exist.

## Decision

### Identity and trust boundaries

Product authentication terminates at Product API and public Gateway edges.
Production uses a deployment-owned standards-based identity provider with
issuer, audience, signature, expiry, and revocation policy pinned by
configuration. The Product maps an authenticated subject to exactly one
tenant-scoped Product principal; caller-supplied tenant or actor headers are
never authoritative.

Development may use an explicit local identity mode on a loopback or otherwise
trusted listener. That mode is rejected by production configuration and is not
deployment or security evidence.

The Product principal classes are:

| Principal | Meaning | Credential rule |
| --- | --- | --- |
| Human | Interactive end user | Authenticates at the Product edge; long-lived identity-provider credentials never enter a Workspace |
| Agent | Delegated Product actor for one bounded run | Uses a short-lived delegation issued by Product authority; never receives the human refresh token |
| Service | Product component or operator automation | Uses workload identity scoped to one audience and service role |

The Product-to-Provider call uses a Product service identity under the locked
Provider calling standard. The Provider sees the Product caller and sanitized
correlation/evidence bindings, not the end-user credential. Product API,
Gateway, reconciler, Guest Agent, PostgreSQL, object storage, and Provider each
have distinct service identities and audiences.

### Tenant and role model

Every durable Product resource belongs to one `tenant_id`. Authorization is
evaluated from authenticated principal, tenant membership, role, resource,
action, and current resource state. A resource identifier alone never grants
access, and not-found responses must not reveal cross-tenant existence.

The policy vocabulary reserves these roles:

| Role | Initial authority |
| --- | --- |
| `owner` | Workspace lifecycle, policy, delegated Agent runs, recordings, artifacts, and control acquisition |
| `controller` | Bounded interactive control and allowed mutations, but no ownership or retention changes |
| `viewer` | Authorized reads and non-control data-plane observation only |
| `operator` | Deployment operations through a separate audited administrative boundary; not an implicit tenant member |

The first version permits one human `owner` per Workspace plus delegated Agent
actors and service actors. It does not implement invitations, rooms, chat,
shared cursors, control queues, or simultaneous human controllers. The
`controller` and `viewer` policy vocabulary is reserved so later collaboration
can be added without treating every connection as an owner.

### Agent delegation

An Agent run is created only by an authorized Product actor. Product stores the
parent actor, Workspace, optional slot, requested task reference, allowed tools
and actions, network/storage policy, maximum lifetime, and revocation state.

The run receives a short-lived, audience-bound delegation containing at least:

- tenant, Workspace, Agent run, and delegated actor identities;
- optional exact slot/session identities;
- explicit action scopes and policy revision;
- issuer, audience, issued-at, not-before, expiry, and unique token ID; and
- a parent-authorization and run-generation binding.

Delegation lifetime cannot exceed the Agent run or parent authorization. It is
non-refreshable by the Agent. Product services re-evaluate current run,
Workspace, slot, and revocation state before security-sensitive operations.
Revoking or cancelling a run invalidates new work, closes its control-bearing
connections, and causes the Guest Agent to stop or quarantine outstanding
actions. A child Agent receives a new narrower delegation and a parent-run
link; delegation cannot widen authority.

Agent tools act through Product- or Guest-Agent-owned mediated interfaces.
Agents do not receive database credentials, Provider controller credentials,
object-store root credentials, host paths, raw runtime endpoints, or the
human's identity-provider tokens. User secrets are references in Product
state. A Guest Agent may exchange an authorized reference for a short-lived,
single-purpose grant whose audience, target, operations, and expiry are
bounded to the active run.

### Product control lease

A Product control lease serializes mutating human or Agent input for one exact
scope: a Workspace or runtime session. Its authority is Product PostgreSQL.

The state machine is `active -> released`, `active -> expired`, or
`active -> revoked`. At most one unexpired lease exists per tenant and scope.
Database time determines expiry. Acquire and replacement issue a strictly
increasing per-scope `control_fence`; renewal retains the fence. Supported
durations are 5 through 120 seconds and are bounded by actor and session
expiry.

Acquire does not silently steal an active lease. A conflicting controller gets
a safe conflict response unless an explicit, separately authorized revocation
has committed. Only the bound controller may renew or release, using the exact
lease ID and fence. Expired, released, revoked, or stale-fence requests fail
before data-plane work. Viewers never need or receive a control lease.

The Gateway checks current authorization and control lease before admitting a
control-bearing connection, watches revocation/expiry while it is open, and
closes the connection on authority loss. Every mutating frame is bound to the
admitted session, lease, and fence; reconnect requires a new one-use
connection grant and a fresh check.

The following authorities are distinct and must never be substituted:

| Authority | Owner | Protected resource |
| --- | --- | --- |
| Product control lease and fence | Product PostgreSQL | End-user or Agent mutation of a Workspace/session |
| Reconciler worker lease | Product PostgreSQL | Temporary right to dispatch one reconciliation partition |
| Provider operation fencing token | Calling service and Provider Contract | One Provider mutation attempt |
| Gateway capacity reservation | Gateway coordination store | Admission capacity, not control ownership |
| Browser downstream action fence | Browser Gateway/Provider profile | Ordered Browser actions after private ingress |
| Connection grant | Product API and Gateway | One short-lived data-plane admission, not a renewable lease |

### Audit and privacy

Authentication, authorization, delegation issuance/revocation, control-lease
transitions, secret-reference access, and administrative actions emit immutable
security events with safe actor and correlation identifiers. Logs and events
must not contain credentials, connection tickets, secret values, Provider
handoffs, raw endpoints, host paths, terminal content, media content, or
private Agent reasoning.

Agent trace recording may include user-visible instructions, tool names,
bounded arguments/results after policy filtering, approvals, and action
outcomes. It does not attempt to capture hidden model reasoning.

## Threat model

| Threat | Required control | Residual risk / later gate |
| --- | --- | --- |
| Cross-tenant object access or identifier guessing | Server-derived tenant, resource authorization on every read/write/stream, non-enumerating errors, tenant-bound storage keys | Formal policy tests and hostile multi-tenant review remain future gates |
| Credential or connection-ticket replay | Audience/target binding, short expiry, unique ID, one-use atomic consumption, encrypted transport, hashed ticket retention | Client compromise during the valid window remains possible |
| Stale or concurrent controller | One active Product control lease, monotonic fence, continuous Gateway checks, frame/session binding | Multi-human handoff UX is intentionally absent |
| Delegated Agent privilege escalation | Explicit narrow scopes, parent/run binding, non-refreshable expiry, mediated tools, child authority narrowing | Tool-specific policy and sandbox escapes require separate testing |
| Confused deputy between Product and Provider | Separate audiences and identities, locked Provider request bindings, no end-user credential forwarding | Incorrect Product authorization remains a Product defect |
| Provider/backend identity disclosure | Private adapter records, safe DTOs/events/logs, public Gateway indirection | Operator-only diagnostics need separate access controls |
| Guest Agent compromise | Outbound-only authenticated control channel, scoped grants, no control-plane credentials, bounded filesystem/network view | Guest compromise can affect data legitimately exposed to that slot |
| Browser SSRF or egress abuse | Restricted network profile, DNS/IP policy, private-ingress separation, action fencing, rate and size limits | Destination-policy completeness and hostile-web testing remain open |
| Gateway bypass or stale connection | No public Provider endpoint, one-use Product grants, private handoff resolution, revocation/expiry watch | Network and identity deployment must be qualified independently |
| Recording leaks sensitive data | Separate recording classes, encryption, access policy, retention/deletion, redaction and recording indicators | Content classification and jurisdiction policy are deployment concerns |
| Database restore, split brain, or stale worker | PostgreSQL authority, monotonic fences, reconciliation generations, strict restore procedure, single current binding | Multi-region authority and disaster-recovery evidence remain open |
| Outbox duplication or ambiguous external result | Stable idempotency, attempt ledger, level-triggered reconciliation, `outcome_unknown` | Non-idempotent future dependencies require explicit adapters |
| Resource exhaustion | Per-tenant and per-principal quotas, bounded inputs/streams, Gateway capacity, deadlines, backpressure | Capacity numbers require load evidence per deployment profile |
| Compromised build or dependency | Pinned inputs, signed immutable artifacts, provenance verification, least-privilege deployment | Full supply-chain and incident-response qualification remains open |

## Security invariants

1. No end-user or Agent credential is accepted by the Provider as Product
   authorization.
2. Every Product resource lookup is tenant-bound before existence is revealed.
3. Delegated authority is narrower and shorter-lived than its parent.
4. One control scope has at most one unexpired Product control lease.
5. A stale control fence cannot produce a data-plane mutation.
6. Secret values and private runtime coordinates never enter stable Product
   resources, events, recordings, or ordinary logs.
7. Losing an authority watch fails control-bearing connections closed.
8. Development identity mode cannot start in production deployment level.

## Consequences

- Product authorization and Provider admission remain independently testable.
- The single-human first version keeps the durable fields needed for later
  collaboration without claiming that collaboration is implemented.
- Gateway and Guest Agent implementation must consume Product-issued authority
  rather than infer it from network reachability.
- Production release requires threat-control tests and deployment evidence;
  accepting this ADR is design evidence only.

## Rejected alternatives

### Forward human access tokens to Provider or Guest runtimes

Rejected because it couples trust domains, expands credential exposure, and
turns Provider admission into end-user authorization.

### Use connection ownership as the control lock

Rejected because disconnect detection is delayed, reconnects race, and several
Gateway instances cannot derive a durable monotonic fence from socket state.

### Reuse Provider or Browser fences as Product control authority

Rejected because their resources, owners, lifetimes, and failure semantics are
different.

### Implement collaborative control in the first version

Rejected because queues, handoff, presence, chat, fairness, and simultaneous
editing require a separate product and security design.

## Non-goals

This ADR does not choose an identity-provider vendor, implement policy code,
define operator break-glass procedures, authorize multi-human collaboration,
or claim hostile multi-tenant security.
