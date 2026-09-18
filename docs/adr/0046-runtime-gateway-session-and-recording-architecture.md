# ADR 0046: Runtime Gateway, Sessions, and Recording Architecture

- Status: Accepted for Phase 1 architecture; protocols are target definitions,
  not advertised capability or implementation evidence
- Date: 2026-09-18

## Context

The Product API owns durable session intent, authorization, control leases,
connection grants, and recording policy. Interactive terminal, Browser,
Desktop, editor, notebook, preview, file, and MCP traffic has different
latency, framing, backpressure, and recording requirements and should not pass
through Product control-plane request handlers.

The repository already contains bounded terminal and Browser Gateway ports and
reference evidence. Those components use caller-owned grants, metadata audit,
capacity, revocation, and profile-specific Provider resolution. They are not a
public Product Gateway service, and their `gateway.Recorder` records metadata
audit rather than terminal, media, or Agent-trace content.

## Decision

### Control plane and data plane are separate boundaries

Product API is the control plane. It commits session create/close/resize
intent, evaluates authorization and Product control leases, issues one-use
connection grants, and owns catalogs and policy.

Product Runtime Gateway is the public data plane. It authenticates a grant,
enforces its bindings and live authority, resolves private Provider or Guest
Agent attachment through Product adapters, proxies the selected protocol, and
applies capacity, backpressure, revocation, and recording policy.

They use separate listeners and service identities. They may be co-deployed in
a development or standalone package, but there is no in-process authority
bypass: Gateway consumes committed Product state and the same explicit adapter
contracts used by a separate deployment. Provider attachment remains private
and never becomes a public client coordinate.

### Session protocol profiles

The following names define target Product Gateway profiles. A profile is not
usable merely because it appears here or in a schema; Product capability
advertisement requires its complete identity, control-plane, Gateway, runtime,
recording, deployment, and evidence graph to be ready.

| Session kind | Target profile | Public transport | Control/data semantics |
| --- | --- | --- | --- |
| `terminal` | `product-terminal.v1` | WSS | Binary ordered terminal bytes; compression disabled; resize and close are Product mutations, not magic frames |
| `browser_automation` | `product-browser-automation.v1` | WSS | Closed, size-bounded action/result messages; ordered action fence; raw Browser endpoint is never exposed |
| `browser_live` | `product-browser-live.v1` | WebRTC with authenticated HTTPS signaling | Media plus bounded input/control channels; control input requires a Product control lease |
| `desktop` | `product-desktop.v1` | WebRTC with authenticated HTTPS signaling | Display/audio media and bounded input/control; clipboard and file transfer are separate policy capabilities |
| `editor` | `product-editor.v1` | Authenticated HTTPS proxy | Path-confined application HTTP/WebSocket traffic; no arbitrary private-network proxy |
| `notebook` | `product-notebook.v1` | Authenticated HTTPS proxy | Origin/path-confined notebook HTTP/WebSocket traffic with token stripping |
| `preview` | `product-preview.v1` | Authenticated HTTPS proxy | Explicitly selected guest port, origin isolation, header filtering, and egress policy |
| `files` | `product-files.v1` | WSS plus bounded HTTPS transfers | Structured list/watch/change messages and digest-checked binary transfer grants |
| `mcp` | `product-mcp.v1` | WSS or HTTPS | Size-bounded JSON-RPC with Product tool authorization and cancellation |

Each connection selects exactly one profile and session. Protocol negotiation
cannot upgrade to another profile, tunnel arbitrary TCP, or expose Provider,
Guest, container, host, or object-store coordinates.

### Connection-grant admission

Product API returns only a public `wss` or `https` Gateway URI, selected
protocol profile, opaque one-use ticket, and expiry. The initial maximum ticket
lifetime is 60 seconds; deployments may reduce it. Product retains only a
ticket digest and bindings.

Gateway admits a connection in this order:

1. parse and bound the public request before expensive work;
2. atomically consume the one-use ticket;
3. load the committed tenant, actor, Workspace, slot, session, profile,
   generation, recording policy, and optional Product control lease binding;
4. re-evaluate current authorization, expiry, revocation, and capacity;
5. establish mandatory audit/recording sinks;
6. resolve the private Provider handoff or Guest Agent target through the
   selected adapter with a fresh service credential;
7. connect the upstream and begin bounded proxying; and
8. watch session, actor, lease, grant, slot generation, and recording health
   until close.

Any disagreement fails closed before upstream dial. The ticket is consumed
even when a later admission step fails, preventing probing by replay. A client
reconnect requests a new connection grant and repeats the full checks.

### Session lifecycle and live behavior

Durable Product session states are `requested`, `provisioning`, `ready`,
`active`, `draining`, and a terminal state. Live connections are projections,
not the durable authority.

- `close` first commits Product intent and revocation, then drains or closes
  Gateway connections and reconciles runtime cleanup. It is idempotent.
- `resize` commits an expected-version mutation bound to the current Product
  control lease and reaches runtime only through a capability-specific adapter.
- lease expiry, actor/run revocation, slot rebinding, session expiry, required
  recorder failure, or inability to maintain an authority watch terminates
  affected control-bearing connections.
- client loss does not close the durable session unless session policy says so.
  Reconnect never resurrects closed or stale authority.
- every profile has bounded frames/messages, connection and tenant quotas,
  idle and absolute deadlines, upstream dial deadlines, and bounded queues.
  Slow consumers cause protocol-specific backpressure and ultimately a safe
  close rather than unbounded memory growth.

### Guest Agent boundary

The Guest Agent runs inside an authorized slot image and establishes an
outbound authenticated control channel to the Product/Gateway boundary. No
public inbound Guest port is required. Workload identity is bound to tenant,
Workspace, slot, binding generation, image/profile, and expiry.

The initial Guest Agent protocol may supply only capability-negotiated,
size-bounded operations such as file list/watch/transfer, allowed application
port discovery, process/session attachment, Workspace revision staging, and
health. It cannot mutate Product authority, select another tenant or slot,
obtain Provider credentials, or advertise an unconfigured capability. Channel
loss makes Guest-dependent capabilities unavailable and starts bounded
reconciliation; it does not infer that the slot or Workspace was deleted.

### Audit and content recording are different ports

Implementations must use separate interfaces and stores:

| Port | Data class | Required behavior |
| --- | --- | --- |
| `MetadataAuditSink` | Connection/auth/admission/close metadata without frame content | Immutable safe security events; equivalent to the intent of the current `gateway.Recorder` |
| `TerminalRecorder` | Timestamped terminal input/output segments and resize markers | Ordered, bounded chunks with integrity linkage and terminal replay metadata |
| `MediaRecorder` | Browser/Desktop audio, video, and control-event timeline | Profile-specific encoded segments plus integrity and synchronization metadata |
| `AgentTraceRecorder` | User-visible instructions, tool calls, approvals, bounded results, and outcomes | Structured trace; excludes private model reasoning and raw secrets |
| `RecordingCatalog` | Product metadata, authorization, integrity, retention, and state | PostgreSQL authority linked to immutable object-store content |

Recording mode is `disabled`, `metadata_only`, or `required`. The Product and
Gateway must report the selected mode honestly. When content recording is
required, failure to initialize recording rejects the connection and loss of
the recorder terminates it. A deployment must not silently downgrade to
metadata-only or disabled.

Content is written as immutable encrypted segments to object storage. Each
segment records sequence, time range, media/profile metadata, size, digest,
and previous-segment digest. A final signed or authenticated integrity manifest
binds the ordered segment set. The Product catalog becomes `available` only
after finalization succeeds. Access, playback/export, retention, legal hold,
expiry, and deletion are separately authorized and audited. Ordinary logs do
not contain recorded content.

### Capability graph and known dependencies

Product advertises a session profile as `ready` only when all of these are
ready for the selected deployment level:

- Product session/control routes and persistence;
- authorization, control lease, one-use grant, and revocation paths;
- Gateway protocol implementation, limits, and public TLS identity;
- private Provider or Guest attachment capability;
- required runtime image/driver and network policy;
- selected audit/recording mode and durable storage; and
- the profile's named component, integration, security, and deployment gates.

The current Provider Contract does not expose complete session close or resize
semantics. Its terminal profile has a bounded connect path but not the Product
session lifecycle described here. Browser has reference controller/Gateway
components but no general production Product resolver and public deployment.
Desktop and the Guest Agent protocols are absent. These are dependencies for
later Contract and implementation phases, not permission for private package
imports, raw endpoints, or in-process fallback.

## Invariants

1. Product control-plane success is committed before a connection grant exists.
2. A public connection grant contains no Provider or backend coordinate.
3. Every Gateway connection is bound to one tenant, actor, Workspace, slot,
   session, generation, and protocol profile.
4. A one-use ticket cannot be replayed, even after partial admission failure.
5. Control-bearing traffic stops when its Product authority is stale or
   unverifiable.
6. Metadata audit cannot be presented as terminal, media, or Agent-trace
   recording.
7. Required recording failure is fail-closed.
8. Guest Agent reachability does not grant Product or Provider authority.

## Consequences

- Product control handlers remain durable and retryable while high-volume
  streams use a separately scalable path.
- Session types can evolve independently behind explicit protocol profiles.
- Some useful APIs may exist before any interactive profile is advertised;
  capability honesty takes precedence over route presence.
- Full session implementation depends on Provider Contract expansion and new
  Guest Agent/Gateway work in later phases.

## Rejected alternatives

### Stream all bytes through Product API handlers

Rejected because it couples durable control transactions to long-lived,
high-volume protocols and obscures independent data-plane limits.

### Return Provider handoffs or private endpoints to clients

Rejected because it bypasses Product identity, control, revocation, recording,
and deployment topology.

### Treat current Gateway audit as content recording

Rejected because it intentionally omits frame content and has a different
privacy, storage, integrity, and replay contract.

### Add a private in-process fast path

Rejected because co-deployment must not change authority or bypass the locked
Product-to-Provider boundary.

## Non-goals

This ADR does not implement a Gateway, Guest Agent, codec, WebRTC stack,
recording pipeline, public listener, or Provider lifecycle route. It does not
claim any target profile is currently available.
