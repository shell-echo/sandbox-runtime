# ADR 0049: Product Browser Phase 4 Boundary

- Status: Accepted for Product Phase 4 scope; only Slice 1 is implemented
- Date: 2026-09-18

## Context

The repository contains two easily confused bodies of Browser work. The older
Provider optional-profile track owns Browser sandbox execution, protected
Provider routes, opaque handoffs, and several fixed reference Gateway evidence
topologies. Product v1 owns end-user identity, Workspace/slot/session truth,
public grants, control leases, recording policy, catalogs, Web experience, and
capability advertisement. Product Phase 3 did not compose those Browser
responsibilities.

Treating historical Provider/reference Browser evidence as Product readiness
would bypass Product authorization, persistence, public data-plane policy,
recording, recovery, and release gates. Reusing the Terminal path would also
confuse PTY bytes with Browser automation, media, and input semantics.

## Decision

Product Phase 4 follows the fixed plan in
`docs/plan/product-v1-phase-4-browser.md`. Product Browser sessions are durable
Product resources bound to a separate `browser` Workspace slot. Product
application code uses Product ports; only `product/adapter/provider` consumes
the locked Provider Browser wire DTOs over the protected network boundary.
There is no in-process Provider or historical reference-composition shortcut.

The two Product profiles remain distinct:

- `product-browser-automation.v1` carries closed, bounded action/result
  messages over the public Product Gateway; raw CDP is private.
- `product-browser-live.v1` carries authenticated visual media plus bounded
  input control. Viewing does not imply input authority.

One Product session may have authorized viewers but at most one live
controller. Mutating input requires the current Product control lease and
fence plus the profile-specific downstream action fence. Multi-human
collaboration, control queues, shared cursors, presence, and simultaneous
controllers are deferred.

Clipboard, upload, download, navigation, popup, device permission, egress,
resolution, codec, frame rate, bitrate, queues, reconnect, and recording are
explicit bounded policies. Missing policy denies the action. Required
recording failure rejects or terminates the affected connection; metadata
audit never substitutes for media/control-event content recording.

Browser capability readiness is the conjunction of Product session/control
authority, Browser slot and exact Provider readiness, public Gateway and TLS,
grant/revocation/capacity/fencing, network/runtime isolation, the selected
recording mode, storage, recovery, cleanup, and the named release gate. A
route, schema enum, historical Provider run, or component test cannot advertise
the capability by itself.

## Slice 1 authority

The first slice adds the earliest safe Product authority only. Exact Browser
kind/profile pairs can be accepted through the already authenticated, strict
Product session route only when a ready Product `browser` slot declares
`sandbox.browser@1.0.0` with `browser-v1`. Product PostgreSQL commits the
session, operation, event, audit, idempotency result, and a Browser-specific
outbox message before external work. Terminal workers cannot lease that work.
Closed, expired, and failed sessions are absorbing.

No Product Browser capability is advertised by this decision or Slice 1.

## Consequences

- Existing Provider/reference Browser components remain separate dependencies
  and evidence tracks.
- Browser Provider adaptation, public data planes, recovery, policy, Web, and
  recording are implemented and gated incrementally.
- The missing Provider Browser close semantics require an explicit Contract or
  lifecycle decision; Product cannot infer cleanup from a disconnected client.
- Phase 4 completion requires the independent-process Slice 13 gate and still
  does not establish production, HA, hostile-multitenant, or collaboration
  readiness.
