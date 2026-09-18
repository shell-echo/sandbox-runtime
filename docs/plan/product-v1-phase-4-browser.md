# Product v1 Phase 4: Browser

Status: In progress; Slice 1 implemented locally, 12 slices remain

Started: 2026-09-18

Baseline: `e9bdc77478f4df15b53f6b7e3fa3fbdda9d76d4f`

## Objective

Deliver the Product Browser capability defined by ADRs 0042-0047 and 0049:
durable Browser slot/session authority, exact Provider adaptation, automation
and remote visual control data planes, one-controller fencing, safe recovery,
policy-bounded content transfer and permissions, recording/catalog
composition, Web experience, cleanup, and an independent-process release gate.

The historical Provider "P4 Browser" track is an input, not completion
evidence for this phase. Product capability advertisement remains unavailable
until Slice 13 passes for the exact composed topology.

## Fixed slice order

| Slice | Deliverable | Required acceptance gate | Status |
| --- | --- | --- | --- |
| 1 | Startup audit; Product Browser session kind/profile authority; ready-browser-slot binding; absorbing state machine; Browser-specific outbox isolation; PostgreSQL migration constraint; strict authenticated API projection | Focused race tests; strict input/profile rejection; tenant/actor nondisclosure; idempotency; migration replay; real PostgreSQL transaction/outbox isolation; full race/shuffle, vet, and Contract verifiers | **Implemented; local and real-PostgreSQL gates passed** |
| 2 | Auxiliary Browser slot create/read/update authority and reconciliation intent | Expected-version/idempotency/quota races; immutable key/kind; exact capability request; event/outbox atomicity; cross-tenant nondisclosure; restart-safe reads | Not started |
| 3 | Exact-revision Provider Browser readiness and network-only adapter for Browser sandbox plus session open/handoff observation | Locked capability/profile selection; mTLS/JWS; no private coordinate projection; timeout, cancellation, replay, stale generation, ambiguous outcome, and capability-drift tests | Not started |
| 4 | Browser lifecycle reconciliation, disconnect/expiry/close cleanup, unknown-outcome recovery, slot replacement, and retained evidence | Restart at every commit/dispatch/observe boundary; no duplicate current binding; no session resurrection; exact-owned cleanup; coordinated Contract decision for missing Provider close semantics | Not started |
| 5 | Viewer/control authorization, single-controller Product lease/fence binding, one-use grants, revocation, and Browser quotas; multi-human collaboration remains deferred | Viewer cannot mutate; one live controller; stale fence/replay/revocation/expiry/limit races; database-time authority; nondisclosing errors | Not started |
| 6 | Public Browser automation WSS data plane with closed action/result messages and downstream action fencing | Separate-process edge/Gateway/Provider test; bounded messages/queues; ordered actions; stale-owner suspension; reconnect; no raw CDP or endpoint exposure | Not started |
| 7 | Public Browser live viewing/control data plane with authenticated signaling, bounded media/input channels, resolution/encoding negotiation, bitrate, and backpressure | Origin/TLS/authentication; unsupported codec/size rejection; slow-consumer closure; control fence per input; view-only admission; no unauthenticated upgrade | Not started |
| 8 | Explicit keyboard/pointer/touch, clipboard, upload, download, navigation, popup, and permission policy | Deny-by-default matrix; size/type/count/digest bounds; activation/consent; filename/path confinement; cross-origin and policy-change revocation tests | Not started |
| 9 | Browser network and runtime isolation composition | Exact restricted-egress policy; DNS/IP/metadata/private-network denial; immutable verified image; permission/device denial; resource bounds; cleanup and fault injection | Not started |
| 10 | Connection loss, Gateway/Provider restart, reconnect, visual resynchronization, resolution changes, and recovery UX | Fresh-grant reconnect; authority recheck; keyframe/resync bounds; no stale input; retained session recovery; dependency-loss fail-closed behavior | Not started |
| 11 | Browser metadata audit, media/control-event recording, Product catalog, retention/deletion, integrity, and quota composition | Consent and visible mode; required-recorder fail closed; encrypted chained segments; authorized replay; content excluded from logs/control-plane lists; quota races | Not started |
| 12 | Product Web Browser experience for slot/session lifecycle, live view, controller state, recovery, downloads/uploads, and recording catalog | Generated/checked client; authenticated browser E2E; CSP/CSRF/origin/accessibility; viewer/control UX; error/reconnect/cleanup cases; no private coordinates | Not started |
| 13 | Product Phase 4 independent-process release gate and reproducible evidence bundle | Fresh PostgreSQL and required coordination/object storage; separate Product/Gateway/Provider/Browser roles; exact locked identities; restart/fault/security/backpressure/recording/cleanup matrix; strict independent validation | Not started |

Slices are dependency ordered. A later data-plane demo cannot replace Product
authority, exact Provider selection, recovery, policy, or cleanup gates.

## Slice 1 exact boundary

Slice 1 uses the Product Contract's existing generic session route and Browser
kind/profile names. It does not change or advertise the Contract. Browser work
is committed as `browser_session.open` or `browser_session.close`, which the
Terminal dispatcher cannot lease. The session remains `requested` or
`draining` until later Browser-specific workers reconcile retained external
evidence.

The Product Provider adapter still authorizes only Terminal in this slice, no
public Browser grant is issued by a complete readiness graph, and a fresh
Workspace still lacks an implemented auxiliary Browser-slot mutation. These
are deliberate fail-closed boundaries, not implied functionality.

### Slice 1 local evidence

Focused Product, Product API, and PostgreSQL adapter race/shuffle tests pass.
The full repository race/shuffle suite, `go vet ./...`, Provider Contract
verifier, Product Contract verifier, retained Phase 3 evidence verifier, and
`git diff --check` pass. The existing tagged four-process Phase 3 gate also
passes as a regression check; it is not counted as Browser evidence. A
disposable `postgres:16-alpine` container pinned to
`sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
passes the complete tagged Product PostgreSQL integration package, including
migration apply/replay, exact Browser kind/profile persistence, idempotent
replay and conflict, tenant/actor nondisclosure, Terminal-worker isolation,
close intent, and the database profile constraint. The exact container is
removed after the run.

This is local component and real-adapter evidence. No Browser runtime or
public data-plane integration was applicable to Slice 1, and no frontend was
changed. Docker Browser-driver and frontend build results are therefore not
claimed.

## Evidence rules

Every slice records the lowest evidence tier it actually passed: unit,
Contract projection, real adapter, same-repository separate process,
independently implemented caller, deployment, multi-controller, hostile
multi-tenant, HA, or production. Historical Provider Browser evidence is cited
only as historical Provider/reference evidence.

Phase completion requires Slice 13. It will still not imply production, HA,
hostile-multitenant isolation, or multi-human collaboration without their
separate named gates.
