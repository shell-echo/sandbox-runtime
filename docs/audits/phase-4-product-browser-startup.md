# Product v1 Phase 4 Browser Startup Audit

Date: 2026-09-18

Baseline: `e9bdc77478f4df15b53f6b7e3fa3fbdda9d76d4f`

Branch: `codex/product-v1-phase-4-browser-slice-1`

## Conclusion

Product Phase 4 starts from a clean merge of the completed Product Phase 3
baseline. Browser is not Product-ready at that baseline. The repository has a
locked Provider Browser protocol, Provider-local Browser runtime components,
and several historical reference evidence tracks, but no composed Product
Browser authority, Provider adapter, public visual data plane, recovery path,
or Product-integrated release evidence.

The old Provider delivery label "P4 Browser" and the new Product v1 Phase 4
are different scopes. Historical Provider or reference-caller results remain
valid only for their recorded revisions, topologies, profiles, and scenarios.
They are not renamed, aggregated, or treated as Product evidence.

## Verified entry state

- `HEAD`, local `main`, and `origin/main` were all
  `e9bdc77478f4df15b53f6b7e3fa3fbdda9d76d4f` before the branch was created.
- The worktree was clean.
- The Provider Contract verifier, Product Contract verifier, and retained
  Product Phase 3 evidence verifier passed at the baseline.
- Product Phase 3 remains complete for its bounded four-process, fresh
  PostgreSQL, same-repository standalone topology. That result is not a
  Browser result or a production/deployment claim.

## Authority and evidence inventory

| Layer | Fact at the baseline | Evidence level | Product Phase 4 consequence |
| --- | --- | --- | --- |
| Product Contract/design | The Product Contract already names `browser_automation`, `browser_live`, `product-browser-automation.v1`, and `product-browser-live.v1`. ADRs 0042-0047 assign durable session, control, grant, Gateway, recording, and catalog authority to Product. | Locked design/Contract authority | Resource names authorize implementation work; they do not advertise readiness. |
| Provider Contract | The locked Provider Contract exposes Browser sandbox creation, asynchronous Browser session open, retained operation read, and an opaque Browser handoff. It does not expose Product users, grants, viewing policy, or a complete Product Browser close/visual protocol. | Locked Provider wire authority | Product must use the network Contract through `product/adapter/provider`; missing semantics require a coordinated Contract slice or a fail-closed Product workflow. |
| Provider Browser components | Signed image, Docker runtime, provenance verification, restricted egress, protected Browser routes, opaque references, usage, and recovery components exist under Provider ownership. | Unit, component, real-adapter, and recorded reference evidence depending on component | These are eligible Provider dependencies only after exact readiness selection. Product cannot import their implementations or expose their private coordinates. |
| Historical Browser Gateway/reference tracks | Caller-owned reference Gateway, edge limits, capacity, revocation, downstream action fencing, history witnesses, and controlled-restore harnesses exist. | Historical fixed-topology reference/same-runner evidence; some real Browser/Valkey/PostgreSQL components | Product composition may reuse neutral reviewed ports, but it may not import historical Provider/reference composition or relabel those runs as Product results. |
| Product Phase 3 | Product owns authenticated Workspace/session APIs, PostgreSQL, control leases, one-use grants, Terminal Gateway, recording/catalog primitives, secure Web, and dependency-derived capability output. | Bounded Product component plus same-repository standalone evidence | Phase 4 extends these Product authorities. Terminal grants, Browser action fences, and Product control leases remain distinct. |
| Product Browser implementation | Generic session schemas mention Browser kinds, but application creation is Terminal-only, the Provider adapter is Terminal-only, Product has no browser-slot workflow, public Browser Gateway, live visual transport, Browser recording composition, or Browser Web UI. | Missing | Browser capability must remain unadvertised until the complete graph and the Phase 4 gate pass. |

## Material gaps and risks

1. A Browser session requires a separately reconciled `browser` Workspace
   slot. Reusing `primary-code` would violate ADR 0044 and select the wrong
   runtime/network profile.
2. The current Provider Browser wire surface supplies CDP-style automation
   handoff, not the Product `browser_live` media/input protocol. Live viewing
   needs an explicit visual transport and a fresh security/evidence gate.
3. The Provider Contract has no general Browser close mutation. Product close
   intent therefore cannot be declared complete from a local socket close; a
   coordinated cleanup/expiry/slot-lifecycle decision is required.
4. Product control lease, Gateway capacity lease, Provider mutation fence,
   Browser connection generation, and downstream action fence protect
   different resources. Substituting any one for another creates stale-owner
   and replay failures.
5. Browser viewing and Browser control differ. The first version permits one
   controller, while authorized viewers must never acquire mutation authority.
   Multi-human collaboration, handoff queues, presence, and simultaneous
   control remain deferred.
6. Clipboard, upload, download, navigation/egress, permissions, frame size,
   resolution, encoding, queues, bitrate, reconnect, and recording failure all
   need explicit bounded policies. Browser defaults must deny or fail closed.
7. Metadata audit is not media or control-event recording. Browser recordings
   need immutable encrypted segments, integrity linkage, catalog finalization,
   retention, authorization, and failure semantics.

## Slice 1 decision

The earliest safe implementation dependency is Product Browser session
authority, not Provider or Gateway composition. Slice 1 therefore:

- admits only exact Browser kind/profile pairs through the existing strict,
  authenticated Product session route;
- requires a ready Product slot of kind `browser` with the exact
  `sandbox.browser@1.0.0` / `browser-v1` requirement;
- commits session, operation, event, idempotency, audit, and a Browser-specific
  outbox record in Product PostgreSQL before external work;
- defines an absorbing Product session state machine and prevents Terminal
  workers from consuming Browser work; and
- keeps Browser capability advertisement empty because browser-slot creation,
  Provider dispatch, public data plane, recovery, recording, and release gates
  are still missing.

This is Product component and real-PostgreSQL authority evidence only. It is
not a working Browser, Provider interoperability result, public Gateway,
deployment, hostile-multitenant, HA, or production evidence.
