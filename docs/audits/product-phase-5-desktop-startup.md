# Product v1 Phase 5 Desktop Startup Audit

Date: 2026-09-19

Baseline: `e3c839fbb6a040a2b31a36ec05212924a69237fe`

Branch: `codex/product-v1-phase-5-desktop-slice-1`

## Conclusion

Product Phase 5 starts from the clean completed Product Phase 4 baseline.
Desktop is not Product-ready at that baseline. The Product Contract and design
ADRs reserve Desktop slot and session names, but the locked Provider Contract
did not authorize a Desktop capability, runtime profile, session lifecycle,
handoff, or usage-evidence shape. The repository also had no Product Desktop
authority, Provider Desktop application, runtime image, runtime adapter,
display/input broker, public data plane, recovery path, recording composition,
or unified Product Desktop experience.

The dependency order is therefore Contract-first. Product persistence or a
runtime implementation before Provider authority would invent wire behavior
and make later compatibility evidence ambiguous. Slice 1 authorizes only the
Provider Desktop wire contract and its Go projection; it does not compose or
advertise a working Desktop.

## Verified entry state

- `HEAD`, local `main`, and `origin/main` were all
  `e3c839fbb6a040a2b31a36ec05212924a69237fe` before work started.
- The worktree was clean and the Phase 5 branch was created from that exact
  baseline.
- Product Phase 3 remains complete only for its recorded Workspace, Terminal,
  Files, catalog, recording, and same-repository four-process scope.
- Product Phase 4 remains complete only for its recorded Browser authority,
  automation/live paths, policy, recording, Web experience, and
  same-repository four-process scope.
- The Product Web package is an embedded Product-facing shell/BFF component.
  The normal command path does not yet compose the Product API and Web shell
  as a deployable listener; the retained Phase 3 and Phase 4 gates construct
  their exact test topologies explicitly.
- The pre-Phase-5 Provider lock selected revision
  `98995384c60a924f25ca58d3b7e561207bfa5be8`, tree
  `0a627baed11c8a6ddbe8a24bbc1869e4f85edc16`, and a 60-case local Suite.
  Those identities remain historical evidence and are not relabeled by this
  phase.

## Authority and implementation inventory

| Layer | Fact at the baseline | Consequence for Phase 5 |
| --- | --- | --- |
| Product design and Contract | Slot kind `desktop`, session kind `desktop`, and public profile `product-desktop.v1` are reserved. Product owns users, tenants, Workspaces, grants, controller leases, policy, audit, catalog, recording, and public Gateway authority. | The names permit a later Product implementation but do not establish Provider compatibility or capability readiness. |
| Provider Contract | Desktop was absent from the locked capability, runtime-profile, session, handoff, usage, admission, fixture, and Conformance authority. | Slice 1 must establish a complete separate Desktop wire authority before Product or runtime work. |
| Product Phase 3 | Durable Product kernel, primary-code Terminal/Files, recording catalog primitives, and a Web shell exist within a bounded standalone gate. | Reuse Product-owned neutral ports where their semantics match; do not reuse Terminal routes, DTOs, byte streams, or evidence as Desktop. |
| Product Phase 4 | Separate Browser slots/sessions, automation/live control, policy, recovery, recording, and Web tab exist within a bounded release topology. | Browser decisions are useful design inputs, but Browser routes, DTOs, runtime, and evidence do not authorize Desktop behavior. |
| Provider Desktop implementation | No Desktop domain/application/repository package, runtime image, driver, private resolver, broker, protected route composition, or readiness graph existed. | Provider advertisement must remain empty until later slices compose and verify every required dependency. |
| Product Desktop implementation | No Desktop slot/session workflow, Provider adapter, public display/input plane, policy, recovery, recording, or Web experience existed. | Product cannot advertise `product-desktop.v1` until the fixed Phase 5 release gate passes. |

## Material gaps and risks

1. Desktop must have a separate Provider capability/profile/runtime tuple.
   Combining it with Terminal or Browser would silently inherit the wrong
   transport, policy, and lifecycle semantics.
2. A Desktop session is not just a media connection. Open, read, handoff,
   close, expiry, revocation, generation fencing, cleanup, and usage evidence
   need one durable authority and explicit outcome-unknown handling.
3. Provider controller identity is not end-user authorization. Product must
   own tenant/user grants, one-controller leasing, reconnect policy, policy
   decisions, audit, quota, and public admission.
4. Public signaling and private Provider resolution are separate trust
   boundaries. Provider handoffs must remain opaque and must not disclose
   addresses, ports, credentials, candidates, or session descriptions.
5. Video and optional audio output do not authorize microphone, camera, host
   device, clipboard, input, or file access. Missing Product policy denies
   those actions.
6. Session expiry and explicit close must share the same revoke-first cleanup
   path. Success before exact absence confirmation would leave reconnectable
   or metered resources behind.
7. Product and Provider generation fences, Product controller leases, public
   Gateway capacity, and private input authority guard different resources.
   None can substitute for another.
8. A development environment needs an immutable runtime image, broker
   protocol, workspace materialization, startup health, and toolchain policy.
   Merely rendering pixels is not a development-environment result.
9. The final Product experience must compose Workspace, Terminal, Files,
   Browser, Desktop, and recordings without exposing private Provider
   coordinates or claiming a deployment topology that does not exist.

## Slice 1 result and boundary

Slice 1 establishes the repository-owned Provider Desktop Contract authority:

- exact `sandbox.desktop@1.0.0` / `desktop-v1` capability and
  `sandbox-runtime-desktop-v1` runtime-profile mapping, with optional separately
  governed lifecycle control;
- Desktop-only sandbox creation and separate asynchronous open/close routes;
- retained operation read, opaque Desktop handoff read, expiry/revocation,
  generation fencing, exact cleanup, and duration usage evidence;
- strict identity, deadline, idempotency, request-digest, replay, error,
  capacity, security, and nondisclosure semantics;
- OpenAPI, schemas, semantic rules, fixtures, manifest, and an executable
  71-case local Conformance Suite;
- Go DTOs, strict bounded decoders, admission bindings, capability projection,
  and executable Suite mappings; and
- a dedicated immutable historical lock for the completed coding/shell
  qualification Profile, so its 60-case identity remains verifiable without
  being rewritten to the new authority; and
- a derived compatibility lock selecting exact Contract revision
  `720ad15c343e71f36615dc4499edd5e764178bca` and tree
  `343ffde0819207cf99c005096c336735dd33a735`.

This result is Contract and projection evidence only. It adds no Provider
Desktop runtime, image, driver, protected route composition, Product Desktop
authority, Guest protocol, public Gateway, Web experience, independent caller,
deployment, multi-controller, hostile-multitenant, HA, or production-readiness
claim. Desktop capability advertisement remains empty by default.

Slice 2 subsequently implements the Product Desktop intent and PostgreSQL
authority described in
[`product-phase-5-desktop-slice-2.md`](product-phase-5-desktop-slice-2.md).
That later result does not alter this startup baseline or the Slice 1 Contract
identity.
