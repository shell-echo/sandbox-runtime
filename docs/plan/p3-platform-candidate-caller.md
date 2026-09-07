# P3 Platform Candidate Caller

Status: **Retired / Superseded by ADR 0037.** Local and hosted candidate
integration completed and its evidence is retained at the original boundary.
This historical slice added a runnable Agent Platform candidate caller and
process-level harness inside the independently versioned `e2e/` module. It
consumed the Provider only through the Contract wire surface and recorded
candidate integration evidence; it did not establish compatibility with a
separately owned production application and is not generic caller evidence.

## Scope

- model the platform-owned run binding, ProviderRevision selection, and
  new-run-only canary/rollback/drain policy in the candidate process;
- shadow-check the live Provider capability document and a candidate create
  request before dispatch;
- invoke the existing black-box Provider caller from a separate
  `platform-caller` process over mTLS/JWS HTTPS and WebSocket;
- persist a bounded candidate run record across the orchestrator's restart and
  resume phases; and
- emit candidate-owned lifecycle/exec/session/resource/reconciliation counters
  without importing Provider implementation packages.

## Non-goals

This slice does not modify the Provider Contract or Provider runtime, add
platform production services, define Veronica's accepted Application model,
replace platform WorkOrder/Run or usage/artifact/Gateway authorities, prove
aggregate conformance, prove multi-controller or hostile multi-tenant safety,
or establish deployment or production readiness. The reference stack remains a
test deployment, and a passing candidate run is not production evidence.

## Acceptance evidence

- candidate caller and Provider stack run as separate processes over real
  loopback TLS/WebSocket connections;
- capability and request shadow checks happen before the Provider caller run;
- existing run bindings remain unchanged through canary rollback, while only
  new bindings use the rolled-back stable revision;
- the candidate state survives the orchestrator's Provider restart/resume
  phase and rejects identity drift;
- caller code imports no Provider implementation package; and
- the e2e module's race/shuffle, vet, boundary, and Docker candidate run pass.

The evidence boundary remains `Agent Platform candidate integration only`.
It did not close the real-platform P3 gate before that program was retired, and
it must not be relabeled as generic caller, aggregate conformance, deployment,
or production evidence. Any future caller integration starts under ADR 0037
with a new plan, evidence identity, and the coordinated generic issuer protocol
slice required for protected admission.
