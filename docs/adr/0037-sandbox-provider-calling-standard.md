# ADR 0037: Sandbox Provider Calling Standard and Generic Caller Boundary

- Status: Accepted; supersedes ADR 0001's concrete Agent Platform binding
- Date: 2026-09-07

## Context

ADR 0001 established the durable ownership boundary between this Provider and
its caller, but expressed the caller side in terms of one concrete Agent
Platform, its application package, and its business models. That platform is no
longer an integration target. Its disappearance does not transfer tenant,
authorization, aggregate operation, public Gateway, Artifact, or billing truth
into this service.

ADR 0003 subsequently made the MIT-licensed Provider Contract in this
repository authoritative and removed the unavailable external Contract as a
build and compatibility dependency. The locked OpenAPI, JSON Schemas, semantic
rules, fixtures, and Conformance Suite now define the Provider wire boundary.
They must remain usable by a caller that has no dependency on the former Agent
Platform.

The P3 migration plans assumed that a separately owned Agent Platform would
eventually supply real traffic, authoritative WorkOrder/Run mappings, canary
selection, rollback, drain, and metric comparison. There is no longer a target
against which that migration can be completed. Keeping P3 merely blocked would
misrepresent a retired product dependency as an environment delay.

One protocol-specific dependency also remains in the implementation. Protected
admission currently accepts only the legacy JWS issuer `agent-platform`. The
repository-owned Contract does not yet define a generic caller issuer model,
issuer provisioning, or a compatibility transition from that legacy value.
Changing the constant locally would alter protected wire behavior without the
required Contract, fixture, and conformance review.

## Decision

### Repository-owned calling standard

`sandbox-runtime` owns the Sandbox Provider calling standard. Its normative
resources remain under `contract/` and are locked by
`compatibility/sandbox-runtime/contract.lock.json`. Repository architecture and
ADRs define ownership and release gates, but cannot override the locked wire
resources.

The standard describes a Provider protocol, not a complete end-user product.
It may be consumed by an independently deployed control plane, orchestrator,
embedded product, or a separately versioned compatibility adapter. No caller
needs to adopt the former Agent Platform's source tree or application package.

A generic caller integration must pin the exact Contract identity,
ProviderRevision, capability versions and profiles, runtime profile, and the
deployment evidence on which it relies. Route presence alone does not authorize
a capability. A local component test, reference caller, or candidate harness
does not establish interoperability with a separately owned caller.

### Ownership boundary

The generic caller owns:

- its tenant, user, workload, desired-state, and authorization truth;
- Provider selection and immutable ProviderRevision/profile binding for each
  admitted workload;
- its aggregate operation ledger, idempotency keys, attempts, fencing values,
  retry policy, reconciliation, and final product decisions;
- public terminal and Browser Gateway authentication, authorization,
  revocation, admission, recording, and audit policy; and
- public Artifact publication and metadata, retention, billing, quotas, and
  aggregate usage accounting.

`sandbox-runtime` owns:

- Provider-local sandbox, operation, lease, session, and runtime state;
- backend provisioning, observation, execution, cancellation, cleanup, and
  unknown-outcome evidence;
- opaque internal endpoint and staging references plus bounded retained
  results and usage evidence; and
- fail-closed enforcement of the selected Provider Contract and configured
  runtime capabilities.

Caller-specific business DTOs must be translated at an adapter boundary and
must not become Provider wire or persistence models. The local `/instances`
management API remains separate and is not a substitute for the Provider API.
These generic ownership rules retain the architectural substance of ADR 0001
while superseding its dependency on a specifically named Agent Platform,
`SandboxRegistry`, or Agent Application package.

### Generic caller adapters

A product-specific adapter belongs with the caller or in its own explicitly
versioned integration boundary. It may map caller jobs, runs, workspaces, and
policies into the Provider Contract, but it must not:

- make its private model authoritative over the repository-owned Contract;
- reuse local `instance` or backend driver structs as Provider DTOs;
- infer support for unadvertised capabilities;
- expose backend identifiers, raw endpoints, credentials, or private staging
  references; or
- relabel repository reference evidence as evidence for its deployment.

Adding a reusable SDK or black-box caller is allowed as a future delivery
slice, but it must consume the same locked public Contract and keep caller
policy outside Provider packages.

### P3 retirement and historical evidence

The P3 Agent Platform migration program is retired and superseded by this ADR.
There is no remaining release gate to shadow, canary, roll back, or drain the
former Agent Platform. Any future migration or adoption program must name a
real generic caller, define its separately owned authority, and establish new
acceptance evidence rather than reopening P3 by analogy.

The repository-local `migration` component, commit `4212e88`, hosted candidate
run `33970773345`, and the recorded local candidate runs remain historical
evidence for their exact code, Contract lock, topology, and scenarios. They are
not deleted or reclassified. They continue to prove only the bounded migration
and candidate behavior originally recorded; they do not prove generic caller
interoperability, aggregate conformance, multi-controller reliability,
multi-tenant safety, deployment readiness, or production readiness.

### Generic issuer protocol slice

Generic protected callers remain gated on a coordinated issuer change. A
future protocol slice must, before implementation:

1. define the issuer's authority and canonical identifier without assuming the
   retired Agent Platform;
2. define how a Provider binds an admitted issuer to mTLS identity, audience,
   key identifiers, trust material, and rotation policy;
3. decide whether the legacy `agent-platform` issuer has an explicit bounded
   compatibility window or requires a new protocol/profile version;
4. update the normative Contract resources, fixtures, rejection cases,
   Conformance Suite, compatibility lock, DTOs, and admission implementation
   together; and
5. prove both rejection of issuer substitution and successful admission from a
   separately implemented generic caller.

Until that slice passes, existing protected-admission evidence remains valid
only for its exact locked legacy issuer behavior. Documentation or adapter
configuration must not claim that an arbitrary issuer is already supported.

## Consequences

- The Provider remains independently useful and repository-governed without
  inheriting the retired platform's business responsibilities.
- P3 status becomes retired rather than indefinitely blocked; its historical
  evidence and code remain available without being promoted to a new claim.
- New caller integrations need their own versioned adapter, black-box evidence,
  and deployment gates.
- Generic protected interoperability is not complete until the issuer slice is
  authorized by the Contract and exercised end to end.
- The existing Provider Contract, implementation behavior, capability
  advertisement, and production-readiness gates are unchanged by this ADR.

## Non-goals

This decision does not change Provider routes, schemas, JWS validation,
capability advertisement, runtime composition, or persistence. It does not
implement a replacement platform, SDK, public Gateway, generic issuer,
multi-controller repository, hostile multi-tenant boundary, deployment, or
production readiness.
