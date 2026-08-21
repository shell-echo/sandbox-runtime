# ADR 0009: Coding and Remote-Shell Ownership Boundary

- Status: Accepted for P2.0a authority inventory
- Date: 2026-08-21

## Context

The architecture Phase 2 describes bounded exec, cancellation, retained
results, usage evidence, terminal sessions, and artifact staging. The current
repository-owned Provider Contract does not define those wire resources. The
existing admission vocabulary is not sufficient authority to implement HTTP
routes or runtime dispatch.

## Decision

The P2 coding/remote-shell profile is split into separately gated Contract and
runtime slices. A future additive Provider v1 Contract revision must define the
request, result, session, usage, and artifact-staging documents before any
corresponding runtime code is exposed.

Ownership is divided as follows:

- The calling platform owns user and tenant authorization, workload policy,
  ProviderRevision binding, aggregate operation truth, artifact publication,
  usage accounting, and public session authorization.
- `sandbox-runtime` owns provider-local execution progress, bounded retained
  results, cancellation evidence, runtime observations, and staging evidence.
- The Runtime Gateway owns public terminal/session authorization, proxying,
  reconnect policy, and recording metadata. Provider responses may contain only
  opaque internal endpoint references with bounded expiry.
- Secret grants and environment references are platform-issued, short-lived,
  least-privilege inputs. Provider wire documents and logs must not contain
  plaintext secret values or credentials.

The future exec request must be represented as bounded structured data, not an
arbitrary shell command string. Its Contract and semantic rules must cover
argv, working directory, environment-reference policy, stdin mode, deadline,
output bounds, cancellation intent, result retention, and unknown outcomes.
The future session Contract must cover opaque references, expiry, capability
profile, and gateway handoff. Artifact staging remains evidence only; the
provider never becomes the artifact authority.

Before P2.1 runtime implementation, P2.0 must add additive OpenAPI/JSON
Schemas, semantic rules, valid/rejection fixtures, executable Conformance Suite
cases, a lock update, projection tests, and an implementation ADR. No
exec/session/snapshot/artifact route or driver dispatch is authorized by this
ADR.

## Consequences

- P2.0 can proceed as Contract and authority work without creating an
  implementation-shaped compatibility claim.
- Provider DTOs remain separate from `instance`, Docker, and gateway models.
- External-caller compatibility, cross-tenant safety, deployment readiness, and
  production readiness remain unproven until their named gates pass.
