# ADR 0012: Artifact Staging and Usage Evidence Boundary

- Status: Accepted for P2.4 Contract authority and provider-local evidence
- Date: 2026-08-25

## Context

The coding profile needs bounded artifact staging and usage observations, but
the calling platform owns artifact metadata, publication, billing, usage
accounting, and final audit truth. The Provider must be able to prove what it
observed without turning a staging reference into a public artifact URL or
inventing prices and tenant authority.

The repository-owned Provider Contract previously had no artifact or usage
resources. Existing usage-shaped fields in unprojected DTOs are not Contract
authority and cannot authorize a route or runtime behavior.

## Decision

The additive Provider v1 Contract defines:

- a protected `POST /v1/sandboxes/{sandbox_id}/artifacts:stage` request carrying
  an opaque platform artifact reference, a stable `/outputs` source path,
  expected digest and media type, a size bound, and bounded evidence expiry;
- a protected `GET /v1/operations/{operation_id}/artifact-staging-evidence`
  document carrying only provider-local staging evidence, digest/media/size
  observations, tenant-binding evidence, active-content evidence, malware
  evidence, and an opaque staging reference;
- a protected `GET /v1/operations/{operation_id}/usage-evidence` document with
  bounded wall-time, CPU, memory, network, storage, workspace, and execution
  count dimensions, explicit meter source and reconciliation status, and
  opaque evidence references.

Artifact staging is accepted only for the `/outputs` stable mount and only
after tenant binding, active-content, and malware checks are represented. The
Provider never emits a public artifact URL, billing total, price, currency,
rate, plaintext credential, host path, or tenant authority. Expiry, operation
binding, idempotency, generation, and fencing remain admission requirements.

This ADR authorizes Contract resources, DTO projection, fixtures, and local
evidence ports. It does not compose HTTP routes, artifact publication,
repository or driver dispatch, distributed usage reconciliation, billing, or
external-caller compatibility.

## Consequences

- P2.4 can implement provider-local staging and usage evidence without
  claiming ownership of platform artifacts or accounting.
- The Contract lock, projection tests, and Conformance Suite must remain
  synchronized before any corresponding runtime adapter is composed.
- Provider-local evidence is component evidence only; aggregate conformance,
  multi-controller reliability, multi-tenant security, deployment, and
  production readiness remain separate gates.
