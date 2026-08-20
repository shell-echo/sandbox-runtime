# ADR 0003: Repository-Owned Provider Contract

- Status: Accepted
- Date: 2026-08-20

## Context

The former external Agent Platform Contract is unavailable and must not remain
an authority or build dependency. The repository still needs a stable wire
Contract for Provider DTOs, capability discovery, protected admission, and
future lifecycle work. Copying a proprietary upstream Contract into this MIT
repository is not acceptable.

## Decision

`sandbox-runtime` owns an MIT-licensed Provider Contract with namespace
`urn:shell-echo:sandbox-runtime:provider-v1` and version `1.0.0`. Its normative
resources live under `contract/`:

- OpenAPI;
- JSON Schemas;
- semantic rules;
- fixtures; and
- a versioned Conformance Suite.

`compatibility/sandbox-runtime/contract.lock.json` binds the Contract tree,
manifest, OpenAPI digest, semantic rules, fixtures, and Suite identity to an
immutable repository revision. The verifier reads only this repository. CI
must run the local lock and projection gates without an external checkout or
secret credential.

The initial Contract covers `GET /v1/capabilities` and explicitly defines its
request metadata and `400`/`501` transport outcomes. Mutation and lifecycle
operations remain reserved for later additive Contract revisions and are not
advertised by the current capability document.

## Consequences

- Historical Agent Platform compatibility evidence is not evidence for this
  Contract and must be re-run.
- A future external integration requires a separately owned adapter and
  compatibility Contract; it cannot silently become this Contract's authority.
- Contract changes require coordinated updates to schemas, semantic rules,
  fixtures, tests, plans, and the lock.
- P1.2 lifecycle work remains prohibited until the local P1.1 release gate is
  closed.
