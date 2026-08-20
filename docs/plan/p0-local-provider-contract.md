# P0 Local Provider Contract Migration

Status: merged through PR #17 as `43ff3d755811545c0d3a1f1799e55afa97402587`;
post-merge CI run `32360376058` passed all required jobs. The follow-up P0.4
revalidation is in progress on `codex/p1.1-local-admission-contract@f9297c4`.

The former external Agent Platform Contract is no longer an authority or a
runtime dependency. This plan establishes the repository-owned MIT Contract
before any P1.1 compatibility claim is reused.

## Locked Ownership

- namespace: `urn:shell-echo:sandbox-runtime:provider-v1`;
- version: `1.0.0`;
- license: MIT;
- resources: `contract/openapi`, `contract/schemas`,
  `contract/semantic-rules`, `contract/fixtures`, and
  `contract/conformance`;
- lock: `compatibility/sandbox-runtime/contract.lock.json`.

The Contract currently defines the discovery surface `GET /v1/capabilities`.
Its OpenAPI explicitly authorizes `200`, `400`, `401`, `403`, `500`, `501`, and
`503` responses. The semantic rules require verified mTLS identity, reject
request metadata and mutation dispatch, and keep capability/runtime-profile
arrays empty until a later reviewed protocol change.

## Slice Order

1. P0.0: land the Contract resources and bind their Git tree/digests. Passed
   in `c0efc67` and `fb83eb5`.
2. P0.1: replace the external lock verifier with local tree, digest, manifest,
   semantic-rule, fixture, and Suite checks. Merged in PR #17.
3. P0.2: migrate projection tests, DTO fixtures, and CI to the local Contract.
   Merged in PR #17.
4. P0.3: update architecture, development standards, ADRs, README, plans, and
   status ledger. Merged in PR #17.
5. P0.4: rerun P1.1a-b-c/d evidence under the local Contract. The current
   branch has passed local verification; PR and post-merge evidence remain
   required. Do not advance P1.2 until the P1.1 release gate closes.

## Evidence and Boundaries

The lock verifier proves identity and resource integrity only. Projection tests
prove selected schemas and fixtures. The local Conformance Suite remains
unexecuted until a runner is implemented or adopted. No external-caller E2E,
aggregate lifecycle conformance, multi-controller reliability, multi-tenant
security, deployment readiness, or production readiness is implied.

## Rollback

Rollback removes the local Contract migration commits and restores the previous
implementation only as historical code. It must not restore a claim of current
external compatibility or reintroduce a proprietary Contract checkout without
a new explicit ownership decision.
