# ADR 0026: Browser Reference Caller E2E

- Status: Accepted for the P4 Browser external-caller evidence slice
- Date: 2026-09-04

## Context

ADR 0025 composes the default-disabled Browser Provider graph but deliberately
keeps the public Browser Gateway and user authorization outside Provider
ownership. Component tests and the locked Contract Suite cannot establish that
an independent caller can use the complete mTLS/JWS, HTTPS, opaque-handoff,
WebSocket, restricted-egress, recovery, and usage path.

The existing `e2e/` module is an independently runnable process boundary inside
this repository. A separate repository is not required for the evidence, but
the Browser caller must remain unable to import Provider implementation code
and a clean committed harness revision must identify every run.

## Decision

Add an explicit Browser profile to the E2E module with separate
`browser-caller`, `browser-e2e`, and Browser-only reference-stack processes.
The black-box caller uses only the locked wire documents it implements, mTLS,
JWS, HTTPS, and WebSocket. Only the reference stack may import exported
Provider and Gateway composition packages.

The Browser reference stack supplies explicit ephemeral caller-owned Gateway
policy, PKI, JWS keys, and two distinct caller/tenant identities. It composes
the exact signed Browser publication, the pinned GitHub CLI provenance
verifier, a locally built immutable restricted-egress Gateway image, one
operator-owned uplink, durable single-controller stores, protected Provider
routes, and the caller-owned Browser Gateway. This Browser-only reference
deployment advertises the exact Contract-authorized `sandbox.browser@1.0.0` /
`browser-v1` shape and binds its runtime profile to the current Docker
architecture. The production command remains default-disabled and unchanged.

An evidence run uses initial and reconstructed processes over the same durable
state. It covers protected lifecycle create, Browser session allocation,
opaque handoff, CDP version exchange, allowed and denied egress, missing-token
and cross-tenant denial, grant expiry, active revocation, partial and complete
duration evidence, mTLS/JWS caller binding rejection, process reconstruction,
handoff reconnect, expiry cleanup, and absence of managed Browser resources.
The manifest pins the clean harness and Provider commits, Contract revision and
tree, Suite count, signed runtime image, platform, configuration digests,
reports, commands, and evidence boundary. Secrets and runtime state remain in
ignored ephemeral directories and are not included in evidence.

Add a separately named hosted workflow. It authenticates to GHCR, provides the
short-lived GitHub token required by the real provenance verifier, reruns the
harness race/vet checks, executes the Browser runner, and uploads only the
sanitized evidence directory.

## Release Boundary

The local result is Browser reference external-caller evidence only after the
harness is committed, the checkout is clean, `browser-e2e -check` passes, and
the complete Docker run emits a valid manifest. Hosted evidence is recorded
separately only after its workflow and uploaded artifact pass.

The gate does not enable Browser advertisement in the production command and
does not establish aggregate conformance, real Agent Platform compatibility,
multi-controller reliability, hostile multi-tenant isolation, deployment
readiness, or production readiness. The reference-only advertisement is
required because the Contract forbids creating an unadvertised Browser profile.
The two test identities exercise bounded authorization failures; they are not a
claim of hostile multi-tenant isolation.

## Consequences

- Browser behavior is tested through an independent caller and real process,
  TLS, WebSocket, Docker, registry, provenance, and network boundaries.
- Coding/shell Reference and Platform Candidate evidence remain separate and
  are not relabeled as Browser results.
- Advertisement remains a later decision gated by this evidence plus any
  remaining security, concurrency, deployment, and operational requirements.
