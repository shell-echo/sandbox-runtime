# P4 Optional Profiles

Status: authority and readiness planning accepted in ADR 0017. No optional
profile is implemented or advertised. This plan does not change the Provider
Contract and does not close P3, aggregate conformance, deployment, or
production gates.

## Objective

Add optional runtime profiles one at a time while preserving the Provider and
Agent Platform ownership boundary. Every profile must have an explicit
Contract, image, runtime, session, usage, security, and independent-caller
evidence chain before it can be advertised.

## Current facts

- The locked Provider Contract currently supports the coding/shell profile and
  terminal-session behavior; the terminal-session semantic rules forbid
  browser, desktop, and port-forward runtime requests.
- The repository has no browser or desktop runtime image, guest endpoint
  protocol, or deployable public Gateway composition.
- `blocks/` can validate an internal digest-pinned Block manifest, but it does
  not authorize a Provider capability or establish image provenance.
- A real Agent Platform caller and migration traffic harness remain unavailable;
  the co-located candidate harness is evidence only within its named boundary.

## Profile order and gates

| Order | Profile | First slice | Required gates before advertisement |
| --- | --- | --- | --- |
| 1 | Browser | Contract and authority audit; image/provenance fixture design | Browser route/session authority, image and guest tests, Gateway policy, usage/artifact evidence, security/concurrency matrix, independent caller |
| 2 | Desktop | Contract and authority audit; display/input/session boundary design | Desktop protocol and image, display/input security, Gateway/reconnect, usage, fault and caller evidence |
| 3 | Workspace snapshot/restore | Digest and compatibility audit | Secret exclusion, digest verification, new sandbox identity, restore fault/recovery, Contract and caller evidence |
| 4 | Port-forward | Target and egress authority audit | Explicit target allowlist, network isolation, expiry/revocation, cross-tenant and caller evidence |
| 5 | GPU | Device and scheduler authority audit | Device isolation, scheduling, image/driver matrix, accounting, hostile security and deployment evidence |
| 6 | Nested-container / stronger isolation | Host boundary and deployment audit | Privilege, namespace, daemon, kernel, multi-controller, deployment, and production gates |

## Browser first slice

The browser first slice is documentation and fixture design only:

- inventory the repository-owned Contract resources and identify missing
  browser capability, session, endpoint, usage, and artifact semantics;
- define the browser profile readiness record without inventing wire IDs;
- list the image build inputs, architecture matrix, digest publication,
  provenance attestations, user identity, mounts, limits, and network policy;
- identify the caller-owned authorization, revocation, audit, and reconnect
  interfaces needed for a browser data plane; and
- define rejection, restart, expiry, cross-tenant, egress, secret, and
  resource-boundary cases before implementation.

No browser route, `sandbox.browser` advertisement, runtime image, or public
endpoint is part of this first slice.

## Acceptance evidence

- ADR 0017 and this plan are indexed from the project context and plan index;
- the profile matrix distinguishes Contract, component, caller, migration,
  multi-controller, tenancy, deployment, and production gates;
- the browser first slice has no Provider code or Contract lock changes; and
- `git diff --check` passes.

## Next work

After this authority slice, implement browser Contract resources only if the
missing semantics are approved and can be locked with fixtures and Suite cases.
Then build and verify a real digest-pinned browser image and provider-local
runtime/session components. Do not enable advertisement until the complete
profile dependency graph and an independent caller run pass.
