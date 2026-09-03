# ADR 0023: Browser Protected Provider Transport

- Status: Accepted for the P4 Browser protected-transport component
- Date: 2026-09-03

## Context

The locked Provider Contract authorizes separate Browser session open and
handoff routes. The Provider-local Browser application already owns durable
session coordination, operation state, opaque references, usage evidence, and
the fail-closed runtime dependency graph described by ADRs 0020-0022. Until
this decision, the protected router deliberately returned an empty `404` for
both Browser routes.

The Browser data-plane boundary is not the Provider HTTP endpoint. The caller
owns user and tenant authorization, revocation, audit, reconnect policy, and
the public Gateway. The Provider may return only a bounded opaque handoff for
fresh resolution by that Gateway. Implementing Provider handlers must not be
used to infer that the caller-owned Gateway or the complete Browser profile is
available.

## Decision

Add a narrow `BrowserApplication` port to the protected Provider transport and
match the two Contract-authorized routes:

- `POST /v1/sandboxes/{sandbox_id}/browser-sessions`; and
- `GET /v1/operations/{operation_id}/browser-session`.

The open route applies the existing mTLS, JWS, admission-context, request
digest, replay, and fencing gate. Bounded closed-JSON decoding occurs before
the mutation guard can consume replay or fencing state. After admission, the
transport correlates operation, attempt, fencing, sandbox, Provider revision,
deadline, digest, capability profile, generation, and expiry fields before it
calls the application. A successful acceptance projects an asynchronous
`open_browser_session` Provider operation and no runtime or backend model.

The handoff route uses the read admission descriptor and asks the application
for the admitted operation only. The transport rechecks returned operation,
attempt, fencing, and sandbox identity, enforces expiry at response time, and
projects only the Contract-shaped `ref:browser-session:*` reference,
connection generation, and Browser identity. URL, IP address, port, CDP
endpoint, backend token, host path, container, and credential fields have no
transport projection.

Browser repository, lifecycle-authority, application, and cancellation errors
map to bounded Contract errors. Pending reads are retryable `503`, expired
handoffs are `410`, unavailable or unknown operations are `404`, authority
conflicts are `409`, unsupported sandbox/profile state is `422`, invalid input
is `400`, and unknown or durability failures fail closed as retryable `503`.
Malformed application projections fail closed and are not returned.

The existing operation-family aggregator can include the Browser reader when
a composition root supplies the Browser application. An absent
`BrowserApplication` does not fall back to a repository or runtime driver: an
otherwise valid admitted Browser request returns retryable `503`.

## Release boundary

Tests cover route and Contract binding, strict and oversized preflight before
the mutation guard, replay/fencing admission before application dispatch,
request and response correlation, accepted operation projection, pending,
expired, unavailable, conflict, unsupported, invalid, and durability errors,
opaque handoff projection, forbidden endpoint-detail absence, nil-application
failure, concurrency, cancellation, and Browser operation-family aggregation.
The locked Contract verifier and 48-case Conformance Suite must remain
unchanged and pass.

This slice does not add Browser startup configuration, compose the
caller-owned Gateway, enable `sandbox.browser` capability advertisement, or
run a Browser external caller. It is Provider admission/transport component
evidence only. It does not establish aggregate conformance, real Agent
Platform compatibility, multi-controller reliability, hostile multi-tenant
isolation, deployment, or production readiness.

## Consequences

- A future composition root must inject the complete Browser application and
  its operation-family reader explicitly; transport does not construct or
  discover runtime dependencies.
- Provider routes can be exercised under the locked protected admission model
  without exposing a public Browser endpoint.
- The next independent slice is the caller-owned Browser Gateway with explicit
  user/tenant authorization, revocation, audit, reconnect, and fresh-reference
  resolution. Capability advertisement remains disabled until that graph and
  Browser external-caller gate pass.
