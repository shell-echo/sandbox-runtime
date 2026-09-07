# ADR 0039: Content-Addressed Suites and Portable Remote Conformance

- Status: Accepted
- Date: 2026-09-07

## Context

The Provider Contract's `suite_digest` was a syntactically valid placeholder.
The lock verifier compared the declared Suite and lock values but did not
derive either value from Suite content. The exact Contract Git tree still
protected the file, but consumers could not independently validate the
advertised Suite identity with a defined content algorithm.

The only executable runner mapped the 50 Contract case IDs to this repository's
Go tests. Those tests include source projections, cross-resource checks,
startup configuration, fault injection, and internal dispatch observations.
An arbitrary remote Provider cannot expose all of those facts through HTTP.
Relabeling that runner as portable would turn partial network observations into
a false 50-case result.

## Decision

### Content-derived Suite identity

Contract lock format 2 requires the digest profile
`rfc8785-full-document-excluding-suite-digest-v1` for every selected Suite. The
digest input is the complete Suite JSON object with only its top-level
`suite_digest` member removed. The remaining object, including
`suite_digest_profile`, is canonicalized with RFC 8785 JCS and hashed with
SHA-256. The lowercase algorithm-qualified result must match the embedded Suite
value and the lock.

Verification is fail closed. Suite input must be one bounded UTF-8 JSON object
with closed and unique members, valid non-empty identities, unique profiles,
unique case IDs within each profile, and no trailing JSON. Array order remains
significant. Lock format 2 intentionally prevents an older verifier from
silently claiming the new digest semantics.

The verifier returns the case inventory from the same validated read used for
digest computation. The local runner must not reopen the Suite after
verification. The digest covers Contract case inventory and metadata, not the
repository-owned Go mapping or runner implementation; execution evidence must
therefore pin the exact clean runner revision. The local runner executes Go
tests from a bounded, read-only Git archive of that same revision rather than
from the mutable source checkout, requires exact mapped test passes from the
`go test -json` stream, and uses the Go toolchain version recorded in its build
identity.

### Separate execution profiles

The existing `sandbox-provider/sandbox-runtime-provider-v1` profile retains its
50 repository Go-test cases and `repository-go-test` execution mode. It is not
redefined as a remote protocol.

A second Contract resource, `sandbox-provider-remote`, defines
`sandbox-runtime-provider-remote-discovery-v1` with
`remote-http-black-box` execution mode and `mutations_performed=false`. Its six
cases cover authenticated mTLS discovery, rejection without a client
certificate and with a chain-valid but unadmitted URI SAN, strict
response-schema validation, byte-stable sequential discovery, empty-request
rejection, and GET-only routing.

The remote runner requires an explicit HTTPS origin, trust roots, client
certificate and private key, a second chain-valid but unadmitted client
certificate and private key, the client CA roots used to validate both
identities, and a server name. Each leaf must have client-auth usage and exactly
one distinct absolute URI SAN. It fixes TLS 1.3, disables proxy, redirect, and
transparent compression behavior, bounds all input and output, preserves
cancellation and deadlines, and never records private material or raw backend
diagnostics. It consumes one locked Contract byte snapshot and fails closed
unless its Go build has an unmodified VCS revision. It emits a versioned
machine-readable report with the exact Contract, Suite, runner, and target
identities, case status, timing, incomplete state, unsafe-method-probe
disclosure, and evidence boundary. It has no unscoped `conformant` field.

`mutations_performed=false` means that this profile calls no
Contract-authorized Provider mutation route. The GET-only case sends unsafe
method probes to the discovery path. A conforming target rejects them, but the
runner cannot prove that an arbitrary failing implementation caused no side
effect, so the report does not claim actual zero mutation.

There are no skipped or not-applicable cases in this first remote profile. A
case that cannot execute makes the profile incomplete; it is neither executed
nor counted as a Provider failure. Cancellation stops the remaining cases.
Future capability-specific or mutating profiles require
their own Contract resource, cleanup authority, prerequisites, and report
semantics.

## Consequences

- Suite content drift is independently detectable even outside Git, while the
  Git revision/tree remains the broader Contract identity.
- A remote green report is useful black-box evidence for discovery, but it is
  neither the 50-case local Suite nor independently implemented caller evidence.
- Protected admission, lifecycle, exec, terminal, Browser, artifacts, usage,
  controlled faults, and cleanup remain outside the first portable profile.
- Historical Suite counts, runs, and `suite_exercised=false` records retain
  their exact meaning and are not rewritten.

## Non-goals

This decision does not define a caller product or SDK, remote JWKS discovery,
multi-issuer admission, an external-caller qualification protocol, mutating
remote tests, aggregate conformance, multi-controller or multi-tenant safety,
HA, deployment, or production readiness.
