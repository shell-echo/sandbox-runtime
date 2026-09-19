# Product Phase 5 Desktop Slice 6 Evidence

Date: 2026-09-19

Implementation: `2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240`

## Accepted boundary

Slice 6 adds the Product-owned, network-only Desktop Provider adapter and its
durable PostgreSQL worker paths without composing a production process or
advertising Desktop capability:

- `product/adapter/provider.NewDesktop` accepts only Provider Contract revision
  `720ad15c343e71f36615dc4499edd5e764178bca`, tree
  `343ffde0819207cf99c005096c336735dd33a735`, one exact
  `sandbox-runtime-desktop-v1` profile, the signed Slice 4 image, bounded
  resources, a selected amd64 or arm64 architecture, and an explicit
  restricted-network policy reference;
- every readiness check re-reads Provider discovery and requires the exact
  Desktop capability/profile, runtime profile, container isolation, runtime
  class, selected architecture, and sufficient advertised limits;
- create, suspend/resume/terminate, Desktop open/close, retained operation
  reads, and Desktop handoff reads use the protected Provider HTTP surface with
  request deadlines, exact operation types, correlation/fencing checks, stable
  digests and idempotency keys, and bounded strict response decoding;
- the Product slot generation remains the Product fencing token while the
  independently retained Provider generation is used only as the Provider
  expected generation;
- dedicated Desktop slot, lifecycle, session, expiry, and observation workers
  lease only Desktop rows. The pre-existing generic, Terminal, and Browser
  workers cannot consume Desktop work;
- PostgreSQL migration 9 locks the two Desktop session provider actions.
  Accepted and outcome-unknown operations remain recoverable after Store and
  client reconstruction; and
- a successful Desktop close clears the Product handoff authority and closes
  or expires the session while retaining the current ready slot binding. It
  does not apply Browser's terminate-and-replace cleanup policy.

Desktop close and expiry dispatch is admitted only after a positive retained
connection generation exists. This prevents an uncorrelated cleanup request
from being sent for a session that has not produced a valid Provider handoff.
The later recovery slice still owns close-during-open and replacement fault
matrices.

## Real-store and recovery evidence

The tagged PostgreSQL integration uses the real Product migrations and Store
with an HTTP Provider fixture behind the production network adapter. It covers:

- strict readiness followed by a protected Desktop slot create;
- exclusion from Browser dispatch and generic observation leases;
- accepted-attempt persistence and successful observation after Store/client
  reconstruction;
- a Provider generation of 7 carried independently from Product slot
  generation/fence 1;
- Desktop session open, retained operation recovery, protected opaque handoff
  read, and persisted connection generation;
- Desktop close after another reconstruction, handoff removal, terminal
  Product session state, retained current slot binding, and absence of Browser
  replacement work; and
- migration replay plus all retained PostgreSQL race/shuffle tests.

The development-host run used fresh PostgreSQL image
`postgres@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
on native `linux/arm64`:

```text
SANDBOX_RUNTIME_PRODUCT_POSTGRES_URL=postgres://... \
go test -tags=integration -race -shuffle=on -count=1 \
  ./product/adapter/postgres

ok  github.com/shell-echo/sandbox-runtime/product/adapter/postgres
```

The temporary PostgreSQL container was stopped after the run.

## Validation

The implementation passed:

- focused Product and Product Provider adapter tests;
- tagged PostgreSQL integration compilation and the full real-store
  race/shuffle gate;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- the Provider and Product Contract verifiers;
- the retained Product Phase 3 and Phase 4 evidence verifiers;
- the existing tagged Docker instance and Provider lifecycle integration; and
- `git diff --check`.

Unit and HTTP tests additionally cover protected mutation/handoff requests,
deterministic replay bodies and digests, invalid response ambiguity,
retryable rejection, request timeout, caller cancellation, capability/runtime
drift, locked image/profile rejection, and separate dispatch/observation retry
rules.

## Evidence boundary

Slice 6 is Product network-adapter and real-PostgreSQL component evidence. The
HTTP peer is a same-repository test fixture, not an independently implemented
or production Provider. The production command still does not compose the
Desktop graph, and Provider/Product capability advertisement remains disabled.
There is no Product end-user grant, public signaling/media/input Gateway,
clipboard or transfer policy, recording, development template, unified Web
experience, independent-process release evidence, deployment, HA,
hostile-multitenant, or production-readiness claim.
