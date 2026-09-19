# Product Phase 5 Desktop Slice 7 Evidence

Date: 2026-09-19

Implementation: `0649d62911abb89229de40136347286736152ec6`

## Accepted boundary

Slice 7 adds Product-owned Desktop view/control connection authority without
adding a public Desktop signaling, media, or input transport:

- only a ready `desktop` session with exact public profile
  `product-desktop.v1`, a current Product slot binding, a positive retained
  Provider connection generation, a live opaque handoff, and an unexpired
  session may mint a Desktop grant;
- a `view` grant has no control lease or fence. A `control` grant requires the
  exact active session-scoped Product lease, controller actor, and monotonic
  fence;
- connection tickets are cryptographically random, live for at most 60
  seconds, are stored as a SHA-256 lookup digest plus AES-256-GCM ciphertext,
  and transition from `issued` to `consumed` on their first presentation;
- PostgreSQL migration 10 adds independent bounded Desktop viewer/controller
  tenant quotas, a live-grant quota index, and renames the pre-existing unique
  controller index to reflect its actual one-controller-per-session scope;
- a tenant-scoped PostgreSQL advisory lock serializes Desktop quota admission.
  A partial unique index and the session-scoped control lease independently
  prevent two live controller grants for the same session;
- database time decides grant, session, handoff, and control-lease expiry.
  Lease release/expiry, grant closure/expiry, session state change, binding or
  handoff replacement, generation drift, and tuple substitution fail the
  continuous authority check closed; and
- successful grant issue and control-lease mutations retain metadata-only
  security audit rows in the same transaction. Tickets and Provider handoffs
  are excluded from audit metadata and public grant responses.

The existing Product Contract already defines generic view/control grant
semantics for `product-desktop.v1`, so this slice changes no Provider wire
resource and does not relabel historical Terminal or Browser evidence.

## Real-store evidence

The tagged PostgreSQL integration builds two independent ready Desktop
sessions through the real Product Store and exercises:

- strict Desktop view grant issue, exact idempotent replay, encrypted ticket
  retention, one-use consumption, and explicit connection closure;
- viewer bindings with no control lease/fence and Product API denial of a
  viewer-requested Desktop control grant;
- cross-owner nondisclosure and stale rejection for substituted handoff,
  connection generation, or retained authority;
- session-scoped control acquisition, one live controller, release
  revocation, strictly increasing replacement fences, and stale-fence denial;
- concurrent Desktop viewer quota admission with exactly one winner;
- concurrent Desktop controller quota admission across two sessions with
  exactly one winner; and
- continuous authority failure after database-time control-lease expiry.

The development-host run used fresh PostgreSQL image
`postgres@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
on native `linux/arm64`:

```text
SANDBOX_RUNTIME_PRODUCT_POSTGRES_URL=postgres://... \
go test -tags=integration -race -shuffle=on -count=1 \
  ./product/adapter/postgres

ok  github.com/shell-echo/sandbox-runtime/product/adapter/postgres
```

The full package run also replays migrations 1-10 and retains the Terminal and
Browser grant, quota, fencing, lifecycle, and recording regressions. The
temporary PostgreSQL container was stopped after the run.

## Validation

The implementation passed:

- focused Product API and Desktop grant tests;
- the focused and complete tagged real-PostgreSQL race/shuffle gates;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- the Provider and Product Contract verifiers;
- the retained Product Phase 3 and Phase 4 evidence verifiers; and
- `git diff --check`.

## Evidence boundary

Slice 7 is Product authorization and real-PostgreSQL component evidence. The
opaque Provider handoff remains private Product storage and is returned only
to the later trusted Gateway composition through an internal binding. There
is no public Desktop Gateway, signaling, display/audio transport, input
execution, clipboard or transfer policy, recovery/resynchronization,
recording, development template, unified Web experience, production startup
composition, capability advertisement, independent-process release evidence,
deployment, HA, hostile-multitenant, or production-readiness claim.
