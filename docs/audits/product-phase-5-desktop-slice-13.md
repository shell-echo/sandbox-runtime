# Product Phase 5 Desktop Slice 13 Evidence

Date: 2026-09-20

Implementation: `84698c371d35edb862ffc81b484a3e31cc8120d9`

E2E baseline lock: `25283420377baebd9aaac8c1199068fb90735403`

## Accepted boundary

Slice 13 extends the authenticated Product Web BFF and embedded application
into one capability-derived shell for Workspace, Terminal, Files, Browser,
Desktop, and recording catalog flows:

- the checked client reads the exact Product capability document before
  loading Workspaces. Navigation fails closed unless the expected capability
  version and protocol profile are `ready`; duplicate or incompatible
  capability documents are rejected;
- Desktop slot and session lifecycle use only the locked public Product DTOs:
  `sandbox-runtime-desktop-v1`, `sandbox.desktop@1.0.0` / `desktop-v1`, and
  `product-desktop.v1`. The browser receives no Provider handoff, backend ID,
  host path, object reference, or raw private endpoint;
- view and control connections use a fresh Product connection grant, an exact
  same-origin HTTPS Gateway URL, receive-only VP8 with optional output-only
  Opus, and the ordered `product-desktop-control.v1` channel. Controller
  leases are released on disconnect, Workspace change, logout, close, or
  failed connection admission;
- bounded reconnect attempts reacquire a fresh grant. Stream resynchronization,
  closed display/audio configuration, current-media pointer coordinates,
  keyboard input, explicit clipboard consent, recording consent/mode, and
  digest-checked Product-bound transfers map to the existing Desktop Gateway
  protocols;
- the shared transfer BFF retains the Browser-compatible route and adds the
  neutral `/web/transfers` route with the same authenticated session, exact
  Origin/CSRF, size, digest, and metadata projection controls; and
- keyboard-operable ARIA tabs, labeled controls, live status, visible
  controller/recording/recovery state, reduced-motion behavior, and a strict
  no-inline CSP preserve the existing accessibility and browser security
  boundaries.

## Browser and regression evidence

The real headless-Chrome tagged test establishes an authenticated HTTPS
Product Web session, receives only an opaque Secure/HttpOnly/SameSite cookie,
loads the checked module client, reads the capability snapshot and Workspace
page through the BFF, enables the Desktop navigation entry from the exact
`product.desktop` profile, and confirms the Product bearer and browser cookie
are not forwarded together. Static regressions cover the unified landmarks,
closed public profiles, CSP/HSTS/frame policy, generated-client use, transfer
authorization, and absence of browser storage and private-coordinate fields.

Existing Desktop Gateway tests remain the authority for real WebRTC media,
ordered input, recovery, policy, recording, and backpressure behavior. This
slice does not relabel those same-process component tests as browser-to-runtime
or independent-process evidence.

## Validation

The implementation passed:

- generated Product Web client regeneration with no diff;
- JavaScript syntax validation under Node 24;
- focused Product Web race/shuffle tests and `go vet`;
- the real Chrome `browser` tagged Product Web test;
- full `go test -race -shuffle=on -count=1 ./...` and `go vet ./...`;
- Product and Provider Contract lock verification; and
- retained Product Phase 3 and Phase 4 evidence verification; and
- all eight parent-checkout E2E lock checks against the exact implementation
  revision, including reference, candidate, Browser, capacity, revocation,
  downstream fencing v1/v2, and PostgreSQL controlled restore.

## Evidence boundary

This is authenticated Product Web/BFF and real-headless-browser component
evidence at 13/15. Desktop capability advertisement remains fail closed in
production because the real Provider media/input bridge and exact production
startup graph are not yet composed. It does not provide the Slice 14 composed
cleanup/security/fault gate, the Slice 15 independent-process release gate,
deployment, HA, hostile-multitenant qualification, or production readiness.
