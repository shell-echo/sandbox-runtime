# Product v1 Phase 6 Slice 4 — Data-Plane Role Boundaries

Date: 2026-09-21

Status: **implementation present; corrective immutable candidate and final
evidence rerun pending; Phase 6 remains 3/15 complete**.

## Implemented repository scope

- `gateway serve`, `guest serve`, `browser serve`, and `desktop serve` are
  separate commands with separate `*_process` configuration sections.
- Gateway is restricted to an explicit public TLS listener; Guest is
  outbound-only; Browser and Desktop are restricted to private TLS 1.3 mTLS
  listeners with an exact URI identity allowlist.
- Every role has a distinct loopback-only process probe. Probes expose only
  `/livez` and `/readyz`; they do not expose `/instances`, Product routes,
  Provider Contract routes, credentials, or backend coordinates.
- Commands reject enabled Product/Provider or sibling-role authority in the
  same process. Private authority files are absolute, distinct, and bounded by
  configuration validation.
- `cmd/browser-executor-backend` supplies an independently runnable,
  operator-owned Browser CDP relay. It terminates private mTLS, validates the
  complete executor authority before opening the upstream, bounds sessions,
  rejects replay, and has no Provider database or Docker dependency.
- `cmd/desktop-executor-backend` supplies the corresponding Desktop relay. It
  accepts only `executor.v2`, requires a Provider-signed `desktop-bridge.v2`
  statement, verifies executor identity binding, and bridges only to a
  mode-0600 Unix Desktop broker socket. The broker's v2 session route is
  isolated from the legacy `desktophandoff.v1` route and verifies its own
  pinned Provider key, broker digest, expiry, fence, epoch, and replay ledger.
- Provider's remote Desktop adapter now requires explicit Ed25519 bridge key
  material and executor identity. The non-release local candidate runtime
  injects only the corresponding public key and key ID into the broker process;
  missing key material or an implicit session protocol fails closed.
- The broker persists a bounded replay ledger using canonical closed JSON,
  mode 0600, atomic replacement and directory synchronization. Concurrent or
  post-restart reuse, expired claims, corrupt state and capacity exhaustion are
  rejected. Desktop readiness performs `probe.v2`, rather than treating a
  reachable legacy broker as ready.
- `build-phase6-candidate.sh`, `internal/desktopcandidate`, and the Provider
  local-candidate constructor keep Slice 4 integration identity separate from
  the signed Phase 5 production lock. Production rejects `executor.v2` until
  Slice 7 publishes the replacement runtime.
- Browser and Desktop restricted egress share neutral Docker primitives but
  use sealed role identities and distinct thin provisioners. Recovery requires
  one exact role-owned workload name plus matching sandbox, session,
  generation, fence, network and identity labels; cross-role substitution,
  drift and extra workloads fail closed.

## Authority decision

ADR 0052 fixes the Browser/Desktop boundary: Provider remains the sole owner
of private handoff, PostgreSQL session/reference truth, tenant binding,
generation/fence/expiry/revocation/recovery, and Docker runtime attach. The
independent Browser/Desktop processes are restricted media/input executors
using a versioned opaque-only private mTLS protocol. They must not copy state,
write Provider databases, or hold Docker control authority.

## Pending acceptance evidence

The tagged Slice 4 gate starts Product, Gateway, Provider, Guest, Browser and
Desktop as six independent OS processes, plus independently runnable Browser
and Desktop executor backends. It uses fresh PostgreSQL containers, pinned real
Chromium and a locally built digest-bound Desktop candidate. The strict
manifest verifier accepts exactly six roles and twelve scenarios:

- normal Desktop attach, real VP8 RTP and fenced pointer input;
- replay, expired authority, capacity and generation/fence/epoch/policy drift
  rejection;
- authenticated Guest bounded reconnect and Provider dependency-loss
  readiness closure/recovery;
- broker-session, Desktop-role and Provider process restart;
- bounded active Browser drain; and
- Desktop close plus exact zero process, listener, socket, container, network
  and temporary Gateway-image cleanup.

Earlier local candidates are investigation inputs only and are not accepted
evidence. The corrective gate must write evidence outside the source tree and
immediately re-verify it with `cmd/verify-product-phase6-evidence`; the manifest
must bind the final clean implementation revision, source tree and
configuration.

## Claim boundary

This does not close Slice 4 yet. The Desktop image remains
`local-candidate-non-release`: it is not published, signed or production
qualified. The result proves role boundaries and internal executor data paths,
not complete public Product-to-Gateway-to-Provider E2E, deployment, HA,
hostile-multitenant isolation, SLO attainment or production readiness. Slice 5
must not begin until the Slice 4 evidence gate closes.
