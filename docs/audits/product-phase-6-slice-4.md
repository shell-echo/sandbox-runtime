# Product v1 Phase 6 Slice 4 — Data-Plane Role Boundaries

Date: 2026-09-22

Status: **complete within the bounded local independent-process scope; Phase 6
is 4/15 complete**.

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
- The signed Phase 5 runtime now has its own byte-exact
  `phase5-production-release-manifest.json` and parser, while the evolving v2
  image uses `phase6-local-candidate-manifest.json`. The configuration and
  constructors select exactly one identity from `deployment_level`; both
  cross-combinations fail closed. This corrects a Slice 4 development
  regression where the candidate package manifest had overwritten the
  production adapter's verification input. It does not change the historical
  signed artifact or its evidence.
- The historical signed image did not contain an installed-set OCI label. Its
  production schema requires that label to remain absent and validates the
  exact historical custom-label set. The immutable manifest retains the
  installed-set digest as build-input evidence, but startup does not claim to
  attest it from a label. The local Phase 6 candidate still requires its
  per-platform installed-set label; Slice 7 owns the stronger published
  Phase 6 supply-chain gate.
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

## Accepted evidence

The tagged Slice 4 gate started Product, Gateway, Provider, Guest, Browser and
Desktop as six independent OS processes, plus independently runnable Browser
and Desktop executor backends. It used fresh PostgreSQL containers, pinned real
Chromium and a locally built digest-bound Desktop candidate. The strict
[evidence manifest](product-phase-6-slice-4-evidence.json) records exactly six
roles and twelve passed scenarios:

- normal Desktop attach, real VP8 RTP and fenced pointer input;
- replay, expired authority, capacity and generation/fence/epoch/policy drift
  rejection;
- authenticated Guest bounded reconnect and Provider dependency-loss
  readiness closure/recovery;
- broker-session, Desktop-role and Provider process restart;
- bounded active Browser drain; and
- Desktop close plus exact zero process, listener, socket, container, network
  and temporary Gateway-image cleanup.

The accepted run observed the following immutable identities:

- runtime implementation revision
  `78f5987fda45873e497bce6d336e29dd4a61dc74`, with source-tree digest
  `sha256:94e6d500778ad6e2d731f97d82f37f1b0d1f432baf9276b6b7c0d5b3dfa17124`;
- evidence-tool revision `e2f4abacf03418c7b18f179c3e7459292d8626df`,
  with tree digest
  `sha256:1b2b45dbac9bc5f282c3129f499c90d6027c13964e9e95ba3a1a5ded6c4c81f6`;
- configuration digest
  `sha256:24c3575b54be47cc0d71ce17afe3ff2385dd39822f6a7880a6a94b6f0843c199`;
- Desktop candidate manifest digest
  `sha256:d9e062cc96be9f3428e220a0b7b96de3f3dbd90c47ae3e1504c54a7d1bd9d470`
  and image digest
  `sha256:0592a69e8f85125360eb6805132b3654324ab9a56c0ea019ea3dc7aade103d4e`
  for `linux/arm64/v8`; and
- sealed evidence-manifest digest
  `sha256:d01b3c41a0094657f18b4014b0649a799ea7fcf0e4ccaf07aa82cdd2052cc0d2`.

The gate ran 150 Desktop mux stress sessions and 750 inputs with zero
first-frame, input, timeout or cleanup failures. Its 20-session media sample
recorded a 153,540-microsecond first-frame p95, zero RTP sequence gaps, bounded
frame rate and bitrate, 201 concurrent inputs, a 10,974-microsecond maximum
input round trip, exact backpressure recovery, and a stable 23-to-23 goroutine
boundary. After all roles joined, all eight named process, container, network,
socket, image and listener resource classes were exactly zero.

Earlier local candidates remain investigation inputs only. The accepted gate
wrote evidence outside the source tree and immediately re-verified it with
`cmd/verify-product-phase6-evidence`; the checked-in canonical manifest binds
the clean implementation and evidence-tool revisions, source trees and
configuration.

The retained real Phase 5 adapter gate also passed against the exact signed
index and restored byte-exact production manifest. Both locked platform
metadata entries and the exact historical custom-label set match. The
historical image never contained an installed-set OCI label, so its strict
legacy schema requires that label to be absent; its manifest's installed-set
digest remains immutable build-input evidence, not a startup label attestation.
The Phase 6 v2 chain continues to use only the local candidate, which requires
its installed-set label and may not satisfy the production gate.

## Claim boundary

This closes Slice 4 only within its bounded local independent-process scope.
The Desktop image remains `local-candidate-non-release`: it is not published,
signed or production qualified. The result proves role boundaries and internal
executor data paths, not complete public Product-to-Gateway-to-Provider E2E,
deployment, HA, hostile-multitenant isolation, SLO attainment, visual quality
or production readiness. The 30-second first-frame limit is a test safety bound,
not a production SLO. Slice 5 production secret references, KMS/HSM envelope
keys, scoped workload credentials, rotation, revocation and break-glass audit
are next.
