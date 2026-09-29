# Product v1 Phase 6 Slice 6 Startup Audit

Date: 2026-09-23

Status: implementation underway. Product Phase 6 remains **5/15**.

Checkpoint 2026-09-27 (repository role source-to-image input): the reviewed
58-deployment inventory now maps each local application role to an exact build
target; Browser retains its separate historical signed publication and Desktop
its separate candidate. A new operator-only local-role recorder accepts an
immutable Docker store digest, creates a stopped networkless observation
container, verifies its selected platform manifest and a private OCI archive,
independently rebuilds the role binary and compares its bytes to the effective
executable in the verified ordered layers, removes the observation container,
and retains an exclusive mode-0600 manifest plus archive sidecar outside the
checkout. The loader rederives clean source/toolchain/build inputs, archive
bytes, descriptor/config/layers/rootfs and binary proof; it rejects
tampering and public archive permissions. The real high-UID core-role Docker
integration, full root race/shuffle, vet and Product Contract lock pass. See
[`phase6-local-role-candidate.md`](../phase6-local-role-candidate.md).
Only one core target has passed this retained-candidate integration; the other
targets, the 58 running roles, network graph, 16-scenario same-run gate and
immutable Slice 6 evidence remain open. No Slice 6 counter movement or
production-artifact claim follows from this component checkpoint.
The opt-in topology preflight now consumes exactly one private manifest/archive
pair per distinct profile-selected local role image, verifies each against the
clean checkout and reviewed deployment→target map, and rejects missing, extra,
duplicate or cross-target reuse before side effects. Its tagged race tests
pass; this is still input admission, not a real topology or scenario result.

Checkpoint 2026-09-27 (measured single-target space and owned cleanup): at
clean revision `a5f2bbd197e4bc589298e2761491fc55bddca760`, one
`browser-action-ingress` local image build's largest observed free-space drop
was 63,135,744 bytes; recording its exact 13,836,800-byte private OCI
archive and manifest had a largest observed drop of 44,847,104 bytes. At clean
revision `c9cb492db1f25f8efff06fe4dccdeb8c9740501a`, the core build
had a largest observed drop of 116,137,984 bytes, and recording its exact
22,594,560-byte archive had a largest observed drop of 61,546,496 bytes.
Samples were polled every 0.5 seconds, so these are observed maxima, not a proven bound
on sub-sample spikes or other targets. The host's free-space baseline moved
from about 16 GiB to about 30 GiB during this work for a reason not
established by this task; no general Docker cleanup was performed here.

The Docker resource-ledger component now requires the current-source,
independently reloadable `provider-runtime`/`core` manifest and image label.
Its opt-in real-Docker race run passed on the c9cb492 candidate: a high-UID
core process ran in an isolated network, returned container/network IDs were
deliberately dropped, run-label rediscovery removed both exact resources, and
post-run Docker listings showed no matching containers or networks. Its
observed host-space peak was 10,391,552 bytes above the start sample; the
ledger test does not exercise the complete service chain. These per-revision
diagnostic candidates are not the final same-run Slice 6 evidence. Remaining
budget gaps include other unique role targets and bounded live PostgreSQL,
recording, logs, writable layers and cleanup headroom; 4 GiB is a
conservative stop threshold, not a proven system minimum or a release gate.

## Fixed Slice 6 open-item ledger

This table tracks the existing Slice 6 acceptance conditions; component
checkpoints below do not add slices or imply their closure. “Safety hold” is
not counted as recovered availability. The local candidate is not a release
artifact.

| Acceptance condition | Existing evidence | Remaining gap | Owner |
| --- | --- | --- | --- |
| Provider-bound Browser finite UID, exact create/recovery/cleanup | Real PostgreSQL plus high-UID Browser/gateway Docker integration; atomic Reserved retirement; finished-dispatch proof; live and terminal pre-commit recovery/cleanup; lost terminal-cleanup response finalization; focused in-flight barrier | Unknown Docker/network result with no finished proof remains Creating and consumes capacity. Need a gate-backed quiescence/terminal-result path where required, plus full process-crash coverage. | Provider Browser application, PG ledger and Docker adapter |
| Three isolated Provider production processes and Desktop v3 | v3 config, profile/identity validators, separate Browser/Desktop PostgreSQL client signers, real Browser/Desktop PostgreSQL+Docker finite-slot component gates, and real Desktop candidate broker/media/input gate; both v3 command compositions have static preflight and continuous admission dependencies | Prove the three distinct Provider commands in the same full topology with real Vault PKI, broker, server HBA/role/grants, restart/drain and exact cleanup. Desktop v3 remains local-candidate-only. | Provider commands and runtime adapters |
| Complete mTLS/CRL and fixed external-service trust graph | Signed PKI/peer-CRL guard, broker profiles, isolated component handshakes and real Vault adapters | Independent live Product/Gateway/Guest/Browser/Desktop/three-Provider flows, action ingress, Redis/PostgreSQL external legs, expiry/revocation/restart observations and cross-role denial. | Role compositions and TLS/egress adapters |
| Real network, UID/GID and host privilege enforcement | Pinned image descriptors, high-UID Browser/Desktop component gates, static policy validators | Same-host full-topology Docker network bypass/DNS/metadata denial, all role process credentials and container capability/seccomp/filesystem measurements, exact dependency-loss and cleanup observations. | Deployment gate and security evidence |
| Immutable Slice 6 gate and handoff | Strict profile/evidence validator and partial real-component observations; the implementation checkpoint passes root race/vet/Contract and affected real Browser/Desktop component gates | The independently runnable full-inventory Slice 6 harness itself is not yet complete. Build and run one same-runID topology with the frozen 16 scenarios, raw receipts, clean resource inventory, immutable source/evidence checkpoint and successful branch push. Do not advance 5/15 before all pass. | Phase 6 gate, audit and release owner |

The undispatched `Reserved` path and known-finished `Creating` path are
current safety requirements within the first row. A generic dispatch-owner
lease service is *not* approved as a new step. Unknown side effects without
quiescence proof remain a named availability limitation rather than an
automatic recovery claim. Artifact publication, signed multi-platform images
and redistribution/license clearance belong to later Slices 7/11, not a
shortcut for this local Slice 6 gate.

Checkpoint 2026-09-27 (Desktop finite identity wiring, not acceptance): the
existing Desktop session authority and Provider-owned PostgreSQL slot document
now transact the exact Open claim, Creating permit, Close source-Open
retirement, independent absence callback, and Released proof. The Desktop
candidate driver has a v3 local state with bound UID/GID, exact Creating
completion ticket/receipt, read-only recovery, and a fsynced cleanup fence.
Broker `describe` and session exec use that slot's UID/GID; a bound broker mux
fences and drains exact admitted Unix clients before workload/network delete.
The Provider application coordinator rejects Creating redispatch and uses the
same original Open claim for authorized Close. v3 composition is present but
the outer production startup gate is intentionally still closed. Focused race
tests cover known-finished and unknown Creating, drifted proof, invalid slot,
missing broker drain, ordered cleanup and mux replay. These are component
checks only: no v3 high-UID Desktop candidate, real Desktop PG+Docker gate,
full process topology or final evidence manifest has passed. Phase 6 stays
**5/15**.

Checkpoint 2026-09-27 (image identity and evidence admission): Sandbox
resolved the Slice 6/7 artifact-order ambiguity. All repository-owned roles
may run their real commands from source-bound, retained, local-only candidate
images for the Slice 6 same-host gate; publication/signature/SBOM and final
artifact qualification remain Slice 7. The internal profile now distinguishes
local/registry location and `local_config`/`oci_manifest`/`oci_index` object
kind, pins platform and config (plus selected manifest for an index), and
requires distinct runtime store ID, container-selected manifest and OCI config
observations. The original assumption that Docker inspect `.Id`/`.Image`
always equals config digest was falsified by this host's containerd store;
the schema and helper were corrected without switching Docker storage modes.
Raw descriptor-byte verification rejects config/manifest/index
substitution, platform drift and tag fallback. A closed Slice 6 evidence
validator now requires the complete profile, container/network inventory,
process, external-dependency, scenario and exact cleanup projections.
An opt-in real Docker component test on the existing containerd store creates
one exact pinned Alpine container with `--pull=never`, uses its actual
`ImageManifestDescriptor`, re-reads the image descriptor, verifies the raw
saved OCI index/selected-manifest/config blobs and every selected compressed
layer against its ordered uncompressed config diff ID, and removes the exact
test container/archive. Unit negatives reject wrong selected manifest,
config, runtime store ID, rootfs diff ID, missing/tampered/duplicate layers,
unsafe archive paths and tag fallback. This is an image-identity component
check on Alpine, not a real repository-role process gate.
Synthetic unit fixtures prove only rejection logic: no real full-inventory
manifest has been written, and the existing Alpine-probe Docker checks are
not promoted to the real-role gate. Phase 6 remains **5/15**.

Checkpoint 2026-09-23: a distinct signed controller peer-CRL v2 protocol now
binds policy identity, security profile, edge, local principal, direction,
anchor, full issuer DER digest and operator-selected source. The controller
re-authorizes that tuple and persists a shared replay nonce before Vault
access; the agent's v2 adapter resolves only its role's source ID and checks
the signed complete CRL. Both commands now have explicit peer-CRL configuration
versions and private canonical source-file loading; old configurations cannot
silently enable this capability. Canonical-wire, mutation, Unix signed
round-trip and fixed-source Vault component tests pass. This is not yet a
live role handshake/drain or full-inventory gate, so the counter does not move.
Sandbox's follow-up ruling fixes restart semantics: live roles must detect
CRL rollback and revoked-leaf resurrection in memory; a restarted role starts
unknown and must make a fresh online read from the fixed Vault source before
admission. Agent/controller restarts may not reset a still-running role's
watermark. A historical rollback of trusted Vault itself is explicitly outside
this single-cluster Slice 6 claim. No local peer-CRL observation ledger or
extra role-writable volume is authorized.

Checkpoint: signed controller and agent v2 snapshots now carry canonical
collection time; role-side `PeerCRLGuard` checks the actual TLS-verified
leaf/issuer, re-verifies the complete CRL, bounds source age, detects process-
local CRL/source/clock rollback and revoked-to-good resurrection, and starts
not-ready with no inherited good state. The Provider and Gateway private mTLS
handshake callbacks now invoke it after identity verification. A real TLS 1.3
handshake component test admits a good leaf and rejects a revoked leaf.
At that checkpoint, per-connection poll/drain, pre-handshake readiness
bootstrap, all-role wiring and distinct-process evidence remained open.

Checkpoint: Sandbox required zero-peer readiness with an operator-pinned
issuer, not first-peer discovery. The agent v2 snapshot now carries bounded
full issuer DER and signed-source collection time. A private role derivative
of the canonical source mapping binds each required mTLS edge to the complete
issuer digest and the full mapping digest; production Provider/Gateway configs
pin that document and digest. Agent/controller peer-CRL commands pin their
full source-document digest, and agent v2 requests/responses bind it. The
role guard bootstraps a complete signed CRL before any peer, then still checks
the actual TLS-verified immediate issuer and leaf on every handshake.
Provider Contract/private HTTP transports now track active and hijacked
sockets, poll the source and drain on revocation/loss with an exact close
hook; Gateway's outbound Provider transport uses a context-bound TLS dial
and guarded active-connection registry. Readiness invokes an online bootstrap
for both Provider edges and the Gateway outbound edge. Focused race tests pass.
This is component evidence only: full-role rollout, root-only/multi-CA anchor
negatives, real restart/source-loss gate, all-principal network/privilege
observations and the immutable Slice 6 manifest are still open. The counter
remains **5/15**.

Checkpoint 2026-09-26 (Browser external-authority inventory): the closed
Phase 6 profile now requires distinct `capacity-valkey` and
`action-history-postgres` external identities, Gateway/ingress logical
application edges, broker-to-external legs, one fixed-target egress policy
and independent policy-state authority per caller. Target DNS, port,
protocol, trust anchor and service ingress-edge sets are validated; missing,
swapped, extra or bypass paths are rejected by component tests. This is not
an ingress production command, real Redis/PostgreSQL witness wiring,
independent storage/restore-domain proof or Docker network-enforcement gate.
The Phase 6 count remains **5/15**.

Checkpoint 2026-09-26 (broker DNS and fixed-alias clients): both new broker
roles now declare the DNS mTLS edge required by the existing broker command.
The `phase6egress` adapter binds action-history PostgreSQL and Valkey capacity
to exact profile aliases, a profile-pinned external CA and a tracked broker
TLS connection. pgx host resolution is pinned to the original hostname so
only the broker resolves DNS; alternate host, plaintext/fallback and `PG*`
environment defaults are rejected. The go-redis custom dialer performs the
external TLS handshake itself and refuses a plaintext capacity tunnel.
Focused race tests pass. The adapter is not yet wired into an independent
production action-ingress command or a real Redis/PostgreSQL gate, so Phase 6
remains **5/15**.

An operator-only derivation command now writes the minimal role document as a
new mode-0600 canonical file from independently pinned profile/source inputs;
it refuses to overwrite an existing file. Its subprocess test validates the
generated artifact and absence of Vault locators. This does not create a
production deployment or an all-role configuration gate.

The accepted runtime edge matrix exposed a second configuration omission:
Guest-to-Product, Provider-to-Browser and Provider-to-Desktop were named in
ADR 0055 but absent from the test profile and production v3 composition.
Sandbox ruled that the simultaneous target needs three distinct Provider
process profiles (coding-shell, Browser-only and Desktop-only), not one
aggregate Provider identity. The canonical profile component validator now
requires the separate Product/Gateway Contract/private edges for each exact
Provider instance, the Browser/desktop attach directions only from their
matching Provider instances, Guest-to-Product, and both role-to-backend
edges. It checks the fixed listener, route, tenant scope, private target IP,
isolated two-member network and two CA purposes, and rejects missing or
aliased runtime edges. The test fixture gives each Provider instance a
distinct principal/UID/GID, TLS agent and socket; race-enabled negatives
reject coding-to-Browser attach, Browser-to-Desktop attach, route/target drift
and duplicate aliases. This is still profile/component evidence. Browser-only
Provider production composition, Desktop v3, Product's Guest receiver and
per-instance database/material/admission/cleanup isolation are absent, so
the full graph and Slice 6 evidence remain open at **5/15**.

Checkpoint: the three declared Product→Provider Contract and Gateway→Provider
private edges now have exact per-instance TLS boundary selectors. The
Provider server constructor can select six distinct inbound edge IDs and
resolves the matching instance's TLS agent, UID/GID, peer identity, anchors
and CRL binding; Gateway has a separate per-instance outbound constructor.
Negative tests reject wrong private origins, route relabeling and unknown
Provider instances. This removes an implementation alias but does not create
Browser-only or Desktop-v3 Provider processes, isolated databases, actual
network flows, or the full-inventory evidence gate.

Checkpoint 2026-09-24: Sandbox resolved the Desktop v3/Slice 7 artifact-order
conflict. Slice 6 may run the exact protected Desktop Provider command with
`provider-process.v3` and `deployment_level=local_candidate`, but the image is
explicitly `local-candidate-non-release`, never the Phase 5 signed image or a
production readiness claim. The Desktop v3 command now selects its own Product
Contract and Gateway private `/desktop` inbound mTLS/CRL edges and the
Provider→Desktop `/executor` outbound mTLS/CRL edge, with independent signer,
bootstrap, polling, bounded lifetime and readiness checks. Its candidate
manifest must match the configured actual source tree at startup, and the
runtime still validates the locally loaded image and fixed policy. Config
negatives reject production relabeling, candidate/production manifest crossing,
mutable image, pull downgrade, raw/static TLS keys and wrong routes. This is
component composition only: a real distinct-UID three-Provider-process gate,
real Browser-only Provider, Vault/Docker network/privilege measurements,
media/input/restart/drain/cleanup observations and immutable Slice 6 evidence
remain open. Phase 6 stays **5/15**. Slice 7 must publish and independently
verify the matching executor-v2 runtime before enabling Desktop v3 production
artifact admission; it must repeat artifact-affected security gates.

Validation note: root `go test -race -shuffle=on -count=1 ./...`, `go vet
./...`, both Contract lock verifiers, and tagged Docker lifecycle integration
passed for this component checkpoint. A rerun of the native arm64 Desktop
image tagged integration failed during the pinned APK archive-set check.
An isolated reproduction using the same pinned Alpine base and exact top-level
package versions downloaded archive set
`sha256:84b1ca112e795f356957af456cf02bce5cd8072c689059222b2702aaca6242c0`,
not the source-pinned
`sha256:f6a17c5b4031b4068ae345333cdfc3d09a3ef30dfe77a461f13306d3cf5ac656`.
This proves an archive-set mismatch under today's recursive repository
resolution, not which individual package/version/bytes changed. The prior
per-APK set has not yet been recovered, so a precise per-package cause is
unproved. Sandbox ruled that Phase 6 needs a separate candidate-only recipe
and closed per-architecture APK lock. The Phase 5 signed artifact, historical
recipe and publication lock remain untouched; neither the failed native gate
nor the passing Go suites establishes Slice 6 readiness.

Checkpoint 2026-09-24: separate candidate-only arm64/amd64 locks now enumerate
176/177 recursive APKs with exact bytes, source repository and license fields.
The new recipe verifies the staged set twice and installs offline; the local
candidate identity binds the lock file and OCI labels, while the historical
Phase 5 build/publication inputs remain unchanged. The arm64 native image
integration now passes a deterministic double build, real X11 display,
broker-v2 RTP, input/close, and exact test cleanup. A diagnostic Go 1.26.5
image had eight high-severity broker findings; rebuilding with the candidate-
only Go 1.26.8 pin yielded zero high/critical Alpine or broker findings in a
point-in-time Trivy scan. This is component evidence only. An amd64 native
runner, full three-Provider/Vault/Docker gate, signed multi-platform artifact,
redistribution-license clearance and Slice 6 manifest are still open; the
counter stays 5/15.

The first scan (Go 1.26.5 broker) reported CVE-2026-33818,
CVE-2026-39821, CVE-2026-46600, CVE-2026-56853, CVE-2026-56858,
CVE-2026-56859, CVE-2026-56860 and CVE-2026-56862 as HIGH. The replacement
toolchain's official macOS arm64 archive SHA-256 was verified against
`https://go.dev/dl/` as
`a012b25b571bd0138a03dcd25375ceba866fe5ca822f426d2c66a4de56fd3f4b`;
its extracted `go/bin/go` SHA-256 matched the installed toolchain at
`2ebc27dd4e38e9b86a9f41df0307785f4f7e2997e4be761a7b4af04b41a0de57`.
The tagged native integration also inspected the actual image broker's
`go version -m` metadata and candidate/lock/archive/installed-set labels.
Trivy 0.74.0 with vulnerability DB v2 updated 2026-09-24 09:10:28 UTC
reported zero HIGH/CRITICAL findings in both Alpine and Go broker for the
repaired arm64 candidate at 2026-09-24 11:18:51 UTC and the cross-built amd64
candidate at 11:23:18 UTC. The amd64 offline build repeated the same image ID
`sha256:db076907ce82d27cd0def19de00c70abf498c72e9198af3e128327a410013d1f`,
but no amd64 native runtime gate has run. These results are a dated scanner
observation, not future vulnerability absence or license clearance.

Targeted local-use license review followed the exact signed APKs' `.PKGINFO`
`origin`/aports commit to their versioned APKBUILDs, then checked the upstream
release's `COPYING`/`LICENSE`/`PATENTS` text. The five `custom`-tagged packages
in the actual arm64 image are:

| Package | Exact source and observed grant |
| --- | --- |
| `aom-libs` 3.14.1-r0 | [aports recipe](https://gitlab.alpinelinux.org/alpine/aports/-/blob/ab59db22db1f671fb8e69c79d4a10c273c862292/main/aom/APKBUILD) points to `libaom-3.14.1`; its release `LICENSE` permits use and redistribution subject to notices, and `PATENTS` has separate Alliance for Open Media Patent License 1.0 conditions. |
| `rav1e-libs` 0.8.1-r0 | [aports recipe](https://gitlab.alpinelinux.org/alpine/aports/-/blob/0f7061c11f34e1653f80475dd8e8917016fe4634/community/rav1e/APKBUILD) points to [rav1e v0.8.1](https://github.com/xiph/rav1e/tree/v0.8.1); release `LICENSE` is BSD-2-Clause and `PATENTS` is Alliance for Open Media Patent License 1.0. |
| `font-alias` 1.0.5-r0 | [aports recipe](https://gitlab.alpinelinux.org/alpine/aports/-/blob/ae9232982eb677d120e663a4ead0cabc81b244d8/main/font-alias/APKBUILD) points to X.Org 1.0.5; its `COPYING` permits use, modification and copies subject to retained copyright/terms. |
| `xdpyinfo` 1.4.0-r0 | [aports recipe](https://gitlab.alpinelinux.org/alpine/aports/-/blob/743b0d2f60b7518aa3e531ea7d407667f96e2818/community/xdpyinfo/APKBUILD) points to X.Org 1.4.0; its `COPYING` permits use/copy/modification/distribution subject to copyright and permission notices. |
| `xwd` 1.0.9-r2 | [aports recipe](https://gitlab.alpinelinux.org/alpine/aports/-/blob/9e2b12b780de7b2605b877273ec4f3179e619130/community/xwd/APKBUILD) points to X.Org 1.0.9; its `COPYING` has X.Org-style use/copy/modification terms and retained-notice conditions. |

All five downloaded upstream archives matched the exact SHA-512 in their
respective APKBUILDs. This resolves the `custom` label's local-use ambiguity,
not its distribution obligations. `glslang-libs` and `libelf` carry GPL-3.0-
or-later among their package-level declarations; no local-running conflict
was identified, but their exact component/file licenses remain a Slice 7
distribution review. The actual image's `ffmpeg -buildconf` reports
`--enable-gpl`, `--enable-version3` and GPL-associated external libraries
including x264/x265/xvid; it is not a blanket LGPL build. The candidate is
kept local with `pull=never`, no registry push or third-party artifact upload.
Neither the `custom` tag nor this bounded local-use inspection is a legal
opinion or a release license clearance. Slice 7 must resolve actual linked
components, notices, applicable corresponding source and build materials,
and any specialist patent/commercial questions before external distribution.

Checkpoint 2026-09-24: Browser/Desktop role v3 configuration now refuses raw
TLS files and static material selections. Their candidate application graph
resolves only the matching Provider-instance attach edge and the separate
role-to-backend edge from the complete profile, requires a remote signer,
fresh inbound/outbound peer-CRL guards and bounded WebSocket lifetimes, and
tracks upgraded attach sockets through revocation/shutdown. A real TLS/WebSocket
component test verifies hijacked-socket drain. Sandbox resolved a backend
identity omission: each backend server now requires exactly one canonical
profile DNS SAN in addition to the URI and `server_auth` EKU. Profile and
edge-boundary negatives reject missing, multiple, wildcard and IP names;
numeric dialing with pinned TLS ServerName and wrong DNS/URI negatives are
covered by the shared live TLS tests. Agent/controller policy validation
already binds issuance DNS to the profile. This remains code and component
evidence; the complete distinct-process Vault/Docker gate and immutable Slice
6 manifest are absent, so Phase 6 stays **5/15**.

Checkpoint: the 10-second profile drain claim exposed a real scheduling
contradiction: 30-second CRL staleness had produced a 15-second poll interval.
The common guard now derives one total pull deadline and poll interval from
the exact local principal's drain bound; the 10-second candidate caps them at
2 seconds each and budgets the entire connection collection at 1 second.
Provider/role server polling and outbound-client polling share that result.
Permit waits consume the same pull deadline, and an independent expiry timer
closes tracked sockets at the earlier of freshness or CRL validity loss.
Fixed-width parallel closure prevents one slow `Close` from serially blocking
all other sockets, while an over-budget close fails readiness. Component
budget, timeout, early-expiry and slow-close tests pass. This is not measured
Vault publication, scheduler jitter or full-capacity real-process drain
evidence; 10 seconds remains an unproved candidate until the named gate passes.
Guest v3 configuration now also rejects static TLS material and retains one
role-owned Guest signing-key binding. Its candidate outbound client selects
only the canonical Guest→Product `/agent` edge, live signer and peer-CRL
source, with numeric dialing, pinned Product DNS/URI and a bounded WebSocket
lifetime. This does not imply that Product's production private Guest Hub is
composed; that receiver and the complete process graph remain open.

Checkpoint: Product v3 now requires a separate numeric private Guest-control
listener, the exact pinned peer-CRL role and its live Product signer. The
candidate command composes the existing `guestagent.Hub` with the real Product
PostgreSQL Guest-binding authenticator; only `/agent` is mounted on the
private listener. TLS admits the exact Guest client identity, pulls a fresh
signed CRL, and tracks idle and upgraded sockets for revocation and shutdown.
Its explicit `guest_control_max_connections` bounds accepted sockets before
TLS/HTTP admission; excess connections close without consuming Hub authority,
and exact close restores capacity.
Focused real TLS 1.3/WebSocket tests cover route separation, revocation drain
and exact connection cleanup. The Product public production handler still
advertises `product.workspace` unavailable and has no Files/Development
service entry point; the Hub's presence alone does not establish those
capabilities. The full Vault/Docker multi-process gate and immutable Slice 6
manifest remain absent; Phase 6 stays **5/15**.
Sandbox's scope ruling keeps this slice responsible for a real independent
Product/Guest command gate with durable binding challenge, revocation,
database/source loss, restart/reconnect and exact drain. The future manifest
may assert `guest_security_edge_proven` only via observed scenario evidence
after those checks; its existing non-claim mechanism must leave
`files/development_public_composition` unclaimed. These labels do not add
manifest fields or a parallel evidence system. The formal
Files/Development/transfer/recording business
graph is a mandatory Slice 8 delivery and Slices 11/14/15 release blocker,
not an implicit consequence of Guest transport readiness. The fixed Phase 6
plan now inventories every promised public entry, service and dependency.
Review of the live private WebSocket clients exposed a redirect downgrade
path in the shared HTTP transport. The candidate now rejects redirects at
Guest, Gateway and Browser/Desktop backend clients, denies all plaintext
`DialContext` calls in the guard and retains exact numeric-target TLS dialing.
Component negatives cover policy and transport; the actual multi-role
network-bypass campaign remains open.

Checkpoint 2026-09-24: Desktop private transport v2 now has a bounded
prepare/start/started activation barrier. The Provider reserves capacity and
rechecks the current handoff without opening the broker until an exact start;
the Product side waits for connected WebRTC senders and ready media readers,
while its original absolute connection and first-media deadlines continue to
run. Race tests reject pre-start commands/media, bad started acknowledgements,
allocation/generation/fence/epoch drift, replay and over-capacity admission;
they also check timeout, cancellation, broker-open failure and exact local
capacity/session cleanup. The current arm64 native Desktop image tagged test
passes deterministic double build, real X11, broker-v2 input/close and a
complete VP8 keyframe decoded to a 1280×720 RGB frame by ffmpeg inside the
read-only container. The decoder receives IVF bytes over stdin; no writable
root filesystem or image-policy exception was introduced. This is a real
broker-to-decoder observation, not a client-decoded Product→Provider v2
end-to-end process gate. The distinct Slice 6 multi-process gate and immutable
evidence remain absent; Phase 6 stays **5/15**.

## Corrected premises

The repository does not already enforce Slice 6 merely because TLS 1.3,
`internal/netpolicy`, seccomp files and hardened Browser/Desktop container
options exist. Current production role TLS identities are parsed and frozen at
startup. The generic network-policy library is not the mandatory path for all
role traffic and cannot prevent a process from opening a direct socket. The
Slice 5 process gate intentionally records one host UID. Those facts are
component foundations, not certificate-rotation, network-enforcement or
least-privilege evidence.

The opposite shortcut is also rejected: moving the complete production system
into Kubernetes or platform-specific manifests now would consume Slice 11
without first freezing the portable security contract.

## Reused foundations and open gaps

| Area | Reused authority | Gap that Slice 6 must close |
| --- | --- | --- |
| TLS parsing | `internal/tlsmaterial`, TLS 1.3 transports, exact SAN/EKU and role material registries | Real Vault PKI issuance, role-local key generation, atomic live swap, bounded overlap, CRL/revocation-driven connection drain, outage and clock-rollback closure. |
| Workload credentials | Slice 5 credential controller, renewable leases and agent identities | A separate certificate-controller identity and least-scope Vault PKI policy; no workload may hold CA or arbitrary PKI-role authority. |
| Network policy | `internal/netpolicy` and Browser/Desktop restricted-network provisioner/gateway | Mandatory alias-based broker path for every declared egress edge, role-isolated internal networks and topology proof that direct/raw-IP/DNS/proxy bypasses fail. |
| Runtime hardening | Existing runtime read-only rootfs, drop-all, no-new-privileges, resource bounds and selected seccomp checks | A closed all-principal profile, unique container UID/GID, role-specific seccomp and exact drift/privilege/resource negative tests. |
| Evidence | Slice 4 and 5 immutable/retained verifiers | A Slice 6 manifest binding the full principal/edge/profile inventory to real PKI, Docker network, Browser/Desktop smoke and cleanup observations. |

## Frozen order

1. Add the closed security profile and inventory validator.
2. Add the independent certificate controller, closed signed CSR protocol,
   real Vault PKI adapter, role-local key generation and atomic live TLS
   rotation/revocation path.
3. Add the alias-only egress broker and prove role-isolated Docker topology,
   DNS/metadata/rebinding/direct-socket denial and policy-revocation drain.
4. Enforce unique container UID/GID, read-only filesystem, mounts, capabilities,
   seccomp and resource limits for the complete repository-owned principal set.
5. Run the immutable full-inventory gate, real Browser CDP and Desktop
   media/input smokes, exact cleanup, strict evidence verifier, root race/vet,
   both Contract verifiers, and retained Slice 4/5 verifiers.

The order is fixed by ADR 0055. Focused component checks may establish a
checkpoint but cannot advance the Phase 6 counter.

## Implemented checkpoint: principal-bound PKI and local signers

The repository now has the shared closed `securityprincipal.v1` registry, a
separate `workload-credential.v2` lease/ledger protocol, the signed
principal-bound certificate protocol and a real Vault PKI adapter. Version 2
cannot reinterpret a Slice 5 v1 request or lease. Certificate-controller Vault
credentials are exact-policy scoped; substitution, delegation, mixed-version,
replay, restart, expiry and revocation tests fail closed.

`workload-tls-agent` generates P-256 keys locally, obtains an exact CSR-bound
certificate and exposes only a peer-credential-bound Unix snapshot/signing
capability. Its rotation, overlap, CRL staleness, issuer outage, clock rollback,
replay, capacity, cancellation and exact socket/key cleanup tests pass under
the race detector. A real TLS 1.3 handshake succeeds through the remote signer
without exporting a private key.

The certificate controller now requires a private regular descriptor-5 key
and strictly validates its operator bootstrap certificate before first Vault
use. A tagged real integration starts the fixed-digest Vault image with TLS 1.3
and mandatory client certificates, proves certificate-less denial, performs
the initial PKI operation, closes the bootstrap transport, switches to the
locally generated managed certificate, performs a post-switch CRL operation,
revokes the managed certificate and observes its serial in the authoritative
Vault CRL before exact container cleanup.

The alias-only egress broker is now implemented as an independent principal-
bound process with a closed target protocol, broker-side bounded DNS resolution,
address validation, checked-IP dialing, replay/capacity limits and policy-
revocation drain. Its focused tests use controlled resolvers and dialers; they
do not establish the real topology gate.

A tagged Docker topology checkpoint now starts two distinct-UID/GID Alpine
probe containers on an actual `isolated` internal bridge network, adds the
broker probe alone to a separate uplink and starts a fixture on that uplink.
Docker inspect
and in-container `/proc` probes verify read-only roots, zero effective
capabilities, `no-new-privileges`, active seccomp, configured PID/memory/CPU
bounds confirmed in the live cgroup, exact network membership and broker-only
uplink. Direct connections from the protected probe to the fixture IP and a
public IP fail, while the dual-homed probe reaches the fixture; exact run-owned
containers and networks
are removed and checked absent. The fixture and broker probe are **not** the
real egress-broker binary or the complete role inventory. The test does not
prove role-specific seccomp, resource exhaustion, DNS rebinding, authenticated
broker transport or all-principal enforcement.

An additional real negative probe exposed a host-gateway bypass:
Docker 29.7.2 allowed a container attached **only** to a `--internal` bridge to
connect to that bridge's gateway (`172.20.0.1`) where a disposable host-network
fixture listened on port 18080. Thus the internal bridge alone does not enforce
the ADR's no-direct-socket claim against host services. The exact probe
containers and network were removed and checked absent. Sandbox ruled that
every role/trust-edge network must use the Docker `isolated` IPv4 gateway mode,
with IPv6 disabled until separately proven. The updated tagged test now
reproduces the ordinary-bridge bypass with the same host fixture, then proves
the fixture is reachable from the uplink but not from the isolated role via
the former internal gateway, another bridge gateway, Docker host aliases,
public IP or metadata IP. It also proves the role can reach its declared
broker probe. Network inspect confirms `isolated`, no host gateway, exact
members and disabled IPv6; live probes confirm no default route/IPv6 address.
This remains a topology checkpoint using probe processes, **not** the real
egress-broker binary or all-principal network-complete evidence.

The closed observation validator rejects principal/image/UID/GID/seccomp,
resource, network and cleanup drift, including resource-controller digest
substitution and container-ID reuse. A bounded Docker-network-inspect importer
now extracts exact driver, gateway mode, subnet, host-gateway absence, IPv6
state and member container IDs and binds the raw inspect document by digest;
the tagged topology checkpoint exercises that importer against the live
daemon. Unit fixtures remain synthetic, and the active probes do not yet
produce retained raw receipts tied to every repository principal. This is not
the full Docker collector or release evidence. The complete least-privilege
inventory and immutable Slice 6 evidence gate remain open, so Phase 6 remains
**5/15**.

The policy-revocation component now has a closed Ed25519 state protocol,
operator-owned single-writer atomic/fsynced CAS ledger, independent authority
command, challenge/response Unix Current protocol and production broker
startup/continuous polling path. The broker does **not** read a state file:
it refuses to listen before a fresh signed online
Current, then polls at a profile-bound interval and revokes/drains on the
first invalid, unavailable, rolled-back or revoked response. Each policy is
bound to a distinct controller principal, key digest, socket and managed
persistent ledger volume in the canonical security profile. Component tests
cover replay, restart high-water, old active versus committed revoked state,
peer credentials, stale active-ledger refusal, failed revocation commit without
a receipt, healthy refresh, online revocation and live TLS tunnel
drain. A tagged Docker checkpoint runs the authority protocol in a real
container under UID/GID 20001:30001 and its client under 20002:30000 with
only a read-only managed-volume view. It observes active Current, abrupt
authority death, SIGTERM/SIGKILL without false permanent revocation,
safe same-owner stale-socket recovery on restart, signed
revocation, revoked restart despite restoration of an old audit snapshot,
authority outage denial, wrong-UID peer rejection, broker denial on reading
the private ledger and exact fixture container/volume cleanup. A separate
read-only authority-UID process verifies the committed revoked generation,
binding, timestamp and ledger digest; a crash with active ledger fails that
inspection. The fixture
embeds a deterministic test key in a shared test binary; it does **not** prove
production signing-key isolation. It calls the protocol package directly and
is **not** the production
broker/authority pair or a full Slice 6 gate. The obsolete file monitor and
snapshot-file publication path were removed; a legacy signed active file is
ignored in the restart test. The profile
exception for one authority-private
managed persistent volume is explicit; broker and business roles have no
ledger access or host-path bind mount.

This is still **not** an independent authority/broker OS-process or Docker
gate. Distinct UID/GID socket directory/mount behavior, real broker and
authority restart/failure isolation, all-principal hardening, retained raw
topology receipts, full DNS/egress negative matrix and strict Slice 6 evidence
are outstanding. Privileged operator restoration of both key and ledger is
outside this local trust claim. Phase 6 therefore remains **5/15**.

A subsequent tagged Docker checkpoint builds and runs the actual
`egress-policy-state-authority` command under its profile-bound UID/GID,
with a private descriptor-3 signing key and managed ledger/socket volumes.
It proves explicit initialization, fresh signed Current to a distinct-UID
client, wrong-UID and private-ledger denial, SIGTERM and SIGKILL recovery
without a false revocation receipt, safe stale-socket recovery, SIGUSR1
successful exit, a separate read-only `inspect` receipt, revoked restart
rejection and exact run-owned cleanup. This test exposed and fixed a
production public-key type comparison that had rejected a valid signing key.
The client is a Current-protocol probe, **not** the production broker; this
checkpoint does not establish the full Slice 6 gate. The next production
broker test exposed the role-local TLS agent's old 0700 parent and 0600
socket permissions: distinct agent and broker UIDs could not traverse or
connect. Sandbox ruled a closed v2 production layout.

Sandbox retained `workload-tls-agent.v1` wire messages but mandated a closed
production config/socket layout v2. The shared implementation now creates an
agent-UID-owned, role-GID 0710 parent with an agent-UID-owned 0666 socket,
checks exact ownership/modes and stable path inode, verifies peer UID/GID
before reading, and actively closes accepted connections on cancellation.
Half-frame read timeout, replay/capacity and permission-drift tests pass under
the race detector. A tagged Docker test starts the real signing listener
and client package code in separate agent/role processes with different
UID/GID, verifies certificate snapshot and ECDSA remote signature, denies a
wrong UID, wrong GID and extra role, then proves agent-loss denial and exact
container/volume cleanup. Its issuer is a test fixture and its client is not
the production egress broker. Profile-bound socket mounts/trust edges for
every role and executor, full production broker TLS/DNS mTLS, and the Slice 6
gate remain outstanding. Phase 6 remains **5/15**.

The key-owner audit found a second independent gap: the existing eight
`material_agent` identities are Vault KV/credential processes, not separate
TLS-agent processes. The private principal registry now has a distinct
`tls_agent` kind, and the certificate delegation matrix permits only one
exact TLS agent per runtime/executor/registered broker subject plus the
certificate controller's internal managed-signer exception. TLS agents are
denied by the v2 Vault-credential issuance matrix even when a backend policy
is configured. This is a registry/PKI component checkpoint, not a complete
profile inventory or a migrated runtime TLS path. The detailed ownership
inventory is in `product-phase-6-tls-key-ownership.md`.

A full race/shuffle run also exposed a real authority timing race in the
online revocation test: the socket handler sampled time before waiting for
the ledger lock, then compared that old instant with a just-committed revoked
record. The live Current path now samples its clock while holding the same
lock as the ledger read; a deterministic pre/post-commit regression and 100
repeated race-enabled broker revocation tests pass. Unbounded package
parallelism on this host repeatedly delayed local WebRTC ICE/media assertions
and exposed a separate Close/Recover test that incorrectly equated one CAS
effect owner with one observer of the final durable state. The data-path
tests now have test-only admission/event budgets; the CAS test checks exact
effect counts and permits both callers to observe the committed outcome.
The root `go test -race -shuffle=on -count=1 ./...` completed with exit 0
under `GOFLAGS=-p=4`, without concurrent Docker tests. This is a reproducible
host-concurrency condition, not a default-parallelism claim or the Slice 6
release gate.

The earlier single-Provider profile checkpoint required eight static TLS-agent deployments
and one additional agent for each registered egress broker. Each binding
checks both principal digests, separate process UID/GID, the exclusive
private socket storage and read-only subject mount, 0710/0666 socket layout,
one subject-to-agent Unix edge, issuer policy/Vault role and cleanup class.
Agent/subject substitution, mode/path drift, missing binding and third-party
mount sharing fail closed in race-enabled profile tests. The production TLS
agent now reads that profile before its signing key and rejects a self-
submitted requester, subject, issuer or socket mapping; the egress broker
checks the same subject binding before opening its TLS-agent client. This is
configuration/component evidence only. Other runtime and executor commands
still use local TLS key material, and there is not yet a real production
broker→agent→controller→Vault→DNS/mTLS gate. Phase 6 remains **5/15**.

Sandbox then identified the reverse trust edge that the first binding did
not close: TLS-agent configs could independently select the certificate-
controller endpoint, peer and response key. The profile now declares one
controller authority and an exclusive agent→controller Unix endpoint per TLS
agent, plus an explicitly separate managed-TLS self endpoint. It binds the
controller response key and each agent's CSR request key by purpose-separated
public-key digests. The TLS-agent command checks these fields before opening
its client; the certificate-controller command uses the same validated
profile-derived registry (including dynamic broker agents) and rejects a
missing/extra/substituted listener or policy set. Its production config is
v2, with no v1 production fallback. The shared Unix inode/ownership and
connection tracker replaced the old PKI socket `chown` and unbounded first-
frame/close behavior. Targeted race tests pass. A tagged Docker gate now runs
one controller and two agents under three distinct UID/GID pairs, with
separate controller-owned/agent-group 0710 directories and read-only agent
mounts. Both agents issue and renew strict CSR certificates, revoke and read
CRLs; cross-agent, wrong UID/GID and wrong controller-response key are denied;
a half-frame peer times out; cancellation and exact run-owned container/volume
cleanup are observed. This gate uses a repository-private test CA rather than
the production certificate-controller command or Vault. The full
broker→agent→controller→Vault→DNS/mTLS process graph is still outstanding, so
this is not a Slice 6 release gate and the count remains **5/15**.

The Browser/Desktop executor production TLS constructor now uses a neutral
live TLS 1.3 signer builder instead of the Provider transport helper. It binds
both directional CA pools to the same validated profile, checks the exact
profile URI/DNS/EKU/TTL and P-256 signer proof for each new handshake, disables
server session tickets, and refuses a missing or failed signer. Focused
race-enabled handshakes prove generation swap, signer loss, issuer/identity/
usage drift, extra peer SAN/EKU, expired leaf, and public versus mutual TLS
semantics. These are component tests, not the production distinct-UID graph.
The same unpublished backend authority v2 is now tightened with pinned
peer-CRL role/source digests in both real command entrypoints. Each command
verifies the derivative role document before constructing a live signer and
inbound peer-CRL guard; remote-signer backend constructors reject a missing
guard, signer probe or bounded connection lifetime. The shared connection
registry retains hijacked WebSockets, polls revocation, drains them on source
loss or revocation, and forgets the exact socket on close. Browser and Desktop
component race tests observe that an accepted mTLS WebSocket closes and the
CDP upstream or Unix broker session closes too, with zero tracked sockets.
Each new `/executor` upgrade also performs a bounded fresh signer/CRL check,
including when HTTP reuses a prior TLS connection; a cached handshake alone
does not admit a new WebSocket after source loss.
This checkpoint also reruns the real pinned Chromium `Browser.getVersion`
integration and the native arm64 Desktop image/X11/RTP broker integration;
both pass and their run-owned containers are removed. These exercise the
backend compatibility path and the Desktop image respectively, not the
unreleased production command/agent/CRL graph.
The static constructor still imports the Provider mTLS file loader for
historical component compatibility; the production remote branch never calls
that loader. These tests do not substitute for the distinct-UID commands,
real Vault CRL and full principal/network inventory gate; the counter remains
**5/15**.
Product now also has an explicit v3 public-listener command path: its material
registry contains only runtime DSN and identity key ring, while the validated
profile, exact public listener, pinned issuer anchor and separate agent
provide TLS identity. The Product transport now accepts an exclusive live
certificate callback instead of requiring a static certificate array; a
mixed callback/static configuration is rejected. Its dependency monitor
rechecks the signer. The v2 path
remains explicit historical compatibility, not an automatic v3 fallback.
At that checkpoint Provider/Gateway/Guest/Browser/Desktop and Product's
internal edges still needed live-signer migration; all existing-connection revocation drain remains
mandatory. No Slice 6 evidence manifest is issued.

The canonical profile now has exactly two closed `public_listeners` bindings:
Product API and Gateway signaling. Each binds the runtime principal digest,
specific TCP listener/port, server issuer anchor and explicit `none` client
certificate policy. The validator rejects a third public listener, an
unbound listener, an optional-client-certificate mode, a client-verification
anchor, or a role lacking server-auth usage. This is profile component
evidence only; Product v3 command composition has not passed a real
distinct-UID process gate, and the public listener's
user/grant authorization remains application-owned.

The profile's earlier global `SeccompDigest` uniqueness check was not a
least-privilege requirement: two separate TLS agents with the same reviewed
syscall needs can use the same digest without sharing UID, GID, key, mount or
network authority. The check was removed while each principal still binds an
exact digest and runtime observation still rejects per-principal drift. A
positive equal-policy regression and the retained seccomp-drift negative
test cover the distinction. The final gate must still inspect actual policy
bytes and denial behavior, not merely a digest-shaped string.

Sandbox resolved the public ingress topology as one operator-owned fixed
TCP relay: it alone joins `public_ingress` NAT and the two separate isolated
Product/Gateway trust networks; the roles have no host publication. The
relay owns no TLS signer, material agent or business secret and cannot select
targets through HTTP, CONNECT, SOCKS, DNS or SNI. The canonical profile now
requires its own principal/UID/GID/image/resource identity and two exact
digest-bound mappings, including frontend and target IPs, networks, host
bindings, ports and per-route limits. Non-relay `ingress_frontend` listeners,
extra relay listeners, role host publication and endpoint drift are rejected.
Every profile network now binds a canonical non-overlapping IPv4 CIDR;
frontend and target IPs must belong to their declared networks, and Docker
inspect must report that exact subnet. The Docker-network importer records
exact member IPv4 addresses, and
the observation validator binds the two relay publications and destination
IPs to the profile. A tagged Docker checkpoint built and ran the actual
`phase6-ingress-relay` command as a distinct non-root process; it exercised
host-published routing through a NAT frontend to two `isolated` networks,
inspected exact relay-only publication/network membership and UID/capability
bounds, observed upstream loss and restart, and verified exact run-owned
container/network/volume cleanup. The upstreams were fixed-response Alpine
`nc` probes, not the Product/Gateway commands. This proves neither TLS/user
or grant authorization through ingress nor WebRTC ICE/UDP/media delivery,
all-principal seccomp/resource enforcement, or the final release graph.
Phase 6 remains **5/15**.

A further component checkpoint imports raw `docker inspect` port mappings and
requires the relay to be the sole host-published principal, with exactly two
configured and active TCP bindings; Product/Gateway probes must have none.
The real relay Docker test now verifies this observation and disabled kernel
forwarding as well as isolated networks, upstream restart and exact cleanup.
The canonical local mTLS anchor rule now binds each caller and server to both
read-only CA artifacts for distinct own-leaf and peer-verification purposes.
A two-issuer handshake test rejects swapped roots and mismatched signers. The
profile adds an isolated Product→Provider Contract edge and a separate
Gateway→Provider private Terminal edge, each with a numeric target, canonical
route, exact listener, identities and two CA purposes.

Gateway v3 now uses an exclusive live public signer and a separate live
private Provider client; its material registry contains only Product DSN and
grant key. Provider coding-shell v3 now selects two distinct profile-bound
live mTLS listeners: Contract admits Product, private Terminal admits Gateway
and only the exact `/private/terminal` path. Provider v3 runtime material
contains only DSN and admission verification keys; Desktop v3 is explicitly
rejected. Provider transport constructors reject static/live mixing, TLS
downgrade, optional client certificates, session-resumption bypass and
client-hello configuration replacement. Real TLS handshake tests show that
the listener-specific client URI allowlist rejects a wrong role even under a
trusted client CA. Targeted race tests, root race/vet and both locked Contract
verifiers pass for this code checkpoint. These are not the actual three-role
command, cert-rotation, revocation-drain or full-inventory gates. No Slice 6
manifest or count change follows.

The next Provider transport checkpoint tracks accepted Contract and private
Terminal sockets beneath `net/http`, including hijacked Terminal connections.
V3 binds their maximum lifetime to each exact profile trust edge; shutdown
drains accepted sockets rather than relying on `http.Server.Shutdown`, which
does not own hijacked sessions. A real mTLS private-listener test upgrades a
connection and verifies the socket is closed and the registry reaches zero;
the Contract test verifies an idle keep-alive socket is also drained. This
does not yet wire authoritative revocation notifications or prove the
profile's revocation drain bound during a live process gate.

Sandbox selected a versioned read-only pull from the existing Vault PKI →
certificate-controller → role TLS agent chain for peer revocation; v1 Unix
snapshot/sign semantics remain closed. The first code prerequisite verifies a
complete CRL against the exact CA DER identity, signature, issuer, AKI,
number and validity window, then checks a peer leaf under that same issuer.
Its test rejects a same-serial/different-issuer substitution. This helper is
not yet wired to the v2 Unix protocol or live TLS admission. The remaining
gate requires fixed-version Vault publication-policy observation, exact
profile source mapping, freshness/rollback protections, budgeted polling,
new-handshake denial and existing-connection drain across roles.
The tagged PKI integration used the pinned Vault image (reporting v2.1.1)
and observed `disable=false`, `auto_rebuild=false`, `enable_delta=false`;
after a real revoke, the complete CRL number advanced and the CRL verified
under the actual issuing CA. This establishes that fixture's publication
behavior only, not a production Vault configuration or end-to-end latency
bound.
The Vault PKI client now has an explicit `RequireImmediateCompleteCRL` mode:
before reading a CRL it uses the same scoped credential to read `config/crl`
and rejects missing, disabled, auto-rebuild or delta policy. Unit negatives
and the fixed-image integration pass with a read-only config ACL. Existing
v1 controller composition does not silently enable this option; the future
v2 peer-revocation path must opt in and bind the policy to its exact issuer
source before it can claim enforcement.
The next component now rejects delta, distribution-point-scoped, indirect or
unknown-critical CRL semantics even when a CRL signature is valid. A fixed
Vault source lookup accepts only an operator-supplied immutable issuer UUID,
mount and full issuer DER digest; it reads that issuer's CA and complete CRL,
checks both against the pinned DER and never falls back to `/pki/crl`.
Wrong/missing issuer, wrong signed CRL, alias/path injection and a disabled
complete-CRL policy fail closed in unit tests. The pinned real Vault image
also passed the exact issuer endpoint read after a real revoke. This is
component evidence only: the mapping is not yet bound to the profile's edge
authorization, controller/agent v2 wire path or live handshake/drain, and
there is no current Slice 6 manifest.
A separate `workload-tls-agent.v2` peer-CRL wire codec is now drafted beside
the frozen v1 snapshot/sign codec. Its canonical bounded request binds the
profile digest, exact edge, local principal, direction, peer anchor and full
issuer digest without accepting a caller-selected Vault path; its response
binds those fields and a source ID, complete CRL bytes, digest, number and
times. Decoding re-verifies the signed CRL against the caller's exact issuer
DER and rejects a v1 fallback. This codec is not yet an agent socket service
or controller authorization path, so no live handshake/drain claim follows.
An additional closed canonical operator source document is bound to the
existing security profile digest and Vault external identity. It maps fixed
issuer sources separately from exact local-principal/edge/direction/peer-
anchor authorizations; unknown edge, role, direction, anchor or actual issuer
DER cannot select a source. It allows two directions to reference one actual
issuer without implying separate CAs from differing anchor names. This
document is not yet loaded by production controller/agent commands and does
not establish source caching, least-privilege ACLs or full edge coverage.
The existing restricted Unix signer socket can now accept the distinct v2
peer-CRL request only when an explicit provider capability is configured;
the v1 snapshot/sign decoder and client remain intact. A real Unix socket
round trip verifies the returned issuer-bound signed CRL, while replay,
capacity, wrong-edge, v1-only fallback, cancellation and upstream-cancel
tests pass. This provider is still a test fixture, not the production
controller-backed authorization path; the role commands do not require v2
yet, and no live mTLS admission or existing-connection drain is proven.
The operator binding now exposes an agent-facing authorization lookup that
returns only a source ID for the exact role/edge/anchor/issuer digest; the
full Vault mount and immutable issuer ID stay in the controller-side source
record. The production controller must independently reauthorize the same
tuple before reading Vault; this is not yet wired.

Checkpoint 2026-09-24: Browser session and handoff-reference state now have
Provider-owned PostgreSQL adapters. A real PostgreSQL integration exercises
two independent runtime connection pools, concurrent idempotent reservation,
allocation/handoff persistence, one-winner competing tenant-digest binding,
revocation, stale-fence rejection and restart retention. The private Browser
handler now binds only after its authorizer, re-resolves the reference before
dial, and polls the reference so revocation or authority loss cancels an
active stream. The reference resolver also checks current Provider revision,
generation, fence and lease when the session repository exposes that
authority. These are component checks, not a Browser-only Provider v3 process
or a caller-grant authorization proof. The Browser production backend command
now rejects a fixed CDP `UpstreamURL` and requires a restricted Provider mux.
That mux resolves each opaque Browser handoff to the current Provider-owned
allocation before `Driver.Attach`, rechecks authority while streaming, bounds
replay capacity, and cleans up its Unix socket by inode. A real pinned
Chromium Docker test exercised the bounded RFC 6455/CDP translator; a two-
target fake test exercised the mux selection and revoke drain. These are not
the composed Provider v3 process or the full action-fencing gate. The Browser
Provider now also records one-use executor request IDs/digests under the same
transactional reference and current sandbox authority; local backend/mux
replay caches are bounded rather than treated as restart evidence. The real
PostgreSQL component gate checks the duplicate and changed-content request
after reconstructing the mux authority. This does not yet bind the v2
Gateway connection tuple or replace ADR 0033 action fencing. The Browser
handoff v1 optional request digest and remote attach's fresh random fence /
generation-derived epoch cannot be asserted as verified Gateway connection
authority. The v1 Browser private handler now rejects non-test composition so
it cannot accidentally serve as the v3 route while that protocol is unfinished.
No complete Browser v3 attach or full-inventory evidence exists;
Phase 6 remains **5/15**. This source-tree change invalidates the previously
recorded Desktop local-candidate source digest, requiring a new exact
candidate build and affected gate rerun before a Slice 6 manifest.

Sandbox's follow-up ruling retains ADR 0033's unique action ingress outside
the Gateway. The raw Redis capacity claim belongs only to the existing
capacity authority, must travel through the protected ingress, and is
validated for exact membership/high-water inside the same per-session gate
as each complete CDP write. Product's one-use grant and control lease are
separate caller-owned checks; Provider may verify exact delegated principal
and opaque resource/connection tuple but does not become the grant authority.
A new Product-signed grant attestation is not required for this threat model.
The existing `cdpfence.NetworkHandler` now has an explicit fenced-resolver
path that forwards the exact admitted subject and claim inside `Ingress.Open`;
component tests cover that ordering. Browser v3 must compose that path as
the unique ingress, add its exact principal/TLS/CRL/Redis/witness/network
edges, use mandatory canonical `browser-handoff.v2`, and remove direct
Gateway-to-Provider/raw-CDP bypass. The current inventory still declares a
direct Gateway-to-Provider edge, so it cannot pass or be described as the
completed topology. Phase 6 remains **5/15**.

Checkpoint: Sandbox fixed the previously unspecified Browser tenant/resource
digest as a new, caller-only HMAC-SHA-256 v2 derivation over the exact
Provider handoff and nine ordered committed fields. The Product adapter now
has an exact golden vector and drift tests; the Browser executor and durable
Provider bind/claim paths reject historical v1 digests in production while
retaining historical records for compatibility reads. A dedicated secret
purpose is limited to Product/Gateway; a narrow keyring helper resolves only
the caller-supplied committed version through that purpose, checks the
material's exact version and active window, and wipes its copy. A separate closed canonical
`browser-handoff.v2` message validates the Provider revision, reference,
generation, connection epoch, control lease digest/fence, expiry and both
authority/request digests. The executor v2 request digest now binds its
one-use request ID, and the reference registrar accepts new v2 records
without redefining historical v1 syntax. The real two-pool PostgreSQL
integration still passes after the v2 format migration. This is a protocol,
format and durable-reference component checkpoint, not a production Browser
connection. At this earlier checkpoint Product had not yet persisted caller
scope and key version atomically with the first binding or composed the
keyring in its runtime;
the v2 message is not yet wired through actual
one-use grant consumption, unique ingress, Provider v3 handler, exact
executor connection tuple or independent process gate. A lost active key
must fail closed; no default-key or v1 fallback is allowed. Phase 6 remains
**5/15**.

Checkpoint: additive Product migration 14 stores a narrow immutable row per
exact tenant/Product session/Provider audience/handoff, with a composite
grant foreign key that is null only for historical paths. The new opt-in
Product Store constructor prepares the caller-owned secret selection before
opening the Provider-observation SQL transaction; on a successful Browser
open, it verifies the exact observed handoff, current Provider binding and
resource tuple, inserts/rechecks the immutable row, and commits the Product
session's ready/current pointer in the same transaction. A mismatched
selection rolls the complete observation back. The repository bounds retained
rows and makes competing key versions one-winner/conflict rather than
last-writer-wins. The targeted real PostgreSQL test uses two independent
pools, verifies competition/idempotence, atomic mismatch rollback, and
current-read denial for missing, wrong-audience and draining bindings.
An opt-in Browser v2 GrantRepository now fixes that row's audience/reference
on grant issuance, rejects historical/unbound ticket replay in v3, and
checks the same row's digest/version and current Provider tuple on ticket
consumption and continuing Gateway authority reads. The real PostgreSQL
component gate rejects a stale ticket and active stream after a handoff
switch, tampered key version, wrong audience and draining session. This is
still not complete: the Product v3 runtime does not yet construct these
opt-in repositories, the unique ingress and Provider v3 handler do not yet
consume the closed v2 wire, and full concurrent switch/consume/forwarding
linearization remains a gate. The legacy constructor stays historical;
production v3 must not choose it. This schema/component result is not a
Slice 6 release gate.

Checkpoint 2026-09-24: Product migration 14 now persists the exact non-secret
secret binding reference/purpose/role/version and canonical binding digest,
and a PostgreSQL trigger rejects UPDATE of an established handoff row. The
two-pool test checks exact readback and immutability; the focused tagged
PostgreSQL integration passes. The Desktop composed PostgreSQL/WebRTC race
test exposed a separate real timing defect: the historical v1 bridge starts
private media before public WebRTC is connected, so its 32-frame bounded
preconnection queue can fail closed on frame 33. Sandbox selected an explicit
v2 prepare/start/started transport, not buffer inflation or frame dropping.
The new closed canonical v2 protocol binds start to the exact session,
generation, epoch, fence and authority/request/transport digests. Provider
v2 prepare now reserves capacity and continuously checks authority without
opening the executor reader; start rechecks current authority, opens once,
sends started before media and closes on cancellation. Product v2 arms its
WebRTC consumer and recording before activation and rejects pre-start
commands. The production Desktop Provider private listener requires v2;
historical v1 remains a separate test profile. The targeted prepare wait,
replay/capacity, epoch/generation/fence/allocation drift, no-start timeout,
pre-start command/media, bad acknowledgement, broker-open failure, cleanup
and Product PostgreSQL/WebRTC race tests pass. The native arm64 image test
also verifies a full broker VP8 keyframe is decodable, but the composed fake
Product media test still sees only one synthetic RTP packet. Neither test is
the Product→Provider v2 decoded-display or full-inventory process gate;
Phase 6 remains **5/15**.
The current v2 candidate does not rerun `TestPhase6Slice5ReleaseGate` with a
v1 request against a v2-only listener. Slice 5's original runtime/evidence
tool revisions and byte-identical archive remain verifiable only with the
retained verifier (`current_head_covered=false`). A current-source v2 process
gate needs a separate Slice 6 identity and evidence, reusing only neutral
orchestration and cleanup code rather than relabeling old evidence.

Checkpoint 2026-09-26: the Browser v2 Provider reference now retains one
immutable ingress connection claim per exact epoch, a single reserved
executor attempt, consumed replay evidence, and monotonic close status.
The retained consumed bit is cross-checked against the replay entry even
after close, so a damaged snapshot cannot silently discard one-use evidence.
The state transition clones its maps before validation so failed conflicts
cannot mutate in-memory authority. The executor fence derives from the
complete private v2 authority digest, never Provider generation or a fresh
random fence. A separate remote `AttachConnection` path reserves the exact
attempt before send, copies the original absolute authority expiry, and
closes the epoch after an ambiguous send failure without permitting a new
request ID. The Provider mux resolves the persisted connection before and
after Docker attach and consumes the exact reservation atomically. The
two-pool real PostgreSQL integration now tests one active writer, close and
replacement, old-epoch denial, replay and authority drift across pools and
after mux reconstruction. Atomic bind also reports whether the caller created
the claim: an idempotent duplicate cannot close another active stream, while
the creator can close its own failed pre-attach path. A separate
`browser-handoff.v2` private handler
checks one exact route/host and a verified TLS 1.3 ingress URI, bounds
concurrent sessions, validates canonical requests, attaches only through the
connection-aware resolver, monitors current authority and closes its owned
claim. Its WebSocket test injects a synthetic verified TLS state, so it is
component evidence. A separate real TLS 1.3 mTLS component test issues a
test CA and distinct SPIFFE client certificates: only the exact ingress
principal can open the v2 route, and accepted close releases the claim.
This is not a multi-process inventory or Product/Redis authorization gate.
The Browser-only
Provider v3 command, Product v3 one-use grant/lease composition, unique
Redis-backed action ingress, real mTLS/process graph and two-session
Chromium gate remain open. No Slice 6 release manifest exists; Phase 6
remains **5/15**.

Checkpoint 2026-09-26 (topology correction): the Sandbox architecture
decision confirms a separate Browser action-ingress process, rather than
the earlier direct Gateway→Browser Provider private edge. The canonical
security profile now requires Gateway→action ingress `/browser/action` and
action ingress→Browser Provider `/private/browser` as distinct isolated
networks and principals. The Browser Provider config admits only the action
ingress URI; a direct Gateway peer and an extra legacy edge are rejected in
component tests. Its v3 configuration also has a closed Browser-only runtime
matrix, while `provider serve` explicitly rejects Browser composition until
the production graph exists; it cannot fall through to Coding. These are
declarations and component checks, **not** evidence of a live ingress,
Redis/witness gate, or complete deployment. The added process, TLS agent,
material agent, CRL boundary, network edges and cleanup are additional Slice
6 work, not a new slice. Phase 6 remains **5/15**.
The revised profile also rejects an undeclared direct shared network, not
just a second named trust edge. The private TLS client constructor now has
separate Gateway→ingress and ingress→Browser Provider selectors with their
own issuer, peer, signer and CRL guards; the old Gateway→Provider selector
returns an error for Browser. Repository-wide race/shuffle tests and `go vet`
pass at this checkpoint, as do both locked Contract verifiers. These are
source-level checks only; no new immutable Slice 6 release evidence exists.

Checkpoint 2026-09-26 (Browser Provider assembly): a separate, still
startup-disabled Browser-only Provider constructor now composes PostgreSQL
session/reference stores, the pinned Browser Docker image and restricted
network, lifecycle/session recovery, protected Browser operation/usage
projection, capability from the Docker-inspected image architecture, live
Contract/private/executor TLS and CRL guards, v2 connection-aware remote
attach and the Provider-owned allocation mux. It has no file registry or
static executor key fallback. The canonical profile additionally fixes the
Browser mux Unix edge, exclusive mounts and Provider/backend UID/GID; both
Provider and backend command configs pin `/run/browser-mux`. Focused race
tests cover profile drift, wrong socket owner, Browser-only advertisement and
revoke-before-exact-cleanup. The tagged real Docker Browser relay test passes.
This constructor is not yet selected by `provider serve`: no independent
production action-ingress/Redis/PostgreSQL witness process graph or full gate
has run. It is component assembly, not release evidence; Phase 6 remains
**5/15**.

Checkpoint 2026-09-26 (Browser v2 action transport): the closed Gateway→
action-ingress Open now binds the consumed Product grant's current tenant
digest, Provider audience/revision, reference/generation/expiry, control
lease digest/fence and exact bearer-like capacity claim. Unknown, duplicate,
omitted and noncanonical JSON are rejected. Product automation explicitly
maps its public protocol to the locked Provider `browser-v1` capability; a
separate grant-bound Gateway resolver sends the Open only to `/browser/action`.
The ingress v2 handler derives a deterministic one-use Provider epoch only
inside the existing Redis admission/per-session closure callback, then uses
the distinct `/private/browser` Provider client. An exact attempt replay
reuses its epoch; a newly authorized internal attempt receives a new epoch.
The capacity claim, raw control lease and Product grant ID are excluded from
the Provider Open. Gateway and ingress component tests cover wrong audience,
denied admission, replay, reconnect, malformed projection and CDP transport.
The v2 private stream tracks each CDP request ID until its exact response:
an incomplete action on any close is terminal, while only a confirmed idle
or answered normal close is reconnectable. Ingress emits distinct terminal
fence-loss/witness-unavailable closes and bounds pending sockets before
upgrade; targeted race tests cover unknown outcome and authority loss.
The Product PostgreSQL Browser integration test also rejects runtime-session
pointer drift at both grant-consumption and continuous-authority boundaries.
These tests used a disposable real PostgreSQL container, subsequently
removed. They do **not** establish separate OS processes, real Redis/witness
admission, production mTLS, real Chromium, or a Slice 6 manifest; Phase 6
remains **5/15**.

Checkpoint 2026-09-26 (exact broker address): Sandbox selected the profile's
single role→broker `tls` edge as the only numeric broker address authority.
The closed profile now pins each policy's unique private IPv4 address inside
its two-member isolated network; the broker command rejects an alternate or
wildcard bind, and a shared `phase6egress` constructor derives the role's
broker dial address from the same edge with its exact TLS/CRL identity. A
tagged Docker topology probe assigned the profile IP to the broker interface,
observed role→broker reachability, rejected broker loopback/uplink listening,
and checked no host-port publication and exact cleanup. The closed network
observation verifier now also rejects a broker target IP assigned to any
different container ID. This Alpine network
probe is not the production broker-command/mTLS/Vault/DNS gate. No Product,
Gateway or action-ingress production client has yet completed the whole
dependency graph, and there is no Slice 6 evidence manifest. Phase 6 remains
**5/15**.

Checkpoint 2026-09-26 (external credential ownership): Sandbox approved two
Gateway-family `KindSecret`/`SystemTenant` purposes with deployment-level
isolation: Browser action ingress alone may consume
`action_history_witness_dsn`; ingress and Gateway may each consume
`capacity_valkey_credentials` only through distinct bindings and Valkey ACL
accounts. The existing material-agent/Vault mechanism is reused. Secret
binding validation, role-aware Vault purpose checks, agent deployment
allowlists and the deployment-bound registry reject cross-role and same-role
cross-agent swaps in component tests. The witness URI parser rejects alternate
targets, credentials, TLS downgrade and pgx fallback; the closed Valkey JSON
cannot choose an endpoint, DB, namespace or TLS mode. Redis binding rejects
preinstalled/dynamic credentials. Real Vault credential rotation/revocation,
Valkey/PostgreSQL ACLs, independent service processes and end-to-end drain
are still unproved. These source checks do not advance Phase 6 beyond
**5/15**.

Checkpoint 2026-09-26 (external credential lifetime): a new ingress-side
credential guard resolves both purpose-bound secrets through the uncached
role-owned material registry at bootstrap, pins their binding, digest,
revision and rotation window, and re-resolves their identity before every
fenced CDP action. An independent bounded poll catches idle-stream agent
loss, expiry, revocation or rotation, latches failure and invokes one
process-owned drain callback. Focused race tests cover version drift,
agent loss, expiry and denied action forwarding. Full repository race/shuffle
and vet pass. The existing tagged real Vault/material-agent integration also
passes with an empty temporary Docker CLI config; the first attempt was
blocked by a hanging local Docker credential helper before its assertions.
The Browser external-client constructor now assembles only the profile's two
fixed broker aliases, requires a separately pinned Valkey ACL user, creates
bounded Redis and PostgreSQL pools, and calls the existing capacity/fencer
`Verify` paths rather than `Provision`. It closes both pools on partial
startup failure. This is source/component evidence, not yet the Browser
action-ingress production command: no real pools or upgraded sockets have
been shown to drain under Vault rotation. There is no Slice 6 evidence
manifest, and the counter remains **5/15**.

Checkpoint 2026-09-27 (independent action-ingress command):
`browser-action-ingress serve` now reads a mode-0600 canonical private
authority, checks its exact security-profile and CRL-role digests, agent
principal/binding identities, numeric two-edge routes and bounded capacity
settings, then composes the v2 Browser ingress over the distinct Gateway and
Browser Provider mTLS edges. It bootstraps and polls the inbound, outbound and
broker CRL guards; uses the profile-selected broker and the two external
clients above; refuses redirects; checks uncached credential authority before
each CDP write; and cancels its server on idle credential/CRL loss. The
private server drains upgraded connections and closes pools on shutdown.
Focused race tests reject duplicate/unknown/noncanonical configuration,
wildcard/loopback/DNS binds, cached/slow material resolution, wrong agent,
cross-purpose bindings and unbounded session/poll settings. A corrective
bounded action budget separates two uncached credential reads plus fence and
Provider work from each single-dependency timeout; the startup Redis/witness
verification has a bounded multi-operation budget. The command has
not yet passed a real multi-OS-process Vault/Valkey/witness/Provider/Chromium
gate, and the newly written topology has no immutable Slice 6 manifest.
Phase 6 remains **5/15**.

Checkpoint 2026-09-27 (action-history witness privilege split): ADR 0055 now
supersedes ADR 0035's earlier runtime `INSERT` recommendation. The migration
owner retains schema and cleanup authority, a separate one-shot provisioning
identity alone receives initial-row `INSERT`, and the action-ingress runtime
receives only `CONNECT`, schema `USAGE`, table `SELECT` and column-scoped
`UPDATE(sequence, token, updated_at)`. The operator upgrade instructions
explicitly revoke old table/column and inherited `INSERT` grants; no real
unreviewed database is automatically changed. Real disposable PostgreSQL and
Valkey component integration used distinct admin, runtime and denied roles.
The local images were `postgres@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
and `ghcr.io/valkey-io/valkey@sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`;
both were bound only to temporary loopback ports and removed after the run.
It observed runtime `Provision`/valid `INSERT`, `DELETE`, `TRUNCATE`, identity
column update, schema/table DDL, role/owner escalation and `SET ROLE` denial;
normal two-pool CAS had exactly one winner, and read-only restore checks
rejected an old Redis snapshot. After an admin removed a witness row, runtime
verification/action rejected it without re-creating the row or changing the
Redis checkpoint. An injected post-Redis/pre-witness interruption recovered
exactly one step through runtime `Verify`, while strict restore verification
remained read-only. PostgreSQL may return a successful `GRANT` with a warning
when a role lacks grant option, so the test checks effective `INSERT` privilege
after the attempt rather than treating command success as escalation. This is
an isolated external-storage component gate, not the complete action-ingress
multi-process/Vault/network gate or immutable Slice 6 evidence. The count
remains **5/15**. The full `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, Product Contract lock verifier and `git diff --check` also
passed after this component change.

Checkpoint 2026-09-27 (live witness ACL admission): the candidate Browser
action-ingress now refuses to create its external-client graph until the
actual PostgreSQL role/database and effective required/forbidden grants pass
a bounded live check. The same check runs on each new physical pool connection
before it enters the pool. A separate process-level poll stores the last
successful check's monotonic START time; each action checks only local
freshness and terminal state before the unchanged Redis+witness fence. The
profile must satisfy `P+T+C+1s<D` for poll, complete pool wait/query,
actual close and scheduling allowance. Persistent overgrant/undergrant,
timeout, starvation or stale evidence latches failure and invokes the existing
cancel/drain path; later ACL repair does not unlock the process. Against a
fresh disposable PostgreSQL instance, runtime inherited-provisioner drift
was rejected; a live table-level `INSERT` grant caused a new physical
connection to fail and the fully idle monitor to drain, and the exact grant
revoke restored only a new connection, not the failed guard. Pool starvation
closed within the bounded timeout. The real tagged PostgreSQL/Valkey packages
passed with shuffle and race. This is not a full Browser OS-process/real Vault
and egress-broker scenario or immutable Slice 6 manifest; brief grant/revoke
between samples and malicious DBA action are outside this local ACL-monitor
claim. Phase 6 remains **5/15**.
After this ACL-monitor change, the full repository race/shuffle suite,
`go vet ./...`, Product Contract lock verifier and `git diff --check` passed.

## Exact final inventory

The gate covers Product, Gateway, Guest, Browser role, Desktop role, three
separate Provider instances and the Browser action ingress as nine runtime
processes, two executor backends, their eleven distinct TLS agents, one TLS
agent per egress broker, eleven declared Vault material agents,
workload-credential/break-glass/certificate controllers, two one-shot
migration jobs, all egress brokers and their one-to-one policy-state
authorities, and the existing Desktop broker/Browser
runtime enforcement observations, plus the public ingress relay and its two
exact published paths. Vault, Product PostgreSQL, independent
action-history PostgreSQL, Valkey capacity and DNS are external dependencies
whose digest, identity, ingress and authorized-client edges are bound; their
deployment, storage-domain separation and HA remain non-claims.

## Required negative matrix

- substituted role, agent, tenant, trust domain, SAN or EKU;
- TLS 1.2/downgrade, expired certificate, revoked serial, stale CRL, issuer
  restart, Vault/controller loss and clock rollback;
- cross-role and cross-tenant service traffic;
- undeclared target alias, port or protocol, raw IP, alternate DNS, proxy
  environment, redirect, metadata/private/link-local/loopback/reserved answer
  and DNS rebinding;
- broker/DNS/policy loss and policy revision drift/revocation;
- root execution, UID/GID reuse, writable root, undeclared mount/tmpfs,
  capability addition, disabled no-new-privileges, seccomp drift, extra
  listener/network/device/daemon socket and PID/memory/CPU exhaustion; and
- process, connection, socket, file, container and network cleanup to the exact
  declared zero-resource boundary.

## Non-claims

Until the final gate passes, Phase 6 stays 5/15. Even after Slice 6 closure,
the result remains a same-host local-container gate. HSM-backed CA authority,
published/signed application images, platform service accounts, Kubernetes or
Apple Container deployment qualification, HA, independently administered
failure domains, hostile-multitenant safety and production readiness remain
later gates.

### 2026-09-27 native Desktop v2 local-candidate checkpoint

The Desktop candidate identity correction is implemented: current admission
now requires v2 plus an exact raw OCI archive sidecar; historical v1 remains
readable but cannot be admitted. Unit rejection tests cover a store manifest
misrepresented as config, selected-manifest mismatch, v1 current admission and
altered archive bytes. The real cached Desktop image was built from an older
source revision and cannot be promoted by changing its record. Its cached
`phase6-candidate` tag is not authority: image inspection also shows missing
candidate-classification and candidate APK-lock labels, so current admission
must reject it regardless of its valid raw OCI descriptor chain. The narrow
baseline ARM64 comparison treats omitted variant and `v8` as the same
canonical `linux/arm64/v8` platform while preserving the original raw digest
bytes and rejecting ambiguous duplicate canonical platforms. A real Docker
component check on this cached image now verifies the store manifest,
container-selected manifest, config and ordered layers/diff IDs; it does not
qualify the image as a current candidate.

An isolated, clean, test-only Git checkpoint at
`ade169ed0c2a6300923fe98f80466c86702a1785` captures the current source
without changing the active branch/index or pushing a release. Its source-tree
digest is
`sha256:49367d73a1d58a053c6ce863650590a4428e9eb941d0f1ef9e8c5070b91741ea`.
The native arm64 locked build generated a new candidate with store/selected
manifest `sha256:352fbaef96b62e86464b0b5b6e7baf1a3d7d6a530d26aa9d86eedcc619a062fd`,
distinct raw OCI config
`sha256:0e230d8e7bbfa449cf5093c05f57edbef0e755cc0f8588b4c84abab1fccf05ef`,
and private, re-importable 151323136-byte archive
`sha256:32761bbf5cf232ce6b2d8ed6e885df4501fd5bd42f1164adef66515246f76747`.
The canonical v2 candidate manifest digest is
`sha256:4600d17cfe24caa29972433a3a8c70c0fae247ef64eecba0588d0833db7447d8`.
The producer verified the actual stopped-container selected manifest, raw
config and every ordered layer/diff ID, matched the source/build locks and
required candidate labels, then removed its exact observation container. The
real Docker broker-mux → executor → VP8/input integration and native two-build
reproducibility/X11/media/input gate passed against this checkpoint; their
test-owned containers, networks and temporary image tags were observed absent.
This is still a local component checkpoint, not the full Slice 6 role graph,
Vault/network/privilege matrix or an immutable Slice 6 release manifest.
Phase 6 remains 5/15.

### 2026-09-27 Desktop broker containment model correction

The required inventory had classified `desktop-broker` as a separate container
principal even though the executable actually runs inside
`desktop-sandbox-runtime`. Sandbox ruled that this must be a required
in-container process/component, not a dummy container or a second UID/network
security boundary. The unpublished closed profile now requires the exact
broker executable digest, argv, Unix socket and protocol under the Desktop
sandbox parent. Observation/evidence validators require the parent's real
container and image identity, broker effective UID/GID, PID/start ticks,
executable, 0600 socket and session-association receipts. The Desktop sandbox
controller is `provider-desktop-runtime`; executor backend does not acquire
Provider Docker/allocation authority. Closed unit fixtures reject missing,
mis-parented, substituted and fake-container broker records. These are
validator tests, not a completed real full-inventory gate or immutable
manifest. Phase 6 remains **5/15**.

The identity conflict affects both runtime images: the current Browser and
Desktop images and Provider Docker adapters pin `1000:1000`, while the Slice 6
profile requires distinct non-root numeric UID/GID values in 10000..60000.
Sandbox ruled for explicit, finite, profile-bound per-allocation identities,
durable Provider ownership/spec binding and exact effective create/exec
observation; neither a relaxed profile nor fixed replacement constant is
accepted. An isolated local diagnostic ran the existing Desktop candidate at
`20000:30000` with read-only root, dropped capabilities and owner-matched
workspace/output tmpfs: Xvfb started but Openbox exited with signal 11, then
the broker stopped. `getent passwd 20000` had no entry. A test-only derivative
adding that exact passwd/group entry, with the same run flags, stayed running;
the broker's signed-observation endpoint returned ready, PID 1 was the
expected executable and argv, and its Unix socket was mode 0600 owned by
`20000:30000`. This A/B result supports an NSS account dependency but is not
yet a full v2 media/input gate. The test container and diagnostic image tags
were removed. The candidate still cannot be admitted as a Phase 6 security
profile artifact; Browser requires the same identity treatment and its own
Chromium/CDP checks. Phase 6 remains **5/15**.

The separately signed Browser image was also run unchanged with effective
`21000:31000`, read-only root, dropped capabilities, no-new-privileges, its
locked Chromium seccomp, no network, and owner-matched workspace/output
tmpfs. Chromium stayed running as PID 1 and its loopback `/json/version`
returned HTTP 200, Chrome 151 and CDP 1.3. This narrow start/CDP probe is
evidence that the existing Browser image may support a high-UID runtime
override without new image bytes; it is not proof of `Browser.getVersion`,
Chromium sandbox integrity, restricted egress, session authority or the full
identity/recovery/cleanup gate. The test container was removed. Phase 6
remains **5/15**.

The existing restricted-network provisioner was also found to create a
separate egress gateway container for each Browser/Desktop allocation while
pinning every gateway to `65532:65532`. This is not the broker-in-parent
exception. Sandbox therefore approved a finite deployment-level slot model
with two distinct container identities per allocation (sandbox and gateway),
durable Provider reservation, and per-allocation container/network/process
observations in addition to the fixed service-principal inventory. The
static profile's `Principals` maximum of 128 and one-container-per-principal
observer cannot stand in for up to 1000 dynamic allocation slots; neither
1000-slot configuration expressibility nor 1000 live-container throughput is
currently demonstrated. Browser sandbox control was corrected from executor
backend to `provider-browser-runtime`; the dynamic slot/schema, driver
reservation and full gate remain to implement. Phase 6 remains **5/15**.

The closed profile now has an initial `sandbox_identity_slots` registry with
exact Browser/Desktop Provider owner, template digest and two distinct
workload/gateway UID/GID pairs per slot. It rejects missing/unknown templates,
executor ownership, owner/template digest drift, duplicate/unsorted slots,
root/out-of-range values, cross-slot and static-principal reuse, and an
implicit capacity clamp. Race tests pass. A unit-only bound check serializes
1000 Browser plus 1000 Desktop slots under the existing 2 MiB document cap;
it does not claim those containers or concurrent sessions ran. This is an
intermediate schema checkpoint: fixed sandbox records have not yet been
reclassified as dynamic templates, gateway image/security templates and the
durable reservation/observation chain remain absent. Phase 6 stays **5/15**.

An earlier Provider-private same-host file-lock reservation prototype passed
component tests, including two simultaneous test processes, but it is not
the approved production authority: distinct Browser/Desktop Provider UIDs
cannot share its owner-private directory. That prototype was retired rather
than wired into either runtime driver. It supplies no Slice 6 release-gate
evidence or claim that a real allocation used a slot. Phase 6 remains
**5/15**.

Sandbox subsequently ruled that the Desktop candidate must carry a canonical
finite build-time allowlist of supported workload UID/GID accounts. A single
candidate can cover multiple assigned slots; support in the image does not
authorize a Provider allocation. A closed 1..1000-account parser, canonical
private-file loader, allowlist digest and exact slot-pair matcher now pass
targeted race tests. The candidate build now embeds deterministic non-login
passwd/group fragments, verifies the canonical allowlist digest before final
scratch repack, and binds the digest and full account list in a new v3 local
candidate manifest. Historical Phase 5 source/image locks remain unchanged;
the previous Phase 6 v2 candidate does not qualify as a current v3 artifact.
The opt-in native arm64 Docker component test built twice without cache and
reproduced the image ID, then ran a second real container as `20000:30000`
with read-only root, dropped capabilities, NNP and owner-matched private
tmpfs. It verified account entries, UID/GID, mode-0600 broker socket and the
real v2 broker VP8 media/input path. This is a worktree component test, not a
clean committed source/candidate OCI record, full Provider allocation/egress
gate or immutable Slice 6 evidence manifest. Phase 6 remains **5/15**.

Sandbox ruled for globally disjoint profile-owned pools with each Provider
managing only its pool in its existing PostgreSQL transactional authority. A
neutral finite state model and PostgreSQL adapter now implement explicit
clean-authority initialization, atomic reservation before side effects,
exact retry, capacity, creating/active/cleaning fences, and exact-ticket
release. The adapter binds `current_database()` and `current_user` to its
trusted owner plan. A tagged real PostgreSQL integration created two separate
databases and runtime roles, revoked public database access, proved crossed
connections fail, raced reservations through two Provider handles, retained
unknown creation and failed cleanup, kept slow external checks outside the
global `control_state` row lock, and retained both pools across PostgreSQL
restart. These are component proofs; the integration's clean and absence
callbacks are test fixtures, not Docker observations or production bootstrap
authority. The production deployment's actual DB grants, driver wiring,
exact Docker absence checks, high-UID allocations and full Slice 6 gate are
still open. Phase 6 remains **5/15**.

The complete security profile now additionally binds each Provider owner to
its exact namespace/controller, PostgreSQL service identity and trust edge,
database, runtime role and existing purpose-bound DSN material ID. Projection
derives these values from the validated profile rather than accepting
caller-chosen database or role parameters. Both Provider-to-PostgreSQL edges
and their external CA mounts were added to the closed fixture; swapped owner,
role, controller, material, edge, service and duplicate authority records
fail targeted race tests. The PostgreSQL adapter also checks both
`current_user` and `session_user`, and runtime-role verification rejects
elevated role attributes and role memberships. This remains static/SQL
component evidence; it does not prove a live Provider-to-broker-to-PostgreSQL
deployment. Phase 6 remains **5/15**.

Following Sandbox's fixed-egress ruling, the complete profile fixture now
contains two distinct Provider-owned control-plane broker principals, each
with its own TLS agent, policy authority, internal/uplink networks, CA
consumers, role-to-broker mTLS edge and broker-to-PostgreSQL/DNS edges. Each
policy has only the one `postgres` alias. The Provider database binding
explicitly references that broker/policy/edge chain, and a neutral strict
PostgreSQL DSN parser is shared with the existing action-history witness
without enlarging the witness's 16-connection ceiling; Provider binding has
its separate 64-connection bound. Static profile and alias negative tests
pass. A not-yet-activated v3 Browser/Desktop Provider pool-construction helper derives its exact
owner, database, role, DSN binding and finite capacity from the complete
profile, constructs its own alias-only mTLS broker client and revocation
monitor, requests a fresh profile-validated client certificate from its own
workload TLS agent for each inner PostgreSQL TLS handshake, and replaces
pgx's DNS/dial/fallback path before pool construction. Every new or
reconnected PostgreSQL connection rechecks its actual database, session and
current role, role attributes/membership and minimal schema/table grants; an
existing pooled connection cannot be acquired when broker revocation
readiness is lost.
The helper additionally requires the owner-local ledger to have been
explicitly initialized; it never repairs a missing ledger or falls back to
the legacy direct-dial opener. Actual v3 Browser/Desktop startup refuses
before any database dial while the dedicated PostgreSQL certificate purpose
and Docker reservation chain are incomplete. Browser Provider's top-level
production composition remains disabled. Real two-database PostgreSQL integration now also checks
the non-elevated runtime-role query. This is code/component evidence only:
the separate broker/agent processes, PostgreSQL server-side client-certificate
requirement, exact client URI-to-SQL-role mapping, external certificate
revocation and real high-UID allocation/cleanup are not yet proven by a live
deployment gate. Phase 6 remains **5/15**.

The Sandbox architecture review selected a distinct PostgreSQL-client
certificate purpose and TLS-agent instance per Provider owner. PostgreSQL 16
matches client certificate CN (or mapped DN), not URI SAN, while the existing
workload certificate has an intentionally empty Subject. The inner TLS helper
now rejects that ordinary certificate and requires the separate client
purpose, exact runtime-role CN, owner URI SAN, client-auth-only EKU,
profile-pinned PostgreSQL issuer CA, and a live P-256 signer challenge before
pool construction and on each TLS handshake. Browser/Desktop v3 process
configuration has a distinct PostgreSQL signer socket and UID/GID, and the
pool helper checks it against the complete profile. Actual PostgreSQL
`hostssl` evidence was still missing at this increment; the early startup
refusal remains. No shared-purpose exception or authorization claim is made. Phase 6
remains **5/15**.

The repository-private certificate protocol now has a separate
`postgres-client-certificate.v1` domain and a closed identity validator.
It requires a CN exactly equal to the profile-bound unique SQL runtime role,
exact owner URI SAN, P-256 key, client-auth EKU, digital-signature use, and no other Subject or
SAN values. The ordinary v1 protocol still rejects nonempty Subject; signed
request/response downgrade tests and an agent-generated PostgreSQL CSR/leaf
test pass under the race detector. The certificate controller now validates
the returned leaf against the signed request and closed policy before writing
its ledger, revoking a wrong-purpose result; it no longer relies solely on
the Vault adapter for this check. The complete profile now separately binds
two PostgreSQL-only agents, their issuer policies and Vault roles, distinct
keys and sockets, CNs and a dedicated client CA artifact mounted only to the
two Provider owners. The TLS-agent and certificate-controller commands
require purpose-specific configuration and an exact inventory of the two
additional policies/listeners; omission and cross-purpose substitutions fail
targeted tests. The tagged pinned Vault container test now proves a dedicated
PostgreSQL client PKI mount and restricted issuance token can issue the exact
role CN/owner URI/client-auth leaf, refuse alternate CN and URI CSRs, publish a
revocation in its CRL, and clean up the container. Vault's real leaf omits a
Basic Constraints extension; admission checks non-CA status and the pinned
chain, not an extension-presence assumption. A real PostgreSQL 16.15 HBA
test exposed an incompatible premise in the prior architecture ruling:
`scram-sha-256 clientcert=verify-full map=...` is rejected at server startup
because `map` is not an option for SCRAM authentication. Sandbox corrected
the decision to require certificate CN exactly equal to the profile-bound
unique runtime role, with SCRAM-SHA-256 and
`clientcert=verify-full clientname=CN`, without a `pg_ident` map. The pinned
PostgreSQL 16.15 Docker gate now derives the anticipated Docker bridge source
before startup and starts with the profile-rendered restricted `/32` HBA. It
rejects a mismatch between that approved CIDR and PostgreSQL's observed
client address, and checks the raw HBA/client-CA bytes,
read-only configuration volume and server file settings, compares the complete
ordered `pg_hba_file_rules` projection to the controlled HBA document, and
proves both Browser and Desktop certificate-plus-SCRAM
logins. A second real Docker client with the same valid Browser certificate
and SCRAM password, but an unapproved source address, is rejected by the
final HBA catch-all; its container is removed and absence-checked. A
successful same-target control precedes missing-certificate,
wrong-CN, ordinary empty-Subject, wrong-issuer, wrong-purpose, cross-owner,
cross-database and wrong-password refusals with checked failure reasons.
`pg_hba_file_rules` describes the current disk file, not necessarily the last
HBA loaded by PostgreSQL; successful reload and new positive/negative
connections are separate observations. The test also substitutes a malformed
on-disk HBA: the file view reports an error and `pg_reload_conf()` returns
true, yet new connections still follow the previously loaded approved rule.
After restoring and reloading the approved bytes, positive and
unapproved-source negative connections pass again. This explicitly prevents
treating a changed file view or reload signal as proof of active policy. No
temporarily broad accepting HBA is used at startup.
The real container is then restarted; the gate rechecks its read-only mount,
actual HBA/CA raw bytes against the profile policy and dedicated CA digest,
complete parsed file, both role logins and unapproved-source rejection. The
raw-artifact validator independently rejects one-byte HBA or CA drift. Docker
Desktop may briefly refuse the published TCP port after Unix-socket readiness;
the test retries only that transport error for a finite window and fails
immediately on authentication or HBA errors.
PostgreSQL does not inspect the owner URI SAN; the local closed certificate
validator separately rejects wrong-URI material. This is a component gate,
not a deployed Provider-to-broker-to-PostgreSQL path. No actual combined
certificate-controller/agent process, runtime rotation, revocation drain,
broker transport or six-role gate has passed.
The early v3 startup refusal remains. Phase 6 remains **5/15**.

The repeatable component commands are:

```bash
SANDBOX_RUNTIME_POSTGRES_CLIENT_VAULT_INTEGRATION=1 mise exec go@1.26.8 -- env -u GOROOT go test -tags=integration -count=1 -run '^TestVaultPostgresClientPurposeIntegration$' -v ./internal/workloadpki
SANDBOX_RUNTIME_POSTGRES_CLIENT_HBA_INTEGRATION=1 mise exec go@1.26.8 -- env -u GOROOT go test -tags=integration -count=1 -run '^TestRealPostgresRequiresExactClientCNAndScramRole$' -v ./internal/phase6egress
```

The complete security profile now has one Provider-database-only PostgreSQL
server-authentication policy referenced by both Provider database bindings.
It binds the exact PostgreSQL service identity, controlled HBA artifact ID and
raw-byte digest, existing dedicated client-CA anchor, and a canonical
approved ingress CIDR. The closed renderer emits one ordered HBA containing
local operator peer access, both Provider-specific SCRAM + exact-CN client
certificate rules, and IPv4/IPv6 rejecting catch-alls. Cross-reference,
digest, service, CA, CIDR, database and role drift fail profile tests. The real
PostgreSQL component test now uses that renderer for its final restricted HBA;
it separately checks the actual read-only volume, raw HBA/CA bytes, server
file settings, parsed file and new positive/negative connections. This
provider-only scope does not authorize or prove Product or other PostgreSQL
roles on a shared instance. The final deployment gate must either accurately
expand the complete service rule inventory or use an explicitly separate
PostgreSQL instance; it may not silently drop existing role access or add a
broad fallback. There is still no full broker path or Slice 6 evidence.

The existing Slice 6 evidence schema now requires its PostgreSQL external
record to cross-bind the complete profile digest, the single HBA artifact and
raw-byte digest, the existing client-CA artifact and bundle digest, and the
approved ingress CIDR. It also requires digest references for raw receipts of
the read-only mount, server file settings, ordered file parser result,
controlled startup/reload, new connection outcomes and restart
reconciliation; unrelated external services cannot carry this proof. The
verifier checks exact profile agreement and refuses omitted or substituted
receipts, but cannot manufacture or authenticate their observations. No
Slice 6 manifest has been emitted.

Current Desktop candidate admission now compares actual digest-verified OCI
`/etc/passwd` and `/etc/group` against every allowlisted workload account,
rejecting missing, duplicate and additional high identities even when the
manifest and image label agree. The native arm64 tagged integration rebuilt a
real candidate and confirmed one filesystem layer plus BuildKit's 32-byte
empty layer; the verifier accepts only a bounded empty-layer extension, then
passed actual NSS inspection. The test image and observation container were
removed. This still is not a clean committed candidate record or a Provider
high-UID allocation/cleanup gate. Phase 6 remains **5/15**.

The restricted-network Docker core and both Browser/Desktop adapters now
carry an optional private identity slot, selecting the slot's gateway UID/GID
for Docker `Config.User` while keeping the signed gateway image's default
`65532:65532` unchanged. The core labels all four workload/gateway numbers
and slot ID, reconstructs them canonically during replay/inspect/release, and
rejects malformed slots, changed slot, noncanonical labels and user drift.
`TestGatewayReservedSlotDocker` built the gateway image from the pinned
Dockerfile, used its actual immutable local image ID
`sha256:4ad516aa5075855897ab937e448561d843eb3fcc5f6b7d2393139b324ccd558f`,
started a real isolated Docker network and gateway, observed the live gateway
process as UID/GID `20001:30001`, proved exact replay/cross-slot refusal, and checked
container plus internal-network absence after release. The first attempted
run mistakenly supplied BuildKit's config digest rather than Docker's actual
image ID and failed closed at image admission; the corrected run passed with
the final UID assertion. This is disposable local component evidence only:
no Provider PostgreSQL reservation is consumed by this gateway-only test, no
complete process graph or manifest exists. The v3
Provider remains disabled and Phase 6 remains **5/15**.

```bash
SANDBOX_RUNTIME_GATEWAY_SLOT_INTEGRATION=1 \
SANDBOX_RUNTIME_GATEWAY_SLOT_IMAGE=sha256:<actual-local-image-id> \
mise exec go@1.26.8 -- env -u GOROOT go test -tags=integration -race -shuffle=on -count=1 \
  -run '^TestGatewayReservedSlotDocker$' ./provider/network/restricted/docker
```

Sandbox then located the reservation CAS in a thin Provider application
coordinator rather than the Docker adapter. The adapter is slot-aware but has
no database authority; the coordinator must commit Reserve and win
BeginCreate before calling it, preserve ambiguous Creating, reconcile from
PostgreSQL first, and only release Cleaning after exact absence. This is an
architecture ruling, not a claim that the coordinator exists yet.

`TestBrowserImageHighUID` ran the locked published Browser image under
`20000:30000`, original seccomp, read-only root and dropped capabilities;
private CDP and the sandboxed zygote process tree were observed, with every
process at the assigned UID/GID. The Browser Docker adapter now projects
pure spec digests for every profile-projected slot, validates a Creating
ticket's plan/slot/claim/spec before side effects, and uses its workload
UID/GID for container creation and CDP relay exec. In bound mode bare legacy
runtime methods are refused; Active-ticket Observe/Attach recheck exact local
state. Fake-engine tests cover invalid ticket zero side effects and Creating
replay refusal. `TestBrowserBoundSlotDockerIntegration` then ran a real
Browser-plus-gateway topology with a fixture ticket: Browser process/relay
at `20000:30000`, gateway at `20001:30001`, real CDP Browser.getVersion,
Creating replay rejection, and exact test-owned container/network absence.
The fixture ticket is not a PostgreSQL reservation; cleanup was done by the
test harness because a production bound cleanup/absence checker and
application coordinator are still missing. No Slice 6 manifest or readiness
claim is emitted; Phase 6 remains **5/15**.

```bash
SANDBOX_RUNTIME_BROWSER_HIGH_UID_INTEGRATION=1 \
mise exec go@1.26.8 -- env -u GOROOT go test -tags=integration -race -shuffle=on -count=1 \
  -run '^TestBrowserImageHighUID$' ./profiles/browser/image
SANDBOX_RUNTIME_BROWSER_BOUND_SLOT_INTEGRATION=1 \
SANDBOX_RUNTIME_BROWSER_GATEWAY_IMAGE=sha256:<actual-local-image-id> \
mise exec go@1.26.8 -- env -u GOROOT go test -tags=integration -race -shuffle=on -count=1 \
  -run '^TestBrowserBoundSlotDockerIntegration$' ./provider/browser/driver/docker
```

The next combined real-PostgreSQL/real-Docker attempt initially failed on a
newly observed post-cleanup replay: the old Browser Claim could Reserve the
freed identity slot and even create a second container. The test-owned
containers, networks and database were removed by their exact namespace
cleanup, and Docker inventory was independently checked empty. This failure
was not counted as a passing gate. Sandbox chose the existing Provider Browser
session authority, not a second tombstone ledger, as the durable replay
boundary. The Browser-bound repository now checks the exact session and
sandbox fence atomically with Reserve and BeginCreate, writes a full-claim
retirement into the existing Browser session state with BeginCleanup, and
rechecks it with CompleteCleanup after external absence. The generic pool
repository cannot satisfy the Browser production coordinator port.

`TestBrowserBoundPostgresDockerIntegration` subsequently passed with two
independent runtime PostgreSQL pools, a real persisted Browser open record,
concurrent allocation from those pools with exactly one observed Docker
`AllocateBound` dispatch,
actual Browser `41000:51000` and gateway `43000:53000` process identities,
CDP Browser.getVersion, read-only Active retry, coordinated exact cleanup,
PostgreSQL restart with new mapped-port discovery and reconstructed Provider
pool/network/Docker adapters, injected post-commit cleanup response loss followed by
post-restart exact finalization from the existing Browser retirement record,
replay rejection before any new Docker side effect, and a distinct authorized
session reusing the released UID. Retrying the old cleanup after that reuse
left the new Browser running. The first restart test incorrectly retained
Docker's old mapped host port and was terminated after it could not reconnect;
the exact disposable database/uplink were removed. The corrected fresh-pool
restart test passed and its Docker inventory is empty. This is a local
component-composition gate, not the complete role/broker/issuer deployment
topology. Creating uncertainty, cancellation/drain races, Desktop integration
and Slice 6 evidence remain open. Phase 6 remains **5/15**.

The separate real-PostgreSQL finite-pool gate now also holds the external
absence callback at a deterministic barrier: another runtime pool can read
without a long Docker lock, but Reserve cannot reuse either the Cleaning or
unresolved Creating slot and a stale BeginCreate cannot cross the Cleaning
CAS. Only after CompleteCleanup does the exact UID become reusable. This is
state-machine/transaction evidence with a test-only absence callback, not a
second real-Docker cleanup or an authorization gate for the generic pool.

Checkpoint 2026-09-27 (never-dispatched Browser reservation): a terminal
Browser session with no allocation can now retire an exact still-`Reserved`
UID ticket in the same PostgreSQL transaction as the existing Browser session
authority. Because `BeginCreate` is the sole first-side-effect permit under
that row lock, the transaction can release this UID without inventing a
Docker receipt. It retains a full-claim, released, `never_dispatched`
retirement in the existing session state, rejects old-claim replay, and does
not retire `Creating`, `Active` or `Cleaning` on missing-receipt inference.
`Cancel` and terminal `Recover` invoke the path; an unknown `Creating` result remains
held for explicit quiescence reconciliation. The tagged real
PostgreSQL-plus-Docker test now first reserves and retires such a terminal
session, verifies zero Browser Docker dispatch, then reuses the exact UID
for the normal high-UID Browser/gateway flow. Focused race tests and this
tagged gate passed. This narrows a capacity leak; it is not the complete
Slice 6 deployment/evidence gate. Phase 6 remains **5/15**.

Checkpoint 2026-09-27 (known-finished Browser dispatch): the bound Browser
driver now fsyncs a full claim/slot/plan/spec/receipt completion record only
after its sole `AllocateBound` invocation has returned from all synchronous
network, Docker and CDP readiness work. A `Ready` bit without this later
record is explicitly insufficient. The Provider coordinator can read-only
verify that exact completed dispatch and move its existing `Creating` CAS to
`Active` after a pre-commit PostgreSQL failure, without dispatching again.
For an already terminal Browser session with no attached receipt, the same
completion proof allows the application to commit the known result and enter
the ordinary fenced exact cleanup path; it does not restore end-user access.
Focused race tests use an in-flight barrier to reject takeover; the real
PostgreSQL-plus-Docker gate tests both live and terminal pre-commit failure
and verifies no duplicate Docker dispatch. Unknown external outcomes without
the fsynced completion proof remain `Creating`, not retried or released.
The tagged gate also injects a lost cleanup-commit response for a terminal
session, then uses only the existing PostgreSQL `Released` retirement to
finalize its local tombstone and repeat the operation idempotently.
This is not automatic recovery for that unknown case. Full process-crash,
quiescence and Slice 6 deployment evidence remain open at **5/15**.

Checkpoint 2026-09-27 (Desktop identity transaction foundation): following
Sandbox's ruling, the existing Desktop session state now retains an exact
source-Open identity retirement; a Close operation does not reserve a second
UID. A Desktop-bound PostgreSQL adapter composes the current Desktop session,
finite slot and initialized marker under one Provider row lock for Reserve,
BeginCreate, known CompleteCreate, Close-authorized BeginCleanup and exact-
absence CompleteCleanup. Unknown absence does not release the slot; released
retirement rejects old Open claim replay. A real disposable PostgreSQL gate
with separate Browser/Desktop databases and runtime roles verifies the
source-Open Close linkage, CAS sequence, withheld absence, released proof and
UID return. This gate's absence callback is test-only; no Desktop Docker or
media/broker session was exercised by it. The Desktop bound driver,
application, mux and distinct-process v3 graph remain unimplemented and
startup remains closed. Phase 6 remains **5/15**.

The Desktop candidate driver now also has a profile-bound constructor and
pure per-slot spec projection. In bound mode its old bare `Allocate` rejects
before any network/Docker call, and unit tests check distinct high-UID spec
digests and zero side effects. No ticket-accepting Desktop dispatch method is
yet exposed, so this is an admission guard, not the Desktop runtime gate.

```bash
SANDBOX_RUNTIME_BROWSER_BOUND_POSTGRES_INTEGRATION=1 \
SANDBOX_RUNTIME_BROWSER_GATEWAY_IMAGE=sha256:<actual-local-image-id> \
mise exec go@1.26.8 -- env -u GOROOT go test -tags=integration -race -shuffle=on -count=1 \
  -run '^TestBrowserBoundPostgresDockerIntegration$' ./provider/browser/driver/docker
```

### 2026-09-27 Provider v3 composition checkpoint and remaining gate

Implementation revision `11b424b054d1e8fd48be851fae4445519457e0ab`
is a clean local checkpoint, not a Slice 6 release revision. The `provider
serve` command now permits only Browser v3 `production` and Desktop v3
`local_candidate` in addition to the existing coding-shell route. Before the
first material-registry or database/broker dial, it checks the complete signed
profile, peer-CRL role document, per-owner PostgreSQL signer/slot projection,
Contract/private/attach edges, pinned Browser image, and Desktop candidate
source, platform, archive and workload-account coverage. Browser and Desktop
then use their real separate compositions; Browser/Desktop v3 use only the
profile-bound PostgreSQL broker and independent client signer, never the
historical direct-DSN fallback. Desktop v3 `production` is rejected at both
command and composition boundaries. The v3 protected transport stays closed
until its readiness checker is bound and thereafter requires live database,
TLS/CRL, material, identity runtime, mux and executor-backend readiness.
Constructor failure closes acquired monitors, transports and servers.

The exact arm64/v8 Desktop local candidate built from that clean checkpoint
has image digest
`sha256:0afbca02f5be4990ab0c516b52aac47ddaa7a2ec7fb1e3a8b9494b24013b597f`
and canonical candidate manifest digest
`sha256:b3dc58de944cfed64e9f025eac120a6068770c7f629ccaa8ba6194fa7a00459d`.
Root race/shuffle, vet and both Contract verifiers pass. The candidate's
tagged, race-enabled real Desktop PostgreSQL + high-UID Docker/egress test
and broker mux → executor → RTP/input/close tests pass. The real Browser
PostgreSQL + high-UID Docker/egress test also passes as a separate component
gate. These
tests do not start the complete Provider/Gateway/Product/Guest/Browser/Desktop,
action-ingress, controller/agent/broker, Vault and external-service graph
under one security profile or exercise its 16 frozen fault scenarios. No
Slice 6 success manifest exists, no remote push has occurred, and the phase
remains **5/15**.

The old “six-process” shorthand is insufficient for this gate. The complete
profile's actual principal, process, in-container broker, dynamic sandbox,
external-service and network inventories are the acceptance scope. Existing
Slice 4/5 host-process/static-TLS or Guest-fixture tests cannot be relabeled
as Slice 6 observations. The table below maps every frozen scenario in
`internal/phase6security/slice6_evidence.go` to the real edge, reusable
component starting point and still-missing same-run assertion. Reusable
components are not substitute evidence; the new harness must execute its own
one-run observations, fail on any missing row, and retain raw private receipts.

| Frozen scenario | Real edge / principals | Existing starting point | Missing same-run assertion |
| --- | --- | --- | --- |
| `browser_cdp_and_capacity_replay` | Browser Provider → Browser role → executor backend → mux → high-UID Browser | Browser bound PG+Docker and executor-v2 component gates | Live v3 attach/CDP, capacity and exact replay rejection with one allocation ledger |
| `browser_external_witness_isolation` | Gateway → action ingress → separate action-history PostgreSQL and capacity Valkey | Action-ingress command, fixed-alias clients and witness-role guard | Real external identities, isolated grants/restore domains, no bypass path |
| `cross_role_and_tenant_denial` | Gateway and distinct coding/Browser/Desktop Provider private edges | Closed profile selectors and protected admission | Wrong role, route, client certificate and tenant rejected on live listeners |
| `desktop_media_input_and_cleanup` | Desktop Provider → Desktop role → executor backend → mux → in-sandbox broker | Desktop bound PG+Docker and real RTP/input component gates | Same-run v3 open/media/input/close, broker process proof and exact zero dynamic resources |
| `direct_egress_and_metadata_denial` | Product → its dedicated broker; all role-internal networks | Docker isolated-network probe and broker policy | Actual Product/container direct-IP, DNS and metadata bypass denial |
| `dns_rebinding_and_alternate_path_denial` | Product broker → pinned external DNS/service edge | Fixed-alias and network-policy tests | Live rebinding/alternate endpoint denied with controlled DNS observations |
| `external_dependency_loss` | Action ingress → Valkey and action-history PostgreSQL | Witness and broker client components | Loss closes ingress/action readiness; bounded recovery only after exact service return |
| `guest_auth_and_reconnect` | Guest → Product private `/agent` Hub and Product PG binding | Product/Guest commands and Guest protocol components | Real hello/challenge/signature/welcome, business revoke, DB/CRL loss and upgraded drain |
| `least_privilege_active_probes` | Product/Gateway plus every profile-owned role/container | OCI, Docker network/port and in-container observation validators | Actual UID/GID, seccomp, capabilities, mounts, writable paths and resource limits for full inventory |
| `mtls_identity_and_downgrade_denial` | Gateway → coding Provider Contract/private edge | Live signer/peer-CRL transport components | Wrong identity, plaintext and legacy/static downgrade rejected on real edge |
| `policy_authority_loss_and_revocation` | Product egress broker ↔ dedicated policy-state authority | Real authority-process Docker component gate | Real role traffic denied on authority loss/revocation, recovered only with fresh state |
| `provider_and_executor_restart` | Three Providers and Browser/Desktop executor backends | Browser/Desktop bound recovery and Slice 5 process lifecycle patterns | New OS-process identities, retained authority, bounded reconnect and no stale admission |
| `resource_exhaustion_denial` | Product/Gateway protected ingress and all bounded executors | Config/capacity unit and Slice 5 process patterns | Saturation denied within limits without unbounded worker/resource growth |
| `revoked_leaf_and_crl_rollback_denial` | Gateway ↔ Provider live TLS/CRL; controller → agent source | Peer-CRL guard and handshake components | Real Vault revoke, active drain, stale/recovered source and rollback rejection |
| `role_and_controller_drain` | Browser/Desktop roles and certificate controller | Executor drain and controller components | SIGTERM/cancel bound, active connection close and exact lease/socket cleanup |
| `vault_pki_rotation_and_loss` | Vault PKI → credential/certificate controllers → role TLS agents | Vault PKI and live TLS component tests | Same-run issue/overlap/rotation/loss/restart with distinct owner certificates and no stale admission |

The harness is still an implementation task, not merely a test invocation.
Its first milestone is one profile/runID/source-bound disposable topology with
real commands, constrained materials and basic authenticated traffic; then
the full role/container/edge inventory and the 16 negative/fault assertions.
Only a complete single run with independently observed zero-resource cleanup
may produce and verify the strict Slice 6 manifest. Until then, do not push
or count Slice 6 as closed.

The first harness increment exposes the verifier's scenario/participant list
as a copied, read-only API and checks an exact route/assertion plan under the
separate `phase6slice6gate` tag. Its opt-in preflight requires a canonical
private full profile, a clean exact source revision, the matching verified
Desktop candidate/archive and all named local role images already loaded; it
does not run a release scenario or write evidence. A candidate-only local
role recipe builds actual repository commands from Go 1.26.8 and a pinned
base with Docker build networking disabled. Its first real high-UID command
smoke is a component check; the final gate must still retain and independently
verify each candidate's raw OCI archive/descriptor chain, then observe the
running containers and complete all 16 scenarios in one run.

Checkpoint `ef071f1` extends that component smoke: a clean, source-bound
`core` role image actually runs the repository command under `21001:31001`,
read-only root, no network, all capabilities dropped, no-new-privileges and
bounded memory/PIDs. A separate same-policy container reports the effective
UID/GID. The test independently saves the local OCI archive, reads raw
store/selected-manifest/config bytes and every ordered layer/diff ID, and
matches them to Docker's stopped-container selection before exact test
container cleanup. The role image is local-only and not published. A separate
Browser executor image was built from the same recipe; invoking it without
its private authority correctly fails closed, so this is not an executor
service-start or attach result. The Vault PostgreSQL-client-purpose test
passed with wrong-CN/URI denials, and the controlled PostgreSQL HBA test
passed exact CN/SCRAM/source grants and wrong-issuer, wrong-purpose,
cross-owner/database, missing-cert and wrong-password denials. The real Vault
workload TLS bootstrap/revocation component test also passed. These are
different disposable component runs, not spliceable Slice 6 evidence. No
complete real-command topology, retained raw same-run receipts or release
manifest exists; Phase 6 remains **5/15**.

Next gate-infrastructure increment (not acceptance): loaded local images in
the opt-in preflight are now checked against the profile's exact Docker store
ID, Linux platform and OCI descriptor kind/digest, instead of merely requiring
that `docker image inspect` returns some ID. Negative tests reject a wrong
store ID, descriptor, platform, object kind and ambiguous inspection. A
separate opt-in real-Docker resource-ledger component uses a fresh random
128-bit run label, runs a source-bound high-UID repository command on an
internal network, and re-discovers then removes only exact run-labeled
containers/networks/volumes. It checks the final three Docker classes are
empty. The component deliberately discards the returned IDs of a second
created network/container, then checks label re-discovery and cleanup; this
simulates a lost create receipt after the daemon committed the side effect,
but not an actual network timeout. This still has no authenticated
Product→Gateway→Provider chain,
Vault-issued live topology, same-run 16-scenario observations, retained
non-Docker cleanup receipts or success manifest. The phase stays **5/15**.

Sandbox resolved the same-run evidence question: internal Slice 6 evidence
version 2 now requires a 128-bit canonical `run_id` and a digest of a private
receipt index. The bundle verifier reads every run-generated digest reference
from the manifest, requires a unique matching index entry, opens bounded
mode-0600 raw bytes and a companion canonical envelope, recalculates both
digests and checks run/profile/config/source/type/subject identity. Cleanup
receipts additionally carry the same ownership run ID and a zero remaining
resource inventory. Scenario raw results must name the exact frozen assertion
set and participants, not merely a generic `passed` flag. Tests reject
cross-run substitution even after rewriting
the envelope and index, wrong subject/config, raw tamper, duplicate/orphan
reference, missing file, public mode, traversal, unreviewed assertions and
wrong-run cleanup. Local
candidate build/archive and source digests remain pre-existing immutable
inputs; no new build is implied by a new run ID. This is a verifier/component
checkpoint, not an observed Slice 6 success bundle. It cannot independently
prove command execution or resist rewriting by an actor who owns all files.
The trusted full-topology harness, all 16 live scenarios, and complete exact
cleanup are still absent. Phase 6 remains **5/15**.

Next capture increment: the one-run recorder now creates only a fresh private
bundle, durably writes each raw observation and companion envelope once,
rejects cross-run and duplicate logical keys, and refuses to write a manifest
until the complete run-generated digest set is recorded. Its finalization
reopens the entire bundle through the independent verifier. A unit-only
synthetic complete bundle proves writer/verifier agreement; an incomplete
fixture proves no manifest is written. This does not create live execution
provenance or close the missing full-topology gate. Phase 6 remains **5/15**.

The next real-Docker network component creates an `isolated` internal bridge
and a separate NAT uplink bridge with exact profile names, subnets and gateway
modes. It re-reads raw Docker network inspection rather than inferring the
result from create replies, then observes a running disposable container's
actual endpoint and rejects an undeclared second member. A fresh random run
label permits exact container/network cleanup even if returned IDs are lost;
the component verifies no run-owned Docker resource remains. The disposable
Alpine processes do not execute repository role commands, and this does not
prove protected-role direct-egress denial, the ingress relay, egress broker,
Vault PKI, the complete inventory or any same-run scenario. No Slice 6
manifest was emitted; Phase 6 remains **5/15**.

Sandbox's profile-supply ruling selects a repository-owned reviewed desired
inventory and a reproducible local generator, not an externally supplied
complete profile. Controlled Vault/external/empty-network bootstrap and actual
immutable image/issuer resolution precede canonical profile freeze; no
application role starts under a permissive interim profile. The independent
observer later reads actual Docker, process, TLS, PostgreSQL and request
results. A changed expected rule ends that run and requires a new full run.
The first inventory module fixes the exact approved deployment set, every
reviewed shared/dedicated network edge and deterministic `172.31.0.0/16`
allocation into /24 networks. It also fixes distinct non-root container
UID/GID partitions by approved deployment name; dynamic sandbox account slots
still require their separate image-account allowlist gate. Slice 6 preflight
now rejects a profile that changes the network graph, CIDR plan or static
UID/GID mapping even if its internal profile digest is updated. A deterministic
endpoint planner assigns declared members addresses before launch; its
comparison helper rejects a post-hoc observed IP, but the full-role runner
still must actually start each role at that address and retain raw inspect.
The source-bound core command's Docker ownership smoke now uses the reviewed
Provider role network, its planned IP and its exact static UID/GID pair rather
than an unrelated high-UID/random-network combination. It still invokes a
short `--help` command, not an authenticated Provider service chain.

The next generator module freezes all 77 trust edges, including 17 local
numeric mTLS targets, external destinations and Unix peers, by exact
source/target, route, port, protocol, anchor, tenant scope and lifetime. The
network binder deterministically assigns each target's planned IP, rebinds
both ingress frontend/upstream addresses, recomputes ingress digests and
revalidates the canonical profile without mutating its input. A changed
network kind, local edge lifetime or external Vault edge lifetime is rejected
even with a recomputed profile digest. The reviewed ingress rule also fixes
loopback host ports and limits, rejecting a self-consistent changed host
publication or relay frontend IP. The positive fixture still has synthetic
identities and artifacts; this module does not author a real full profile,
launch a listener or observe a handshake. External-service and Unix peer edges
still require live capture. Phase 6 remains **5/15**.

An additional preflight comparison now requires every one of the 17 local
numeric targets to equal the preplanned IP of its declared recipient, not just
an arbitrary address inside the correct /24. An internally valid profile with
a changed Product→Provider target IP is rejected after its digest is
recomputed. This remains desired-configuration enforcement; actual container
IP and mTLS connection evidence must still come from the live run.

The next preflight increment freezes the five external-service names, SPIFFE
URIs, DNS SANs and permitted inbound trust-edge IDs. A profile with a rewritten
Vault identity and SAN, including recomputed external/edge/profile digests,
remains generically valid but fails this reviewed inventory check. This does
not verify an OCI descriptor, run Vault or observe a certificate handshake;
Phase 6 remains **5/15**.

The five local egress policies are now checked against reviewed role/broker/
authority ownership, exact alias destinations, socket/ledger mount identities
and refresh/lease limits. A self-consistent new Product destination or longer
lease is refused. Actual key material, DNS answers, broker reachability,
revocation and ledger recovery still require the real gate.

Sandbox ruled out provisioning a new public fixture as the default. The
Product positive-control alias now names the existing public Docker Registry
HTTPS API for a minimal unauthenticated `GET /v2/`; it is a third-party
reference endpoint, not a run-owned image or server. One bounded local check
with `dig @1.1.1.1` returned `198.18.0.32`; `netpolicy` explicitly blocks
`198.18.0.0/15`. Sandbox then obtained genuine public A records through
authenticated DoH and a strict TLS 1.3 `GET /v2/` response from the real
Registry on the host; this disproves a blanket claim that the host has no
safe public route, but is not Product→broker gate evidence. The first
opt-in wireformat DoH bootstrap diagnostic fetched A and AAAA successfully,
then correctly refused their combined 16-address answer against the reviewed
`DNSMaxAnswers=8` limit (minimum TTL 33 seconds). Sandbox then reviewed and
approved `DNSMaxAnswers=16` for the Product policy only; the other four remain
at 8 and the general 32-answer ceiling is unchanged. Product has only one
approved alias, `registry-probe`, so this policy-level change does not expand
an additional Product destination. Netpolicy and real broker fixtures show 16
public answers can proceed, 17 answers or a forbidden mixed final address
cause zero numeric dials, and cancellation shares one deadline. The opt-in
real DoH diagnostic then passed with 16 public answers and a minimum TTL of
12 seconds, retaining both raw-response digests in its test log. No answer
was truncated or reclassified, and this is not a Product→broker→Registry
live scenario. The positive egress gate is still open, not skipped or counted.
The trust-anchor layout is now separately checked against five reviewed names,
purposes, operator artifact IDs, mount locations and consumer sets. Real CA
bytes and issuance remain unproved.

An additional reviewed TLS-identity verifier fixes each static deployment's
SPIFFE URI, permitted DNS SAN/EKU, certificate TTL, rotation overlap,
revocation staleness and drain bound. A recomputed profile with a changed
Product SAN or lifetime fails. It does not issue or observe a certificate;
Phase 6 remains **5/15**.

The reviewed image-source inventory now maps all 58 deployments to their
corresponding executable build targets; an unreviewed principal cannot inherit
`core`, and a static role cannot substitute a registry image for a current-
source local candidate. Preflight inspects each local principal, even when
several share one cached Docker image inspection, and rejects missing or
incorrect source-revision/target/toolchain labels. Desktop retains its
separate current-source candidate manifest. Per Sandbox confirmation, Browser
**sandbox** reuses the exact previously signed GHCR publication and original
source/provenance identity; the current Browser role, Provider and executor
programs do not. Profile admission binds the complete Browser registry
repository and index digest, platform and selected manifest; preflight refuses
Docker store ID, repository, platform or descriptor substitution. This is an image
input check, not a fresh signature verification, container/runtime observation
or complete OCI archive chain. The full 58-deployment topology, 16 scenarios,
same-run evidence and exact cleanup remain open. Phase 6 remains **5/15**.

A separate read-only verification of that reused publication fetched the raw
OCI index by its immutable GHCR reference. Its SHA-256 matched
`87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`,
and it listed exactly the locked `linux/amd64` and `linux/arm64/v8` selected
manifests. `gh attestation verify` accepted one SLSA provenance attestation
with the exact repository, signer workflow, historical source commit and
hosted-runner restriction; its subject digest matched the same index. This
reconfirms the input publication only. No Slice 6 container selected-manifest,
effective UID/CDP/slot, network, or cleanup observation was produced by it.
The diagnostic used these exact read-only inputs:

```bash
docker buildx imagetools inspect --raw \
  ghcr.io/shell-echo/sandbox-runtime-browser@sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f
gh attestation verify \
  oci://ghcr.io/shell-echo/sandbox-runtime-browser@sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f \
  --repo shell-echo/sandbox-runtime \
  --signer-workflow github.com/shell-echo/sandbox-runtime/.github/workflows/browser-image.yml \
  --source-digest 58ed0093816d3daa3000750013b8e5991ef4bcf7 \
  --deny-self-hosted-runners --format json
```

The unpublished Slice 6 evidence v2 nonclaim now says
`complete_application_image_publication_and_signing`: the complete topology
has not passed publication/signing qualification. It no longer risks being
read as denying the exact Browser sandbox publication above. The obsolete
ambiguous value is rejected; historical Slice 4/5 evidence is unchanged.
The local-role Docker-inspect preflight is now a reusable strict security
check rather than a test-only label helper. It checks source/target/toolchain
labels, exact descriptor and platform, fixed executable entrypoint and
non-root default user, while retaining the separate raw OCI/runtime proof
requirements. Neither change supplies missing live Slice 6 receipts.

A reusable local-role candidate probe now composes the private re-importable
OCI archive reader, original-byte descriptor and layer checks, Docker's
container-selected manifest and image inspection, and a separate full archive
digest/rootfs-chain digest. The probe intentionally uses a stopped run-owned
container before profile freeze; it cannot be reused as the final running
role observation. Build-context-to-image binding and all actual-role
observations still need the complete gate.

The next source-input increment binds every local candidate evidence row to
the reviewed executable `build_target`; a shared image digest cannot silently
serve two different target binaries. It also adds independently recomputable
clean-checkout inputs for current-source role builds: HEAD and byte-exact
committed tree, Dockerfile, build script, `go.mod`/`go.sum`, fixed base digest,
build parameters, Go 1.26.8 compiler/linker executables and standard-library
source. `VerifySource` re-derives these from disk rather than trusting receipt
strings. A retained candidate record and full topology are not yet complete,
so this remains a component boundary and Phase 6 remains **5/15**.

At clean source revision `b105a6c2eb63731e4feb75a4c2c4e2f3557821cb`,
the opt-in native Docker core-candidate test rebuilt the current role image,
saved its private OCI archive, verified
the selected manifest/config/ordered layers, and independently ran the same
fixed Go build from the clean source inputs. The rebuilt binary bytes matched
the regular executable extracted from the verified image layer; the high-UID
role entrypoint ran and the test-owned containers were removed. Negative unit
cases reject a replaced layer path, whiteout, symlink, duplicate, wrong mode,
and missing executable. The exact command was:

```bash
SANDBOX_RUNTIME_PHASE6_LOCAL_ROLE_INTEGRATION=1 \
go test -tags=integration -race -count=1 \
  -run '^TestLocalCoreCandidateRunsAsHighUID$' -v ./profiles/phase6/local-role
```

This is one current-source `core` image component, not a retained all-target
candidate inventory, final running-container observation, complete profile,
16-scenario run, or Slice 6 evidence bundle.

### 2026-09-27 typed v3 artifact/descriptor admission checkpoint

Sandbox ruled that the unaccepted Slice 6 evidence draft must have finite
typed local candidate rows, not a generic role-build field set applied to
Desktop. V3 now separates repository-role and Desktop projections; each
points to its own source-bound private manifest and OCI archive. A reusable
upper-layer admission verifier reopens the clean source, all role candidate
pairs and the current Desktop candidate pair, and compares exact typed rows
to the profile. Its final CLI requires these private inputs and refuses the
old bundle-only argument set. The Browser sandbox remains pinned to its
historical signed publication and selected platform manifest.

An evidence-chain audit found that the v2 draft incorrectly placed the
domain-separated OCI descriptor proof in a field whose verifier required
SHA-256 of raw receipt bytes. A real receipt cannot naturally satisfy both.
Sandbox approved a separate `descriptor_receipts[].receipt_digest` for the
canonical raw payload file, retaining original OCI index/manifest/config
bytes without rewriting them. The semantic proof and run-envelope hashes
remain distinct. The candidate v3 admission recomputes the content and
semantic hashes, compares local archive bytes, and reparses each role and
external dependency's running Docker container/image inspect pair. Other
receipt-index entries were classified as raw run observations; source,
profile, configuration, artifact and semantic proof digests do not enter
the raw-content channel.

Targeted and full-root race/shuffle, vet, both Contract verifiers, real-archive
producer-to-recorder component proof and strict Slice 6 tagged preflight pass.
The complete live 58-deployment/16-scenario topology is still pending. No
accepted success bundle exists; Phase 6 remains **5/15**.

The opt-in capacity precheck reads host physical and Docker backing free
bytes separately, compares each against a finite draft topology write budget,
and tests its early-stop threshold without filling a filesystem. On
2026-09-27 the disposable pinned-Alpine probe observed 32,224,526,336 host
bytes and 364,156,092,416 Docker backing bytes available; the draft required
23,085,449,216 and 17,179,869,184 bytes respectively. The host, not the
Docker VM's large virtual availability, is the limiting observation. The
sample passed and its exact run-labeled probe was cleaned; the numbers are
instantaneous, not a guarantee for the full topology. No user-owned Docker
images, cache, volumes or archives were pruned. PostgreSQL/WAL, Vault,
recording, logs and writable-layer growth still need live limits/monitoring
and a separate stop-producers-before-cleanup path in the full gate.

Source-identity review found that the existing local candidate verifiers
require each original build revision C to match the declared runtime baseline
R. The first final-admission path keeps that strict, auditable C=R condition
rather than inventing a compatibility claim for older runtime binaries. It
now independently checks the gate/recorder/verifier source E through the
existing evidence revision/tree fields. A later evidence-tool or docs commit
may therefore advance E without rewriting candidate provenance or rebuilding
unchanged R artifacts. The current strict C=R path does not support a changed
R with only the affected target rebuilt: every local candidate must originate
from the newly frozen R unless a separately reviewed target-specific
byte-level equivalence path is implemented. No such cross-runtime reuse or
full candidate admission is claimed by the clean-source unit test here.

The first attempt to bind the executing verifier to E by Go VCS build info
was fail-closed but unusable here: a clean local Go 1.26.8 build, including
explicit `-buildvcs=true`, exposed no `vcs.*` settings in `go version -m`.
Two clean fixed-recipe builds of the current verifier matched byte for byte
(`sha256:6cacb8943eebccd1955bf4afd6d59a7ade70c8cf8562af63ffa4f9fd828d9374`
with `CGO_ENABLED=0`). Final CLI admission therefore uses a separate bounded
offline rebuild from E and compares its bytes to the actual executing file;
VCS metadata is not the sole gate. This demonstrates local reproducibility,
not a signed publication or unique origin. A positive real CLI/bundle gate
is still pending.

Profile-supply increment after `e55004e`: the reviewed 58-deployment image
target inventory now exposes copied deployment and 12 distinct local-command
target lists. A new pre-profile loader requires exactly one private,
source/archive-verified role candidate per target, with common R revision,
tree and platform, plus the independently verified Desktop candidate. A
separate raw OCI reader discovers the Browser config digest only from the
locked selected manifest, then reopens and verifies the index/manifest/config
and layer chain; an opt-in real Docker run passed on the cached pinned Browser
publication. The gate-owned image-supply layer rejects missing/duplicate
reviewed deployments and targets. It supplies expected image identities only:
the remaining identity, trust, external-service and TLS builder, a complete
frozen profile, all running deployments, 16 same-run assertions, exact cleanup
and final evidence are still absent. No counter or publication claim follows.

The next builder increment derives each static container's reviewed UID/GID
and exact network membership before Docker is created. For one fresh run ID,
it derives all 56 non-template authorization identities (the two sandbox
templates retain only their Provider controller binding) and fixed TLS leaf
policy; no key or certificate is issued by this identity construction. Its
principal skeleton is intentionally invalid as a deployable profile until
image, listener, mount, seccomp/resource, trust-anchor, external-service and
issuer/bootstrap fields have been bound and the full profile validated.
The 77 desired local, external and Unix trust edges can now be constructed
from that identity inventory and independently verified external identity
inputs; local numeric targets are derived from reviewed IPAM, not observed
Docker endpoints. No external image/certificate is attested by this pure
construction step.

A disposable real Docker route diagnostic of the reviewed
`certificate-controller` isolated bridge observed only the directly connected
`172.31.25.0/24` route and no default route; the run-labeled test container
and network were removed and re-inventoried. This does not alone prove a
Vault connection failure, because Vault was not deployed, but it exposes a
physical-path question for the reviewed external HTTPS `certificate-vault`
edge (and analogous external database edges). No undeclared NAT attachment or
external service network member was added. Sandbox was asked to adjudicate
the safe path before a full-topology launch.
Sandbox resolved the physical-path question: 17 reviewed external logical
and broker edges now have a finite 12-path logical-caller → actual-dialer →
service → dedicated isolated-network mapping in source. Only the certificate
controller/Vault and Product/PostgreSQL paths are direct; the other logical
role edges retain their broker as the sole actual dialer. The transport-plan
test rejects missing edges, direct-role substitutions and shared-network
rewrites. The Network/ExternalService profile schema and actual service
containers have not yet been extended to enforce this mapping, so the
diagnostic is not a positive external-service gate.
The 17/12 plan covers the current reviewed table, not all actual command
dependencies: Sandbox confirmed that the coding Provider v3 startup still
opens its own required PostgreSQL registry, which has no coding Provider
external trust/network/client-signer purpose in this Slice 6 table. The
approved next work is a dedicated coding Provider → PostgreSQL isolated
direct path and purpose-specific DB identity/HBA, without borrowing the
Browser/Desktop broker route or DB role. Before final R/build, the gate must
inventory every real command/bootstrap/migration dependency and correct the
counts; no success evidence can rely on the incomplete 17/12 mapping.

Later command-level audit and Sandbox review approved 18 direct external
dependencies and a 28-path target service-bridge plan; these have not yet
replaced the partial 17/12 installed profile graph. The approved material
agent mTLS topology adds 11 distinct TLS-agent key-owner deployments for the
11 actual Vault KV clients. The intermediate profile inventory is now 69
deployments, 67 non-template authorization identities, 29 TLS-agent bindings
and 99 trust edges. The first 58 UID/GID assignments and isolated role CIDRs
remain stable; new signers use separate reserved ranges, outside the dynamic
Desktop sandbox UID/GID slots and the external-service bridge subnets. The
existing `workload-tls-agent` image target is reused. This is still source/
profile validation, not live certificate issuance, Vault client mTLS, a full
16-scenario run or Slice 6 evidence. The prior 58/56/77 figures above are
historical checkpoint counts, not the current complete target.

Checkpoint 2026-09-28 (PostgreSQL final-owner components, not Slice 6
acceptance): the reviewed final profile candidate resolves nine distinct
PostgreSQL runtime/migration owner, SQL role, signer, peer-CRL and source-path
tuples. Explicit Product/Provider migration v2 paths use controlled precreated
schemas and deny database-level CREATE. Against a disposable pinned PostgreSQL
16 container, the full Product and three Provider migration sets completed
under these limited roles; a separate test observed server-side
`ssl_crl_file` rejecting a revoked client leaf while a healthy control
connected. A real pgx pool using a per-connection selected client leaf closed
its old connection on signer rotation, reconnected with the healthy leaf, and
interrupted an observed active long query within the local two-second test
bound without replay. These are test-local CA/role/component observations,
not the nine-role Vault/topology gate. The local conservative policy sacrifices
in-flight availability on normal certificate rotation; the actual
Vault-publication → agent CRL poll → application snapshot poll → socket close
elapsed time, including scheduling margin, has not been measured against the
profile's ten-second drain bound. A TLS-agent rollback/non-resurrection
hardening check and a pinned real Vault mTLS integration passed, but they do
not substitute for that end-to-end clock.

The frozen 16-scenario route plan and strict candidate/profile preflight
remain non-executing inputs. A same-runID launcher for all 82 independent
roles, controlled Vault and external services, scenario observers, raw
receipts, exact resource cleanup and immutable manifest issuance is not yet
implemented. Consequently Phase 6 remains 5/15; no local-only component
diagnostic or present audit prose authorizes moving the counter or pushing a
Slice 6 acceptance claim.

Checkpoint 2026-09-28 (final-profile admission and network bootstrap only):
the live-gate preflight had still called historical 17/12 network and external
service validators, which would reject the final 82-deployment profile. It
now admits only the reviewed final 32-path/37-edge graph, exact local image
locations, nine PostgreSQL owner/signer resolutions and rendered HBA digest;
tests reject the earlier 17/12 and 28/33 candidates. A real Docker diagnostic
created and independently inspected all 127 final isolated/NAT bridges in one
run, then rediscovered and removed the exact run-labeled inventory to zero.
The first attempt caught an empty-network helper that expected an external
service endpoint before its service container had joined; that bootstrap
ordering bug was fixed. A separate controlled name-conflict run verified
partial network rollback while preserving the unrelated conflicting bridge.
The public Slice 6 evidence/bundle verification path now shares that exact
final-profile predicate, rather than relying on callers to run preflight;
synthetic final-inventory fixtures and old-candidate rejection tests cover
the static admission boundary. An initial ninefold full-profile revalidation
made the race suite time out; the corrected gate validates the profile once,
then checks the fixed nine signer/HBA tuple set linearly. The focused security
race package and the subsequent full repository race/shuffle suite pass after
that correction. This checks consistency, not
whether any process actually ran.
These observations prove only final IPAM coexistence and fail-clean network
creation, not the Vault/external-service bootstrap, any running role, a
scenario, or release evidence. At this checkpoint the scenario receipt
validator still accepted bare `passed`/assertion labels without a typed raw
measurement link; Sandbox required that gap be closed before any final
manifest could be issued.

Checkpoint 2026-09-28 (private scenario receipt v2 and one Vault route
diagnostic, not Slice 6 acceptance): private scenario raw receipts now reject
the old claim-only shape. Each of the frozen 48 assertions must carry its
reviewed probe family, source/target, same-run source/target instance IDs and
existing inspect-receipt digests, start/end timestamps and elapsed time, plus
a typed result. Denial/drain rows require a nearby accepted healthy control
on the same inspected instances; active socket drain is limited to ten
seconds. The closed criteria also cover zero/82 counts, nonzero observations,
stable/distinct identity digests and effective UID/GID, with negative tests
for missing measurement, wrong target/probe, cross-run instance, digest,
control and timing. This is a stronger semantic admission schema, not an
origin proof: the trusted same-run harness must still capture actual probe
commands and outputs, close their references, and test application-specific
semantics (for example, real CDP version and paired RTP/input), rather than
populate a count from a claim.

A separate opt-in Docker diagnostic booted the pinned Vault process on the
reviewed isolated `network-certificate-controller` bridge. A second real OS
container at the controller's planned address reached Vault over TLS with
the generated CA; the network inspect showed Vault alone at its approved
address after the probe exited, and run-labeled containers/networks/volumes
were removed to zero. The probe was a Vault CLI, not the repository's actual
certificate-controller, and the server used test-only dev TLS, not the final
external identity or controlled PKI configuration. It narrows the physical
bridge/TLS feasibility question but cannot count as any of the 16 scenarios.

Checkpoint 2026-09-28 (restart history receipts and replacement diagnostic,
not the Provider/executor scenario): Sandbox identified and approved a repair
for a receipt-index collision: `process/<deployment>/command` silently
overwrote the prior command digest on a second instance. Canonical process
keys are now `process/<deployment>/<sequence>/command` and
`process/<deployment>/<sequence>/inspect`; sequence is contiguous per
deployment and capped at eight. Each process envelope binds the exact
sequence, container, config and start/finish times, while a historical Docker
inspect must carry the same run label, container ID and start time and be
stopped at its recorded finish. The final instance remains separately bound
to ContainerObservation. The three restart scenario measurements now require
old/new references for Provider and both executor deployments, each to one
actual same-deployment process pair; old command and inspect files can be
independently reopened. Tests reject missing old raw, wrong sequence,
container, config, run, historical inspect and cross-deployment pair after
digest recomputation where applicable. This fixes structural closure, not
trusted execution origin or probe semantics.

An opt-in Docker diagnostic also stopped and removed one run-labeled Alpine
container, started a different container with the same command at the same
reviewed isolated Provider-network address, inspected both real process
lifecycles and the sole final network member, then removed all run-owned
resources. Alpine is not the Provider and this diagnostic does not prove
retained Provider authority, stale-admission denial, either executor restart
or the final 16-scenario gate. The full runner still needs to feed real
per-instance raw receipts and monotonic probe timing into the private bundle.

Checkpoint 2026-09-28 (capacity admission and runtime interlock component,
not Slice 6 acceptance): the real two-sided preflight measured
29,149,560,832 host-available bytes against a strict 23,085,449,216-byte
requirement and 360,560,373,760 Docker-backing-available bytes against a
17,179,869,184-byte requirement. The previously insufficient host space had
recovered for reasons outside this task; no cleanup is attributed to this
gate, and capacity must be remeasured before each resource-heavy stage. A
test-side runtime interlock now samples host `statfs` and the Docker backing
filesystem through a known run-owned container. Initial admission requires
both sides; a failed subsequent sample, parent cancellation or `stopEarly`
threshold invokes the supplied producer-stop callback exactly once. Focused
race tests and a real run-labeled Docker sampling/cleanup diagnostic pass.
The full runner has not yet wired that callback to every writer, measured
stop lag, or retained same-run capacity receipts. This is not a role-chain,
scenario, immutable-evidence or release result; Phase 6 remains **5/15**.

Checkpoint 2026-09-28 (credential-controller mTLS source correction, not
acceptance): the complete candidate profile now declares one additional
`workload-credential-controller` → `certificate-controller` Unix CSR edge,
without adding a
principal or network privilege. It binds a unique policy, Vault role,
request-key digest, two exact socket mounts and distinct peer UID/GID. The
certificate controller rejects omitted/substituted policy and listener
entries. The v2 credential-controller command now verifies the complete
profile and FD-only P-256 bootstrap client identity, serves only the
certificate-controller credential listener while obtaining its own managed
certificate; it waits only for the exact controller socket with a bounded,
cancellable startup deadline, drains pre-switch HTTP responses, destroys the
bootstrap key, then opens other listeners. The private PKI protocol now admits only this
controller's self CSR in addition to the original certificate-controller
self CSR; cross-subject and other-controller issuance stay denied. Focused
race tests pass. No two-controller non-dev Vault bootstrap, real managed
switch or final profile process gate has yet been observed. The earlier
R-bound image candidates
remain tied to their old source revision and cannot be relabeled; this
runtime correction requires an R2 freeze and complete rebuild before the
real Slice 6 gate. Phase 6 remains **5/15**.

Checkpoint 2026-09-28 (real Vault token-role component, not Slice 6
acceptance): Sandbox selected fixed operator-created Vault token roles for
the v2 controller. The role name is derived from each exact backend policy;
the v2 command requires a limited management token that can create only
through those role paths, read those role configurations, and look up/revoke
accessors. Before opening any listener it checks the real role configuration
for one allowed policy, explicit default/root denial, no globs/aliases,
non-orphan nonrenewable service children and the 15-minute ceiling. The
controller checks the issued token and accessor lookup for complete binding,
role, policy and TTL. Vault's accessor lookup omits the child token ID; this
test does not claim to recompare those bytes. A pinned non-dev Vault
component test on a
disposable loopback test CA passes init/unseal, limited orphan management
token creation, initial root revocation, generic-create/wrong-role-policy/
business-read denials, fixed-role issue/verify/revoke and exact container
removal. It also verifies the management token can look up and revoke an
unrelated orphan token's accessor; the dedicated-domain requirement is a
real observed blast-radius limit, not an accessor-owner isolation claim.
This component run does not exercise the actual certificate
controller, the managed mTLS switch, final bridge, or the 82-role/16-scenario
same-run gate. Vault ACLs cannot restrict accessor lookup/revoke to only
controller-owned accessors, so a compromised management token's broader
blast radius requires a dedicated Vault security domain with no unrelated
business tenants. Phase 6 remains **5/15**.

Checkpoint 2026-09-28 (bootstrap mTLS drain component, not Slice 6
acceptance): certificate-controller and credential-controller v2 now share a
non-reusing transport that counts every pre-switch Vault request until its
body completes. Both wait under a bound before destroying bootstrap keys;
certificate-controller additionally waits for its managed-agent loop and
closes its leased PKI token on early failure. The existing pinned non-dev
Vault mTLS component test now uses that transport and passes the managed
certificate switch and authoritative revocation check. It still runs in one
test process with a loopback Vault port, not the two-controller process chain
or final isolated network. Phase 6 remains **5/15**.

Validation checkpoint 2026-09-28: focused race tests for workloadcredential,
workloadtlsagent, certificate-controller and credential-controller v2 pass;
the pinned non-dev Vault scoped-token and managed-mTLS component tests pass;
`go vet ./...`, the Product Contract lock verifier and `git diff --check`
pass. The required full `go test -race -shuffle=on -count=1 ./...` was run
with the host's default Go 1.26.5 and exited nonzero in
`internal/desktopcandidate`, `internal/phase6rolecandidate` and
`provider/desktop/driver/docker`. The later locked-toolchain rerun below
passed all packages, so the earlier "old R rejects the modified checkout"
explanation was incorrect: these test failures were caused by selecting the
wrong Go version. A clean source-bound R is still required for actual
candidate build and Slice 6 admission, not to relabel this earlier test run.

Checkpoint 2026-09-28 (credential.v2 cross-UID transport, not Slice 6
acceptance): the previous 0700/0600 same-UID credential issuer socket was
inconsistent with the profile's distinct controller/client UIDs and GIDs.
The unpublished v2 path now uses the shared restricted-Unix 0710/0666
layout, exact SO_PEERCRED identity, per-client profile-bound directory,
storage and Unix edge, finite first-frame deadline, tracked accepted-socket
closure before handler wait, and inode-safe cleanup. The production
certificate-controller and material-agent clients bind their endpoint and
peer identity to the same resolver; the credential-controller command rejects
listener or policy coverage drift before startup. The desired edge inventory
includes all approved issuer clients and is derived from the exact set,
rather than preserving a prior manually stated edge count. A tagged pinned
Alpine Linux gate passes real nonroot 20000:30000 server and 20001:30001
client issue/renew/status/revoke, wrong UID/GID denial, no/half-frame bounds,
stalled-peer close and substituted-inode cleanup. The separate pinned Vault
PKI test remains only a direct-controller token-policy component gate, not
Unix transport or the actual two-controller process chain. No new immutable
Slice 6 manifest has been issued; Phase 6 remains **5/15**.

The first non-launchable profile-builder layer now composes fresh per-run
principals, reviewed UID/GID/network placement, and those exact per-client
issuer mounts without copying a manually supplied path or identity. The
profile verifier additionally rejects ancestor/descendant mount overlap,
including an unrelated tmpfs mount, and tests that negative case. This draft
still lacks the remaining image/resource/TLS/external-service bindings and
cannot be used to start the 82-principal topology.
Its separately verified image-supply mapper now also rejects a local
candidate with a mutable reference, a Browser image relabeled as local, a
wrong platform-selected Browser manifest, malformed OCI digests and missing
or surplus reviewed build targets. This mapper is not yet a complete
launchable profile or a live image-selection observation.
The next non-launchable builder entry point opens only a clean-source role
candidate directory, Desktop candidate and locked Browser OCI archive through
the existing byte-verifying `LoadImageSupply`, then binds those image fields
to a fresh 82-principal draft. It refuses prebound image fields instead of
silently overwriting them; tests confirm UID/GID, networks and issuer mounts
are unchanged. It still cannot launch a role or emit Slice 6 evidence.
The exact Go 1.26.8 full `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, Product Contract lock verification and `git diff --check`
pass after this builder change. No new candidate or final evidence was
created by those source-level checks.

Checkpoint 2026-09-29 (resource/seccomp input admission, not a deployed
policy): the reviewed 82 deployment names now have an exact 23-duty-class
mapping. A closed native-platform manifest loader requires all 23 classes,
all 82 assignments and all five external-service resource entries. It binds
finite limits and checked seccomp policy digests to an already image-bound
draft, rejects missing/extra duty entries and prebound policy, and computes
the six lifecycle budget envelopes. Original and applied JSON, license bytes,
an immutable source revision and any derivation rationale are explicit inputs.
The JSON parser rejects duplicate keys, unknown fields, absent target
architecture, non-denying default and unsafe actions. Unit fixtures use
synthetic tiny limits solely to exercise admission logic. **Neither native
production manifest nor any reviewed duty-specific policy/limit set exists
yet**; the source-bound builder therefore fails closed and cannot launch a
topology. A source URL and local digest do not themselves verify upstream
provenance, least privilege, runtime application or measured headroom. These
remain live gate obligations. Sandbox accepted the 23-class mapping but
requires identical policy bytes to be reused where actual syscall needs
match, with distinct real scenario coverage for each binary. Phase 6 remains
**5/15**.
The loader retains checked policy bytes and returns a caller-isolated copy
with its digest, never the mutable repository path. Tests replace the source
file after load and mutate a returned copy without changing the snapshot.
The future Docker launcher must use that snapshot and independently verify
the actual applied policy and running-process seccomp state.
The tagged Slice 6 preflight now compares every profile principal's platform,
resource tuple and seccomp digest to that fixed manifest before candidate
admission, retaining the same checked byte snapshot for a future launcher.
It rejects duplicate/missing names or drift, including after the original
source file changes. Focused race and tagged preflight tests pass. Because
the reviewed production manifest is still absent, this is fail-closed input
admission, not a launchable profile or a completed least-privilege gate.

Desktop seccomp diagnostic checkpoint 2026-09-29: the exact Moby profiles
`default.json` at commit `836ae4d37ef2ec995c77c99fc55f5b5f3af3a897`
is retained with its Apache license and a source-only notice. Original JSON
SHA-256 is
`536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74`.
The closed parser now retains and bounds `errnoRet`, including the source's
`clone3` ENOSYS behavior; it does not silently discard that rule. Sandbox
approved source retention for derivation and audit, **not** automatic reuse
as any of the 23 applied duty policies.

The first high-UID Desktop test runs were invalid: the retained candidate
image `sha256:6d5e7a9f0088387423ffe8041f7f0d2407d34566cd192f44ea53f4b4fa51ea71`
from source `4f50193d1ee9f254d1d91fb9dd982d8e4766b985` contains the workload
account `42000:52000`, not the test's hard-coded `20000:30000`. With the
nonexistent account, Openbox crashed before broker readiness under pinned
Moby, explicit Docker builtin and implicit Docker default seccomp alike;
this was not valid evidence of Moby-specific incompatibility. The opt-in
diagnostic now checks the requested finite UID/GID against the image's
`/etc/passwd` and `/etc/group` before launch. With the image's actual
`42000:52000` account, implicit default, explicit builtin and exact pinned
Moby each passed the real v2 broker media/input/close flow, cgroup sample
and exact container cleanup. In the Moby run, Docker's inspected compact
JSON SHA-256 was
`afb4934b023cfceaaec1a9d752ca3f801aaa96eb2e59abe6e7ea16976948e080`;
it differs from the original whitespace-preserving byte digest. These are
single-candidate compatibility observations, not a reviewed Desktop duty
policy, resource-tier/headroom decision, all-principal runtime check, or
Slice 6 acceptance. No diagnostic container remains; Phase 6 stays **5/15**.
The tagged full-gate input preflight now independently compares every
profile-authorized Desktop workload UID/GID against the source-bound
candidate's verified account allowlist before role launch. Its positive,
missing and mismatched-slot tagged race tests pass. The retained diagnostic
image with `42000:52000` cannot be substituted into a profile requiring
another Desktop slot merely because the image digest and platform match.

The unchanged Playwright original of the separately derived Browser seccomp
JSON is now retained at its pinned upstream commit with SHA-256
`cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849`;
the existing derived Browser policy remains
`3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`.
Retaining those bytes makes the derivation reviewable; it does not approve
their use for other duties or prove application in a running container.
Sandbox accepted a bounded review of the existing Browser-only `chroot`
exception. The opt-in real arm64 Docker A/B diagnostic reused the same
published Browser image digest and changed only the external seccomp JSON:
A used the locked policy and completed private CDP navigation plus a
7,005-byte PNG capture with a sandbox zygote; B removed only the unconditional
`chroot` name and exited 133 at Chromium's
`sys_chroot("/proc/self/fdinfo/")` zygote check. Both launches used UID/GID
20000:30000, `cap-drop ALL`, no-new-privileges, read-only root, network none
and identical tmpfs/resource settings; Docker inspection matched each
normalized policy's complete JSON. The source-file byte digest and Docker's
compact JSON digest are recorded separately. A's initial process had zero
effective/bounding capability masks, NNP=1 and seccomp mode 2; its direct
`chroot /` probe was denied. The sampled Chromium zygote had the same UID/GID,
zero effective capabilities, NNP=1 and seccomp mode 2, but a distinct child
user namespace and the same container mount namespace; its bounding mask
was nonzero and must not be mistaken for host capability. Docker reported no
privileged mode, host bind, device, extra mount, or host PID/IPC/cgroup mode;
`UsernsMode` was empty, which is not proof of initial user-namespace
isolation. The daemon socket/undeclared `/host` path were absent. Both run-owned
containers were verified absent after cleanup. These observations support
only the existing exact Browser policy as a Browser-specific exception under
the tested runtime constraints. They do not prove an independently isolated
initial user namespace, generic `setns` safety, or the full Slice 6 gate; no
historical Browser publication or locked digest changed. Phase 6 remains
**5/15**.

Capacity-planning checkpoint 2026-09-29 (not deployment evidence): the
reviewed 82-name lifecycle inventory now yields one steady envelope, four
separate migration envelopes and a Browser+Desktop-active envelope. Each
migration envelope includes its job, material agent, material TLS agent and
PostgreSQL TLS agent; the two dynamic sandbox templates are included only in
the media/input envelope. All five external services are counted in each
envelope. An exact-map calculator rejects omitted or surplus principals and
services and computes finite memory, CPU and PID sums from supplied limits.
Those limits have **not** yet been supplied by a measured, repository-owned
duty-class policy; the calculator's synthetic unit test is not a release
budget. The future startup coordinator must enforce the envelope sequencing,
otherwise additional overlap must be measured and budgeted. Docker/kernel
overhead, headroom, cgroup peaks and CPU throttling are not inferred from the
sum. No host-admission or Slice 6 acceptance claim follows from this work.
An initial full race run under the host default Go 1.26.5 failed the same
three candidate-related packages. A complete rerun using
`mise exec go@1.26.8 -- env -u GOROOT GOTOOLCHAIN=local` passed **all**
packages, including those three. The earlier candidate-drift attribution was
wrong; toolchain selection caused that test failure. This green source test
does not supply the missing clean-R image candidates or live Slice 6 gate.
`go vet ./...`, the Product Contract lock verifier and `git diff --check`
also pass with the locked toolchain at this checkpoint.
The pinned real arm64 Desktop-image integration was rerun with explicitly
selected Go 1.26.8 and the previously retained, fully verified private APK
cache. It passed native broker, complete VP8 RTP keyframe decode, pointer
input acknowledgement and high-UID account checks. Its newly logged raw
cgroup v2 samples (including docker-exec probe overhead) showed memory peaks
of 124,551,168 and 116,006,912 bytes, PID peaks of 72 each, and zero OOM and
OOM-kill events in both runs. Under the test's 1-CPU limit, CPU throttling was
nonzero (3 of 9 periods / 77,183 microseconds, and 1 of 7 periods / 26,030
microseconds). The test's 512 MiB / 128 PID limits were existing component
fixtures, **not** a reviewed Slice 6 resource tier. This is two component
samples from one test invocation, not repeated recording/load, the 82-role
topology, a headroom study or a release-limit decision. The integration
containers and named integration images were absent after test cleanup.
The pinned published Browser image's separate real high-UID Chromium/CDP
component gate also passed with UID/GID 20000:30000 and a locked seccomp
profile. Its one cgroup v2 sample showed 64,462,848 bytes memory peak, 56 PID
peak, zero OOM/OOM-kill and CPU throttling in 11 of 29 periods (1,034,940
microseconds) under the fixture's 1-CPU limit. Its run-owned container was
absent after cleanup. This short CDP startup/probe is not Browser action
load, full session capacity, or a resource-tier/headroom decision.
Both tagged Browser and Desktop gates were rerun after adding a bounded
cgroup v2 parser with duplicate/missing/malformed/overflow checks and
zero-OOM assertions; they passed. No release-tier values or policy bytes have
been selected from these samples.

Remaining Slice 6 work stays within the original gate, in four deliverables:

1. Build one executable controlled Vault/external-service bootstrap, freeze
   the complete final profile from verified artifacts, and start the real
   deployments and one-shot migrations in dependency order with failure
   cleanup. The existing image/placement/skeleton builder is only a partial
   input; start with one true vertical path, then cover the full inventory.
2. Add the same-runID live observer and 16 scenario executor to that startup
   chain. Retain raw process/container, handshake, denial, timing and cleanup
   receipts; reject a failure run, missing observation or cross-run splice.
3. Run the complete Vault and external-dependency topology, fix observed
   failures, measure the client/server revocation budget end to end, and pass
   all 16 scenarios plus exact zero run-owned resource cleanup and immutable
   evidence verification. One-shot jobs belong to their real lifecycle, not
   an artificial all-at-once count.
4. Only after the full gate passes, update the status and cross-machine
   handoff, commit and push the Phase 6 branch, compare complete remote/local
   SHAs, and stop before Slice 7. Git-external candidate/evidence artifacts
   need an explicit safe storage or deterministic rebuild procedure.

The clean-source candidate build and preflight require a committed runtime
revision R. A local-only checkpoint commit may therefore freeze R before the
gate; it is a candidate source identity, not an acceptance claim and must not
be pushed as one. If runtime code changes, create a new R and rebuild/retest
its source-bound candidates. The final acceptance/handoff commit and remote
push remain contingent on the complete gate and immutable evidence. Evidence
tooling or documentation may advance separately as E without relabeling an
older candidate as a new runtime revision.

External DNS candidate checkpoint 2026-09-29 (E-side diagnostic, not a
deployment gate): official CoreDNS `v1.14.7` was selected by immutable index
`sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286`.
The native arm64 selected manifest is
`sha256:9a631b1e34491f93a35334bc02d8ae190f16224be41689c7f42cc1711a95fe3a`
and OCI config is
`sha256:5d3b3e589fcf57f626c7967bff5171924cf9c55068911247a1f7bd2458e726c3`.
A private mode-0600 Docker OCI archive was independently reopened and its raw
index→manifest→config, ordered compressed layers and diff IDs were verified;
an unstarted `--pull=never` container selected the same manifest and was
removed exactly. The semantic descriptor proof is
`sha256:a5b3e5986897169bffbacc7a29ff39dc669379de26cac8087bd244cd2dd37059`.
This uncovered and repaired a verifier omission for Docker's closed
`application/vnd.docker.image.rootfs.diff.tar.gzip` media type; it did not
relax unsupported codecs. The archive and its local receipt remain private,
not published release evidence. CoreDNS was not yet launched with the final
Corefile, CA, network or broker, and no TLS/DNS scenario passed. In particular,
the stock server's TLS 1.2 minimum and lack of native broker-URI/CRL checks
remain explicit non-claims; the distinct broker-side TLS 1.3, exact server
identity/peer revocation, limited client CA and isolated network obligations
are recorded in ADR 0055. The true Vault→credential controller→certificate
controller→TLS/material-agent process chain and complete profile remain open.
Phase 6 remains **5/15**.

The subsequent E-side broker revision makes the existing broker→DNS
peer-revocation requirement explicit in code, but remains unaccepted runtime
work. Only the five frozen `dns_tcp` outbound broker edges may omit a client
anchor while deriving a peer-CRL role; source selection still requires an
operator-mapped exact issuer and anchor. The broker config is now v3 and
requires that role derivative and its full source-mapping digest. Startup
bootstraps fresh DNS server CRL evidence before listening; each TLS 1.3 DNS
handshake verifies identity, checks and tracks the peer, and the polling path
drains tracked sockets and revokes active broker sessions on authority loss.
The same role derivative also binds the existing role→broker inbound edge:
the broker now bootstraps its client-issuer CRL, checks/tracks the verified
client certificate before reading a request frame, and closes established
tunnels on revocation. A race-enabled component test observes rejection,
active-tunnel drain and zero retained tracked connections; this is not a
substitute for actual Vault CRL publication and two-process timing evidence.
The actual DNS address must equal its preplanned isolated bridge endpoint.
Source/unit checks and the immutable CoreDNS image check are green; no real
Vault/controller/agent/CoreDNS same-run request or revocation timing has yet
passed. This broker runtime change needs a later fresh source revision R and
rebuilt source-bound role candidates before the final gate. The older R
candidate receipts are retained as historical diagnostics only. Phase 6
remains **5/15**.

Validation at this checkpoint: targeted broker, DNS binding, peer-CRL and
real pinned CoreDNS OCI tests pass; the existing tagged Docker isolated-network
component test also passes. The unbounded package-parallel full race/shuffle
run twice encountered timing failures in unrelated Gateway slow-header and
qualification child-start tests under high host load; each failed test passed
three isolated race/shuffle repetitions. A subsequent complete
`go test -race -shuffle=on -count=1 -p=2 ./...` passed every package. `go vet
./...`, Product Contract lock verification and `git diff --check` pass. This
bounded test rerun is source validation, not the missing same-run Vault/DNS
deployment or Slice 6 acceptance.

The next controlled-Vault input increment adds
`internal/phase6vaultbootstrap.ObserveIssuer`. It accepts only a direct,
bounded TLS 1.3 mTLS operator client with a verified exact server name,
a single reviewed Vault URI SAN and server-only leaf purpose, plus a
short-lived token; it refuses redirects, proxy-capable/custom-dial transport,
duplicate or excessively nested JSON, an unstable mutable default alias,
non-immediate complete-CRL configuration, invalid issuer DER, and an expired or
mis-signed complete CRL. It returns the actual fixed issuer UUID, complete DER
digest and CRL number/times, not a selected leaf or a workload credential.
The pinned non-dev Vault scoped-role integration now mounts PKI, generates a
real issuer, successfully observes it over mTLS before revoking the initial
root token, then continues its fixed-role and cleanup checks. Targeted race
tests and that tagged real-Vault component test pass. This is a verified
bootstrap input boundary only: it has no isolated final service bridge,
complete final profile, two-controller/agent OS-process chain, same-run CRL
drain measurement or Slice 6 manifest. Phase 6 remains **5/15**.
After this source change, the complete `go test -race -shuffle=on -count=1
-p=2 ./...` run, `go vet ./...`, Product Contract lock verification and
`git diff --check` passed under Go 1.26.8. The additional CRL-signature
rejection test passed under targeted race/shuffle after that complete run;
it does not alter runtime behavior or convert component evidence into the
missing full-topology gate.

Checkpoint 2026-09-29 (external-image input, not a live service gate): a
separate `phase6profilebuilder` loader now pins the four official Vault,
PostgreSQL, Valkey and CoreDNS registry indexes and the native arm64 platform
manifests. It reopens private mode-0600 OCI archives outside the checkout,
checks the raw index→selected-manifest→config chain and every compressed layer
against the ordered config diff IDs, then binds the reviewed five external
service names; the action-history and Product PostgreSQL identities share one
image but remain separate service authorities. A symlink-resolved source-tree
check rejects an apparent external archive actually under the checkout.
The exact verified descriptor proof digests are, respectively,
`sha256:2850f4fcd021dcb4e400511ab77800a2a18445267312b1aa2fc092dddc5f71ea`,
`sha256:9b3a1bb275b6fa12bdb10b7ce1d86a57b111315270f7185cedce08ed407763b2`,
`sha256:d17187a8936f85d5213ca83bfd7756f41be643e40e89a5b51520bedd5fd69487`,
and `sha256:a5b3e5986897169bffbacc7a29ff39dc669379de26cac8087bd244cd2dd37059`.
The corresponding complete private archive SHA-256 digests are
`197d50221e900ccaef05db51982d3a3e225035c349631419cc5119cc0b5c62b6`,
`4e66c369aa67aaabc489a8bce6b115b0ae110cdbc4cc36f8916ae599275750f4`,
`442dbf4153726033650d96ad6abf04166a77399191d297c208687d5fd2a1030a`,
and `7958948400a0036d2a262a92e4ba276475cc06e21fdaf47061c669d8101140b7`.
Docker's Vault export contained the index and selected manifest but omitted
the config and layers, so it was rejected. A bounded separate download of the
same pinned Vault platform supplied the missing original content-addressed
blobs; the combined private archive then passed the same independent verifier.
The tagged four-archive/five-service input test passes. This establishes
descriptor bytes, not registry publication authenticity, running Docker
selection, service TLS/SQL/Redis/DNS behavior, final profile, privilege
enforcement, the 16-scenario gate or immutable evidence. Phase 6 stays
**5/15**.

An additional opt-in real-Docker component check then created one stopped,
networkless, `--pull=never` observation container from each exact pinned
image. It compared Docker's runtime store descriptor, selected arm64 manifest,
OCI config and ordered rootfs diff IDs with the independently verified archive
bytes, then removed each exact container and its anonymous volumes. Vault,
PostgreSQL, Valkey and CoreDNS all passed; a post-run exact-name listing was
empty. This closes only the four image-selection input observations. The
external services were not started, no TLS/SQL/Redis/DNS connection or network
policy was exercised, and no full-inventory or Slice 6 acceptance is claimed.
The private archive reconstruction and exact opt-in commands are recorded in
[`phase6-external-image-input.md`](../phase6-external-image-input.md).

Checkpoint 2026-09-29 (complete image inputs, still no topology): at clean
source R `b3f02f0e8f48f413d144bf80be3cb308070d4906`, all 12 distinct
repository-owned command targets were built as local-only arm64 images,
independently rebuilt/byte-compared and retained as 12 private mode-0600
manifest/archive pairs. The same R produced a new non-release Desktop
candidate from the preverified closed APK cache. The opt-in image-supply
preflight reopened those 12 pairs, the Desktop candidate and the historical
locked Browser publication archive and passed exact coverage; no profile or
role was launched by that preflight. A real Desktop candidate mux/executor
component check passed RTP frame, pointer input and cleanup. A separate
high-UID (42000:52000) explicit pinned-Moby seccomp diagnostic passed real
media/input; one cgroup v2 sample reported memory peak 117,751,808 bytes,
PID peak 74, CPU throttling 6/9 periods (503,093 microseconds), and zero OOM
and OOM kills. That Moby byte set and 512 MiB/128 PID/1 CPU diagnostic fixture
are **not** a reviewed Desktop duty policy or final resource tier. The image
receipts remain private local candidates, not published artifacts. This
source checkpoint did not bind resource/seccomp, full profile, live Vault or
the final 16 scenarios; Phase 6 remains **5/15**.

Sandbox's resource-policy clarification permits a fully reviewed, finite
arm64 *candidate* table before separate per-duty benchmarks, then requires
representative real startup/migration, credential rotation/revocation,
Browser/Desktop media/input, fault and pressure calibration under the frozen
candidate. Each deployment still needs its actual UID/GID, applied policy,
mount, network and cgroup observation; a shared binary is not a shared duty
proof. Source/license/original/applied digests, duty rationale, sample basis,
unmeasured assumptions and headroom must be recorded. No synthetic limit,
unconfined/default seccomp, empty placeholder or production validation skip
may stand in for a candidate. A policy/limit change ends and cleans that run;
only a new run ID with re-frozen inputs may attempt full acceptance. The final
run must cover the actual concurrent role set plus five external services,
daemon/observer and cleanup reserve, all 16 scenarios and zero leftovers;
unchanged inputs that pass all gates need no artificial rerun. See ADR 0055.
These documentation-only E changes move this checkout's HEAD beyond R. They
do not change R's runtime/build bytes or automatically invalidate its image
identity; the present candidate loaders do, however, require a clean checkout
at the exact R to reopen it. A separate clean R checkout may retain that
component proof. A later actual resource-policy or runtime/build input change
must freeze a new R and rebuild affected source-bound candidates before the
final gate. No candidate here is a Slice 6 acceptance manifest.
