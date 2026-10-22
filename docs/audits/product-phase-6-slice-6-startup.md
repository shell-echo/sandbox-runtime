# Product v1 Phase 6 Slice 6 Startup Audit

Date: 2026-09-23

Status: implementation underway. Product Phase 6 remains **5/15**.

Latest investigation checkpoint: [Artifact-refusal observation](#2026-10-22-artifact-refusal-observation).

Checkpoint 2026-09-30 (FD startup deadline, component evidence only): the
six-target one-shot loader now reads Docker's non-TTY stdin through a
nonblocking, polled descriptor under one absolute 30-second startup deadline.
It requires actual EOF before canonical envelope validation; a held-open
stream cannot become an unbounded pre-exec container. Focused race tests cover
an empty open stream, a partial prefix, continuous slow input, pending final
bytes with HUP, legitimate/truncated/oversized EOF and cancellation. A real
restricted Docker run additionally observed the held-open container exit by
`State.Running=false` within the bounded window without an automatic restart,
then closed the test-side input pipe and collected the stage-code failure.
The earlier test's `exec.Cmd.Wait` timeout alone was ambiguous because Go may
wait for its own stdin-copy goroutine after the container has exited; it was
not proof that the previous loader stayed alive. PID1 sealed-FD fixture and
other negative cases still pass, with exact run-label cleanup. This does not
launch the actual certificate-controller or establish the 82-principal gate.

Checkpoint 2026-09-30 (isolated non-dev Vault bridge component, not the
managed controller chain): the opt-in `phase6slice6gate` Docker test now runs
the pinned non-dev Vault image with in-memory storage and two distinct
Vault-internal PKI root issuer UUIDs on the reviewed isolated
`network-certificate-controller` bridge. A separate container at the reviewed
certificate-controller address successfully reaches Vault over mutually
authenticated TLS; a second, certificate-less container at that address is
rejected. Temporary TLS keys are current-user-only, both containers run with
a matching non-root UID/GID, and the bootstrap unseal key is sent via a
pseudoterminal rather than a process argument. The ephemeral root token is
revoked, and run-labeled containers/network plus local temporary files are
removed. This does not launch the production certificate-controller or
credential-controller, issue managed role certificates, prove rotation or
revocation, retain final issuer sources, or establish the 82-principal/
16-scenario gate. No Slice 6 manifest was emitted; Phase 6 remains **5/15**.

Checkpoint 2026-09-30 (two-issuer/DNS client-CA boundary, component evidence
only): the production certificate-controller draft now partitions the five
egress-broker signer policies from all ordinary policies across two immutable
Vault issuer UUID/DER sources; v1 revocation reads select the authenticated
policy's fixed complete CRL, never the mutable mount default. Issuance checks
the Vault role's actual `issuer_ref` and returned immediate issuer DER. The
source-bound candidate input advances to composition v2 with a separate
single-certificate DNS broker-client CA file; the final Profile binds its
exact bytes, issuer and five intended subjects to DNS external identity.
The unaccepted Slice 6 manifest advances to v4 and requires same-run DNS
mount/issuer/positive-broker/negative-general raw receipts. Unit and targeted
race/shuffle checks pass; no real manifest exists.

A tagged real non-dev Vault plus stock CoreDNS component gate now generates
two Vault-internal root issuers in one `/pki` mount, reads both fixed UUIDs,
DER and complete CRLs, pins three restricted roles, verifies actual leaves,
rejects a wrong broker URI and per-issuer signing override, and performs a
real DNS-over-TLS query with the broker certificate. An otherwise valid
ordinary client certificate, forced onto the wire despite CoreDNS advertising
only the broker CA, receives the TLS `unknown certificate authority` alert;
a second broker query confirms the listener remains reachable. Both Docker
containers are removed exactly. This still uses loopback component ingress,
not the 82-role isolated network or all 16 live scenarios. The locked stock
CoreDNS image fails to execute with `--cap-drop=ALL` and succeeds with only
`NET_BIND_SERVICE` added to the bounding set, consistent with the upstream
image's file capability. Sandbox adjudicated the one-service exception: the
final Profile now binds original index/selected arm64 manifest, 65532:65532,
drop-all/add-only-`NET_BIND_SERVICE`, NNP, read-only root, seccomp mode and
finite source-derived limits. The v4 evidence requires effective process
UID/GID and all five capability sets, plus a private raw `/proc` status
receipt. 853 is below 1024, and the capability also grants residual low-port
authority in the namespace; actual listener and network inspection remain
required. Repository-owned roles still have no CapAdd. All previously frozen
image candidates are prior-revision inputs after these source changes. Phase 6
remains **5/15**.

The gate-only CoreDNS PID 1 inspector also passed a tagged real-Docker
component test against that stock image. A freshly built static arm64 binary
was mounted as exactly one read-only file, executed as 65532:65532 with a
three-second deadline, and read only `/proc/1/status` (64 KiB maximum). Docker
inspection before and after verified one unchanged container ID, image,
`/coredns` entrypoint, host PID, start time and restart count. Observed PID 1
had UID/GID 65532, NNP=1, seccomp=2, CapInh=0, CapPrm/CapEff/CapBnd=0x400 and
CapAmb=0. The diagnostic container was removed exactly. This validates the
observation method, not a same-run final DNS service or its complete listener
and TLS edges. Inspector source/build/binary/mount/exec/status receipts must
still be captured in the final gate; the mount lasts until container cleanup.
The retained selected arm64 OCI archive was independently reopened to verify
the effective `/coredns` layer's `security.capability` xattr: its effective and
permitted bit is `NET_BIND_SERVICE` only, with no inheritable or high bits.
The source-bound external-image loader now rejects an absent or changed DNS
file capability. This strengthens candidate preflight but is not a live
82-principal observation.
The current component source passes the full repository race/shuffle suite
with local package concurrency `-p=2`, `go vet ./...`, integration-tag vet for
the touched packages, the Product Contract lock verifier, the tagged real
Vault/CoreDNS two-issuer check, the pinned CoreDNS archive and inspector
Docker checks, and the Slice 6 tagged plan tests. These checks do not admit
the final same-run topology or advance the phase count.

Checkpoint 2026-09-30 (candidate input composition, not admission): all 12
distinct local-role targets were built and recorded from clean revision
`19b1561a8f05de8ec76da810b139087789f2651d` as private arm64 OCI
candidate inputs; the complete four-archive external image supply also passed
its tagged source-reopening integration. A new source-bound composition entry
point and operator CLI walk the full image/resource/CA/external/egress/
certificate/static chain and refuse an incomplete or changed source before
writing a canonical exclusive candidate Profile. These code changes themselves
change the source revision: the 19b1561 image set is component evidence only
and must be rebuilt at the eventual clean freeze revision. There is still no
positive real-issuer Profile or launch evidence. Sandbox confirmed that a
same-host bootstrap may be run-owned and short-lived, but the actual issuer,
signing and revocation authority must be non-dev Vault PKI, with the five
purpose-specific bundles checked against real chains and edges. See ADR 0055
and [`phase6-slice6-candidate-profile.md`](../phase6-slice6-candidate-profile.md).
No local synthetic CA set, profile file, 16-scenario receipt or release
manifest was fabricated. The count remains **5/15**.

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
| Provider-bound Browser finite UID, exact create/recovery/cleanup | Real PostgreSQL plus high-UID Browser/gateway Docker integration; atomic Reserved retirement; finished-dispatch proof; live and terminal pre-commit recovery/cleanup; lost terminal-cleanup response finalization; focused in-flight barrier; test-only independent-PID finished-dispatch and network-side-effect crash component | Unknown Docker/network result with no finished proof remains Creating and consumes capacity. The component does not prove every `ContainerCreate` uncertainty, full `provider serve v3` process recovery or the final gate's three Provider commands. | Provider Browser application, PG ledger and Docker adapter |
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

Checkpoint 2026-10-01 (R20 real two-controller issuance and terminal-cycle
failure): revision `bb0451ba478f969ffcb80ce8d5887f99151614be` was frozen
locally and all 12 role targets plus Desktop rebuilt and retained from that
same clean source. The real file-backed non-dev Vault diagnostic loaded those
source-bound artifacts, composed a 78-principal Profile, prepared 50 isolated
controller socket volumes and five trust-anchor volumes, installed the scoped
Vault token/PKI policy set, and passed production validation for all 38
certificate policies. Both real controller PID1 processes ran. The
certificate ledger showed active self and credential-controller managed
leaves, and the credential controller opened its post-switch listeners.
Stopping the credential controller first then the certificate controller
ended with certificate PID1 `stage credential-revoke` (exit 1), proving the
terminal mutual-revocation dependency rather than resolving it. The tagged
test therefore failed after 198.16 seconds; exact run-labeled containers,
networks and volumes were independently observed at zero. This is component
diagnostic evidence only, not a passed gate.

R21 source `ee64de3b5c9de1ad5fda8004a30347dad035e394` added durable,
idempotent quiesce markers to both exclusive ledgers. A private `SIGUSR1`
transition stops certificate/token issuance and token renewal while
authenticated revocation, status and fixed CRL reads remain available;
reconstruction from each ledger stays fail-closed. It also revoked and
removed the bootstrap Vault root token before either controller PID1
started. All role images and Desktop were rebuilt from the same clean source.
The 204.79-second non-dev Vault run observed managed startup and both actual
PID1 ledger quiesce receipts, then failed closed on the unchanged terminal
`credential-revoke` cycle. Exact labeled Docker cleanup returned to zero.
The full Go race suite, vet and locked Contract verifier passed for R21, but
no independent terminal operator ran.

R22 source adds a one-shot private cleanup plan and restricted Vault client
that reject unbound ledgers, unknown targets, noncanonical input,
ambiguous accessor absence, missing CRL entries and failed remote readback in
component tests. Management-token mint binds exact run/Profile/owner metadata
and accessor. The gate now declares an operator-only container path, but its
independent receipt and the complete 16-scenario Slice 6 gate remain unproved. There is
no release manifest or push; Phase 6 remains **5/15**.

R22 source `c5ad79d4c2ca74490f047917fbca5861abf48129` was then rebuilt
into 12 role candidates plus Desktop and exercised against the same-run
file-backed non-dev Vault. The 205.73-second test passed actual management
token metadata/accessor readback, signed and read back the dedicated operator
leaf/token, started both managed controller PID1 processes, and observed both
durable quiesce receipts. It failed before giving the operator its stdin:
the pinned Vault image used as the one-shot executable carrier declared
`/vault/file` and `/vault/logs` volumes, so Docker added two anonymous
writable volumes and the exact effective-mount check rejected the task.
The controlled root token had already been revoked before the controllers;
the operator token and leaf were issued but received no cleanup authority
use. The run-labeled container/network/volume sets returned to zero, but
unlabeled anonymous volumes may remain and **no exact zero-resource claim**
is made for this failed run. Two dangling empty volumes created at the
failure time were deliberately retained because timestamp and emptiness do
not prove ownership. A separate no-secret reproduction container's two
volumes were inspected as its exact mounts and removed with that container.
Sandbox approved switching the finite task to the already pinned no-volume
Alpine carrier, fixed `20090:30090` UID:GID and created-container bind-byte
hash verification; that corrected gate has not yet passed a full Vault run.

R23 gate revision `dca37d2` reused the unaffected R22 resident image
candidates and verified the Alpine carrier's effective no-volume config,
fixed non-root identity, sole read-only binary bind and actual mounted bytes
before delivering operator stdin. A separate no-secret probe confirmed that
this UID can execute the bound static binary under the locked seccomp policy.
The real 203.47-second Vault run again reached two managed PID1 processes,
both quiesce receipts and the independent operator task, but it returned no
complete private cleanup receipt. That is a failed component test, not a
successful revocation. A follow-up source checkpoint adds only redacted
stage codes to distinguish input, Vault client, preflight, CRL and revoke
failures without emitting token/accessor/serial or raw remote diagnostics.
No release manifest or count change follows.

R24 source `4ebf6aba2be0a6a4e9539727fe9c3ada6d6a1b71` built a separate
operator executable before Vault credential minting and recorded its Git
revision/tree, Go 1.26.8 flags and SHA-256. The 208.83-second same-run real
Vault test again reached both managed controller PID1s and both quiesce
receipts, then failed at Docker `create` for the one-shot task, before
delivering stdin. The gate had placed the binary under Go's system test temp
directory, which was outside Docker Desktop's shared host tree. A bounded
no-secret reproduction using a private sibling of the workspace confirmed
that the fixed `20090:30090` Alpine container can create with exactly one
read-only executable bind from that shared location. R25 changes only this
gate-owned build path; R22 resident images remain valid under the C/R/E
partition, and the operator's actual clean source is checked separately.
The internal remote failure stage is still unobserved; no release evidence
or count advancement is claimed.

R25 gate revision `c5a9888299057a628de6d7e3fc2f467721b7943f` used the
Docker-shared private sibling for the separately source-verified operator
binary. The real 200.04-second test passed both managed PID1 startups and
quiesce receipts, then started the no-volume, non-root one-shot task; it did
not produce a complete cleanup receipt. The attempted redacted stderr
diagnostic rendered the `error` implementation's generic text instead of
the fixed stage code, so this run establishes only an incomplete operator
result, not which Vault operation failed. R26 fixes that formatting and
reads a bounded partial private receipt's fixed failure stage if present.
No root fallback, synthetic revocation or release count advancement is
permitted.

R26 source `bbff7e00589210eb9b84074f15503d1c8364b729` returned a useful
fixed stage after the 208.72-second real run: `execute-token-readback`.
This proves the one-shot operator reached the independent token post-revoke
lookup after its earlier certificate/complete-CRL work, but it is **not**
proof that the token revocation was confirmed. A separate real non-dev mTLS
Vault component test then observed the exact revoked-accessor response:
authenticated HTTP 400 with one bounded error string
`1 error occurred:\n\t* invalid accessor\n\n`. The restricted operator
adapter had accepted only the unwrapped `invalid accessor`; R27 adds this
one observed form and explicit negative tests, still rejecting 403, 404,
timeouts, malformed JSON and other 400 errors. The real complete terminal
path remains to be rerun, and Phase 6 remains **5/15**.

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

Checkpoint 2026-09-29–30 (arm64 resource/seccomp source candidate, **not** gate
admission): [`policy-arm64.json`](../../profiles/phase6/security/policy-arm64.json)
now supplies exact finite limits and policy provenance for all 23 duty classes,
82 deployment assignments and five external services. The source-bound loader
accepts its canonical bytes; a repository test checks complete coverage,
the Browser-specific digest, the seven derived controller/agent duties and six
capacity-envelope arithmetic outputs. For the initial controller/agent
behavior family, the applied Moby derivative excludes the unconditional
`ptrace`/`process_vm_*` rule and the `CAP_SYS_PTRACE` process-inspection branch,
while preserving the `clone3` ENOSYS fallback. Fifteen other duty classes
still use the original Moby profile as an **unreviewed calibration baseline**;
the Chromium policy remains its distinct locked Browser exception. Neither
the loader nor static syscall check proves running-container enforcement or
least privilege. Sandbox clarified that a generic source baseline may be a
controlled candidate, but accessible sensitive calls without business need
cannot be excused by cap-drop or deferred into a final policy; behavior-family
review and actual positive/negative probes remain required.

The candidate arithmetic is 7,680 MiB / 7,750m / 2,096 PIDs for steady state
and 9,216 MiB / 9,750m / 2,480 PIDs with both sandboxes active. The current
Docker VM reports ten CPUs, leaving only 250m of nominal quota in that active
envelope before daemon, observer and cleanup reserve. These initial limits
therefore **do not establish host admission**; 50m/16-PID agent classes and
the two media classes still need real startup/rotation/media/fault calibration.
CPU quota is an upper bound, not a reservation: that 250m arithmetic is
neither observed remaining CPU nor, by itself, a decision to enlarge the host.
See the [candidate rationale](../phase6-resource-seccomp-candidate-arm64.md).
The final full profile, actual 82-role/Vault service graph, 16 scenarios,
same-run evidence and exact cleanup remain open. Phase 6 stays **5/15**.

The opt-in arm64 Docker seccomp A/B component test then used the exact pinned
Alpine fixture, a locally built self-process syscall probe and otherwise
identical high-UID/cap-drop/NNP/read-only/networkless/finite-limit containers.
Docker inspection matched each policy's normalized source JSON, and both
processes reported zero effective capabilities, NNP=1 and seccomp mode 2.
Original Moby permitted six-byte `process_vm_readv` and `process_vm_writev`
on self plus `PTRACE_TRACEME`; the derived controller/agent policy denied all
three with EPERM. Both run-owned containers and the private probe directory
were verified absent.
This differential checks one concrete sensitive allowance; it is not a real
Vault→credential controller→certificate controller→agent startup, a general
syscall-minimality proof, or final resource/headroom evidence. Phase 6
remains **5/15**.

The existing opt-in credential-v2 cross-UID Docker gate was then run with
the exact derived policy explicitly applied to its issuer and clients.
Normal issue/renew/status/revoke, wrong identity/GID, incomplete input,
cancellation and substituted socket passed at the candidate 128 MiB/200m/32
issuer and 96 MiB/100m/32 client tiers. Docker's normalized applied-policy
JSON matched the checked source; the issuer had high UID, zero effective
capabilities, NNP=1, seccomp mode 2 and exact cgroup maxima. One issuer
sample showed 13,012,992 bytes memory peak, 10 PIDs, zero OOM/OOM-kill and
2/66 throttled CPU periods (45,736 microseconds). The two named test-owned
containers, volume and build directory were checked absent; transient
`--rm` clients were not separately inventoried. This uses a
test binary and fake credential backend, **not** the Vault management token,
production credential/certificate commands, managed TLS switch or the
final same-run gate; it cannot validate the 50m/16-PID TLS-agent tier or
revocation deadline. Phase 6 remains **5/15**.

Validation reliability checkpoint 2026-09-30: on Go 1.26.8, one default
`go test -race -shuffle=on -count=1 ./...` completed successfully before the
integration-tag-only credential test changes. A later default run over the
same default-tested behavior (plus integration-tag test and documentation
edits) failed the **package-wide** ten-minute timeout in
`internal/phase6security`, not a test assertion. Its shuffle seed was
`1790731853139135000`; the timeout stack showed
`TestSlice6FinalGateProfileRejectsEarlierCandidates` had run for about three
seconds when the package budget expired, so that test is not shown to have
hung for ten minutes. No contemporaneous host-load sample was retained;
resource contention is suspected, **not proven**. A separate complete
`internal/phase6security` race/shuffle run passed in 417.667 seconds; the
failing seed also passed when the complete package was replayed alone.
The heavier failing-seed tests included the nine-owner PostgreSQL/CRL
binding (150.96 seconds), receipt tampering (41.35 seconds) and evidence
inventory (35.39 seconds). A single complete
`go test -race -shuffle=on -count=1 -p=2 ./...` then passed with the
original ten-minute package timeout; its security package took 317.104
seconds. `-p=2` limits package concurrency only. This is a locally
resource-controlled repository validation, **not** a claim that default
concurrency is reliably green or that unchanged remote CI passed. The
targeted real Docker seccomp A/B and cross-UID credential gates, `go vet
./...`, tagged package vet and Product Contract lock verifier passed.
None of these source/component gates is the missing real 82-role/16-scenario
Slice 6 evidence. Phase 6 remains **5/15**.

Checkpoint 2026-09-30 (TLS-agent candidate calibration, still component
only): the opt-in distinct-UID Docker socket gate was re-run with the exact
derived controller/agent seccomp applied to its high-UID TLS-agent helper at
64 MiB/50m/16 PIDs. Docker inspection matched the normalized source policy;
the active process had zero effective capabilities, NNP=1 and seccomp mode 2,
with exact cgroup maxima. Authorized signing, wrong UID/GID denial, SIGKILL
restart and graceful-loss denial passed. The two pre-shutdown samples peaked
at 9,109,504 bytes/13 PIDs and 8,298,496 bytes/13 PIDs, with no OOM, but
were throttled 26/31 and 21/25 CPU periods. Probe `docker exec` calls
contributed to both samples. This is a test binary with a local test manager,
not the production TLS-agent command or real Vault rotation/CRL; frequent
throttling leaves the 50m tier and revocation deadline **unapproved**. The
named agent and both volumes were checked absent; transient `--rm` clients
were not separately inventoried. Phase 6 remains **5/15**.

Sandbox's follow-up ruling retains this tier as an unapproved finite candidate
until the minimal **real** Vault→credential controller→certificate
controller→production TLS-agent process chain is measured. The next run must
cover startup, signing, credential/certificate rotation, CRL publication to
denial and active-connection close, restart/cancel cleanup, monotonic operation
timings, CPU usage/throttling, bounded memory/PID/OOM observation and the
existing ten-second revocation budget. A helper throttling ratio is not a
request-latency or p99 measurement. Do not repeatedly sample the fake-manager
helper, auto-double agent quotas, change the Docker VM without explicit user
approval or admit the full topology when its frozen conservative host budget
fails. Minimal-chain success remains component evidence, not Slice 6 closure.

Checkpoint 2026-09-30 (pre-freeze CA supply layer, no new runtime evidence):
the Phase 6 profile builder now has a closed five-anchor input step after
resource/seccomp binding. It reads each operator-owned CA PEM from a private
0700 directory and a read-only regular file, rejects missing/surplus IDs,
symlinks, invalid/expired/duplicate CA records and check/read identity drift,
then binds the exact original-byte digest, reviewed consumer set and read-only
mount identity. Callers can retrieve only a copy of the checked bytes; a
mutated snapshot fails binding, and the binder reopens all five original
operator files before freeze so changed or unavailable bytes fail. The desired
template derives from the same
reviewed final-anchor inventory used by profile validation. This does **not**
attest operator identity, Vault issuer correspondence, Docker mount contents,
leaf issuance, the production command chain or final profile completeness;
those remain live gates. No synthetic `validProfile()` is promoted to a
launchable profile, and Phase 6 remains **5/15**.
The final-source `go test -race -shuffle=on -count=1 -p=2 ./...`,
`go vet ./...`, Product Contract lock verifier and `git diff --check`
passed. These are source tests only; no new tagged Docker or full-chain
runtime result was produced by this checkpoint.

Checkpoint 2026-09-30 (reviewed final-topology draft, no new runtime
evidence): the builder now reopens the original four pinned external OCI
archives before combining their five service identities with the checked CA
draft. The new non-launchable topology layer applies the reviewed 32 isolated
physical service paths and finite 37 external trust edges, yielding 152 total
trust edges. It rejects changed source descriptors/layers, external identity
substitution, mismatched platform, changed CA mounts or consumers, TLS identity
drift and IPAM drift. The edge builder is checked against the existing final
external profile target, while focused draft tests verify every path's dialer,
service and ingress-edge membership. Unit test image descriptors are synthetic
and are only policy tests; the public binder rejects them because no original
OCI archives can be reopened. The opt-in real four-archive integration reopened
the previously retained complete private archives: their outer SHA-256 values
match the recorded 2026-09-29 input checkpoint, including Vault
`197d50221e900ccaef05db51982d3a3e225035c349631419cc5119cc0b5c62b6`.
The archive/layer and new second-pass source verifier succeeded for all four
indexes; the separate Docker store/container-selection component gate also
passed for all four native arm64 manifests and removed its exact stopped
observation containers. A fresh Docker `save` of the Vault index again emitted
only index and selected-manifest bytes (9,216 bytes), so that incomplete
temporary export correctly failed the directed Vault archive test. The
retained complete archive, not the incomplete export, was used for the passing
checks. No registry download or replacement digest was necessary.
The new opt-in public topology-binder component test also passed by reopening
the four real archives under explicitly synthetic CA and resource/image draft
inputs; it provides source-reopen and 152-edge wiring coverage only, not a
deployable or final profile.
Remaining work includes source-bound complete profile fields and bootstrap,
the real Vault→credential controller→certificate controller→production
TLS-agent process measurement, the full 82-role/16-scenario local gate,
resource and revocation bounds, exact cleanup and an immutable manifest.
The final-source resource-controlled full repository race/shuffle run, `go vet
./...`, Product Contract lock verifier and diff check passed. This checkpoint
cannot raise Phase 6 above **5/15**.

Checkpoint 2026-09-30 (retained pre-freeze source handles, no admission):
the image-supply layer now retains its clean-source revision, local-role
candidate directory, Desktop candidate and locked Browser archive paths and
reopens the exact source-bound artifacts before final freeze. The
resource/seccomp layer similarly reopens the repository-owned manifest,
original and applied policies and license bytes; a changed policy source
fails even when the old digest snapshot is still in memory. Both supplies
survive subsequent draft binding. The incomplete final-topology draft has an
all-input source-recheck method and deliberately rejects synthetic image or
resource fixtures. The new image recheck has not yet passed against one fresh
clean revision's complete local-role, Desktop and Browser artifacts; the
existing retained candidates are from earlier source revisions. Therefore
this method is a fail-closed pre-freeze boundary, not evidence that a final
profile was frozen or any role launched. Phase 6 remains **5/15**.
The final-source locally resource-controlled full race/shuffle suite
(`-p=2`), `go vet ./...`, integration-tag builder vet, Product Contract lock
verifier and diff check passed. No fresh role-image candidate was built or
accepted at this checkpoint.

Checkpoint 2026-09-30 (private egress-key source and policy draft, no
admission): the next non-launchable builder layer accepts exactly five
reviewed egress-authority raw Ed25519 private-key source files from a private
0700 operator directory. Each file must be owned by the current operator,
regular, non-symlink, mode 0600, 64 bytes and seed/public-half consistent.
The layer retains only public keys and private source paths, derives the
profile policy key digests from the real public halves, and reopens every key
source together with the previous image/resource/CA/external source chain
before a future freeze. It binds the reviewed five policy targets, the five
broker listeners and the exact authority socket/ledger mounts, rejecting
foreign mounts and weakened broker-authority edges. Key paths and private
bytes are not written into the profile. These focused tests use freshly
generated test keys only; no production authority key was generated or
launched, and the complete Profile still lacks controller/TLS-agent bindings,
SQL/HBA, ingress, components and live Vault issuer proof. This remains
component/source-policy evidence only; Phase 6 stays **5/15**.

Checkpoint 2026-09-30 (certificate-controller/TLS-agent binding draft, no
live PKI evidence): the builder now accepts the closed controller response,
controller-managed request, credential-controller-managed request and all
ordinary/PostgreSQL-purpose TLS-agent Ed25519 key sources from private 0700
operator directories. It reads each exact 0600 raw key only to retain its
public half, rejects changed/missing/duplicate or inconsistent sources and
prevents reuse of an egress authority public key. The reviewed agent/subject
inventory constructs separate ordinary and nine PostgreSQL-purpose bindings,
including distinct request-key digests, controller and signer Unix edges,
private socket mount pairs, UID/GID bindings and issuer policy/role IDs.
The controller self and credential-controller managed sockets are also
bound. These are desired declarations from real key sources, not attestation
that Vault has issued matching leaves, that private FDs were delivered to
the production commands, or that peer/CRL/revocation behavior passed. Tests
use generated private test sources solely for builder validation. The full
Profile still needs remaining source-bound fields and actual process proof;
Phase 6 remains **5/15**. The final-source repository race/shuffle suite
passed with local package concurrency limited to `-p=2`; the security
package took 258.156 seconds. This does not establish default-concurrency
CI health, a tagged Docker integration gate, or the real 82-role run.

Checkpoint 2026-09-30 (full-profile assembly path, not frozen): the next
builder layer now supplies the reviewed non-secret listener, Browser mux
socket, two public ingress, two sandbox identity slots, two Provider database
bindings, complete nine-role shared PostgreSQL HBA digest and cleanup class
fields. A deliberately synthetic *test-only* image/component fixture was
used to check that these fields form a structurally valid
`phase6security.Profile`; it is neither a source-bound candidate nor a
launch artifact. The production finalizer accepts only the prior source-
rechecked layers, reads the effective Desktop broker executable from the
selected, original-byte-verified OCI layers and sets the component digest
from those bytes before calling the complete Profile and final-gate static
validators. Layer tests reject whiteout, symlink, unsafe mode and ambiguous
replacement. The finalizer correctly refuses current synthetic draft inputs;
no fresh clean-revision Desktop/role image set and full real key/CA supply
has yet produced a positive frozen Profile. The full live dependency chain,
issuer mapping, 82-role/16-scenario evidence and cleanup remain outstanding;
Phase 6 stays **5/15**.

The opt-in Desktop broker archive component test passed against the retained
private arm64 Desktop candidate from source revision
`6d78afaa844ea598dba2a1b0f82d250627c7c79a`. It reopened the candidate
sidecar/151,323,136-byte OCI archive, verified the selected descriptor and
ordered layers, and extracted the effective 5,124,505-byte broker executable
with SHA-256
`f794d0324a72062d800c7da6bc3164d933db9bb67e3c6ea95e6204e601922e96`.
This is a **prior-revision component input**, not the current-source Desktop
image, running broker or positive full-profile freeze.
The final-source locally resource-controlled repository race/shuffle suite
(`-p=2`) passed; the security package took 277.587 seconds. This source
validation still does not prove default-concurrency CI or any live Slice 6
scenario.

Checkpoint 2026-09-30 (Vault persistent trust cutover and FD-loader
components, not acceptance): a tagged real Docker test now uses a run-owned
private native Vault `file` backend on the isolated controller bridge. It
generated two distinct internal issuer UUIDs/certificates, signed final
Vault server and controller-client leaves from the general issuer, inspected
each issuer's signed complete CRL, stopped and restarted the same server on
the same storage with final TLS 1.3 mTLS trust, then securely unsealed without
key argv. Both issuer DERs survived and neither complete CRL number regressed.
A separate non-root observer container at the exact controller bridge address
now invokes the repository's strict fixed-issuer HTTP observer both before
and after the restart. It verifies the real TLS 1.3 peer URI/name/EKU, mTLS
client, both issuer UUIDs/DER digests and complete signed CRL metadata across
the trust switch; it emits only public issuer/CRL metadata and is exactly
removed after each read.
A separate client at the reviewed controller address succeeded under final
trust, both temporary client-CA and temporary server-CA directions were
rejected, and a second final-trust positive probe followed the denials.
The bootstrap root token was revoked, temporary trust files were removed and
run-labeled Docker resources were exactly cleaned. The scoped controller ACL,
all production role `issuer_ref`s, managed certificate-controller/agent chain,
DNS broker/general admission and full Profile freeze are still absent. This
component cannot be counted as one of the 16 scenarios.

The six FD-bearing role build targets have a closed input inventory in
`product-phase-6-slice-6-fd-startup-inventory.md`. A Linux one-shot loader
with a canonical, bounded run/target/container-ID/nonce envelope now creates
sealed 0600 seekable memfds, maps only fixed FD0/FD3…FD6, and `exec`s the
unchanged role as PID 1. A real repeated test exposed Go runtime epoll FD4
colliding with direct loader mapping, so the FD-stage image now uses a fixed
Alpine shell `exec` trampoline to reserve FD3…FD6 as `/dev/null` before Go
starts. The loader verifies those inherited slots and marks unused slots
close-on-exec; it rejects unsafe startup environment names. A non-secret
fixed-role fixture passed in a real
non-root, capability-dropped, no-new-privileges, read-only, seccomp-constrained
Docker container for ten bounded repeated positive/negative runs without a
netpoll crash; stale nonce was rejected and exact resources cleaned. The
local role image builder now selects a loader stage only for those six
targets, and the private source-bound candidate schema is v2 so the second
binary must match an independent build and selected OCI layer. This is
component/provenance preparation only: the same real Docker test also rejected
a truncated envelope, handled absent fixed exec target with a fixed stage
code, rejected missing/forged reserved slots and unsafe shell-related
environment, and stopped on pre-exec TERM without automatic restart. The real
certificate-controller launch, held-open-input deadline, all 82 principals,
all 16 scenarios,
immutable evidence and push remain open. Phase 6 remains **5/15**.

Checkpoint 2026-10-01 (source-bound desired Profile, not role admission):
all 12 repository-owned role candidates, the matching Desktop candidate,
locked Browser archive, and four external service archives were rebuilt or
reopened from clean runtime revision
`142ea0c3e372178cc3cfbaf1714621cfdb21a955`. The opt-in real
persistent-Vault trust-switch test also composed and validated an 82-principal
desired Profile using same-run real Vault general and broker issuer CA bytes
plus distinct run-owned authority keys. This remains a *desired* source-bound
document: the five logical trust purposes are not five issuers. The initial
composition diagnostic incorrectly used general-only for the internal server
bundle; the reviewed two-issuer mapping below corrects that input. It is
still not independently proven service-specific chains. No controller,
credential agent, TLS agent, or 82-principal topology was launched by this
test.

| Profile trust purpose | Minimal issuer set in candidate source | Reviewed consumer/edge dependency |
| --- | --- | --- |
| `external-server-ca` | general | External Vault, PostgreSQL, Valkey and DNS server leaves on the 18 direct external edges. |
| `internal-client-ca` | general | Clients on the 17 local numeric mTLS edges, including roles dialing broker servers. None of these edges has a broker as client. |
| `internal-server-ca` | general + broker-only | Ordinary local servers plus the five `egress-role-*` broker server edges. |
| `postgres-client-ca` | general | Dedicated PostgreSQL client leaves and exact HBA/CN/database/source checks; CA trust is not SQL authorization. |
| `vault-client-ca` | general | Controller bootstrap/managed Vault client-leaf validation and Vault's corresponding client-CA admission on `certificate-vault`; Vault policy/role ACL remains separate. |
| DNS broker client CA, separate from the five Profile anchors | broker-only | Five `egress-dns*` client leaves; general-client negative admission must be observed at real CoreDNS. |

The table reflects the fixed two-issuer ADR and reviewed 152-edge inventory,
not a statement that every listed service has already run or that sharing
general CA creates separate compromise domains. The real gate must compare
issuer UUID/DER, fixed Vault `issuer_ref`, leaf URI/SAN/EKU and peer-CRL
source for every observed edge. A service's authorization denial must not be
misreported as a TLS CA denial.
The source-bound finalizer now enforces these exact CA DER sets and rejects a
general-only internal server source, broker trust on unrelated purposes,
duplicate/extra roots or a general DNS client CA. This closes a static
configuration hole but still says nothing about running mounts or handshakes.
The same-run real-Vault composition now also passes the strict Slice 6 gate
input loader against clean R=`142ea0c3e372178cc3cfbaf1714621cfdb21a955`:
82 principals, all 12 source-bound local-role candidates, the matching
Desktop candidate, resource/seccomp policy and frozen scenario routes. The
same-run preflight also inspected 14 distinct loaded Docker image identities
against the Profile's local and locked Browser references. The tagged
non-race run took 120.31 s and cleaned its exact Docker resources.
This is input admission only, not a launched controller, a 16-scenario run,
or an immutable evidence manifest.

The composition path now fully loads the original image/external inputs,
performs only private pure intermediate binds, and independently reopens all
original sources at final candidate verification. Public Bind/Freeze and
VerifySources boundaries remain strict. An optional diagnostic records source
load counts and per-stage elapsed time without entering the Profile digest or
release evidence. In one non-race Docker run the observed counts were exactly
two full image loads and two external archive passes; image/resource load took
26.01 s, external archives 3.49 s, Desktop broker extraction/profile
derivation 3.06 s, and final independent source reopen 32.94 s. The whole
corrected two-issuer Vault trust-switch plus composition and source-mutation
test took 95.46 s and exactly cleaned its
run-owned Docker resources. These timings are host-specific diagnostics, not
a bootstrap deadline or deployment-capacity guarantee. The corrected
two-issuer tagged Docker/race diagnostic passed in 668.48 s; the race tool's
overhead must not be mistaken for production startup duration. A same-run
negative recheck
replaced one general-issuer anchor source with the
other valid Vault broker CA at the same read-only mode; the frozen candidate
rejected the changed source, and the test restored the exact run-owned bytes
with exact cleanup. This is source-integrity evidence,
not proof of a live service certificate chain. The still-unlaunched
controller/agent chain, live external-service issuer mapping, 16-scenario
gate, immutable evidence and push keep Phase 6 at **5/15**.

Checkpoint 2026-10-01 (capacity restoration, still no topology launch): after
the source-bound input/Docker-store preflight, host available space had fallen
to 21,133,668 KiB, below the existing 21.5 GiB full-gate admission bound.
The pinned Sandbox coordination approved one `go clean -cache` for the exact
Go 1.26.8 `GOCACHE=/Users/echo/Library/Caches/go-build` after all active Go
builds ended. This removed only cross-project, rebuildable compile cache
(31,565,328 KiB before, 8 KiB immediately after); no Docker container,
volume, image, candidate OCI archive, module download, source or evidence was
cleaned. Actual host free space rose by 31,681,580 KiB, not assumed from
the cache's `du` figure. The real opt-in host+Docker capacity probe then
reported 53,784,285,184 host-available bytes versus 23,085,449,216 required,
and 356,393,771,008 Docker-backing-available bytes versus 17,179,869,184
required. The cleanup incurs cold Go rebuild cost and is not durable capacity
proof: the full runner must remeasure both sides immediately before each
writer-heavy stage and stop early on reserve loss. No topology was launched
or Slice 6 evidence emitted.

Checkpoint 2026-10-01 (two-issuer peer-CRL controller input, not controller
execution): the same-run real persistent-Vault test now derives the canonical
private peer-CRL source document from the two independently observed issuer
UUIDs and DER digests plus the complete candidate Profile. It obtains 48
edge/direction/principal bindings, derives and revalidates minimal role
documents for all 16 ordinary TLS subjects that actually own an mTLS peer
edge, and separately covers all nine PostgreSQL-purpose signer roles. A
Unix-only material agent with no mTLS peer edge correctly gets no peer-CRL
role document. The source file is reopened through the production strict
decoder, then exactly removed with the run-owned temporary directory.
The tagged real test passed in 128.64 s with exact Docker cleanup. No
certificate-controller process consumed this document, no active connection
was revoked, and no 16-scenario or release evidence was emitted; Phase 6
remains **5/15**.

Checkpoint 2026-10-01 (v3 consumer correction, supersedes the old candidate
counts above but not their historical observations): the Browser/Desktop v3
executor paths consume live `phase6tls` signers and peer-CRL guards, not the
V2 material registries. Sandbox therefore removed only `browser-agent`,
`desktop-agent` and their two dedicated Vault-client TLS agents from the
unaccepted final desired inventory. The current closed target is **78**
deployments, **36** ordinary TLS-agent bindings, **11** material agents,
**12** credential issuer sockets, **30** final external paths and **35**
external edge IDs. Nine PostgreSQL-purpose signers, five egress brokers,
real Browser/Desktop runtime/executor signers and all 16 release scenarios
remain. Existing UID/GID and role/service CIDRs are unchanged for every
survivor: tombstones reserve the retired slots, and a snapshot comparison
against clean old R pins all 78 surviving identities and 121 final networks.
The resource/seccomp assignment manifest now has 78 exact deployments; its
recomputed steady envelope is 7360 MiB, 7450 CPU millicores, 2000 PIDs and
the Browser+Desktop active envelope is 8896 MiB, 9450 millicores, 2384 PIDs.
The new `phase6security` and `phase6profilebuilder` package suites and
non-Docker tagged gate tests pass. This is a revised desired candidate, not a
measured process topology. Existing R=`142ea0c3e372178cc3cfbaf1714621cfdb21a955`
images embed the old profile validators and cannot be combined with it;
the C/R/E source and affected role archives must be rebuilt together.

The same checkpoint adds a repository-owned private material authority
plan for the **11** remaining actual v3 material agents. It binds owner,
principal, UID/GID, credential socket, backend policy, fixed Vault token
role, exact secret binding/version/purpose and **18** distinct KV v2 data
paths. Each agent's policy text grants only `read` on its own exact paths;
the readback verifier rejects even a formatting or extra-capability drift.
The `certificate-controller-pki` policy remains separate. This is a static
plan and test only: no KV mount or document has been created, no ACL/token
role has been read back from real Vault, no actual material or managed TLS
certificate has been issued to the two controllers, and no agent has read a
live secret. Vault service-side ACLs cannot limit a reader to one KV version;
the existing client still must check the requested and returned version.
The prior 82-principal/two-issuer composition and 48-edge peer-source run is
historical evidence for the superseded source candidate, not a 78-principal
gate result. Phase 6 remains **5/15**, with no release evidence or push.

Checkpoint 2026-10-01 (material policy enforcement and real Vault diagnostic):
the v2 material-agent command now checks its complete material binding set,
fixed backend policy, credential policy/socket, migration property and KV
mount/reference authority against the verified 78-principal Profile plan.
The credential-controller command separately requires all 11 corresponding
policy/peer/renewability bindings before starting. This closes a source-level
configuration substitution route; it does not attest a launched process.
The persistent, file-backed non-dev Vault trust-switch test additionally
installed and read back one disposable exact KVv2 read-only policy and fixed
token role, then used Vault's privileged capability query against a scoped
token to observe own-path `read` and cross-owner/metadata/PKI/generic-token
`deny`. It retained the root-token revocation, two-issuer trust cutover and
exact run-owned cleanup. The diagnostic installed no business material and
is not one of the release scenarios. A separate opt-in test path is written
to install/read back the full 11-agent/18-path ACL inventory, 12 fixed token
roles and distinct certificate-controller PKI policy against a same-run
source-bound Profile; it remains unexecuted until the corrected clean-source
candidate images are rebuilt. Sandbox explicitly approved run-owned real
PostgreSQL/Valkey accounts and appropriately generated short-lived keys as
local operator bootstrap input, provided genuine one-shot migrations and
consumer-side reads/operations follow and all secrets/resources are precisely
destroyed. Capability inspection alone remains insufficient. Phase 6 remains
**5/15**.

Checkpoint 2026-10-01 (corrected R18, actual Vault PKI role installation;
component evidence only): local commit `18aec6db4620bf50c54091c7f3ebd264c7e2f5d3`
froze the corrected 78-principal runtime source, and twelve role candidate
archives were built from it. A clean independent R18 checkout, those exact
archives, the pinned Browser/Desktop/external images and the same-run real
file-backed non-dev Vault were used to recompose and reopen the final desired
Profile. Vault was restarted across the final mTLS trust switch while the two
issuer UUIDs and complete CRLs remained stable. The test installed and read
back the KVv2 mount, all 11 exact material ACLs covering 18 data paths, all
12 fixed scoped token roles and the separate certificate-controller PKI ACL.
It then installed and read back 38 distinct PKI roles bound to the two actual
issuer UUIDs. The roles explicitly disallow localhost, arbitrary names,
wildcards, IP SANs, subdomains, URI templates and unreviewed OtherName SANs;
the PostgreSQL-purpose roles are client-only even where their owning runtime
also serves HTTPS. The managed controller CSR was signed by both the root
bootstrap token and a real constrained certificate-controller token, while a
different principal's CSR was rejected under both; the resulting certificate
was checked for issuer, URI and client EKU. Vault capability probes verified
positive own-path and negative cross-owner, metadata, PKI and generic-token
access. The tagged Docker test passed in 148.44 s with exact run-owned Docker
cleanup and root-token revocation. It did **not** start either controller,
write business KV documents, run a material agent, execute the 16 scenarios,
emit release evidence or push. Phase 6 therefore remains **5/15**.

The subsequent same-run Docker repeat also attached that Vault process to
the separate reviewed `service-workload-credential-controller-vault` isolated
bridge at its fixed service address and exact DNS alias, independently
observed the sole expected Vault endpoint there, and kept the existing
`network-certificate-controller` bridge intact. The full PKI/ACL test then
passed again in 148.56 s with exact cleanup. This establishes the two
controller network prerequisites only; neither controller container has
started or exercised a managed certificate exchange.

Checkpoint 2026-10-01 (unfrozen post-R18 source correction): the proposed
final Profile now assigns the certificate and credential controllers separate
exclusive persistent ledger mounts and assigns 75 actual Profile consumers
dedicated read-only private-config mounts with closed filenames, purposes and
storage IDs. Startup checks bind controller ledger paths and the first set of
static authority/Profile/peer-role paths; ordinary and PostgreSQL-purpose
derivatives are separate, and migration jobs receive only their PostgreSQL
role. Both controller ledger implementations now reject an unknown or
SIGKILL-leftover temporary file at restart and before another write, rather
than accumulating or silently deleting it. Focused package tests pass. This
revision has not been frozen into new role images, and the R18 archives cannot
be used as evidence for it. Sandbox clarified that named-volume `MaxBytes`
is a logical file-set budget, not a Docker hard quota: the future live gate
must measure files/bytes/owner/mode, read-only write denial and disk headroom.
No new controller process, full topology, 16-scenario result, release
manifest, push or Phase 6 count advancement is claimed; Phase 6 remains
**5/15**.

Checkpoint 2026-10-01 (restricted private-config preparation component): a
same-run, labeled Docker named volume was prepared by a one-shot UID-0
container using a pinned Alpine image, no network, read-only root filesystem,
all capabilities dropped except `CAP_CHOWN`, no-new-privileges, locked
seccomp and bounded memory/CPU/PIDs. Non-secret fixture bytes entered only
through stdin; ownership and 0700/0600 modes were set before the prep
container exited and was removed. A distinct non-root reader reopened the
same volume read-only, checked exact file count/owner/mode/SHA-256 and observed
write denial. Docker inspect confirmed the effective capability, seccomp,
resource, network, rootfs and sole-volume settings; rerunning prep against
the nonempty volume was rejected. The labeled volume and containers were
precisely cleaned. An
initial test attempt exposed the necessary `chmod`-before-`chown` ordering
under the constrained capability set; the corrected test passed. This is a
fixture mechanism test, not the 75-principal file distribution, actual
Profile/peer-role semantic verification or live controller startup.

Checkpoint 2026-10-01 (exact archive handoff and validation): the private
configuration preparation input now goes through a per-deployment archive
builder before Docker stdin. It accepts only the Profile-declared closed file
set, requires the exact canonical Profile bytes, bounds each file and the
aggregate logical byte count, emits deterministic 0600 regular-file tar
members, and records file SHA-256 digests and the total byte count for subsequent
independent reopen. The real restricted Docker prep component was rerun using
this builder and passed; the full Go race suite and `go vet ./...` also passed
for the preceding source checkpoint. The component still used a synthetic
Profile and is **not** the 75-principal distribution or evidence that Docker
enforces a named-volume disk quota. The current post-R18 source remains
unfrozen, with no controller launch, 16-scenario receipt, release manifest or
push. Phase 6 remains **5/15**.

The same handoff API now rejects an incomplete or extra deployment set and
returns no partial archive unless all 75 actual Profile readers have exact
private file sets. It clears already-built private archives on later failure.
This validation is exercised with synthetic document bytes; it does not
claim that the 75 real authority/peer-role inputs have been generated or
mounted in their final containers.

Checkpoint 2026-10-01 (R19 source-bound diagnostic): source commit
`ca775af31af267f34067f2b12d594984ef6a37ce` passed the complete race,
vet and Product Contract lock checks. Twelve repository role images and a
Desktop image were rebuilt and privately recorded from that revision; the
independent image-supply preflight reopened all 12 role pairs, Desktop and
locked Browser OCI chains. The first attempt at the real Vault composition
failed early because the test creates run-private files under its current
package directory, making that same checkout dirty during the source lock
check. It left no labeled Docker container, network or volume. The test now
rejects a same-checkout source path before side effects. With a separate clean
R19 checkout, the same-run file-backed non-dev Vault diagnostic passed in
155.11 seconds: the complete 78-principal Profile, 48 peer-CRL bindings, two
real issuer roots and complete CRLs, 11 exact material ACLs, 12 scoped token
roles, 38 issuer-pinned PKI roles, scoped/root CSR positive and foreign
denial, capability probes, root-token revocation and exact labeled Docker
cleanup were observed. No controller process, actual business KV document,
material-agent consumer, first migration, 16-scenario result, release
manifest or push was produced. Phase 6 remains **5/15**.

Checkpoint 2026-10-01 (same-run real controller startup file transfer):
using the separate clean R19 source checkout and its matching private image
candidates, the real Vault diagnostic now also prepares the two actual
controller `private_config` named volumes from the just-composed Profile and
peer-CRL source document. The certificate controller received the exact two
declared files (429987 logical bytes) as UID:GID `20010:30010`; the
credential controller received only its Profile file (418680 bytes) as
`20057:30057`. Each one-shot UID-0 preparer ran with no network, read-only
rootfs, only `CAP_CHOWN`, no-new-privileges, the locked seccomp policy,
bounded memory/CPU/PIDs, no logging and a sole fresh named volume; effective
Docker inspect fields were checked. It exited and was removed before a
distinct non-root reader mounted the volume read-only and verified the exact
file count, ownership, 0700/0600 modes, SHA-256 digests and write denial.
The full same-run Vault PKI/ACL diagnostic passed again in 151.05 seconds,
and the run-labeled container/network/volume inventories returned zero after
cleanup. This is real input transfer for **2 of 75** Profile readers, not a
controller launch or certificate/credential/material consumer result. The
other 73 private file sets, both persistent ledger mounts, business KV
documents, migrations, full topology and 16 scenarios remain unobserved.
No release evidence or push was produced; Phase 6 remains **5/15**.
After adding effective seccomp/no-new-privileges/no-logging inspect checks
and clearing private archive bytes on every helper exit, the same real
diagnostic passed again in 191.02 seconds while the full race suite was
running. The final full race suite, tagged test compilation, ordinary and
tagged vet, Product Contract lock and diff checks passed; exact labeled
Docker cleanup again observed zero containers, networks and volumes.

Checkpoint 2026-10-01 (same-run empty controller ledgers): the same R19
Vault/Profile diagnostic now also creates two distinct run-labeled local
named volumes for `certificate-controller-ledger` and
`credential-controller-ledger`. Their one-shot, no-network preparers only
assign the intended controller UID:GID and 0700 directory mode; they do not
write `ledger.json` or another file. Effective Docker rootfs, capability,
seccomp, no-new-privileges, no-logging, resource and sole-volume settings
were inspected. A distinct non-root read-only observer saw an empty directory
with its own UID:GID and write denial for each. The real Vault/78-principal
composition, two private-config volumes and full ACL/PKI diagnostic passed
in 148.23 seconds; run-labeled containers, networks and volumes returned
to zero. This proves only empty, exclusive startup storage allocation, not
ledger creation by a controller, a persistent restart, corruption/loss
denial, a hard volume quota or any accepted release scenario. Phase 6
remains **5/15** with no release manifest or push.

Checkpoint 2026-10-01 (real credential-controller bootstrap, still a
diagnostic): the R19 source-bound same-run Vault/Profile test now derives 12
distinct credential-client Ed25519 keys, creates 13 isolated restricted Unix
socket directories and five separate root-owned trust-anchor file volumes,
and independently checks each anchor's Profile SHA-256, 0444 file mode and
non-root read through its eventual read-only bind. The limited 15-minute
Vault management token, bootstrap P-256 private key and Profile-bound managed
CSR request key enter the immutable credential-controller image only through
the one-shot sealed FD-loader envelope; none is placed in its JSON config,
arguments, environment, volume or log. The container uses the reviewed
non-root UID:GID, exact private-config and ledger volumes, isolated Vault
bridge, read-only rootfs, dropped capabilities, no-new-privileges, locked
seccomp and Profile resource bounds. The real controller process reached its
certificate-controller-only credential listener and created its own 0600
`ledger.json`; an intentional pre-switch stop removed the socket inode and
the exact labeled Docker container/network/volume inventories returned to
zero. This passed in 158.17 seconds at the prior R19 candidate image source
revision `ca775af31af267f34067f2b12d594984ef6a37ce`.

Earlier same-run diagnostic attempts failed closed before a live listener:
Vault's 30-second NotBefore backdate exceeded the bootstrap certificate's
strict total-life ceiling, its default non-CA Basic Constraints setting was
incompatible with the production validator, and a concatenated PEM chain
lacked a separator. The operator PKI role now explicitly pins and reads back
the 30-second backdate and non-CA Basic Constraints setting; bootstrap signing
requests a shorter lifetime, and the exact bundle passes both
`tls.X509KeyPair` and the production bootstrap-certificate validator before
FD delivery. Those failures were diagnostic, not accepted evidence. The
certificate controller has **not** started, the credential controller has
**not** switched to a managed Vault mTLS identity or exposed its other 11
listeners, no material agent consumed a scoped lease, and no full-topology
16-scenario receipt or release manifest exists. Phase 6 remains **5/15**;
there is no push or production-readiness claim from this checkpoint.

Checkpoint 2026-10-01 (two-controller startup diagnostic and validator
repair, not an accepted gate): after a corrected credential socket cleanup
check, the same-run real R19 Vault diagnostic passed again in 182.00 seconds
and observed zero run-labeled Docker resources. A subsequent pass also signed
an independent certificate-controller bootstrap leaf through its exact Vault
role and assembled a canonical 38-policy v4 config (71,719 bytes in that
run); it did not yet start the certificate process. The opt-in two-process
attempt prepared all 50 restricted controller socket directories and started
the real credential process, but the real R19 certificate-controller PID1
rejected its policy set at `certificate-policy` before managed issuance. Its
failure run cleaned all labeled Docker containers, networks and volumes.

A separate same-run production-`Policy.Validate` preflight then classified
all 38 policies in one pass: 12 ordinary TLS and 7 PostgreSQL-purpose policies
were rejected by the older private delegation validator; 19 were accepted.
The two split Provider PostgreSQL signer policies happened to pass under a
shared historical `provider_tls_agent` name and still require the final
Profile's full instance/purpose/owner binding. A limited private policy
repair now separates ordinary and PostgreSQL-purpose delegation and adds
only the already approved finite relationships; focused race tests pass, but
the corrected runtime source has not yet been frozen into a new candidate
image or retested as a real certificate process. A separate source audit found
a cyclic final revocation dependency between the two controllers. Sticky
Close-result tests now preserve remote-revocation failure after local secret
destruction; a bounded quiesce, independent short-lived operator cleanup,
exact remote readback and production acceptance are still incomplete. The
older diagnostic retains its initial root token until the end and cannot be
used as final rootless-managed-operation evidence. No managed switch, full
16-scenario receipt, release manifest, push or count advancement is claimed;
Phase 6 remains **5/15**.

Checkpoint 2026-10-01 (R27 real source-bound terminal operator component):
the R22 immutable role/Desktop image candidates and a separately built clean
R27 operator source were exercised with a file-backed non-dev Vault, complete
78-principal Profile, and both real controller PID1 processes. Both
controllers issued managed leaves and produced bounded quiesce ledger receipts.
The independent one-shot operator then read back a signed complete CRL
containing the two exact controller certificate serials, observed revocation
of both exact target token accessors through Vault, and revoked its own
short-lived token. The targeted real-Docker test passed in 211.00 seconds.
This is a controller trust-switch/terminal-cleanup **component** pass, not a
16-scenario Slice 6 release gate, deployment, evidence manifest or production
readiness result. Phase 6 remains **5/15**. A real Vault 400 response for a
revoked accessor uses the precisely reviewed wrapped `invalid accessor`
error; the restricted adapter accepts that one observed shape while still
rejecting other 400s, forbidden, missing and unavailable responses.

R22 exposed an accounting gap: the pinned Vault image declares `/vault/file`
and `/vault/logs` VOLUME paths, so Docker creates two implicit anonymous
volumes even with only explicit bind mounts in the command. Earlier runs
verified zero **run-labeled** containers, networks and named volumes but did
not prove cleanup of those unlabeled implicit volumes. The R28 cleanup change
uses `docker rm -f -v` only for the exact run-labeled container. A no-secret,
real-Docker opt-in test captures both exact mount-to-volume associations,
requires Docker's anonymous-volume metadata, removes that exact container,
and checks `no such volume` for both IDs; it passed. The R28 full Vault test
captures the same associations for its real Vault server and checks their
removal after its own cleanup. Earlier dangling anonymous volumes are
retained because their exact historical container ownership is unproved;
age, emptiness or dangling status alone is not deletion authority.

R28 subsequently passed the full real source-bound Vault/two-controller/
one-shot operator path in 223.78 seconds. The test captured the two exact
anonymous volume IDs from the running Vault server's Docker mounts, confirmed
their anonymous metadata, and after labeled cleanup required Docker's
`no such volume` response for both. Managed issuance, both persisted quiesce
receipts, complete CRL with both target serials, both target accessor
revocation readbacks and operator self-revocation also passed. At this
checkpoint the complete `go test -race -shuffle=on -count=1 ./...` run, ordinary
and tagged `go vet`, Product Contract lock verifier, and diff check passed.
This proves same-run component cleanup only; historical unowned volumes and
the full 78-deployment/16-scenario gate remain outside the claim. Phase 6
remains **5/15**.

Checkpoint 2026-10-02 (R29/R30 first run-owned business KV material):
R29 added a Guest-specific, create-only KVv2 write of a freshly generated
Ed25519 signing key, with exact binding digest, version, revision, rotation
window and SHA-256 envelope. A short-lived `guest-agent-kv` token actually
read back KV version 1 and the exact key; a cross-owner Gateway path returned
explicit permission denial. R29 then failed closed because that deliberately
KV-read-only token had no `auth/token/revoke-self` authority. Sandbox chose to
keep the production ACL unchanged and perform this diagnostic token's exact
accessor revocation through the controlled bootstrap, before root destruction
and before the managed controller chain. R30 implements that narrower cleanup:
the accessor is read back with its sole expected policy, revoked through a
file-fed bootstrap call, and independently read back as Vault's `400 invalid
accessor`; no token or accessor appears in a command argument or log. The
real source-bound Vault/Guest-KV/two-controller/one-shot-operator test passed
in 219.56 seconds, including managed issuance, both quiesce receipts,
complete CRL, two target accessor revocations and exact same-run Docker plus
implicit-volume cleanup. The Guest key is genuine run-owned material, but no
material-agent or Guest process consumed it yet; this is not a Slice 6 release
scenario, immutable evidence bundle, push or count advancement. Phase 6
remains **5/15**.
The subsequent complete race/shuffle suite, ordinary and tagged vet, Product
Contract lock verifier and diff check passed against this checkpoint; the
run-labeled Docker container, network and volume inventories remained empty.

Checkpoint 2026-10-02 (R31 Guest TLS-agent startup input): the same-run
source-bound Vault diagnostic additionally derived the ordinary v3
`guest-agent-tls-agent` command document from the exact frozen Profile,
peer-CRL source digest, and its run-owned certificate request key. It checked
the request and controller-response public-key digests against the Profile
and validated the certificate policy before producing a 2,799-byte canonical
configuration. The full real Vault/Guest-KV/two-controller/operator path
passed in 209.82 seconds with exact run-owned cleanup. No Guest TLS-agent,
material-agent or Guest process has started, so this is startup-input
component evidence only and Phase 6 remains **5/15**. The next live process
step is pending a closed authority check for the material and break-glass
Unix sockets; gate-only hand-entered paths cannot replace the Profile.
The checkpoint's complete race/shuffle suite, ordinary and tagged vet,
Contract lock verifier, and diff check also passed.

Checkpoint 2026-10-02 (material socket static boundary and v2 transport):
Sandbox's architecture ruling identified that the historical same-UID
material and break-glass sockets cannot connect the planned independently
identified processes. The unaccepted final Profile now derives 11 closed,
unique material-agent endpoints and mount directions from the existing
agent→owner facts. Focused negative tests reject missing/duplicate endpoints,
owner or identity drift, broader modes/deadlines/capacity, storage alias,
extra reader, writable owner mount and overlapping parent mount. The explicit
`workloadagent` v2 path uses the restricted cross-UID Unix layout, exact peer
credentials, two-second first-frame deadline, tracked connection drain and
same-inode cleanup; its real Linux Docker test passed with distinct agent
and owner UID/GID, wrong UID/GID denial, stalled first frame, canceled
client request, and tracked stalled-connection drain. v1 remains unchanged
for Slice 5 compatibility. The v2
material agent checks its Profile endpoint before credential issuance;
Guest v3 checks its Profile and exact v2 binding inventory before the first
signing-key resolution. This invalidates the prior R22 runtime images as a
final Slice 6 candidate. Break-glass v2 and the full live topology still
remain open; no new R was frozen and Phase 6 remains **5/15**.
The complete race/shuffle suite, ordinary and tagged vet, Product Contract
lock verifier and diff check passed; the newly added config v2 negative test
also passed separately. Exact `sr-material-v2-*` Docker container and volume
inventories were empty after the live component test.

Checkpoint 2026-10-02 (break-glass static and Unix v2 component boundary):
following Sandbox's explicit ruling, the unaccepted Profile now contains
one operator→controller control, seven agent→controller consume and seven
operator→agent delivery sockets, plus eight finite one-shot operator tasks
outside the 78 fixed deployment principals. Exact kind/target/UID/GID,
operation set, path, storage, `0710+0666` modes, mount direction, first-frame
limit, capacity, resource bound and cleanup are revalidated even after a
Profile digest rewrite. Focused negatives reject wrong-endpoint operations,
cross-agent target, aliased storage, extra reader, task privilege or mount
drift. The controller's ledger and audit now share an exclusive, bounded
persistent allocation; its private Profile file raises actual Profile readers
from the historical 75 to 76. Explicit controller and agent v2 Unix
constructors preserve the v1 signed business payload while refusing
same-UID v1 transport fallback. A real Linux Docker controller component
test passed signed submit across different UIDs, unsigned consume rejection,
wrong-operation/peer/GID rejection, stalled connection drain and exact
socket/container/volume cleanup. The material-agent v2 command now verifies
both its consume and delivery endpoints against the Profile before credential
issuance. No break-glass production controller command, complete
actor/target public-key supply, full signed approval/issue/delivery/consume,
restart/replay proof or 78/16 release gate is claimed. Phase 6 remains
**5/15**; previous R22 images and Profile are not final candidates.

Checkpoint 2026-10-02 (break-glass finite binary-bind correction): Sandbox
rejected the draft Alpine-only task because that carrier lacks the named
operator executable. The unaccepted Profile now binds one source-built static
Linux arm64 artifact with exact revision/tree/toolchain digest/build/binary and
carrier index/manifest/config identity. Each of eight tasks declares only a
read-only executable file plus its sole read-only socket directory. The
source-bound composer independently rebuilds and byte-compares the artifact;
the dedicated command accepts bounded, canonical, pre-signed input and no
actor private keys. Unit and static Profile tests are component evidence.
The Profile-bound v2 controller command now checks all 11 actor public keys,
its signer FD, eight endpoint bindings and persistent state path before
opening the ledger/listeners; that path has not yet passed a complete live
controller gate. A separate real Linux Docker one-shot component test passed
pinned carrier index/selected arm64 manifest/config checks, exact two read-only
mounts, container security policy, created-container binary readback, a
pre-signed submit, socket disappearance, persistent ledger/audit presence
and exact container/volume cleanup. It did not run the complete approvals,
issue, delivery, consume, replay or restart path; no release gate or count
advancement is claimed.

Checkpoint 2026-10-02 (source-bound break-glass actor identity): composition
input advances to v3 and now supplies 12 existing credential identity keys
before Profile freeze, plus four external actor public keys and one controller
signer private key. Seven nonmigration agents project their existing identity
key as the break-glass target key. The Profile digest covers exact actor ID,
kind, owner, key ID and public-key digest; the final static gate rejects a
missing/duplicate/aliased actor inventory. The v2 material agent compares
its identity FD public key to its target binding before credential issuance.
This is source/configuration and unit evidence only; the production
controller's full live proof and 78-deployment/16-scenario gate are still
absent. Phase 6 stays
**5/15**.

Checkpoint 2026-10-02 (same-run break-glass storage preflight): clean source
`1f2c8b3cd536b5e045681372f6d6cb6c2f1e28b4` produced 12/12
independently verified local-role OCI candidates and a matching arm64 Desktop
candidate. The strict image-supply and resource-draft preflights passed, as
did the real Desktop broker/executor-v2/Provider candidate chain. In a real
file-backed non-dev Vault run, the complete source-bound 78-principal Profile
was composed and reopened; the live test prepared three separate controller
private-config volumes, three empty persistent ledgers (the break-glass ledger
and audit share their exclusive 128 MiB allocation), 50 certificate/credential
socket allocations, 15 additional break-glass control/consume/delivery socket
allocations, and five trust-anchor allocations. Each new break-glass socket
volume was created empty with its declared server UID, sole client GID and
`0710` directory mode, observed read-only, and removed with the run. In the
same run, both existing controller PID1 processes reached managed issuance,
quiesced, and the independent terminal operator completed its confirmed
cleanup; Docker resources returned to zero. The production break-glass v2
controller, finite signed approval/issue/delivery/consume chain, role graph,
16 scenarios and strict Slice 6 manifest were **not** run or produced. This
is a diagnostic checkpoint only; Phase 6 remains **5/15**.

Checkpoint 2026-10-02 (real break-glass controller and finite control chain):
the independent clean source `1f2c8b3cd536b5e045681372f6d6cb6c2f1e28b4`
supplied the exact local controller/operator candidate binaries to a same-run
real Vault/Profile preparation. A separate break-glass-controller container,
running as the Profile's `20000:30000` identity with a sealed FD 3 signer,
opened all eight v2 control/consume listeners on its distinct restricted
socket volumes and created its own persistent ledger and audit. Each of seven
finite, networkless operator invocations was a separate `20091:30091`
container with only the Profile-bound read-only executable and the designated
read-only control socket mount; the test inspected the created container and
rehashed its actual mounted executable before passing pre-signed input. The
real controller accepted a requester submit, two different signed approvers
at exact revisions and a signed one-use capability issue. It rejected a
different, correctly signed request that reused the submit JTI, excluding
duplicate request ID as the explanation. After stopping and removing that
controller container, a separate non-root, read-only observer found the
ledger and audit present and all eight controller sockets absent. A new
container ID and startup nonce, with the same exclusive persistent allocation,
then loaded the ledger, rejected a new correctly signed request reusing the
recent issue JTI, accepted a fresh request/JTI, and again closed all eight
sockets on stop. The complete real Vault/controller diagnostic passed in
248.76 seconds; the run-owned `sr-p6-` Docker container and volume inventories
were empty afterward. The target material agent was not started, so
capability delivery, online target consume, one-use replay after consume,
controller/agent concurrent failure, the 78-deployment/16-scenario gate and
an immutable Slice 6 manifest remain unproved. This is component evidence;
Phase 6 stays **5/15**. The complete repository race/shuffle suite, ordinary
and Slice 6 tagged vet, tagged gate compilation, Product Contract lock
verification and diff check passed at this checkpoint.

Checkpoint 2026-10-02 (material-agent v2 GID correction, component scope):
reviewing the pending real Guest target revealed a deterministic contradiction:
the Profile binds the material socket directory to the consumer's GID and
requires it to differ from the agent's GID, while the v2 Vault mTLS client
compared that directory GID to the agent process/subject GID. Sandbox confirmed
this as an implementation defect, not a reason to weaken identity isolation.
The v2 material agent now checks its actual primary UID/GID and all
supplementary groups against the Profile's agent identity before first
credential issuance, and repeats that rule before Vault client construction.
It separately verifies the exact material socket's consumer directory GID and
the TLS signer binding; v1 remains unchanged. Focused race/shuffle and
negative tests cover distinct agent/consumer groups, wrong primary identity,
extra owner/operator/root groups, source drift and signer substitution; the
existing real Linux cross-UID/GID material socket gate passes. The R1 role
images used above predate this correction and cannot serve as final Slice 6
candidate artifacts. The actual Guest material-agent Vault mTLS/material
service process, delivery/consume chain and final gate still need a rebuilt
clean-source candidate and live observations. The complete repository
race/shuffle suite, ordinary vet, Product Contract lock verifier and diff
check passed after the code correction. Phase 6 remains **5/15**.

Checkpoint 2026-10-03 (Product PID1 pre-issuer image admission recovery):
the first approved Product runtime component attempt, run label
`9aa04d490f668b3d577befb7b01757b6`, stopped at Docker exit 125 before
Vault startup, issuer allocation or Product PID1. The pinned Vault
`repo@sha256` reference was absent from the local Docker store despite valid
source-bound OCI archives. The run-labeled container/network/volume inventory
was zero afterward, but the harness had copied Docker error text into its
container-ID variable; it therefore could not produce an exact historical
anonymous-volume receipt. That missing receipt is **not** reconstructed as a
successful cleanup proof. This attempt supplies no Product/SQL/fault evidence.

The then-repaired pre-issuer path checked fixed external, local-role,
Desktop, Browser, Alpine-preparation and network-probe Docker references after
source/archive verification and before any live network or issuer material.
Docker Hub's canonical repository-digest spelling is normalized without
changing the digest or accepting a different repository. Vault now uses
`create`, validates its exact name/run label and two anonymous-volume IDs,
then `start`; an invalid/lost create response is recovered only by exact
name **and** run label for cleanup, never as permission to start, and an
unresolved create remains a failed/unknown cleanup result. Preflight
rejection before `create` has no anonymous-volume
assertion; completed creates retain the strict two-volume removal proof.
The missing fixed external and network-probe caches were restored only by
their pinned digests. A no-secret real Docker start-failure drill and the
existing two-volume cleanup drill passed without starting Vault or an issuer.
The four external images' stopped-container selection tests rechecked the
index, selected arm64 manifest and OCI config against the complete private
archives. This is cache/preflight/component evidence only. A new Product
runtime issuer-consuming run needs separate Sandbox authorization. The
source-bound no-issuer admission passed for the then-enumerated 12 local
role targets, Desktop, Browser, four external images and two auxiliary
images after cache restoration; it did not create a container. A subsequent
fail-closed correction forbids `start` even when exact name/label recovery
succeeds if Docker `create` reported an error or a noncanonical ID. Unit
regressions cover error, noncanonical, wrong-ID, exact success and unknown
responses; separate no-secret real Docker drills recovered the two implicit
volumes from the actual container ID and removed them for both simulated
lost and noncanonical create responses without starting Vault. Phase 6
remains **5/15**.

Checkpoint 2026-10-03 (finite task carrier omitted from the prior admission):
the one approved run `0f7ce67ed9637b0bfef15a1df5a49ddf` passed source and
Docker admission, composed/reopened the 78-principal Profile, started the
Vault/controllers/PostgreSQL chain and completed a separate Product
`migrate v2` PID1 with same-PostgreSQL ledger/ownership/grant readback. It then
failed at the first finite break-glass task `docker create`, **before**
Product `serve` PID1, readyz, runtime SQL or network fault. The locked task
reference was `docker.io/library/alpine@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40`;
Docker reported that exact image absent. The prior admission had checked the
distinct `d858...` prep/terminal/observer reference and `85fe...` network
probe but not the finite task's index. Therefore its “all fixed references”
claim was incorrect. The same run's terminal operator confirmed three
certificate revocations, two token accessors, complete CRL and self-revoke;
the two recorded Vault anonymous volumes were absent after cleanup, and the
run-labeled container/network/volume inventories were zero. This is a failed
Product component attempt, not Product runtime or Slice 6 success.

The offline correction adds the finite task's **index** from the locked
Profile authority to pre-issuer batch admission, separate from its selected
manifest. With `d858...` present but `fd791...` absent, a complete no-issuer
source-bound admission rejected `missing=[break-glass-operator-task]` before
any container creation. The original `fd791...` digest was then pulled from
its registry; no tag, lock or candidate image was substituted. A no-secret,
stopped-container drill used the same reference and finite-task read-only
executable/socket mount shape, verified the raw index, selected arm64
manifest, config and layers against a private Docker export, and removed its
exact container and socket volume without starting an operator or issuer.
Unit regressions cover batch missing/drift, artifact/task-vs-admission
binding, and bounded, redacted Docker create categories with context/exit
status. The corrected no-issuer source-bound admission passed after cache
restoration. This remains component/preflight evidence; a fresh issuer run
requires new explicit authorization and Phase 6 remains **5/15**.

Checkpoint 2026-10-03 (approved Product runtime component pass): Sandbox
approved one issuer-consuming rerun bound to E
`1e607f6fa498de136445800d2092c92df855ce34`, unchanged clean R3
`923813f9a195ca7f49202ee11de4796ee6a8ef17`, Go 1.26.8 and the
previously approved Product observer digest
`sha256:7151292b6f4571892502d786c8486cdf24ac7b19bb25e2cf171eec5ad1b99123`.
The single run `6f518819018b5ea95246a57c05f09c6d` passed in 409.91 seconds.
Its pre-issuer source/archive/21-image admission and observer mount passed;
the same-run 78-principal Profile digest was
`sha256:b10950396fc683b041de332d2e84c9a330422e1b3df71749780f7dfdeaf9cef0`.
The real finite task passed the previously failing create point and exercised
nonce/JTI replay rejection. Independent PostgreSQL and Product `migrate v2`
PID1 processes completed with same-PostgreSQL ledger, ownership and grant
readback. Product `serve` PID1 then passed its exact seven-network/three-socket
Profile, TLS `/readyz` ready → SQL-edge loss not-ready → original-PostgreSQL
recovery ready, and a read-only `product_runtime` SQL session. The same-run
Guest TLS/material-agent and break-glass consume/restart chain also passed,
but the formal Guest production PID1 and Product↔Guest security edge were not
exercised. The Product material helper's earlier “SQL login remains unproved”
log describes only that helper; this later Product PID1 test did prove the
runtime SQL session. Terminal cleanup confirmed three certificate revocations,
two token accessors, complete CRL and self-revoke. After the passing test,
an independent check found zero run-labeled containers, networks and volumes;
both recorded Vault anonymous volumes were absent, and E/R3 were clean. This
is Product runtime component evidence, **not** the same-run 16-scenario Slice 6
release gate, immutable manifest, deployment or production qualification.
Phase 6 remains **5/15**. The historical instruction above to stop after
Slice 6 was superseded by the user's later request to continue subsequent
Phase 6 slices after their own gates; it is not current work sequencing.

Checkpoint 2026-10-03 (Guest storage preparation, no issuer): Sandbox approved
true Guest-only business storage after review of the development service's
actual startup and materialization needs. The proposed final Profile now
closes three exclusive Guest named volumes (`/workspace` 3 GiB logical,
`guest-state` 1 MiB logical, `/inputs` 1 MiB logical read-only) and two 8 MiB
Guest tmpfs mounts. Source-side startup checks bind exact directory ownership,
mode, canonical run/storage receipts and the selected-image BusyBox executable
digest; development materialization preserves the volume receipt across
commit/rollback. A separate no-secret Docker component drill used the
previous R3 source-bound core image only to verify actual UID:GID/modes,
read-only input denial, tmpfs type/size/options, volume identity retention
across two containers and exact run-owned cleanup. This is **not** a new R
freeze or formal Guest PID1 evidence. The preflight budget conservatively adds
3 GiB + 2 MiB because the existing 10 GiB estimate did not isolate Guest
storage. Docker named volumes have no hard quota; deep-path metadata/inode
limits and full Development capacity remain Slice 8 gaps. No new issuer was
run. The accepted R3 Product component result remains historical and Phase 6
remains **5/15**.

Follow-up 2026-10-03 (Guest persistent-state closure and offline startup):
the source-bound final Profile composer was missing the new Guest storage
attachment even though the desired Profile path had it; the offline
composition test found this before any issuer use, and the composer now
attaches the same closed mounts. Guest v3 now checks a closed state directory
before material resolution: only the receipt and two 8192-byte-bounded
materialization documents are permitted, no symlink or group-writable file
is accepted, and unknown/oversized/corrupt/crash-temporary entries fail
closed without deleting evidence. Focused race tests cover the negative cases
and receipt survival across commit, rollback and restart. A synthetic-CA
offline source-bound composition has passed; it is not a Vault-issued Guest
certificate, Product-owned durable Guest binding, formal Guest PID1 or release
scenario. The six-file Guest v3 private configuration was checked in a
separate no-issuer Docker volume drill: the source-bound composition and
real Guest private-config volume passed ownership, mode, exact file digest,
read-only denial and four-volume exact cleanup in 119.61 seconds. The
synthetic Guest ID/generation is construction input only, not Product-owned
PostgreSQL binding evidence. The full repository race/shuffle suite, ordinary
and tagged Slice 6 vet, Product Contract lock verifier and diff check passed
after these source changes. Phase 6 remains **5/15**.

Sandbox then approved an initial-binding-only local fixture plan, not an
issuer run: one source/binary-digest-bound, finite, build-tag-only process
may use the original Product runtime UID:GID, fixed PostgreSQL IP, runtime
SQL role, material socket and remote TLS signer before Product PID1 starts.
It must create/read back Workspace and Guest binding through the real Product
Store, then close every dependency and release that endpoint before Product
occupies it. A ready-slot seed is limited to exact run-owned tenant,
workspace, slot and expected generation with one-row CAS/readback. No HBA,
production API, migration/admin privilege or Guest private-key expansion is
approved. At this checkpoint the build-tag-only fixture command and the
sequential finite-container harness are implemented but **not yet executed
against the real Product PostgreSQL service**. The fixture reads only canonical,
bounded run/Profile-bound non-secret identity and the public half of the
actual Vault Guest signing key; it resolves the runtime DSN through the
existing v3 Product material registry, PG signer and peer-CRL path. It uses
the real Product Application and GuestService, performs a one-row exact
ready-slot CAS and readback, verifies the persisted binding's public-key
digest, event, audit and idempotency replay, and emits only a private bounded
receipt. The ordinary CLI does not include this build-tag-only command.

The gate harness builds the Linux/arm64 binary from the same separately
clean source revision, requires an externally supplied exact binary SHA-256,
probes it under Product's non-root UID:GID without network, and, only after
the real Product migration and signers are online, may start it on Product's
original fixed PostgreSQL source IP. Its container is read-only, drop-ALL,
no-new-privileges, seccomp-bound and no larger than Product; it mounts the
Product private config, runtime material socket, PostgreSQL signer and
Product trust anchors, but **not** the public TLS signer or Guest private key.
The harness requires a clean finite-process exit, exact container removal
and PostgreSQL bridge readback with the source endpoint released before
formal Product startup. A no-issuer Docker ownership probe additionally
confirmed that a missing or wrong-run private volume is rejected before
Docker can silently create it, then returned its one run-labeled volume to
zero. A diagnostic build from the current mutable checkout
cross-compiled and executed `--help` in a real non-root, networkless, read-only
Alpine container; a separate `docker create -i` / `docker start -ai` probe
verified bounded stdin and exit observation with `--log-driver=none`. These
are no-issuer mechanics checks, not immutable-source, database, Product–Guest
or release evidence. No new Vault issuer run was authorized or performed;
Phase 6 remains **5/15**. Live Guest PID1, Product–Guest authentication,
restart/revocation behavior and the complete 16-scenario gate remain open.

Sandbox subsequently approved a separate build-tag-only live-revocation task
which temporarily shares only the exact running Product container's network
namespace. ADR 0055 records the exception, while preserving the fixed
PostgreSQL HBA and normal Product CLI. The command's first implementation
accepts one canonical run/Profile/executable/target/initial-receipt-bound
operation; it reads the exact unexpired connected Product-owned binding,
calls the existing `Store.RevokeGuest`, and classifies a bounded readback
without retrying an unknown mutation. It does not issue general SQL, expose
a production endpoint or claim a persisted revocation audit. Tagged race
tests cover input/target/key/generation drift, before/after binding scope,
database-time expiry and the distinction between confirmed, still-connected
and revoked-after-unknown outcomes. Only `confirmed` may later count as a
passing gate mutation; a revoked row after an unknown write is not attributed
to the helper. The helper also includes its own PostgreSQL backend PID in a
private receipt for post-exit absence checking; that readback is not yet wired
to a live scenario.
A separate no-issuer Docker test observed actual `--network=container:<target>`
net namespace equality, independently private IPC/PID namespaces, zero added
network endpoints/ports, non-root read-only/drop-ALL constraints, target
namespace survival after helper removal and exact run-owned zero cleanup.
The first probe exposed Alpine's absence of a standalone `/bin/readlink`;
using its pinned `/bin/busybox readlink` applet passed. Docker reported
`IpcMode=private`, which is the expected isolated mode, not a shared IPC
namespace. This remains a mechanism test: no live Product/Guest process was
revoked and no issuer was used. Phase 6 remains **5/15**.

The next no-issuer source-bound synthetic-CA composition reused immutable
R3 supply and passed in 121.96 seconds after adding a strict Guest launch
plan. It admitted the exact `guest-product` and `network-guest-runtime`
isolated networks, Guest-owned material/TLS sockets, six-file private config,
three exclusive storage volumes and two tmpfs mounts. The existing real
Docker private-config preparation verified Guest/Product/PG-agent file
owners, modes and digests, read-only denial and four run-owned volume cleanup
to zero. The old R3 shell digest is construction-only; a new R must reobserve
the selected executable. This does not start Guest or Product PID1, issue a
real CA certificate, create a durable binding or complete any Slice 6 release
scenario. Phase 6 remains **5/15**.

Follow-up 2026-10-03 (Guest PID1 launch wiring, still no issuer): the Product
component runner now keeps its exact PID1 and PostgreSQL/signers alive while
the dependent Guest chain runs, then rechecks their process fingerprints and
Product SQL endpoint after that chain returns. A tagged Guest runner now
requires the finite Product binding receipt, the same-run running Product
container and its existing isolated `guest-product` bridge; it measures
`/bin/sh` from the selected Guest image, prepares six private configuration
files and three run-owned storage volumes, joins exactly the Product and
Guest-internal bridges, admits only two private signer sockets and closed
trust/storage/tmpfs mounts, and checks the real Guest process's connected
`/readyz` before exact container cleanup. These are implementation paths,
**not** observed live Guest PID1 or formal scenario evidence. The new opt-in
flag cannot be selected without the initial binding fixture. The no-issuer
synthetic-CA offline composition was rerun against retained historical R3
candidate inputs and passed in 122.90 seconds, now deriving the shell digest
from the selected image at runtime instead of reusing a historical literal.
It again verified six Guest, four Product, two PostgreSQL-agent private files,
one signer socket and four-volume cleanup to zero. The initial fixture's real
SQL path, Guest PID1 connection, live revocation harness and complete 16-case
gate are still unrun. Historical R3 inputs cannot certify the changed source;
a new clean R freeze and explicit Sandbox issuer authorization are required.
Phase 6 remains **5/15**.

The approved live-revocation helper is now wired as an optional nested
operation only after the Guest PID1's dependency-derived connected `/readyz`.
Its same-source sealed executable receives a canonical run/Profile/Product-ID/
initial-binding-bound operation on stdin. The finite task mounts only the
Product private config, runtime material socket, PostgreSQL TLS signer,
trust anchors and its own read-only binary. Docker admission checks the exact
running Product/Guest/PostgreSQL and Guest-agent fingerprints, aggregate
run-owned memory caps against Docker VM memory with a reserve, and host/Docker
disk headroom. The task shares Product's network namespace only, with
separate PID/IPC, no new endpoint/port and no public signer or Guest key.
After the Store mutation, the harness requires the command's exact confirmed
receipt, clean exit/removal, absence of all recorded helper PostgreSQL backend
PIDs, an explicit bounded Guest `/readyz` HTTP 503 or independently verified
same-run Guest exit1 of unproven cause, a second negative observation three seconds
later, and independent PostgreSQL readback of `revoked`, null nonce and an
unexpired binding. Product/PostgreSQL and Guest agents retain their original
PID1 and endpoint fingerprints; the Guest PID1 is permitted to exit after
revocation. This is **code and component validation only**: no real live
binding has been revoked and no formal challenge/welcome/reconnect transcript
was captured. The no-issuer Docker namespace probe exercised aggregate memory
admission and exact cleanup. Phase 6 is still **5/15**.

Follow-up 2026-10-03 (Sandbox capacity/reconnect review, no issuer): the
live-revoke helper now uses a one-connection pool under the unchanged shared
`product_runtime` SQL role limit of four. Admission counts idle and active
same-role backends, records each helper backend PID, and rejects replacement.
The helper holds its sole connection at a one-shot stdin handshake; only after
the gate sees a distinct Product SQL backend and Product's independent HTTPS
readiness may it continue to the single Store revoke. The Guest probe now
parses exact HTTP 204/503 and fails on arbitrary Docker/timeout errors. A
deterministic `guestagent` component test witnesses a denied reconnect and
`ErrUnauthorized` termination; the real process harness deliberately makes
the narrower claim of explicit not-ready or post-mutation exit1, not an
attributable reconnect denial. Capacity sampling with the Guest's additional
3 GiB + 2 MiB budget now starts before run-owned writers and cancels/stops
exact run-labeled writer containers on loss. A no-issuer real Docker drill
verified stop-before-zero-cleanup, and a separate no-issuer Docker stdin
handshake drill passed. R4 runtime images may pair with a later E fixture only
when a machine-checked clean R4→E Git diff contains fixture-tagged command
files, gate tests or docs, not ordinary runtime/build inputs. These are
mechanism tests and implementation changes, **not** the real Vault issuer
run, full 16-scenario gate or release evidence. Phase 6 remains **5/15**.

Follow-up 2026-10-03 (capacity-stop race correction, no issuer): Sandbox
accepted the exact R4 runtime/E fixture split and the sealed helper digest,
but found that the first capacity-stop implementation returned immediately
when an enumerated container disappeared during nested cleanup. It could
therefore miss still-running Product/PostgreSQL/Vault writers. The corrected
gate treats only Docker's exact `no such object: <same ID>` as confirmed
disappearance, retains ambiguous inspection failures, and attempts stop/kill
for every separately verified same-run target. Two bounded inventory passes
and a final active-writer readback catch late starts; after the nested runners
unwind, a second sweep uses the **same** original 90-second stop budget before
the registered exact run cleanup, so no new writer can start after that
lifecycle barrier. A deterministic multi-target test covers first-target
deletion, target-specific stop failure with later writer still processed,
foreign-run protection and a late writer. A real no-issuer Docker drill then
deleted its first enumerated writer while another continued, observed the
second stop and an unrelated run still live, and cleaned both labels to zero.
The first drill exposed a leading newline in Docker's exact missing-object
response; the parser now accepts only those two exact wire spellings. These
checks do not prove the full topology or authorize a Vault issuer run.
Actual Guest exit1 remains a post-mutation observation of **unproven cause**,
not confirmed authorization denial or completed old-binding reconnect gate.
Phase 6 remains **5/15**.

Follow-up 2026-10-03 (one authorized R4/E2 issuer diagnostic, **failed**):
clean R4 runtime revision `4e02121f84a13622e15d732090335850aaa90cd3`
and clean E2 fixture revision `2f5632508731c89840f23bc6f013cc9b750f0c6c`
entered one real-Vault run `810d129d6d98d5dc976a8817cf18d26a` with Profile
`sha256:0099088dccefbdd053ea4a3f5911ead51aed1707dbbe68f002b6fe725e0fe347`.
The external PostgreSQL PID1, two managed controller PID1 processes, guarded
Product migration and its ledger/grants readback, and Product signers were
observed. The first reported failure was a generic Product material-agent
callback error before any confirmed initial Guest binding or Product `serve`;
the old callback used `t.Fatal` and discarded its actual cause. Quiesce
receipts were observed, but the certificate controller retained a terminal
credential-revoke error and independent v2 terminal plan binding failed. The
external PostgreSQL leaf's terminal revocation remains **unconfirmed**; exact
run-labeled Docker containers/networks/volumes were subsequently zero, and
both recorded Vault anonymous volumes were absent. Docker resource removal is
not credential-revocation evidence. No second issuer run, complete topology,
Guest live-revoke observation, 16-scenario gate or manifest is claimed.

No-issuer follow-up found a separate, reproducible fixture admission bug: a
source-bound synthetic-CA offline run reached finite container create/inspect
but rejected Docker's pre-start empty `NetworkID` as a fixed-IP drift. That
race-enabled diagnostic failed in 861.83 seconds; it did **not** start the
fixture, connect SQL or use Vault. The tagged gate now checks the unique
requested network key and IPAM address at `created` state, allowing only an
empty or exact `NetworkID`; after `docker start -ai`, it keeps stdin open and
checks the exact running container, effective NetworkID/IPAddress and
PostgreSQL bridge membership **before** sending the one bounded canonical
payload. The fixture's `RunE` blocks reading stdin to EOF before it opens a
SQL pool. Wrong/extra network identities, address drift, early exit and
cancel all keep the payload withheld. Fixed Alpine no-secret Docker barrier
tests passed; the corrected source-bound offline container admission passed
in 130.65 seconds with exact run-resource cleanup. These establish mechanism
and container-admission evidence only. Because the original real-run callback
cause was lost, this bug is a strong candidate, not a proven retrospective
cause of run `810d…`. Non-migration and migration material-agent failure paths
now preserve callback errors and perform once-only stop/drain/remove/socket
cleanup before outer signer/controller teardown; focused race tests cover
failure, cancellation-style cleanup and `Goexit`. No terminal strictness,
ordinary runtime image or Provider Contract was relaxed. Phase 6 stays
**5/15** pending a fresh Sandbox decision and real-gate evidence.

Follow-up 2026-10-03 (R4/E3, one further **authorized** real issuer
diagnostic, **failed**): the first E3 invocation stopped before Vault or run
allocation because the gate checkout was also supplied as the supposedly clean
fixture source; the pre-issuer observer build had placed a temporary directory
there. A separate clean checkout was fixed at E3 revision
`19f60a14a31e5c6ddd0898c90a5a0a39e386b0a7`, tree
`2240a15ab40fd9ad63ba0b422c18a1965620c560`. A no-issuer source-bound
offline admission then passed in 124.41 seconds with exact Docker cleanup. The
first invocation did not consume the real signing permission.

The subsequent single real run `04d45efd81f8c5027ca3e944d65e5422` paired
the same R4 runtime with E3 and froze Profile
`sha256:c530b2ec54260ba2ebe5975af2e1e5f9924be22986d005a8342ba41a4ff8f709`.
Its source, 21 fixed image references, E3 Guest fixture and Product observer
hashes, R4 terminal operator hash, non-root mount probes and continuous capacity
admission passed. A fresh local Vault and real server leaf were observed, so
the signing permission was consumed. The 78-principal/12-candidate Profile and
48 peer-CRL edge bindings were derived, explicitly without a live controller
read. The first reported failure was `create exact run-owned controller
private-config volume` after the 20-minute parent deadline; the capacity
monitor reported `context deadline exceeded` and confirmed both emergency and
final stop attempts without an error. The race-instrumented source/archive
reopens consumed much of the budget, but the fixed safe error does not expose
the exact Docker failure cause, so deadline causation is an inference. The
test exited failed in 1245.17 seconds without controller PID1, Product
migration/serve, external PostgreSQL leaf, Guest binding/PID1 or live revoke
evidence. Strict v2 terminal cleanup did not run; Vault root self-revoke,
accessor revocation, CRL readback and any credential-revocation conclusion
remain unconfirmed. This run never signed a PostgreSQL leaf.

Independent post-run inventory found zero containers, networks and volumes
with the exact run label, and both recorded Vault anonymous volume IDs were
absent. The separate R4/E3 source checkouts and temporary build directories
were clean. Docker/file removal is not credential-revocation evidence. No
automatic real issuer retry, Slice 6 release manifest, 16-scenario gate or
production-readiness claim follows; Phase 6 remains **5/15** pending Sandbox
review.

Follow-up 2026-10-04 (one Sandbox-authorized ordinary, non-race R4/E3 issuer
diagnostic, **failed**): run `7113b25683391e4a29a434d392dde62f`, Profile
`sha256:4dfb9c04580c085b8be28e5248a1bd7483f2e037f35b0a0ab09ed8720de5786b`,
used the same clean R4 runtime and E3 fixture. It reached the real Vault and
PostgreSQL leaves, two controller PID1 processes, Product migration with the
same-PostgreSQL ledger/grant readback, an initial durable Guest binding
(generation 1, one event, one audit), and Product `serve` PID1 with
ready→SQL-edge-loss not-ready→same-PG recovered-ready readback. The Guest
material agent and break-glass replay/recovery component paths were observed.
The Guest runtime PID1 and live revoke/reconnect were **not** observed. The
capacity monitor stopped run-owned writers with only its former generic reason.
At that revision, normal cleanup removed the observer **before** closing the
monitor, so the monitor could also have fired during cleanup; the log has no
causal timestamp proving it fired before the Guest branch ended. The at-event
host threshold, Docker threshold, sampling/exec failure or parent-context
cause cannot be distinguished retrospectively, and the capacity stop is
**not** established as the cause of missing Guest evidence. A later host
free-space read is not an at-event measurement. The quiesced certificate
controller retained a sticky terminal credential-revoke failure; the separate
v2 terminal operator confirmed three certs, two token accessors, complete CRL
and self-revoke, but that receipt does not erase the controller error. Main
Docker cleanup was attempted with the canceled business context and failed; its
registered fallback then removed exact run-labeled containers/networks/volumes
to zero, and both recorded anonymous Vault volumes were absent. This diagnostic
does not establish the 16-scenario release gate or a manifest.

Sandbox then directed an E-only observability and cleanup-order correction,
with **no** further real issuer/business mutation run permitted. The capacity
interlock now emits only closed stage/class, sample number, elapsed time,
valid available/required or stop thresholds, context class and last-success
age. Unknown or missing metrics are unavailable rather than zero; raw Docker,
`df`, paths and environment are not emitted. It distinguishes input, host stat
read/value, bounded Docker exec/output, `df` syntax/value, host/Docker/both
thresholds, parent cancel/deadline, sample timeout and unknown while retaining
`errors.Is(..., errSlice6Capacity)`. The monitor captures context state before
its own cancellation and commits the first trigger before invoking the stop
callback. The ordinary exit and `testing.T` fallback now share one independent
45-second exact run-labeled cleanup deadline and preserve the first cleanup,
business, capacity and terminal failures. Normal exit closes the monitor
before removing its observer; fatal/`Goexit` cleanup remains registered.
Create-unknown recovery, anonymous-volume readback and exact zero-resource
assertion remain in the same cleanup path. No production runtime, fixture,
observer binary, Provider Contract or threshold/cadence was changed.

Deterministic tagged race tests cover failure classes and redaction, both
thresholds, `df` integer/output overflow, parent cancellation versus sample
timeout, normal-close sampling race, once-only stop and first-error cleanup.
One opt-in no-issuer, no-Vault/PG/business-write Docker drill used fixed Alpine,
one exact-label observer and at most two extra network-none, read-only
containers. It passed an idle period and ten sequential create/remove
perturbations without a natural monitor trigger, then deliberately injected
one classified sample loss and observed both exact-run writers stopped and
exact-label cleanup to zero in 8.07 seconds. This does **not** reproduce the
old capacity incident or justify a new issuer run. Phase 6 remains **5/15**.
Post-edit checks passed: `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, the focused `phase6slice6gate` race/shuffle test set,
`go vet -tags=phase6slice6gate ./productphase6gate`, the fixed no-issuer
Docker diagnostic, the Product Contract verifier and `git diff --check`.

Sandbox review identified and approved one further E-only error-reporting
connection before any new issuer run: the Vault gate's pre-issuer monitor
admission and the direct no-issuer diagnostic admission call sites now print
the monitor's already-closed, bounded failure rather than replacing it with a
generic message. A deterministic admission test asserts the safe
`stage=admission class=invalid-input` projection. This changes no admission
decision, threshold, poll interval, sample timeout, stop action or runtime
artifact. The historical `7113…` monitor alert may have been caused by the
observer's removal during ordinary cleanup; its old log cannot order that
alert against the missing Guest runtime evidence. The audit therefore does
not assign the Guest failure to capacity. A further single real issuer run
requires a clean, independently validated E-only successor revision and is
not evidence already obtained here.
The successor's focused tagged race/shuffle test, tagged vet, full repository
race/shuffle/count-one test, ordinary vet, Product Contract verifier and diff
check passed before it was selected for any further real issuer diagnostic.

Follow-up 2026-10-04 (one further Sandbox-authorized ordinary, non-race R4/E3
real issuer diagnostic, **failed**): clean E-only gate/observer revision
`f0403fbe370983db327efc459de1e35a6b30e26f`, tree
`45c04207300788bd775d987779505b50b9693c9b`, paired with the same clean
R4 runtime/terminal and independent E3 fixture. New run
`c67fee7bd535215e91cae2b998f44c37` froze Profile
`sha256:947895a14644701fbb4fdf3f73b9d596df4dba8efc466f9c269774a66cdee385`.
Source/archive/image and pinned observer/fixture/operator hashes, non-root
mounts and continuous capacity admission passed. Real Vault server and
PostgreSQL leaves, PostgreSQL PID1, two controller PID1 processes, Product
migration with same-PG ledger/ownership/grants, Guest initial durable binding
(generation 1, one event, one audit), Product `serve` ready→SQL-edge loss
not-ready→recovered ready, and Guest material-agent/break-glass consume and
replay/restart paths were observed. Guest runtime PID1 and live revoke were
**not** observed. The first retained business error was `Product live dependent
gate failed` → `Guest private signer socket volume missing` during the Guest
runtime's pre-create socket-volume admission. No capacity monitor failure or
emergency-stop error was reported in this run. It exited failed in 440.30 s.

Read-only source analysis narrows the missing socket to a likely gate-topology
gap, not a proven runtime or Docker defect: the Guest launch plan requires the
`guest-tls-agent`→`guest-runtime` signer socket; the Guest agent input step
adds only the distinct `guest-agent-tls-agent`→`guest-agent` socket and Guest
material socket. The certificate-controller allocation covers agent→controller
directories, not each agent→subject signer socket. The live chain starts the
Guest material agent's TLS signer but does not start the separate Guest
runtime TLS signer. This hypothesis needs a bounded no-issuer topology check
before any correction or new real signing attempt.

Both controllers persisted quiesce receipts, but the certificate controller
still retained its sticky terminal credential-revoke failure. The independent
v2 terminal operator confirmed three certificates, two token accessors,
complete CRL and self-revoke; this does not erase the controller error. The
new shared exact Docker cleanup reported no error. Independent post-run
label inventory found zero containers, networks and volumes; both recorded
Vault anonymous volume IDs were absent, all three source checkouts were
clean, and the diagnostic log was mode 0600. Docker cleanup does not prove
credential revocation. This run consumed its single issuer permission and
does not authorize an automatic retry, complete the 16-scenario gate, or
produce a release manifest. Phase 6 remains **5/15**.

Follow-up 2026-10-04 (Sandbox-directed E-only Guest dependency correction;
**no new issuer run**): the failed `c67fee…` diagnostic exposed a missing
deployment edge in the gate, not evidence of a Provider, Contract or runtime
change. The existing frozen Profile already binds a separate
`guest-tls-agent` to `guest-runtime`. The gate now checks the complete prior
67-socket Guest supply against each storage ID and same-run volume name,
prepares that agent's source-bound private Profile/peer-CRL config and
exclusive subject socket, and projects a separate
68-socket map only into Guest runtime startup. The Guest material agent keeps
its original 67-socket map; Product's original 67→74 chain is unchanged. A
dedicated `guest-runtime` label selects the ordinary TLS-agent runner without
using the older `guest` diagnostic label. The direct signer must report ready
before Guest PID1 starts and remains alive through its callback; Guest PID1
returns before the signer cleanup sequence. The runner's existing exact
signer-socket cleanup, failure-path fallback and run-labeled Docker cleanup
remain in force. The terminal operator derives certificate revocations from
its ledger rather than a frozen count of three.

The final opt-in, no-issuer Docker check used the fixed R4 source/role/Desktop
candidate, locked Browser publication, four selected arm64 OCI manifests and
synthetic public CA material. The four external archive components were
independently reverified. Two earlier no-issuer attempts failed closed before
Docker business startup because the diagnostic command first selected an R6
Desktop candidate against R4 source, then used three top-level OCI index
digests where selected arm64 manifest digests were required. Neither attempt
issued credentials or tested the new Guest path. The corrected check admitted
the full Product→Guest direct dependency plan, tested rejection of missing,
aliased and swapped cross-subject sockets plus an incorrect signer label, then
prepared and inspected the direct signer's
private config, controller edge and distinct subject socket with exact
UID/GID/0710/read-only checks. It passed in 120.85 seconds and cleaned all
exact run-owned diagnostic resources to zero. It did **not** start Vault,
PostgreSQL, the direct signer, Guest PID1 or Product PID1, issue a certificate,
or prove live revoke. The `c67fee…` first error is addressed in the gate
topology, but the real Guest path and the full release gate remain unproved;
Phase 6 remains **5/15**. No further real issuer run is authorized by this
offline result alone.

Follow-up 2026-10-04 (Sandbox-reviewed E-only Guest create-state correction;
**no real issuer run**): independent review of the preceding commit found that
the Guest container verifier demanded an effective Docker `NetworkID` before
`docker start`. The repository's existing finite Guest fixture already
distinguishes requested pre-start IPAM from running effective identity, and
Docker may leave the created container's effective ID empty. This was a
verified source-level mismatch, not an observed failure of a real Guest PID1.
The Guest gate now uses that same strict stage distinction for both approved
networks: exactly one name-or-ID key and requested IP per edge before start,
with an empty effective ID allowed only then; after start it requires the two
actual network IDs, assigned IPs and requested IPAM values. Missing, unknown,
duplicate, swapped and wrong-ID/IP endpoints fail closed. The running
network witness is tied to the same labeled Guest PID1 and does not replace
the later actual bridge-membership/readiness checks.

The real Guest PID1 gate and no-issuer diagnostic now share one closed Docker
`create` request for the selected image, non-root identity, private config,
two subject sockets, three business storage mounts, trust anchors, seccomp,
read-only root and exact tmpfs options (size, mode, UID/GID and hardening).
The corrected no-issuer diagnostic created the same Guest container on
`guest-product`, connected `network-guest-runtime`, inspected all requested
network/mount/tmpfs/resource constraints, confirmed state `created` and PID
zero, removed that container, then cleaned all exact run-owned resources to
zero. It passed in 143.30 seconds. It did **not** start Guest, Product, their
agents, PostgreSQL or Vault, and did not issue or revoke credentials. This is
Docker lifecycle mechanism evidence only; running effective networks, Guest
ready/live revoke and all 16 release scenarios remain unproved. Phase 6 stays
**5/15** pending a separately authorized real issuer gate.

Follow-up 2026-10-04 (one Sandbox-authorized ordinary non-race real issuer
diagnostic, **failed**, no retry authorized): clean E-only gate/observer
revision `81788808bc5f03cb7e07e150a30cc98ba0c40e2b`, fixed clean R4
runtime/terminal source and independent E3 fixture ran under exact label
`45361d9b18338f5fff47ad74341030b8`, Profile
`sha256:df809ccab4a4f5edc99050001cb72169fdf14911c72dd04ed56949e2b8233d1a`.
The 0600 diagnostic log is
`/Users/echo/.codex/phase6-slice6-run-E5.6EtkG8/gate.log`. Pre-issuer
source/archive/image, immutable binary hashes, non-root mount and continuous
capacity admission passed. The run reached real Vault and PostgreSQL, both
controller PID1 processes, Product migration with same-PG ledger/ownership/
grant readback, initial durable Guest binding (generation 1, one event and
audit), Product serve ready→SQL-edge loss not-ready→same-PG recovery, and
Guest material-agent/break-glass consumption and recovery.

The previous `Guest private signer socket volume missing` gate failure was
actually crossed: the separate `guest-tls-agent` private config/socket was
allocated; that PID1 issued a managed leaf and opened its listener in 21.05
seconds. The Guest runtime gate then returned from its created-container
check, `docker start` and running two-network check into the fixed readiness
loop. This is a conclusion from the branch's control flow and the subsequent
error, not a claim that Guest reached connected readiness. The first retained
business error was `Product live dependent gate failed` → `Guest PID1 did not
reach connected readiness within fixed deadline` after 45 seconds. No Guest
ready, live revoke, post-revoke 503 or exit-1 observation occurred. The
existing `/readyz` aggregates startup, Guest material resolution, peer-CRL
readiness and authenticated Product connection; the sanitized log does not
identify which prerequisite failed, so no cause is assigned. No capacity
trigger or emergency-stop error was reported.

Both controllers persisted quiesce receipts, but the certificate controller
retained its sticky terminal credential-revoke failure. The independent v2
terminal operator confirmed three certificates, two token accessors, complete
CRL and self-revoke; that receipt does not erase the controller error. The
main exact Docker cleanup reported no error. Independent read-only post-run
inventory found zero containers, networks and volumes with the exact label;
both recorded Vault anonymous-volume IDs were absent, and the gate, R4 and
E3 source trees were clean. Docker cleanup is not proof of credential
revocation. This single real issuer permission is consumed, does not complete
the 16-scenario release gate, and does not produce a manifest. Phase 6 remains
**5/15**.

Post-run source analysis (not a second issuer observation): the E5 Gate
builder emitted the exact Guest v3 `urn:sandbox-runtime:guest:no-recording`
marker, while the runtime `/readyz` path passed it to `secretref.Parse`, which
accepts only `file://`, `secret://` and `kms://`. Consequently the emitted
configuration could not reach a successful readiness result on that runtime.
This is a deterministic necessary blocker, not evidence that it was the only
cause of E5's 45-second failure. The correction confines the marker to Guest
production v3 and shares validation between startup and readiness; the Gate
now requires an explicit bounded HTTP 204 under one fixed deadline. These are
unaccepted runtime-plus-E source changes. R4 images cannot serve as fixed
runtime candidates; no new candidate or real issuer result is claimed.

No-issuer regression on the corrected Gate source: the clean R4 source and
its archived 12 role/Desktop candidates, locked Browser publication and four
external OCI archives passed static input admission. The opt-in offline
Product/Guest input test then called the actual Guest Gate generator,
decoded its emitted startup TOML as the runtime configuration, accepted the
exact Guest v3 marker through both startup and shared readiness validation,
and rejected a fake `kms://` replacement. Synthetic-CA private config,
read-only/mode/digest checks and four run-owned Docker volumes passed exact
cleanup in 115.15 seconds. This is a construction-only regression using old
R4 inputs, not compatibility evidence for the changed runtime, a new
candidate, connected Guest PID1, Vault issuance or live revocation.

Follow-up 2026-10-04 (Sandbox-authorized **no-issuer** new R candidate): the
corrected Guest v3/readiness code was committed as
`884fde822d9d9bad2abc428b5722403148fafcfa`, tree
`c87fb2d672ed1396e463769bdf67863eadbb9fb3`. All twelve local role
targets and the Desktop runtime were rebuilt for `linux/arm64/v8` from this
clean source; their local manifests/OCI archives are under
`/Users/echo/.codex/phase6-slice6-candidates-R884fde8.6bEh1r` and
`/Users/echo/.codex/phase6-desktop-R884fde8.MkmuXJ`. The new R static input
admission passed in 58.22 seconds, image-store admission passed in 59.62
seconds, and the no-issuer Product/Guest offline builder/configuration check
passed in 118.23 seconds with exact four-volume cleanup. These checks reused
the locked Browser publication and independently verified selected external
archives; they did not start Guest PID1, issue Vault credentials or establish
connected readiness. No image was published or signed for this result.

Independent clean R and F worktrees at distinct canonical paths now both
select that exact commit and tree. The E-only source-pair amendment accepts
the same-revision/same-tree case or the pre-existing strictly allowlisted
descendant case, rejecting dirty, aliased, wrong-revision, ancestor,
unrelated and ordinary runtime/dependency changes. Both fixture files retain
the exact build tag and locked Go target selection was exercised with and
without the tag. The actual R/F no-issuer source-pair test passed. A fixture
binary built from F under the locked Linux/arm64 flags was 39,645,657 bytes,
mode 0555, SHA-256
`3b581d68cebbf64c5bf27657a28b24bba19c534df60dbfc31104d3f4bff88af7`;
its exact digest was externally approved by Sandbox **only for no-issuer
Docker admission**. The independently
built R terminal operator was 9,965,229 bytes, mode 0555, SHA-256
`d9dd4bd4b47bf2a12e6e7cf88473e51522442f58e74224800c898a60763e2444`.
With that approval, the source-pair check, locked fixture rebuild/digest
readback, non-root networkless executable probe, and finite Docker
create/inspect admission passed in 126.46 seconds. The fixture container
remained unstarted; only a separate networkless `--help` executable probe
ran, not a business fixture operation. The test cleaned its exact run-labeled
containers, networks and volumes to zero. An additional read-only Docker inventory found
no resources with the Slice 6 run-label key. No SQL fixture mutation, Guest or
Product PID1, Vault issuer or live revocation was exercised. The E amendment's
complete regression passed full repository race/shuffle, the complete tagged
Slice 6 gate package race/shuffle, `go vet ./...`, Product Contract lock verification,
and `git diff --check`. Its commit is separate from this offline result. No real
issuer retry is authorized by these results; Phase 6 remains **5/15**.

Follow-up 2026-10-04 (one Sandbox-authorized ordinary non-race real issuer
diagnostic, **failed**, permission consumed): clean E4 source
`32a9fa1fdb3abc2bc05a8d7a973bcb30bcbc1f74`, independent clean R/F
`884fde822d9d9bad2abc428b5722403148fafcfa`, selected R candidates and
locked external archives ran under exact Docker label
`io.github.shell-echo.sandbox-runtime.phase6-slice6-run=f2277f0729bc587e52d59d23815e78ce`.
The 0600 log is
`/Users/echo/.codex/phase6-slice6-run-E6.froPzU/gate.log`. Pre-issuer
source/archive/observer/fixture/terminal digests matched. Vault, PostgreSQL,
both controllers, Product migration and durable initial Guest binding passed;
Product PID1 recovered readiness after a SQL-edge loss. Both Guest agents,
break-glass consume/recovery and **actual Guest PID1 connected `/readyz` 204**
passed while Product and agents remained live. The first retained business
failure was `Product live dependent gate failed` → `Guest live dependent gate
failed` → `old Guest identity was not persistently revoked with no nonce before
expiry`. The fixture's confirmed mutation receipt and temporary Guest
non-readiness did not pass that independent persisted readback. The later
Product/PG/agent liveness checks did not run. Two controllers quiesced; the
certificate controller retained its sticky credential-revoke failure. The
independent terminal operator confirmed three certificates, two token
accessors, complete CRL and self-revoke, but did not rewrite the controller's
failure. Exact run-label Docker container/network/volume inventory returned
zero, including the two recorded Vault anonymous volumes. No 16-scenario
release result or evidence manifest was produced. Phase 6 remains **5/15**.

Post-run diagnosis, **not** a corrected live-issuer observation: the read-only
SQL explicitly used `(expires_at>clock_timestamp())::text`, whose output under
the Gate's exact `psql -X -w -q -A -t -v ON_ERROR_STOP=1` flags is `true` for
an unexpired row. The old Gate expected `revoked||t`, which a matching row
could not produce. A narrowly scoped E-only patch keeps the original SQL and
compares exactly one `revoked||true\n` row; all other output and command
failures remain closed. Pure tests cover wrong spelling, expired/unrevoked/
nonce-present/missing/duplicate rows, whitespace, SQL failure and overflow.
An opt-in no-issuer networkless PostgreSQL arm64 Docker test used the same
formal SQL/psql path, passed the positive and negative persisted-row cases,
and cleaned its exact run label to zero. Its pinned upstream index is not the
exact E6 selected OCI archive manifest. Sibling explicit boolean `::text`
Product migration assertions already expect `true`/`false`; the other scoped
casts are integer fields. This narrows a false-negative mechanism but does
not prove the E6 row was actually persisted as intended or authorize another
issuer run.

The E-only successor passed `go test -race -shuffle=on -count=1 ./...`
(including the 339.639-second `internal/phase6security` package), the complete
tagged Slice 6 Gate package race/shuffle run with the opt-in no-issuer
PostgreSQL case, `go vet ./...`, tagged Gate `go vet`, Product Contract lock
verification and `git diff --check`. The no-issuer run's exact-label Docker
container/network/volume inventory was empty after cleanup. These receipts
do not change the failed E6 disposition or the **5/15** Phase 6 count.

Follow-up 2026-10-04 (one separately Sandbox-authorized ordinary non-race
real issuer diagnostic, **component PASS**, permission consumed): clean E
`34d72e05a115aa8fccbe5b9c0d94896c2ba26fb3` (tree
`e1c0609047fd9abaa1fafc7de0556ac7ecd74495`) and independent clean R/F
`884fde822d9d9bad2abc428b5722403148fafcfa` (tree
`c87fb2d672ed1396e463769bdf67863eadbb9fb3`) ran the unchanged
functional scope with the same twelve role candidates, Desktop candidate,
Browser publication and four selected external manifests. The formal
PostgreSQL selected arm64 manifest was
`sha256:2c942175a1255a9abe0366e48c1b401d9f50f835b04dfea13f111609b5530df7`,
not the upstream index used in the no-issuer SQL regression. The Gate built
the observer anew from E and matched approved SHA-256
`7151292b6f4571892502d786c8486cdf24ac7b19bb25e2cf171eec5ad1b99123`;
F fixture and R terminal matched their approved exact digests before issuer
allocation. Run label
`io.github.shell-echo.sandbox-runtime.phase6-slice6-run=c83334643195cf58aeaba5b54bbf2ec0`;
Profile
`sha256:e0701980a0413f33b8820132bb2b5f7d1d7ab6f7e16fbccdb4ce3e578ccc1926`.
The 0600, 19,477-byte log is
`/Users/echo/.codex/phase6-slice6-run-E7.EHgD5k/gate.log`, SHA-256
`79b32dec6a4c071982841bf01b625435342be68051bd53dbe470b0bfad87c521`.
The one tagged test exited zero after 479.29 seconds.

The actual Guest PID1 reached connected `/readyz` while Product PID1 and
both Guest agents remained live. The same-netns restricted task confirmed
one Product Store mutation; a bounded Guest 503 or exact exit-1 observation
followed. The successfully returned live-revoke function had first required
an independent single-row `revoked||true` PostgreSQL readback with an empty
nonce and DB-clock unexpired, helper SQL-backend absence, three seconds of
non-recovery before natural expiry, unchanged Product/PostgreSQL PID1
fingerprints, unchanged Guest PID1 or exact exit-1, unchanged Guest agent
fingerprints, and a live Product SQL session. This control-flow success is
not independent proof that the Guest 503/exit-1 was caused solely by business
revocation. Product's ready → SQL-edge loss not-ready → same-PG ready check,
initial durable binding and migration ledger/ownership/grant readbacks also
passed in the same run.

Both controllers wrote quiesce receipts; the certificate controller retained
its sticky **local credential-revoke failure**. The independent v2 terminal
operator separately confirmed three certificates, two token accessors,
complete CRL and self-revoke, with private plan digest
`sha256:4933a5f75af9c308b415007e6cad2652b04bf57c29904c8f63f24bd6fa049dc5`.
That remote cleanup does not erase the local controller failure. The Gate's
exact cleanup passed, and a separate read-only inventory found zero containers,
networks and volumes under the exact run label and both recorded Vault
anonymous-volume IDs absent. E, R and F worktrees remained clean. E6 remains
failed. This E7 result is a same-run **component chain**, not the required
full frozen deployment inventory and 16-scenario release gate, immutable
manifest,
publication or production-readiness result. No further issuer run is
authorized by this pass; Phase 6 remains **5/15**.

Follow-up 2026-10-04 (preissuer, no new Vault issuer run): clean R/F
`c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635` passed the required full
race/shuffle suite, vet, Product Contract lock and tagged attached-Docker
producer checks. Twelve role candidates were built from clean R; one Desktop
arm64 candidate was built from clean F using an existing APK cache, with the
build's exact lock-byte verification still enabled. An initial no-cache
Desktop build failed at locked APK staging and produced no candidate. The
new candidate outputs are local, unsigned and not yet release evidence. The
exact preissuer static-input admission passed for the clean R/F source,
twelve role candidates, Desktop candidate, Browser archive and four complete
external OCI archives. The separate preissuer image-store admission passed
for the 21 fixed references without a Docker create or issuer allocation.

E-only follow-up code now bounds the actual Guest-running, network-inspect
and first-readiness steps by the same 45-second deadline. It stages the
private evidence binding under `binding.pending`, verifies synced bytes,
publishes via no-replace link, syncs and independently rereads, and attempts
same-inode rollback on any failed publication. A failed rollback or storage
sync is reported as uncertainty and fails the trusted gate, not claimed as
zero disk residue. The mutation digest covers exact file bytes including LF;
independent verification checks externally supplied candidate and actual
container/image tuples. Focused race tests inject sync, readback, publish
and rollback failures. These corrections are partial E-owned evidence only;
the issuer gate, sixteen scenarios, formal evidence manifest, release and
production-readiness claims remain unpassed. Phase 6 remains **5/15**.

Follow-up 2026-10-04 (preissuer source-clean path correction): an independent
read of the live Gate found that Product observer, Guest fixture, several
diagnostic observers and the Vault trust-switch runtime root were created as
untracked directories inside E. The E-owned final receipt verifier correctly
uses strict `git status --porcelain --untracked-files=all`, so those still-live
directories would deterministically reject an otherwise valid component run.
Sandbox withdrew any inference of issuer permission and directed an E-only
path correction. The actual Gate chain now creates these private 0700
temporary directories as siblings of their source checkout, never inside
E/R/F; build commands continue to execute from the reviewed source root.
Cleanup pins the created directory/parent inodes, walks entries with bounded,
FD-relative no-follow operations, and refuses to remove a replacement. The
strict E/R/F source-status and revision/tree checks remain in force. A
single noissuer test holds all live temporary classes and externally frozen
observer/fixture/terminal binaries across the finish-equivalent boundary,
checks source cleanliness and non-root Docker mounts, and rejects digest or
cleanup drift. The result of that test and the new E revision must be
recorded separately after validation; no issuer has been started and Phase 6
remains **5/15**.

Follow-up 2026-10-04 (one Sandbox-authorized real issuer component attempt,
**failed**): clean E `49173d30f5cdc9d153a1851833a789411b3e20ea`
and clean R/F `c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635` entered the
unchanged persistent-trust component chain once. The exact run ID was
`dca5ebb28066e5b675d668050dcf516e`; the selected Profile digest was
`sha256:7d0cb786ad9f572b22872eb0a467b7e1aae2877661e9210cb8c732a273bcf180`.
The tagged test exited 1 after 450.26 seconds. Its first trusted failure was
`Product PID1 graceful receipt shutdown unavailable`; attached-stream stop
verification, Product/Guest receipt pairing and durable binding were not
reached. The raw Product and Guest PID1 files contain apparent begin/events/
seals, and the live Guest reached connected `/readyz` before the same-netns
Product Store mutation and observed post-mutation 503/exit-1. These unverified
raw events do not establish the causal or persistent-trust gate. The terminal
operator separately reported three certificates, two token accessors,
complete CRL and self-revocation; the certificate controller's sticky local
credential-revoke failure remains unresolved.

The private 0700 evidence root is
`/Users/echo/.codex/phase6-slice6-run-evidence-E491.b1jU78`; the run child
contains only 0600 `product-pid1.stdout`, `guest-pid1.stdout` and
`incomplete.json`, with no mutation receipt or binding. Their SHA-256 values
are respectively `69aff3708687a15857822908515a04c151970c5545962e62026797e9f96c93db`,
`f026366c97982ad021bd7a55917fb44cb679bfd8eee21122f479536e8dbaef90`
and `8de89d14bec85d8b36d0a8cbff65a25ca28d8bb2521c7010e2af9e15d9298ad9`.
The 0600 private Gate log is
`/Users/echo/.codex/phase6-slice6-run-E491.ZkIRcy/gate.log`, SHA-256
`eacb8a7a03206ec36a24b73feb972a66645044e2c5cf8b82244adae9bff62f83`.
Exact Gate cleanup and a separate read-only Docker inventory found zero
containers, networks and volumes under the run label; both observed Vault
anonymous volumes were absent. E/R/F sources remained clean.

The narrow failure was a Docker CLI response mismatch: the host's Docker
29.7.2 emitted a deprecation warning on stderr for `docker stop --time 10`
before the exact ID on stdout. The bounded helper intentionally combines
both streams and rejects anything other than the exact ID, so the Gate
rejected an exit-zero stop response. Independent no-issuer probes showed
`docker stop --timeout 10` returns only the ID for both running and already
stopped containers. Sandbox approved an E-only equal-duration flag correction,
not a looser parser or a second issuer run. The same-chain stop calls now use
`--timeout 10`, preserving exact output, bounded execution and downstream
PID1 exit/OOM/image/config/logdriver/TTY/attached-stream receipt checks. A
real no-issuer Docker drill passed the actual stop helper, SIGTERM-sealed PID1
capture, `verifyStopped` and already-stopped path; the full tagged race suite
also passed. The full repository race/shuffle suite, ordinary and tagged vet,
Product Contract lock, and diff checks passed after the repair. Neither this
repair nor the failed real attempt advances Phase 6
past **5/15**. A second issuer attempt requires separate Sandbox approval.

Follow-up 2026-10-04 (preissuer strict-stop negative regression): a serial,
test-private fake `docker` executable now exercises the actual bounded stop
helper with the exact `stop --timeout 10 <ID>` argument tuple. It admits only
the exact ID, rejects extra stdout, extra stderr, nonzero exit despite an ID,
combined-output overflow beyond 128 bytes, and a pre-cancelled context without
invoking Docker. This test neither contacts the daemon nor allocates an issuer;
the real no-issuer positive stop/receipt drill above remains separate.

Follow-up 2026-10-04 (second, separately authorized issuer component attempt,
**failed**): clean E `5a74e021a31e6c9a6de5229cb75c81a6cfbfd7ff` and the unchanged
clean R/F `c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635` ran once with the
same 20-minute parent and 25-minute test budgets, original stop/cleanup
interlocks, frozen candidates and external archives. New run
`f329c97ebe232b5a105c59363becc909` bound Profile
`sha256:82aa6fa29c2073edde0de32d9329e5f5e47012486f76be4b48c87691a9cb81f3`.
The tagged test exited 1 after 447.10 seconds. Its first final error was
`private Guest receipt evidence unavailable`, after the previous stop-flag
failure had been crossed. Product and Guest raw PID1 streams were captured
and sealed. Read-only projection showed matching original attempt events,
Product authority-stale close, Guest read termination and a different fresh
attempt rejected as revoked. No mutation-receipt or durable binding was
written, so those raw records are **not** a verified persistent causal
receipt. The certificate controller still retained its local sticky
credential-revoke failure; the independent terminal operator confirmed three
certificates, two accessors, complete CRL and self-revocation. Exact Gate
cleanup and a separate Docker inventory showed zero run-labeled containers,
networks and volumes; both exact Vault anonymous volumes were absent.

The new 0700 private root is
`/Users/echo/.codex/phase6-slice6-run-evidence-E5a.nl6mQ4`. Its child contains
only 0600 `product-pid1.stdout` (SHA-256
`16fdfbc8f30bab0bdc755365a0ce712051238d53514056f95f773d720417edcf`),
`guest-pid1.stdout` (`9368d594c28c529439798f8d7e69015078dbf5a1046d354835da642e35c734d4`)
and `incomplete.json` (`1d1a44f3021c20076eb6c9db9590aa0614b57f9de4b2c496f4c536c8cae8ff94`).
The 0600 private log is
`/Users/echo/.codex/phase6-slice6-run-E5a.ufODvf/gate.log`, SHA-256
`641aa2952b3c7eecbdf356be2ffab7d9c67b9b5187f3acb349023ed4d52bb0da`.
E/R/F remained clean; a subsequent no-issuer exact static-input reread
passed. This was a failed single component attempt, not a Slice 6 gate pass.

An E-only source review identified a deterministic pre-publication rejection:
the receipt artifact mapper compared the candidate's nonempty selected
manifest descriptor against `ImageBinding.SelectedManifestDigest`, which is
intentionally empty for `oci_manifest` and only populated for `oci_index`.
The frozen `core` candidate uses `oci_manifest`; a no-issuer test loaded its
real source-bound OCI artifact and reproduced failure under the old mapper.
The proposed repair branches strictly on image kind: a single manifest must
bind the selected descriptor to the root/runtime-store digest and retain an
empty index-child field; an index must have a valid distinct child digest
matching the candidate descriptor. The receipt still records the actual
nonempty selected manifest. R/F, locked Provider Contract and candidates are
unchanged. This code-level explanation is not retroactive verified evidence
for the failed E5a run. Phase 6 remains **5/15**.

The E-only repair was checked without another issuer: the same frozen `core`
candidate failed the pre-fix mapper and passed the kind-aware mapper. Pure
mapping tests admit both canonical single-manifest and index/child forms and
reject kind, child/root, config, source revision/tree, reference and actual
image drift. A separate private test fixture used the reviewed clean R/F
sources and candidate identity with explicitly synthetic Product/Guest
streams, container IDs and mutation facts. It passed bounded two-stream
collection, canonical raw verification, `slice6FinishGuestReceiptEvidence`,
exact mutation file publication, source/image binding and independent durable
reread; wrong external image identity and incomplete-run reread were rejected.
Existing injected rollback/sync and tamper tests remain negative. Fixed,
non-sensitive `input`, `source_reopen`, `artifact_map`, `raw_binding`,
`mutation`, `publish` and `independent_read` stages now preserve the original
error identity while distinguishing bounded failure classes. These are
synthetic no-issuer tests, not a new real Docker/PG observation. The failed
E5a directory is untouched, and the official count remains **5/15**.

The first race-enabled finish-fixture attempt exhausted its own five-minute
context during the second source/OCI reread and failed with fixed
`stage=source_reopen`; it was not counted as a pass. Only that synthetic
fixture's bounded context was extended to eight minutes, leaving the real
Gate's 20-minute parent, 25-minute test, startup, stop and cleanup budgets
unchanged. The full tagged race/shuffle suite and tagged vet passed after the
edit. The same source-bound fixture then passed with `-race -shuffle=on`
in 304.95 seconds under the eight-minute bound, including publication and
independent reread. This still does not authorize or substitute for a new
real issuer component attempt.

Follow-up 2026-10-04 (third, separately authorized real issuer **component
pass**, independently reviewed by Sandbox): clean E
`f49ee748f5e8790cd58c62d04bc5304b1a363b49` (Git tree
`82dc4876d8be62dcd883082c4d7f4b35f12695d6`) and clean R/F
`c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635` (tree
`ed5b679ef69bf769ef511ec45a32766322e68df2`) ran the same bounded
Product/PostgreSQL/Guest live business-binding revoke component once. Run
`20efb6c95a0fa39cb0441f580a86888f` selected Profile
`sha256:ba1253f7736ae66c582f56f6ea5c86b0494f1a64d4564667d9be6e3a35adbd3f`.
The ordinary tagged test exited 0 in 437.83 seconds under the unchanged
20-minute parent, 25-minute test, 45-second Guest startup, 10-second Docker
stop, 90-second stop interlock and 45-second final cleanup budgets. The
0600 log is `/Users/echo/.codex/phase6-slice6-run-Ef49.ZBnxXQ/gate.log`,
SHA-256 `158f739ba9f46d4cce15c4984ac95735367c0b12597d9e53e116acd0079e8bac`.

The private 0700 evidence root is
`/Users/echo/.codex/phase6-slice6-run-evidence-Ef49.o7iKwM`; its 0700 run
child contains exactly four regular owner-only 0600 files, no
`binding.pending` or `incomplete.json`:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `binding.json` | 3,219 | `61092c5f49fb9fb08db452486ccb78570d2ddc15b59a0416ee1172d5755f0c04` |
| `mutation-receipt.json` | 659 | `f839566e9824d0ff995dad145c27783faf7cb6b50595875274d7b71a60862574` |
| `product-pid1.stdout` | 2,471 | `82a91bd50b7faf625802106bba3f98a8c571604297a57e66359fbf58ff0eebbf` |
| `guest-pid1.stdout` | 1,783 | `d5728d26860b0a09f256046b95982ad74ce169c34e66f935dfd0269b446223f2` |

The binding's disposition is `component_verified`; independent reread
checked canonical bytes, E/R/F source revisions and source digests,
candidate/runtime image and config identities, exact Docker instances and
exit codes, mutation file digest, run/Profile/generation and closed receipt
streams. Product and Guest recorded the same original signed attempt digest
and generation 1. Product accepted authentication, wrote welcome and
installed the peer; after same-PostgreSQL durable business-binding revoke it
observed stale authority and completed the original upgraded connection's
close. Guest recorded welcome acceptance then read termination. A distinct
fresh signed attempt was written by Guest and was rejected by Product's
validated-revoked joined-row path. Both streams sealed with `dropped=0`.
The mutation receipt confirms prior connected state, revoked binding and
cleared nonce on PostgreSQL backend PID 638; its exact Product container ID
matches the bound Product instance and differs from Guest. The prior log line
at mutation time still correctly said cause was then unproven; the later
durable receipt pairing and independent reread established this bounded cause.

The certificate controller retained its sticky local credential-revoke
failure. A separate independent terminal operator confirmed three serials,
two token accessors, complete CRL and self-revocation; this does not erase
the controller failure. Exact Gate cleanup and a separate read-only Docker
inventory found zero containers, networks and volumes under the run label;
both recorded Vault anonymous-volume IDs were absent. E/R/F remained clean
at their recorded full revisions and trees. The earlier E491 and E5a runs
remain failed with their original incomplete evidence; neither is relabeled.
Sandbox accepted only this one component result after independent source,
receipt, digest and cleanup review. It does not prove PostgreSQL-loss
closure/recovery, peer-TLS revocation, CRL-source loss, replacement
restart/reconnect, nine live SQL callers, the full 16-scenario/78-deployment
gate, a formal Slice 6 manifest, deployment or production readiness.
Phase 6 remains **5/15**.

Follow-up 2026-10-04 (E retained-file inventory component, no issuer): the
E-only terminal preflight now captures a canonical private inventory after
exact Docker/original-ID zero and the seven sibling-directory absence replay.
The inventory names the exact 117 successful-path evidence files and binds
their owner-only regular-file inodes, byte counts and SHA-256 digests. A
separate read-only opener compares the entire run-directory name set, reopens
every file with no-follow checks and verifies the externally supplied
inventory digest; a later canonical `incomplete.json` remains a failure marker
and is never a successful E binding. A no-issuer race-enabled synthetic test
passed positive replay and negative wrong-digest, extra-file, same-inode
content-mutation, same-content replacement-inode, widened-mode and malformed
incomplete-marker cases. The retained-file reader also now treats file close
errors as failures. The E launcher still unconditionally fails after this
component preflight: live E, actual process/writer joins, credential-lease
reconciliation, external R/F/E freeze, final independent binding and the
16-scenario gate are not proved. No issuer, release manifest or push was
produced; Phase 6 remains **5/15**.

Validation for this no-issuer component used the locked Go 1.26.8 toolchain:
the final-code full `go test -race -shuffle=on -count=1 ./...` exited 0,
the full `phase6slice6gate` tagged race/shuffle package exited 0, ordinary
and tagged `go vet` exited 0, Product Contract lock verification passed,
and `git diff --check` was clean. An earlier attempt under the host default
Go 1.26.5 failed expected toolchain-lock tests and was superseded; it is
not counted as a passing validation.

Follow-up 2026-10-04 (early process ownership and typed convergence, no
issuer): after Sandbox's `S6-A1-helper-convergence-receipt-20261004` ruling,
the ordinary TLS signer and both controller startups register failure cleanup
at their exact `docker create` boundary, before readiness. Break-glass now
tracks its initial controller and each replacement separately under one
shared finite failure-cleanup deadline. No-issuer tests cover Goexit,
cancel/stop/join/remove ordering, one-shot behavior, historical replacement
retirement and wrong-run/profile/count/duplicate-instance rejection. A real
disposable Alpine PID1 Docker drill passed exact attach cancellation and
zero labeled-resource cleanup; it exercised no Vault issuer or PostgreSQL.

The certificate result now distinguishes physical convergence from
`clean_exit`: the known sticky `credential-revoke` exit remains typed failure
and remains controller-drain OPEN even if an independent terminal operator
subsequently succeeds. A limited Guest E component may retain that exact
class only with proved physical cleanup and v3 binding; it does not establish
full Slice 6 controller shutdown. The E admission also checks the joined
capacity monitor result, credential controller stop/drain/remove outcome,
seven fixed role-bound TLS signer outcomes and exact three-instance
break-glass outcome. The
full tagged race/shuffle package passed after these edits. This is component
evidence, not a fixed-stage E receipt, a new source freeze, an issuer approval,
a formal E run, a release manifest or a push. Phase 6 remains **5/15**.

Follow-up 2026-10-04 (terminal ledger projection reuse, no issuer): the
one-shot v3 path now projects the same two complete ledger reads already used
by `BuildV2`, after its canonical/quiesced and exact target validation. It
does not read either volume twice or retain original nonce/JTI, lease ID or
backend accessor bytes. The closed projection binds run/Profile/plan, both
original byte lengths/SHA-256 values, relevant per-record state and times,
and domain-separated identifier digests. Its own digest is included in the
private v3 binding and the successful-path file inventory grows from 117 to
118 exact owner-only files. A no-issuer synthetic fixture passed positive
replay and negative nonterminal-active, original-hash, plan, terminal-
accessor and unknown-field cases. The verifier states explicitly that the
projection cannot independently reconstruct cleared ledger bytes. This does
not settle the final actual-issuance-set comparison, all helper/writer joins,
frozen E/R/F binding, real E, 16 scenarios or controller-drain OPEN status.
No issuer, manifest or push was produced; Phase 6 remains **5/15**.

Follow-up 2026-10-04 (pending-overlap and exact E issuance guard, no issuer):
the terminal planner now rejects a credential record if either the previous
backend accessor or previous-revoke time remains set; table tests cover
terminal active and nonterminal revoked records with clean, accessor-only,
time-only and combined cases. The E projection is checked against the fixed
seven TLS signer and three material-agent launch roles plus the two
controller certs and one controller PKI token, not the full optional Profile.
An extra, missing, duplicate, wrong-principal or unrevoked nonterminal record
fails. The same retained projection is rechecked at terminal-zero preflight.
This does not establish the fixed-stage process/writer receipt, actual E
issuer observations, R/F/E freeze or formal Slice 6 gate. No issuer or
manifest was produced; Phase 6 remains **5/15**.
The pending-overlap condition changes `internal/phase6terminalcleanup/plan.go`,
which is linked by the source-bound `cmd/phase6-terminal-cleanup` binary.
Therefore the prior clean R/F checkout and reviewed terminal binary do not
stand in for this candidate: freeze and review a new E/R/F source and
terminal-binary identity before another real issuer run. Tagged E-only
projection edits alone would not have required that rebuild.

Follow-up 2026-10-04 (fixed E helper convergence receipt, no issuer):
Sandbox ruling `S6-A1-fixed-convergence-stage-set-20261004` froze exactly
14 logical slots: seven TLS signers, credential/certificate/break-glass
controllers, three material agents and one joined capacity monitor. Product/
Guest PID1 writers, SQL/action chain, migration, fixture, PG stop and v3
terminal operator retain their existing independently checked evidence rather
than duplicated slots. The E-only receipt is assembled from actual helper
return/cleanup points, including material-agent stop/drain/remove/socket
guards and migration natural exit. It binds run/Profile/source/terminal,
ordered typed outcomes and exact IDs to the existing precleanup/v3/Docker/
private-zero digests, then is synced, read back, independently reopened and
included in the successful-path 119-file inventory. No-issuer race tests
passed the fixed-stage positive fixture and missing/unknown/duplicate slot,
wrong run/container, wrong exit, unjoined outcome, causal inversion, sticky
washing and late file-sync failures. Full tagged validation and final E/R/F
binding remain open. No issuer, manifest or push; Phase 6 stays **5/15**.

Follow-up 2026-10-04 (final-binding candidate, no issuer): a closed E-only
binding now has separate E, R and F revision/tree fields; the convergence
receipt's former ambiguous source field is explicitly `RRevision` because it
comes from the runtime source, not the executing E checkout. The private
publisher code uses a synced pending file, exact-inode link/unlink, rollback
on failure and independent read-only replay; the verifier requires the
119-file inventory plus only the final binding, the 14-slot receipt and
terminal v3/plan/projection chain. A final-looking file next to an
`incomplete.json` marker is rejected. The live E launcher currently builds
and validates only a candidate after all preflight and clean E/R/F source
checks, then deliberately fails without calling this publisher pending the
external freeze/real-run review. The no-issuer unit cases do not substitute
for that run; Phase 6 remains **5/15**.

Follow-up 2026-10-04 (Sandbox A/B/C final-publisher gaps closed in source,
**no issuer run**): the live E path now freezes E/R/F revision/tree identity
before issuer allocation, compares the same identities after cleanup and
publishes the final E-only component binding only after terminal-zero, exact
119-file inventory and fixed 14-slot convergence replay. A shared pure
terminal-zero digest computation is used by preflight and the final verifier.
The final verifier checks the publisher-selected inode, canonical binding,
v3/ledger replay and all five zero-chain references. The publisher cannot
return success until both owned directory descriptors close and an independent
fresh reopen passes. Late close/reopen failure attempts inode-pinned rollback,
retains incomplete evidence and reports uncertainty if exact rollback cannot
be proved; an unknown or replacement inode is never unlinked.

A no-issuer fixture generated a valid synthetic v2 plan, issuer-signed
complete CRL, v3 event/receipt chain, terminal ledger projection and 14-slot
convergence receipt. The positive full publisher path passed, as did failures
for link/no-replace, post-link directory sync, pending unlink, independent
reopen, replacement inode, rollback unlink/sync uncertainty, late run/root
close and post-close reopen. Tagged `productphase6gate` race/shuffle tests
and tagged vet passed. These are source and component checks, not a real
Vault issuer observation or full Slice 6 acceptance. A clean E/R/F/terminal
binary freeze and exact command still need Sandbox approval before one new
issuer-consuming attempt. No manifest or push; Phase 6 remains **5/15**.

Follow-up 2026-10-05 (formal E receipt-mode contradiction, **no issuer run**):
the E preissuer environment requires the private Guest receipt and forbids
the legacy component live-revoke flag, but the shared Vault test previously
required that flag whenever the receipt was enabled. That old condition was
after Vault/issuer work, so it could not serve as a safe preissuer rejection.
Under Sandbox ruling `S6-E-mode-guard-20261005`, one pure mode guard now runs
both in formal E preissuer admission and at the very start of the shared
entry, before private root, Docker run, issuer or trust-switch allocation.
Formal E requires Product/Guest PID1 and the private receipt while rejecting
the legacy callback; the historical non-E receipt still requires all three,
and receipt-off diagnostics retain their prior behavior. A no-issuer truth
table and complete formal-environment/shared-guard combination passed;
finite dependency edges were checked by removing each prerequisite and
requiring preissuer rejection.

The clean R/F source pair at `e5816d0d3de0541bd9a677560096b3527f58f7b9`
remains the selected runtime/fixture/terminal source. Its 12 source-bound
local role images and manifests, Desktop candidate, R terminal binary and F
fixture are not relabeled as a new E build and need no rebuild for this tagged
test-only guard. The E checkout will receive a successor commit and its own
revision/tree/observer identity must be rechecked before any real attempt.
The first aggregate static admission failed closed with an old Desktop
candidate, which was correctly rejected because Desktop must share R's
revision/tree. After rebuilding only that source-bound Desktop candidate,
complete static admission and the 21-image Docker-store admission passed
without creating a business run or issuer. R/F source-pair and non-root
observer mount probes also passed. The single real issuer command remains
unapproved; no manifest or push, Phase 6 remains **5/15**.

Follow-up 2026-10-05 (externally approved terminal binary lock, **no issuer
run**): Sandbox ruling `S6-E-terminal-approved-digest-20261005` identified
that clean R build, capability probe and mounted-byte replay all bound the
terminal operator to the digest measured *during this run*, but the live E
path did not compare that digest to the independently approved prebuilt R
value. A strict lowercase `sha256:` digest equality check now runs after
the R build and before `newSlice6DockerRun`, terminal capability Docker
probe or issuer allocation. The existing no-issuer external-temporary test
uses the same pure check; missing, wrong, uppercase, short and malformed
expected values fail in an isolated no-issuer regression. The other two
externally approved executable inputs—the E observer and F fixture—were
checked at their already-existing preissuer call sites; no fourth such
binary approval input exists in this bounded live entry. This tagged-only
change does not modify R/F production code or their 12 role, Desktop,
terminal and fixture artifacts. The final clean E successor and aggregate
tagged validation still precede the one-run Sandbox approval. Phase 6
remains **5/15**.

Follow-up 2026-10-05 (one Sandbox-approved formal E attempt, **failed**):
under ruling `S6-E7f83-single-run-approved-20261005`, the only executed
command was the reviewed private script with SHA-256
`3f27c67c292c19993a1afa57373f6d97e8112ebcdcfa5769d6dfe1883e32eb42`.
Its clean source freeze was E
`7f83c70f4d80638d4db122ffe3c9feaf483184a9` / tree
`3bf8b31f7de13c48c8ed0b21089dab4d78329efe` and physically separate
R/F checkouts at `e5816d0d3de0541bd9a677560096b3527f58f7b9` / tree
`8fd8b10e48a9e90d920ee0f0d3f1796b19f43a66`. Complete static/image
admission, E Product observer, F Guest fixture and R terminal operator
external digest equality all passed. The run ID was
`d3bd3cdef8c3547e5d1d6864362a9a7c`. The original closed network
inventory was allocated once, the non-dev Vault process initialized and
unsealed, and the final positive mTLS probe returned successfully. The next
`old-client-denied` probe (final server CA with bootstrap client
certificate) did not yield attributable TLS-denial evidence after its
existing three attempts; the only retained last-attempt CLI error was a
TCP write `broken pipe`. This cannot be promoted to certificate rejection.
The test failed after 113.85 seconds; the private `gate.log` SHA-256 is
`f0e633f4538bd509b0d72a6f5b21fe1d8c08ca63baa2d74e6e8993df5b05ec3f`.

The exact run-label container/network/volume queries were empty after exit,
the two known Vault anonymous-volume IDs returned `no such volume` on
exact inspect, and no `.sr-*` private siblings remained in the E/R/F
checkout parents. All three Git source identities remained clean and
unchanged. The retained private evidence contains only four files:
created-network binding, two original-network inspect receipts, and v2
`incomplete.json` (SHA-256
`7fcee8685a4038cb2d1c61995d844b2aa5b62771ff75b42c732c0ccece8cf997`).
It contains no final component binding. No second issuer attempt, release
manifest or push followed; Phase 6 remains **5/15**.

Two isolated **no-issuer** TLS diagnostics used the pinned Vault image, an
ephemeral local test CA pair and private scratch outside E/R/F. Both a Go
TLS 1.3 mTLS server and an uninitialized pinned Vault server accepted the
new client; the old client failed with an explicit unknown-CA TLS alert and
the server recorded the corresponding certificate-verification error.
The Vault diagnostic was not initialized and no PKI issuer was mounted.
Both diagnostic container/network labels were empty after exact removal.
Neither of these initial models reproduced the formal run's `broken pipe`;
the later isolated Docker-network replay below did. The original
Vault server log was not retained, so its reason remains unknown. Sandbox
reviewed whether an exact client-source-port/server-handshake-log
correlation could provide fail-closed evidence on a future, separately
approved run. A generic `broken pipe`, EOF or reset is not TLS-denial
evidence.

Follow-up 2026-10-05 (Sandbox ruling
`S6-E-old-client-TLS-correlation-20261005`, **no second issuer**):
the approved change is limited to formal E's old-client negative probe;
old-server denial and the legacy non-E diagnostic continue to require
their former explicit client-side evidence. The actual no-issuer replay
used the pinned Vault v2.1.1 server/CLI image on an isolated internal
Docker network with static local test CAs, and did **not** initialize
Vault or mount PKI. Its old-client CLI exited 1 with
`write tcp 172.20.0.3:37088->172.20.0.2:8200: write: broken pipe`.
The same server container's timestamped log recorded one x509
unknown-authority handshake failure from `172.20.0.3:37088`
between the exact probe container's Docker StartedAt and FinishedAt.
This is a new diagnostic run, not missing evidence retroactively supplied
to the failed formal E attempt.

The E-only collector now requires the exact run/server/probe/network/image,
fixed probe command, read-only certificate mount and public certificate
digest, unchanged live Vault PID/StartedAt, failed non-OOM probe exit,
unique client TCP source and target, stopped probe's reserved IPAM address,
and one matching server TLS refusal in a closed daemon/application clock
window. The stopped probe's Docker `IPAddress` is empty; its
`IPAMConfig.IPv4Address` is only a configuration constraint, not live
endpoint evidence. Actual source attribution additionally requires the
CLI socket and exact Vault server log socket. One bounded 64 KiB
`docker logs --timestamps --since/--until` read is used; raw logs are
cleared, and only a closed diagnostic record and its digest may be logged.
The actual no-issuer EPIPE/server pair passed the collector read-only
replay; mismatch, ambiguity, truncation and time/identity drift cases are
covered by no-issuer pure tests. Both diagnostic containers, their
network and all four anonymous volumes were absent after exact removal.
Disposable test certificates and keys were deleted; only non-sensitive
reproduction source/config remains in a private external scratch root.
The formal E run remains `incomplete`, and the new E-only implementation
passed one aggregate tagged race/shuffle suite (including
`productphase6gate` at 22.040 seconds and
`internal/phase6security` at 336.999 seconds) and tagged vet. The
prior unaffected ordinary full race/vet and Provider Contract lock
results are reused under Sandbox's source-impact decision. A clean new
E source freeze, no-issuer observer/source check and another separate
Sandbox run review still precede any issuer. Phase 6 remains **5/15**.

Follow-up 2026-10-05 (second one-shot formal E attempt, **failed**):
Sandbox separately approved the exact E3d19 script
`fafdbbb601afa5b59fb248d37a8b7ac8f0a20960632a05620433b9bae0cca94e`
once. Its clean E source was `3d19f3c359159e30e0a36b620effbcd5cf007eca`
(tree `144c5aaf50661d16115bb3c0de78d45fb0188394`); R/F remained the
independent clean `e5816d0d3de0541bd9a677560096b3527f58f7b9` pair.
Run `67a8794ca4959dfb9394ed1d5baa7248` passed the old-client TLS
probe, Vault/PKI/KVv2 and PostgreSQL/migration setup, but the formal Guest
recovery E precleanup returned `private Guest receipt unavailable` before
any source-to-terminal binding. The only Product-A PID1 raw file is zero
bytes; no Guest-A raw file exists. The private log has SHA-256
`9b3ad806a9629f2128ef094327130c3ac5d580d330c27fb04d3182cce3ffa6fa`.
The retained v2 marker says `incomplete`, not accepted. The separate
terminal operator observed three certificate serials, two token accessors,
complete CRL and self-revocation in cleanup-only mode, but the sticky
certificate-controller credential-revoke failure and missing full terminal
chain remain OPEN. Exact run-labeled Docker container/network/volume lists,
the two recorded Vault anonymous volumes and E/R/F private siblings were
absent after cleanup. Physical cleanup does not turn this attempt into
business, terminal or release evidence.

The first visible E-only failure lies after creation of the Product-A raw
file and before Guest-A receipt creation. Docker's retained short event
history still showed the original Product-A container's later exact
destruction but no start/die record for that container; its prior running
state and exit cause cannot be reconstructed. Static review found a possible
startup race: the formal Product/Guest A/B path launched asynchronous
`docker start -a` and inspected running state only once, while its existing
no-issuer Docker capture tests retried this observation. This is a plausible
explanation, **not a proven root cause** of the failed run.

Under Sandbox ruling `S6-E-start-observation-20261005`, the E-only startup
observer now treats only the exact same-run, same-ID/image/label,
log-driver-none, non-TTY, non-OOM, error-free `created/pid0` state as pending.
It polls that same start at a fixed cancellable 50 ms cadence inside the
original absolute Product 28-second or Guest 45-second startup budget;
running still requires exact PID/StartedAt and live attached collector.
Exited, malformed, failed inspect, identity drift, completed collector,
deadline and cancellation fail closed. B start-call/start-observed events
remain one-shot and ordered. Closed stage diagnostics do not retain raw
stderr or broaden private receipt/evidence acceptance. Deterministic
pending-to-running and negative unit cases, plus a real no-issuer four-PID1
Docker capture with exact created and running observations, passed. This
correction also passed the complete ordinary repository race/shuffle test
(`internal/phase6security` 336.926 seconds) and the complete tagged
`phase6slice6gate` repository race/shuffle test
(`productphase6gate` 22.748 seconds,
`internal/phase6security` 340.114 seconds) using Go 1.26.8. These are
component/source results, not real issuer observations. This correction has
not been verified by a new issuer run; no third issuer is authorized, no
release manifest or push exists, and Phase 6 remains **5/15**.

Follow-up 2026-10-05 (third one-shot formal E attempt, **failed**):
Sandbox approved exact review-only script
`b6ab84ca8dc0c93cdb50639c20d99ee112b35931b0d99f46e641bc1dd8cb1bdd`
once under `S6-E176a-single-run-approved-20261005`. E was clean
`176a25a29ef30ab5cd731deed247bb757ccb3ddd` / tree
`1d9c1a0c1aa542a6029be3b9eadfbc8379b8a35b`; R/F stayed at the
separate clean `e5816d0d3de0541bd9a677560096b3527f58f7b9` source.
Run `27f3fe5853e6172252a63c41c5665242` failed after 506.65 seconds;
the private log SHA-256 is
`939021969b0726f2f8dfbace365199b93c06d5ab361a93a138b712547a1c82db`.
It passed the old-client TLS probe, actual Vault/PKI/KVv2, PostgreSQL,
Product migration, controllers and agents. Unlike the preceding run, its
private Product-A and Guest-A v2 stdout files contain 15 and eight lines,
respectively, with zero-drop seals; the 107-file private directory also
contains before-B admission, Product-B begin and both B start inspections.
Guest-B stdout is zero bytes. These are partial raw observations, not a
verified full A/B causal binding or accepted E component.

The first failure was `Guest running network witness PID1 unavailable`.
Source inspection shows a deterministic validator wiring error: formal
Guest-B calls the shared running-network witness, but that witness required
the literal Guest-A container name even though Guest-B creation and its
separate start inspection require the fixed `-b-` name. This explains this
specific rejection without proving every otherwise-unseen Docker field at
the failure instant. The prior asynchronous-start correction did allow this
run to reach the B stage, but the second run's exact root cause remains
unproved. The third run has only a v2 `incomplete` marker, no final binding,
119-file result or 14-slot convergence. Its cleanup-only terminal operator
confirmed three certificate serials, two token accessors, complete CRL and
self-revocation, while the sticky controller credential-revoke failure and
external PostgreSQL leaf v2 terminal revoke remained OPEN. After exact
cleanup, run-labeled Docker container/network/volume inventories, both
recorded Vault anonymous volumes and E/R/F private siblings were absent.
That physical zero does not complete the terminal or business evidence.

Under Sandbox ruling `S6-E-Guest-B-network-witness-20261005`, the E-only
formal witness now derives one exact name from the closed `guest-a` or
`guest-b` slot and run ID; the historical component wrapper remains
Guest-A-only. Container ID, run label, live PID1, no OOM/restart, and both
effective network IDs/IPs remain mandatory. The formal B startup and
readiness checks use the same slot-bound identity. Static review of the
remaining replacement shared-attempt, shutdown, seal, precleanup and
removal path found no further A-only container-name assumption; A-only
fault-stage helpers remain A-only. Pure wrong-slot/name/run/ID/PID tests
and a real no-issuer two-network Docker A/B witness passed, including
A/B cross-slot and wrong-network/IP rejection. This is a source/component
correction only. The subsequent single aggregate Go 1.26.8 tagged
`phase6slice6gate` repository race/shuffle test passed
(`internal/phase6security` 337.884 seconds), as did tagged vet and
`git diff --check`. The unaffected ordinary repository/Contract gates,
R/F sources and frozen candidate images were reused under the E-only
source-impact decision. No fourth issuer has been authorized and Phase 6
remains **5/15**.

Follow-up 2026-10-05 (fourth one-shot formal E attempt, **failed**):
Sandbox approved review-only script SHA-256
`f6bb37b42e99914c42dc94e63a88ba2e77cd0523da4b402ab5630dfbc91fa0fd`
exactly once under `S6-Efbd2-single-run-approved-20261005`. Clean E was
`fbd2502fc6e685cd2353d515f44d247e6da99763` / tree
`066afd225c4c4a470b03ca7e4ffadefca7bdf739`; R/F stayed at separate
clean `e5816d0d3de0541bd9a677560096b3527f58f7b9`. Run
`20e961e6eeccb74d14109c4619193fd8` failed after 505.56 seconds;
private log SHA-256 is
`758f5792b2f8cb6ea7318e3c8bf57382cbf7594b3c51ba3cd08aaa50fb5c54a6`.
The 105-file private root retains `incomplete.json`, not a final binding,
119-file inventory or 14-slot convergence. Event journal 26-29 records
Product-B and Guest-B start call/observation. Their v2 streams contain eight
and five lines with zero-drop seals and the same replacement attempt digest;
this alone does not establish every downstream replay condition. The
29-event journal is deliberately fixed at Guest-B start observation, and
its persisted seal is later in the E29 call path. No same-named precleanup
file is expected: precleanup returns an in-memory digest. Source-path
review of the terminal branch, together with the absence of the fixed
cleanup-only marker in the log, supports the inference that formal
precleanup replay succeeded and the formal terminal sink was entered.
The old generic terminal error does not prove which validation stage failed
or that remote revocation completed.

The reported failure was `terminal v3 original stdout or independent replay
unavailable`; the certificate controller's sticky terminal credential-revoke
failure and external PostgreSQL leaf v2 terminal revoke confirmation remain
OPEN. Exact run-label Docker containers, networks and volumes were absent
after cleanup, and both recorded Vault anonymous volumes were absent.
This physical zero is not a clean controller drain or terminal receipt.
Sandbox ruling `S6-E-terminal-first-failure-diagnostics-20261005` permits an
E-only diagnostic split of the existing short-circuit terminal checks into
closed stages, with no raw issuer response, ledger, token, accessor, key,
endpoint or stderr in diagnostics. It does not authorize a fifth issuer run,
change the nine-certificate/four-credential expectations, expand the fixed
scenario or evidence inventory, or advance Phase 6 beyond **5/15**.

The E-only diagnostic candidate preserves the prior short-circuit order:
strict v3 stdout decode, independent evidence replay, run/Profile identity,
terminal ledger projection, exact issued-set check, then sink persistence.
Failure reports only a fixed stage name; persistence further distinguishes
input/replay, CRL and projection time, projection validation and bounded
private writes. Terminal operator stderr-derived stages are mapped through
the reviewed finite CLI vocabulary, with all other strings reduced to
`unknown`. The formal-vs-cleanup-only branch and independent runtime,
convergence, terminal, capacity, binding and Docker-cleanup booleans are
logged without copying raw issuer responses or ledgers. Deterministic
no-issuer stage-order, multistage-first-failure, redaction, offline v3
fixture, persist input/CRL/projection-time and four exact private-write
failure injections, plus existing terminal/issued-set tests pass;
these diagnostics do not reclassify the failed original run.
The final stable E-only candidate passed the complete Go 1.26.8 tagged
`phase6slice6gate` repository race/shuffle test (the longest
`internal/phase6security` package took 341.413 seconds), tagged `go vet
./...`, and `git diff --check`. Ordinary untagged, Contract, separate R/F
and pinned-image gates are unchanged and reused under the prior E-only
source-impact ruling. No fifth issuer was run or authorized.

Follow-up 2026-10-05 (E issued-identity namespace correction, **component
only**): independent source review found a deterministic mismatch in the
terminal E exact-issued-set check. Profile deployment labels locate the
requester and subject, but real `workloadpki` ledger `AgentID` and `Principal`
hold their `AuthorizationPrincipal.Name` values. The prior E expectation used
the deployment labels, while R's private `buildVerifiedV2` and the certificate
controller use the authorization names. A no-issuer test built from the
reviewed desired authorization identities first failed against the old E
check, then passed after E resolved each fixed deployment to its exact
authorization name and digest. The nine certificate/four credential set,
full identity comparison, and ordinary-signer revoked requirement remain
unchanged; only the two exact controller policies allow active or revoked
terminal states. Negative tests reject deployment-name spoofing, wrong
identity/digest, state drift, and missing/duplicate/extra records. A bounded
source search found no second E comparison of ledger `AgentID`/`Principal`
against deployment names; the existing small synthetic projection-shape test
now uses an independent fixed expectation rather than deriving it from the
projection being checked. This is not a complete Profile-to-public-R-BuildV2-
to-E-FromProfile cross-package fixture: existing R tests use its private
builders, and the E test uses the reviewed identity builder and production E
conversion helper. The mismatch is a plausible later rejection, not a proven
root cause of the fourth run's old generic terminal error. The obsolete
E571681 review-only script was not executed; a fifth issuer still needs a
new clean E binding and fresh one-shot approval. No manifest was issued and
Phase 6 remains **5/15**. At the stable E source, the complete Go 1.26.8
`phase6slice6gate` repository race/shuffle/count suite passed (the longest
`internal/phase6security` package took 339.243 seconds), as did tagged vet
and the focused E/R terminal checks. Ordinary untagged, Contract, separate
R/F and pinned-image results are reused only under the E-only impact ruling;
this is not a fresh real issuer or final-topology result.

Accepted bounded Guest recovery E component (2026-10-05): Sandbox one-shot
`S6-Ea065-single-run-approved-20261005` was consumed exactly once by script
`/Users/echo/.codex/phase6-slice6-run-Efix.CQdy6i/issuer-run.review.sh`
(`sha256:b5229789bc6624930e9f1c19c27d01975fb93b50563451869713148e413cba78`).
Run `550dba360065dce4f46fa14476225ce5` passed the real
`TestPhase6Slice6GuestRecoveryE` in 533.78 seconds; the script exited zero
including post-run source checks. Its private log is
`/Users/echo/.codex/phase6-slice6-run-Efix.CQdy6i/gate.log`
(`sha256:44d2d3337d5893eba37db2658a0e3c366d92c8aa07e6eb660fc66fe208c2c084`).
Clean E commit/tree are `a065277e406bf09c4c22d4ce187e1d181e513316` /
`e6e569dcec2c814526630dcfbb2e4fe12caa49bb`; independent R and F each
remain `e5816d0d3de0541bd9a677560096b3527f58f7b9` /
`8fd8b10e48a9e90d920ee0f0d3f1796b19f43a66`. Frozen role/image inputs
and auxiliary binary digests were checked before the issuer.

Private evidence root:
`/Users/echo/.codex/phase6-slice6-run-evidence-Efix.GTGjew/550dba360065dce4f46fa14476225ce5`.
The final binding is
`sha256:e66dc29a217c82e1ae9071b8046c33461afae8d216e488751c9a68e312549177`;
its inventory is
`sha256:ecc4649fa28503c208e523be690290ffe7249ebb2a2f33ad923b43246877053a`,
convergence is
`sha256:f3ee68806a016f7a8dc7ca377aff52f265a67b0442b9f26d5ab3a8e1a86516a2`,
and terminal v3 binding is
`sha256:3fdb73001712ace32ba65adbedb335b50db10c6b8f2875bca71d4f599a375907`.
The bounded disposition is `guest_e_component_verified`. Independent review
matched all 119 inventoried files' exact metadata and hashes, 14 ordered
convergence slots, chained terminal/zero digests and three serial/two-token
complete-CRL/self-revoke confirmation, with no `incomplete.json`. Exact
run-label Docker containers/networks/volumes were zero, both anonymous Vault
volumes absent, and seven private siblings absent. Ruling
`S6-E550dba-bounded-recovery-accepted-20261005` closes fixed delivery step 1:
real PostgreSQL fault/recovery, ordered A→B replacement, recovered close and
terminal remote cleanup are established within this component. The controller
still reports `sticky_credential_revoke` with `ControllerDrainOpen=true`;
remote operator cleanup is not clean controller drain. This run cannot be
spliced into the future 78-deployment/16-scenario same-run gate. No Slice 6
manifest or push follows, and Phase 6 remains **5/15**.

Browser independent-PID crash component (2026-10-05, **bounded component
only**): Sandbox ruling `S6-Browser-process-crash-component-boundary-20261005`
authorized a test-only subprocess extension of the existing real
PostgreSQL/high-UID Browser/gateway Docker integration. The parent reserves
the Provider Browser operation in the real repository, and the child builds
the Browser identity runtime, PostgreSQL repository, restricted-network
adapter and bound Docker driver in its own OS process. Its fsynced checkpoint
is observed before the parent sends `SIGKILL` and verifies the signal via
`Wait`; a fresh child PID then rebuilds from the same private PostgreSQL and
Docker state. The first cut occurs after the one permitted `AllocateBound`
dispatch and its completed proof, but before PostgreSQL `CompleteCreate`:
the replacement recovers the exact receipt without any second
`AllocateBound`, retains the same Docker IDs, and reaches Active before
exact terminal cleanup. The second cut occurs after a real network/gateway
acquire but before a completed dispatch proof: the replacement holds the
same Creating claim and finite UID, rejects both replay and a competitor,
performs zero second dispatches, and leaves the observed gateway container
and network IDs unchanged. Test-owned teardown removes those disposable
Docker resources; it is **not** application release of an unknown result.

The source-bound local gateway component image used for this test was
`sha256:4ad516aa5075855897ab937e448561d843eb3fcc5f6b7d2393139b324ccd558f`
(`arm64`, `browser-egress-gateway-v1` label); it is not a release artifact.
The exact `TestBrowserBoundPostgresDockerIntegration` run with Go 1.26.8,
`-tags=integration -race -count=1 -v`, real PostgreSQL and Docker passed on
the reviewed crash-test candidate in 96.30 seconds. Both logged checkpoints show
`SIGKILL`; the run-specific PostgreSQL container and Browser containers and
networks were absent afterward. The ordinary repository race/shuffle test,
`go vet ./...`, integration-tagged package vet and Product Contract lock
verifier also passed; the ordinary suite does not itself execute this
opt-in tagged Docker test. No production Provider API, configuration or
identity-authority surface changed. This proves only the Browser
application/identity-runtime subprocess crash component, not a production
`provider serve v3` replacement, every Docker `ContainerCreate` uncertain
outcome, the three Provider commands or same-run 78-deployment/16-scenario
Slice 6 gate. No manifest or push follows; Phase 6 remains **5/15**.

Review-only test harness follow-up: Sandbox accepted the two actual crash
observations at commit `91fcb312f3a8d23eeb38f2bd3c947f423b14bf20`
under `S6-Browser-crash-91fcb31-component-reviewed-20261005`, but found
that the failing checkpoint-timeout branch read a child-output buffer while
the process writer could still be active. The helper now discards raw child
stdout/stderr, waits for process exit before classifying the bounded timeout
or exact signal, and never includes raw output in diagnostics. A separate
no-Docker child emits over 1 MiB and times out; its targeted tagged race
test, tagged vet and diff check pass. This helper-only change does not alter
either real Docker fault boundary, so the 96.30-second real observation stays
at its recorded commit rather than being relabeled as a fresh run.

Three Provider `serve` v3 wiring difference audit (2026-10-05, **source
inspection, not a live gate**): “three commands” means three separately
launched `provider serve` OS processes with mutually exclusive Profile-bound
configurations, not three new Provider API surfaces. `runProviderServe` already
dispatches by `profile` to three compositions. The old comment above
`newProductionBrowserProvider` saying that `provider serve` did not select it
is stale; this audit uses the actual `runProviderServe` dispatch. The comment
is deliberately left for the next reviewed runtime-source revision so a
documentation-only checkpoint does not silently change frozen R. Static
wiring is not live process proof.

| Deployment / selected entry | Existing source-enforced dependency | Missing final-topology observation |
| --- | --- | --- |
| `provider-runtime` / `coding_shell`, v3 `production` | `preflightProviderCodingV3Postgres` binds the final Profile, Contract address and PG peer-CRL role. `openProviderCodingV3Postgres` uses its own PostgreSQL client signer and direct final PG edge. `newProductionCodingProvider` composes lifecycle/exec/Terminal/artifact, Contract and private Terminal listeners, then reconciliation/readiness. | Own Vault-backed material and TLS agents, direct PG server/HBA/SQL role/grants and live mTLS/CRL, workload/terminal, dependency-loss, restart and drain observations from this exact PID. The older production-process integration uses a local test CA/v1-style configuration, not this v3 final Profile. |
| `provider-browser-runtime` / `browser`, v3 `production` | `preflightProviderV3Serve` checks pinned Browser image, Profile-bound Contract/private action-ingress/attach addresses and CRL role. `openProviderV3Postgres` uses its separate PG client signer and broker-only final PG edge. The composition binds the PostgreSQL finite-slot ledger to Docker/network, action-ingress private v2 listener, Provider-owned allocation mux, Browser executor TLS/CRL client, backend probe and protected admission readiness. | Own Vault-backed signers, egress broker, PG server/HBA/role/grants, ingress plus action-history PostgreSQL/Valkey witnesses, executor backend and one live Provider PID. The independent-PID crash test covers only the application/identity-runtime component, not this full command or every unknown Docker cut. |
| `provider-desktop-runtime` / `desktop`, v3 `local_candidate` only | `preflightProviderV3Serve` checks local candidate manifest, exact source, architecture and slot UID/GID allowlist; PG uses its own client signer and broker-only edge. The composition binds finite-slot Desktop Docker/broker mux, signed bridge key, private Desktop listener, executor TLS/CRL client and backend probe. | Own Vault-backed signers, broker, PG server/HBA/role/grants, real Desktop candidate/broker/executor PID1, RTP/input, restart/drain and exact cleanup. This is not published production Desktop artifact admission. |
| Three one-shot Provider migration jobs, outside the runtime PIDs | `provider migrate` v2 requires the exact Profile-bound job (`provider-migration-job`, `provider-browser-migration-job`, `provider-desktop-migration-job`), own PG signer/material agent, distinct SQL migrator role and precreated schema; unknown DDL outcome is not replayed automatically. | Observe each job's real exit and removal before corresponding runtime admission, with server HBA/grants and no migrator connection/authority retained by the runtime. |

Reuse the existing final Profile and `Slice6PrivateConfigMount`/archive contract
as the *single* source of deployment/file identities. For the already frozen
78-deployment inventory, prepare the three runtime config volumes and three
migration volumes from their declared private file sets; do not add a second
roster or translate Provider DTOs into local `/instances` structs. After the
shared Vault, PostgreSQL, policy/broker and TLS/CRL sources are live, run and
observe the three one-shot migrations, then start each runtime with its own
material agent, subject signer and PostgreSQL client signer. Browser/Desktop
executor backend and Provider mux may start as a bounded dependency group;
wait for both actual readiness checks before admitting work, rather than
assuming a fixed sequential readiness order. Record distinct PID1/UID/GID,
source/config/agent/role/edge bindings, Contract and private listener identity,
real DB privilege denials, peer-CRL/agent loss, restart and drain under the
same future run ID. The presently accepted Guest E and Browser crash
components cannot be spliced into that run. This table narrows the existing
second and third ledger rows only; it neither introduces an extra slice nor
changes Phase 6 **5/15**.

The direct-versus-broker distinction matters to placement: the coding-shell
Provider owns a direct PostgreSQL service bridge; Browser and Desktop
Provider PIDs must **not** join their broker's PostgreSQL service network.
Their own Profile network membership and broker endpoint must be checked
separately. A discarded, uncommitted static projection draft failed on this
exact false direct-network assumption before any deployment or issuer call.
The next gate-only wiring must reuse existing Profile accessors and produce
actual per-deployment `startup-config.toml` and closed private-file inputs;
a static launch projection alone is not a completed step or evidence.

Checkpoint 2026-10-05 (Provider startup prerequisite audit, **open architecture
decision**): the attempted no-issuer offline input run hit Go's default
10-minute test timeout inside the pre-existing source-image/build-context
reverification, before any new Provider migration builder assertion. It did
not validate migration inputs; exact run-owned Docker resources were absent
afterward. Sandbox permits one 20-minute outer timeout only after meaningful
aggregation of all three runtime and three migration inputs, matching the
test's existing 20-minute context; no production deadline or admission bound
changes. Because runtime inputs lack an authorized Docker-control and storage
path, that aggregate run has **not** been repeated.

The three v2 migration startup/private-file constructors are now gate-only
drafts. They recheck the selected job, SQL role, direct PostgreSQL signer,
one-purpose material binding, owner-specific PostgreSQL peer CRL role and
exact Profile/archive inventory. Cross-job startup, role, signer and material
swaps are added to the opt-in negative matrix, but the full source-bound
positive run has not yet reached them. A green tagged compile is not positive
migration evidence and none of the jobs has run.
One previously retained 78-principal Profile/peer-source pair was checked as
a no-Docker shortcut: the current strict peer-source decoder rejected it.
The optional diagnostic was removed rather than treating an older fixture as
current authority or creating a second synthetic Profile framework.

Read-only Provider PID1 prerequisite review found a more basic conflict:
all three current runtime constructors synchronously open and ping Docker via
the Moby client, whereas the final Profile bans daemon sockets, host mounts,
host network and unreviewed egress. No Profile-declared scoped Docker API
channel was found. The coding driver also needs a real daemon-visible
workspace DataRoot and artifact staging root; Browser/Desktop drivers need
their state DataRoots, and Desktop needs its broker mux socket directory.
The frozen Provider mount inventories do not declare these writable roots
(Browser alone has its reviewed mux socket). Coding additionally always
constructs artifact staging and advertises content checks, yet its bounded
command configuration proves only executable presence; `/bin/true` is not a
real active-content or malware check. Treating it as one would contradict
the existing Provider capability and artifact semantics. Sandbox has been
asked to decide an explicit least-privilege Docker/control-and-storage design
and real scanner asset source before runtime config or a six-input rerun.
There is no new issuer, approved exception, runtime topology, manifest,
release claim, push or Phase 6 count change.

Sandbox decision `S6-Docker-control-storage-and-scanner-direction-20261005`
approves a **new reviewed design direction**, not activation: one
operator-owned daemon-facing control principal with three authenticated,
typed Provider scopes; isolated per-owner persistent state/staging and
daemon-managed per-allocation coding volumes; and one real, fixed-asset
coding scanner with a separate active-content policy. The old 78-deployment
inventory must be revised explicitly, retaining the same 16 scenario
meanings and adding negative control/storage/scanner observations. Direct
Provider daemon sockets, generic Docker HTTP proxy, unrecorded host gateway,
privileged/DinD and `/bin/true` content checks remain forbidden.

| Required runtime dependency | Existing call or Profile input | Boundary packet still needed |
| --- | --- | --- |
| Coding Docker lifecycle/exec/Terminal/output | `newProductionCodingProvider` calls `lifecycledocker.New`, whose Moby client pings the daemon before admission; its `DataRoot` creates sandbox inputs/workspace/outputs for Docker bind mounts. | Closed coding operation projection and daemon-managed allocation volumes, transfer confinement, one private durable state volume, exact cleanup and unknown-outcome receipt. Current host-bind path is not an admissible container input. |
| Browser Docker/network | `newProductionBrowserProvider` constructs restricted-network and bound Docker drivers; each opens its own Moby client. Its `DataRoot` holds per-sandbox local state; the final Profile has a Browser mux socket volume. | Same control principal but separate Browser scope, own durable state volume, ownership/relay/network operation types and replay/recovery denial. No Browser executor Docker access. |
| Desktop Docker/network/broker | `newProductionDesktopProvider` constructs restricted-network and bound Docker drivers; its `DataRoot` holds per-sandbox state, while its broker mux needs an exact socket directory. | Separate Desktop scope, state and broker-mux volumes, bounded container broker session type and same-slot close ordering. Local-candidate artifact boundary stays intact. |
| Three material/TLS/PostgreSQL signer chains | Existing final Profile accessors, v2 migration preflight, runtime v3 preflight and direct coding versus broker-only Browser/Desktop PG edges. | Actual agent/socket UID, CRL, HBA, SQL/grant and PID1 observations; no substitution of one Provider or migration job's signer/role for another. |
| Coding artifact checks | `newProductionProviderArtifact` unconditionally builds active-content and malware `CommandChecker`; support currently checks only executable presence. | One isolated scanner, exact engine/platform/rule digest and freshness, real active-content format policy, bounded private transport, resources and fail-closed negative cases. No content-check advertisement on a fixture. |

Current-daemon read-only observation: Docker Desktop `linux/arm64`, Engine
`29.7.2` / API `1.55`, VM memory `12,526,370,816` bytes. On this host the
Docker context socket is owned by UID 501/GID 20 at mode 0755, and
`/var/run/docker.sock` is a symlink to it. The old Profile admits ordinary
role UIDs only in its high-UID partition. These facts do **not** prove that
the proposed control principal can mount or connect to a daemon endpoint;
no privileged diagnostic container has been started. The next boundary
packet must resolve its exact daemon-side UID/GID/socket mapping and deny
cross-principal access before any activation. ClamAV's official Docker
guidance requires at least 3 GiB RAM; this cannot be silently fitted into
the old small-role budget. A source-pinned engine/rule/version choice and
current-daemon volume behavior are still open, with no pull or installation.

The subsequently authorized **one-container, no-control diagnostic** used
an already local `linux/arm64` Alpine 3.23 image at
`sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0`
and fixed probe-argv source digest
reported `sha256:e10e3cf3804bbc17fbabac6ee0209ea4f85ef2986e5fb6eb949ca25c3a20d70f`.
`sr-p6-docker-socket-probe-20261005-1` had only the exact read-only
`/var/run/docker.sock` mount, UID/GID 21099:31099, read-only root, no
network/capabilities/privilege escalation, and 64 MiB/0.25 CPU/16-PID
limits. Inside the container the socket was a socket owned by `0:0` at mode
`0660`, unlike the host-side `501:20`/`0755` view. The image's BusyBox `nc`
did not support `-U`; the fixed `/_ping` was **not sent**. Thus there is no
observed connection success or `EACCES`, only an on-container UID/mode
observation that suggests a high-UID permission conflict. The attempted
response path bounded stdout to 64 bytes, but unsupported-flag help from
`nc` went unbounded to stderr; the extra text was tool usage, not daemon
data. The shell pipe lacked `pipefail`, so `head` masked `nc`'s failure;
the command's exit zero is not counted as a ping. Only `nc` had a five-second
timeout; the approved 30-second total wall deadline was not enforced by a
separate supervisor, although this run ended in 443 ms. Future probes must
capture critical status and bound combined stdout/stderr and total lifetime.
The exact named and
labeled probe is absent after `--rm`; no image, volume, network or historic
Docker cache was removed. No retry with root/group addition/chmod/other
image was made. This diagnostic neither authorizes the daemon mount for a
production broker nor establishes a workable broker UID.

Validation at this uncommitted checkpoint: the ordinary full
`go test -race -shuffle=on -count=1 ./...` exited zero in 370.955 seconds;
`internal/phase6security` alone took 338.700 seconds. Ordinary `go vet
./...`, Slice 6 tagged package vet, targeted tagged race compilation,
`git diff --check`, and the **Product** Contract lock verifier exited zero.
The opt-in source-bound migration positive path remains unexecuted; none of
these checks is the Provider Contract lock verifier or the final gate.

#### Reviewed control/storage/scanner implementation direction (not activated)

This is the Sandbox-reviewed implementation direction
`S6-Control-storage-scanner-boundary-v1-reviewed-20261005`, **not** an
accepted new Profile or a running service. The old inventory is 78 deployments. The minimum
proposed explicit delta is four deployments: one daemon-facing
`provider-docker-control`, its dedicated TLS agent, one
`provider-artifact-scanner`, and its dedicated TLS agent (provisional 82,
subject to exact Profile derivation). Reuse the two existing issuer roots;
new identity policies/edges are not a new issuer. No other principal may
mount or connect to the daemon. The existing three Provider material, live
TLS and separate PostgreSQL signer chains remain unchanged.

| Principal / edge | Closed inputs and permission | Volume / resource proposal and unresolved proof |
| --- | --- | --- |
| Three Providers → `provider-docker-control` | Three separate private internal control networks, each containing only one Provider and the common broker; no direct Provider-to-Provider L3 path. Direct mTLS plus ingress-network identity pins the exact Provider URI and disjoint coding/Browser/Desktop operation set; no additional application-message signing key. Request binds Provider revision, tenant digest, opaque allocation, sandbox/session, generation/fence, operation/request digest, request ID and expiry. Broker checks its retained physical ownership record before every action. | No Provider Docker socket/host bind. Existing Provider TLS agents supply caller identity. Exact private network addresses and byte/time/capacity bounds must be derived in the revised Profile. |
| `provider-docker-control` → daemon | One fixed daemon endpoint only for this operator TCB; no generic HTTP/JSON, arbitrary image/path/mount/label/network/exec target. Persist accepted, completed or unknown physical-operation receipts before/after dispatch and require exact reconciliation before reuse. | One exclusive bounded persistent receipt volume and the exact read-only daemon socket mount; read-only socket mount does **not** limit Docker authority. Preferred candidate is one unique high numeric UID/primary GID with **only this principal** explicitly granted the observed socket's supplementary GID 0. The group is fixed in the revised Profile, never autodetected at startup. Actual access, ACLs and cross-role denial remain unproved; no root primary UID, chmod, generic proxy or extra agent is permitted. |
| Coding Provider → allocation storage | Lifecycle create/start/inspect/pause/unpause/remove, exact sandbox-bound exec/Terminal/output under the one coding scope. User-supplied sandbox argv remains permitted only after immutable allocation/UID/path/resource checks. | Dedicated persistent coding state and staging volumes, plus separate daemon-managed per-allocation inputs(read-only)/workspace/outputs volumes. Driver's current host bind mount must be replaced; confined transfer and daemon-side path semantics require a real current-daemon component gate. |
| Browser/Desktop Provider → control | Fixed image/provenance/finite-slot allocate/inspect/start/relay or broker session/close and restricted-network acquire/inspect/release; no caller-selected Docker ID or network. Unknown result retains the allocation and denies redispatch. | Separate persistent Browser/Desktop state volumes; existing Browser mux volume, new Desktop broker-mux socket volume. No executor Docker authority. |
| Coding Provider → `provider-artifact-scanner` | One private mTLS content stream with exact coding URI and bounded request size/deadline; separate active-content and malware results. Scanner has no Docker, Provider DB or Vault secret, and no runtime public or updater listener. | Selected candidate ClamAV `1.4.6-debian13-slim` image index `sha256:6d0680780fd29855cb7018f68272cb520821f614259e2066f8ec669069ac91b3` / arm64 manifest `sha256:fe182632e3f8de585c539fb22d84144dd6a7e2bf7d9470607b86ad8c368d1e3b`, observed remotely but **not** pulled or verified locally. Rules/config need operator-supplied immutable read-only volume, verified whole-set identity and 72-hour trusted successful-check freshness; hard limits are 4 GiB, 2 CPU, 64 PIDs and one concurrent scan, outside old small-role budget. |

The control protocol must expose role-specific typed operations rather than
mirror `engine` structs or Docker HTTP. Existing coding, Browser, Desktop and
restricted-network engine interfaces identify call sites; a remote adapter
must not make physical IDs stable Provider API fields. A pending request
records its exact owner before the daemon call; an ambiguous completion is
`unknown` and is not silently retried or released. Broker restart reloads a
strict receipt ledger; Provider restart reauthorizes from PostgreSQL and
queries that exact receipt. Drift, extra endpoint/volume, label mismatch,
replayed ID, stale fence/epoch, wrong Provider, missing ledger, broker loss,
or unknown operation all fail closed. Drain stops new actions, waits boundedly
for in-flight operations, closes streams before exact owned resource removal,
and verifies zero. The scanner needs benign, EICAR, actual active-content,
oversize/encrypted/unsupported, rule-loss/stale, cancellation and error
negatives. The 16 original scenario meanings remain; these are additional
negative observations, not substitute scenarios.

Proposed closed broker operation families (internal v1, not Provider Contract):

| Authenticated caller | Typed request family | Existing implementation to adapt; excluded caller fields |
| --- | --- | --- |
| `provider-runtime` | `coding.ready_image`, `coding.allocate`, `coding.inspect`, `coding.start`, `coding.pause`, `coding.resume`, `coding.exec_create`, `coding.exec_start`, `coding.exec_attach`, `coding.exec_inspect`, `coding.terminal`, `coding.read_output`, `coding.release` | `provider/lifecycle/driver/docker` engine, exec and terminal plus artifact output reader. User argv is permitted only for sandbox-bound `coding.exec`/`coding.terminal`. Fixed image inspect/readiness, exec lifecycle and stream termination must be covered; current Moby `ImagePull` branch is **not** a production action. Image, mount, host path, UID, limits and privilege are broker/Profile-fixed, not request-selected. |
| `provider-browser-runtime` | `browser.ready_image`, `browser.network_acquire`, `browser.network_inspect`, `browser.allocate`, `browser.inspect`, `browser.relay`, `browser.close`, `browser.network_release` | Browser bound Docker engine plus shared restricted-network provisioner. The latter internally uses fixed image/network/container inspect, create, connect, start and removal; a typed composite may keep those physical steps private but must receipt each side effect/unknown. No runtime pull. Policy reference and exact owner tuple select one frozen network/gateway/template; arbitrary container/network IDs and attachment endpoints never travel as authority. |
| `provider-desktop-runtime` | `desktop.ready_image`, `desktop.network_acquire`, `desktop.network_inspect`, `desktop.allocate`, `desktop.inspect`, `desktop.broker_describe`, `desktop.broker_session`, `desktop.broker_session_end`, `desktop.close`, `desktop.network_release` | Desktop bound Docker engine/session plus shared restricted-network provisioner. The existing code uses `ExecCreate`/`ExecAttach`/`ExecInspect` and close ordering for the broker session; each status and stream terminal path needs an exact typed projection. Broker command remains one fixed argv in the owned Desktop allocation, not arbitrary exec; no runtime pull. |

Every request is strict/size-bounded and carries a short-lived typed
envelope over role, tenant binding, opaque allocation, sandbox/session,
generation, fence, Provider revision, operation/request digest and request ID.
Only the corresponding mTLS Provider principal can exercise the family.
There is no second per-request signature or repurposed TLS private key.
The broker binds the authenticated peer, Profile/policy digest and physical
mapping in its durable receipt. Identical request IDs and digests may query
safe status or completed results without redispatch; conflicting use fails.
The broker records physical IDs and the exact ownership template privately;
it never trusts caller-supplied IDs or exports them to stable APIs. Its
receipt has `reserved`, `completed`, `unknown` and `released` states; an
unresolved `unknown` prevents second dispatch or capacity release. This
physical receipt is **not** a second Provider session or desired-state ledger.

The current host has about 42 GiB free on the workspace filesystem and the
Docker VM reports 12.53 GB memory, but these figures do not establish enough
headroom for 78 existing roles plus scanner and renewal peaks. No source/
image/volume change is made before an exact R/F/E impact and resource budget
check. Rollback closes new admission, retains unknown run-owned resources for
quiescence proof and exact cleanup, and restores the old frozen inputs only as
historical component evidence, **not** an operable Slice 6 topology.
The active-content policy must inspect bytes independently. The accepted
first policy is `passive-json-v1`: only actual UTF-8 JSON documents with
`application/json`, complete parse/EOF, duplicate-key and malformed-Unicode
rejection, and bounded depth/token/string complexity. HTML/SVG/PDF/Office,
scripts/executables, archives and text/plain are not initially supported.
This does not promise arbitrary downstream rendering or prompt-injection
safety. The stager's prior filename-extension-first MIME detection is being
removed; injected `true` checkers stay component fixtures, not production
evidence. Raw EICAR must independently reach the real malware scanner, while
benign JSON must pass both checks and staging.
ClamAV's malware verdict cannot substitute for that policy. The observed
official ClamAV index/arm64 digests above are selected download-verification
candidates only; no rule database snapshot, engine runtime, test corpus or
license disposition has yet been verified. The operator-side rule check must
be real, whole-set and no older than 72 hours; copying or retimestamping old
files cannot refresh it. Runtime update/networking is forbidden. The
aggregate hard-cap budget must include all simultaneous roles, allocation
peaks, helper/build conflicts and 512 MiB Docker VM reserve, not merely RSS.
Changing the canonical inventory, mount/identity/edge allowlists and driver
adapters changes the selected source: the old R/F candidate pair cannot be
relabeled. A new clean source revision must rebuild and independently reload
the affected repository-local images, prove any unchanged external/published
images separately, rederive the exact new Profile and issuer-source mappings,
and run fresh E observations under one run ID. Earlier Guest E and Browser
crash components remain historical component evidence only; no old receipt
may be spliced into the revised 16-scenario gate. Failure rolls back only
the new candidate/config after exact owned-resource accounting, not the
previous evidence or the locked Provider Contract.

Checkpoint 2026-10-05 (`passive-json-v1` source component, no scanner runtime):
Sandbox's reviewed boundary is now recorded in ADR 0055 and this audit. The
new `provider/artifact/staging.PassiveJSONChecker` accepts only a complete
UTF-8 JSON document with expected `application/json`; it rejects duplicate
keys (including escaped-equivalent keys), malformed UTF-16 surrogate escapes,
trailing content, and policy complexity beyond depth 64, 250,000 tokens or
1 MiB per decoded string/number, with an at-most-6 MiB encoded-string
preallocation bound. The existing 64 MiB Contract artifact maximum is
unchanged. One invocation of the closed policy parser enforces token limits
before allocation and checks cancellation at most every 4 KiB while scanning
strings, numbers and long whitespace; an individual object key is decoded
atomically only after its 6 MiB encoded bound, with direct cancellation checks
before and after key decoding/map insertion. That bounded key decode is not
interruptible mid-call. The parser does not hand a 64 MiB token to
`json.Decoder`. Content-based MIME detection uses the staging context and
propagates cancellation instead of falling back to text/plain. It never
consults a filename extension. Targeted race/shuffle tests cover benign
JSON, HTML rejection, MIME/extension mismatch, in-flight cancellation,
escaped and duplicate keys, valid/invalid JSON grammar and Unicode, exact
and limit+1 string/number/key/depth/token boundaries, and a legal 64 MiB
total document. That 64 MiB whitespace-dominated parse allocated under
8 MiB beyond its already-held input buffer in the targeted test; this is
not a measured worst-case Stage or large-key-map memory bound. The same
Stager currently parses valid JSON once for MIME and again in an injected
`PassiveJSONChecker`; any future production composition must account for or
remove that duplicate CPU work without bypassing scanner verification.
The Provider Contract lock verifier passed. Existing generic
injected-checker tests remain component fixtures; this checker is **not yet
wired** into production `provider serve`; it does not establish real malware
scanning, ClamAV rule identity, production scanner transport, coding
advertisement or staging at the final
multi-process gate. `stager.Stage` still buffers up to 64 MiB in Provider
memory; scanner transport and exact Provider peak-memory budget remain open.
The Stager now treats a checker returning `not_run` without error as an
unavailable check error, which the existing application maps to
`outcome_unknown`; it no longer manufactures a content-rejected evidence
record for a skipped active-content or malware check. Targeted staging and
application race tests pass; an actual scanner skip/timeout drill remains
necessary.

The single authorized official-asset fetch completed: Docker pulled
`clamav/clamav@sha256:6d0680780fd29855cb7018f68272cb520821f614259e2066f8ec669069ac91b3`
for `linux/arm64`; local inspect reports the same repository digest,
`arm64/linux`, 186,283,862 bytes and upstream `/init` entrypoint with an
empty configured user. This is **not** a source-bound scanner image, an SBOM/
vulnerability/license verification, a rule snapshot or a running scan. The
upstream root/default-entrypoint configuration is not accepted as the final
runtime. No container, rule updater or daemon-facing service was started, and
Phase 6 remains **5/15**.

Current-VM admission arithmetic is already negative before a new complete
Profile exists. The old source-bound arm64 candidate's conservative
`browser_desktop_active` hard-cap sum is 8,896 MiB
(`internal/phase6profilebuilder/resource_seccomp_test.go`), including its five
external services. Adding only the reviewed scanner's 4,096 MiB and the
minimum 512 MiB Docker VM reserve yields 13,504 MiB. The observed Docker VM
has 12,526,370,816 bytes, about 11,946 MiB, so this lower bound is short by
about 1,558 MiB **before** the new control service, two agents, dynamic coding
allocation, helper/build conflicts or daemon/kernel overhead. This arithmetic
does not claim a measured new Profile or production capacity. It does forbid
starting the complete revised topology on the current VM without a separately
reviewed resource/environment change; no VM setting, existing cap or cache
was changed to hide the shortfall. The old envelope's CPU quota sum is 9,450
millicores; adding the candidate scanner's 2,000 gives 11,450 millicores
before new roles against the observed 10-vCPU VM. Unlike hard memory
reservation, summed CPU quotas alone do not prove an OS startup refusal;
actual concurrency, overcommit policy and deadline behavior require a
complete revised envelope and load observation. No timeout was extended.

Final validation of this source-component checkpoint: the repository-wide
`go test -race -shuffle=on -count=1 ./...` exited 0 with
`internal/phase6security` taking 337.488 seconds; ordinary `go vet ./...`,
both Provider and Product Contract lock verifiers, tagged Slice 6 gate
compile/race and tagged vet, plus `git diff --check` exited 0. The tagged
offline-input test's actual positive path is opt-in and remained skipped;
the separately allowed 20-minute six-input source-bound rerun was **not**
spent. No new scanner/broker/Provider PID, Vault issuer or final 16-scenario
gate was run. This is not a Slice 6 success receipt or a Phase 6 manifest.

Checkpoint 2026-10-05 (private scanner source components, still no v3
composition): `internal/artifactscanner` now has a strict canonical private
authority/response protocol, a bounded Unix-only ClamD `INSTREAM` adapter,
an mTLS scanner service and client, one shared scan/readiness permit, exact
Profile/rule/body/request bindings, and a canonical Profile-digest-pinned
three-file rule verifier. The verifier checks actual file bytes, version
floors, a 72-hour asserted operator-check time and in-process clock rollback;
the manifest is mode 0600. It does not introduce an unapproved rule-signing
private key. This source verification does **not** prove official-current
rules, the operator receipt, engine-loaded identity or an immutable deployed
mount. Tests use tiny fake rule files and injected engine verdicts.

Sandbox review `S6-Scanner-v3-composition-review-20261005` found and corrected
an accepted-request time bug: validating the original `Retention` again at
scan time would reject a valid request immediately after acceptance when
`Deadline = acceptedAt + Retention`. The private authority now validates
the already accepted structure without restarting that window and uses the
earliest live context/original request/operation deadline; expired or
early/future responses fail. A real TLS partial-body test repeated three
times under race proves timeout releases the sole capacity slot; policy
rejection does not invoke malware scanning; simultaneous expensive ready
verification is bounded. A scanner peer monitor is now required on the
server, and the client requires an injected non-keepalive guarded TLS
transport and monitor rather than silently building a default dialer.
An injected peer-loss test closes an already established TLS scan, returns no
clean result, releases the one scan permit and refuses subsequent readiness;
five targeted race/shuffle repetitions pass. The peer in that test is an
in-memory monitor, not the production CRL/agent source.
Existing `phase6tls` Profile/agent/CRL assembly is **not yet wired** to this
component, so no established-peer revocation claim follows from the test
double. Scanner Client/Server v3 Profile entries, production Provider
composition, whole-set official check, loaded-engine proof, and complete
resource envelope are still missing.

Two isolated real-engine diagnostics failed and are retained as failures,
not successful scanner evidence. The first Docker attempt could not mount
the host's private temporary tree because Docker Desktop did not share it.
The second started a candidate container from the exact local image but
readiness did not appear within 60 seconds; `--rm` removed the exited
container before an exit/OOM/log diagnosis could be captured. Afterward,
the exact test-name container query was empty; a separate directory query
mistakenly included a leading dot that the actual `sr-clamd-real-*` prefix
did not have, so that query was **not** proof of directory absence. The test's
exact `t.Cleanup` returned no error, but the earlier diagnostic remains
incomplete. Neither benign nor EICAR reached a verified real-engine result.

An offline, single-container identity probe then observed the image's
`/var/lib/clamav` directory as UID/GID `1000:1000`, mode 0700, and the
`clamav` account as `1000:1000`; the probe's `--rm` container was absent
afterward. This invalidated the old host-UID attempt. Sandbox also rejected
the premise that a macOS process can necessarily dial a Linux VM Unix socket
merely because the shared path is visible. The revised tagged candidate
therefore cross-compiles a small current-source Go probe and runs it **inside
the same Linux ClamAV container** at fixed non-root `1000:1000`; it checks the
three image-embedded rule bytes, starts `clamd`, and calls this repository's
`NewClamd/Ready/Scan` on a private owned tmpfs socket. It has no raw TCP or
host writable socket mount. The only host mount is one exact read-only,
non-secret probe binary directory. It fixes `--pull=never`, exact image index,
no network, read-only root, 4 GiB/2 CPU/64 PID, bounded Docker output and
contexts, process exit/OOM/log observation, owner-labelled exact removal and
successful Docker absence query. Linux/arm64 cross-build and tagged
compile/skip pass. Sandbox approved one exact local trial under
`S6-Clamd-single-container-local-trial-approved-20261005`; it passed in
12.78 seconds (full Go command 13.244543375 seconds). The source-subset
digest was `sha256:b7a70b03683707b59e757e25956cc3536ebcfcd2782a6932ba7be259df28ac75`
(not a complete clean source-tree digest), with HEAD
`c22d5340e3ea30ea67e3e0fc64be00c5e147cd63` and a dirty worktree.
Go 1.26.8 built the Linux/arm64 CGO-disabled tagged probe binary at
`sha256:fdfeeaa4a9079a02aa640c267f7f8d444f400d396611d6ee3fe7202535beb3ec`.
Within the one container, the fixed `1000:1000` probe read/hash-checked all
three image rules, reached real private Unix PING, and obtained
`benign=clean` plus raw 68-byte `EICAR=infected` from this repository's
`NewClamd/Ready/Scan` adapter. The fixed configuration digest was
`sha256:c657038742d626c5fc869ef496095660ed68900b3da6fa57e4e13603aae23de9`;
rule digests were bytecode
`sha256:6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb`,
daily `sha256:0f7520addba76ca2fc500a95a9da946f3f12de512b42f861f7f89a4fddeb2375`,
and main `sha256:0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365`.
The tagged test asserted stopped exit 0, non-OOM state, owner-label/ID-checked
removal and successful exact-name absence; a separate post-run query found no
remaining test container or `sr-clamd-probe-*` host directory. No fourth
attempt was made. The [bounded raw component receipt](product-phase-6-slice-6-clamd-adapter-component.md)
retains the non-SKIP output and source/binary/config/rule hashes. This is real
engine/adapter component evidence only. The
image-bundled database observed on 2026-10-05 was already older
than the 72-hour rule window, even though `sigtool --info` reported signature
verification for `daily.cvd`; it cannot qualify the final rule-set gate.
The current VM memory shortfall and Phase 6 **5/15** status are unchanged.

Security Profile migration decision (`S6-Security-Profile-v2-boundary-reviewed-20261005`):
the old v1 closed validator/digest/source remains historical, while the
revised Docker-control/scanner/storage/rule/resource permissions require
explicit Profile v2 protocol/version/digest domain and one complete new
source-derived inventory. This distinction is driven by trust semantics,
not mechanically by adding four to 78. Current `ProviderProcess` v3 coding
still assembles both legacy command checkers, so it cannot select scanner
composition or advertise that new boundary. A v2 draft missing any required
control, scanner, network, volume, current-rule or peak-resource field is
non-runnable. The next offline work is v1 byte/digest replay plus v2 closed
DTO/roster/negative validators, then v3 fail-before-side-effect preflight
and guarded checker injection. No daemon-facing control service, new issuer,
full topology or 16-scenario runner was started by this decision.

The first v2 identity slice now adds only Sandbox-approved control, scanner,
and their two TLS-agent name/kind/role tuples to a separate registry; the
v1 built-in registry and principal wire/digest remain unchanged. An offline
fragment checks the provisional 78+4 Profile inventory, unique numeric UID/GID
and TLS URI, and exact new agent-to-subject delegation. This is **not** the
final inventory: dynamic coding allocation identities, whole volumes and
peak envelope still need source-derived bounds. A v1 Profile containing the
four new identities is rejected. The original v1 Profile test factory has
map-dependent ordering. A deterministic historical sample sorts its set-like
mount lists, then freezes canonical document SHA-256
`27c5d37f02b5f0158d1b576f29a0f890bd1a18b1ba7da01fe19a9c229b0087f0`
and v1 Profile digest
`sha256:5eb253af1da927bce2810b9c0b208bf5bc7efc7bd39a3886e28ef802769cfb36`;
Decode/re-encode must reproduce the exact bytes. Source provenance is HEAD
`c22d5340e3ea30ea67e3e0fc64be00c5e147cd63`, with historical Git blobs
`6973a6ef1d4796975c8b72dafbf11c5a9b5b42fb` for `profile_test.go`
and `f5eb7c67488a554fed32d7058b260e592dcaed6f` for `profile.go`.
This is frozen v1 byte/digest replay, not merely an implementation-vs-itself
digest calculation.

The coding Provider v3 serve and direct composition paths now deliberately
refuse startup before material, PostgreSQL or Docker side effects. Its
existing implementation still builds two legacy command scanners and a
daemon-facing lifecycle driver. Until complete Profile v2 authority,
private scanner and Docker-control composition replace those paths, allowing
the old code under a v3 production label would violate the reviewed boundary.
Historical Provider v2 compatibility and Browser/Desktop v3 routes are not
changed by this coding-specific guard. This is a safety hold, **not** a
completed implementation or a passing Slice 6 gate; Phase 6 remains **5/15**.

Sandbox decision `S6-Coding-allocation-v2-bounded-plan-reviewed-20261005`
now fixes the *current local candidate* at two explicit coding slots. This
does not turn terminal session limits into container capacity or make two a
production default. The old 78-entry Profile roster includes one-shot jobs
and Browser/Desktop dynamic templates; 82 is only the provisional v2
Profile inventory count, not a steady-running process count or final resource
envelope. Coding needs a dedicated bounded reservation model under existing
Provider PG operation truth, distinct high UID/GID, `network=none`, and three
whole named volumes per slot (six allocation data volumes total). Unknown
physical outcomes hold capacity through restart until exact container/volume
absence is verified; timeout does not reclaim or redispatch. This remains
an offline design/coding authorization. It does not approve a new daemon
service, unreviewed volume ownership helper or full Docker deployment.
An `internal/codingidentity` offline model now validates explicit finite
capacity, owner/Profile/template/image/config digest, `network=none`, limits,
globally supplied UID/GID collision set, and exactly three whole volume
names per slot. Effective names bind Profile, allocation and generation. Its
reservation-state test holds two unknown/active slots through serialization,
rejects a third, refuses replay/cleanup while create outcome is unresolved,
retains capacity on failed absence callback and rejects an old ticket after
verified-model cleanup/reuse. These tests use an in-memory absence callback;
they are **not** PostgreSQL atomicity or physical Docker/volume-absence
evidence. Sandbox review identified that deleting a cleaned reservation alone
would allow the old Claim to reserve again. The model now requires an
`authorize` callback at every Reserve; the eventual Provider PG transaction
must atomically verify the existing lifecycle operation is accepted and still
eligible, with exact tenant/allocation/generation/fence/request binding and
terminal replay rejection. An offline callback negative covers old Claim and
Reserved-ticket replay after cleanup/restart, but is **not** proof of the
actual PG coupling. The model has no terminal SessionID, gateway or egress
authority.
The cleanup API was then split so the external exact-absence callback runs
through `ConfirmAbsence` **outside** the future Provider PG row lock; the
state mutation consumes only its ticket-bound proof and rejects missing or
stale-fence proofs. This API shape prevents accidental Docker I/O inside the
locked reservation mutation, but a simulated callback still is not real
container/three-volume absence evidence.

Sandbox decision `S6-Coding-allocation-origin-approved-20261005` resolved the
missing AllocationID mapping without a new business table or public field.
The offline mapping now hashes fixed-order canonical JSON of the persisted
Provider revision, tenant, sandbox and accepted create operation ID under a
versioned domain. A separate tenant digest reuses the existing private
scanner domain. A pure Provider lifecycle-state projection checks exactly
one matching idempotency record for the original request digest (because
`StartCreate` does not populate `Operation.RequestDigest`), current initial
generation/fence/lease, accepted non-cancelled unexpired create, and the
no-network coding profile. It rejects missing/mixed records, already Running
or terminal create, and post-create generation drift. It passes repeated
offline race/shuffle tests and preserves ID across state export/import.
The next private PostgreSQL adapter increment now wraps that projection in
`CodingBoundCreateRepository.BeginFirstCreate`: one locked `control_state` row
loads the initialization marker, finite coding reservations and existing
lifecycle ledger. It checks the original Accepted create, reserves one of the
two local-candidate slots, transitions Reserved→Creating, and writes the
operation to Running plus sandbox to Provisioning in the same commit. It
cannot replay a committed first permit from Running/Unknown; no Docker I/O
occurs under the row lock. Initialization requires an explicit external
clean-namespace callback and cannot silently recreate a missing marker.
Unit race/shuffle negatives and the real pinned PostgreSQL integration
`TestProviderTransactionalStateIntegration` passed: 16 contenders across
two PG clients yielded exactly one first permit, and restart retained the
Creating ticket while refusing redispatch. That integration's clean callback
is a component fixture, **not** physical absence evidence. The adapter is not
yet wired into production coordinator or a complete Profile v2 projection;
the v3 startup guard remains active. Docker-control receipt/reconciliation,
real three-volume cleanup, complete v2 admission and the 16-scenario gate
remain open. No coding create was physically dispatched; Phase 6 remains
**5/15**.

Sandbox review of the PostgreSQL component found that the prior test cleanup
removed only the container: the pinned Postgres image declares an anonymous
`/var/lib/postgresql/data` volume. Earlier runs proved the transaction and
restart behavior but **not** complete test-resource cleanup; anonymous volumes
from those historical runs have no retained exact ownership record and were
not guessed at or pruned. The tagged harness now assigns a run-specific label,
captures the exact Docker container ID and its single anonymous data-volume
name, rechecks that identity under an independent bounded cleanup context,
uses `docker rm -fv` on only that container, and verifies both container and
that volume absent. The first rerun correctly exposed a case-sensitive
Docker "no such volume" response parser and failed without promoting the
result; after fixing the parser, the real pinned-PostgreSQL tagged race test
passed with exact cleanup. This is still only component evidence, not the
Slice 6 physical coding-volume cleanup gate.

Sandbox ruling `S6-Coding-coordinator-pending-dispatch-approved-20261005`
then selected a dedicated optional Coding lifecycle path rather than reusing
legacy `Driver.Create`/`Inspect`. `CodingLifecycleRepository` binds lifecycle
reads and `BeginCodingFirstCreate` to the same Provider Store and freezes the
two local-candidate slot spec digests. The PG transaction now writes the
existing `provisioning` event with the Running/Provisioning/Creating first
permit; an event collision aborts all three documents and produces no ticket.
The coordinator's explicit `NewWithCodingFirstCreate` requires a ticket-only
`DispatchCodingCreate` capability. Nil dispatch means only accepted/in-flight:
Operation stays Running, Sandbox Provisioning, slot Creating. Running/Unknown
recovery never uses legacy `Create` or `Inspect` and returns unresolved until
exact control receipt handling exists; it cannot rewrite OutcomeUnknown as
Succeeded. Expired, cancelled, conflict and exhausted attempts do not use a
stale Accepted snapshot to mark another contender Failed or release a slot.
After a contested first-permit error, the coordinator performs one bounded
read-only operation/sandbox readback and preserves the original error with
`Dispatched=false`; it does not present its earlier Accepted snapshot as the
current state. Cancelled contexts return promptly, and failed readback is
reported without fabricated state.

Unit race/shuffle tests cover no legacy fallback, no premature Ready,
Unknown/restart no redispatch, missing capability and expired first permit.
The real pinned-PostgreSQL tagged race integration now also goes through the
coordinator: 16 cross-pool contenders for a second accepted allocation yield
one ticket-only dispatch; two slots remain held, a third stays Accepted with
no dispatch, and restart cannot reissue the second permit. A real row-lock
delay past its deadline, cancellation while waiting for the row lock, missing
marker/state and corrupt state all reject without dispatch. A deliberately
conflicting provisioning event proves rollback of the first permit and slot.
The same real-PG concurrency path checks that conflict losers report the
winner's durable Running/Provisioning observation without new dispatch.
The dispatch driver in this integration is a probe, **not** Docker-control or
physical readiness evidence. The v3 startup guard remains in place; actual
control receipt, exact three-volume cleanup, complete v2 Profile, full
resource envelope and the 16-scenario gate remain open. Phase 6 stays
**5/15**, with no release manifest or push from these component checks.

### 2026-10-05: offline Coding Docker-control authority and receipt component

Sandbox ruling `S6-Control-receipt-ledger-order-and-keys-reviewed-20261005`
requires the first `Unknown` intent to be durable before a one-time physical
callback; reopened `Unknown` and ambiguous commits may only be inspected,
never redispatched. The new private `internal/dockercontrol` component now
models that order. Its strict Coding authority carries separate request and
physical-effect keys: changing attempt, fence, policy or request ID cannot
make a second effect for the same original allocation/creation generation.
The authority is bound to the Provider-accepted ticket, exact two-slot plan,
three-volume mapping digest, original deadline, authenticated peer digest
and current generation. Its canonical decoder rejects noncanonical, unknown,
duplicate, oversized, expired or drifted input.

The local ledger uses an exclusive private lock, strict bounded canonical
state plus digest, temporary-file sync, rename and directory sync. An explicit
clean-namespace check is required for first initialization. A missing ledger
after initialization does not become an empty ledger. A callback failure or
restart leaves `Unknown` and preserves the effect tombstone; two unreleased
effects and 4096 retained records are the closed local-candidate bounds.
Focused race/shuffle tests exercise replay, changed request/same effect,
capacity, corruption, missing state, permission drift, cancellation and
callback ordering. The initializer's clean-namespace callback and physical
callback in these tests are fixtures, **not** Docker observations. There is
no completed/released proof transition, daemon activation, mTLS socket, full
Profile v2, exact container/volume cleanup or full topology gate yet. The
Coding v3 startup guard stays active; Phase 6 remains **5/15** with no
production-readiness or push claim from this component.

Sandbox's aggregated review exposed and closed four model-level gaps. First,
the dedicated Coding dispatcher now receives the Running operation from the
same PostgreSQL first-permit transaction as its ticket. The authority cannot
borrow its original deadline from its own wire fields; the Provider verifies
the operation's create/running/uncancelled identity, deadline and (when
present) request digest, while preserving the historical empty operation
digest whose accepted value resides in the idempotency record. It also
independently derives the allocation ID and matches the frozen plan owner to
the peer. Second, Control validation uses its own frozen plan, per-slot spec
map, mapping derivation, policy and authenticated peer, without accessing PG.
An unreleased physical slot cannot be claimed by a different allocation.
The persisted complete spec-map digest also rejects a changed unused slot
after restart, not merely drift in already occupied records.
Third, the ledger samples a trusted local clock after acquiring its lock and
after the durable write, bounds callback context by expiry, runs external
work outside the state lock, and retains the writer lock until in-flight
callbacks finish or a bounded Close reports non-quiescence. Fourth,
deterministic pre-write and post-rename failures, queued expiry, post-commit
expiry/cancellation and callback-time lookup are tested. A test callback is
still not a Docker operation or a trustworthy completion/absence proof;
`Completed` and `Released` remain unimplemented. This review does not change
the **5/15** count, v3 startup guard or live-gate obligations.

Validation of this final component snapshot: `go test -race -shuffle=on -count=1 ./...`
exited 0 (the longest `internal/phase6security` package
took 345.159 seconds); `go vet ./...` exited 0; the tagged real pinned-
PostgreSQL `TestProviderTransactionalStateIntegration` with race/shuffle
exited 0 after the dedicated dispatcher/Running-deadline change; Provider
and Product Contract lock verifiers and `git diff --check` exited 0.
`internal/dockercontrol` plus coordinator repeated race/shuffle count=5
also passed. These are component/source-bound results, not evidence that
the daemon-facing process, exact Docker volumes, failover/quiescence, Profile
v2 or the full 16-scenario gate ran. No Phase 6 count or push change follows.

A separate current-daemon permission probe used the already-local pinned
Alpine index `sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40`,
one uniquely named/labelled temporary Docker volume and two `--rm` probe
containers. With `network=none`, read-only root, all capabilities dropped,
`no-new-privileges` and UID:GID `57000:58000`, a write to a newly mounted
named `/workspace` failed `Permission denied`; the volume root inspected as
`0:0 755`. Both probe containers were absent afterward, and the exact
labelled test volume was removed. This is **not** the pinned Coding image or
three-volume release gate. It establishes a concrete incompatibility between
the approved distinct high-UID slot plan and an unprepared local named
volume. A restricted, observable daemon-side ownership/preparation design
and real Coding image test are required; the old host bind/0777 fixture is
not an acceptable v3 fallback.

The same narrow probe was repeated with the actual published arm64 Coding
image `ghcr.io/shell-echo/sandbox-runtime-coding-shell@sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1`.
A newly attached named `/workspace` reported `65532:65532 770`, inherited
from the image directory. Under the same `network=none`/read-only-root/
drop-all/no-new-privileges options, `57000:58000` failed to write with exit
1, while image-default `65532:65532` wrote successfully with exit 0. All
three unique `--rm` probe containers were absent, and the exact labelled
temporary volume was deleted and verified missing; the pinned image remains
as a local cache for later gates. This confirms the high-UID mismatch on the
real image, but is still not a three-volume or exact physical-cleanup gate.

### 2026-10-05: v2-only template and bounded volume-preparation probe

Sandbox ruling `S6-Coding-template-and-volume-prep-probe-reviewed-20261005`
selected one closed v2 Coding runtime-template projection and a bounded
current-daemon experiment. The new source-derived template pins the published
OCI index identity and selected platform/config, embedded image manifest
command, fixed environment and workdir, network `none`, read-only root,
all-capability drop, no-new-privileges, pinned seccomp digest, memory/CPU/PID
limits, exactly three named-volume mount targets, per-slot high UID:GID, and
one 32 MiB owner-only `/tmp` tmpfs. The template omits the final Profile
digest to avoid a cycle; a Plan must reference the template digest. This
fragment does **not** constitute a complete admitted Profile v2. The archive
generator accepts only `/workspace` or `/outputs` and emits one zero-length
directory header with fixed slot owner and mode `0770`, no files or caller
content. Focused race/shuffle component tests pass.

The approved real-daemon probe uses the already-pulled pinned Coding image,
Docker 29.7.2/API 1.55 on linux/arm64, one uniquely labelled disposable
container and three uniquely labelled named volumes. Its first invocation
stopped in local preflight before any Docker creation because the test's slot
volume-prefix fixture violated the existing exact `codingidentity.Slot`
rule. After correcting that fixture, the second invocation created exactly
one stopped container and three volumes, observed the original workspace
inode as `65532:65532 0770`, then failed its strict post-create
inspect/template equality check **before** `CopyToContainer`, container
start, or high-UID write checks. The original failure output did not identify
the differing field; it cannot be attributed to daemon normalization without
another observation. The test now reports only the mismatched field name,
without dumping seccomp or daemon diagnostics. Independent label-filtered
Docker container and volume listings for run
`18db83e3f41a3830bdab` were both empty after exact cleanup. No
archive-put success, ownership change, writable high-UID slot, input/root
denial, production Control service or release gate is claimed. A further
physical attempt awaited Sandbox review. The v3 guard remained active and
Phase 6 stayed **5/15**.

Sandbox review `S6-Coding-volume-prep-aggregate-retry-approved-20261005`
found that the published image supplies a fixed `PATH` that Docker merges
into container environment. The v2-only template now freezes the complete
four-entry environment, the published index/selected-manifest sizes and
selected config digests for both platforms. The probe's denial check now
requires the actual `touch` process to exit with a matching permission or
read-only message; a context or Docker transport failure cannot pass. A
subsequent single physical attempt again stopped before archive-put, this
time because the probe incorrectly equated Docker's containerd store image
ID with the OCI config digest. Only that field differed in its aggregated
closed-field diagnostic; run `18db849061aeb608c0b8` had exact zero owned
containers and volumes after cleanup. Existing `ObserveDockerRuntimeImage`
already binds store ID, selected manifest, original OCI config and RootFS
diffIDs distinctly. The probe now reuses that verifier and the existing OCI
archive descriptor/layer-chain checks instead of dropping image identity
verification.

The separately reviewed corrected attempt `18db84d26d870178c1ec` passed
the cached published-image index→selected manifest→config→layers check
before creation, and passed stopped-container/template/actual-image checks.
Its single `CopyToContainer` of a zero-size USTAR `.` directory into
`/workspace` returned success with `CopyUIDGID=false` and directory/file
overwrite disabled, but an independent `CopyFromContainer` immediately
observed the mount root still owned by `65532:65532` at `0770`, not slot
`57000:58000`. The probe failed before `/outputs` preparation, container
start or high-UID write/denial checks. Label-filtered independent Docker
container and volume queries were empty after exact cleanup. This is a real
negative result for the proposed root-metadata archive mechanism on Docker
29.7.2/API 1.55, not a successful volume-preparation gate. The daemon's
published `go.mod` pins `github.com/moby/go-archive v0.3.3`; that version's
`Unpack` explicitly skips any tar entry whose cleaned name is `.` before
metadata application. See the [pinned extractor source](https://raw.githubusercontent.com/moby/go-archive/v0.3.3/archive.go)
and [daemon extraction path](https://raw.githubusercontent.com/moby/moby/docker-v29.7.2/daemon/archive_unix.go).
The observed success-without-change is therefore consistent with the exact
daemon implementation, not proof that the archive safely changed the root.
No other tar shape or root/helper fallback has been run. Production Control
activation and complete Profile v2 remain open;
Phase 6 is **5/15**.

Sandbox ruling `S6-Coding-stopped-preparation-carrier-probe-approved-20261005`
allowed one different, finite mechanism experiment. The old `.` archive
shape is no longer the template's preparation mode. The new generator emits
only two zero-length USTAR directory headers, `workspace` and `outputs`,
with the exact slot owner and `0770`; the extraction destination is fixed
`/`. A dedicated never-started preparation carrier uses the same pinned
image and slot high UID, three named mounts, network `none`, cap-drop ALL,
no-new-privileges, pinned seccomp and resource bounds. Its rootfs is
explicitly writable only to pass the daemon's extraction-point check; its
argv is inert `/bin/false`, and it is deleted before a distinct workload
container can be created. The latter retains read-only rootfs, original
manifest command, owner-only bounded `/tmp` and `NoCopy=true` on all three
volumes. Focused tagged race/shuffle tests check the phase separation,
wrong slot/policy/plan/phase rejection and archive allowlist. These are
component checks, not production authority.

The one approved current-daemon run `18db85b5f45aa0b8d203` passed. Its
cached published-image index→selected-manifest→config→layers chain and both
container image observations matched the frozen template. Before extraction,
the newly created workspace and outputs roots were `65532:65532 0770` and
empty. The stopped carrier remained `created`/not-running/PID 0 with zero
start time; one `/` archive-put made both roots `57000:58000 0770`, while
root and read-only inputs metadata remained unchanged. After carrier
deletion was confirmed, the separately created runtime preserved both
owners through `NoCopy=true`, retained rootfs read-only and started. Fixed
high-UID `touch` commands succeeded in workspace, outputs and `/tmp` and
returned actual exit-1 permission/read-only errors for inputs and the root.
The tagged test exited 0 in 1.26 seconds. Its exact cleanup and independent
label-filtered Docker container/volume listings found zero of the two
containers and three volumes afterward. No new image was pulled/built and no
root helper or host bind was used. This proves only that the bounded
two-container preparation mechanism works on this daemon. The production
Control ledger still has no physical Completed/Released receipt,
crash/uncertainty recovery and whole-resource cleanup, complete Profile v2,
scanner/rule/CRL composition or fixed 78-deployment/16-scenario gate.
Coding v3 startup remains fail-closed and Phase 6 remains **5/15**.

Sandbox independently accepted run `18db85b5f45aa0b8d203` only as a
current-daemon mechanism component (`S6-Coding-stopped-preparation-component-
accepted-20261005`). It then approved single-effect, deterministic resource
inventory and durable `Unknown` before the first physical action, without a
second per-Docker-command phase ledger (`S6-Coding-single-effect-receipts-and-
cleanup-reviewed-20261005`). The new offline resource projection derives
both possible container names and three whole volume names from the same
frozen Plan/create authority; labels bind effect, authority, Profile, Plan,
template, slot and exact object role. It is not a create/inspect adapter.

The remaining production proof cannot be shortened to a digest setter or
caller boolean: `Completed` requires original-daemon raw observation of
the exact resource set, stopped-carrier removal, runtime policy and actual
ownership/permissions. Cleanup must have a separate Provider-PG-authorized,
durably fenced intent before any deletion. A local callback returning,
client cancellation, flock acquisition, elapsed time or even two exact
absence reads do not exclude a late Docker daemon create after timeout.
That branch retains `Unknown` and its UID/capacity claim. Release requires
external quiescence/fence proof, precise ID/name/label/config-matched deletion
and independent twice-observed absence of both containers and all three
volumes, including effect-label inventory; only then may a durable Control
tombstone precede Provider's PG CAS. This is the next Step 2 test matrix,
not an assertion that those transitions already exist. Phase 6 is **5/15**.

The offline source now provides that deterministic five-object projection
and exact-label comparison, plus a separate canonical short-lived cleanup
authority bound to the original create effect, original birth generation and
fence, a current Provider `terminate` operation, current generation and
higher fence. It refuses `Creating` tickets. Receipt schema v2 records this
cleanup authority orthogonally to `Completed`; the ledger commits it before
any optional cleanup callback, never infers `Released` from callback success,
and rejects same-effect replay. Race/shuffle tests exercise source drift,
stale fences, wrong tenant, callback-after-commit ordering, persistence
failure before write and after rename, and a deterministic late-effect model
where two empty reads precede a delayed create. The tests use a deliberately
constructed `Completed` fixture because no trusted production completion
observer, daemon quiescence proof, release transition or PG cleanup CAS is
implemented yet. They are component evidence only; the production guard and
5/15 count remain unchanged. The offline receipt schema changed from v1 to
v2 for the cleanup authority field; an old persisted v1 ledger is rejected
rather than silently reinterpreted or reset. The v2 receipt digest uses a
separate v2 domain and freezes the original Docker daemon identity digest;
opening the same ledger against a different daemon fails closed. This is
still only a binding until a trusted observer supplies the actual daemon
identity and resource observations.

The reviewed read-only observer now separates `Info.ID` plus a frozen
endpoint-scope digest from an environment digest of Linux OS type, explicit
native-architecture mapping, root-path digest and daemon version. It reads
through one supplied client before/after inventory and rejects drift,
cancellation, missing/unsafe fields and errors without returning absence.
The opt-in actual Docker API component run of `TestCodingDaemonInfoObservationRealAPI`
passed in 0.07 seconds on this host and observed `linux/arm64/v8`; it read
`Info` twice and made no container, volume, image-build or network mutation.
Its endpoint scope was a fixture, so it is not authenticated daemon identity,
not external quiescence and not a production Control or Slice 6 gate.

The adjacent source-only private `readCodingResourceInventory` checks the same
source-verified template/OCI-config inherited labels, exact two container
names, three generation-scoped volume names and effect-label listings on a
single supplied client bracketed by the before/after daemon observation.
Its deterministic fake-API matrix rejects foreign same-name objects,
missing/extra inherited or binding labels, unlisted/extra effect resources,
volume warnings, API errors and cancellation. The returned private IDs and
presence bits are only one observation. The component does not verify full
runtime config, authorize deletion, prove daemon quiescence or emit a
`Completed`/`Released` receipt. The real descriptor→container-label→inventory
chain and full physical proof remain open; 5/15 is unchanged.

Independent cleanup-model review found and corrected three source-level
gaps before production wiring: Provider rebinding now permits a legitimate
earlier parent-context expiry while rejecting any expiry beyond the original
operation/30-second ceiling and any operation-deadline drift; the cleanup
request digest is nonempty even when the general lifecycle model would allow
both idempotency fields absent; and container label matching now combines
the exact labels from a descriptor-verified pinned OCI image config with the
eight Control binding labels, rejecting collisions and extras. Volumes still
use only their closed binding labels. Pure tests cover inherited labels,
collision, extra/missing labels, parent deadline and blank digest. A future
Provider PG cleanup transaction must additionally compare the current fence
high-water mark: being above the create fence alone is not current authority.
The private Control process never reads Provider PG.

The subsequent read-only client component applies Sandbox ruling
`S6-Control-unix-only-bounded-observer-reviewed-20261005`: one explicitly
bound Unix socket, root:root mode `0660`, root-owned non-writable ancestors,
no symlinks, no environment/context/default endpoint or fallback. Its fixed
Moby v1.55 client has a restrictive `RoundTripper`, not a response hook:
the SDK forbids a hook from reading or closing the response Body. The
transport refuses all unreviewed methods/paths/queries/endpoint Hosts
before the underlying dial, and reads at most 1 MiB plus one byte before
SDK decoding, including 404 responses. It rejects oversized, truncated,
malformed-success, read/close-error and cancelled responses as errors rather
than `NotFound`; the request and full-inventory ceilings are five and ten
seconds respectively, without extending a shorter caller deadline. Focused
race/shuffle tests repeated three times pass for
socket metadata/path denial, the eight actual SDK inventory requests,
foreign method/path/host denial before dial and slow-404 cancellation.
The source does **not** yet authenticate a complete Profile v2/operator
endpoint or run as a production Control service. It has no trusted complete
runtime-config observer, external daemon quiescence proof, deletion path or
`Completed`/`Released` receipt. The current Coding v3 startup guard stays
active; no fresh mechanism run, issuer, manifest or push was produced and
Phase 6 remains **5/15**.

Sandbox's independent review then caught three unsafe assumptions in that
first client draft. A bounded but malformed inspect `404` could still be
classified by the SDK as NotFound; a syntactically valid `null` container
list or missing/null `Volumes` field could be decoded as an empty list;
and a contended mutex could delay cancelled inventory/close callers.
The correction validates an inspect-404 JSON error envelope/media type
before SDK classification, validates successful list top-level shapes and
required `Volumes`, and replaces the blocking mutex with a context-selectable
single-client admission gate. `CloseContext` reports a timed-out acquisition
as failure; `Close` uses a bounded context and does not silently mark drain.
The real SDK is exercised through the transport and inventory for both
container and volume malformed 404, invalid/empty list shapes, and a valid
empty inventory. A controlled held-gate test shows the second expired read
and close return without waiting for the first. Targeted
`go test -race -shuffle=on -count=3 ./internal/dockercontrol` passes after
these changes. All 404/list sources in this correction are deterministic
test transports, not a newly observed physical daemon; native Linux socket
permission and actual daemon-response conformance remain to be measured.
This repair does not activate Control or change Phase 6 **5/15**.

Sandbox's final same-batch review found two smaller mismatches: a lowercase
`volumes`/`warnings` alias can overwrite the independently checked canonical
field during SDK decoding, and the first ten-second budget began after
waiting for client admission. Both are corrected. The validator rejects
case-fold aliases of the two known fields in either order, without making
unrelated future top-level fields illegal. The same absolute budget is now
created before queue admission. The SDK→inventory alias matrix and a held-
gate short-budget test pass in a fresh three-repeat race/shuffle package run.

Under `S6-Control-observer-response-and-budget-closeout-reviewed-20261005`,
one opt-in local read-only component run of
`TestCodingReadOnlyEmptyNamespaceRealDaemon` used a unique newly derived
effect and exactly one frozen test-only Unix SDK client/API 1.55. It made
exactly nine bounded GETs: Info before/after, five named-object inspects
and two effect-filtered lists. The observed status counts were four `200`
and five `404`, with JSON media type on all five `404`s; the strict current
list parser accepted both empty lists, and the before/after projected
daemon identity/environment digests matched. The tagged test passed in
0.03 seconds. No create, delete, build, retry, issuer or new resource was
involved. Its host endpoint and endpoint-scope digest were test fixtures,
not the admitted production Profile/operator scope; no raw endpoint,
daemon ID, path or 404 body is audit evidence. This proves current-daemon
response compatibility for one empty namespace only, not delayed-effect
quiescence, exact physical config/metadata, Completed, cleanup, Released,
PG CAS, Control activation or a Slice 6 release gate. Phase 6 remains
**5/15** and the Coding v3 startup guard remains active.

Next source-only work follows
`S6-Control-complete-runtime-observation-scoped-reads-reviewed-20261005`.
The read-only transport now admits only the template's exact digest-pinned
image reference, with no query or the frozen native-platform query. Its
archive branch is initially closed until an exact runtime ID is verified;
it recognizes only the three roots of this allocation, caps the full
response at 32 KiB before SDK use, and rejects wrong tar media, status,
path-stat metadata, owner, mode, extra entries, truncation and nonzero
trailing bytes. The existing real stopped-carrier probe's container-policy
comparator was moved unchanged into shared source, except that its selected
manifest platform comparison now derives arm64/v8 or amd64 from the frozen
template instead of assuming arm64. Original tagged probe pure tests and
new read-route/aggregate-tar rejection tests pass. No new physical Docker
operation was made for these source changes. The live runtime-ID binding,
descriptor→image inspect chain, full one-budget observation and durable
Completed transition remain unimplemented. Archive GET can hold a daemon
container lock and emit an archive event; client cancellation cannot prove
daemon quiescence. Rollback closes the new observer entry and holds Unknown,
resources and UID capacity. Phase 6 remains **5/15**.

The subsequent unexported `observeCompleted` source skeleton now combines
those checks under one pre-admission ten-second deadline, returning a
Control-private proof only after exact initial and final five-object
inventories, original-daemon Info equality, a running runtime with full
shared probe-policy comparison, descriptor-verified index/selected image,
three bounded empty-root archives and final same-ID inspect. It binds
authority/effect/Profile/Plan/template/receipt revision and the observed
digests. The constructor additionally binds exact seccomp bytes to the
template digest. Positive pure tests exercise the selected-image and
running-runtime projections; negative tests reject wrong effect, fabricated
Completed status and zero revision before physical reads, with cancellable
admission. Three-repeat package race/shuffle passes. No durable Completed
setter, Provider outcome change, full positive physical chain or production
Control service exists; the prior 9-GET empty-namespace test does not fill
that gap. If a late daemon call remains possible, snapshot equality does
not prove quiescence. This source-only progress leaves **5/15** unchanged.

2026-10-05 follow-up, still fixed Slice 6 Step 2. Sandbox review found
that the locked Coding image's `/inputs` is root:root `0555`, while only
`/workspace` and `/outputs` are prepared to the selected high UID/GID and
`0770`. The bounded archive reader now checks those root-specific owners,
full directory mode including special bits, and a single PathStat response
header. The actual HTTP parser has a 16 KiB total response-header ceiling.
The shared runtime comparator additionally rejects supplementary groups,
host/other-container namespace sharing, secondary devices/volumes/ports,
sysctls and unapproved runtime options; single-field mutations are tested.
The private proof now retains bounded initial/final identity and volume
metadata, safe runtime-security projections, descriptor observations and
three empty-root metadata projections, then rechecks them against the frozen
plan/policy before return. Neither that recheck nor a checksum proves the
durable ledger revision is still current; there is no Completed setter.

The original cached, digest-pinned Coding image was exported exactly once
through an explicitly fixed local Unix endpoint to a private 0600 archive
under Sandbox ruling `S6-Control-cached-image-raw-doc-recovery-approved-20261005`.
The archive was 6,526,464 bytes. Existing descriptor/layer verifiers accepted
its index, selected arm64/v8 manifest, config and layers. Only the exact raw
public metadata bytes were retained in
`internal/dockercontrol/testdata/coding-oci-arm64-v8/` (index 670 bytes,
manifest 668 bytes, config 4,037 bytes); their SHA-256 values equal the
repository publication/config locks. The full tar is not a repository
fixture. A positive same-client bounded SDK test now walks all 23 expected
GETs using those bytes, and branch-specific negative tests verify receipt,
runtime ID/privilege, volume labels, image digest, root metadata, final list
and daemon drift. Three-repeat targeted race/shuffle and tagged vet passed.

The one conditionally approved real-daemon batch then persisted a single
Unknown receipt before mutations, created three exact labelled volumes,
prepared and removed one never-started carrier, and started one separate
read-only runtime. Every mutation returned success, with no timeout,
disconnect or retry. The first full observation nevertheless rejected at
the initial inventory's seventh GET: the Docker Desktop 29.7.2 container
list reports one extra list-only `desktop.docker.io/ports.scheme=v2` label
not present in the exact container inspect `Config.Labels`. The inspect has
the exact 20 expected inherited/binding labels; the list has those same 20
plus that one key. ID, name and effect match. One bounded read-only diagnosis
of the *retained same effect* reported Info 200, prep inspect 404, runtime
inspect 200, three volume inspects 200, then container list 200 and the
closed label mismatch. The exact effect volume-list read found only the
three expected local volumes, each with eight binding labels, and no
warning. No second resource batch, exec/touch, cleanup, Completed or
Released transition occurred. The durable receipt remained Unknown and the
runtime plus three volumes stayed retained pending a narrow compatibility
decision; Phase 6 remained **5/15**.

Sandbox ruling `S6-Control-list-only-metadata-compatibility-and-retained-effect-review-20261005`
then permitted exactly that one additional key only in container-list
labels, bounded to 4,096 bytes and never treated as ownership authority.
Inspect still requires the complete exact 20-key set; list still requires
every expected key/value, exact single ID/name, no duplicate or extra effect
object. Any other additional list label is rejected. The raw value of the
list-only key is not trusted or retained in the ownership proof. Pure tests
cover the observed `v2` projection and all the forbidden variants. With this
change, one authorized same-effect, same-runtime read-only recheck completed
all 23 bounded GETs in 0.22 seconds, including initial/final daemon Info,
two exact whole-effect inventories, index/selected image, and the three
empty-root archives. The safe private proof independently rechecked against
the frozen plan, original OCI bytes and seccomp policy, producing digest
`sha256:dda5c571f7115857fb755db1c50c035a20d0250eda9a6e313ca7e1cfd005254f`.
This is component evidence only; the durable receipt is still Unknown.

Under Sandbox ruling
`S6-Control-retained-effect-proof-persistence-and-cleanup-approved-20261005`,
one further *same-effect* tagged race integration run repeated the full
23-GET observation in the same process that performed exact cleanup. Before
any delete, it exclusively persisted the full minimal proof, 23-request
trace, original OCI reference and Unknown receipt revision 2 to a private
0600 file, then fsynced, read back and independently rechecked the record.
The proof digest remained
`sha256:dda5c571f7115857fb755db1c50c035a20d0250eda9a6e313ca7e1cfd005254f`.
After verifying the same runtime ID against its complete frozen policy,
labels and effect, the absent prep carrier, and all three exact volume
identities/labels, the run removed that one runtime and those three volumes
exactly once. Two subsequent complete container/volume inventories each
reported zero effect resources. The tagged test passed; no second physical
resource batch or retry occurred.

The observed tool receipt was `exec-30232e79-ce81-4688-a955-dd777907a3b4`
(`TestCodingExistingUnknownReadOnlyDiagnosis`, test body 0.45 seconds). The
source snapshot was base HEAD `c22d5340e3ea30ea67e3e0fc64be00c5e147cd63`
plus uncommitted files; the test source SHA-256 was
`0012bfde710bfb15d7db7effdbc7681a423aee5f54abc93d851da0a91c257b20`,
observation source `048445c30476de0c8ed1654f11c9460daca6034d8a4a0450286b472dcdd98ac2`,
proof recheck source `c1e54bbfa7b61a034c9b441be62e009db5c3383c0e51543d3bed0d498d69f277`,
inventory source `e2dc125ac88c76bc0f4d992dc79f46e9aba23131c7c08161ee7fa012fdbaef3c`
and private-record test source
`a65a3dfc461591b16e9a0de2233d48f8f0318fc5a64cf3ab366b781d51c59791`.
This identifies the exercised implementation without implying that HEAD
alone contains the uncommitted changes.

Private retained evidence is in
`/Users/echo/.codex/phase6-coding-control-3935310749` (directory 0700,
files 0600): `private-completion-observation-retained.json` SHA-256
`1df5dcb98ad3c5df3067691e149ef5a7a61b04a7da8b55c93faca7de15227cd6`,
`private-cleanup-intent.json` SHA-256
`6359f00fbcbb0d84e89fae72bbe947a7cf488048dd12fa023b5cdab61bf4292c`,
and `private-cleanup-result.json` SHA-256
`0d8783b29f8b6a752dbb8a753affadd9db0f6645286d8e770a80d41f5409c81d`.
The no-longer-needed 6,526,464-byte private OCI tar was moved from its
temporary directory to the user's Trash as
`/Users/echo/.Trash/phase6-coding-published-20261005.oci.tar`; the empty
temporary directory was removed. The private proof/cleanup records were
not moved or deleted. The tar remains recoverable from Trash.
The original durable receipt remains Unknown at revision 2; neither
Completed nor Released was fabricated. The two clean inventories establish
observed absence after this batch, not a general late-effect quiescence
fence, production Control activation or a Slice 6 release gate. Sandbox
accepted this as a component result under
`S6-Control-complete-observation-and-retained-cleanup-component-accepted-20261005`;
it does not advance the step. Do not recreate or rerun this physical effect
to establish the same result. Phase 6 stays **5/15** and the Coding v3
startup guard remains active.

2026-10-05 live-completion source follow-up, still fixed Slice 6 Step 2.
Sandbox ruling
`S6-Control-live-completion-CAS-and-historical-Unknown-boundary-20261005`
forbids retroactive completion of the now-cleaned test effect. The new
unexported ledger path accepts only the internally constructed live Unix
observer after this process's create callback returned unambiguously and
synchronously. It excludes other local physical dispatch during the bounded
observation without holding the ledger mutex over Docker I/O, then rechecks
the original receipt revision, authority, effect, status and closing state.
A canonical full proof is exclusively written to a 0600 file in a private
0700 ledger directory, fsynced, read back and rechecked before the atomic
receipt write; active Completed reads/reopen require the matching evidence.
Persist-before-write and post-rename ambiguity tests preserve fail-closed
behavior. Cancellation, close/drain, wrong authority, stale revision,
reopened/ambiguous Unknown and replay tests do not grant a second physical
create. Three-repeat targeted race/shuffle passed. This is source/component
validation, not an activated Control service, daemon late-effect fence,
Released transition, PG CAS or a formal gate. Phase 6 remains **5/15**.

The next Sandbox review,
`S6-Control-live-Completed-aggregate-boundary-corrections-20261005`,
identified three candidate gaps and the source was corrected together.
The original create authority expiry now bounds the entire normal live
observation; fake-clock expiry before admission performs zero GET. Expiry
or cancellation after evidence durability but before receipt commit leaves
Unknown plus unusable orphan evidence; cancellation after commit reports an
uncertain response while read-only reconciliation finds Completed. The
receipt now separately seals the entire canonical evidence envelope and
retains the original physical proof digest. Reopen rejects missing evidence,
inner proof drift, noncanonical JSON, capture-time drift and source-state
digest drift, including when the inner proof digest is unchanged. Unknown
receipts omit the new field and preserve existing canonical bytes; old
unsealed Completed prototypes are rejected. The first full race run after
the initial live path passed, but it predates these three corrections and
is not the final source candidate gate. No real Docker batch was repeated.

Sandbox accepted the three source corrections as a component under
`S6-Control-live-Completed-three-boundary-fixes-accepted-20261005` after
reviewing race/shuffle/count=3 receipt
`exec-e74232d0-999d-41c1-b1f5-4aaa98629d66` (package 9.392 seconds)
and full vet receipt `exec-3e112a2d-43e9-46e1-97f2-fd235fa8c274`.
The reviewed source SHA-256 values were `coding_completion_ledger.go`
`44896e1ddb279cd607caf0a08cb60b92f09b614119fb6dc01040a255a5c38ccb`,
its test `8bc6a4248178d8a3af4b6d7dca2ed98a382a16f63dddc02de6f6f0e2663a34a4`,
`receipt_state.go`
`97437cc51883b2d503fef68b5578aa0fd0d3c10f7eab734297478cfb15d15521`
and `receipt_ledger.go`
`ad18c623b91504c4ddc837903463c557d14fc684285e5f54546adfedbfbb1451`.
These files are still uncommitted on base HEAD
`c22d5340e3ea30ea67e3e0fc64be00c5e147cd63`. Acceptance covers this
source component only; the stable-candidate full race gate is reported
separately after it finishes.

The stable candidate's required `go test -race -shuffle=on -count=1 ./...`
then exited zero; its long-running `internal/phase6security` package passed
in 342.526 seconds, and `internal/dockercontrol` had already passed in the
same full run. `go vet ./...`, tagged integration compilation and tagged
vet for the affected packages, the Product Contract lock verifier, `gofmt`
and `git diff --check` also passed. The tagged integration compile is only
compile evidence; no second physical Docker batch was run. These checks do
not turn the Component into a production release gate or advance **5/15**.

2026-10-05 PG current-cleanup source follow-up, still fixed Slice 6 Step 2.
Under `S6-Coding-current-terminate-and-historical-create-outcome-reviewed-20261005`,
the private cleanup authority now accepts a fence equal to birth only when
it represents the current PG highwater; lower fences remain invalid. A
Provider-owned retirement binding is retained on a Cleaning slot with the
original claim/authority, current terminate operation/attempt/request,
generation/fence and Control Completed receipt revision/state/proof/evidence
digests. The source-only PG triple-row projection checks the current
accepted terminate and unique idempotency record, original create identity,
lease/current highwater and trusted in-process Control Completed snapshot,
then moves Creating/Active to Cleaning, the terminate to Running, the
sandbox to Terminating and appends the existing event together. The old
create remains Succeeded or outcome_unknown exactly as stored; no Ready
intermediate state is published. Control Unknown, wrong IDs, record aliases,
stale highwater and a second same-fence operation are rejected in pure
tests.

Sandbox review `S6-Coding-PG-current-cleanup-projection-reviewed-20261005`
found that the first draft had lost the shorter caller deadline and had
not checked map-key/value identity for operation and lease reads. Both were
corrected. The retirement binding now stores the exact canonical cleanup
envelope and its digest, so a lost PG response can be read back without
renewing its original clamped expiry. A canceled admission returns no
permit. Three-repeat race/shuffle of `internal/codingidentity`,
`internal/dockercontrol` and `provider/adapter/postgres` passed after these
source corrections. This is not a real two-client PG row-lock or
crash/restart gate: running the existing tagged PG integration would create
a new Docker container, which was not done under the no-new-batch ruling.
The cross-process Control edge, durable cleanup intent/deletion/Released,
Provider exact release CAS and all full-topology gates remain open. Coding
v3 stays guarded; Phase 6 remains **5/15**.

2026-10-05 bounded real-PostgreSQL current-cleanup component gate. Sandbox
approved one aggregated PG-only batch under
`S6-Coding-PG-cleanup-source-corrections-and-bounded-PG-gate-20261005`.
The existing `TestProviderTransactionalStateIntegration` reused a single
locally present digest-pinned `postgres:16-alpine` image without pulling,
with 512 MiB/one CPU/128-PID limits, a three-minute parent context and
30-second exact cleanup. Its new test-only input is an explicitly synthetic
Control Completed receipt; it cannot attest a production Control process or
authorize Docker. Two actual PostgreSQL clients contended on the same
`control_state` row with different terminate operations at the same fence.
Exactly one cleanup authority committed; replay, Control Unknown and stale
allocation failed. An injected post-event transaction abort rolled back the slot
and terminating event, and a second client's shorter deadline canceled on
the held row lock without a write. The original create outcome_unknown
remained unchanged. The winning exact canonical envelope survived a
*simulated* lost success response (the test ignored the return value and
read back independently) and an actual PostgreSQL container restart without
expiry renewal or a second permit. It did not inject a SQL COMMIT response
loss or real connection interruption.

The sole tagged run passed on its first attempt in 2.92 seconds of test body
(3.648 seconds package). The test removed its exact labeled container and
anonymous volume and verified both absent; a separate read-only label
inventory returned no containers. The affected tagged packages compiled,
the untagged full repository race/shuffle/count-one suite and `go vet ./...`
passed, the Product Contract verifier passed, and `gofmt`/`git diff --check`
were clean. The full untagged race suite predates only the newly tagged
integration test source and does not include that tagged test; the tagged
PG run did not use `-race` or `-shuffle`. The stale allocation test changes
only the input create authority while leaving the synthetic Completed
receipt unchanged, so it rejects at admission rather than proving a PG
new-occupant CAS. A different-fence contest and the public
`BeginCodingCurrentCleanup` post-commit cancellation branch were not
exercised. These remain for the later release-CAS aggregate gate; no extra
PG container is opened now. Sandbox accepted only this bounded component
under `S6-Coding-PG-current-cleanup-bounded-component-accepted-20261005`.
No Coding
Docker effect was recreated. This is a real PG transaction component gate,
not cross-process Control attestation, exact Control Released/Provider release
CAS, a 16-scenario Slice 6 gate, a success manifest or production readiness.
The startup guard remains closed and Phase 6 remains **5/15**.

2026-10-05 Control Released → PG final release CAS source candidate, under
Sandbox review. An unexported Control path now uses the existing durable
cleanup-intent transition before any deletion. It binds a sealed original
completion runtime ID to a fresh full-effect inventory, then uses a separate
typed Unix client whose transport admits only one exact runtime ID DELETE
and the three effect-derived whole-volume DELETEs. Each deletion requires
a net/http-visible 204 with an empty exposed body; that alone cannot prove
raw late wire bytes or daemon quiescence. Any error, cancellation or uncertain
response stops the sequence and retains the occupied Completed receipt with
its cleanup intent. After confirmed mutations, two complete same-daemon
absence inventories feed a private proof. The full canonical evidence is
exclusively written at 0600, fsynced and read back before the durable
Released tombstone. `AbsenceDigest` binds the physical proof and the new
optional `AbsenceEvidenceDigest` seals the whole envelope; non-Released
receipts omit the new field. Open/reopen and a targeted Released Lookup or
snapshot recheck both release evidence and retained completion evidence;
routine unrelated reads only recheck active Completed evidence. A private
in-process Released snapshot is
not cross-process attestation.

The companion PG source-only transaction verifies the exact original
claim/create operation and idempotency record, stored retirement envelope,
current terminate operation/attempt/request/generation/fence, sandbox and
lease highwater, plus Control Released revision/state and the completion and
absence digests before it removes only that slot/retirement, applies
ObservedTerminated, updates a Running terminate to Succeeded while retaining
an already-Unknown terminate, and appends the existing terminated event.
It does not use a generic `ConfirmAbsence(callback)` as release authority.
Fake-daemon and pure-state tests exercise normal/reopen/replay, bounded
DELETE allowlist, failure, cancellation, evidence/commit ambiguity, stale
proof/occupant and event conflict. No real Coding DELETE was run and no
mTLS Control/Provider wire is enabled. Sandbox review may change this
candidate. The Coding v3 guard remains closed; Phase 6 remains **5/15**.

The follow-up Sandbox review
`S6-Coding-release-source-review-and-bounded-PG-CAS-gate-20261005` required
five corrections. The pre-delete observation now checks the full frozen
runtime configuration against the sealed completion proof while allowing a
config-matching exited runtime; a config drift causes zero DELETE. The
deletion client's serial admission and CloseContext use a cancellable gate,
with the five-second mutation budget starting before admission and no lock
held across network I/O. The PG final CAS compares the current terminate
deadline to the cleanup authority and accepts a later PG repair only if the
durable Released timestamp was formed inside the original authority window.
Historical Released evidence is fully checked on Open/reopen or a targeted
lookup/snapshot, not scanned on every unrelated ledger read. The 204 check
asserts only net/http-visible framing and empty body; the fake malformed-204
test is not raw-wire evidence. Two post-delete full inventories remain
necessary but do not establish arbitrary future daemon quiescence.

The same approved, single-container PostgreSQL-only final-CAS aggregate
ran once with `-race -shuffle=on -count=1` and passed on its first attempt
(shuffle seed `1791191549780953000`; test 3.81 s, package 5.569 s). Two
real PG clients competed for the same final release and exactly one won.
The aggregate also exercised a transaction-local higher-fence drift and
rollback, forced post-event rollback, short row-lock deadline and canceled
context, simulated lost-return readback, retention of the original create
Unknown, actual normal first-create of a new occupant in the freed slot with
old-proof rejection, and PG restart/readback. It used a synthetic Released
receipt as PG test input, not cross-process Control attestation. The exact
labeled PostgreSQL container and its anonymous volume were removed and a
separate read-only labeled inventory was empty. There was no actual COMMIT
packet loss, persisted competing higher-fence operation, real Coding Docker
deletion, physical absence attestation or complete 16-scenario Slice 6 gate.
The Coding v3 guard remains closed; Phase 6 remains **5/15**.

Sandbox then accepted the bounded PG-only final-release component as
`S6-Coding-PG-final-release-bounded-component-accepted-20261005`, not as a
cross-process or release gate. The test source and output bind the one real
PG run described above; there is no reason to recreate it for subsequent
Control-only corrections. The full untagged repository race/shuffle/count-one
run on the preceding Control source snapshot passed, including the existing
long security suite; `go vet ./...` and the Product Contract lock verifier
also passed. These results predate the following narrowly scoped Control
patch and are not presented as its full-repository validation.

That review identified four additional Control source boundaries. Pre-delete
GET admission now checks the mutable observer client only *after* obtaining
its serial gate, so a CloseContext winner cannot race a queued preflight
into a nil client. The configuration comparison first validates all three
realized volumes and at most one exact private `/tmp` tmpfs, then normalizes
only that optional tmpfs's presence and semantically irrelevant realized
mount order; the closed pre-delete projection remains in private evidence
except its non-authoritative diagnostic text, while configured mounts and
HostConfig.Tmpfs stay in the frozen digest. A
matching exited runtime may therefore be cleaned up whether Docker reports
the private tmpfs or omits it; an unknown, duplicated or mismatched mount
still reaches zero DELETE. The DELETE transport also checks visible
`Response.TransferEncoding` and explicit nonzero `Content-Length` headers,
without claiming raw-wire parsing. Finally, daemon `State.Error` text is
discarded before persistence because it can carry a host path; it never
serves as cleanup authority. These remain source/fake-daemon checks, not a
real Coding deletion or full Slice 6 acceptance. Coding v3 stays guarded
and Phase 6 remains **5/15**.

Sandbox accepted those four corrections under
`S6-Control-cleanup-four-source-boundaries-accepted-20261005`. The stable
post-correction repository snapshot passed `go test -race -shuffle=on
-count=1 ./...` (the security package took 340.317 seconds), `go vet
./...`, `go run ./cmd/verify-product-contract -source-root .`, `gofmt`
and `git diff --check`. The Product Contract verifier's tree digest was
`sha256:9490513228774da2e06cc3d01bc65192d37adea89d12d4ad83efdd6ce0f14560`;
this is not a claim that a separately named Provider Contract lock gate ran
for a later Provider API change. These full-suite results precede the new
retirement-barrier source below.

Sandbox decision
`S6-Provider-Control-v2-wire-and-retirement-barrier-reviewed-20261005`
keeps the fixed Slice 6 Step 2 open. A code audit found that the generic
`LifecycleRepository` could advance a Coding sandbox's fence/lease through
`ReserveMutation` while a separate Coding transaction held a durable
`Cleaning`/`Retirements` slot. That would not admit a new slot occupant, but
it could leave an already physically deleted effect with its final PG
release CAS rejected. The chosen correction checks protected lifecycle
writes against the retirement under the *same* PG singleton-row lock, even
for a separately constructed generic repository. Conflict is a temporary,
retryable 503 before acceptance, not a stale-fence fiction; exact replay,
reads and the same attempt's lawful Unknown report remain. No lock spans
network/Docker work. A higher fence first wins only if cleanup has not yet
committed; retirement first wins until trusted Released→final CAS. A new
supersession protocol or distributed abort service is out of scope.

The first source implementation adds that guard to generic PG lifecycle
mutations and maps its internal blocked sentinel to the existing Provider
503 error shape. Pure tests cover highwater, sandbox, lease, terminal
operation and event drift, exact replay, same-attempt Unknown and unrelated
sandbox work. This is not yet a real two-client PG barrier run or an active
Provider↔Control wire. Full Profile v2, authenticated typed wire, real Coding
physical create/cleanup and the fixed topology gate remain open. The v3
guard stays closed and Phase 6 remains **5/15**.

The adjacent source-only `internal/codingcontrolprotocol` candidate fixes
three repository-private Coding actions (`create`, `cleanup`, `status`) under
one exact version and scope. Canonical, bounded decoding rejects unknown or
duplicate members, cross-effect cleanup, wrong authenticated peer digest,
expired physical authorities and future-issued status keys. A historical
status read may use the original expired authority but cannot renew or
dispatch it. The closed response has only status, original authority/effect
digests, Control revision/state digest, completion/absence seals and capture
time; it has no Docker/container/volume IDs, paths or full private receipt.
`not_found` carries no absence proof. Pure protocol tests are not mTLS
identity/CRL evidence, a trusted client constructor, PG final CAS input or
an activated Control service. The full Profile v2 source and real process
gate remain missing, so Phase 6 remains **5/15**.

The pending state is explicit: `cleanup_pending` means the original create
proof and exact cleanup intent are durable, but absence is not yet
confirmed; a cleanup mutation cannot label the original create's plain
`completed` state as cleanup success. A malformed `Cleaning` reservation
whose `Retirements` binding is missing is corruption, not an unprotected
slot that a generic lifecycle writer may advance.

Sandbox review
`S6-retirement-barrier-corrections-and-bounded-PG-batch-reviewed-20261005`
accepted the source boundary and authorized one new, bounded PG-only batch.
The corrected guard validates finite/sorted/unique reservations, both sides
of the Cleaning/retirement binding, the canonical historical cleanup envelope,
and original/current operation, idempotency, sandbox, lease, tenant, network
and fence bindings. Generic lifecycle writes still use the same singleton
row lock. Historical create Unknown events use birth generation/fence; an
old birth fence below current highwater remains rejected by the pre-existing
State writer. Event time uses one explicit transaction clock with no hidden
allowance. The wire maps Completed plus durable cleanup intent to
`cleanup_pending`, rejects a Released timestamp outside the original cleanup
window, and requires an exact cleanup, current time and a later Control
revision/state for a read-side release observation. That observation does
not construct PG-trusted release evidence or attest an mTLS peer.

Sandbox accepted this bounded PG component under
`S6-retirement-barrier-bounded-PG-component-accepted-20261005`. The one
approved real PG run used the existing pinned, cached
`postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
single-container harness, two independent pools in the retirement-first path,
`--pull=never`, 512 MiB,
one CPU, 128 PIDs, loopback random port, the original three-minute parent
deadline and exact container/anonymous-volume cleanup. Command:
`SANDBOX_RUNTIME_PROVIDER_PROCESS_INTEGRATION=1 mise exec go@1.26.8 -- env -u GOROOT GOFLAGS= GOTOOLCHAIN=local go test -tags=integration -race -shuffle=on -count=1 -run '^TestProviderTransactionalStateIntegration$' -v ./provider/adapter/postgres`.
It passed once (seed `1791196881993510000`, test body 4.08 seconds, package
5.814 seconds). The test asserts retirement-first higher-fence/lease/terminal
rejection with unchanged PG row, independent consumed JTI/replay/highwater,
same-attempt replay and Unknown/event, unrelated sandbox mutation,
higher-fence-first rejection of an older cleanup permit through one pool,
restart retention,
final CAS preserving Unknown and an old proof unable to displace a new
occupant. The harness verified its exact container and anonymous volume absent;
a separate post-run label query found zero containers. Nil/wrong binding and
old birth-fence rejections are pure tests, not new two-client observations.
The two ordering checks are sequential committed states; this batch did not
add a simultaneous generic-mutation-versus-cleanup lock race. Existing
cleanuppermit/final-CAS tests provide their own two-client concurrency and
row-lock deadline checks. The synthetic Completed/Released receipts are not
authenticated Control attestations, and discard-return readback is not
actual COMMIT packet loss.
No Control mTLS/CRL edge, real Coding Docker operation, late-effect producer,
full Profile v2 or topology gate ran. Coding v3 remains guarded and Phase 6
remains **5/15**.

On the same post-PG source snapshot, the required all-package
`go test -race -shuffle=on -count=1 ./...` passed (the security package took
339.978 seconds), as did `go vet ./...`, `go run ./cmd/verify-contract
-source-root .`, `go run ./cmd/verify-product-contract -source-root .`,
`gofmt` for changed Go files and `git diff --check`. The Provider lock remains
at revision `720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`; the Product tree remains
`sha256:9490513228774da2e06cc3d01bc65192d37adea89d12d4ad83efdd6ce0f14560`.
These checks do not replace the missing authenticated Control or topology
gate, and they do not advance **5/15**.

After that full-suite snapshot, the read-side private Released observation
helper was narrowed to reject a zero Control revision floor or absent prior
state digest; this prevents an empty caller-provided floor from appearing
fresh. Its source and tests, `provider/adapter/postgres` and `providerapi`
passed `go test -race -shuffle=on -count=3` afterward. The earlier full-suite
result is not silently attributed to those later lines. Sandbox then ruled
under `S6-Control-authenticated-observation-layering-reviewed-20261005` that
the next production path must keep repository pre-read, actual mTLS/CRL
observation, application binding and PG row-locked CAS separate. A transport
client may not read PG, and a wire response may not manufacture the local
Control snapshot. That vertical source path is not yet implemented.

The current post-floor Go source was subsequently rerun with the full
required `go test -race -shuffle=on -count=1 ./...` and passed (security package
342.413 seconds); `go vet ./...` passed again. This supersedes the preceding
full-suite timing for the current source, without changing the component-only
claim or the **5/15** count.

### Atomic-original Coding PG component extension, 2026-10-05

Sandbox rulings `S6-original-create-envelope-atomic-persistence-reviewed-20261005`,
`S6-Coding-durable-authority-mode-marker-reviewed-20261005` and
`S6-atomic-original-PG-aggregate-batch-reviewed-20261005` authorized a new
source and one bounded real-PG component extension. A Coding-only marker
freezes `atomic-original-envelope` mode and Control policy before permits;
the first permit persists its exact canonical original authority in the same
PG transaction. Legacy first-create and local-snapshot cleanup/release reject
v3 mode, as does a legacy marker mixed with v3 originals. New typed PG
Completed/Released observation entries recheck marker, exact original,
retirement and lifecycle tuple under the singleton row lock. The v3
coordinator carries the original bytes to a focused dispatcher and refuses
old Driver lifecycle shortcuts. The Control ledger's status projection reads
receipt, revision and state digest under one lock. These are source/component
boundaries, not authenticated transport or a runnable v3 composition.

The first authorized PG attempt used source
`coding_atomic_original_integration_test.go` SHA256
`35e44b67a20503c4cd4d71d2d287608d1cb11c8ff3604d33c81e273f71f28d4a`.
The integration-tagged race/shuffle/count-one package exited 1 after a
4.23-second test body (4.955-second package), seed
`1791203173252292000`. Its retirement-first overlap fixture prepared a
new terminate from an older sandbox timestamp. Ordinary
`ReserveMutation` returned lifecycle conflict before the retirement guard;
the result did not prove the guard had run. Later release, reuse, restart and
damage cases therefore had not executed. The failure is retained, not
retroactively reported as a pass. The harness reported no exact cleanup
error; a post-run label query was empty and the Docker container/volume
counts matched the pre-run check.

Sandbox approved one fixture-repair supplement under
`S6-atomic-PG-fixture-repair-once-reviewed-20261005`. A pure State clone
test first proved that a lease-expiry change passes ordinary lifecycle
validation after cleanup but is rejected specifically by the retirement
barrier. The revised source SHA256 was
`92ca3bcc767015d656f5df12cd58c8b6c1f01670c43e90d0f572b30213cf36ac`.
The same `TestProviderTransactionalStateIntegration` with `-tags=integration
-race -shuffle=on -count=1` exited 0; the package took 6.293 seconds. Go's
successful output did not print its shuffle seed, so no seed is claimed.
The one cached pinned PostgreSQL container kept `--pull=never`, 512 MiB,
one CPU, 128 PIDs, a loopback random port, a three-minute parent context,
one-second Store operations and exact 30-second cleanup. The additional
database existed only inside this disposable container.

The successful run covers the rejected clean-check bootstrap with unchanged
documents/revision; zero-record v3 rejection by another legacy instance;
legacy local cleanup/release rejection; a canceled, visibly row-queued
first permit with no commit; one winning first permit across two pools and
exact original readback; wrong-policy read/mutation rejection; controlled
retirement-first row queues in both pools where only Begin commits and an
otherwise-valid lease update receives `ErrRetirementBlocked` without lease,
operation or fence drift; the inverse higher-fence-first queued commit where
the other pool's old cleanup receives no permit/retirement; typed PG
Completed→Released CAS supplied by an explicitly synthetic Observer; original
retention after release and slot reuse; PostgreSQL restart readback of both
historical and new-occupant originals; and rejection of another accepted
create after isolated missing-original or mixed-marker damage, with unchanged
row bytes/revision for each rejected attempt. The test's exact run-owned
container ID/name/label/anonymous-volume cleanup reported no error. After
the run, the label-filtered container list was empty, total containers were
zero, and total local volumes were 144, equal to pre-run. The run does not
simulate actual COMMIT-packet loss or a production Control peer.

Targeted five-package race/shuffle/count-three, tagged PG compilation,
`go vet ./...`, Provider/Product Contract locks and `git diff --check` passed
on the relevant source checkpoints. A full `go test -race -shuffle=on
-count=1 ./...` also exited 0 during this work, but the fixture and two
legacy pre-read checks changed after it began; that full-suite result is not
claimed for the final PG supplement snapshot. No Control mTLS/CRL process,
real Coding Docker deletion/absence, full Profile v2, fixed 16-scenario gate
or Slice 6 manifest followed. Coding v3 startup remains guarded; Phase 6
remains **5/15**.

### Profile-v2 inventory cross-check checkpoint, 2026-10-05

Sandbox confirmed an independent `ProfileV2` type, strict decoder/validator
and v2 digest domain; the frozen v1 `Profile` wire, digest and validator remain
unchanged. The current v2-only static identity fragment now rejects drift of
historical principal digests/authorization and missing or crossed historical
TLS delegation, in addition to its four new principals. It remains a
fragment, not a runnable Profile v2.

A new v2-only Coding slot subcheck intersects the two Coding UIDs/GIDs and
six whole-volume prefixes with all 82 provisional static identities and
Browser/Desktop workload/gateway slots. This exposed a real fixture gap:
isolated Coding template GIDs `58000/58001` collide with the existing
`gateway-postgres-tls-agent` and `product-migration-postgres-tls-agent` GIDs;
`57000` also collides with a historical TLS agent GID. The cross-inventory
test preserves those collisions as negatives and uses `57500/57501` only
for its positive fixture. These are not selected production IDs.

Conservative v2 resource arithmetic now counts all 80 non-template static
deployments (including every migration bundle, Control, scanner and agents),
every declared Browser/Desktop workload plus its gateway, both Coding
workloads, all five external services and a 128-MiB minimum double-parse
memory allowance. It requires the reviewed scanner cap of 4 GiB, 2 CPU and
64 PIDs, rejecting missing/surplus limits. This is source arithmetic, not
real cgroup, daemon/kernel, disk-quota or host-headroom evidence. The full
v2 document still must bind gateway/external limits and all authority fields
to one canonical digest and pass the live topology gate. The three focused
v2 tests passed `-race -shuffle=on -count=3`; no daemon was activated or
manifest produced. Coding v3 stays closed and Phase 6 stays **5/15**.

The follow-on source draft adds a separate `ProfileV2` Go type and
`DecodeV2`/`VerifyFileV2` entrypoints. They reject duplicate, unknown,
oversized, trailing and noncanonical JSON; v2 uses its own digest domain,
and cross-version decoding fails. A v2-only validator links the static
identity fragment, slot/resource subchecks, shared pure field checks and
fixed Control/Scanner scope checks. Focused synthetic boundary tests cover
the sole daemon socket owner, exact supplementary socket GID, three
Provider-Control networks and Coding-only scanner route/rules. The v1
canonical/digest golden test still passes. This is not a complete positive
Profile-v2 candidate: Control/Scanner command and image-source targets,
actual TLS/CRL composition, host-scope socket enforcement and final
source-to-binary image checks do not yet exist. A partial v2 document is
rejected; `ProfileV2.Validate` also retains an unconditional final admission
hold so a self-consistent draft cannot become runnable by accident.
`provider serve v3` remains fail-closed. The earlier full
repository race run passed before these v2 source files were added, so it
does not verify this later draft; targeted v2 race, vet, both Contract locks
and diff-check pass. No change to **5/15** follows.

Sandbox review `S6-ProfileV2-draft-fields-order-reviewed-20261005` found a
real draft omission: the two new TLS agents could otherwise inherit the
new-principal TCP listener allowance. Their v2-only field rule now requires
zero listeners and zero networks, leaving only the declared Unix signer and
controller sockets. Dedicated negative tests cover both. The v2 field chain
was split from the final admission hold solely for same-package testing. A
complete synthetic 82-static plus two-Coding-slot, four-private-network,
dedicated-TLS, receipt/rule-volume and resource-limit fixture passes that
unexported field chain. The identical canonical fixture remains rejected by
public `Validate`/`DecodeV2`. Self-consistent digest mutations at the field
layer reject wrong protocol/version, Control socket group/receipt/route,
scanner scope/rules/issuer, TLS-agent listener, identity and Coding slot
collisions, and resource omission/undercount. The aggregate focused
`-race -shuffle=on -count=3` run passed (79.252 seconds). All identities,
digests and rules in this fixture are test-only; this is neither a real
image/issuer nor permission to remove the production admission hold.

A subsequent package-private Control status HTTP server draft accepts only
TLS 1.3 with verified client certificates, an exact SPIFFE Provider URI,
bounded canonical Coding status POSTs and a concrete receipt-ledger
projection. Its test hook and projector are not exported; no production
constructor, client, Control OS process or v2 TLS/CRL factory is connected.
Focused race tests reject plaintext/header peer spoofing, unverified TLS,
missing handshake verification and loose listener/timeout/profile inputs.
Follow-on tests exercise the real ledger-locked bound read: a missing record
returns only `not_found`, while an ambiguously failed create remains
`unknown` with a sealed Control revision and never gains an absence claim.
Wrong peer/policy and write-action requests are rejected. A localhost TLS
1.3 mutual-certificate HTTP round trip confirms the bounded status route,
wrong content-type and write-action rejection. Its test-only verification
hook is not a production Profile-v2 CRL guard; there is still no positive
live fixed-source CRL exchange or source-bound Control command. The full
repository `go test -race -shuffle=on -count=1 ./...` exited 0 on the
earlier v2/status-server draft (security package 366.331 seconds); after
these follow-on status changes, focused `-race -shuffle=on -count=3` passed.
The v2/public startup holds remain closed and Phase 6 stays **5/15**.

Sandbox decision `S6-ProfileV2-CRL-typed-boundary-reviewed-20261005`
retains the old peer-CRL source/role wire and digest domains but requires
explicit Profile-v2 entry points. The new source-level required-set compiler
derives all ordinary role-owned mTLS directions, the fixed DNS exception and
nine PostgreSQL-purpose owner edges from one complete synthetic v2 field
graph. The resulting mapping must contain every required tuple exactly once;
unknown and missing tuples, wrong direction/anchor/principal, cross-profile
reuse and a broker-only DNS issuer assigned to Control/Scanner fail. It
derives Control's three inbound and Scanner's one Coding inbound role
documents and compiles a scalar-only exact tuple/purpose index. Strict
canonical decoders compare against independently supplied source/role
digests. Focused `-race -shuffle=on -count=3` passed for the mapping and
status transport; this does not demonstrate the controller/agent/role
independently loading and enforcing that mapping, actual issuer DER/CRL
freshness, or a live Vault-backed peer. All public v2 validation and
derivation still fail closed under `ProfileV2.Validate`; there is no Control
OS process or image-bound activation. Phase 6 remains **5/15**.

Sandbox then found the first synthetic v2 CRL source fixture had invented a
third PostgreSQL issuer/mount and mapped all non-PostgreSQL edges to a generic
source. Its passing tests established tuple enumeration only, not the
approved two-issuer partition; this is retained as a failed review finding,
not accepted component evidence. The corrected field validator now requires
exactly two distinct issuer UUIDs and DER digests from the existing `/pki`
mount. The broker source must match the Profile's DNS broker-client CA, and
each mapping selects the broker source only when the *verified peer* is one
of the five fixed egress brokers; all other peers, including Control,
Scanner, PostgreSQL and the DNS server, select the general source. The
synthetic positive uses only those two sources. Recomputed-digest negatives
cover omitted broker source, a used third PostgreSQL issuer, broker/general
edge swaps, broker UUID/DER drift and coincident issuers. The isolated v2
mapping test passed `-race -shuffle=on -count=3` after correction. This is
still pure source validation, not controller policy/Vault enforcement or a
live CRL handshake; public v2 admission remains closed and **5/15** holds.
The affected synthetic Profile/CRL and certificate-controller issuer-policy
tests passed focused race/shuffle/count-three checks. A separate, parallel
whole-`internal/phase6security` count-three run hit Go's default ten-minute
test timeout inside the existing large evidence-validation test; it is not a
passing full-package result or evidence against that test's semantics. The
required final whole-repository `go test -race -shuffle=on -count=1 ./...`
then exited 0 without another concurrent heavy security-package run
(`internal/phase6security`: 383.709 seconds). Final `go vet ./...`, both
Provider/Product Contract locks and `git diff --check` also passed. These
are source-quality checks only, not the live Slice 6 release gate.

### Interim old-to-new-computer source checkpoint, 2026-10-05

The operator requested a machine change after the two-issuer correction
naturally finished. This is a reviewed source checkpoint, not a new Slice 6
acceptance result. Sandbox identifier
`S6-ProfileV2-CRL-two-issuer-correction-reviewed-20261005` accepted only the
corrected component boundary: exact existing `/pki` broker/general sources,
selection by verified peer, PostgreSQL on general. The earlier invented
third-issuer fixture is a failed review finding. The final corrected source
passed the required whole-repository race/shuffle/count-one test, vet, both
Contract locks and diff check. Focused affected v2 CRL/Profile, status
transport and certificate-controller issuer-policy count-three runs passed;
the concurrently attempted entire security package count-three timed out
at Go's default ten minutes in a pre-existing large evidence-validation
test. Do not report that timeout as a passing three-run suite. No source
behavior changed after the final count-one run; the subsequent checkpoint
edits are documentation and Git handoff only.

The fixed step ledger remains: step 1 bounded Guest E component accepted;
step 2 live startup edges still open; step 3 must freeze the revised complete
Profile-v2 source inventory (including Control/Scanner, dedicated agents,
bounded dynamic Coding allocations and peak resources), then run the
original 16 scenarios in one fresh gate with strict evidence review; formal
step 4 post-gate handoff is not yet reached. The historical 78-deployment
baseline and provisional 82-static Profile-v2 fixture are neither the final
revised live inventory nor release evidence. Public Profile-v2
validation and v3 admission remain held closed. There is no live Controller/
agent v2 CRL enforcement, Control/Scanner OS process or image, physical
Coding deletion/absence gate, release manifest or production readiness.

The accepted bounded Guest E run ID is
`550dba360065dce4f46fa14476225ce5` with clean E
`a065277e406bf09c4c22d4ce187e1d181e513316` and clean R/F
`e5816d0d3de0541bd9a677560096b3527f58f7b9`. Its 119-file private
root `~/.codex/phase6-slice6-run-evidence-Efix.GTGjew/<run-id>/` is 0700;
final binding SHA256 is
`e66dc29a217c82e1ae9071b8046c33461afae8d216e488751c9a68e312549177`.
The separate 0600 gate log under
`~/.codex/phase6-slice6-run-Efix.CQdy6i/` has SHA256
`44d2d3337d5893eba37db2658a0e3c366d92c8aa07e6eb660fc66fe208c2c084`.
Old-host Docker container/network/volume lists filtered by this exact run
label were all empty at checkpoint. The three Coding private receipt hashes
and local OCI candidate/rebuild inventory are in the handoff plan; none of
these files or the ignored `e2e/evidence/` directory is carried by Git.
Preserve private observations with verified digest and restrictive access;
do not put their contents or credentials in a source commit.

## 2026-10-08 new-host typed v2 CRL component checkpoint

The new-host source baseline was restored from the verified migration bundle
at `91fe315641779e6ea640632538309d63ad1b303f`, on
`codex/product-v1-phase-6-hardening`. The user explicitly confirmed that the
old host and other sessions have stopped writing, old automation will not
resume writes, and this session owns new-host implementation with a separate
read-only reviewer. Historical idle/paused records were not used as proof of
that current arrangement. This is an uncommitted component checkpoint, not
Slice 6 step 4 or a replacement for the private restoration report.

The source additions freeze typed Profile-v2/source inputs before compiling
their exact CRL authorization index. A separate PostgreSQL-purpose role
derivation, canonical decoder and verifier bind one owner to one outbound
edge and require independently pinned mapping/role digests. Ordinary role
documents cannot acquire those edges. All nine synthetic PostgreSQL owners
continue to select the existing general issuer; there is no third issuer.

The Controller now stores a version-independent scalar/index binding for
peer-CRL enablement, request profile checks and policy-selected revocation
reads. The explicit v2 constructor and pure startup preflight require the
complete policy set, exact principals and request-key digests, Vault roles,
URI/DNS/usages/TTL, peer UID/GID, PostgreSQL identity tuples, both controller
self policies and the reviewed broker/general partition before authority or
ledger work. Control/Scanner TLS delegation now includes only their two
fixed agent-to-subject pairs; the unchanged v1 registry still rejects them.
The agent and consuming-role guard have explicit v2 constructors and reuse
the existing signed-response, issuer-DER, freshness, bootstrap, handshake,
poll and drain machinery.

Every public v2 entry still calls the held `ProfileV2.Validate`; no exported
field-only admission or v1 projection was introduced. Positive field and
runtime tests use package-private fixtures. The PostgreSQL guard is a
low-level component: production composition must still bind its dedicated
signer socket, process UID/GID and supplementary groups. The Controller
command must run the pure policy preflight before reading signing FDs or
contacting credential/Vault services, then retain its command-specific
key-ID, private-file, listener and process checks.

An independent read-only `implementation_agent` reviewed the component
patch and its follow-up corrections, with no blocking finding in this
scope. It required a complete valid PostgreSQL identity in the new
Control/Scanner cross-purpose rejection test; that correction is included.
A further entry-point review identified that the legacy Controller could
otherwise accept those newly valid v2 policies without a Profile-v2. Both
roles reproduced that downgrade before the fix. The legacy constructor now
rejects their subject kinds or dedicated agent requester names before
authority/ledger access; only the explicit held v2 constructor reaches the
private shared construction path. The reviewer did not execute tests or
approve command/live admission.

New-host validation is recorded separately from old-host evidence. The
initial Control/Scanner delegation regression reproduced rejection before
the fixed pairs were added. The first four-package run passed three packages
and failed one new test whose ordinary-role fixture selected a subject with
no ordinary peer edge; selecting the explicit Control subject fixed it.
The focused race/shuffle/count-one rerun passed. The first whole-repository
run inherited the evidence writer's `umask 077`, so existing tests requesting
insecure `0644` fixtures instead created secure `0600` files. The affected
witness test passes under the host's normal `022` test-process mask. Raw
failed logs remain retained outside Git; evidence files retain `0600`.
`go vet ./...` and both Contract lock verifiers passed on the corrected
source. Both tagged distinct-UID Docker checks were actually invoked and
failed their pinned-image availability preflight, before creating containers
or volumes. Their fixture image is not restored; no Docker scenario pass
or inherited old-image acceptance is claimed. The final whole-repository
`go test -race -shuffle=on -count=1 ./...` run under the normal test-process
mask passed on Go 1.26.8 darwin/arm64 in 439.779 seconds, with no timeout
extension. The final reviewed Go sources were hashed before this run and
remained unchanged. `go vet ./...` passed in 13.486 seconds; both Contract
locks passed. The Controller package also passed race/shuffle/count-one
after the legacy-entry downgrade repair. None of these is a Docker, live
Vault, original Guest receipt replay or formal Slice 6 acceptance result.
The exact fixture registry index was subsequently readable and listed its
Linux arm64/v8 manifest. This read-only lookup did not download/load an
image, execute supply/signature/provenance/vulnerability gates or establish
private-registry/Vault credentials.

The fixed four-step state remains: (1) historical bounded Guest E evidence
accepted only within its original scope and preserved without replay;
(2) startup/security audit in progress, now including this component source
checkpoint; (3) revised complete live Profile-v2 inventory and the original
16-scenario independently reviewed gate not complete; (4) formal
post-acceptance documentation/commit/push handoff not reached. Phase 6 stays
**5/15**. Next is actual v2 command/role composition, including Controller
preflight ordering, dedicated signer/process checks and Control/Scanner
source-bound commands/images, followed by the remaining real security edges.
Neither a local image metadata directory nor the provisional 82-static
fixture supplies those inputs or proves live admission.

## 2026-10-08 v2 Controller and TLS-agent command preflight

The follow-up uncommitted checkpoint connects typed v2 admission to the real
`certificate-controller` and `workload-tls-agent` command `run` paths.
Controller config v5 selects Profile-v2; agent v5 is ordinary TLS and agent
v6 is the dedicated PostgreSQL purpose. Unknown versions, purpose mixing,
missing source pins and v2 failure cannot select a legacy constructor.
Existing Controller v3/v4 and agent v2/v3/v4 keep their Profile-v1 and purpose
semantics. The agent's wrong-process-identity diagnostic now follows its
read-only Profile check; UID/GID and supplementary groups still must match
before private FD reads or service work.

The public typed accessors and private config/ledger validators call the
held `ProfileV2.Validate`. Shared package-private field lookups do not
project v2 through Profile-v1. The four new role/agent config volumes have
closed file purposes, exact deployment storage IDs, read-only declarations
and bounded bytes. The Control receipt ledger additionally rejects same,
parent/child path and storage aliases across every mount kind. Positive
field tests use the complete synthetic draft; this remains neither a live
inventory nor actual file/mount permission evidence.

Controller preflight now checks complete policy and listener coverage,
request-key IDs/digests, principal instances, process identity, socket peers,
Vault endpoint/anchors, source pins, finite broker/general issuer groups and
bounded timings/concurrency before inherited key reads. V5 fixes the Vault
mount to `pki`. TLS-agent preflight binds its exact ordinary or PostgreSQL
signer, sources and policy before FD3. Actual inherited private keys must
still match the pinned public identities after reading. The existing
bootstrap, client, manager, listener and drain paths remain composed behind
these checks; no new issuer, public Contract or admission bypass is added.

The first focused command test failed because an old pure-comparison fixture
left listener `MaxConnections` at zero. The real listener already rejected
that value; the check now runs earlier. The fixture now supplies eight, and
zero/257 rejection tests preserve the boundary. The focused corrected
race/shuffle/count-one command tests passed. Separate-process tests execute
the real commands with inherited files and verify Controller FD3–FD6 and
agent FD3 offsets stay zero on the constructed draft rejection. These tests
use intentionally incomplete v2 documents, so they establish that refusal
path, not successful full-v2 startup. Complete synthetic field-positive and
public-hold tests remain in the security package.

Independent read-only implementation-agent review found no blocking issue
in this command checkpoint. It explicitly bounded the FD tests as above and
did not run tests or approve live admission. The final new-host combination
passed `go test -race -shuffle=on -count=1 ./...` in 437.982 seconds and
`go vet ./...` in 2.006 seconds, plus both Provider and Product Contract lock
verifiers, on Go 1.26.8 darwin/arm64. No test timeout was extended. The 37
changed Go files matched the pre-run hash inventory throughout validation;
subsequent edits only record these results in documentation. Full logs,
source hashes, the earlier fixture failure and review notes are retained
outside the repository and migration package in the private continuation
report. These passes do not replace the blocked Docker or live gates.

Slice 6 retains its fixed order: (1) original bounded Guest E acceptance is
unchanged and not replayed; (2) startup/security audit is in progress, with
this command component closed; (3) complete live v2 inventory, original
16 scenarios and independent formal acceptance remain incomplete; (4)
post-acceptance document/commit/push handoff is not reached. Phase 6 remains
**5/15**, with no commit or push in this checkpoint. Actual Control/Scanner
business commands, Provider-side operations and consuming-role TLS/CRL
composition are next. Their fresh source-bound images and real Docker/Vault,
network/UID/GID/permission, failure/unknown-outcome and Guest
peer-revoke/CRL-loss/replacement evidence remain outstanding. The previously
missing pinned Docker fixture has not been restored, and the blocked tagged
gates have not been re-run merely to restate that unchanged condition.

## 2026-10-09 Control status and Scanner command components

This uncommitted new-host continuation remains based on full HEAD
`91fe315641779e6ea640632538309d63ad1b303f` on
`codex/product-v1-phase-6-hardening`. The confirmed root writer owns code;
the implementation agent reviewed read-only. Original migration bytes,
historical receipts and optional-artifact declarations remain untouched.

The two new command entry points consume bounded canonical stdin and perform
typed Profile-v2/private-file/pinned-role preflight. `provider-docker-control`
selects only `sandbox-runtime.provider-docker-control-status-config.v1`:
existing Coding receipt ledger, exact immutable binding/template, mTLS
Provider identity, source-bound CRL and bounded coding listener. No namespace
initialization, Docker mutation, Browser/Desktop route or old-authority
redispatch exists in that command. Its status projector previously bypassed
the shared cleanup-intent check. A regression first reproduced acceptance
of an Unknown receipt without the requested cleanup intent; the final
projector reuses `ProjectLedgerStatus` and rejects it. Not-found remains an
observation, never physical absence or permission to release a PG slot.
`NewStatusObserverV2` supplies the typed Coordinator's status port with exact
address, Provider/profile/policy pins and pre/post-response peer checks.
Actual PG/Coordinator/Provider-v3 selection and physical Control execution
remain unimplemented continuation work.

`provider-artifact-scanner` selects
`sandbox-runtime.provider-artifact-scanner-config.v1`. It binds the actual
fixed engine config to Profile-pinned canonical rule-manifest bytes, checks
rules before and after child startup, fixes the absolute ClamD executable
and arguments, and supervises one child without automatic respawn. Runtime
config/socket/scratch have one fixed 256 MiB private tmpfs declaration; the
actual directory must have the Scanner UID/GID and mode 0700. The 4 GiB,
2 CPU, 64 PID and one-operation envelopes are unchanged. The consuming-role
TLS factories enforce scoped numeric edges, exact delegated signer and
process identity/groups, source/role pins, real trust anchors, peer tracking
and bounded connection lifetimes. Control alone retains its reviewed extra
GID 0. Scanner/Provider accept no extra supplementary groups. The dedicated
remote scanner factory owns peer polling and propagates Provider lifetime
cancellation into active HTTP scans; Close is idempotent.

Rule-manifest bytes are defensively copied and rechecked against the full
Profile digest binding; every verification rehashes actual rule files and
checks the 72-hour trusted-check window and latched clock rollback. A manifest
cannot bless altered bytes/timestamps, engine input or config. Its exact
versions are snapshot constraints, not cross-Profile anti-rollback. PING,
rule hashing and a supply-input digest do not prove official signatures,
current rules, actual loaded rules or the final composite image's source.
Those claims still require independent operator/supply/cold-start evidence.

Subprocess component tests cover the fixed config write, successful private
socket PING, early exit, cancellation, child reaping, refusal of existing
config/socket or unsafe directory, and preserving replaced files. Readiness
requires the same captured socket inode/owner/mode before and after PING.
If a child creates a socket and exits before the first observation, there is
no inode ownership receipt: that unknown path is preserved and blocks the
next startup. This failure is not reported as zero-resource cleanup; recovery
must use a fresh run-owned tmpfs or independently authorized exact cleanup.
The subprocess is a test double, not ClamD evidence. Separate real mTLS
component tests show Provider-lifetime cancellation aborting an active scan.
New command refusal tests use invalid draft Profiles, so they prove that
early refusal path, not successful complete-profile startup. Complete
synthetic field-positive/public-hold tests stay in `phase6security`.

Independent read-only review found no confirmed blocker within these held
component boundaries, including the 256 MiB scratch refinement. It prompted
the socket inode/readiness repair and explicit early-socket-exit test and did
not run tests or approve live admission.

The first whole-repository race/shuffle/count-one run completed in 551.621
seconds with two failures in the unchanged `cmd` migration pool fixture.
The same two cases failed when isolated. That file's Git object was exactly
the baseline `80259fed1d1ed4e9aacd0f027e004657a977eb7e`: the fixture replaced
`DialFunc` but still asked host DNS to resolve a `.test` name before dialing.
Locked pgx 5.9.2 resolves in `buildConnectOneConfigs` before `connectOne` calls
the dial hook. The independently reviewed repair changes only the test
fixture: resolve the one expected hostname to loopback, assert the exact
TCP dial target and register pool cleanup even on an early fatal assertion.
Production diagnostics, timeout values and cancellation/classification
assertions are unchanged. Corrected migration tests passed under race and
shuffle. The original red runs remain in the external private evidence.

The first final-source run passed vet, both Provider/Product Contract locks,
and Linux/arm64 compilation of the two new commands. Its source inventory
contained 1,965 Go/module files, unchanged for that run. The only subsequent
Go change is the migration `_test.go` repair; the unaffected Contract and
production binary input evidence is retained. The actual opt-in pinned
ClamAV integration failed at image preflight because local index
`sha256:6d0680780fd29855cb7018f68272cb520821f614259e2066f8ec669069ac91b3`
is absent. It started no container and did not run the engine. Cross-builds
are not candidate images, image supply verification or positive command
startup. The final repaired snapshot passed
`go test -race -shuffle=on -count=1 ./...` in **625.296 seconds** and
`go vet ./...` in **1.112 seconds** on Go 1.26.8 darwin/arm64. No test timeout
was extended. Its 1,965 Go/module hashes stayed identical before and after
validation; all 59 cumulative changed Go files pass `gofmt` verification.
Subsequent changes only record results in documentation. Original main stays
clean, and the continuation HEAD, upstream and live remote branch all remain
`91fe315641779e6ea640632538309d63ad1b303f`. Full original failures, final logs,
source inventories, cross-build metadata and independent review notes remain
outside Git and the migration package in the private continuation report.

The four-step state is unchanged: **1** historical bounded Guest E is accepted
only in its original scope; **2** startup/security audit remains in progress
with this source checkpoint; **3** the complete revised live Profile-v2
inventory, original 16 scenarios and independent formal acceptance remain
incomplete; **4** formal post-acceptance documentation/commit/push is not
reached. No public ProfileV2 or Provider serve v3 hold is removed. Phase 6
stays **5/15**. Remaining work includes full Control create/cleanup and
Browser/Desktop scopes, real Provider/PG/Coordinator/scanner composition,
source-bound role images and correct current rules, Provider Browser
failure/uncertain outcomes, the three isolated Provider commands, actual
network/UID/GID/mount/resource enforcement, Guest peer revoke/CRL loss and
replacement, then the original same-run gate. Existing role-image packaging
still does not include these new commands; no candidate image was built or
old evidence relabelled. No commit, push, publication or deployment occurred.


## 2026-10-09 held Provider v3 dependency composition

This continues step 2 on the restored uncommitted checkpoint at handoff
commit `91fe315641779e6ea640632538309d63ad1b303f`. The actual `provider serve`
Coding-v3 selection now enters a separate typed-v2 function. Its existing
serve hold still refuses before reading profile/materials or opening PG and
private clients; `ProfileV2.Validate` independently stays closed. The legacy
Coding material entry rejects v3, and the v1 Docker/command-scanner route
cannot be reached by this selection.

The held candidate preflight binds the private Profile/ordinary-role/PG-role
paths, exact PG owner, database, role and dedicated signer, canonical bounded
receipt binding, frozen template/plan/owner, and exact Control/Scanner edges.
`coding.private_services` is Coding-v3-only and rejects legacy runtime
configuration overrides. It is private startup input, not a Provider DTO or
an authorization to initialize/re-sign old evidence. PG/material constructors
use typed v2 entry points and share only private admitted-field/runtime
primitives with v1. The complete field checker now also closes the existing
nine PG networks and fixed external identity/edges/HBA recipe. It does not
add a tenth owner or third issuer; PG remains on general. Independent
ordinary and PG mapping/role pins stay distinct.

The candidate opens a bound PG pool with peer and own-leaf guards, verifies
runtime SQL role and schema, constructs the policy-bound Coding repository,
then the production typed status Observer, Coordinator and private Scanner
plus passive JSON checker. It creates no lifecycle Application, which would
start a mutation-producing lease sweep. No automatic Begin/Finish call,
namespace initialization, recovery mutation or fallback Docker driver is
registered. Partial startup cancels/closes the private clients; shutdown is
idempotent. The final command still explicitly rejects serving without the
physical mutation executor and daemon-free runtime ports.

Synthetic field-positive tests cover the nine owner/source/role tuples and
reject CIDR/routing/extra-network/extra-edge/broker/service/HBA/SQL-role drift,
even with a recomputed enclosing digest. Command/config tests cover canonical
original-binding inputs, owner/profile/plan/spec mismatch, held selection,
no v1 material fallback and rejection before material resolution. These are
component and refusal tests; neither the public v2 factories nor the entire
PG/Control/Scanner candidate can have a positive live test while held. The
first new PG field test exposed an overly broad rejection of the separate
action-history PostgreSQL service; the check was restricted to the shared
`postgres` service, preserving that independent authority. The original red
log and corrected focused run are retained outside Git/migration materials.

Independent read-only review found no blocker in this held candidate scope;
it did not execute tests or authorize public admission. The final source
passed `go test -race -shuffle=on -count=1 ./...` in **496.298 seconds**,
`go vet ./...` in **2.438 seconds**, both Provider/Product Contract locks,
and Linux/arm64 core cross-compilation on the restored Go 1.26.8 toolchain.
All 1,972 inventoried Go/module file hashes stayed unchanged throughout the
run; all 75 cumulative changed Go files pass `gofmt`. No timeout was extended.
The opt-in `TestRealSharedPostgresNineSourceHBA` failed at its pinned-image
preflight. Docker `desktop-linux` was reachable as Linux/aarch64, but local
`postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
was absent. The test created no network, volume or container and did not
execute HBA/PG scenarios; that real component gate remains blocked by its
input. Cross-compilation is not a role image or supply-chain acceptance.
No other unchanged image-dependent batch was rerun. Full logs, source hashes,
red/corrected focused runs, review and binary metadata are retained privately
outside Git and the migration package. Only documentation changed after this
final Go validation.
The four-step status remains: **1** original bounded Guest E only; **2** this
startup/security continuation is in progress; **3** revised live inventory,
original 16 scenarios and independent formal acceptance are incomplete;
**4** post-acceptance handoff is not reached. Phase 6 remains **5/15**. No
commit, push, publication, image build or deployment is performed.

## 2026-10-09 held Coding Control executor

This continues the uncommitted restored checkpoint at
`91fe315641779e6ea640632538309d63ad1b303f`. The Control command has an explicit
`sandbox-runtime.provider-docker-control-coding-config.v2` input carrying
bounded raw OCI descriptor and seccomp bytes. Its existing status-only input
remains read-only. The concrete executor uses only the Profile's Unix path
and the unchanged original ledger binding. It does not initialize state,
recompute daemon identity, pull/build images, accept caller Docker options,
or expose Browser/Desktop mutation scope. Profile-v2 and Provider serve v3
public holds remain closed before effects; positive live factory composition
cannot be claimed from private component tests.

Source verification precedes startup and per-effect planning. Creation
persists Unknown before any physical work, checks the live supplied image,
original daemon and exact namespace, then consumes eight fixed write
requests. The separate GET-only observer checks the prep container, actual
empty volume roots, carrier removal and runtime policy before Start. Only
an unambiguous same-process create may enter full sealed completion. The
normal cleanup route reads the sealed runtime identity and reuses the
existing exact pre-delete configuration check, durable intent, single-use
deletion and Released evidence path. Historical Unknown remains occupied;
neither a timeout nor missing objects authorizes retry or cleanup.

The stateful fake daemon applies each write independently of response
success. Tests lose the response at each of the eight steps and verify
durable Unknown, no retry and no supplementary completion. Other tests
cover missing images before the first write, incorrect root ownership before
prep deletion, privileged runtime drift before Start, original request
replay, Unknown cleanup denial, invalid response framing, exact source bytes,
frozen create-body privileges/resources and explicit config-mode isolation.
These are component tests, not a real daemon or new operator-signed result.

At this checkpoint `desktop-linux` resolves to the new host's Docker socket,
but that socket is absent. The read-only integration and image availability
checks therefore cannot establish a current live daemon/image state. The
previous checkpoint's missing-image result is historical, not a fresh image
inventory. No old one-shot create/cleanup probe authorization is reused.
Real creation/cleanup, the original 30-second authority-window performance,
role images and same-run security scenarios remain unverified.

The four-step status remains: **1** bounded historical Guest E only; **2**
startup/security work in progress with this candidate; **3** revised full
live inventory, original 16 scenarios and independent formal acceptance
incomplete; **4** post-acceptance handoff not reached. Phase 6 stays **5/15**.
Next implement the daemon-free Provider create/cleanup dispatch and remaining
lifecycle/exec/terminal/artifact ports, retaining both holds, then supply the
correct inputs for real gates. No commit, push, publication or deployment
is performed.

Independent read-only review found ambiguous volume-create JSON handling:
Go could fold `Name`/`name` aliases and duplicate nested label keys before
ownership checks. Both counterexamples failed in a new test before the fix.
The write path now checks the exact API-1.55 local-volume field grammar and
types before decoding: aliases, unknown fields, duplicate labels and nonempty
options are rejected. Each rejected response permanently consumes that write
capability. The reviewer confirmed this blocker closed and found no further
clear safety defect in the reviewed source scope. The reviewer did not run
tests or Docker. Original red logs and the pre-fix full check, deliberately
interrupted with SIGINT after the finding, remain separately retained and
are not counted as passing evidence.

The repaired combined source passed
`go test -race -shuffle=on -count=1 ./...` in **582.811 seconds**,
`go vet ./...` in **2.433 seconds**, both Provider/Product Contract locks,
and Linux/arm64 Control cross-compilation. No timeout was extended. All
1,975 Go/root-module files selected by this run's inventory stayed identical
before and after checks; the two nested E2E module files outside that
selector remain present and byte-identical to the previous verified
checkpoint. All 82 cumulative changed Go files pass `gofmt`. Subsequent
changes only record these outcomes in documentation and private reports.

The tagged read-only daemon Info/empty-namespace integration failed in
**2.154 seconds** because the Docker socket was unavailable; the separate
locked-image inspect also failed to connect. Neither result is a pass,
an image-absence proof, a physical mutation run or a release gate. No new
container, volume or network was created. The cross-built binary remains a
dirty-source build artifact, not a role image or supply/signature acceptance.
Full logs, source inventories, original failures, reviewer notes and build
metadata are retained outside Git and the migration package. Original main
remains clean; working HEAD, upstream and live remote still equal the full
handoff SHA above. No commit or push is performed.

## 2026-10-09 held Provider original-authority dispatch

This continuation starts from the restored branch and full handoff HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, preserving the previous uncommitted
source and all migration evidence. The user-confirmed single-writer and
independent read-only reviewer arrangement remains in force. No old machine
automation or one-shot operator authorization is resumed.

The candidate now connects the existing atomic PG first-create permit to a
dedicated typed Control client. Cleanup uses Completed observation and the
existing PG row-lock admission, then sends only the exact original create
and fresh cleanup returned by that same successful call. There is no extra
post-commit read that could lose the sole fresh dispatch opportunity. A PG
error/uncertain commit or cancelled call cannot send; a lost mutation reply
cannot retry. Historical ReadFinishBinding remains an observation hint,
never a renewal or second permit. The existing Finish path separately checks
Released and revalidates the current PG tuple before slot release.

The private transport shares the source-bound TLS/CRL factory. It bounds the
request by caller context, original expiry and configured timeout, checks
the peer before/after exchange and rejects redirects, replay, compression,
truncation, chunked framing, noncanonical JSON and mismatched receipt tuples.
The server writes an explicit exact response length. Create acknowledgement
also checks receipt time against the original authorization window. Neither
ACK publishes Ready or releases PG state. Command composition selects both
coordinators without a lifecycle Application, lease sweep or legacy daemon
driver. Public Profile-v2 and Provider serve v3 remain closed before effects.

Component tests send exact canonical original envelopes through loopback
TLS 1.3 mutual certificates. They cover lost replies, redirects, wrong
action/effect, pending status, future receipt, truncation, chunked/gzip
response, duplicate fields, pre/post peer-check failure, cancellation and
expired/crossed authority. Separate coordinator tests cover one same-call
send, no historical retry, uncertain commit, cancellation after commit and
wrong cleanup binding. Loopback peer monitors are test fakes; these are not
positive Profile-v2, production CRL, real PG/Docker or operator-signed gates.

Independent read-only review found no blocker in the final eight Go files.
It also identified the required next boundary: atomic Completed-to-Active/
Ready needs durable Control evidence plus a generic PG writer guard. Merely
adding an Active binding would leave a generic lifecycle Ready bypass and
could break the existing Creating-to-Active-to-Cleaning transaction. The next
section must test these together while preserving normal termination and
historical OutcomeUnknown. No readiness implementation, new private state
field or migration is claimed by this dispatch checkpoint.

Slice 6 status: **1** bounded historical Guest E only; **2** startup/security
in progress, with original-authority dispatch source added; **3** complete
live v2 inventory, original 16 scenarios and independent formal acceptance
incomplete; **4** post-acceptance handoff not reached. Phase 6 remains **5/15**.
Remaining work includes the Ready CAS, remaining runtime ports, Provider
Browser failure/uncertainty, the three isolated Provider commands, network/
UID/GID/permissions and Guest peer-revoke/CRL-loss/replacement scenarios.
No commit, push, merge, deployment or artifact publication is performed.

The final combined source passed
`go test -race -shuffle=on -count=1 ./...` in **535.336 seconds**,
`go vet ./...` in **2.157 seconds**, both Provider/Product Contract locks,
and Linux/arm64 core compilation in **17.979 seconds**. No timeout was
extended. All **1,980** inventoried Go files and root/nested module files
stayed unchanged during validation. The final eight changed Go file hashes
match the independent review; all 87 cumulative changed Go files pass
`gofmt`. Later changes record outcomes only in documentation/private reports.

The tagged read-only Docker integration failed in **1.605 seconds**, and
the real Provider PG transactional integration failed in **1.933 seconds**,
because the configured Docker Unix socket does not exist. The PG harness
could not start its container; its cleanup identification also failed to
connect to the same absent socket. These are failed/blocked integration
attempts, not skips, passes or evidence of current image availability. No
old one-shot physical probe, image pull/rebuild, live CRL scenario or new
operator-signed acceptance is claimed. The compiled binary remains a
dirty-source build artifact, not a supplied/signed role image. Full logs,
source inventories, review hashes and the next Ready-CAS checklist are
preserved outside Git and the migration package.


## 2026-10-09 held Provider Completed-to-Ready CAS

This continuation retains the restored branch and full handoff HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, previous uncommitted work, private
migration evidence and the user-confirmed single-writer arrangement. No old
automation or one-shot operator authority is resumed. The implementation
scope is create readiness and its shared PG writer boundary, not formal
Slice 6 acceptance.

The held v3 command now composes a read/commit-only create coordinator with
the existing source-bound Control client. Only authenticated Completed for
the exact original effect can reach the typed PG entry. The transaction
revalidates original authority, frozen spec, current generation/fence/lease
and absence of successor operations. Under the existing single row lock it
records allocation-keyed Control revision/state/completion/evidence/time,
changes Creating to Active and Provisioning to Ready, and persists the
operation/idempotency/events. A repeated identical read aborts before SQL
UPDATE, so it does not increment the PG revision. No acknowledgement is
substituted for this observation and no expired mutation is redispatched.

An on-time Running operation succeeds; late or cancelled Running becomes
OutcomeUnknown while Ready is recorded. Existing Unknown remains unchanged.
The completion map retains history after release and slot reuse; it cannot
be rebound to the next allocation. Generic writes are checked against a
reconstructed full sandbox projection. They cannot manufacture Ready,
successful creation, bare lease replacement, termination progress or forged
events. Exact normal terminate/Active lease admissions remain possible;
lease-expired additionally verifies the stored lease really expired and the
complete deterministic expiry request. Non-create v3 reconciliation still
returns its explicit hold, so lease admission is not completed execution.
The existing direct Creating-to-Cleaning transaction remains valid without
claiming Ready; cleanup following Ready must preserve its proof binding.

Independent read-only implementation-agent review identified generic bare
termination and side-write/event bypasses during development. The retained
red tests reproduce bare termination and nonstandard event acceptance.
The fixed guard compares sandbox, lease, fence, all related operations,
idempotency and events, including released history. It requires standard
event IDs/digests and shares the existing lease-expiry request derivation
without changing its five-minute internal deadline. Final review found no
remaining definite blocker across the 17 changed Go files and independently
matched their hashes. The reviewer did not edit files or execute tests.

Focused race/shuffle/count-one checks of identity, lifecycle, PG and command
packages passed in **7.150 seconds**. Tagged PG tests compiled in **2.223
seconds**; that command ran no tests. New component cases cover deadline/
cancellation, historical Unknown, stale or mismatched proof, generic writer
bypasses, terminate-first/Ready-first ordering, release and slot reuse. The
existing real-PG harness now includes two independent connections racing
Ready and exact-repeat revision checks, then continues its cleanup/restart/
reuse path. Its Control observer is synthetic even when PG is real; it
cannot establish production CRL or physical execution evidence. Earlier
fixture failures and red reproductions remain separately retained.

The final combined source passed
`go test -race -shuffle=on -count=1 ./...` in **514.886 seconds**,
`go vet ./...` in **5.218 seconds**, both Provider/Product Contract locks,
and Linux/arm64 core compilation in **6.185 seconds**. No timeout was
extended. All **1,987** inventoried Go files and root/nested module files
remained unchanged throughout validation; the 17 reviewed hashes match that
snapshot. All **103** cumulative changed Go files pass `gofmt`. Later edits
only record these outcomes and the continuation point in documentation.

Tagged Docker observation failed in **4.047 seconds** and real PG
transactional integration failed in **1.543 seconds** because the configured
Docker Unix socket is absent. PG startup and cleanup identification both
failed to connect; no real PG concurrency/restart or physical creation/
cleanup result was obtained. These are failed/blocked attempts, not skips or
passes, and cannot establish image availability. No image pull, rebuild,
old one-shot probe or live CRL run was performed. The compiled binary is a
dirty-source artifact, not a signed/supplied role image. Original main is
still clean; branch HEAD, upstream and live remote remain the full handoff
SHA above. Logs, preserved failures, source inventories and review records
are outside Git and the migration package.

Slice 6 status: **1** bounded historical Guest E only; **2** startup/security
in progress with this Ready-CAS component; **3** complete live v2 inventory,
original 16 scenarios and independent formal acceptance incomplete; **4**
post-acceptance handoff not reached. Phase 6 remains **5/15**. Both public
Profile-v2 and Provider serve v3 holds remain closed, and no Application or
automatic lease worker starts. The next bounded implementation is to connect
existing typed cleanup Begin/Finish to lifecycle termination reconciliation,
keeping fresh dispatch separate from historical/uncertain readback. Remaining
exec/terminal/artifact ports and correct-input real gates follow, along with
Browser failure/uncertainty, isolated Provider commands, network/
UID/GID/permissions and Guest peer-revoke/CRL-loss/replacement scenarios.
No commit, push, merge, publication or deployment is performed.


## 2026-10-09 held Provider typed termination reconciliation

This continuation preserves the restored branch at full handoff HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, earlier uncommitted work, the
migration package and original receipts. The user-confirmed root single
writer and independent read-only implementation-agent review remain in force.
No old automation or one-shot operator authorization is resumed.

The actual held v3 command now connects lifecycle termination to the existing
typed cleanup Begin/Finish mechanism. The route runs before generic terminal
shortcuts, including for retained Succeeded. One read-only PG SELECT gives
marker, slots and lifecycle documents the same snapshot. It validates exact
original allocation, configured plan/policy/spec, operation/idempotency,
current generation/fence/lease and either current retirement or released
terminal projection. It does not infer a historical allocation from a reused
slot or authorize any mutation from a read.

Accepted may attempt fresh Completed observation, PG admission and one send.
The existing retirement gains a private `dispatch_acknowledged` flag,
default false. Only a typed result from this fresh call's successful Control
dispatch can set it under the same PG row lock; send error records Unknown.
Recovery first retains unacknowledged Running as Unknown, including when
Control is Pending/Unknown/NotFound, then only observes Released and runs the
existing PG release CAS. ACK by itself cannot release a slot. Running may
succeed only with durable ACK, a live operation deadline, no cancellation
and exact independent Released. A Finish that wins before ACK instead
retains Unknown, which a late ACK cannot upgrade. Legacy markers reject the
new flag and atomic-v3 release cannot use the legacy acknowledgement-free
helper path. Already-released Succeeded/Unknown returns without a Control
call or write. The returned dispatch-attempt flag is independent of this
persisted ACK. ACK does not publish termination. An uncertain PG commit,
lost POST reply or cancelled
call cannot recover a dispatch permit from historical state. A live caller
may read what actually committed while preserving the error; a cancelled
caller leaves that read for a later explicit reconcile. The original window,
retirement barrier and no-retry policy remain unchanged.

Independent design review found the old release helper could call Succeeded
after the operation deadline or cancellation. The retained
`late-release-red.log` reproduces late Running becoming Succeeded. The fix
keeps a late/cancelled Running termination as OutcomeUnknown in the same
release transaction while recording observed termination and releasing the
slot on exact historical Released evidence. Existing Unknown stays unchanged.
The helper applies transitions to copies until every check/event succeeds,
and the typed entry rechecks the complete final PG state. The optional ACK
flag is retained only in the existing private retirement;
no release-history map, SQL migration, issuer or evidence reuse rule is added.

Root review against the locked calling standard then found a second issue:
the initial composition retained Running after a lost dispatch reply and
could later report success. The `uncertain-dispatch-red.log` reproduces it.
The first full validation was explicitly interrupted with SIGINT after this
finding; its original log/source snapshot are preserved, not passing evidence.
Independent design review confirmed a post-error write alone would leave a
Finish/process-loss race and required the durable ACK/recovery rules above.
Final independent read-only review covered this corrected combination and
matched all **16** changed Go file hashes. It found no remaining definite
blocker against the locked calling standard. The reviewer did not edit files
or run tests. Request cancellation or process death may prevent Unknown from
being persisted in that call; a later explicit recovery conservatively records
it. No automatic recovery worker is claimed.

The corrected focused race/shuffle/count-one identity/lifecycle/PG/command
packages passed in **6.311 seconds**. The tagged PG suite compiled in **3.738
seconds**, without executing a test. Component tests use the actual typed
coordinator and PG state helpers under an in-process mutex with synthetic
Control responses.
They cover two stale Accepted readers (one dispatch), lost Begin/Finish
returns, lost mutation reply, cancellation after admission, non-Released
status, late/cancelled and historical Unknown, malformed read snapshots and
slot reuse. Additional tests cover ACK commit reply loss versus no ACK
commit, unacknowledged recovery with all non-Released statuses, Finish or
recovery winning before late ACK, forged typed results, Unknown event
collision rollback and legacy-marker rejection. Separate lifecycle tests
trap generic sandbox/driver fallback
and prove termination routes before the terminal shortcut while other
runtime ports stay held.

The real PG harness now also composes lifecycle AcceptTerminate/reconcile
with two independent connection pools, synchronized stale Accepted reads,
exactly one dispatch (one admission plus one ACK revision), exactly one
release revision, and no repeated
terminal writes/Control calls. The existing restart/slot-reuse scenario also
checks the new single-snapshot reader. Control is still synthetic in that
harness; these tests cannot establish production CRL, physical absence or
actual COMMIT packet loss.

The final combined source passed
`go test -race -shuffle=on -count=1 ./...` in **430.728 seconds**,
`go vet ./...` in **2.718 seconds**, both Provider/Product Contract locks,
and Linux/arm64 core compilation in **3.739 seconds**. No timeout was
extended. All **1,994** inventoried Go and root/nested module files stayed
unchanged during validation. All **113** cumulative changed Go files pass
`gofmt`; the 16 independently reviewed hashes match this final source.

Unlike the preceding checkpoint, Docker was reachable in this run. Both
real read-only daemon Info and empty-namespace observations passed in
**1.751 seconds**, without creating or deleting Docker objects. This does
not prove physical cleanup, Control TLS/CRL or the full topology. The real
PG transactional gate failed in **1.211 seconds** because its exact pinned
PostgreSQL image was absent from the local Docker store. The test's cleanup
did not report an error. No PG concurrency/restart/termination result was
obtained from that attempt; its failed log remains preserved.

The next input check read the exact public registry index and verified its
SHA-256 and selected `linux/arm64/v8` manifest against the preserved lock.
Only this needed PostgreSQL image was then downloaded and exported to a new
private archive outside Git and the migration package. The existing
`TestPinnedExternalArchiveComponent/postgres` verified the complete index,
selected manifest, config, compressed layers and diff IDs in **3.197 seconds**.
The new export happens to match the historical tar SHA-256; that byte match
does not inherit any old run, device/inode binding or acceptance. Other
omitted inputs and the full four-archive supply were not restored. No
signature/provenance/SBOM/vulnerability acceptance is claimed from this
component check; those supply/release requirements remain open.

With the correct bounded test input available, the same real PG transactional
test passed in **4.896 seconds**, including the new two-connection termination
path, retained Ready/cleanup/restart/reuse checks, and explicit exact container
and anonymous-volume absence assertions. The earlier missing-image failure
is retained separately. The harness uses real PostgreSQL with synthetic
Control; this is PG component evidence, not physical execution, live Control
TLS/CRL, actual COMMIT packet-loss or complete Profile-v2 acceptance. The full
race suite was not repeated for this input-only recovery.

Branch HEAD, upstream and live remote still match the full handoff SHA above;
original main remains clean and no changes are staged. New logs, source
inventories, independent review, preserved failures and the new PostgreSQL
archive are private outside Git and the migration package. The Linux/arm64
binary remains an unsigned dirty-source build, not an accepted role image.

Slice 6 status: **1** the original bounded Guest E evidence only; **2**
startup/security work remains in progress with this source/component
termination path; **3** the updated complete live Profile-v2 inventory,
original 16 scenarios and independent formal acceptance remain unfinished;
**4** post-acceptance handoff has not been reached. Phase 6 remains **5/15**.
Both public holds remain closed. No Application/automatic worker, commit,
push, merge, publication or deployment is performed. Next close remaining
lease completion and daemon-free runtime ports, then correct-input real
Control/Scanner/Provider gates, Browser failures/uncertainty, network/UID/GID/
permissions and Guest peer-revoke/CRL-loss/replacement scenarios.


## 2026-10-09 held Provider atomic lease completion

This continuation preserves full handoff HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, all earlier uncommitted work,
the original main checkout, migration package and raw receipts. The confirmed
root single writer and independent read-only implementation-agent arrangement
continue. The prior termination checkpoint's 1,994 Go/module source hashes
matched before new work. No old automation or one-shot operator is resumed.

The new policy-bound Coding repository overrides only ExtendLease admission.
Under the existing control_state row lock it applies the real lifecycle
admission, checks the unchanged Coding admission barrier, and completes
operation/idempotency plus the deterministic success event in the same
transaction. Expiry and both events therefore become visible with Succeeded
in one revision. Independent design review checked the locked calling
standard, semantic rule and operation schema: HTTP 202 with an extend_lease
operation already in Succeeded is allowed. No wire schema or status code
changes. Legacy construction and other mutations keep their existing path.

The locked callback rechecks current old-lease validity and the operation
deadline, including time spent waiting for the row lock. Exact current
Active/Ready allocation, original create completion, generation, fence,
idempotency and canonical admission event are required. New failure or event
collision leaves no partial in-memory or PG effect. Exact replay makes no
UPDATE, extra event or revision. Lease completion sends nothing to Control
or Docker and grants no new mutation permit.

A focused typed lease port is explicitly wired in the held v3 command and
routes before the generic terminal shortcut. A successful historical result
is read-only and remains distinct from the sandbox's current generation,
lease and slot occupant. Original allocation, frozen create completion and
idempotency are checked; retained events must be exact. Pruned events may be
accepted only with the retained-window proof. Missing history with a floor
at exactly the success timestamp is conservatively unreadable, not guessed.
An older Accepted record can complete only when its exact current admission
is still latest, including same-timestamp/same-fence disambiguation. Its
already-committed DB effect is known; later completion does not renew expiry
or reopen any deadline. Superseded, cancelled, Running or Unknown old records
remain unchanged and rejected. This does not claim every historical lease
state has been resolved.

Independent source review found an early coordinator replay path could return
a non-lease operation before reaching the new PG checks; it also bypassed
request validation and the retained deadline check. Four retained red cases
reproduce wrong type, substituted deadline, zero extension and expired POST
acceptance. The typed v3 lease entry now validates the request before lookup,
checks operation type/deadline and the immutable tuple, then reads the result
through the PG lease port. Legacy coordinator behavior is unchanged; expired
POSTs use historical reads rather than new admission. The initial review
hashes and red log are preserved separately from the corrected snapshot.

Final independent read-only review matched all **8** changed Go file hashes
and found no remaining definite safety blocker. The reviewer did not run tests
or edit files. Historical generation/extension values rely on the canonical
request digest; the operation does not retain those fields independently.
The old-record and equal-time retention limits above remain formal-acceptance
work, not a promise of complete historical recovery.

Final focused race/shuffle/count-one lifecycle/PG/command tests passed in
**9.542 seconds**. They cover atomic completion/replay, stale lock-time
admission, substituted authority, same-fence/same-time supersession, generic
writer denial, event collision, late known-commit completion, finite event
retention and routing before generic terminal reads. An earlier retention
test fixture referenced a nonexistent operation and failed; it was replaced
with a real second lease admission, and the original failure log remains.

The existing owned real-PG transactional test passed on the corrected code
in **6.475 seconds**. Two independent pools are synchronized after reading
the same old sandbox, then race the same lease: both return Succeeded and
only one complete admission/completion revision commits. Exact POST replays,
reconstructed coordinator reads and post-termination historical reads add no
PG revision or Control call. Existing Ready/termination/restart/slot-reuse
checks and exact container/anonymous-volume absence assertions also pass.
This uses the locked PG input recovered and independently byte-checked in the
preceding checkpoint. Create/termination Control observations remain
synthetic; no physical deletion, live TLS/CRL or actual COMMIT packet-loss
claim follows. Unaffected Docker observation and image-input results are
retained at their previous snapshot rather than rerun for reporting.

The first full `go test -race -shuffle=on -count=1 ./...` invocation failed
after **626.244 seconds**: `internal/phase6security` reached the default
ten-minute package timeout. All 182 files in that package and its principal
dependency match the preceding passing checkpoint. The test active at the
timeout passed alone in **2.916 seconds**; this does not establish the cause
of the cumulative package timeout or turn the full invocation into a pass.
The original failure and diagnostic logs are preserved. One full retry changes
only package scheduling to `-p=1`; race, random order, count one, the complete
test set and the default timeout remain unchanged.

The complete retry `go test -race -shuffle=on -count=1 -p=1 ./...` passed in
**1,062.257 seconds**; `internal/phase6security` took **489.945 seconds**.
This is a passing full test set with serialized package scheduling, not a
passing first invocation or a proven diagnosis of its timeout. `go vet ./...`
passed in **3.044 seconds**, both Provider/Product Contract locks passed, and
Linux/arm64 core compilation passed in **5.943 seconds**. All **1,998** Go and
root/nested module source hashes remain unchanged from the final validation
snapshot, and all eight reviewed hashes match. All **117** cumulative changed
Go files pass `gofmt`. The build is an unsigned dirty-source binary, not an
accepted role image.

The branch HEAD, upstream and live remote match the full handoff SHA above;
original main remains clean and nothing is staged. The full test processes
have exited, the read-only review is complete, and the real PG test proved
exact container and anonymous-volume cleanup. Private logs, source hashes,
failure records and review evidence remain outside Git and the migration
package. No new image recovery or build was needed in this continuation.

Slice 6 fixed steps: **1** only the previously bounded historical Guest E;
**2** startup/security work remains in progress, with this lease component
implemented; **3** complete live Profile-v2 inventory, the original sixteen
scenarios and independent formal acceptance remain incomplete; **4** formal
post-acceptance documentation/commit/push handoff has not been reached.
Phase 6 remains **5/15**. Both public holds remain closed and no Application
or automatic expiry worker starts. Remaining historical lease recovery limits, daemon-free runtime ports,
correct-input Control/Scanner/isolated Provider gates, Browser failure and
uncertainty, network/UID/GID/permissions, and Guest peer-revoke/CRL-loss/
replacement remain. No commit, push, merge, publication or deployment.

## 2026-10-09 held Coding runtime preflight

This checkpoint starts at the same full handoff HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, with all **1,998** previous Go and
root/nested module hashes matching the completed lease checkpoint. The original
main checkout, migration package, manifests and historical receipts remain
untouched. The confirmed main-session source writer and independent read-only
implementation-agent arrangement continue; no old automation is resumed.

Independent boundary review found no existing daemon-free implementation of the
legacy exec/Terminal/artifact ports. The existing Control wire has exactly three
actions and the legacy exec vertical reads lifecycle and reserves its separate
exec document in different operations. Connecting it directly would not make
current Coding allocation/lease/fence admission atomic. The reviewed first
increment is therefore a single-snapshot read and explicit exec preflight, not
physical exec dispatch or a candidate mutation authority.

The new PG port validates marker, plan, policy, specs, unique live allocation,
original create/completion, both desired/observed Ready, current generation,
matching lease/fence and expiry from one SELECT. It returns no original Control
authority or physical target. The held v3 command constructs its focused
SupportChecker without a runtime Executor or Application. Request shape and
unsupported reference checks precede the read; parent cancellation/deadline,
clock rollback, stale/future read time, lease and request expiry are rechecked
afterwards. A higher prospective fence changes no PG state. This read can become
stale immediately after it returns and cannot authorize a later physical send.

Final independent review matched all **7** Go hashes and found no remaining
definite blocker. Its earlier review identified a coherent operation/idempotency
record with Running create alongside Ready and a completion record: existing
self-guards allowed that contradictory cross-document combination. A retained
red test reproduced it in **3.362 seconds**. The final reader requires the
original create to be Succeeded or OutcomeUnknown with no future observation
time. The positive case retains legitimate historical Unknown and an expired
original create envelope while current readiness/lease are independently valid.
The reviewer edited nothing and did not run tests.

Final focused race/shuffle/count-one PG, codingcontrol and command tests passed
in **8.931 seconds**. Adversarial cases cover missing/crossed marker, allocation,
completion and lease identity; pending termination; expired or substituted
request/snapshot; unsupported references; signed/unsigned integer boundaries;
parent deadline and post-read cancellation; and absence of execution ports.
The initial unit fixture omitted the required termination reason, and the first
tagged build used CreateRequest.SandboxID instead of Spec.SandboxID. Both failed
logs remain separate from the corrected results.

The final owned real-PostgreSQL transactional test passed in **7.817 seconds**.
A separate pool completes current/high-fence preflight while another transaction
holds the row's write lock; the complete PG document, revision and Control call
counts remain unchanged. Renewed lease rejects the old fence. Accepted
termination rejects preflight before cleanup. A new allocation explicitly reuses
the same slot, yet the old sandbox stays ineligible and the new Ready sandbox can
be read without writes. Earlier retained PG scenarios and exact test-owned
container/anonymous-volume cleanup also pass. Create/termination observations
remain synthetic; this is PG component evidence, not a physical exec, runtime
byte stream, live Control TLS/CRL or full-topology run. The previously recovered
locked PG image is reused; no new image pull or full image build is required.

The full `go test -race -shuffle=on -count=1 -p=1 ./...` passed in
**1,022.115 seconds**, including `internal/phase6security` in **456.931 seconds**.
Serialized package scheduling was selected before this run because the previous
checkpoint's default parallel invocation timed out while its unchanged full
serial retry passed. The full package set, race, random order, count one and
default timeout remain intact; this does not diagnose or erase that historical
failure. `go vet ./...` passed in **1.746 seconds**, both Provider/Product
Contract locks passed, and Linux/arm64 core compilation passed in **3.147 seconds**.
All **2,003** inventoried Go and root/nested module hashes remain unchanged
through final validation, and all **7** independently reviewed hashes match.
All **122** cumulative changed Go files pass `gofmt`. The resulting binary is
an unsigned dirty-source build, not an accepted role image. Logs, retained
failures, source hashes and independent review stay private outside Git and
the migration package.

Slice 6 fixed steps: **1** retain only the originally bounded Guest E evidence;
**2** current startup/security work continues, with this read-only component
closed; **3** the complete live Profile-v2 inventory, original sixteen scenarios
and independent formal acceptance remain unfinished; **4** post-acceptance
documentation/commit/push handoff has not been reached. Phase 6 remains **5/15**.
Both public holds stay closed. No Application, automatic worker, commit, push,
merge, publication or deployment is performed. Next define and independently
review same-row exec admission and its separate Control operation/receipt
boundary before connecting physical exec. Remaining Terminal/output-transfer,
real Control/Scanner/isolated Provider, Browser failure/uncertainty, network/
UID/GID/permissions and Guest peer-revoke/CRL-loss/replacement gates remain open.

## 2026-10-09 held Coding exec intent ledger

This continuation starts from the previous runtime-preflight checkpoint at full
HEAD `91fe315641779e6ea640632538309d63ad1b303f`. All **2,003** starting Go and
root/nested module hashes match that checkpoint. Root remains the confirmed sole
source writer; the independent implementation-agent reviewer is read-only.
Original main, migration material, old receipts and automation remain untouched.

Independent investigation confirmed that generic exec replay compares only a
narrow identity tuple and that its separate lifecycle read/exec reservation cannot
supply Coding atomic physical authority. The reviewed increment therefore stores
full requests in a separate bounded **no-permit intent ledger** under the same
row lock as marker, allocation and lifecycle. It emits no public Accepted
operation, runtime dispatch reference, Control permit or fence reservation.
The held command constructs the focused recorder only. Existing Control actions
and public holds remain unchanged.

Explicit marker-mode initialization requires an already bootstrapped but unused
atomic namespace. Review identified that empty slots alone miss an Accepted
create before its first slot reservation; the final initializer also requires
empty lifecycle history and absence of the generic exec document. Committed
initialization can be recovered read-only. Missing initialized history is never
recreated. Review also found that the generic decoder conflated present JSON
null with an absent key; the dedicated decoder now rejects present null, with
unit and real-PG corruption fixtures preserving the failed state until the test
restores its exact prior disposable bytes.

New intents verify current Active/Ready, original completion, generation,
lease/fence and request deadline under the row lock. Retained records bind full
requests and an independent internal-payload digest, allocation, immutable
completion and the historical runtime snapshot. This is not validation of the
Contract wire digest or caller authentication. Every replay field must match,
including argv, workdir, capture settings, deadline, generation, fence, retention,
attempt and idempotency identity. Unsupported reference fields remain rejected.
Historical replay after lease/termination/release/slot reuse returns only the old
receipt and does not re-admit work. No global PG revision is recorded in that
receipt. Single-request, record-count and total-document limits reject overflow
without GC or discarded conflict history.


Final self-review, confirmed independently, found one additional historical
replay gap: a coherent original Running operation/idempotency beside retained
Ready/completion could still return an old intent receipt. A second case moved
the original completion later than the recorded intent snapshot. The retained
red test reproduced both in **8.711 seconds**. Historical validation now requires
Succeeded or OutcomeUnknown with observation time no later than that intent's
snapshot. A positive fixture proves legitimate Unknown followed by independently
completed Ready remains readable without changing Unknown. The reviewer matched
all **7** final Go hashes after the correction and found no remaining blocker
within this no-permit scope; the reviewer did not write files or run tests.

The final focused race/shuffle/count-one PG, codingcontrol and command tests
passed in **16.032 seconds**; the final real-PG parent gate passed in **7.176
seconds**. Cases cover exact full-request replay/conflict, unsupported references,
request and retained-document bounds, expired/stale authority, original-history
corruption, explicit bootstrap/missing/null handling, same-row lock cancellation,
two-pool single-commit concurrency and reopen recovery. The PG matrix also checks
lease-first rejection, termination-before-cleanup rejection, released history
through exact slot reuse, unchanged revisions on replay, and no Control calls.
Reopen/ignored-return fixtures do not simulate actual network COMMIT packet loss.

A first full-repository validation was deliberately interrupted after the
historical-replay gap was confirmed. Its log, original reviewed hashes and source
snapshot remain separate and are not counted as a pass. After the corrected
focused/PG gates and independent review, a fresh full run was started on the
frozen final source.

That full `go test -race -shuffle=on -count=1 -p=1 ./...` invocation **failed**
in **1,548.146 seconds**: `internal/phase6security` reached its unchanged default
600-second timeout (package exit after 600.615 seconds); all other tested
packages passed. The current receipt-reader test had run for only four seconds
when the package budget expired. Its stack was in file Sync while constructing
raw/envelope receipts, which does not prove that Sync caused the timeout.
Independent read-only inspection found no path from the seven changed Go files
into this package/test import chain, and its 180 Go files plus directly relevant
codingidentity/artifact sources match the prior passing checkpoint. Earlier
runtime-preflight evidence for this unchanged package was 456.931 seconds; that
historical pass is not a pass for this invocation.

After the failure, the 10-logical-CPU host showed load averages above 200,
while unrelated unchanged test packages also took substantially longer
(qualificationadapterprotocol 188.751 versus the prior 20.167 seconds;
qualificationharness 97.794 versus 21.426). This is recorded resource-pressure
evidence, not a proven causal diagnosis. No unrelated process was stopped and
no timeout, durability Sync, assertion or security gate was weakened. After the
full invocation and its exact owned process group exited, a single standalone
verbose race/count-one diagnostic was started with the original shuffle seed
1791542819690610000 and the unchanged default timeout. That standalone diagnostic
passed in **535.950 seconds** (package 534.842 seconds), with 156 top-level tests
passing and only the existing optional synthetic-fixture export skipped because
it was not requested. The longest completed top-level cases took 63.96, 54.35
and 52.17 seconds, supporting cumulative package cost as an observed concern,
not proving the original root cause. This single-package pass does **not** turn
the failed full-repository invocation into a pass. A successful full invocation
for this checkpoint remains unestablished; no formal release gate is advanced.

`go vet ./...` passed in **1.770 seconds**, the Provider and Product Contract
locks passed in **0.162** and **0.081 seconds**, and Linux/arm64 compilation
passed in **4.261 seconds**. The produced binary is an unsigned dirty-source
candidate, not an accepted role image. The full failed run, deliberate earlier
interruption, red regression test and corrected component results remain
separate raw evidence outside Git and the migration package. All **2,007** Go and
root/nested module hashes remain identical to the corrected frozen combination;
all **7** reviewed hashes match, and all **127** cumulative changed Go files are
formatted. No source changes were made during either corrected validation run.

The real PostgreSQL parent test reuses the previously restored pinned image and
proves exact owned container/anonymous-volume cleanup. Its Control observations
are synthetic. No exec command, physical cancellation, runtime bytes, production
TLS/CRL, actual COMMIT packet loss or full Profile-v2 topology is exercised here.
The generic exec repository remains unchanged and isolated by held composition;
future public exec must close that entry point and cross-document operation-ID
conflicts before issuing physical permits. A prospective higher intent fence
never overrides a later lease or termination. No old receipt or intent is
reusable physical authorization.

Slice 6 fixed steps: **1** preserve only the originally bounded Guest E;
**2** startup/security continues with this no-permit PG component; **3** the
complete live Profile-v2 inventory, original sixteen scenarios and independent
formal acceptance remain incomplete; **4** post-acceptance documentation/commit/
push handoff is not reached. Phase 6 remains **5/15**. Next complete the separately
reviewed current exec permit/Control receipt and cleanup-quiescence chain before
physical exec, then remaining runtime ports and real isolated Provider, Browser
failure/uncertainty, network/UID/GID/permissions and Guest revoke/CRL-loss/
replacement gates. No commit, push, merge, publication or deployment.


## 2026-10-10 held Coding exec namespace isolation

This continuation started from all **2,007** prior Go/module hashes unchanged,
branch `codex/product-v1-phase-6-hardening`, HEAD
`91fe315641779e6ea640632538309d63ad1b303f`. The root remains the sole source
writer under the user's confirmed new-machine arrangement. No old automation,
old Guest authorization or old operator receipt was resumed. Recovery evidence
is retained outside Git and the migration input in the private
`provider-exec-control-20261010` checkpoint.

The next physical-exec investigation reproduced two prerequisite defects in
real disposable PostgreSQL: a generic exec reservation could enter a database
with Coding intent mode enabled, and a typed lease could reuse a retained exec
operation ID. The red test failed on both assertions. The first attempted red
run failed before database creation because Docker Desktop was not running;
that environment failure is retained separately. Starting the local daemon
used the previously restored locked PG image, with no registry pull.

The repair adds one shared row-lock guard across generic and typed lifecycle
writers and Coding bootstrap, and one-statement snapshot rejection across all
generic exec reads. It validates before callbacks (including unchanged replay
sentinels) and before commit, rejects reverse ID collisions, mixed or orphan
histories and mode downgrades, and returns zero mutation results on failure.
The existing intent transaction now also rejects historical ID collisions and
any coexisting legacy exec document during ordinary and initialization replay.
The guard does not replace frozen-plan authorization validation or create an
exec permit. Current fence high-water marks and Control wire are unchanged.

The real-PG parent regression passed in **18.943 seconds**. It covers both
admission orders, two independent connection pools contending for one operation
ID with exactly one committed revision, all generic exec read/write surfaces,
generic create/terminate rejection, typed lease rejection, lock cancellation,
damaged/missing/null documents before replay, orphan bootstrap rejection,
exact document/revision preservation, and the existing create/lease/termination/
release/slot-reuse chain. Earlier existing fixture failures are retained: the
old fixture tried to inject corruption through production helpers that now
correctly reject it. It now asserts that rejection, separately injects damage
only into the disposable database, retains the original recovery rejection
assertions and restores exact original document bytes. Two compile failures
while adding a cancellation assertion are also retained, followed by the
corrected passing run; no failed result is relabeled as a pass.

Independent `implementation_agent` design review required pre-callback checks
for unchanged-replay sentinels, candidate marker/slots checks, zero results on
transaction errors and protection of the dedicated intent document. The final
read-only review matched all **10** changed Go file hashes and found no blocking
issue within this no-permit PG namespace scope. The reviewer did not write
source or independently run tests.

The final full `go test -race -shuffle=on -count=1 ./...` invocation **failed**
in **624.328 seconds**, with two failures:

- `cmd/certificate-controller`: `TestControllerV2RejectsBeforeReadingInheritedKeys`
  failed during TempDir `RemoveAll` cleanup with `bad file descriptor`, under
  seed `1791596476270923000`. An unchanged-source single-package diagnostic
  with that same seed subsequently passed in **5.356 seconds** (package
  **2.986 seconds**). This is diagnostic evidence only, not closure of the
  failed full invocation. Inspection found a separate pre-existing descriptor
  ownership risk in the negative `readBounded` test: it passes live `os.File`
  descriptors to a function that wraps and closes them, leaving the original
  objects eligible for later finalization. The exact causal chain for this
  cleanup failure has not been demonstrated; no Controller source was changed.
- `internal/phase6security` exceeded its unchanged default **600-second**
  timeout (reported **600.555 seconds**). The current test was
  `TestSlice6ReceiptBundleRejectsCrossRunAndTampering`, running for **21 seconds**;
  the sampled stack was runnable in the Profile/HBA verification chain, not
  evidence of a 600-second hang in that case. Seed: `1791596490140389000`.
  This package's source is unchanged from the starting checkpoint. No timeout
  was extended, assertion removed or new passing full-run claim made.

All other packages in that full invocation passed. `go vet ./...` passed in
**3.067 seconds**, Provider and Product Contract locks in **0.397** and
**0.154 seconds**, and Linux/arm64 compilation in **10.062 seconds**. The binary
is an unsigned dirty-source candidate, not a supply-chain-approved role image.
All **2,010** Go/module hashes stayed identical across final validation. The
failing and passing raw runs remain separate in the private checkpoint. Full
repository validation remains unresolved; the two failure investigations take
priority before claiming a green combined source checkpoint.

The PG image remains the previously checked index/platform input, not a newly
accepted supply-chain candidate. Control observations are synthetic; no actual
exec command, detached process, physical cancellation/output, production TLS/CRL,
actual COMMIT packet loss, role-image rebuild or full Profile-v2 topology was
exercised. Component success cannot prove physical execution or quiescence.

Slice 6 fixed steps: **1** retains only the originally bounded Guest E;
**2** continues startup/security with cross-document exec isolation now closed;
**3** complete live Profile-v2 inventory, original sixteen scenarios and
independent formal acceptance remain incomplete; **4** post-acceptance handoff
is not reached. Phase 6 remains **5/15**. Next define and independently review
the current exec fencing/Control Unknown receipt/quiescence/observe-cancel-result
chain, then finish the remaining Provider, Browser failure/uncertainty,
network/UID/GID/permissions and Guest revoke/CRL-loss/replacement gates.
No commit, push, merge, publication or deployment occurred.

## 2026-10-10 Controller descriptor and validation-cost repair

This continuation preserves branch `codex/product-v1-phase-6-hardening`, HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, the existing dirty source and the
user-confirmed sole new-machine writer. All 2,010 starting Go/module hashes
matched the preceding exec-isolation checkpoint. Private diagnostics, CPU
profiles and raw test logs are outside Git/migration inputs in the
`provider-validation-repair-20261010` checkpoint. The original main checkout
remains unchanged. This is a source-quality repair within Slice 6 step 2.

The Controller negative-descriptor fixture deterministically lost its own
file descriptor: the red assertion failed with `stat |0: bad file descriptor`.
The fixture passed an `os.File` descriptor to `readBounded`, which wraps and
closes that descriptor. The original object retained a second owner/finalizer
for the same descriptor number. Tests now duplicate descriptors before
transferring ownership, retain and close the originals, and assert originals
remain usable. Existing pipe/directory/missing/oversize rejection assertions
remain. Production descriptor handling is unchanged. The exact cause of the
previous TempDir cleanup failure remains unproven; this repair closes the
independently reproduced ownership defect. Three repetitions of the Controller
package with the original failing shuffle seed passed in 9.059 seconds.

CPU profiling of the unchanged receipt cross-run/tamper test established
repeated complete `Profile.Validate` calls in the composed final-profile
verifiers and once per broker policy during observation checking. Every
public entry still fully validates each input. Package-private helpers reuse
that precondition only within the same call on the same unchanged profile;
all desired inventory/address/identity/HBA comparisons remain. No cross-call
cache, evidence reuse, digest encoding change, raw-receipt shortcut or fsync
removal was introduced. The standalone broker method and the old intermediate
profile/anchor entry points retain full validation.

Seventeen public-entry regressions cover a successful call followed by digest
substitution, a rehashed unsafe root filesystem configuration, and valid input
again. The observation regression also rejects the unsafe profile when its
observation digest is updated to match. The initial new-test run correctly
rejected an unplanned synthetic network fixture; the corrected positive uses
the existing network-plan binder, with unchanged production rejection rules.
Focused race/shuffle regressions then passed in 27.888 seconds. Both raw runs
are retained. The same complete cross-run/tamper case passed before and after:
package times 81.364 and 41.530 seconds; measured command times 83.397 and
43.027 seconds. CPU samples attributed to complete Profile validation fell
from 14.82 to 2.39 seconds. These are one-run diagnostic measurements, not
production capacity or topology evidence.

Independent implementation_agent review compared all sixteen changed Go
file hashes (fourteen security production files, the Controller test and the
new regression test). It found no blocking issue, verified each private
helper's validation precondition and both public holds, and performed no
source writes or test execution. The root inspected the full turn diff and
ran validation on the final combined source.

The final `go test -race -shuffle=on -count=1 ./...` passed in **625.022
seconds** overall. The Controller package passed in **3.369 seconds** and
`internal/phase6security` in **580.323 seconds**, inside its unchanged default
600-second package timeout. The package still has limited timing headroom;
this successful invocation does not establish future timing stability or
replace either preserved earlier failed invocation. `go vet ./...` passed in
**4.213 seconds**, Provider/Product Contract locks in **0.234/0.098 seconds**,
and Linux/arm64 compilation in **6.022 seconds**. The latter is an unsigned
dirty-source binary, not an accepted role image. All **2,011** Go/module hashes
were identical before and after final validation. No timeout, test selection
or security condition was relaxed. Local HEAD, upstream and a fresh live
remote read all match `91fe315641779e6ea640632538309d63ad1b303f`; the implementation
worktree retains the cumulative uncommitted changes.

The prior real-PG exec-isolation evidence remains scoped to unchanged PG and
Coding runtime code; this increment changes no driver/lifecycle implementation.
No Docker gate ran here. The optional isolated-network probe's locked Alpine
image is absent locally; it was inspected, not pulled or declared recovered.
Full Profile-v2 role images and live topology require their own correct inputs
and supply/identity gates. No actual exec, physical quiescence, real TLS/CRL,
original sixteen-scenario gate, operator authorization or release acceptance
is claimed. Receipt bytes and frozen-R reuse rules remain unchanged.

Slice 6 fixed steps: **1** retains only the bounded historical Guest E;
**2** continues startup/security, with the reproduced descriptor defect and
this combined source validation addressed; **3** the complete live v2 inventory,
original sixteen scenarios and independent acceptance remain open; **4**
post-acceptance handoff is not reached. Phase 6 remains **5/15**. The next
substantive source result is the independently reviewed current-authority
exec CAS/persistent fencing plus distinct Control Unknown-before-effect
receipts, execution/cleanup quiescence and observe/cancel/result recovery.
Public command composition stays held until that complete boundary is ready.
No commit, push, merge, publication or deployment occurred.

## 2026-10-10 held Coding PG exec fence reservation

This continuation retains branch `codex/product-v1-phase-6-hardening`, HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, all cumulative uncommitted work and
the user-confirmed single new-host source writer. The starting 2,011 Go/module
hashes matched the preceding validation repair. Private logs, exact source
hashes and independent review are outside Git/migration inputs in
`provider-exec-authority-20261010`. The original main checkout is preserved.

The new explicit unused-state-only fence mode is additive to the existing
no-permit intent mode. Its first reservation locks the PG singleton, validates
the complete request and current Active/Ready allocation against the intent's
frozen tuple, checks original/completion and live lease/deadline, then commits
one record plus exactly the scope/lease fence pair. The record contains the
pre-bump runtime snapshot and an immutable full-request reference, not a
physical exec or independent before/after snapshot pair. Generic writers retain
their old readiness barrier and now protect recorded floors; marker changes,
missing/null/orphan/mixed/corrupt history cannot bypass typed replay callbacks.
Runtime/termination preflight reads check the documents in the same MVCC SELECT.

History replay/read preserves the original time, revision and target fence.
A separate read works past the original request deadline and after allocation
release/slot reuse; it does not grant execution or refresh an expired POST.
Commit/context errors return an empty result. Tests reconstruct a second
repository and inspect committed history; they do not inject a network failure
precisely at the PostgreSQL COMMIT acknowledgement. Both the receipt type and
held command dependency remain separate from any Executor or Control permit.

Independent implementation_agent review of thirteen changed Go files (eight
production, five test) found no blocking issue; all supplied review hashes
match the final source snapshot. The reviewer performed no writes or tests.
It confirmed that only the pre-bump snapshot is stored, and identified an
existing limitation: original create OutcomeUnknown+Ready reconciliation may
reject after a lease/fence advance. This PG increment does not claim to close
that physical recovery path or grant any original create authority.

Initial validation had two preserved failures: two old test call sites were
mechanically given one extra nil argument, and the new retiring-state fixture
assigned into an uninitialized map. Both test defects were corrected without
relaxing production checks. Focused race/shuffle tests of the PG adapter,
Coding control and command packages passed in **17.353 seconds**. The first
real PostgreSQL invocation passed in **30.655 seconds**; after adding the
explicit fence-vs-terminate race, the final gate passed in **27.087 seconds**.
It used the already-local locked PostgreSQL 16 Alpine Linux/arm64 input in a
fresh disposable Docker fixture, with synthetic Control observations. It covers
unused bootstrap/replay, missing/null/orphan rejection, bounded row-lock
cancellation, two-pool same-request single-commit replay, fence-vs-lease and
fence-vs-terminate single-winner races, stale mutation rejection, and unchanged
history after release and reuse. No physical exec is dispatched by this test.
Its run-owned container and anonymous volume are removed by the existing exact
cleanup checks; unrelated local MySQL/Redis containers are outside the run.

The first combined `go test -race -shuffle=on -count=1 ./...` invocation
failed after **743.913 seconds**. Its only failed package was the unchanged
`provider/lifecycle/repository`: the Go driver reported `Test killed with
quit: ran too long (11m0s)` at **660.108 seconds**, with no captured shuffle
seed, test name or Go panic stack. The security package passed in **525.856
seconds**, Controller in **2.652 seconds**, and the changed PG adapter in
**32.511 seconds**. Inspection of the local Go 1.26.8 test driver confirms this
is its fallback SIGQUIT deadline after the default ten-minute test timeout;
this task did not extend a timeout. The package's three source files and its
direct lifecycle import match the starting hashes. Lack of captured startup
output cannot establish a specific test, runtime, OS, scheduling or pipe cause.
No cause is claimed and no speculative source patch was made.

A focused `go test -race -shuffle=on -count=3 -v
./provider/lifecycle/repository` then passed all six tests three times in
**2.209 seconds** overall (**1.658 seconds** package time). That diagnostic
does not replace the failed full invocation. Vet passed in **4.025 seconds**,
Provider/Product Contract locks in **0.464/0.190 seconds**, and Linux/arm64
compilation in **5.543 seconds**. The binary is an unsigned dirty-source output,
not an accepted role image. The full same-source recheck, `go test -race
-shuffle=on -count=1 -v ./...`, passed in **355.541 seconds** overall. Only
`-v` was added for diagnostic output; default timeout, concurrency, race,
shuffle and count settings were unchanged. Security passed in **335.582
seconds**, Controller in **2.566 seconds**, the PG adapter in **22.466 seconds**,
and the previously stalled lifecycle repository in **1.256 seconds**. This
successful full invocation does not erase the first failure or establish its
root cause or future timing stability. No timeout or safety assertion was
relaxed and no code was changed between these invocations.

All **2,015** Go/module files match the frozen snapshot before and after final
validation; the thirteen changed files match independent review hashes. The
local/upstream/live branch SHA remains the fixed handoff commit above. The
original main checkout is still clean, and the test commands and reviewer have
finished. The cumulative implementation work remains uncommitted. Detailed
raw results, the fallback-timeout diagnostic and final source/state hashes are
retained in the private checkpoint.

Slice 6 fixed steps: **1** retains only the bounded historical Guest E;
**2** continues, with the reviewed PG fence reservation prerequisite addressed;
**3** complete live Profile-v2 inventory, the original sixteen scenarios and
independent acceptance remain open; **4** post-acceptance handoff is not reached.
Phase 6 remains **5/15**. Next is the distinct Control Unknown-before-effect
and exec/cleanup quiescence boundary, including fresh dispatch authority and
observe/cancel/result recovery. Correct source-bound role images and real
TLS/CRL, isolated Provider/Browser, network/UID/GID/permission and Guest failure
gates are still required. No new image acceptance, operator signature, frozen-R
reuse change, public admission, commit, push, merge or deployment is claimed.

## 2026-10-10 Coding exec containment mechanism probe

This continuation starts on the same hardening branch and full HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, preserving all 2,015 previous
Go/module hashes and the user-confirmed single source writer. The two added
files are a tagged integration test and its Linux-only `testdata` helper;
there is no production Go change. Private logs, source hashes and review are
outside Git/migration inputs in `control-exec-boundary-20261010`. The original
main checkout and historical raw evidence are unchanged.

The intended next boundary was Control Unknown-before-effect and execution
stop proof. Read-only independent review identified a prerequisite that cannot
be assumed: legacy `provider/lifecycle/driver/docker/exec.go` sends TERM to
one direct child and calls cancellation confirmed after the wrapping exec
stops. `provider/exec/port.go` requires the exact attached execution to have
stopped; detached descendants and possible late Docker calls are not covered
by that inspect. The reviewer recommended a bounded real containment probe
before adopting a new physical execution or receipt protocol. This checkpoint
implements that probe only. It does not change legacy Cancel, add Control
exec receipts, grant physical authority or select a production architecture.

`TestCodingExecContainmentRealDaemon` is explicit opt-in with a local Unix
socket. It uses the cached PostgreSQL index
`sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`,
arm64 manifest
`sha256:2c942175a1255a9abe0366e48c1b401d9f50f835b04dfea13f111609b5530df7`
and verified config
`sha256:ef738a34a8651d11b2bace81c55c7e2187f786b484add6c83070884340074368`.
It exports and verifies cached OCI index/manifest/config/layer bytes without
pulling, building or accepting any product image. The PG entrypoint is
overridden; no database or network listener starts. Missing locked Coding
images remain missing and are not replaced by this fixture.

The source-built Go 1.26.8 linux/arm64 static helper forks/re-execs into new
sessions twice, orphans a writer under namespace PID 1 and closes inherited
streams. UID/GID is fixed at `57000:58000`. The helper and parent directory
are root-owned/non-writable; each private case directory is `0700`. One
unique labelled named volume is prepared through a never-started carrier.
All running fixtures have a read-only root, private PID/IPC, network none,
all capabilities dropped, no-new-privileges, the fixed repository seccomp
bytes, 256 MiB memory/swap limit, 0.5 CPU, 64 PIDs and bounded tmpfs. The
image's declared data VOLUME is explicitly covered; host binds, additional
and anonymous volumes are rejected. Each helper has a 90-second hard exit.
Exact acknowledged IDs and labels govern cleanup. Any uncertain mutation or
changed socket binding retains resources rather than retrying. This branch
is a fail-closed fixture safeguard, not a tested lost-reply recovery protocol.

The first invocation failed after **34.592 seconds** when Docker archive-read
could not read the PID file from `/tmp`; the underlying error was not recorded,
so its cause is unknown. The run-owned resources were cleaned up, and this
failure remains in `real-containment.log`. The assertion was changed to
read and compare the PID file inside the workload and check that exact PID
is still live, before running the unchanged legacy cancellation shell. The
next invocation passed in **41.734 seconds**. Independent review then found
the test's mutable socket path could redirect a new connection. The final
test rejects symlink components, binds the initial socket inode, checks it
before/after each new dial and before owned mutation/cleanup, and closes a
connection if its path binding changes. This reduces accidental endpoint
drift; it is not a hostile-host or authenticated production-endpoint proof.

The final affected real test passes in **64.466 seconds** overall (test body
**57.50 seconds**, package **59.263 seconds**), run
`9224bb6298cafc3691ef4c8f`, with race, shuffle and count=1:

- Negative case: the direct child is observed alive with the expected PID;
  TERM exits 0, the wrapping exec stops with exit 143, yet the detached orphan
  counter advances **17 -> 29**. This is the legacy algorithm's mechanism
  counterexample, not an invocation of the legacy driver's host-bind path.
- Candidate mechanism, fresh container 1: exact SIGKILL yields stopped,
  Pid=0 and exit 137 without OOM/restart; counter **12** stays unchanged in
  five 100 ms observations.
- Candidate mechanism, fresh container 2: natural command/PID 1 exit yields
  stopped, Pid=0 and exit 0; counter **12** stays unchanged over the same
  finite window. Both positive cases first observe a live advancing orphan.
- The final daemon identity/environment matches its initial observation,
  and all exact run-owned containers and the named volume are removed.

Independent implementation_agent read-only final review matches both frozen
file hashes and the original final probe log, with no blocking findings. It
performed no writes or tests. All **2,017** Go/module hashes stayed frozen
through final validation; all original 2,015 are unchanged. The complete
`go test -race -shuffle=on -count=1 -v ./...` passes in **312.806 seconds**
(security package **288.533 seconds**, Docker Control **19.977 seconds**,
lifecycle repository **1.524 seconds**) with default timeout/concurrency.
`go vet ./...` passes in **1.242 seconds**, and the Provider/Product Contract
locks pass in **0.179/0.082 seconds**. The opt-in probe is validated separately
above; it is not included in the untagged full test. The helper's Linux/arm64
build actually runs inside the probe. No unchanged role-image build or PG
transactional gate is repeated for this test-only increment. Earlier failures,
including the previous checkpoint's unexplained full-test timeout, stay in
their original records; this successful run is not a root-cause fix claim.

The positive cases do not prove late mutation quiescence, simultaneous cancel
versus natural-completion races, output sealing/retention, restart recovery,
receipt authority or PG/Control release. A command-per-container design would
change frozen Coding resources/image/mount/accounting and needs independent
design review before adoption. A trusted per-exec supervisor/cgroup is another
unproven alternative; killing a PID or process group is insufficient. The next
complete design must bind a fresh PG possible-exec claim to distinct Control
Unknown-before-effect and the same allocation-level cleanup serialization,
then close observation, cancellation, output and uncertain-reply/restart cases.

Slice 6 fixed steps remain: **1** historical bounded Guest E only, unchanged;
**2** ongoing, with the cancellation premise investigated and no new physical
execution admission; **3** full live Profile-v2 inventory, original sixteen
scenarios and independent acceptance remain open; **4** post-acceptance handoff
not reached. Phase 6 remains **5/15**. Both public holds, the two issuers and
frozen-R reuse rules remain unchanged. No commit, push, merge, publication or
deployment occurred.

## 2026-10-10 Coding exec resource and shared scratch checkpoint

This continuation starts from the preceding checkpoint's exact **2,017**
Go/module hashes on `codex/product-v1-phase-6-hardening`, HEAD
`91fe315641779e6ea640632538309d63ad1b303f`. The user-confirmed sole writer
continues in the new-host checkout; the original clean main checkout is
preserved. Three Go files are added and all earlier Go/module bytes remain
unchanged. Private evidence is outside Git and the migration package, under
`control-exec-protocol-20261010`.

The [private protocol plan](../plan/product-v1-phase-6-coding-exec-protocol.md)
addresses the containment probe's next design prerequisites. It keeps a
resident plus at most one possible command per allocation, preserves shared
`/tmp` through a fourth whole tmpfs volume, and requires a new complete
Profile/resource/template/receipt mode in an empty namespace. The prospective
`ExecutionResources` validator checks the resident/command/scratch split
against one slot ceiling and derives its own digest. It rejects invalid,
unaccounted, over-limit and overflowing values without changing old Plan v1.
It is consumed by the real test's Docker create inputs, not production
dispatch; `BindCeiling` is not a new Profile authorization.

`TestCodingSharedScratchResourcesRealDaemon` uses the preceding probe's
already-cached, index/arm64-manifest/config/layer-verified PostgreSQL image and
fixed seccomp. It does not fetch, build or substitute a Coding image. The
explicit local Unix socket is inode-bound, every run has unique labels/names,
and uncertain mutation or endpoint drift retains exact resources. The fixture
uses numeric UID/GID `57000:58000`, private PID/IPC, no network/capabilities,
read-only root, no-new-privileges and fixed resource limits. Its inert workload
self-expires after 90 seconds. The image-declared data VOLUME is explicitly
covered by a bounded private tmpfs, avoiding an anonymous volume.

The real run `fad43840f16cd7630810232f` passes in **23.599 seconds** overall
(test **19.96 seconds**, package **21.425 seconds**). The 256 MiB/500 milliCPU/
64 PID test ceiling is consumed as resident 64 MiB/100/16, command
160 MiB/400/48, plus 32 MiB scratch. Docker inspection matches these limits;
guest `statfs`/mountinfo and bounded assertions establish:

- actual tmpfs data capacity **33,554,432 bytes**, UID/GID `57000:58000`,
  `0700`, and rw/nosuid/nodev/noexec flags;
- bidirectional resident/command visibility and executable-file rejection;
- a bounded 33 MiB write fails with ENOSPC after reaching near capacity;
- removing/replacing the command preserves both parties' files while the
  resident stays mounted; and
- full unmount/remount loses scratch. This is explicitly **not** a daemon
  restart test. All exact run-owned containers and the named volume are removed.

Read-only implementation_agent review accepts the three-file arithmetic and
mechanism scope, with no code blocker. Its findings were incorporated into
the plan: original create must be Completed and not cleaning up under the
same Control allocation gate; retirement/late tickets linearize there;
aggregate output reservations and public acceptance share a PG transaction;
Control rejection after acceptance needs durable no-effect closure, never a
retroactive 429. Lost closure replies remain held. The reviewer also limited
32 MiB to data blocks: fixed inode/object bounds, empty-file/directory
exhaustion and metadata/cgroup memory evidence remain open. A subsequent
read-only document review accepts this constrained direction, without runtime
or formal-gate approval. No reviewer writes or tests are represented here.

All **2,020** Go/module hashes stay fixed through the final checks, including
the unchanged original 2,017. The complete
`go test -race -shuffle=on -count=1 ./...` passes in **403.955 seconds**, with
default timeout/concurrency (security **352.602 seconds**, Docker Control
**23.571 seconds**, lifecycle repository **1.569 seconds**). `go vet ./...`
passes in **6.156 seconds**; Provider/Product Contract locks pass in
**0.307/0.093 seconds**. The opt-in real probe runs separately above; the
untagged full command does not run it. The initial focused tagged component
command passes in **4.528 seconds**, with the real probe intentionally skipped
until its explicit opt-in invocation. No failure occurred in this checkpoint;
earlier checkpoints' preserved failures remain valid history. Unchanged PG
transactional tests and role-image builds are not repeated for this increment.
Final branch/HEAD/upstream/live remote remain at the fixed SHA above, the
original main checkout remains clean, and the exact real run's container and
volume label scope is empty.

Production resource/storage caps, closure metadata headroom, the complete new
source-bound resource/template/Profile, locked Coding inputs and actual
PG-to-Control claim consumption are still absent. Async Unknown/cancel/result
handling, output sealing/retention, daemon restart, late effects and exact
cleanup/release require their own implementations and real gates. The legacy
Cancel path, old plans/receipts, two issuers, frozen-R reuse rules and both
public holds remain unchanged. No third issuer, image rebuild, commit, push,
merge, publication or deployment is performed.

Slice 6 fixed steps: **1** historical bounded Guest E unchanged; **2** active,
with resource arithmetic/shared-scratch mechanism and constrained protocol
direction reviewed; **3** full live Profile-v2 inventory, original sixteen
scenarios and independent formal acceptance remain open; **4** not reached.
Phase 6 remains **5/15**. Next freeze the new production resource/template and
storage bounds, then implement the fresh claim through private Control with
its cancellation, uncertainty and cleanup paths rather than another unused
reservation ledger.

## 2026-10-10 Coding execution template and storage budget candidate

The next checkpoint starts from all **2,020** matching Go/module hashes on
`codex/product-v1-phase-6-hardening`, HEAD
`91fe315641779e6ea640632538309d63ad1b303f`. The sole writer adds four Go
files and updates only the existing shared-scratch integration test among
those starting files; all other 2,019 remain unchanged. Original main is
preserved. Private reports/logs/hashes are outside Git and migration inputs
in `control-exec-budget-20261010`. No old manifest or receipt is regenerated.

Independent read-only implementation_agent design review confirmed that the
Control 1 GiB declaration is shared by three ingress scopes and cannot be
treated as a Coding-only budget. The old 4096-record limit, 32 MiB single
state and two possible 1 MiB evidence files per allocation also do not prove
aggregate disk capacity. The initial proposed 256 MiB output region was
reduced to 192 MiB so dedicated closure and physical headroom each retain
their own positive 64 MiB region. This design correction preceded source
implementation, not a weakened gate after failure.

`CodingExecutionTemplate` is a distinct canonical source candidate with new
protocol/resource-mode identity. It fixes the locked image and static inputs,
separate resident and argv-as-PID1 command roles, source-derived scratch per
slot, private PID/IPC, no init/restart, disabled Docker logs and bounded private
shared memory. New/old decoders reject interchange; old Plan binding cannot
consume the new digest. Constructor copies do not mutate or alias original
template slices. Unknown/duplicate/noncanonical/oversized documents, changed
image/policy/resource values and scratch/slot aliasing reject.

Its candidate slot split is R=128 MiB/100 milliCPU/16 PIDs,
E=832 MiB/900/48, scratch data=32 MiB and metadata reserve=32 MiB, within the
existing candidate 1 GiB/1000/64 ceiling. The additional metadata check and
fixed `nr_inodes=4096` are in a new scratch policy; old resource/Plan/receipt
bytes remain unchanged. The memory reserve is not a measured kernel bound.

The frozen 512 MiB Coding child storage candidate contains output peak
192 MiB, allocation evidence 64 MiB, execution evidence 64 MiB, state plus
atomic replacement 64 MiB, close/cleanup 64 MiB and physical/transient
headroom 64 MiB. `ExecutionStorage` computes per-stream default/cap and two
output copies, rounded to 64 KiB, actual canonical request length (up to
2 MiB) plus a 32 KiB envelope, and independent byte/count checks. Six full
double-stream captures fit exactly; a seventh rejects. Sixty-four retained
command records is a count ceiling, not capacity for 64 maximum requests:
the 32 MiB single-state limit can reject sooner. Full-state encoding must
fit its reservation too. JSON-expansion coverage explicitly distinguishes
the domain/internal encoding from the unchanged 256 KiB public body cap.
These are pure arithmetic helpers, with no durable authority or release API.

The updated real Docker fixture consumes the new scratch options. Its
test-only ceiling remains 256 MiB/500 milliCPU/64 PIDs, now split into
resident 64 MiB/100/16, command 128 MiB/400/48, data 32 MiB and metadata
reserve 32 MiB. Cached PG OCI index/selected arm64 manifest/config/layers,
seccomp, socket inode, exact labels/IDs and existing no-network/high-UID
fixture protections remain checked. The locked Coding image is still absent
on this host; this fixture does not replace it or run a database.

Actual run `dbad81b12897bf7b5fb36b66` passes in **23.994 seconds** overall
(test **21.49 seconds**, package **22.875 seconds**):

- `statfs` verifies 33,554,432 data bytes and **4096 inodes**, together with
  the previous actual UID/GID/mode/mount-flag checks.
- A single bounded awk loop creates exactly the remaining empty-file inodes.
  With free inodes at zero and more than 7000 free data blocks, both `touch`
  and `mkdir` fail with ENOSPC. Existing shared data remains readable.
- Removing one empty file yields one free inode; creating a directory
  consumes it. Removing the test objects restores free inodes. The earlier
  data-capacity, noexec, shared visibility, replacement continuity and full
  unmount/remount loss assertions also pass.
- The command cgroup's limit is observed as 134,217,728 bytes. Before/full
  inode samples show memory.current **9,863,168 / 11,395,072**, shmem
  **12,288 / 12,288**, slab **582,304 / 4,478,448** bytes. These separate
  samples are not a synchronized attribution, worst case or host/kernel bound.
- Exact owned cleanup completes; no unrelated resource is removed.

Read-only final review accepts the candidate/arithmetic/real-mechanism scope
without a code blocker. It explicitly leaves the complete new receipt mode
and empty namespace, the other Control scopes' storage allocation, and
physical enforcement of all 1024 storage objects/bytes/transition peaks for
the future durable admission path. `Reserve` cannot issue a dispatch ticket.
The reviewer performed no writes or tests. Existing public holds, two issuers,
frozen-R reuse and old operator authorizations remain unchanged.

Final validation uses the same **2,024** frozen Go/module hashes. The initial
focused tagged component command passes in **5.738 seconds** (real probe
skipped without opt-in); the explicit actual probe is reported separately
above. The complete `go test -race -shuffle=on -count=1 ./...` passes in
**357.458 seconds**, using default timeout/concurrency (security package
**312.374 seconds**, Docker Control **22.641 seconds**, lifecycle repository
**1.596 seconds**). This full run includes the later JSON-expansion test and
does not include the opt-in real probe. Vet passes in **3.584 seconds**;
Provider/Product Contract locks pass in **0.382/0.114 seconds**. No test fails
in this checkpoint. Unchanged PG integration, role-image builds and earlier
containment probes are not repeated merely for reporting.

The first live-remote read times out and is preserved in the private remote
check record. One bounded read-only retry succeeds in **1.070 seconds**;
local HEAD/upstream/live branch SHA remain the fixed value above. The original
main checkout remains clean, no files are staged, and the actual run's container
and volume label scope is empty. The missing locked Coding image was confirmed
by local inspect; no registry pull, rebuild or credential change is claimed.

Slice 6 steps: **1** historical bounded Guest E unchanged; **2** active,
candidate template/budget and local inode mechanism reviewed; **3** full live
Profile-v2 inventory, original sixteen scenarios and independent formal
acceptance incomplete; **4** not reached. Phase 6 remains **5/15**. Next bind
the fresh receipt namespace and shared storage scopes, make the PG/Control
durable path consume the exact request/budget/claim, and complete the real
Coding sizing, cancellation, Unknown, restart and cleanup gates. No commit,
push, merge, publication, deployment or image rebuild occurs in this checkpoint.


## 2026-10-10 Coding private storage namespace

This step-2 checkpoint verifies all **2,024** starting Go/module hashes at
`codex/product-v1-phase-6-hardening`, HEAD
`91fe315641779e6ea640632538309d63ad1b303f`, before writing. The main agent
remains the sole source writer. Three new `internal/controlstorage` Go files
and the two held execution-template files produce **2,027** final Go/module
hashes; the other 2,022 starting files remain byte-identical. Original main,
unrelated cumulative work, historical raw evidence and migration manifests
are preserved. Private logs, script, hashes and reports live outside Git and
the migration package in `control-storage-namespace-20261010`.

Independent read-only implementation_agent investigation finds no implemented
Browser/Desktop Control receipt consumer in the current command: assigning
those scopes a “sufficient” 192 MiB each would have no workload basis. The
selected layout therefore binds Coding's existing 512 MiB partition and keeps
the other **512 MiB unallocated and unavailable**, with no non-Coding writer
API. The held `CodingExecutionTemplate` advances explicitly to protocol and
digest-domain **v2**, embedding the layout without a digest back-reference.
Previous candidate v1 documents reject; existing `CodingRuntimeTemplateV2`,
Plan v1, populated receipts, public validators and source evidence are not
upgraded or reinterpreted.

The new private file component is a prerequisite, not a receipt state machine
or dispatch capability. Its separate runtime binding records the fixed layout,
a fresh namespace and `control-execution-<namespace>` storage ID, Profile and
template digest strings, Control principal and owner UID/GID. These syntax and
persistent-equality checks do not validate the source documents. Initialization
requires an existing mode-0700 empty root, writes/syncs an exclusive permanent
lock marker before calling the external physical-empty check, and holds the
lock for the owner lifetime. The callback does not itself prove a source-bound
empty physical volume. That proof, full-mount coverage and exclusive subject
access remain adoption gates; an empty directory under an old volume is not
an acceptable substitute.

All I/O is relative to the held directory descriptor, with no-follow and
root/lock device/inode/owner/mode checks. The canonical manifest and complete
root-level inventory reject unknown fields/duplicates, extra files or
directories, symlinks, hardlinks, changed content, mode/source drift, copied
roots, missing state and unfinished temporaries. No old namespace is silently
initialized or repaired. Lifetime flock excludes another cooperating process;
it does not protect against an authorized same-UID process bypassing the API.

Actual publication consumes each class's byte, per-file and object limits.
Accounting uses the larger of rounded logical size and allocated blocks,
with 64 KiB units and a checked filesystem block size. The classified budget
is 448 MiB; root/lock/manifest/replacement metadata stays inside the separate
64 MiB headroom. State replacement permits one same-ID state, charges the
old and new copies, and retains the independent manifest peak. Immutable
objects publish exclusively, so even a same-name entrant after inventory is
preserved rather than overwritten. Output exhaustion cannot consume the
closure/state partition. Ordinary writes check current free filesystem space
plus the full closure/headroom allowance. This is not a kernel mount quota or
a guarantee against outside filesystem writers. There is no remove/expiry or
physical-execution-capacity release API.

Writing poisons the owner until the complete successful write and subsequent
inventory check. Errors leave bytes and temporary files in place. Object and
manifest updates are separately synchronized: interruption between them makes
reopen fail closed, **not** a recoverable two-file transaction. A consistent
state after a full manifest replacement can reopen, but yields no dispatch
ticket. Future PG/Control composition must retain the hold or obtain a reviewed
recovery protocol. Opaque closure documents are not signed/sealed no-effect
receipts; generic state bytes cannot establish Unknown, completion or release.

The initial Darwin focused race/shuffle/count=1 component test passes in
**24.952 seconds**. Final code additionally uses exclusive link publication
for immutable objects and tests the late same-name entrant. Independent final
read-only review accepts this correction and the bounded file-component scope;
the reviewer performs no writes or tests and leaves physical-volume admission,
same-UID isolation, receipt semantics and PG-to-Control dispatch open.

The first Linux fixture setup fails in **0.572 seconds** because Docker refuses
copying the test executable into the read-only root. No test ran. The owned
container was removed; the failed log/script/record are retained. The corrected
fixture uses separate exact-labelled local volumes for the executable and test
data, with a short preparation container setting data ownership. The actual
test runtime has a read-only root and executable volume, network none,
UID/GID **57000/58000**, dropped capabilities, no-new-privileges, no restart,
768 MiB memory/1 CPU/64 PIDs, and bounded private tmpfs. It uses only the cached,
exact PG image index as a fixture carrier; no database starts, no image is
pulled or rebuilt, and no locked Coding image gate is claimed.

Final Linux/arm64 run `5a430b8252294f4d9ae031cd1ba8f30f` passes in
**8.388 seconds** overall. It executes the cross-compiled final Go test binary
without race instrumentation, including actual file output exhaustion, close
space, double-state peak, restart, exclusive second-process lock, child-process
exit in a write window, input/source/file tampering and late entrant protection.
Both exact test-owned containers and both volumes are removed. This is Linux
local-volume file-component evidence, not power-loss durability, physical
volume identity admission, production capacity or a real Coding exec run.


The final **2,027** Go/module hashes remain unchanged through validation.
`go test -race -shuffle=on -count=1 ./...` passes in **553.057 seconds**, with
default timeout/concurrency (storage **163.989 seconds**, Docker Control
**41.844 seconds**, security **500.853 seconds**). Vet passes in **3.898 seconds**;
Provider and Product Contract locks pass in **0.339 / 0.096 seconds**. This
whole-repository run includes the final immutable-publication test. There is
no failed Go test in this checkpoint; the separate initial Linux fixture setup
failure above remains recorded. Unchanged PG integration, scratch/containment
probes and role-image builds are not rerun merely for reporting.

The live remote read succeeds in **2.051 seconds** and matches full local HEAD
and upstream at the fixed SHA above. Original main remains clean and nothing
is staged. The read-only reviewer is finished, no owned command is left
running, and both fixture run labels have zero containers/volumes. This is
uncommitted component work, with no push/merge/deployment/publication and no
old automation restored.

Slice 6 fixed steps: **1** historical bounded Guest E unchanged; **2** active,
private storage component and its independent review pass; **3** full live
Profile-v2 inventory, original sixteen scenarios and independent formal
acceptance remain incomplete; **4** not reached. Phase 6 remains **5/15**.
The next deliverable is the new source-bound Profile/receipt namespace and
common create/exec/retirement authority consuming this file boundary, followed
by atomic PG accepted-operation/occupancy and actual asynchronous Control
Unknown admission. No separate readable reservation ledger is a substitute.
Physical-volume/subject isolation, full other-scope allocation, correct locked
Coding input and actual sizing/cancellation/late-effect/restart/cleanup remain
required. Both public holds, the two-issuer decision and frozen-R reuse rules
stay unchanged.

## 2026-10-10 held common Control execution state

This continues Slice 6 step 2 after the private file namespace checkpoint.
The implementation checkout remains `codex/product-v1-phase-6-hardening` at
full HEAD `91fe315641779e6ea640632538309d63ad1b303f`, with cumulative uncommitted
work preserved. The previous 2,027 Go/module hashes matched before this change.
The user-confirmed single writer and approved read-only `implementation_agent`
review arrangement remain in force; no old automation resumes. New private
logs, frozen source hashes, failure records and fixture receipts are outside
Git and the migration package in `control-execution-state-20261010`.

### Implemented boundary

The new package-private `executionLedger` binds one fresh file namespace and
held execution template to Profile, Control principal, daemon/environment,
endpoint and policy digests. It has a new receipt protocol and source-derived
preparation/resident/four-volume names; workload UID/GID come from the selected
slot and are distinct from the file owner's binding. Valid digest strings are
not proof of a complete Profile, exclusive physical mount or same-UID isolation.
There is no command, Provider transport or PG caller for this component yet.

`controlstorage.ReadState` returns checked state bytes with the whole manifest
revision. `CompareState` validates the expected revision/state digest under
the same store mutex before publishing. A changed evidence object invalidates
the comparison too. Reopen requires a present canonical new state and restores
all retained record/output reservations. Missing, legacy, noncanonical,
under-accounted or mismatched state fails closed. An interrupted state/manifest
commit remains unrepairable here; no reset or migration path was introduced.

Create, execute and cleanup commit Unknown before bounded callbacks and release
the state mutex during external work, while retaining the lifetime file lock.
Create callback success alone is insufficient: completion also needs a new
typed observation of the exact four-volume/image/UID/GID resource binding,
matching current state revision/digest and the same process's successful create
return. Intervening retirement/state mutation or reopening rejects that path.
The new physical collector is intentionally not implemented by these tests.

All possible executions share the allocation state with retirement. Exact
claim closure blocks late replay and raises the observed fence; it cannot
downgrade Unknown or advance beyond an existing retirement fence. Retirement
requires a strictly newer generation and an operation distinct from create.
Retirement can persist while an execution callback is still in flight, but
cleanup cannot enter until there is neither Unknown execution nor an in-flight
callback. Callback return, cancellation, local drain and restart never release
the reservation. Owner close with an expired context retains its flock until
actual callback drain. No terminal, Released, deletion or slot-reuse path exists
yet; a local closure tombstone is not sealed no-effect evidence for PG.

### Independent review and component evidence

The read-only reviewer used the configured `implementation_agent` role
(`gpt-6-sol`, `xhigh`); the previously accepted lack of independent runtime
model metadata is unchanged. The reviewer wrote no files and ran no tests.
Review found two issues, both fixed with regression coverage: exact claim
closure originally did not advance the fence high-water mark, and retirement
originally allowed the birth generation/create operation. Final review found
no remaining component-level blocking issue and explicitly left physical
collection, full source admission and PG/mTLS composition open.

The first focused run failed before Docker Control compilation because the
test imported the image constants from the wrong package; the storage tests
passed separately. That failed **6.022-second** result is retained. Correcting
the import yields a **12.655-second** focused pass; the final fence/retirement
fixes pass race/shuffle/count=1 in **11.778 seconds**. Tests cover Unknown before
callback, replay/collision and stale fences, closure-before-arrival, retirement
while callbacks run, lock retention on bounded close, restart occupancy,
completion source CAS and old-resource rejection, publication uncertainty,
state drift, record exhaustion and preserved closure capacity.

The first Linux fixture setup fails in **0.268 seconds**, before any container
or volume creation: its script incorrectly compared Docker's index-level image
ID with a config digest. The actual index and platform descriptors were checked,
and the correction compares their separate index/manifest IDs. The failed
script, log and receipt remain preserved. It does not indicate a passed test
or authorize changing the pinned image inputs.

The corrected fresh Linux/arm64 fixture run
`d4c267b09b7945febb6369dc00227f98` passes in **2.523 seconds**. It uses only the
cached locked PostgreSQL index/platform as a carrier, with no database startup,
pull or rebuild. The integration-tagged test binary runs without race
instrumentation as UID/GID 57000/58000, with a read-only root and binary volume,
independent writable local receipt volume, network none, all capabilities
dropped, no-new-privileges, no restart, bounded memory/CPU/PIDs and tmpfs. The
image's declared PG data volume is explicitly covered by bounded tmpfs to avoid
anonymous volumes. The test verifies the high UID and RO/RW mount conditions
and runs the new ledger cases using synthetic completion/effect callbacks.
Both exact-labelled containers and both named volumes are removed; the run's
remaining container/volume sets are empty. This is actual Linux filesystem
component evidence, not real four-volume creation, Coding execution, physical
namespace admission, power-loss durability or a release gate.

The final **2,033** Go/module hashes remain frozen through validation.
`go test -race -shuffle=on -count=1 ./...` passes in **376.398 seconds**, using
default timeout/concurrency. Vet passes in **6.589 seconds**; Provider and
Product Contract locks pass in **0.357 / 0.091 seconds**. The initial failed
focused/setup runs above remain failed records, not part of these passes.
Existing unaffected PG, scratch/containment and role-image gates are not rerun
solely for reporting.

The live remote read succeeds in **1.791 seconds**, matching full local HEAD
and upstream at the fixed SHA above. The preserved original main checkout is
clean; no files are staged. The reviewer is finished, all owned validation
commands have exited, and the final Linux run has no remaining labelled
containers/volumes. Source changes remain uncommitted.

### Remaining work and fixed steps

Next provide a source-bound physical completion collector for the new exact
four-volume topology and full Profile/namespace admission, then atomically
accept the public operation and fresh claim in PG and consume only its initial
ticket through the new asynchronous mTLS Control action. The old three-volume
completion and PG intent/fence history cannot authorize this mode. Terminal,
cancel/natural-exit, late daemon effects, exact inventory cleanup and PG release
CAS still need real locked Coding inputs and independent gates. The cached PG
carrier is not a restored Coding image or inherited old acceptance.

Slice 6 fixed steps: **1** historical bounded Guest E unchanged; **2** active,
the common Control state is only a component checkpoint; **3** full live
Profile-v2 inventory, original sixteen scenarios and independent formal
acceptance remain incomplete; **4** not reached. Phase 6 remains **5/15**.
No public hold, issuer count, frozen-R reuse standard or old receipt changes;
no staging, commit, push, merge, publication or deployment is performed.

## 2026-10-10 held four-volume completion observer

This continues Slice 6 step 2 from the common Control state checkpoint. Full
HEAD remains `91fe315641779e6ea640632538309d63ad1b303f` on
`codex/product-v1-phase-6-hardening`. All previous 2,033 Go/module hashes
matched before writing; cumulative uncommitted work and the separate original
main checkout were preserved. The already-confirmed single writer and read-only
`implementation_agent` arrangement remain unchanged. Private logs, raw local
inspection receipts, review notes and source hashes are kept outside Git and
the migration package in `control-execution-observer-20261010`.

### Implemented boundary

The new package-private `executionUnixObserver` implements the common ledger's
collection port with its own four-volume transport, inventory and runtime
policy. It never casts the new template to the legacy three-volume Plan.
Only pure bounded archive/descriptor/projection helpers are shared. There is
still no command/PG/Provider transport caller that admits this held mode.

The source constructor binds the full template/allocation digest, verified OCI
index/manifest/config sources, seccomp bytes and root-owned Unix socket policy.
The socket identity is checked before and after dialing, across reused requests,
and after the complete response body has been read and closed. Each request
has a five-second bound; the whole observation, including gate waiting, has a
ten-second bound inside the create authority's existing expiry. API 1.55 admits
only exact inspections, binding-filtered lists and four exact root archives.
Bodies are bounded before SDK decoding, framing and duplicate/case-alias JSON
members are rejected, and archive permission is cleared on every return.

Collection requires preparation absence, one exact resident, and exactly four
label-bound local volumes. Scratch driver options must match the template,
including its bounded tmpfs data/inode configuration. Both configured and
realized mounts, per-role UID/GID/mode, selected image descriptor/config/rootfs
chain, resident limits, private namespaces, logging/init, seccomp and default
Linux path protections are checked. Every secondary SDK Resources field is
included in the safe rejection digest, including CPU period/quota, memory
reservation, OOM overrides, cgroup parent, blkio and ulimits. Only explicit
unset normalizations are accepted. The four empty-root tar responses must
contain exactly the expected directory; extra content, links or metadata fail.
Initial/final daemon, inventory and runtime projections must agree.

Receipt protocol `sandbox-runtime.coding-isolated-receipts.v2` now retains the
safe physical projections and locked raw OCI descriptor sources inline with
the same canonical state. Reopen recomputes the descriptor, inventory, runtime
and empty-root constraints rather than accepting caller hash strings alone.
The ledger deep-copies returned evidence before current-revision comparison.
Candidate v1 state cannot initialize, upgrade or reopen as v2; a new empty
namespace is required. No old receipt or manifest is rewritten, and no extra
proof/state multi-file transaction or repair algorithm is introduced.

This proves only what the source reads can establish. Docker Options and tar
metadata do not prove kernel tmpfs mount flags, actual data/inode capacity,
noexec, physical receipt-volume exclusivity, complete Profile validation or
independent operator acceptance. Exact Linux masked/read-only lists are frozen
from the local Docker 29.8.2 fixture; changed defaults fail closed and require
a reviewed compatibility/version decision before production admission.

### Review and observed checks

Read-only `implementation_agent` review used the configured `gpt-6-sol` / `xhigh`
role; the previously accepted lack of separate runtime model metadata remains
unchanged. The reviewer wrote no files and ran no tests. Review found and
closed three gaps: socket checking ended at response headers, secondary
resource controls were omitted, and masked/read-only path protections were
unobserved. Final review found no remaining blocking issue within this held
component scope and explicitly left positive Coding/kernel and full-source
admission gates open.

The first focused race/shuffle/count=1 check passes in **17.603 seconds**.
The socket/resource repair check passes in **34.622 seconds**; the later path
protection additions are covered by the final-source checks below. Positive
SDK tests use synthetic Docker responses with the locked raw OCI metadata,
not running containers. They cover the full 26-request chain, legacy topology,
missing/extra/replaced resources, archive owner/mode, descriptor/rootfs drift,
all secondary resources, path protections, socket header/body/close drift,
cancellation, retained-proof resealing and current-state completion races.

The first opt-in real-daemon command has no fixture-enable environment and
**skips**; its 4.119-second successful process exit is not a real test pass.
The correctly enabled tagged race check then passes in **6.344 seconds**.
It selects the explicit local Docker socket with same-file checks and performs
**11 GETs**: five successful Info/scoped-list reads and six exact 404 responses
for a fresh two-container/four-volume namespace. The collector rejects that
empty namespace and produces no completion. This test makes no mutation or
image execution and does not use/relax the production root-owned constructor.

A freshly built Linux/arm64 integration binary passes the high-UID local-volume
fixture without race instrumentation in **3.545 seconds**, run `88022f4e60dc46aeae541c49e72c37c1`.
The cached locked PostgreSQL index/platform is only a carrier, with no database
startup or image rebuild. UID/GID 57000/58000 execute on a read-only root and
binary volume with an independent writable receipt volume, network none,
capabilities dropped, no-new-privileges and bounded CPU/memory/PIDs/tmpfs.
The image's declared data mount is explicitly masked with bounded tmpfs.
The wrapper now also exercises the new observer and retained proof while its
Docker responses remain synthetic. The actual Linux file/owner/reopen evidence
is distinct from a real positive Coding gate. Both exact-labelled containers
and both volumes were removed; final run-owned sets are empty.

The final **2,040** Go/module hashes remain unchanged through validation.
`go test -race -shuffle=on -count=1 ./...` passes in **410.539 seconds**
with default timeout and concurrency; vet passes in **5.090 seconds**.
Provider and Product Contract locks pass in **0.927 / 0.224
seconds**. Formatting and whitespace checks pass. These are final combined
source results, not a sum of subtask passes. Unaffected PG, issuer, containment
and role-image gates were not rerun for reporting.

The first live remote read exits 128 after **18.022 seconds** and is retained
as a failed check; its failure cause was not established. One bounded recheck
succeeds in **1.633 seconds**, with full local/upstream/live remote SHA matching
the fixed HEAD above. The preserved main checkout is clean and nothing is
staged. The reviewer has finished; the owned test/fixture processes have exited
and the fresh labelled fixture resources are absent. Source remains uncommitted.

### Restored inputs and next boundary

The public locked Coding index
`sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1`
was downloaded successfully in **16.783 seconds** for `linux/arm64/v8`.
Separate local index and platform inspection match the selected manifest
`sha256:a3d9567ee49482582baff67cc3b8679bbe08b79909f7375145004f1c92b4d5f3`.
This is new-host artifact availability, not merely retained JSON metadata.
The image was **not executed**. Fresh supply/signature/provenance/vulnerability
checks were not run; the relevant verification tools have not been restored.
No old scan/attestation pass or exact historical binary is inherited. No other
role/Desktop image set was rebuilt and no credentials were changed.

Next restore only the verification inputs needed for this pinned Coding image,
then run the new positive four-volume/physical-namespace gate with fresh run
bindings and complete Profile admission. The remaining production composition
still requires atomic PG accepted-operation/claim and only its initial ticket
through asynchronous mTLS Control dispatch, plus terminal/cancel/natural-exit,
late-effect quiescence, exact cleanup and PG release CAS. No readable PG
history, old three-volume proof or downloaded image alone authorizes it.
The other Provider/Browser/network/UID/GID/Guest and original sixteen scenarios
remain on their existing fixed queue.

Slice 6 steps: **1** historical bounded Guest E unchanged; **2** active with
this observer component complete, real/source/dispatch boundaries still open;
**3** full live Profile-v2 inventory, original sixteen scenarios and independent
formal acceptance incomplete; **4** not reached. Phase 6 remains **5/15**.
Both public holds, the broker/general two-issuer decision and frozen-R reuse
rules remain unchanged. No staging, commit, push, merge, release or deployment.

## 2026-10-10 Coding image supply revalidation

This is the next Slice 6 step 2 checkpoint after the four-volume observer.
All 2,040 prior Go/module hashes and six documentation hashes matched before
work. Branch `codex/product-v1-phase-6-hardening` remains at full HEAD
`91fe315641779e6ea640632538309d63ad1b303f`; cumulative work is preserved.
The original main checkout remains separate. The user-confirmed single writer
continues; no old automation is resumed. New private tool archives, original
image exports, bundles, scan/SBOM, raw logs and failed checks are outside Git
and the migration package in `coding-image-supply-20261010`.

### Inputs restored and checks actually performed

Only the required macOS arm64 verification tools were restored: GitHub CLI
2.102.0 and Trivy 0.74.0. Official immutable-release asset API SHA-256 values
and published checksum files match their downloaded archives. Extracted binary
hashes are recorded. They live in the private checkpoint, not a global tool
installation. This is release-checksum verification; retained Trivy Sigstore
asset bundles are not claimed as independently verified tool signatures.

The historical image is still the fixed index
`sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1`,
selected arm64/v8 manifest
`sha256:a3d9567ee49482582baff67cc3b8679bbe08b79909f7375145004f1c92b4d5f3`,
config `sha256:eb764728c62bef0c3ad87bf76d51e7c06e652c4e8ba77656520e9d8abadce97c`.
Docker's selected-platform export succeeds, but omits the original dual-platform
index blob; it cannot by itself satisfy that original-index proof. The
6,524,928-byte selected export and its limitation record are retained. A new
ordinary full save contains the exact original index, matching the separately
fetched registry bytes. No manifest was synthesized or rewritten to pass.

The existing `ReadOCIArchiveDescriptorChain` and `VerifyOCIArchiveLayers`
validators pass the complete private export in a **15.896-second**
race/shuffle/count=1 check. A recorded private Go test overlay compares the
original index/manifest/config with the unchanged source fixtures and checks
compressed-layer digests and rootfs diffIDs; no test file is added to the
repository. The selected scan export uses those same manifest/config/layer
bytes. The actual broker was read from the layer without execution: static
`go version -m` reports Go1.26.5, Linux/arm64, CGO disabled, and broker SHA-256
`dfc35a9fdd33b9dcf2f4c2f0586f4407ff9a32dddf4a0156eacadc43d99e77f7`.

The initial online `gh attestation verify` exits **4** in **0.130 seconds**
because GitHub CLI is not logged in. That is a preserved environment failure,
not a cryptographic rejection. No login, token extraction or credential
configuration follows. An anonymous pull-scoped registry token fetched only
the public locked index, provenance manifest and bundle; the token is not
retained in the checkpoint. The manifest matches the locked digest
`sha256:bf31ce86deb5b7f6d2ba374753042e1e2a95c299bb5e6e025976249ddd4536a0`;
its bundle matches
`sha256:0f421e0b8974e4538065e673e95e947f2c4fee55daea8f59ec36b316ca030b97`.

Offline-bundle `gh attestation verify` succeeds in **21.980 seconds** on the
exact raw index file, enforcing repository, signer workflow, source digest,
`refs/heads/main` and hosted-runner restriction. The verified signed certificate
is additionally checked for exact GitHub OIDC issuer, workflow SAN, repository,
source `cf1830e9bbfcd08d6f171e60f67d949d839e1069`, ref and run
`35171475925/attempts/1`. Its sole subject is the fixed index, predicate is
SLSA provenance/v1, and the verified Rekor entry is index `2870923506` with
signing time 2026-09-17 01:41:54 UTC. This is a fresh cryptographic verification
of historical provenance, not new build/publication or an independent
standalone OCI image signature. The latter is not established by this check.

### Failed vulnerability gate

Trivy scans the selected original archive without starting a container, using
explicit empty config/ignore rules, all severities, OS and Go vulnerability
scanners, full package inventory and disabled telemetry. The scanner completes
successfully in **61.770 seconds**; process exit zero means report generation,
not vulnerability acceptance. DB v2 was fetched during this run from the
scanner's standard mirror; metadata records UpdatedAt
`2026-10-10T07:01:36.894063512Z` and DownloadedAt
`2026-10-10T08:19:14.945358Z`. Scanner binary, raw DB, metadata, command and
report hashes are bound in the private failed `supply-gate.json` receipt.

| Actual arm64 scan target | HIGH | CRITICAL | Other findings |
| --- | ---: | ---: | --- |
| Alpine 3.23.5 (16 packages) | 2 | 0 | 7 MEDIUM, 12 LOW |
| Go1.26.5 terminal broker (5 packages) | 11 | 0 | 5 MEDIUM, 1 LOW, 5 UNKNOWN |

The total is **13 HIGH occurrences / 12 distinct HIGH CVEs**, zero CRITICAL,
12 MEDIUM, 13 LOW and 5 UNKNOWN. No suppressions, unfixed exclusions, accepted
exceptions or application reachability conclusions are applied. The two OS
HIGH occurrences are CVE-2026-14456 in `libcrypto3` and `libssl3` 3.5.7-r0;
Alpine records 3.5.8-r0 as a fixed version. The eleven Go HIGH CVEs are
CVE-2026-33818, -39821, -46600, -56853, -56858, -56859, -56860, -56862,
-78667, -78669 and -97031. The last three require the Go1.26 line's 1.26.9
fixes; the original planned 1.26.8 candidate is also inside those affected
version ranges. Official [Go](https://pkg.go.dev/vuln/GO-2026-6609)
[advisories](https://pkg.go.dev/vuln/GO-2026-6611)
[confirm](https://pkg.go.dev/vuln/GO-2026-6607) those version boundaries;
[Alpine's security database](https://secdb.alpinelinux.org/v3.23/main.json)
confirms the OpenSSL package correction. Version findings are not proof of
reachable/exploitable behavior in this broker.

The same complete scan report converts to a private CycloneDX inventory with
23 components. It is **unsigned**, point-in-time inventory; it is neither an
original release SBOM nor signed provenance or Slice 7 completion. No duplicate
scan or unrelated role/Desktop build was run to make the report look green.
Only arm64/v8 was scanned; amd64 is unexecuted.

### Decision and remaining boundary

The restored old image's fresh vulnerability gate **fails**. Therefore no
Coding container or new four-volume positive scenario is started. The static
image identity lock would not automatically reject these findings; it remains
unchanged and does not override the failed gate. No old manifest, receipt,
image identity, Profile hold, issuer count or frozen-R reuse rule is changed.

A separate [Coding candidate repair proposal](../plan/product-v1-phase-6-coding-image-candidate.md)
selects a clean source and limits the remedy to a new recipe/lock with a repaired
base and broker. The source Go1.26.8 instruction is explicit, so a candidate-only
Go1.26.9 exception needs the user's decision before use. Official download
metadata and archive SHA-256 were retrieved, but no Go1.26.9 toolchain was
downloaded/installed and no candidate was built. The new base digest is not yet
selected. New candidate trust/template/Profile/receipt binding and affected
runtime evidence still require independent review. Existing historical
publication is not replaced, and an unsigned local candidate cannot inherit it.

Production Go/module source is unchanged in this turn; the previous frozen
2,040-file full race result (**410.539 seconds**), vet and Contract results
remain evidence for that same source. They were not rerun just for reporting.
The new actual archive check and scanner/verifier results above are separate
input evidence. Documentation changes record the failed gate and proposal.

An implementation_agent reviewer, uninvolved in these checkpoint writes,
directly read the raw scan, verified attestation, DB metadata, archive check,
broker metadata, SBOM and official fix records. The reviewer independently
confirmed the counts and identity bindings and found no blocking overclaim in
the audit or candidate proposal. This read-only review did not run tests,
scans, network or Docker operations and is not independent operator acceptance.
The initial summary-only review was superseded by this raw-evidence review.
Local HEAD, upstream and a fresh remote query all resolve to
`91fe315641779e6ea640632538309d63ad1b303f`; the remote query took
**1.250 seconds**. The original main checkout remains clean; cumulative
implementation-checkout changes are preserved and unstaged.

Slice 6 steps: **1** historical bounded Guest E unchanged; **2** active, with
archive/provenance recovery passing but vulnerability gate failing and positive
Coding execution held; **3** full live Profile-v2 inventory, original sixteen
scenarios and formal independent acceptance incomplete; **4** not reached.
Phase 6 remains **5/15**. No staging, commit, push, merge, publication or deployment.

## 2026-10-10 repaired Coding candidate and managed tools

The user explicitly approved Go1.26.9 **only for a new Coding candidate**,
repair/build/verification of that candidate, and retention of the repository's
Go1.26.8 and historical publication locks. A later user instruction requires
mise or Docker for development environments. Explicit `mise install` now manages
Go1.26.8, Go1.26.9 and Trivy0.74.0, without global activation, PATH/shell changes
or repository-wide toolchain replacement. All 15,036 files of the earlier
Go1.26.8 extraction and all 15,045 files of the candidate Go1.26.9 extraction
match their managed installations byte-for-byte. Those two redundant,
session-created extracted directories were removed; original archive/verification
records remain. Historical receipts retain their historical paths. Both brokers
were rebuilt through mise and match the already-built candidate brokers exactly;
unchanged images were not rebuilt again merely for that manager transition.

### Locked inputs and distinct output identity

The separate [candidate recipe and lock](../../profiles/coding-shell/candidate/README.md)
use a new `git archive` of clean source
`91fe315641779e6ea640632538309d63ad1b303f`, tree
`15070834772f766c46a62a61a7aaa8c5afd5411b`. The source archive, module files,
official Go archive, recipe, base and broker/output bytes are hashed separately.
The cumulative dirty implementation checkout is not mislabeled as clean source.

Alpine 3.23.6 is frozen at index
`sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0`,
with amd64 manifest
`sha256:1f3591b8a02ea153f41c5bba878ad477f63ab3d19349762cb77504db02a23e15`
and arm64/v8 manifest
`sha256:ae959799024a09da597284763c417a6e820e020fad0634c5267cf4f125e682bf`.
Raw index/platform/config bytes, compressed layers, diffIDs and installed package
inventories match those locks; both platforms have 16 OS packages including
`libcrypto3`/`libssl3` **3.5.8-r0**. Selection through the official registry and
exact digest checks is not a claim of a separately verified base signature.
No mutable `apk add` or extra dependency closure was introduced.

The repack runs in Docker with disabled build-step network, zero source epoch,
no cache reuse, no push and no attached generated attestation/SBOM. Each platform
was built twice; each pair's full OCI tar, manifest, config and layer bytes match.
BuildKit's local metadata is unsigned build information, not signed provenance.

| Platform | New candidate manifest | New OCI config |
| --- | --- | --- |
| arm64/v8 | `sha256:32438af3c0972f77c45bbcd2ef293c90a923f4366621719a52560035605d61ee` | `sha256:ee521c6e999066eaba76c3e32f20db1b0767893ea9da0ecac1e4fe4db85a8af0` |
| amd64 | `sha256:ac02197a8fc72146f92b9970cccfae22eef9ac8f50ad5e3092e0423533946cb9` | `sha256:8c3d13d369da6c97698cd64a07cbdfa58b5fae648250c5fea45320a957cd51b3` |

The native arm64 Docker builds took **15.370 / 1.330 seconds**; amd64 builds
using the arm64 host's emulated Docker support took **1.481 / 1.127 seconds**.
The latter are not native amd64 runtime gates. Image labels explicitly identify
a local candidate, and the historical published image remains unchanged.

### Actual checks and retained finding

The clean broker source passes its Go1.26.9 race/shuffle/count=1 package tests
(**11.682 seconds**) and vet (**2.902 seconds**). Offline module verification
passes (**1.020 seconds**). Broker build metadata for both architectures reports
Go1.26.9, Linux, CGO disabled and the locked dependency versions. The existing
repository descriptor/layer validators pass both actual candidate archives in
a private Go overlay check under mise-managed Go1.26.8 (**7.124 seconds**).
The overlay does not add repository source or grant image admission.

Mise-managed Trivy0.74.0 has the same binary hash as the previously verified
official release. Each actual candidate is scanned with all OS/Go packages,
all severities, empty config/ignore rules and no exceptions. The same still-current
DB bytes are copied into a new private cache, checked by SHA-256 and used with
`--skip-db-update`; UpdatedAt is `2026-10-10T07:01:36.894063512Z`, NextUpdate is
`2026-10-11T07:01:36.894063051Z`. This is explicit reuse of the current database,
not a claim that another DB was downloaded. Each OCI layout's bytes are bound
to its original tar; descriptors and layers were not rewritten for scanning.

Both platforms have **0 HIGH, 0 CRITICAL and 1 MEDIUM**. The remaining finding
is **CVE-2026-85091**, `zlib` **1.3.2-r0**, with reported fix **1.3.2-r1**.
It remains visible and unignored; no application reachability or zero-vulnerability
claim follows. The Go broker reports no findings in this scanner/database
snapshot. Full-package JSON is retained, and each report is converted to its
own unsigned CycloneDX SBOM without rescanning. HIGH/CRITICAL input checks pass;
this does not establish complete supply, signature or production release gates.

### Native diagnostic smoke and failure preservation

Independent read-only review of the actual input/build/scan records found no
rule requiring zero MEDIUM findings before this bounded local diagnostic.
The reviewed harness rechecks the complete archive hash before import, separates
Docker manifest store ID from the OCI config digest, binds selected descriptors
and ordered diffIDs, and uses a fresh run-owned container/input fixture.

The native arm64 diagnostic passes in **5.077 seconds**. It runs the actual
candidate with a high numeric UID/GID, read-only root, no network, all
capabilities dropped, no-new-privileges, bounded memory/CPU/PIDs, read-only input
and private data/scratch tmpfs. It verifies input/root write refusal, writable
data/output, scratch owner/mode **0700**, a byte-identical BusyBox ELF with
**0755** bits rejected with status **126** on `noexec`, live zero capabilities,
and an actual terminal-broker PTY round trip plus a separate shell-written marker.
The exact run-labeled container is removed and the scoped cleanup list is empty;
the tiny read-only input fixture and raw evidence are deliberately retained.

A final independent implementation_agent review directly checked the raw
image/container inspections, command/exit ledger, security and PTY output and
empty cleanup list. It found no blocking issue in the bounded diagnostic-pass
claim. The reviewer wrote no files and ran no tests, scans, network or Docker;
this is technical evidence review, not an independent operator signature.

This smoke uses diagnostic 128 MiB / 0.25 CPU / 64 PID limits, not the new
execution template's resident/command budget split. Its separate tmpfs mounts
are not the four named volumes or a physical receipt namespace. It proves
neither native amd64 runtime behavior nor resource stress, inode capacity,
restart continuity, the complete Profile or formal operator acceptance.

Failed attempts are retained: the system Python lacked the newer safe-extraction
keyword (no extraction occurred before the compatibility fix); direct registry
blob HTTPS timed out (exact Docker pulls/exports supplied the same locked bytes);
an incorrect mise binary-lookup invocation failed before scanning; Trivy rejected
pure OCI tar input before the exact directory-layout scan; and the first smoke
incorrectly expected Docker store ID to equal OCI config digest. That smoke
stopped before container creation, retained an empty cleanup list, and was
corrected against the repository's existing descriptor-based identity model.
No production validator was relaxed to hide these failures.

### Remaining boundary

The candidate is unsigned and not selected by `LockedPublication`,
`CodingRuntimeTemplateV2`, `CodingExecutionTemplate`, a full Profile or production
startup. The next result is an independently reviewed, source-bound candidate
admission protocol and new template/receipt/Profile binding, followed by the
actual four-volume scenario. Candidate diagnostic success does not inherit the
historical publication or qualify the unresolved zlib finding for production.

All 2,040 implementation Go/module files remain unchanged from the previous
full-suite snapshot. Its full race/vet/Contract evidence is reused for those
same bytes, not reported as newly run. This turn changes only candidate
recipe/lock/output metadata and documentation. No staging, commit, push, merge,
publication, deployment, new issuer or frozen-R reuse-rule change occurred.
Slice 6 step **1** remains historically bounded; **2** continues with this
candidate's bounded checks passed; **3** full live inventory/original sixteen
scenarios/formal independent acceptance remains incomplete; **4** has not been
reached. Phase 6 remains **5/15**, with both public holds closed.

## 2026-10-10 held Coding candidate template and receipt binding

The repaired unsigned candidate now has a source-owned identity record and a
separate `CodingCandidateExecutionTemplate` v3. The held common Control ledger
uses receipt protocol v3; old runtime-v2 and execution-v2 templates keep their
original bytes and historical publication. This is component implementation,
not full Profile adoption, publication, production admission or Slice 6 closure.

### Record, template and observation boundary

The identity embeds exact original inputs/artifact/recipe bytes, a sanitized
historical evidence index and original arm64/amd64 OCI manifest/config metadata.
Source-owned hashes freeze the clean broker commit/tree/archive, separate recipe,
Go1.26.9 archive, base and platform output, broker, scan/SBOM and evidence records.
The recipe is not relabeled as part of clean source 91fe315. Matching this
identity proves agreement with the reviewed records; it does not run a build or
scanner, restore OCI layers, sign an artifact or authenticate an independent
operator. Historical scan results retain the unignored zlib MEDIUM. There is
no caller-selected candidate digest, exception flag or fresh-pass API.

The new canonical type has its own protocol/digest domain and preserves the
four-volume policy, limits, storage accounting, ordered unique high-UID slots
and security configuration. Local image reference/store ID equals the selected
OCI manifest; the template selected-manifest field stays empty under the
existing manifest rules. Docker container descriptor comparisons use the actual
manifest digest/size, never the empty template field or config digest.

Real Docker image inspection confirms this local manifest's descriptor omits
platform, even with a platform query. The observer requires Docker OS/arch and
the original OCI config platform, plus the container selected-manifest platform.
An optional descriptor platform must agree if present. The existing socket pin,
GET allowlist, response limits, cancellation, four-volume/runtime checks and
retained proof recheck are preserved. Candidate identity is included in the
template/binding and hence allocation, resource, claim and completion digests.
Reopening v1/v2 state fails; trying to initialize a populated namespace also
fails and leaves its old bytes unchanged.

### Independent review and bounded checks

The existing implementation_agent reviewer performed independent read-only
design and code review, without implementation or test execution. It accepts
the held component scope with no blocking findings, and required the local
manifest/platform treatment above. Future candidate lock changes must separately
review the fixed UID, command, environment and working-directory policy; an
updated hash is not permission to broaden that policy. No full Profile or
operator acceptance is inferred from this review.

Managed Go1.26.8 performs all repository checks. This turn installs no toolchain,
changes no global mise/PATH/shell settings, and rebuilds or rescans no image.
The already-built candidate alone remains Go1.26.9. New checks:

- Focused race/shuffle/count=1 identity/template/ledger/observer tests pass in
  **44.261 seconds**, including caller identity substitution, platform/config/
  store-ID confusion, legacy protocols, state reopen and unchanged unsafe-policy
  rejection. The first compile attempt failed on an unused import; it was fixed
  without changing behavior or weakening a check.
- Explicit tagged race checks pass in **6.689 seconds**. Both private original
  candidate archives are reopened, exact full-file hashes and embedded original
  descriptor bytes match, and actual compressed layer/diffID chains pass. This
  proves retained input availability, not a new build or fresh vulnerability gate.
- In the same tagged run, the actual daemon rejects a fresh empty scope using
  eleven bounded GETs (five successful info/list reads and six missing objects).
  Two additional exact plain/platform image GETs accept the new candidate's
  descriptor/config policy with missing descriptor platform. No Docker object
  is created or mutated, no Coding command is executed, and no four-volume
  completion or runtime acceptance is produced.
- `go vet ./...` passes in **14.198 seconds**; Provider and Product Contract
  lock verification pass in **1.612 / 2.133 seconds**.

The first full-suite attempt exposed mise's injected `GOROOT`, rejected by two
existing Conformance Runner assertions. It is a failed run, terminated after
**211.701 seconds**, not a pass or timeout workaround. Only its verified owned
Go/test processes were stopped. The invocation now uses
`mise exec go@1.26.8 -- env -u GOROOT ...`, preserving the managed executable
while removing that override only inside the child process. The two failing
Conformance tests pass in **5.077 seconds**; no product code or assertion was
changed for this environment correction.

The next full-suite invocation completes in **504.052 seconds** but fails five
packages' permission-rejection fixtures. The evidence wrapper's umask 077 was
inherited by tests, silently changing their requested unsafe 0644 files to
0600. That run is also a failure, not a pass. The wrapper now keeps its evidence
files private while setting only the test child to umask 022. All five failing
packages' exact cases pass in **3.084 seconds** with unchanged code/assertions.
The scoped `GOROOT`/umask requirements are recorded in `docs/development.md`;
neither changes global configuration or production permission validation.
The final `go test -race -shuffle=on -count=1 ./...` run passes in
**346.761 seconds**, using managed Go1.26.8, a scoped unset `GOROOT` and test-child
umask 022. The frozen 2,054 source/module/candidate entries remain byte-identical
to the reviewed snapshot. Default test timeout, concurrency, product code and
test assertions remain unchanged throughout these environment corrections.
Both preceding failures remain in the private evidence record; the final pass
does not relabel them as successful runs.

### Remaining authority and next result

The complete Profile still has an old `CodingRuntimeTemplateV2` field; its
slot inventory, whole-topology resource budget and command `BindPlan` path are
not v3. `controlstorage.Binding.ProfileDigest` validates syntax only. Local slot
uniqueness and a substituted Profile hash cannot establish complete principal
collision checks, physical receipt-volume identity/exclusivity or admission.
The next result must bind the new candidate/template and revised resources into
the complete source-owned Profile and physical namespace, then prove the actual
four-volume positive/failure scenarios with new run identities and review.
Kernel scratch flags/data/inodes/noexec, UID/GID, workload headroom, replacement
and exact cleanup remain open, followed by atomic PG claim and asynchronous
mTLS Control composition. Old counts are not a new live inventory.

Private logs, original failed commands, reviewed source hashes and reports live
outside Git and the migration package in `coding-candidate-binding-20261010`.
No stage, commit, push, publication, deployment, new issuer or frozen-R reuse
change occurs. Step **1** stays historically bounded; **2** remains in progress
with this component completed; **3** full live inventory/original sixteen
scenarios and formal independent acceptance are incomplete; **4** is not
reached. Phase 6 remains **5/15** with both public holds closed.


## 2026-10-10 held Coding Profile mode and kernel root

The next source component adds an explicit candidate-v3 alternative inside the
complete Profile-v2 field chain and a separate kernel-checked Store path.
It does not activate the Profile, derive a production permit or admit a physical
receipt volume. The root session remains the sole writer; implementation_agent
performs independent read-only design and code review. The previously completed
candidate locks, old runtime/execution templates, public Provider command holds,
two issuers and frozen-R rules retain their original boundaries.

### Complete declared field binding

`ProfileV2.CodingExecution` is optional only for the historical mode. In new mode
it has an explicit v3 protocol, exact candidate template, fresh namespace policy
and new capacity record, while the old Coding template and budget must be fully
zero. Mixing them rejects. When absent, historical canonical Profile encoding
and old three-volume checks stay unchanged. Neither template nor Profile is
stripped or converted into an old accepted type.

The complete source validation still checks principal/TLS/CRL/network/Control/
Scanner/private-storage/PG fields and the final canonical Profile digest. The
new Coding checks bind Provider and Control platform, both high-UID/GID slots,
all declared static identities/storage IDs and Browser/Desktop slot identities,
plus eight Coding volume prefixes including scratch. Browser/Desktop dynamic
volume prefixes are absent from the current slot schema: this result cannot
prove those undeclared names or replace the final live inventory. The old static
count remains a source-field roster, not a current runtime count.

The new budget counts all declared static roles, Browser/Desktop workloads and
gateways, external services and double-parse headroom. For each of two Coding
slots it preserves the frozen 1 GiB/1000 milliCPU/64 PID ceiling, covering resident
and command limits plus scratch data/metadata. It records two residents, two
possible command containers, two stopped preparation carriers and eight volumes.
The Control filesystem declaration remains 1 GiB; Coding has 512 MiB and the
other 512 MiB is explicitly unallocated with no writer. This is declared
arithmetic, not measured host/kernel/daemon/workload or all-scope capacity.

Storage Binding is derived after the complete field check from that Profile's
final digest, candidate template/layout, fresh namespace/storage ID and Control
principal/UID/GID. It is not embedded back into the Profile preimage. The public
method first requires public Profile admission and remains closed. Synthetic
positive tests exercise the private complete-field derivation and reject arbitrary
Profile hashes, mixed modes, owner/platform/image substitutions, static/dynamic
UID/GID collisions, scratch/static storage aliases, omitted unrelated network/
trust/resource fields, shared receipt mounts and understated budgets.

### Actual-fd kernel checks and remaining physical boundary

`InitializeKernelChecked` and `OpenKernelChecked` accept no success callback.
Linux observation reads the actual pinned Store fd via stat/statfs/statx plus a
bounded mountinfo document. It requires an exact private whole filesystem root,
high-UID/GID mode 0700, a persistent ext4/XFS filesystem, nosuid/nodev/noexec,
a supported allocation unit and observed data geometry between the Coding quota
and Control ceiling. Fresh initialization also checks available space. Ordinary
subdirectories, shared visible aliases, tmpfs/overlay, missing flags, wrong
ownership and unbounded geometry reject before namespace-marker creation.

The reviewer identified that matching path/fd device and inode alone was
insufficient against mount replacement. The final code additionally obtains the
live path's statx mount ID and requires it to match the pinned fd, device and
inode on every anchor check. Negative tests cover the same-inode/different-mount
case and missing mount-ID facts. Mount ID is a session anchor; the manifest
retains stable root/filesystem/source geometry, so a new session does not require
an identical mount ID. Reopening checks all retained facts; no legacy manifest
can upgrade itself or strip kernel mode through the old opener. Existing
file-only APIs retain their component semantics and never become physical
admission. Darwin refuses the Linux-only path.

The kernel references distinguish filesystem data-block observations from mount
root/path identity: [Linux proc documentation](https://www.kernel.org/doc/html/v6.7/filesystems/proc.html)
and [Linux statfs documentation](https://www.man7.org/linux/man-pages/man2/statfs.2.html).
Neither a bounded statfs reading nor one visible mount proves exclusive ownership
in other namespaces, an unchangeable quota, absence of host writers or exact
Docker volume identity. Those remain explicit blockers to physical admission.
The next requirement is a closed source-bound Docker volume/Control mount/sole-
consumer observation chain and a reviewed persistent capacity backend, followed
by real positive/failure four-volume scenarios. No arbitrary digest, callback or
synthetic positive proof may substitute for that chain.

### Validation and real negative evidence

All repository checks use existing mise-managed Go1.26.8 with child-only unset
GOROOT and umask 022; evidence remains private. No toolchain installation, global
activation or image rebuild/rescan occurs. Only the already-built candidate
retains its approved Go1.26.9 origin.

- Initial complete-Profile and old-mode focused checks pass in **4.095 seconds**.
- Darwin Store race/shuffle/count=1 passes in **25.820 seconds**.
- Final focused Profile/old-budget/kernel-manifest race checks pass in
  **28.405 seconds**.
- The final tagged Linux/arm64 test binary is cross-compiled with Go1.26.8 and
  runs in the existing exact Coding candidate image. A fresh named local volume
  is prepared by a short root container with only CHOWN/FOWNER added, which exits
  and is removed before observation. The test subject uses high UID/GID, no
  capabilities or network, read-only root, no-new-privileges and bounded
  memory/CPU/PIDs. It receives only the fresh receipt volume and a read-only
  test-binary bind. This fixture does not start a Coding workload.
- Initial Linux pure checks and real ordinary-volume refusal pass, with exact
  cleanup, in **1.074 seconds**. After the mount-ID correction, a fresh final run
  repeats the affected checks, including the new mount-ID negative, in
  **0.646 seconds**. The actual local volume lies on a filesystem larger than
  1 GiB, is rejected and remains empty with no namespace marker. Both runs remove
  their exact owned containers/volume and finish with zero run-labeled objects.
  The final result supersedes only the affected implementation evidence; original
  logs are retained. Linux tests are non-race binaries; positive kernel facts
  remain synthetic, not a positive physical-volume or quota test.
- `go vet ./...` passes in **14.386 seconds**. Provider and Product Contract
  locks pass in **1.823 / 1.464 seconds**.
- The tagged Linux/amd64 test binary compiles in **6.842 seconds**; this is
  cross-compilation only, with no native amd64 execution claim.
- Final `go test -race -shuffle=on -count=1 ./...` passes in **493.025 seconds**
  with the default timeout and concurrency unchanged. The 2,063 frozen
  source/module/candidate entries match the reviewed final snapshot. No later
  source edit invalidates that run; the remaining updates record its result.

After correction, independent read-only review reports no remaining blocker for
this held component. It explicitly does not accept Docker identity/exclusivity,
stable hard quota or positive physical admission. Raw commands/results, source
hashes and private reports reside outside Git and the migration package under
`coding-profile-namespace-20261010`.

Step **1** remains historically bounded. Step **2** continues with the declared
Profile/kernel component and actual negative evidence; physical admission is
blocked on the requirements above. Step **3** full live inventory/original sixteen
scenarios/formal independent acceptance is incomplete. Step **4** has not been
reached. Phase 6 stays **5/15**. No stage, commit, push, publication, deployment,
production permit or old evidence rewrite occurs.


### 2026-10-10 held Docker consumer observation and dedicated backend

The [Control storage backend component](../plan/product-v1-phase-6-control-storage-backend.md)
adds a separate bounded global Docker observer and a fresh dedicated Store
mode. It checks stopped consumers, exact volume/Control mounts, unsafe aliases
and device authority, live root-fd facts and fixed loop geometry. A Linux
operator-only helper prepares and seals a one-GiB ext4 image offline, with
source inode and initial-byte binding. This does not yet prove physical admission:
shared-VM loop/device operations await explicit scope authorization, complete
source-inode/volume composition and real positive/failure gates. Current real
Docker evidence covers ordinary-volume and stopped-consumer refusal only.
The new offline image is not an attached quota backend, a release image or an
old receipt upgrade. Public Profile/provider v3 holds and Phase 6 **5/15** remain.


### 2026-10-11 authorized real backend diagnostic; admission remains blocked

The user authorized the exact shared-VM loop7 diagnostic. Fresh census, original
image hash/dev/inode checks and atomic attach passed. High-UID raw ext4 writes
survived two container replacements; physical ENOSPC and ELF noexec refusal
passed. The mounted-device O_EXCL test returned EBUSY, and the helper refused
detach while preserving the exact backing inode. These are separate component
facts, not Store quota or full Control acceptance.

The positive Store admission test **failed**: actual mountinfo carried
`master:5`, and sysfs exposed `/receipt.ext4` instead of the required absolute
backing path. No Store namespace was initialized; both strict checks remain.
The next step is independent review of a source-inode/volume observation
composition and an actually private mount, then fresh Store positive gates.
The high-UID Store and root-owned Docker socket are not yet one composed
observer authority. Details and evidence boundaries are in the
[Control storage backend plan](../plan/product-v1-phase-6-control-storage-backend.md).

Slice 6 step **1** retains only its historical bounded evidence; step **2**
continues with these real diagnostic results and explicit admission blockers;
step **3** full live inventory/original sixteen scenarios/independent acceptance
is incomplete; step **4** has not begun. Phase 6 remains **5/15** and public
Profile/provider v3 stay closed. No commit, push or release is authorized here.

Validation for this checkpoint: mise Go1.26.8 full Darwin race/shuffle/count=1
suite passed in **440.344 seconds**, `go vet ./...` in **7.430 seconds**, and
Provider/Product Contract verification in **0.496 / 0.130 seconds**. The two new
Linux integration test binaries executed in restricted arm64 Docker; their
Linux integration-tag vet passed in **0.917 seconds**. Production Go files and
locks were unchanged in this turn. The positive Store test remains a recorded
FAIL; raw and mounted-refusal PASS results do not convert it to acceptance.

Exact cleanup completed: owned consumers and ext4 volume removed, helper
observed ENXIO after detach, all eight granted loop nodes were unconfigured,
offline fsck passed, then the backing volume was removed. No run-owned
containers or volumes remained; both new diagnostic image tags were removed.
Retained pre-removal and fresh post-removal inventories also show no mount
source overlapping either owned volume path or its ancestors/children. This
relies on the coordinated sole operator and does not fence daemon-external
writers. The unrelated existing containers and prior diagnostic utility image
were preserved. Private commands/results, image/binary identities, both the
executed and reviewed-follow-up cleanup scripts, and exact source delta are in
`coding-persistent-backend-live-20261011` outside Git and the migration package.


### 2026-10-11 source observer and private-mount follow-up

A fresh independently reviewed diagnostic used local-driver
`o=rw,nosuid,nodev,noexec,private`. The actual mount no longer contained
`master`, and the unchanged strict kernel-root check passed. This corrects
the earlier review's conflation of container bind propagation with the local
driver's underlying mount options. The held Docker observer now requires
this exact option set and still checks the live Store fd separately.

The helper's new `observe` action uses a read-only backing mount and only
read-only pinned file/loop descriptors, canonical seal and before/after
statx/census/ioctl checks. Actual observation passed, including with an active
filesystem consumer; wrong mount access, absent device and wrong namespace
were refused without output. It emits diagnostic identity fields, not a
Store capability or signed receipt. The positive Store test still fails on
its unchanged exact backing-path check; the private-mount blocker alone is
closed for this observed configuration. See the [backend plan](../plan/product-v1-phase-6-control-storage-backend.md).

Next: independently select the live source-capability/Store-root/Docker-volume
composition. Do not turn serialized helper JSON into caller authority. ADR
0055's existing high-UID Control plus fixed supplementary GID 0 candidate
remains the separate Docker-socket direction, with access/denial gates pending.
Phase 6 stays **5/15**; Slice 6 steps **1/2/3/4** remain historical bounded
evidence / in progress / incomplete / not begun. Public Profile/provider v3
admission stays closed, and no commit, push or release occurs.


### 2026-10-11 live source/Store/Docker composition checkpoint

The user explicitly requested independent review before completing the live
source-inode, Store-root and Docker-volume composition. The root session
remained the sole source writer; `/root/exec_budget_review` independently
reviewed the design, permission/DAC feasibility, actual Desktop representation
corrections and request budget. The reviewer remained read-only. Its configured
implementation_agent role remains gpt-6-sol/xhigh; the already disclosed runtime
metadata visibility limit has not been converted into a stronger claim.

The [design and actual evidence boundary](../plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-live-source-store-and-docker-composition)
records the separate source-provision.v2 root-owned 0750/0640/GID57011 mode,
held read-only descriptors, shared maintenance lock, actual source/loop/root
binding and private Docker-composed Store lifetime. High UID57010/GID57011 has
only fixed supplementary GID0 and exact loop0–7 RO devices. Existing private
legacy material and old seals are not upgraded. The wrapper persists actual
volume/daemon/endpoint identity, rechecks raw complete inventories around each
operation and fails closed or uncertain on drift. Both production holds stay
closed and no full Profile or Coding dispatch authority follows from it.

The first actual admission rejected the expected `/var/run/docker.sock` versus
Desktop's daemon-normalized proxy path. After separately reviewed exact source
selection, the second admission rejected list/inspect representations for
unrelated macOS binds. Neither failure initialized a Store: empty roots and
unchanged original seals were checked before retry. The reviewed normalization
is limited to nonowned `/Users/...` binds for that exact Desktop candidate;
raw safety projections and inventory digests remain checked. Unrelated services
were not changed. The initial high-UID probe's group assumption, compile error
and a later evidence-file-name mistake are also retained as failed commands.

The v3 fixture passed the actual composition and precise cleanup. Main-session
review then found a missing shared deadline around constructor preflight and
initial source reads. Independent review accepted a ten-second request context
covering construction or each complete operation, including queue wait; actual
Store mutations receive that child context. Post-write drift/timeout retains
uncertainty and poisons the wrapper; failed initialization keeps its marker.
Blocking filesystem syscalls are not interruptible by context and are not
claimed to finish physically within ten seconds.

The final fresh namespace `84f26f4977c34f10b51b2a38fe7794b7` passed all composed
positive and negative scenarios again after that repair: 102,400-byte durable
state/CAS, allocation object quota, replacement-Control reopening, wrong seal,
three kinds of stopped extra consumer, helper exclusion under a held shared
lock, and same-byte seal inode replacement. Both Store and wrapper detect the
last mutation. The complete quota scenario took 20.664 seconds across 65 bounded
operations; this is not a twenty-second single-operation budget. Exact teardown
removed owned containers/filesystem/backing/image, verified loop7 ENXIO, all
loop nodes unconfigured and clean offline e2fsck. Original seal bytes, failed
runs and new private evidence remain outside Git in
`control-storage-composition-20261011/v4-budget-final` and its parent.

Full race/shuffle/count=1 and vet passed in 256.398/5.495 seconds before the final
Docker-only repairs. The final affected package passed race/shuffle/count=1,
native vet and Linux tagged vet in 34.723/0.427/0.492 seconds. Linux helper and
source-FD tests plus the final actual fixture pass. The ordinary-volume/stopped-
consumer integration passed before the final deadline repair; it is not relabeled
as a final-byte run. Contract inputs are unchanged. mise Go1.26.8 and restricted
Docker supplied the toolchain/runtime; no host development installation or
whole-repository toolchain change occurred.

This closes the live storage composition component. Store ENOSPC, uncertain-
write/recovery and actual wrong-principal socket denial gates, complete source
Profile/operator admission, Coding ledger lifetime integration, physical
four-volume scenarios and final topology remain open. Advisory locks and two
snapshots do not fence administrators or future daemon calls. Slice 6 fixed
steps: **1** historical bounded Guest E; **2** ongoing with this component
passing; **3** full live topology/original sixteen scenarios and independent
acceptance incomplete; **4** not begun. Phase 6 remains **5/15**. No Git staging,
commit, push, merge, publication or production deployment occurred.


### 2026-10-11 Store ENOSPC, uncertainty and principal gates

The user requested independent review before implementation and real
verification of the next Store ENOSPC, uncertain-write recovery and wrong-
principal scenarios. `/root/exec_budget_review` reviewed design, test assertions,
exact fixture orchestration and raw evidence without writing files or running
Docker/tests. Root remained the sole writer. The prior 2,468-file source snapshot
matched before work. Two Go files change: the Store privately observes actual
write syscall failures for tests and now fails closed on Close errors; a Linux
tagged gate exercises the existing failure/reopen semantics. No recovery API,
legacy receipt upgrade, public error detail or release admission is introduced.

Ten separate fresh namespaces use the previously reviewed one-GiB source-v2
loop7/ext4/Control composition. Actual low-space preflight returns ErrCapacity
without touching files and resumes healthy writes after releasing the exact
unlinked pressure fd. The separate after-preflight case consumes actual space
down to 32,768 bytes, then observes pending.object **Write ENOSPC**. Put returns
ErrUncertain, the owner stays poisoned and the empty pending object remains.
Original manifest/state bytes do not change. Independent Store reopen and
InitializeSourceBound both reject the residue without modifying its files;
the replacement Control's composed constructor also refuses it.

Caller cancellation before Put has no effect; cancellation after object sync
retains uncertainty and pending evidence. Five controlled `os.Exit(73)` points
skip Go defers. Before-object and after-manifest-rename states revalidate as
consistent in a new process; the three middle stages retain their exact
object/manifest inconsistencies and reject. The published payload and original
state are independently checked, and all eight recovery-attempt snapshots retain
identical name/hash/inode/length/mode mappings. This does not prove power-loss
survival or a caller-observed successful transaction/exec permit.

Wrong UID57012/GID57012, correct UID57010 with wrong GID57012, and correct
57010:57011 without GID0 each run in a separately created candidate after the
previous owner was removed. Actual supplemental groups contain only their
primary GID. File DAC is tested separately from an actual Unix socket connect,
which returns EACCES in every wrong-principal case; source-Store admission
also rejects. Correct UID may still read its own Store root, and the correct
primary group may still read the RO source; neither is mislabeled as a denial.
After each probe, a fresh correct owner successfully performs composed reopen.

All ten fixture namespaces were reclaimed exactly: stopped/removed consumers,
filesystem volume removal, exact loop7 detach with ENXIO, eight unconfigured
loop statuses, offline fsck, original seal equality and zero owned containers/
volumes. The shared new diagnostic image was removed once at the end. Base image
and unrelated services/volumes remained. Independent review matched the two
final Go file hashes and these original records, and accepted the bounded
fault/principal component. Raw evidence remains outside Git in
`control-storage-fault-gates-20261011`; no migration inventory was regenerated.

The [backend plan](../plan/product-v1-phase-6-control-storage-backend.md#actual-fault-and-principal-results)
records exact case classifications and limitations. Complete Profile/operator
admission, Coding ledger/PG/dispatch integration, four-volume physical scenarios
and the remaining Slice6 startup/security and full-topology gates are still open.
Slice6 fixed steps are **1** historical bounded E, **2** ongoing with Store
fault/principal gates passing, **3** incomplete, **4** not begun. Phase6 remains
**5/15**. No staging, commit, push, merge, publication or deployment occurred.


Final validation for these same Go bytes passed: `go test -race -shuffle=on
-count=1 ./...` in **524.358 seconds**, full `go vet ./...` in **8.867 seconds**,
focused Store/Docker race tests in 27.622 seconds, and Linux tagged vet in
1.622 seconds. The full race run retained its existing 600-second runner limit;
no timeout was extended. The ten actual Linux fixtures used the frozen final
Go snapshot; subsequent changes only record results in documentation. Contract
inputs, Go module/toolchain locks and AGENTS are unchanged, so their unchanged
historical checks were not rerun for narration.


### 2026-10-11 source-owned Coding ledger checkpoint

The ledger now owns the composed source/Store/Docker lifetime through a private
marked port. Ordinary-directory constructors compile only in tests; the held
constructor checks the storage/template/daemon/endpoint/platform join before
I/O. Failed loading retains markers, while missing state never triggers repair.
Cancellation while draining callbacks keeps the owner locked and closed to new
work until a later Close completes.

Six fresh Linux/arm64 fixtures pass durable Unknown before an effect probe,
replacement-process refusal of replay/Completed/exec, canceled Close and lock
retention until drain, before/after-state interruption without dispatch, missing
state refusal without reset, and a stopped second consumer causing an absorbing
source-owner failure. Removing that peer does not revive the old owner; a new
owner reopens the unchanged empty ledger. All six namespaces, loop mappings and
the new diagnostic image were reclaimed exactly. The raw evidence and one
preserved outer snapshot-comparison failure are outside Git in
`control-storage-ledger-20261011`. The failure compared the replacement container's
parent-directory mtime; independent review restricted comparison to the Store
root/entries, with all original files retained and no scenario rerun.

This is a held source-storage/ledger component using explicit fixture Profile,
principal and policy digests plus bounded callbacks. Full source-derived
Profile/operator and four-volume effects remain unproved. Independent review
found the current complete Profile cannot represent the diagnostic candidate's
RO backing, exact eight RO loop devices and different socket target, and its
required service networks/mounts differ. Next introduce and independently review
an exact source-access mode and operator binding without widening generic
HostDevices/mount rules; then wire the complete command and PG/mTLS paths.
See the [backend design](../plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-source-owned-execution-ledger-lifetime).

Slice6 remains **1** historical bounded E, **2** in progress with this component
passing, **3** full live topology/original16 and independent acceptance incomplete,
**4** not begun. Phase6 stays **5/15**; public Profile/provider v3 holds, two issuers,
frozen-R reuse and old locks stay unchanged. Development uses mise Go1.26.8 and
Docker; no staging, commit, push or release occurred.


Final validation for the unchanged Go snapshot passed: full
`go test -race -shuffle=on -count=1 ./...` in **474.875 seconds**, full
`go vet ./...` in **18.48 seconds**, the focused ledger/source-owner race tests
in 15.317 seconds, and final Linux tagged vet in 0.516 seconds. Six real fixtures
and independent evidence/documentation review passed within the stated scope.
The existing 600-second full-suite runner limit was not changed. No Go byte
changed after the real-fixture snapshot; subsequent edits only record results.
Contract inputs, Go module/toolchain locks and AGENTS remain unchanged.


## 2026-10-11 complete-Profile source-access permission checkpoint

An independently reviewed optional source-access v1 mode now represents the
exact source-v2 backing, eight RO loop devices, canonical Docker socket, owner
UID/GID/groups and new Control image identity inside the complete declared
Profile v2. A pre-seal source-intent digest breaks the backing-label/Profile/seal
cycle; the final Profile then binds the original seal. Read-only operator review
checks either canonical stage and never grants runtime admission. Legacy wire
encoding and the public Profile/provider v3 holds remain unchanged.

The real Docker fixture passes source Store initialization, replacement reopen,
a create-only positive baseline, eight stopped permission/configuration
refusals and a stopped unauthorized private-config consumer refusal followed by
successful reopen. Exact loop/volume/container/network/image cleanup passes.
The actual observer checks seven mounts and three internal isolated networks,
but this is **Control-only staging**: other role supply identities are synthetic,
and live Provider/TLS peers, CA/CRL content, service readiness and release supply
are not proved. Two failed preparation attempts remain preserved outside Git;
neither is counted as acceptance. Evidence: `control-profile-source-access-20261011`.

Next establish separately reviewed operator admission and exact legitimate
Provider/TLS/CA consumer identities, then connect the source-owned ledger and
complete Control/PG/mTLS command path and four-volume effects. See the
[permission-mode design and evidence boundary](../plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-complete-profile-source-access-declaration).

Slice6: **1** historical bounded E accepted in its original scope; **2** ongoing,
with this permission component passing; **3** full live topology/original16 and
independent formal acceptance incomplete; **4** not begun. Phase6 remains5/15.
Development remains mise Go1.26.8 and Docker. No commit, push or release.


Final checkpoint validation passed on the unchanged Go snapshot: full
`go test -race -shuffle=on -count=1 ./...` in **340.282 seconds**, full
`go vet ./...` in **8.66 seconds**, both Contract lock verifiers and Linux tagged
vet. Independent design/code/raw-evidence/documentation review accepted the
stated held Control-only component scope. All 237 commands in the final physical
fixture completed successfully; the two earlier failed attempts remain retained
and excluded. No Go source changed after the final real-fixture image build.
The original 600-second suite limit, public admission holds and Phase6 5/15
status remain unchanged. This completes this permission component checkpoint,
not Slice6 formal acceptance or its step4 handoff.


## 2026-10-11 operator and consumer observation checkpoint

Independent design/code review added a held operator-signature and consumer
observation component. Admission re-derives the complete canonical Profile,
then binds a fresh single-use challenge to actual source/root, original seal,
Docker volume and consumer graph observations before Store initialization.
Signatures use a separate test-key commitment, expire within120seconds and do
not create production authority. Every subsequent Store operation rechecks the
approved graph. The old Control-only staging branch remains unchanged.

Real Docker checks passed for the Profile-derived19 diagnostic containers and
three isolated Control/Provider networks: initialize/reopen, signature/review
forgery and graph-drift refusals, stopped/missing consumers, extra endpoint, and
same-name/label wrong UID/image/command/group/config/CA mount permission/source
refusals. Legitimate replacement required a fresh signature. These are fixed
sleep-process permission/session observations, **not real Provider/TLS identity
or readiness**. No CA/CRL bytes or production operator credential are accepted
by this evidence. The test pipe is not an added private-config file. One private
harness preparation failure remains preserved and excluded from acceptance.

Evidence: `control-operator-consumers-20261011`; see the
[operator/consumer component boundary](../plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-operator-and-consumer-observation-component).
Next establish the production bootstrap and real role launch/service identity,
then the source-owned Control/PG/mTLS command path and four-volume effects.
Slice6: **1** historical bounded E; **2** ongoing; **3** final live topology,
original16 and independent formal acceptance incomplete; **4** not started.
Phase6 remains **5/15**. Development uses mise Go1.26.8 and Docker, with no
commit, push, merge or release. Public admission holds remain closed.


Final validation on the unchanged Go snapshot passed: full
`go test -race -shuffle=on -count=1 ./...` in **260.098 seconds**, full
`go vet ./...` in **3.184 seconds**, both Contract lock verifiers and Linux
tagged vet. Independent review matched all2091Go files to the frozen snapshot
and accepted only the stated held diagnostic scope. Exact cleanup removed all
19 remaining diagnostic containers, six volumes, three networks and the new
image tag; all eight loop nodes were unconfigured and offline fsck passed.
The original600-second suite limit was unchanged. No Go byte changed after the
real fixture binary build. This is a Slice6 step2 component checkpoint, not
formal acceptance or step4 handoff.


## 2026-10-12 held bootstrap and actual process evidence

The [bootstrap/process checkpoint](../plan/product-v1-phase-6-control-operator-bootstrap.md) adds a canonical
operator public-key declaration, independent empty-by-default executable pin,
fixed sealed Control FD3 and an explicitly held Control config protocol.
Eight launch declarations bind original OCI role/loader bytes. A trusted
operator probe distinguishes actual PID1 executable/credentials/argv from
container labels and distinguishes the loader from the role.

Real Linux checks passed for sealed-FD positive/negative cases, eight OCI byte
bindings, five direct-entry Control/TLS process-byte observations, two loader
observations and identity/environment/mount refusals. Direct-entry observations
are diagnostic overrides, not approved startup or service readiness. Three
actual Provider commands still reject v2 at the core v1 startup reader; actual
Control/TLS commands remain held. Production pin/probe delivery, operator
challenge transport, Store dispatch and full consumer readiness remain open.
The five private config volumes, all owned containers and three new diagnostic
image tags were reclaimed. Failed fixture attempts and the first600-second
full-race timeout remain evidence, never passes. See the private checkpoint
`control-production-bootstrap-20261012` for final validation and raw logs.

Next independently review the production delivery and post-observation
challenge/signature composition. Public holds, two issuers and frozen-R rules
are unchanged. Phase6 remains5/15; Slice6 steps1/2/3/4 are historical bounded E /
ongoing / incomplete / not started. Development remains mise Go1.26.8 and Docker;
no commit, push, merge or release.


Final checkpoint validation passed on the final Go combination: full
`go test -race -shuffle=on -count=1 -json ./...` in **582.294seconds**, full
`go vet ./...` in **6.491seconds**, both Contract lock verifiers and Linux
tagged vet. The first600.019-second timeout is retained as failed, not erased
by the later pass; no timeout limit was extended. Only the opt-in test fixture
generator changed after the real binary build (it rebinds the selected image
into its synthetic source intent); production Go inputs and real image bytes
were unchanged. The final whole-repository run includes that correction. This
is held Slice6 step2 component evidence, not production acceptance or step4.


## 2026-10-12 held process-delivery continuation

The [versioned pin/probe and post-observation signature component](../plan/product-v1-phase-6-control-process-delivery.md)
adds an independent build-time public pin, the fixed image probe, real loader
and Control PID1 observation, sealed loader-generated binding, and a one-use
host-signature reply. The signature scope is only `held-control-process-delivery`;
it cannot open Store or authorize the earlier diagnostic consumer graph.
The host observes twice before signing; Control re-observes after signing.
The selected Unix Docker endpoint remains an operator-controlled trust premise.

Final source and original OCI inputs, actual positive/negative transcripts,
required verification and exact cleanup are indexed in private checkpoint
`control-production-delivery-20261012`; older failed attempts remain retained.
These are dirty-source diagnostic images with a test key, not clean release
or independent production operator acceptance. The next result is separately
reviewed source/root/volume/full-consumer and actual service composition.

Phase6 remains **5/15**. Slice6 **1** historical bounded E / **2** ongoing /
**3** final topology, original16 and independent formal review incomplete /
**4** not started. Public holds, issuer policy, old release/toolchain locks and
frozen-R reuse rules remain unchanged. No Git submission or release occurred.


## 2026-10-12 held Control source-observation continuation

The [source-observation component](../plan/product-v1-phase-6-control-source-observation.md) binds the same real Control process
and retained source/root FDs to backing/filesystem volumes, fixed socket,
eight read-only loop grants and three isolated Control networks. It introduces
an explicit v3 target/bootstrap/startup tuple, v5 config and the distinct
`held-control-source-observation` signature scope. Host probes compare actual
source evidence twice before signing; Control rechecks its retained session
behind the signature. No Store is initialized or opened.

The real CLI positive passed in35.622seconds; the tagged Docker integration with
race passed in33.869seconds. Seven actual refusal cases cover old startup,
wrong key/signature, replay, stopped second consumer, source record inode
replacement and deadline. Both physical drift cases carried a valid test
signature and failed at source re-observation. Fifteen host projection cases
plus wrong backing-volume options reject unsafe inputs. Empty-root assertions,
original seal preservation, exact loop7 detach/ENXIO and eight-device census
are separate private fixture evidence. These facts do not prove Store contents
or full consumer/service readiness. Logs and prior failed attempts are retained
in private checkpoint `control-source-process-composition-20261012`.

Independent review required fixed daemon logging/resource settings and exact
four-label checks in original OCI, selected image and container metadata; both
repairs are applied. Image labels do not attest clean source or provenance.
The new operator key is recorded as local development only, with no independent
production approval. The GET-only collector does not make the mounted Docker
socket a kernel-enforced read-only capability.

The next reviewable result is production operator/Store admission composed with
the actual Provider/TLS/CA consumer graph, retaining the public holds until its
named gate is met. Phase6 remains **5/15**: Slice6 step1 historical bounded Guest
E; step2 ongoing; step3 final live topology, original16 scenarios and formal
independent review incomplete; step4 documentation/submission/push handoff not
started. Existing two-issuer, PostgreSQL general, frozen-R, Go1.26.8/release-lock
rules remain unchanged. Development uses mise and Docker; no Git submission.

## 2026-10-12 held CA directory prerequisite

The [trust-v4 component](../plan/product-v1-phase-6-control-trust-observation.md) addresses the reproduced named-volume-at-PEM mismatch. It binds the two exact read-only CA directories, retained file identities and bytes to the existing source/process signature. Public and old Store admission remain held. This advances Slice6 step2 only; actual Provider/TLS consumers, production operator authority, final live topology/original 16 scenarios and formal handoff remain open. Phase6 stays **5/15**.

Actual v4 positive, three signed physical drift refusals, bounded initial-input refusals, Linux reader execution and the same new binaries on legacy v3 are recorded in private `control-real-consumers-20261012`. Full race (462.510s), vet, both Contract locks and tagged Docker race passed. Exact cleanup passed after the first attempt safely refused an in-use network; the wrong-owner wrapper assertion failure is also retained. See the component document for evidence limits.


## 2026-10-12 held Provider / Control TLS peer

The [real-process peer component](../plan/product-v1-phase-6-provider-tls-peer.md)
connects one fixed Coding control edge through separate Linux role/agent test
processes using production TLS, Unix signing, retained CA FDs and source-bound
CRL enforcement. The selected 20-case matrix covers a real TLS1.3/mTLS POST,
nine initial refusals and ten active-fault closures plus fresh-client refusals.
The closures take 1.142–3.462 seconds within the unchanged 10-second bound.
Original fixture failures are retained and excluded from negative passes.

This is integration-only dirty-source component evidence with diagnostic X.509
issuers, not actual production Provider/Control commands, Vault/controller
issuance, operator approval, Store or full-topology admission. Public holds,
the broker/general issuer rule, old receipts and frozen-R reuse remain intact.
Private inputs, logs and exact resource receipts are in
`provider-tls-peer-20261012`; see the component document for failure stages,
verification and next work. Phase6 stays **5/15**: Slice6 step1 historical
bounded E; step2 ongoing; step3 final live topology/original16/formal independent
acceptance incomplete; step4 not started. No staging, commit, push or release.


At the peer checkpoint, implementation and real component cases were recorded, but
whole-repository code acceptance was **blocked**: three full race/shuffle/count1
runs exited124 at the unchanged 600-second bound, including the process-local
GOMAXPROCS=4 scheduling experiment. The phase6security package passed separately
in492.302s; full vet, both Contract locks, Linux tagged vet/package execution
and exact resource cleanup passed. These do not substitute for the incomplete
full race gate. Resolve that bounded verification issue before broader command
composition or any acceptance claim; no timeout, assertion or public hold is
relaxed. Original failures and final source/evidence hashes are preserved in
private `provider-tls-peer-20261012`.


## 2026-10-12 bounded full-repository race follow-up

The [verification follow-up](../plan/product-v1-phase-6-provider-tls-peer.md#repository-verification-status)
passes the complete race/shuffle/count1 suite with `-p=6` in **510.429 seconds**
under the unchanged 600-second bound (phase6security 475.785 seconds). All 267
packages have final outcomes. The Go/module source, tests and assertions are
unchanged; only package scheduling differed, with no `GOMAXPROCS` override.
The three prior timeouts remain failed evidence, not default-concurrency or CI
passes. Independent review accepts this local gate result within that scope.
Prior vet, Contract and Linux component results are reused on matching source;
no new Docker execution or production acceptance is claimed. Evidence is in
private `race-gate-diagnosis-20261012`, outside the migration package and Git.

This removes the missing local full-race result as the immediate blocker.
Phase6 remains **5/15**: Slice6 step1 retains bounded historical Guest E;
step2 continues with production operator/Store, actual Provider/Control/Scanner
commands and source-bound Vault/controller/agent composition; step3 final live
topology, original16 and independent formal acceptance remain incomplete;
step4 post-acceptance handoff is not started. Public holds and the two-issuer
rule remain unchanged. No staging, commit, push, merge or release occurred.


## 2026-10-13 Vault two-issuer continuation

The [reviewed component and evidence boundary](../plan/product-v1-phase-6-vault-two-issuer.md) fixes a reproduced
duplicate-source/omitted-issuer acceptance in VaultClient and prepares an
opt-in real broker/general test for Control, Scanner, broker and PostgreSQL
client policies. PostgreSQL stays on general. The exact pinned Vault archive
has been restored and verified, but cryptographic image signature/provenance
is unverified; the required supply gates block starting the real service.
Neither ordinary skipped tests nor archive verification are real two-issuer
execution or Controller/agent/command acceptance. See the component document
and private `vault-controller-continuation-20261013` checkpoint for final
verification results, failed attempts and next evidence.

Phase6 remains **5/15**. Slice6 step1 retains historical bounded Guest E; step2
continues with supply resolution, actual issuer/source binding and the complete
operator/Store/Provider/Control/Scanner/Controller/agent composition. Step3
final live topology, original16 and independent formal acceptance remain open;
step4 post-acceptance handoff is not started. Public holds and frozen-R reuse
remain unchanged. No Git staging, commit, push, merge or release occurred.

Final bounded verification: workloadpki tagged race/shuffle/count1, full vet,
tagged vet and both Contract verifiers pass. The new whole-repository race
run timed out at 600.297 seconds (exit124), with phase6security unfinished; it
is not replaced by the historical 510.429-second result. The fresh exact-input
Trivy scan has 6 HIGH findings (4 unique CVEs), and image signature/provenance
remains unverified. No Vault service or real two-issuer scenario ran. Both the
full-race and supply blockers remain open; all original failure records are
preserved.


## 2026-10-13 race diagnosis and Vault supply proposal

The [reviewed diagnosis](../plan/product-v1-phase-6-race-budget-diagnosis.md)
identified redundant desired-topology construction inside each nine-rule HBA
call. Fresh plans are now reused only within that call, preserving all original
validation, per-owner checks and output bytes. New characterization and
mutation-isolation tests passed before and after the change. The final full
`go test -race -shuffle=on -count=1 -p=6 -json ./...` passed in **503.355 seconds**
under the unchanged 600-second limit; all267 packages ended. Full vet and both
Contract lock verifiers passed. All2148 Go files match the pre-run snapshot.
This supplies the missing local full-race result for this source; previous
timeouts remain failed evidence and single profile samples are not a stable
performance guarantee or proof of the sole historical timeout cause.

The independently reviewed [Vault supply proposal](../plan/product-v1-phase-6-vault-supply-remediation.md)
keeps image authenticity/provenance and the six HIGH findings as independent
blockers. No Vault lock, trust root or toolchain lock changed; no new candidate
was fetched or Vault service started. Next produce an exact candidate dossier,
verify all supply gates, and independently review candidate-specific consumption
before running the new two-issuer matrix and complete command composition.
Private evidence: `race-vault-remediation-20261013`, outside Git and migration.

Phase6 remains **5/15**. Slice6 steps1/2/3/4 remain historical bounded Guest E /
startup and real-boundary work ongoing / final live topology, original16 and
independent formal acceptance incomplete / post-acceptance handoff not started.
Public holds, broker/general issuers, PostgreSQL general and frozen-R reuse
remain unchanged. Development stays mise Go1.26.8 or Docker. No staging, commit,
push, merge or release.


## 2026-10-13 Vault 2.1.2 candidate supply result

The [candidate investigation](../plan/product-v1-phase-6-vault-candidate-supply.md) restores and verifies the exact new
index, arm64 manifest, config and seven original layers, including ordered
diff IDs and wrong-identity refusals. Its private repository-validator race
check passed in **24.044 seconds**. Trivy0.74.0 completed the fresh full-image
report in **1.853 seconds**, bound to the actual config and unchanged scan/DB
bytes, but the existing vulnerability gate **fails: 4 HIGH, 0 CRITICAL**.
The actual binary contains Go1.26.8 and x/net v0.59.0; all lower/unknown
findings remain recorded. Image signature and build provenance also remain
unverified. Independent review confirmed rejection, not runtime qualification.

No Vault service ran. Exact new ECR Docker references were removed without
force/prune, preserving the historical image. Failed transfers and incomplete
Docker exports remain in private `vault-candidate-supply-20261013`; the accepted
locks and receipts are unchanged. All2148 repository Go files match the prior
503.355-second full-race snapshot, so that same-source evidence is reused.
Next review a replacement/build proposal covering fixed embedded inputs and
independent publisher/builder authority. Vault compiler selection is a separate
decision; the existing Go1.26.9 exception remains Coding-only.

Slice6 step1 retains historical bounded Guest E; step2 remains ongoing and
blocked on these Vault supply inputs for the real issuer/command composition;
step3 final live inventory, original16 and independent formal acceptance remain
incomplete; step4 post-acceptance handoff is not started. Phase6 remains **5/15**.
Broker/general, PostgreSQL general, public holds and frozen-R reuse are unchanged.
Development uses mise/Docker. No staging, commit, push, merge or release.

## 2026-10-13 Vault rebuild proposal review

The [decision package](../plan/product-v1-phase-6-vault-rebuild-proposal.md) fixes
upstream `76fdd6587523c4c6cb079635075e019714d23470`, tree
`6704d399e391f48f64ec66ac7ec2dcc6b03b6841`. A separate shallow checkout has
9,090 current-tree files, no submodules, clean status and passing strict fsck.
Its source archive and selected raw source/blob identities are retained. The
three-file proposed compiler/root x/net patch passes `git apply --check`; no
patch was applied and no upstream source was executed. Public checksum-database
verification of x/net0.60.0 passed using existing mise Go1.26.8.

Independent read-only review closed three proposal defects: explicitly require
UI tag and complete embedded assets; label the derived source inside binary
metadata; freeze and constrain generator/UI package-script execution. Review
acceptance is only for the narrow compiler-scope decision, not build, image
supply or runtime. Full MVS, generator/UI tools, runtime base/APKs, private
UID/GID, approved publisher/builder and resulting artifacts remain unresolved.
Failed fetch attempts are preserved in `vault-rebuild-proposal-20261013`; no
new candidate image or Vault process exists. Repository Go source is unchanged,
so its existing matching full-race/vet/Contract evidence is reused.

Phase6 remains **5/15**. Slice6 step1 historical bounded E is unchanged; step2
is ongoing with real issuer/command work blocked by supply; step3 final live
topology/original16/independent acceptance is incomplete; step4 has not started.
Next obtain the Vault-only compiler decision, then close exact build inputs.
The earlier Go1.26.9 authorization remains Coding-only until that decision.


## 2026-10-13 approved Vault diagnostic input preparation

The user confirmed the private Vault-only Go1.26.9/root x/net v0.60.0 build
exception. The [input checkpoint](../plan/product-v1-phase-6-vault-build-inputs.md) records a new
uncommitted source copy, an actual module graph with only that x/net version
delta, exact compiler materials, 1,852 compatible registry UI archives and
four Git-package source correspondences. Node22 is a separately reviewed
private UI tool delta; the dependency lock is unchanged. Source-bound download
recovery, 15 enumer outputs and UI lifecycle conditions have read-only
independent review; actual source/generator/UI execution has not occurred.

Incomplete builder/module transfers remain failed evidence. Final runtime
identity, Ember5.8 support, publisher/builder approval and all downstream
candidate/runtime results remain unresolved. No accepted lock, trust root,
ordinary repository toolchain, public Profile/provider hold or frozen-R rule
changed. No commit, push, publication or Vault service execution occurred.
Private evidence: `vault-rebuild-inputs-20261013`.

Phase6 remains **5/15**. Slice6 step1 retains historical bounded Guest E;
step2 is ongoing; step3 final live inventory/original16/independent acceptance
is incomplete; step4 has not started. The next acceptable result is complete
checked inputs and a reviewed isolated build recipe, followed by a genuinely
new diagnostic output and scan; this checkpoint is not formal acceptance.

## 2026-10-13 Vault builder material closure and rejection

The [builder record](../plan/product-v1-phase-6-vault-builder-admission.md)
closes24 remaining Go materials and three Node layers.987/987 ZIP/mod hashes
and actual offline root go mod verify pass; original native OCI hashes, all
diff IDs and Node executable/archive correspondence pass. Full-image scan
report generation succeeds, but admission **fails on4 CRITICAL/65 HIGH**.
Actual inspected proof locations supply no verified signature/source authority;
unsigned index-linked SPDX/SLSA statements do not close that gate.

The independent-review scope is the held plan and evidence boundary, not approval
to execute the rejected builder or an unfinished pnpm/tool recipe. No image
import, source/lifecycle/generator/UI execution, new Vault ELF or Vault service
occurred. The next result must independently admit a viable exact builder and
close offline store/generator preparation before bounded execution. Private
checkpoint: `vault-isolated-build-20261013`; original failed inputs are preserved.

Phase6 remains **5/15**. Slice6 step1 retains historical bounded Guest E; step2
continues with material recovery passed and builder admission failed; step3
final live inventory/original16/independent acceptance is incomplete; step4
has not started. Go/module/Contract inputs retain their existing matching gate
evidence; this material/documentation turn does not rerun full tests or claim
new runtime acceptance. Public holds, broker/general and frozen-R are unchanged.

## 2026-10-13 Vault builder selection and dependency gate rejection

The [new builder/recipe checkpoint](../plan/product-v1-phase-6-vault-builder-selection.md)
selects an exact Chainguard arm64 carrier with eight verified signature/attestation
checks, a signed apko/75-package source correspondence and a zero-finding full
image scan. A separately reviewed Docker init-layer reconciliation accounts
for the saved export without rewriting its original strict failure. Node22.23.3
and authenticated pnpm10.34.7 are the selected private tools; builtin Node26 is
covered by the read-only exact Node mount. The new private enumer graph closes
all9 archive/mod checksum inputs. Historical Vault source and accepted locks
remain unchanged.

Complete material inventories now recognize all9 enumer dependencies and1852
compatible registry packages. They report8 HIGH and51 HIGH/4 CRITICAL respectively;
the separate admission command exits1. Four Git sources have separate bindings,
not coverage by those scans. Generator and complete UI/Vault build execution
remain rejected; offline transport/store probes cannot waive these findings.
Next review scoped repair inputs, unresolved advisories and the complete offline
graph. No Vault service or new candidate binary/image is claimed. Private evidence:
`vault-builder-candidate-20261013`. Phase6 stays5/15; Slice6 steps1/2/3/4 remain
historical bounded E / ongoing / incomplete / not started.


## 2026-10-13 generator dependency and execution checkpoint

The [new private enumer candidate](../plan/product-v1-phase-6-vault-dependency-remediation.md)
changes only its go.mod/sum and closes12 authenticated module pairs. Complete
inventory scan yields0 HIGH/CRITICAL and1 retained OpenPGP UNKNOWN; independent
review checks184 actual packages and the original test subprocess inputs before
permitting only this generator. The original3 top-level tests pass, with12 real
non-CGO testdata programs and the existing1 CGO skip; test/build plus isolated
run/cleanup complete in45.290seconds. Actual output ELF scan recognizes the
derived main,4 dependencies and stdlib1.26.9 with no findings. Raw EXDEV failure,
its cleanup and the first zero-recognition scan are preserved and excluded.
Full UI remains blocked, and no Vault15 generation, Vault ELF/image, real
issuer service or final topology gate ran. Step1 historical bounded E retained;
step2 continues; step3 original16/full topology incomplete; step4 not begun.
Phase6 stays5/15 with both public holds, two issuers and frozen-R rules fixed.

## 2026-10-13 Vault generation scope and bounded execution

The [source-generation diagnostic](../plan/product-v1-phase-6-vault-generator-output.md)
verifies the9090-file private input,15 root CE directives and offline graph
metadata. The first Docker dry-run times out before any generated output;
cleanup succeeds but the later full input check exceeds the wrapper, so that
run remains failed. The v3 attempt stops on OCI load at90.548seconds without
creating a container; exact cleanup succeeds, while the wrapper interrupts
its input postcheck. A separate full-input verification passes in248.239seconds,
without changing either failed execution result. Full-root dependency inventory has16 HIGH findings and
full UI supply remains blocked. Independent review permits only the named
isolated compiler/generator diagnosis with exact output comparisons and
unchanged time/storage/network/privilege limits. Step1 historical bounded E
is retained; step2 is ongoing; step3 final topology/original16 acceptance is
incomplete; step4 has not begun. Phase6 remains5/15 and no production admission,
new operator authority, issuer or evidence-reuse exception is introduced.

The subsequent lower-load v4 run passes OCI load in10.159seconds but its
10-package dry-run times out in60.063seconds. No export or enumer executes.
The full176.071-second failure includes full input pre/postchecks and precise
cleanup. V5 SIGQUIT at the same limit yields no stack; its271.977-second failure
also completes these checks and preserves all15 working target bytes/modes.
Following the user's manual readiness request, the reviewed v6 async observer
runs with recovered host/daemon samples. OCI load passes in7.315seconds; its
scheduled SIGQUIT interrupts the10-package dry-run at55.069seconds and captures
all17637 stderr bytes without truncation. The171.237-second failure completes
input pre/postchecking and exact cleanup, preserving all15 working target bytes
and0644 modes. Two workers are traversing module-index directories while the
main goroutine waits for package loading. This single stack does not establish
the whole delay, a specific module, virtiofs causality or a natural60s timeout.
No export/enumer executes. Independent outcome review accepts these bounded
claims; actual15 outputs remain open. The heartbeat remains deleted and no
unrelated process or original limit/gate is changed.

The separately reviewed one-shot v7 tests fixed-Go1.26.9 `GODEBUG=goindex=0`
without changing the ten dry-run targets,15 enumer commands, empty cache or
time/resource/isolation constraints. OCI load passes in3.340seconds; dry-run
passes in15.938129seconds with all15 directives. The actual `go list -e -deps
-export` completes in76.485729seconds with process exit0, but1741 package rows
carry errors/incomplete state, including534 direct ENOSPC errors. The compiler
gate correctly rejects this result before enumer. A separate post-failure
metadata-only comparison matches all2637 paths, module identities and selected
compile/embedded files/Imports; it does not pass actual exports. There are zero
generated outputs, and all15 original target bytes/sizes/0644 remain intact.

The full v7 run fails in158.554seconds. New explicit input-check receipts pass
in26.322seconds before and30.223seconds after, covering the original185291
files/21283 directories, new7-file probe and authenticated CE metadata. Exact
container and sole-tag image cleanup completes without force. Memory peak
reaches2147483648 bytes with448 max events and zero OOM; the final tmpfs sample
is after compiler cleanup and cannot measure failure-time occupancy or prove
host-disk exhaustion. This is a new bounded scratch-allocation blocker, not a
reason to increase limits, skip exports or accept cached evidence. Stop repeat
execution and independently review a measured scratch/cache repair. Private
evidence: `vault-generator-index-fallback-20261013`. Slice6 step2 remains ongoing;
steps1/3/4 retain historical bounded E / incomplete / not started, Phase6 5/15.


## 2026-10-13 measured compiler storage and rejected repair

Independent design and concrete reviews precede v8 observation and v9 repair.
V8 fails in119.142seconds after dry10.196s/export48.863s:510 direct ENOSPC,
1710 erroneous/incomplete rows,0enumer.194 samples reach /work free bytes0
with at least45905 free inodes. A complete non-atomic snapshot records
507559936 cache and497942528 temporary allocated bytes; Go source explains
work/cache archive copies coexisting. V8 has no OOM/kill, despite memory2GiB.

V9 adds only private `-gcflags=all=-dwarf=false`, preserving empty cache and all
limits/checks. It fails in172.604s:dry6.977s passes, export109.725s yields1549
erroneous/incomplete rows,475 direct ENOSPC and one compiler signal-killed
error. Cgroup oom2/oom_kill1 and Docker OOMKilled=true show an additional memory
failure. No enumer executes; observer completion and2637 matching post-failure
metadata do not pass the real export gate. Original full185291-file/21283-dir
checks plus new9-file probes pass before/after in both runs;15 old targets and
all non-targets remain, and exact owned containers/images are removed without
force. Independent outcome reviews accept only these bounded failure claims.

Further real attempts stop pending a concrete same-run cache/stage design that
addresses both storage and peak memory within the original aggregate budget.
Full-cache capacity and largest-package memory remain unknown; final2637
simultaneous real exports and15 generated original bytes remain mandatory.
Private evidence: `vault-generator-scratch-20261013-1404` and
`vault-generator-scratch-recipe-20261013-1436`. Step1 retains historical bounded
Guest E; step2 root-cause diagnosis progresses but repair/output validation is
blocked; step3 final topology/original16 scenarios remain incomplete; step4
formal handoff has not begun. Phase6 stays5/15, with all public holds, two-issuer
rules and frozen-R standards intact. Automation remains deleted.

## 2026-10-14 staged-cache preparation and supply recheck

The independently checked2637-package graph produces a26-stage proposal; only
three stages ending at compute/v1 are implemented as an unexecuted diagnostic.
Independent review accepts the probe/decoder preparation after final OOM and
structured-overflow fixes.29 Node and9 Python host fixtures plus syntax pass;
no actual compiler, container or enumer runs, so0/15 new generated results.
Existing tmpfs/memory/time bounds and final real-export/byte gates stay fixed.

The expired DB is superseded only by new raw data in a separate private
checkpoint:31 previously successful ranges revalidated, one4MiB range obtained,
complete OCI layer hash checked, exact two-member DB imported with fresh raw
metadata. Earlier TLS/range failures remain. This is not a vulnerability scan.
The actual official Node22.23.3 tool lacks completed release-signature and
core/native/bundled-dependency vulnerability coverage; independent review holds
execution at that boundary. Next close that supply evidence, run the necessary
fresh scoped scans, then review the complete v10 controller before a real run.
Private evidence is `vault-generator-staged-cache-20261014-0128`; Phase6 stays
5/15 and Slice6 step2 ongoing. No automation was restored.

## 2026-10-14 Node tool supply hold

The [Node static supply checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-node-tool-static-supply-checkpoint)
closes source/archive/ELF byte checks and124 verifier source-map correspondences.
Its9-package verifier scan recognizes all packages with zero findings, but the
current registry-signature gate fails on argon2id1.0.1's expired key. Neither
OpenPGP nor Node22.23.3 is loaded. Node release verification, complete embedded
and dynamic library coverage remain unresolved. Independent review records an
OpenSSL HIGH version hit; absent a proved exclusion, the zero-HIGH gate remains
blocked. No compiler/container/enumer runs;15 outputs
and ENOSPC/OOM repair remain unverified. Existing quotas/deadlines, Go1.26.8 and
old locks stay fixed; automation stays deleted. Phase6 remains5/15, Slice6 step2
ongoing, step3 incomplete and step4 not started. Private evidence:
`node-tool-supply-20261014-0207`.

## 2026-10-14 alternative tool supply checks

The [alternative-candidate checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-node-and-verifier-alternative-candidates)
records independent design/concrete/result review and new raw evidence in
`node-tool-alternatives-20261014-0253`. Exact image/ELF/source-locator checks and
the fresh75-APK scan pass. Supplementary actual-JS coverage matches163/163 but
reports a HIGH in http-cache-semantics4.2.0; admission exits1. Its upstream dispute
does not remove the current gate. The entire carrier is rejected and Node26
embedded coverage remains incomplete. The replacement gpg APK is available only
as raw unverified input with embedded recipe/SBOM; its gpgconf dependency hits
the25s transfer bound. All prior and new failures are retained. Index/APK
signatures, full dependencies and source/patch/scan admission remain open.
No candidate/container/compiler or15-output verification executes. Host samples
do not prove stable readiness. Existing mise tools, limits, old candidates and
locks are preserved; automation stays deleted. Formal Phase6 remains5/15;
Slice6 steps1/2/3/4 remain historical bounded E / ongoing / incomplete / not started.

## 2026-10-14 signed Node and GPG chain checkpoint

The [new vendor-candidate checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-vendor-signed-node-and-gpg-chain-checks)
verifies eight new signature/attestation checks for each fixed Node and wolfi-base
index/native pair. Node's complete28-APK scan has zero findings, but its161-package
installed-JS scan reports the same http-cache-semantics4.2.0 HIGH and rejects the
candidate. Embedded Node coverage remains open. wolfi-base has five missing layers
after a measured TLS handshake timeout; its full scan and APK-verifier execution
are unperformed. Gpgconf and five libraries are retained as unverified raw APKs;
npth also hits the TLS connection limit, leaving it and four unattempted packages
missing. Index/APK signatures and the complete GPG chain remain open. Original
failures and all old candidates/locks are retained; no candidate/container/compiler
runs. Existing mise tools, quotas/deadlines and deleted automation remain unchanged.
Only documentation changes; prior matching Go/race/vet/Contract evidence is reused,
not rerun. Evidence: `node-minimal-gpg-chain-20261014-0343`. Phase6 remains5/15;
Slice6 steps1/2/3/4 remain historical bounded E / ongoing / incomplete / not started.

## 2026-10-14 native APK verifier and GPG source checkpoint

The [APK/GPG supply checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-native-apk-index-verification-and-gpg-source-gaps)
restores the five missing wolfi layers and five GPG raw packages, verifies full
19-package signed-assembly correspondence and fresh19/19 coverage with zero
findings, then passes a narrowly admitted native APKINDEX diagnostic: original
signature succeeds and wrong-key/modified-index cases both return BAD signature.
Isolation,97-input before/after checks and precise container/image cleanup pass;
the two previous runtime failures and all raw warnings remain retained.
The12 unsigned APK additions have signed-index/control/data hash correspondence,
not individual APK signatures. A static31-package proposal records overlaps,
three unresolved RPATH objects and other unimplemented installation/loader
semantics. Five original GPG patches are missing; exact publisher commit/recipe
anonymous queries return404. Neither static completion nor source references
admit GPG. Complete fresh proposed-package/source coverage remains open.
The previous Node HIGH rejection is unchanged; no GPG/Node/compiler runs.
Existing mise/Docker, quotas/deadlines and old candidates/locks are preserved;
automation remains deleted. Only documentation changes in Git; matching earlier
Go/race/vet/Contract evidence is reused, not rerun. Evidence:
`gpg-supply-tls-recovery-20261014-0442`. Phase6 remains5/15. Slice6 steps1/2/3/4
remain historical bounded E / ongoing / incomplete / not started;15 outputs and
ENOSPC/OOM repair are still unverified.

## 2026-10-14 GPG replacement-material checkpoint

The [replacement-material checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-gpg-replacement-materials-and-renewed-host-pressure)
retains Alpine edge gpg2.5.22-r0 and its same-commit official mirror APKBUILD.
Static12-source/SHA512 declaration pairing passes; source originals, trusted
key, actual signatures, index and full dependency/ELF/scan/carrier admission
remain open. The signature member is not a verification result. Public Wolfi
gpg2.4.9-r11 matches the historical CGR index but its exact source is not yet
obtained or verified; its execution-candidate route stops. gpgv is not used to
bypass
expiration/revocation policy. No GPG/Node/container/compiler runs. Host pressure
returns (saved load252.39); a single fast Docker ping does not prove readiness.
Next review exact authority/material collection, then close full supply before
actual policy tests. Existing mise/Docker, limits, old evidence/locks and deleted
automation remain unchanged. Only six repository documents change; no new
Go/race/vet/Contract scan or runtime result is claimed. Evidence:
`gpg-verifier-candidate-20261014-0704`. Phase6 remains5/15; Slice6 steps1/2/3/4
remain historical bounded E / ongoing / incomplete / not started, with15 outputs
and ENOSPC/OOM repair still unverified.

## 2026-10-14 Alpine GPG key/source/data checkpoint

The [new limited checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-alpine-gpg-key-source-and-signature-data-checkpoint)
binds the exact official publisher key through same-record pages/fixed recipe,
restores12 source originals matching SHA512 declarations, and passes9 crypto
process plus2 datahash cases with existing Apple-signed OS OpenSSL via mise Python.
Original APK/index match, wrong-key/tamper cases reject, full inputs/tool remain
unchanged. These are data diagnostics; native apk, complete dependency/source/
ELF/helper/scans, carrier admission and GPG/Node runtime remain open. No source
signature or reproduced build is claimed. CPU load improves in one sample, but
the Docker socket is absent and three API calls fail; no container/compiler runs.
Next review index-bound dependency materials and complete fresh scans, then real
native/carrier gates when the same daemon is ready. No global installation,
quota/deadline relaxation, old input/lock mutation, commit/push or automation
occurs. Only six documents change; previous matching Go evidence is retained,
with no new race/vet/Contract claim. Evidence: `gpg-alpine-authority-20261014-0848`.
Phase6 remains5/15; Slice6 steps1/2/3/4 remain historical bounded E / ongoing /
incomplete / not started.15 outputs and ENOSPC/OOM repair remain unverified.

## 2026-10-14 Alpine GPG dependency materials and proposal prescan

The [limited checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-alpine-gpg-dependency-materials-and-proposal-prescan)
restores the37 fixed-index proposed APK originals and passes their limited
signature/control/data correspondence (36 new OS crypto checks plus exact old
GPG evidence reuse). A full37-package/source/PURL metadata prescan reports zero
findings with the unchanged fresh DB. This is a proposal prescan, not actual
installed/full-image/embedded coverage or GPG/Node execution admission. Static
ELF audit visits133 regular files/55 ELF and152 edges, retaining one SQLite
RUNPATH as unresolved; installation/trigger/helper effects and mtab's runtime
mount remain open. The existing Docker context still names the missing same
socket; no container/candidate/compiler executes. Original transfer and v3
parser failures are preserved. Existing mise/Docker, quotas/deadlines, old
candidates/locks and deleted automation remain unchanged. Evidence:
`gpg-alpine-closure-20261014-1006`. Phase6 remains5/15, Slice6 step2 ongoing;
15 outputs,2637 exports and ENOSPC/OOM repair remain unverified.
Only six handoff documents change; all2148 Go files retain earlier matching
race/vet/Contract evidence, without new Go or formal runtime acceptance claims.
Slice6 steps1/2/3/4 remain historical bounded E / ongoing / final topology and
original16 scenarios incomplete / post-acceptance handoff not started.

## 2026-10-15 Docker restored native admission still held

The [bounded follow-up](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-docker-restored-native-admission-still-held)
confirms the existing desktop-linux Docker daemon has returned: five interval
samples retain the same daemon/platform/version, with all15 ping/version/info
calls successful in13.14–34.17ms. Host load/CPU improve, but continuing swap
activity prevents accepting stable whole-host readiness. The previous DB
expired at2026-10-15T01:19:20Z; a reviewed new official metadata request fails
at the unchanged10second TLS connection bound. No DB layer/import/new scan or
native APK/install/GPG/container/compiler execution occurs. Original failures
are preserved without further retry, alternate source or relaxed limits. Independent
review also identifies an unresolved installation path under RO root/noexec
work/tmp: skipping scripts or adding an executable writable root is not
acceptance. Existing mise/Docker, old locks/candidates and deleted automation
remain unchanged. Evidence: `gpg-native-readiness-20261015-093139`. Phase6
remains5/15, Slice6 step2 ongoing;15 outputs and ENOSPC/OOM remain unverified.
Only six handoff documents change. All2148 Go files retain earlier matching
race/vet/Contract evidence; no new Go gates are run for this read-only/data
checkpoint. Slice6 steps1/2/3/4 remain historical bounded E / ongoing / final
topology and original16 scenarios incomplete / post-acceptance handoff not started.

## 2026-10-15 fresh vulnerability DB and scans with native execution held

Fresh official DB import and both new scans pass:37/37 Alpine proposal records and19/19 exact signed Wolfi carrier packages, including source/PURL coverage, with zero findings. These are supply data results; proposal metadata is not installed/full GPG/Node coverage. Host swap remains active and the final CPU sample fails at its unchanged5second bound; native APK execution stays held. Installation/helper execution has no newly admitted path and requires separate concrete independent review. See [the complete checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-fresh-vulnerability-db-and-scans-with-native-execution-held); private evidence is `gpg-db-native-20261015-094855`.

Only six handoff documents change. Existing mise/Docker, Go1.26.8/old locks/candidates, quotas/deadlines and deleted automation remain unchanged. No Go test, container, candidate, compiler, commit or push occurs in this continuation. Phase6 remains5/15. Slice6 steps1/2/3/4 remain historical bounded E / step2 ongoing / final topology and original16 scenarios incomplete / post-acceptance handoff not started.15 outputs,2637 exports and ENOSPC/OOM repair remain unverified.

## 2026-10-15 interval readiness recheck keeps native APK held

Three independently reviewed interval samples confirm the same daemon and27 bounded calls pass, but continuing large swap deltas keep native APK unadmitted. The original v2 DB remains fresh, and prior37/19 raw reports match and are reused without new scans. No container/image/candidate executes, and installation/GPG helpers retain their separate review boundary. See [the measured checkpoint](../plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-interval-readiness-recheck-keeps-native-apk-held), private `gpg-native-recheck-20261015-102127`. Existing mise/Docker, quotas/deadlines and deleted automation stay unchanged. Only six handoff documents change;2148 Go files retain prior matching evidence without a new Go test claim. Phase6 remains5/15; Slice6 steps1/2/3/4 remain historical bounded E / ongoing / incomplete / not started.

## 2026-10-21 CRL source-loss connection admission

This closes a source-level connection-registration gap within the existing
TLS/CRL row of the fixed step2 ledger; that row and Phase6 remain open.
Independent review selects this work because it does not depend on Docker
management authority, candidate images, native observation or the held SDK/TUF
execution route. Private evidence: `slice6-crl-late-track-20261021-232634`.

The real outbound transport checks the peer during TLS handshake and calls
`PeerCRLGuard.Track` afterward. A source-loss pull between those operations
marks the guard unavailable, stops its evidence timer and drains existing
connections. Track previously ignored unavailable and could register the
late connection using the still-unexpired old CRL. It now checks availability
under the same mutex as registration. No new state machine or authority is
introduced; a successful fresh pull remains the only recovery route.

The test-only regression on unchanged production source fails in both the
synthetic verified-state case and the real TLS-handshake good-peer case:
late Track incorrectly returns nil. That identity naturally exits1 in
16.640260seconds; its raw failure is preserved, not rerun or reclassified.
After the fix, focused race/shuffle/count1 tests for phase6tls and
connectiondrain pass in6.470469seconds. They verify existing-pipe EOF,
rejection without registration or an implicit pull, and successful explicit
CRL-number2 bootstrap before admitting a new connection. Existing real TLS
good/revoked assertions remain, with source-loss late registration added.
This is test-PKI/real-TLS component evidence, not a live Vault, Guest or three-
Provider process result.

The first whole-repository attempt naturally exits1 in307.404116seconds:
this stage's additional GOPROXY=off setting prevents missing locked module
lookups. Independent review permits standard development-only restoration
through the official Go proxy and sumdb, with private/checksum exceptions
removed, GOENV/GOWORK disabled and module versions read-only. The original
failure remains. A new identity completes all267 package outcomes for
`go test -race -shuffle=on -count=1 ./...` in564.207446seconds under the
unchanged600-second parent. Full `go vet ./...` passes in53.924708seconds.
Both use mise Go1.26.8, cleared GOROOT, child umask022, GOMAXPROCS2 and -p2;
source hashes and go.mod/go.sum remain unchanged throughout. No global tools
or configuration are installed/changed. Ordinary developer caches are used;
sealed caches and the final admission verifier's fixed offline recipe are
not altered. No old source checkpoint is represented as this new full pass.

The implementation is only the Track condition and its explanatory comment,
plus regressions. No Provider DTO, Contract, Docker driver or lifecycle code
changes; no Docker tagged integration or full-topology result is claimed.
Existing images and receipts do not inherit this source fix: affected runtime
candidates and real scenarios still need their eventual source-bound checks.
No candidate rebuild, host admission, daemon operation, native observer or
release occurs here. Original guards, quota/time bounds and evidence-reuse
rules stay; timers remain off. Reviewed source/tests and progress documents
follow normal commit/push, with actual synchronization checked separately.

Phase6 remains5/15. Slice6 step1 is historical bounded Guest E only; step2
continues with this component gap closed, real revocation/source-loss/
replacement and remaining startup rows open; step3 full live Profile-v2,
original16 scenarios and independent acceptance are incomplete; formal step4
has not started. Docker management authority and both held execution routes
remain held. Continue the existing startup ledger on its own dependencies;
this component success is no new runtime admission.


## 2026-10-22 admission clock rollback

Status: source-level component passed; Slice6 step2 remains open. This selects
the existing complete-mTLS/CRL ledger row without depending on the held Docker
management-authority evidence or changing its requirements.

The actual outbound transport invokes Track after TLS VerifyConnection and
CheckHandshake; inbound PeerConnState asks Ready before Track. Previously,
Track's `now < lastNow` returned an error without retaining the failure, so a
restored clock could reuse the old CRL and register another connection. Ready
retained failure but left the existing registry and sockets open without a
subsequent Poll or explicit Close; the expiry callback skips a failed guard. Both contradict ADR0055's clock-rollback fail-closed and
active/hijacked-connection drain requirements.

At either entry's first observed rollback, the original admission mutex now
latches failed before releasing it. The existing Close runs after unlocking,
invalidates the expiry timer/sequence and drains using the original total
close budget. Concurrent admissions see failed; Close/Forget can reacquire
the mutex without a held-lock close. Restoring the clock or pulling again does
not revive this failed live guard. No new timer, worker pool, authority,
state machine, protocol or compatibility branch is introduced. Ordinary
source-loss recovery remains unchanged.

The new deterministic regressions use two previously registered net.Pipe
connections, advance the watermark by two seconds, then roll back by one
second through Track-only or Ready-only. They require actual EOF on both old
peers, no registry entries, expiry-sequence advancement and no recovery or new
authority pull after the clock is restored. Separate same-time/forward-time
controls still admit a valid connection. The original source-loss/recovery,
real-TLS and revocation tests remain.

| This stage's identity | Actual result | Actual seconds / original bound |
| --- | --- | --- |
| repro-v1, original production source plus new tests | Natural exit1; both entry regressions fail, preserved as expected old-code evidence | 6.127135 / 90 |
| focused-v1, phase6tls and connectiondrain race/shuffle/count1 | Natural exit0 | 6.222765 / 90 |
| root-race-v1, full race/shuffle/count1 | Natural exit0, 229 ok + 38 no-test = 267 final package outcomes | 420.862909 / 600 |
| vet-v1, full vet | Natural exit0, both streams empty | 3.627552 / 600 |

All owned commands reaped naturally without active signals, capture failure,
truncation or timeout. Go1.26.8 remains selected through existing mise;
GOTOOLCHAIN=local, GOROOT unset, -mod=readonly, -p2/GOMAXPROCS2 and the test
child's umask022 remain. Ordinary official Go proxy/sumdb and developer caches
are the preceding stage's reviewed recipe; frozen diagnostic caches and the
final verifier's offline recipe are unchanged. No global installation,
configuration, credentials, go.mod/go.sum or AGENTS change occurs. The tested
two Go files and locks remain byte-identical through subsequent progress-doc
updates. Full Go checks are newly run, not inherited from the previous commit.

Only two Go files and PROJECT_CONTEXT/STATUS/this audit change. There is no
Provider DTO/wire/Contract or Docker driver/sandbox-lifecycle change; named
Contract-lock CLI and tagged Docker integration are not triggered or claimed.
This test PKI and real pipe EOF evidence is a component result, not live Vault,
Guest revoke/CRL-loss/replacement, three isolated Provider commands, network/
UID/GID enforcement or the final topology/original16 gate. Old images and
receipts cannot inherit this changed source without their affected source-bound
candidate and real gates. The fixed five-row ledger remains open.

Evidence: private `slice6-crl-track-clock-20261022-074336` outside Git; old
`slice6-crl-late-track-20261021-232634` and original failures are preserved.
Reviewed source and progress docs follow normal commit/push with full
local/upstream/live SHA checks; this paragraph is not a claim of completed
Git synchronization. No force push, release or merge is authorized here.

Slice6 step1 retains historical bounded Guest E without replay; step2
continues with this source gap closed; step3 complete live Profile-v2 inventory,
original16 and independent formal acceptance are incomplete; formal step4
has not started. Phase6 remains **5/15**. Docker authority/Linux/native/P2 and
public ProfileV2/provider-v3 holds remain. Broker/general only, PostgreSQL
using general, old locks, guard/reuse rules, quotas and timeouts stay fixed.
Timers remain off. Continue another independently reviewed existing startup
audit item; held runtime routes still require their original authority proof.


## 2026-10-22 late-tracking revocation observation

Status: source-level component passed; the fixed complete-mTLS/CRL ledger row
and Slice6 step2 remain open. This work does not require or replace the held
Docker management-authority evidence.

The real outbound transport invokes Track after TLS VerifyConnection and
CheckHandshake; inbound PeerConnState uses Ready then Track. With no active
peer, Poll uses Bootstrap and does not check a particular leaf. Thus CRL#1 can
admit a handshake, zero-peer Poll can install CRL#2 revoking that peer, and
late Track can first observe the actual revoked leaf. Previously Track only
returned a generic refusal without retaining the observation; a higher-number,
validly signed CRL#3 omitting the still-unexpired serial could then admit a new
handshake/connection. This violates ADR0055's live-role monotonic observation
requirement. No other entry necessarily observes this late peer.

One mutex-only helper now shares the existing bounded serial deep copy and
NotAfter retention across refresh, Poll and Track. Track records only after
VerifiedCRL.CheckPeer returns ErrPeerRevoked, which follows its actual leaf/
issuer, signature, validity and complete-CRL checks. A successful observation
advances lastNow even though the connection is refused. Other peer errors do
not record or advance it. The original len>=8192 failure rule stays fixed,
including the same serial at capacity; a new Track capacity failure latches
failed before unlocking and reuses existing Close to stop the expiry timer
and drain old sockets within the original total budget. The refused untracked
socket still belongs to the caller for cleanup. There is no new authority,
protocol, persistence ledger, worker pool or compatibility branch.

The deterministic regression follows CRL#1 good handshake → zero-active Poll
with CRL#2 revoked → late Track refusal → CRL#3. Omitting the unexpired peer
must latch failure; retaining the revocation must keep source readiness while
still refusing that peer. A fresh CRL after leaf expiry can retire the old
observation, while the expired leaf still cannot connect. The valid revocation
observation also establishes the t+2 watermark, so a t+1 clock is refused and
restoring t+2 cannot revive the failed guard. Two capacity fixtures seed only
8192 observation entries, for a new or repeated serial, and require no growth,
no implicit pull, failed readiness, active0 and actual EOF on an old pipe.
Those seeded entries are not claimed as real prior certificate observations.

| This stage's identity | Actual result | Actual seconds / original bound |
| --- | --- | --- |
| repro-v1, original production source plus new tests | Natural exit1: omitted, clock rollback and both full-table cases fail; retained/expired controls do not fail | 4.430389 / 90 |
| focused-v1, phase6tls/connectiondrain race/shuffle/count1 | Natural exit0 | 7.319011 / 90 |
| root-race-v1, full race/shuffle/count1 | Natural exit0, 229 ok + 38 no-test = 267 unique final package outcomes | 582.757202 / 600 |
| vet-v1, full vet | Natural exit0, both streams empty | 3.901219 / 600 |

All owned commands reaped naturally without active signals, truncation,
capture failure or timeout. The full run uses its original600-second bound,
not an extension. Existing mise Go1.26.8/Python3.13.16, GOTOOLCHAIN=local,
GOROOT unset, readonly module locks, -p2/GOMAXPROCS2 and the Go child's umask022
remain. Ordinary official Go proxy/sumdb/developer caches retain the prior
reviewed recipe; no frozen diagnostic cache/index or final verifier offline
recipe changes. Two private preparation assertion errors are preserved and
corrected before their dependent actions: explicit immutable lock names replace
an order-dependent snapshot check; a Git preparation membership assertion is
fixed before candidate output/Git writes. The successful formatter and failed
old-source run are not replayed. Neither correction changes Go inputs or gates.

Only two Go files and three progress documents change. Both tested Go files,
go.mod/go.sum and AGENTS remain byte-identical after full checks. No Provider
DTO/wire/compatibility metadata/Contract or Docker driver/sandbox-lifecycle
change triggers the named Contract-lock CLI or tagged Docker integration;
neither is claimed as run. Existing source-loss recovery and actual TLS tests
remain. Test PKI, pipe EOF and full Go checks do not prove live Vault, Guest
revoke/CRL-loss/replacement, three isolated Provider commands, network/UID/GID,
or final topology/original16 acceptance. Old candidates and receipts cannot
inherit this source change without their affected source-bound and real gates.

Evidence is private `slice6-crl-track-revocation-20261022-082700` outside Git;
old checkpoints and failures are preserved. Reviewed source/docs follow a
normal commit/push with exact local/upstream/live SHA checks recorded separately;
this source paragraph alone is not proof of synchronization or formal step4.
Phase6 remains **5/15**: step1 historical bounded GuestE unchanged/unreplayed;
step2 continues with this source gap closed; step3 final complete liveProfile-v2,
original16 and independent formal acceptance incomplete; formal step4 not started.
Docker authority/Linux/native/P2, public ProfileV2/provider-v3 holds, two-issuer
broker/general with PostgreSQL using general, quotas, deadlines, guards, old
locks and evidence-reuse rules remain. Timers stay off. Continue a separately
reviewed existing startup item; held runtime paths still need original proof.


## 2026-10-22 observed CRL expiry checkpoint

Status: source fix implemented and focused race/vet passed; required full
race **FAILED** at the unchanged limit. This is an unaccepted interim source
checkpoint, not closure of the fixed complete-mTLS/CRL ledger row or Slice6.
It neither needs nor replaces Docker management-authority evidence.

The relative evidence timer calculates its delay when a CRL is installed.
After a wall-clock jump forward, Ready or Track can first observe
`now >= collectedAt+S` or `now >= nextUpdate` before that timer fires.
Previously these entries only refused new work; old sockets remained tracked,
and a subsequent clock rollback could reuse the unexpired-at-old-time state.

One mutex-held transition now marks that observed expiry unavailable,
advances lastNow to its first observed expiry time, invalidates the old timer
sequence and stops the timer. Ready and Track unlock before one existing
drainAll call, preserving the original total C and worker limit. There is no
new failureSequence increment: completion-time signature/binding/freshness
and clock checks still reject old responses, while genuinely fresh pulls,
including an in-flight pull, may recover ordinary expiry. Observed rollback
beneath that first expiry watermark still latches failure. This is observation
at those entries, not a continuous wall-clock monitor. Existing conservative
concurrent refresh/drain semantics are retained. Refused untracked sockets
remain caller-owned. No persistence, authority, protocol or fallback is added.

The regressions cover Ready/Track with source freshness or signed CRL
nextUpdate taking precedence, at deadline-1ns, exactly at it and after it.
Before-expiry controls actually forward a byte. Expired cases require actual
pipe EOF, active0, timer invalidation and the new watermark; a newly signed
CRL#2 restores readiness and admits only a new connection. Atomic clocks and
channel synchronization cover stale and fresh in-flight responses; rollback
cannot restore the expired guard. Old code fails these connection/watermark
checks. Its fresh in-flight subcases additionally consume the existing 1s
pull deadline while waiting 1s for missing EOF; that secondary timeout does
not independently establish the cause or a failureSequence policy change.

| This stage's identity | Actual result | Actual seconds / original bound |
| --- | --- | --- |
| repro-v1, original source plus new tests | Natural exit1; expiry and rollback regressions fail; four before-expiry forwarding controls do not fail | 16.974111 / 90 |
| focused-v1, phase6tls/connectiondrain race/shuffle/count1 | Natural exit0 | 6.849086 / 90 |
| root-race-v1, required full race/shuffle/count1 | FAILED: timeout, actively SIGKILLed owned group, child exit-9 / recorder exit2 | 600.011412 / 600 |
| vet-v1, full vet | Natural exit0; both streams empty | 5.311936 / 600 |

The failed root run received 8587 stdout bytes and zero stderr bytes before
timeout, with 87 ok and 24 no-test package outcomes, no emitted failure stack
and no complete full-run result. Unreceived/buffered output completeness is
unknown because natural EOF was not observed. Neither these 111 outcomes nor
the last ordered package line locates the blocked test or proves the remaining
packages. The owned group was reaped; the failed identity is preserved and not
retried. No per-stream byte cap was reached. Focused/vet commands reap
naturally without signals or capture failures. The two Go files and existing
locks match the tested snapshot. Existing mise Go1.26.8, GOTOOLCHAIN=local,
GOROOT unset, -mod=readonly, -p2/GOMAXPROCS2, ordinary developer caches and test
umask022 remain. No global tool installation, frozen cache/index, go.mod,
go.sum or AGENTS change occurs. Narrative updates do not cause another full run.

Only the two Go files and these three progress documents change. No Provider
wire/Contract or Docker driver/sandbox-lifecycle change triggers named Contract
or tagged Docker CLI gates; none are claimed. Test PKI and real pipes remain
component evidence, not live Vault/Guest revoke-loss-replacement, three Provider
processes, network/UID/GID enforcement or final topology/original16 acceptance.
Old candidates require affected source-bound builds/gates before inheriting
changed source. A separate identified gap remains: Close errors are ignored,
and Poll partial close failure may leave other tracked sockets. Fixing it must
preserve one total C; this stage neither fixes nor counts it as closed.

Private evidence: `slice6-crl-observed-expiry-20261022-093433`, outside Git,
with old `slice6-crl-track-revocation-20261022-082700` and failures unchanged.
The validation summary v2 clarifies that timeout logs are received bytes, not
proof of natural EOF; v1 and all original raw records are retained. Independent
review permits normal commit/push as an explicitly unaccepted interim
checkpoint; it does not waive the failed root gate. Full local/upstream/live
SHAs and actual synchronization are verified separately. No force push,
release or merge occurs. Next independently locate the full-race timeout before
a new justified validation identity; do not repeat the failed identity or
extend the limit.

Slice6 step1 historical bounded E is unchanged/not replayed; step2 remains
ongoing; step3 full live Profile-v2 inventory/original16/independent acceptance
is incomplete; formal postacceptance step4 has not started. Phase6 remains
**5/15**. Docker authority/Linux/native/P2 and ProfileV2/provider-v3 holds stay.
Broker/general only, PostgreSQL general, original guards, budgets, quotas,
locks and evidence-reuse rules remain; timers stay off.

## 2026-10-22 Peer-CRL same-call validation

This is an **unaccepted interim checkpoint: full validation remains FAILED**.
PeerCRLSources now uses the existing private final-profile verifier after its
same-call entry Profile.Validate, removing one duplicate validation on the
unchanged snapshot. Complete final-graph/nine-owner, ordinary/DNS/purpose and
source checks remain; both public entries still revalidate every call. New
refusals rehash both Profile and Sources bindings before rejecting unsafe
root/privilege settings and accepting the original input again. Existing
race benchmark samples show median allocated bytes -43.95% and allocation
count -33.83%, but median ns/op is 29.1% slower with a wide range: no latency
improvement or previous-timeout cause is proved. Focused race passes in
84.742314s under 90s; full vet passes in 56.586027s. Required full race reaches
its unchanged 600s boundary (actual 600.034008s), is actively terminated/reaped
and **fails**. Its 111 received package outcomes do not establish full success
or identify a stuck test. All 2166 fixed source/lock pins match; existing
mise Go1.26.8, -p2/GOMAXPROCS2 and test umask022 remain. Evidence:
`slice6-peercrl-validation-once-20261022-032759`. Earlier f46 local/upstream/
live synchronization is confirmed separately; this checkpoint's normal Git
synchronization is checked separately from validation. No new runtime,
Vault/Guest/three-Provider or final 16-scenario gate runs, and old candidates do not
inherit changed source. Close-error/partial-drain handling remains open.
Docker authority/Linux/native/P2 and public ProfileV2/provider-v3 holds,
two-issuer policy, PostgreSQL general, old locks, reuse rules and budgets
remain. Phase 6 stays **5/15**: Slice 6 step 1 historical bounded E unchanged,
step 2 ongoing, step 3 incomplete, formal step 4 not started. Timers stay off.

The local allocation measurement reuses the existing compile_index_once benchmark, three iterations per sample and three samples, under the original 90-second recorder. Each new allocated-byte/count sample is below every old sample; timing samples are dispersed and cannot be attributed to the host. No benchmark or failed full-race identity is rerun. Two read-only owned-process snapshots are not a full census at the deadline or a stack trace, so they do not locate the timeout. This change does not alter cache/index authority or evidence-reuse rules. There is no Docker driver/lifecycle or Provider Contract change; no new tagged Docker or named Contract-verifier result is claimed.


## 2026-10-22 bounded race timeout diagnosis

This is an investigation checkpoint, with **no Go source change or formal
acceptance**. Phase6 remains **5/15**. Existing full-race failures remain
FAILED; this stage does not blindly repeat `./...`.

Independent read-only review compared the two previous 600s failures and the
582.757202s successful run. Both failures received the same 111-package
prefix; the successful run received 267 outcomes, including phase6security at
400.906s. These summaries lack arrival times/test names/seeds, and the prefix
does not prove that later packages were unexecuted. A failed-run process
snapshot at Go elapsed7:59 with phase6security.test elapsed1:39 suggests a
rough6:20 delay before that test process appeared, but does not prove a hung
test, function-level CPU cause, cache cause or host/I/O bottleneck.

A new reviewed identity, `slice6-race-timeout-diagnosis-20261022-041657-package-json-v1`,
ran only `./internal/phase6security`, adding JSON observations to the original
race/shuffle/count1 recipe. Existing mise Go1.26.8, -p2/GOMAXPROCS2, test
umask022, module checksum sources and cache paths stay fixed. There is no
increase in quotas/deadlines, no cache/index option change, no global tool
installation, and no unrelated-process intervention. Read-only Git checks
separately disable optional locks; this does not alter the Go environment.
The observer drains Go and ps pipes concurrently through one selector, samples
only this run's process group about every10s (ps2s/64KiB), and keeps the Go
600s deadline independent. Nine synthetic refusal/scheduler tests pass,
including simultaneous pipe draining, deadline/stream refusal, cleanup and
separate read-only Git environment. The final offline analyzer adds three
passing timeline/unknown/-O refusal tests. These are private diagnostic tests.

The actual diagnostic is **FAILED** due to the original stdout1MiB cap:
controller elapsed456.539950s; Go receipt456.529678s, exit-9, signalled and
reaped, received1048933B/stored1048576B; stderr0. This is not a600s timeout or a
package PASS. Complete source/tool/evidence postchecks match all2166 fixed
source/lock inputs with unchanged clean c0f08d3666d8b747c8d36757929ec599c5c90c9e.
No failed identity was repeated and the cap was not increased. Its known
process-group postcheck returned no matching rows; escaped/unobserved children
are not inferred absent.

After independent input review, offline analysis froze and rechecked all142
raw files (1320465B) and ten additional pins. It decoded3961 complete events;
the final115-byte partial JSON line is retained and excluded. Seed:
`1792643411634575000`. The complete prefix reports151 top-level passes,5 skips,
0 observed top-level failures and **no package terminal result**. The final
unpaired run in the saved prefix is not a stuck-test finding; its terminal
record may be beyond the truncated prefix. The five slowest completed tests:

| Test | Reported seconds |
| --- | --- |
| TestCompleteV2SyntheticFieldsHaveSuccessPathButNoAdmission | 48.90 |
| TestPostgresPeerCRLV2OwnerIsolationAndPinnedDecode | 38.00 |
| TestSlice6EvidenceRequiresCompleteClosedInventory | 32.49 |
| TestSlice6ReceiptBundleRejectsCrossRunAndTampering | 27.40 |
| TestCompiledPeerCRLAuthorizerMatchesClosedSources | 24.98 |

The first test-run event was received2.782432s after launch in this run. It
cannot be transplanted to explain the older full-run startup delay. Forty-six
ps samples yield44 matched test-process intervals, with360.99s of observed
user+system CPU counter progress over endpoint windows spanning approximately
438-444s. Parent observer CPU is0.963395s; ps command elapsed times sum2.829914s
and overlap the Go run. These observations show computation progress in this
window, not continuous absence of waits, full host accounting or function-level
attribution. CPU display quantization and ps coverage bounds apply. Exited,
escaped and short-lived processes are not fully counted. Summed test durations
may overlap if tests run in parallel and are not a serialized wall-clock
breakdown. Old received summaries and new JSON results remain separate.

Next review a focused CPU attribution plan for the measured48.90s synthetic-v2
test and its validation call chain, using a fresh identity and an applicable
unchanged original boundary; do not repeat the failed whole-package JSON run.
The existing public-authorization loop remains only a static cost candidate,
and multiple measured tests contribute cost. No source optimization, old
failure closure, full-race PASS or runtime gate is claimed by this stage.

Evidence is private under `slice6-race-timeout-diagnosis-20261022-041657` outside
Git. A preparatory historical-index schema mismatch and draft Git optional-lock
review block are preserved; old content-only index fields were all compared,
and new full identities do not invent historical inode proof. Old indexes,
seals and raw failures were not regenerated. New dynamic raw files were frozen
before offline derivation. Development remains mise/Docker; timers stay off.

Slice6 fixed four steps: step1 historical bounded Guest E unchanged; step2
ongoing with this diagnosis; step3 full live Profile-v2 inventory, original16
and independent acceptance incomplete; formal postacceptance step4 not started.
Docker authority/Linux/native/P2 holds, public ProfileV2/provider-v3 holds,
broker/general two-issuer policy, PostgreSQL general, original nine bindings,
64 barriers, locks and evidence-reuse rules remain. No Docker/Vault/Guest/three
Provider/final16 run occurs. This progress-only documentation commit is not
formal step4; normal Git synchronization is checked separately.


## 2026-10-22 targeted synthetic v2 CPU diagnostic

This independently reviewed single-test investigation is **FAILED**, not a
source optimization or a formal gate result. Phase6 remains **5/15**. The
prior package/stdout and full-race/600s failures are preserved, not retried.

Fresh identity `slice6-v2-target-cpu-20261022-050334-target-cpu-v2` targets only
`TestCompleteV2SyntheticFieldsHaveSuccessPathButNoAdmission` with the existing
race/shuffle/count1/JSON recipe and managed mise Go1.26.8. Standard CPU profiling
retains the test binary in a new private root. The test and two local-only
pprof reports share the original90s absolute deadline, original1MiB per-stream
cap and -p2/GOMAXPROCS2 recipe. Profile1MiB/binary16MiB checks are observed
thresholds, not kernel file-size caps. No quota, timeout, cache/index,
fixture, lock or admission rule changes. No unrelated process is touched.

Final review first blocked a controller gap that could start a child after
preparation consumed the deadline. The v2 correction rechecks the absolute
cutoff immediately before Popen; a synthetic crossing-deadline case proves no
child starts and empty raw files remain. All11 offline refusal tests pass
naturally in0.433463s, covering output bounds, identity/replacement/link checks,
cleanup and complete exact test outcomes. This private harness result is
separate from the real diagnostic. The unexecuted v1 and review block remain.

Actual shared batch elapsed is25.428685625s; the target Go receipt records
25.428160834s, exit-9, active termination and leader reap, failure
`Refused: exact artifact file set`. This is not a90s timeout or stream
truncation. Stdout18455B/stderr0 are retained. All68 saved JSON events are
complete. There are16 observed run/pass pairs: the top test reports21.97s and
all15 children pass. A later output says `ok ... 23.821s`, but the JSON package
terminal is absent and the Go command was actively stopped. Therefore neither
the command nor the diagnostic passes. Both flat/cumulative pprof commands
were **NOT STARTED**; no CPU hotspot, optimization gain or historical-timeout
root cause is established. The profile is not analyzed through a salvage path.

After stopping, the owned0700 artifact directory contains only two owned,
single-link regular files: profile31646B/mode0644 and binary16370002B/mode0755,
both below their original observed thresholds. Original modes, dev/inode,
full hashes and bytes are retained; no post-failure chmod or deletion occurs.
All24 direct input pins,3 helpers,74 tool-source files and2166 source/lock
entries remain consistent; postchecks record the unchanged clean d58 baseline
and upstream. There is no Go code change and no broad test rerun.

The frozen Go tool source has a concrete lifecycle candidate:
`work/shell.go` moveOrCopyFile creates `dst+"-go-tmp-umask"`, reads its mode,
then removes it before rename; `test/test.go` schedules retained-binary install
after the test run. However, the controller did not save the unexpected names
at refusal time. Static source and the final two-file listing do not prove
which name caused this failure. Next independently review exact lifecycle
observations and refusal tests; do not simply allow unknown files, remove
the guard or repeat the failed identity. No further real test was launched.

Private evidence: `slice6-v2-target-cpu-20261022-050334`. Independent actual-result
review agrees with FAILED/no hotspot and retaining original artifact modes.
Only progress documents are checkpointed in Git; the private binary/profile,
source excerpts and failed receipts stay outside it. Normal commit/push and
full local/upstream/live SHA equality are checked separately.

Slice6 four steps remain: step1 historical bounded Guest E unchanged; step2
ongoing; step3 full live Profile-v2 topology, original16 and independent formal
acceptance incomplete; formal postacceptance step4 not started. Docker authority,
Linux/native/P2 and public ProfileV2/provider-v3 holds remain. Broker/general
only, PostgreSQL general, nine bindings,64 barriers, locks, evidence-reuse rules
and original limits remain. No Docker/Vault/Guest/three-Provider/final16 gate
runs. Development stays mise/Docker and timers stay off.


## 2026-10-22 artifact refusal observation

The new evidence closes the missing **triggering-name observation for this run**;
it does not complete CPU attribution or repair a formal validation gate.
Phase6 remains **5/15**, with the prior full-race and package failures intact.

A reviewed fresh identity, `slice6-v2-artifact-refusal-20261022-060936-artifact-refusal-v2`,
uses the same single exact synthetic-v2 test and managed mise Go1.26.8 recipe.
Only private observation code changed: the first file-set refusal is retained
in memory before the original owned-process stop/reap, followed by optional
nofollow metadata while the original deadline has time left. Sixteen observed
entries/1024B names and64KiB total event bounds keep overflow/truncation explicit;
unknown names, including the exact umask probe, still reject. Scandir observations
are non-atomic and cannot establish a simultaneous directory snapshot. Review
blocked v1 because optional listing-inode failure introduced an extra rejection
for valid two-file input. Corrected v2 records unknown inode while preserving
full original lstat checks;21 offline tests pass naturally in0.517111375s, with
no signal/truncation. The blocked/unexecuted v1 and original19-test results remain.

The single actual batch is **FAILED**:19.196844667s; target Go19.195984958s,
exit-9, active termination and leader reap, `Refused: exact artifact file set`.
Neither90s nor the1MiB stream limit was reached. Stdout18605B/stderr0 are saved.
The69 complete JSON events contain16 test run/pass pairs, top test15.84s and
one package PASS17.751s. That component terminal does not turn the actively
stopped Go command or diagnostic into a pass. Both pprof commands are NOT STARTED;
CPU hotspots, latency gains and the old full-race timeout cause remain unknown.

The first refusal records reason `unknown_name`, scan EOF, no name/event
truncation or extra-entry overflow. Its observed entries are `cpu.pprof`
and `phase6security.test-go-tmp-umask`; their listing inodes and the bound root
identity are retained privately. This extra observed name is the cause of this
run's file-set rejection. These local observations are not an operator
authority claim. After leader reap, bounded
nofollow metadata in the same verified root finds the profile and records the
probe ABSENT. No refusal-time owner, mode, full identity or creator was recovered
for the probe. The final directory contains the normal two saved files. Fixed
Go source uses that exact probe name in moveOrCopyFile while retaining a binary;
name agreement alone does not establish independently authenticated creation,
a historical failure's identical cause or a production trust boundary result.

All35 direct pins,3 helpers,2166 source/lock inputs and74 tool-source files
match post-execution, with unchanged clean f483 baseline/upstream. Private
profile/binary bytes and original modes0644/0755 remain. No product Go code,
fixture, lock, cache/index recipe, quota or deadline changes. Test, optional
metadata, handoff checks and any pprof still share90s; original2CPU recipe and
stream/profile1MiB/binary16MiB observed thresholds remain. No broad test or
failed identity is repeated and no failed profile is analyzed through salvage.

Independent review BLOCKS a producing/closed proposal that would allow this
third name during writing: it changes the runtime exact-two-name invariant,
and a matching empty-file name does not authenticate its creator. It was not
implemented and no exception was requested. Next review the fixed Go tool's
existing CopyFile branch with an exact private directory configuration,
preserving runtime exact-two names, owner-only access and final full input
binding. That alternative remains a read-only proposal requiring source,
permission, refusal-test and final-input review before execution. No new
permission configuration, copy/rename/native-ABI path or extra binary was
implemented by this checkpoint. Gate/reuse-rule changes remain unapproved.

Evidence is private under `slice6-v2-artifact-refusal-20261022-060936`, outside
Git. Only the three progress documents are checkpointed; normal commit/push
and full local/upstream/live SHA equality are verified separately. Slice6 fixed
steps remain:1 historical bounded E unchanged;2 ongoing;3 full live Profile-v2
inventory/original16/independent formal acceptance incomplete;4 formal
postacceptance handoff not started. Docker authority/Linux/native/P2, public
ProfileV2/provider-v3, two issuers, PostgreSQL general, nine bindings,64 barriers
and evidence-reuse holds stay. No Docker/Vault/Guest/three-Provider/final16 gate
runs; timers remain off.


## 2026-10-22 private copy-root fixture

This checkpoint passes a private filesystem prerequisite, not another Go
diagnostic or formal gate. The fixed Go1.26.8 source checks the destination
parent's ModeSetgid before creating its umask probe and selects its existing
CopyFile branch. Darwin stat maps the directory setgid bit accordingly.
Independent review continues to reject allowing any third runtime artifact
name. CopyFile's destination open lacks O_NOFOLLOW: this local configuration
assumes no hostile same-UID writer and proves no production authority or
hostile same-UID safety. CopyFile may add temporary I/O/space; original quotas
and the future shared 90-second diagnostic budget receive no increase.

Independent design and final code/full-input review admitted one fresh
fixture identity under `slice6-v2-copy-root-20261022-064857`. It naturally
exits 0 in 0.060627333 seconds under its 30-second fixture limit. The new root
changes through the same FD from 0700 to 02700 and back to 0700, retaining
device/inode/type/UID/GID; actual mode and ctime changes are recorded. Its rwx
permissions remain 0700. Two tiny new samples created with local umask022
have modes 0644 and 0755, nlink1, current UID/GID and no privilege bits. Root
tightening preserves their full metadata and bytes. Their own FDs then
tighten to 0600, retaining original hashes and all 72 aggregate bytes.
All final new directories are 0700 and files 0600.

Eight original `ls -ldne` observations naturally exit 0/reaped under the
unchanged two-second/64KiB command limits, with empty stderr and complete
headers showing no extra ACL rows or ACL marker. Each is separately bound
to the target FD/path/stat before and after observation. All 35 direct input
pins and three helper pins match before and after execution. Original raw
observations, identities and permissions remain private outside Git.
All eight headers do carry `@` extended-attribute markers; these are distinct
from the absent `+` ACL marker and are not treated as extra ACL grants.

The first offline test identity naturally exits 5 with zero tests because
unittest discovery sees the bootstrap module; its code, plan and error remain
FAILED evidence. The new identity explicitly loads all 24 unchanged test
methods and requires both the actual count and success. It naturally exits 0
in 0.124690083 seconds with all 24 passing, no signal/truncation/timeout.
Refusals cover wrong permissions/UID/GID, dropped setgid, links, replaced
paths, changed bytes, malformed/extra ACL output and exhausted deadlines.
The tested rule and capture modules are unchanged for the real fixture.

No Go, pprof, Docker, build, scan or host-performance admission ran. No CPU
hotspot, latency improvement or old-timeout root cause follows. All prior
diagnostic/full-race failures and sealed evidence remain intact. Next
integrate this qualified directory configuration into the private controller,
with the original runtime two-name invariant, full final bindings, ACL checks
and limits. Final controller/refusal tests/new complete inputs require
independent review before a new real Go identity; the fixture alone is not
runtime admission. No product Go, Contract, old lock, cache/index recipe or
evidence-reuse policy changed, so no full Go/vet/Contract rerun is claimed.

Only three progress documents are checkpointed in Git; normal commit/push
and full local/upstream/live SHA equality are checked separately. Phase6
remains **5/15**: Slice6 step1 historical bounded E unchanged; step2 ongoing;
step3 full live Profile-v2 inventory/original16/independent formal acceptance
incomplete; formal postacceptance step4 not started. Docker authority,
Linux/native/P2 and public ProfileV2/provider-v3 holds, broker/general only,
PostgreSQL general, nine bindings, 64 barriers and evidence-reuse rules remain.
Development stays mise/Docker and timers stay off.


## 2026-10-22 targeted CPU profile

One fresh reviewed diagnostic now completes the previously blocked CPU
observation path. This is component evidence, not a full-race or runtime
release gate; Phase6 remains **5/15** and the earlier full gate stays FAILED.
Private evidence: `slice6-v2-copy-cpu-20261022-072553`.

Independent design and final implementation/test/full-input reviews preserve
the original exact target, 15 child names, managed Go1.26.8, race/shuffle/count1,
umask022, GOMAXPROCS2/-p2, module/cache/index recipe and default profiling rate.
The fresh artifact root is exactly 02700, with rwx0700/current UID/GID and a
held directory FD/path/ancestry binding. Producing allows only the original
two names, with not-yet-generated files permitted as before; final collection
requires both. Every third name, including the old umask probe, still rejects.
Per-name modes 0644/0755, expected GID, regular type, nlink1, stable identity
and the original observed 1MiB profile/16MiB binary thresholds are checked.
Fixed Go selects CopyFile before the umask probe for this directory mode.
CopyFile lacks destination O_NOFOLLOW and can add temporary I/O/space; this
is only a private diagnostic with no hostile same-UID writer assumed, not
production authority, exclusive control or resistance to that attack model.
There is no quota or time extension, and observed thresholds are not kernel
file quotas. Go concurrency settings are not a kernel CPU-quota claim.

The first offline identity executes 41 methods with 40 passes and one ERROR:
its optimized-interpreter refusal child exceeds the original two-second
limit. It naturally exits 2; the specific waiting/import cause is unknown.
Original code, input and raw failure remain. The reviewed new bootstrap
rejects the same invalid flags before additional imports, removing the later
duplicate check. A new identity executes all 41 methods successfully in
5.616076s under unchanged 30s/1MiB bounds, with no timeout/truncation/signal.
Coverage includes a binary larger than 1MiB within the original 16MiB cap,
oversize and mode/GID/ACL/link/replacement/byte/deadline refusals, and preventing
permission changes or analysis after natural-command/complete-JSON failure.
The immutable prior root/capture primitives are reused, not rewritten.

The actual shared batch passes in **75.914772167s** under 90s, including new
root preparation, seven ACL checks, Go, complete final binding/permissions
and two pprof commands. Go naturally exits 0/reaped in 71.236237166s with
69 complete JSON events, all 16 test run/pass pairs and one package PASS.
The top test reports 52.41s and the package 55.156s. Only then does the same
root FD tighten 02700 to 0700, preserving device/inode/UID/GID while recording
actual mode/ctime changes. Original full file pins and bytes survive the root
transition; the held file FDs then tighten to 0600 and freeze full pins.
The profile is 52,787B and binary 16,370,002B. Seven raw ACL observations
naturally pass under two seconds/64KiB each, with FD/path/stat checks, no
stderr, no extra ACL rows or `+` ACL marker; `@` is extended-attribute metadata.
No artifact-refusal event is observed. Non-atomic, bounded observation cannot
prove that no transient ever existed. Final collection is exactly two files.

Flat pprof naturally exits 0 in 4.064807417s and cumulative pprof in
0.409137542s; each stdout is 52,595B, stderr empty, with no timeout/truncation/
active signal. Frozen artifact bytes and identity checks pass before and
after each. All 73 direct, three helper, two module, 2166 source-lock and
74 tool-source inputs match afterward; the source checkout remains clean at
ae6bdfd476dc5c396e4f264fef3a30b40a8d73ce with the same recorded upstream.
Original bounded pre/postchecks remain separate from the diagnostic batch.

Both reports cover 52.38s and 32.09 sampled CPU seconds. Leading flat nodes
include `__tsan_read` 6.30s/19.63%, `racecall` 2.66s/8.29% and `runtime.madvise`
1.93s/6.01%. Application cumulative paths include `testCompleteV2Fields`
10.86s/33.84%, `BuildSlice6FinalExternalProfileTarget` 9.15s/28.51%,
`Profile.Validate` 8.70s/27.11% and `BindSlice6DesiredNetworkPlan` 7.37s/22.97%.
JSON Marshal and regexp MatchString appear at 4.67s/14.55% and 3.96s/12.34%
cumulative. These paths overlap and cannot be added. This samples the test
process, not controller/build/startup waiting or whole-host use; it proves
neither a paging cause, latency gain nor the old 600s full-race timeout cause.
Keep race detection and all existing assertions and bounds.

Next independently audit same-call repeated validation in
`BindSlice6DesiredNetworkPlan`. Source shows direct input validation followed
by public verifiers that revalidate that unchanged draft; its rewritten bound
profile is a separate snapshot. Any later equivalent optimization must keep
both snapshot boundaries and fresh validation at every public entry. No
product Go, Contract, old lock, cache/index recipe or reuse rule changed here,
and no full Go/vet/Contract rerun is claimed. Only the three progress documents
are checkpointed; normal commit/push and full local/upstream/live SHA checks
are separate from diagnostic acceptance. Private raw evidence stays outside
Git. Slice6 step1 historical bounded E is unchanged; step2 ongoing; step3 full
live inventory/original16/formal review incomplete; formal step4 not started.
Docker authority/Linux/native/P2, public ProfileV2/provider-v3, two issuers,
PostgreSQL general, nine bindings, 64 barriers and reuse holds remain. No live
Vault/Guest/three-Provider/final16 gate or release runs; timers stay off.


## 2026-10-22 network-plan same-call validation

This is an **unaccepted interim source checkpoint**: focused component tests and
full vet pass, but the required full race run fails its original 600s limit.
Phase6 remains **5/15**, with Slice6 step2 open. Private original evidence stays
outside Git under `slice6-network-plan-validation-once-20261022-083637`.

Independent design and final implementation/input review preserve distinct
input/output snapshots in BindSlice6DesiredNetworkPlan. The unchanged draft
receives full Profile.Validate followed by the same eight domain checks. After
the original copy-on-write network/address/digest transformation, the rewritten
bound profile receives a fresh full Profile.Validate and all eight output
checks. Existing private verifiers replace only redundant public-wrapper
validation on these same unchanged snapshots. Three new private helpers share
the unchanged trust-edge, external-service and edge-address checks; the last
still checks both edges and networks. All public entries validate every call.
The successful path goes from 18 top-level full Profile validations to 2; no
validation token, cross-call cache or weaker acceptance path is introduced.
Concurrent caller mutation remains unsupported, not a newly claimed safety.

New/extended assertions compare the complete JSON input before and after both
success and failure; reentry tests reject digest drift and rehashed unsafe
profiles, then accept the original profile again. A separate counterexample
passes input validation and every public preflight, then loses a reciprocal
Vault/network association when canonical networks replace the draft. The
rewritten profile's full validation fails, and the actual binder must return
an empty Profile/error while preserving its complete input.

Identical benchmark source and race/3x/count3 settings run before and after the
three production-file changes. Median ns/op is 1,927,685,514 to 307,982,097
(-84.02%), B/op 138,828,117 to 19,394,877 (-86.03%), allocs/op 185,257 to 41,114
(-77.81%). These three-sample synthetic results describe this benchmark only;
B/op is not peak resident memory, and command elapsed times also include build/
cache/context differences. No historical timeout cause or general latency
guarantee follows. The baseline/fixed commands naturally finish in52.562468/
12.472355s under the unchanged90s, with no truncation or active signal.

The first focused identity is FAILED at90.103202s/90, actively terminated and
reaped without truncation. Its nine top-level/23 child passes and bare PASS
lack package completion; they are not a passing command. A separately reviewed
new informative identity adds JSON receive-time/offset/EOF/reap observations
to the same nine tests and assertions under the same90s/1MiB limits. All18
offline parser/timeline refusal tests pass. The actual command naturally exits0
in14.860998s with133 complete JSON records,32 test run/pass pairs and one
package PASS. Forty-one bounded read events link exactly33766 stdout/0 stderr
bytes to both EOFs and reap. Receive times are upper bounds, not emission/CPU
measurements or an explanation of the first failure; that failure remains.

After independent acceptance of this same-source component predecessor, one
new full `go test -race -shuffle=on -count=1 ./...` identity hits the original
600s boundary: actual600.672669s, exit-9, active termination/owned leader reap,
no truncation,8592 stdout bytes/0 stderr. The111 completed package outcomes
(87 ok,24 without tests) do not establish full success or identify the
unfinished test. No failed identity is repeated and no deadline is extended.
The same fixed source's full `go vet ./...` naturally passes in27.874392s.
Complete pre/post source/Git checks and the subsequent2167-input check pass.
Existing mise Go1.26.8, GOMAXPROCS2/-p2, test umask022, module/cache/index recipe
and actual Contract lock bytes remain unchanged. No Provider wire/API/DTO or
driver/lifecycle change requires new Contract/Docker integration evidence here.

Next independently narrow the unfinished full-suite work from present package
receipts and a bounded informative observation; do not blindly repeat a whole
suite. The separate close-error/partial-drain source gap remains open. Old
failures and sealed evidence stay original, and old runtime candidates do not
inherit this source change. Three production files, three test/benchmark files
and these three progress documents form the reviewed interim Git checkpoint;
normal commit/push and full local/upstream/live SHA equality are checked
separately. Private raw evidence is not committed.

Slice6 fixed steps remain:1 historical bounded Guest E unchanged;2 ongoing;
3 full live Profile-v2 inventory/original16/independent formal acceptance
incomplete;4 formal postacceptance handoff not started. Docker authority,
Linux/native/P2, public ProfileV2/provider-v3, broker/general-only, PostgreSQL
general, nine bindings/64 barriers, old locks and reuse rules remain. No live
Docker/Vault/Guest/three-Provider/final16 or release gate runs. No global
development installation, quota increase or unrelated process intervention
occurs; development stays mise/Docker and timers remain off.


## 2026-10-22 streamed race-frontier diagnostic

This completes one reviewed diagnostic, not full repository or Slice acceptance.
The prior full race remains FAILED at600.672669s; Phase6 stays **5/15**. Private
evidence is `slice6-race-frontier-20261022-102125`, outside Git. Source baseline
is263478021b423d1ee565e5de8025efe09fa1029f with clean HEAD/upstream and0/0.

Read-only analysis confirms111 unique received outcomes (87 ok,24 no-test),
matching the first111 of an older267-package successful output and two earlier
failed prefixes. The next historical package is internal/phase6security. The
other156 are historical entries unreceived in this run, not proved unrun, stuck
or the current entire package inventory. Current fixed Go1.26.8 orders print
actions and buffers ordinary multi-package output; the original run has no
test-event/receive/process timeline. Old process group/PID observations belong
to different source/run identities and cannot bind this failure.

The already-received controlstorage/dockercontrol/desktopcandidate packages
report114.529/69.779/22.952s versus34.977/36.625/3.930s in the historical success.
Reported seconds for the same87 tested packages total405.244 versus237.607,
but parallel package durations are not an additive wall-clock/CPU decomposition.
This is a competing early-stage cost observation, not a host or source diagnosis.

Independent design, implementation/refusal-test and final full-input reviews
admit exactly one new single-package command: `test -race -shuffle=on -count=1
-v ./internal/phase6security`. It keeps miseGo1.26.8, GOMAXPROCS2/-p2, umask022,
module/cache/index recipe,600s and1MiB per stream. It does not run./..., CPU
profiling, ps, Docker or a new observer. The prior package-JSON failure preserves
1MiB containing165174B decoded Output payload plus an incomplete115B tail; plain
-v has measured format-cost justification, not a promise to stay within the cap.
Current target sources have no testing.Verbose/test.v/TestMain branch. This is
a different informative diagnostic, not a replay or a changed release/reuse rule.

Nineteen new pure parser/reception refusal tests pass naturally in0.053364208s
under30s/1MiB. They cover nested/parallel/paused and multiple pending names,
partial tails, duplicate/missing/wrong terminals, byte/clock/EOF/reap/guard failures,
and refusing command failure despite prefixPASS. A pre-execution inline launcher
SyntaxError exits1 before any test or output root; its original plan and failure
remain. The saved, precompiled new offline-v2 launcher executes the unchanged
19 methods once. An intervening reviewer argv-prefix BLOCK was disproved by
actual source/AST inspection and retracted; both opinions remain recorded.

The real command naturally exits0/reaped in **359.789372291s** under600s with
196771 stdout bytes,0 stderr, no timeout/truncation/signal and complete source/
actual Git postchecks. It has185 top-level outcomes (179 PASS,6 SKIP) and1154
all-name outcomes (1148 PASS,6 SKIP), no pending names/partial final line, bare
PASS and one package ok356.268s. Seed1792666130455392000 is this new order, not
the unavailable old full-race order. The six skips are fixture/export cases:
ControlBootstrapFixture, ControlBootstrapRealImageBytes, ControlSourceProfileFixture,
ExportSyntheticPeerCRLConstructorFixture, HeldPeerTLSFixture and HeldPeerTLSRevokedFixture
(each with the Test prefix). They are not live gate acceptance.

Constant458B metadata records start/spawn, first/last receive, stream byte totals,
EOF and reap; it stores no per-test receive or CPU observations. First stdout
receive is4.031167s after the command clock start, a receive upper bound rather
than exact startup/build time. Both EOFs and final stream lengths link to the
raw original bytes. Full40 direct/3 helper/1 module plus2167 source/lock inputs
remain, with actual clean2634780 branch/upstream/origin/staged/status guards.

The largest completed top-level reported durations are28.09s for
TestSlice6EvidenceRequiresCompleteClosedInventory,27.21s for
TestSlice6ReceiptBundleRejectsCrossRunAndTampering,25.31s for
TestPostgresPeerCRLV2OwnerIsolationAndPinnedDecode,18.05s for
TestSlice6RestartReceiptsRetainBothProcessInstances and17.68s for
TestSlice6DescriptorReceiptDigestIsNotSemanticProof. SyntheticV2 is11.27s in
this run. These rows may overlap and are not CPU attribution or a controlled
historical speed comparison. The new package completes under its own boundary;
it neither identifies the old unfinished tests nor excludes concurrency, other
packages, host variation, short waits or deadlock in the old run.

Next independently review a bounded exact-test CPU attribution for the28.09s
evidence case under the existing90s diagnostic budget, before any optimization.
Its source builds the full synthetic profile/evidence fixture, then exercises
strict decoding and complete validation through many independent refusals; this
is a candidate cost chain, not a measured function hotspot. Preserve original
assertions, input/output identity and exact artifact guards. Do not repeat a
whole repository/package run for reporting or transfer old candidate acceptance.

Only the three progress documents change in Git. Go/dependencies/fixtures and
locks match the tested source; existing full vet coverage remains valid and no
new fullrace/vet/Contract/Docker gate is claimed. Normal commit/push and full
local/upstream/live SHA equality are separate from diagnostic/acceptance status.
All original failures and sealed material remain unchanged. Slice6 step1 bounded
historical Guest E stays; step2 ongoing; step3 complete live Profile-v2 inventory/
original16/independent formal review incomplete; formal step4 not started.
Docker authority/Linux/native/P2 and public ProfileV2/provider-v3 remain held.
Broker/general only, PostgreSQL general, nine bindings/64 barriers and reuse
rules stay fixed. No global installation, quota/deadline increase, unrelated
process intervention, release/merge or automation restart occurs; timers stay off.


## 2026-10-22 evidence-inventory CPU attribution

This is one independently reviewed targeted diagnostic, not full repository,
release or Slice acceptance. Private originals remain in
`slice6-evidence-inventory-cpu-20261022-112148`. Starting complete HEAD/upstream
is87b380e04660c5678824c1746a50f52fe53038c7, clean0/0 on the fixed Phase6 branch.

The exact target TestSlice6EvidenceRequiresCompleteClosedInventory contains
19 generic,7 PostgreSQL and12 DNS named children plus3 unnamed malformed-JSON
refusals and0600 acceptance/0644 rejection in the parent. Preserve all of them.
The prior same-source streamed run reports28.09s, which is not CPU attribution
or a completion guarantee. The earlier different-source/different-test75.915s
CPU diagnostic is only scheme feasibility evidence, not inherited acceptance.

Independent design, final implementation/new refusal tests and complete new
input reviews admit a single new identity. Only BASE, TARGET,38 literal child
names, fresh output/identity and the original2167-file manifest count differ
from the existing controller; generic guard/capture/root/ACL bodies stay exact.
Original41 tests are reused only in that unaffected generic scope. Seventeen
new synthetic methods actually pass naturally in0.177236083s under30s/1MiB,
including each38missing-run/pass refusal, exact39success and reverse order,
old16frame rejection, unknown/duplicate/skip/fail/nonfinite/partial/missing
package/seed refusal, complete39+non-natural receipt refusing retention, and
complete39 routed through accept_target before retention. They are not real
artifact/runtime evidence. There is no zero-discovery or failed identity replay.

The actual recipe remains miseGo1.26.8, childumask022, GOMAXPROCS2/-p2,
GOENVoff/GOWORKoff/GOTOOLCHAINlocal, original public module/cache/index recipe,
-race/-shuffle=on/-count1/-json/-run exacttop/-cpuprofile/-o. The fresh root is
sameFD0700→02700 during producing; exactly cpu.pprof<=1MiB and
phase6security.test<=16MiB, no third name including an umask probe. Only natural
exit0/reaped/noflags plus complete39test/unique-packagePASS and one shuffle seed
permits sameFD02700→0700 and both held original files→0600. Seven bounded ACL
commands, full EOF/hash/owner/GID/singlelink/identity checks and all transitions
consume the same original90s as test and two pprof commands; pre/post full input
and Git checks keep their separate old bounds. Do not call the whole controller
wall time90s or these concurrency/observed-size controls kernel quotas.

Actual shared batch passes naturally in **51.520067625s**. Target command
49.617582875s, flat1.214565208s and cumulative0.300383333s all naturally exit0,
reap, have empty stderr and no signal/truncation/timeout. The42273B/161complete
JSON events contain39unique run/pass names (top+38), zero skip/fail/build-fail,
one package PASS and seed1792668764300528000. Top reports43.68s; this differs
from the prior unprofiled28.09s under a different order/context, with no product
source change, so it establishes no controlled regression or speed improvement.

Profile52335B SHA7b685756309dea966910dc6502cef60662f3429a5eeb294a0d46837b61adbec5
and binary16387570B SHA79e77f8ef41be7b6b5ee464066d42694b96ff68c774bb72f846dfd06b6b0378d
retain original bytes through permission tightening. Both final files are0600,
root0700, UID501/GID20/nlink1, exact2names. All7ACL observations pass without
extra ACL rows or '+' marker; '@' extended attributes are not an ACL. No third
name is observed, which does not prove no transient ever existed. Complete80
direct/3helper/2immutable module plus2167source/74tool references pass pre/post,
2326references over2325unique paths because shell.go occurs in two categories;
actual Git pre/post clean87b guards also pass. No manifest is regenerated.

Both original pprof heads report duration43.87s and32.25 sampled CPU seconds.
Leading flat rows are __tsan_read6.28s/19.47%, racecall3.37s/10.45% and
racecalladdr2.38s/7.38%. Cumulative VerifySlice6Evidence9.94s/30.82% and
rejectDuplicateMembers3.87s/12.00% are overlapping global rows;
Slice6Evidence.Validate3.32s/10.29%,
Profile.Validate2.65s/8.22% and Decoder.Decode5.74s/17.80% are other overlapping
paths. These sampled cumulative rows cannot be added. The profile covers the
test process, including race/runtime effects; it does not measure compiler/mise/
whole-host CPU or swapping, or explain old all-package600s failure/deadlock.
No remote symbolizer, third observer, whole-suite rerun or profile salvage runs.

Next read-only and independently examine VerifySlice6Evidence duplicate-member
scan/typed decode/canonicalization for a provably equivalent path, retaining all
size/duplicate/unknown/trailing/canonical and public-entry checks. This profile
provides a candidate chain, not an approved optimization or completed source fix.
Only3progress docs change in Git; product Go/dependencies/fixtures/Contract locks
stay identical, existing full vet remains valid, prior full race stays FAILED.
All old failures and sealed originals remain. Normal commit/push/fullSHA sync is
separate. Step1 historical bounded E unchanged;2ongoing;3live topology/original16/
formal review incomplete;formal4notstarted. Phase6 stays **5/15**. Docker authority/
Linux/native/P2/public holds, broker/general-only/Postgres general,9bindings/
64barriers and reuse rules remain. No quota/deadline increase, unrelated process
intervention, global installation, merge/release or automation start; timersOFF.
