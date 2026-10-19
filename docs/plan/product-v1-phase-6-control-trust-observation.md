# Held Control CA directory observation

2026-10-12. Slice6 step2 component following the
[source observation](product-v1-phase-6-control-source-observation.md).
Phase6 remains **5/15**; public `ProfileV2.Validate`, Provider serve v3,
production operator approval and Store admission remain held.

## Reproduced prerequisite and bounded decision

Before composing real Provider/TLS consumers, the old CA volume declaration
was tested in Docker. A named volume mounted at the declared `.pem` target
produced a directory; a regular-file check as the Control UID/GID failed.
An empty volume or metadata-only consumer is not CA or TLS evidence.

The independently reviewed prerequisite introduces only the explicit target
`provider-docker-control-trust-v4`. Its bootstrap and startup protocols are v4,
command config is `sandbox-runtime.provider-docker-control-trust-config.v6`,
and observation/signature domain is `sandbox-runtime.control-trust-observation.v1`.
The receipt scope is `held-control-trust-observation` and admission remains
`held-not-a-permit`. The old v1/v2/v3 formats cannot carry the new directory
field or trust proof; their existing bytes and scopes are preserved.

Only `internal-client-ca` and `internal-server-ca` gain `mount_directory` at
`/run/trust/<anchor-id>`. Their `target_path` is that directory's `bundle.pem`.
Every declared consumer must bind the exact storage, directory, read-only flag
and trust-anchor kind. Parent/child aliases, extra consumers and other-anchor
use are rejected. Frozen desired anchors and evidence-reuse rules do not change.
The prior public consumer-review entry and both old Store construction paths
explicitly reject the new mode.

## Observation and failure behavior

Control retains directory and file descriptors across the challenge/signature.
Linux uses bounded no-follow opens, exact root-owned directory mode 0555 and
file mode 0444, one regular single-link `bundle.pem` entry, a bounded CA bundle,
validity and exact digest checks. Each observation checks the original FDs
against current names, device/inode, UID/GID/mode/size, read-only filesystem and
exact mount ID with no nested mount. Failure poisons and closes the session.

The two artifacts and their exact Docker volume inspection digests join the
existing retained source/root/loop/volume/consumer/process observation. Two
host-invoked fixed probes compare the actual evidence before signing; Control
re-observes its retained inputs after signature verification. The 10-second
observation and 120-second ceremony limits remain unchanged. The source
session still exposes no Store initialization, admission or dispatch.

The actual daemon remains a trusted boundary. GET-only collectors and a
read-only socket mount do not confine daemon authority. Production confinement
and independent operator key approval remain open.

## Evidence scope and continuation

The diagnostic CA is one fresh local general test CA copied into the two
purpose-specific bundles; its key never enters Docker. It does not add a third
production issuer or replace the broker/general two-issuer rule (PostgreSQL
uses general). The development operator key is explicitly reused and unapproved
for production. Images are dirty-source local diagnostics, not release candidates.

Real checks exercise CA input and signed observation, not actual Provider/TLS
listeners, mTLS handshakes, issuance, rotation or CRL enforcement. Other service
claims in the complete fixture remain declaration metadata. The final live
Profile-v2 inventory and original 16 scenarios still require fresh evidence.

Private commands, original failures, OCI inputs, signatures, physical mutations
and exact cleanup are indexed outside Git by
`control-real-consumers-20261012/RESULT.md`. No migration originals are changed.

Next independently review and connect a real Provider/TLS peer to the corrected
CA layout, including source-bound certificate/CRL readiness and its failure
behavior. Production operator authority, the complete consumer graph, kernel
confinement of daemon authority and Store admission remain separate open gates.
Slice6 step1 retains its bounded historical acceptance; step2 is ongoing;
step3 final topology/16 scenarios and independent acceptance, and step4 formal
post-acceptance handoff, remain incomplete. No staging, commit, push or release.

## Component verification

The real v4 operator positive passed in 10.209 seconds. Its tagged Docker race
invocation passed in 68.986 seconds, including build/test overhead. Actual Linux
reader tests passed as non-root in a restricted container. Three signed physical
negative cases reject same-byte inode replacement, changed bytes and changed
file mode at source re-observation with no held receipt. Initial directory mode,
extra entry, symlink, missing file and old startup were rejected; writable CA
mounts and wrong volumes were rejected before startup. The wrong-owner case
also rejected at source checking, but the wrapper asserted the wrong error text;
that preserved harness failure is not counted as a clean script pass.

The same exact role/loader/probe/operator binaries also passed a fresh real v3
source-only ceremony in 25.782 seconds, without a trust field. Both source seals
were preserved; empty Store roots, exact loop7 detach, all eight loop nodes
unconfigured and offline fsck were verified. All owned containers, volumes,
networks and new diagnostic image tags were reclaimed. A premature first
cleanup attempt overlapped the tagged command; the network consumer guard
refused it before network/volume deletion. Cleanup resumed only after that
command completed. The refusal and all raw outputs remain preserved.

The final combination passed full `go test -race -shuffle=on -count=1 ./...`
in 462.510 seconds, `go vet ./...` in 7.945 seconds, both Contract lock
verifiers and tagged vet. All 2141 Go files, including 1095 production files,
match the real-image build snapshot. The original 600-second test bound and
mise Go1.26.8/Docker environment are unchanged. Independent read-only code and
raw-evidence review found no blocker within the held CA component scope.
