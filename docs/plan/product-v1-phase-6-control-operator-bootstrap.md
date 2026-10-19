# Slice 6 Control operator bootstrap and process evidence

2026-10-12 — independently reviewed **held component**, not production
operator admission, service readiness, or Slice 6 acceptance. Phase 6 stays
5/15. Public `ProfileV2.Validate`, core v2 startup and provider serve v3 holds
remain closed. The existing two-issuer policy and frozen-R reuse rules do not
change.

This page records the earlier v1 bootstrap checkpoint. Its then-open delivery
work is continued by the [v2 held process-delivery component](product-v1-phase-6-control-process-delivery.md);
that component still grants no production or Store admission.

## Declaration and independent trust root

The optional `docker_control.operator_bootstrap` member is part of the single
canonical, fully checked Profile-v2. Absence preserves old encoded bytes and
does not admit the new bootstrap protocol. Its fixed protocol and target are
`sandbox-runtime.control-operator-bootstrap.v1` and
`provider-docker-control-bootstrap-v1`. FD3 contains exactly 32 public
verification-key bytes; no operator private signing key enters Control.

The Profile's key ID/digest is a declaration, **not its own trust anchor**.
`internal/controlbootstrap` separately requires an executable-provisioned key
commitment. Normal builds leave this commitment empty and fail closed. Neither
stdin, environment, Profile, nor the loader envelope selects the commitment.
Production provisioning, attestation and rotation of that commitment still need
a separate reviewed implementation. The local-role build target exists but
its clean-source requirement, Go1.26.8 lock and empty default pin are unchanged.

The versioned loader target has a distinct FD table: Control FD3 is a 32-byte
public key; the existing TLS agent FD3 remains its 64-byte request-signing
private key. The Control reader checks actual FD number, inherited non-CLOEXEC
O_RDWR sealed memfd, regular mode0600, exact owner/size/link count, zero offset
and all four immutable seals. A FIFO, ordinary file, incomplete seals, a wrong
FD, pin or process identity is refused. Control runs with its declared
UID/GID and the exact observed primary/supplementary group set.

The new Control config protocol is
`sandbox-runtime.provider-docker-control-bootstrap-config.v3`. It uses the
fixed private Profile path and does not accept mutation inputs. After bootstrap
verification it **still returns held**. It does not reuse the old diagnostic
pipe, authorize a Store, or dispatch a Docker mutation. The operator challenge
must follow actual source/root/volume/graph observation; it cannot be signed
in advance in the one-shot loader envelope. That post-observation production
transport and source-owned Store/Control composition remain unimplemented.

## Image and process evidence

Eight launch declarations cover Control, three Provider endpoint roles and
those four roles' TLS agents. They bind source revision, actual source snapshot
digest, executable digest and (where applicable) loader digest. These fields
are claims until independently proved; the other eleven members of the earlier
19-consumer diagnostic census are not upgraded by this component.

`ReviewControlServiceImage` re-derives those identities from complete canonical
Profile bytes and checks the original OCI index, selected platform manifest,
config and effective ordered layer bytes. It checks role/loader byte hashes,
fixed entrypoint, empty image Cmd, default non-root user, working directory,
exact PATH environment, no declared volumes, healthcheck or OnBuild actions.
This proves bounded byte correspondence, not signed supply provenance, a clean
release candidate, or live identity. Container create overrides and actual
mounts still require their own complete census.

`tools/control-process-observe <deployment> <role|loader>` reads a canonical
Profile from stdin and observes only namespace PID1 on Linux. It hashes an
opened `/proc/1/exe` descriptor and brackets the read with actual executable
identity, start ticks, command line, all UID/GID values, supplementary groups,
namespace PID, zero capabilities, no-new-privileges and seccomp state. Loader
and role are distinct stages; a loader result cannot pass the role check.
Errors expose no observed host identity through a stable service API.

The probe is an explicit trusted-operator Docker exec action. It is **not**
added to the runtime GET-only Docker collector. The operator must bind the
probe's own bytes, selected image, complete container ID, Docker PID/StartedAt,
launch environment and exact mounts before and after the observation. The
probe's JSON cannot authenticate its collector or claim service readiness.
This tool has not been packaged or authorized in production role images.

## Local actual evidence and limits

Private evidence is retained outside Git under the recovery checkpoint named
`control-production-bootstrap-20261012`. Its source is a dirty workspace
snapshot, with full file hashes; HEAD91fe315 is only its baseline. The three
local test images are explicitly non-release diagnostic fixtures, compiled
using mise Go1.26.8 for Linux/arm64. The probe is baked into their read-only
image layers; its original OCI bytes match the locally compiled binary. No
extra writable executable mount, privileged role, Docker socket, loop device,
external network or production operator key is provided.

Actual checks passed for sealed FD bootstrap positive/rejections, original OCI
role/loader byte binding for all eight declarations, five Control/TLS role
PID1 byte observations, two loader PID1 observations and UID/group/argv/wrong
binary refusals. Docker create environment and extra read-only mount negatives
were refused before start/exec. Linux on this Docker daemon actually exposes
primary GID in the supplementary list (Control `0,57011`); this is observed
platform evidence, not a portable Linux assumption.

The five role observations used an explicit direct-entry diagnostic override
while the actual binaries awaited stdin. They are **not** approved loader-to-
role startup or service-ready positives. The two approved loader launches
subsequently ran the actual Control/TLS commands and exited held. The three
actual Provider commands refused the v2 Profile at the current core v1 startup
reader. That earlier refusal does not establish later Provider TLS behavior.
No full topology, CA/CRL content readiness or production operator signature
was accepted. All test containers, five config volumes and three new image
tags were precisely reclaimed; no devices or networks were created.

Preserved failed attempts include the first manifest-vs-index export mismatch,
a test Profile with a stale image-bound source intent, test-volume ownership
initialization order, and an unnecessarily order-sensitive Env assertion.
Only test harness/generation was corrected; validation was not weakened and
failed raw outputs and OCI archives were retained. A first full race run reached the unchanged
600-second ceiling and is explicitly failed. Its owned orphan test was stopped;
no stack output was recovered after the Go parent exited. Separate Vault race
reproduction passed. Final whole-repository results are recorded in the
checkpoint result, with the failed run retained.

## Remaining gate and next result

Design and independently review production pin/probe delivery and the
post-observation operator challenge/signature transport. Compose those with
the source-owned Control Store and actual Provider/TLS command path before
attempting a service-ready positive. That work must preserve the public holds
until the named formal gate is satisfied. Actual CA/CRL bytes, peer revocation,
loss/replacement, remaining Browser/isolated Provider scenarios, final live
Profile-v2 topology and the original16 scenarios remain open.

Slice6 step1 retains its historical bounded E acceptance without replay;
step2 is ongoing, with this held component evidence and production blockers;
step3 is incomplete; step4 has not started. No commit, push, merge or release
is authorized by this checkpoint.


Final checkpoint validation passed on the final Go combination: full
`go test -race -shuffle=on -count=1 -json ./...` in **582.294seconds**, full
`go vet ./...` in **6.491seconds**, both Contract lock verifiers and Linux
tagged vet. The first600.019-second timeout is retained as failed, not erased
by the later pass; no timeout limit was extended. Only the opt-in test fixture
generator changed after the real binary build (it rebinds the selected image
into its synthetic source intent); production Go inputs and real image bytes
were unchanged. The final whole-repository run includes that correction. This
is held Slice6 step2 component evidence, not production acceptance or step4.
