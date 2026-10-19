# Held Control pin, probe and post-observation delivery

2026-10-12. This independently reviewed component continues Slice6 step2.
Phase6 remains **5/15**. It does not authorize production operator admission,
Store, dispatch, service readiness or the full consumer graph. Public
`ProfileV2.Validate`, core v2 startup and provider serve v3 remain held. The
broker/general issuer policy, PostgreSQL general issuer, frozen-R evidence
rules and existing toolchain/release locks are unchanged.

## Version and trust boundary

The complete canonical Profile can explicitly select
`sandbox-runtime.control-operator-bootstrap.v2` with target
`provider-docker-control-delivery-v2` and observation protocol
`sandbox-runtime.control-process-delivery.v1`. Only this Control launch adds a
required `probe_digest`; the other seven Provider/TLS launch declarations keep
their existing shape. The v1 declaration, EOF-only startup and TLS FD3's64-byte
private key remain separate. A v1 receipt cannot become v2 authority.

The new local-role build target requires a separately supplied, mode0600,
regular32-byte **public** key file as its third argument. The build checks
clean committed source and Go1.26.8, reads that file through `tools/control-pin`,
compiles its digest into Control and records the pin, source revision and module
lock blob identities. Pin reading and all builds use the fixed offline Go
configuration with `GOENV=off`, `GOWORK=off` and `GOTOOLCHAIN=local`. Runtime
config, environment, Profile and loader input cannot override this commitment.
Normal pinless builds stay closed. This mechanism does not itself approve a
production operator key, attest its origin or implement key rotation.

The new Dockerfile stage alone adds the fixed mode0555 probe. The operator
compares independently built role, loader and probe bytes with the original
ordered OCI layers, selected index/manifest/config and complete Profile. The
probe checks its own executable inode/bytes and the fixed root-owned parent
chain; Control checks that provisioned probe before and after the signature.
No executable bind mount or runtime Docker permission is added.

The operator must already control the selected local Unix Docker endpoint and
keep it trustworthy throughout the ceremony. The input names it explicitly;
no environment/default endpoint or network daemon is selected. Docker's
self-reported daemon ID detects accidental target drift; it is **not daemon
authentication**. This component does not independently authenticate a malicious
Docker server, pin the host socket inode or protect against a hostile operator
host. These are trust assumptions of the operator environment, not guarantees
created by the signature. The private signing key stays on that host.

## Transport and actual observation

The new loader target reads one uint32-big-endian length-prefixed canonical
startup envelope (`sandbox-runtime.phase6-fd-startup.v2`). It does not wait for
EOF. It generates sealed FD0 config and FD3 public key, retains the original
read-only nonblocking Docker stdin pipe as FD4, and creates sealed FD5 itself
from the validated outer run ID, nonce, full container ID and target. FD5 is
not an operator-supplied `Files` member. The fixed shell reservation of FD3–6
and the old targets' descriptor tables remain intact.

The new Control config protocol is
`sandbox-runtime.provider-docker-control-delivery-config.v4`. Only authenticated
FD3 creates an opaque in-memory credential. Mutable review JSON, a raw public
key or a caller-selected pin cannot substitute for it. The session checks the
actual FD4 pipe and private FD5 seals/ownership/offset/bounds, binds FD5 to the
actual hostname, and observes actual namespace PID1 role bytes and credentials.
It emits a framed challenge with a fresh256-bit nonce, full startup binding,
complete Profile byte/digest identities, process and probe observations.

`tools/control-delivery-sign <private-input.json> <new-private-transcript.json>`
performs the host side. `controloperator.Input` defines the closed input fields:
explicit endpoint/daemon/container IDs, read-only config volume, canonical
Profile/envelope paths, independent source binaries, original OCI archive and
raw descriptor paths, and the private signing-key path. The input and transcript
are mode0600. The output is exclusively created; failures retain a transcript
with `status=failed`, which can include a received held receipt if a later
tail/exit check fails. Only `status=verified-held` denotes completion of every
check; the receipt field alone never proves success. This tool starts only the
already-created, unprivileged, single-attach, non-restarting container. It creates
no container, volume, device, network or permission grant; exact cleanup belongs
to the operator.

Before sending the startup frame it independently probes actual PID1 **loader**
identity. After the challenge it probes actual PID1 **role** identity twice.
Every probe is bracketed by full Docker ID, Created/PID/StartedAt, selected image,
entrypoint, UID/GID/groups, environment and mount checks. Original OCI documents
are connected to both image-inspect views and the selected container manifest.
Docker's startup normalization of `OomKillDisable=false` to null is treated as
the same enabled OOM handling; `true` is refused. The only mount is the named
read-only config volume. No source/root/ledger volume, Docker socket, device or
business network is available. Probe execution is host operator work; it does
not expand the runtime GET-only collector.

Only after these observations does the host sign the complete challenge and
its independently collected observation digest under domain/scope
`held-control-process-delivery`. It sends one bounded frame followed by EOF.
Docker stdout/stderr demultiplexing is strict and bounded; stderr/log bytes are
never challenge bytes. The complete Control session has the original120-second
wall-clock and monotonic limit, with bounded poll-based input/output and
cancellation. Host Unix connections inherit the ceremony and request deadlines
at connection establishment, including Docker attach/exec upgrade handshakes;
cancellation closes them and the wrapper retains half-close support. This
deadline enforcement does not authenticate the selected socket. Malformed,
oversized, partial, multiple, expired, replayed or
wrong signatures consume the session. Owned FD4/FD5 are closed on failure.

Control verifies with the already pinned credential and re-observes itself and
the probe after the signature. A successful receipt says only
`admission=held-not-a-permit`; the command then exits held with code1. Evidence
is **host observations before signing plus Control self-observation after
signing**, not an additional independent host probe after signing. There is no
Store `Open` method or reuse of the older diagnostic sleep-process signature
session. The signed delivery cannot retroactively authorize container grants.

## Evidence and remaining work

Private checkpoint: `control-production-delivery-20261012`. Final `fixture3`
uses a recorded dirty source snapshot, mise Go1.26.8 and Linux/arm64 Docker,
with newly built diagnostic Control/loader/probe bytes and a new test operator
key. This is not a clean production artifact, signature by an independent
production operator, supply-chain acceptance or inherited frozen-R evidence.
Earlier failed fixture attempts and partial transcripts remain preserved.
Only new Control diagnostic inputs are rebuilt; the old seven launch artifacts
are not presented as freshly running services.

Final real checks, complete Go verification, independent evidence review and
precise cleanup are indexed in the private checkpoint result. This document
specifies the evidence boundary; test success does not remove any public hold.

The next independently reviewed composition must join trusted production
operator-key provisioning and the real source inode/Store root/volume and full
consumer observations with actual Control/Provider/TLS startup. Source-bound
Store initialization, PostgreSQL/mTLS command effects, CA/CRL content and the
remaining Browser/isolated Provider/Guest failures remain open. Do not adapt
this held receipt into a source/root/volume/full-graph permit by changing its
label or reusing its signature domain.

Slice6 step1 retains historical bounded Guest E acceptance; step2 continues
with this component; step3's final live Profile-v2 topology, original16 scenarios
and independent formal review remain incomplete; step4 has not started. No
commit, push, merge, publication or release is part of this checkpoint.
