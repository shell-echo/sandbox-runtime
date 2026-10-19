# Held Control source observation and operator signature

2026-10-12. Slice6 step2 component; Phase6 remains **5/15**. This follows
the [process delivery component](product-v1-phase-6-control-process-delivery.md)
and retains every public startup and Store admission hold.

## Closed scope

The versioned target `provider-docker-control-source-v3` composes the actual
Control PID1 identity with retained read-only source and root descriptors,
source seal, backing and filesystem volume identities, the fixed Docker socket,
eight read-only loop device grants and three isolated Control networks.
The canonical complete Profile supplies all expected inputs. Caller-created
review JSON is not an admission credential. The source session exposes only
observation and close; it never initializes or opens the persistent Store.

This is Control-only observation. Each network has exactly the Control endpoint;
no other consumer, including a stopped container, may share its private inputs.
The three Providers, four relevant TLS agents and remaining consumer graph have
not thereby been started or admitted. Empty TLS/CA fixture volumes prove no TLS
service or trust material. The historical 19 sleep carriers are not upgraded.

`SourceProbe` checks the root inode and mount identity, source descriptor and
loop binding. It does not inspect Store contents or obtain a Store owner lock.
An external empty-root assertion is additional evidence for its particular
fixture only. Its digest must not be described as Store content acceptance.

## Versions and identity checks

The exact tuple is bootstrap `sandbox-runtime.control-operator-bootstrap.v3`,
startup `sandbox-runtime.phase6-fd-startup.v3`, config
`sandbox-runtime.provider-docker-control-source-config.v5`, and observation
`sandbox-runtime.control-source-observation.v1`. The new signature domain and
receipt scope are `held-control-source-observation`. The prior v2 process-only
target and scope cannot carry source proof or be exchanged for this tuple.

FD3 still contains only the independently pinned public key. The loader creates
sealed FD5 from its validated full container ID, run ID and nonce; the caller
cannot supply that descriptor. The Control process holds its original source
and root descriptors and shared source lock across the challenge and signature.
Source, volumes, inventory and actual process session are bracketed and compared
before the challenge and after the signature. Any failure closes the session.

The host operator independently verifies original OCI index/selected manifest/
config/layers against the source-built role, loader and fixed probe binaries.
The new target requires the four exact local-role image labels in original OCI
config, selected live image config and container metadata. Labels bind expected
metadata; they do not attest clean source or provenance. Container identity,
Created/StartedAt/PID, actual PID1 executable and UID/GID/groups are observed.
Two host-invoked probes independently collect and compare source evidence with
the challenge before signing. The Control rechecks its retained physical inputs
after verification. These checks retain the 10-second observation and 120-second
ceremony bounds, including cancellation. The final held receipt does not grant
dispatch, Store access or service startup; Control still exits held with code1.

The new target fixes daemon logging to `none`, with no driver parameters. It
rejects extra CPU, memory, blkio and ulimit overrides, OOM priority, storage
options, runtime annotations and altered proc masking/read-only path sets.
The existing Profile determines memory, CPU and PID budgets, seccomp, mounts,
networks and devices. Unknown Docker defaults fail closed rather than becoming
implicit authority.

## Trust and evidence boundaries

The operator host must independently trust its explicitly selected Unix daemon
endpoint. A daemon ID is not authentication. The in-container collector limits
its own requests to bounded GET operations and checks socket identity; the
mounted Docker socket is not made read-only by those software restrictions.
Production daemon authority confinement remains an open boundary.

A newly generated local development Ed25519 key and its source/pin record can
exercise this component. Such a key, matching Profile digest, FD3 and compiled
pin are not independent production approval. No production key, key rotation,
Store authority or original Guest operator signature is inferred from them.

Private run inputs, failures, original OCI exports, physical observations and
cleanup records belong outside Git in the recovery evidence directory. A dirty
source diagnostic image is not a clean-source candidate or a release.
Slice6 steps3 and4 remain incomplete.

## Verified component checkpoint

The real v3 operator positive passed in 35.622 seconds and the tagged Docker
race test passed in 33.869 seconds. Seven real refusals cover old startup,
wrong key, wrong signature, replay, a stopped second consumer, source inode
replacement and the unchanged ceremony deadline. Both physical drift cases
carry explicitly test-only signatures and fail at source re-observation;
neither is operator-positive evidence. Fifteen unsafe host projections and
wrong backing-volume options are also rejected. The same new binaries pass
the original v2 process-only ceremony in 2.936 seconds, with no source proof.

The final Go combination passed full `go test -race -shuffle=on -count=1 ./...`
in 513.580 seconds, full `go vet ./...` in 5.939 seconds, both Contract lock
verifiers and tagged vet. All 1091 production Go files match the real-image
build inputs; no Go byte changed after the full-race snapshot. The original
600-second suite bound was unchanged. Development used mise Go1.26.8 and Docker.

Independent read-only design, code and raw-evidence review accepted only this
held Control-only component. The original seal was preserved, every fixture
retained an empty root, exact loop7 detach and the eight-node unconfigured
census passed, and offline fsck passed. All run-owned containers, volumes,
networks and newly loaded diagnostic images were reclaimed. Earlier preparation
and observation failures remain retained and excluded from acceptance.
Private evidence and the final result are indexed by
`control-source-process-composition-20261012/RESULT.md` outside Git.

Next review the actual Provider/TLS/CA consumer composition and its operator
and Store admission boundary. The production operator key remains unapproved;
full consumer readiness, kernel confinement of daemon authority and persistent
Store admission remain open. Public holds and Phase6 **5/15** are unchanged.
No staging, commit, push, merge or release occurred.
