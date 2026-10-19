# Held Provider / Control TLS peer component

2026-10-12. This continues Slice6 step2 after the
[CA directory observation](product-v1-phase-6-control-trust-observation.md).
Phase6 remains **5/15**. The independently reviewed scope is one real
Linux-process TLS edge, not production command admission or the final topology.

## Boundary and implementation

The fixed edge is `provider-runtime` → `provider-docker-control`,
`provider-coding-control`, with the declared address and `/control/coding`
route. Two separate role processes and two separate agent processes run under
their exact Profile UID/GID and supplementary groups in restricted Docker
containers. Agent containers have no network. The roles use an internal,
run-owned network with no published ports, daemon socket or devices.

The test-only process entry points invoke production workload-agent Manager,
Unix signer protocol and peer credentials, TLS identity verification,
source-bound CRL guard, polling and connection tracking. A bounded diagnostic
POST proves the actual TCP/mTLS exchange; it does not dispatch a Coding command
or open Store. CSR generation and leaf private signing stay in the agent.

Each role retains its own two read-only CA directory/file descriptors, obtains
an independent certificate pool from the verified original FD, and continues
checking identity, mount, permissions and bytes before TLS use and during
service. CA loss closes the guard and listener. The production transport
assembly is package-private; its public factories still require full Profile
admission before any signer or CA access.

The complete fixture Profile, all-edge source mapping and role derivatives are
field-validated inside the security package's test bridge. Original-byte hashes
bind those documents into each process. These hashes prove local fixture
consistency, not independently approved operator authority. The previous
Control-only signed observation cannot authorize this changed consumer graph.

## Evidence limits

The fresh X.509 broker/general authorities are diagnostic fixtures. The
general fixture issuer key is present only in private agent input; role input
contains no private key. This is not the production Vault → certificate
controller → agent issuance or collection path. It neither adds a production
issuer nor changes PostgreSQL's general issuer. The local image is built from
the preserved dirty worktree, not a clean or published release candidate.

`ProfileV2.Validate`, Provider serve v3, public v2 TLS factories and production
controller/agent startup remain closed. No old Profile projection, operator
signature, issuer-run authorization or frozen-R reuse is inherited.

Fixture generation and Linux integration process sources are in
`internal/phase6security/peer_tls_fixture_test.go` and
`internal/phase6tls/peer*_integration_test.go`. Private fixture bytes, exact
Docker commands, image identity, failures, scenario receipts and cleanup are
retained outside Git in `provider-tls-peer-20261012`. Use mise Go1.26.8 for
the fixture/tests and Docker for the actual Linux processes; do not activate
another global toolchain. The Go1.26.9 Coding-candidate exception is unchanged.

## Real process checks

The selected matrix contains 20 completed cases: one positive, nine initial
refusals and ten active-connection failures followed by a new-client refusal.
The positive proves TLS1.3 mTLS and the bounded POST through four Linux
processes, with exact process IDs, identities, image and mount observations.

Initial CRL absence, expiry and a broker-signed CRL presented under the general
issuer binding fail before listening. Wrong URI, DNS SAN and EKU leaves fail
even earlier during TLS assembly, not during a successful listener's peer
handshake. Changed role/source bytes and a wrong process UID also fail before
listening. The latter cases do not claim malicious-network-peer rejection.

The active cases are CRL absence, expiry, sequence rollback, source drift,
revocation of the actual client serial, agent loss, same-byte CA inode
replacement, same-inode CA byte mutation, wrong socket owner and replacement
of the socket path by a regular file. Each first establishes a connection,
then injects the fault, observes closure within the unchanged 10-second bound,
and starts a fresh client. Observed closure ranges from **1.142 to 3.462
seconds**, including fixture mutation overhead. The revocation case uses a
fresh signed CRL naming that run's verified client serial; this is not a
Vault publication latency measurement.

For the two CA mutations, both roles briefly pause while the fixture restores
the exact single-file directory and permissions, then resume with their
original descriptors. Raw stat/hash evidence distinguishes inode and content
changes; transient setup permissions are not counted as those failures.
CA loss closes the guard, cancels the test process context and closes the
listener; those cases prove combined fail-closed behavior, not that guard
closure alone caused the disconnect. The fresh client after same-byte inode replacement
therefore fails because the original server has exited; after byte mutation it
fails its own CA retain check. Other active cases fail the fresh TLS handshake.
Replacing the socket with a regular file is not proof about replacement by
another correctly identified agent process.

Original failures remain in the private checkpoint: restricted setup-helper
ownership/traversal errors; a polling race after a short-lived positive client;
omitted fault arguments that produced extra positives; and a leaf rejection
whose script initially expected the later readiness error text. None is
included as a negative pass. Their fixes change only the diagnostic harness.

## Repository verification status

Three full race/shuffle/count1 commands reached the unchanged 600-second
wrapper bound (600.028, 600.036 and 600.066 seconds, exit124); none is a pass.
The first ran alongside the Docker matrix, the second without Docker test
concurrency. After the JSON single-package diagnostic passed in **492.302
seconds** with a stricter 540-second package deadline, the third used only
process-local `GOMAXPROCS=4`. It still executed the same all-package
race/shuffle/count1 command under the original wrapper bound. The reduced
concurrency improved several other package durations but did not close the
full gate. No assertion failure was emitted before these terminations, which
does not prove the unreported packages passed. Both new generator tests skip
in the ordinary package diagnostic; other long-running existing fixture tests
continued passing. Cross-package slowdowns and observed host load support
resource contention, but do not establish it as the only cause.

The follow-up `race-gate-diagnosis-20261012` checkpoint closes the missing
**local full-repository race result** on exactly the same Go/module source.
Before running it, all 2,544 source-file hashes matched the peer checkpoint.
A focused race CPU profile completed in 18.869 seconds; it showed repeated
synthetic fixture construction and substantial race/runtime overhead, without
establishing a single cause for the prior timeouts. Independent review accepted
limiting package concurrency rather than changing validation. No production
code, test, assertion, per-test parallelism or timeout was changed.

Using mise Go1.26.8 on darwin/arm64, the complete command
`go test -race -shuffle=on -count=1 -p=6 -json ./...` passed in **510.429 seconds**
under the same 600-second wrapper; `phase6security` passed in 475.785 seconds.
All 267 package outcomes match `go list ./...`: 229 passed and 38 have no test
files. The 8,774 test/subtest run events ended in 8,754 passes and 20 existing
runtime skips, with no unfinished event or failure. Those counts are ordinary
repository test events, not Slice6 real-scenario or formal acceptance counts.
The wrapper retains test umask022, private evidence umask077, and only its own
process-group termination authority; `GOMAXPROCS` was not overridden.

The earlier three timeouts remain failures under their recorded settings.
This bounded package-concurrency pass does not claim default-concurrency or CI
success, nor establish low timing sensitivity on a busy host. It authorizes
continuing the existing work, not opening a production hold. No unrelated
workload was stopped and no global tool or scheduling configuration changed.

`go vet ./...` passed in 7.659 seconds, both Contract locks passed, and the
Linux integration-tag vet passed. The exact Linux test image also passed its
package tests as non-root with a read-only root, no network or capabilities,
and private temporary storage. This Linux execution is not a race build; the
separate required host race gate is the bounded package-concurrency result
above. These vet, Contract and Linux component results are reused from the
unchanged peer Go/module inputs; they were not rerun or relabeled as newly
executed. Twelve selected prior receipts and their original index hashes were
rechecked. No image or Docker scenario was rebuilt merely for reporting.

Every selected case removed its exact containers and ten volumes. Final checks
show zero run-labeled containers, volumes and networks and no new diagnostic
image tag; the pinned previous base image remains unchanged. No devices, Store
inputs, unrelated services or old evidence were cleaned. The final private
source/evidence index and independent review state belong to this checkpoint,
not the historical migration receipts.

## Continuation

Production operator authority, the complete source/Store/consumer observation,
actual Provider/Control/Scanner command composition and source-bound Vault /
controller / agent startup remain separate open gates. The next design must
bind that real consumer graph and issuance path without converting the held
test bridge into a public bypass. Browser uncertainty, the isolated Provider
commands, remaining network/identity/permission and Guest revoke/loss/replacement
scenarios still follow in Slice6 step2.

Slice6 step1 retains its bounded historical Guest E acceptance; step2 continues;
step3's final live inventory, original16 and independent formal acceptance are
incomplete; step4's post-acceptance documentation/submission/push handoff has
not started. No Git staging, commit, push or release is part of this component.
