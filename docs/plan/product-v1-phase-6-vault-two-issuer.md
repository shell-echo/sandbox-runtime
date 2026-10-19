# Vault two-issuer source-binding continuation

2026-10-13. This continues Slice6 step2 after the held Provider/Control TLS
peer and its bounded full-repository race follow-up. Phase6 remains **5/15**.

## Reviewed scope

Independent design review keeps the next component at the real VaultClient
boundary. The complete Profile/source compiler is private to the security
package, while production Controller/agent constructors require the public
Profile admission that remains held. A copied authorizer or a new field-only
public permit would not establish the required source-bound command graph.
Neither is introduced. Actual Provider/Control/Scanner commands, the Unix
Controller/agent chain, operator/Store admission and complete topology remain
separate unfinished work.

The selected component uses the locked Vault input and exactly the broker and
general PKI issuers. PostgreSQL remains on general. A fresh Vault dev TLS root
secures this local test's admin/client transport; it is not a third workload
issuer or production bootstrap. All identifiers, leaves, serials and CRLs must
come from that new run. No old receipt or issuer-run authority is inherited.

## Source-set correction

`VaultClient.ValidatePeerSources` previously compared the number and each
configured source tuple without requiring unique source IDs. A two-entry list
containing general twice could therefore omit broker and still succeed.
The new regression reproduced both duplicate/omitted-issuer cases before the
fix. The method now rejects repeated IDs, which together with exact length and
tuple matching requires the complete configured set. Both orderings remain
valid; missing, extra, duplicate and changed identity fields are rejected.
This tightens an internal consistency check without changing any Contract or
opening an admission hold.

## Opt-in real component

`TestVaultTwoIssuerSourceBindingIntegration` is integration-tagged and requires
`SANDBOX_RUNTIME_VAULT_TWO_ISSUER_INTEGRATION=1` plus the private archive path
in `SANDBOX_RUNTIME_PHASE6_VAULT_ARCHIVE`. Its ordinary skipped outcome is not
real Vault evidence. Before opting in, establish the required image supply,
signature, provenance and vulnerability conclusions; archive integrity alone
does not establish those gates. The test never pulls an image or changes a
lock. Use mise Go1.26.8 and the existing Docker runtime, not a global install.

The test reopens the exact index, selected linux/arm64/v8 manifest, config and
all layers, then binds actual Docker container/image observations to that
descriptor proof. It uses a fresh loopback-only Vault dev TLS service with a
bounded lifetime and a separate scoped client token. Root-token setup and
fault injection do not establish production operator authority. Raw Docker
inspection contains the temporary token environment and must stay in memory;
logs omit headers, response bodies, token material and raw inspection.

The four policies are Control, Scanner, broker and PostgreSQL client. The
planned checks cover exact issuer UUID/DER, fresh-leaf CRL readiness, immediate
serial revocation and CRL-number advancement, cross-issuer separation, mutable
default drift, role alias/wrong-issuer rejection before signing, wrong DER,
disabled CRL publication, actual CRL access denial and sealed-Vault rejection.
Default and role settings are read back; HTTP 403/503 distinguish the intended
faults from generic transport failures. Container cleanup is limited to the
fresh run identity and checks exact container/anonymous-volume absence.

Optional `SANDBOX_RUNTIME_VAULT_TWO_ISSUER_OUTPUT` creates a new private file
containing only run ID and public issuer UUID/DER. It is not a signed operator
receipt or cleanup result; use the final test/cleanup outcome with it. A future
complete Profile/source/role field check must consume those actual issuer
bytes inside the security package's test boundary, while public validation
continues to reject admission. That follow-up is not implemented by this
VaultClient test.

## Input and verification results

The exact Vault index and arm64 manifest from the external-input lock were
restored without changing either digest. Raw index, selected manifest, config,
seven compressed layers and their ordered uncompressed diff IDs verify. The
repository's `TestPinnedExternalArchiveComponent/vault` passed in 15.998
seconds, with descriptor proof
`sha256:2850f4fcd021dcb4e400511ab77800a2a18445267312b1aa2fc092dddc5f71ea`.
The rebuilt minimal OCI tar is 179,302,400 bytes with outer SHA-256
`66a2a1dd584453b05f2f4c0fc627404957141819eec49a5cc296ca66e23098bd`;
that new tar hash is not a replacement for the locked registry identities.

Real service execution is **blocked by supply**. Registry referrer queries
returned empty lists for the index and selected manifest. Legacy signature
lookups returned 404; one selected-manifest attestation lookup had a network
error and remains undetermined. No cryptographic image signature or build
attestation was verified. Verified Publisher metadata and image labels are
not substitutes. Trivy 0.74.0, using a newly downloaded database and explicit
empty config/ignore files, reported 6 HIGH findings (4 unique CVEs), 15 MEDIUM, 13 LOW and 7 UNKNOWN,
with no CRITICAL finding. Scan completion is not vulnerability-gate success;
no new exception or replacement input was approved. Failed download/format
attempts remain in the private supply records.

The source-set regression failed before the fix (3.139 seconds) and passed
after it (3.329 seconds). The final integration-tagged workloadpki package
race/shuffle/count1 run passed in 8.609 seconds with real Vault opt-ins unset.
Full vet passed in 4.917 seconds, tagged workloadpki vet in 0.285 seconds, and
both Provider and Product Contract lock verifiers passed. Component code has
independent design/code review with no remaining bounded code finding.

Whole-repository acceptance is **blocked**. The new full command
`go test -race -shuffle=on -count=1 -p=6 -json ./...` exited124 at 600.297
seconds under the unchanged 600-second wrapper. Of 267 started packages, 228
passed and 38 had no tests; phase6security had no terminal result. The log has
8,627 test/subtest starts, 8,606 passes and 19 skips, with the final PostgreSQL
peer-source/role test and its gateway-runtime subtest unfinished. No emitted
FAIL event does not prove success, absence of a deadlock or a cause for the
timeout. The previous 510.429-second full pass remains historical evidence on
its original source; it does not qualify this change. No timeout increase or
repeat full run was used. A cleanup-reporting edit touched only the new
integration-tagged file during that run; it is excluded from the ordinary
build and was covered by the final tagged package/vet commands afterward.

No Vault service was started. The four-policy real matrix, actual issuer
output, actual-issuer complete field checks and Controller/agent/command
composition therefore remain **unexecuted**, not failed-scene passes. Resolve
the external supply and bounded whole-repository verification blockers before
claiming the next acceptance result. Any changed Vault candidate or supply
exception requires its own independently reviewed decision; do not silently
upgrade the lock, self-sign the old image or reuse an old authorization.

## Evidence and continuation

The new private checkpoint is `vault-controller-continuation-20261013`, outside
Git and the migration package. Its baseline matched all 2,544 files from the
previous checkpoint. Work continues in the restored phase6 checkout at
`91fe315641779e6ea640632538309d63ad1b303f`, preserving existing uncommitted work.
The original migration-directory location is no longer present; this turn
does not claim to have re-run slim recovery verification there.

Slice6 step1 retains bounded historical Guest E acceptance. Step2 is ongoing;
the source-set correction is code/component work, not full command acceptance.
Step3 final live topology, original16 scenarios and independent formal review
remain incomplete. Step4 post-acceptance handoff has not started. Public
Profile, Provider serve v3, Controller/agent and Store holds, two-issuer rules
and frozen-R evidence reuse remain unchanged. No staging, commit, push, merge
or release belongs to this checkpoint.
