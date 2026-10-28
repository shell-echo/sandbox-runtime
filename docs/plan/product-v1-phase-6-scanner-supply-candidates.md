# Scanner supply candidates and source-route decision

Date: 2026-10-28. Status: documentation feasibility complete; no candidate
selected or admitted. Phase6 remains **5/15**, Slice6 step2 ongoing.

The fixed engine remains **ClamAV 1.4.6 LTS**. ADR0055 and the
[source-closure boundary](product-v1-phase-6-delivery-and-handoff.md#current-builder-source-closure-2026-10-25)
still require authenticated complete engine/base/dependency/rule inputs,
full-image vulnerability checks, private socket and exact loaded rules with
a real operator check no older than72hours. Scanner limits remain4GiB/2CPU/
64PIDs/one scan. No existing lock or historical receipt is changed.

## Bounded official-source comparison

| Route | Actual documentation observation | Decision |
| --- | --- | --- |
| Chainguard ClamAV | The [product page](https://images.chainguard.dev/directory/image/clamav/overview) points to entitled organization access/trial; exact1.4.6 arm64 input is unestablished | HELD; public free-image signing examples cannot authenticate this private-organization image |
| Docker Hardened Images ClamAV | [Catalog](https://hub.docker.com/hardened-images/catalog/dhi/clamav) lists the product; [verification docs](https://docs.docker.com/dhi/how-to/verify/) require registry authentication | HELD under the current no-login scope; free account availability is not an approved credential or evidence |
| Alpine v3.23/community/aarch64 package route | Both [clamav](https://pkgs.alpinelinux.org/package/v3.23/community/aarch64/clamav) and [clamav-daemon](https://pkgs.alpinelinux.org/package/v3.23/community/aarch64/clamav-daemon) extracted pages state1.4.4-r0 | HELD for mismatch with fixed1.4.6; no other branch, edge package or version substituted |

These are provider-extracted pages and search leads, not original HTML,
live signed APKINDEX or OCI responses. A Chainguard tags-page tool error
is not HTTP404 or global product/version absence. DHI's public key and
attestation documentation are leads, not approved trust roots or verified
subject coverage; its skip-tlog example does not change project policy.
Generic multiarch claims and an amd64 search lead cannot establish exact
1.4.6 arm64 availability. No login/account creation or payment occurred. No registry body, key,
APK, index or source recipe was fetched; no cryptographic verifier, build
or candidate was run.

## Next source investigation and refusal boundary

The two fixed Alpine pages share origin/recipe-commit declarations, but their
version prerequisite failed. The approved conditional APKBUILD request
therefore stays unexecuted. Stop these routes at their stated conditions.

Next independently assess the exact official1.4.6 signed-source route and
the minimum controlled build inputs; do not install a C compiler or SDK to
discover whether its inputs can be authenticated. A distribution-package
route may be reconsidered only with new independently reviewed evidence for
the exact version, release, architecture, key/index/package signatures,
recursive dependencies and ABI. Do not mix edge with stable repositories.

Existing Desktop locks cover fixed Desktop packages, not Scanner. Their
Go verifier proves closed inventory/hashes; it is not a generic APK-signature
verifier. Earlier GPG edge mathematical diagnostics do not grant new package,
signer, native installation, ELF or full-image admission.

Keep RuleManifest.EngineImageDigest as the independent engine OCI identity,
separate from the composite Scanner image; a package-set hash cannot stand in.
Before implementation, independently review how authenticated engine/source,
base and dependencies produce that complete engine image, then how its exact
files and the same clean Go1.26.8 role map into the composite image. The ordinary
recipe selector currently refuses Scanner and must stay closed until this
complete path and its refusal tests are reviewed. No metadata-only success
or new source-proof issuer is introduced.

Required later evidence includes release signatures and independently sourced
keys; source/patch/compiler/SDK/ABI/dependency locks; immutable selected-platform
OCI bytes and source-to-image mapping; fresh complete scans; official rules,
operator freshness and actual load; and affected runtime/refusal/cleanup gates.
Audited local Slice6 candidates do not waive third-party authenticity. Slice7
still owns publication and release-signature acceptance. No new publisher key,
compiler, SDK or trust-policy change is approved by this plan.

Private evidence: slice6-scanner-alternative-discovery-20261028-v1. Both
documentation stages have separate independent review; no native gate passes
are claimed. Existing source/runtime evidence is reused only within its
unchanged coverage. Timers stay off, development uses mise or Docker, budgets
and evidence-reuse rules stay unchanged. Slice6step3 topology/original16/
independent acceptance and formalstep4 remain incomplete.
