# Scanner supply candidates and source-route decision

Updated: 2026-10-29. Status: official release and bounded four-file source observation
complete; no package, engine image or Scanner candidate admitted.
Phase6 remains **5/15**, Slice6 step2 ongoing.

## Fixed authority

ClamAV remains **1.4.6 LTS**, with complete authenticated engine/base/dependency/
rule inputs, full-image vulnerability coverage, exact loaded official rules and
a real operator check no older than72hours. Scanner limits stay4GiB/2CPU/64PIDs/
one scan; no runtime updater, raw unauthenticated TCP or credential expansion.
Keep RuleManifest.EngineImageDigest as the independent engine OCI identity,
separate from the composite Scanner image. A package-set hash cannot replace it.

## Official release and fixed source observations

The [official release API](https://api.github.com/repos/Cisco-Talos/clamav/releases/tags/clamav-1.4.6)
returns release366392298, tag clamav-1.4.6, published2026-08-07. Its24 assets
include the following declarations; no listed body has been recovered here.

| Declared asset | API-declared bytes | Companion .sig bytes |
| --- | ---: | ---: |
| clamav-1.4.6.tar.gz | 45,990,124 | 801 |
| clamav-1.4.6.linux.aarch64.deb | 89,947,786 | 801 |
| clamav-1.4.6.linux.aarch64.rpm | 34,027,456 | 801 |

The [vendor download page](https://www.clamav.net/downloads) also lists1.4.6 LTS
and embeds PGP public-key armor. Its
[installation guide](https://docs.clamav.net/manual/Installing.html#verifying-clamavnet-downloads-with-gpg)
describes Talos GPG verification. The old2018 key-ID example is not an approved
current fingerprint. Embedded armor was observed as page content, not imported,
independently authenticated or used for verification; the complete standalone
key URL, subkeys, validity and revocation policy remain to be established.
API digests and filenames are publisher declarations, not cryptographic proof.

Fresh fixed API responses map the named ref to annotated tag26071af7b26cd71e66b13dcbe4bcb6bae8a8c2be,
then commit5853e1396777bae4d909cd3dd44f58352e7cf9b3 and root tree
068e789176d55b4df647788cda773cc9be058e8d. The root listing has55 entries and is
not truncated. The commit has two parents; no linear-history assumption is made.
GitHub's verified flag and release.target_commitish=main do not authenticate
the source archive, release-asset build or image provenance.

Four decoded UTF-8 source files match that tree's exact sizes and Git-blob
SHA1s: [CMakeLists.txt](https://github.com/Cisco-Talos/clamav/blob/5853e1396777bae4d909cd3dd44f58352e7cf9b3/CMakeLists.txt),
[Cargo.lock](https://github.com/Cisco-Talos/clamav/blob/5853e1396777bae4d909cd3dd44f58352e7cf9b3/Cargo.lock),
[INSTALL.md](https://github.com/Cisco-Talos/clamav/blob/5853e1396777bae4d909cd3dd44f58352e7cf9b3/INSTALL.md)
and [arm64 cross-build instructions](https://github.com/Cisco-Talos/clamav/blob/5853e1396777bae4d909cd3dd44f58352e7cf9b3/INSTALL-cross-linux-arm64.md).
This is byte correspondence to official API metadata, not source authentication.

They declare CMake3.17+, C/C++ and Rust toolchains plus a target sysroot.
Cargo.lock contains196 records:194 registry entries with declared checksums,
one pinned git dependency and one local package. This is not the actual
downloaded/compiled dependency set. C/C++ libraries, patches, source bytes,
compiler/SDK/ABI and all transitive build inputs remain unqualified.
The fixed CMake Linux RPM recipe declares CPACK_RPM_PACKAGE_AUTOREQ as
space-prefixed no; actual release RPM generation has not been checked.
Missing package Requires cannot prove absence of ELF dependencies.

## Proposed next material route

Prioritize independent authentication and data-only assessment of the official
aarch64 package before deciding to introduce a new C/SDK build chain. Its
availability may avoid local engine compilation; it does not establish a
usable package or approve an image. Source compilation remains the alternative
requiring separately reviewed complete compiler/sysroot/material locks.

First bind the exact official signature/package URLs and independently sourced
current Talos key identity, rotation/expiry/revocation rules and verifier inputs.
Then separately review bounded original retrieval and signature refusal tests.
Do not import a key from beside a download as its own trust decision, execute
installer scripts or install tools globally.

The generic installer guide discusses static external dependencies, glibc and
/usr/local, while its architecture prose still names x86/i686. It cannot prove
the actual aarch64 ELF interpreter, library/embedded-component inventory,
Alpine-musl compatibility or the required /usr/sbin/clamd mapping. Inspect
actual authenticated bytes and a compatible authenticated base before choosing
an assembly recipe. Package signatures alone cannot replace source/provenance,
complete image vulnerability/embedded-component checks or the separate engine
OCI→composite Scanner mapping. A base-family change is a separately reviewed
architecture, source, vulnerability and runtime decision.

The ordinary role recipe selector still refuses Scanner. Keep it closed until
the complete source/image path and refusal tests are reviewed. No new source
proof issuer, publisher key, compiler, SDK or trust-policy exception is approved.
Later evidence still includes fresh complete scans, official-rule verification,
operator freshness, real cold-start loaded set and affected runtime/cleanup gates.
Audited local Slice6 candidates do not waive third-party authenticity; Slice7
still owns publication and release-signature acceptance.

## Earlier alternatives retained as observations

On2026-10-28 the [Chainguard product page](https://images.chainguard.dev/directory/image/clamav/overview)
pointed to organization access/trial; [DHI verification](https://docs.docker.com/dhi/how-to/verify/)
required authentication. Both stayedHELD under the no-login scope, without
claiming a paid account was necessary. The two fixed Alpinev3.23/community/
aarch64 package pages advertised1.4.4-r0 rather than1.4.6; their conditional
APKBUILD request was not made. No edge or other branch was substituted.
Desktop APK locks and old edge GPG mathematical diagnostics do not authorize
new Scanner materials or native installation.

## Evidence boundary

Private evidence: slice6-scanner-signed-source-20261029-v1. Official pages are
provider-extracted text and API envelopes, not original HTML or successful
replays of old native source stages. Old failures remainFAILED. No standalone
archive/package/key/signature was fetched; no upstream source, verifier,
Cargo/CMake, compiler, Docker/build/scan or candidate runtime executed.
Existing mise Python and source gates, budgets, old locks, two issuers and reuse
rules remain unchanged; timers stayOFF.
Only five existing documents change. No Go/Contract/driver behavior changes or
unaffected test reruns; current five-document deltas must be explicitly bound
by future real producers without regenerating the old originalSOURCE2190.
Full topology/original16/independent acceptance and formalstep4 remain open.
