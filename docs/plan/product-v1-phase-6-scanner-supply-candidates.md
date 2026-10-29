# Scanner supply candidates and source-route decision

Updated: 2026-10-29. Status: current official declarations still point to the
refused Talos key; fresh TLS-only phase observation passes, old HTTP failure unexplained.
Independent authority/revocation and trusted-verifier supply remain held.
No package, engine image or Scanner candidate admitted.
Phase6 remains **5/15**, Slice6 step2 ongoing.

## Fixed authority

ClamAV remains **1.4.6 LTS**, with complete authenticated engine/base/dependency/
rule inputs, full-image vulnerability coverage, exact loaded official rules and
a real operator check no older than72hours. Scanner limits stay4GiB/2CPU/64PIDs/
one scan; no runtime updater, raw unauthenticated TCP or credential expansion.
Keep RuleManifest.EngineImageDigest as the independent engine OCI identity,
separate from the composite Scanner image. A package-set hash cannot replace it.

## Original-budget Talos phase observation (2026-10-29)

The [startup audit](../audits/product-phase-6-slice-6-startup.md#2026-10-29-original-budget-talos-phase-observation)
records the reviewed two-process DNS/TCP/TLS observer and complete failure closure.
The original10-second parent deadline and one8-second worker soft timer remain;
no GET or key/verifier/scan/build runs. Source-bound CA/context, all public DNS
answers, single socket/FD/peer/SNI/verified chain and closed owned descriptors are
mandatory. Missing, changed or same-byte replaced DNS/TLS receipts fail.

Fresh offline stage-policy-v5b passes28 methods, unit7.564s and whole8.979755s/90.
It keeps all original25 test methods and their assertions and adds negative-first-timestamp plus
signal/reap failure tests. Failed startupv3, actual25-method v4
(1 failure/4 errors, whole10.022942s) and unexecuted retiredv5 remain preserved.
The actual fixes reject initial relative_ns=-1 and record killpg errors without
masking the primary failure or skipping the original bounded reap. EPERM's OS
cause is unknown; it is never interpreted as proof the child has stopped.
482 test artifacts and full original input checks are retained.

Fresh tls-observe-v1 passes in4.367839s/90, parent terminal validation2.643320s/10,
worker terminal2.635746s/8. DNS/TCP/TLS function calls measure
0.633409/0.000779/1.983391s, not wire RTTs.14 events, two accepted public DNS
answers and complete TLS peer/chain receipts close naturally; child reaped,
no signals/truncation. Source2190/runtime1191/five-document/527-input full
pre/post checks pass;58 native artifacts are retained in the private directory
slice6-talos-stage-observation-20261029-v1.

This closes the bounded phase-observer item only. It neither attributes the old
HTTP timeout nor authenticates a response body, current release key or signature.
Old key **REFUSED**, independent authority **NOT_ESTABLISHED**, current revocation
**UNKNOWN**, trusted-verifier supply/Scanner admission held. Next prioritize an
independently authenticated compatible certificate/authority or a separately
reviewed supply-complete alternative. Do not rerun the old GET or execute GPG
merely because TLS succeeds. Phase6 **5/15**, Slice6step2; topology16/acceptance/
formalstep4 remain open. Existing mise, timersOFF; old evidence/locks preserved.

## Current Talos authority investigation and native endpoint failure (2026-10-29)

Fresh official provider responses still map main to documentation commit
88e34cf7c031213747c965f3c56ee854629dd7b7, root6701ff86, src460dfd33,
manual72288b85 and the same mode100755/3858B key blob55837de3. The decoded
provider blob exactly matches old SHA2565bfca75f and all original bytes.
The [download page](https://www.clamav.net/downloads) also exposes 59 armor
payload lines / 3720 base64 characters equal to the old original. That is
extracted-page data correspondence, not original HTML or independently current
signer authorization. No old-key parsing or weak-signature math is rerun.

The [vendor FAQ](https://docs.clamav.net/faq/faq-upgrade.html) gives a general
rotation statement and an old2018 key-ID example. Seven fixed official URL
observations and four domain-limited searches do not establish a policy-compatible
new certificate, independently approved current full fingerprint, rotation rule
or timely revocation authority. This bounded investigation does not prove that
such material does not exist elsewhere. Unrelated FMC TLS-certificate renewal
and malware-rule hash documentation cannot substitute for release-key authority.

The direct [key endpoint](https://www.clamav.net/downloads/gpg_public_key) is
unsupported by the web extraction tool for its reported application/gpg-keys
type. A separately reviewed new source-specific native diagnostic accepts only
that exact type at this fixed host/path. It retains public-only complete DNS,
single-socket FD/peer/SNI/verified TLS, HTTP200/no redirect/noTE/no encoding,
exactCL3858/old SHA256/GitOID and original 10-second request / 88-second worker / 90-second outer / 64 KiB stream bounds.
Old helpers/locks and their media-type profiles remain unchanged. It cannot
admit a different certificate or turn an old matching key into a trusted signer.

The new controller records bounded private error frames and lossless raw-byte
base64 files. Its first 15-method offline run, endpoint-policy-v2, fails because
finally's timeout error masks the original deadline ValueError. Preserve it as
FAILED (whole 2.835138 s / 90 s), with complete postchecks. A separate v3 implementation
only corrects exception precedence; the same frozen 15 tests and original
ValueError assertion then pass (unittest0.126s; whole 7.280807 s / 90 s). No failed run identity was reused; the same 15 tests were rerun under a fresh
identity without weakening their assertions. The earlier v1 plan was retired unexecuted.

One fresh endpoint-original-v1 native attempt **FAILS** at the internal 10-second request
deadline; worker naturally returns exit1 after full postchecks, whole wrapper 11.649875 s / 90 s.
The actual request duration is not recorded and is not inferred from the wrapper.
All three raw files decode to zero bytes, no key is published and http.json is absent.
The missing metadata receipt prevents attributing the wait to DNS, TCP or TLS,
or claiming a known HTTP status/peer. Outer capture did not kill or truncate the
worker; that does not mean the internal deadline signal did not fire.
The incomplete native evidence is a failure, not a certificate or gate pass.
Do not immediately repeat the request or reuse this identity.

Original 2190 source files, 1191 runtime files, current five documents and full
execution inputs are reread before/after without new manifests or hash caches.
Independent review checks 45 offline success artifacts / 44 inputs and 48 native
failure artifacts / 49 inputs. The old 45-artifact failed-test set is retained.
Private evidence: slice6-talos-current-authority-20261029-v1; raw provider
responses, full identity pins, private errors and failures remain outside Git.

Trusted-verifier source research remains held. The
[GnuPG release-key page](https://www.gnupg.org/signature_key.html) declares full
fingerprints, long-term-key cross-signatures and a qualified-signed PDF route;
none of those keys, cross-signatures or PDF signatures is authenticated here.
The [integrity guidance](https://gnupg.org/download/integrity_check.html) does not
authorize using the new GPG download to authenticate itself. The fixed Alpine
package page is inaccessible via the extraction tool, not proof of package
unavailability. Existing Wolfi/Alpine supply, installation, ELF/helper, current
complete vulnerability and isolation/management-authority gaps remain binding.
No new GPG version, candidate, package/source archive, tool install or scan runs.

End this bounded official-path investigation with old-key **REFUSED**, independent
authority **NOT_ESTABLISHED**, current revocation **UNKNOWN** and native endpoint
**FAILED**. Next separately review a read-only phase-observation and within-budget
failure-recording design before any fresh endpoint request; keep the original
10-second boundary. A current compatible certificate and independent authority
are still prerequisites for OpenPGP or package verification. Do not use this
network failure to waive source, signature, trust or freshness gates.

Only five progress documents change. No Go/Contract/driver behavior or old locks,
two-issuer/reuse rules, quota or timeout changes; no unaffected test reruns.
Phase6 **5/15**, Slice6step2; bounded old Guest E is not replayed, full topology/
original16/independent acceptance/formalstep4 remain incomplete. TimersOFF.

## Talos key data refusal and verifier-source boundary (2026-10-29)

A new reviewed offline data parser reads the exact original3858B/SHA2565bfca75f
and Git blob55837de36413784018702116365d2f061294e7db, preserving its footer space.
Armor/CRC24 and six packet bodies parse completely. This is data correspondence,
not a trusted OpenPGP verifier, publisher identity or release-signature result.

| Item | Actual data-only observation |
| --- | --- |
| Primary v4 fingerprint | 5BADCA2665EF59DCF8A23D8B707F0DB480836771 |
| Subkey v4 fingerprint | 69853AB2972F0C9970A842FBF567B6B2D1F17126 |
| Public keys | Two RSA4096, exponent65537 |
| Packet order | 6,13,2,2,14,2 |
| UID certification | Packet2/type0x13/hashID2/SHA1; claimed primary issuer |
| Subkey binding | Packet5/type0x18/hashID2/SHA1; claimed primary issuer |
| Additional certification | Packet3/type0x10/hashID2/SHA1; unverified third-party issuer |
| Declared creation | 2025-03-13T14:51:54Z, unauthenticated |
| Declared key expiry | 63072000seconds; calculated2027-03-13T14:51:54Z, unauthenticated |
| Revocation packets | None in this fixed file; current revocation UNKNOWN |

[RFC9580](https://www.rfc-editor.org/rfc/rfc9580.html) distinguishes the v4
fingerprint's specified SHA1 construction from signature-hash acceptance. The
required claimed self-certification and binding actually use SHA1; this is not
inferred from the fingerprint algorithm. Under the reviewed strict policy, the
real run returns **REFUSED/REJECTED_WEAK_REQUIRED_SIGNATURE**, natural exit1.
No old-date, allow-weak or verification-time exception is adopted. Stop B:
no self-signature math, import, GPG, release-signature or package execution.
This refuses available evidence for admission; it does not assert the signatures
are mathematically bad, the key expired or the publisher compromised.

38 synthetic offline methods pass, including the independent
[RFC4880 section6.6 CRC24 vector](https://www.rfc-editor.org/rfc/rfc4880.html),
weak algorithms1/2/3, issuer/time conflicts, malformed lengths/MPI/CRC, missing
bindings and revocation observations. A legal unimplemented0x19 signature is
UNSUPPORTED rather than reported malformed; that test was added before any
test execution. The original37-method plan was retired unexecuted, with its
source snapshots preserved. Tests whole1.349083s/90. Actual parse/publication
0.005061s/10, wrapper4.013133s/90; no signal, timeout or truncation.
All original2190 source and1191 runtime files, current five documents and full
new inputs are reread before/after. This is not an APK/build/scan or whole-repo
test. Raw results, complete input identities and independent reviews remain
private under slice6-talos-key-policy-20261029-v1; previous failures stayFAILED.

No existing GPG candidate is execution-admitted: Wolfi2.4.9-r12 has carrier HIGH
and incomplete supply closure; Alpine2.5.22 lacks complete install/ELF/helper/
UID/runtime closure. Historical37/19 scans use a database past recorded
NextUpdate and do not supply current evidence. OpenPGP.js's refused chain is
not a fallback. The [GnuPG integrity guidance](https://gnupg.org/download/integrity_check.html)
requires an already trusted verifier rather than letting a new tool bootstrap
itself. Prefer completing one distribution-signed route only after separately
reviewing exact roots/index/APK/source/signature/dependency/installation locks,
complete fresh vulnerability coverage and original isolation/authority gates.
No global installation, compiler family, quota or timeout change is approved.

The [vendor verification FAQ](https://docs.clamav.net/faq/faq-upgrade.html)
describes key rotation but its old2018 key-ID example does not establish a
current full fingerprint. Existing vendor key links are declarations from the
same publisher; current independent fingerprint/rotation/revocation authority
remains missing. Search did not establish that authority, not proof it does not
exist. Next independently review current official certificate/recertification
discovery using permitted signature algorithms and a separate current authority
source before material recovery or verifier execution. Do not treat merely
downloading another copy or computing expiry as authentication. Any later GPG
plan must use explicit isolated keyrings/no ambient trust/network and complete
machine-status/error checks; --check-sigs alone omits signing-key revocation
status according to the [GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html).

Original locks, reuse rules, resource/deadline gates and evidence remain fixed.
Phase6 **5/15**, Slice6step2; full topology/original16/independent acceptance/
formalstep4 remain open. TimersOFF. Only five progress documents change; no Go,
Contract, driver or supply policy implementation changes, and unaffected tests
are not rerun. Future producers must explicitly bind these current document
deltas without regenerating SOURCE2190.

## Fixed Talos public-key original (2026-10-29)

The installation guide names
[the documentation repository key](https://raw.githubusercontent.com/Cisco-Talos/clamav-documentation/main/src/manual/cisco-talos.gpg).
The download page separately names
[its key download endpoint](https://www.clamav.net/downloads/gpg_public_key)
and embeds armor. Both are observed vendor declarations, not independent roots
of trust. Neither the download endpoint nor any release .sig was requested.

The official GitHub metadata maps main→commit
88e34cf7c031213747c965f3c56ee854629dd7b7, tree6701ff86, src460dfd33,
manual72288b85, then cisco-talos.gpg with mode100755, size3858 and Git blob
55837de36413784018702116365d2f061294e7db. The unexpected execution bit was
recorded after the initial100644 assumption was refused; the file is never
executed. Decoded connector bytes match that exact blob, including a final
space. This does not establish the website build's commit.

One fresh native GET of the
[fixed commit key](https://raw.githubusercontent.com/Cisco-Talos/clamav-documentation/88e34cf7c031213747c965f3c56ee854629dd7b7/src/manual/cisco-talos.gpg)
recovers the full3858B, SHA256
5bfca75f112f04b89cd992f5f925018e8dfc28e0e7f6e33f6a4c33ed9e29d911,
byte-identical to the mapped Git blob. The saved original is0600 data,
with no keyring import. All DNS answers are public; the single socket's native
FD transfer, numeric TLS peer/SNI/verified chain, no redirect/TE/encoding,
HTTP200/exactCL/MIME and full body correspondence pass. The931B header was
parsed in RAM; only length/hash/projection is retained, so the header parse
cannot be independently replayed from raw recorded bytes.

13 offline component refusal methods pass. The old launcher cap failure is
retainedFAILED and not counted as a test pass. The successful offline wrapper
takes9.253769s/90; native request including cleanup1.002362s/10, wrapper3.288563s/90.
Source2190, runtime1191, five progress documents and all new execution inputs
are fully reread before/after; no hash cache or evidence-reuse rule changes.
Independent review checks45 test artifacts/49 inputs and47 native artifacts/
98 inputs. This authenticates neither OpenPGP self-signatures nor the publisher.
Fingerprints/subkeys, expiry/rotation/revocation policy, trusted verifier and
release-signature/package correspondence remain open. TLS authentication is
transport evidence only.

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
independently authenticated or used for verification. The fixed key URL and
body correspondence are now recorded above; subkeys, validity and revocation
policy remain to be established.
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

Private evidence: slice6-scanner-talos-key-20261029-v1; previous source research
remains in slice6-scanner-signed-source-20261029-v1. Official pages are
provider-extracted text and API envelopes, not original HTML or successful
replays of old native source stages. Old failures remainFAILED. No standalone
archive/package/release-signature was fetched; only the fixed key body above
was recovered. No upstream source, verifier,
Cargo/CMake, compiler, Docker/build/scan or candidate runtime executed.
Existing mise Python and source gates, budgets, old locks, two issuers and reuse
rules remain unchanged; timers stayOFF.
Only five existing documents change. No Go/Contract/driver behavior changes or
unaffected test reruns; current five-document deltas must be explicitly bound
by future real producers without regenerating the old originalSOURCE2190.
Full topology/original16/independent acceptance and formalstep4 remain open.
