# Scanner supply candidates and source-route decision

Updated: 2026-10-30. Status: current-device differential observation is complete.
The fixed Debian security certificate11873B is recovered with matching candidate fingerprints;46 offline methods and the
bounded native data observation pass. Authority NOT_ESTABLISHED, revocation
UNKNOWN and verifier NONE ADMITTED. Original34770B Release remains unauthenticated
and its old native FAILED is unchanged. Talos key refused.
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

## Current device identity observation (2026-10-30)

Before the next Debian signature-declaration investigation, current verification
against the sealed401-file index refuses an identity mismatch. The index itself
retains SHA256 ebdb3c7973879eff72a8f81af71d0ba32e47ec904aaa91badec701fb7ba83c27;
no old manifest, receipt or byte is rewritten. This current refusal does not
retroactively invalidate the recorded historical runs.

A separately reviewed read-only differential run compares every indexed byte
and identity. All401 sealed files and43 directory anchors,2190 indexed source
files,1191 Python runtime files,108 runtime directories and7 links differ only
in device number16777232→16777233. Other file identities, size, SHA256, modes,
owners and link targets match; the runtime census is exact under its original
site-packages exclusion. The2190-source check covers its pinned set, alongside
a separate clean Git check; it is not a census of all ignored working-tree data.

V3 remains FAILED: process comm output receives81920B beyond64KiB, records
truncation and kills only its owned PID30201, which is reaped; postchecks are
incomplete. V4 uses the separately reviewed compact ucomm column under the same
64KiB/command10s/whole90s limits. It naturally completes in1.433120875s/90,
all seven command receipts are natural0/reaped without signal/truncation/late
or capture errors, process stdout33782B, and all current input postchecks finish.
Boot/mount records identify the current data filesystem but do not prove why the
device changed. Process names do not prove absence of other writers.

Independent review accepts only this complete observation. The user's existing
new-run/new-binding rule permits subsequent untrusted declaration work after
separate review of its new identity, complete current input pins and output root.
New commitments cannot replace old manifests, skip the device field in the old
guard, replay old receipts or inherit historic acceptance. No crypto/supply
admission follows. The previously recovered11873B certificate still has12 opaque
signature packets; authority NOT_ESTABLISHED, revocation UNKNOWN, verifier NONE
ADMITTED. Talos REFUSED and Release native FAILED remain unchanged.

Next: review a bounded data-only view of those12 actual signature bodies, including
issuer claims, hashed/unhashed fields, critical/unknown data, revoker declarations
and embedded signatures. Only then assess one concrete noncircular verifier path;
no GPG, new Go verifier, package, Docker, APK, scan or build runs here. Production
Go/Contract/driver behavior is unchanged; unaffected suites are not rerun.
Private slice6-device-identity-observation-20261030-v1; existing mise only, timersOFF.
Phase6 remains **5/15**, Slice6step2; topology16/independent acceptance/formalstep4
remain incomplete.

## Debian security certificate original (2026-10-29)

A separately reviewed fixed-source observation recovers exactly
https://ftp-master.debian.org/keys/archive-key-12-security.asc as untrusted public
certificate bytes. It does not select a trust root, run GPG or change a Scanner
base/engine, package lock, issuer set or evidence-reuse rule. The source and
fingerprint declarations are the previously recorded official FTP/2023-announcement
observations, not an independent root or final allowlist.

The new private observer reuses the previously tested parent/capture/durable
writer and DNS/public-address/TLS/SNI/peer/single-FD/closure path. Only the exact
certificate host/path/purpose, source-specific closed MIME and public-data
declaration change; entry wires the already reviewed key_data module.
Present MIME permits application/pgp-keys as well as the existing closed plain/
octet-stream forms; absence records null/false only for this source. Present
empty/duplicate/unknown types, missing or noncanonical CL, redirects/TE/range/
cookie/encoding ambiguity, short/extra body and unknown source still reject.
The old Talos exactCL3858/MIME and weak-required-signature refusal are unchanged.

The public-data view reuses unarmor/CRC24/packets/public only. It requires one
leading v4RSA primary, one bounded ASCII UID and one v4RSA subkey in the defined
order, with bounded opaque signature bodies in UID and subkey contexts.
Both full fingerprints must match the declared candidates. The original ASCII,
decoded SHA256 and each packet ordinal/tag/body size/SHA256 are retained;
no duplicate byte-offset parser is added. Signature packets are neither
interpreted nor verified; their presence cannot prove self-certification,
binding, cross-signature, flags, expiry or non-revocation. Unsupported actual
formats would be a profile failure with original bytes retained.

An unexecuted45-method test plan is preserved: root static review corrected the
HTML fixture's first rejection to armor-lines and added a64KiB boundary method
before freezing the fresh46-method identity. certificate-tests-v2 actually
passes46 methods, unit2.579s, whole6.825139s/90, platform natural exit0,
135 raw artifacts and644 full inputs with complete source2190/runtime1191/
five-document pre/post checks. Its known3858B Talos fixture patches only
test-process expected fingerprints and inherits no key admission. The explicit
opaque-signature test even preserves signature_verified=false after replacing
a signature body: this is data observation, not a cryptographic success vector.
The64KiB test covers header/armor bounds, not a live maximum-size network run;
broad replacement-error assertions prove refusal, not a unique error reason.

After final implementation/test review and separate new native identity/input
review, certificate-original-v1 performs one GET. Its actual response is200,
Content-Type application/pgp-keys, header510B, exactCL/body11873B and extra0B.
Complete original body SHA256:
74f81645b4e3156d1e9a88c8dd9259271b89c7099d64af89a2a6996b592faa1f.
Parent-verified completion is7.383214375s/10, worker7.262759750s/8,
whole8.778805292s/90. Platform/worker naturally exit0, owned worker is reaped,
socket is closed, no active signal/truncation/timeout/cleanup errors, and full
source2190/runtime1191/five-document/780-input pre/post checks complete.
Raw headers/body/extra, stdout/stderr, plan/nonce/PID bindings, terminal and
parent results remain private;45 native artifacts are pinned.

The original decodes to8709 bytes and15 packets: one primary, one UID, one subkey
and12 uninterpreted signature packets (5 in primary context,6 after UID,1 after
subkey). Primary and subkey are RSA4096/e65537 and reproduce the complete
candidate fingerprints05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0 and
B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8. Their creation field declares
2023-01-21T11:45:33Z; that is unverified data, not authenticated lifetime.
No particular opaque packet is claimed as a valid FTP-master/Bullseye
cross-signature or revocation. CRC and v4 fingerprint construction do not
authenticate a publisher; fingerprint SHA1 is not permission for weak signatures.
This original file need not be byte-identical to a source keyring changeset or
another certificate encoding.

Internal PASS-untrusted-metadata labels refer only to certificate-original data,
not Release metadata or key validity. Independent uninvolved acceptance checks
the actual component and native records against requirement-derived scenarios.
Authority remains NOT_ESTABLISHED, current revocation UNKNOWN, verifier NONE
ADMITTED; publisher/signature/freshness/supply flags remain false. The old Release
native FAILED and Talos weak-signature refusal remain untouched.

Next separately review the actual signature/certification/rotation declarations
and complete original cross-signature authority inputs, including current
independently anchored revocation state. Complete the selected noncircular
verifier's supply, installation/ELF/helper/UID/isolation/management and fresh
vulnerability prerequisites before any key/Release signature math. No GPG/import,
candidate, package/index recovery, Docker, build or scan executes here.
Only private diagnostics plus five progress documents change; unaffected Go/
Contract/Docker suites are not rerun. Source/runtime old manifests are preserved.
Original10/8/88/90,64KiB/two-executor/resource gates, public holds and issuer count
remain; mise only, timersOFF, no global install or unrelated-process action.
Private evidence: slice6-debian-security-certificate-20261029-v1.
Phase6 remains **5/15**, Slice6step2; full topology16/acceptance/formalstep4 remain open.

## Debian archive authority and verifier bootstrap review (2026-10-29)

This independently reviewed source investigation and future verification proposal
make no new key, verifier, base or Scanner selection. The previous34770B Release
original remains unverified and its native terminal remains FAILED; the previous
54 offline methods are earlier component evidence, not new tests in this stage.

The [FTP-team key page](https://ftp-master.debian.org/keys.html) lists the
Bookworm security primary below, separately from the ordinary archive and stable
release keys. It describes announced/cross-signed rotation and designated
revokers, while requiring other verification of its informational content.
These are purpose and procedure declarations, not current authorization.

| Declared candidate | Full fingerprint | Observation scope |
| --- | --- | --- |
| Bookworm security primary | 05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0 | Current FTP-team page and historical announcement search extraction |
| Bookworm security signing subkey | B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8 | Historical announcement search extraction only |
| Ordinary Bookworm archive primary | B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8 | Separate scope; no automatic substitution |
| Bookworm stable release key | 4D64FEC119C2029067D6E791F8D2585B8783D481 | Separate scope; no automatic substitution |

The search provider extracts the [2023-03-09 transition announcement](https://lists.debian.org/debian-devel-announce/2023/03/msg00001.html)
with the security signing-subkey identity,2031-01-19 expiry and a claim of two
FTP-master plus Bullseye-key cross-signatures. A later direct open is tool-refused
with a reported403. This is not an authenticated announcement original, signer
binding or current expiry/revocation result. The proposed pair is not a final
allowlist and is not claimed to be the actual signer of the saved Release.

The [package page](https://packages.debian.org/bookworm/debian-archive-keyring)
and [source index](https://sources.debian.org/src/debian-archive-keyring/)
declare2023.3+deb12u2 for Bookworm; the index also lists2025.1 for newer suites.
The displayed [README](https://sources.debian.org/src/debian-archive-keyring/2023.3%2Bdeb12u2/README/),
[maintainer notes](https://sources.debian.org/src/debian-archive-keyring/2023.3%2Bdeb12u2/README.maintainer/)
and [Makefile](https://sources.debian.org/src/debian-archive-keyring/2023.3%2Bdeb12u2/Makefile/)
separate active and removed keyrings and describe moving entries out of active
trust. A retired key is not necessarily cryptographically revoked; do not join
both rings or use absence from an old removed directory as timely non-revocation.
No source recipe is executed. The chosen older security-manual URL reports a
tool404, and the source changelog is tool-inaccessible. Original errors remain;
neither establishes global source absence. The initial find on the failed manual
also refetches its404; no native failed run is retried.

The [Bookworm gpgv2.2.40 manual](https://manpages.debian.org/bookworm/gpgv/gpgv.1.en.html)
says its supplied keyring is already trusted and expiry/revocation are not checked.
Its success exit alone cannot close those independent gates. The
[GnuPG integrity guidance](https://www.gnupg.org/download/integrity_check.html)
rejects a newly downloaded verifier authenticating itself; the
[release-key page](https://www.gnupg.org/signature_key.html) provides further
long-term/QES references, which remain unauthenticated leads here.
A Debian gpgv/keyring package authenticated only by this untrusted archive would
be circular. No new binary, adjacent checksum, self-signature or ownertrust mark
becomes an independent root.

No verifier is admitted. Existing Wolfi2.4.9-r12 carrier-HIGH/supply gaps and
Alpine2.5.22 installation/ELF/helper/UID/runtime/full-supply gaps remain. Old37/19
scan database freshness is not inherited, and Docker management-authority
requirements remain. Prefer evaluating one existing distribution route against
all current gates before adding a tool/compiler; this does not approve2.5.22 or
a build/run. Unsupported material remains HELD/UNSUPPORTED; actual wrong
identity/signature/hash/freshness must fail under its applicable gate.

The private proposal orders exact current certificate/transition/removal
original recovery; independently anchored current authority and authenticated
primary/subkey certification, binding/cross-certification, algorithms, flags,
expiry and revocation; complete verifier supply/execution admission; then an
isolated exact-keyring/no-ambient-trust/no-network command with complete machine
statuses/errors and refusal tests. Only afterward can preserved Release
signature/time/anti-rollback and actual index/package/dependency hashes be
accepted. HTTPS, GOODSIG, exit0 or a declared Valid-Until cannot replace those
steps. No old FAILED receipt is relabeled.

Three separately reviewed identities limit the research to7 exact initial pages,
3 exact follow-up pages plus3 official-domain searches, then6 exact transition/
keyring pages; newly returned URLs are only recorded. The runtime/provider calls
are documentary observations, not a passing10-second native request gate.
Source2190/runtime1191/current-five-document and complete604-input postchecks
pass, with prechecks and immutable old manifests retained. No native client,
GPG/import, package/index/key payload, candidate, Docker, scan or build executes.
No production Go/Contract/driver changes or unaffected suite reruns.
Private slice6-debian-archive-authority-20261029-v1 holds raw tool responses,
failures, input pins, observations and the future proposal outside Git.
Timings reported by provider retrieval are not repurposed as native evidence.

Current authority NOT_ESTABLISHED, revocation UNKNOWN, verifier NONE ADMITTED;
publisher/signature/freshness/supply remain false. Next independently review
bounded exact-original recovery and noncircular verifier inputs, preserving
original10/88/90,64KiB and all resource/performance/supply/isolation gates.
Phase6 remains **5/15**, Slice6step2; full topology16, independent acceptance and
formalstep4 remain open. Mise only in this stage; timersOFF.

## Debian untrusted-body recovery and component declarations (2026-10-29)

This is a private untrusted metadata observation and parser correction. It does
not admit Debian as the Scanner base or make the Bookworm-security1.4.6 lead a
verified package. Existing engine/source/whole-image vulnerability/runtime gates
and the fixed two issuer policy remain unchanged.

Independent requirement review finds the mandatory Content-Type predicate local
to this observer. The repository's Coding passive-json/output and Vault KV-v2
requirements apply to their named surfaces. [HTTP semantics section8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3)
allows a recipient to process a response without that declaration.
[APT archive security](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html)
uses the trusted archive key and signed Release/index hash chain; MIME absence
cannot establish that authority. The correction records MIME=null/present=false
only for the exact security.debian.org Bookworm-security InRelease purpose.
Present empty, duplicate or unsupported MIME, redirects, TE, ranges, cookies,
encoding, noncanonical/oversized CL, short/extra body, unknown source and closure
failures retain rejection. No fallback, guessed MIME or content sniffing is added.

Fresh mime-tests-v2 passes48 methods, including the preserved40 and a complete
missing-Type fixture/parent path: unit1.309s, whole2.578556s/90, natural exit0.
One independently reviewed release-original-v2 GET then records HTTP200,
header666B/body34770B/extra0B, body SHA256
f41a694e321a2140205bb22f53f2b1313a62da40b05422c33baa90914a9d6432.
Its native terminal is **FAILED** at arm64/main declaration, with natural exit1,
owned worker reaped/connection closed, worker0.990525s, capture1.059532s/10 and
whole2.422736s/90. Full input postchecks complete. This is not a passing native
metadata gate and is never relabeled by later offline parsing. The previous
release-original-v1 failure with body0 remains untouched.

The recovered body literally declares Components as updates/main, updates/contrib,
updates/non-free-firmware and updates/non-free. It also separately lists the two
original exact SHA256 targets main/binary-arm64/Packages.xz and
main/source/Sources.xz, with declared sizes356212 and280092B.
The [Debian repository format description](https://wiki.debian.org/DebianRepository/Format)
documents prefixed components; its nested-directory example does not certify
this URL, body, key or a mapping between updates/main and main/.
A separately reviewed offline-only correction requires arm64 and exactly one
occurrence across the literal main and updates/main component tokens. It preserves
the original field and both independently required positive-size main/... targets,
without normalization or interpretation of other component tokens. Repeated or
simultaneous accepted tokens, lookalike paths, absent arm64 and missing/renamed/zero
targets fail the relevant predicates. It is not a complete component-name validator.

Unexecuted components-offline-v3 is retired after both reviewers identify a
fixture expectation error: updates/ main splits into a literal main token. The
negative fixture becomes updates/ ma in, which has no accepted token; the parser
and original48 assertions are unchanged. Fresh components-offline-v4 passes54
methods, unit1.367s, whole2.557165s/90, natural platform exit0, 222 exact inputs
and source2190/runtime1191/current-five-document pre/post complete. Actual saved
headers/body/extra are checked against full identity/hash pins before offline
declaration parsing; a separate assertion retains the old FAILED terminal.

The parent request10, soft8, worker88/outer90, per stream64KiB and original
resource boundaries remain. Shortened fixtures test timeout/signal refusal;
no live maximum-boundary experiment or cryptographic signature calculation is
claimed. All publisher/signature/freshness/supply flags remain false. This turn
does not run GPG/import, download package/index payloads, select a base, scan/build
or change production code. It does not rerun unaffected Go/Contract/Docker suites.
Independent final acceptance checks the implementation, assertions and actual
outcomes; private raw materials and failed identities stay outside Git at
slice6-debian-release-mime-policy-20261029-v1. Timers remain OFF; existing mise only.

Next: independently establish the Debian archive key's current authority,
rotation/revocation and a supply-admitted verifier execution path; authenticate
the saved Release and exact index/package/dependency inputs before any supply
decision. If those inputs are unavailable, record the gap rather than inherit
Talos or old candidate acceptance. Phase6 remains **5/15**, Slice6step2; steps3/4
and the original full-topology16 gate remain open.

## Debian route and response MIME refusal (2026-10-29)

The [startup audit](../audits/product-phase-6-slice-6-startup.md#2026-10-29-debian-route-and-response-mime-refusal)
records a new distribution-authenticated-route investigation. The fixed
[Trixie daemon page](https://packages.debian.org/trixie/clamav-daemon) and
[security tracker](https://security-tracker.debian.org/tracker/source-package/clamav)
declare1.4.3+dfsg-1 for Trixie, so its1.4.6 predicate stops. The tracker and arm64
search expose Bookworm-security1.4.6+dfsg-0+deb12u1 as a lead, while specific daemon
pages remain older and two fixed entries are web-tool inaccessible. These are
unverified and partly conflicting page observations, not package authentication
or proof of global absence. Conditional later pages are not fetched after failure.

Official [apt-secure](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html)
describes archive Release signatures and index/package hashes, not per-package
signature verification. [apt-ftparchive](https://manpages.debian.org/bookworm/apt-utils/apt-ftparchive.1.en.html)
documents Release fields and index generation. These specifications inform the
new data-only observer; no APT/GPG tool executes. The wiki format page's403 is
retained. Debian key authority, rotation/revocation, complete actual signed
indices/packages/dependencies and a Debian base/ABI decision remain open.

The reviewed observer keeps all original Talos predicates; a new purpose makes
one fixed official InRelease GET, under whole-child10/worker-soft8/outer90,
2Python executors and64KiB streams. Forty offline methods pass (unit1.497s,
whole4.029698s/90;119 artifacts), including causally bound failure fixtures and
outer/owned-process barriers. Old prepared v1/v2/v3 plans remain unexecuted.

Fresh release-original-v1 **FAILS** at headers: HTTP200/declaredCL34770, but no
Content-Type, so this private observer's frozen MIME policy rejects before body. Complete666B
header/body0B are retained; no Release body/field/signature is obtained.
Child0.895025s/10, whole3.147806s/90, natural exit1/reaped, no timer expiry,
active signal or truncation; complete source2190/runtime1191/five-doc/158-input
pre/post checks and45 native artifacts. An uninvolved requirement-first
review confirms component PASS/native FAILED; full10s/64KiB live-boundary tests
are absent. Do not adapt the predicate or repeat the native identity here.

Next independently distinguish this private response-format predicate from the
actual HTTP and supply requirements before deciding a change or alternate source.
No new source-proof issuer, key, package, base, engine OCI or Scanner is admitted.
A package-set hash cannot replace EngineImageDigest; fresh complete scans,
official loaded rules/operator freshness and real isolation/cleanup remain required.
Old key REFUSED/authority NOT_ESTABLISHED/revocation UNKNOWN and all existing
holds remain unchanged. Private slice6-debian-release-metadata-20261029-v1;
mise, timersOFF, Phase6 **5/15**, Slice6step2; formal topology16/steps3-4 open.

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
