# Project Context

Updated: 2026-10-27

This is the stable handoff index for a new developer, AI agent, development
device, or implementation session. It summarizes the system, engineering
constraints, verified maturity, and evidence boundary; it does not override
the Provider Contract, architecture, accepted ADRs, or reproducible evidence.

## Stage checkpoint workflow

User direction, 2026-10-19: after each completed small stage with repository
changes, check tracked and untracked files for omissions, commit the coherent
reviewed changes and normally push the current implementation branch. This is
standing authorization for those stage commits and pushes; do not wait for a
separate request each time or accumulate several finished stages locally.
Verify the full local HEAD, upstream reference and live remote SHA after each
push. If authentication, divergence or another failure blocks the push, retain
the local commits and report the exact unsynchronized state; never force-push.
No-change stages need no empty commit. Keep private evidence outside Git and
preserve the existing validation/review gates. Intermediate checkpoints do not
constitute formal Slice acceptance, merge, release or publication authority.

## Prelaunch implementation policy

User direction, 2026-10-21: this project has not launched. Do not retain old
implementations, fallback branches or adapters solely to preserve compatibility
with historical code. Prefer one coherent current implementation, judged by
functionality, performance, completeness and maintainability; remove redundant
paths within the affected change. This does not discard original evidence or
waive security, trust, review or validation requirements. Current locked
Contracts and named gates remain authoritative until changed through their
applicable review and validation process.

## Active Phase 6 delivery and machine handoff

The [delivery priorities and handoff plan](plan/product-v1-phase-6-delivery-and-handoff.md)
records the 2026-10-04 comparator findings, product-positioning hypothesis,
architecture boundaries, evidence-reuse decisions and next work. Phase 6
remains **5/15**, with Slice 6 open; component results are not full-topology
acceptance. The 2026-10-05 interim source checkpoint is for changing
computers, not completion of the formal Slice 6 step 4: commit and normally
push reviewed source, compare full local/upstream/live remote SHAs, and
inventory private evidence and local artifacts separately from Git. Resume
Slice 6 step 2 on the new computer; only independent acceptance of step 3
permits 6/15, and formal step 4 still follows that acceptance. The existing
authorization and fixed order for Slices 7–15 remain unchanged.

The [held peer lifecycle checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-27-held-token-peer-lifecycle)
passes 42 component methods in 12.542392 seconds/90 including complete input
checks. It binds source-owned CA/context and one selected peer, rejects hidden
redials, and covers the actual HTTP client response-file handoff with controlled
sockets. This is offline evidence, not real TLS peer verification. The owned-pipe
negative targets 10 seconds and is refused after 10.007898 seconds including
cleanup. Real B2 stays FAILED, B3 unexecuted, and the original noTE/exactCL gate
is unchanged. Next independently decide the real token framing/entry boundary
before any live request. Private slice6-scanner-token-peer-held-20261027;
mise Python, timers OFF. Phase6 **5/15**, Slice6 step2; formal holds stay.

The [held token-controller checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-held-token-controller-integration)
passes24 new methods in11.638106seconds/90 including input checks. Its one
owned-pipe negative targets10seconds and is refused after10.005125seconds
including cleanup; this is no successful network response. Real B2 stays
FAILED/unchanged and B3 unexecuted. Next review the fixed real-entry boundary,
TLS/peer evidence and new-run inputs. Private
slice6-scanner-token-controller-held-20261026; four docs only, mise Python,
timers OFF. Phase6 **5/15**, Slice6 step2 and all formal holds stay.

The [offline token-frame candidate](audits/product-phase-6-slice-6-startup.md#2026-10-26-offline-token-frame-candidate)
passes38 new methods in1.793398seconds/90 including complete input checks.
The strict raw reader and frozen claim bridge are component evidence only;
the operational B2 gate is unchanged and B3 remains unexecuted. Next review
held-controller integration and close/deadline/privacy tests before any real
admission decision. Private slice6-scanner-token-frame-candidate-20261026;
four docs only, mise Python, timers OFF. Phase6 **5/15**, Slice6 step2.

The [Scanner framing authority audit](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-framing-authority-and-invariants)
traces the B2 refusal to the frozen private metadata helper, called before
body ingestion and again by token policy. Other protocols retain their own
framing rules. A token-only bounded raw-framing proposal is prepared for a
separate boundary decision; it changes the current accepted set and is not
approved for implementation. No requests, tests or gate changes; private
slice6-scanner-framing-authority-20261026. Phase6 **5/15**, Slice6 step2,
timers OFF. See the audit for exact scope and remaining checks.

The [Scanner official-path review](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-official-path-and-http-framing-review)
completes bounded official documentation research. No alternative satisfying
the original framing gate is demonstrated; B2 remains FAILED and B3 unexecuted.
Next independently audit the exact framing guard's authority, callers and
security invariants read-only. No parser or gate change is approved. No new
candidate request or test run; four docs only, private
slice6-scanner-auth-paths-20261026. Phase6 **5/15**, Slice6 step2, timers OFF.

The [fixed Scanner token checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-fixed-scanner-token-boundary-and-framing-refusal)
passes25 new synthetic methods in1.650444seconds/90, but the single real B2
request remains FAILED. HTTP200 declares chunked transfer and no Content-Length;
the original noTE guard refuses before application body reads. Request0.367607
seconds/10; whole failed stage2.017721seconds/90, naturalexit1/reaped without
timeout/signal/truncation. Complete input postchecks do not convert it to PASS.

No token JSON/TTL check, usable bearer, registry request or B3 executes. Raw
headers/body stay unpersisted; safe typed framing/hash/count evidence remains.
Zero application reads do not prove absence of network-buffer prefetch. Worker
core limits are local0/0; no physical-erasure or OS-swap guarantee is claimed.
Prior48/31/9/23 and valid Go results are reused unchanged, not rerun.

Next independently review read-only official retrieval-path research. Keep the
current failed identity untouched; no blind URL/header retry, chunked parsing,
CL waiver, unofficial proxy or B3 before a compliant path and new input review.
Original10/88/90/public-peer/supply/resource/reuse guards stay. Four docs only;
private slice6-scanner-base-token-20261026, mise Python, timersOFF. Phase6 stays
**5/15**, Slice6step2; base/source/signature/supply/runtime holds remain.

The [previous fixed Scanner base metadata checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-fixed-scanner-base-metadata-and-401-observation)
passes23 new focused methods and one new unauthenticated GET, naturally in
5.226318 and4.809703 seconds/90 including full input checks. The actual request
takes0.730643 seconds/10 and receives401 with a complete163-byte JSON body.
Original framing/strictJSON/challenge guards accept only the exact
clamav/clamav-debian pull challenge naming the existing token endpoint.

This is a challenge observation, not base existence, OCI kind, publisher
signature or source/supply/runtime acceptance. Unknown headers and401 body
stay in RAM; only safe typed facts/hashes persist. No token, child object,
Docker/build/scan or crypto executes. Complete2190 source/1191 runtime and
1142 direct inputs pass pre/post checks with12 Git receipts. Prior48/31/9
and valid Go evidence are reused unchanged, not rerun; old failures remain.

Next independently review this actual challenge and the B2 anonymous-token
refusals/TTL/RAM-only lifetime and B3 continuation scheme. No bearer persistence,
scope expansion or automatic token acquisition is approved. Original metadata
10/88/90 and network/supply guards stay; heavy APK/TUF host admission is not
silently imported into this light observer. Four docs only; private
slice6-scanner-base-metadata-20261026, mise Python, timers OFF. Phase6 stays
**5/15**, Slice6 step2 and all formal holds unchanged.

The [previous Scanner declared-base discovery checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-declared-base-source-discovery)
locates the official Debian recipe path and distinguishes download-package GPG
instructions from OCI publisher authentication. Both are discovery only:
basea3cbbbc2...'s OCI kind, exact source commit and image signature stay UNKNOWN.
The current Hub arm64 tag view cannot replace that fixed material or prove drift.

A separately reviewed new local closure passes two complete2190 source/lock and
1191 runtime-file checks,7aliases/108directories and12 Git queries in1.800612
seconds/90. Its first prepared plan was rejected before execution for an old
active-plan pointer; the corrected plan uses the current stage and newv4 output.
Original failures stay intact. Prior9/31 methods and valid Go evidence are reused,
not rerun; no local candidate HTTP, Docker/build/scan or crypto executes.

Next freeze and independently review the fixed clamav/clamav-debian metadata/
challenge implementation, new identity and complete inputs. B1–B3 remain a
proposal; assess applicable host gates before execution and preserve original
HTTP10/88/90, framing, public-peer and supply gates. Four docs only; private
slice6-scanner-base-discovery-20261026, existing mise Python, timers OFF.
Phase6 remains **5/15**, Slice6 step2; all formal/source/supply/runtime holds stay.

The [previous Scanner embedded-recipe checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-embedded-recipe-and-material-boundaries)
passes9 new focused methods and a separate saved-original audit in1.548265 and
3.972352 seconds/90. The fixed provenance embeds Dockerfile.add-db:159 bytes,
five lines, ARG/FROM/RUN. Its tagged BASE_IMAGE declares clamav-debian1.4.6_base
with material digesta3cbbbc2..., distinct from the SBOM generatorae4f3b55....
The update syntax permits ignored failure; it does not prove an update failed,
succeeded, passed signatures or met the72h gate.

This describes database augmentation, not a verified complete engine build.
The embedded recipe's byte association, VCS5853e139... claim and current peeled
API correspondence do not authenticate the declared base, compiler/dependencies
or published OCI signature. All source/base/rules/publisher/supply/runtime
approval remains false; external signature existence stays UNKNOWN. Generic
Alpine documentation cannot substitute for this fixed candidate's declarations.

Next independently review the declared base's official source, digest object
kind and signature/acquisition entry. Do not auto-fetch or promote that material
to a new trusted candidate/key, change the original image or waive auth/framing.
Prior31 content tests are reused, not rerun;1099 actual direct inputs plus2190
source/lock rows and1191 runtime files pass pre/post checks. Private evidence:
slice6-scanner-recipe-binding-20261026. Four docs only, mise Python, timers OFF;
Phase6 **5/15**, Slice6 step2 unchanged.

The [previous Scanner peeled-body checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-peeled-commit-body)
passes a new single-GET complete-body run in3.844461 seconds/90. This actual
response is HTTP200 with CL13089; the original framing, exact body consumption,
full SHA and strict JSON gates pass. Its reported commit5853e139... matches the
fixed VCS claim. GitHub verified=true/valid remains a remote declaration;
local Git signature, source/image binding, publisher/supply/runtime admission
remain unproved. Unknown body and raw headers remain RAM-only.

Eight new focused methods pass in4.424786 seconds including full input checks;
test execution takes0.011 seconds. Prior48 methods are reused for nine identical
common modules, not rerun. Actual pre/post checks cover974 direct inputs,
14 scripts, four originals, three helpers,2190 source/lock rows,1191 runtime
files and12 Git receipts. Previous failed producers remain FAILED; this new
identity does not repair their missing postchecks or prove old header causes.

Next independently review signature-material binding and a compliant official
acquisition path while auth/release remain held; no new publisher authority,
chunked/CL waiver, alternate route or retry loop is approved. Only four progress
docs change; private evidence: slice6-scanner-peeled-body-20261026. Prior valid
Go tests reused, existing mise Python only, timers OFF. Phase6 **5/15**, Slice6
step2; original formal gates and acceptance order stay unchanged.

The [previous Scanner response-framing checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-response-framing-observations)
passes48 offline methods and a new four-GET header-only run in1.745659 and
9.213936 seconds/90. Current anonymous-auth and release responses each declare
chunked transfer with no Content-Length: the unchanged noTE/requiredCL gate
rejects them. This time peeled-commit reports CL13089 without TE; the401 control
reports CL156. Header acceptance does not read or approve either body.

The four original request templates and all-public DNS/numeric-peer/TLS checks
stay. No body API, token acceptance, raw response-header/entity persistence,
redirect or alternate resolver is used; socket buffering may prefetch bytes.
These are current response facts, not reconstruction of the old failed headers.
Original metadata/signature/source/supply/runtime admission remains false and
all three prior network producer failures remain FAILED.

Next independently review a single peeled-commit body run with a new identity
and fresh original framing/body/JSON gates. Its current length is no promise
about the next GET. Auth/release still require a compliant official retrieval
path; no alternate is verified and no protocol waiver is approved. Complete
2190 source/lock and1191 runtime checks pass before/after; prior valid Go tests
are reused. Private evidence: slice6-scanner-framing-20261026. Four docs only,
existing mise Python, timers OFF; Phase6 **5/15**, Slice6 step2 unchanged.

The [previous Scanner signature-metadata checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-signature-metadata-and-source-mapping)
passes 33 offline policy methods in 1.701123 seconds/90, including the retained
refusals, linear token-shape scanning and exact annotated-tag discovery guards.
Three actual network stages remain FAILED: registry anonymous auth, GitHub
peeled commit and release responses stop at the unchanged framing gate. No
referrers are queried and no signature payload or image layer is fetched.

Limited complete responses report the claimed commit and show that official
tag clamav-1.4.6 points through annotated object26071af7... to the same
5853e139... commit. Fixed-commit README bytes are fully read and hashed.
GitHub's verified=true is a remote declaration; no local signature, image-to-source
binding, release correspondence or complete source authentication is established.
Original unknown bodies/headers remain RAM-only; hashes and typed facts persist.

A separate fresh read-only closure passes both complete2190 source/lock and1191
runtime-file checks plus12 exact Git receipts. That is a later local check,
not a postcheck or PASS for the failed producers. Old failures and exact inputs
remain intact. Next independently design safe typed framing-rejection observations
and check compliant official retrieval paths before any new metadata identity;
do not infer the missing raw-header cause, retry failed identities or relax framing.
Only four progress docs change; prior valid Go tests are reused. Existing mise
Python only, no Docker/build/scan, DNS/proxy/route or quota/deadline change;
timers OFF. Private evidence: slice6-scanner-signature-metadata-20261026.
Phase6 remains **5/15**, Slice6 step2; source/signature/supply/runtime gates held.

The [previous Scanner JSON and trust-boundary checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-json-and-trust-boundary)
passes 31 policy methods (positive and refusal cases, zero skips) and a new
full-original offline run, naturally in 1.948730 and 1.405507 seconds under the original 90-second bounds. Four
fixed JSON objects match their descriptors; the statements share ten unique
subject names bound to the selected arm64 manifest. SPDX internally checks
113 packages, 2722 file declarations, 3343 relationships and 104 LicenseRef
records, including the exact declared document root. This is candidate-specific
structure/reference evidence, not full SPDX conformance or actual file proof.

Provenance has two materials but declares materials completeness and
reproducibility false. Its configSource lacks a digest; the BuildKit VCS
extension does contain a 40-hex revision/source claim. That claim is parsed and
hashed, not authenticated. An earlier diagnostic incorrectly reported no
revision; its original receipts remain audit-rejected for that field. Private
diagnostic code/tests and a new actual identity correct it without rewriting old evidence.
The builder's declared linux/amd64 environment is separate from the selected
linux/arm64 output. The upstream /init, unspecified User and exposed TCP ports
do not approve the final Scanner runtime configuration.

The four supplied objects contain no publisher signature envelope; external
registry signatures remain UNKNOWN and no cryptographic verifier runs here.
Source, signature, full Scanner supply and runtime admission remain held.
Next independently review fixed official registry signature/referrer metadata
and source-commit/release correspondence, then actual trust inputs and exact
signature coverage. Seven image layers, vulnerability coverage, official72h
rule/current-check and actual loaded-set gates stay open. All2190 Go/lock rows
remain identical; prior valid Go tests are reused, not rerun. Actual diagnostic
runs are offline, existing mise Python only; no Docker/build/scan or network
configuration change, timers OFF. Four progress docs change; private evidence
is slice6-scanner-content-20261026. Phase6 remains **5/15**, Slice6 step2.

The [previous Scanner CDN raw-object checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-cdn-raw-object-recovery)
recovers all four fixed objects under two new independently reviewed identities.
The two configs and provenance pass whole-object size/SHA checks at
3919/241/7231 bytes; SPDX passes three exact 206 ranges and the complete
2,099,349-byte SHA. Both runs finish naturally with full input postchecks in
8.168748/9.118952 seconds under their original 90-second bounds.

Fresh anonymous pull credentials and per-object registry Locations stay in RAM.
Every CDN response uses fresh all-public DNS, numeric-IP/TLS peer checks and
original Host/SNI/CA verification. Request10s/body1MiB/headers64KiB/worker88s/
outer90s and the five-second postcheck reserve stay. The original 14-method
policy evidence is reused for unchanged code; no test or Go command is rerun.
The prior small-v1 and manifest-producer failures remain FAILED and are not
replayed. This result does not explain the historical non-public DNS answer.

Only fixed raw bytes are recovered. Next independently inspect the complete
JSON/attestation content and establish publisher/source/signature and complete
Scanner supply/recipe evidence. Seven image layers, fresh vulnerability
coverage, official rules/current check within72h and actual ClamD loaded-set
gates remain open. Phase6 stays **5/15**, Slice6 step2; original foursteps/16
scenarios and public holds remain. No system DNS/proxy/route edit, alternate
resolver, Docker, build or scan; existing mise Python only, timers OFF.
All2190 Go/lock rows match prior valid tests. Only four progress documents
change; private originals stay in slice6-scanner-cdn-current-20261026.

The [previous DNS/route checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-current-dns-route-and-service-candidates)
finds four public IPv4 answers in each new A/B sampling window. DNS/interface/
route facts are stable within each window. For one fresh selected public IPv4,
two kernel queries return en5; configuration maps it to the enabled first USB
Ethernet service. The global DNS candidate also binds en5 and two private-address
nameservers. The earlier benchmarking answer's cause and owner remain unproven.

A system proxy snapshot reports HTTP/HTTPS/SOCKS and automatic-PAC disabled.
The configured-connection list has one disconnected PPP entry; neither result
proves absence of transparent NE/VPN software. Actual answering resolver and
packet/NE ownership remain UNKNOWN. No unrelated processes are enumerated.

The reviewed access proposal keeps the existing resolver and route unchanged.
A future body run needs a new identity, complete current inputs, fresh all-public
DNS, numeric-IP/TLS peer checks and the original size/SHA/time gates. No body,
DoH, proxy or DNS change occurs here; prior small-v1 remains FAILED and SPDX is
not run. A14/B9 offline methods pass; real A/B stages complete naturally in
4.695594/1.417593 seconds under their original 90-second bounds. All 2190 Go/lock
rows match; prior Go race/vet are reused, not rerun. Phase 6 stays **5/15**,
Slice 6 step 2. Existing mise Python only, no install/Docker/build/scan, timers
OFF. Private evidence: slice6-dns-route-attribution-20261026. Only four progress
documents change; this checkpoint does not authorize actual CDN recovery.

The [Scanner blob checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-26-scanner-blob-discovery-and-address-guard)
passes four header-only registry Location observations and 14 new offline
restore-policy methods, including synthetic complete-body and 1 MiB reads.
The real three-small-blob run fails before its first CDN HTTP response:
zero body bytes and zero restored blobs, with no producer postcheck. A new
single-DNS observation returns one non-global benchmarking-range address and
the unchanged address guard rejects it. This reproduces a current access
blocker; the original small-run cause remains unproven. No failed identity
is replayed or relabeled, and SPDX is not run.

Next independently review read-only resolver/route attribution and a compliant
access proposal. Do not connect to that address, replace the system resolver,
alter a proxy, or infer supply approval from the Location. Full JSON contents,
publisher/source/signature, vulnerability/rule and actual loaded-set gates
remain open. All 2190 Go/lock rows remain unchanged; prior race/vet are reused,
not rerun. Phase 6 stays **5/15**, Slice 6 step 2. Existing mise Python3.13.16
only; no Docker/Go/build/scan, quota/deadline increase or automation change.
Private originals: slice6-scanner-blob-recovery-20261026 and
slice6-scanner-blob-restore-20261026; only four progress documents change.

The [Scanner supply metadata checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-25-scanner-supply-metadata-discovery)
identifies one fixed arm64 candidate and its associated attestation manifest.
The index passed its real bounded HTTP run. Both manifest originals match
raw SHA-256, response digest and declared size, but their producer run remains
FAILED: it applied the 1 MiB response cap to an unfetched 2,099,349-byte SPDX
blob declaration. A new, separately reviewed offline classifier passes without
replaying HTTP or changing that failure. Nine offline test methods pass;
classification completes naturally in 0.743224 seconds/90 seconds.

Only metadata is available. Image configs, seven image layers, SPDX/provenance
contents, publisher signatures, official rules and the actual ClamD loaded set
remain unverified. Every blob remains unauthorized for fetching; the response
cap stays 1 MiB and the original attestation declaration total stays 4 MiB.
The slim inventory has no ClamAV image/rule original. No Go source changes:
all 2190 tested Go/lock inputs match, so prior race/vet results are reused,
not rerun. Phase 6 stays **5/15**, Slice 6 step 2; holds and formal scenarios
remain open. mise Python3.13.16 only; no Docker operation, timers OFF. Private
evidence: slice6-scanner-supply-discovery-20261025. Next independently review
bounded config/attestation recovery and authenticated supply/source closure
before any image restore, recipe integration or current-model admission.

The [Scanner original-rule custody fix](audits/product-phase-6-slice-6-startup.md#2026-10-25-scanner-original-rule-custody)
retains the original directory and all three rule file descriptors through a
complete verification. Native openat/Fstatat checks bind current paths to the
held device/inode/mode/UID/GID/link count/size/mtime/ctime; fresh enumeration
rechecks the exact three names. A changed earlier file or restored bytes/mtime
cannot reuse an earlier successful hash. Hash/size/context/freshness rules stay.

Original-code red records nine named failures (parent plus eight mutation
cases) and two passes. Final Darwin component race passes19roots/65named tests,
zero skips, and package vet in6.606058s/90s. At base
3a70b0db40358f7001f83f81ed6c3cc66913d4fc plus6Go files, full race passes
naturally399.978324s/600s (267unique packages:230pass/37no-tests); full vet
passes2.202584s, complete stage3.103693s/90s. All2190 Go/lock inputs match
before/after; only four progress documents change afterward. The passive
observer stops after29samples on a different process group at280.035613s;
this does not fail Go or establish CPU attribution/leakage. All four PIDs
from that sample are absent in the bounded post-run check.

These are same-call filesystem/component results using tiny synthetic rules,
not official signatures, new current-check receipts or proof ClamD loaded the
snapshot. Darwin/Linux provide native custody; other OS refuses explicitly,
with an unsupported-OS test supplied but not run on Darwin. RO mounts, official
rule/source/signature/vulnerability gates,72h freshness and actual engine load
remain required. Complete Scanner supply and actual Control key/source/OCI
origin, old78 ImageSupply/resource/model migration and real management authority
remain open. Phase6 stays **5/15**, Slice6step2; public holds, original foursteps/
16scenarios, twoissuers/PGgeneral,9bindings/64barriers, hostsigner120 and old
locks/reuse stay. miseGo1.26.8; no Docker operation and timersOFF. Private
originals: slice6-scanner-rule-custody-20261025. This ten-file checkpoint's
commit/push disposition is separate.

The [held Control source-candidate checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-25-held-control-source-candidate-correspondence)
adds a reachable `tools/control-source-review -candidate` mode. It independently
rebuilds the fixed current Control package, FD loader and probe from clean
source/Go1.26.8, binds the actual linked public pin and compares selected OCI
bytes. Original FD/path/full-byte guards and a private64MiB snapshot protect
inputs. The21-field output remains held/offline and explicitly leaves operator
key origin unverified; it is not a Manifest, source-proof grant or permit.

Final affected component race passes17 named results/zero skips plus package
vet in27.434272s/90s. Another65 unaffected named passes are reused from the
preserved failed first command; that command remains FAILED. A fresh synthetic
CLI run checks all21 independently derived fields and completes naturally in
6.894106s/90s. Its tiny clean test source/OCI is not the current project image.
At baseline0eaa012881439ca45f747f05dd60180a4d518987 plus12Go files, required
full race passes naturally401.598465s/600s (267unique packages:230pass,
37no-tests); full vet passes1.534335s, complete stage2.167106s/90s. All2186
Go/lock rows match before/after; only these five documents change afterward.
Default opt-in skips do not replace the explicit synthetic component tests.
The41 passive process samples do not establish CPU attribution or speedup.

Ordinary Manifest/VerifySources APIs still refuse Control/Scanner. Current
production key origin, actual authenticated Control originals, complete Scanner
engine/dependency/rule recipe and old78 ImageSupply/resource roster migration
remain open. The host signer120, public holds, twoissuers/PGgeneral, old locks/
reuse and9bindings/64barriers stay unchanged. Phase6 remains **5/15**, Slice6
step2; original foursteps/16scenarios and formal acceptance/handoff remain open.
Development uses mise Go1.26.8; Docker is untouched and timers stayOFF. Private
originals: slice6-control-source-candidate-20261025. This17-file checkpoint's
commit/push disposition is recorded separately.

The [closed local-role build recipes](audits/product-phase-6-slice-6-startup.md#2026-10-25-closed-local-role-build-recipes)
now connect source collection, independent role/loader rebuilding and image
entrypoint checks to one fixed package/stage policy for the existing 12 complete
ordinary-role targets. Go discovery/builds and the shell recipe use matching
closed compilation environments, native helpers stay on the host platform,
and image binaries use the exact Linux target with GOMAXPROCS=2 and -p=2.
PATH and storage/cache inputs still need their existing origin controls.

Final component race passes 11 roots/39 named results without skips and package
vet; the whole stage completes in 5.077400 seconds/90 seconds. At base
091d94c9ed58fd3e50a13d1fc0617a992105eff3 plus seven Go files and the build script,
root race passes naturally in 389.152669 seconds/600 seconds (267 packages:
229 pass, 38 without tests), and full vet passes in 1.536765 seconds. All 2179
source/lock rows and direct script/tool inputs match before/after; only four
progress/plan documents change afterward. Original red and the incorrect GOENV
output test failure remain preserved. The passive observer is not trusted CPU
attribution or evidence of a speedup.

This implements the ordinary-role foundation of the offline verifier boundary;
current Control/Scanner inputs remain incomplete and their targets stay refused.
No image, production key, source-proof authority or Profile generation is added.
New parameter digests do not overwrite old candidates or change frozen-R reuse.
The host signer retains 120 seconds; public holds, two issuers/PG general and
the original four steps/16 scenarios remain. Phase 6 stays **5/15**, Slice 6
step 2. Development uses mise Go1.26.8; Docker and timers are untouched/OFF.
Private evidence: slice6-offline-role-recipe-20261025. Commit/push disposition
is recorded separately. Continue current Control pin/role/loader/probe source
binding and the separate complete Scanner recipe before joint model migration.

The [current builder source-closure inventory](audits/product-phase-6-slice-6-startup.md#2026-10-25-current-builder-source-closure)
completes a bounded read-only checkpoint; **current inputs remain incomplete**.
ImageSupply's exact target/directory and composed builder still cover the old
78-role model. Generic candidate rebuilding cannot reproduce the current
Control package alias, independent public pin and probe. Scanner source exists,
but its target, fixed clamd engine/dependencies/rules and full image recipe are
not connected. The arm64 resource policy has78assignments and omits the four
new roles. No current source/production operator approval is inferred.

All2177 previously tested Go/lock rows and43selected direct/script/helper/
historical inputs match before/after. Fourteen bounded read-only Git commands
exit0; inventory publication0.520651s/90s,outer0. The historical20,938,752B OCI bytes were hashed; only role/loader/probe
hashes were compared with old delivery-v2 launch declarations. They are not
current trust-target candidates, clean-source provenance or production keys;
no OCI gate, signature or old authorization was replayed. No Go/Docker/network,
private-key read, build or automation operation occurred. The prior99named
component,391.106795s full-race and2.534549s vet results are reused under the
same2177rows, not newly executed or current image qualification.

The [closed input matrix and next implementation boundary](plan/product-v1-phase-6-delivery-and-handoff.md#current-builder-source-closure-2026-10-25)
selects fixed offline source-candidate verification into existing ImageSupply/
VerifySources. The host signer starts120seconds before load; source rebuilding
or a new source-proof signing authority is not added there. Current independent
key origin, actual Control/Scanner original inputs and source/Store/daemon
permissions still require their existing gates. No placeholder digest map,
extra Profile generation or old runtime fallback is authorized. Only four
progress/plan documents change. Phase6 remains **5/15**, Slice6step2; formal
foursteps/16scenarios, public holds, twoissuers/PGgeneral, old locks/reuse,
9bindings/64barriers, mise/Docker and timersOFF remain. Private evidence:
slice6-current-builder-source-closure-20261025. This checkpoint's commit/push
disposition is separate; source code integration has not occurred.

The [peer-CRL constructor consolidation](audits/product-phase-6-slice-6-startup.md#2026-10-25-peer-crl-constructor-consolidation)
now uses one private post-admission provider construction core. Both typed
entries still perform their own complete validation and private snapshot;
only that snapshot's digest, bindings and compiled authorizer reach the core.
The old PostgreSQL constructor now rejects an empty owner before dependencies,
matching the current-model entry. Previously it could construct an ordinary
provider through the PostgreSQL API. Command binding checks are additional;
this is not evidence of a demonstrated production exploit.

Original-code red preserves4named failures (two parents/two children), Goexit1.
Final component race passes31roots/99named results withzeroSkip and packagevet;
postpublication7.984248s/90s,outer0. New synthetic fixture inputs establish
ordinary/PG success, exact owner/source isolation, private-copy protection,
dependency refusals and the existing public hold. They are not current
broker/general topology, actual issuer or full-model admission evidence.

At base5a52e9f625574ab78eda14e0a648c060d14d724c plus4Go files, required
root race passes naturally391.106795s/600s:267unique packages,229passing/
38without tests,20650Bstdout/0stderr, no signal/timeout/truncation. Fullvet
passes2.534549s; publication completes3.200131s/90s. All2177source/lock rows
match before/after; only4policy/progress docs change afterward. The observer's
40complete samples are passive diagnostics using unpinned ps, not trustedCPU,
performance gains or a historical timeout-cause finding. Default fixture skips
in the full run do not replace the explicit99pass component run.

Global Profile consolidation and real service/whole-topology acceptance remain
open. The [current-model migration sequence](plan/product-v1-phase-6-delivery-and-handoff.md#single-current-profile-migration-2026-10-25)
first requires source-bound current builder inputs, then a joint model/consumer/
tagged-harness switch without old runtime aliases, fallbacks or a new generation.
Desired dynamic/peak bounds and actual same-run observations remain distinct;
78/82are not final live counts. Phase6 stays **5/15**, Slice6step2; original
foursteps/16scenarios, holds, twoissuers/PGgeneral, old locks/reuse,9bindings/
64barriers, miseGo1.26.8 and timersOFF remain. Private evidence:
slice6-peercrl-constructor-unification-20261025. The eight-file checkpoint's
commit/push disposition is separate.

The [CRL-required command cleanup](audits/product-phase-6-slice-6-startup.md#2026-10-25-crl-required-command-cleanup)
removes the unconsumed pre-CRL controller config.v3 and agent config.v2
startup paths, missing-source/nil-provider successes and the old raw request
TTL exception. Current configurations always bind an absolute CRL-source path
and digest, use the existing backdated TTL and require immediate complete
Vault CRLs. Exact policy, identity, issuer and inherited-key-FD refusals remain.
The three active tagged builders are byte-identical; no new protocol is added.

This is the first cleanup stage under the user's prelaunch single-implementation
policy. Global Profile consolidation is still incomplete: both Profile types,
constructors and active consumers remain to be replaced together with the real
harness. Their current presence is a migration task, not a promise of historical
runtime compatibility. ProfileV2.Validate and Provider v3 admission stay closed.

Focused race records120 named passes (controller69/agent51), one existing
operator fixture SKIP and package vet natural0. The inner result records
15.796966s; the original outer tail/exit is unavailable after context truncation,
so no complete focused90 outer0 claim is made. Tagged Go compile/empty selection
exits0 in6.999336s. Its controller stays FAILED because of a wrong ok-tab output
expectation; Go1.26.8 emits ok-two-spaces-tab. Independent offline review accepts
the original bytes with1positive/17refusals, without Go replay or real scenarios.

On baseb7d56f5dbf3f5592628668ba32f89790c3b7139e plus these eight Go files,
required root race passes naturally419.582453s/600s:267unique packages,
229passing/38without tests, stdout20650B/stderr0B, no signal/timeout/truncation.
The passive observer completes42samples; this is not a controlled speedup or
historical-timeout-cause finding. Full vet passes1.627352s; outer publication
completes2.408668s/90s. All2176 source/lock inputs match before/after; only these
five policy/progress documents change afterward. These are component/root-module
checks, not real Controller/agent/Vault/Docker or full-topology acceptance.

Phase6 remains **5/15**, Slice6step2. Docker management authority, remaining
real startup/recovery boundaries, step3 fresh whole inventory/original16/
independent acceptance and formalstep4 remain open. Next scope the single
current Profile with its constructors, role consumers and live harness together;
do not add another internal generation or bypass a hold. Old locks/receipts/
reuse,9bindings/64barriers, miseGo1.26.8 and scheduled tasks OFF remain.
Private evidence: slice6-profile-cleanup-20261025. This13-file source/test/
policy/progress checkpoint's commit/push disposition is recorded separately.

The [CRL pull completion guard](audits/product-phase-6-slice-6-startup.md#2026-10-25-crl-pull-completion-and-retained-watermark)
now checks the original parent/operation contexts after verification/lock wait
and immediately before publication. CheckPeer and leaf parsing complete before
that last check; timely valid CRLs still retain their sequence before a peer
semantic error, preserving rollback refusal. Expiry scheduling deducts the
monotonic verification time, so this move does not extend evidence freshness.
No new timeout, quota, cache, issuer, protocol, driver or public hold is added.

Final focused race passes27 named results (21 new/6 existing) and package vet
in13.442044s/90s. On baselineb75ce2b5ce46ddde5fb685d10c9c432145a64ea7 plus
three Go files, root-module full race passes naturally511.094589s/600s:
267unique packages,229passing/38without tests, stdout20651B/stderr0B, no
signal/timeout/truncation. Full vet passes5.101528s; complete stage6.831918s/90s.
Complete2176 source/lock inputs match before/after; only these progress docs
change afterward. These are component/root-module checks, not live role gates.

Historical failures stay intact:19 original-code Go failures were independently
attributed from189 raw events; their controller failed on nonexistent intermediate
parent names. A fixture set its deadline after net.Pipe had closed; its failed
run remains. A preliminary candidate could lose a timely verified CRL watermark;
its own full run was precisely stopped at351.249009s and stays FAILED, not a
600s timeout or performance finding. The final watermark regression passes.
Observer INCOMPLETE:29 samples; at280.046422s a qualification-adapter child had
a different process group. This neither fails Go nor proves the old timeout cause.

Phase6 remains **5/15**, Slice6step2. Real Controller/agent/Guest/Provider flows,
Docker management authority, step3 live Profile-v2/original16/independent
acceptance and formalstep4 remain open.9bindings/64barriers, old evidence/locks/
reuse, miseGo1.26.8 and scheduled tasks OFF remain. Private evidence:
slice6-crl-completion-deadline-20261025-v1. This six-file checkpoint's commit,
normal push and full live-SHA reconciliation are recorded separately.

The preceding [Provider reconciler readiness fix](audits/product-phase-6-slice-6-startup.md#2026-10-24-provider-reconciler-lifetime-readiness)
binds readiness to the active single-use worker and rejects an expired current
recovery pass even when its dependency has not returned. Each step checks
cancellation before starting; final publication retains cancellation/deadline
errors and clears the current pass before its deferred cancellation. Stopping
or a late nil result cannot reuse old success. Normal failure/recovery remains.
No polling interval, timeout, runtime driver, Contract or public v3 hold changes.

Two bounded reproductions retain 9 expected failures on original production
and one new active-deadline failure on the preliminary fix. Final process tests
pass all14 named results (10 new and4 existing), including eight new boundary
scenarios and handler-only stopped-worker readyz503, plus package vet in a
complete9.478036s/90s. This is component evidence, not real Provider commands,
PostgreSQL or Docker. Coding v3 remains held.

At base3a25bd1a577a92ce13ed8143380258072ae65682 plus the two Go changes,
root-module full race passes naturally in384.341810s/600s:267 unique packages,
229passing/38without tests, stdout20648B/stderr0B, no timeout/signal/truncation.
Full vet passes in1.929341s; complete stage2.567144s/90s. All2175 source/lock
inputs match before/after; only progress docs change afterward. Observer
INCOMPLETE:21 samples, stopping at200.041617s after a qualificationsupervisor
child has a different process group. This is not a test fault or timeout-root-
cause finding. One full preflight failed before Go started because strip()
removed a valid Git-status space; raw failure and all rejected drafts remain.

Phase6 stays **5/15**, Slice6step2. Real Provider/PG/Docker recovery and authority,
step3 live inventory/original16/independent acceptance and formalstep4 remain
open; gates, locks/reuse,9bindings/64barriers, miseGo1.26.8 and timers OFF remain.
Private evidence: slice6-reconciler-readiness-20261024-v1. This five-file
fix/test/progress checkpoint's commit/push disposition is separate.

The preceding [Browser terminal-intent audit](audits/product-phase-6-slice-6-startup.md#2026-10-24-browser-terminal-intent-during-uncertain-creation)
adds four deterministic cancellation/expiry interleavings during creation,
without changing production code. Unknown completion retains the exact
Creating identity, UID and capacity, excludes a competing allocation and never
redispatches or grants a handoff. A simulated finished proof permits terminal
cleanup only; failed fresh absence keeps Cleaning. Reconstructed application
objects share an in-memory ledger and boolean proof, so this is component
evidence, not another OS process, PostgreSQL/fsync or Docker acceptance.

The new test passes five named results (parent plus four scenarios) and package
vet in a complete 6.628684s/90s stage. At base HEAD
fdf17e0bf1591d409e0d7e96d6fc99c44005cc54 plus this exact new test, root-module
`go test -race -shuffle=on -count=1 ./...` passes naturally in 574.172236s/600s:
267 unique packages, 229 passing and 38 without tests, empty stderr and no
signal, timeout or truncation. All 2175 source/lock inputs match before/after.
Full vet passes in 2.199113s, with its complete stage 3.273768s/90s. Only these
progress documents change after verification; no measured speedup is claimed.

The observer remains incomplete after 41 process samples: at 400.061617s it
sees a terminalbroker.test descendant shell in another process group and
conservatively stops sampling. Go continues naturally; this does not prove a
shell fault, leaked process or the historical race-timeout cause. Old failures
and evidence remain intact. Phase 6 stays **5/15**, Slice 6 step 2; Docker
management authority and real recovery gates, step 3 live inventory/original
16 scenarios/independent acceptance, and formal step 4 remain open. Existing
holds, gates, locks, 9 bindings/64 barriers, reuse rules, mise Go1.26.8 and
timers OFF remain. Private evidence: slice6-browser-uncertainty-audit-20261024-v1.
This four-file test/progress checkpoint's commit/push disposition is separate.

The preceding [whole-repository verification](audits/product-phase-6-slice-6-startup.md#2026-10-24-whole-repository-race-verification)
now passes at tested source d23a19ff3294bdc02843c2e106bb3bc96b9353e0.
The original `go test -race -shuffle=on -count=1 ./...` finishes naturally in
503.982350s/600s: 267 unique package lines, 229 passing test packages and38
packages without tests, empty stderr, no timeout/truncation/active signal.
Full2174 source/lock and direct/tool/Git checks match before/after. This is
one current root-module execution, not a repeatability or nested-module claim.

Separate `go vet ./...` passes naturally in67.234062s; its complete stage,
including bootstrap, inputs/Git pre/post and publication, finishes in
87.628873s/90s. miseGo1.26.8, GOMAXPROCS2, `-mod=readonly -p=2`, original
cache/module settings and all safety/refusal boundaries remain unchanged.
No repository Go or fixture change occurs in this verification stage.

The passive observer is explicitly incomplete: one valid process sample,
then an erroneous duplicate-FD-unregister marker stops further sampling.
Its failure does not interrupt Go. A separate private corrected copy passes
24 offline methods, including two positive multi-cycle/early-EOF tests;
no second full-race run occurs. Old failed preparations and the original
600.014672s timeout remain unchanged. This pass does not establish that
failure's unique cause, any individual optimization's savings or a stable
performance margin. Earlier entries below retain their then-current status.

Phase6 stays **5/15**, Slice6step2. Resume independently selected remaining
startup/safety audits; Docker management authority, step3 live inventory and
original16 scenarios/independent acceptance, and formalstep4 remain open.
Timers stay OFF; no gate, quota, timeout, old lock or evidence-reuse rule changes.
Private evidence: slice6-fullrace-observe-20261024-v1. This three-document
checkpoint's commit/push disposition is recorded separately.

The preceding [DNS lexical validation change](audits/product-phase-6-slice-6-startup.md#2026-10-24-dns-lexical-validation)
replaces separate lowercase/regexp/consecutive-dot checks with one bounded
ASCII pass in validDNSName. The original1..253-byte language, permissive label
structure and net.ParseIP exclusion remain; all consumers and separate full
entry/snapshot validations remain. The unused host regexp is removed.

A passes95 named results (70 new,25 original), including7241 bounded comparisons
against an independent original-policy oracle, and package vet in16.701829s/90s.
B passes the original73 PeerCRL results in12.217274s/90s, reusing A vet under
identical2174 source/lock inputs. Both include complete inputs/Git pre/post
and publication. A source-attribution preparation count failed; its raw diff
and failure remain. Independent offline review confirms the raw source attribution
without replay; the preparation failure stays FAILED.
No new CPU profile, measured speedup or whole-repository pass is claimed.
Fullrace **FAILED600.014672s** remains unsatisfied; Phase6 **5/15**, Slice6step2,
original gates/miseGo1.26.8/locks/reuse and timers OFF remain. Private evidence:
slice6-dns-policy-scan-20261024-102141. Commit/push disposition follows separately.

The preceding [principal digest check](audits/product-phase-6-slice-6-startup.md#2026-10-24-principal-digest-validation)
removes only the duplicate outer-digest regexp in validatePrincipal after
Registry.Validate and exact identity-digest equality. The Registry still
checks the same digest syntax and recomputes the identity hash; Digest is a
field getter. TLS, authorization, sandbox controlling-digest checks and every
public/snapshot validation boundary remain. No cross-call reuse is added.

Independently reviewed A passes58 named results (33 new,25 original) and
package vet in14.408291s/90s. Separate B passes the unchanged73 PeerCRL results
in13.286053s/90s, reusing A vet under identical2173 source/lock inputs. Both
include complete inputs/Git pre/post checks and publication. These are component
checks; existing cumulative CPU samples do not measure this predicate's cost
or savings. Fullrace **FAILED600.014672s** remains unsatisfied; Phase6 **5/15**,
Slice6step2, original gates/miseGo1.26.8/locks/reuse rules and timers OFF remain.
Private evidence: slice6-principal-digest-guard-20261024-081613. This five-file
source/test/progress checkpoint's commit/push disposition follows separately.

The preceding [Profile-v2 single-encoding change](audits/product-phase-6-slice-6-startup.md#2026-10-24-profile-v2-single-encoding)
removes one full JSON encoding from each complete private field validation.
One value-copy encoding clears only the root ProfileDigest; the original
domain hash is shared with Digest. Restoring the valid71-byte ASCII digest
for the size check preserves the original signed-document2MiB boundary.
All earlier field guards, marshal-error rejection, public holds and separate
snapshot/final-role validations remain. No cache or JSON byte substitution.

Independently reviewed A passes44 named results (20 new,24 original) and
package vet in51.556528s/90s. Separate B passes the original73 PeerCRL results
in15.635456s/90s, reusing A vet with identical2172 source/lock inputs. Both
complete naturally with full input/Git pre/post checks and publication inside
their own90s boundaries. Size -1/at/+1, independent old-policy oracle, escaping,
nested digests, mutable aliases and current type assumptions pass. No new CPU
profile, measured speedup, whole-repository pass or runtime admission is claimed.

Phase6 stays **5/15**, Slice6step2; required fullrace **FAILED600.014672s**
remains unsatisfied. Next independently choose another useful retained-profile
target or remaining startup audit item; do not blindly repeat full tests.
miseGo1.26.8, old locks/reuse rules and timers OFF remain. Private evidence:
slice6-profile-v2-encoding-20261024-003430. The reviewed six-file checkpoint's
commit/push/live SHA disposition follows separately.

The preceding [peer-CRL retained-profile source attribution](audits/product-phase-6-slice-6-startup.md#2026-10-23-peer-crl-recheck-source-attribution)
passes three local reports in3.208271s under the original shared90s, including
publication. Complete2171 source/lock,74 tool sources and the entire442-file
saved CPU checkpoint match before/after. The strict parser is unchanged;
its24 previously passed methods are reused, not rerun. No Go change or new test,
profile, vet or runtime admission occurs.

requiredPeerCRLV2 has8.60s cumulative sampled weight, including8.37s at its
profile.validateFields call. The field validator's sampled callees include
validatePrincipal1.82s, Digest1.79s and json.Marshal1.58s. These overlap and
are not call counts, savings or the old600s timeout cause. Next independently
inspect the two profile encodings and their size/digest/error semantics before
proposing an equivalent change; Digest clears ProfileDigest, while the size
check encodes the supplied value. Keep full public/final/snapshot validation.

The preceding checkpoint792f5b9769a8422a36518560e4da3accd586564a is now
normally pushed and verified local/upstream/live equal, clean0/0, through
GitHub's officialSSH443 route with the existing strict host key. The oldSSH22
10s failure remains. Private evidence: slice6-peercrl-checkpoint-ssh443-20261023-234529
and slice6-peercrl-recheck-lines-20261023-235125. Phase6 stays **5/15**, Slice6
step2, required fullrace **FAILED600.014672s** unchanged; timers OFF. This new
documentation checkpoint's commit/push disposition is recorded separately.

The preceding [peer-CRL post-optimization CPU recheck](audits/product-phase-6-slice-6-startup.md#2026-10-23-peer-crl-post-optimization-cpu-recheck)
passes the unchanged TestPostgresPeerCRLV2OwnerIsolationAndPinnedDecode target:
73 named results, one package PASS and297 complete events. Target55.726909s,
flat pprof1.478675s and cumulative pprof0.396227s complete naturally in a
57.995788s/90s diagnostic batch. Complete input/Git/environment pre/post retain
their separate original bounds; this is not the entire operation elapsed.

New23 offline methods pass0.206235s/30s, preserving original refusals and adding
strict event/actual-retention-path refusal and old297-event compatibility.
The new real profile and binary are retained as exactly two private files,
with original FD/UID/GID/nlink/ACL/hash/mode guards and1MiB/16MiB observed
thresholds unchanged. Full137 direct/3helper/2module,2171 source and74 tool
checks pass before/after. Tested HEAD/upstreambf8a73d is clean0/0; no Go or
fixture code changes occur in this recheck, and no new vet/full-race pass.

The profile spans47.66s with28.35 sampled CPU seconds. Application cumulative
rows include ProfileV2.validateFields9.76s, requiredPeerCRLV2 8.60s,
Postgres role validation7.51s and pinned decode4.75s. Rows overlap and are
sampled, not call counts, savings, waits or the cause of the old600s timeout.
Old19.370434s versus new57.995788s comes from different contexts and is not a
controlled regression or benefit measurement. The source-level3-to-2 change
remains verified separately; absent samples cannot prove an edge disappeared.

Next independently inspect this new retained profile's source/caller/line
attribution before any further equivalent-change proposal. Keep full public
entry and snapshot validation, final role checks and every refusal. Phase6
remains **5/15**, Slice6 step2; step3 live inventory/original16/independent
acceptance and formalstep4 remain incomplete. Required full race remains
**FAILED600.014672s**, not rerun. miseGo1.26.8, all existing gates, timers OFF.
Private evidence: slice6-postgres-peercrl-cpu-recheck-20261023-230152.
This is the precommit source record; normal push/full SHA disposition follows.

The earlier [peer-CRL same-call graph reuse](audits/product-phase-6-slice-6-startup.md#2026-10-23-peer-crl-same-call-graph-reuse)
implements the independently reviewed private Postgres derive change from three
to two source-level full graph/field validations. One unchanged source-validator
body returns its required map only after every check succeeds; its existing
entry remains a full-check wrapper. Empty-owner ordering, nil graph on error,
all source/issuer/mapping refusals, fresh output and final complete role
validation remain. Public launch holds, separate entry validation and snapshot
boundaries remain; no cross-call cache or input-mutation reuse is introduced.

The first v3 test batch naturally FAILED in48.445792s/90 because one new
expected edge literal disagreed with the unchanged authoritative dependency:
provider-runtime uses provider-coding-postgres. The production implementation
was unchanged by that test correction. Independent review permits reuse of117
named passes in five unaffected complete parents. Fresh v5 passes the affected
13 named results and package vet in11.252236s/90, with complete input/source
checks before/after; this is not130 passes in one batch. Old failures remain.

A global filesystem device-number change was separately observed; hashes and
all other identity fields matched. Its cause is unknown. v4 was never run;
new v5 uses independently reviewed fresh full eight-field bindings without
editing old manifests or receipts. No measured performance benefit, whole-repo
pass or runtime acceptance is claimed. Full race remains **FAILED600.014672s**,
not rerun. Phase6 stays **5/15**, Slice6 step2; step3 and formal step4 remain
incomplete. mise Go1.26.8, all existing gates and timers OFF remain.
Private evidence: slice6-peercrl-graph-reuse-20261023-155048.
This is the precommit record; commit/push/live SHA disposition is separate.

The earlier [peer-CRL same-call validation analysis](audits/product-phase-6-slice-6-startup.md#2026-10-23-peer-crl-same-call-validation-proposal)
completes three read-only reports on the retained profile in 2.289901s under
the original shared 90s boundary. All exit0/reaped, empty stderr, no signal,
timeout or truncation; full source/lock, tool-source and old archive checks
pass before/after. New 24 parser/refusal methods pass in 0.074500s/30s.
No application test, new profile, Go optimization or runtime acceptance occurs.

Exact source and directed caller evidence identifies three full graph/field
validations on the private Postgres derive's complete source-level happy path.
Independent review accepts a minimal 3-to-2 design: one source-validator body
returns its required map only after all checks succeed; the existing validator
remains a full-check wrapper, and only this derive reuses the returned map.
Keep empty-owner ordering, nil graph on every error, all source/issuer/mapping
refusals, fresh output construction, and the final complete role validator.
Public launch holds, independent decode/file/compiler calls and snapshot
boundaries remain. No cross-call cache or input-mutation reuse is permitted.

The removable direct derive-to-required edge has only 120ms sampled weight.
That is not a call count or measured benefit; the overlapping 2.68s/3.03s totals
cannot be claimed as savings. Next review the concrete minimal implementation
and refusal tests before a new bounded execution identity. The required full
race remains **FAILED600.014672s** and was not rerun. Phase6 stays **5/15**,
Slice6 step2; step3 acceptance and formal step4 remain incomplete. All existing
security, evidence, resource and time gates hold; mise Go1.26.8, timers OFF.
Private evidence: slice6-peercrl-field-cpu-lines-20261023-144932.
This is the precommit record; commit/push/live SHA disposition is separate.

The earlier [PostgreSQL peer-CRL CPU diagnostic](audits/product-phase-6-slice-6-startup.md#2026-10-23-postgresql-peer-crl-targeted-cpu-diagnostic)
passes the exact TestPostgresPeerCRLV2OwnerIsolationAndPinnedDecode target:
73 named results, one package PASS and 297 complete JSON events. The unchanged
test retains additional owner, pin, encoding and public-hold assertions inside
those named cases. This is pure Go component evidence, not a live PostgreSQL run.

The original shared 90-second batch completes naturally in 19.370434s:
target command 18.317265s, flat pprof 0.661247s and cumulative pprof 0.146760s.
All three exit0/reaped with empty stderr and no signal, truncation or timeout.
New 21 offline refusal methods pass in 0.118586s/30s. Complete 2170 source/lock,
74 tool-source and frozen direct/helper/module checks pass before/after, with
local HEAD/upstream f98b8c522799d27345ddf28e549fe7b31234f7e7 clean0/0.
The earlier independent sync stage observed this same full live remote SHA.

The profile spans 13.22s with 12.12 sampled CPU seconds. Cumulative rows show
ProfileV2.validateFields 3.03s, requiredPeerCRLV2 2.71s,
PeerCRLRoleDocument.validatePostgresV2Fields 2.21s and
decodePostgresPeerCRLRoleDocumentV2Fields 1.46s. Rows overlap; they are not
exclusive cost, invocation counts, wait time, measured savings, host/build CPU
or the cause of the earlier full-race timeout. No Go source changes or
optimization are accepted. Next independently inspect those source/caller paths
using this saved profile, preserving full public-entry validation and all
owner, mapping, issuer, encoding and launch-hold refusals.

The required full race remains **FAILED600.014672s**; it was not rerun.
Phase6 remains **5/15**, Slice6 step2. Step1 historical bounded E is unchanged;
step3 live full Profile-v2/original16/independent acceptance is incomplete;
formal step4 has not started. mise Go1.26.8, existing resource/cache/proxy
settings and all security/evidence gates remain unchanged; timers OFF.
Private evidence: slice6-postgres-peercrl-cpu-20261023-141819.
This is the precommit source record; reviewed commit, push and final full
local/upstream/live disposition are recorded separately.

The earlier [bundle/canonical CPU attribution](audits/product-phase-6-slice-6-startup.md#2026-10-23-bundle-and-canonical-cpu-attribution)
naturally passes in4.441331s under the original shared90s, including full
input/Git/archive pre/post and three local reports. Those commands take
1.103288s/0.269843s/0.269676s, all exit0/reaped, empty stderr, no signal,
timeout or truncation. New18 parser/refusal methods pass0.308325s/30s.
Complete47 direct/2170 source-lock/74 tool-source and oldQ149-file archive
checks pass; local HEAD/upstreambfb8da325b654672f2359f34cb648da226a7fb9b
is clean0/0. No Go test, new profile, project build or host/Docker run occurs.

Old sampled bundle cumulative7.29s attributes3.72s to manifest-file verification,
2.60s to private reads and810ms to canonical receipt calls. Source rows split
private index/raw/envelope reads10ms/2.09s/500ms and canonical index/envelope
640/170ms. Canonical helper total890ms contains duplicate scan410ms,
typedDecode370ms and Marshal110ms; scenario validation contributes another
incoming80ms. Rows and graph weights overlap and round: they are not invocation
counts, waits, measured savings, host CPU or the cause of the old600s timeout.
Unsampled EOF/digest/identity/canonical checks remain necessary.

No production optimization is accepted. Keep early duplicate rejection,
typed unknown/type/trailing refusal, exact canonical bytes, run/config/content
digests, every public entry and dynamic filesystem checks. Current samples do
not justify custom decoding, reordered checks, new maps or caches. One stale
source-text mutation in an unexecuted fixture draft was corrected before final
review; old draft/plan bytes remain and no failed identity is replayed.
Next independently select another high-cost target from retained phase6security
evidence and require a discriminating bounded plan before new execution.
Do not keep replaying this completed diagnostic or the full repository blindly.
Private evidence: slice6-bundle-canonical-cpu-lines-20261023-124851.

The prior sync stage naturally pushesbfb8 and observes identical complete
local/upstream/final live SHA, clean0/0; old failures stay preserved. This
analysis freezes precommit source records; its later reviewed docs-only commit
and normalpush/full live disposition will be recorded separately.
Required fullrace remains **FAILED600.014672s**, Phase6 **5/15**/Slice6step2.
Step1 historical boundedE unchanged; step3 live fullProfileV2/original16/
independent acceptance incomplete; formalstep4 not started. Docker authority/
Linux/native/P2/publicProfileV2/provider-v3/twoissuer broker+general/
PostgreSQLgeneral/9bindings64barriers/oldlocks/reuse stay held. Existing
miseGo1.26.8/-p2/cache/publicproxy recipe remains, no kernelquota/networkexclusion
claim, globalinstall, unrelatedprocess intervention or quota/deadline expansion.
TimersOFF.

The earlier [receipt-file source CPU attribution](audits/product-phase-6-slice-6-startup.md#2026-10-23-receipt-file-source-cpu-attribution)
naturally passes the complete retained-profile operation in3.526027s/90s.
The three local reports take0.791644s,0.169803s and0.453769s; all exit0/reaped,
with empty stderr and no timeout/signal/truncation. Complete120 direct,
2170 source/locks,74 tool sources and the old149-file archive pass pre/post
checks. Local HEAD/upstream089eac50dc8a4a16c0aaa1b1a3eb85f86b384fe1 is clean0/0.
No Go test, new profile, project build, Docker or host observation runs.

Root cumulative1.67s resolves to Lstat1.65s and lexical/Clean20ms.
File cumulative2.60s receives a sample edge from VerifySlice6EvidenceBundle;
root-call1.67s, ancestor/file Lstat280/90ms,Open420ms,ReadAll100ms,
Dir10ms and graph Close30ms remain rounded overlapping CPU samples.
Graph weights are not invocation counts, wait time, measured savings or the
cause of the earlier full-race timeout. Unsampled checks remain necessary.
No production optimization is accepted: dynamic filesystem checks cannot
be cached as immutable computation; small lexical samples do not justify
extra code. Diagnostic artifact UID/GID/link checks are not invented as
existing application helper assertions.

Original lines-v1 remains FAILED2.666709s: its first pprof exits0/0.969017s
but the absolute-only parser refuses the correct repository-relative source
header; later reports do not run. A separate0.816133s after-failure closure
does not pass that identity. Independent correction review permits only the
two complete exact path spellings, with every source line still byte-matched.
Corrected18 parser/refusal methods pass0.048450s/30s; old16/failure originals
remain. An unexecuted draft with wrong branch/artifact names is blocked before
a precisely corrected executor and full new identity receive independent review.

Next independently inspect this same retained profile's bundle/canonical-decode
source and callers, preserving early duplicate/type/unknown/trailing/canonical/
digest/content and every public-entry refusal. No change is approved here.
Private evidence: slice6-receipt-file-cpu-lines-20261023-114816.
The required fullrace remains **FAILED600.014672s**; no rerun or fresh pass.
Phase6 stays **5/15**: step1 historical bounded E unchanged; step2 ongoing;
step3 live full Profile-v2/original16/independent acceptance incomplete;
formalstep4 not started. Docker authority/Linux/native/P2/publicProfileV2/
provider-v3/two-issuer broker/general/PostgreSQLgeneral/9bindings64barriers/
oldlocks/reuse stay held. Existing miseGo1.26.8/-p2/cache/public-proxy recipe
remains; no kernel-quota or network-exclusion claim, expanded quota/deadline,
installation or unrelated process intervention. TimersOFF.
This is the precommit source record; actual reviewed commit/push and full
local/upstream/live disposition will be recorded separately, not preclaimed.

The earlier [receipt-bundle targeted CPU diagnostic](audits/product-phase-6-slice-6-startup.md#2026-10-23-receipt-bundle-targeted-cpu-diagnostic)
naturally passes its original shared90s batch in40.124208s. The exact
TestSlice6ReceiptBundleRejectsCrossRunAndTampering parent and all seven children
pass, with37 complete JSON events, one package PASS and a new shuffle seed.
The parent also retains raw/index/path/permission/scenario/cleanup assertions;
eight outcomes do not mean only eight business checks. No fixture or Go source
changes. The old full-repository race remains **FAILED** at600.014672s.

The target command takes38.628149s, flat pprof0.989787s and cumulative pprof
0.220421s, all natural0/reaped with empty stderr and no signal, timeout or
truncation. Shared90s includes root preparation, test, complete artifact retention
and both local pprof commands. Full input/Git/environment pre/post checks keep
their original separate bounds; this is not a whole-operation90s guarantee.
Complete2170 source/lock,74 tool-source,105 direct,three helper and two module
pins and clean local HEAD1ca31bcea10e11bd350e77956a2d5443394f2565 checks pass.
Recorded upstream0154f0de708d35a49978858552c788432524a85a remains one commit behind;
that is frozen local identity, not proof of current remote synchronization.

Exactly two outputs remain: cpu.pprof40914B and phase6security.test16424322B.
Same held FDs bind root0700->02700->0700, generated0644/0755->retained0600,
unchanged full bytes/hashes, UID/GID/single-link identities and seven ACL checks.
The existing1MiB/16MiB thresholds are observed caps, not kernel quotas or proof
against a hostile same-UID writer. New18 offline refusal methods naturally pass
in0.159219s/30s, including old16 and actual old39-case stream refusal.
An initial preexecution plan was blocked for stale top-level bootstrap/root
metadata before any Go command; its original remains. Corrected v2 inputs
received independent approval, without code changes or replaying a failed run.

The profile spans33.60s with22.48 sampled CPU seconds (66.91% as reported by
pprof). It covers this test process including race/runtime, not builder or host
CPU. Global cumulative rows show VerifySlice6EvidenceBundle7.29s,
VerifySlice6Evidence3.71s, Decoder.Decode2.74s,
readPrivateSlice6ReceiptFile2.60s and absoluteSlice6ReceiptRoot1.67s.
Rows overlap: do not add them or call them caller-exclusive cost, measured saving,
CPU saturation, IO/swap cause or an explanation of the earlier600s failure.
The historical unprofiled27.21s is a different context, not a controlled comparison.

Next independently review bounded source-line/caller inspection of this retained
profile for private-file/root checks, without rerunning tests. Identify dynamic
filesystem checks versus repeated same-call computation before proposing any
equivalent change. Preserve every public entry, root/file identity, symlink,
ownership/mode/replacement, EOF/hash/canonical/content refusal; do not cache
evidence across calls or assume alias stability. No optimization is accepted here.
Private evidence: slice6-receipt-bundle-cpu-20261023-111347.

mise Go1.26.8/GOMAXPROCS2/-p2/umask022 and existing module/cache/index recipe
remain; concurrency flags are not kernel quotas. Public GOPROXY remains capable
of fetching missing modules; no network-exclusion or no-implicit-download claim.
No full-repository rerun, Docker/runtime scenario, global installation, unrelated
process intervention, quota/deadline expansion or reuse-rule change occurs.
Phase6 stays **5/15**: Slice6step1 historical bounded Guest E unchanged; step2
ongoing; step3 live full Profile-v2 inventory/original16/independent acceptance
incomplete; formalstep4 not started. Docker authority/Linux/native/P2, public
ProfileV2/provider-v3 holds, broker/general-only/PostgreSQL general,
nine bindings/64 barriers and old locks/evidence remain. TimersOFF.
This source record freezes the precommit checkpoint. Actual reviewed commit/push
and full local/upstream/live disposition will be recorded separately; no successful
remote synchronization is preclaimed.

The earlier [retained race-timeout analysis](audits/product-phase-6-slice-6-startup.md#2026-10-23-retained-race-timeout-action-analysis)
completes one independently reviewed offline operation naturally in10.902611s/90s,
including full input/local-Git pre/post checks and22 passing synthetic tests.
No Go test, build, Docker command, fresh host observation or network operation
runs in this analysis. The required full-repository race remains **FAILED** at
600.014672s; its213 received package records do not provide a causal timeline.

Original logs independently yield182 tested and31 no-test records, an exact
package/status prefix of the historical267-record success. On the recorded
two-action-worker model, conservatively subtracting1ms per displayed duration,
the received test-action intervals imply a necessary span of at least524.019s;
the same historical prefix gives330.2395s and the old complete run373.476s.
These are conditional action-span lower bounds, not CPU use, full-command elapsed,
remaining budget or proof of a cause. Never splice old suffix durations into
this run. Go's ordered/buffered output leaves54 historical names without received
results; none is thereby proved unstarted, hung or failed.

The largest displayed intervals include phase6security345.135s (old191.013s),
controlstorage56.678s (22.065s) and qualificationadapterprotocol47.310s
(19.987s). Multiple packages increased in different run contexts; no controlled
regression is established. No old process CPU/stacks/profile, actual PID timeline
or compile/queue timings exist in these records. Installed Go1.26.8 source ties
the displayed duration to the last test execution attempt through preformatting,
including post-Run buffer handling and rounding; it is not exact process CPU/wall.

Next prepare an independently reviewed exact-case CPU diagnostic for
TestSlice6ReceiptBundleRejectsCrossRunAndTampering, whose retained earlier
single-package trace reports27.21s. Current source repeats full bundle
verification across seven named envelope mutations and further raw/scenario/
cleanup refusal paths. Retain every assertion and fixture; collect complete
test events plus the existing exact-two-artifact CPU profile/binary under the
original90s batch and unchanged tool/cache/resource settings. This is a proposal,
not an executed or admitted diagnostic, and success would not explain the old
full-run timeout. New controller/target refusal tests, identity and complete
inputs require review before execution.

All2170 source/lock pins, three preanalysis progress docs,28 direct inputs,
three helpers and both sealed228/333-file checkpoints pass complete pre/post
checks. Content differences from the old successful source are only two added
and two changed phase6tls files; that does not establish build/runtime/environment
equivalence. The earlier focused93 outcomes and vet remain their recorded
same-Go-source evidence; no new full-suite pass is claimed. Private evidence:
`slice6-race-timeout-analysis-20261023-094817`.

Phase6 remains **5/15**: step1 historical bounded Guest E unchanged; step2
ongoing; step3 live full Profile-v2 inventory/original16/independent acceptance
incomplete; formalstep4 not started. Docker authority/Linux/native/P2,
public ProfileV2/provider-v3 holds, broker/general-only/PostgreSQL general,
nine bindings/64 barriers, old locks and reuse rules remain. mise/Docker only;
no quota/deadline expansion or unrelated process intervention. TimersOFF.
Prior0154 source push naturally succeeded and one postpush query observed it;
the later final live query and a separate readonly attempt failed. Do not claim
latest remote equality from local tracking alone. This document freezes the
precommit analysis checkpoint; a separately reviewed Git stage will record actual
commit/push and final local/upstream/live disposition.

The earlier [CRL drain source checkpoint with a full-race timeout](audits/product-phase-6-slice-6-startup.md#2026-10-23-crl-close-errors-and-single-budget-drain)
is an unaccepted intermediate source checkpoint. It fixes three independently
reproduced guard defects: discarded Close errors,
remaining peers omitted after a partial failure, and fresh authority restoring
readiness while an old socket is still closing. The old-source three-test command
naturally failed in2.751586s; its original failure remains preserved.

One guard-wide batch claims identities under the admission lock and runs Close
outside that lock with at most16 workers. The first real monotonic close deadline
is shared across the same call and concurrent joins; it may shorten, never renew.
A Close error or deadline permanently fails the guard and claims the remaining
peers within that batch. Pending closure refuses Ready/Track/fresh authority
commit; synchronous Registry.Forget cannot erase an uncertain closing identity.
Successful ordinary source-loss/expiry closure may recover only after a fresh
verified pull. Existing budget derivation and the8192 total identity cap remain.

Focused race naturally passes93 test outcomes (including children) and2 packages
in9.596221s/90s, with382 complete JSON events and no failure/skip.
The required final default-tag repository race **FAILED** at its original600s
limit (actual600.014672s, owned process group killed/reaped). Its16430B stdout
contains213 complete package records:182 ok and31 without tests, including
phase6tls5.488s, connectiondrain2.642s and phase6security345.135s. The remaining54
names in the old267-package list have no received result; this does not prove
which tests ran, stalled or failed. No cause is established and no full rerun occurs.
Final vet naturally passes in4.631769s. All2170 source/lock and direct/Git
pre/post checks pass. Focused/vet have no timeout, truncation or active signal;
the failed full race is neither a pass nor replaced by the old095 checkpoint. mise Go1.26.8,
GOMAXPROCS2/-p2 and childumask022 remain; concurrency flags are not kernel quotas.
These are component/development gates, not live Vault/Guest/Provider evidence.

If16 arbitrary Close calls never return, the17th stays queued: it is not proved
physically closed. The guard retains uncertainty and rejects admission; cleanup
may continue on the original pool after failure, without converting it to success.
New tests release their owned blockers and verify cleanup, no retry and bounded
concurrency. No old receipt, manifest, lock or reuse rule is overwritten.

Next independently analyze this full-race timeout's retained output and any
available process evidence, then propose a discriminating bounded diagnostic;
do not blindly replay the whole repository or reuse this failed identity. Private evidence:
`slice6-crl-close-budget-20261023-085001`.
Phase6 remains **5/15**: step1 historical bounded Guest E unchanged; step2
ongoing; step3 live full Profile-v2 inventory/original16/independent acceptance
incomplete; formalstep4 not started. Docker authority/Linux/native/P2, public
ProfileV2/provider-v3 holds, broker/general-only with PostgreSQL general, nine
bindings/64 barriers and old locks remain. mise/Docker only; no quota/deadline
expansion or unrelated process intervention. TimersOFF.
This source record freezes the precommit checkpoint. Stage commit/push and full
local/upstream/live SHA equality are recorded separately after actual
synchronization checks.

The earlier [same-call evidence Profile validation checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-23-evidence-same-call-profile-validation)
passes the required default-tag repository race and vet on the final reduced
Go source. Slice6Evidence.Validate uses a private observation check immediately
after FinalGate fully validates the same unchanged Profile. Independent transitive
alias review found no intervening writes; every public observation, decode and
evidence entry retains complete validation. This is same-call validation, not
cross-call evidence reuse or protection against concurrent alias writers.

New tests preserve inputs, reject rehashed unsafe public reentry and retain eight
observation-domain refusals with an independently valid final Profile. Earlier
focused57 pass covers the same production/test logic; the final full race naturally
passes in407.273025s under600s with267 complete package records (229 ok,38 without
tests), including phase6security191.013s. Final vet naturally passes in4.932974s.
Full2168 source/lock and direct/Git pre/post checks pass; no timeout, truncation or
active signal. Final Go scope is two production files plus one test file.

The attempted old/new benchmark comparison remains **FAILED**: equal851443-byte
lengths had different corpus hashes. No measured latency/allocation benefit is
accepted; only one redundant Profile.Validate is structurally removed. Temporary
benchmark/fixture changes were withdrawn. Old failures, a blocked unexecuted
baseline wrapper and prelaunch preparation refusals remain private originals.
This success does not explain or retrospectively pass older timeout identities.

Next independently review CRL close-error/partial-drain handling under one existing
total budget. Private evidence: `slice6-evidence-profile-validation-once-20261022-125628`.
Phase6 stays **5/15**: Slice6step1 historical bounded Guest E unchanged; step2
ongoing; step3 live full Profile-v2 inventory/original16/independent acceptance
incomplete; formalstep4 not started. Docker authority/Linux/native/P2, public
ProfileV2/provider-v3 holds, broker/general-only with PostgreSQL general, nine
bindings/64 barriers, old locks and reuse rules remain. mise/Docker only;
no quota/deadline expansion or unrelated process intervention. TimersOFF.
At this precommit checkpoint, stage commit/push are pending. Record full
local/upstream/live SHA equality only after actual synchronization checks.

The earlier [evidence-decoder optimization review](audits/product-phase-6-slice-6-startup.md#2026-10-22-evidence-decoder-optimization-review)
completes read-only pipeline analysis with **no accepted production change**.
Three local lists of the retained profile finish naturally in1.015508s under
the original shared90s; no test, benchmark, project build or new profile runs.
Exact VerifySlice6Evidence source rows attribute3.87s to duplicate scanning,
2.27s to typed Decode,0.47s to canonical Marshal and3.33s to equality/full
validation. These are old sampled CPU costs, not fresh wall-time or saved
budgets. Recursive scanner-list11.58s counts repeated frames and is not unique
CPU; global5.74s Decode/2.41s Marshal include other callers.

Independent review rejects moving duplicate scanning later because early
duplicate large inputs would incur extra decode/serialization work. A digest
copy change is deferred: the entire append+SHA line sampled20ms, with no measured
allocation benefit. Keep byte limit, early duplicate scan, unknown/type/trailing
refusal, exact canonical equality and every public semantic/digest check.
Complete2167 source/74 tool source and129-file retained archive pre/post
verification passes;77 old direct inputs remain current, while3 superseded
progress docs retain byte-matched old copies and separate current pins.

Next independently audit whether Slice6Evidence.Validate can avoid the second
same-call Profile.Validate in observation validation after FinalGate succeeds,
proving no intervening slice/map alias mutation and retaining full validation at
every public entry. No implementation of that candidate is approved here.
Prior full race stays **FAILED**; unchanged-source vet is historical and no
whole-suite run is repeated. Private evidence: `slice6-evidence-decode-analysis-20261022-122648`.
Phase6 remains **5/15**, Slice6step2ongoing, step3/formalstep4 incomplete; all
existing holds, locks, nine bindings/64 barriers and reuse rules remain. TimersOFF.
Stage Git synchronization is checked separately.

The earlier [evidence-inventory CPU attribution](audits/product-phase-6-slice-6-startup.md#2026-10-22-evidence-inventory-cpu-attribution)
completes one fresh exact-test CPU diagnostic in **51.520068s** under the
unchanged shared90s. TestSlice6EvidenceRequiresCompleteClosedInventory and all
38 children pass (39 test outcomes plus one package PASS); the natural test
command takes49.617583s and the two local pprof commands1.214565/0.300383s.
The complete stream has161 JSON events/42273B with no skipped/failed test,
truncation, active signal or timeout. Seventeen new synthetic parser/gate refusal
tests pass; old41 tests cover only unchanged generic guard behavior, not this
new target. Full2326 pin references (2325 distinct paths), including2167 original
source/locks and74 tool sources, and actual Git pre/post checks pass. No source,
assertion, module/cache/index or evidence-reuse rule changes.

The fresh held root stays02700 while producing exactly cpu.pprof/phase6security.test,
then changes through the same FD to0700 after natural complete test success;
both original files tighten to0600 with full bytes unchanged. Seven ACL checks
pass; final profile52335B/binary16387570B are below the unchanged1MiB/16MiB
observed thresholds. These are bounded observations under the private same-UID
premise, not kernel quotas, proof of no transient or production authority.
The profile covers43.87s with32.25 sampled CPU seconds. Flat race helpers lead:
__tsan_read6.28s/19.47%, racecall3.37s/10.45%, racecalladdr2.38s/7.38%.
Cumulative VerifySlice6Evidence is9.94s/30.82%; the global cumulative row for
rejectDuplicateMembers is3.87s/12.00%. Slice6Evidence.Validate3.32s/10.29% and
Profile.Validate2.65s/8.22% also overlap. Do not add cumulative rows or treat this
as compile/mise/host CPU, swap attribution or old full-race cause. New43.68s test
reporting versus prior28.09s is not a controlled regression/speed comparison.

Next read-only and independently examine duplicate scanning, typed decoding and
canonicalization in VerifySlice6Evidence for a provably equivalent optimization,
preserving duplicate/unknown/trailing/canonical and every public-entry rejection;
no optimization is implemented or accepted yet. The prior full race stays
**FAILED**, and prior same-source vet remains valid without another whole-suite
or vet run. Evidence: `slice6-evidence-inventory-cpu-20261022-112148`, private and
outside Git. Phase6 remains **5/15**, Slice6step2ongoing; step1 historical E unchanged,
step3 live inventory/original16/formal review incomplete, formalstep4 not started.
Docker authority/Linux/native/P2, public holds, two issuers/PostgreSQL general,
nine bindings/64 barriers and old locks remain. Timers stay off. Reviewed normal
progress-doc commit/push and fullSHA synchronization are recorded separately.

The earlier [streamed race-frontier diagnostic](audits/product-phase-6-slice-6-startup.md#2026-10-22-streamed-race-frontier-diagnostic)
passes one fresh phase6security single-package race/shuffle/count1/-v identity
in 359.789372s under the unchanged 600s/1MiB bounds. Its 196771B stdout and
empty stderr contain 185 top-level outcomes: 179 PASS, 6 SKIP; including children,
1148 PASS and 6 SKIP, with one package ok at356.268s. No pending names or partial
line remains; natural0/reap, constant reception metadata and complete2167 source/
lock plus actual Git pre/post checks pass. Nineteen offline observation/parser
refusal tests pass; a separate pre-execution launcher SyntaxError remains recorded.
The first stdout receive bound is4.031167s, not exact startup/build time or CPU.
The prior full race remains **FAILED**. Its111 received outcomes exactly match
an older267-package success prefix, whose next historical item is phase6security;
156 historical entries were unreceived, not proved unrun or stuck, and the
current whole-repository package count was not newly enumerated. Fixed Go orders
plain multi-package summaries and buffers package output. New single-package
-v provides test-level evidence without replaying the old capped JSON identity.
Early received controlstorage/dockercontrol/desktopcandidate report114.529/
69.779/22.952s versus historical34.977/36.625/3.930s; these parallel package times
cannot be added as wall time or identify a host/source cause. Current slowest
tests report28.09s for complete evidence inventory,27.21s for receipt-bundle
cross-run/tamper refusal and25.31s for PostgreSQL peer-CRL owner/pinned decoding.
Next independently review exact-test CPU attribution for the28.09s case under
the existing90s diagnostic boundary, preserving all assertions and artifact guards.
This new run proves neither the old full-race cause nor absence of deadlock;
source, order and execution context must not be conflated. Evidence:
`slice6-race-frontier-20261022-102125`. No product Go, locks, cache/index or reuse
rules changed. Existing same-source vet remains valid; no whole-suite or vet
rerun is claimed. Phase6 stays **5/15**, Slice6 step2 ongoing; step1 historical
bounded E unchanged, step3 live inventory/original16/formal review incomplete,
formal step4 not started. Docker authority/Linux/native/P2, public holds,
two-issuer policy and nine bindings/64 barriers remain. Timers stay off; normal
progress-doc Git synchronization is checked separately.

The earlier [same-call network-plan validation checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-22-network-plan-same-call-validation)
is an **unaccepted interim checkpoint: required full race remains FAILED**.
BindSlice6DesiredNetworkPlan now fully validates its input draft and rewritten
output once each, reducing successful top-level Profile.Validate calls from
18 to 2 while retaining every domain check and complete validation at every
public entry. New tests check full input preservation, unsafe reentry after
rehashing and rejection of a rewritten output that loses a reciprocal network
association. Identical race benchmark samples show median ns/op -84.02%,
allocated B/op -86.03% and allocs/op -77.81%; these are descriptive synthetic
results, not peak RAM, end-to-end latency or old-timeout causation.
A new informative JSON identity passes the same nine top-level/23 child tests
and one package PASS naturally in 14.860998s under 90s; its 18 private refusal
tests pass. The first focused run remains FAILED at 90.103202s, despite test
PASS lines without package completion. Full vet passes in 27.874392s. The new
full race reaches the unchanged 600s boundary (actual 600.672669s), is actively
terminated/reaped and fails; 111 received package outcomes do not establish
all-package success or identify the unfinished test. All 2167 fixed source/lock
pins match; mise Go1.26.8, GOMAXPROCS2/-p2, child umask022 and cache/index recipe
remain. No failed identity is rerun. Evidence:
`slice6-network-plan-validation-once-20261022-083637`. Next independently narrow
the unfinished full-suite work using existing receipts and an informative bounded
observation, without another blind full run. Close-error/partial-drain handling
remains open. No live Vault/Guest/three-Provider/final16 acceptance follows.
Docker authority/Linux/native/P2, public ProfileV2/provider-v3, two issuers,
PostgreSQL general, nine bindings/64 barriers, old locks and evidence-reuse
rules stay. Phase6 remains **5/15**, Slice6 step2 ongoing, step3 incomplete,
formal step4 not started; timers stay off. Normal interim Git synchronization
is recorded separately from validation.

The earlier [targeted CPU profile](audits/product-phase-6-slice-6-startup.md#2026-10-22-targeted-cpu-profile)
completes one reviewed diagnostic in 75.914772s under the unchanged shared
90s. The exact Go test naturally exits 0 in 71.236237s with all 16 test passes
and one package PASS; both local pprof commands naturally pass. A fresh root
is strictly 02700 while producing and changes through its held FD to 0700
only after natural Go success and complete JSON verification; both held files
tighten to 0600 with unchanged bytes. Seven ACL checks, final exact two files
and all 73 direct/3 helper/2 module plus 2166 source-lock/74 tool-source checks
pass. No third-name refusal is observed; bounded observations do not prove
that no transient ever existed. The new combined 41 refusal tests pass; the
first optimized-interpreter startup timeout remains FAILED evidence.
Evidence: `slice6-v2-copy-cpu-20261022-072553`. CPU samples cover 52.38s with
32.09 sampled CPU seconds. Race helpers lead flat rows; Profile.Validate has
8.70s/27.11% cumulative cost in this sample. Cumulative paths overlap and
cannot be added. This neither proves the old full-race timeout cause nor a
latency improvement; the earlier full gate stays FAILED and is not rerun.
Next independently examine repeated validation within BindSlice6DesiredNetworkPlan,
keeping separate input/output snapshots and fresh validation at every public
entry. No product code, old lock, cache/index or reuse policy changed. This
remains a private diagnostic under the stated nonhostile same-UID premise,
not production authority. Phase6 stays **5/15**, Slice6 step2 ongoing, step3
incomplete, formal step4 not started; timers stay off. Git sync is separate.

The earlier [private copy-root fixture](audits/product-phase-6-slice-6-startup.md#2026-10-22-private-copy-root-fixture)
passes the directory configuration prerequisite in 0.060627 seconds, after
independent design and implementation/input review. A fresh owner-only root
changes through the same FD from 0700 to 02700 and back to 0700, retaining its
device/inode/UID/GID. Two new tiny samples have no privilege bits, retain their
bytes through root tightening, then tighten from 0644/0755 to 0600. All eight
bounded ACL observations and 35 direct plus three helper input checks pass.
Twenty-four offline refusal tests pass; the initial zero-test discovery failure
is preserved separately. Evidence: `slice6-v2-copy-root-20261022-064857`.
Fixed Go source checks parent setgid before the umask probe and uses CopyFile;
this fixture does not execute that Go path or establish its I/O budget. No Go
or pprof ran and CPU hotspots remain unknown. Runtime third-name acceptance
remains blocked. Next integrate the qualified configuration into the private
controller, preserving exact two names and original limits, and independently
review final code/tests/full fresh inputs before another Go diagnostic. This
is not hostile same-UID protection or production authority; CopyFile may use
extra temporary I/O/space. No product code, locks, cache/index or reuse rules
changed. Prior full-race failures remain FAILED. Phase6 stays **5/15**, Slice6
step2 ongoing, step3 incomplete, formal step4 not started; timers stay off.
Normal Git synchronization is checked separately.

The earlier [artifact-refusal observation](audits/product-phase-6-slice-6-startup.md#2026-10-22-artifact-refusal-observation)
identifies this new run's guard trigger: a non-atomic scan observed the extra
`phase6security.test-go-tmp-umask` name with its listing inode retained privately. The scan
reached EOF without truncation; this is not a simultaneous directory snapshot
or creator/full-stat proof. That name was absent after leader reap. It matches
the fixed Go tool's umask-probe path, without proving the older failure's cause.
The new diagnostic remains **FAILED** at19.196845s with active termination/reap,
not timeout/truncation. Its69 complete JSON events include16 test passes and
a package PASS, but the Go command exits-9 and no pprof runs; CPU hotspots remain
unknown. Twenty-one private observer/refusal tests pass; all2166 source/lock
pins match after execution with clean f483 baseline/upstream. Evidence:
`slice6-v2-artifact-refusal-20261022-060936`. Independent review blocks
allowing a third name during production; no exception was implemented. Next
review the fixed tool's existing copy branch and a precise private execution
configuration that preserves the runtime two-name invariant and owner-only
access. That alternative is not implemented or admitted.
No Go code, locks, budgets, cache/index or evidence-reuse rules changed. Phase6
stays **5/15**, Slice6 step2 ongoing, step3 incomplete, formal step4 not started;
timers stay off. Normal Git synchronization is checked separately.

The earlier [targeted synthetic-v2 CPU diagnostic](audits/product-phase-6-slice-6-startup.md#2026-10-22-targeted-synthetic-v2-cpu-diagnostic)
is **FAILED**, with no CPU hotspot attribution. One fresh exact-test run stopped
at25.428686s on the unchanged artifact-file-set guard, actively terminating and
reaping its leader; this was neither a90s timeout nor stream truncation. Its
68 complete JSON events include the top-level test pass at21.97s and all15
child passes, but no package terminal result. Both pprof commands were not
started. The retained profile/binary remain unaccepted original evidence.
Fixed Go source creates a transient umask probe when retaining a binary; this
is a concrete mechanism candidate, not an observed cause, because refusal-time
names were not recorded. All2166 source/lock pins and the clean d58 baseline
match after execution. Evidence: `slice6-v2-target-cpu-20261022-050334`. Next
review exact transient-file lifecycle observations and refusal tests before
another diagnostic identity; no test or guard is weakened. No Go code, locks,
quotas, deadlines or cache/index recipe changed. Earlier full race remains
FAILED; Phase6 stays **5/15**, Slice6 step2 ongoing, step3 incomplete and formal
step4 not started. Timers stay off; interim Git synchronization is separate.

The earlier [bounded race-timeout investigation](audits/product-phase-6-slice-6-startup.md#2026-10-22-bounded-race-timeout-diagnosis)
adds diagnostic evidence only; full validation remains **FAILED**. A reviewed,
fresh single-package `phase6security` race/JSON run stopped at its unchanged
1 MiB stdout boundary after 456.539950s, before its 600s deadline; its leader
was terminated and reaped. The saved prefix contains 151 top-level passes,
5 skips and no package terminal result. Its slowest completed tests report
48.90s, 38.00s, 32.49s, 27.40s and 24.98s. Across 44 covered intervals the
sampled test process's CPU counter advances 360.99s; this is computation
progress, not function-level attribution or a complete host/wait diagnosis.
The first test event arrived after 2.782432s in this run, which does not
explain the old full-run startup delay. Original failures, guards, cache
recipe and 2166 source/lock bytes remain. No Go code changed or full gate was
rerun. Evidence: `slice6-race-timeout-diagnosis-20261022-041657`. Next review a
focused CPU attribution plan for the measured costly tests before execution.
Phase6 remains **5/15**, Slice6 step2 ongoing; timers stay off. Git checkpoint
synchronization is recorded separately from diagnostic/validation results.

The earlier [2026-10-22 same-call peer-CRL validation checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-22-peer-crl-same-call-validation)
is an **unaccepted interim checkpoint: full validation remains FAILED**.
PeerCRLSources now uses the existing private final-profile verifier after its
same-call entry Profile.Validate, removing one duplicate validation on the
unchanged snapshot. Complete final-graph/nine-owner, ordinary/DNS/purpose and
source checks remain; both public entries still revalidate every call. New
refusals rehash both Profile and Sources bindings before rejecting unsafe
root/privilege settings and accepting the original input again. Existing
race benchmark samples show median allocated bytes -43.95% and allocation
count -33.83%, but median ns/op is 29.1% slower with a wide range: no latency
improvement or previous-timeout cause is proved. Focused race passes in
84.742314s under 90s; full vet passes in 56.586027s. Required full race reaches
its unchanged 600s boundary (actual 600.034008s), is actively terminated/reaped
and **fails**. Its 111 received package outcomes do not establish full success
or identify a stuck test. All 2166 fixed source/lock pins match; existing
mise Go1.26.8, -p2/GOMAXPROCS2 and test umask022 remain. Evidence:
`slice6-peercrl-validation-once-20261022-032759`. Earlier f46 local/upstream/
live synchronization is confirmed separately; this checkpoint's normal Git
synchronization is checked separately from validation. No new runtime,
Vault/Guest/three-Provider or final 16-scenario gate runs, and old candidates do not
inherit changed source. Close-error/partial-drain handling remains open.
Docker authority/Linux/native/P2 and public ProfileV2/provider-v3 holds,
two-issuer policy, PostgreSQL general, old locks, reuse rules and budgets
remain. Phase 6 stays **5/15**: Slice 6 step 1 historical bounded E unchanged,
step 2 ongoing, step 3 incomplete, formal step 4 not started. Timers stay off.

The earlier [2026-10-22 observed CRL expiry checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-22-observed-crl-expiry-checkpoint)
implements a source-level fix independent of Docker management authority,
but full validation is **FAILED**, so this is an unaccepted interim checkpoint.
After a forward wall-clock jump, Ready/Track now invalidate expired evidence
and drain old connections under the original total close budget. They share
one locked transition, advance the first observed expiry watermark and stop
the old timer. Fresh signed pulls, including genuinely fresh in-flight pulls,
can recover ordinary expiry; clock rollback remains latched. Old-source
regressions fail; fixed phase6tls/connectiondrain race passes in 6.849086s and
full vet passes in 5.311936s. The required full race hits its original 600s
limit (actual 600.011412s), is actively terminated and fails. Its 111 completed
package results do not establish full success or locate the timeout cause.
No failed identity is retried. Tested Go/lock bytes match; existing mise
Go1.26.8, -p2/GOMAXPROCS2 and test umask022 remain. Evidence:
`slice6-crl-observed-expiry-20261022-093433`. Close-error/partial-drain handling
remains a separate open source gap requiring a single-budget design. No live
Vault/Guest/three-Provider or final16 gate runs; old candidates do not inherit
changed source. Docker authority/Linux/native/P2 and public admission holds
remain. Phase6 stays **5/15**: Slice6 step1 historical E unchanged, step2
ongoing, step3 incomplete, formal step4 not started. Guards, quotas, deadlines,
issuer policy and reuse rules stay fixed; timers remain off. Next independently
locate the full-race timeout before another justified validation identity.
Normal interim commit/push and full SHA synchronization are checked separately.

The earlier [2026-10-22 late-tracking revocation observation](audits/product-phase-6-slice-6-startup.md#2026-10-22-late-tracking-revocation-observation)
closes a source-level live-role CRL monotonicity gap independent of Docker
management authority. A zero-peer poll could install a revoked CRL between
a good handshake and Track; Track rejected that peer without retaining the
observation, allowing a later higher-number CRL to omit the unexpired serial.
Track now retains the verified revoked serial and certificate NotAfter through
one bounded helper shared with refresh and Poll, and advances the guard's
live clock watermark. The original 8192-entry
cap, including repeated-serial refusal at capacity, stays fixed; capacity
failure drains through existing Close after unlocking. Expired observations
can still retire, and ordinary source-loss recovery is unchanged. Old-source
regressions fail; fixed focused race passes. This stage's full race/shuffle/
count1 passes 267 package outcomes in 582.757202 seconds under the original
600 seconds; full vet passes in 3.901219 seconds. Tested Go/lock bytes match,
with existing mise Go1.26.8, -p2/GOMAXPROCS2 and test umask022. Evidence:
`slice6-crl-track-revocation-20261022-082700`. Test PKI, pipe EOF and synthetic
capacity fixtures are component evidence only; old candidates do not inherit
changed source. Docker authority/Linux/native/P2 and public admission holds
remain. Phase6 stays **5/15**: Slice6 step1 historical bounded E, step2 ongoing,
step3 incomplete, formal step4 not started. Guards, quotas, deadlines, issuer
policy and reuse rules stay fixed; timers remain off. Git sync is recorded
separately.

The earlier [2026-10-22 admission clock rollback](audits/product-phase-6-slice-6-startup.md#2026-10-22-admission-clock-rollback)
closes another source-level mTLS/CRL gap independent of Docker management
authority. Track previously rejected a backwards clock without latching the
failure, while Ready latched it without draining existing connections. Both
now latch under the admission mutex and reuse the existing Close after
unlocking, stopping the expiry timer and draining under the original budget.
Old-source regressions fail for both entry points; fixed focused race passes,
including unchanged/forward-clock controls. This stage's full race/shuffle/
count1 passes all 267 packages in 420.862909 seconds under 600 seconds, and
full vet passes in 3.627552 seconds. The two Go files and existing locks match
the tested snapshot. Development remains mise Go1.26.8 with -p2/GOMAXPROCS2
and test umask022. Evidence: `slice6-crl-track-clock-20261022-074336`.
These are component checks, not live Vault/Guest/three-Provider or final
16-scenario acceptance; old candidates do not inherit the changed source.
Docker authority and Linux/native/P2 remain HELD. Phase6 stays **5/15**:
Slice6 step1 historical bounded E, step2 ongoing, step3 incomplete, formal
step4 not started. Original guards, quotas, deadlines, issuer policy, public
holds and evidence-reuse rules remain; timers stay off. Stage Git sync is
verified separately.

The earlier [2026-10-21 CRL source-loss connection admission](audits/product-phase-6-slice-6-startup.md#2026-10-21-crl-source-loss-connection-admission)
closes a source-level TLS/CRL gap independent of Docker authority: a peer
whose handshake preceded source loss could register afterward using old CRL
evidence. Track now rejects unavailable state under its registration mutex.
Old-code regressions fail; fixed focused race and a real-TLS component pass.
The new full race/shuffle/count1 run completes all267 packages in564.207446s
under600s; full vet passes in53.924708s. Source/locks match, mise Go1.26.8,
-p2/GOMAXPROCS2 and test umask022 remain. A prior offline module-lookup failure
is preserved; normal official Go dependency restoration does not change the
final verifier's offline recipe or sealed caches. Evidence:
`slice6-crl-late-track-20261021-232634`. No real Vault/Guest/three-Provider,
Docker or final-topology gate follows. The earlier
[management-authority gap](plan/product-v1-phase-6-pbs-alternative-observation.md#2026-10-21-management-authority-evidence-paths)
and Linux/native/P2 holds remain. Phase6 stays **5/15**: Slice6 step1
historical bounded E, step2 ongoing, step3 incomplete, formal step4 not started.
Original guards/limits/reuse rules stay; timers remain off. Stage Git sync is
checked separately.

The earlier [2026-10-21 real Docker metadata screen](plan/product-v1-phase-6-pbs-alternative-observation.md#2026-10-21-real-docker-metadata-screen)
completes one reviewed read-only `/info` then `/version` identity. Both return
complete HTTP200 in0.043382/0.004288seconds under the unchanged3-second request,
64KiB wire and8KiB header bounds. All2875 input rows and old aliases match
before/after; the final pre-flush marker is1.950375seconds with outer natural0
under the original90-second parent. The actual Authorization value is **null**,
kept distinct from missing, empty and nonempty; it proves neither endpoint
identity nor management exclusivity. Raw HTTP is not retained and cannot be
independently reparsed. New26 execution-binding mocks pass; the earlier shell
redirection failure remains recorded, with no results attributed to that identity.
Evidence: `docker-metadata-readonly-20261021-191746`. The old reader bytes are
unchanged in a new bound location and both output roots are outside sealed
checkpoints. No Docker CLI, credential access, host admission, container,
build, scan, native observer or P2 runs. Next independently establish a concrete
management-authority/injection-control evidence path before any executor
qualification. Product code, old locks and all existing guards remain; no
Go/Contract rerun is claimed. Timers stay off. Phase6 remains **5/15**:
Slice6 step1 historical bounded E only, step2 ongoing, step3 incomplete,
formal step4 not started. Stage Git synchronization is checked separately.

The earlier [2026-10-21 metadata mock checkpoint](plan/product-v1-phase-6-pbs-alternative-observation.md#2026-10-21-bounded-mock-harness-checkpoint)
passes27 harness refusals and the unchanged17 original mock cases through new
reviewed identities, with complete35/53-row pre/post checks retaining the
original nine exact inputs. Both runs naturally exit0 under the same10-second
parent/64KiB bounds; final pre-flush markers are0.452756/0.379147seconds.
A class-shaped socket guard fixes an intervening `ssl` import failure, whose
raw failed identity remains unchanged. The earlier9.38-second delay is still
unexplained; these new timings do not attribute its cause. Evidence:
`metadata-unit-budget-20261021-100906`. This is private mock component evidence
only: no real daemon request, host admission, native observer, P2, build or
scan runs. A new complete metadata execution identity and actual inputs still
require review; never run a reader that writes into a sealed checkpoint.
Product code/old locks are unchanged; no Go/Contract rerun is claimed. Timers
stay off. Phase6 remains **5/15**, Slice6 step2 ongoing, step3 incomplete,
formal step4 not started. Stage Git synchronization is recorded separately;
these component results do not establish that local commits reached the remote.

The earlier [2026-10-21 alternative observation assessment](plan/product-v1-phase-6-pbs-alternative-observation.md)
rejects a direct Darwin-to-Docker substitution. A separately qualified Linux
prevention design is conditional only: daemon-side process injection, subsequent
exec, network rejection and full timing/identity proofs remain open. The new
private metadata probe is not executed. Its independently reviewed17-case mock
identity fails the original10-second parent, returning no test results or
complete post-input receipt; it is not retried or counted as passing. The
metadata screen and both real executor routes remain **HELD**. Evidence:
`pbs-linux-observation-feasibility-20261021-152922`. All old evidence and guards
remain; unchanged product component evidence is reused, with no Go/Contract
rerun. Reviewed design/progress documents follow normal commit/push; no native
observer, host admission, container, build, scan or real P2 starts. Timers stay
off. Phase6 stays **5/15**; Slice6 step2 ongoing, step3 incomplete, formal step4
not started.

The earlier [2026-10-21 immutable XNU discovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-xnu-immutable-discovery-held)
accepts bounded official metadata, while exact current-platform source remains
**HELD**. The official XNU repository reports `main`; the named
`tags/xnu-13432.` prefix query returns an empty array. Its actual main commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` has an unsigned API message naming
`xnu-12377.1.9`, not the target `13432.1.9`. This is a discovery clue, not
cryptographic version authentication or permission to substitute older source.
Six separately staged requests yield five200 responses and one complete404:
the immutable `config/MasterVersion` Contents request fails; no source is
decoded. The later complete, nonrecursive root tree has21 entries, including
a `config` tree. No child is followed; its contents do not explain the404.
These bounded routes do not prove absence across all official channels.
All requests retain the original10-second/1MiB bounds; all dynamic pointers
are frozen and independently reviewed. New private reader tests pass31+26+16
cases; these73 checks are metadata-tool component evidence only. Existing
product code/tests are unchanged; no Go or Contract suite is represented as
rerun. Evidence: `xnu-immutable-discovery-20261021-123142`, preserving17 prior
sealed checkpoints and1954 initial input rows; current-document versions are
explicitly overlaid. Native provenance/ABI, coherent census, zombies,
no-escape, before-reap supervision and real P2 remain **HELD**. Next require an
authenticated exact current-platform source pointer before recovery and
semantic work. No host admission, native observer, build, scan or container
runs. Four reviewed progress documents follow normal commit/push; private
evidence stays outside Git, original guards/budgets remain and timers stay off.
Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 Apple release mapping check](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-apple-release-mapping-gap)
independently accepts bounded official metadata reads, while exact current-platform
XNU provenance remains **HELD**. Fresh platform metadata still records
macOS27.0.1/26A434, Darwin27.0.0, arm64 and `xnu-13432.1.9~1`.
Apple's release HTML points to a script containing its release catalog; the
complete script has no current version/build/XNU literal. Two separately
retrieved official distribution tag pages contain166 unique tags without a
macos27 tag. These observations do not establish absence from every official
channel; macOS26/XNU12377 records cannot substitute for this platform.
All four HTTP reads return200 within the original10-second request bounds;
source-only parents naturally finish in3.045703/8.712990seconds. Private reader
tests pass27 plus11 focused cases; these are not product/runtime acceptance.
No exact source, native observer, host gate, P2, build or scan is admitted.
Evidence: `xnu-release-mapping-20261021-103210`, preserving16 old sealed trees
and1690 initial input rows, with explicit current-document version overlays.
Next obtain an independently authenticated exact official source/platform
correspondence before recovery and semantic/ABI work. Four reviewed progress
documents follow normal commit/push; private materials stay outside Git,
original guards/limits remain and timers stay off. Phase6 stays5/15;
Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 native API source discovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-native-api-source-discovery-held)
independently reviews a new bounded metadata/source-only identity. The platform
read naturally finishes in0.093355seconds: macOS27.0.1/26A434, arm64,
Darwin27.0.0, kernel label `xnu-13432.1.9~1`. The first exact-tag Apple Contents
request returns404 in0.715244seconds; the other3 files are not requested.
A separately reviewed, distinct root-tree lookup returns404 in2.123506seconds.
Both failures are retained without retry or version substitution. These two
routes do not establish absence from all official channels. Their response
headers/status are retained; the unchanged reader rejects before reading error
bodies, so the0-byte files are not complete error text. Native provenance/ABI,
zombie visibility and coherent complete enumeration remain **HELD**. No libproc
observer or process-group enumeration API runs; the fixed `os.uname` metadata
read does not qualify either. No host gate, P2, build or scan starts. Evidence:
`pbs-native-api-evidence-20261021-095856`. All15 prior sealed trees and1552
previous input rows remain intact; original limits/guards and disabled timers
stay. Next independently identify an official source/platform correspondence
path before semantic analysis or observer implementation. Phase6 stays5/15;
Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 PBS source closure and observation review](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-pbs-source-closure-and-observation-review)
restores all three missing fixed sigstore-go v1.2.2 sources through one new
independently reviewed identity. Exact blob/size checks pass in0.781880/0.979875/
1.100053seconds under unchanged10-second request bounds; source-only joint
review accepts original HTTP bytes and1539 input rows. Static URI/issuer/Rekor
edges are now available; actual stderr/crypto acceptance remains unproved.
The [process/cwd plan](plan/product-v1-phase-6-pbs-process-observation.md) selects
held component-wise directory FDs for CWD, conditionally accepted for later
implementation/refusal tests. Native group observation remains **HELD**:
coherent enumeration, provenance/ABI/zombies/races/no-escape and the current
premature-reap calling chain are unresolved. No native call, host/Cosign case,
build or scan starts. Evidence: `pbs-source-closure-20261021-092647`.
Next independently review bounded official-source/ABI/coherence evidence
collection; do not treat local SDK declarations or equal snapshots as proof.
The old prepared identity stays unexecuted,14 sealed checkpoints remain intact,
and unchanged Python code reuses its49 component tests without a rerun.
Reviewed documentation follows normal commit/push; private materials stay
outside Git, original limits remain, and timers stay off. Phase6 remains5/15;
Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 strict PBS diagnostic components](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-strict-pbs-diagnostic-components)
implement original-bundle provenance postchecks, finite complete error frames,
full input/inode guards and bounded eight-case orchestration. The final managed
Python component suite passes49 tests; a separately reviewed metadata-only read
finishes naturally in0.079128seconds, binding the1926-byte certificate's SAN and
OIDC issuer as candidates. This does not authenticate a signature or prove
Sigstore's field selection. Real P2 remains **HELD**: three fixed Sigstore source
edges and a concrete independently reviewed outer/guard/group-census observer
still need closure. A prepared identity carries eight frozen case inputs and
an explicit non-runnable hold; no host/Cosign case starts. Evidence:
`pbs-controller-20261021-082537`. All13 prior sealed trees and1137 old input
rows/9aliases remain exact; old failures stay failed. New components and three
progress documents follow normal commit/push; private evidence stays outside
Git, original budgets/guards/reuse rules remain, and timers stay off.
Phase6 remains5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 Cosign attestation source recovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-cosign-attestation-source-restored)
restores the exact missing Cosign3.1.3 entry through one independently reviewed
official Contents request in 1.335761 seconds, within the original10-second
boundary. Nine direct loader/predicate/wrapper/default/output dependencies also
pass exact Git-blob checks; one intervening raw10-second failure remains and a
separately reviewed new Contents identity recovers that file. Source review
connects explicit local
root, keyless identity, new-bundle digest verification and predicate checking;
malformed new bundles with an explicit root fail before legacy clients.
Independent design review accepts eight cases, strict original-bundle provenance
checks, deny-network isolation and the unchanged25-second leaf/90-second total
budget. It is a design checkpoint; actual P2 remains held pending implementation,
refusal tests, a separately reviewed new identity/full execution inputs and fresh
original dual-host readiness. No host/Cosign case, archive/SDK recovery, native
build or scan starts. Evidence: `cosign-attestation-entry-20261021-002703`.
Old failures,1061 input rows/9aliases and12 sealed checkpoints remain exact.
Three progress documents follow normal commit/push; timers remain off.
Phase6 remains5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-21 Python/SDK authentication prerequisite review](plan/product-v1-phase-6-vault-generator-output.md#2026-10-21-python-sdk-authentication-prerequisites-held)
confirms the retained Python candidate metadata/bundles, the authenticated good
TUF target, all 27 selected compiler/ABI inputs and the complete 264-file,
5-directory Python header tree. Two separately reviewed source-only batches
each verify 7/8 fixed source files. The same missing Cosign attestation entry
times out at the original 10-second boundary through raw and immutable blob
paths; both failures remain, with no identity retry or further endpoint loop.
Independent review accepts 14 source files and the conditional target-use
analysis, while actual Python verification remains **HELD**: helper/library
behavior cannot prove the missing entry's real wiring. Python archive bytes
and the exact original signed Apple SDK package remain absent from the inspected
recovery materials. No host sampling, Cosign verification, build or scan starts.
Evidence: `python-sdk-auth-20261020-235600`. Next close that exact source edge,
then independently review complete execution inputs, strict provenance/refusal
checks and fresh original host readiness. Existing TUF 4/4 remains limited to
its frozen top chain. Three progress documents follow normal commit/push;
private evidence, original limits/guards/reuse rules and disabled timers stay.
Phase6 remains 5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 frozen TUF four-case pass](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-frozen-top-tuf-four-case-chain-passes)
passes the original dual-host gate and independently accepts **4/4** only for
this new identity's frozen top metadata/target chain. At23:26:44/23:27:50
Asia/Shanghai, load4.37/2.65, top idle81.57%/80.31%, free42%/41% and both Mach
checks pass;65.846674seconds has1253 swapin pages (19.578125MiB) and zero
swapout. The unchanged fixed Cosign then naturally rejects root13, timestamp
and target mutations, while the same-base unchanged good authenticates all
four top roles and11 cached target files. Joint review binds exact variants,
empty isolated caches, strict complete error frames, actual bytes/receipts
and post-state. All31 bounded captures are natural/reaped;1031 input rows and
eight old sealed checkpoints remain exact. Evidence:
`tuf-fourcase-resume-20261020-232404`. Old failures are not reclassified;
raw provisional parser fields remain unchanged, and modern partial root14
files are not authority. This does not prove syscall reads of13, official latest,
inherited rollback/delegation, Python archive/SDK/native or product acceptance.
Next independently review concrete authenticated-target use and provenance for
existing archive/SDK candidate records with all downstream gates intact. Three
reviewed progress documents follow normal commit/push; no implementation,
limit/cache/index/reuse changes, build/scan/new material or timer follows.
Phase6 remains5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 dual-host paging recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-dual-host-recheck-rejects-both-paging-deltas)
uses a new independently reviewed identity with928 complete inputs, preserving
all825 prior rows/9aliases and unchanged approved source. At09:43:52/09:44:58
Asia/Shanghai, load4.41/4.86, top idle64.82%/60.38% and memory-pressure free31%/
31% pass, with first Mach76.902174%. Over65.930274seconds, swapin increases71339
16KiB pages (1114.671875MiB), above32pages/second, and swapout increases95336
pages (1489.625MiB), above zero. Both original paging predicates fail; second
Mach and TUF never start. All25 bounded receipts are natural/reaped without
signal/truncation/timeout; wrapper exit0 is not readiness. All928 before/after/
current input rows and seven old sealed checkpoints remain exact. Role expiry
is still future as a time check only. Evidence: `tuf-fourcase-resume-20261020-094023`.
The failed identity is retained without retry; no gate/limit/tool/cache/index/
reuse changes, build/scan/new material or timer follows. Three reviewed progress
documents follow normal commit/push. A new independently reviewed identity must
pass the complete original dual gate before four-case unchanged-good joint
review. TUF stays0/4, Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-20 dual-host interval recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-dual-host-recheck-rejects-interval-swapin)
uses a separately reviewed new identity with825 complete inputs, retaining all722
prior rows/9aliases and the unchanged approved implementation. Final role
expiries remain future as a time check only. At09:29:40/09:30:46 Asia/Shanghai,
load3.47/3.01, top idle79.37%/75.52% and free40%/33% pass both base samples;
first Mach idle84.791252% also passes. Over65.817397seconds, swapin rises6131
16KiB pages (95.796875MiB), exceeding the original32pages/second bound;
swapout stays zero. The second guard stops before its Mach check and no TUF
case starts. All25 bounded receipts naturally finish/reap without signal,
truncation or timeout; wrapper exit0 is not readiness. All825 before/after/
current rows match, and six old sealed checkpoints remain exact. Evidence:
`tuf-fourcase-resume-20261020-092705`. This failed identity is not retried.
Next a new independently reviewed identity must pass the complete original
dual gate before the frozen four-case batch and joint causal review. Only three
progress documents follow normal commit/push; no gate/limit/tool/cache/index/
reuse changes, external material, build/scan or timer follows. TUF stays0/4,
Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete, step4 not started.

The earlier [2026-10-20 source-bound host recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-source-bound-host-recheck-stops-before-tuf)
independently reviews a new true execution identity with722 complete inputs,
preserving all610 old rows/9aliases and four17-file mirrors. The approved
four-line implementation is unchanged; final role expiries are still future,
which is only a time check. At08:58:05 Asia/Shanghai, load3.60 and free40% pass,
but top idle46.22% fails the original60% floor. The first guard stops before
Mach, the second sample or any TUF case; no paging interval is measured.
All13 bounded receipts naturally finish without signal/truncation/timeout and
are reaped; host wrapper exit0 does not override its false readiness result.
All722 before/after/current inputs match; five old sealed checkpoints remain
exact. Evidence: `tuf-fourcase-resume-20261020-085244`. The failed identity is
retained without retry. Next use a separately reviewed new identity and the
original dual gate before the frozen four-case batch and joint causal review.
Only three progress documents follow normal commit/push; no tool/limit/supply/
cache/index/reuse changes, new external material, build/scan or timer follows.
TUF stays0/4, Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-20 strict four-line capture policy](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-strict-four-line-capture-policy)
adds a reusable pure-Python fixed-Cosign3.1.3 parser and independent synthetic
tests in tools/tuf-diagnostic-policy. It exactly matches both distinct warnings,
case-specific full duplicated payloads and complete target expected/got hashes;
strict natural receipt, original25second/1MiB bounds and empty negative stdout
are required. New private caller glue records target/no-success facts before
parsing, rejects broken symlinks/unknown errors and retains all good/post/input
checks. Independently reviewed component suites pass96 repository tests and18
adapter/unaffected regression tests;17 unchanged old tests pass separately as a
historical baseline. D4 raw matches only as a format fixture, without changing
its failed result. No actual execution lock, host sample or Cosign/TUF case is
started. Fresh source-bound execution inputs, original host/supply/isolation
gates and unchanged-good joint causal review still precede any TUF acceptance.
All610 inputs/9aliases/four old sealed checkpoints are preserved. Evidence:
`tuf-fourline-policy-20261020-083751`. Only three tool files and three progress
documents follow normal commit/push; private data stays outside Git, original
limits/toolchain/cache/index/reuse rules and disabled timers remain unchanged.
TUF stays0/4, Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete,
step4 not started.

The earlier [2026-10-20 util and standard-log source closure](plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-util-and-standard-log-source-correspondence)
verifies18 new fixed-version source/module files and one complete tree through
19 successful original10second-bounded requests. Legacy util confirms
13.root.json naming and the complete expected/got hash error. A new independently
reviewed read-only static observation passes in1.323606seconds after36 synthetic
tests, locating global log.SetFlags at CUE0.16.1 adt/log.go:54; verified source
sets0 in init, consistent with D4's untimestamped final line. Eight module-identity
byte tests pass before strict CUE decoding. Failed diagnostic/fixture/invocation
identities and unexecuted drafts remain preserved. Static metadata uses pinned
Go intervals within participating Mach-O sections;15988 text suffix bytes stay
unexplained. This closes the two source-correspondence gaps, not actual13 reads,
cryptographic mutation-versus-good causality or TUF acceptance. The conditional
strict-four-line repair now requires the full target hash payload and concrete
parser/refusal review before any new original-gated four-case run. All610 inputs,
9aliases and three old sealed checkpoints remain exact. Private evidence:
`tuf-source-gap-20261019-151705`. No Cosign/host/TUF/build/scan/container or repository
test runs; no TUF parser/root/cache/index/reuse/limit/toolchain change or timer starts.
TUF stays0/4, Phase6 stays5/15; Slice6 step2 ongoing, step3 incomplete,
step4 not started. Only reviewed progress documents follow normal commit/push.

The earlier [2026-10-19 fixed Cosign client/error source recovery](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-fixed-cosign-client-and-error-source-recovery)
verifies27 source/module files and two complete updater trees in a new
independently reviewed identity. Source explains modern14 persistence before
Refresh, legacy's separate memory/DB and embedded12 selection, old/new root
threshold checks, success-only disk synchronization, and Cobra/main's two
error emissions matching D4's four lines. Three10second-deadline requests
fail and remain recorded; util VersionedPath/hash-format source and global
logger-flag attribution are still missing. Core paths are source-supported,
but the complete helper chain, actual13 read and mutation-versus-good
causality are not proved. Root/timestamp and target failures also have different
wrappers; predicted unexecuted cases are not actual results. The conditional
repair keeps root13, nil external root, exact case-specific error frames,
all refusal checks and the original four-case order/bounds. No implementation,
new host/TUF run, test/build/scan/container or timer starts. Private evidence:
`tuf-source-recovery-20261019-133746`. Old evidence stays exact; TUF remains0/4,
Phase6 stays5/15, Slice6 step2 ongoing, steps3/4 incomplete/not started.

The earlier [2026-10-19 fixed Cosign root investigation](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-fixed-cosign-roots-and-causality-held)
identifies static legacy root12 and modern root14 in the exact Cosign3.1.3
binary; D4's cached root exactly matches the modern root's5491 bytes. Exact
initialization source calls modern first and falls back to legacy with nil
external root. These distinct paths do not make cached14 proof of a legacy14
bootstrap, and do not establish that D4 read13 or rejected its mutation.
Three official source requests fail at the unchanged10second deadline;
network stops and complete client/updater source remains missing. A strictly
reviewed local FS observer maps all11 embedded file blobs to official tag
objects; its earlier failed plain-hash hypothesis is preserved. This is static
storage evidence, not actual TUF execution or acceptance. The conditional
repair proposal first requires complete source review, then strict error-frame
and refusal tests and a new original-gated four-case run including unchanged
good. No parser, fixture, root, old cache/evidence, quota or timeout changes.
Private evidence: `tuf-bootstrap-readonly-20261019-130227`. No new host sample,
CLI/test/build/scan/container or timer starts; TUF stays0/4 and Phase6 stays5/15,
Slice6 step2 ongoing, steps3/4 incomplete/not started.

The earlier [2026-10-19 host pass and held TUF root attribution](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-host-gate-passes-tuf-root-attribution-held)
passes the original dual-host gate in its actual20:45:13/20:46:18 Asia/Shanghai
window: load2.01/1.85, top idle88.18%/77.96%, free38%/42%, both Mach checks,
and65.717408seconds with105 swapin pages (1.640625MiB) and zero swapout.
The existing TUF batch then starts only `bad-root13`. Its CLI naturally exits1,
but four actual stderr lines fail the parser's strict three-line expectation;
the case is not accepted and the remaining three do not start (0/4 accepted).
The cache also contains unverified root v14 while the mutation targets v13;
the rejection's causal link to that mutation is unproved. Do not clear this
by only accepting another error format. Next independently review the fixed
tool's bootstrap/update paths, mutation causality and any strict parser/case
correction before another identity. All610 inputs/9aliases/four mirrors remain
exact; old evidence is preserved, no implementation or limit changes and no
retry or timer follows. Private evidence: `tuf-chain-resume-20261019-124329`.
Phase6 remains5/15, Slice6 step2 ongoing, steps3/4 incomplete/not started.

The earlier [2026-10-19 two-sample recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-two-sample-recheck-refuses-interval-paging)
uses a new independently reviewed identity and the unchanged implementation.
At19:57:03/19:58:09 Asia/Shanghai, both base samples pass load, top CPU idle and
memory floors; the first Mach observer also passes. Over65.723560seconds,
swapin rises4112 pages (64.25MiB) and swapout1456 pages (22.75MiB), violating
both original interval predicates. The second guard stops before its Mach
observer, so original dual readiness fails and TUF four cases remain unstarted.
All512 locked inputs,9aliases and four17-file mirrors match before/after;
the previous184-file/19-directory checkpoint and seal remain exact. Frozen
tests are reused without rerunning them. Evidence:
`tuf-chain-resume-20261019-115426`. This dated observation does not establish
ongoing host performance or attribute paging to a process. No retry, new
external material, scanner/build or timer is started. The progress update
follows the standing stage-checkpoint commit/push direction;
Phase6 stays5/15 and Slice6 step2 remains ongoing, with steps3/4 incomplete/not started.

The earlier [2026-10-19 local source checkpoint and held TUF chain](plan/product-v1-phase-6-vault-generator-output.md#2026-10-19-local-source-checkpoint-and-held-tuf-chain)
preserves the existing implementation in local commits and updates this handoff.
All2148 Go files and all2390 Git-visible non-document files exactly match the
2026-10-13 validated snapshot by file set and SHA256. Its503.355-second full
race run with `-p=6`, vet and both Contract results are same-source historical
evidence; none was rerun during this resource-constrained checkpoint. Its last
actual host attempt at14:53:30 Asia/Shanghai has load5.15/free31% but CPU idle
35.65%<60%, so it stops at the first sample; no second sample or TUF case starts.
The added same-boot guard has25 passing tests, but supplies no host or TUF
admission. Timestamp812 remains an unverified candidate. Private evidence stays
outside Git, automation stays off, and all existing supply/isolation gates and
public holds remain. This is an intermediate local source checkpoint, not
Slice6 step4, a new scan, remote synchronization or release. Phase6 remains5/15;
Slice6 step2 is ongoing and steps3/4 remain incomplete/not started.

The earlier [2026-10-15 interval readiness recheck](plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-interval-readiness-recheck-keeps-native-apk-held) confirms the original DB remains fresh at that dated observation and both37/19 raw scan reports match, reused without rescanning. Three manual samples87.190/78.641seconds apart retain the same Docker daemon and all27 calls pass, but continuing large swap deltas and load28.44→20.16→16.79 fail whole-host stability. Native Alpine APK execution remains unperformed in that checkpoint; no new container execution plan is admitted. Installation/GPG helpers remain separately held. Evidence: `gpg-native-recheck-20261015-102127`. Existing mise/Docker, limits and deleted automation remain unchanged. Phase6 remains5/15, Slice6 step2 ongoing; steps3/4 remain incomplete/not started. The dated DB freshness is not current supply admission.

The earlier [fresh DB and scan checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-fresh-vulnerability-db-and-scans-with-native-execution-held) restores and authenticates the complete official Trivy v2 DB layer. New scans recognize all37 Alpine proposal package/source/PURL records and all19 packages of the exact signed Wolfi carrier, with zero findings. The proposal result is metadata coverage, not installation or final GPG/Node admission. Six interval host samples retain the same Docker daemon, but swap activity continues; the final load is17.47 and the5second CPU sample fails. Native Alpine APK execution stays held. Installation and GPG helper paths require their own concrete independent review; existing RO/noexec/UID boundaries are unchanged. Earlier manifest/range/scan-precheck failures remain recorded. Private evidence: `gpg-db-native-20261015-094855`. Existing mise/Docker, quotas/deadlines, old locks/candidates and deleted automation remain unchanged. Phase6 remains5/15, Slice6 step2 ongoing;15 outputs and ENOSPC/OOM remain unverified.

The earlier [Docker/readiness checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-15-docker-restored-native-admission-still-held)
confirms the existing desktop-linux Docker daemon has returned: five interval
samples retain the same daemon/platform/version, with all15 ping/version/info
calls successful in13.14–34.17ms. Host load/CPU improve, but continuing swap
activity prevents accepting stable whole-host readiness. The previous DB
expired at2026-10-15T01:19:20Z; a reviewed new official metadata request fails
at the unchanged10second TLS connection bound. No DB layer/import/new scan or
native APK/install/GPG/container/compiler execution occurs. Original failures
are preserved without further retry, alternate source or relaxed limits. Independent
review also identifies an unresolved installation path under RO root/noexec
work/tmp: skipping scripts or adding an executable writable root is not
acceptance. Existing mise/Docker, old locks/candidates and deleted automation
remain unchanged. Evidence: `gpg-native-readiness-20261015-093139`. Phase6
remains5/15, Slice6 step2 ongoing;15 outputs and ENOSPC/OOM remain unverified.

The earlier [Alpine GPG dependency/prescan checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-alpine-gpg-dependency-materials-and-proposal-prescan)
restores the37 fixed-index proposed APK originals and passes their limited
signature/control/data correspondence (36 new OS crypto checks plus exact old
GPG evidence reuse). A full37-package/source/PURL metadata prescan reports zero
findings with the unchanged fresh DB. This is a proposal prescan, not actual
installed/full-image/embedded coverage or GPG/Node execution admission. Static
ELF audit visits133 regular files/55 ELF and152 edges, retaining one SQLite
RUNPATH as unresolved; installation/trigger/helper effects and mtab's runtime
mount remain open. The existing Docker context still names the missing same
socket; no container/candidate/compiler executes. Original transfer and v3
parser failures are preserved. Existing mise/Docker, quotas/deadlines, old
candidates/locks and deleted automation remain unchanged. Evidence:
`gpg-alpine-closure-20261014-1006`. Phase6 remains5/15, Slice6 step2 ongoing;
15 outputs,2637 exports and ENOSPC/OOM repair remain unverified.

The earlier [Alpine GPG key/source/data checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-alpine-gpg-key-source-and-signature-data-checkpoint)
binds the exact publisher key through official same-record pages and its fixed
mirror recipe, restores all12 GPG source originals with matching recipe SHA512,
and passes a reviewed9-process/2-datahash cryptographic data diagnostic using
the existing Apple-signed OS tool via mise Python. Original APK/index signatures
match; wrong-key/control/signature and data-only tampering reject. Full inputs
and tools match before/after. This is not native apk compatibility, full supply
or GPG/Node execution admission; no source/build reproduction is claimed. Host
load falls to2.53 in one sample, but the expected Docker socket is absent and
all three API calls fail. No container/compiler runs. Next review complete
dependencies/ELF/helpers and fresh coverage, then actual native/candidate gates
when the same daemon is ready. Evidence: `gpg-alpine-authority-20261014-0848`.
Old inputs/limits and deleted automation remain intact; Phase6 remains5/15,
Slice6 step2 ongoing, with15 outputs and ENOSPC/OOM repair still unverified.

The earlier [GPG replacement-material checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-gpg-replacement-materials-and-renewed-host-pressure)
retains an Alpine edge/aarch64 gpg2.5.22-r0 APK and the same declared commit's
official aports mirror recipe. All12 source tokens correspond to12 SHA512
declarations (GNU archive,10 patches,1 rules file); those12 originals are not
yet fetched or verified. The APK contains a signature member, but signing-key
authority, actual verification, index/dependency/source/ELF closure, fresh full
coverage and a qualified carrier remain open. The public wolfi2.4.9-r11 bytes
match the earlier authenticated CGR index, but lack a standalone signature;
the exact recipe is not yet obtained or verified, and that execution-candidate
route is stopped. No GPG,
Node, container or compiler executes. Host load again exceeds250 in a saved
read-only sample; a fast single Docker ping does not establish stable readiness.
Evidence: `gpg-verifier-candidate-20261014-0704`. Old candidates/locks and all
limits remain intact; automation remains deleted. Phase6 remains5/15, Slice6
step2 ongoing;15 outputs and ENOSPC/OOM repair remain unverified.

The earlier [APK verifier and GPG source checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-native-apk-index-verification-and-gpg-source-gaps)
restores the five missing wolfi layers and five GPG raw packages. The fixed
wolfi carrier has full signed-assembly correspondence,19/19 fresh APK scan
coverage with zero findings, and an independently reviewed narrow native APKINDEX
run: original signature passes; wrong-key and modified-index cases both reject
with BAD signature. Isolation, input checks and exact cleanup pass. Two earlier
runtime failures remain failures. A subsequent static31-package GPG proposal
records file overlaps, unresolved loader/installation semantics and missing
patch originals; its diagnostic completion is not GPG admission. Two anonymous
queries of the exact publisher source commit/recipe return404. GPG, Node and
compiler execution remain held; the previous Node HIGH rejection is unchanged.
Evidence: `gpg-supply-tls-recovery-20261014-0442`. Automation remains deleted;
Phase6 remains5/15, Slice6 step2 ongoing.

The earlier [vendor-signed Node/GPG checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-vendor-signed-node-and-gpg-chain-checks)
verifies eight new index/native signature and attestation checks for each of the
free Node and wolfi-base candidates. The smaller Node image has28 APKs with
zero findings, but complete161-package installed-JS coverage still reports the
same http-cache-semantics4.2.0 HIGH; it is rejected. Node embedded coverage
remains open. wolfi-base has five missing layers after a measured TLS handshake
timeout, so its full static/scan and APK-verifier admission are unperformed.
Gpgconf and five missing library APKs are now retained as unverified raw inputs;
npth transfer also fails at the unchanged TLS connection bound, and four further
packages are not attempted. APK/index signatures and the GPG verification chain
remain incomplete. No candidate/container/compiler executes. Old locks and
candidates stay intact; automation stays deleted. Evidence:
`node-minimal-gpg-chain-20261014-0343`. Phase6 remains5/15, Slice6 step2.

The earlier [Node/verifier alternative checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-node-and-verifier-alternative-candidates)
rechecks the fixed signed carrier and finds zero vulnerabilities in75 APKs, but
an independently reviewed supplementary scan recognizes all163 installed JS
packages and reports one HIGH in npm's http-cache-semantics4.2.0. The full
carrier remains rejected; upstream's dispute does not waive the current gate.
Node26 is investigated only for the generator controller, not the locked Node22
UI. Its18-node ELF closure and source-locator SBOM are bound, but embedded
component coverage remains incomplete. The replacement gpg2.4.9-r12 raw APK
and embedded recipe are available; gpgconf transfer fails at the original25s
bound, and index/APK signatures, dependency admission and source review remain
open. No candidate/container/compiler executes. Host samples also show continued
swap activity. Old candidates/locks remain intact; automation stays deleted.
Evidence: `node-tool-alternatives-20261014-0253`. Phase6 remains5/15, Slice6 step2.

The earlier Node tool supply checkpoint completes static source/archive/ELF
identity checks and a nine-package scan of the proposed OpenPGP verifier, but
admits neither the verifier nor Node22.23.3. The verifier registry check fails
on argon2id1.0.1's expired signing key; zero scanner findings do not replace it.
The actual Node release signature and complete core/native/bundled/dynamic
library vulnerability coverage remain open. Upstream OpenSSL3.5.8 additionally
matches a newly recorded HIGH advisory. Independent review finds DTLS is not
disabled in the saved arm64 configuration; JS API reachability is unproved,
which does not satisfy the existing zero-HIGH gate. No candidate
Node, compiler or container executes. The15 outputs and ENOSPC/OOM repair remain
unverified, with quotas/deadlines unchanged and automation deleted. Evidence:
`node-tool-supply-20261014-0207`. See the
[static supply checkpoint](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-node-tool-static-supply-checkpoint).

The earlier2026-10-14 continuation prepares a reviewed three-stage cache
diagnostic and passes29 Node host fixtures plus9 Python decoder tests; no
container/compiler executes. Fresh Trivy DB data is recovered by validating31
saved ranges and fetching one missing4MiB range, but candidate scans remain
unperformed. Independent review identifies unresolved signed-release and
complete vulnerability coverage for the actual Node22.23.3 tool. Close that
supply boundary before constructing/reviewing the v10 controller. Final2637
exports,15 generated outputs and ENOSPC/OOM repair remain unverified; existing
quotas/deadlines and deleted automation are unchanged. Evidence:
`vault-generator-staged-cache-20261014-0128`. See the
[generator plan](plan/product-v1-phase-6-vault-generator-output.md#2026-10-14-staged-cache-preparation-execution-remains-held).

Prior Slice6 step2 work: [held Provider / Control TLS peer](plan/product-v1-phase-6-provider-tls-peer.md), following the source/process and CA directory observation components. It connects separate Linux role/agent test processes through the production TLS, signer and source-bound CRL machinery; production Provider/Control commands, Vault/controller issuance, operator/Store and full-graph admission remain open. The follow-up local full-repository race/shuffle/count1 run passed with package concurrency `-p=6` in 510.429 seconds under the unchanged 600-second bound, on the same Go source. The three earlier timeouts remain failed evidence; this is not a default-concurrency or CI result. See the peer document for diagnosis and unchanged production gates.

The [2026-10-13 Vault continuation](plan/product-v1-phase-6-vault-two-issuer.md)
fixes a reproduced duplicate-source/omitted-issuer acceptance in VaultClient
and prepares an opt-in real broker/general component. The exact locked Vault
archive has been restored and verified; image signature/provenance remains
unverified and the fresh scan reports HIGH findings, so real Vault execution
is blocked by the required supply gates. The new full race run also timed out
at the unchanged 600-second bound; component tests, vet and Contract checks
do not substitute for it.
No real two-issuer result or Controller/agent/command composition is claimed.
The private checkpoint is `vault-controller-continuation-20261013`.

The subsequent [race budget diagnosis](plan/product-v1-phase-6-race-budget-diagnosis.md)
removes repeated desired-graph construction within one HBA call while retaining
every validation and per-call freshness. The final full race/shuffle/count1
run with existing `-p=6` passed in **503.355 seconds** under the unchanged
600-second limit; full vet and both Contract locks passed on matching source.
Earlier timeouts remain failed evidence. The independently reviewed
[Vault supply proposal](plan/product-v1-phase-6-vault-supply-remediation.md)
keeps the six HIGH findings and unverified image signature/provenance as
separate unresolved blockers; no candidate lock or trust root was changed and
no Vault service started. Next establish an exact, independently reviewed
candidate dossier before actual two-issuer/command work. Evidence is private
checkpoint `race-vault-remediation-20261013`; Phase6 remains5/15 and Slice6
steps1/2/3/4 remain historical bounded E / ongoing / incomplete / not started.

The [Vault2.1.2 candidate investigation](plan/product-v1-phase-6-vault-candidate-supply.md)
completed original-byte index/platform/config/seven-layer verification and a
fresh full-image scan. The archive race diagnostic passed in24.044 seconds;
scan report generation took1.853 seconds, but the vulnerability gate **fails**
with4 HIGH findings in the actual Go1.26.8/x/net v0.59.0 binary. Image signature
and build provenance remain unverified. Independent review confirmed this
bounded rejection. No Vault service ran and no accepted lock changed; both
new ECR Docker references were precisely removed, retaining historical inputs.
Private evidence: `vault-candidate-supply-20261013`. All2148 Go files still match
the503.355-second full-race snapshot. Next review a replacement/build proposal
with fixed embedded inputs and independently established supply authority;
the Coding-only Go1.26.9 permission does not authorize a Vault toolchain change.
Phase6 remains5/15 and Slice6 step2 remains open.

The subsequent [Vault isolated rebuild proposal](plan/product-v1-phase-6-vault-rebuild-proposal.md)
was independently reviewed, and the user confirmed the Vault-only private
diagnostic Go1.26.9/x/net v0.60.0 exception. The
[input checkpoint](plan/product-v1-phase-6-vault-build-inputs.md) records the
private source patch, unchanged other module selections, full compatible UI
archive checks and reviewed generator/lifecycle boundaries. Ordinary repository
work remains Go1.26.8. The subsequent
[builder admission checkpoint](plan/product-v1-phase-6-vault-builder-admission.md)
closes all24 remaining Go materials, verifies987/987 archive/mod pairs and an
actual offline root go mod verify, and restores all missing Node layers.
However, the complete Node builder scan **fails with4 CRITICAL/65 HIGH** and
signature/build-source admission remains unverified. The held isolation plan
does not authorize that image. No builder/source execution, new Vault binary
or service has run. Next admit an exact viable builder and close the generator
and pnpm store recipes before execution; unsupported Ember5.8, runtime UID/GID
and candidate supply remain unresolved. New private evidence is
`vault-isolated-build-20261013`; previous checkpoints are preserved. Phase6
remains5/15, with Slice6 step2 ongoing and steps3/4 uncompleted/not started.

The subsequent [builder selection and offline recipe checkpoint](plan/product-v1-phase-6-vault-builder-selection.md)
verifies an exact signed Chainguard/apko carrier, its75-package closure and
zero-finding full-image scan, plus a reviewed source-accounted Docker export.
Authenticated pnpm10.34.7 and fixed Node22.23.3 are the private selected tools;
all9 enumer dependency materials now close. The bounded Docker environment and
one-package two-stage offline store probe pass; full UI is not qualified.
Full material inventories expose
8 HIGH generator findings and51 HIGH/4 CRITICAL UI registry findings, so the
separate execution gate rejects complete builds. Historical source/locks stay
unchanged. Next review scoped dependency repairs and unresolved advisories,
then complete the full offline graph and source-build gates. Private evidence:
`vault-builder-candidate-20261013`; Phase6 stays5/15, Slice6 step2 remains open.

The [generator dependency remediation checkpoint](plan/product-v1-phase-6-vault-dependency-remediation.md)
derives only private enumer go.mod/sum, verifies12 module pairs and removes the
old8 HIGH findings. One OpenPGP UNKNOWN stays in the material inventory;
independent exact-package/subprocess review permits only the generator scope.
The reviewed offline Docker run passes original tests and builds the new ELF
in45.290seconds; its actual output scan recognizes all embedded modules and
has no findings. The EXDEV fixture failure and zero-recognition first scan are
retained, not passes. Complete UI remains blocked by the unfixed braces HIGH
and Ember5.8 support boundary. Next verify the fixed15 Vault generation outputs
and independently review a supported UI repair graph. Private evidence is
`vault-dependency-remediation-20261013`; Phase6 remains5/15, Slice6 step2 open.

The [Vault generator output checkpoint](plan/product-v1-phase-6-vault-generator-output.md)
binds the unchanged9090-file private source, exact15 CE root commands and
authenticated offline module graph. The host full-CE dry-run passes; the
original enterprise-tagged selection and first Docker full-root dry-run fail
and remain recorded. A complete986-module root inventory exposes16 HIGH
findings, so the independently reviewed diagnostic scope cannot grant full
Vault build, supply or service admission. The latest v3 attempt reaches the
90-second OCI load limit before container creation; exact cleanup succeeds
and the wrapper later interrupts input postchecking. A separate full-input
check passes in248.239seconds without accepting either failed run. A later
lower-load v4 run imports the same OCI archive in10.159seconds but still hits
the10-package dry-run60-second bound. Its176.071-second failure completes full
input pre/postchecking and precise cleanup. A separate v5 SIGQUIT diagnostic
also times out without returning a stack; its271.977-second failure is retained.
Neither executes compiler exports or enumer. After the user's manual readiness
request, separated samples show61–65%CPU idle and same-daemon info below0.8s.
The reviewed v6 asynchronous observer captures17637 untruncated Go stack bytes
and deliberately interrupts dry-run at55.069s; its171.237s failure is not a
natural60s timeout or a generation pass. At that instant two workers traverse
module-index directories while the main goroutine waits for package loading.
This supports a targeted hypothesis, not a unique root cause. Full input
pre/postchecking and exact cleanup complete; no export/enumer executes. The
heartbeat was deleted at the user's request and remains off. Current evidence is
`vault-generator-resume-20261013-115951` and `vault-generator-stack-probe-20261013`;
older `vault-generator-output-20261013` is preserved. Actual15-output byte
verification and supported UI remediation remain open. Phase6 remains5/15 and
Slice6 step2 ongoing.

The independently reviewed, one-shot `goindex=0` private Go1.26.9 fallback
then passes the same10-package dry-run in15.938seconds with all15 exact
directives. Real compiler export runs for76.486seconds but the gate rejects
534 direct ENOSPC errors and1741 erroneous/incomplete package rows. The2637
package/module/selected-file identities match in a separate post-failure
metadata comparison; clean exports and actual generation do not pass. No
enumer executes. Full input before/after receipts,15 source-target checks
and exact cleanup complete; the run fails in158.554seconds. Evidence is
`vault-generator-index-fallback-20261013`. Next investigate bounded compiler
scratch/cache storage and independently review a concrete repair before any
new attempt; do not enlarge limits, import unknown cache or repeat this failure.
The undocumented index switch is private diagnostic scope only. Phase6 remains5/15.

The subsequent v8 measurement establishes `/work` byte exhaustion rather than
inode exhaustion: free bytes0 with at least45905 inodes available, and nearly
1GiB of combined cache/work allocations. Its119.142-second failure preserves
full inputs and exact cleanup. The reviewed v9 DWARF-off candidate also fails
in172.604seconds:475 direct ENOSPC plus one compiler signal-killed error,
with cgroup oom2/oom_kill1 and Docker OOMKilled=true. Dry-run passes, but actual
exports fail and generated outputs remain0/15. Full input checks,15 old target
bytes and exact cleanup pass; post-failure2637 metadata identity is not export
acceptance. Evidence is `vault-generator-scratch-20261013-1404` and
`vault-generator-scratch-recipe-20261013-1436`. No further runtime attempt or
automation is started. Next independently review a same-run cache/stage design
that addresses both capacity and peak memory within one300-second aggregate
compiler budget/390-second container budget, retaining final simultaneous2637
real exports and15 original output bytes. Feasibility remains unknown; no new
cache policy, `-l`, quota/time increase or production admission is approved.

## Current verified state

- the fixed P2.7 independent external-caller qualification plan is **24/24**;
- the public `sandbox-runtime-external-caller` plan is **13/13**;
- hosted run `35203241121` executed all 15 initial and 5 reconstruction
  scenarios, matched all 91 required observations, and restored the exact
  run-owned resource scope to zero across three stable samples;
- artifact `10488622806` contains the accepted seven-file evidence archive,
  validator receipt, and bounded `qualified` result envelope; and
- post-documentation core CI run `35204434771` passed every required job; and
- Product v1 architecture Phase 1 is complete as committed design and
  Product Contract-definition authority; and
- Product v1 Phase 2 is complete for its fixed nine-step scope: implementation
  revision `98995384c60a924f25ca58d3b7e561207bfa5be8` is selected by lock
  revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`, the clean-VCS 60-case
  Suite and all required release gates pass, and the repository-owned
  independent-process reference run passes 15+5+9 scenarios; and
- Product v1 Phase 3 is complete at **13/13** for its bounded standalone scope.
  In addition to the Product authority, authenticated API, locked Provider
  reconciliation, control, Terminal/Gateway, Guest/Files, transfer/revision,
  Web, catalog, and recording components, run
  `20260918T111903.806694000Z` at implementation
  `04c2755bec125db7e2c04df3f4e2f8cfedb6ec1d` passed nine black-box scenarios
  through four separate role processes and fresh pinned PostgreSQL. Its strict
  evidence manifest records complete process, schema, and container cleanup.
  This same-repository Provider-fixture topology is not deployment, HA,
  hostile-multitenant, independently implemented caller, or production
  evidence; and
- Product v1 Phase 4 Browser is complete at **13/13** for its bounded
  same-repository separate-process scope. Run
  `20260918T152110.677058000Z` at source baseline
  `322eb342650d2ade838f1b3a24e0d5bc0bfbb3e1` passed 12 exact scenarios
  through separate Product, Gateway, Provider, and Browser OS processes with
  fresh digest-pinned PostgreSQL and Valkey plus fresh encrypted recording
  storage. Strict evidence validation confirms the locked Contract identities,
  four roles, scenario set, and cleanup. Deployment, HA, hostile multi-tenant,
  independently implemented caller, and production readiness remain explicit
  non-claims; and
- Product v1 Phase 5 Desktop is **15/15 complete** for its bounded
  same-repository independent-process topology. Slice 1 establishes the
  separate Provider Desktop Contract and Go projection authority at revision
  `720ad15c343e71f36615dc4499edd5e764178bca`, tree
  `343ffde0819207cf99c005096c336735dd33a735`, with a content-derived 71-case
  local Suite. Slice 2 implementation
  `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00` adds exact Product Desktop
  slot/session intent, PostgreSQL migration 8, atomic audit/outbox persistence,
  quotas, concurrency closure, nondisclosure, and restart-safe reads. Slice 3
  implementation `f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5` adds the separate
  Provider Desktop domain, application policy, memory/atomic-file authority,
  restart and unknown-outcome reconciliation, operation projection, and
  optional protected handlers. Slice 4 candidate implementation
  `163dd8a258a24cf4727169b1cbd8ed7c0fe29292` adds the locked Desktop image
  inputs, fixed Unix-only broker, reproducible local outputs, passing native
  arm64 smoke, and a manual native publication/provenance workflow. Run
  `35447651328` at source `e4a940bda6c5172a78d0dbe40963ca1a99911976`
  passes native amd64/arm64/v8 gates, publishes exact signed index
  `sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`,
  and passes fresh independent provenance and architecture verification.
  Slice 5 implementation `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b`
  adds the Provider-local Docker adapter, durable opaque reference authority,
  fresh attach/reconnect checks, lifecycle readiness, exact duration usage,
  and revoke/cleanup/absence composition. Slice 6 implementation
  `2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240` adds the locked network-only
  Product adapter, isolated Desktop slot/lifecycle/session/observation workers,
  retained operation recovery, separate Product/Provider generations, and
  Desktop-specific close cleanup with a real-PostgreSQL gate. Slice 7
  implementation `0649d62911abb89229de40136347286736152ec6` adds exact
  Desktop-only viewer/controller grants, encrypted one-use tickets,
  session-scoped controller fencing, independent viewer/controller quotas,
  revocation, continuous authority checks, and metadata-only audit. At that
  boundary, production startup composition, public signaling/media/input,
  policy, unified Web, capability advertisement, and release evidence remained
  absent.

  Slice 8 implementation `040c560f3701b7c972c25f05928dd435d9f55c20`
  adds a separate bounded Desktop WebRTC handler with authenticated encrypted
  signaling, exact Origin, receive-only VP8/optional Opus, viewer/controller
  separation, ordered fenced input, continuous authority, and backpressure
  closure. Durable Desktop policy, a real Provider media bridge, recovery,
  recording, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 9 implementation `24f5c741eb605614f77f8d9d546708b9993e42dd`
  adds immutable versioned Workspace policy, PostgreSQL migration 11,
  deny-by-default keyboard/pointer/touch/clipboard/transfer authorization,
  activation and consent, bounded clipboard/media/digest/count/size/path
  rules, exact Product transfer binding, and continuous policy-revision
  revocation. A real Provider media/input bridge, reconnect/recovery,
  recording, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 10 implementation `f23b16130c97e99d5d28008b01346779a0c681ee`
  adds database-time Desktop Gateway leases for bounded crash recovery,
  fresh-grant reconnect with exact authority/generation rebinding, visual and
  audio resynchronization with rate bounds, closed display/audio-output
  changes, connection-epoch stale-input rejection, and transactional cleanup
  plus one-generation replacement for a replaced Desktop slot. A real Provider
  media/input bridge, recording, production composition, unified Web,
  capability advertisement, and release evidence remain absent.

  Slice 11 implementation `c5b045abc5192b76b7d615ddbb0858b998ef98d5`
  composes required Desktop content recording into the public Gateway. The
  client supplies an explicit bounded consent reference and receives the exact
  selected recording mode; missing initialization or live recorder loss closes
  admission/connection. Encrypted immutable segments retain bounded VP8/Opus
  RTP plus minimized control/synchronization metadata, monotonic timestamps,
  and digest linkage. Existing Product authorization, quotas, integrity replay,
  retention, and deletion apply to Desktop media. Clipboard text, transfer
  paths/identities, private coordinates, and content are absent from public
  catalog and metadata audit. A real Provider media/input bridge, development
  templates, production composition, unified Web, capability advertisement,
  and release evidence remain absent.

  Slice 12 implementation `490c2db96d6ba7a851d7846bc9e5f818dae2be77`
  adds the immutable development template catalog, validated revision-manifest
  persistence, exact Guest generation/capability/health authority, bounded
  content-addressed workspace materialization, and private two-phase
  rollback/restart recovery. Migration 13 and the complete fresh PostgreSQL
  package pass. Host paths, object paths, credentials, Guest IDs, and runtime
  coordinates remain outside stable health, event, and audit projections. A
  real Provider media/input bridge, unified Web, production composition,
  capability advertisement, and release evidence remain absent.

  Slice 13 implementation `84698c371d35edb862ffc81b484a3e31cc8120d9`
  adds the capability-derived authenticated unified Product Web/BFF for
  Workspace, Terminal, Files, Browser, Desktop, and recordings. Exact public
  Desktop slot/session shapes, fresh grants and controller leases,
  same-origin WebRTC, bounded recovery/configuration, explicit clipboard and
  recording consent, digest-checked transfers, keyboard-accessible tabs, and
  strict browser security/nondisclosure pass focused, full repository, and
  real headless-Chrome gates. Desktop advertisement remains off pending the
  real Provider media/input bridge, production startup composition, Slice 14
  composed security/fault cleanup, and Slice 15 independent-process release.

  Slice 14 implementation `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d`
  adds the closed neutral private Desktop media/control protocol, Product
  network source, Provider trusted-peer handler, fresh attach and continuous
  handoff authority, capacity/backpressure bounds, and a real-PostgreSQL
  composed public-WebRTC/private-bridge/recording/security/cleanup gate. Full
  race/vet, tagged store, Contract, and retained Phase 3/4 evidence regressions
  pass. This is same-repository same-process composition evidence with a
  reference media executor.

  Slice 15 implementation `024a768d51965f8949bacf3c97e499fb26a6e648`
  adds the strict independent-process release gate. Run
  `20260919T200125.484855000Z` passes 14 exact scenarios through separate
  Product, Gateway, Provider, Desktop, and Guest OS processes with fresh
  pinned PostgreSQL, the exact signed Desktop runtime, real X11 capture and
  fenced pointer control over public WebRTC/private mTLS, encrypted recording
  replay, actual Guest development materialization, Product/Gateway/Guest
  restart recovery, Provider-dependency fault closure, and exact cleanup. The
  exact gate topology derives Desktop/development capability readiness from
  live dependencies. The strict manifest rejects identity/scenario drift,
  incomplete cleanup, secrets, private coordinates, and host paths. This does
  not compose the production command or establish deployment, HA, hostile
  multi-tenant, independently implemented caller, or production readiness.
  Corrective commit `59de37d5ee22776305dfaab866c25ea6bd5406bc`
  deterministically closes the Provider media session before its private
  WebSocket closure becomes observable. E2E lock
  `d5d6ed1a815b49625a054d9931a8cec2234d8e7e` binds all eight
  parent checks to evidence/CI baseline
  `59de37d5ee22776305dfaab866c25ea6bd5406bc`; full E2E race/shuffle, vet,
  and all eight clean-checkout checks pass; and
- Product v1 Phase 6 production hardening is **5/15 complete** under ADR 0051
  and the fixed Phase 6 plan. The startup audit distinguishes existing
  components and same-repository gates from deployable/operable/production
  authority. Slice 1 adds `sandbox-runtime product serve`, strict
  development-only `product_process` configuration, bounded private
  PostgreSQL and frozen identity files, real Product migrations/store,
  independent liveness/readiness, empty capability advertisement, and
  fail-closed primary-slot authorization. The root `serve` command refuses an
  enabled Product section, so the Product, Provider, and local API roles remain
  separate. This is source/component evidence for a runnable development
  Product process, not a published deployment, standalone/production
  qualification, HA, hostile-multitenant safety, SLO attainment, or production
  readiness. Slice 2 adds production-kernel configuration, TLS 1.3, a closed
  Ed25519 Product access-token key ring with overlap/revocation, distinct
  migration/runtime PostgreSQL roles, exact read-only schema compatibility,
  and a fail-closed recovery monitor. Slice 3 adds the independent
  production-only `provider serve` role with TLS 1.3 mTLS, exact protected
  admission, separate PostgreSQL migration/runtime authority, transactional
  lifecycle/exec/Terminal/artifact/usage/Desktop state, bounded recovery and
  loopback probes, and exact single-profile coding-shell or Desktop
  advertisement. Real PostgreSQL concurrency/fault/restart, process restart,
  coding-shell Docker lifecycle, and signed Desktop broker gates pass locally.
  Product dispatch remains uncomposed, so `product.workspace` is still
  explicitly unavailable. Slice 4 adds separate Gateway/Guest/Browser/Desktop
  roles, restricted executor v2 backends, sealed Browser/Desktop egress
  identity, and a Provider-owned signed Desktop broker mux. Its corrective
  immutable candidate passes the six-role/twelve-scenario gate and strict
  evidence verification. Runtime revision
  `78f5987fda45873e497bce6d336e29dd4a61dc74`, evidence-tool revision
  `e2f4abacf03418c7b18f179c3e7459292d8626df`, manifest digest
  `sha256:d01b3c41a0094657f18b4014b0649a799ea7fcf0e4ccaf07aa82cdd2052cc0d2`,
  and candidate image digest
  `sha256:0592a69e8f85125360eb6805132b3654324ab9a56c0ea019ea3dc7aade103d4e`
  are fixed by the accepted evidence. The Desktop OCI remains a non-release
  local candidate; public Product E2E, publication, deployment and production
  readiness remain open. Slice 5 is complete within its bounded local
  independent-process and real-adapter evidence scope:
  ADR 0054 adds a repository-private canonical purpose/tenant/role/version
  secret binding, an exact adapter over the existing secret provider, a
  bounded invalidation-safe cache and an opaque envelope-key port. The existing
  Product recording port now carries explicit tenant scope; a tenant-bound KMS
  store wraps one random DEK per recording and a strict Vault Transit adapter
  passes a digest-pinned TLS integration with overlap rotation, restart,
  dependency loss and cleanup. Product's no-cache one-shot migration
  command/agent is physically separate from
  the v2 runtime registry for the TLS pair, runtime PostgreSQL DSN and identity
  key ring. A real Vault KV/TLS gate and real Product/PostgreSQL process gate
  prove pre-migration bind denial, cross-purpose denial, exact bootstrap
  cleanup, agent restart/loss and readiness closure/recovery. All six runtime
  roles use separate material agents; six renewable runtime and two one-shot
  migration credentials, controller restart, Vault/agent loss, revocation,
  expiry, dual-control break-glass, plaintext exclusion and exact cleanup pass
  the immutable gate. Runtime revision
  `c189330c5ed0aa52c60b6b85c5cd9c6b59fbef10`, evidence-tool revision
  `39fd1025f6fa838325aced711d8a024a9ce5d1b6` and manifest digest
  `sha256:e6a6fdcc299c721e1fa2c48009d98a6ca4c52d59318c507af8b68fd8596e840c`
  are retained. The local gate records `distinct_os_uid_established=false`;
  Product recording-content composition, HSM, deployment and production
  readiness remain false. Slice 6 is underway under ADR 0055 with real Vault
  PKI, live TLS rotation/revocation, role-isolated egress enforcement and exact
  container least privilege as its frozen order. Current source-level work
  closed the historical pre-v2 desired inventory of 78 deployments, 30 isolated
  external paths, 35 external edge IDs, 11 actual material agents, 12
  credential issuer sockets, 9 PostgreSQL-purpose signers and one ordered
  nine-role shared-service HBA. Four unconsumed V2 Browser/Desktop material
  deployments were removed without renumbering surviving identities or
  networks. The earlier 82-deployment source-bound candidate is historical
  component evidence and must be rebuilt before use with this topology.
  Real same-run Vault ACL/issuer installation, two controller PID1 processes,
  distinct Product/Guest TLS and material agents, and a source-bound pinned
  PostgreSQL PID1 have now passed a composed component gate. PostgreSQL used
  its Vault-issued server leaf, exact final HBA and nine isolated bridges;
  after mounted-leaf verification and shutdown, an independent one-shot v2
  operator confirmed three certificate serials, two token accessors, complete
  CRL and self-revocation, followed by zero run-labeled Docker resources.
  The separate no-secret provisioner probe and strict PEM/mount-order tests
  also pass. A further mutable-tree component run started PostgreSQL before
  Vault root revocation, used client-side encrypted native role creation to
  establish separate non-elevated Product migration/runtime SCRAM logins,
  precreated only the operator-owned database/schema, and stored their real
  DSNs in separate create-only KVv2 version-1 purpose bindings. Scoped
  readback, cross-purpose/cross-owner denial, token revocation, controller
  quiesce, v2 terminal PKI cleanup and exact Docker cleanup passed. A second
  same-run component test proved distinct-owner runtime DSN resolution. The
  clean-source R3 run `50f6810acddb8bffd5ba4167b0e424e2` additionally
  completed independent Product `migrate v2` PID1 with exit 0 and exact
  same-PostgreSQL migration-ledger, table-owner and grant readback. The known
  certificate-controller terminal failure remained recorded; the accepted
  independent one-shot operator confirmed revocation, complete CRL and
  self-revocation, followed by exact resource cleanup. Earlier failures remain
  historical. A later clean E `f49ee748f5e8790cd58c62d04bc5304b1a363b49`
  with clean R/F `c83fcbc125f3d3f8f67ceaad403c6a7b8e7de635` passed one
  independently reviewed Product/PostgreSQL/Guest runtime component: a signed
  hello/welcome installed an upgraded connection, a same-PostgreSQL durable
  business-binding revoke drained it, and a fresh signed attempt was rejected
  as revoked. Run `20efb6c95a0fa39cb0441f580a86888f` retains four private
  source/image/process/mutation-bound zero-drop receipt files and exact
  zero-resource cleanup. The two earlier receipt attempts remain failed and
  incomplete; the certificate controller's sticky local terminal failure
  remains despite independent operator cleanup. This is not the complete
  Guest security edge: PostgreSQL loss/recovery, peer TLS revocation, CRL-source
  loss and replacement restart/reconnect remain unproved. Nine live SQL callers,
  the revised complete Profile-v2 inventory and its full 16-scenario Slice 6
  gate, formal signed evidence and deployment also remain unproved. The
  historical 78-deployment baseline and provisional 82-static-principal
  fixture do not establish the revised live topology. Phase 6 stays 5/15.

  The 2026-10-08 new-host uncommitted component checkpoint adds explicit
  typed v2 CRL Controller policy/issuer preflight, agent/guard constructors
  and single-owner PostgreSQL role decoding. Its follow-up wires explicit
  Controller config v5 and TLS-agent config v5/v6 into the actual commands,
  with typed Profile/source/policy/process checks before private key FDs.
  Public Profile-v2 validation and Provider v3 admission remain held.
  The 2026-10-09 continuation adds held Control Coding status and Scanner
  command entry points, scoped consuming-role TLS/CRL factories, a typed
  status Observer and dedicated Scanner client. The Control command only
  opens an existing receipt ledger; that original status-only config remains
  read-only.
  Scanner owns its fixed ClamD child and private 256 MiB runtime tmpfs.
  The next 2026-10-09 checkpoint explicitly selects a separate held Coding
  v3 dependency path: typed v2 PG/materials, PG lifecycle repository, status
  Coordinator, passive JSON checker and private Scanner. No Application or
  automatic lease worker is started. The subsequent held Control checkpoint
  adds a concrete Coding create/Completed-only cleanup executor and explicit
  `sandbox-runtime.provider-docker-control-coding-config.v2` command input.
  It preserves Unknown-before-write, single-use physical requests, same-process
  completion, original daemon binding and both public admission holds. It
  does not initialize a ledger or retire historical Unknowns. The following
  Provider dispatch checkpoint adds the typed original-authority mutation
  client and candidate command composition. Create uses the PG atomic first
  permit; cleanup sends only the original create and fresh cleanup returned
  by that same explicitly successful PG admission. Historical reads, lost
  replies and uncertain commits do not authorize another send. ACKs never
  publish Ready or release a slot; separate authenticated observations and
  typed PG commits remain required. No Application/automatic worker starts.
  The following Ready checkpoint adds a separate authenticated Completed
  readback and one PG transaction for allocation-bound completion history,
  Active and Ready. Exact repeats do not write another revision. Late or
  cancelled Running becomes OutcomeUnknown; existing Unknown is retained.
  A generic-writer guard protects the full sandbox projection, including
  after release and slot reuse, while allowing exact terminate/lease
  admission and the existing direct Creating-to-Cleaning path. The command
  composes this readback without an Application or automatic worker.
  This continuation connects typed cleanup Begin/Finish to lifecycle
  termination, including already-terminal reads before any generic shortcut.
  One read-only PG SELECT validates marker, allocation/retirement and the
  operation/sandbox tuple from the same snapshot. Accepted may attempt one
  fresh admission/send. Only that send's typed successful result may record
  a durable ACK in the existing retirement. Recovery preserves unacknowledged
  Running as Unknown before observing; Released cannot upgrade it. ACK plus
  independent exact Released, an unexpired operation and no cancellation are
  required for Running to succeed. Uncertain replies cannot grant another
  send, and late ACK cannot upgrade Unknown or a released allocation.
  Already-released Succeeded/Unknown reads leave the new slot occupant alone.
  Late/cancelled Running finishes as Unknown while observed termination and
  slot release commit together. New-host full race/vet, both Contract locks,
  read-only Docker observation and the real PG transactional component now
  pass; the PG run uses only a newly recovered locked image and synthetic
  Control, not physical execution or complete supply/release acceptance.
  The following lease continuation commits new Coding-v3 lease admission,
  Succeeded, idempotency and both events in one PG transaction. It rechecks
  deadline and the old lease under the row lock; replay adds no revision and
  never invokes Control. The locked Contract permits a 202 response carrying
  an already-completed operation. Typed historical readback runs before the
  generic terminal shortcut. Only an exact current older Accepted admission
  can be completed; superseded or unsupported old states stay unchanged.
  This does not renew runtime mutation authority or start an expiry worker.
  The next runtime-preflight checkpoint adds one read-only PG snapshot of
  marker, allocation/completion and lifecycle/lease state, with an explicit
  exec support checker in the held command. A higher prospective fence cannot
  advance PG state, and accepted termination immediately closes eligibility.
  This snapshot is not physical authority: exec still needs atomic current
  admission and its own closed Control protocol, receipts and recovery.
  The following no-permit exec-intent checkpoint adds a separate bounded PG
  ledger with same-row current-state checks and complete-request replay. Explicit
  initialization requires an unused atomic namespace; no startup upgrades it.
  Its history receipt cannot execute work or advance a fence. Physical exec still
  needs a new current-authority CAS, distinct Control permit/Unknown receipts,
  cleanup quiescence and observation/cancellation/result handling. This run's
  full race invocation failed on phase6security's unchanged default timeout;
  component/PG checks, review, vet, locks and compilation passed. The audit
  retains that failure separately from the passing same-seed standalone
  diagnostic; a passing full invocation for this checkpoint is not claimed.
  The 2026-10-10 [exec isolation checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-exec-namespace-isolation)
  closes the generic-exec bypass and reverse lifecycle operation-ID collision:
  enabled intent mode rejects generic exec reads/writes, and the same PG row
  lock protects both admission orders and typed read-only replay callbacks.
  It adds no physical authority or fence reservation. See the dated audit for
  this combination's validation, independently reviewed scope and remaining work.
  The following [descriptor and validation-cost repair](audits/product-phase-6-slice-6-startup.md#2026-10-10-controller-descriptor-and-validation-cost-repair)
  fixes the Controller test's duplicated FD ownership and removes redundant
  whole-Profile validation within a single unchanged-input call. Public
  entry points still fully revalidate each input. Independent review, the full
  default race run, vet, both Contract locks and Linux/arm64 compilation pass
  on the combined new-host source. The security package took 580.323 seconds,
  so default-timeout headroom remains limited; older failed runs stay recorded.
  This restores a passing source checkpoint, not physical exec authority or
  formal Slice 6 acceptance.
  The subsequent [PG exec fence reservation](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-pg-exec-fence-reservation)
  adds a reviewed, explicitly initialized unused-state-only ledger. Same-row
  admission requires the intent's complete request and current runtime tuple,
  then advances only the scope/lease fence pair. Two-pool lease/terminate races,
  corruption rejection and historical reads after slot reuse pass the real-PG
  component gate. These receipts grant no execution authority; a future
  physical dispatch still needs a fresh CAS. Distinct Control Unknown receipts,
  execution/cleanup quiescence and observe/cancel/result recovery remain the
  next complete source boundary. Full race/shuffle, vet, both locks and
  Linux/arm64 compilation pass on the frozen source. The audit separately
  preserves the first full invocation's unexplained test-process fallback
  timeout and the successful diagnostic/full recheck; no root-cause fix is
  claimed.
  The following [exec containment probe](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-exec-containment-mechanism-probe)
  reproduces detached descendants writing after the legacy direct-child TERM
  and wrapper exit. Separate PID 1 containers stop writing in the bounded
  observed window after SIGKILL/natural exit, using a locked PG process fixture,
  not a Coding candidate. No production architecture or exec authority is
  adopted by this experiment. Distinct Unknown receipts remain pending the
  reviewed containment/dispatch/cleanup design; the old canceller is unchanged.
  The next [resource and shared-scratch checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-exec-resource-and-shared-scratch-checkpoint)
  adds a prospective resident/command partition within one slot ceiling and a
  passing real Docker 32 MiB shared-tmpfs component test. The [private protocol
  plan](plan/product-v1-phase-6-coding-exec-protocol.md) preserves shared `/tmp`,
  requires a new resource/Profile mode, and specifies PG acceptance/occupancy
  plus Control Unknown, late-request closure and allocation cleanup ordering.
  This is still no physical dispatch: production partition/storage caps,
  inode/metadata bounds, locked Coding inputs and restart/cancel/release gates
  must be frozen and validated before adoption. Legacy plans/receipts and both
  public holds remain unchanged.
  The subsequent [execution-budget checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-execution-template-and-storage-budget-candidate)
  freezes an independently reviewed new template **candidate**, with separate
  resident/command/data/metadata allowances, 4096 scratch inodes and a 512 MiB
  Coding child storage budget inside the shared 1 GiB Control volume. The
  updated real scratch probe proves inode exhaustion/reuse on the local daemon.
  PG/Control durable quota consumers, new receipt namespace, other-scope
  allocation, actual Coding workload sizing and restart/release gates remain
  open. Arithmetic reservation is not dispatch permission.
  The next [private storage checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-private-storage-namespace)
  implements a new exclusive file namespace, class byte/object limits, exact
  restart inventory, state replacement peak and independent closure space.
  The held execution template is now explicitly v2 and includes its layout;
  the other 512 MiB remains unallocated with no write entry point. Darwin and
  Linux file-component checks and independent review do not prove a physical
  volume admission, new execution receipt, or PG-to-Control dispatch. A partial
  state/manifest commit stops rather than reconstructing authority. Complete
  new Profile/receipt/atomic claim composition and real workload gates remain
  the next boundary; both public holds remain closed.
  The [common Control state checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-common-control-execution-state)
  now consumes that file store with a held, package-private create/exec/retirement
  state machine. Durable Unknown, exact claim closure, monotonic fences and
  retirement share one state/owner; callbacks cannot clear occupancy. Typed
  four-volume completion uses current-state comparison. The subsequent
  [four-volume observer checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-four-volume-completion-observer)
  supplies a separate bounded read-only SDK collector with retained physical
  projections rechecked on receipt-v2 reopen. Synthetic positive observations,
  real Docker empty-scope rejection and Linux file-component checks do not
  prove a positive Coding workload or kernel scratch gate. The pinned arm64
  Coding image has been downloaded but not executed. The next
  [supply revalidation](audits/product-phase-6-slice-6-startup.md#2026-10-10-coding-image-supply-revalidation)
  verifies its original archive and signed provenance, but the fresh arm64 scan
  fails with 13 HIGH occurrences. The positive Coding gate remains held. A
  [separate candidate proposal](plan/product-v1-phase-6-coding-image-candidate.md)
  now has the user's candidate-only Go1.26.9 approval. Its separate clean-source
  Alpine3.23.6 candidates reproduce byte-for-byte on both platforms and scan
  with zero HIGH/CRITICAL, retaining one zlib MEDIUM each. Native arm64 diagnostic
  smoke and exact container cleanup pass, without formal four-volume admission.
  Development tools now use mise, with ordinary Go1.26.8 retained; image builds
  use Docker. Historical locks and production templates remain unchanged.
  See the [candidate audit](audits/product-phase-6-slice-6-startup.md#2026-10-10-repaired-coding-candidate-and-managed-tools).
  The subsequent [held binding component](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-candidate-template-and-receipt-binding)
  connects source-owned candidate records to a separate execution-template v3,
  internal receipt v3 and read-only observer; old v1/v2 state is not migrated.
  A historical scan hash is not current supply admission. The subsequent
  [candidate Profile/kernel-root component](audits/product-phase-6-slice-6-startup.md#2026-10-10-held-coding-profile-mode-and-kernel-root)
  adds an explicit v3 alternative to the full Profile field chain, derived
  storage binding and revised declared resource accounting. Mixed old/new modes
  reject. The Store checks its actual Linux root fd and live pathname mount ID;
  an ordinary unbounded Docker local volume is rejected without a marker.
  This is not physical admission: exact Docker volume/consumer identity,
  external exclusivity, stable hard quota, a final live inventory and positive
  four-volume scenarios remain required, followed by atomic PG claim and
  asynchronous mTLS dispatch. Both public holds remain closed.
  Remaining daemon-free runtime ports, source-bound images and real same-run gates
  are still open. These command paths are not live admission. See the dated
  [startup audit](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-coding-runtime-preflight)
  for new-host validation, limitations and preserved failures. See also the
  [exec intent checkpoint](audits/product-phase-6-slice-6-startup.md#2026-10-09-held-coding-exec-intent-ledger).

The qualification applies only to Provider revision
`170459266af5f4fad359ca8c63f2ae19741055c5`, external-caller revision
`b3ebcc783e5db20395e29b029e0eb55f7819b49b`, and the recorded Contract,
profile, artifacts, topology, and scenarios. Aggregate conformance,
multi-controller reliability, hostile multi-tenant isolation, HA, deployment,
and production readiness remain separate non-claims.

The Product Phase 1 result adds no implemented Product API, database migration,
public Gateway, Guest Agent, capability advertisement, deployment, or SLO
attainment claim. See
[`plan/product-v1-phase-1.md`](plan/product-v1-phase-1.md) for its exact output
and [`plan/product-v1-phase-2-provider-lifecycle.md`](plan/product-v1-phase-2-provider-lifecycle.md)
for the fixed nine-step Provider lifecycle closure plan. ADR 0048 and the
Step 1 audit and completion record include termination, reversible desired
state, lease renewal/expiry, resumable events, and terminal-session close; they
exclude resize and snapshot/restore from Phase 2. See
[`audits/phase-2-provider-lifecycle-completion.md`](audits/phase-2-provider-lifecycle-completion.md)
for the selected authority, release evidence, and exact non-claims.
The Phase 3 startup inventory, fixed slice order, and completion evidence are
recorded in
[`audits/phase-3-product-surface-startup.md`](audits/phase-3-product-surface-startup.md)
[`plan/product-v1-phase-3-product-kernel-terminal-files-web.md`](plan/product-v1-phase-3-product-kernel-terminal-files-web.md),
with the accepted standalone run in
[`audits/product-phase-3-standalone-completion.md`](audits/product-phase-3-standalone-completion.md).
Product Phase 4 startup scope and slice order are recorded in
[`audits/phase-4-product-browser-startup.md`](audits/phase-4-product-browser-startup.md)
and [`plan/product-v1-phase-4-browser.md`](plan/product-v1-phase-4-browser.md),
with the bounded release result in
[`audits/product-phase-4-browser-completion.md`](audits/product-phase-4-browser-completion.md).
Product Phase 5 startup findings, boundary decision, and fixed slice order are
recorded in
[`audits/product-phase-5-desktop-startup.md`](audits/product-phase-5-desktop-startup.md),
[`audits/product-phase-5-desktop-slice-2.md`](audits/product-phase-5-desktop-slice-2.md),
[`audits/product-phase-5-desktop-slice-3.md`](audits/product-phase-5-desktop-slice-3.md),
[`audits/product-phase-5-desktop-slice-4-candidate.md`](audits/product-phase-5-desktop-slice-4-candidate.md),
[`audits/product-phase-5-desktop-slice-4-publication.md`](audits/product-phase-5-desktop-slice-4-publication.md),
[`audits/product-phase-5-desktop-slice-5.md`](audits/product-phase-5-desktop-slice-5.md),
[`audits/product-phase-5-desktop-slice-6.md`](audits/product-phase-5-desktop-slice-6.md),
[`audits/product-phase-5-desktop-slice-7.md`](audits/product-phase-5-desktop-slice-7.md),
[`audits/product-phase-5-desktop-slice-8.md`](audits/product-phase-5-desktop-slice-8.md),
[`audits/product-phase-5-desktop-slice-9.md`](audits/product-phase-5-desktop-slice-9.md),
[`audits/product-phase-5-desktop-slice-10.md`](audits/product-phase-5-desktop-slice-10.md),
[`audits/product-phase-5-desktop-slice-11.md`](audits/product-phase-5-desktop-slice-11.md),
[`audits/product-phase-5-desktop-slice-12.md`](audits/product-phase-5-desktop-slice-12.md),
[`audits/product-phase-5-desktop-completion.md`](audits/product-phase-5-desktop-completion.md),
[`adr/0050-product-desktop-phase-5-boundary.md`](adr/0050-product-desktop-phase-5-boundary.md),
and
[`plan/product-v1-phase-5-desktop-development-unified-product.md`](plan/product-v1-phase-5-desktop-development-unified-product.md).
Product Phase 6 authority, ordering, startup gaps, and the first four slices are in
[`adr/0051-product-phase-6-production-hardening-order.md`](adr/0051-product-phase-6-production-hardening-order.md),
[`plan/product-v1-phase-6-production-hardening.md`](plan/product-v1-phase-6-production-hardening.md),
[`audits/product-phase-6-production-startup.md`](audits/product-phase-6-production-startup.md),
[`audits/product-phase-6-slice-1.md`](audits/product-phase-6-slice-1.md),
[`audits/product-phase-6-slice-2.md`](audits/product-phase-6-slice-2.md),
[`audits/product-phase-6-slice-3.md`](audits/product-phase-6-slice-3.md),
[`adr/0052-phase-6-executor-role-boundary.md`](adr/0052-phase-6-executor-role-boundary.md),
[`audits/product-phase-6-slice-4.md`](audits/product-phase-6-slice-4.md), and the
[`strict Slice 4 evidence manifest`](audits/product-phase-6-slice-4-evidence.json).
ADR 0053 defines default finalization versus explicit historical retained
verification, with Slice 4's immutable
[`closure record`](audits/product-phase-6-slice-4-closure.json).

See [`STATUS.md`](STATUS.md) for the complete evidence ledger and
[`qualification/external-caller-coding-shell-v1.md`](qualification/external-caller-coding-shell-v1.md)
for the exact qualification boundary.

## Start Here

Read this document after `AGENTS.md`, then verify the checkout before relying on
the snapshot:

```bash
git status --short --branch
git branch -vv
git rev-parse HEAD main origin/main
git log --oneline --decorate -8
```

Preserve uncommitted work. Do not reset, switch away from a dirty checkout, or
assume that a recorded evidence baseline is the current `HEAD`.

Use these sources in authority order:

1. The repository-owned MIT Provider Contract under `contract/`, including its
   Provider Calling Standard, OpenAPI, JSON Schemas, semantic rules, fixtures,
   Conformance Suite, and
   `compatibility/sandbox-runtime/contract.lock.json`, defines authorized wire
   behavior and caller obligations.
2. The independent Product Contract under `product-contract/` defines the
   target client-to-Product control protocol. It is Phase 1 design authority,
   not implementation or readiness evidence.
3. [`architecture.md`](architecture.md) and accepted
   [ADRs](adr/) define ownership, boundaries, delivery order, and release
   gates.
4. [`development.md`](development.md) and `AGENTS.md` define engineering and
   validation rules.
5. [Phase plans](plan/README.md) refine implementation slices without relaxing
   architecture gates.
6. [`STATUS.md`](STATUS.md) is the detailed evidence ledger. Code, Git state,
   and reproducible test or CI results must still support every status claim.

Start external integrations with the normative
[`Sandbox Provider Calling Standard`](../contract/specification/provider-calling-standard-v1.md).
The [`Provider Integration Guide`](platform-integration-profile.md) is a
non-normative implementation summary; the Contract resources and lock remain
authoritative.

When sources disagree, do not silently blend them. Apply the higher-authority
source, verify the implementation, and update the stale narrative document.

## System in One Page

`sandbox-runtime` is a backend-independent sandbox Provider and local runtime
control plane. The first intended compatibility profile is coding and remote
shell. Browser, desktop, snapshots, GPU, and stronger isolation remain optional
until their own Contract and evidence gates pass.

Three API surfaces must remain separate:

| Surface | Purpose | Ownership boundary |
| --- | --- | --- |
| Local `/instances` API | Local instance management over fake or Docker drivers | Internal implementation; its DTOs and state are not Provider wire models |
| Provider API v1 | mTLS/JWS-protected asynchronous Provider protocol | Repository Contract controls routes, documents, semantics, and projection |
| Product API v1alpha1 | End-user Workspace control plane | Independent Product Contract; Phase 6 Slices 1-2 add development and production-kernel listeners with real PostgreSQL, TLS 1.3 signed identity, separated database authority, empty/unavailable capability projection, and fail-closed runtime mutation; Slice 3 adds a separate Provider process, while Slice 4 adds bounded independent data-plane roles without yet composing public Product dispatch |

The calling service owns its business correlation records, desired business
state, tenant/user authorization, ProviderRevision selection, Artifact
publication, billing/accounting, aggregate operation ledger, and public Gateway
policy. It adapts to this repository's Contract; the Provider does not carry a
consumer-specific adapter.
The target Product is the calling service defined by ADRs 0042-0047. It owns
Workspace aggregates, user/Agent authorization, Product operations, outbox,
reconciliation, sessions, public Gateway policy, and catalogs. This repository
owns provider-local execution, durable Provider operations,
runtime/session resources, and bounded evidence. Provider storage references
and backend endpoints are never public artifact URLs or client endpoints.

Protected admission uses one caller trust domain per listener. The issuer is an
explicit exact value with no default or fallback; the Provider-instance
audience and Provider revision are local startup anchors rather than facts
accepted from the bearer or Admission Context. The listener freezes 1..32
issuer-scoped verification keys and its admitted URI SAN identities. One
listener does not currently support multiple issuers or consumers.

Dependencies point inward:

```text
Provider HTTP/mTLS/JWS transport
              |
              v
application policy and coordinators
              |
              v
repository and capability ports
              |
              v
runtime, persistence, session, and evidence adapters
```

Provider operations are asynchronous and preserve idempotency, attempts,
fencing, deadlines, cancellation, and unknown-outcome reconciliation. A
compatible coding/shell runtime must eventually expose stable guest paths
`/inputs`, `/workspace`, `/outputs`, and `/tmp`. Terminal clients receive only
an expiring opaque handoff; a Runtime Gateway resolves and proxies the internal
endpoint after its own authorization.

The default security posture is deny and fail closed. Do not expose backend
IDs, host paths, raw endpoints, daemon diagnostics, credentials, or secrets.
The existing Docker defaults and mTLS admission are useful component controls,
but they are not evidence of hostile multi-tenant isolation or production
readiness.

## Development Contract

- Keep transport, application policy, repositories, and runtime drivers in
  separate packages. Provider DTOs must not reuse local `instance` or backend
  engine structs.
- Preserve `context.Context` cancellation and deadlines for external work.
- Reject unknown, malformed, and oversized input before mutation when the
  Contract requires it. Unsafe production configuration must fail closed.
- Use narrow optional capability interfaces. Advertise a capability only when
  the complete configured dependency set and its named gate pass.
- Scope each change to one delivery slice. Ownership, public protocol,
  reliability, or security-boundary changes require an ADR and coordinated
  Contract review.
- Preserve unrelated worktree changes. Never turn local callbacks, fakes, or
  same-repository tests into external compatibility claims.

For Go changes, format with `gofmt` and run:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

For driver or lifecycle changes, also run the tagged Docker integration test in
an available Docker environment. For Contract metadata, DTO, Provider API, or
conformance changes, also run:

```bash
go run ./cmd/verify-contract -source-root .
runner_dir="$(mktemp -d)"
go build -buildvcs=true -o "$runner_dir/run-conformance" ./cmd/run-conformance
"$runner_dir/run-conformance" -source-root . -race -shuffle
```

The local Suite runner requires a clean VCS-built binary, records its revision
and Go version from build information, and executes a bounded read-only archive
of that revision. Every case declares an exact mapped-test count and requires
all matching tests to appear as distinct, started, non-skipped passes in `go
test -json`. The Runner rejects an explicit `GOROOT`, resolves Git once to a
single absolute executable path reused for verification and archive creation,
and records that the host OS, filesystem, initial Git selection, and Go and Git
executables remain trusted local inputs. `go run ./cmd/run-conformance` lacks
the required VCS settings under Go 1.26.5 and correctly fails. The separate
remote discovery prerequisites and command are documented in
[`compatibility/sandbox-runtime/README.md`](../compatibility/sandbox-runtime/README.md).

Record an unavailable environment separately from a failed test. Keep these
evidence tiers distinct: component, Contract projection, CI, Provider
admission, external caller E2E, aggregate conformance, multi-controller,
multi-tenant, deployment, and production readiness.

## Current Snapshot

The selected Product Phase 2 implementation snapshot is
`98995384c60a924f25ca58d3b7e561207bfa5be8`; lock-selection revision
`3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1` binds its exact Provider Contract
tree and E2E metadata. No remote CI result is assigned to these local release
revisions.

The latest remotely verified documentation baseline remains
`27081dfde4dfc726ba4df06d1f3b50012a04d2f2`. Core CI run `35204434771`
passed all six jobs, including the current Contract and clean VCS-built local
Suite, full race tests, vet, Docker integration, Browser provenance, and the
Ubuntu/macOS qualification-supervisor matrix. The detailed component ledger
below retains older per-gate commits and run IDs because those identify exact
historical evidence rather than the newest documentation commit.

The ADR 0038 calling-standard slice remains implemented. The current Contract
authority is revision `720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`, and a content-derived 71-case
local Suite. Product Phase 5 Slice 1 maps every case to executable repository
tests and keeps Desktop advertisement disabled. The historical Phase 2
60-case Runner, remote Runner, hosted CI, Product Phase 3/4, and external-caller
results retain their recorded identities and are not relabeled as current
runs. Product Phase 5 Slice 2 separately adds Product Desktop intent at
implementation `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`. Slice 3 adds
Provider-local Desktop authority and optional protected handlers at
`f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5`; neither slice changes the
Provider Contract identity or any historical result, and Slice 3 is not
production startup composition or capability advertisement.
The independently implemented caller result is instead the separate bounded
P2.7 qualification recorded above. Rotation remains operator-driven, and
protected/mutating remote conformance, aggregate conformance, multi-controller,
hostile multi-tenant safety, HA, deployment, and production readiness remain
outside the completed first-version claim.

This snapshot was audited on 2026-09-06 against browser Contract authority
`5096e71fb84fbec22aa3487a0e55a1b49602ab8b`, Provider projection baseline
`24b2e36485c334634e561009850d1905ec3115d5`, browser session implementation
`9a5d225f793f37ccafdac31c276ccbcb1bc862ad`, sandbox/provenance implementation
`6e02f1c22f489802b0b2c9f06f4a807d2e7c36e5`, Browser Docker adapter
`cd33ba35c59bba62c48d13c0dcd08aeef5d9a434`, Browser provenance verifier
`939055475f73b0023b3946172a2c40750a99c7ea`, Browser restricted-egress and
create-policy implementation `7e60340`, protected Browser transport
implementation `b8423f5`, caller-owned Browser Gateway implementation
`5aae2810c4957ec7abad7de0e67f9507d9543c81`, default-disabled Browser command
composition `66183b1f49b22c211e43c841d15383b745e89967`, Browser DNS compatibility
implementation `f760369dd4b71f507b15a2aecf988e98ca74854b`, Browser Gateway local
capacity implementation `7b062e6511f73b916dd18977041d83732e590088`, Browser
pre-upgrade edge implementation `44ea2eecc75752870d4e8580a75be26578dcd63a`,
Browser listener/TLS/HTTP implementation
`b8f89413cb34110793fa552ba1620f1529f6f416`,
Browser authenticated-capacity implementation
`997fb0db9d3517cf1c3e153217b1ac7305b4ebfd`, its co-located E2E lock
`49d1c20`, and hosted harness/evidence baseline
`6b01b75f0e1f6ca1c60f033f8d5bab3898720a3b`, plus Redis-compatible shared
capacity implementation `94345407c149eb095f27ac1c51f60fa38a16a4af`,
shared-capacity Provider baseline
`2ed5e689f68627c2d7c8e96cf903fc001ea4a546`, and local evidence
harness/Gateway source `ddbb2c4771a356bc3ab66295c93bef3b749e2c09`, plus hosted
shared-capacity harness/Gateway source
`de297e7d951881f8ed3792b4c3dd0553be87284c` and run `33949577876`, plus
durable exact-grant revocation component implementation
`c0a55d1e0a862f9e5a592abd27b1e25be3c85b3e` and earlier regression E2E
lock/harness baseline `59e08d542b05ad1a047f439f4ea72e82c8c37404`, plus durable-revocation
harness/Gateway source `e952ef9dabf4e9e6f2a984ce0c7944cb2bc569c7`, local run
`20260905T095109.569973000Z`, and hosted run `33959122456`, plus downstream CDP
fencing component and real-backend adapter integration implementation
`b4d41c9a32b4ccf39edaba3fb8bf5ad239c1f945`, downstream caller bootstrap
implementation `58488d70c0a43d68747ca6e14f81c56f1e23237a`, caller provisioning/process
implementation `8a1049bfa1d68bdd88c9df3ebd02c2c9ac0434b5`, local downstream-fencing
harness/run `550c7855704f22809e989ede0f67240033f320ba`/
`20260906T050213.016063000Z`, and hosted downstream-fencing harness/run
`2cadc534e54c6eacd37497887820a157a89585f5`/`34013982796`, plus fixed witnessed
v2 harness `059357cdd1f6f4ecd78ccbbaf9923add0fcd2230`, local run
`20260906T100233.295973000Z`, and hosted run `34026680591`, plus PostgreSQL
controlled-restore implementation `ffa40d643605e51d4ea1baebab1bd3f8bd710b5f`,
PR #47 merge `a0cddf40d07f9ad81b02d3eb028f141aeb424228`, and post-merge run
`34038556283`. The later main run `34069851741` at
`838d3bb2dea52c10fdc1ddf3136641709fedcb20` is the current canonical ADR 0036
run and passes the same 18/18 profile. Its independently inspected artifact is
`browser-postgres-controlled-restore-e2e-evidence-34069851741`, ID
`10000177842`, digest
`sha256:96817b74f3faabb0226d7dee1f2ac8128901865a3834f9bcadcaae6459b76032`.
Merge commit `a0cddf4` also passes repository CI `34038556281`,
Reference `34038556295`, Candidate `34038556284`, Browser `34038556297`,
shared-capacity `34038556314`, durable-revocation `34038556293`,
downstream-fencing v1 `34038556291`, downstream-fencing v2 `34038556299`, and
PostgreSQL witness `34038556301`. These remain distinct evidence tracks.
The Contract slice authorizes an atomic browser-only capability shape,
create/session/handoff schemas, protected admission bindings, opaque reference
security, operation/usage projection, and 10 new Suite cases. The browser image
component is implemented under
`profiles/browser/image/`. The Provider-local browser
session/application/reference/usage component is implemented under
`provider/browser/`. ADR 0020 and `provider/browser/driver/docker` add a
fail-closed Docker adapter for that runtime port. ADR 0023 and
`b8423f5` add protected Browser open/handoff routing, admission correlation,
bounded error projection, and opaque response projection through a narrow
application port. ADR 0024 and `5aae281` add a separate caller-owned Browser
Gateway component with exclusive Browser identity/reference binding, explicit
authorization/revocation/audit/WebSocket-admission dependencies, bounded
reconnect, and RFC 6455 CDP framing. ADR 0025 and `66183b1` add an explicit,
default-disabled Browser Provider graph. ADR 0026 and the co-located harness add
a separate Browser-only reference stack and black-box caller. ADR 0027 and
`7b062e6` add non-blocking process-local total/per-session connection capacity
before revocation and Provider resolution. ADR 0028 and `44ea2ee` add
process-local global connection/fixed-window request control before Browser
WebSocket admission and upgrade. ADR 0029 and `b8f8941` add a separate bounded
accepted-connection listener, frozen server-auth certificate, TLS
1.3/HTTP/1.1-only policy, header/time limits, and context-aware lifecycle for
the reference Gateway. ADR 0030 and `997fb0d` add an authenticated-capacity
port after exact grant binding, typed loss/unavailability events, bounded
release, stable revocation/expiry/capacity termination priority, and a
process-local memory reference with atomic global, tenant, and session
accounting. Browser composition requires the port. ADR 0031 and `9434540` add
a Redis-compatible implementation with one bounded atomic capacity record,
server-time leases, renewal, TTL reclamation, and stale-owner fencing. The
production command still exposes no public Browser Gateway route and does not
advertise Browser; only the reference stack advertises the exact locked Browser
profile.

The Contract verifier and root race/shuffle and vet gates pass against the
current projection. E2E race/shuffle passes except for its intentional clean
parent-checkout test, and E2E vet and all other lock tests pass. Clean Docker
reference run `20260907T044611.598221000Z` at harness
`b8d4829` and Provider baseline `af8a505` passed 15 initial and 5
process-reconstruction/resume coding/shell scenarios over real mTLS/JWS HTTPS,
WebSocket, separate caller/reference-stack processes, and Docker. Its manifest
SHA-256 is `60bda2dae83053db447417cea5c5e38d4798e1e90b91fbb5cfc75d2991c6993e`
and it pins locally built linux/amd64 runtime digest
`sha256:60baefac927a0a77743aeca268b271b62b07079f31521f98fd3a4cb33474a999`.
This is same-repository reference evidence; it does not execute the then-current
50-case
Suite or qualify an independently implemented caller. An earlier clean
reference run `20260904T081521.464863000Z` passed 15 initial and 5
process-reconstruction/resume coding/shell scenarios over real mTLS/JWS HTTPS,
WebSocket, separate caller/reference-stack processes, and Docker. Its manifest
pins Provider `44ea2ee`, harness `249cdd4`, the Contract, and linux/amd64 runtime
image digest
`sha256:bcd5dbff8b2d108ee7dab464a85ee7d39ef74a8616a6af73a94ebb10ff8eaf75`.
This is reference coding/shell evidence only; it does not exercise browser.
Hosted Reference E2E run `33854020874` passed the same 15 initial and 5
reconstruction/resume coding/shell scenarios against harness/Provider lock
`e7e7f03`/`44ea2ee`. Its artifact
`reference-e2e-evidence-33854020874` has digest
`sha256:220650f1b61b0297ec445ded03bf3a15870514a9482c9e55012ddfba8ae0da2d`.
This remains reference coding/shell evidence only and contains no browser
scenario.

The explicitly named `agent-platform-candidate` mode passed local run
`20260904T081706.648122000Z` against harness/Provider lock
`249cdd4`/`44ea2ee`: 15 initial and 5 resume coding/shell scenarios over
separate `platform-caller` and `reference-stack` processes with candidate
shadow/selection/rollback/drain policy and state reconstruction. Hosted
workflow run `33854020947` passed the same scenario set against
harness/Provider lock `e7e7f03`/`44ea2ee`. Its artifact
`platform-candidate-e2e-evidence-33854020947` has digest
`sha256:48cbe44c433e5b3a858a2691fe1f736469b2e8d71228541f2bdfcc4aab1c15b1`.
Local and hosted candidate results do not represent browser evidence, real
Veronica, aggregate conformance, hostile multi-tenant security, deployment, or
production readiness.

Hosted Browser Reference E2E run `33854020809` passed all 12 initial and 5
process-reconstruction scenarios against harness/Provider lock
`e7e7f03`/`44ea2ee`. The path uses separate reference-stack and black-box caller
processes over mTLS/JWS HTTPS and a caller-owned WebSocket Gateway, the exact
signed `linux/amd64` Browser image, real GitHub OIDC/Sigstore provenance,
restricted egress, durable state, duration usage evidence, and exact resource
cleanup. The capacity scenario holds one CDP connection, rejects a second
same-session grant without disrupting the first, and connects a replacement
after release. The edge scenario sends 16 authenticated wrong-Origin requests,
observes ordinary `403` plus generic pre-upgrade `429` with bounded
`Retry-After`, and recovers. Artifact
`browser-reference-e2e-evidence-33854020809` has digest
`sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`.
Its inspected run directory `20260904T083407.182245415Z` pins the Contract/tree,
48-case Suite, signed Browser image, and `linux/amd64`. Both reports contain
only passing scenarios. The 20-record metadata-only Gateway audit has six
`authorized`, six `connected`, four `client_closed`, and one each
`capacity_rejected`, `denied`, `expired`, and `revoked`; it contains no
`grant-browser-edge-*` identity, endpoint, token, or CDP payload. This closes
the process-local post-authorization capacity and pre-upgrade Browser service
scenarios within the Browser reference external-caller gate only.

Clean local Browser run `20260904T080946.250607000Z` then passed 12 initial and
5 process-reconstruction scenarios against harness/Provider lock
`249cdd4`/`44ea2ee` on `linux/arm64`. ADR 0028 adds a process-local global
connection and fixed-window request gate before Browser WebSocket admission and
upgrade. The added black-box scenario sends 16 authenticated wrong-Origin
requests, observes ordinary `403` plus generic pre-upgrade `429` with bounded
`Retry-After`, and observes ordinary `403` again after the window. The
20-record Gateway audit retains the six `authorized`, six `connected`, four
`client_closed`, and one each `capacity_rejected`, `denied`, `expired`, and
`revoked` events, with no `grant-browser-edge-*` identity.
At that baseline, listener/TLS/HTTP-layer limits remained open, together with
partition-aware shared or distributed capacity, durable distributed revocation,
production advertisement, generic-consumer interoperability, aggregate, multi-controller,
hostile multi-tenant, deployment, and production gates.

ADR 0029 and implementation `b8f8941` then add the bounded public TLS edge.
Clean local Browser run `20260904T091156.303717000Z` passed 13 initial and 5
process-reconstruction scenarios against harness/Provider lock
`35cf068`/`b8f8941` on `linux/arm64`. Hosted Browser run `33857739150` passed
the same 13+5 set against harness/Provider `7a20d9d`/`b8f8941` on
`linux/amd64`. The new black-box scenario rejects TLS 1.2, negotiates TLS 1.3
with HTTP/1.1, rejects slow and oversized request headers before the handler,
holds the configured accepted-connection limit, and recovers after release.
Artifact `browser-reference-e2e-evidence-33857739150` has digest
`sha256:94bcdfa53b667d4a6bc17fd6714cc9895e8402b830b8c6425c604c835f9228f`;
its inspected run directory is `20260904T091942.992885726Z`. Its 20-record
Gateway audit retains the prior type counts and contains no edge grant, token,
endpoint, credential, CDP, or payload field. This closes the listener/TLS/HTTP
component and Browser reference-caller scenario only. Authenticated
partition-aware shared or distributed capacity, durable distributed
revocation, production storage/configuration and metrics, production
advertisement, generic-consumer interoperability, aggregate, multi-controller, hostile
multi-tenant, deployment, and production gates remain open.

ADR 0030 and implementation `997fb0d` then add the post-binding
authenticated-capacity port and process-local global/tenant/session memory
reference. Hosted repository CI `33940332882` passes `provider-contract`,
`test`, `browser-provenance`, and `docker-integration`. Hosted Reference,
Candidate, and Browser runs `33940332897`/`33940332881`/`33940332911` all pin
harness `6b01b75`, Provider `997fb0d`, the Contract/tree, and 48 cases.
Reference and Candidate pass their separately named 15+5 coding/shell sets;
their artifacts have digests
`sha256:c5294520236200c06597bcc383455b9a74cb3668557cce313ab7e4dab0af0537`
and
`sha256:5fad63cd7dfc863af83faf2e5324529852cc8b741deeac5414f12d5fd0dd26f5`.
Browser passes 13+5 on `linux/amd64`; artifact
`browser-reference-e2e-evidence-33940332911` has digest
`sha256:f4133967b6e573c701b82c72dc4d101febd4e6b28199e188fa0c8db049bff9ae`.
Its active contention scenario reaches the authenticated memory authority, and
the 20-record metadata-only Gateway audit retains six `authorized`, six
`connected`, four `client_closed`, and one each `capacity_rejected`, `denied`,
`expired`, and `revoked`. This is a single reference Gateway process, not a
shared backend or two-Gateway-process capacity result. TTL/renewal, crash
reclamation, stale-owner fencing, durable distributed revocation, real Agent
Platform, aggregate, multi-controller, hostile multi-tenant, deployment, and
production gates remain open.

ADR 0031 and implementation `9434540` then add the Redis-compatible shared
capacity adapter, followed by the WebSocket close and deterministic stale-lease
harness and edge-timing corrections through `ddbb2c4`. Clean local evidence
`e2e/evidence/shared-capacity/20260905T061037.558537000Z` passes all 10 scenarios
on `linux/arm64` through two independent Gateway OS processes and a real pinned
Valkey authority. It covers cross-process global/tenant/session contention,
unaffected-tenant service, renewal beyond three lease TTLs, confirmed loss,
Gateway crash reclamation, stale-owner fencing, renew/release cleanup,
retained-store outage failure closure and recovery, and evidence sanitization.
Shared-capacity rejection occurs after WebSocket `101` and is observed as a
normal `1000` close, not the pre-upgrade limiter's HTTP `429`. The manifest pins
harness/Gateway source `ddbb2c4`, Provider baseline `2ed5e68`, policy fingerprint
`1b29321807530907a8407cd6d33bdefbbb980fd7cb0b297592181a2333a8bacd`, Valkey
index `sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`,
and arm64 child
`sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e`.
Valkey provenance is explicitly not established. The Contract revision/tree
and 48-case Suite are pinned as metadata with `exercised=false`; Provider API,
real Browser/CDP, image provenance, restricted egress, artifact/usage, HA,
durable distributed revocation, downstream fencing, Provider multi-controller,
hostile multi-tenant, generic-consumer interoperability, deployment, and production gates are
not established by this local run.

Hosted Browser Shared Capacity E2E run `33949577876` independently passes the
same 10 scenarios on `linux/amd64` against harness/Gateway source `de297e7` and
Provider baseline `2ed5e68`. Artifact
`browser-shared-capacity-e2e-evidence-33949577876` has GitHub digest
`sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`;
its downloaded run directory `20260905T062246.271594332Z` contains exactly the
manifest, report, two audit logs, and two observation logs. All 10 report
entries pass. The combined audits contain 22 `authorized`, 22 `connected`, 18
`client_closed`, five `capacity_rejected`, two `capacity_lost`, and two
`capacity_unavailable` records; the observations contain 22 `resolve` and 22
`dial` records. The manifest pins the same Contract/tree/48-case metadata with
`exercised=false`, the same Valkey index, amd64 child
`sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478`,
and `provenance_not_established=true`. This is hosted Gateway/Valkey
shared-capacity evidence only; it does not exercise Provider API, real
Browser/CDP, image provenance, restricted egress, Provider artifact/usage,
HA/failover, durable distributed revocation, downstream fencing, Provider
multi-controller, hostile multi-tenant, generic-consumer interoperability, aggregate,
deployment, or production behavior.

ADR 0032 and implementation `c0a55d1` then replace the split revocation
check/watch with one exact-grant level-triggered watch, cancel blocked Provider
resolution and dial work when the authority terminates, and add a
Redis-compatible retained-tombstone source/writer. The adapter verifies an
immutable policy, hashes namespace and grant identities, uses Redis server time
to bound grant lifetime and tombstone expiry, preserves the greatest expiry
under duplicate or out-of-order revoke, polls within bounded operations, and
fails closed on malformed state or authority loss. Focused/full race-shuffle,
vet, Contract verification, the unchanged 48-case Suite, and the tagged real
pinned-Valkey component integration pass locally. This establishes Gateway
revocation port semantics plus one retained-backend adapter component only.

Historical E2E lock `59e08d5` pins Provider `c0a55d1`. Its local Browser run
`20260905T080015.795386000Z` passes 13+5 scenarios, Reference run
`20260905T080530.577843000Z` and Platform Candidate run
`20260905T080623.861033000Z` each pass 15+5, and shared-capacity run
`20260905T080725.227680000Z` passes 10/10 on `linux/arm64`. These are regression
evidence within their existing names: Browser still uses one process-local
memory revocation authority, and shared capacity does not exercise revocation.
Harness/Gateway source `e952ef9` now supplies the separate durable-revocation
runner. Local `linux/arm64` run `20260905T095109.569973000Z` and hosted
`linux/amd64` run `33959122456` each pass all seven locked scenarios through
two independent Gateway OS processes, two independent black-box caller
processes, an independent revoker/control process, and the same retained Valkey
authority. They prove active and pre-resolution revocation, restart retention,
exact-grant scope, outage failure closure, recovery without resurrection,
bounded propagation, and sanitized evidence. The hosted artifact has digest
`sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`.
Contract/tree/48 cases are metadata with `exercised=false`; the fixture is not
a real Browser/CDP path, and downstream CDP fencing remains a separate later
ADR and gate.

Hosted pre-ADR0033 repository CI `33955437033` passes at repository revision
`c7fe24d`. Reference, Candidate, Browser, and shared-capacity runs
`33955436969`, `33955437046`, `33955436984`, and `33955436968` pass with harness
`c7fe24d` locked to Provider `c0a55d1`.
Downloaded artifacts pin the unchanged Contract/tree/48 cases and contain only
passing 15+5 Reference, 15+5 Candidate, 13+5 Browser, and 10/10 shared-capacity
reports. Their GitHub digests are recorded in `STATUS.md`. Browser still uses
the process-local memory revocation authority, while shared capacity still does
not exercise revocation, so these hosted runs also do not close ADR 0032's
independent caller gate.

The later dedicated hosted run `33959122456` is the separately named ADR 0032
caller gate; it must not be conflated with those four regression tracks.

ADR 0033 and implementation `b4d41c9` then add narrow downstream action-fence
ports, a Redis-compatible exact-member/session-high-water authority adapter, a
private ingress component that serializes complete CDP actions, and explicit
fail-closed Browser composition. Targeted and full race/shuffle tests, vet,
Contract verification, the unchanged locked 48-case Suite, and tagged real
integration against pinned Valkey index
`sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
pass. Local run `20260906T050213.016063000Z` at harness `550c785` additionally
passes all 13 ADR 0033 external-caller scenarios on `linux/arm64` through two
Gateway processes, two independent mTLS/JWS caller processes, one authenticated
unique ingress, retained Valkey state, and signed real Chromium. This closes
the local named caller gate; hosted run `34013982796` passes the same 13
scenarios on `linux/amd64` and closes that platform-specific caller gate. Its
artifact digest is
`sha256:9c00f3ba184e82d7eff661b831c05c1bdf331fa41caf2d8bbb3353168ab155b0`.
The Contract/tree/48-case identity is pinned, but the Suite is not exercised.

ADR 0034 then adds a separately selected v2 action-fencing component. One
bounded permanent Redis hash detects missing or malformed retained session
history, and an independent sequence/token witness rejects a Redis action state
restored behind it. The included Darwin/Linux `0600` file witness is
single-process component evidence and is valid only outside the Redis
snapshot/restore domain. Local focused/full race-shuffle, vet, Contract
verification, the unchanged 48-case Suite, and tagged integration against the
same pinned Valkey index pass. The existing downstream caller results still use
ADR 0033 v1, so neither prior run is deletion/restore evidence. A separately
locked 18-scenario v2 real-Chromium runner is implemented with an independent
file witness and orchestrator-only Redis fault credential. Clean local run
`20260906T100233.295973000Z` at fixed harness `059357c` passes all 18 scenarios
on `linux/arm64`, including retained-field and complete-state deletion,
restored-old snapshot rejection with the same numerical capacity fence, witness-adapter
reconstruction, exact one-ahead recovery, other checkpoint mismatch rejection,
and proof of no new upstream dial before the rejected actions. Its exact five
`0600` files pass cleanup and sanitization. This closes only the local ADR 0034
caller gate. Hosted run `34026680591` at the same checkout independently
passes the same 18 scenarios on `linux/amd64`. Its inspected artifact contains
evidence directory `20260906T101111.796974798Z` with exactly five sanitized
files; artifact ID `9987350368` has digest
`sha256:3e68f1c4b5bd74e0ae0ff0fde2c9ffefc63852cf9fc82b3019bedfb228bf2c9a`.
This closes only the hosted ADR 0034 caller gate; the Suite remains unexercised.
Production witness/storage, Valkey provenance/HA/failover, production
metrics/configuration and topology, deployment, multi-controller, hostile
multi-tenant, generic-consumer interoperability, aggregate conformance, and production
readiness remain unproved.

ADR 0035 now adds a PostgreSQL production-candidate witness adapter and strict
read-only `VerifyRestoredState`. Rows are isolated by both the private capacity
namespace digest and witnessed-v2 policy digest; mutations use atomic
conditional updates, force primary-local synchronous commit, preserve bounded
contexts, and redact database detail. The repository includes an explicit
migration, column-scoped runtime grants, real PostgreSQL/Redis integration
tests, and a separate workflow. Local full race/shuffle, vet, Contract
verification, the unchanged 48-case Suite, and the pinned-Valkey strict
one-ahead non-mutation case pass. Hosted workflow run `34031784793` at
implementation `3ff58dc` passes the exact migration, runtime and denied roles,
concurrent CAS/reconnect, missing and malformed state, bounded pool starvation,
and combined pinned-Valkey rollback cases against real PostgreSQL. Its initial
tag pull resolved PostgreSQL digest
`sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`,
which the workflow now pins. The local service remained unavailable. This is
not production or HA evidence; independent failure and backup domains, server
provenance, both stores' HA/failover, deployment, correlated rollback, and
deployment-owned controlled ingress operations remain open.

ADR 0036 now implements a separately locked same-runner operational reference
for the controlled ingress sequence. Its 18-scenario runner retains the first
ten real-Chromium fencing scenarios, stops both Provider/private-ingress
listeners, proves the live Gateways have no alternate downstream path, restores
an older Redis snapshot, and requires strict `VerifyRestoredState` to reject it
without advancing PostgreSQL or opening a listener. It then restores the exact
current Redis state, verifies without mutation, resumes the listeners, and
performs a real-CDP read and write. The runner uses an orchestrator-only Redis
restore credential and a PostgreSQL runtime role available only to the
orchestrator and Provider/private-ingress process. The latest canonical
`linux/amd64` main run is `34069851741` at
`838d3bb2dea52c10fdc1ddf3136641709fedcb20`; all 18 scenarios pass. Its
independently inspected artifact
`browser-postgres-controlled-restore-e2e-evidence-34069851741` contains
evidence directory `20260907T002737.609312407Z` with exactly five sanitized
files; the report is 18/18, and the manifest records three ingress
reconstructions, every cleanup and sanitization flag true, no file-witness v2
field, PostgreSQL restore evidence, and an unexercised Contract Suite. Artifact
ID `10000177842` has GitHub digest
`sha256:96817b74f3faabb0226d7dee1f2ac8128901865a3834f9bcadcaae6459b76032`.
This closes only the hosted same-runner ADR 0036 operational reference gate.
The lock and manifest record `same_runner=true` and
`independent_failure_domain=false`; this adds no independent host, storage,
backup, operator, HA, deployment, or production evidence.

Intermediate hosted run `34025787520` at documentation checkout `ef63be4`
failed in the restore-control verification rather than the fencing behavior.
The helper compared post-`RESTORE` hash `DUMP` bytes with the original dump,
although that binary encoding is not a canonical logical hash representation.
Fix `059357c` keeps real `DUMP`/`RESTORE` injection and instead compares Redis
type, logical string/hash/zset content, missing-key state, and TTL semantics.
The fresh local and hosted runs above establish the fixed-harness evidence.

ADR 0018 records the original reproducible browser image component, while ADR
0019 requires the current `sandbox.runtime/browser-image/v2` sandbox posture
and signed publication. The image has no `--no-sandbox` path and binds a
fail-closed Chromium seccomp profile with digest
`sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`.
Local arm64 and amd64 integration runs returned Chromium `151.0.7922.109` over
loopback, found a sandboxed zygote, and retained the numeric user, read-only
root, drop-all, no-new-privileges, network-none, mount, and resource controls.
Manual publication run `33724368530` passed both native-architecture gates and
published
`ghcr.io/shell-echo/sandbox-runtime-browser@sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`
under tag `sha-58ed0093816d3daa3000750013b8e5991ef4bcf7`. Attestation `44912296`
binds the GitHub OIDC/Sigstore signer to this repository, workflow, source
commit, and hosted runner, and a constrained `gh attestation verify`
invocation succeeded independently. Independent registry inspection found
exactly `linux/amd64` and `linux/arm64/v8` descriptors and no extra manifest.
This closes the exact browser image sandbox/provenance publication gate. No
Provider route, Gateway composition, advertisement, or caller scenario is
implied by the publication evidence.

ADR 0020 and the Browser Docker adapter machine-bind that exact publication,
the checked-in seccomp profile, numeric identity, bounded stable guest mounts,
finite resources, durable private allocation state, and a fresh non-TTY relay
to container-loopback CDP. Focused/full race-shuffle, vet, Contract verification,
the unchanged 48-case Suite, and the tagged Docker driver matrix pass locally.
The live Browser case deliberately uses `network=none`; it proves private CDP
discovery, RFC 6455 upgrade, and `Browser.getVersion` only, not restricted
egress or complete runtime startup. The public adapter still requires
provenance verification and restricted-network implementations and fails
closed without them. ADR 0021 and `provider/browser/provenance/ghcli` provide
the real provenance-verifier component. It pins and
rehashes an operator-supplied `gh` executable, verifies the immutable GHCR
bundle against exact GitHub OIDC/Sigstore identity and signed statement fields,
bounds output and environment inheritance, and preserves cancellation. Its
tagged live GHCR integration passes locally. ADR 0025 wires the exact verifier
only inside the default-disabled Browser graph.

ADR 0022 and implementation `7e60340` add the restricted-egress Gateway process,
Docker provisioner, and immutable lifecycle/create-policy binding. Each
allocation receives an internal bridge; the Browser has only that network and
the Gateway private IP as DNS, while the Gateway has that bridge plus one
explicitly owned uplink. DNS, HTTP Host, TLS SNI, resolved public-address,
image/container/network identity, policy digest, lease, and restart checks fail
closed. The original combined local tagged integration passed allowed
HTTP/HTTPS navigation, denied unlisted and metadata targets, reconstruction,
and exact cleanup. Implementation `f760369` additionally accepts only zero
additional DNS records or one bounded RFC 6891 EDNS0 OPT record; malformed,
repeated, non-OPT, wrong-version, unsafe-flag, and oversized forms remain
rejected. The current local tagged rerun reached the real provenance verifier
but timed out there after 120 seconds, so it is recorded as unavailable external
provenance rather than a passing or failing network scenario. Hosted Browser
run `33838215924` independently passes the complete restricted-egress scenario
on `linux/amd64` with this fix.

ADR 0023 and `b8423f5` compose the two protected Browser handlers behind
existing mTLS/JWS/admission controls. ADR 0024 and `5aae281` compose the
caller-owned Browser Gateway boundary with exclusive terminal/Browser identity,
exact endpoint binding, metadata-only audit, bounded reconnect/revocation, and
RFC 6455 validation. Caller authorization, revocation, recording, WebSocket
admission, and reconnect policy remain explicit dependencies. ADR 0025 and
`66183b1` bind those Provider-local runtime dependencies into a fail-closed,
default-disabled command graph with durable recovery and cleanup. It still adds
no Provider-owned user authorization, production Browser advertisement, or
public Browser Gateway. ADR 0026 and `79fee2b` supply those caller-owned policies
only in a separate reference deployment and first proved the complete 10+5
Browser external-caller path in hosted run `33838215924`. ADR 0027 and
`7b062e6` add process-local connection capacity; capacity harness `28a9a5e` and
hosted run `33846603547` add its active rejection/release scenario without
changing the production advertisement boundary. ADR 0028 and `44ea2ee` add the
process-local pre-upgrade connection/rate gate, and harness `249cdd4` proves its
rejection, recovery, and Gateway-audit exclusion locally; hosted run
`33854020809` passes that 12+5 baseline. ADR 0029 and `b8f8941` add the bounded
TLS listener/HTTP component; harness `7a20d9d` and hosted run `33857739150`
pass its 13+5 Browser reference scenarios.

The internal Block manifest foundation is available under `blocks/` with ADR
0016 and plan `block-manifest-loader.md`. It is a strict, bounded local
configuration registry only; it does not advertise Provider capabilities,
execute blocks, or establish browser/desktop, deployment, or production
evidence.

P4 authority planning is recorded in ADR 0017 and
[`plan/p4-optional-profiles.md`](plan/p4-optional-profiles.md). Browser Contract
authority and Go projection are locked; ADR 0018/0019 and run `33724368530`
provide exact amd64/arm64/v8 sandbox and signed publication evidence. ADRs 0020
through 0024 cover the Provider-local runtime, provenance, restricted egress,
protected transport, and caller-owned Browser Gateway components. ADR 0025 and
`66183b1` compose the default-disabled Provider graph; ADR 0026 defines the
independent reference caller. ADR 0027 and `7b062e6` add process-local Gateway
capacity, and harness `28a9a5e` exercises its original 11+5 hosted scenario.
ADR 0030 and `997fb0d` add the authenticated-capacity port and process-local
global/tenant/session memory component. E2E lock `49d1c20` passes all three
clean lock checks. Hosted CI `33940332882` and Reference/Candidate/Browser runs
`33940332897`/`33940332881`/`33940332911` pass against harness `6b01b75` and
Provider `997fb0d`. ADR 0031 and `9434540` add the Redis-compatible adapter;
local run `20260905T061037.558537000Z` passes its separate 10-scenario
real-Valkey, two-independent-Gateway black-box gate against harness/Gateway
source `ddbb2c4` and Provider baseline `2ed5e68`. Hosted run `33949577876`
passes the same 10-scenario gate on `linux/amd64` against harness/Gateway source
`de297e7` and the same Provider baseline.
ADR 0032 and `c0a55d1` add exact-grant level-triggered revocation port and
real-Valkey adapter component evidence. Historical E2E lock `59e08d5` passes local
Browser 13+5, Reference/Candidate 15+5, and shared-capacity 10/10 regressions;
none is the separately required two-Gateway/independent-revoker revocation
caller gate. Pre-ADR0033 hosted CI `33955437033` and four regressions also pass
against harness `c7fe24d` and Provider `c0a55d1`: Reference `33955436969`,
Candidate `33955437046`, Browser `33955436984`, and shared capacity
`33955436968`. They do not expand those boundaries.
Separate harness/Gateway `e952ef9`, local run
`20260905T095109.569973000Z`, and hosted run `33959122456` pass the seven-case
durable-revocation caller gate on arm64 and amd64. Its Contract identity is
unexercised metadata and its private echo path is not Browser/CDP.
ADR 0033/`b4d41c9` subsequently passes targeted/full race-shuffle, vet, Contract
verification, the unchanged locked 48-case Suite, and tagged pinned-Valkey
integration for its downstream CDP fencing component and real-backend adapter.
Implementation `58488d7` then wires Provider bootstrap into each persistent
downstream caller OS process. The dual-process test gives each caller a distinct
mTLS/JWS Controller identity, reconciles its own capability/create/operation/
sandbox/Browser-session/handoff chain, binds the opaque handoff only in private
process state, and confirms both processes remain in the JSONL control loop.
Implementation `8a1049b` adds the correlated FD 3/4/5 request, private endpoint
envelope, and exact final-configuration handoff; strict bounded EOF-framed JSON;
fixed direction validation and close-on-exec setup; canonical live expiry checks;
at-most-once delivery; cancellation, failure, and natural-exit cleanup; a
fail-closed parent process manager with kill plus bounded wait; and the full Contract handoff-reference
grammar in `gatewaystack`. FD5 delivery is not child acceptance; a correlated
JSONL response establishes readiness. FIFO type validation cannot distinguish a
named FIFO from an anonymous pipe, so the `os.Pipe` launcher is trusted. The
Contract has no Browser-session termination mutation, so handshake failure does
not prove Provider resource cleanup. These remain process/component boundaries.
Runner implementation `a2b82b0` and corrections through harness `550c785` then
compose the complete local topology. Clean run
`20260906T050213.016063000Z` passes 13/13 on `linux/arm64`, including stale
action rejection, higher-fence replacement, terminal closure without
reconnect, outage recovery, unaffected scopes, retained high-water across
ingress reconstruction, bypass exclusion, cleanup, and sanitization. The
Contract identity is pinned and six Provider routes are exercised, but the
48-case Suite remains unexercised (`suite_exercised=false`).
Hosted checkout `2cadc53` passes repository CI `34013982778`, Reference
`34013982794`, Candidate `34013982784`, Browser `34013982785`, shared-capacity
`34013982786`, durable-revocation `34013982798`, and downstream-fencing
`34013982796`. Downloaded downstream artifact
`browser-downstream-fencing-e2e-evidence-34013982796` contains evidence
directory `20260906T052710.781616339Z` with exactly five sanitized files; its
report passes 13/13 and its manifest pins the required amd64 image identities,
topology, and cleanup state.
ADR 0028 and `44ea2ee` add process-local pre-upgrade connection/rate control;
hosted run `33854020809` passes the combined 12+5 Browser caller against harness
`e7e7f03`. ADR 0029 and `b8f8941` add listener/TLS/HTTP bounds; hosted run
`33857739150` passes the 13+5 Browser caller against harness `7a20d9d`.
ADR 0034 separately passes its witnessed v2 deletion/rollback-detection
component and pinned-Valkey adapter gates. It is not selected by this v1 caller
topology. The separately locked v2 caller topology passes its 18-scenario local
`linux/arm64` gate in run `20260906T100233.295973000Z` at harness `059357c`;
hosted run `34026680591` passes the same 18 scenarios on `linux/amd64` at the
same checkout. Its Contract identity is pinned while the Suite remains
unexercised. Production Browser advertisement/public Gateway and v2
private-ingress deployment, a production independent witness, controlled
restore operations, Valkey provenance and HA/failover consistency, remaining
profile-specific security and concurrency, aggregate, multi-controller,
multi-tenant, deployment, and production gates remain separate and open.

Contract identity:

- namespace: `urn:shell-echo:sandbox-runtime:provider-v1`
- version/license: `1.0.0` / MIT
- revision: `720ad15c343e71f36615dc4499edd5e764178bca`
- Contract tree: `343ffde0819207cf99c005096c336735dd33a735`
- manifest digest:
  `sha256:483111511a588b41bd40d3fef686f0b21f465bb65d3215450ebb2ccf37a5de89`
- OpenAPI digest:
  `sha256:5a3da5d239f83e94eff09fc75438755f834e77bce8cd1c0f91c25055bf0cba2a`
- semantic-rules digest:
  `sha256:7953d05e65f00c68e0428b6dd4fcebef1af103f2cab2fa6b214905b2496c8785`
- local Suite: `sandbox-provider@1.0.0`, profile
  `sandbox-runtime-provider-v1`, `repository-go-test`, 71 cases, digest
  `sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`
- remote Suite: `sandbox-provider-remote@1.0.0`, profile
  `sandbox-runtime-provider-remote-discovery-v1`, `remote-http-black-box`, 6
  cases, digest
  `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0`

| Phase | Verified maturity | Open gate |
| --- | --- | --- |
| P0 | Passed: repository-owned MIT Contract migration and lock | Retain lock and projection regression |
| P1.1 | The DTO, mTLS discovery, JWS/digest/replay/fencing admission, ADR 0038 repository-local gates, and the exact P2.7 independent external-caller qualification pass. The listener has one explicit caller trust domain, Provider-local audience/revision anchors, and up to 32 frozen keys | Production identity infrastructure, multi-issuer admission, deployment-owned rotation, and qualification of other callers remain unproven |
| P1.2 | Passed for the selected Contract-authorized lifecycle subset and development composition | Snapshot/restore, resize, and production gates remain open |
| P2 components | P2.1-P2.5h local component, Contract projection, Docker, and recorded repository CI gates pass within their named boundaries | Retain single-controller/development constraints and exact Contract lock |
| P2.5i | Latest completed local run `20260907T044611.598221000Z` passed 15 initial plus 5 restart/resume coding/shell scenarios against historical harness/Provider lock `b8d4829`/`af8a505`; hosted regression `33970773414` remains historical evidence against `17ed6ca`/`b4d41c9` | Neither run contains a Browser scenario or proves interoperability with an independently implemented external caller, durable-revocation caller behavior, or production properties |
| P2.6 | The historical 50-case local and separate 6-case remote profiles passed at `3fe314a`/`ae476fe`. The later content-derived 60-case local Suite passed from a clean VCS-built Runner at lock-selection revision `3caf38c6bc0b62d2eeb2c1e1c4ed473fae5baab1`; Product Phase 5 separately selects the current 71-case authority | Protected or mutating remote profiles and broader aggregate/reliability/deployment gates remain separate |
| P2.7 | Complete at **24/24**; the public independent caller is **13/13**. Hosted run `35203241121` executed all 15+5 cases against Provider `170459266af5f4fad359ca8c63f2ae19741055c5` and caller `b3ebcc783e5db20395e29b029e0eb55f7819b49b`, matched all 91 required observations, completed stable zero-resource teardown, and produced accepted seven-file artifact `10488622806` with result-envelope digest `sha256:d5e6fd528f2302252a38f49aa466c85767106a8bcef430120f230a8127f96758` | No step remains in the fixed first-version plan. Other callers/profiles, aggregate conformance, multi-controller, hostile multi-tenant, HA, deployment, and production readiness require new scopes and evidence |
| P2 | Reference coding/shell caller and Product Phase 2 lifecycle release gates passed; the latter includes a repository-owned independent-process 15+5+9 black-box run | Independently implemented external-caller lifecycle interoperability, aggregate conformance, multi-controller, hostile multi-tenant isolation, deployment, and production gates remain open |
| P3 | Retired by ADR 0037. Historical revision binding/shadow/metrics components and candidate runs retain their recorded evidence boundaries | No named-platform migration gate remains; external consumers adapt to the exact locked Provider Contract |
| P4 | Browser Contract authority/projection, exact sandboxed signed amd64/arm64/v8 publication, Provider-local components, default-disabled command/runtime composition, process-local Gateway limits, the separately recorded Browser/shared-capacity/durable-revocation caller gates, ADR 0033 component/caller evidence, the ADR 0034 v2 local/hosted deletion and rollback-detection gates, the ADR 0035 PostgreSQL component gate, and the ADR 0036 hosted same-runner controlled-restore gate pass within their named boundaries | Production independent witness/storage and restore operations, production Browser advertisement/public Gateway, Valkey/PostgreSQL provenance and HA, production configuration/metrics, aggregate, multi-controller, multi-tenant, deployment, and production gates remain open |
| Product Phase 5 | **15/15 complete** for the bounded same-repository independent-process topology. The exact Product/Gateway/Provider/Desktop/Guest process graph passes 14 strict scenarios with fresh pinned PostgreSQL, signed runtime, real display/control, Guest development materialization, restart/fault/security/recording checks, dependency-derived exact-topology advertisement, strict evidence validation, and exact cleanup | Production command composition and deployment qualification, HA, hostile multi-tenant isolation, independently implemented caller interoperability, and general production readiness remain later gates |

Production readiness is not a numbered phase shortcut. Aggregate conformance,
multi-controller reliability, hostile multi-tenant security, deployment, and
production operations remain separate and unproven after the reference P2 gate
and require their own future evidence.

The Browser protected-transport implementation `b8423f5` and harness lock refresh
`a2721ad` are covered by repository CI run `33760609353`, which passed
`provider-contract`, `test`, `docker-integration`, and the separately named
`browser-provenance` job. Its Docker job does not execute the Browser
restricted-egress tagged integration; that live evidence remains local. Hosted
Reference and Candidate runs `33760609272` and `33760609231` passed their
separately named coding/shell scenarios. Repository CI remains distinct from
caller evidence, and neither hosted caller run contains a Browser scenario.
The Browser Gateway implementation `5aae281` and harness lock `9eb32ba` were
pushed together after all local gates and fresh 15+5 Reference/Candidate
coding/shell runs passed. Repository CI `33826813073` passed
`provider-contract`, `test`, `browser-provenance`, and `docker-integration`;
hosted Reference and Candidate runs `33826813099`/`33826813100` also passed their
separately named coding/shell scenarios. None of these hosted results contains a
Browser caller scenario.
Previous implementation `f760369` and harness lock `79fee2b` are covered by
repository CI `33838215949`; all four `provider-contract`, `test`,
`browser-provenance`, and `docker-integration` jobs passed. Hosted coding/shell
Reference/Candidate regressions `33838215917`/`33838215882` also passed their
separate 15+5 scenarios, while hosted Browser Reference E2E `33838215924`
passed its separate 10+5 Browser scenarios. ADR 0027 capacity implementation
`7b062e6` and harness `28a9a5e` are covered by repository CI `33846603580`;
all four jobs passed. Hosted Reference/Candidate regressions
`33846603323`/`33846603454` pass 15+5 coding/shell scenarios, while Browser
Reference E2E `33846603547` passes its separate 11+5 scenarios including active
same-session capacity rejection/release. These three caller modes retain their
distinct evidence boundaries.

The GitHub Actions Node 24 migration `6c1ddde` and lock refresh `e75869d` are
covered by repository CI `33850219645`, Reference `33850219700`, Candidate
`33850219664`, and Browser `33850219667`; all passed without the previous Node
20 or `punycode` warnings. This is CI runtime maintenance only. The subsequent
Browser edge implementation `44ea2ee` and harness `249cdd4` pass all required
local Go/Contract/E2E gates and the clean local Browser 12+5 run described
above. Repository CI `33854020951` passes all four jobs. Hosted Reference
`33854020874`, Candidate `33854020947`, and Browser `33854020809` pass their
separate 15+5, 15+5, and 12+5 scenario sets against harness `e7e7f03` and
Provider `44ea2ee`; their artifact digests are
`sha256:220650f1b61b0297ec445ded03bf3a15870514a9482c9e55012ddfba8ae0da2d`,
`sha256:48cbe44c433e5b3a858a2691fe1f736469b2e8d71228541f2bdfcc4aab1c15b1`,
and `sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`,
respectively. The three caller modes retain distinct evidence boundaries.

## P2.5i Reference Result

The earlier audit correctly found no existing platform caller. A separately
versioned reference harness now exists as the `e2e/` Go module and process
boundary inside this Provider repository. Its caller module has an
import-boundary test that forbids Provider implementation imports; the separate
reference-stack process alone composes exported Provider/Gateway packages with
explicit caller-owned policy.

The clean `e329150` harness run against Provider `d58497e` verified exact
Contract/Suite identity, two ephemeral mTLS/JWS controller identities, locked
capability discovery, protected lifecycle, replay, exec/result/usage, stale
fencing, cancellation, opaque terminal handoff, Gateway bytes, wrong-caller and
cross-tenant denial, grant expiry, revocation, artifact staging/evidence,
process reconstruction, retained evidence, and same-shell reconnect. It
exposed no backend endpoint and left no managed container or new temporary run
directory.

This closes the reference external-caller P2.5i gate. It does not prove real
Veronica compatibility, aggregate conformance, distributed revocation caller behavior,
multi-controller reliability, hostile multi-tenant isolation, deployment, or
production readiness.

The latest local pre-ADR0033 coding/shell lock-refresh runs use harness
`59e08d542b05ad1a047f439f4ea72e82c8c37404` and Provider
`c0a55d1e0a862f9e5a592abd27b1e25be3c85b3e`. Reference evidence
`e2e/evidence/20260905T080530.577843000Z/manifest.json` and candidate evidence
`e2e/evidence/platform-candidate/20260905T080623.861033000Z/manifest.json` each
record 15 initial plus 5 reconstruction/resume coding/shell passes, Contract 48
cases, and linux/amd64 runtime digest
`sha256:c1da999518ed8cf3c422142b705f3eeca5d60104be07bc28c15a7d527d2907fc`.
Neither manifest contains a browser scenario; the candidate manifest also
remains explicitly bounded to candidate integration and does not represent real
Veronica or production traffic.

## Retired Platform Candidate Track

ADR 0037 retires the former named Agent Platform migration target. Earlier
audits correctly established that no runnable platform caller or migration
harness had been supplied, but that absence is no longer an active project
blocker because this repository will not implement or wait for a
consumer-specific adapter.

The historical `agent-platform-candidate` harness, commits, runs, and artifacts
remain valid only within their recorded revision-binding, shadow, canary,
rollback, drain, and metric-component boundaries. Their names and evidence are
not rewritten. A future consumer owns its integration and rollout evidence and
must conform to the exact locked Provider Contract.

## Completed Implementation History and Future Scope

The fixed first-version plan is complete; there is no remaining numbered P2.7
implementation step. The material below records the completed dependency order.
Any further multi-controller, HA, hostile multi-tenant, deployment, production,
or additional-profile work is a new scope with its own authority and gates.

P2.5a established [ADR 0015](adr/0015-coding-shell-vertical-composition.md) and
the [vertical-composition plan](plan/p2.5-coding-shell-vertical-composition.md).
P2.5b then locked one atomic exec+terminal coding/shell profile in Contract
commit `22a148e` and projected it fail closed in `123d16a`. Its local gates and
repository CI `32924361132` pass. P2.5c commits `6c2962b` and `6340604` move
create/session bounded strict decode ahead of mutation guard reservation and
bind the regression into the locked Suite runner; local gates and CI
`32926181615` pass. P2.5d commit `de18787` adds the independent Provider Docker
lifecycle adapter and passes its local fault/restart, full Go, Contract/Suite,
and real Docker integration gates; CI `32929140044` passed all three jobs.
P2.5e commit `5917a57` locally composes strict protected exec/cancel/result and
operation projection, durable accept-before-dispatch and restart
reconciliation, bounded private output capture, real Docker execution and
cancellation, and fail-closed development composition. Full race/shuffle, vet,
Contract verification, the locked 38-case Suite, diff checks, focused race
matrices, and real Docker integration passed locally. CI `32937530059` passed
all three jobs. P2.5f0 then audited terminal/Gateway authority, data-plane,
recovery, persistence, cleanup, capacity, and deployment boundaries without
changing runtime behavior. P2.5f1 commit `6778d3c` adds the backend-neutral
terminal runtime port, a PTY-owning guest broker, adapter-private durable Docker
identity, bounded per-sandbox/per-controller capacity, identity-bound cleanup,
and fresh attach to the same shell after Provider driver reconstruction. Full
race/shuffle, vet, module verification, unchanged Contract verification, the
locked 38-case Suite, diff checks, focused terminal tests, and live Docker
integration passed locally. This is runtime-adapter evidence only; repository
CI `33033284420` subsequently passed all three jobs for evidence baseline
`66dd3d1`. P2.5f2 implementation `ccffd52` then adds the uncomposed durable
session vertical, provider-neutral allocation evidence, v1-to-v2 migration,
trusted lifecycle projection, exact-identity allocation recovery, observation,
expiry cleanup, and a success-commit hook that accepts but does not mint opaque
reference evidence. Full race/shuffle, vet, module and Contract verification,
the locked 38-case Suite, diff checks, focused fault/restart/migration matrices,
and live Docker integration passed locally. Repository CI `33045725476`
subsequently passed all three jobs for evidence baseline `3abefd4`. P2.5f3
implementation `b1acdd1` adds a durable opaque reference registry and resolver
in a separate repository. Registration mints a random 128-bit
`ref:session:*` value for a running allocation; resolution rechecks registry
expiry/revocation and exact committed-handoff identity, then constructs a fresh
adapter-private attach for each dial. File-backed restart, collision, expiry,
revocation, generation/reference mismatch, and concurrent resolve/revoke tests
pass locally. The registry/session repositories are intentionally non-atomic,
and no command composition or public backend endpoint is added. Repository CI
`33059304542` passed all three jobs for evidence baseline `7138a4c`. P2.5f4
implementation `14f14cc` adds `gateway/adapter`: a direct
`github.com/coder/websocket@v1.8.15` dependency (ISC-licensed, source-reviewed
for context reads/writes, message limits, control frames, and close behavior),
plus bounded adapters between the WebSocket/terminal byte surfaces and
`gateway.Stream`. It requires a caller-supplied pre-upgrade admission callback,
rejects wildcard origin patterns, retains the library's default same-origin
protection and disabled compression, accepts only text/binary data-plane
frames, and uses a 32 KiB default with a 64 KiB hard cap. Focused adapter
race/shuffle tests cover admission, origin rejection, binary flow, control
frames, over-limit `1009` close, cancellation, close, abrupt disconnect, and
partial terminal I/O. Full race/shuffle, vet, module verification, unchanged
Contract verification, the locked 38-case Suite, diff checks, and both Docker
regression packages passed locally. Repository CI `33064864447` then passed
`provider-contract`, `test`, and `docker-integration` for evidence baseline
`1d9da67`. `govulncheck` and an OSV scanner were not available, so no
vulnerability scan is claimed. P2.5f5 implementation `fdfc771` adds
`gateway/composition`, which requires caller-owned `Authorizer`,
`RevocationSource`, `Recorder`, and WebSocket handshake admission together with
a Provider reference resolver. It projects each freshly resolved Provider
terminal dial through the bounded f4 terminal adapter, rejects missing and
typed-nil dependencies and incomplete endpoint data fail closed, and closes the
caller stream on all connection exits. Focused and full race/shuffle, vet,
module verification, unchanged Contract verification, and the locked 38-case
Suite passed locally. This is a composition component, not Provider command
configuration, external-caller E2E, aggregate conformance, multi-controller,
multi-tenant, deployment, or production
evidence. Repository CI `33067526022` then passed all three required jobs for
evidence baseline `754c57d`; it is still not external-caller, aggregate,
multi-controller, multi-tenant, deployment, or production evidence. P2.5f6
commits `c4c7cbc` and `8a794c0` then add default-disabled development terminal
command composition with recovery before protected transport injection,
idempotent reference registration, file locking, bounded cleanup, and
production rejection. P2.5f7 test `0e8b284` then closes the local
single-controller terminal vertical gate with a real Docker session, durable
handoff, test-supplied Gateway policy, and same-shell reconnect after process
reconstruction. Their full local gates pass, and evidence baseline `cefbc74`
passed repository CI `33134521467`. P2.5g implementation `0e6e108` then adds
the default-disabled artifact/usage command vertical. It
binds staging to lifecycle readiness, tenant, generation, lease, and fencing;
reads only regular files beneath the owned Docker `/outputs`; runs injected
content scanners without shell interpolation; returns only opaque private
staging references; persists async artifact outcomes and partial exec-derived
usage across restart; and includes artifact operations in the family reader.
Its focused, full local, and Docker-tagged gates pass, and repository CI
`33157119149` passes all three jobs. P2.5h implementation `2c55173` and
repository CI `33159099578` also pass their bounded readiness/projection gates.
Reviewed documentation baseline `bba02a6` passes repository CI `33160646494`.

The private FD 3/4/5 provisioning protocol, parent process manager, and
Contract-wide `gatewaystack` handoff validation are implemented at `8a1049b`.
Harness `550c785` composes them into the complete local ADR 0033 topology, and
run `20260906T050213.016063000Z` passes all 13 scenarios on `linux/arm64`.
Hosted harness `2cadc53` run `34013982796` passes the same scenarios on
`linux/amd64`; the downloaded artifact contains evidence directory
`20260906T052710.781616339Z` with exactly five sanitized files and has been
inspected.

P2.7b validation requires an operator-enforced writer handoff: the validator is
the evidence root's exclusive writer from `Verify` entry through return,
including against producers and other processes with the same UID. Its dirfd
and TOCTOU checks fail closed on detected changes; they do not prove integrity
against a continuously writable attacker. The validator stages its owned
receipt, repeats the final evidence checks, and commits only if cancellation or
a competing destination has not won; publication does not attest that reported
interactions correspond to original request bodies. External packaging and
archive digesting happen only after a successful return.

P2.7c.1 locks the language-neutral adapter JSON schema and its
first Darwin/Linux inherited-pipe transport semantics. Its protocol authority is
bound through startup, process-supervisor, validator, and receipt evidence.
All qualification Schema compilers use one ECMA-262 regexp engine and reject
ASCII controls without POSIX-only classes. Invocation paths/endpoints now use
closed canonical profiles. The definition requires digest-bound preflight
commitment before the supervisor or harness acquires or generates credential or
forbidden-correlation material, plus cross-phase byte identity; runtime proof
awaits the supervisor and operator-upstream non-derivation remains trusted.
Non-error output invocation IDs and phases now bind to the single validated
inbound invocation, including scenario case-ID phase prefixes. Protocol-error
branches now distinguish unbound `invalid_invocation` from
bound post-acceptance terminal failures. Its monotonic deadline anchors retain
one execution budget across reconstruction, clip each case to remaining global
and parent time, prevent resets, and bound failure termination separately.
P2.7c.2a adds the runtime-independent strict codec. Invocation bytes are counted
through EOF; output record limits exclude the LF delimiter while the stdout
total includes delimiters and invalid or truncated bytes. The codec rejects
invalid UTF-8, duplicate members, invalid surrogate escapes, multiple values,
unknown fields, wrong-direction messages, and mismatched startup protocol
authority with stable sanitized failures. It deliberately does not validate
message order, recompute transcripts, enforce deadlines, or launch a process.
P2.7c.2b.1 now locks the exact transition table, terminal-to-EOF-to-clean-exit
completion, cross-phase canonical startup equality, and the closed sanitized
transcript preimage Schema at
`sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293`.
This is definition evidence only, not runtime state or transcript evidence.
P2.7c.2b.2 adds the runtime-independent startup gate: it consumes the first
strictly decoded adapter record, requires `startup_identity` sequence zero,
rejects empty, duplicate, and out-of-order startup, preserves the first
sanitized failure, and grants invocation-input authorization once. It neither
performs I/O against a process nor advances into invocation acceptance.
P2.7c.2b.3 records the invocation only after the startup gate authorized input,
requires the invocation and output to originate from the same verified Codec
and stdout decoder, rejects skipped output records, and accepts only sequence
one with matching invocation ID and phase. A package-private document digest
and revalidation prevent mutable decoded fields from changing the bound
message; only a sanitized invocation reference is retained. P2.7c.2b.5 adds
the valid pre-binding error branch.
P2.7c.2b.4 obtains both phase case orders from that same verified profile
result, copies them into the per-phase machine, and accepts exactly one result
per case in order. `completed` requires an immediately preceding
`scenario_started` for the same case; `not_executed` forbids a preceding start.
Sequence, invocation, phase, Codec, stdout-stream, wire-byte, and decoded-record
integrity remain bound for every accepted scenario message. The machine stops
at `awaiting-terminal`. P2.7c.2b.5 accepts exactly one normal
`invocation_finished` whose completion matches all observed dispositions, or
the exact pre-/post-binding `protocol_error` branch. It rejects output after
terminal, requires EOF on the bound decoder, and accepts a clean-exit event only
after EOF. The pure state-machine slice neither launches nor waits on a process;
c3.6 now supplies this event from the owned child's bounded real exit observation.
A process boundary alone cannot prove caller source independence or exact
PID-level request attribution.

1. Retain the completed P2.7 publication, 24/24 qualification, and public
   caller 13/13 evidence at their exact recorded identities. Retain the
   completed Product Phase 2, Phase 3, and Phase 4 results at their exact
   historical Contract and topology identities; the current Desktop-extended
   Contract lock does not relabel them.
2. Before adding protected or mutating remote profiles, define their explicit
   cleanup authority, prerequisites, case-specific evidence, and incomplete-run
   semantics; do not reinterpret the discovery profile.
3. Preserve the Browser, coding/shell Reference, and historical Platform
   Candidate harnesses as separately named evidence modes. The candidate mode
   is historical and P3 is retired; future consumers own their adapters and
   rollout evidence.
4. Prove independent PostgreSQL/Valkey failure and backup domains, HA, and
   operator controls only in a deployment-owned environment. Retain hosted ADR
   0036 evidence as same-runner reference evidence.
5. Retain the completed Product Phase 5 15/15 evidence at its exact Contract,
   runtime, template, process, and scenario identities. Define a separate
   Phase 6 or deployment plan before enabling production command composition,
   production advertisement, collaboration, HA, hostile-tenant, or operational
   readiness claims.
6. Keep multi-issuer admission, aggregate conformance, multi-controller,
   multi-tenant, HA, independent external-caller interoperability, deployment,
   and production-readiness claims blocked until their separately named gates
   have reproducible evidence.

The detailed case-by-case evidence and exact open claims remain in
[`STATUS.md`](STATUS.md).

## Maintenance Rule

Update this document when architecture ownership, mandatory engineering gates,
phase maturity, Contract identity, primary blockers, or the next implementation
order changes. Put commit-by-commit evidence in `STATUS.md`, design rationale in
ADRs, and protocol details in `contract/`.

Use dated evidence baselines rather than statements such as `HEAD is <sha>`;
the latter becomes false as soon as a documentation update is committed. Every
handoff must leave facts, inference, and unproven claims visibly separate.


### 2026-10-10 held Docker consumer observation and dedicated backend

The [Control storage backend component](plan/product-v1-phase-6-control-storage-backend.md)
adds a separate bounded global Docker observer and a fresh dedicated Store
mode. It checks stopped consumers, exact volume/Control mounts, unsafe aliases
and device authority, live root-fd facts and fixed loop geometry. A Linux
operator-only helper prepares and seals a one-GiB ext4 image offline, with
source inode and initial-byte binding. This does not yet prove physical admission:
shared-VM loop/device operations await explicit scope authorization, complete
source-inode/volume composition and real positive/failure gates. Current real
Docker evidence covers ordinary-volume and stopped-consumer refusal only.
The new offline image is not an attached quota backend, a release image or an
old receipt upgrade. Public Profile/provider v3 holds and Phase 6 **5/15** remain.


### 2026-10-11 authorized real backend diagnostic; admission remains blocked

The user authorized the exact shared-VM loop7 diagnostic. Fresh census, original
image hash/dev/inode checks and atomic attach passed. High-UID raw ext4 writes
survived two container replacements; physical ENOSPC and ELF noexec refusal
passed. The mounted-device O_EXCL test returned EBUSY, and the helper refused
detach while preserving the exact backing inode. These are separate component
facts, not Store quota or full Control acceptance.

The positive Store admission test **failed**: actual mountinfo carried
`master:5`, and sysfs exposed `/receipt.ext4` instead of the required absolute
backing path. No Store namespace was initialized; both strict checks remain.
The next step is independent review of a source-inode/volume observation
composition and an actually private mount, then fresh Store positive gates.
The high-UID Store and root-owned Docker socket are not yet one composed
observer authority. Details and evidence boundaries are in the
[Control storage backend plan](plan/product-v1-phase-6-control-storage-backend.md).

Slice 6 step **1** retains only its historical bounded evidence; step **2**
continues with these real diagnostic results and explicit admission blockers;
step **3** full live inventory/original sixteen scenarios/independent acceptance
is incomplete; step **4** has not begun. Phase 6 remains **5/15** and public
Profile/provider v3 stay closed. No commit, push or release is authorized here.


### 2026-10-11 source observer and private-mount follow-up

A fresh independently reviewed diagnostic used local-driver
`o=rw,nosuid,nodev,noexec,private`. The actual mount no longer contained
`master`, and the unchanged strict kernel-root check passed. This corrects
the earlier review's conflation of container bind propagation with the local
driver's underlying mount options. The held Docker observer now requires
this exact option set and still checks the live Store fd separately.

The helper's new `observe` action uses a read-only backing mount and only
read-only pinned file/loop descriptors, canonical seal and before/after
statx/census/ioctl checks. Actual observation passed, including with an active
filesystem consumer; wrong mount access, absent device and wrong namespace
were refused without output. It emits diagnostic identity fields, not a
Store capability or signed receipt. The positive Store test still fails on
its unchanged exact backing-path check; the private-mount blocker alone is
closed for this observed configuration. See the [backend plan](plan/product-v1-phase-6-control-storage-backend.md).

Next: independently select the live source-capability/Store-root/Docker-volume
composition. Do not turn serialized helper JSON into caller authority. ADR
0055's existing high-UID Control plus fixed supplementary GID 0 candidate
remains the separate Docker-socket direction, with access/denial gates pending.
Phase 6 stays **5/15**; Slice 6 steps **1/2/3/4** remain historical bounded
evidence / in progress / incomplete / not begun. Public Profile/provider v3
admission stays closed, and no commit, push or release occurs.


### 2026-10-11 live source/Store/Docker composition checkpoint

The independently reviewed held component now admits one actual high-UID
Control only after composing retained source FDs/inode and original seal,
strict private whole-ext4 Store root, exact Docker volumes and complete current
consumer inventories. The new source-provision.v2 mode has no legacy receipt
upgrade; its root-owned group-readable source, exact RO loop nodes and fixed
socket group are restricted to that candidate. Both original sysfs-path and
Desktop representation failures remain recorded. See the
[reviewed design](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-live-source-store-and-docker-composition)
for the capability and timeout boundaries.

The final fresh Linux/arm64 fixture passes initialization, persisted state/CAS,
64-object allocation quota refusal, replacement-Control reopening, stopped
receipt/backing/socket consumer refusal, cooperative helper exclusion and
same-byte source seal inode-replacement refusal. Its exact containers, volumes
and new image were removed; loop7 ENXIO and offline fsck passed. Logs, binaries,
source hashes and failed attempts are outside Git in
`control-storage-composition-20261011`, with the final run in `v4-budget-final`.
Development stayed in mise Go1.26.8 and Docker. The worktree remains uncommitted.

Next complete the held Store's physical ENOSPC/uncertain-write/recovery and
wrong-principal denial gates, then integrate the composed lifetime with the
source-derived Coding ledger and complete Profile/operator command admission.
A private fixture with synthetic Profile/principal digests is not that full
admission. The complete four-volume Coding scenarios and original sixteen-
scenario/topology acceptance remain open. Slice 6: **1** historical bounded
Guest E; **2** ongoing, this component passes; **3** incomplete; **4** not begun.
Phase 6 remains **5/15** and both public holds remain closed.


### 2026-10-11 Store fault and wrong-principal checkpoint

The [held Store fault gates](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-store-fault-and-principal-gate-design)
now have independent review and ten fresh Linux/arm64 real fixtures: actual
pending-object Write ENOSPC, no-effect space preflight, two cancellation points,
five process-exit points, and wrong UID/GID/missing-socket-group denial. Incomplete
state remains preserved and refuses reopen/reinitialization; complete canonical
state may be revalidated in a new process, without a success receipt or dispatch
permit. Socket denial is actual connect EACCES, not a permission-mode inference.
This does not prove power-loss durability. All exact fixture resources and the
new diagnostic image were reclaimed; private evidence lives outside Git in
`control-storage-fault-gates-20261011`. mise Go1.26.8/Docker remain the only
selected development toolchain/runtime; source remains uncommitted.

Next bind the composed Store lifetime to the source-derived Coding ledger and
full Profile/operator command path, then run the four-volume physical scenarios
and the still-open Slice6 security/topology gates. Step **1** retains historical
bounded E; **2** continues with these Store gates passing; **3** complete live
topology/original16 and independent acceptance remain incomplete; **4** has not
begun. Phase6 remains **5/15**, with both public admission holds closed.

The same final Go snapshot passes full race/shuffle/count=1 in 524.358 seconds,
full vet in 8.867 seconds, Linux tagged vet and all ten real fixtures.


### 2026-10-11 source-owned Coding ledger checkpoint

The ledger now owns the composed source/Store/Docker lifetime through a private
marked port. Ordinary-directory constructors compile only in tests; the held
constructor checks the storage/template/daemon/endpoint/platform join before
I/O. Failed loading retains markers, while missing state never triggers repair.
Cancellation while draining callbacks keeps the owner locked and closed to new
work until a later Close completes.

Six fresh Linux/arm64 fixtures pass durable Unknown before an effect probe,
replacement-process refusal of replay/Completed/exec, canceled Close and lock
retention until drain, before/after-state interruption without dispatch, missing
state refusal without reset, and a stopped second consumer causing an absorbing
source-owner failure. Removing that peer does not revive the old owner; a new
owner reopens the unchanged empty ledger. All six namespaces, loop mappings and
the new diagnostic image were reclaimed exactly. The raw evidence and one
preserved outer snapshot-comparison failure are outside Git in
`control-storage-ledger-20261011`. The failure compared the replacement container's
parent-directory mtime; independent review restricted comparison to the Store
root/entries, with all original files retained and no scenario rerun.

This is a held source-storage/ledger component using explicit fixture Profile,
principal and policy digests plus bounded callbacks. Full source-derived
Profile/operator and four-volume effects remain unproved. Independent review
found the current complete Profile cannot represent the diagnostic candidate's
RO backing, exact eight RO loop devices and different socket target, and its
required service networks/mounts differ. Next introduce and independently review
an exact source-access mode and operator binding without widening generic
HostDevices/mount rules; then wire the complete command and PG/mTLS paths.
See the [backend design](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-source-owned-execution-ledger-lifetime).

Slice6 remains **1** historical bounded E, **2** in progress with this component
passing, **3** full live topology/original16 and independent acceptance incomplete,
**4** not begun. Phase6 stays **5/15**; public Profile/provider v3 holds, two issuers,
frozen-R reuse and old locks stay unchanged. Development uses mise Go1.26.8 and
Docker; no staging, commit, push or release occurred.


Final validation for the unchanged Go snapshot passed: full
`go test -race -shuffle=on -count=1 ./...` in **474.875 seconds**, full
`go vet ./...` in **18.48 seconds**, the focused ledger/source-owner race tests
in 15.317 seconds, and final Linux tagged vet in 0.516 seconds. Six real fixtures
and independent evidence/documentation review passed within the stated scope.
The existing 600-second full-suite runner limit was not changed. No Go byte
changed after the real-fixture snapshot; subsequent edits only record results.
Contract inputs, Go module/toolchain locks and AGENTS remain unchanged.


## 2026-10-11 complete-Profile source-access permission checkpoint

An independently reviewed optional source-access v1 mode now represents the
exact source-v2 backing, eight RO loop devices, canonical Docker socket, owner
UID/GID/groups and new Control image identity inside the complete declared
Profile v2. A pre-seal source-intent digest breaks the backing-label/Profile/seal
cycle; the final Profile then binds the original seal. Read-only operator review
checks either canonical stage and never grants runtime admission. Legacy wire
encoding and the public Profile/provider v3 holds remain unchanged.

The real Docker fixture passes source Store initialization, replacement reopen,
a create-only positive baseline, eight stopped permission/configuration
refusals and a stopped unauthorized private-config consumer refusal followed by
successful reopen. Exact loop/volume/container/network/image cleanup passes.
The actual observer checks seven mounts and three internal isolated networks,
but this is **Control-only staging**: other role supply identities are synthetic,
and live Provider/TLS peers, CA/CRL content, service readiness and release supply
are not proved. Two failed preparation attempts remain preserved outside Git;
neither is counted as acceptance. Evidence: `control-profile-source-access-20261011`.

Next establish separately reviewed operator admission and exact legitimate
Provider/TLS/CA consumer identities, then connect the source-owned ledger and
complete Control/PG/mTLS command path and four-volume effects. See the
[permission-mode design and evidence boundary](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-complete-profile-source-access-declaration).

Slice6: **1** historical bounded E accepted in its original scope; **2** ongoing,
with this permission component passing; **3** full live topology/original16 and
independent formal acceptance incomplete; **4** not begun. Phase6 remains5/15.
Development remains mise Go1.26.8 and Docker. No commit, push or release.


Final checkpoint validation passed on the unchanged Go snapshot: full
`go test -race -shuffle=on -count=1 ./...` in **340.282 seconds**, full
`go vet ./...` in **8.66 seconds**, both Contract lock verifiers and Linux tagged
vet. Independent design/code/raw-evidence/documentation review accepted the
stated held Control-only component scope. All 237 commands in the final physical
fixture completed successfully; the two earlier failed attempts remain retained
and excluded. No Go source changed after the final real-fixture image build.
The original 600-second suite limit, public admission holds and Phase6 5/15
status remain unchanged. This completes this permission component checkpoint,
not Slice6 formal acceptance or its step4 handoff.


## 2026-10-11 operator and consumer observation checkpoint

Independent design/code review added a held operator-signature and consumer
observation component. Admission re-derives the complete canonical Profile,
then binds a fresh single-use challenge to actual source/root, original seal,
Docker volume and consumer graph observations before Store initialization.
Signatures use a separate test-key commitment, expire within120seconds and do
not create production authority. Every subsequent Store operation rechecks the
approved graph. The old Control-only staging branch remains unchanged.

Real Docker checks passed for the Profile-derived19 diagnostic containers and
three isolated Control/Provider networks: initialize/reopen, signature/review
forgery and graph-drift refusals, stopped/missing consumers, extra endpoint, and
same-name/label wrong UID/image/command/group/config/CA mount permission/source
refusals. Legitimate replacement required a fresh signature. These are fixed
sleep-process permission/session observations, **not real Provider/TLS identity
or readiness**. No CA/CRL bytes or production operator credential are accepted
by this evidence. The test pipe is not an added private-config file. One private
harness preparation failure remains preserved and excluded from acceptance.

Evidence: `control-operator-consumers-20261011`; see the
[operator/consumer component boundary](plan/product-v1-phase-6-control-storage-backend.md#2026-10-11-reviewed-operator-and-consumer-observation-component).
Next establish the production bootstrap and real role launch/service identity,
then the source-owned Control/PG/mTLS command path and four-volume effects.
Slice6: **1** historical bounded E; **2** ongoing; **3** final live topology,
original16 and independent formal acceptance incomplete; **4** not started.
Phase6 remains **5/15**. Development uses mise Go1.26.8 and Docker, with no
commit, push, merge or release. Public admission holds remain closed.


Final validation on the unchanged Go snapshot passed: full
`go test -race -shuffle=on -count=1 ./...` in **260.098 seconds**, full
`go vet ./...` in **3.184 seconds**, both Contract lock verifiers and Linux
tagged vet. Independent review matched all2091Go files to the frozen snapshot
and accepted only the stated held diagnostic scope. Exact cleanup removed all
19 remaining diagnostic containers, six volumes, three networks and the new
image tag; all eight loop nodes were unconfigured and offline fsck passed.
The original600-second suite limit was unchanged. No Go byte changed after the
real fixture binary build. This is a Slice6 step2 component checkpoint, not
formal acceptance or step4 handoff.


## 2026-10-12 held bootstrap and actual process evidence

The [bootstrap/process checkpoint](plan/product-v1-phase-6-control-operator-bootstrap.md) adds a canonical
operator public-key declaration, independent empty-by-default executable pin,
fixed sealed Control FD3 and an explicitly held Control config protocol.
Eight launch declarations bind original OCI role/loader bytes. A trusted
operator probe distinguishes actual PID1 executable/credentials/argv from
container labels and distinguishes the loader from the role.

Real Linux checks passed for sealed-FD positive/negative cases, eight OCI byte
bindings, five direct-entry Control/TLS process-byte observations, two loader
observations and identity/environment/mount refusals. Direct-entry observations
are diagnostic overrides, not approved startup or service readiness. Three
actual Provider commands still reject v2 at the core v1 startup reader; actual
Control/TLS commands remain held. Production pin/probe delivery, operator
challenge transport, Store dispatch and full consumer readiness remain open.
The five private config volumes, all owned containers and three new diagnostic
image tags were reclaimed. Failed fixture attempts and the first600-second
full-race timeout remain evidence, never passes. See the private checkpoint
`control-production-bootstrap-20261012` for final validation and raw logs.

Next independently review the production delivery and post-observation
challenge/signature composition. Public holds, two issuers and frozen-R rules
are unchanged. Phase6 remains5/15; Slice6 steps1/2/3/4 are historical bounded E /
ongoing / incomplete / not started. Development remains mise Go1.26.8 and Docker;
no commit, push, merge or release.


Final checkpoint validation passed on the final Go combination: full
`go test -race -shuffle=on -count=1 -json ./...` in **582.294seconds**, full
`go vet ./...` in **6.491seconds**, both Contract lock verifiers and Linux
tagged vet. The first600.019-second timeout is retained as failed, not erased
by the later pass; no timeout limit was extended. Only the opt-in test fixture
generator changed after the real binary build (it rebinds the selected image
into its synthetic source intent); production Go inputs and real image bytes
were unchanged. The final whole-repository run includes that correction. This
is held Slice6 step2 component evidence, not production acceptance or step4.


## 2026-10-12 held process-delivery continuation

The [versioned pin/probe and post-observation signature component](plan/product-v1-phase-6-control-process-delivery.md)
adds an independent build-time public pin, the fixed image probe, real loader
and Control PID1 observation, sealed loader-generated binding, and a one-use
host-signature reply. The signature scope is only `held-control-process-delivery`;
it cannot open Store or authorize the earlier diagnostic consumer graph.
The host observes twice before signing; Control re-observes after signing.
The selected Unix Docker endpoint remains an operator-controlled trust premise.

Final source and original OCI inputs, actual positive/negative transcripts,
required verification and exact cleanup are indexed in private checkpoint
`control-production-delivery-20261012`; older failed attempts remain retained.
These are dirty-source diagnostic images with a test key, not clean release
or independent production operator acceptance. The next result is separately
reviewed source/root/volume/full-consumer and actual service composition.

Phase6 remains **5/15**. Slice6 **1** historical bounded E / **2** ongoing /
**3** final topology, original16 and independent formal review incomplete /
**4** not started. Public holds, issuer policy, old release/toolchain locks and
frozen-R reuse rules remain unchanged. No Git submission or release occurred.
