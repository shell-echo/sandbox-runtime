# Vault 2.1.2 candidate supply investigation

2026-10-13. This follows the independently reviewed
[supply remediation proposal](product-v1-phase-6-vault-supply-remediation.md).
It evaluates a new candidate without changing the accepted historical inputs,
executing Vault or granting runtime admission. Phase6 remains **5/15**.

## Discovery and exact candidate identity

Live GitHub release metadata and Docker Hub metadata identify 2.1.2 as the
stable candidate. The returned newer 2.2.0-rc1 entry is explicitly prerelease
and was not selected. Cached search results showing only 2.1.1 were not used
as current version authority. The official
[2.1.2 release](https://github.com/hashicorp/vault/releases/tag/v2.1.2) is a
discovery source, not proof of an image's publisher or contents.

| Candidate field | Observed identity |
| --- | --- |
| Registry reference | `docker.io/hashicorp/vault@sha256:c2f666266f383d2cf424d86b8bb8ce7d065562173ffec2b476d762943608bb55` |
| linux/arm64 selected manifest | `sha256:7d8aca849b113b416a5b90b73659c46190c3720463f0b53da22440c2ada3b36e` |
| Config descriptor | `sha256:f2108ec5733b3e8a5d4c538acd0f11c22141de573c90acf2d3ba09ef1aa64f61` |

The direct registry responses' raw SHA-256 values match both the index and
selected manifest identities. The index has exactly one matching Linux arm64
descriptor, whose size and digest match that raw manifest. Omitted arm64
variant is normalized to the project's linux/arm64/v8 convention. These are
candidate identities; the old 2.1.1 digest, locks and receipts remain unchanged.

## Publisher and build proof remain unverified

For both the index and selected manifest, Docker Hub returned empty OCI
referrer lists and 404 for the referrer-tag fallback and legacy Cosign
signature, attestation and SBOM tags. ECR Public's 2.1.2 tag returned the same
raw index; its two subject queries also returned empty referrers and 404 for
the checked fallback/signature/attestation tags. Raw bodies, hashes, HTTP
status and pagination headers are retained. These observations do not prove
that no signature exists in another system. No actual signature or attestation
has been cryptographically verified for this candidate.

The fixed release's [container build configuration](https://raw.githubusercontent.com/hashicorp/vault/v2.1.2/.github/actions/containerize/action.yml)
names Docker Hub and ECR Public outputs. The
[referenced Docker build action](https://raw.githubusercontent.com/hashicorp/actions-docker-build/4e0c63aad578fbc5d9dc5a88d108b8fc6253f769/action.yml)
and [release orchestration](https://raw.githubusercontent.com/hashicorp/vault/v2.1.2/.release/ci.hcl)
describe build and promotion steps, but do not supply a verified attestation
for these observed digests; later shared promotion internals could not be
anonymously inspected. Workflow text, Git signatures, registry badges and
image labels are not accepted as image proof.

The same release config lists a Quay UBI image. That is a different candidate
with different base/runtime inputs, not a proof source for these Alpine
bytes. It has not been fetched or scanned here. A Red Hat signing key listed
in vendor documentation does not establish that a particular artifact was
signed by it, or approve a new project trust root. Do not silently switch
image family or inherit a key as a way to bypass the pending proof.

## Actual archive and vulnerability evidence

The official fixed [Go version declaration](https://raw.githubusercontent.com/hashicorp/vault/v2.1.2/.go-version)
is 1.26.8. It is a reason to inspect the real binary, not a substitute for
actual byte-bound build metadata or a full-image scan. The complete original
descriptor graph and all seven compressed layers and ordered uncompressed
diff IDs have now passed the existing repository validators. The private
race/shuffle/count1 overlay, including wrong-platform and wrong-manifest
refusals, passed in **24.044 seconds**. This proves bounded archive integrity,
not publisher authenticity or runtime admission.

The actual `bin/vault` is a 512,729,417-byte Linux arm64 binary with SHA-256
`46509642fccc208331e53f0cfa9961004fac751f5c1e91313b54ff9f5a5c00e5`.
Trusted `go version -m` parsing of its non-executable data copy confirms
Go1.26.8 and `golang.org/x/net v0.59.0`. The candidate binary was never run.

Trivy0.74.0 produced the full-image report in **1.853 seconds**, with 19 Alpine
packages and 487 Go packages. The report's image ID equals the original config
digest above. Counts are **4 HIGH, 0 CRITICAL, 9 MEDIUM, 7 UNKNOWN, 1 LOW**;
all severities and unfixed findings remain in the raw report. Report generation
exit0 is not a vulnerability pass: the existing HIGH/CRITICAL policy **fails**.

| Affected material | Actual version | Reported fixed version | HIGH findings |
| --- | --- | --- | --- |
| `golang.org/x/net` | v0.59.0 | v0.60.0 | CVE-2026-78669 |
| Go standard library | v1.26.8 | 1.26.9 or 1.27.2 | CVE-2026-78667, CVE-2026-78669, CVE-2026-97031 |

The four findings represent three distinct CVEs. This candidate's report has
no OpenSSL HIGH finding; that does not erase the historical candidate's six
HIGH findings or qualify the new bytes. Trivy also warns that Alpine3.24 is
not on its EOL list; this run does not establish OS lifecycle qualification.

Private archive diagnostics reuse the repository's existing descriptor and
layer validators through an explicit test overlay outside the repository.
They compare index/manifest bytes with the direct registry response and
require wrong platform and wrong selected-manifest identity to fail. No
production pin or opt-in runtime test is changed by that overlay. Independent
review found and closed two size-bound gaps in the private archive-preparation
script before execution. The historical tool and receipts remain untouched.

Docker's ECR pull and direct platform-manifest pull succeeded, but the two
successful exports were only 9,216 and 7,680 bytes and omitted the actual
config/layers. Explicit platform export also failed. Those results are not
complete portable archives. Direct restoration therefore uses the original
registry descriptors and bounded HTTP ranges, with exact response range,
complete size and SHA-256 checks; HTTPS redirects strip cross-host credentials.
The original failed and timed-out transfers remain evidence. Resumption only
fetches absent ranges and cannot establish integrity until the full digest
matches. No timeout was extended.

Trivy's default database transfer, explicit GHCR transfer and HTTP/1 diagnostic
all failed. A separately verified raw GHCR OCI layer then supplied the fresh
database: manifest
`sha256:1f6a12218a171613283404aaf8cee31fe38a60f6787aa7c91de5b0f32d871717`,
layer `sha256:7f3ba3d6e00f030a48ae163bcdbba68ddade03910ced826cc03400395b6362cc`.
Its version-2 metadata records update 2026-10-13T01:09:18Z and next update
2026-10-14T01:09:18Z. The importer accepts exactly two bounded regular tar
members, preserves raw metadata, and creates new DB files without overwriting
an old database. The raw metadata's zero `DownloadedAt` is preserved; a separate
receipt records actual retrieval and import times. This is not old-DB reuse.

Independent review required re-reading the scanner's selected-platform input
copies and hashing all original blobs, local wrappers, DB files and empty
configuration/ignore files before and after scanning. That binding mechanism
passed for all 16 files before and after the scan. The local selected-only OCI
wrapper is not an upstream signature subject. No vulnerability ignores or
severity exceptions are introduced. Independent final review rechecked the
raw identities, report binding and failed supply decision.

The two exact ECR Docker references pulled during this investigation were
removed without force or prune, with no container consumers and subsequent
absence checks. The historical Vault reference and rootfs identity remained
unchanged. The initial cleanup attempt refused Docker's digest references
appearing in `RepoTags`; the corrected diagnostic allowed only those same
two exact references, never additional tags. No service, volume or network
was created by this investigation. Raw archives and failed attempts remain
private evidence, including the small-blob resume's receipt-name collision.

## Continuation boundary

The private checkpoint is `vault-candidate-supply-20261013`, outside Git and
the migration package. At entry all 2550 tracked/unignored files matched the
previous checkpoint, at branch `codex/product-v1-phase-6-hardening` and HEAD
`91fe315641779e6ea640632538309d63ad1b303f`. Existing uncommitted work is retained.
The prior 503.355-second full-race result is source-bound local evidence, not
a test rerun in this candidate investigation. All 2148 Go files still match
that final gate snapshot; no repository Go source or lock was changed.

Only complete supply proof, a fresh passing full-image scan and independent
candidate-consumption review can authorize the subsequent real two-issuer
component. This official stable candidate fails those prerequisites and must
not be selected by changing a digest or archive environment variable.
The next bounded work is a separately reviewed replacement/build proposal
that fixes both embedded Go inputs and supplies independently established
publisher/builder authority. Merely updating Alpine or signing these same
bytes would leave the HIGH findings. Any Vault-specific compiler decision is
separate from the existing Coding-only Go1.26.9 permission; neither that
permission nor a new local key provides Vault supply authority.
The current test still hardcodes historical inputs. There is no
new Vault service, operator identity, issuer receipt or Controller/agent/command
acceptance. The existing broker/general issuers, PostgreSQL general, public
Profile/provider v3 holds and frozen-R reuse rules remain unchanged.

Slice6 steps remain: **1** historical bounded Guest E; **2** startup and real
security-boundary work ongoing; **3** final live inventory, original 16 and
independent formal acceptance incomplete; **4** post-acceptance handoff not
started. Development tools remain mise-managed and Docker is the existing
local Desktop runtime. No staging, commit, push, merge or release.
