# Vault supply remediation proposal

2026-10-13. Slice6 step2; Phase6 remains **5/15**. This is a proposed
sequence for replacing a blocked input, not an approved replacement lock,
trust root, vulnerability exception or production deployment. The
[two-issuer continuation](product-v1-phase-6-vault-two-issuer.md) retains the
original failed supply results and the unexecuted real-service matrix.

## Two independent blockers

The restored historical Vault index is
`sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2`;
its selected linux/arm64/v8 manifest is
`sha256:3aae140ea5b73deaf10d70607194ab52ff80f4ebfc4ef4796ad1a7be5f4db682`.
The raw OCI descriptor chain and Docker identity were checked, but no image
signature or build attestation was verified. Empty referrer responses and
legacy signature 404 responses are observations, not proof that no publisher
proof exists anywhere. The failed attestation request remains undetermined.

The fresh full-image Trivy report contains six HIGH findings, representing
four unique CVEs, and zero CRITICAL findings. The original report is retained
in private checkpoint `vault-controller-continuation-20261013`, under
`supply/vault-vulnerabilities-explicit.json`:

| Affected input | Installed | Reported fix | HIGH findings |
| --- | --- | --- | --- |
| libcrypto3 and libssl3 | 3.5.7-r0 | 3.5.8-r0 | CVE-2026-14456, once per package |
| golang.org/x/net | v0.59.0 | v0.60.0 | CVE-2026-78669 |
| Go stdlib in the Vault binary | v1.26.8 | 1.26.9 or 1.27.2 | CVE-2026-78667, CVE-2026-78669, CVE-2026-97031 |

These are scan observations for those exact bytes and database, not a
prediction about another candidate. Replacing only Alpine packages cannot
remove the findings embedded in the existing Go binary. Signing the old image
cannot repair those findings. A new candidate must independently satisfy both
authenticity/provenance and vulnerability gates, including any newly reported
findings; the historical six-item list is not an allowlist.

## Preferred route: evaluate a publisher candidate

First inspect official release metadata and publisher verification procedures
without executing the candidate. Resolve the exact index, selected platform
manifest, registry and publisher evidence identities. Do not use a mutable
tag as an input lock. Preserve the raw manifest, config, compressed layers,
ordered diff IDs and hashes under a new private candidate/run identity.

The official [Vault v2.1.2 release](https://github.com/hashicorp/vault/releases/tag/v2.1.2)
is dated 2026-10-07. It is a discovery lead, not a selected or verified input.
The Go advisories [GO-2026-6609](https://pkg.go.dev/vuln/GO-2026-6609),
[GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611) and
[GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607) describe the relevant Go
fixes; a version tag or release date alone does not establish which bytes an
image contains. No newer candidate has been fetched, scanned or approved by
this proposal.

Before service execution, verify cryptographic publisher identity and build
provenance for the exact selected subject, including the index-to-platform
relationship. Fix the expected key or certificate issuer/identity through an
independently reviewed source. Reject proof with an unrelated subject,
builder, source, recipe, material or platform. Verification must bind the
actual image bytes; a registry badge, label, signed Git commit or matching
binary checksum alone is insufficient. Sigstore's
[verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/)
describes signature identity and subject checks but does not establish that
HashiCorp publishes a suitable proof for this candidate.

Inspect the binary's build metadata and produce a fresh full-image scan with
the approved scanner and fresh database. Record scanner/version/database,
configuration, complete raw result and image descriptor binding. Preserve the
existing HIGH/CRITICAL rejection policy and all other supply requirements;
no ignore file entry, severity override, suppressed unfixed issue or binary-only
scan may replace that gate. Discovery and scanning may proceed while publisher
proof is unresolved, but the candidate must remain unexecuted and unaccepted.

If a candidate satisfies all of these checks, prepare a separately reviewed
new candidate declaration and update only the intended current consumption
points. Inventory all fixed Vault consumers first: the two-issuer test shares
`vaultPKIIntegrationImage` with existing workloadpki tests, and other packages
have their own Vault inputs. A global digest substitution would silently alter
historical scenarios. Prefer an explicit new candidate scope and retain old
locks, receipts and archived manifests as historical evidence. Do not make a
test accept an arbitrary archive or unverified environment-supplied digest.

Current consumers to classify during that review include
`internal/phase6profilebuilder/external_images.go`, the workloadpki,
workloadtlsagent, workloadcredential and secretref/workloadagent integration
constants, and the material-agent and Slice6 Vault-path tests in
`productphase6gate`. The Slice5 verifier constant in
`internal/productphase6slice5evidence/verify.go` and the accepted Slice5 JSON
manifest describe old evidence and must not be rewritten to a new digest.
This is an initial consumption map, not permission to migrate every consumer.

## Fallback if publisher image proof is unavailable

A separately reviewed custom image may use an already fixed official Vault
release binary. Follow HashiCorp's
[binary verification procedure](https://developer.hashicorp.com/well-architected-framework/operational-excellence/verify-hashicorp-binary):
independently establish the publisher PGP key, verify the signature over the
release checksum file, then match the exact platform archive and binary. An
untrusted key downloaded beside an archive is not its own trust decision.
HashiCorp's [official release channels](https://www.hashicorp.com/en/official-release-channels)
describe binary distribution; that description is not a cryptographic image
attestation.

This route still needs a reviewed digest-pinned base and dependency inputs,
build recipe, controlled builder identity, approved image publisher and
image-level signature/build attestation binding the resulting OCI subject to
those materials. A signed upstream binary is only one material in that proof.
A new self-generated local key does not become an approved publisher or
production operator authority. Do not self-sign the old image as a shortcut.
The full resulting image must pass the same vulnerability and provenance gates.

If no fixed official binary exists, source compilation is another decision,
not an automatic extension of this fallback. It requires independently
reviewed clean source, build/dependency locks and candidate-specific compiler
selection. The earlier Go1.26.9 exception applies **only to the new Coding
candidate**; it does not authorize a Vault build or a repository toolchain
upgrade. Ordinary development remains mise Go1.26.8 or Docker. No global
installation, public upload, paid builder or publication is implied here.

## Compatibility and real acceptance after supply

Before approving a replacement, inspect the actual configuration and policies
against the selected release changes. Vault v2.1.2 documents changes to PKI
ACME sign-verbatim SAN handling, policy-name validation and role/path matching.
Keep the existing fixed lowercase policy/role names and exact paths; review
allow and deny semantics rather than opting into an unsafe compatibility
switch. The current signing path and all rejection paths must be exercised
against the selected candidate; matching a version string is insufficient.

After supply proof, candidate consumption code and independent review pass,
run the two-issuer component with a fresh run ID and the exact approved archive.
Its current code hardcodes the old index and arm64 manifest: a candidate needs
separately reviewed candidate-specific consumption code and test identities;
changing the archive environment variable alone cannot select it. Preserve
the existing scenario assertions. The run must produce actual broker/general UUIDs and DER, exact
role issuer bindings, fresh certificate/CRL readiness, revocation and CRL-number
advancement, cross-issuer isolation, mutable-default drift refusal, role alias
and wrong-issuer refusal, wrong-DER refusal, disabled publication, CRL access
denial and sealed-Vault refusal. Read back injected settings and distinguish
the intended 403/503 failures from unrelated transport errors. Reclaim only
the run-owned container and anonymous volumes and prove their absence.

Then bind those new issuer bytes into the complete Profile/source/role field
checks, followed by the separately reviewed production Controller/agent and
Provider/Control/Scanner command composition. The only workload issuers remain
broker and general; PostgreSQL uses general. A local test's admin TLS root is
not a third workload issuer or production operator authority. Public Profile
and provider serve v3 holds remain closed until their named acceptance gates.

The next acceptable supply result is a new candidate dossier containing exact
OCI identities, independently verified publisher and builder identities,
source/material/recipe binding, a passing fresh full-image scan, compatibility
review, and a precise consumption patch. The next acceptable runtime result
is the new two-issuer matrix plus exact cleanup. Neither exists yet. Frozen-R
reuse rules, old Guest receipts and their identities remain unchanged.

## Delivery boundary

This checkpoint changes no Vault lock, trust root or supply policy and starts
no Vault service. Independent read-only proposal review accepted this sequence
and its bounded claims, including the explicit candidate-consumption boundary.
A reviewed proposal does not itself approve candidate bytes, a new trust root
or a candidate-specific implementation.
Slice6 steps remain: **1** historical bounded Guest E accepted in its original
scope; **2** startup and real-boundary work ongoing; **3** final live inventory,
original16 scenarios and independent formal acceptance incomplete; **4**
post-acceptance handoff not started. No staging, commit, push, merge or release.
