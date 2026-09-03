# ADR 0021: Browser Runtime Provenance Verifier

- Status: Accepted for the uncomposed P4 Browser provenance component
- Date: 2026-09-03

## Context

ADR 0019 records the exact signed Browser image publication, and ADR 0020
requires a real provenance verifier before the Docker adapter can start. The
existing `profiles/browser/image.Publication` validation and OCI label checks
bind configuration and local image metadata, but neither operation validates a
signature. Treating those checks as provenance would convert checked-in values
into their own trust proof.

Directly importing the GitHub CLI attestation implementation is not available
as a stable public Go API, while integrating the complete Sigstore trust-root,
Fulcio, Rekor, DSSE, OCI, and GitHub certificate-policy stack locally would add
a large security-sensitive implementation surface. The publication workflow
already uses GitHub CLI attestation verification with explicit identity
constraints.

## Decision

Add an independent `provider/browser/provenance/ghcli` adapter implementing the
Browser Docker runtime's `ProvenanceVerifier` port. It invokes an operator-
supplied GitHub CLI executable directly, without a shell. Construction requires
an absolute executable path and an independently configured SHA-256 digest.
The executable must be a bounded regular executable that is not group- or
world-writable and is rehashed before every verification. Missing, replaced,
oversized, writable, set-ID, or digest-mismatched executables fail closed.

The verifier reads the attestation bundle from the locked immutable GHCR image
with `--bundle-from-oci`, rather than trusting an API response as the bundle.
The GitHub CLI still requires authentication before it will run this command,
even for a public OCI bundle. The deployment must therefore supply a short-
lived, read-only GitHub CLI token and may supply a separately scoped registry
credential through the CLI's OCI credential path. Missing authentication fails
closed. Verification fixes all of these constraints:

- exact image repository and index digest;
- repository `shell-echo/sandbox-runtime`;
- signer workflow
  `github.com/shell-echo/sandbox-runtime/.github/workflows/browser-image.yml`;
- source commit `58ed0093816d3daa3000750013b8e5991ef4bcf7`;
- GitHub Actions OIDC issuer and GitHub-hosted runner policy; and
- SLSA provenance v1 with no more than two fetched candidates.

Success output is bounded to one MiB and must contain exactly one verified
attestation. The adapter independently rechecks the signed certificate and
statement fields: subject digest, workflow identity and branch, source commit,
manual publication trigger, hosted runner, SLSA build type, source dependency,
publication run/attempt, builder, and a verified timestamp. This parsing is an
additional fail-closed policy check after the GitHub CLI has cryptographically
verified the bundle. The recorded GitHub attestation ID remains release-ledger
identity; the signed run invocation, subject, and source identity are the
runtime-verifiable fields exposed by the verifier result.

The adapter discards command diagnostics and returns only stable errors. It
passes only the environment needed for GitHub/registry authentication,
credential discovery, proxy/CA policy, and temporary files; unrelated control-
plane environment values are not inherited. It preserves cancellation and
deadlines. The Browser Docker driver gives network readiness, provenance
verification, image pull, and image inspection separate bounded contexts so a
real registry verification does not inherit the private relay's ten-second
connection probe limit.

## Release boundary

Unit tests use an injected command runner and synthetic verified-result JSON to
cover exact argv, identity drift, ambiguous or malformed output, executable
replacement, bounded output, safe errors, and context propagation. A tagged
integration invokes the pinned local GitHub CLI against the exact GHCR
attestation bundle. Repository CI runs that integration as a separately named
`browser-provenance` job with a read-only package credential. The integration
hashes the selected CLI for that test process; it does not prove how a future
deployment independently distributes or audits the configured CLI digest.

This is real provenance-verifier component evidence only. The integration does
not start the Browser image, enforce restricted egress, bind create policy,
compose protected handlers or a caller-owned Gateway, advertise Browser, or run
a Browser external caller. Aggregate conformance, multi-controller reliability,
hostile multi-tenant isolation, deployment, and production readiness remain
separate open gates.

## Consequences

- Browser adapter construction can use cryptographic publication verification
  instead of a configuration-only fake once a deployment supplies the pinned
  verifier executable.
- Deployments must distribute and rotate the GitHub CLI binary digest as an
  explicit trust input, provide bounded registry access to the immutable GHCR
  publication, and provision a short-lived read-only CLI token.
- GitHub CLI output or attestation schema drift fails closed and requires a
  reviewed adapter update.
- The next P4 slice remains the real restricted-egress provisioner and
  create-time policy binding before any Browser transport composition.
