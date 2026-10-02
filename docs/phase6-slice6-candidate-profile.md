# Slice 6 source-bound candidate profile

`cmd/freeze-product-phase6-slice6-candidate` composes the reviewed desired
security profile from original, private source artifacts. It is an operator
preflight tool, not a launcher, live observation, evidence generator or release
gate. A successful output does not move Phase 6 beyond **5/15**.

The canonical, mode-0600 input JSON has schema version
`sandbox-runtime.phase6-slice6-composition.v3` and exactly these top-level
fields: `schema_version`, `images`, `trust_anchors`, `external_images`,
`dns_client_ca`, `egress_keys`, `certificate_keys`, `credential_keys`,
`break_glass_keys`, `break_glass_operator_binary`. `dns_client_ca` names the
private, single-certificate broker-only public CA bundle and its immutable
Vault issuer UUID; this is an additional original input, not a sixth general
trust anchor. The `images` object names the clean source
root/revision, run ID, environment and principal-profile digests, the complete
12-target local-role manifest directory, matching Desktop candidate manifest,
and locked Browser publication archive. `external_images` names the same
source root, exact platform, and four complete OCI archives with their
platform-selected manifest digests. The five maps name the reviewed CA bundle,
egress authority, certificate key, credential identity and break-glass actor
key source inventories. Names, topology and policy are selected
by the repository; the input cannot submit a deployment-to-image or edge map.
The 12 `credential_keys` are existing per-agent identity private-key sources,
including the certificate controller. Seven nonmigration agents reuse those
same keys as break-glass target signers; no extra target keys are generated.
The five `break_glass_keys` sources comprise four public-only requester,
two-approver and operator files plus one controller-signer private source.
Requester/approver/operator private keys remain outside the Profile builder
and production controller. The resulting closed 11-actor public-key digest
inventory is included in the Profile digest. Every source is reopened before
freeze, but live process FD possession and signed-operation behavior remain
separate release gates. Composition v2 candidates cannot silently upgrade.
The operator binary is an absolute path outside the clean source checkout in
a private directory. It must be a mode-0555, single-link static Linux arm64
ELF, at most 32 MiB. The builder independently rebuilds
`./cmd/phase6-break-glass-operator` with the pinned Go 1.26.8 options and
requires byte-for-byte identity. Only the executable digest/size, build
provenance, toolchain digest, container target path and pinned Alpine index/selected manifest/
config/platform enter the Profile; the source host path stays in private
composition input. Eight finite tasks reference this one artifact and allow
only its read-only file bind plus one task-specific read-only Unix socket
directory. A successful static freeze does not prove Docker mounted those
bytes; the live gate must inspect and read them from the created container
before delivering any signed request or capability. This local binary-bind
candidate is not a self-contained published OCI or cross-platform release.
The five CA IDs are trust purposes, not five independent issuer requirements:
under the reviewed two-issuer plan, `internal-server-ca` contains both the
general and broker-only roots because the five egress brokers serve local
mTLS edges. The other four Profile anchor bundles use the general root on
their actual edges; the separate DNS client CA is broker-only. This mapping
must be checked against live leaf chains and fixed issuer/CRL policy before
release, not inferred merely from a valid Profile digest.
The candidate finalizer now rejects any source whose exact CA DER sets drift
from this mapping, including an absent broker root on the internal server
purpose, broker trust on the other four purposes, duplicate/extra roots, or
general trust in the DNS broker-client source. This is source configuration
admission only, not proof that a running service mounted the bundle.

Every source file must satisfy its individual private owner/mode and digest
checks. The command canonicalizes neither a malformed nor a reordered input:
serialize the typed input without indentation or duplicate fields. It writes
only a new mode-0600 output under a current-user-owned mode-0700 directory,
refuses overwrite, reopens all original sources, verifies the final Profile,
and prints only its non-secret digest/revision. It does not emit a manifest
from missing input or use a synthetic fixture as a fallback.

The five CA bundle files must correspond to actual constrained issuer and
service trust relationships established in the isolated non-dev Vault
bootstrap. The separate `dns_client_ca` file must contain only the broker
issuer CA, and its UUID/DER must match the five-broker-only Vault source and
controller policy. Valid PEM bytes alone are insufficient. The full gate must later
independently observe Vault issuer UUID/DER/CRL, live leaf chains and uses,
the exact CoreDNS read-only mount, broker success and general-client rejection
at a reachable DNS listener, running process and Docker policy, all 16
scenarios and exact cleanup. A
candidate from a previous source revision, changed issuer, or changed private
artifact cannot be carried forward to a new run.
