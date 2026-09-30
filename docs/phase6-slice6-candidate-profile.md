# Slice 6 source-bound candidate profile

`cmd/freeze-product-phase6-slice6-candidate` composes the reviewed desired
security profile from original, private source artifacts. It is an operator
preflight tool, not a launcher, live observation, evidence generator or release
gate. A successful output does not move Phase 6 beyond **5/15**.

The canonical, mode-0600 input JSON has schema version
`sandbox-runtime.phase6-slice6-composition.v1` and exactly these top-level
fields: `schema_version`, `images`, `trust_anchors`, `external_images`,
`egress_keys`, `certificate_keys`. The `images` object names the clean source
root/revision, run ID, environment and principal-profile digests, the complete
12-target local-role manifest directory, matching Desktop candidate manifest,
and locked Browser publication archive. `external_images` names the same
source root, exact platform, and four complete OCI archives with their
platform-selected manifest digests. The three maps name, respectively, the
five reviewed CA bundle IDs, five egress authority names, and every reviewed
certificate request/response key ID. Names, topology and policy are selected
by the repository; the input cannot submit a deployment-to-image or edge map.

Every source file must satisfy its individual private owner/mode and digest
checks. The command canonicalizes neither a malformed nor a reordered input:
serialize the typed input without indentation or duplicate fields. It writes
only a new mode-0600 output under a current-user-owned mode-0700 directory,
refuses overwrite, reopens all original sources, verifies the final Profile,
and prints only its non-secret digest/revision. It does not emit a manifest
from missing input or use a synthetic fixture as a fallback.

The five CA bundle files must correspond to actual constrained issuer and
service trust relationships established in the isolated non-dev Vault
bootstrap. Valid PEM bytes alone are insufficient. The full gate must later
independently observe Vault issuer UUID/DER/CRL, live leaf chains and uses,
running process and Docker policy, all 16 scenarios and exact cleanup. A
candidate from a previous source revision, changed issuer, or changed private
artifact cannot be carried forward to a new run.
