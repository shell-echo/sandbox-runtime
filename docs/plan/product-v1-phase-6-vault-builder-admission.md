# Vault builder material closure and rejected admission

2026-10-13. Phase6 remains **5/15**, Slice6 step2. This follows the
[input checkpoint](product-v1-phase-6-vault-build-inputs.md) under the confirmed
private Vault-only Go1.26.9/root x/net v0.60.0 scope. Development tools remain
mise/Docker-managed; the ordinary repository toolchain remains Go1.26.8.
Private evidence is `vault-isolated-build-20261013`, outside Git and the
migration package. Earlier input/failed-transfer receipts remain unchanged.

## Completed material verification

The remaining24 fixed Go requests completed in83.899 seconds. Nine previously
lacked archive/mod bytes; fifteen lacked complete frozen checksum authority.
Recovery uses a new private clone of the download cache and checksum-DB-enabled
Go verification. Fifteen copied old ziphash markers are retained separately
in the new checkpoint so Go rechecks those bytes; the prior cache and authority
records are not rewritten. Cached signed checksum responses and live requests
are not distinguished, so this is not a claim of24 new online attestations.

Independent ZIP h1 and go.mod h1 recomputation now matches **987/987** fixed
requests in6.483 seconds. Actual root `go mod verify` with GOPROXY=off passed in
9.980 seconds. The9,090-file derived source and five local replacements remain
unchanged. This closes the root external-module material set and exact enumer
archive, not enumer's standalone dependency graph or a source build.

The three missing Node layers were recovered in70.984 seconds, with exact
HTTP206 range/size checks followed by whole-layer hashes. The original index,
selected linux/arm64/v8 manifest, config, all five compressed layers and diff
IDs match; the extracted Node executable matches the separately pinned official
Node22.23.3 archive. The retained OCI tar contains the selected platform, not
every platform in the original index. No image was imported into Docker or
executed; daemon rootfs correspondence remains untested.

Fixed Node22.23.3-bookworm-slim identities:

- index: `sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392`;
- arm64 manifest: `sha256:b20fe038d9592822dd534600a1ddf467e985178aa3fed60ec441a056c2cc45bd`;
- config: `sha256:cd2df7ff65c5fce1f8a18ce89e3aac24a80c1db3776d5842a4cf86bc27f300a2`.

## Builder admission fails

The complete OCI image was scanned using the existing pinned Trivy0.74.0 and
the preserved official DB updated2026-10-13T01:09:18Z, before its next update.
Input bytes and DB hashes remained unchanged. Report generation passed in
3.964 seconds; the vulnerability gate **fails** with **4 CRITICAL and65 HIGH
finding records**. Debian findings account for4 CRITICAL/54 HIGH; bundled
Node.js packages account for11 HIGH. No unfixed/package findings were hidden.
The separate admission command records rejection and exit1, not success.

The exact index/platform OCI referrer queries returned empty lists, and the
inspected legacy `.sig`/`.att` locations returned404. The index-linked SPDX and
SLSA statements were retrieved and their descriptor/subject hashes checked;
they do not supply a verified signature or approved publisher/builder identity.
This is a bounded search, not proof that no signature exists anywhere. Official
source mappings and Node archive correspondence do not authenticate the entire
builder image. Signature/build-source admission remains independently unresolved.

No builder container, dependency lifecycle, generator, UI or Vault source was
executed. No new Vault ELF/image, candidate scan, runtime or two-issuer result
exists. Missing approved Vault runtime UID/GID remains a separate runtime-image
condition; fixture100:1000 is not authority.

## Held build plan

Read-only independent review accepted the private `isolated-build-plan.md`'s
conditional stages, failure boundaries and current builder rejection. It did
not approve an executable recipe or authorize this rejected builder.
A viable replacement needs exact materials, approved signature/source authority,
a fresh zero-HIGH/CRITICAL full-image scan and actual tool/runtime compatibility.
No replacement or new trust root has been selected. Distroless Node22 was only
surveyed as an investigation lead; its debug runtime is not a validated full
UI build environment.

After builder admission, close enumer's own graph and a real pnpm10.22.0
offline frozen install with lifecycle scripts disabled and compatible optional
dependencies retained. Freeze the actual CLI/link identities and writable sets
before execution. Keep the previously reviewed15 enumer outputs, explicit
TypeScript5.6.3 client build, direct locked webpack/Ember invocation and complete
CE UI. Ember writes **http/web_ui**, as configured in ui/.ember-cli; it does
not write ui/dist. Do not use implicit pnpm run/exec installation, a minimal UI,
unreviewed hooks, tools/build.sh or testonly builds. Ember5.8's unsupported
status remains an unresolved supply concern.

Proposed containers use native arm64, a diagnostic non-root identity, network
none, no capabilities or privilege gain, a read-only root, read-only frozen
inputs and only declared new private writable paths. No host credentials or
Docker socket are mounted. Sequential stages retain the600-second bound;
proposed limits are4 CPUs/4GiB/512 PIDs. Per-stage writable byte/inode and log
limits still need concrete values and enforcement before recipe approval.
Every exit must recover the exact
recorded container and verify absence, without broad pruning. These are plan
constraints, not evidence that a container has run or a complete executable
recipe is ready.

The next acceptable result is an independently admitted exact builder plus
frozen store/tool recipes, then a new complete UI/CE diagnostic output with
derived-source identity and fresh scans. Production image ownership, supply
and consumption reviews still precede Vault execution. The existing diagnostic
Go/x-net authorization does not need to be requested again.

## Validation and Slice6 ledger

This turn changes documentation and private input/evidence only. Repository Go,
module and Contract inputs retain the prior matching503.355-second full-race,
vet and two Contract-lock evidence; those gates are not rerun for reporting.
The final checkpoint checks exact file hashes, Git state, private source and
remaining processes. No accepted lock, trust root, public Profile/provider hold,
frozen-R rule, production identity or old receipt is changed. No staging,
commit, push, publication or Vault process follows from this checkpoint.

1. Historical bounded Guest E: prior acceptance retained, no replay this turn.
2. Startup audit/real security boundary: ongoing; material recovery passed,
   current builder admission failed and blocks isolated execution.
3. Final live inventory, original16 scenarios and independent acceptance:
   incomplete.
4. Post-acceptance documentation/commit/push handoff: not started.

The later [builder selection checkpoint](product-v1-phase-6-vault-builder-selection.md)
records a different admitted private carrier, generator material closure and a
reviewed pnpm10.34.7 replacement proposal. This historical Debian builder
rejection remains unchanged; new generator/UI dependency findings separately
block complete builds.
