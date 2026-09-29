# Phase 6 Slice 6 external image input checkpoint

This procedure reconstructs private, local-only OCI inputs for the Slice 6
candidate gate. It does not publish images, start services, establish registry
signature/provenance, or qualify a deployment. The authoritative identities
are the fixed registry index and platform manifest digests below. The
repository verifier reopens the raw index, selected manifest, config and all
compressed layers, and checks the ordered uncompressed diff IDs.

| Service image | Pinned registry index | linux/arm64/v8 manifest |
| --- | --- | --- |
| Vault | `docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2` | `sha256:3aae140ea5b73deaf10d70607194ab52ff80f4ebfc4ef4796ad1a7be5f4db682` |
| PostgreSQL | `postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28` | `sha256:2c942175a1255a9abe0366e48c1b401d9f50f835b04dfea13f111609b5530df7` |
| Valkey | `ghcr.io/valkey-io/valkey@sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd` | `sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e` |
| CoreDNS | `docker.io/coredns/coredns@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286` | `sha256:9a631b1e34491f93a35334bc02d8ae190f16224be41689c7f42cc1711a95fe3a` |

Prepare one absolute directory outside the checkout with mode 0700. Pull the
exact pinned indexes for `linux/arm64/v8`, then `docker image save` each to a
different file in that directory and set each file to mode 0600. Do not use a
tag, an operator-supplied manifest digest as authority, or an archive copied
into the source tree. The loader rejects duplicate paths and wrong platforms.
The action-history and Product PostgreSQL *services* share one image archive;
they remain distinct network, TLS and SQL identities.

On the observed Docker Desktop/containerd store, `docker image save` of Vault
contained only its index and selected manifest, omitting the config and all
seven layers. That export failed the verifier, as required. To reconstruct a
complete private Vault archive from the same pinned image:

1. Export the exact Vault index from Docker to a private OCI tar. Verify that
   `blobs/sha256/47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2`
   is present and SHA-256 hashes to its filename.
2. Use `crane` v0.22.1 as a downloader, not an identity authority, with
   `crane pull --format=oci --platform=linux/arm64` and the exact Vault index
   reference above. Its output is an OCI *directory*. Confirm that the
   selected manifest, its config and all referenced layer blobs are present.
3. Copy only the original raw index blob from the Docker archive into the OCI
   directory's `blobs/sha256/` path. Create a private tar of exactly the
   directory's `blobs`, `index.json` and `oci-layout` entries, with names
   relative to that directory and no `./` path prefix. Set mode 0600. The
   wrapper `index.json` is not treated as the registry index authority.
4. Run `TestPinnedExternalArchiveComponent/vault` with the private tar path
   and exact selected manifest digest, then the complete supply test below.
   Failure at any descriptor or layer requires a fresh download, not a
   replacement digest or weaker verification.

Set the eight `SANDBOX_RUNTIME_PHASE6_{VAULT,POSTGRES,VALKEY,DNS}_{ARCHIVE,SELECTED}`
environment variables to the four complete private tar paths and the four
selected manifest digests in the table. With the repository's locked Go
toolchain, run:

```bash
SANDBOX_RUNTIME_PHASE6_FULL_EXTERNAL_IMAGE_SUPPLY=1 \
  go test -tags=integration -run '^(TestPinnedExternalArchiveComponent|TestFullPinnedExternalImageSupply)$' \
  -count=1 -v ./internal/phase6profilebuilder

SANDBOX_RUNTIME_PHASE6_DOCKER_EXTERNAL_IMAGE_SELECTION=1 \
  go test -tags=integration -run '^TestDockerPinnedExternalImageSelections$' \
  -count=1 -v ./internal/phase6profilebuilder
```

The second opt-in test creates one stopped `--pull=never --network none`
container per pinned image, compares Docker's runtime store/index, selected
platform manifest, OCI config and rootfs diff IDs with the verified archive,
then removes the exact containers and anonymous volumes. It is component
evidence only: no Vault, PostgreSQL, Valkey or CoreDNS service is started,
and no network, TLS, least-privilege or 16-scenario Slice 6 gate passes from
these checks. A new source/image revision must repeat the affected checks.

The observed private archive outer SHA-256 values are recorded in the
[Slice 6 startup audit](audits/product-phase-6-slice-6-startup.md). A rebuilt
tar may have a different outer hash because tar metadata and ordering are
not the registry identity; the raw descriptor chain and layers must still
verify against the same pinned index and selected manifest. Keep the private
archives outside Git and transfer or rebuild them only under operator control.
