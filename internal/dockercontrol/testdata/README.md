# Coding OCI metadata fixture

`coding-oci-arm64-v8/` contains exact raw public OCI index, selected manifest,
and config bytes from the digest-pinned Coding image. The opt-in recovery test
verifies the cached archive's full descriptor and layer chain before writing
these three files. Tests re-verify their locked digests; the full image archive
is intentionally not committed.
