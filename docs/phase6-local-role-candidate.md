# Phase 6 local role candidate recorder

This operator-only path records one already-built, digest-addressed Docker
image for a reviewed Slice 6 role deployment. It is a
`local-candidate-non-release` input to the same-host security gate, not a
published image, signature, SBOM, provenance receipt, running-role observation,
or production admission.

The repository checkout must be clean and committed, and Go 1.26.8 must be the
active toolchain. Build a selected target with
`profiles/phase6/local-role/build.sh <platform> <target>` and use its printed
`image=sha256:...` value. Create a private mode-0700 directory outside the
checkout, then run:

```bash
go run ./cmd/record-phase6-local-role-candidate \
  -source-root /absolute/clean/checkout \
  -deployment product-runtime \
  -platform linux/arm64/v8 \
  -image sha256:EXACT_LOCAL_STORE_DIGEST \
  -output /absolute/private/directory/product-runtime.json
```

The recorder requires the exact reviewed deployment→build-target mapping. It
does not accept an image tag, pull, rebuild, publish, sign, or prune. It creates
one stopped, networkless Docker observation container, reads its selected
platform manifest, saves a private OCI archive, checks its config and ordered
layers, independently rebuilds and byte-compares the executable, removes the
exact observation container, then creates two exclusive 0600 files:
`product-runtime.json` and `product-runtime.json.oci.tar`. A failure does not
issue a valid manifest. The manifest binds clean source inputs, image/selected
manifest/config descriptors, archive and rootfs chain, binary and build
context. Its loader recomputes those claims from the retained archive and
checkout; it rejects dirty source, tampering, wrong mode, unknown or duplicate
JSON members, and digest drift.

The complete Slice 6 gate must still inspect each final running role container,
retain separate raw Docker receipts, exercise all reviewed topology/scenarios,
and prove exact cleanup. Reusing one role image for multiple reviewed
deployments does not collapse their independent runtime or security checks.
