# Local Sandbox Runtime Contract

This directory records the immutable metadata for the repository-owned
Provider Contract. The Contract is MIT-licensed, lives under `contract/`, and
uses the namespace `urn:shell-echo:sandbox-runtime:provider-v1`.

The lock identifies the Contract tree, manifest, OpenAPI, semantic rules,
fixtures, and Conformance Suite. Validation reads these resources from this
repository; it does not clone or consume Agent Platform sources.

Run the verifier with:

```bash
go run ./cmd/verify-contract -source-root .
```
