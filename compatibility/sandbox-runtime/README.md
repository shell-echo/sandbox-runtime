# Local Sandbox Runtime Contract

This directory records the immutable metadata for the repository-owned
Provider Contract. The Contract is MIT-licensed, lives under `contract/`, and
uses the namespace `urn:shell-echo:sandbox-runtime:provider-v1`.

The format-2 lock identifies the Contract tree, manifest, Provider Calling
Standard, OpenAPI, semantic rules, fixtures, and two content-derived
Conformance Suites. Validation reads these resources from this repository; it
does not clone or consume a caller's sources. External callers adapt to this
exact locked Contract.

| Item | Locked value |
| --- | --- |
| Contract revision | `9206e601f75a54db0b66969239d7e8cc5bcc8af9` |
| Contract tree | `c5e4221f2ceaaaad53c8038e1ebaacfe0c5a4daf` |
| Manifest digest | `sha256:23405c62747b6c678d2fcc84dfd885e435ab12771befdb29499b2e7367404da1` |
| Local Suite | `sandbox-provider@1.0.0`; profile `sandbox-runtime-provider-v1`; mode `repository-go-test`; 50 cases; `sha256:bf177a5bd2b4228605b3ebc311d25a1cc348d9548b2b5c2d333a0c69e71ca528` |
| Remote Suite | `sandbox-provider-remote@1.0.0`; profile `sandbox-runtime-provider-remote-discovery-v1`; mode `remote-http-black-box`; 6 cases; `sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0` |

The P2.6 release gate passes locally at implementation `3fe314a` and E2E lock
refresh `ae476fe`: the Contract verifier, clean VCS-built 50-case local
Runner, clean VCS-built six-case remote Runner against a separately started
local mTLS Provider, root and E2E race/shuffle and vet, parent-lock check, and
all eight E2E `-check` commands pass. This is repository-owned conformance
evidence within the boundaries below, not an independently implemented caller
qualification.

Run the verifier with:

```bash
go run ./cmd/verify-contract -source-root .
```

## Local Suite runner

The local runner must be a clean VCS-built binary. It reads its exact revision
and Go version from `debug.ReadBuildInfo`, and rejects a missing revision or
`vcs.modified=true`. Build and run it from a clean checkout:

```bash
runner_dir="$(mktemp -d)"
go build -buildvcs=true -o "$runner_dir/run-conformance" ./cmd/run-conformance
"$runner_dir/run-conformance" -source-root . -race -shuffle
```

The runner verifies the lock once, then executes the immutable 50-case snapshot
from a bounded, read-only `git archive` of the exact Runner revision. Run it
with `GOROOT` unset: it rejects any explicit value, invokes the default
`runtime.GOROOT()/bin/go`, and verifies `go env GOVERSION` against the build
identity. It resolves Git once from the initial `PATH` to an absolute,
symlink-resolved, regular executable and reuses that exact path for Contract
verification and the Runner archive. It clears Go path overrides and uses
`GOWORK=off`, `GOENV=off`, `GOTOOLCHAIN=local`, an empty `GOFLAGS`, and
`-mod=readonly`.

The output records Git's self-reported version and states that the host OS,
filesystem, initial Git selection, and Go and Git executables are trusted local
inputs. Path and version checks do not attest host-tool integrity.

Each case mapping declares an exact expected pass count. The `go test -json`
stream must show every matching test as a distinct, started, non-skipped pass
and the observed count must equal that declaration. Zero or unexpected extra
matches, a scaffold-only parent pass, a skip, failure, malformed evidence, or
cancellation fails closed. `go run ./cmd/run-conformance` is not a valid
substitute because the supported Go toolchain does not put VCS settings in that
generated executable.

## Remote discovery runner

The remote CLI requires all of the following: an HTTPS Provider origin, the
server CA, the client CA, one admitted client certificate/key pair, one denied
client certificate/key pair rooted in that same client CA, the TLS server name,
and the expected immutable Provider revision. Both client leaves must have
client-auth usage and one distinct absolute URI SAN.

```bash
go build -buildvcs=true -o "$runner_dir/run-remote-conformance" ./cmd/run-remote-conformance
"$runner_dir/run-remote-conformance" \
  -source-root . \
  -target https://provider.example.invalid:8443 \
  -ca /absolute/path/server-ca.pem \
  -client-ca /absolute/path/client-ca.pem \
  -client-cert /absolute/path/admitted-client.pem \
  -client-key /absolute/path/admitted-client-key.pem \
  -denied-client-cert /absolute/path/denied-client.pem \
  -denied-client-key /absolute/path/denied-client-key.pem \
  -server-name provider.example.invalid \
  -provider-revision 3fe314a012b808fe60dbd783d7c7c7121d3c548e
```

This six-case profile is read-only at the Contract route level and covers only
remote capability discovery. Its report sets `unsafe_method_probes_sent=true`
only after a POST, PUT, PATCH, or DELETE probe is actually written to the
discovery path. A written probe prevents a zero-side-effect claim for an
arbitrary non-conforming target. This is not the local 50-case Suite, protected
or mutating remote conformance, independent-caller interoperability, aggregate
conformance, multi-controller or multi-tenant evidence, HA, deployment, or
production readiness.
