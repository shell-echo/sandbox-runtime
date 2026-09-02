# sandbox-runtime E2E

Independent reference caller and deployment harness for the repository-owned
MIT `sandbox-runtime` Provider Contract. This is a separate Go module and
process boundary inside the Provider repository; it is not a same-package
integration test and does not require a second Git repository.

The black-box caller uses only mTLS, JWS, HTTPS, and WebSocket. A separate
reference deployment process composes exported `sandbox-runtime` Provider and
Gateway packages with explicit test policy. The caller never imports Provider
models, repositories, drivers, command packages, or test helpers.

`cmd/platform-e2e` runs an additional Agent Platform candidate mode. Its
`platform-caller` process owns a bounded candidate Run/ProviderRevision policy,
performs live capability/request shadow checks, and then invokes the same
black-box wire caller. This is a candidate integration harness only; it does
not represent the separately owned Veronica Application or close the real P3
platform gate.

## Locked input

| Item | Value |
| --- | --- |
| Provider implementation | `24b2e36485c334634e561009850d1905ec3115d5` |
| Contract namespace | `urn:shell-echo:sandbox-runtime:provider-v1` |
| Contract revision | `5096e71fb84fbec22aa3487a0e55a1b49602ab8b` |
| Contract tree | `859f76dc0e855a0c8abdbbb5648df100dabb4328` |
| Suite | repository-owned Provider v1, 48 cases |

`go.mod` points to the parent Provider checkout. The verifier refuses to run if
the Provider commit or Contract lock differs from the values above. A full
evidence run also refuses tracked or untracked harness changes and records the
exact enclosing repository commit in its manifest.

The lock now includes browser Contract authority and projection. The reference
and platform-candidate runners still execute only the coding/shell scenarios;
advancing this identity is not browser runtime, browser caller, or browser E2E
evidence.

## Latest historical verified evidence

The previous lock-refresh baseline `2f165f9eb023392c1b6fb33845549f27e7364734`
passed the complete reference run against Provider
`e5d7324ef1d4508b8b0c474fe5ead47edd6f5146`. The ignored local evidence
directory is `evidence/20260902T035608.264731000Z`; its manifest records the
two commits, the previous Contract identity, configuration digests, and a locally
built `linux/amd64` runtime image pushed to a uniquely labeled temporary
`registry:2` and addressed by its immutable named manifest digest.

All 15 initial scenarios and all 5 reconstruction/resume scenarios passed.
This is the P2.5i reference external-caller result only, within the evidence
boundary below.

## Evidence boundary

This project is intended to prove the P2.5i reference external-caller gate:
real sockets and processes, mTLS/JWS admission, lifecycle, exec, terminal
Gateway, artifact/usage, restart, expiry, endpoint non-disclosure, and negative
cross-tenant authorization.

It does not prove compatibility with `agent-blueprints`, production identity
infrastructure, distributed revocation, multi-controller operation, hostile
tenant isolation, deployment readiness, or production readiness.

Current implementation status is tracked in [../docs/STATUS.md](../docs/STATUS.md).

## CI Publication

`../.github/workflows/reference-e2e.yml` runs this module from the Provider
checkout. It verifies the locked Contract, runs the harness race/vet gates, and
executes the Docker reference run before uploading sanitized evidence. The
hosted runs `33351621726`, `33352179181`, and `33352689522` failed because
locally built Docker images had no usable named `RepoDigest`. The temporary
registry fix enabled run `33377404561`, which passed the first 11 initial
scenarios but then exposed a caller-side false negative: one Gateway revocation
read did not drain a queued PTY frame before close. The caller now drains frames
until close within a bounded timeout. Hosted run `33379217800` then passed all
15 initial and 5 restart/resume scenarios on commit `555436c` and uploaded
artifact `reference-e2e-evidence-33379217800` with digest
`sha256:68250a85683dcbd8f01397d7373e98215382379ff895c0a58692de23c1880733`.
A green run proves only the named reference caller scenarios;
it does not prove Agent Platform compatibility, aggregate conformance,
multi-controller reliability, hostile tenant isolation, deployment readiness,
or production readiness.

`../.github/workflows/platform-candidate-e2e.yml` independently verifies the
candidate mode, runs the same race/vet gates, executes `cmd/platform-e2e` with
Docker, and uploads `platform-candidate-e2e-evidence-<run-id>`. Its artifact and
workflow name deliberately remain separate from reference caller evidence. A
green candidate workflow proves only candidate integration, not compatibility
with the real Veronica Application or any production gate.

Hosted run `33460370618` passed all 15 initial and 5 restart/resume candidate
scenarios on workflow baseline `c7ff5eb`. Artifact
`platform-candidate-e2e-evidence-33460370618` has digest
`sha256:54f0aea847dcb0b1808c6c902f1465979a3ec4362d52ab8884187e85ea6343f7`.
