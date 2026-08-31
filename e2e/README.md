# sandbox-runtime E2E

Independent reference caller and deployment harness for the repository-owned
MIT `sandbox-runtime` Provider Contract. This is a separate Go module and
process boundary inside the Provider repository; it is not a same-package
integration test and does not require a second Git repository.

The black-box caller uses only mTLS, JWS, HTTPS, and WebSocket. A separate
reference deployment process composes exported `sandbox-runtime` Provider and
Gateway packages with explicit test policy. The caller never imports Provider
models, repositories, drivers, command packages, or test helpers.

## Locked input

| Item | Value |
| --- | --- |
| Provider implementation | `d58497e5359056858564b9ac663178958cf5a6d6` |
| Contract namespace | `urn:shell-echo:sandbox-runtime:provider-v1` |
| Contract revision | `22a148e2898477790512d5bb742605654ff00ebf` |
| Contract tree | `1a967c9c6ce9646c8431f6ee48699ec9f406a589` |
| Suite | repository-owned Provider v1, 38 cases |

`go.mod` points to the parent Provider checkout. The verifier refuses to run if
the Provider commit or Contract lock differs from the values above. A full
evidence run also refuses tracked or untracked harness changes and records the
exact enclosing repository commit in its manifest.

## Latest verified evidence

The clean implementation baseline
`b28923b25079245c3088993badb4831c44598494` passed the complete reference run
against Provider `d58497e5359056858564b9ac663178958cf5a6d6`. The ignored local
evidence directory is `evidence/20260831T025259.339167000Z`; its manifest
records the two commits, unchanged Contract identity, configuration digests,
and a locally built digest-pinned `linux/amd64` runtime image.

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
first hosted run `33351621726` failed because the local Docker image had no
registry RepoDigest; the image-ID digest fallback is fixed in `b28923b` and a
rerun is pending. A green run proves only the named reference caller scenarios;
it does not prove Agent Platform compatibility, aggregate conformance,
multi-controller reliability, hostile tenant isolation, deployment readiness,
or production readiness.
