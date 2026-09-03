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
| Provider implementation | `cd33ba35c59bba62c48d13c0dcd08aeef5d9a434` |
| Contract namespace | `urn:shell-echo:sandbox-runtime:provider-v1` |
| Contract revision | `5096e71fb84fbec22aa3487a0e55a1b49602ab8b` |
| Contract tree | `859f76dc0e855a0c8abdbbb5648df100dabb4328` |
| Suite | repository-owned Provider v1, 48 cases |

`go.mod` points to the parent Provider checkout. The verifier refuses to run if
the Provider commit or Contract lock differs from the values above. A full
evidence run also refuses tracked or untracked harness changes and records the
exact enclosing repository commit in its manifest.

The lock now includes browser Contract authority/projection, the sandboxed
image/provenance publication implementation, the explicit arm64/v8 index
descriptor correction, the uncomposed Provider-local browser session
component, and the fail-closed Docker/private-relay adapter. The reference and
platform-candidate runners still execute only the coding/shell scenarios;
advancing this identity is not Browser external-caller E2E, restricted-egress,
aggregate conformance, or production evidence.

## Latest verified evidence

Hosted Reference E2E run `33732133556` and Platform Candidate E2E run
`33732133569` passed harness lock `e1de512` against Provider `cd33ba3` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their
artifacts are `reference-e2e-evidence-33732133556` (digest
`sha256:99f610aece673129923a36e176d11d90e10ca5587dec6a0c017b0db0a7a3ac34`)
and `platform-candidate-e2e-evidence-33732133569` (digest
`sha256:41b42b9f9fe7060e9ac1a74a676fe28cf89416bcdabb231fcefe95d111c1bf5d`).
Both manifests pin Contract revision `5096e71`, tree `859f76d`, and 48 Suite
cases. The latest local runs, `20260903T081108.412519000Z` and
`20260903T081149.245310000Z`, passed the same respective scenario sets with
harness/Provider lock `e1de512`/`cd33ba3` and runtime digest
`sha256:c52ed6549ee4f91f119b0c0b167e93dd488aa9566bd7f3e40d9289131150f595`.
These remain coding/shell regression and candidate-integration evidence only;
they contain no browser scenario.

## Previous hosted evidence before this lock update

Hosted Reference E2E run `33725665014` and Platform Candidate E2E run
`33725664854` passed harness lock `e7e4d57` against Provider `83a7884` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their
artifact digests are
`sha256:0b821ace9d7c358ab4e27621ea00358a0b6181efbeaf92dadc5d02143fcce709`
and
`sha256:b8af85f45206aa09b63e01fd1f173d4f39d819f87b75a5ac19c80a315aff4776`.

Hosted Reference E2E run `33724009124` and Platform Candidate E2E run
`33724009180` passed harness lock `58ed009` against Provider `c91d83f` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their
artifact digests are
`sha256:8f257b294d6deba1cb2f2c34819b3f56bcbffa10815d14364da089edf6971729`
and
`sha256:2636237004c4d35db8325a5deda5d37e5b312f9ff0255fb8af5588086386e0e8`.

Hosted Reference E2E run `33721442750` and Platform Candidate E2E run
`33721442749` passed harness lock `4db7c97` against Provider `99b8d36` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their
artifact digests are
`sha256:ac517e4c3add088550d53a39877fdb5f0fbd55dcc95d860d5d87ee798784b7e9`
and
`sha256:94f37525d0fece0571492b84bdba9f6f79b68a2e66022d4ce6be77d56d829db7`.

Hosted Reference E2E run `33712412443` and Platform Candidate E2E run
`33712412503` passed harness lock `6163de1` against Provider `9a5d225` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their
artifacts are `reference-e2e-evidence-33712412443` (digest
`sha256:aa7a6bebf51ac917a9d1fe5e238a57ef0f90ac9566dc652c6402405ec75befa4`)
and `platform-candidate-e2e-evidence-33712412503` (digest
`sha256:308016d3012d2e61ae68af8606523e6c8f2e4f2b76c80360f36321d1ebdbb147`).

Earlier Hosted Reference E2E run `33708670563` and Platform Candidate E2E run
`33708670564` passed Provider lock `4df7f22` with 15 initial and 5
reconstruction/resume coding/shell scenarios each. Their artifacts are
`reference-e2e-evidence-33708670563` (digest
`sha256:36596ce808833b12cfcab44277d1acc1715c559608c5e2b57293f00d5e3af961`)
and `platform-candidate-e2e-evidence-33708670564` (digest
`sha256:80e2828d0cabb613bf0cb683202690c9876f94d9d86a73018380cae3b2a88542`).
Both manifests pin Contract revision `5096e71`, tree `859f76d`, 48 Suite
cases, and the named linux/amd64 runtime image digest. These remain
coding/shell regression and candidate-integration evidence only; they contain
no browser scenario.

## Previous verified local evidence before this lock update

The following evidence was produced before the browser image component and
against the previous Provider baseline `24b2e36485c334634e561009850d1905ec3115d5`:

- reference run `20260902T065111.030014000Z` passed 15 initial and 5
  reconstruction/resume scenarios;
- platform-candidate run `20260902T065200.812211000Z` passed the same 15 and 5
  scenarios with its separately named candidate policy; and
- both manifests pin Contract revision `5096e71`, tree `859f76d`, 48 Suite
  cases, and linux/amd64 runtime image digest
  `sha256:93b6504a7ee1a78e46dbe9fc3e71a70eabf09f96834f5ab148d2bed9c558812c`.

These runs are coding/shell regression evidence only. They do not exercise the
Contract-authorized browser routes, a browser runtime, or a browser caller.

Hosted release baseline `13c6a57` passed that previous lock in Reference E2E run
`33602869956` and Platform Candidate E2E run `33602870006`. Their artifacts
have digests
`sha256:1b0ccc43b254041c618d58c1c14039162bbf1a31ecd22cbe5c72e64cefa6351e`
and
`sha256:958dee960d3503a20f987393307ae14c6d10b3adbf02d2684ed952a9a34b8b0c`,
respectively. Both manifests pin Provider `24b2e36`, Contract revision
`5096e71`, tree `859f76d`, 48 Suite cases, and coding/shell-only scenarios.
The preceding 38-case-lock runs remain `33591808946` and `33591808961` at
baseline `b72fc3b`.

The historical evidence above remains valid only for its named Provider and
harness locks. None of these runners contains a browser scenario.

## Previous verified evidence

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
The latest recorded lock-refresh run `33732133556` passed Provider `cd33ba3`
with harness `e1de512` and uploaded `reference-e2e-evidence-33732133556` with
digest
`sha256:99f610aece673129923a36e176d11d90e10ca5587dec6a0c017b0db0a7a3ac34`.
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
The latest recorded lock-refresh run `33732133569` passed Provider `cd33ba3`
with harness `e1de512` and uploaded
`platform-candidate-e2e-evidence-33732133569` with digest
`sha256:41b42b9f9fe7060e9ac1a74a676fe28cf89416bcdabb231fcefe95d111c1bf5d`.
