# sandbox-runtime E2E

Independent reference caller and deployment harness for the repository-owned
MIT `sandbox-runtime` Provider Contract. This is a separate Go module and
process boundary inside the Provider repository; it is not a same-package
integration test and does not require a second Git repository.

The module also contains separately named Browser Gateway shared-capacity and
durable-revocation runners. They exercise only WSS, Gateway fixture processes,
and one real Redis-compatible authority. They pin Contract identity for context
but do not call or exercise the Provider API.

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
| Provider implementation | `b4d41c9a32b4ccf39edaba3fb8bf5ad239c1f945` |
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
descriptor correction, the Provider-local browser session
component, the fail-closed Docker/private-relay adapter, and the real GitHub
CLI/Sigstore provenance-verifier component, the restricted-egress provisioner,
immutable create-policy binding, protected Browser transport component, and
the caller-owned Browser Gateway boundary, followed by the default-disabled
Browser command/runtime graph and the process-local total/per-session Browser
Gateway connection-capacity component, plus the process-local Browser
public-edge connection and fixed-window request limiter, and the bounded
accepted-connection TLS 1.3/HTTP/1.1 listener with explicit HTTP limits. It now
also includes the authenticated-capacity port and its process-local atomic
global, tenant, and session memory reference component. ADR 0031 and Provider
commit `9434540` additionally add the Redis-compatible shared-capacity adapter;
Provider baseline `2ed5e68` and clean harness/Gateway source `ddbb2c4` pass its
separately locked local two-Gateway evidence run. Hosted harness/Gateway source
`de297e7` passes the same locked boundary in run `33949577876`. Both remain
separate from the Browser reference evidence track.
ADR 0032 and Provider `c0a55d1` additionally change the Gateway revocation port
to one exact-grant level-triggered watch and add a Redis-compatible
retained-tombstone adapter. Historical E2E lock/harness `59e08d5` passes the
latest local pre-refresh Browser `13+5`, Reference `15+5`, Candidate `15+5`,
and shared-capacity `10/10` regressions. These runs do not include the separate
two-Gateway plus independent revoker durable-revocation caller scenario.
Harness/Gateway source `e952ef9` adds that independent runner. Clean local
`linux/arm64` run `20260905T095109.569973000Z` and hosted `linux/amd64` run
`33959122456` each pass all seven locked scenarios.
ADR 0033 and Provider `b4d41c9` subsequently add downstream CDP fencing ports,
the Redis-compatible action-fence adapter, private ingress component, and
fail-closed Browser composition. Advancing this E2E lock permits the existing
regression workflows to consume that Provider implementation; it is not the
separate two-Gateway/unique-ingress/real-Chromium ADR 0033 caller gate.
The latest verified hosted regressions before this lock refresh used harness
`c7fe24d` and Provider `c0a55d1`: Reference `33955436969`, Candidate
`33955437046`, Browser `33955436984`, and shared capacity `33955436968`. Each
retains its existing evidence boundary.
This Provider identity also includes the GitHub Actions migration from Node 20
action runtimes to Node 24 action runtimes. That infrastructure update adds no
Browser behavior, caller compatibility, or production-readiness evidence.
The reference and platform-candidate runners still execute only the
coding/shell scenarios; advancing this identity records regression coverage
only and is not Browser external-caller E2E, aggregate conformance, or
production evidence.

## Browser reference runner

`cmd/browser-e2e` runs a separate Browser-only reference stack and
`cmd/browser-caller` process. The caller has no Provider implementation import
and communicates only through mTLS/JWS HTTPS and the caller-owned Browser
WebSocket Gateway. The stack uses the locked signed Browser image, real GitHub
OIDC/Sigstore provenance verification, restricted egress, and durable
single-controller state.

From a clean committed checkout with Docker and authenticated `gh` available:

```bash
cd e2e
go run ./cmd/browser-e2e -check
go run ./cmd/browser-e2e -evidence-root evidence/browser
```

The run exercises the initial and reconstructed Browser lifecycle/session,
opaque handoff, CDP, allowed/denied egress, Gateway authorization expiry,
revocation, concurrent same-session capacity/release, authenticated
wrong-origin pre-upgrade rate rejection and recovery, TLS downgrade rejection,
slow/oversized header rejection, listener saturation/recovery, duration usage,
and cleanup paths. The Browser-only reference stack
advertises the exact locked Browser profile required by lifecycle admission;
the production command remains default-disabled and does not advertise it. A
passing run is Browser reference external-caller evidence only; it is not
aggregate conformance, real Agent Platform compatibility, hostile multi-tenant
isolation, deployment, or production readiness. ADR 0026 defines the exact
boundary.

No Browser run is recorded as verified evidence until the committed harness
passes this command and emits its manifest. Hosted execution is isolated in
`.github/workflows/browser-e2e.yml` and publishes a separately named artifact.

## Shared-capacity runner

`cmd/shared-capacity-e2e` runs the independently named
`Browser Gateway shared-capacity black-box evidence` profile. It starts one
pinned Valkey container, provisions the locked policy once, then starts two
independent Gateway OS processes and independent black-box caller processes.
The callers communicate only over TLS 1.3 WSS and do not import Provider
implementation packages.

From a clean committed checkout with Docker available:

```bash
cd e2e
go run ./cmd/shared-capacity-e2e -check
go run ./cmd/shared-capacity-e2e -evidence-root evidence/shared-capacity
```

The lock in `shared-capacity.lock.json` fixes the Provider adapter revision,
Valkey index and native amd64/arm64 manifests, policy, Lua identities, two
Gateway processes, and ten scenarios. The scenarios cover simultaneous
global/tenant/session contention, unaffected-tenant service, renewal, confirmed
loss, Gateway crash reclamation, stale-owner fencing, renew/release cleanup,
retained-store outage recovery, and evidence sanitization. Shared-capacity
rejection occurs after WebSocket upgrade and is observed as a normal `1000`
close; the HTTP `429` plus `Retry-After` behavior belongs only to the separate
pre-upgrade edge limiter.

A passing run is real-backend, two-Gateway Browser Gateway shared-capacity
black-box evidence only. It uses a private echo resolver and does not exercise
Provider routes, Contract cases, a Browser/CDP runtime, image provenance,
restricted egress, artifacts, or usage. It also does not establish Valkey
provenance, HA/failover consistency, durable distributed revocation, downstream
fencing, Provider multi-controller reliability, hostile multi-tenant isolation,
real Agent Platform compatibility, deployment readiness, or production
readiness. Hosted execution is isolated in
`.github/workflows/shared-capacity-e2e.yml`; artifacts are uploaded only after
the run's sanitization checks pass.

## Durable-revocation runner

`cmd/durable-revocation-e2e` runs the independently named
`Browser Gateway durable distributed revocation black-box evidence` profile.
It starts one pinned retained Valkey authority, two independent Gateway OS
processes, two independent black-box caller processes, and one independent
revoker/control process. The revoker uses only the exported revocation writer
and Redis-compatible adapter ports; callers have no Provider dependency.

From a clean committed checkout with Docker available:

```bash
cd e2e
go run ./cmd/durable-revocation-e2e -check
go run ./cmd/durable-revocation-e2e \
  -evidence-root evidence/durable-revocation
```

The lock fixes Provider `b4d41c9`, the Valkey index and native platform
manifests, 10-minute test grants, 100 ms revocation polling and operation
timeouts, a 2-second propagation/outage bound, local capacity `16/8/4`, a
one-reconnect upper bound with 10 ms backoff, and exactly seven scenarios. The
scenarios prove active exact-grant disconnect on both Gateways, pre-resolution
rejection, retained rejection after both Gateway reconstructions, exact-grant
scope while another same-session grant and another tenant remain active,
store-outage failure closure, recovery without resurrection, bounded
propagation, no revocation/outage reconnect, and sanitized evidence.

A passing run closes only ADR 0032's durable exact-grant caller gate. The
private echo fixture is not Browser/CDP, and Contract/tree/48-case identity is
metadata with `exercised=false`. The result does not establish downstream CDP
fencing, Valkey provenance or HA/failover, ACL role separation, Provider API or
real Agent Platform compatibility, Provider multi-controller reliability,
hostile multi-tenant isolation, deployment readiness, or production readiness.

## Latest verified evidence

The latest verified local regressions before this lock refresh ran against
Provider `c0a55d1` and harness `59e08d5`: Browser run
`20260905T080015.795386000Z` (`13+5`), Reference
run `20260905T080530.577843000Z` (`15+5`), Platform Candidate run
`20260905T080623.861033000Z` (`15+5`), and shared-capacity run
`20260905T080725.227680000Z` (`10/10`, `linux/arm64`). The Browser reference
still uses one process-local memory revocation authority; shared-capacity still
uses a private echo fixture and does not exercise revocation. Therefore none is
the ADR 0032 durable distributed revocation caller gate.

The latest verified hosted pre-refresh Reference run `33955436969` passes 15+5,
and its artifact
`reference-e2e-evidence-33955436969` has digest
`sha256:68642bb9810b397fada89bdb2666c11d46ddc0961eec6d6fd7d5e826e7336a70`.
Platform Candidate `33955437046` passes 15+5 and its artifact digest is
`sha256:2b745f256e4a0e1bdfa46c5129b1d92548a6f7afd2630a0c0720eb552ed35147`.
Browser Reference `33955436984` passes 13+5 and its artifact digest is
`sha256:a5b0be338190b39f16c27e2a7b31ba983022fc8da8f60fa23c9d4fdce1834173`.
Shared Capacity `33955436968` passes 10/10 on `linux/amd64` and its artifact
digest is
`sha256:d99d76374c745fb9a7adcc9b7e09e1f24963641e7d86b277a9a0647b870acdc2`.
All manifests pin harness `c7fe24d`, Provider `c0a55d1`, and the same locked
Contract/tree/48 cases; the shared-capacity manifest retains
`contract.exercised=false`. These are the same four distinct regression tracks,
not the ADR 0032 independent-revoker caller gate.

The post-refresh hosted runs pin harness `17ed6ca` and Provider `b4d41c9` and
pass their existing scenario sets on `linux/amd64`: Reference `33970773414`
passes 15+5 with artifact digest
`sha256:de2c6f2d31d9dd5a8323d82560bf0f314970c8e1825d815d224d48aac2dcba16`;
Platform Candidate `33970773345` passes 15+5 with digest
`sha256:546c3ecd6f2cd23a629ab53eb61bbe23fa7361c8440297c0fb039886802d7bc0`;
Browser Reference `33970773330` passes 13+5 with digest
`sha256:38bb2d7edd0cf04350a3eb7974526296daf4b0cd58da7637ad889e4490c8d866`;
shared capacity `33970773388` passes 10/10 with digest
`sha256:2350e3fbed3801366ade3bb4ed204545c1b0f55037a2dc7148de2ef4952e4216`;
and durable revocation `33970773353` passes 7/7 with digest
`sha256:062bfea835758424eb399f22f63b78656b323c379d26e5cbaa78a9343fcc4eb9`.
The shared-capacity and durable-revocation manifests retain
`contract.exercised=false`. None of these unchanged scenario sets exercises the
ADR 0033 two-Gateway/unique-ingress/real-Chromium downstream action-fence gate.

Clean local durable-revocation run
`evidence/durable-revocation/20260905T095109.569973000Z` passed all seven
scenarios on `linux/arm64` against harness/Gateway `e952ef9` and Provider
`c0a55d1`; Gateway A/B closed 72/72 ms after revoke acknowledgement. Hosted run
`33959122456` passed the same seven scenarios on `linux/amd64`; downloaded run
`20260905T095228.504289461Z` contains exactly seven sanitized files and records
97/99 ms propagation. Artifact
`browser-durable-revocation-e2e-evidence-33959122456` has GitHub digest
`sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`.
Both manifests pin Contract/tree/48 cases as metadata with
`contract.exercised=false`, Valkey provenance as unestablished, and ACL role
separation as false. These are durable-revocation Gateway/Valkey caller results,
not Provider API, Browser/CDP, downstream-fencing, real-platform,
multi-controller, hostile multi-tenant, deployment, or production evidence.

Clean local shared-capacity run
`evidence/shared-capacity/20260905T061037.558537000Z` passed all 10 scenarios on
`linux/arm64` against harness/Gateway source `ddbb2c4` and Provider baseline
`2ed5e68`. It used two independent Gateway OS processes and Valkey index
`sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
with arm64 child
`sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e`;
the policy fingerprint is
`1b29321807530907a8407cd6d33bdefbbb980fd7cb0b297592181a2333a8bacd`.
The manifest records 48 Suite cases only as locked metadata and explicitly sets
`contract.exercised=false` and Valkey `provenance_not_established=true`.
Capacity rejection occurs after WebSocket `101` as a normal `1000` close, not
as HTTP `429`. This run uses a private echo resolver and does not exercise the
Provider API, a real Browser/CDP runtime, image provenance, restricted egress,
artifacts, or usage; it is not hosted, HA/failover, durable distributed
revocation, downstream fencing, Provider multi-controller, hostile
multi-tenant, real Agent Platform, deployment, or production evidence.

Hosted Browser Shared Capacity E2E run `33949577876` independently passed all
10 scenarios on `linux/amd64` against harness/Gateway source `de297e7` and
Provider `2ed5e68`. Artifact
`browser-shared-capacity-e2e-evidence-33949577876` has GitHub digest
`sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`.
Downloaded run `20260905T062246.271594332Z` contains exactly six sanitized
files: one manifest, one report, two audit logs, and two observation logs. All
10 report entries pass. The audits contain 22 `authorized`, 22 `connected`, 18
`client_closed`, five `capacity_rejected`, two `capacity_lost`, and two
`capacity_unavailable`; observations contain 22 `resolve` and 22 `dial`.
The manifest pins Valkey index
`sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
and amd64 child
`sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478`,
but records `provenance_not_established=true`. Contract/tree/48 cases remain
metadata with `contract.exercised=false`. The private echo fixture does not
exercise Provider API, real Browser/CDP, image provenance, restricted egress,
Provider artifact/usage, HA/failover, durable distributed revocation,
downstream fencing, Provider multi-controller, hostile multi-tenant, real Agent
Platform, aggregate, deployment, or production behavior.

Hosted Browser Reference run `33940332911` passed harness `6b01b75` against
Provider `997fb0d`: all 13 initial and 5 process-reconstruction scenarios
passed on `linux/amd64`, including the authenticated process-local memory
capacity path. Artifact `browser-reference-e2e-evidence-33940332911` has digest
`sha256:f4133967b6e573c701b82c72dc4d101febd4e6b28199e188fa0c8db049bff9ae`.
This remains single-Gateway process-local Browser reference evidence; it is not
the separately locked Redis shared-capacity runner or production evidence.

Hosted Browser Reference run `33857739150` passed harness `7a20d9d` against
Provider `b8f8941`: all 13 initial and 5 process-reconstruction scenarios passed
on `linux/amd64`. In addition to the prior capacity and wrong-Origin edge
scenarios, the black-box caller rejects TLS 1.2, negotiates TLS 1.3 with
HTTP/1.1, rejects slow and oversized headers before the handler, fills the
accepted-connection limit, and proves recovery after release. The 20-record
Gateway audit keeps the existing six `authorized`, six `connected`, four
`client_closed`, and one each `capacity_rejected`, `denied`, `expired`, and
`revoked` events; it contains no edge grant, endpoint, token, credential, CDP,
or payload field. This is hosted Browser reference external-caller evidence for
process-local service and listener/TLS/HTTP bounds only; partition-aware shared
or distributed capacity, durable distributed revocation, production
advertisement, real Agent Platform, aggregate conformance, multi-controller,
hostile multi-tenant, deployment, and production gates remain open. Artifact
`browser-reference-e2e-evidence-33857739150` has digest
`sha256:94bcdfa53b667d4a6bc17fd6714cc9895e8402b830b8c6425c604c835f9228f`;
its inspected run directory is `20260904T091942.992885726Z`. The clean local
`linux/arm64` precursor is `20260904T091156.303717000Z` on harness `35cf068`
against the same Provider implementation.

The preceding hosted Browser Reference run `33854020809` passed 12+5 against
harness/Provider `e7e7f03`/`44ea2ee` and remains the historical pre-upgrade
service-limit baseline. Its artifact digest is
`sha256:b081ce8a3bf7e3e0c37e4bf036630483735c3812eeaf24d311048ff0a9122779`.

The preceding hosted Browser Reference E2E run `33846603547` passed harness
`28a9a5e` against Provider `7b062e6`: all 11 initial and 5
process-reconstruction scenarios passed on `linux/amd64`. Its manifest pins
Contract revision `5096e71`, tree
`859f76d`, 48 Suite cases, the signed Browser image
`sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`,
and support image
`sha256:5b5b721750a9450682f11c73f3cb1f3c0eb216f812329dfe75f9058a93d635a0`.
Artifact `browser-reference-e2e-evidence-33846603547` has digest
`sha256:b024225aa3545fa56a7cc5113f29c0817a86ebc70c3976e10d81bf3507546cba`;
its run directory is `20260904T065835.995038539Z`. The added scenario holds one
CDP connection, observes a second same-session grant rejected for capacity
without disrupting the first connection, then connects a replacement after
release. The 20-record Gateway audit contains exactly one
`capacity_rejected` event and only bounded metadata. The sanitized evidence
otherwise contains the manifest, two reports, and bounded stack/caller logs.
This is process-local post-authorization capacity plus Browser reference
external-caller evidence, not the newer pre-upgrade edge scenario, distributed
capacity/revocation, production
advertisement, real Agent Platform, aggregate conformance, multi-controller,
hostile multi-tenant, deployment, or production evidence.

Hosted coding/shell Reference run `33857739105` and Platform Candidate run
`33857739189` passed the respective 15+5 scenario sets against the current
harness/Provider lock `7a20d9d`/`b8f8941`. Their artifacts are
`reference-e2e-evidence-33857739105` (digest
`sha256:b9cbf768e7d7b1241643f309cd08cef69efe8c7d9b3a464c3da953f9d03adbb7`)
and `platform-candidate-e2e-evidence-33857739189` (digest
`sha256:61cf80c48b7103418f66acb0e370f19b60b2685271f2bb4a15f68547e4041bbb`).
The candidate result covers only its named shadow/selection/rollback/drain
policy. Neither coding/shell run contains a Browser scenario. Clean local
Reference run `20260904T081521.464863000Z` and Candidate run
`20260904T081706.648122000Z` each pass 15+5 scenarios against the earlier
harness/Provider `249cdd4`/`44ea2ee`; both pin runtime digest
`sha256:bcd5dbff8b2d108ee7dab464a85ee7d39ef74a8616a6af73a94ebb10ff8eaf75`.
These remain reference coding/shell and candidate integration evidence,
respectively, not Browser or real Agent Platform evidence.

The preceding hosted Browser Reference E2E run `33838215924` passed harness
`79fee2b` against Provider `f760369` with 10 initial and 5 reconstruction
scenarios. Artifact `browser-reference-e2e-evidence-33838215924` has digest
`sha256:4acfbc97c0c1f64e987b00870849a2244e33596918d08e659385c428310843ea`.
It established the complete Browser path before the capacity scenario was
added and remains historical evidence for its named lock.

The preceding hosted coding/shell Reference run `33838215917` and Platform
Candidate run `33838215882` passed 15+5 against harness/Provider
`79fee2b`/`f760369`. Their artifact digests are
`sha256:77cd06014bc9ddf4c41130b1ccaf7b35210ebfbedf075662190500e708d23c2e`
and `sha256:9ad455bba6d61a082c2a5136fcf19c4609db6c759f035a0e5299ecc85f31e23e`,
respectively. These remain historical coding/shell regression and candidate
integration evidence only.

The preceding hosted Reference E2E run `33760609272` and Platform Candidate run
`33760609231` passed harness lock `a2721ad` against Provider `b8423f5` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their
artifacts are `reference-e2e-evidence-33760609272` (digest
`sha256:1f8699b9f1dbc1169dd0539e78c349476889cd40c7984260ebc761c78611f70a`)
and `platform-candidate-e2e-evidence-33760609231` (digest
`sha256:d59a779678a79597859afa1d112a09fcb69e2b526519f2d9298dafe5f137bc9e`).
Both manifests pin Contract revision `5096e71`, tree `859f76d`, and 48 Suite
cases. The preceding local runs, `20260903T091011.164430000Z` and
`20260903T091045.591005000Z`, passed the same respective scenario sets with
harness/Provider lock `330f629`/`9390554` and runtime digest
`sha256:a5e7f2dd16bb091f39db3bc6bd98747742ff9902dd2977c4ca6d07d425236291`.
The hosted Reference and Candidate manifests record runtime digests
`sha256:fc5f6d33e3f12bf847cd74316248b8b4c9c06681d225ff172fb4b10a5ca49fc3`
and `sha256:1d3e65e68efc5cb88b6883c765191e754a4f57589241da9790ff7f78309d710c`,
respectively. Their artifact run directories are
`20260903T132114.460630529Z` and `20260903T132112.274851473Z`.
These remain coding/shell regression and candidate-integration evidence only;
they contain no browser scenario.

## Previous hosted evidence

Hosted Reference E2E run `33747803507` and Platform Candidate E2E run
`33747803514` passed harness lock `7f15628` against Provider `7e60340` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their artifact
digests are
`sha256:c0cf1f430bef0f354423412a15db0de5b6fce0201c3a583402b7fa9dcfc233ad`
and
`sha256:3f85c05e23d84f00d88b41302f7d8fd401579bd7ab07b2464d1f346388eb1f5c`.

Hosted Reference E2E run `33737531617` and Platform Candidate E2E run
`33737531705` passed harness lock `330f629` against Provider `9390554` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their artifact
digests are
`sha256:1a7c63d60c3dc61e9acd3057b9218ca85269d61e53157222a93458c4372746fe`
and
`sha256:52ad3fcd3c5c1477be06bc270c9ace9e5988e737d7c4d475ce22ee7267af0ab0`.

Hosted Reference E2E run `33732133556` and Platform Candidate E2E run
`33732133569` passed harness lock `e1de512` against Provider `cd33ba3` with 15
initial and 5 reconstruction/resume coding/shell scenarios each. Their
artifact digests are
`sha256:99f610aece673129923a36e176d11d90e10ca5587dec6a0c017b0db0a7a3ac34`
and
`sha256:41b42b9f9fe7060e9ac1a74a676fe28cf89416bcdabb231fcefe95d111c1bf5d`.

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

This module keeps independent evidence tracks. The reference runner proves the
P2.5i coding/shell external-caller gate through real sockets and processes,
mTLS/JWS admission, lifecycle, exec, terminal Gateway, artifact/usage, restart,
expiry, endpoint non-disclosure, and negative cross-tenant authorization. The
Browser runner proves only its locked Browser reference scenarios. The
shared-capacity runner proves only its WSS/Gateway/Valkey scenarios and does not
exercise the Provider Contract. The durable-revocation runner proves only its
retained exact-grant WSS/Gateway/Valkey scenarios and likewise records Contract
identity as unexercised metadata.

It does not prove compatibility with `agent-blueprints`, production identity
infrastructure, downstream CDP fencing, Valkey provenance/HA, multi-controller
operation, hostile tenant isolation, deployment readiness, or production
readiness.

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
The latest lock-refresh run `33857739105` passed Provider `b8f8941` with
harness `7a20d9d` and uploaded `reference-e2e-evidence-33857739105` with digest
`sha256:b9cbf768e7d7b1241643f309cd08cef69efe8c7d9b3a464c3da953f9d03adbb7`.
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
The latest lock-refresh run `33857739189` passed Provider `b8f8941` with
harness `7a20d9d` and uploaded
`platform-candidate-e2e-evidence-33857739189` with digest
`sha256:61cf80c48b7103418f66acb0e370f19b60b2685271f2bb4a15f68547e4041bbb`.

`../.github/workflows/shared-capacity-e2e.yml` independently verifies the
shared-capacity lock, runs the module race/vet gates, and executes the pinned
Valkey plus two-Gateway black-box runner. It publishes
`browser-shared-capacity-e2e-evidence-<run-id>` only after the E2E command and
its sanitization checks succeed. A green run does not change the Provider
Contract, real Agent Platform, HA, multi-controller, multi-tenant, deployment,
or production-readiness status.
Hosted run `33949577876` passed this workflow on `linux/amd64` and uploaded
`browser-shared-capacity-e2e-evidence-33949577876` with digest
`sha256:6e938a1549f3ffe3b7a08cf9aa7cd58639f3d058f935c6da1e57dad45ffeb423`.

`../.github/workflows/durable-revocation-e2e.yml` independently verifies the
durable-revocation lock, runs the module race/vet gates, and executes the pinned
Valkey plus two-Gateway/two-caller/independent-revoker runner. Hosted run
`33959122456` passed on `linux/amd64` and uploaded
`browser-durable-revocation-e2e-evidence-33959122456` with digest
`sha256:1384a4504725c90717a3a8da058713fb1b8ed763f2c941b961811eb8370b8600`.
Its green status is evidence only for the named ADR 0032 caller boundary.
