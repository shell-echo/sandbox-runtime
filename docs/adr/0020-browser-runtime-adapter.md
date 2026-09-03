# ADR 0020: Browser Runtime Adapter and Private CDP Relay

- Status: Accepted for the uncomposed P4 Browser runtime adapter slice
- Date: 2026-09-03

## Context

The signed Browser image fixed by ADR 0019 listens only on container loopback
`127.0.0.1:9222` and publishes no port. That is the required endpoint posture,
but it means a Provider process cannot dial CDP through a container IP. The
image contains upstream `socat` 1.8.0.3 at `/usr/bin/socat`; ADR 0018 recorded
that binary as inert because no image entrypoint or forwarder invoked it.

The Browser application now has a transport-neutral `browser.Runtime` port and
durable opaque-reference resolution, but the repository has no restricted
egress implementation or runtime provenance verifier. Docker `network=none`
would be useful for an image smoke test but does not satisfy the locked Browser
create authority, which requires a restricted network and an egress gateway.
Publishing port 9222, persisting a container IP, or treating a same-repository
fake as an egress gateway would weaken or misstate that boundary.

## Decision

Add an independent Docker implementation of `browser.Runtime`. It does not
reuse the coding/shell lifecycle Docker driver and does not compose Provider
HTTP routes, the caller-owned Gateway, or capability advertisement.

The adapter binds the exact publication from run `33724368530`:

- image
  `ghcr.io/shell-echo/sandbox-runtime-browser@sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f`;
- source `58ed0093816d3daa3000750013b8e5991ef4bcf7`;
- signer workflow
  `github.com/shell-echo/sandbox-runtime/.github/workflows/browser-image.yml`;
- hosted-runner-only verification and attestation `44912296`; and
- exactly `linux/amd64` and `linux/arm64/v8`.

Startup requires a caller-supplied provenance verifier and restricted-network
provisioner. There is no allow-all, static-success, default-bridge, host-network,
or `network=none` production fallback. The adapter also verifies the local
image's immutable digest, platform, entrypoint, user, work directory, absence
of exposed ports and command overrides, profile labels, source revision, and
seccomp label. Missing or mismatched evidence fails startup.

Every allocation creates a dedicated, deterministically named Browser
container with:

- UID/GID `1000:1000`, read-only root, `cap-drop=ALL`, and
  `no-new-privileges`;
- the exact checked-in seccomp JSON passed to Docker after digest validation;
- bounded no-exec tmpfs mounts at read-only `/inputs` and writable
  `/workspace`, `/outputs`, and `/tmp`;
- finite CPU, memory, PID, stop, and log limits;
- no published or exposed port and no caller-controlled command, environment,
  image, network, or mount field; and
- only the private Docker network attachment returned by the mandatory
  restricted-egress provisioner.

`Attach` creates a fresh non-TTY Docker exec of the fixed command
`/usr/bin/socat STDIO TCP4:127.0.0.1:9222,connect-timeout=5`. Non-TTY mode is
required because a PTY echoes and transforms bytes. Docker's multiplexed
stdout/stderr stream is demultiplexed; only stdout reaches the Gateway-facing
transport-neutral stream, while backend diagnostics are discarded. No relay
port, container address, backend ID, or Docker endpoint is returned or stored
in Provider-neutral state. For every attach, the adapter queries the private
`/json/version` document, validates the exact Browser version and loopback-only
`/devtools/browser/*` URL, opens a second relay, and completes an RFC 6455
upgrade before returning the raw established WebSocket byte stream. The
dynamic path is never persisted. Adapter-private state retains only the exact
allocation binding, backend resource identity, network lease, and readiness
needed for restart observation and cleanup.

## Release boundary

Focused tests may use fake provenance and network implementations to prove
adapter behavior, but those tests are component evidence only. A live adapter
integration requires a real restricted-egress provisioner and provenance
verifier; an unavailable dependency is recorded as unavailable, not replaced
with a weaker network and not reported as a passing Browser runtime gate.
Until a browser concurrency policy is added to Contract authority, the adapter
also accepts at most one live Browser allocation per sandbox.

Protected Browser handlers, Browser Gateway framing and caller authorization,
capability advertisement, independent Browser caller E2E, aggregate
conformance, multi-controller reliability, hostile multi-tenant isolation,
deployment, and production readiness remain separate open gates.

## Consequences

- The already published image does not change; the adapter activates one exact
  relay binary already covered by its immutable digest and provenance.
- The adapter can be tested and reviewed without exposing CDP or changing the
  Provider wire surface.
- Browser composition remains fail closed until real provenance and
  restricted-egress dependencies exist and pass their own evidence gates.
- Removing or replacing `socat`, changing its command, updating the image,
  loosening network policy, or publishing an endpoint requires a new review and
  fresh image/runtime evidence.
