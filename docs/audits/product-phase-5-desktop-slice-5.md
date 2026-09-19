# Product Phase 5 Desktop Slice 5 Evidence

Date: 2026-09-19

Implementation: `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b`

## Accepted boundary

Slice 5 adds the Provider-local Desktop runtime composition without enabling
production startup or capability advertisement:

- `provider/desktop/driver/docker` selects only
  `profiles/desktop/image.LockedPublication`, requires a provenance verifier
  and restricted-network provisioner, persists adapter-private allocation
  state, enforces exact ownership and container isolation, probes the bounded
  broker, attaches through a fresh broker execution, and cleans only the exact
  retained receipt;
- `provider/desktop/reference` stores and resolves opaque
  `ref:desktop-session:*` authority in memory or an exclusively locked atomic
  file. Every attach/reconnect repeats expiry, revocation, succeeded-source,
  receipt, and generation checks before calling the runtime;
- the application composition uses the same durable registrar as handoff
  publisher and revoker. Close and expiry therefore durably revoke before
  runtime cleanup and require a later absence observation before success;
- `provider/desktop/usage` emits only
  `sandbox.desktop_session_milliseconds`, starting at successful handoff commit
  and stopping at the earliest durable revocation, endpoint termination,
  sandbox termination, or expiry; and
- the Desktop lifecycle readiness driver accepts only the exact Desktop
  runtime profile and restricted-egress policy identity.

The private attachment contains fixed profile, opaque display, geometry,
audio-presence, private-input-mode, generation, and observation-time fields.
It contains no container ID, network name/address, host path, Unix socket,
credential, public signaling document, or public media endpoint.

## Fault and recovery evidence

Race/shuffle component tests cover allocation replay, capacity and policy
rejection, foreign ownership, image/runtime/network drift, stale generation,
broker corruption, context cancellation, unknown create/remove outcomes,
restart recovery, fresh attach/reconnect, revoke-before-cleanup, exact absence,
file-registry corruption and locking, bounded usage retention, and earliest
revocation duration.

The real Docker transport gate passed on the development host's native
`linux/arm64/v8` engine against immutable image
`ghcr.io/shell-echo/sandbox-runtime-desktop@sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`:

```text
SANDBOX_RUNTIME_DESKTOP_ADAPTER_INTEGRATION=1 \
go test -tags=integration -count=1 \
  -run '^TestDesktopBrokerTransportIntegration$' \
  ./provider/desktop/driver/docker

ok  github.com/shell-echo/sandbox-runtime/provider/desktop/driver/docker  31.215s
```

It inspects the locked image, starts the real non-root/read-only/drop-all/
no-new-privileges/private-IPC finite-resource container, obtains two fresh
broker descriptions, removes the container, and confirms runtime absence. The
transport test deliberately uses `network=none`; it proves the private broker
transport and runtime cleanup, not a deployed restricted-egress gateway.
Restricted networking remains a mandatory fail-closed driver dependency and
is covered at its adapter boundary here; composed egress/security topology is
again exercised by the later Slice 14 and Slice 15 gates.

## Validation

The following pass on the implementation revision:

- `gofmt` on all changed Go sources;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- focused race/shuffle tests for Desktop application, driver, lifecycle,
  provenance, reference persistence/resolution, usage, and shared usage;
- tagged Desktop adapter integration compilation and the real native gate
  above;
- Provider and Product Contract lock verifiers;
- retained Product Phase 3 and Phase 4 evidence verifiers; and
- qualification profile, adapter-protocol, and report regressions.

## Non-claims

Slice 5 is Provider-local runtime/component evidence. The production command
still does not inject the Desktop graph and capability advertisement remains
empty. No Product network adapter/dispatcher, public signaling/media/control,
end-user grant, input/clipboard/transfer policy, recording composition,
development template, unified Web UI, independently implemented caller,
deployment, HA, hostile-multitenant, or production-readiness result follows.
