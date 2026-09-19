# Product Phase 5 Desktop Slice 10 Evidence

Date: 2026-09-20

Implementation: `f23b16130c97e99d5d28008b01346779a0c681ee`

## Accepted boundary

Slice 10 adds bounded Product Desktop reconnect, resynchronization, restart
recovery, and slot-replacement behavior:

- reconnect uses a fresh encrypted one-use grant and rechecks the complete
  Product/Provider binding, generations, lease, fence, handoff, and expiry;
- migration 12 adds a five-second database-time lease to consumed Desktop
  grants. Exact continuous authority checks renew it, while minting revokes an
  expired crashed-Gateway lease before one-controller and quota admission;
- initial connect and in-grace recovery request full media resynchronization
  plus a keyframe, and stale disconnect timers cannot close a recovered peer;
- ordered `stream.resync` and `stream.configure` controls have a fail-closed
  rate bound. Configuration keeps negotiated codec/bitrate ceilings fixed,
  bounds dimensions/frame rate, and permits only `default` or `disabled`
  audio-output aliases;
- queued controls are tied to one connection epoch and input is revalidated
  against current display dimensions before execution; and
- Desktop close or slot replacement revokes grants and clears private handoff
  authority. Replacement additionally closes live sessions, retires the old
  binding, and produces exactly one next-generation provision intent.

## Real-store and concurrency evidence

The tagged Product PostgreSQL gate ran against a fresh disposable PostgreSQL
16 instance and passed migration application/replay, database-time Gateway
lease expiry, reconstructed-repository recovery, fresh-grant reconnect,
generation substitution denial, deterministic replacement, exact cleanup, and
all retained Product store tests. The disposable database was removed after
the gate.

The Desktop Gateway race loop ran ten shuffled repetitions and covered real
in-process WebRTC media/control, reconnect within grace, stale timer handling,
connection-epoch input rejection, current-resolution input validation,
resynchronization/configuration bounds, and backpressure closure.

## Validation

The implementation passed:

- `go test -race -shuffle=on -count=10 ./product/adapter/gateway`;
- `go test -race -shuffle=on -count=10 ./product/adapter/postgres`;
- `go test -tags=integration -race -shuffle=on -count=1 ./product/adapter/postgres`
  against fresh PostgreSQL;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- the Provider and Product Contract verifiers;
- the retained Product Phase 3 and Phase 4 evidence verifiers; and
- `git diff --check`.

## Evidence boundary

This is Product PostgreSQL and same-process Gateway component evidence. The
Desktop media/input implementation remains an injected test source. Slice 10
does not provide a real Provider media bridge, recording, development
templates, unified Web, production startup composition, capability
advertisement, independent-process release evidence, deployment, HA, hostile
multi-tenant isolation, or production readiness.
