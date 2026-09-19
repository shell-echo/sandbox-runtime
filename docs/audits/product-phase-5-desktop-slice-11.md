# Product Phase 5 Desktop Slice 11 Evidence

Date: 2026-09-20

Implementation: `c5b045abc5192b76b7d615ddbb0858b998ef98d5`

## Accepted boundary

Slice 11 composes required Desktop content recording into the existing Product
recording authority and public Desktop Gateway:

- Desktop signaling accepts one bounded explicit consent reference and returns
  the exact selected recording mode. Required recording initialization occurs
  before the private media source opens; missing consent/recorder, failed
  initialization, or live recorder loss fails closed without downgrade;
- bounded VP8 and optional Opus RTP plus input, resynchronization, and stream
  configuration events are serialized into immutable encrypted segments.
  Concurrent media/control timestamps are normalized monotonically and every
  stored segment is linked to its predecessor digest;
- control events retain only closed action kind/event/touch-count, sequence,
  display, and public audio-output metadata. Clipboard text/results, transfer
  paths, transfer IDs/digests, private Provider coordinates, and tickets are
  not retained as control metadata or ordinary audit content;
- the existing Product catalog and recording service enforce owner-only reads
  and replay, active/byte quotas, chained-digest replay validation, retention
  expiry, and encrypted-object deletion; and
- PostgreSQL recording admission accepts `media` only for Browser Live or
  Desktop sessions and rejects unknown recording types. No migration or
  Provider Contract change is required.

## Real-store and concurrency evidence

The tagged Product PostgreSQL package ran against a fresh disposable
PostgreSQL 16 instance. The Desktop-specific case races two required recording
starts under a one-active-recording quota and observes exactly one winner. It
then records video, audio, minimized clipboard/transfer/configuration/resync
events, finalizes and owner-replays the stream, rejects a different owner,
verifies segment digest linkage, rejects a tampered digest, and confirms that
clipboard content and transfer paths/identities are absent from replay
metadata, public catalog projection, and security audit.

The same case inspects local segment files to reject plaintext media/event
storage, expires the recording, runs retention cleanup, observes the catalog's
deleted state and replay denial, and confirms exact encrypted-object removal.
The disposable database container was removed after the complete tagged
package passed.

The Desktop Gateway gate covers required-recorder initialization before media
open, visible consent/mode, healthy finalization, recorder-loss closure, and
the retained viewer/controller real-WebRTC media/control paths. Ten shuffled
race-enabled package repetitions passed.

## Validation

The implementation and documentation passed:

- `go test -race -shuffle=on -count=10 ./product/adapter/gateway`;
- `go test -tags=integration -race -shuffle=on -count=1 ./product/adapter/postgres`
  against fresh PostgreSQL 16;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- the Provider and Product Contract verifiers;
- the retained Product Phase 3 and Phase 4 evidence verifiers; and
- `git diff --check`.

One initial full-repository race run observed a single three-second Desktop
WebRTC packet-delivery timeout under parallel package load. It did not use a
recorder. Ten shuffled race-enabled Gateway repetitions passed, followed by a
clean full-repository race/shuffle and vet run; the timeout was not counted as
a passing gate.

## Evidence boundary

This is Product recording service, local encrypted content-store, PostgreSQL,
and same-process Gateway component evidence. The media/input source remains an
injected implementation. Slice 11 does not provide a real Provider media
bridge, development-environment templates/toolchains/Guest health, unified Web,
production startup composition, capability advertisement, independent-process
release evidence, deployment, HA, hostile-multitenant isolation, or production
readiness.
