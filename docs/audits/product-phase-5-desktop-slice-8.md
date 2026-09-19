# Product Phase 5 Desktop Slice 8 Evidence

Date: 2026-09-20

Implementation: `040c560f3701b7c972c25f05928dd435d9f55c20`

## Accepted boundary

Slice 8 adds a separate Product Desktop WebRTC edge behind the Slice 7
connection-grant authority. It does not reuse Browser signaling DTOs, Browser
policy actions, or Browser evidence:

- the public signaling request is bounded, closed JSON over HTTPS with one
  exact configured HTTPS Origin and one-use Product ticket authentication;
- production configuration requires relay-only `turns:` ICE with password
  credentials. Host candidates and insecure HTTP are available only through
  explicit test-only switches;
- an offer must contain exactly one receive-only video section and, when
  selected, one receive-only audio section. This rejects upstream camera and
  microphone media;
- the exact initial media matrix is VP8 display video at 320x240 through
  2560x1440, 1-60 FPS, and 128-8000 Kbit/s, with optional output-only Opus at
  16-128 Kbit/s;
- a viewer cannot request or create a control data channel. A controller must
  present the consumed binding's current lease and fence and use exactly one
  reliable, ordered `product-desktop-control.v1` channel;
- only closed keyboard, pointer, and touch input shapes enter the private
  input port. Every input is strictly sequence ordered and rechecks the full
  gateway grant plus an injected Product input-authority port before private
  execution. Clipboard, file, camera, microphone, and device messages are
  rejected;
- signaling, peer, per-session, video, audio, input, RTP-packet, bitrate, and
  control-response buffers are bounded. Overflow or a slow consumer closes the
  connection fail closed;
- live authority is rechecked until the earliest grant or handoff expiry, and
  revocation closes the peer; and
- public responses and audit events contain no Provider handoff, backend
  identity, endpoint, credential, ticket, media, or input payload.

The handler rejects `recording_policy=required` until the later Desktop
recording slice is composed. This prevents the public plane from weakening a
Product recording requirement.

## Real-WebRTC component evidence

The focused race/shuffle tests establish real in-process DTLS-SRTP/SCTP WebRTC
connections for both viewer and controller bindings. They carry VP8 RTP,
optional Opus RTP, and one fenced ordered pointer input through the public
handler and verify the response excludes the opaque Provider handoff.

Additional cases prove:

- authentication, exact Origin, and TLS rejection occur before ticket
  consumption or private media open;
- unsupported codec, resolution, audio, upstream media, viewer-control, and
  required-recording negotiations fail closed;
- clipboard/microphone and malformed or duplicate-member inputs are rejected;
- out-of-order, revoked, or policy-denied input never reaches the media port;
- authority revocation closes an established peer;
- a second control channel is rejected; and
- video and input queue saturation closes the peer.

The Desktop-focused race suite passed ten consecutive runs. The final full
repository race/shuffle and vet gates also pass.

## Validation

The implementation passed:

- `go test -race -count=10 -run 'TestDesktopLive' ./product/adapter/gateway`;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- the Provider and Product Contract verifiers;
- the retained Product Phase 3 and Phase 4 evidence verifiers; and
- `git diff --check`.

No tagged Docker or PostgreSQL gate is attributed to this slice because it
changes neither the runtime/lifecycle driver nor relational authority.

## Evidence boundary

This is a same-process public-handler and real-WebRTC component result using
injected grant, media, input-authority, and audit test peers. It does not yet
provide the Slice 9 durable Desktop input/clipboard/transfer policy, a real
Provider-to-Gateway media bridge, reconnect/resynchronization, recording,
development templates, unified Web, production startup composition,
capability advertisement, independent-process release evidence, deployment,
HA, hostile-multitenant, or production readiness.
