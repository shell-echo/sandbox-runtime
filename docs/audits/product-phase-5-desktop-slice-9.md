# Product Phase 5 Desktop Slice 9 Evidence

Date: 2026-09-20

Implementation: `24f5c741eb605614f77f8d9d546708b9993e42dd`

## Accepted boundary

Slice 9 adds the durable Product policy required before Desktop clipboard or
file-transfer actions can use the bounded Slice 8 control plane:

- `product.DesktopPolicy` is separate from Browser policy and is an immutable,
  positive-revision Workspace snapshot whose zero permissions deny every
  action;
- owner-scoped updates use an exact expected revision and idempotency key.
  PostgreSQL migration 11 retains every revision so historical retries return
  the exact original snapshot even after later updates;
- keyboard, pointer, and touch are independently enabled and may require user
  activation;
- clipboard read and write are independently enabled with UTF-8 byte bounds,
  activation, and consent;
- upload and download separately enforce activation, consent, file-count,
  per-file and aggregate byte limits, canonical allowed media types, SHA-256
  digests, unique transfer identities and paths, and confined UTF-8
  `/workspace/...` paths;
- every transfer descriptor additionally matches the complete Product
  transfer record for the exact tenant, actor, Workspace, ID, direction,
  digest, and byte count. Object references are never returned;
- microphone, camera, and host-device forwarding remain unconditionally
  denied; and
- audit rows contain policy-update metadata only, not clipboard text, file
  names, paths, media content, object references, or transfer payloads.

The Gateway loads and validates a policy before media is opened. A live peer
pins that revision, rechecks it during continuous authority polling and before
each input, and closes on absence, source failure, or revision replacement.
Clipboard read results are UTF-8 and bounded by the admitted policy.

## Real-store and concurrency evidence

The tagged Product PostgreSQL gate ran against a fresh disposable PostgreSQL
16 instance and passed:

- migration 11 application and replay;
- missing-policy denial and exact current-policy reads for a Desktop session;
- cross-owner nondisclosure;
- concurrent expected-revision updates with exactly one winner;
- historical idempotency replay after a later revision exists;
- same-key/different-document conflict;
- reconstructed-Store current-revision reads; and
- metadata-only security-audit assertions.

The disposable database container was removed after the gate. No runtime
driver or lifecycle code changed, so no tagged Docker driver gate is attributed
to this slice.

## Validation

The implementation passed:

- `go test -race -count=10 -run 'TestDesktopLive|TestProductTransferDesktop|TestDesktopPolicy' ./product ./product/adapter/gateway`;
- `go test -tags=integration -race -shuffle=on -count=1 ./product/adapter/postgres` against fresh PostgreSQL;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- the Provider and Product Contract verifiers;
- the retained Product Phase 3 and Phase 4 evidence verifiers; and
- `git diff --check`.

## Evidence boundary

This is Product policy, real-PostgreSQL, and same-process Gateway component
evidence. The media and input executor remains an injected test peer; Slice 9
does not provide a real Provider media/input bridge, reconnect or
resynchronization, restart recovery of active peers, deterministic replacement,
recording, development templates, unified Web, production startup composition,
capability advertisement, independent-process release evidence, deployment,
HA, hostile-multitenant, or production readiness.
