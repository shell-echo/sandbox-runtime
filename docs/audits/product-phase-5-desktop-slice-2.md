# Product v1 Phase 5 Desktop Slice 2 Evidence

Date: 2026-09-19

Implementation: `d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00`

Provider Contract authority: revision
`720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`

## Result

Slice 2 is complete as Product Desktop slot/session intent and relational-store
authority. It does not implement or dispatch Provider Desktop work.

The Product accepts only these exact immutable shapes:

- slot: `desktop` / `sandbox-runtime-desktop-v1` with exactly
  `sandbox.desktop@1.0.0` / `desktop-v1`; and
- session: `desktop` / `product-desktop.v1` on a current ready Desktop slot.

PostgreSQL migration 8 adds matching database constraints, per-tenant Desktop
slot and live-session quotas, reconciliation indexes, and a one-live-session
per Desktop-slot invariant. Existing migration digests remain immutable and
the complete migration ledger replays idempotently.

## Transaction and isolation evidence

An authenticated Desktop slot/session mutation applies the same Product-owned
transaction boundary as the existing kernel:

1. authentication-derived tenant and actor authority;
2. idempotency reservation and canonical request digest;
3. locked aggregate expected-version check;
4. exact slot/session validation and quota admission;
5. durable Product state and operation;
6. one contiguous Workspace event;
7. one security-audit row;
8. one committed outbox intent; and
9. idempotency result binding.

Rollback publishes none of those effects. Concurrent tests prove one winner
for same-key idempotency, expected-version compare-and-set, Desktop-slot quota,
and Desktop-session quota races. Closed, expired, and failed session states
remain absorbing. Reads after constructing a fresh Store recover the committed
slot, session, and replay result from PostgreSQL.

Desktop session intents are `desktop_session.open` and
`desktop_session.close`. Terminal and Browser session workers cannot lease
them. Browser slot workers cannot lease Desktop `slot.reconcile` work. Because
Slice 2 intentionally has no Desktop dispatcher, these intents remain pending
for the later network-adapter slice.

Tenant and owner mismatches return not found. Stable Product DTOs contain no
Provider sandbox ID, Provider operation correlation, handoff reference, backend
endpoint, host path, credential, or database identity.

## Verification

The following gates pass:

- focused Product, Product API, and PostgreSQL-adapter unit tests;
- the complete tagged PostgreSQL adapter package with `-race`, shuffle, and a
  fresh disposable PostgreSQL 16 image pinned to
  `sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- Provider and Product Contract verifiers;
- historical qualification-Profile verification; and
- retained Product Phase 3 and Phase 4 evidence verification.

The disposable PostgreSQL container was removed after the tagged test. No
runtime-driver change was made, so the tagged Docker runtime integration gate
is not applicable to this slice.

## Non-claims

This result is real-PostgreSQL component evidence, not Provider Desktop
dispatch, runtime, image, broker, private resolver, public display/control,
Gateway grant or lease policy, input/clipboard/transfer policy, recording,
recovery, unified Web, capability advertisement, independent-process,
independent-caller, deployment, HA, hostile-multitenant, or production
evidence. Thirteen slices remain, beginning with Provider Desktop
domain/application/persistence in Slice 3.
