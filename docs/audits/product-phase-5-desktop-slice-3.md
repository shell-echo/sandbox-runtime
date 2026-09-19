# Product v1 Phase 5 Desktop Slice 3 Evidence

Date: 2026-09-19

Implementation: `f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5`

Provider Contract authority: revision
`720ad15c343e71f36615dc4499edd5e764178bca`, tree
`343ffde0819207cf99c005096c336735dd33a735`

## Result

Slice 3 is complete as Provider-local Desktop domain, application,
persistence, reconciliation, operation-projection, and optional protected-route
component evidence. Desktop capability discovery remains unchanged and the
production command does not compose the new application.

The implementation introduces an independent `provider/desktop` authority.
It does not reuse Browser session records, lifecycle repository state, local
`/instances` models, runtime-driver structs, or Product DTOs. Runtime allocation
and observation plus private handoff registration and revocation remain narrow
injected ports for later slices.

## Authority and recovery evidence

Open and close operations have separate durable identities, idempotency keys,
digests, attempts, fencing tokens, deadlines, and state machines. Reservation
checks exact sandbox revision, observed generation, Desktop runtime/profile,
restricted-network policy, lease, and current fence before admitting work.
Valid higher close fences advance authority; stale fences and mismatched replay
are rejected.

The durable ordering is:

1. reserve the open operation;
2. commit running state before allocation;
3. persist the immutable allocation receipt before handoff registration;
4. commit the opaque handoff before reporting success;
5. durably revoke the source handoff before close/expiry effects;
6. revoke private handoff authority, clean the exact retained allocation, and
   observe absence before close success.

Restart tests cover accepted-before-running, running-before-effect,
effect-before-receipt, and receipt-before-handoff boundaries. A restarted
running or outcome-unknown open observes the immutable allocation identity and
never blindly allocates again. An uncertain close observes handoff revocation
and allocation state only; it never repeats revocation or cleanup. Expiry uses
the same revoke/clean/observe path as explicit close. Retained operation reads
remain available after handoff expiry while the handoff read itself becomes
expired or revoked.

Memory and exclusive-lock atomic-file repositories share the same validated
state core. Tests cover concurrent replay, digest conflicts, state/fence
transitions, snapshot round trips, process restart, corrupt/unknown/oversized
input, lock exclusion, and caller-safe copies. Context cancellation is checked
before effects and is preserved during external work.

## Protected transport evidence

Optional protected routes implement the locked Desktop open, close, operation,
and handoff shapes behind the existing mTLS/JWS admission boundary. Documents
are strictly bounded and reject unknown members and path/body identity drift
before application mutation. Projection fixes the WebRTC, media, and control
profiles and returns only an opaque `ref:desktop-session:*` handoff reference.

Tests cover authorization and binding, deadline/cancellation, replay, pending,
expiry, revocation, capacity, unavailable and conflict mappings, unknown and
oversized input, and internal-error redaction. Backend identities, raw
endpoints, host paths, credentials, and diagnostics are not projected.

## Verification

The following local gates pass:

- focused Desktop domain/application/repository, lifecycle, operation, and
  Provider API tests with `-race`, shuffle, and count one;
- `go test -race -shuffle=on -count=1 ./...`;
- `go vet ./...`;
- Provider and Product Contract verifiers;
- historical qualification-Profile verification;
- retained Product Phase 3 and Phase 4 evidence verification; and
- tagged Docker integration for the existing command, local driver, and
  Provider lifecycle driver packages; and
- repository diff/status checks.

No runtime driver or image is introduced. The lifecycle change only recognizes
the exact Desktop runtime profile under the existing restricted-network
validation. The tagged gate protects existing lifecycle adapters; it does not
compose or exercise a Desktop runtime.

## Non-claims

This result is in-process Provider component evidence with fake external
ports. It is not a Desktop runtime image, broker, runtime adapter, private
resolver, usage collector, Product outbox consumer, public signaling/media/
control plane, grant/controller policy, transfer policy, recording, unified
Web, capability advertisement, independent-process or independent-caller run,
deployment, HA, hostile-multitenant, or production evidence. Twelve slices
remain, beginning with the immutable Desktop runtime image and broker protocol
in Slice 4.
