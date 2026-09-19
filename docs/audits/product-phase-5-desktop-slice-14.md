# Product Phase 5 Desktop Slice 14 Evidence

Date: 2026-09-20

Implementation revision:
`13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d`

Result: passed for the bounded Slice 14 same-repository composition scope.

## Implemented boundary

Slice 14 adds the missing private Provider-to-Product-Gateway Desktop media
and control transport. Its neutral closed protocol is owned under
`internal/desktopmedia`; Product production code does not import Provider
authority, and Provider production code does not import Product authority.

The Product adapter opens only from an already-consumed exact Desktop binding.
The private Provider handler requires TLS plus an explicit peer authorizer in
non-test construction, compares every private binding field with a freshly
resolved durable handoff, performs a fresh attach, and continuously rechecks
revocation/source/generation/expiry authority. Video, optional audio, control
messages, sessions, per-session connections, deadlines, and queues are
bounded. Unknown input kinds, microphone/camera/device input, malformed
keyboard/pointer/touch, unsafe clipboard or transfer values, stale handoffs,
and tuple substitution fail closed.

## Acceptance matrix

| Requirement | Executable evidence |
| --- | --- |
| Cross-layer composition | `TestIntegrationComposedDesktopProductFaultSecurityAndCleanup` joins real PostgreSQL authority, one-use control grant, durable policy, public WebRTC, private Provider bridge, RTP, fenced input, required encrypted recording, and continuous revocation. |
| Restart and dependency loss | `TestPrivateDesktopMediaBridgeRoundTripAndContinuousRevocation`, the tagged Desktop network reconciliation/restart test, Gateway recovery tests, and Provider application recovery tests close or reconstruct from retained authority without reviving tickets or stale media handles. |
| Stale/replay/tenant attacks | The composed gate denies cross-origin signaling, exact ticket replay, and cross-owner recording replay; focused bridge tests deny sandbox and connection-generation substitution; the complete tagged PostgreSQL package retains cross-tenant and stale-fence cases. |
| Capacity and quota recovery | `TestPrivateDesktopMediaBridgeRejectsSubstitutionAndRecoversCapacity` proves release after private-session exhaustion; tagged PostgreSQL viewer/controller, slot/session, recording, and development quotas retain concurrent admission coverage. |
| Cleanup | The composed gate closes the private media session, expires and removes encrypted recording objects, deletes the exact tenant row graph, and observes zero Workspace/session/grant/policy/recording/audit rows. The retained tagged Desktop Docker adapter verifies exact owned runtime cleanup; disposable PostgreSQL process cleanup is part of the invocation below. |
| Retained regressions | Full repository race/shuffle and vet, current Provider and Product Contract verifiers, and the immutable Phase 3 and Phase 4 evidence verifiers pass. |

## Commands run

```text
go test -race -shuffle=on -count=1 ./...
go vet ./...

SANDBOX_RUNTIME_PRODUCT_POSTGRES_URL=postgres://postgres:phase5@127.0.0.1:51026/phase5?sslmode=disable \
  go test -tags=integration -race -shuffle=on -count=1 ./product/adapter/postgres

go run ./cmd/verify-contract -source-root .
go run ./cmd/verify-product-contract -source-root .
go run ./cmd/verify-product-phase3-evidence \
  -manifest docs/audits/product-phase-3-standalone-evidence.json
go run ./cmd/verify-product-phase4-evidence \
  -manifest docs/audits/product-phase-4-browser-evidence.json
```

The PostgreSQL run used a fresh digest-pinned
`postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
container. It was removed after the gate and `docker inspect` returned no such
object.

## Evidence boundary and non-claims

This proves the private network bridge and the same-process composed Product
path against a real store. The composition media executor is a bounded
repository reference source; this is not yet the Slice 15 independent-process
Product/Gateway/Provider/Desktop/Guest topology or its real display/control
and development scenario. No deployment, independently implemented caller,
HA, hostile-multitenant isolation, production operations, or production
readiness follows. Desktop capability advertisement remains disabled until
the exact Slice 15 topology and strict evidence bundle pass.
