# Product v1 Phase 4 Browser Completion

Date: 2026-09-18

Source baseline: `322eb342650d2ade838f1b3a24e0d5bc0bfbb3e1`

Run: `20260918T152110.677058000Z`

Evidence tier: `same-repository-separate-process`

## Result

The fixed Product v1 Phase 4 Browser plan is complete at **13/13** for its
bounded release topology. The tagged release gate passed 12/12 exact scenarios
through four separate Product, Gateway, Provider, and Browser OS processes.

The run used fresh PostgreSQL 16 and Valkey containers selected by exact image
digests plus fresh encrypted local recording storage. Product used its real
PostgreSQL repository and locked network-only Provider adapter. Gateway used
the real PostgreSQL grant/audit repository, Redis-compatible capacity adapter,
automation WSS, WebRTC live transport, and encrypted recording path. Browser
used a private mTLS and downstream-fenced ingress plus a network media source.
The Provider role was the exact same-repository locked-wire fixture, not an
independently implemented caller or deployment.

## Passed scenario set

1. `contract-identities`
2. `product-authentication`
3. `browser-slot-session-lifecycle`
4. `tenant-nondisclosure`
5. `automation-roundtrip`
6. `viewer-controller-fencing`
7. `browser-live-recording-integrity`
8. `product-restart-recovery`
9. `gateway-restart-recovery`
10. `provider-fault-closure`
11. `bounded-backpressure`
12. `exact-cleanup`

The run proved one-use automation admission, real WebRTC viewing and fenced
control, required encrypted recording and authorized integrity replay, Product
and Gateway reconstruction, Provider dependency failure closure, bounded
message rejection, tenant nondisclosure, durable lifecycle cleanup, and exact
run-owned resource cleanup.

## Selected identities and cleanup

- Provider Contract revision:
  `98995384c60a924f25ca58d3b7e561207bfa5be8`
- Provider Contract tree:
  `0a627baed11c8a6ddbe8a24bbc1869e4f85edc16`
- Product Contract tree:
  `sha256:9490513228774da2e06cc3d01bc65192d37adea89d12d4ad83efdd6ce0f14560`
- PostgreSQL profile:
  `postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
- Valkey profile:
  `ghcr.io/valkey-io/valkey@sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd`
- Recording profile: `encrypted-local-recording-store-v1`
- all child processes were reaped;
- all run-owned containers and recording objects were removed;
- all scoped Product rows were removed; and
- coordination state was drained.

The strict retained manifest is
[`product-phase-4-browser-evidence.json`](product-phase-4-browser-evidence.json).
It records the process executable digests, complete scenario set, cleanup
booleans, and explicit non-claims.

## Reproducible validation

```bash
go test -v -count=1 -tags=phase4browsergate ./productphase4gate
go run ./cmd/verify-product-phase4-evidence \
  -manifest docs/audits/product-phase-4-browser-evidence.json
go test -race -shuffle=on -count=1 ./...
go vet ./...
go run ./cmd/verify-contract -source-root .
go run ./cmd/verify-product-contract -source-root .
go run ./cmd/verify-product-phase3-evidence \
  -manifest docs/audits/product-phase-3-standalone-evidence.json
```

## Non-claims

This result does not establish deployment qualification, an independently
implemented caller, HA, hostile multi-tenant isolation, multi-human browser
collaboration, or production readiness. Those require separate named gates and
reproducible evidence. Historical Provider Browser and reference-caller results
remain separate and are not relabeled as Product Phase 4 evidence.
