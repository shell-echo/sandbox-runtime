# Product Phase 3 Standalone Completion

Date: 2026-09-18

Result: Passed for the fixed same-repository, separate-process topology.

## Fixed identities

- Gate implementation: `04c2755bec125db7e2c04df3f4e2f8cfedb6ec1d`
- Run: `20260918T111903.806694000Z`
- Provider revision: `98995384c60a924f25ca58d3b7e561207bfa5be8`
- Provider tree: `0a627baed11c8a6ddbe8a24bbc1869e4f85edc16`
- Product tree: `sha256:a5c9cfa4fdfcdb481336732b4b33de39b57ef6e30dc668b95a0cf524b143b4d1`
- PostgreSQL image: `postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`
- Four role executables: `sha256:0f8632c216e6bc241ca5959d5a4e3384bd0b2b501f28137aff18f571d5322878`

The Product, public Gateway, outbound Guest Agent, and locked-Contract Provider
fixture ran as four separate OS processes. They intentionally use four copies
of one VCS-built tagged test executable; shared executable bytes do not collapse
their process, listener, or failure boundaries. PostgreSQL ran in a new
disposable container with an empty Product schema.

## Passed matrix

The run passed all nine exact scenarios:

1. authenticated, dependency-derived capability readiness;
2. Product authentication before input authority;
3. tenant/owner nondisclosure;
4. Product process restart and PostgreSQL recovery;
5. challenge-authenticated Guest file listing plus traversal rejection;
6. one-use terminal ticket replay rejection;
7. binary Terminal Client → Gateway → Provider round trip;
8. Provider-process loss reflected as unavailable Terminal readiness; and
9. scoped Product-row removal, child-process reaping, and exact PostgreSQL
   container removal.

The gate wrote the checked-in
[`product-phase-3-standalone-evidence.json`](product-phase-3-standalone-evidence.json)
only after cleanup succeeded. The independent strict validator rejects unknown
fields, missing/duplicate roles or scenarios, wrong Contract or database
identities, incomplete cleanup, absent non-claims, and known secret/private
field markers.

Reproduce and validate with:

```bash
go test -race -v -tags=phase3gate -count=1 -run '^TestStandalonePhase3ReleaseGate$' ./productphase3gate
go run ./cmd/verify-product-phase3-evidence -manifest docs/audits/product-phase-3-standalone-evidence.json
```

## Evidence boundary

This closes the fixed Product Phase 3 standalone gate. The Provider role is a
same-repository locked-wire fixture, not a second qualification of the real
Provider implementation; the real Provider has its separately recorded Phase
2 gates. The run is not an independently implemented caller result and adds no
deployable command/configuration, external identity-provider, KMS/HSM, external
object-store, multi-controller, hostile-multitenant, HA/failover, SLO,
deployment, or production-readiness claim.
