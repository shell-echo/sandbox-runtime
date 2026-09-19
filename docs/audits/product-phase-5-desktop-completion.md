# Product Phase 5 Desktop Completion

Date: 2026-09-20

Status: complete at 15/15 for the bounded same-repository
independent-process topology

## Accepted evidence

The Slice 15 implementation baseline is
`024a768d51965f8949bacf3c97e499fb26a6e648`. Release run
`20260919T200125.484855000Z` passed all 14 required scenarios through five
independent OS processes: Product, Gateway, Provider, Desktop, and Guest. It
used fresh digest-pinned PostgreSQL, fresh encrypted recording storage, fresh
content-addressed development content storage, and the exact signed Desktop
image index
`sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`
with native `linux/arm64/v8` platform digest
`sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505`.

The strict manifest is
[`product-phase-5-desktop-evidence.json`](product-phase-5-desktop-evidence.json).
It binds:

- base Provider revision/tree
  `98995384c60a924f25ca58d3b7e561207bfa5be8` /
  `0a627baed11c8a6ddbe8a24bbc1869e4f85edc16`;
- Desktop Provider revision/tree
  `720ad15c343e71f36615dc4499edd5e764178bca` /
  `343ffde0819207cf99c005096c336735dd33a735`;
- Product Contract tree
  `sha256:9490513228774da2e06cc3d01bc65192d37adea89d12d4ad83efdd6ce0f14560`;
- the locked Desktop runtime publication and exact native platform digest;
- the locked `coding-shell-base-v1` development template and image;
- the exact five-role process set and 14-scenario set; and
- complete child-process, container, scoped-row, object, Guest-state, and
  runtime cleanup.

## Exercised scenarios

The gate proves Product authentication and cross-tenant nondisclosure; exact
Contract identities; dependency-derived Desktop and development capability
readiness; Desktop slot/session lifecycle; real X11 root capture and pointer
movement through public WebRTC, the Product Gateway, private mTLS transport,
and the Desktop runtime; cross-Origin and one-use-ticket rejection; encrypted
recording integrity and replay; Product, Gateway, and Guest restart recovery;
real digest-checked Guest workspace materialization before and after restart;
Provider dependency-loss failure closure; and exact cleanup.

The Desktop media fixture emits a bounded reference VP8 RTP payload while the
same session sends controller input to the locked runtime and independently
captures the real X11 display. This proves the composed display/control path
and runtime authority but is not a production video encoder benchmark or SLO.

## Reproduction

```bash
PRODUCT_PHASE5_EVIDENCE_OUTPUT="$PWD/docs/audits" \
  go test -race -tags=phase5desktopgate \
  -run '^TestProductPhase5DesktopReleaseGate$' -count=1 -v \
  ./productphase5gate

go run ./cmd/verify-product-phase5-evidence \
  -manifest docs/audits/product-phase-5-desktop-evidence.json
```

The verifier rejects unknown fields, identity or scenario drift, incomplete
cleanup, private handoff coordinates, credentials, tickets, database URLs,
host paths, and missing non-claims.

## Claim boundary

This is same-repository, single-host, single-controller evidence. All five
roles are separate OS processes but use the same repository-built test
executable, and the Provider role is a repository-owned fixture conforming to
the two exact locked Provider identities. Capability advertisement is enabled
only inside this exact release topology and is continuously dependency-derived;
the production command is not composed or enabled by this gate.

The result is not deployment-qualified, HA-qualified, hostile-multitenant
qualified, independently implemented caller interoperability, or general
production readiness. Multi-user collaboration, production relay and media
encoding, operational restore/failover, production configuration, SLOs, and
deployment evidence remain later work.
