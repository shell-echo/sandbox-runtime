# Product v1 Phase 6 Slice 4 — Data-Plane Role Boundaries

Date: 2026-09-20

Status: **boundary implementation in progress; not a completed Phase 6
slice**.

## Implemented repository scope

- `gateway serve`, `guest serve`, `browser serve`, and `desktop serve` are
  separate commands with separate `*_process` configuration sections.
- Gateway is restricted to an explicit public TLS listener; Guest is
  outbound-only; Browser and Desktop are restricted to private TLS 1.3 mTLS
  listeners with an exact URI identity allowlist.
- Every role has a distinct loopback-only process probe. Probes expose only
  `/livez` and `/readyz`; they do not expose `/instances`, Product routes,
  Provider Contract routes, credentials, or backend coordinates.
- Commands reject enabled Product/Provider or sibling-role authority in the
  same process. Private authority files are absolute, distinct, and bounded by
  configuration validation.

## Remaining gate

The role listener boundary is not the complete Slice 4 data plane. The
Gateway authorization/relay/capacity/revocation/recording graph, Guest
authenticated reconnect graph, and Browser/Desktop private application
handlers still need to be composed into these commands and exercised through
independent processes with dependency loss, bounded drain, least-authority
credentials, and private-coordinate nondisclosure. No Slice 4 completion,
deployment, HA, or production-readiness claim follows from this boundary
implementation.

The next code step is to compose the already-owned Gateway, Guest, Browser,
and Desktop applications behind these role transports without importing
Provider repositories or local-instance authority into the public roles.
