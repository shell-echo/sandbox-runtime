# Product v1 Phase 6 Slice 1 Evidence

Date: 2026-09-20

Status: implemented; Phase 6 is **1/15 complete**.

## Result

The repository now contains a real independent Product entry point:

```text
sandbox-runtime product serve --config /absolute/path/to/config.toml
```

It is deliberately limited to `application.mode=development` and
`product_process.deployment_level=development`. Standalone and production
values fail startup because production identity, TLS, role-separated database
permissions and the complete runtime dependency graph are later slices.

## Implemented boundary

- strict `product_process` file decoding rejects unknown fields;
- explicit opt-in, loopback-only listener and bounded pool/time configuration;
- PostgreSQL DSN and frozen identity bindings are read only from distinct,
  absolute, bounded, private regular files;
- the identity document is closed JSON with an exact version and at most 128
  validated bindings; rotation is restart-based for this development slice;
- Product PostgreSQL migrations run before bind, the real Product Store backs
  the API, and startup fails when the database is unavailable;
- `/livez` reports only process liveness and `/readyz` rechecks PostgreSQL with
  a deadline and returns `503` on loss;
- Product capability discovery remains empty; primary-slot authorization always
  returns capability unsupported, so the process cannot dispatch runtime work;
- the existing root `serve` command rejects an enabled Product process section,
  preserving local API/Provider/Product role separation; and
- bounded HTTP timeouts, header limits, cancellation-aware bind/shutdown and
  no-store responses are applied.

## Configuration authority

The checked-in template documents the inert section. A minimal identity file
has this closed shape and must be mode `0600`:

```json
{
  "version": "sandbox-runtime-product-static-identities-v1",
  "bindings": [
    {
      "token": "at-least-32-private-characters",
      "tenant_id": "tenant-1",
      "actor_type": "human",
      "actor_id": "actor-1",
      "role": "owner"
    }
  ]
}
```

The PostgreSQL secret file contains one `postgres://` or `postgresql://` DSN
and may have one final LF. Neither secret value is projected through probes or
stable errors.

## Validation

Focused race/shuffle tests cover exact configuration, unknown fields, unsafe
paths/listeners/modes, private-file type/mode/size/symlink checks, strict
identity parsing, duplicate tokens, liveness/readiness failure closure, method
limits and Product API routing. The mandatory full repository and retained
Contract/evidence gates are recorded with the local commit handoff.

The tagged process gate also passed locally with Docker Engine 29.7.2 on
`linux/arm64` and the exact Phase 3-5 PostgreSQL 16 image index
`sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28`.
It built and started the real binary, applied all 13 migrations, observed
authenticated empty capability discovery, rejected Workspace creation before
store mutation, changed `/readyz` from `200` to `503` after database loss,
accepted `SIGTERM` with a zero exit, and removed the exact database container
and temporary secrets.

## Evidence boundary

This is source and component evidence for an independently runnable Product
development process. It is not a published image, deployment qualification,
production identity, TLS termination, Provider/Gateway/Guest/Browser/Desktop
composition, database role/HA/backup evidence, standalone qualification, HA,
hostile-multitenant safety, SLO attainment or production readiness.

Slice 2 is the production Product kernel, identity and database-role slice.
