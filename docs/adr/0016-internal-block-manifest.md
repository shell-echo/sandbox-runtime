# ADR 0016: Internal Block Manifest Boundary

- Status: Accepted for the internal manifest foundation
- Date: 2026-09-02

## Context

The roadmap needs a declarative description of runnable blocks such as a
browser or desktop workload, but the Provider Contract does not define a block
resource. Reusing Provider wire DTOs or adding a block route would move
product configuration into the Provider protocol before a compatible Contract
exists.

## Decision

The first block slice defines an internal, non-wire manifest format identified
by `apiVersion: sandbox.runtime/v1alpha1` and `kind: Block`. A manifest has:

- `metadata.name`, a bounded stable block identifier;
- `metadata.version`, a numeric semantic version;
- an optional bounded description;
- `runtime.runtime_profile`, an opaque bounded runtime profile identifier;
- `runtime.image`, which must be a normalized image reference pinned by a
  lowercase `sha256` digest;
- an optional bounded argv vector and working directory; and
- one or more capability entries with bounded ID, version, and optional
  profile.

The loader accepts YAML and JSON representations, rejects unknown fields,
multiple YAML documents, malformed values, unpinned images, unsafe working
directories, duplicate capabilities, and oversized input. It reads only
regular files with `.yaml`, `.yml`, or `.json` extensions from one directory;
symlinks and nested paths are rejected. A directory is bounded to 256
manifests and each manifest to 256 KiB. The registry returns deterministic,
sorted, defensive copies and fails closed on duplicate block names.

The manifest is configuration for future local block composition. It is not a
Provider capability advertisement, a public API, a tenant or WorkOrder
record, an authorization decision, an artifact publication record, or a
replacement for the locked Provider Contract.

## Consequences

- Future runtime composition can consume a validated, immutable block
  registry without coupling it to `/instances` or Provider wire DTOs.
- Image pinning and path restrictions are enforced before a block can enter a
  registry, but this does not prove image provenance, sandbox isolation, or
  production deployment safety.
- Browser/desktop capabilities, runtime images, CLI commands, public registry
  routes, and Provider advertisement require separate implementation and
  evidence gates.
