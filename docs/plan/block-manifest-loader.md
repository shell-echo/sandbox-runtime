# Internal Block Manifest Loader

Status: implemented as an internal configuration slice. It does not change
the Provider Contract or close any P2, P3, P4, deployment, or production gate.

## Scope

- define the `sandbox.runtime/v1alpha1` `Block` manifest shape;
- strictly parse YAML and JSON with bounded input and no unknown fields;
- validate image digests, identifiers, capabilities, argv, and workspace-safe
  working directories; and
- load a bounded directory into a deterministic, defensive-copy registry.

## Non-goals

This slice does not add a Provider route, capability advertisement, block
execution, browser/desktop image, public registry API, tenant authorization,
artifact publication, or deployment configuration. Manifest validation is
component evidence only.

## Acceptance evidence

- valid YAML and JSON parse to the same manifest;
- unknown fields, multiple documents, oversized files, unsafe paths, invalid
  image references, duplicate capabilities, and duplicate block names fail
  closed;
- symlink and nested-file inputs are rejected;
- registry listing is sorted and returned values cannot mutate stored state;
- canceled contexts stop file loading; and
- the repository's normal race/shuffle, vet, Contract, and diff checks pass.
