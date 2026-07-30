# Agent Platform Contract Lock

This directory records the exact Agent Platform Contract inputs consumed by
`sandbox-runtime`. It does not contain or relicense upstream Contract resources.

The lock binds:

- one immutable upstream Git revision and `contract/` tree;
- the Contract Manifest digest;
- the Sandbox Provider OpenAPI digest;
- the Sandbox Conformance Suite identity, digest, and required core profile.

Verify a checkout with:

```bash
go run ./cmd/verify-agent-contract -source-root /path/to/agent-blueprints
```

The checkout may contain later changes outside `contract/`; its committed
Contract tree must remain identical and its `contract/` worktree must be clean.

## Updating the lock

Treat an update as a compatibility change, not dependency housekeeping:

1. Review the upstream Blueprint, Contract diff, compatibility result, license,
   and Sandbox Suite changes at an immutable revision.
2. Update every field in `contract.lock.json` and the pinned CI checkout
   together.
3. Update Provider DTO generation or validation, mappings, fixtures, negative
   tests, ADRs, and architecture text affected by the new Contract.
4. Run the lock verifier, unit/race tests, vet, applicable integration tests,
   and the declared Sandbox Conformance profiles.
5. Keep compatibility, deployment, reliability, and production conclusions
   separate in review evidence.

Lock verification proves input identity only. It does not prove that this
repository implements or conforms to the locked protocol.
