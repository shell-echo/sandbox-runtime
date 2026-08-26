# Repository Guidelines

## Authority and scope

Read `docs/PROJECT_CONTEXT.md` first when starting a new session, then read
`README.md`, `docs/architecture.md`, the applicable ADRs, and
`docs/development.md` before changing behavior. The project context is a
handoff index, not an authority override. The architecture delivery plan
defines order and release gates. For Agent Platform compatibility, the locked
repository-owned OpenAPI, JSON Schemas, semantic rules, fixtures, and
Conformance Suite outrank local narrative text.

Keep the Provider API separate from the local `/instances` management API.
Provider wire DTOs must not reuse `instance` or Docker engine structs. The Agent
Platform owns business truth, desired state, authorization, and its aggregate
operation ledger; this service owns provider-local execution and evidence only.

## Engineering rules

- Keep transport, application policy, repositories, and runtime drivers in
  separate packages with inward-pointing dependencies.
- Preserve `context.Context` deadlines and cancellation for external work.
- Reject unknown or oversized input and fail closed on unsafe production
  configuration.
- Do not expose backend IDs, host paths, raw endpoints, daemon diagnostics,
  secrets, or credentials through stable APIs.
- Use focused optional capability interfaces rather than expanding every
  driver for features it cannot support.
- Preserve unrelated worktree changes and avoid broad refactors in feature
  slices.

## Required validation

Format Go changes with `gofmt`, then run:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

Run the tagged Docker integration test for driver or lifecycle changes. Run the
Agent Contract lock verifier for compatibility metadata, DTO, Provider API, or
conformance changes. A green unit test is component evidence only; do not call a
revision compatible, production-ready, or multi-tenant safe without its named
release gate and reproducible evidence.
