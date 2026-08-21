# ADR 0008: Provider Lifecycle Composition Boundary

- Status: Accepted for the P1.2.5 composition slice
- Date: 2026-08-21

## Context

P1.2.4 projects the Contract-authorized lifecycle routes through a narrow
`LifecycleApplication`, but the command composition root deliberately leaves
that application unset. A configured protected listener therefore remains
fail-closed with `503`. The Provider lifecycle graph must be composed without
reusing the local `/instances` repository, driver, or model.

## Decision

Add an independent Provider lifecycle composition boundary. Its configuration
selects a Provider lifecycle repository (`memory` for development or `file` for
single-controller development evidence) and a Provider-specific lifecycle
driver. The initial driver is an in-memory fake used only for local validation;
production configuration rejects it until a production-capable Provider driver
has its own implementation and release evidence.

The composition root constructs the Provider lifecycle repository, driver,
coordinator, and application as one owned graph. It performs pending-operation
reconciliation before the Provider server starts and closes the repository with
the server lifecycle. The application is injected only into protected Provider
transport options. Discovery remains independent, and disabling the Provider
listener leaves lifecycle placeholders inert.

Enabling Provider lifecycle requires the protected admission boundary and a
Provider listener. Production additionally requires a persistent Provider
lifecycle repository and rejects the fake driver. No `/instances` dependency,
terminate route, lease mutation, orphan cleanup, or new Contract surface is
introduced by this decision.

## Consequences

- A real configured development process can exercise the three authorized
  lifecycle routes instead of returning the missing-application `503`.
- Memory/file repository evidence remains provider-local and does not establish
  multi-controller safety, external-caller compatibility, or production
  readiness.
- A production-capable lifecycle driver and deployment-specific durability
  remain separate release gates.
