# ADR 0036: Browser PostgreSQL Controlled-Restore Reference

- Status: Accepted for a same-runner reference operational E2E
- Date: 2026-09-06

## Context

ADR 0035 supplies a PostgreSQL action-history witness and the strict,
read-only `VerifyRestoredState` primitive. It deliberately does not supply an
ingress quarantine API, restore workflow, deployment topology, or evidence
that PostgreSQL and the Redis-compatible authority occupy independent failure
and backup domains.

This repository has no production deployment target, Helm chart, Kubernetes
operator, Terraform stack, or separately owned restore controller. Claiming
production restore safety or independent failure domains from this checkout
would therefore be false. A smaller missing step can still be tested: compose
the PostgreSQL witness into the existing two-Gateway, unique-ingress,
real-Chromium harness and execute the required quarantine, restore, strict
verification, and resume order.

The ADR 0034 file-witness runner is already a locked evidence identity. It must
not be relabeled or silently changed to use PostgreSQL.

## Decision

Add the separately named `browser-postgres-controlled-restore-e2e-v1`
reference operational profile and
`cmd/postgres-controlled-restore-e2e`. It content-binds the ADR 0034 transport,
topology, Browser image, Valkey, action-fencing policy, callers, and Contract
identity while explicitly selecting `PostgresActionHistoryWitness`.

The E2E Provider/private-ingress configuration adds a third explicit action
fencing profile. It requires:

- a credentialed PostgreSQL URL for the fixed `witness` database and
  `sandbox_runtime_witness` role on loopback;
- the locked 200-millisecond witness operation timeout; and
- either ordinary `runtime` verification or strict `restored-state`
  verification.

The two verification modes are mutually exclusive. Strict startup calls only
`VerifyRestoredState`; it never calls ordinary `Verify` first. This matters
because ordinary runtime verification may durably finish the exact
Redis-ahead-one interruption case, while restore verification must be
read-only and accept only an exact match. Both checks complete before the
Browser Provider is opened or either Provider/private-ingress listener is
started.

These fields are private E2E composition inputs. They add no Provider wire
route, local `/instances` route, public repair endpoint, or production command
configuration.

### Reference PostgreSQL composition

The runner starts the PostgreSQL image fixed by ADR 0035's immutable index
digest on the same Docker engine as the Valkey and Browser fixtures. It applies
the exact repository migration with an ephemeral administrator, revokes all
`PUBLIC` privileges on the target database and `public` schema, creates the
fixed runtime role, grants only the documented column-scoped operations,
verifies the role shape, and closes the administrator pool before starting the
ingress.

The PostgreSQL runtime credential is available only to the orchestrator and
the Provider/private-ingress process. Gateways and callers receive neither it
nor the administrative credential. The Redis `DUMP`/`RESTORE` credential
remains separately generated and orchestrator-only. Runtime configuration,
credentials, snapshots, and logs stay under the private temporary run root and
are removed; the five-file evidence set contains only hashes and bounded
metadata.

The PostgreSQL and Valkey containers are separate processes and logical
restore targets, but they share one runner, Docker engine, host, operator, and
workflow. The lock and manifest must therefore record
`same_runner=true`, `independent_failure_domain=false`, and image provenance as
not established.

### Controlled sequence

After the first ten inherited real-Chromium fencing scenarios, the runner:

1. captures an older Redis snapshot, advances the live action checkpoint once,
   captures the exact current snapshot, and retains the current PostgreSQL
   checkpoint;
2. stops the combined Provider/private-ingress process, confirms both
   listeners are absent, and proves a live Gateway has no alternative private
   downstream path;
3. restores only the older Redis snapshot through the orchestrator credential;
4. starts the ingress with strict restored-state verification and requires the
   process to fail before either listener opens;
5. reloads PostgreSQL and proves the rejected verification did not advance its
   checkpoint;
6. restores the exact current Redis snapshot while the ingress remains
   quarantined;
7. starts the strict configuration successfully, confirms both listeners are
   ready, and proves verification still did not advance PostgreSQL; and
8. performs a post-resume real-CDP read and mutation through a Gateway and the
   unique ingress, then executes the existing no-bypass, cleanup, and
   sanitization gates.

The older and current snapshots cover the witnessed action state, capacity
fence, and exact lease set. PostgreSQL is never part of either snapshot.

## Release Boundary

The component gate requires config rejection tests, strict/runtime dispatch
tests proving no recovery fallback, lock and explicit-zero-field tests,
manifest overclaim rejection, race/shuffle tests, vet, existing lock checks,
and unchanged root repository checks.

The separate hosted workflow must pass all 18 scenarios on a clean committed
checkout and upload exactly five sanitized `0600` evidence files. A passing run
establishes only that the same-runner reference topology executed the locked
operational order with real PostgreSQL, Valkey, two Gateways, two independent
callers, one unique ingress, and signed real Chromium.

It does not establish:

- independent PostgreSQL and Valkey host, storage, failure, snapshot, backup,
  restore, credential, operator, or control-plane domains;
- PostgreSQL or Valkey HA, replication, synchronous-replica durability,
  promotion, partition, failover, backup correctness, or disaster recovery;
- production ingress quarantine, authorization, maintenance locking,
  concurrent-operator exclusion, rollout, rollback, or repair automation;
- PostgreSQL image provenance, production TLS/ACL configuration, secret
  distribution, monitoring, alerting, capacity, or latency under load;
- protection from coherent rollback of both authorities or a trusted writer;
- CDP exactly-once execution, hostile multi-tenant isolation, Provider
  multi-controller behavior, real Agent Platform compatibility, aggregate
  conformance, production Browser advertisement, deployment readiness, or
  production readiness.

Independent failure and backup domains remain the next deployment-owned gate.

## Consequences

- The PostgreSQL candidate is exercised in the real external-caller Browser
  path without changing the ADR 0034 file-witness evidence identity.
- Restore and ordinary reconstruction remain observably different startup
  modes, preventing exact-ahead recovery from weakening a restore check.
- A reference operator ordering bug can be caught in CI, but the repository
  still cannot manufacture production topology evidence it does not own.
- The new E2E adds another PostgreSQL image pull and real-service runtime cost;
  it remains a separate workflow so other evidence tracks are not conflated.
