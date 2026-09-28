# Phase 6 Slice 6 command-level external dependency audit

Status: incomplete desired graph, not a release-gate result. This audit is
independent of the current 17-edge/12-path desired transport table. It reads
the actual command startup and steady-state dial paths; it does not assert
that a network, certificate, database privilege or container has been observed.

| Actual dialer | External service | Code path | Current transport status |
| --- | --- | --- | --- |
| Product runtime | Product PostgreSQL | `cmd/product_serve.go` `runProductServe` → `openProductPostgresRegistry` | Declared direct path; TLS/HBA/live endpoint still open |
| Gateway runtime | Product PostgreSQL | `roleprocess/gateway.go` `NewGatewayApplicationGraph` → `pgxpool.NewWithConfig` | Missing direct path, distinct Gateway DB credential and server authorization proof |
| Coding Provider runtime | Coding Provider PostgreSQL | `cmd/provider_serve.go` `runProviderServe` → `openProviderPostgresRegistry` → pool Ping/role/schema checks | Missing dedicated direct path and separate client-certificate/DB binding; Browser/Desktop broker bindings do not cover it |
| Browser and Desktop Provider runtimes | Respective Provider PostgreSQL databases | `cmd/provider_serve.go` → `cmd/provider_postgres_v3.go` `openProviderV3Postgres` | Declared role→own broker→PostgreSQL paths; not direct-role exceptions |
| Product and Provider migration jobs | Their separate migration databases/roles | `cmd/product_serve.go` `runProductMigrate`; `cmd/provider_serve.go` `runProviderMigrate` | Both direct paths missing; one-shot migration material and database authority must remain distinct from runtime |
| All eleven currently inventoried material-agent deployments | Vault KV | `cmd/workload-material-agent/main.go` `vaultkv.New`, then `ResolveSecret` | Eleven direct Vault service bridges missing; Unix credential acquisition does not tunnel KV reads |
| Workload credential controller v2 | Vault token issuer | `cmd/workload-credential-controller-v2/main.go` `workloadcredential.NewVaultIssuer` | Direct Vault service bridge missing; bootstrap token scope is separate authority |
| Certificate controller | Vault PKI and complete CRL | `cmd/certificate-controller/main.go` `workloadpki.NewVaultClient` | Declared direct path; existing controller-only isolated network has no external member yet |
| Browser action ingress | Action-history PostgreSQL and capacity Valkey | `cmd/browser-action-ingress/main.go`; role-specific alias adapters | Declared logical edges via its own broker; no direct bypass allowed |
| Gateway runtime | Capacity Valkey | Gateway capacity client and `cmd/egress-policy-broker/main.go` | Declared logical edge via Gateway's own broker; no direct bypass allowed |
| Five egress brokers | DNS | `cmd/egress-policy-broker/main.go` `tls.Dialer.DialContext` | Declared broker→DNS paths; live endpoint/member proof open |

The independently coded direct-dial inventory contains 18 requirements. Only
Product→PostgreSQL and certificate-controller→Vault appear in the current
physical transport table. The other 16 are reported by
`MissingSlice6DirectExternalDependencies`; the existing edge-coverage verifier
must not be read as an executable-dependency admission result. Any new command
dependency must be audited before the final source checkpoint/profile freeze,
not inferred from a successful unit test or retrospectively added to evidence.
The reviewed *target* transport plan now enumerates 28 physical paths and 33
logical/egress edge IDs, but only the old 12/17 subset is installed in the
current desired profile graph. The target-plan verifier freezes exact dialer,
service, dedicated bridge and edge-ID mapping; it does not make the commands
use those paths or prove network enforcement.
Its matching 28-bridge desired plan allocates one dialer and one external
service per internal+isolated bridge, keeps the certificate controller's
reviewed network/CIDR, and uses reserved `172.31.128.0/24` onward for the
other bridges so pre-existing role CIDRs are not silently shifted. These
addresses are planned inputs, not observed Docker endpoints. A new
candidate-profile builder merges the 28 bridges and 33 edge IDs with the old
draft, recalculates external identity and dependent database digests, and
requires complete-graph structural verification. The live commands and
physical services still need to consume this target.
An opt-in Docker diagnostic with the pinned Alpine probe image has exercised
the coding Provider service-bridge subnet and raw Docker network observer:
one isolated bridge, .2 dialer, .3 external member, no host gateway, no
published ports, and exact removal passed locally. These are diagnostic
containers, not the Provider or PostgreSQL service; no live TLS, SQL, or
Slice 6 scenario claim follows from this check.

This audit does not claim Product recording Transit is a Slice 6 runtime dial:
the current production Product command does not compose recording content;
that business graph is scheduled for Slice 8. The Slice 6 gate cannot claim
recording-content readiness on the strength of the Slice 5 Transit adapter.

Sandbox approved these direct paths as a finite batch, with a distinct SQL
login, DSN, client identity and least-privilege check for Gateway; scoped
Vault KV paths for each material agent; a separate restricted Vault issuer
client for the credential controller; and bootstrap-only migration roles.
This is authority to implement and test, not evidence that the current
commands or containers satisfy those constraints.

The material-agent command now has an explicit canonical v2 configuration
branch and a Principal-bound `workload-credential.v2` client. It pins the full
security-profile digest, material-agent deployment/UID/GID and controller
UID/GID, and rejects v2-to-v1 fallback; the v1 branch remains for
retained Slice 5 evidence only. The v2 material-agent Vault transport now
requires its profile-bound, separate TLS-agent signer, exact isolated service
bridge, numeric endpoint, Vault URI/DNS identity and direction-specific CA
bundles; it cannot select the v1 server-only TLS client. This is source-level
fail-closed wiring, not an actual eleven-agent/controller process gate: the
complete Vault edges and anchor consumers exist only in the synthetic target
profile; the live signer/controller chain is not yet present, so no v2 agent
is claimed runnable. The v2 credential
controller still configures only Vault server TLS; a token plus server TLS is
not mTLS. The approved Slice 6 path requires actual bounded client identity,
with the credential controller's
narrow bootstrap exception followed
by managed identity switch and key destruction. Historical v1 semantics must
remain separate and cannot be a production fallback. The complete production
profile/admission gate must also reject v1 command configuration explicitly;
the command's retained compatibility branch alone does not establish that.
The credential-controller socket path and exact Vault KV binding/policy are
not yet cross-bound to the complete profile.

The approved eleven material-agent Vault-client key owners now have eleven
separate TLS-agent deployment/principal/UID/GID/Unix-binding entries in the
closed profile inventory. The current intermediate shape is 69 deployments,
29 TLS-agent bindings and 99 reviewed trust edges; its old 58 UID/GID and role
network allocations are retained, with the new signers in separate reserved
partitions. These are configuration and unit-test facts only. They are **not**
eleven running signers, Vault mTLS, the final principal/edge counts or a
complete external-service graph; the 16 missing direct external edges and
actual command transport wiring remain open. The candidate profile does not
resolve the shared PostgreSQL server-auth scope: the current raw HBA still
covers only Browser/Desktop Provider and cannot authorize Product, Gateway,
coding Provider or migrations as a full service gate.

Open engineering work: expand
trust edges, dedicated internal+isolated external-service membership, target
IP/port and observed Docker endpoints; bind distinct DB/DSN/CA/HBA/client
signer purposes; ensure actual commands use the closed paths; then run the
full 16-scenario independent gate and exact cleanup. No evidence manifest is
authorized by this audit. Phase 6 remains 5/15.

The profile/observer now has a closed representation for a service joining a
dedicated isolated network: service and network membership must agree, and
raw Docker inspect plus evidence validation bind the external container ID
to the observed endpoint. This is a schema and verifier capability, not a
launched service bridge. The activated desired network/edge generator still
lacks the 16 new bridges/edges; its separate candidate builder is not runtime
evidence. The Provider database/client-signer policy remains hard-coded for
Browser/Desktop only.

Sandbox adjudicated the shared database boundary: keep one physical main
PostgreSQL service and one explicit, finite HBA/CA policy. Product and Gateway
must access the same Product database with distinct SQL logins, DSN bindings,
certificates and grants; coding/Browser/Desktop Provider retain distinct
databases/runtime roles. Migration roles are short-lived and scoped to their
actual target database, not a cross-database wildcard. Action-history
PostgreSQL remains a separate witness service. Product, Gateway, coding
Provider and each actual migration job need separate PG-purpose TLS signers;
ordinary role signers and Vault material-agent signers cannot be reused.
This decision is authority for implementation, not a claim that the current
Provider-only HBA has been widened safely or that SQL privileges are proved.
The current code target enumerates seven pool owners (Product, Gateway,
coding/Browser/Desktop Provider, Product migration and the currently
declared Provider migration job). It derives an exact `.2/32` source from
each reviewed physical service bridge and renders one deterministic HBA
line per unique SQL role plus explicit IPv4/IPv6 deny. These are candidate
bytes only: they are not mounted on PostgreSQL, and no positive/negative
SQL, SCRAM, client-certificate or migration-expiry observation exists yet.
If final deployment requires additional per-database Provider migration
instances, the closed deployment/signer/HBA matrix must be expanded before
R freeze; the current single Provider migration deployment cannot be
silently reused as an all-database principal.
