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

Two additional command-level blockers remain: `workload-material-agent`
constructs the frozen `workload-credential.v1` client, which cannot speak to
the Slice 6 v2 controller, and both that agent and the v2 credential
controller currently configure only Vault server TLS, not a client
certificate. A token plus server TLS is not mTLS. The approved Slice 6 path
requires an explicit v2 agent configuration/client and actual bounded client
identity, with the credential controller's narrow bootstrap exception followed
by managed identity switch and key destruction. Historical v1 semantics must
remain separate and cannot be a production fallback.

Open engineering work: expand
trust edges, dedicated internal+isolated external-service membership, target
IP/port and observed Docker endpoints; bind distinct DB/DSN/CA/HBA/client
signer purposes; ensure actual commands use the closed paths; then run the
full 16-scenario independent gate and exact cleanup. No evidence manifest is
authorized by this audit. Phase 6 remains 5/15.
