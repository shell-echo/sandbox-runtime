# Product Phase 6 Slice 6 TLS key-owner audit

Date: 2026-09-23. Status: incomplete implementation inventory, not release
evidence. Phase 6 remains **5/15**.

2026-09-26 topology checkpoint: the Browser action ingress is a ninth
distinct runtime process and requires its own TLS agent and Vault material
agent. The canonical profile now declares eleven static TLS-agent bindings
for the nine runtimes and two executors, and eleven material-agent identities
for the nine runtimes and two migrations; the ingress command and observed signer/CRL graph do not yet
exist. Counts in the original 2026-09-23 rows below describe that earlier
inventory, not the revised deployment target.

The `workload-material-agent` command is a Vault KV/credential process; its
`KindMaterialAgent` principal is not the `workload-tls-agent` process. One
principal cannot stand for both. This audit distinguishes the currently
observed private-key owner from the required Slice 6 topology; a profile
declaration alone does not migrate a process to a remote signer.

| Principal set | Current TLS key path | Slice 6 ownership gap |
| --- | --- | --- |
| Product, Gateway, Guest, Browser and Desktop roles plus coding, Browser-only and Desktop-only Provider processes | Product/Gateway/coding Provider have explicit live-signer v3 paths; Guest and Browser/Desktop roles still have static v2 TLS paths, while Browser-only and Desktop-only Provider production composition is absent. | Eight separate runtime TLS-agent identities are declared, but the missing v3 command paths and the real per-instance signer/CRL process graph remain unproved. |
| Browser and Desktop executor backends | Unpublished production authority v2 now requires separate remote TLS agents and pinned peer-CRL role/source bindings; the static file loader remains component compatibility only. | Real distinct-UID command/agent/controller/Vault and all-principal gate remains missing. |
| Egress-policy broker | `cmd/egress-policy-broker` obtains a server/client certificate through `workloadtlsagent.NewProductionClient`; its dynamic TLS-agent principal and canonical socket/profile binding are now checked at startup. | The real production agent/controller/Vault/DNS mTLS process gate and whole-profile mount enforcement are still missing. |
| Certificate controller | Descriptor-5 operator bootstrap private key, then an internally generated managed key in `workloadtlsagent.Manager` selected by a TLS callback; descriptor-4 response-signing key remains separate. | The profile binds its response key and per-agent exclusive CSR sockets, with one declared internal self endpoint; a distinct-UID two-agent Docker test passes with a test CA, but full production Vault/rotation/revocation process evidence remains missing. |
| Workload credential and break-glass controllers, ten declared Vault KV material agents | The shown command paths use Unix peer protocols and/or Vault TLS root verification, not a separately demonstrated private TLS server key for each. | Two extra Provider runtime material-agent identities are now declared for separate Browser/Desktop instances; exact production delegation and DB/state isolation still require implementation and observation. |
| Product/Provider migration jobs and their material agents | One-shot migration and credential/material paths are distinct; no separately verified TLS private-key owner has yet been bound to the security profile. | Inventory exact DB/Vault transport and any client certificate requirement before choosing an owner. |

The registry now separates `KindTLSAgent` from `KindMaterialAgent`; the
credential-v2 policy denies TLS-agent Vault token issuance even when a backend
policy is supplied. The PKI delegation rule is exact one-to-one for the eight
runtime process instances, two executor backends and each explicitly registered egress
broker. These are necessary policy constraints, not evidence that those
agents are deployed. `securityprincipal.v1` is repository-private and has no
Provider Contract lock; this Slice 6 extension must be frozen only after the
canonical profile, issuer policy, real process topology and full negative
matrix are complete.

The profile now carries digest-bound `TLSAgentBinding` records for the ten
static agents and each registered broker agent, plus their reverse CSR edge
to the one certificate controller. Production TLS-agent, broker and
certificate-controller startup checks have been connected to that profile.
Next: migrate each remaining frozen runtime TLS key path to a live remote signer, and test the
full-inventory production broker TLS 1.3 mTLS/rotation/revocation graph.
Until then the Slice 6 gate is open.
