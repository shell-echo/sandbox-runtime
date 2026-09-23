# Product Phase 6 Slice 6 TLS key-owner audit

Date: 2026-09-23. Status: incomplete implementation inventory, not release
evidence. Phase 6 remains **5/15**.

The `workload-material-agent` command is a Vault KV/credential process; its
`KindMaterialAgent` principal is not the `workload-tls-agent` process. One
principal cannot stand for both. This audit distinguishes the currently
observed private-key owner from the required Slice 6 topology; a profile
declaration alone does not migrate a process to a remote signer.

| Principal set | Current TLS key path | Slice 6 ownership gap |
| --- | --- | --- |
| Product, Provider, Gateway, Guest, Browser and Desktop runtime roles | Role-local static file or registry material is parsed into a frozen `tls.Config`; some outgoing clients load a separate local client key. | Six separate role TLS agents and live signer callbacks are not yet wired into those production role commands. |
| Browser and Desktop executor backends | Their authority JSON supplies local server certificate/private-key file paths. | Two distinct executor TLS agents and remote signer callbacks are not yet wired. |
| Egress-policy broker | `cmd/egress-policy-broker` obtains a server/client certificate through `workloadtlsagent.NewProductionClient`; its dynamic TLS-agent principal and canonical socket/profile binding are now checked at startup. | The real production agent/controller/Vault/DNS mTLS process gate and whole-profile mount enforcement are still missing. |
| Certificate controller | Descriptor-5 operator bootstrap private key, then an internally generated managed key in `workloadtlsagent.Manager` selected by a TLS callback; descriptor-4 response-signing key remains separate. | The profile binds its response key and per-agent exclusive CSR sockets, with one declared internal self endpoint; a distinct-UID two-agent Docker test passes with a test CA, but full production Vault/rotation/revocation process evidence remains missing. |
| Workload credential and break-glass controllers, eight Vault KV material agents | The shown command paths use Unix peer protocols and/or Vault TLS root verification, not a separately demonstrated private TLS server key for each. | Review every declared network edge before assigning a TLS agent; do not create an empty agent identity merely to fill the profile. |
| Product/Provider migration jobs and their material agents | One-shot migration and credential/material paths are distinct; no separately verified TLS private-key owner has yet been bound to the security profile. | Inventory exact DB/Vault transport and any client certificate requirement before choosing an owner. |

The registry now separates `KindTLSAgent` from `KindMaterialAgent`; the
credential-v2 policy denies TLS-agent Vault token issuance even when a backend
policy is supplied. The PKI delegation rule is exact one-to-one for the six
runtime roles, two executor backends and each explicitly registered egress
broker. These are necessary policy constraints, not evidence that those
agents are deployed. `securityprincipal.v1` is repository-private and has no
Provider Contract lock; this Slice 6 extension must be frozen only after the
canonical profile, issuer policy, real process topology and full negative
matrix are complete.

The profile now carries digest-bound `TLSAgentBinding` records for the eight
static agents and each registered broker agent, plus their reverse CSR edge
to the one certificate controller. Production TLS-agent, broker and
certificate-controller startup checks have been connected to that profile.
Next: migrate each frozen runtime/executor TLS key path to a live remote signer, and test the
full-inventory production broker TLS 1.3 mTLS/rotation/revocation graph.
Until then the Slice 6 gate is open.
