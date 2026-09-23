# Product Phase 6 production trust-edge inventory

Date: 2026-09-23. Status: implementation audit, not a deployment receipt or
release evidence. Phase 6 remains **5/15**.

This table follows the actual production command paths. A validated profile
is configuration authority only; the final Docker gate must observe mounts,
UID/GID, network membership, TLS handshakes, failure responses and cleanup.

| Edge / key owner | Current production path | Profile binding and remaining gap |
| --- | --- | --- |
| Runtime role → its TLS agent | The six Product/Provider/Gateway/Guest/Browser/Desktop processes still load local or registry-resolved, frozen server/client TLS private keys. | Eight static role/executor `TLSAgentBinding` records now declare signer socket, subject, UID/GID, issuer and cleanup. None of the six runtime commands yet consumes its live remote signer; local-key fallback must be removed from the final production profile. |
| Browser/Desktop executor backend → its TLS agent | Both production commands now require v2 profile-bound signer sockets; the backend listener uses a live certificate callback and rejects combined local-key fallback. CA bundles are loaded from profile-owned read-only trust-anchor artifacts, not arbitrary command paths. | Component tests prove issuer/URI/DNS/EKU/signer/peer mismatch, signer-loss denial for new handshakes, anchor digest/purpose/domain/source rejection. Distinct-UID production-command Docker handshakes, observed read-only mounts and existing-connection revocation drain are still missing. |
| Egress broker → its TLS agent | `cmd/egress-policy-broker` calls `workloadtlsagent.NewProductionClient` and uses the returned signer for both listener and DNS client TLS. | The broker verifies its canonical signer path and agent UID/GID before connecting. A production broker/agent handshake and existing-connection revocation drain are not yet proven. |
| TLS agent → certificate controller | `cmd/workload-tls-agent` uses the private `workloadpki` Unix client; one controller command owns multiple per-agent listeners. | The profile now fixes each exclusive controller socket/mount/peer edge, CSR request key, controller response key and issuer policy. Both commands verify the same profile and dynamic broker registry. A package-level Docker test proves two distinct-UID agents with a test CA; the actual commands and Vault are not yet in one graph. |
| Certificate controller → own managed TLS self listener | `cmd/certificate-controller` issues/renews its internally held Vault client key through its own PKI listener. | The profile declares a separate 0700/0600 self endpoint and managed request key/policy. This remains the sole internal signer exception, not another TLS-agent principal. |
| Certificate controller → workload-credential controller → Vault PKI | The certificate controller obtains a scoped v2 credential through a Unix peer client, then calls Vault PKI over TLS 1.3 using FD5 bootstrap and managed client key. Config v3 now loads the Vault server CA and a separate bootstrap client CA from profile-pinned read-only anchors. | Credential-controller socket/mount/response key and the full Vault endpoint/identity topology remain incompletely bound. The existing real Vault mTLS integration is component evidence only. |
| Material agent → credential controller / break-glass controller → Vault KV | `cmd/workload-material-agent` has its own credential and break-glass Unix sockets and Vault TLS root verification; `cmd/workload-credential-controller-v2` and `cmd/break-glass-controller` own separate signing/listener material. | These controller sockets, peer identities, public-key digests and exact mounts are not yet all in the canonical Phase 6 profile. Do not relabel Vault KV material agents as TLS agents or grant TLS agents Vault credential tokens. |
| Broker → policy-state authority | The broker uses a profile-bound restricted Unix Current client; each policy has a separate durable authority command and operator signing key. | Actual production authority Docker checkpoint passes. The paired production broker/authority failure and live tunnel drain gate is still missing. |
| Broker → DNS → allowed uplink | Broker config v2 now loads DNS server and inbound client CA bundles from the same profile-pinned read-only anchors; it still pins the numeric DNS endpoint and SAN/URI before alias/answer/connection policy. | Real production DNS mTLS, full endpoint topology binding, policy revocation tunnel drain and egress-bypass negative matrix remain missing. |
| Product/Provider/Gateway/Guest/Browser/Desktop and migrations → declared services | Role and migration commands compose private/public TLS, PostgreSQL, Provider/Gateway and executor clients from several authority files and material registries. | Need exact endpoint/peer/key/mount bindings and live signer callbacks for each declared edge, then observed six-role and all-principal network/UID/secret matrix. Static config validation and same-host component tests do not qualify. |

The next implementation pass should follow this order: migrate Browser/Desktop
executor listeners and the six runtime role TLS paths to the bound live
signers; bind controller/credential/material/Vault edges without adding a
second authority; run the real broker→agent→controller→Vault→DNS mTLS graph;
then run the full distinct-UID, isolated-network negative matrix and strict
evidence verifier. A new authority, permission expansion or locked-protocol
change requires renewed architectural review; adding an exact binding to an
existing edge does not.
