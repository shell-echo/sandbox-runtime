# Phase 6 Slice 6 private-FD startup inventory

Status: reviewed source inventory, **not** a live launch receipt or release
gate. This table freezes the repository-owned local-role image targets that
need Docker stdin-to-FD delivery before the next source-bound image rebuild.
The existing role commands and Profile validation remain authoritative.

| Build target | Existing canonical stdin cap | Private descriptors, exact purpose and cap | Existing managed path/socket inputs |
| --- | ---: | --- | --- |
| `certificate-controller` | 2 MiB | FD3 credential-agent Ed25519 signing key 64 B; FD4 controller Ed25519 signing key 64 B; FD5 Vault TLS private key 64 KiB; FD6 Vault TLS CSR Ed25519 key 64 B | Security Profile path; credential issuer socket; self-managed TLS controller socket; per-agent issuance sockets; ledger; Vault endpoint. |
| `workload-credential-controller-v2` | 2 MiB | FD3 operator bootstrap token 8 KiB; FD4 Vault bootstrap TLS private key 64 KiB; FD5 Vault TLS CSR Ed25519 key 64 B | Security Profile path; credential issuer sockets; managed TLS controller socket; ledger; Vault endpoint. |
| `workload-material-agent` | 2 MiB | FD3 agent identity Ed25519 signing key 64 B | Security Profile path; credential controller socket; TLS signer socket; material and break-glass sockets as Profile-bound. |
| `workload-tls-agent` | 256 KiB | FD3 certificate-request Ed25519 signing key 64 B | Security Profile path; certificate-controller request socket; signer socket. |
| `break-glass-controller` | 1 MiB | FD3 break-glass Ed25519 signing key 64 B | Ledger, audit and break-glass Unix socket. |
| `egress-policy-state-authority` | 16 KiB | FD3 policy-state Ed25519 signing key 64 B | Security Profile path; ledger and current-state Unix socket. |

Caps above are the role readers' ceilings, not a license to generate a key of
any size up to the cap: every Ed25519 purpose requires exactly 64 bytes.
The loader's total decoded input cap is the per-target stdin ceiling plus its
listed FD ceilings, and the encoded envelope has a separate 4 MiB ceiling.
The fixed FD-stage image entrypoint first uses Alpine `/bin/sh -ec` only to
open FD3…FD6 as inherited, read-only `/dev/null` placeholders before Go's
runtime starts, then immediately `exec`s the loader. No shell variable,
stdin, supplied argument or secret is interpreted. The loader verifies these
placeholders against `/dev/null` before parsing input and marks unused slots
close-on-exec for the role.
Only these six fixed targets use the loader. `core`, the two executor backends,
Browser action ingress, egress broker and ingress relay keep their current
direct image entrypoint; `workload-credential-controller` v1 is not a Phase 6
local-role build target. No FD number, command or path comes from the input
envelope. Profile-bound paths remain independently validated by each role and
are not synthesized or mounted as secret files by the loader.

For this same-host gate, the operator and Docker daemon are the trusted
delivery boundary. Docker create metadata fixes run, target and fresh nonce;
the created immutable container ID is checked before stdin delivery. The
loader checks those bindings plus its Docker-assigned hostname prefix. This
does not purport to authenticate an untrusted Docker daemon. Restart means a
new instance and nonce, never Docker automatic replay of old stdin. A sealed
0600 memfd is seekable regular-file input, not a persistent secret file. The
original envelope and Go decoding copies may exist transiently in memory;
neither zeroization nor daemon confidentiality beyond the trusted boundary is
claimed.
