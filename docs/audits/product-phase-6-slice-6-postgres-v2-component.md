# Phase 6 Slice 6 external PostgreSQL and terminal cleanup v2 (non-release)

On 2026-10-03, the tagged same-run real-Docker/Vault component gate
`TestPhase6Slice6VaultPersistentTrustSwitch` passed in 354.71 seconds. It used
the unchanged source-bound R7 role/image candidate and independently built the
one-shot terminal operator from clean revision
`67a368e8e6a4574195caa622e2118fd722090d52` (binary
`sha256:8cd08ebac06998cc484859a9ef5ce105bd32e00046b5793696f5f7a67ec23abe`).
The test compiled from a mutable worktree; this is not a frozen release run.

The same run used real file-backed Vault PKI and KVv2, two controller PID1
processes, distinct Product and Guest TLS/material agents, and a pinned
PostgreSQL PID1. The PostgreSQL server used the general-issuer server-only
leaf with the exact URI/DNS, nine isolated service bridges and source-bound
HBA. Its private configuration was supplied by a networkless, finite
`CAP_CHOWN`-only provisioner to a PG-owned `0700` volume, then mounted
read-only into non-root PostgreSQL. The gate verified final live SSL/HBA
settings, 12 parsed HBA rules with no errors, local SQL readiness, exact
mounted certificate DER, file inventory/modes/owners and read-only mount.
Vault's real leaf and issuer PEM omitted the final LF; the signing boundary
accepted only one exact no-header/no-junk certificate block and canonicalized
the same validated DER before both mount and terminal record. The no-secret
Docker provisioner probe and the independent effective/declared mount-order
and drift regression matrix passed separately. The order-check helper was
extracted after this successful aggregate run; the final helper revision has
focused tests but has not itself been rerun through the long aggregate gate.

After that extraction, `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, the Product Contract verifier, tagged Slice 6 unit tests and
vet, and targeted race tests for PEM/mount behavior passed. These are source
checks and focused regressions; they do not convert the earlier mutable-tree
aggregate result into an immutable release gate.

After Product/Guest agent work and controller quiesce, PostgreSQL was stopped
and removed before terminal cleanup. The independent one-shot v2 operator
confirmed exactly three certificate revocations, two token-accessor
revocations, a complete CRL containing the external PostgreSQL leaf, and
self-revocation. Its private receipt was bound to plan
`sha256:4e632f41bfc1a1585e1226845974005099f38b2085984e6994942a5f49edbd6d`.
An external read-only query after the gate found no containers, networks or
volumes with the Slice 6 run label; the gate also checked its exact cleanup.
No private key, password, token or receipt body is retained here.

Three earlier attempts signed PostgreSQL leaves but did not reach v2 CRL
confirmation. Their public, non-secret markers are retained here; none is a
revocation receipt:

| Run / failed check | General issuer UUID | Leaf serial / DER SHA-256 |
| --- | --- | --- |
| `3bc980a60cf29193a66fe281a326ad47` / record binding | `7200c0ea-0960-3ae1-4820-7c8d7ef9dab6` | `15:8e:af:1a:10:cd:99:02:23:3a:2b:18:7d:57:f1:22:0b:d7:9e:0a` / `29f0325749776aea83d0609a6ef24fdad3b1c70e2e8ba965eb8de93d26230111` |
| `4812339cae8d16f6b9fd6268c4c90d69` / temporary PostgreSQL bootstrap-server readiness | `7568a965-5c82-1da5-575c-614a2eaa6a08` | `15:6c:14:56:74:a5:dc:bf:77:6b:f1:45:fa:cd:bc:a7:bf:d4:49:e2` / `5ed33669bbd6cee3d144d744c91a1ab722117379953460a21ed6dcdc1772bda7` |
| `987d868f5a745f0f2ffe47fb83352343` / Docker inspect mount-array ordering | `9cf07b88-1fa8-fcad-ee2e-888c21aec5f4` | `42:c5:47:07:53:4a:37:66:46:89:78:63:b8:47:e6:93:70:55:57:93` / `f221db4f75090e030bf8ee4082ac0a4f43584a668b21b23fdb9410b06bbc5988` |

Exact run-labeled Docker resources were absent after each. The successful
later run does not retroactively prove those leaves were revoked. The older
v1 component gap is recorded separately.

## Product SQL bootstrap continuation (2026-10-03)

A further opt-in run of the same tagged real-Docker/Vault component gate
passed in 372.95 seconds from the mutable worktree. The same independent
terminal-operator binary was used. This run started PostgreSQL *before*
revoking the Vault bootstrap root. Its final SQL settings were read back,
including `log_statement=none`, `log_min_error_statement=panic`, disabled
duration/parameter logging, and `password_encryption=scram-sha-256`. The
operator created the `product` database and precreated
`sandbox_runtime_product` schema; it did no Product business DDL. Two
independent native client-side encrypted `createuser --pwprompt` operations
created short-lived, NOINHERIT SCRAM login roles with exact 1/4 connection
limits and no elevation or memberships. SQL readbacks checked database/schema
ownership, PUBLIC revocation, Product-only CONNECT, the migrator's
schema-scoped USAGE/CREATE, and the runtime role's lack of schema rights.
No plaintext SQL password was passed in argv, environment or SQL text; the
test did not independently inspect every Docker daemon or OS memory buffer.

Before root revocation, the two live role DSNs were written through exact
create-only Vault KVv2 version-1 migration/runtime bindings. Each scoped
token read back its own document; cross-purpose and Guest cross-owner reads
were denied, and both temporary token accessors were revoked. After the
managed Product/Guest chain, PostgreSQL stopped and was removed before the
v2 terminal operator confirmed three certificate revocations (including the
mounted PG leaf), two token-accessor revocations, complete CRL and
self-revocation. The run's non-secret leaf DER SHA-256 was
`1f1add46837c5f4b510586c92558009e54d5713f43e0a57c90be4ee54ac7e4de`;
its private terminal plan digest was
`sha256:fac3ab92204a60f1d3ee70bbcb1163874291e51a713a03d5b900f4ccef33ac75`.
The gate's exact cleanup passed; a separate read-only query found no
`sr-p6-` containers, networks or volumes afterward.

This continuation proves provisioning and KV isolation, **not** successful
network login with either DSN. In that run, the Product material observer
resolved only the identity key-ring; Product migration v2, runtime SQL,
client-certificate CRL enforcement, nine live SQL callers and the formal
release scenarios remain open. The run was not an immutable candidate and
did not produce a release manifest.

A second mutable-tree continuation, run
`28bfaecb9d450dfbcdfc6fb8c8d949cb`, passed in 370.83 seconds after
adding a separate Product owner-side DSN witness. Its non-secret PostgreSQL
leaf digest was `sha256:27df71a55ac8bd5f27bdb94f32e6c64f426feafc8d976fe4db9aff6bd05bd691`;
its private terminal plan digest was
`sha256:3764c72938e2e92c2588843a87ddc36f2c9523cd123c1db4041351b6c47f2fef`.
The live Product material-agent resolved the runtime DSN through the
scope-bound Vault path for a distinct UID/GID Product owner. The no-network
observer checked the exact binding and material digest, then parsed the
canonical fixed host/port/database/runtime role and `sslmode=verify-full`
without printing secret bytes. Both controller quiesce receipts, PostgreSQL
stop-before-operator, three certificate/two accessor/complete CRL/self-revoke
terminal confirmation and exact cleanup passed again. A separate read-only
query returned no containers, networks or volumes under this exact run label.
This is DSN resolution and parsing, **not a PostgreSQL login** or Product
runtime readiness.

At this component source checkpoint, the complete
`go test -race -shuffle=on -count=1 ./...`, `go vet ./...`, the tagged Slice 6
race suite, the Product Contract lock verifier and `git diff --check` passed.
The long real-Docker gate still ran from a mutable worktree, so those source
checks do not turn it into immutable release evidence.

This is composed component evidence, **not** the 16-scenario Slice 6 release
gate or a signed evidence manifest. Neither Product DSN was consumed by a
live Product SQL client; nine live SQL callers, the full
78-principal topology, public Product E2E, deployment and production readiness
remain unproved. Phase 6 remains **5/15**.
