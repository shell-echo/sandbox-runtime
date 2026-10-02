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

## Migration input and server CRL continuation (2026-10-03)

Another mutable-worktree run of the same real-Docker/Vault component gate
passed in 372.65 seconds. PostgreSQL loaded a canonical, issuer-signature-
checked, currently valid client CRL from an exclusive PG-owned read-only
private volume; the gate read back the active `ssl_crl_file` setting and exact
mounted bytes. This proves the initial server configuration, **not** a revoked
client's refusal or a live CRL refresh. The non-secret server leaf DER digest
was `sha256:985d8fe3daa00afb555e78c89be349178d585f530e0a294ff1c6e8793ede5065`.
Controller quiesce, PostgreSQL stop-before-terminal ordering, three
certificate/two accessor/complete-CRL/self-revoke terminal confirmation, and
the gate's exact Docker cleanup passed in the same run.

Before process launch, the gate independently prepared the Product migration
material signer, one-shot material agent, PostgreSQL-purpose signer and
migration job's four private config readers. Three distinct owner/agent
socket volumes brought the combined count from 70 to 73. The two signer
configs and one-shot material-agent config were assembled from the same
Profile, keys and peer-CRL source mapping; the job received only its own
PostgreSQL peer-CRL role derivative. No migration agent, PostgreSQL client
signer or migration job was launched in this run, and no Product business
schema DDL was performed.

An implementation gap was found before attempting the job: the explicit v2
migration command still calls the legacy material-registry constructor, which
rejects the required `unix-workload-material.v2` owner/agent socket. The
non-secret migration TOML startup mount also needs a closed admission rule.
Both issues were reported for architecture review. Until the v2 command and
its source-bound candidate image are corrected and the live job completes,
this continuation is **not** a migration, SQL login, release gate or evidence
manifest. Phase 6 remains **5/15**.

## Failed R8 pre-DDL diagnostic (2026-10-03)

The first clean-source R8 (`e98fdf93e87358e682acd3e7ee89118a5f992314`)
Product migration attempt, run `741fed5403cdf6c8ee0e92d3adac1934`, is
permanently **failed / revocation-unconfirmed**. The run composed a real
Vault-backed Profile, started external PostgreSQL, bootstrapped the distinct
Product SQL roles and KVv2 DSNs, and reached managed readiness for the
Product migration material and PostgreSQL TLS signers. Before launching the
migration job or issuing Product business DDL, a new pre-DDL observation
mistakenly reused a Vault-only network helper, which hardcodes `vault` as the
external member; the PostgreSQL bridge instead has `postgres`. Existing
PostgreSQL startup had already observed all nine bridges correctly. This was
a diagnostic harness bug, not evidence that the PostgreSQL service bridge
was absent.

The external PostgreSQL certificate was issued by general issuer
`4eb19270-0ebc-eaee-3d2b-18c3a7bdaf7f`, serial
`47:27:a6:a2:65:6d:8c:8f:3f:e7:63:6d:d1:29:0a:e2:01:49:de:8d`, leaf DER
`sha256:8acc0e0a9c238eec6fa1880b64fc442d1f921c9a29904e334c609bfd6c2f1b33`.
The certificate controller had also issued its own and the credential
controller's managed leaves, plus the two migration signer leaves; their
serials were not retained in the bounded public test log. Workload-scoped
credentials and temporary Vault token accessors were used; the bootstrap
root was revoked before the managed chain, but this failure did not produce
a final three-certificate/two-accessor terminal receipt or complete CRL.
No remote revocation of those managed leaves is claimed.

The failure bypassed normal dependent-process/controller shutdown and the
terminal operator. The test's run-label cleanup reported success. An
independent post-run read-only query found zero containers, networks and
named volumes under this exact run label; the run-private
`.sr-vault-trust-switch-*` directory was absent from the package directory.
Vault's image-created anonymous volume identifiers were held only in the
terminated test process; its `docker rm -v` cleanup was invoked, but a
separate exact-ID anonymous-volume readback was skipped on this failure
path, so that class is not independently confirmed. Physical deletion and
eventual certificate expiry are not remote revocation. The old issuer and
secrets will not be recreated or used to manufacture a retroactive receipt.

## Controlled pre-DDL failure and terminal continuation (2026-10-03)

The next real-Docker/Vault/PostgreSQL run, `f2d81cef978fb03f3cc9080cd3f6f419`,
used the frozen R8 candidate/Profile source revision
`e98fdf93e87358e682acd3e7ee89118a5f992314` and a terminal operator
built independently from that **same** clean checkout. It was intentionally
failed after the Product migration material path verified the exact
PostgreSQL bridge member and before creating the migration PID1 or applying
business DDL. The test failed with `controlled pre-DDL Product migration
failure`; it must not be counted as a green migration gate.

The failure propagated through the dependent-process teardown. Both migration
TLS signer sockets were observed cleaned. Both controller PID1 processes
persisted quiesce receipts; the credential controller was stopped before the
certificate controller. The certificate controller retained the known sticky
`credential-revoke` exit, so the independent terminal operator ran. Its
private receipt confirmed three certificate revocations, two token-accessor
revocations, the complete CRL and self-revocation, with plan digest
`sha256:74f13d61e56c5d92b4fbdd6fa701e9b6cfdfec3099cdb2ead4d59461b3e1ba49`.
The PostgreSQL PID1 stopped and was removed before terminal certificate
cleanup. Exact run-label cleanup reported success; a separate read-only
post-run query found no containers, networks or named volumes under the run
label, and no `.sr-vault-trust-switch-*` directory. The image-created
anonymous Vault volume IDs were not retained for a separate ID-based readback;
their independent post-run state is therefore unconfirmed.

This closes the specific terminal-bypass failure demonstrated by the first
R8 attempt, not the normal migration or 16-scenario release gate. No release
manifest was generated. Phase 6 remains **5/15**.

## Normal R8 migration attempt: DDL outcome unknown (2026-10-03)

A fresh-issuer/fresh-PostgreSQL run `6a772dcba60fc814b3d57c7adfe80cbf`
reached both migration-purpose TLS signer listeners and launched the
independent migration attempt. The attached Docker start returned an error.
The then-current harness cleared raw output and reported only that PID1 did
not provide a confirmed successful DDL result. It did **not** retain bounded
process-state classification or inspect the SQL ledger before PostgreSQL
teardown. Consequently neither the process startup stage nor DDL commit
outcome is established. No same-database replay occurred; the database was
removed during exact cleanup. Later diagnostic changes cannot retroactively
fill this evidence gap.

Both signer sockets cleaned, both controller quiesce receipts persisted, and
PostgreSQL stopped before the same-source R8 terminal operator. Its private
receipt confirmed three certificates, two accessors, complete CRL and
self-revocation with plan digest
`sha256:4ed433f5c67cccc2755822f5bdf41b418020b92500ac192dc8dd06c573f7161d`;
the independently built operator digest was
`sha256:f11aece71e588f185f20323caabd79041b9ae05ffd7a2912d304b882945ceb60`.
The run-labeled cleanup reported success. Separate read-only Docker queries
found no exact-run containers, networks or named volumes and no run-private
`.sr-vault-trust-switch-*` directory. The anonymous Vault volume class again
lacks independent exact-ID post-run readback.

Architecture review found an additional latent flaw in the not-yet-reached
success readback: its default-future-table grant exceeded the approved
current-table-only Product SQL bootstrap boundary. The mutable gate harness
must separate read-only failure observation from successful verification and
atomic current-table grants before any further real signing run. This
attempt is permanently **failed / DDL-outcome-unknown**, not a migration
component pass or release evidence. Phase 6 remains **5/15**.

## Test-only diagnostic and grant boundary before another issuer

The mutable gate harness now keeps Docker start output under a hard shared
stdout/stderr cap and maps only single-line, exact known errors to public
stage names. It reads Docker's bounded `State` and restart count, classifying
status, exit/OOM, started/finished presence and a closed State.Error class;
raw daemon/process error text is neither logged nor emitted. Every post-start
failure branch attempts a bounded, explicit `BEGIN READ ONLY` catalog/ledger
observation before PostgreSQL teardown. This separates absent ledger, zero
commits, partial or inconsistent digest rows, exact R8 14-file ledger,
unavailable database, and active migration login. An absent ledger is not
interpreted as proof that no DDL was attempted. Unknown results are never
automatically replayed on the same database.

The success path no longer grants `ALL TABLES` and never changes default
privileges. It checks the frozen R8 SQL's exact 29 table names, the 14 source
digests, object ownership and zero migration connections, then grants schema
USAGE, ledger SELECT and current-table SELECT/INSERT/UPDATE/DELETE only in one
transaction. A SQL assertion rejects ledger write, schema CREATE,
TRUNCATE/REFERENCES/TRIGGER, grant options and Product migrator default ACLs
before commit; post-commit rights are read back under a separate read-only
transaction. A disposable no-network PostgreSQL 16 Alpine syntax probe
verified both the missing-table rollback and successful exact-table grant,
and verified the bounded zero-ledger/catalog readback. The probe container
was removed. Tagged Slice 6 race tests, focused core/config/material/egress
race tests, tagged vet, full `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, the Product Contract lock verifier and `git diff --check`
passed at this harness checkpoint.

These are harness/audit changes only. The R8 candidate images and clean
source remain frozen; no new issuer or database was created for this
diagnostic repair. No normal Product migration success or release manifest is
claimed. Phase 6 remains **5/15**.

## Instrumented R8 migration connection failure (2026-10-03)

Fresh run `cc1ad1011c390330b51bbccc78826ca5` retained the same clean R8
candidate source and same-source terminal binary. Its Product migration PID1
actually started and exited with code 1, OOM=false, restart count 0,
started/finished timestamps set and empty Docker State.Error. The process's
single-line exact whitelisted error was `migration v2 PostgreSQL connection is
unavailable`; the bounded public category is `migration-connect`. Before
PostgreSQL teardown, independent explicit READ ONLY catalog SQL found the
precreated Product schema, no `schema_migrations` relation and zero ordinary
Product business tables. This proves no committed migration was observed in
that database, **not** that the process never attempted connection or DDL.
The underlying `openDirectV3Postgres` substage remains unknown because the
production command intentionally collapses it to one safe error.

Both purpose-specific TLS signers cleaned their sockets, both controllers
persisted quiesce receipts and PostgreSQL stopped before terminal cleanup.
The private terminal receipt again confirmed three certificates, two token
accessors, complete CRL and self-revocation, plan
`sha256:ac682db7407550de5388592062fb699560a53b629b40a32d773a424cc12a60be`,
with independent R8 operator binary
`sha256:f11aece71e588f185f20323caabd79041b9ae05ffd7a2912d304b882945ceb60`.
Docker event metadata recovered the exact run ID after the test; independent
post-run queries found zero labeled containers, networks and named volumes,
and no run-private directory. Exact-ID anonymous Vault volume readback is
again unavailable after teardown. No same-database migration replay or new
privilege grant occurred. This is a **failed component run**, not a release
gate or evidence manifest; Phase 6 remains **5/15**.
