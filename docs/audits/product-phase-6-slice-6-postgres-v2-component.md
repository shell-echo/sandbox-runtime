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

## R9 local migration-stage diagnostic decision (2026-10-03)

Sandbox approved one minimal production-internal correction after the R8
`migration-connect` observation. `openDirectV3Postgres` now selects a closed
stage from trusted control flow for authority, signer client, peer role,
peer-guard construction/bootstrap, TLS client, material resolution, DSN/pool
binding, own-guard construction/refresh, pool creation and monitor start.
Only the local one-shot migration command projects that fixed stage. Product
and Provider runtime callers retain their previous generic error text; no
Provider or Product Contract, public DTO or client error gains the diagnostic.
An unknown stage or untyped error falls back to the generic migration error.
No raw cause, endpoint, host path, socket, SQL, DSN, credential or certificate
identifier is formatted into the result. The existing bounded PID1 output
limit remains in force.

This changes the runtime source and invalidates R8 as evidence for the next
attempt. The follow-up must freeze R9 source and rebuild the exact role
candidates before issuing another real Vault/PostgreSQL attempt. The new run
will record Vault image-created anonymous volume IDs at container creation
and independently inspect those exact IDs after cleanup; earlier runs remain
unconfirmed on that one point. The diagnostic is not a migration-success or
production-readiness claim. Phase 6 remains **5/15**.

## R9 migration output classification failure (2026-10-03)

R9 runtime source `e3d0e96ef885546a8f74d7a3a59d566a5ace8337` passed the full
race/shuffle suite, vet, tagged Slice 6 tests and Product Contract verifier.
All twelve repository role candidates and the Desktop local candidate were
rebuilt from that clean source; the independent image-supply and resource
draft preflights passed. Fresh real run
`6dbaedac069722a749f243e80f47eaca` composed the 78-principal Profile,
Vault issuers/KVv2, controller processes, nine-bridge PostgreSQL and scoped
Product SQL roles/material. Its Product migration PID1 started and exited 1,
with OOM=false, restart count 0, start/finish timestamps and no Docker State
error. Before PostgreSQL teardown, read-only SQL observed the precreated
schema, no `schema_migrations` relation and zero business tables. This is no
observed committed migration, not proof that no connection or DDL was tried.

The test-only failure observer still recognized only the old exact
`migration v2 PostgreSQL connection is unavailable` line; the newly approved
CLI's closed `: stage=...` form was absent from its allowed set. The observed
category was `unknown`, while bounded raw process output was cleared and the
container removed. Therefore this is a proven producer/consumer compatibility
gap, **not** proof that this particular process actually emitted a stage
line. The run did not establish the specific connection substage and cannot
be retrospectively reclassified from its process-state/SQL observations.
Sandbox approved a test-observer-only repair and one further run after
producer/consumer consistency and CLI output-boundary checks.

Both migration signer sockets were cleaned, both controller PID1 processes
quiesced, PostgreSQL stopped, and the independent terminal operator confirmed
three certificate serials, two token accessors, complete CRL and
self-revocation under private plan
`sha256:509ab25e56472bf618df5ce97e1a2e019d9d156f03f61e774afcef3c50d5b54a`.
The run captured the Vault image's two anonymous volume IDs at creation and
the exact-ID post-cleanup check passed. A separate post-run query found no
run-labeled containers, networks or named volumes. The non-secret PostgreSQL
leaf digest was
`sha256:fb4d2b52c337d2918bcb28e00035945e029f0472fe3497cc6c2bb363d7a29587`.
No release manifest was emitted. Phase 6 remains **5/15**.

## E-only stage-observer repair before one approved repeat (2026-10-03)

Sandbox approved a strictly test-observer-only correction, not a new runtime
or issuer path. Commits `7577cf0bb029f83f07c05e9347461a5b9831ab68`
and `e5ffb8d3def38162f239340ca414847d1d52e38e` change only `_test.go`
files. The runtime source stays frozen at R9
`e3d0e96ef885546a8f74d7a3a59d566a5ace8337`; the clean candidate checkout
is detached at that revision. The E checkout has only this audit update
uncommitted while recording the result. R9 role manifests and Desktop candidate
remain in separate private 0700 directories; neither was rebuilt for the
E-only change. Representative candidate identities are the Product core
image `sha256:165ff49f1f4010270b33a11b6799ddc2ee33d491814cc125fac5111b0be69462`,
Product role manifest
`sha256:8e0d253898446fd04b71afea7cfcd28f966825b06744b77a444a997ed65cf63e`,
and Desktop image/manifest
`sha256:72572fdcd7c36523ceb9469b148378e55477fc686b5508ea32068bb883e695a0` /
`sha256:30b8fef0e210dc6c0be8fd79e2a253c02985bfa9b0f65760af451bfe67229dae`.
The other eleven role identities remain in their independently verified R9
private manifests, rather than being substituted with a later source build.

The observer now accepts only the thirteen complete, case-sensitive fixed
stage lines plus its prior generic line. A tagged test extracts the actual
closed stage constants and formatter switch from the clean R9 source, verifies
the exact thirteen-to-thirteen mapping, then checks that each line survives
the independent observer. An actual bounded stdout/stderr capture path passes
one fixed line and rejects extra combined output; a local CLI subprocess
checks Cobra suppression, `errors.Join`, initialized `logger.Sync`, and a
single `Fprintln` line without an issuer. Unknown values, casing drift,
prefix/suffix, multiple lines, CR/NUL, oversized and credential-like samples
remain `unknown`; no raw output is retained. Focused tagged race tests and
cmd race tests passed. The harness now keeps only fixed output-shape and
length buckets on any failed migration; it clears the raw bytes before
reporting. The full post-E `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, tagged Slice 6 race/vet, Product Contract verifier and
`git diff --check` passed before the next issuer. If a new run
still yields `unknown`, stop and investigate those non-secret capture buckets;
do not repeat the same setup.

## E-observed R9 peer-bootstrap failure (2026-10-03)

The single Sandbox-approved repeat, run
`a2f6f59c68af29a2e6e57d188eae5018`, used the unchanged R9 runtime
candidate source `e3d0e96ef885546a8f74d7a3a59d566a5ace8337` and the
E-only observer at `d6d3fe3cf57f4ccb387d359bd783dc632e646584`.
Its real Vault/Profile identity was
`sha256:e26f471af790a91b30cd02cd1b4458a2b52a5c40ef78ec1c9cc02f42cda6c209`.
The Product migration PID1 started and exited 1 with OOM=false, no restart,
start/finish timestamps and no Docker State error. The exact fixed output
classification was `migration-connect-peer-bootstrap`, and only the finite
shape/length `one-lf/65-128` was retained. This identifies the first live
PostgreSQL peer-CRL bootstrap guard boundary; it does **not** identify whether
the failure was socket admission, client/controller request, Vault response,
bounded timeout, binding, signed CRL verification or freshness. No raw
process output or credential was retained.
The frozen desired TLS values for this role are 10-second connection drain
and 30-second maximum CRL staleness; `derivePeerCRLBudget` caps the complete
first pull at 2 seconds. That bound is confirmed source configuration, **not**
evidence that this failure was a timeout, and it was not relaxed.

Read-only SQL before PostgreSQL teardown found the precreated Product schema,
no `schema_migrations` relation and zero business tables. No committed
migration was observed, but no claim is made that the process never attempted
a connection or DDL. Both signer sockets were cleaned, both controller PID1
processes quiesced, PostgreSQL stopped, and the independent terminal operator
confirmed three certificate serials, two token accessors, complete CRL and
self-revocation with private plan
`sha256:bc6b8a30a178eeba1e58bb1731c84801f181b5bb5b6ce8ebdbb9516cf719ba0f`.
The server-leaf DER digest was
`sha256:767d665bf41068ff051555a57e36c8be5403c67eb905a35fcecb386663f1c37c`.
The two Vault image-created anonymous volume IDs were captured at creation
and their exact-ID post-cleanup absence check passed. An independent post-run
query found zero run-labeled containers, networks and named volumes.

This failed component run has been reported to Sandbox for the next
architectural/diagnostic boundary decision. It does not advance the 16-scenario
Slice 6 release gate or issue a manifest. Phase 6 remains **5/15**.

## Offline peer-CRL diagnosis and cancellation repair (2026-10-03)

Sandbox allowed one finite no-new-issuer diagnosis after run
`a2f6f59c68af29a2e6e57d188eae5018`. The original run's internal agent,
controller and Vault timing/status were not retained and cannot be recovered
from the terminal cleanup. The observed stage alone does not distinguish a
socket failure, signed-request/source mismatch, controller queue delay, Vault
read, CRL verification or freshness rejection.

The closed final-Profile fixture was checked for all nine logical PostgreSQL
signer owners: each exact outbound edge, local subject, external server
anchor and general-issuer digest resolved its single fixed source; mutations
of edge, subject, direction, anchor and issuer were denied. This is synthetic
Profile binding evidence, not a reconstruction of the cleaned run. The
real-gate composer source inspection selects its `general` Vault issuer for
the PostgreSQL logical server edge, not the separate PostgreSQL client
issuer. Agent/controller request and response code binds Profile, source
mapping, edge/direction, issuer, nonce, deadline and signed CRL. Both Unix
hops enforce local socket identity and bounded operation/cancellation. These
checks make a simple static tuple swap less likely; they do not exclude a
same-run runtime/config or timing failure.

A controlled fake-issuer diagnostic blocked certificate issuance after the
controller had persisted its nonce. It confirmed the controller mutex stayed
held across the external call. A second ordinary CRL request passed its
initial context check, was then canceled while queued, and returned success
after the issuer was released because the fake authority ignored cancellation.
The deliberately failing diagnostic reported
`queued CRL continued after context cancellation: <nil>`; it was removed
before the retained regressions. This proves the controller's pre-admission
cancellation gap, not that production Vault returned success or that it
caused R9's peer-bootstrap failure.

The full `PeerCRLSources.AuthorizedSourceID` path on an Apple M4 local test
host averaged 41.28 ms/op, 59,865,776 B/op and 400,694 allocs/op over three
non-race benchmark iterations of a synthetic final Profile. Agent and
controller both run source authorization on a pull. This is a local cost
sample, not a restricted-container latency distribution or proof that the
fixed 2-second budget was exceeded. No production timeout was widened.

Sandbox approved a single-slot, context-aware controller admission permit
while preserving the original serialized replay persistence, authority I/O,
ledger mutation and quiesce order. The code now checks caller cancellation
and a locally parseable, in-range claimed request deadline before admission and again when
the permit is received. Reaping and quiesce accept lifecycle contexts; server
stop cancels both queued handlers and its reaper before controller key/policy
destruction. Focused race regressions cover v1/v2 queued cancellation and
expiry, simultaneous permit/cancel readiness, unchanged replay state,
subsequent permit use, quiesce/reap cancellation, server close, repeated
close and exact socket removal. Existing tests retain quiesce persistence
failure/restart and signed normal/invalid peer-CRL response coverage. This
repair keeps external I/O serialized, so it is not a throughput fix.

The R9 candidate image/manifests predate this source repair. Until a new
clean-source candidate is frozen, the complete required source checks and
real same-run gate pass, no migration success, Product runtime readiness,
16-scenario release gate, strict evidence manifest or production safety is
claimed. If the next single approved real run again stops at peer-bootstrap,
the current stage cannot by itself be interpreted as a regression of the
permit repair or as permission for repeated issuer-consuming retries. Phase 6
remains **5/15**.

After the repair, `go test -race -shuffle=on -count=1 ./...`, `go vet ./...`,
the tagged Slice 6 race/vet package checks, Product Contract lock verifier,
and `git diff --check` passed. The tagged Docker
`TestDockerDistinctUIDTwoAgentCertificateController` passed with its pinned
Alpine image; a separate query found no `p6-pki-` test containers or volumes.
These are source, component and socket-isolation results, not a new
source-bound Product migration or release observation.

## R10 immutable inputs and pre-issuer correction (2026-10-03)

R10 source `1b07a0ea6ccc7979475a414c88d6899a511424a8` was rebuilt as
twelve clean-source role candidates plus one Desktop candidate. The separate
source checkout and the candidate manifests were clean and bound to that same
revision. The role/Desktop/Browser preflight passed; the four complete pinned
external archives and five-name topology component also passed. These are
static input checks, not a live migration result.

Two subsequent invocations of the real Vault trust-switch test failed because
of test-operator input errors, not an observed migration failure. The first
used an older terminal-operator source checkout and failed before Docker or
issuer creation. The second used a selected-manifest-only Vault OCI tar in
place of its complete 171 MB archive. It started non-dev Vault, generated the
general and broker CAs and signed the final Vault server/controller client
leaves, then failed at source-bound profile composition with `external image
archives`. It never launched the managed certificate controller or Product
migration PID1. Docker run-labeled cleanup returned without error and a
separate broad-name query found no remaining `sr-p6-` resources, but the
anonymous-volume exact IDs were not retained through that early exit. The
later terminal operator and bootstrap root revocation steps were skipped.
Resource deletion is not revocation proof; no receipt is retroactively
inferred for the deleted run.

Sandbox approved one corrected R10 real run, conditional on a test-only
pre-issuer static-input gate and early-exit cleanup check. The live harness
now freezes source/root/revision, terminal source, role/Desktop/Browser
candidate and all four external archive locations/digests once. It checks
the clean source and fully reopens those immutable image inputs before
allocating a Docker run or launching Vault; composition still independently
reopens the same snapshot after issuer creation. A no-issuer regression
rejects both a stale source revision and the selected-only Vault archive.
The harness logs the exact run label, Vault container ID and both anonymous
volume IDs and checks their absence in `t.Cleanup`, including failure paths
that exit before the ordinary terminal block. Exact Docker deletion evidence
remains distinct from Vault token/certificate revocation evidence. None of
these harness changes require rebuilding R10 runtime candidates or advance
Phase 6 beyond **5/15**.

The one approved corrected-input R10 run used the complete Vault archive and
the same R10 source for the terminal operator. Pre-issuer static verification
passed before Docker allocation; all eleven source-bound composition stages,
including final source reopening, passed. The real Vault, PostgreSQL PID1,
both controller PID1 processes and Product migration material/PostgreSQL TLS
agents started under their reviewed identities. The migration PID1 still
exited 1 at `migration-connect-peer-bootstrap`, with output shape
`one-lf/65-128` and read-only SQL summary
`ledger-absent-catalog-0-0-0-0`. A connection or DDL remains unconfirmed.
This same-stage result does not prove which part of the agent/controller/Vault
peer-CRL pull failed or that the R10 permit repair caused the failure.

Run label `ba3e519f47bf67e213b22d5dd3b36d99` and Vault container
`4b4d2ecad9ad2038a6d6a3460c4bacd893694b8e1fe7fab3e8ecada9f38e494d`
were observed. Both exact Vault anonymous-volume IDs were captured and their
post-cleanup absence verified. The independent terminal operator confirmed
three certificate serials, two token accessors, complete CRL and self-revoke
under receipt plan
`sha256:4246d9962b94a038e740be0509c61b261b6704ab99899254511773b15ff59b7a`.
PostgreSQL stopped; exact Docker cleanup returned no error; a separate
run-label query found zero containers, networks and named volumes. This is a
failed migration component run, not a Slice 6 release manifest. The next
diagnostic must change method and cannot simply repeat issuer-consuming R10.
Phase 6 remains **5/15**.

### No-new-issuer Product migration peer-CRL cost sample

The next diagnostic used a complete synthetic final Profile, its full fixed
peer-source inventory and owner `product-migration-job`; it did not reuse
historical run credentials or reconstruct the removed run. A Linux/arm64
test binary (`sha256:b88ed30f2a69437f35dbd2a241528841dc1b7bbe6130395b2a66b9bd202cc660`)
was built from the R10 base plus benchmark source
`sha256:d02b6f031fc3f5a14996b201f0b879c79e9dab686f9b0e727cde91438129fec5`.
It ran in one-shot, non-root, cap-dropped, read-only, networkless containers
using the locally pinned Alpine image. Exact test-labeled containers,
networks and volumes were zero after the runs.

Under the reviewed TLS-agent limit of 50m CPU, 64 MiB memory and 16 PIDs,
one `IsSlice6FinalPostgresPeerEdge` call took 7.097 seconds and one
`AuthorizedSourceID` call took 7.510 seconds. The explicit sequence of one
owner-edge check plus two source authorizations (agent and controller in one
50m container, so **not** the real two-container timing) took 21.798 seconds.
The reviewer's controller limit of 200m CPU, 128 MiB and 32 PIDs gave a
two-iteration `AuthorizedSourceID` mean of 1.145 seconds per call. Each
authorization allocated about 59 MB cumulatively; this is **not** peak RSS.
The agent's actual first-pull code invokes both owner-edge check and source
authorization before its controller call, while `PeerCRLGuard` bounds the
entire initial pull to 2 seconds. These synthetic component measurements show
that the current repeated immutable-Profile validation is incompatible with
that budget under the tested quota. They do not prove that it was the sole
cause of the deleted R10 run's peer-bootstrap failure; no same-run inner
timing/error-class receipt survived cleanup. A constructor-time validated,
private fixed-binding lookup was proposed to Sandbox, with no CRL cache,
policy relaxation, timeout increase or new issuer run authorized by this
sample alone.

### Successor private-index and closed failure-class checkpoint

Sandbox approved a constructor-time private authority index and local-only
closed peer-bootstrap failure classification in one successor runtime revision.
Runtime R `ac525c615bfb788607da716ce8736e7babfd8fd0` (tree
`756ebed251898520c4713e44e5f68c79f377d537`) freezes the changes but
has not consumed a new issuer. A strict private-copy constructor validates the
same typed Profile/source snapshot before compiling exact
profile/mapping/edge/principal/direction/anchor/issuer/owner bindings. Agent
and controller use independent indexes; the controller's signer purpose and
PostgreSQL owner come from its separately copied policy. The old public
`AuthorizedSourceID` still fully validates arbitrary mutable documents.
Neither index caches CRL evidence or changes freshness, signature, nonce,
Unix peer, deadline, Vault read, timeout or drain behavior. Direct controller
tests reject ordinary-to-PostgreSQL, PostgreSQL-to-ordinary and wrong-owner
reads before Vault authority; agent tests reject mapping/owner drift before
controller. Complete-source equivalence covers nine PostgreSQL owners plus
ordinary and DNS edges, mutation, duplicate/zero and concurrent lookup.

The local diagnostic distinguishes `local-guard`, parent cancellation or
deadline, internal deadline, agent request build, socket/peer, transport,
generic agent error/unverifiable response, guard binding, CRL semantics and
`unknown`. Parent context wins when both parent and internal timers fire.
An agent error frame cannot be called a controller rejection. Error text stays
generic, raw causes are not unwrapped, and only the migration one-shot CLI
projects an exact stage/class line. The E-only bounded observer rejects
unreviewed, multiline, duplicate and oversized output; producer/consumer
source matching remains a freeze-time gate. Component fault injection covers
the major branches and a long malicious error string.

For constructor cost, an opt-in synthetic final-Profile/full-source fixture
was exported without issuer use (`profile.json`
`sha256:e5770cffabfe2575967b39f61016bf36ff72a91d13fd35011a57e09fbd944c9e`,
`sources.json`
`sha256:6848e55cae6b07ca535d03c1d0939463598cb9d8e74ca7cfe0f2b9976f7036ba`).
The actual `NewPostgresControllerPeerCRLProvider` constructor was measured
under the reviewed agent 50m CPU/64 MiB/16-PID quota, non-root, read-only,
cap-dropped and networkless. Its first private-index version took 12.099
seconds and 109.8 MB cumulative allocation (one iteration). Reusing the
already validated private snapshot and the source validation's own
PostgreSQL-owner projection reduced the same constructor to 6.690 seconds
and 61.3 MB cumulative allocation (one iteration); the latter binary is
`sha256:50be26c4c8a7d48e146076786be0a0fe734c19a6d012a71fad45647161684cb7`.
The prior 50m compiled-lookup samples were 15.9–42.0 microseconds, two
iterations each; a 200m controller compiled lookup was 9.3 microseconds,
one iteration. These tiny samples are component observations, not an SLO.
Allocation numbers are cumulative, not peak RSS. The measured constructor
excludes initial file decode, CLI configuration and manager bootstrap, so it
cannot alone prove the 45-second socket-ready startup gate. The 2-second
Product migration peer-CRL first-pull budget is a different clock; the TLS
agent's `manager.Bootstrap` has its own 15-second parent deadline, started
after provider construction. None of these values was changed. Constructor
drift rejection passed against the same fixture on the host. This opt-in test is skipped by the
default `./...` suite unless
`SANDBOX_RUNTIME_PEERCRL_CONSTRUCTOR_FIXTURE_DIR` points to that fixture; it
was separately executed with fixed host test binary
`sha256:85a2d4f0f9abcd124a8a14fc3636c344ec93447e1b563279321465cd9e84d401`
using `-test.run '^TestPostgresControllerPeerCRLProviderConstructorRejectsDrift$'`
and passed. The full repository `go test -race -shuffle=on -count=1 ./...`,
`go vet ./...`, Product Contract lock and diff checks passed before R froze.
The tagged Docker distinct-UID TLS-agent and two-agent certificate-controller
tests passed with separate post-test zero container/volume queries. From a
separate clean checkout of R, the E-only producer/strict-observer test passed
under race. These are component and source-coherence checks, not a live
issuer/SQL result. All labeled benchmark containers were
independently queried absent after `--rm`; no Vault token, certificate,
PostgreSQL DDL or Slice 6 release evidence was created. Phase 6 remains
**5/15** pending source-bound real gate and strict
manifest.

## R11 source-bound pre-issuer inputs (2026-10-03)

Successor runtime R `ac525c615bfb788607da716ce8736e7babfd8fd0`
remains an independently clean checkout. Its twelve local-role candidates and
Desktop candidate were rebuilt from R; the Browser archive was reopened by
the source-bound role/Desktop/Browser image-supply preflight, which passed
under race in 159.05 seconds. Independently, all four complete pinned
Vault/PostgreSQL/Valkey/DNS OCI archives passed the five-service external
image-supply component. The one-shot Linux/arm64 terminal operator was built
from the same clean R source (`sha256:68db76678b088d7f88a0edb27dc758fbd3285be51148fad166257f42d017dcec`)
and returned the exact v2 capability in a non-root, networkless, bounded
Docker preflight container. That container was subsequently absent. These
checks did not launch Vault or issue a certificate.

The first E-only negative-input attempt exhausted its three-minute context
while repeatedly reopening the full role/Desktop/Browser supply. Its error
category was therefore **not** proof that the deliberately incomplete Vault
archive had been rejected. Sandbox approved a narrower test-harness change:
the existing complete external-archive check now precedes the independent
role/Desktop/Browser check, while both remain mandatory for positive
admission; the negative test additionally rejects any result after context
expiry. The three-minute negative-test budget and all live process deadlines
remain unchanged. With this correction, the same admission function rejected
both the stale source revision and selected-only Vault archive before any
Docker run or issuer, in 0.09 seconds under race. The tagged E package race
suite, vet and diff check passed. This is pre-issuer component evidence only;
the approved one-time real Vault→Product migration gate remains separate,
and Phase 6 remains **5/15**.

## R11 single real migration attempt: first pool ping failed (2026-10-03)

The one Sandbox-approved real attempt used immutable runtime R
`ac525c615bfb788607da716ce8736e7babfd8fd0` and separate gate E
`fa77a5152dbf72513f677fc33cfc64861acc2beb`. Run
`23facffa64d091eebe19885a0b450770` passed the pre-issuer source and
complete-image preflight, then composed all eleven source-bound stages and
launched real Vault, PostgreSQL and both controller PID1 processes. The
Profile digest was
`sha256:464dcaa1a321cbdb5a3a1dea56bba2e24560b5bf76e03503076de603cfba544c`;
the mounted PostgreSQL leaf DER digest was
`sha256:26f9d2a83ca5bb9601ec9aa1127dce972abaad234c720e6243d92342ee78e80e`.
The two Product migration TLS agents reached their signer sockets after
21.212 and 20.781 seconds respectively at the unchanged 50m CPU, 64 MiB,
16-PID Profile limits, both under the 45-second socket-ready bound.

The independent Product migration PID1 exited 1 with the strict closed
category `migration-ping`, bounded output shape `one-lf/1-64`, and state
`exited|1|false|0|started-set|finished-set|state-error-none`. The read-only
same-database SQL observation was `ledger-absent-catalog-0-0-0-0`: no
confirmed Product business DDL. This passed the previous
`migration-connect-peer-bootstrap` failure point: construction returned a
pool after initial peer and own-client guard refresh. It did **not** prove
that a PostgreSQL network connection, TLS handshake, SCRAM authentication or
`AfterConnect` privilege verification succeeded. The CLI deliberately wraps
all `pgxpool.Ping` causes in the same generic line; the present evidence
cannot assign a more specific cause. No same-issuer retry is authorized or
performed.

Both controller PID1 processes persisted quiesce receipts. The independent
same-R terminal operator confirmed three certificate revocations, two token
accessor revocations, a complete CRL and self-revocation under private plan
digest `sha256:79da10de395af57acdfbb221e4388fcb2ae4b855840438b7b529f74ded1d615d`.
PostgreSQL stopped before terminal cleanup. The test reported exact Docker
cleanup and both captured Vault anonymous-volume IDs absent. A separate
read-only post-run query found zero containers, networks and named volumes
under the exact run label, both anonymous volume IDs absent, and no local
`.sr-vault-trust-switch-*` directory. Physical deletion and revocation are
reported separately. This is a failed component gate, not a migration or
Slice 6 release pass; Phase 6 remains **5/15**.

### No-new-issuer first-connection investigation

Source inspection found that `runMigrationV2` starts its existing 60-second
context before constructing the material registry and direct PostgreSQL
client, then calls `pgxpool.Ping` only after pool creation. The locked pgx
v5.9.2 pool is lazy; its `Ping` acquires one physical connection and runs one
empty query. The R11 category therefore cannot identify whether the failure
was caller-budget exhaustion, exact dial, TLS/guard/client certificate,
PostgreSQL startup authentication, `AfterConnect` SQL validation or the Ping
query. Docker's event history no longer contained the migration container's
start/die events at the time of a later read-only query, so no exact PID1
duration is reconstructed from those events. The harness checked requested
pre-start IPAM addresses, not a live effective migration endpoint; that
observation cannot be retroactively invented after exact cleanup.

Three independently disposable no-Vault PostgreSQL Docker components passed:
`TestRealMigrationPreDDLPrivilege` (3.51s),
`TestRealPostgresClientCRLActivation` (2.54s) and
`TestRealSharedPostgresNineSourceHBA` (13.92s). The latter exercised all nine
source addresses plus wrong role, database, SCRAM password, missing client
certificate and wrong CN denials. A separate post-test query found no
`p6-migration-ddl-*`, `p6-pg-crl-*` or `p6-shared-hba-*` containers, networks
or volumes. These isolate components with synthetic credentials and do not
establish the R11 combined connection or identify its root cause.

Sandbox approved a private, one-shot migration-only closed classifier and a
strict E observer for a successor source revision, with no new issuer run.
Focused race fault injection covers original-hook call count, exact dial,
TLS/guard callback, `AfterConnect`, typed PostgreSQL rejection, acquire versus
query, caller cancellation/deadline priority, malicious private text,
existing peer-CRL sentinels and concurrent pool close. It caught a typed-nil
`*pgxpool.Conn` interface panic in the new diagnostic's first cancellation
test; the production adapter now converts the failed `Acquire` to a true nil
interface before `Release` can be called. A disposable no-Vault PostgreSQL
classifier integration exercises healthy Ping, synthetic `AfterConnect`
failure and wrong-password server rejection. Its first version was flaky
because `pg_isready` could observe PostgreSQL's temporary initialization
server; after waiting for the final initialization marker and loopback
forwarding, five consecutive runs passed. Its exact test containers were
absent afterward. This fixture correction is **not** an explanation of the
already deleted R11 run. No production timeout, identity, SQL privilege,
network path or CRL policy was relaxed; Phase 6 remains **5/15**.

The diagnostic runtime source was frozen as R2
`01c581afb9b77b2028677fe98a999a5e25d0c75c` (tree
`f9044c18bcc701677ae269b1e9ce4737462910e4`) and opened in a separate
clean checkout. The complete `go test -race -shuffle=on -count=1 ./...`
(including `internal/phase6security` 341.047s), `go vet ./...`, tagged E
race/vet package, Product Contract lock verifier and diff check passed on the
working source before this freeze. The disposable classifier PostgreSQL
integration passed five consecutive runs after final-init admission. The E
producer/strict-observer parity test then passed under race against the
independent clean R2 checkout. These remain source and component checks; no
R2 role/Desktop candidate image, real Vault migration, release scenario or
manifest has been admitted by this result. Another issuer-consuming run
requires separate Sandbox review, and Phase 6 remains **5/15**.
