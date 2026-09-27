# Browser action-ingress process (Phase 6 candidate)

`browser-action-ingress serve /absolute/path/to/authority.json` runs the
separate Browser CDP write boundary. It is not the historical Provider-side
`browser-egress-gateway` and does not own Product grants, Provider sessions,
Docker, or either PostgreSQL authority. The executable is a Slice 6 source
candidate, not a deployment-qualified service.

The authority file must be a non-empty, mode-0600 regular file containing
one canonical JSON object with protocol
`sandbox-runtime.browser-action-ingress-authority.v1`. Duplicate, unknown,
missing, trailing, and noncanonical fields are rejected. It pins the Phase 6
security profile and peer-CRL role file/digests; the exact numeric
Gateway→ingress listener and ingress→Browser Provider origin; the distinct
ingress TLS and material agents; two uncached `KindSecret`/`_system` binding
documents; an expected ingress-only Valkey ACL user and separate witness
database/user; and bounded namespace, capacity, lease, action, session,
credential-poll and operation limits. It contains references and binding
documents, not the Valkey password or witness DSN. The process prints only
redacted stage errors.

The `action_timeout_millis` authority is separate from
`operation_timeout_millis`: it must cover two bounded uncached material-agent
reads, the external fence work and the Provider write, while remaining at
most 30 seconds. A one-operation timeout reused as the whole action budget
would make healthy credential revalidation fail under ordinary latency.

Startup is fail-closed: verify the profile and exact binding/agent identities,
bootstrap the three live CRL guards, resolve both secrets through the
ingress-only material agent, construct profile-derived alias-only broker
tunnels and TLS-verified external clients, then verify existing Redis capacity
policy and independent PostgreSQL witness state. The runtime never calls
`Provision` or repairs missing shared state. Gateway mTLS alone cannot open a
Browser action: the canonical v2 Open must pass the Redis+witness per-session
fence before any Provider private Open. The witness pool first verifies the
actual session/current PostgreSQL role, database, required grants and absence
of provisioning, owner, DDL or escalation authority. Every new physical
connection repeats this ACL check before entering the pool. A single bounded
background check detects persistent permission drift; each activation and
CDP action checks only a local monotonic-time fresh/terminal state. The
profile's drain bound must exceed the sum of poll interval, total database
check timeout, actual close budget and one-second scheduling allowance. Every CDP write
still re-resolves the two credential identities and performs the existing
Redis+witness authorization. An idle poll detects credential expiry/rotation,
agent loss or persistent ACL drift; first failure latches, cancels the private
server, drains upgraded connections and closes both pools. Later ACL repair
cannot unlock that process. The ACL monitor is not a database-transaction lock
against a short grant/revoke between samples or a trusted DBA change racing
with an already authorized action. Redirects and alternate numeric dials are
denied.

Still required before Slice 6 closure: run this command as its own OS process
with real Vault PKI/KV, distinct Valkey and witness ACL accounts, the actual
egress broker/DNS/policy authority and Browser Provider, then exercise normal
actions plus substitution, replay, capacity, rotation/revocation, source and
process loss, restart and exact cleanup. Record observed evidence with the
strict Slice 6 manifest verifier. Until then Phase 6 remains 5/15.
