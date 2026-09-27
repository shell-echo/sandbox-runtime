# ADR 0055: Phase 6 Workload TLS, Network and Least-Privilege Boundary

- Status: accepted
- Date: 2026-09-22

## Context

Phase 6 Slice 5 establishes role-owned secret registries, short-lived Vault
credentials, real Vault Transit recording encryption and bounded break-glass
authority. It does not automate workload-certificate issuance, replace a live
TLS identity without restart, close existing connections after revocation, or
make network and operating-system policy independently enforceable.

The repository already contains strict TLS material parsing, TLS 1.3 role
transports, a DNS-rebinding-aware `internal/netpolicy` library and hardened
Browser/Desktop runtime containers. Those are foundations only. Most TLS
configurations are frozen at process startup, `internal/netpolicy` is not the
mandatory dial path for every role, and the Slice 5 local gate runs repository
processes under one host UID. Configuration text and library unit tests cannot
establish the Slice 6 enforcement claim.

Slice 11 owns platform deployment profiles. Slice 6 must therefore define and
prove one portable security contract without claiming that a local Docker gate
is Kubernetes, Apple Container, cloud service-account or independent-deployment
evidence.

## Decision

### Certificate authority and live rotation

Use real, digest-pinned Vault PKI as the Slice 6 production issuer and
revocation authority. A repository-private CA may appear only in unit tests.
An independent operator-owned certificate-controller process receives its
least-scope, short-lived Vault credential through the Slice 5 workload-
credential controller. It never exposes a Vault token, CA private key or
arbitrary Vault PKI role to a workload.

Each role-owned TLS agent generates its TLS private key locally and sends
a closed, signed CSR request to the certificate controller. The controller
maps the authenticated peer and agent identity to one exact trust domain,
principal URI SAN, optional DNS SAN set, EKU set, Vault role and TTL ceiling.
It rejects caller-selected SANs, wildcard identities, extra usages and an
unconfigured role. The private key never leaves that separate TLS-agent process.

Certificates have a repository hard maximum lifetime of one hour. The closed
security profile fixes a shorter or equal lifetime, a rotation window no later
than two thirds of that lifetime, and a bounded overlap. A role atomically
validates and swaps a complete certificate/key/CA revision through live TLS
callbacks. A failed refresh retains an unexpired previous revision only until
the safety deadline; readiness then closes and new handshakes fail closed.
Resolved PEM is cleared after parsing.

The controller and agents continuously observe authoritative Vault
revocation state. A revoked serial is rejected on a new handshake immediately,
and connection registries drain existing connections within the profile's
bound. Stale revocation state, controller or Vault outage, clock rollback and
issuer restart fail closed. Waiting only for certificate expiry is forbidden.

The runtime peer-revocation feed is a pull through the existing Vault PKI →
certificate-controller → role-owned TLS agent path, never a controller push,
new revocation authority, runtime Vault token or arbitrary AIA/CDP lookup.
The certificate-controller's frozen v1 issue/revoke protocol is not extended:
a separate signed `workload-certificate.v2` request/response carries only the
read-only peer-CRL pull. The controller authenticates the agent's Unix peer and
signature, binds its policy subject to the exact profile edge/anchor/issuer
and independently matches the selected source to the operator document before
persisting a replay nonce and reading Vault. It signs the complete issuer DER
and CRL response; the agent verifies that signature and the CRL under the
returned issuer. The v2 agent path is enabled only by explicit, private,
canonical source documents in both independent processes. Legacy process
configuration remains a compatibility path, not a peer-revocation production
fallback.
Both command configurations pin the canonical full source-document digest;
the role receives only a private, canonical derivative with its exact mTLS
edge/direction/anchor/full issuer digest plus that same source-mapping digest.
The role configuration pins both derivative and full-mapping digests, and
agent v2 requests/responses bind the latter. A changed controller/agent file
or mismatched role document cannot silently select a different live source.
The Provider/Gateway live-signer role-config v3 is still an unpublished,
unfrozen Phase 6 draft. This slice tightens that single v3 definition by
requiring `peer_crl_role_file`, `peer_crl_role_digest` and
`peer_crl_source_mapping_digest` together. Older development snapshots must
be regenerated; missing fields fail closed, with no default, implicit v2
fallback or silent configuration conversion. This is not a compatibility
claim for those old snapshots or a change to the locked Provider wire API.
The agent's current v1 Unix snapshot/sign protocol stays frozen. A distinct
`workload-tls-agent.v2` must bind a read-only complete CRL request/response to
the profile, exact trust edge, local principal, direction, peer-verification
anchor and full issuer certificate DER digest; production roles requiring
peer revocation must reject v1/no-capability fallback. The agent validates
the controller signature; the role validates the agent response binding,
CRL signature, issuer/AKI, serial, sequence,
time and source freshness against its own pinned peer CA before permitting a
new handshake or retaining an existing connection. An actual TLS-verified
peer leaf/issuer, not a header or claimed serial, keys the connection registry.
Before any peer exists, readiness must bootstrap through the same fixed
agent/controller read using the operator-pinned issuer digest. The bounded v2
response carries the full issuer DER, which the role hashes and uses to verify
the complete signed CRL; it neither guesses an issuer from a root bundle nor
adds a trust root. Every subsequent TLS handshake still uses the immediate
issuer and leaf from its actual verified chain. Provider and Gateway readiness
must include this zero-peer online check; source loss makes readiness red.
Active Provider sockets, including hijacked terminals, and Gateway outbound
sockets remain in a bounded registry, are polled for new revocations and are
closed on source loss or a newly revoked leaf. Exact close cleanup and polling
cancellation are required; a successful handshake alone is not a drain gate.
The combined Vault publication, controller/agent collection, role polling and
socket cleanup delay must fit the profile's end-to-end revocation bound;
individual poll and staleness limits alone do not prove it.

For each exact local role, let D be its declared `connection_drain_seconds`,
S its CRL evidence maximum age, T the total timeout for one guard pull
including permit wait and every agent/controller/Vault hop, P the maximum
wait after one check completes before the next attempt, C the total time to
stop forwarding and force-close all sockets tracked by that guard, U the
bound from authoritative revocation to the fixed CRL source becoming
readable, and J the measured scheduling allowance. The strict budget is
`U + 2*T + P + C + J < D`; two pulls cover a revocation racing with an
in-flight old snapshot. The 10-second candidate derives `T <= 2s`,
`P <= min(S/2, 2s)` and `C <= 1s`, reserves at most 2s for U+J and at least
1s unallocated. An effective T is the smaller of the existing operation
timeout and D/5; it constrains the full pull, not certificate issuance.
The guard schedules evidence expiry at the earlier of `collected_at+S` and
CRL `next_update`, even if no next poll arrives. An invalid minimum interval
or insufficient budget rejects the profile-bound guard instead of extending
D. The real Vault and distinct-process gate must measure U, J, active/idle/
hijacked-socket drain and exact cleanup; these formulas alone do not prove
the candidate meets 10 seconds. The measurement starts at successful
revocation confirmation only if the fixed CRL source is already readable;
otherwise publication delay counts as U. A user-request-start SLA must also
include the revocation request itself.

Missing issuer source, stale/rolled-back CRL, authority loss, or revoked-to-good resurrection
of an unexpired observed peer fail closed. Same-issuer reads may be shared,
but an agent cannot substitute its own issuer's CRL for a different peer CA.
Different server/client anchor IDs or purposes do not themselves prove
different issuers: compare the actual issuing CA's full DER SHA-256 first.
The canonical profile/operator source mapping fixes the existing Vault
backend/endpoint, mount, immutable Vault issuer UUID and complete issuer DER
digest for each actual peer CA, then authorizes that source only for the
requesting agent's declared mTLS edges. A mutable `default` issuer alias,
caller-supplied URL/path/issuer reference and `/pki/crl` fallback are
forbidden. The controller verifies the selected issuer certificate against
the pinned DER and re-verifies every complete CRL's signature and scope;
cache identity includes source, profile revision and issuer, while edge
authorization remains separate. Issuer replacement requires a new explicit
profile and controlled transition, not implicit rollover.
The role's CRL number, `ThisUpdate`, same-number content digest and observed
unexpired revoked peer leaves are monotonic only within a live role process.
On role restart the state is unknown, never inherited as good: first admission
requires a fresh authenticated read from the fixed live Vault source through
the controller and agent. Agent or controller restart does not erase a still-
running role's watermark. Vault is the sole persistent revocation truth;
there is no role/agent/controller peer-revocation observation ledger. This
single-cluster contract does not claim detection if the trusted Vault itself
is restored to a historical snapshot or silently replaced by a stale replica.
That stronger anti-rollback property would require a separate recovery design
and gate, not a local mode-0600 file mistaken for independent authority.
The source/edge mapping may be a separate closed canonical operator document
only when it is pinned to the exact security-profile digest and Vault
external identity. Its source set and per-edge authorization set remain
distinct; a source's presence never grants every role permission to read it.

The single-cluster complete-CRL path requires an observed Vault PKI CRL
configuration with building enabled, `auto_rebuild=false` and
`enable_delta=false`, plus a bounded refresh before `NextUpdate`; a contrary
configuration is unavailable, not a reason to poll faster or grant runtime
rotate authority. HashiCorp documents that a successful revoke rotates the
complete CRL unless `auto_rebuild=true`, and that expired complete CRLs may
otherwise need operator rotation
([PKI API: revoke/config/rotate](https://developer.hashicorp.com/vault/api-docs/secret/pki)).
This does not claim multi-cluster/unified CRL or automatic CA rotation.

Every runtime role, Browser/Desktop executor backend, material agent,
credential controller, break-glass controller, certificate controller and
migration job has a distinct URI SAN and exact server/client EKUs for its
declared trust edges. Shared identities and wildcard SANs are forbidden.

The Browser and Desktop executor backend production commands use version-2
authority files and the validated Phase 6 profile's sole role-to-executor
`wss` trust edge. They reject version-1 local server-key authority. Each new
handshake obtains a generation-bound certificate from its separate TLS agent
and verifies the pinned issuer, exact URI/DNS/EKU, lifetime and public signer
key before serving. Static-file backend constructors remain only component
compatibility paths; they are not a production fallback. Existing-connection
revocation drain and the distinct-UID command-level graph remain named gates,
not conclusions from these callbacks.

The backend authority v2 was an unpublished Phase 6 draft. The same v2
definition now requires the three explicit peer-CRL role file, role digest and
source-mapping digest fields; old development snapshots fail closed and must
be regenerated. There is no implicit v1 or no-CRL production mode. Each
backend binds its own `executor-browser` or `executor-desktop` inbound edge to
the derived role document, pulls the actual peer issuer's complete CRL before
readiness, verifies the TLS peer's real chain on every handshake, and tracks
accepted and hijacked sockets for bounded polling, revocation drain and exact
close cleanup. Browser readiness additionally requires its CDP upstream;
Desktop readiness requires the signed broker probe. A TLS signer, CRL source,
CDP upstream or broker failure closes readiness, and CRL loss or revocation
closes existing WebSocket sessions and their upstream/broker transport.
The historical static-file component constructor still imports the Provider
mTLS file loader at package level; the production remote-signer branch does
not call it. Extracting that compatibility helper is a later behavior-neutral
dependency cleanup, not evidence that the package currently has no Provider
import. The complete separate-process principal and network graph remains a
Slice 6 gate.

The private identity vocabulary is the closed, versioned
`securityprincipal.v1` registry. Its kinds are `runtime_role`,
`material_agent`, `tls_agent`, `migration_job`, `controller`, `executor_backend` and
`egress_broker`; every name-to-kind-to-role mapping is explicit. The
`workload-credential.v2` protocol binds the complete principal and its digest
to a separate v2 lease namespace and ledger. Version 1 remains frozen as Slice
5 evidence only: a production Slice 6 caller cannot downgrade to v1 or renew a
v1 lease through v2. Certificate-controller credential issuance is separately
allowlisted to exactly the `certificate-controller-pki` backend policy;
migration credentials are nonrenewable, while runtime roles, migration jobs,
executor backends, egress brokers and the credential controller are denied
direct issuance by default.

The certificate controller's own first Vault connection is the sole bounded
bootstrap exception. An operator-provisioned client private key is inherited
only through descriptor 5 as a private regular file; it is never present in
JSON, environment, arguments, logs, evidence or the repository. The matching
certificate must chain to the configured Vault client trust bundle and carry
the exact certificate-controller URI/DNS identity, empty subject, P-256 key,
digital-signature usage, client-auth EKU, valid time and at most one-hour
lifetime. The scoped Vault token and mTLS identity are both required; static
tokens, anonymous access, server-only TLS and a v1 credential fallback are
forbidden.

The bootstrap identity may perform only the first controlled issuance and CRL
read. The controller then atomically selects its locally generated managed
certificate, closes the old transport connections, destroys the bootstrap
key, and uses the managed signer for subsequent Vault handshakes. Shutdown
revokes overlap material before the current identity, destroys both keys and
closes every connection. Missing, wrong, nonregular, public-permission,
offset, oversized or mismatched descriptor material; wrong SAN/EKU/CA/time;
token-policy mismatch; Vault denial; failed first switch; stale old
connections; and leaked key material all fail closed.

Every role TLS agent exposes the closed `workload-tls-agent.v1` Unix signing
protocol and, only under the explicit peer-CRL profile, the separate read-only
`workload-tls-agent.v2` CRL pull. It authenticates the role by
socket UID/GID, bounds connections and global nonce replay state, and returns
only the certificate chain, public key and generation-pinned ECDSA signature.
The TLS private key remains inside the agent. Rotation preserves the previous
generation only for the declared overlap, while CRL staleness, missed rotation,
issuer outage, clock rollback or revocation closes signing at the earliest
safety deadline.

The signer wire protocol remains v1; peer CRL uses distinct v2. The restricted
socket layout first introduced by `workload-tls-agent-config.v2` is retained in
the peer-CRL v3 command configuration. Version 1's agent-owned
0700 parent and 0600 socket cannot be reached by a role with its required
distinct UID. Each agent/role pair instead gets one private mount directory:
agent UID owner, role GID group, mode 0710; its Unix socket is agent-UID-owned,
mode 0666, with no socket `chown` or dependence on inode group inheritance.
Directory group permits path traversal only, not writes. The agent and role
verify the exact parent owner/group/mode, socket type/owner/mode, no symlinks,
stable socket inode and exact peer UID/GID before any protocol frame. The
agent rejects supplementary groups outside its own GID, and the deployment
drops all capabilities including `CAP_CHOWN`. The role mounts only its own
agent directory read-only; no other role mounts it. An authorized peer that
sends no frame or only half a frame has a bounded initial read deadline;
cancel/close actively closes accepted connections before waiting for handlers.
The v2 layout does not change the v1 message schema or create another
certificate/signing state machine. Production commands do not select the
old layout. The complete profile-to-mount/edge binding and real broker mTLS
gate remain mandatory before Slice 6 is counted.

A TLS agent is a separate OS process and a distinct private
`securityprincipal.KindTLSAgent` identity, not an alias of the existing
`KindMaterialAgent` Vault KV/credential process. TLS agent identities are
ineligible for `workload-credential.v2` token issuance even if an operator
mistakenly configures a backend policy. The PKI delegation relation is one
TLS agent to one exact subject (including separate Browser/Desktop executor
agents and a distinct agent per registered egress broker); the old
material-agent and shared Browser/Desktop role/executor delegation is not a
production authorization path. The certificate controller's own managed
Vault TLS key remains its explicitly audited internal-signer exception.
The private principal vocabulary was extended before a Slice 6 lock or
release evidence was created; Provider Contract is unchanged. The canonical
profile and process gate must inventory every actual key owner and must not
create empty agent principals for processes that do not use one.

The still-unlocked `phase6-security-profile.v1` now binds all eight static
runtime/executor TLS agents and exactly one additional agent per registered
egress broker. Every canonical `tls_agent_bindings` entry fixes the agent and
subject deployment/principal digests, distinct UID/GID pairs, one private
socket storage ID and `/run/tls/<agent>/signer.sock` path, 0710 directory and
0666 socket modes, the exact subject-to-agent Unix peer edge, issuer policy
and Vault role, and socket cleanup class. The profile rejects omissions,
duplicates, cross-subject substitution, extra mounts/edges and sharing with
the policy-authority socket. The production TLS-agent command checks its
config against this profile; the egress broker checks its signer endpoint
against its bound agent before connecting. These checks are configuration
authority only: Product now has an explicit v3 live-signer public listener;
Gateway has an explicit v3 live-signer public listener and a profile-bound
Gateway→Provider private client with separate own-client and peer-server CA
roots. Gateway v3 admits only Product database and grant-key material, not
static TLS material. Its private route is a numeric address on the isolated
Gateway/Provider trust network, bound to the Provider private listener and
canonical path. Provider coding-shell now has an explicit v3 profile-bound
Contract listener for Product and a separate private Terminal listener for
Gateway, each with an exclusive live signer, direction-specific CA pools and
distinct client allowlists; v3 Desktop is rejected. The two Provider listeners
use the same role-owned signer but do not merge route or peer admission. This
remains component evidence: no actual v3 Product/Gateway/Provider command
graph, certificate-rotation, revocation-drain or cleanup gate has passed.
Product's private edges and the other three runtime commands still need
migration, and
a real broker/controller/Vault/DNS mTLS process gate is required before Slice
6 can close.

The same canonical profile, not a second signed document, owns the closed
`trust_anchors` registry. Each anchor records its original bundle-byte SHA-256,
server- or client-verification purpose, trust domain, artifact/storage ID,
read-only target path, operator writer, owner UID/GID and exact consumers.
An `mtls` trust edge references its server-verification anchor and, when the
server is repository-owned, its client-verification anchor. Unix signing
edges cannot cite CA anchors. A bundle can be read-only shared by declared
consumers, but equal bytes do not merge distinct purposes or trust domains.
For a repository-owned internal mTLS edge, both exact endpoint principals
consume both anchors read-only: the caller uses the client anchor to verify
its own agent-issued client leaf and the server anchor to verify its peer;
the server uses the server anchor to verify its own agent-issued server leaf
and the client anchor to verify its peer. The two root pools remain separate;
CA readability grants neither signing authority nor a reverse dial. This
does not invent an external-service mount or change the public server-only
listener into mTLS. Missing or extra consumers/mounts fail closed.
The common loader verifies one stable opened file's owner, non-writable
source, SHA-256 and strict CA-only PEM records before the bytes reach a TLS
config. The controller bootstrap client certificate has a separate
`client_verification` anchor; its local chain check must not reuse the Vault
server-verification root. The CA revision remains frozen for that process; anchor changes
require a new canonical profile and controlled process replacement, not a
new CA rotation control plane. Executor, controller→Vault and broker→DNS/inbound
commands consume this registry now; other production TLS commands and full
trust-edge binding still need the same loader before release.

The production runtime TLS configuration advances explicitly to v3. V3 uses
only a profile-bound live signer and direction-specific pinned anchors; the
v2 material-registry certificate/private-key path is retained solely for its
historical candidate evidence and cannot be an automatic production fallback.
New handshakes must fetch and verify a fresh certificate/signing capability,
and TLS session resumption cannot bypass that check. Existing HTTP, WebSocket
and media connections must separately drain within the profile's revocation
bound. The live TLS 1.3 builder and Browser/Desktop backend hookup are
component checkpoints, not the complete multi-instance command gate.
The Browser/Desktop private role v3 candidate uses its own live signer and
inbound peer-CRL guard for exactly one Provider-instance attach edge. Its
separate outbound backend client uses the same role signer with a different
root and CRL direction; an upgraded backend WebSocket has the edge's maximum
connection lifetime, and an upgraded attach WebSocket is tracked below
`net/http` for revocation and shutdown drain. V3 rejects static certificate
paths/bindings and cannot fall back to the v2 material-registry transport.
This is code/component evidence only until actual distinct-role processes and
the complete profile are exercised together.

Provider Contract and private Terminal listeners track accepted sockets below
`net/http`, enforce the exact trust edge's maximum connection lifetime, and
close both keep-alive and hijacked sockets on shutdown. That transport
registry is a prerequisite, not a revocation feed: the authoritative
controller/agent revocation signal, live drain timing and corresponding
cross-process failure gate remain required before a Slice 6 closure claim.

The canonical profile declares only these runtime dialing authorities:
Product→Provider locked Contract listener; Gateway→Provider separate private
handoff/media listener; Provider→Browser and Provider→Desktop private executor
listeners; Browser→its Browser backend; Desktop→its Desktop backend; and
Guest→Product's separate private Guest-control listener. Each internal edge
binds the exact listener and route, protocol, both deployment/principal
digests, URI/DNS/EKU, distinct server/client CA anchors, connection lifetime
and revocation drain. A response on an authorized connection does not grant a
reverse dial. Browser/Desktop credential fields named `ProviderOrigin` are
SPIFFE peer identities, not outbound Provider URLs; no such reverse edge is
inferred. Gateway's committed Product database reads do not invent a
Gateway→Product HTTP edge. Provider coding and Desktop instances cannot share
one identity that masks their different capabilities.
Each Browser/Desktop backend server identity has exactly one operator-declared
canonical DNS SAN as well as its exact URI and `server_auth` EKU. The backend
target stays a numeric address; the separate pinned DNS name is TLS
ServerName/SNI, not a DNS lookup or an inferred identity. TLS-agent and
controller issuance policies must match this SAN exactly. Zero or multiple
backend DNS SANs, wildcard/IP names, and a name absent from the issued leaf
are invalid; URI-only or hostname-verification bypass is not a fallback.

For the complete simultaneous Product target, Provider is one logical role
implemented by three exact process profiles: coding-shell, Browser-only and
Desktop-only. Each process has a distinct deployment, instance/principal
digest, URI, UID/GID and TLS agent/socket. Product's Contract edge and
the matching private handoff path are instantiated separately for the matching
Provider profile. Terminal and Desktop retain direct Gateway-to-Provider
private edges; Browser does not. Only the Browser Provider may dial the Browser role and
only the Desktop Provider may dial the Desktop role. The coding Provider
cannot inherit either attach edge, and Browser/Desktop private routes cannot
be relabeled as the Terminal private route. Guest-to-Product and each
role-to-its-backend remain separate. The canonical full-inventory profile
must require every actual process and the complete approved edge set, with no
partial-profile production mode. A single-provider fixture can exercise a
component but cannot be used as the simultaneous full-system topology or
evidence. Provider Browser-only production composition, Desktop v3
composition, Product's private Guest receiver and per-instance data/material
privileges must be real before the release gate; profile declarations alone
do not advertise those capabilities.

The Browser-only v3 composition must use its own PostgreSQL session/reference
authority, Provider identity, admission audience and material permissions.
The old Gateway-to-Browser-Provider `/private/browser` edge was an incomplete
inventory entry, not a permissible bypass. Browser v3 replaces it with two
mandatory, isolated trust edges: Gateway→`browser-action-ingress-runtime` at
`/browser/action`, then that distinct principal→Browser Provider at
`/private/browser`. The action ingress has its own UID/GID, URI identity, TLS
agent, material permissions and lifecycle. It is the only Browser CDP write
path, and the Browser Provider listener must reject the Gateway principal.
The ingress uses caller-owned Redis/Valkey capacity authority and the
independent PostgreSQL action-history witness, never Provider PostgreSQL or
Docker. Its exact-member authority, CRL and network denial must be measured
in the complete deployment before Browser v3 can start. On the authenticated private edge,
an authorized request may establish an irreversible, transactionally checked
tenant-digest binding on the current Browser handoff. Gateway mTLS alone does
not authorize a tenant: the request must derive from the current caller-owned
grant/session/fence, and Provider rechecks the current reference, allocation,
generation, Provider revision, lease, revocation and expiry. Active streams
must poll that authority and drain on loss. Browser executor admission must
further bind its opaque capability to the actual Provider-selected CDP target;
the legacy fixed `UpstreamURL` is not such a binding. These are named Slice 6
gates, not consequences of the TLS profile's existence.
The closed security profile declares `capacity-valkey` and
`action-history-postgres` as distinct external identities from Product
`postgres`. Gateway has only a capacity edge; action ingress has capacity
and witness edges. Each also has its own one-to-one egress broker, policy-state
authority, isolated internal network, fixed DNS/port/protocol target list,
and external-uplink broker network. Direct role egress remains blocked.
Each broker has its own DNS mTLS edge; the broker command refuses to start
without that edge and its exact external DNS identity.
The broker-to-external legs are explicit trust edges; a role-to-external edge
records the logical application authorization, not a direct network path.
The profile rejects missing, substituted or additional Browser external
edges and target drift. Profile identities and separate DNS names do not
prove independent storage, volume, backup or restore domains: the real gate
must observe these and the witness's separate database role/schema, plus
rollback detection and Redis/PostgreSQL outage cleanup. No runtime may gain
DDL, truncate, delete, admin or witness auto-rebuild authority.
This tightens ADR 0035's earlier runtime `INSERT` recommendation: Phase 6
ingress receives only CONNECT, USAGE, SELECT and the exact
`UPDATE(sequence, token, updated_at)` column grant. The one-shot provisioning
identity alone receives initial-row INSERT; schema DDL remains with the
migration owner. Existing runtime table/column grants and inherited role
memberships must be explicitly revoked/audited on upgrade. The production
runtime uses only `Verify`, while the library's `Provision` remains for the
operator path and component tests. Column-scoped UPDATE plus adapter CAS
conditions are not a claim that a compromised holder of the SQL credential
cannot modify those granted columns.
Before the Browser ingress becomes ready, its PostgreSQL pool must verify the
actual current/session role, database, effective required grants, forbidden
table/column/owner/DDL/role-membership privileges and escalation attributes.
Each newly opened physical connection repeats that check in a pool
`AfterConnect` hook before admission; the hook uses only that new connection,
not a recursive pool acquire. An independent process-level monitor rechecks
the live pool on one bounded interval. A failed, timed-out or stale result
latches failure, stops new admission, cancels existing streams and closes the
upstream/pools; revoking an unsafe grant cannot unlock a running process.
Every Browser activation and CDP action checks the local observation's
monotonic-time freshness before the unchanged Redis+witness authorization,
without adding a PostgreSQL catalog query per CDP write. For poll interval P,
one complete pool-wait/query timeout T, actual close budget C, fixed scheduling
allowance J=1 second and profile drain bound D, admission requires
`P+T+C+J < D`; local freshness expires after `P+T+J` from the last successful
check's START time. There is no unbounded retry or last-good extension.
This proves only bounded detection and drain for persistent ACL drift in a
running local process, not an atomic lock against a grant/revoke between
samples or a DBA mutation concurrent with an already authorized CDP write.
The database owner/DBA remains an operator trust boundary; planned ACL changes
require ingress isolation and drain first.
The ingress's capacity and witness clients must use a fixed alias-only broker
tunnel. The pgx resolver must return only the authorized hostname to its
strict DialFunc, leaving DNS resolution to the broker; pgx fallback hosts,
plaintext TLS modes and `PG*` environment defaults fail closed. Go-redis's
custom Dialer does not add TLS itself, so its capacity adapter must perform
the external TLS handshake over the broker tunnel and verify the profile-
pinned external peer. These adapters are component code, not evidence that
the production ingress command or container network uses them yet.
Witness and capacity credentials reuse the existing secretref→role-owned
material-agent→Vault KV lifecycle, but not a shared account. Two dedicated
`KindSecret`/`SystemTenant` purposes are `action_history_witness_dsn` and
`capacity_valkey_credentials`. Both belong to the existing logical Gateway
role; the first is allowed only in the Browser action-ingress runtime/agent,
while the second may be bound separately to action ingress and Gateway with
different references, Valkey ACL users and passwords. Deployment, agent peer
UID/GID, exact binding/version and Vault path ACL remain distinct authorities;
the logical role alone never authorizes cross-agent reads. The witness secret
is a strict single-target PostgreSQL URI, with actual host/port/database/user
checked against the profile and separately reviewed least-privilege target.
The Valkey secret is a closed, versioned JSON containing only protocol,
username and password, never an endpoint, database, TLS mode or namespace.
Neither source may install alternate host/fallback/dynamic credential hooks.
Credential expiry, replacement, revocation or material-agent outage must
fail closed and drain dependent pools; a one-time startup parse is not a
lifetime authorization. Redis ACL and witness table privileges require a
real external-service gate before any Slice 6 evidence claim.
The ingress retains the ADR 0033 per-session execution gate: activation,
old-stream close, exact-member/high-water check and each complete CDP write
are serialized outside the Gateway. A Redis capacity claim, Product control
fence, Provider generation and per-connection epoch have separate owners and
must not be substituted for one another. Merely hashing the capacity claim
into a Provider PostgreSQL connection record does not enforce action fencing.
Gateway projects each consumed Product grant and committed Browser metadata
into a closed, canonical `browser-action-ingress.v2` Open. That document
contains the bearer-like capacity claim and is never logged or retained.
Ingress checks its fixed Provider audience and exact subject, admits the claim
through Redis plus the independent PostgreSQL witness, closes the previous
actual upstream under the per-session gate, and only then derives the
`browser-handoff.v2` Provider Open. The latter contains no raw claim, raw
control lease or Product grant ID; exact mTLS identity plus existing authority
and request digests suffice without a new application signing key. The
Product public protocol `product-browser-automation.v1` maps explicitly to
the Provider capability `browser-v1`; an unknown profile cannot inherit that
mapping. The current Product operation uses the Product session ID as its
Provider Browser runtime session ID, so grant consumption, ongoing authority
and metadata selection reject drift rather than assuming the concepts are
interchangeable. A still-live public connection may make bounded internal
reconnect attempts, each with a distinct deterministic opaque Provider epoch
derived from that attempt; an exact replay keeps its old epoch and cannot
reopen a consumed executor reservation. Neither reconnect nor epoch issuance
renews the grant, capacity claim, control lease, or absolute expiry.
The private Gateway stream treats a CDP request without its exact response
as an unknown write outcome on transport loss, including a nominally normal
WebSocket close. That is terminal and cannot enter the ordinary reconnect
branch. Only a confirmed idle or fully answered close may reconnect; explicit
fence-loss and witness-unavailable close codes remain terminal. The ingress
also bounds pending and active private sockets before WebSocket upgrade.
The Browser tenant-binding HMAC key is a separate Product/Gateway-only
`browser_tenant_binding_key` material purpose. No Provider, Browser role or
executor principal may resolve it. Its exact version and stable caller scope
must be fixed with the Product handoff metadata and survive Gateway restart;
key rotation cannot silently change an already-bound reference. This secret
does not authenticate a Product grant by itself and is never projected into a
normal log, public evidence or Provider material registry.

The Desktop private media bridge uses a distinct prepare/start transport v2
for the v3 production candidate. Capacity and continuous authority checks
begin at prepare, but no executor reader or encoder may start before Product
has armed its WebRTC sender, recording sink and private demultiplexer. Start
rechecks current Provider authority and binds the exact connection epoch,
generation, fence and digests; its ACK precedes media forwarding. This fixes
the observed 32-frame preconnection overflow without discarding frames,
inflating buffers or weakening runtime fail-closed backpressure. Historical
v1 streaming tests remain separately identified; a passing v1 test is not v2
activation evidence.

Only exact Product and Gateway public listener bindings use TLS 1.3
server-authentication without a workload client certificate. Product user
authentication and Gateway ticket/grant, Origin, session and fence checks
remain required. These bindings do not create a wildcard external principal
or grant the same optional-client-cert policy to a private listener. WebRTC
media retains its authenticated signaling and DTLS/SRTP binding rather than
being misclassified as a generic mTLS HTTP edge. The Guest remains outbound
only. Slice 6 must compose its private Product receiver from the existing
Guest Hub, Product PostgreSQL binding store, challenge authentication, live
mTLS/CRL and drain under the Product identity. A fixture-only Guest peer is
not security-edge evidence. That receiver is distinct from public
Files/Development readiness: Slice 8 must wire the existing FileService,
FileClient, DevelopmentService, DevelopmentClient and authenticated Web/BFF
paths into the production application graph with real content/storage ports.
Guest transport readiness or negotiated handlers alone cannot advertise
`product.files` or development capability. Slices 11, 14 and 15 must reject a
full-product claim until the formal public business path passes its named
deployment and black-box gates.
Private WebSocket clients must reject HTTP redirects. Their guarded transport
must also deny plaintext dialing so a redirect cannot downgrade an approved
`wss` edge into an unpinned `http` connection; a TLS connection to a different
numeric target is independently rejected.
Database, coordination, object storage, egress broker, agent/controller Unix,
Vault and DNS dependencies each retain their own actual-consumer bindings and
cannot be hidden under the runtime mTLS matrix.

The certificate controller is one logical process, not one controller per
agent. Its production command configuration is v3 and receives the same
validated profile/registry as its TLS-agent clients, including registered
broker agents; the old nil-broker registry is not a production fallback.
The profile fixes the controller principal/UID/GID and its response-signing
key ID/public-key digest separately from Vault CA and mTLS trust material.
Each TLS agent gets a distinct controller Unix endpoint, storage ID, 0710
controller-owned/agent-group directory, 0666 controller-owned socket, exact
agent-to-controller peer edge, and CSR request key ID/digest. The controller
owns each directory read-write and only its corresponding agent mounts it
read-only. The controller command checks its complete listener and policy
sets against the profile, including the managed Vault TLS self-policy. The
agent checks its controller endpoint, peer UID/GID, response key, CSR key and
issuer policy before opening the socket.

The controller's own managed Vault TLS renewal uses a separately declared
internal self endpoint with 0700 directory and 0600 socket; it is not an
extra TLS agent and never shares an external agent endpoint. Both Unix paths
use common no-symlink, stable-inode, owner/mode, stale-socket and active-
connection cleanup checks. External agent endpoints never use `chown`,
supplementary groups or CAP_CHOWN, and a half-sent first frame is bounded.
A two-agent distinct-UID Docker test now proves this Unix/CSR component with a
private test CA; full production broker/controller/Vault/DNS integration is
still required before Slice 6 closure.

### Enforced egress and ingress

Use role-isolated Docker internal networks in `isolated` IPv4 gateway mode and
independent egress-policy broker identities for the portable Slice 6 local
gate. Every protected role and trust-edge bridge must be created with
`--internal --opt com.docker.network.bridge.gateway_mode_ipv4=isolated`.
IPv6 is disabled and verified in this profile; a future IPv6-enabled profile
must also use and prove `gateway_mode_ipv6=isolated`. A protected process has
no host network, Docker socket, host bridge address, default external route or
alternate Docker network. It joins only its own isolated network and explicitly
declared isolated trust-edge networks. Its corresponding broker alone joins a
separate external-uplink bridge and holds no Product/Provider business secret,
database authority or runtime-engine authority.

The stronger mode is mandatory, not an optimization. On Docker 29.7.2 a real
`--internal`-only container reached a disposable host-network service through
the bridge gateway, despite failing an external-network direct-socket probe.
The same host fixture must be a positive control in the gate: ordinary
`--internal` reproduces the bypass, while `isolated` denies that gateway,
other Docker gateways, resolved `host.docker.internal` and
`gateway.docker.internal` numeric addresses, public and metadata addresses.
The protected role must still reach its declared broker and the broker must
reach an allowed uplink fixture. Network inspect verifies exact members,
`Internal`, `bridge`, `isolated`, disabled IPv6 and absent host gateway address;
live route/address probes verify no default route or IPv6 address. A failed
network option, missing positive control or unexpected reachability fails the
gate. [Docker documents why ordinary internal bridge gateways remain host-
reachable and why `isolated` omits the bridge address](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).

Product and Gateway public TCP entry uses one operator-owned, fixed-target
ingress relay process. It alone joins the `public_ingress` NAT network and
two separate `isolated` trust-edge networks; Product and Gateway join only
their respective isolated networks and have no host-published ports. The
relay binds only one explicitly declared frontend IPv4 address and forwards
two exact port mappings to profile-pinned numeric upstream addresses. TLS
terminates in Product/Gateway, not the relay. The relay has its own UID/GID,
image, seccomp and resource bounds, no TLS/material-agent identity, no
business credential, no Docker socket, no HTTP parser, CONNECT/SOCKS,
dynamic DNS/SNI upstream or proxy-header authority. The canonical profile
binds its principal digest, exact frontend/target network membership,
non-overlapping canonical IPv4 CIDRs, listener, host publication, endpoint,
port, per-route limits and mapping
digest. Unknown frontend listeners, role-owned ingress listeners and role
host publication are rejected. The Docker gate must independently inspect
the actual network IPs, port bindings, routes and disabled forwarding,
exercise Product/Gateway TLS and application authorization through those
published ports, test relay/target failure and drain, and prove exact
cleanup. A raw TCP relay does not solve WebRTC ICE/UDP/media reachability;
that remains a separate release gate, not an inferred consequence.

A role can request only a closed target alias, port and protocol. The broker
maps that alias to the immutable security profile, performs DNS itself, checks
every A/AAAA result through `internal/netpolicy`, rejects raw IPs,
redirect-based authority changes, alternate DNS, proxy-environment bypasses,
metadata, loopback, private, link-local, multicast and reserved addresses, and
dials only a checked address. The policy revision and lease bind every
connection; lifetime is bounded and policy revocation closes existing
connections. The external DNS service's exact certificate DNS SAN is part of
the digest-bound profile; broker startup accepts only that SAN and a numeric
DNS endpoint on the declared trust-edge port, never an operator-selected
hostname that would invoke ambient DNS. DNS, policy or broker outage fails
closed.

The only internal `tls` trust edge permitted a numeric `TargetAddress` is the
policy-selected role→dedicated egress broker edge. Its canonical private IPv4
address and listener port must belong to the sole isolated role/broker shared
network. The profile is the only address authority: the broker binds exactly
that IP:port and the role dials exactly that IP:port. Wildcard, loopback,
uplink, public, IPv6, network/broadcast, out-of-CIDR, extra shared-network or
host-published listeners are forbidden. Numeric transport does not relax the
TLS DNS SAN, SPIFFE URI, EKU, pinned anchors, peer CRL or principal checks.
Product, Gateway and Browser action ingress use the same fixed-boundary
client constructor. The Docker network probe checks actual interface ownership
and non-listening loopback/uplink addresses; the strict network observation
also binds the broker's declared target IP to its exact observed container ID.
The real broker-command/mTLS gate
must repeat these observations before Slice 6 evidence can be issued.

Each egress policy has exactly one independent operator-owned authority
process, controller principal, UID/GID, signing key, persistent CAS ledger
and restricted Unix socket; no process signs another policy. A one-time
explicit initialization commits generation one. Later starts recover the
ledger and cannot silently initialize a missing/corrupt record or reactivate
a revoked policy. Every active refresh and revocation commits the atomic,
fsynced ledger; the authority signs Current from that ledger's in-memory
state digest. It does **not** publish a separate state file: distinct broker
and authority UIDs cannot safely share a 0600 file, and file-plus-online
comparison would still have only one underlying trust source while adding
publication races, write load and failure modes. A legacy file, if present,
has no authorization effect.

Before listening, and then at a profile-bound interval no longer than one
second, the broker sends a new random challenge to the live authority over a
per-broker Unix socket. A canonical signed Current response binds that
challenge, exact environment/profile/policy/principal/broker digests,
generation, active/revoked status, committed state digest and short validity.
The authority signs from a linearizable read of its durable ledger. Broker
checks exact peer UID/GID, signature/key, nonce, freshness, monotonic
generation and same-generation immutability. A missing/late/invalid response,
clock rollback, authority loss or revoked status immediately revokes the
broker revision, drains existing sessions and stops admission; it cannot
continue on the previous active response until its nominal expiry. A new
policy revision requires a separate broker and authority instance.

The socket directory is authority-owned, broker-group, mode 0710 and mounted
only into those two containers. On platforms where Unix socket inode group
cannot reliably be assigned, its mode is 0666 **only inside that protected
directory**; exact parent ownership/mode, no symlinks, broker/authority peer
credentials and the signed policy binding remain mandatory. The authority
signing key never enters the broker or repository. Local gates do not prove
independent production operator administration or trusted recovery from a
privileged operator restoring both ledger and key; Slice 14 must explicitly
state that boundary.

An operator SIGUSR1 is only a revocation trigger, not proof of completion.
The operator waits for a successful authority exit, then runs an independent
read-only inspection of the exact private ledger. A successful canonical
receipt must bind the expected environment, profile, policy, principal,
broker, generation, committed time and ledger digest with `status=revoked`.
SIGTERM, SIGKILL, signal delivery, transport loss and nonzero process exit
must never be reported as permanent policy revocation; a visible receipt after
a failed fsync/exit is escalated rather than treated as proven durable.

Equivalent policies may share implementation but not a higher-authority
global broker identity. Negative network-topology tests, rather than an
in-process dialer assertion, prove that direct sockets and alternate paths do
not bypass the broker. Linux host enforcement may strengthen a platform
profile but is not the cross-platform Slice 6 requirement.

### Least privilege and evidence semantics

Every repository-owned container in the Slice 6 gate uses a unique numeric
UID/GID, non-root execution, a read-only root filesystem, only declared tmpfs
and role-private sockets, plus one narrowly scoped managed persistent ledger
volume per policy-state authority. Its ledger volume is writable only by that
authority, never by its broker or another role; arbitrary volumes, host-path
bind mounts and shared business storage remain forbidden. All Linux
capabilities are dropped,
`no-new-privileges`, a role-specific seccomp policy, bounded PIDs/memory/CPU,
no host devices, host mounts, daemon sockets or extra listeners. The gate
rejects drift and exercises privilege escalation and resource exhaustion.
Each principal binds its reviewed policy by exact digest and the gate checks
that binding against the running container. Equivalent least-privilege
syscall needs may share one policy artifact and digest; forcing unique bytes
per principal is not an isolation control. UID/GID, credential, network and
mount separation remains per principal, and a shared policy must not include
the union of unrelated roles' extra syscalls merely for convenience.

Evidence records the exact observed layer:

- `distinct_container_uid_gid_established=true`;
- `container_namespace_isolation_established=true`;
- `host_user_namespace_mapping_established` only from an actual mapping check;
- `platform_service_account_established=false`; and
- `same_host_local_container_gate=true`.

It must not collapse these facts into an unqualified
`distinct_os_uid_established=true` statement.

### Closed security profile and inventory

Add a closed, canonical, versioned Phase 6 security profile. It binds every
process principal, digest-only image identity, UID/GID, filesystem, capability,
seccomp and resource rule, listener/ingress edge, TLS trust domain/SAN/EKU,
allowed service and egress edge, policy digest, DNS/metadata rule, secret
purpose, certificate timing/revocation policy and cleanup class. Missing,
unknown or duplicate principals/edges, mutable images, extra ports, mounts,
capabilities or networks fail validation.

The Slice 6 internal image identity separates object kind from location;
`ImageDigest` never silently changes meaning. `oci_manifest`/`oci_index`
bind the raw descriptor bytes whether local or registry-hosted. A local
candidate uses a full `sha256:<store descriptor>` launch reference with
`--pull=never`; a registry image uses its real `repository@sha256:<descriptor>`
reference. Both pin the selected platform and OCI config digest, and an index
pins its selected platform-manifest digest. `local_config` is reserved for a
separately proven classic-store config-addressable case, not the default
candidate kind. Current Docker Desktop containerd inspection returns the
top-level OCI index digest in both container `.Image` and image `.Id`, not the
OCI config digest. Consequently the gate independently records runtime store
ID, store descriptor, that container's `ImageManifestDescriptor`, OCI config
digest, platform, and private raw-proof/archive digest; none is renamed into
another. It verifies archive index → the container's actual selected platform
manifest → config and layers using original bytes, cross-checks Docker image
and container inspections including ordered rootfs diff IDs, and rejects
missing selected-manifest evidence. OCI layout `index.json` can be a separate
export wrapper; unknown/unknown attestation descriptors are retained but
never selected as the running platform. Missing/unknown kinds, kind/reference
confusion, wrong selected platform/config/layer, tag fallback and automatic
`RepoDigests`-absence downgrade are denied.

All repository-owned roles may use reviewed local-candidate images in the
Slice 6 same-host gate, including Product, Gateway, all three Provider
instances, Guest, Browser, Desktop, agents, controllers, brokers and relay.
They must execute their real corresponding commands, not Alpine/nc probes.
One byte-identical application image may serve multiple roles, but their
containers, UID/GID, authority and config remain independent. Each candidate
binds an immutable source commit/tree and exact build context, Dockerfile,
toolchain, base, dependency lock, parameters, output store descriptor and
separate OCI config digest. Retain
a re-importable local image archive/OCI output with its digest and verify its
config/rootfs input chain. Dirty-tree diagnostics are not immutable evidence.
No candidate is pushed, published or labeled production; credentials and
runtime configuration never enter it. An archive or candidate-document
digest is not an OCI manifest digest. A native arm64 gate proves only arm64;
a cross-build does not substitute for native runtime validation.

The final immutable gate covers:

- Product, Gateway, Provider, Guest, Browser and Desktop runtime roles;
- Browser and Desktop executor backends;
- six runtime plus Product/Provider migration material agents;
- workload-credential, break-glass and certificate controllers;
- Product and Provider one-shot migration jobs;
- every egress broker and its one-to-one operator-owned policy-state authority;
- the public ingress relay and its two exact published Product/Gateway paths; and
- the existing Desktop broker and Browser runtime security assertions.

External Vault, PostgreSQL and DNS remain outside the repository-owned role
set, but their digest/identity/ingress edges and exact reachable clients are
bound. The gate covers identity substitution, downgrade, wrong SAN/EKU,
expiry/revocation, cross-role/tenant traffic, direct/raw-IP/alternate-DNS/
metadata/rebinding attempts, policy outage, privilege escalation, resource
exhaustion and exact cleanup. Real Browser CDP and Desktop media/input smokes
run under the profile. Slice 4's 50/100 stress matrix is repeated only if its
media/broker timing changes.

## Consequences

- Slice 6 proves local enforcement with real Vault PKI and Docker, not an HSM
  CA, cloud identity, published/signed application image, platform service
  account, deployment, HA or production readiness.
- The Desktop v3 Slice 6 gate uses the exact non-release local-candidate
  image/source identity from ADR 0052. Its protected production-mode command
  is not a production artifact claim. The Desktop Contract, private and attach
  edges must still use the live Desktop Provider principal, mTLS, CRL bootstrap,
  polling and bounded drain; static-key fallback and candidate relabeling are
  forbidden. Slice 7 publishes the executor-v2 runtime and revalidates the
  artifact-dependent security gates before Slice 11 or 14 may use it.
- The descriptor-5 first-operation bootstrap is an operator runbook boundary,
  not automatic HSM, cert-manager, cloud workload identity or platform
  bootstrap. Slices 11 and 14 must replace or explicitly revalidate it in each
  deployment and independently administered environment.
- Slice 7 owns SBOM, signature, provenance and publication for all images.
  Its final production profile rejects `local_config` and non-release images.
  It independently verifies the exact published artifacts, repeats every
  security/behavior gate affected by image, entrypoint, base, dependency,
  identity, network or config change, and checks the final complete inventory.
  Candidate evidence is not made publishable by changing a digest label.
- Slice 11 translates this frozen contract into Docker, Apple Container and
  Kubernetes profiles and validates platform ServiceAccount, NetworkPolicy,
  PodSecurity and user-namespace behavior. It may not weaken the contract.
- Slice 14 repeats the security contract from published artifacts in an
  independently administered environment.
- Slice 6 remains open and Phase 6 remains 5/15 until the real PKI, network,
  least-privilege, full-inventory and strict evidence gates all pass.
### Desktop local candidate identity correction

The historical Desktop Phase 6 candidate record v1 used Docker `image inspect`
`.Id` for both `image_digest` and `config_digest`. On a containerd-backed Docker
store `.Id` can identify an OCI index or manifest, not the OCI config. The v1
record remains a historical reader/verifier only. Current local-candidate
admission requires the closed v2 record plus its mode-0600 OCI archive sidecar.
The producer observes a stopped, exact-digest container to bind the actual
selected platform manifest, independently inspects the store descriptor, and
verifies the raw index (when present), selected manifest, config and every
selected layer/diff ID. The record keeps store descriptor kind/media type,
selected manifest, true OCI config digest, source/build locks, archive digest
and descriptor proof separate. The Provider current-candidate path rejects v1
and rechecks the sidecar; container inspection rejects selected-manifest drift.
No historical v1 evidence is rewritten or silently upgraded. The current
candidate is not a published or signed release artifact, and affected real
runtime/admission gates must be rerun before Slice 6 closure.
For the locked `linux/arm64/v8` profile alone, an omitted ARM64 variant and
explicit `v8` compare equal after parsing. This changes no raw descriptor
bytes, digest or selected-manifest rule; duplicate canonical platform entries
remain ambiguous and fail closed.

### Desktop broker containment clarification (2026-09-27)

The Desktop broker is the executable inside the real Desktop sandbox
container, entered as `desktop-broker serve`; it is not another container,
workload identity, UID/GID, network member, or independently isolated process.
The previously drafted separate `desktop-broker` container principal is removed
from the unpublished Slice 6 profile and evidence validators. A dummy broker
container would be false evidence. The fixed required `desktop-broker` component
instead names `desktop-sandbox-runtime` as parent and pins the executable
digest, exact argv, Unix socket and broker/session protocols. The Desktop
sandbox resource is controlled by `provider-desktop-runtime`, not the Desktop
executor backend; Provider remains the allocation and Docker authority.

The local gate must inspect the actual parent container and broker process:
parent container/image identity, effective UID/GID, PID plus process start
ticks to detect reuse, executable and argv, 0600 Unix socket, and a digest of
the actual Provider-mux/session association. Its inherited read-only root,
resources, network, seccomp, mounts and cleanup are validated through the
parent. The broker may be PID 1; no separate broker PID or container is
required. A same-container/same-UID replay file is not a defense against a
compromised workload. No Provider private key, PostgreSQL/Vault credential or
Docker socket may be transferred to this component. The complete gate must
exercise Provider mux to the allocation-specific exec/session, broker,
media/input, stop/replace/remove and exact cleanup. The component schema and
unit fixtures are configuration validation only; they do not establish this
runtime observation or close Slice 6. Phase 6 remains **5/15**.

### Browser/Desktop candidate runtime identity dependency (2026-09-27)

Both historical sandbox images and Docker adapters fixed `1000:1000`; this
cannot substantiate the Slice 6 profile's distinct actual container UID/GID
inventory. Higher numbers alone are not stronger isolation. For the Phase 6
candidate/v3 path, the trusted security profile must bind a finite set of
distinct numeric non-root identities to exact Browser/Desktop allocation
slots and their Provider-owned durable state/spec digest. An allocation has
one identity across create, broker exec/session, inspect, attach, restart and
cleanup. Identity exhaustion, collision or missing restart binding fails
closed. Public Provider DTOs, callers and sandbox requests cannot select it.
The distinctness claim is only for the declared simultaneous local deployment
set, not every UID on a host or a future cluster. The broker inherits the
Desktop parent identity and does not consume a second slot.

The Phase 5 signed images, locked `RequiredUID=1000` and historical Docker
adapter paths remain unchanged. Phase 6 must explicitly separate image
default USER from the effective runtime User, provide owner-matched private
tmpfs and application directories without root startup, extra capabilities
or writable business directories, and observe effective broker/Chromium
process identities rather than trusting `Config.User` alone. Desktop X11,
Openbox, VP8/input, replay ledger, and Browser Chromium/CDP/restricted egress
must pass under the chosen identities. The current Desktop candidate at a
high UID failed Openbox until a diagnostic passwd/group entry was added;
therefore the existing candidate cannot be declared compatible by Docker
User override alone. Any altered candidate image/build input needs new exact
local evidence and affected gates. Slice 6 remains open at **5/15**.

The static principal inventory is not a census of dynamic sandbox instances.
Browser/Desktop sandboxes and their per-allocation restricted-egress gateways
must be defined as closed workload/egress-gateway templates plus finite,
deployment-owned `sandbox_identity_slots`: one distinct numeric UID/GID per
actual independent container member and no more than one uncleared
allocation per slot. Slots bind the exact Provider owner, template digest,
controller, allocation/session, generation/fence and spec digest through a
durable atomic reservation made before network or container creation. A
matching retry recovers the same slot; uncertain creation or incomplete
cleanup retains it. Configured controller capacity cannot exceed its assigned
slots, with no silent clamp or reuse. The 1000 configured maximum is not a
claim that 1000 containers were exercised. Static service principals retain
their separate one-to-one observations; dynamic containers, network edges,
effective identities and each Desktop broker process need per-allocation
observations reconciled against both reservations and the run-owned Docker
inventory. Browser sandbox allocation is controlled by
`provider-browser-runtime`, not the Browser executor backend. The existing
restricted-network provisioner creates one real gateway container per
allocation; its historical shared `65532:65532` user is likewise not a
Phase 6 isolation identity or an exception for a co-container process.

The Phase 6 Desktop candidate image will use a canonical, bounded build-time
allowlist of only the workload UID/GID accounts it supports. One immutable
candidate may support several predeclared Desktop slots, including reuse by
compatible deployment profiles, but an account in the image is not an
allocation grant: the current trusted profile must authorize the exact pair
and the Provider must reserve its slot. The allowlist digest precedes image
construction; the image OCI identity and candidate evidence precede final
profile binding, avoiding a profile/image digest cycle. No full UID-range
account population, dynamic NSS, `LD_PRELOAD`, or mutable `/etc` is admitted.
The standalone egress gateway has its own separate image/runtime identity.
The passwd-entry diagnostic supports an account-lookup dependency, not a
proven Openbox source-level root cause; full high-UID v2 media/input and
cleanup evidence remains necessary.

Browser and Desktop Provider are deliberately different fixed UID/GID
principals. A single owner-private file-lock directory cannot be their shared
production ledger, and the two processes must not receive cross-role writes
or a new reservation broker merely to share slots. The trusted complete
deployment plan statically proves that their finite owner pools (including
both sandbox and gateway members) do not overlap. Each Provider receives only
its exact owner/controller projection and transactionally manages that pool
in its existing Provider PostgreSQL authority. Multiple processes of the
same owner/controller share that authority. No hot slot transfer between
owners or active profile revisions is supported. Initial ledger creation
requires an explicit clean-authority/resource check; a later missing,
corrupt or plan-drifted record is not an empty pool. Reserve commits before
Docker side effects. Uncertain create/cleanup keeps the slot, and release
requires a fenced cleanup state plus exact external absence observation
before a final transaction frees it. Slow Docker calls must not hold the
Provider-wide `control_state` row lock. The file-lock prototype was retired:
its component test is not production cross-role evidence. The owner-local
PostgreSQL adapter now binds the plan to the actual database and runtime role,
requires an explicit new-authority initialization check, and retains unknown
creates and incomplete cleanup transactionally. A disposable two-database,
two-role PostgreSQL integration proves role isolation and restart retention,
but its external-cleanliness callbacks are fixtures. No production driver yet
consumes these reservations or proves exact Docker resource absence, and the
real deployment's database grants and six-role gate remain unproved. Phase 6
remains **5/15**.

The owner-to-database/role/controller/material/target-edge binding belongs
inside this same complete security profile, not an independent deployment
authority. Browser and Desktop use distinct database names, runtime roles,
material references and owner projections, even if the validated PostgreSQL
physical service is shared. The profile binds the external service identity,
Provider-to-PostgreSQL trust edge and external CA artifact; the connection
must also prove that the resolved DSN and actual TLS server match them before
pool creation, and that `current_database()`, `current_user` and
`session_user` match after connection. A non-activated v3 Browser/Desktop pool helper selects
its own profile-bound broker/agent and exact DSN, validates a fresh client
certificate at each inner TLS handshake, and replaces pgx's dial, DNS and
fallback paths before creating the pool. Each subsequent pool connection
rechecks the actual database, current/session roles and minimal grants. The
historical direct-dial opener
remains for other schemas/profiles and is not a valid Browser/Desktop v3
path. No other role's broker, exported private key or direct-dial fallback
is authorized. Actual v3 startup refuses before any database dial until the
separate PostgreSQL-client certificate purpose and slot driver are implemented.
Server TLS validation alone is not mTLS, and native
PostgreSQL `clientcert=verify-ca` plus SQL credentials is not by itself exact
URI-SAN-to-SQL-role authorization. Those live connection/authentication gates
remain open at **5/15**.

The database-client authentication decision is a separate certificate purpose,
not an exception to the existing role/broker workload certificate format.
Each Browser/Desktop Provider receives a distinct PostgreSQL-only key and
restricted TLS-agent instance using the existing Vault PKI, certificate
controller, remote-signing, rotation and revocation machinery. The original
role TLS agent and its empty-Subject URI-SAN certificate remain exclusive to
Provider-to-broker and other established edges. The PostgreSQL certificate
has a CN exactly equal to its profile-bound, globally unique SQL runtime role
and an owner URI SAN, client-auth EKU and
digital-signature use only; it has no other Subject fields or DNS/IP/email SAN.
An explicit versioned private issuance purpose must independently validate
CN, URI, owner, PostgreSQL service/database/role and issuer. Neither CSR
caller nor DSN may select them, and ordinary workload certificates must never
be accepted for database login. The agent keeps the private key; no PEM key,
generic multi-certificate router or new long-running authentication proxy is
authorized.

The first implementation increment uses the separate private
`sandbox-runtime.postgres-client-certificate.v1` signed request/response
domain and a deterministic CN validator. The existing workload certificate
v1 domain and empty-Subject rule remain unchanged. The controller also
revalidates an issued certificate against the closed policy before recording
it, revoking an invalid result. The still-unlocked complete security profile
now has a separate `postgres_client_agents` inventory: two Provider-specific
agent processes, issuer policies and Vault roles, keys, peer-bound Unix
sockets, deterministic CNs and a dedicated client CA artifact. The ordinary
`tls_agent_bindings` remain one-to-one and cannot be reused for this purpose.
The certificate-controller command requires both extra policies/listeners,
and each PostgreSQL agent command requires its versioned purpose and exact
owner/database/role/CN/issuer binding. The Provider Browser/Desktop v3
configuration and pool helper select the second signer, not the ordinary
role signer; client certificate loading checks a fresh exact CN/URI/EKU,
pinned issuer chain and live P-256 signing challenge at bootstrap and every
handshake. These component checks do not constitute the required combined
controller/agent/Vault/PostgreSQL HBA or rotation/revocation deployment gate; v3 startup
remains closed before any database dial.

The PostgreSQL server must use exact `hostssl` database/role/approved-ingress
entries with SCRAM-SHA-256 plus `clientcert=verify-full clientname=CN`, a
restricted PostgreSQL-client issuer and a final rejecting catch-all. The
dedicated certificate CN must exactly equal the unique runtime SQL role;
there is no `pg_ident` map. PostgreSQL 16 rejects `map` with SCRAM at HBA
parse time, so the earlier mapped-CN proposal was infeasible and is superseded
by this decision. The asserted chain is controller-enforced owner URI to
dedicated role CN, then PostgreSQL CN and SCRAM credential to that same SQL
role; PostgreSQL does not itself authorize the URI SAN. Wildcard accepting
rules, `verify-ca` substitution and plaintext/no-certificate paths are
prohibited. The complete profile must bind the PG agent, issuer, purpose,
role CN and actual server-side HBA/CA artifacts, with real process evidence
for issuance, rotation, revocation, cross-owner rejection and bounded existing
connection drain. This decision does not change the locked Provider Contract
or grant Slice 6 completion. Phase 6 remains **5/15**.

The complete profile must carry one closed PostgreSQL service-level
authentication policy referenced by both Provider database bindings. It binds
the actual server identity, a controlled HBA artifact and raw-byte digest,
the existing dedicated client-CA artifact/digest, all approved ordered rules,
and the ingress CIDR PostgreSQL actually sees. There is one HBA per PostgreSQL
instance, not one conflicting file per Provider owner. Other roles using that
instance must be present in the complete rule inventory, or the narrower
candidate gate scope must be explicit; `all`, `trust`, an undeclared include,
an earlier permissive rule and an extra trusted client CA cannot silently
extend authority. CIDR is a network restriction, not an owner identity:
brokers may share a declared SNAT address, and their identity separation
still depends on broker admission, certificate CN, SQL role/password and
database grants.

Existing Slice 6 observation/evidence must bind the actual PostgreSQL process
and image, profile digest, read-only mounted HBA/CA raw bytes and their
digests, complete ordered parsed rules, controlled startup or successful
reload, and new positive/negative connections. `pg_hba_file_rules` reports the
current file, not the HBA last loaded by PostgreSQL; its view is ordinarily
superuser-only. Thus the view and `pg_reload_conf() = true` alone prove neither
active rules nor successful enforcement. The controlled deployment gate, not
the Provider runtime SQL role, performs this observation before v3 admission
and again on controlled recovery. Provider keeps only its own profile, TLS,
CRL, role and least-privilege checks; it gains no HBA-management or server-file
read privilege. Even the component PostgreSQL gate starts with a restricted
HBA whose source is independently checked against PostgreSQL's observed
client address; no broad source-discovery HBA is part of the approved path.
Continuous detection of
subsequent privileged DBA or host mutation is not claimed without a separate
mechanism. No additional signed deployment authority or long-running
database-management process is introduced.

The fixed Provider control-plane brokers are separate static deployments
from the dynamic per-allocation restricted-egress gateways. Each Provider
owner has exactly one dedicated broker, policy authority and `postgres`
alias, with distinct UID/GID and role-internal network. The complete profile
binds these identities and both the outer Provider-to-broker mTLS edge and
the broker-to-PostgreSQL edge. The pool construction now statically enforces
the alias-only path, but no live Provider/broker/PostgreSQL process gate has
proved the deployed chain or server-side certificate requirement. Provider
startup still fails closed after database/ledger checks because the Docker
drivers do not yet consume reservations before their first side effect.

The restricted-network Docker core now accepts an optional Provider-private
slot on the Phase 6 candidate path. It uses the reserved gateway UID/GID as
the actual container `User`, binds the complete slot in network/container
ownership labels, reconstructs it only from canonical labels, and rejects
missing/changed slot, legacy-user drift and mixed or noncanonical labels on
inspect/replay. The historical zero-slot path remains unchanged. A real Docker
component test observes the gateway process running at the assigned high
UID/GID,
exact replay, cross-slot denial and container/network absence after release.
This does not yet authorize a slot by itself: the Provider runtime call chain
must persist the trusted PostgreSQL reservation before calling the network
core, and both Browser/Desktop workload and broker identities must follow it.
Therefore this component does not lift the v3 startup refusal or Slice 6 gate.

Sandbox's follow-up decision puts the reservation repository and state
transitions in a thin Provider application coordinator, not in the Docker
driver. The driver receives only the complete-plan digest, finite slot
membership and exact allocation/claim/spec ticket; it never imports pgx or
the PostgreSQL adapter. The coordinator commits Reserve, then only the unique
winner of Reserved-to-Creating may issue the first network/container side
effect. A saved Creating record is not a new execution permit. Unknown
network, Docker or PostgreSQL CAS outcomes retain the slot and require
dedicated reconciliation. Recovery enumerates PostgreSQL reservations first;
local driver state is evidence, never a replacement empty-pool authority.
Cleanup must enter Cleaning before stopping sessions, prove exact resource
absence outside the row lock, then CAS CompleteCleanup; one 404 or deletion
response is insufficient. Creating-to-Cleaning needs a separate proof that
the former executor cannot still create late resources; it may not be
inferred from elapsed time or one absence observation. Observe stays
read-only, and all v3 attach/mux paths must use the same coordinator.

The Browser Docker driver now has a private bound-mode constructor and pure
per-slot spec digest projection. Its `AllocateBound` requires a matching
Creating ticket before it can issue network/Docker work; stale local state
rejects a replay rather than creating again. Bare legacy
Allocate/Observe/Attach/Cleanup are closed on a bound driver, while
ObserveBound/AttachBound require an exact Active ticket and recheck local
state/spec/slot identity. The Browser workload container and CDP relay exec
use the same high UID/GID, leaving the immutable image's default 1000:1000
untouched. A real Docker component topology with a fixture ticket ran both
Browser and egress gateway at disjoint high UID/GID pairs, attached CDP,
rejected a Creating replay, and removed its exact resources. It did not use
the PostgreSQL CAS or production cleanup coordinator, so v3 remains closed.

The subsequent real PostgreSQL-to-Docker composition exposed a distinct
post-cleanup replay gap: deleting the finite-slot reservation made the exact
old claim eligible for a new Reserve, even though the Browser operation was
retired. The correction does not create a parallel identity tombstone service
or ban an entire sandbox generation. A production Browser-bound Provider
repository atomically reads the existing Browser session authority, current
sandbox fence and finite-slot state under the same PostgreSQL control row for
Reserve and BeginCreate. It permits a first dispatch only for an exact,
unallocated, non-cancelled Accepted operation; an already-Active retry is
read-only and may recover a still-live Running or Succeeded session. During
BeginCleanup it persists a monotonic full-claim retirement in that existing
Browser session document before releasing the slot. CompleteCleanup rechecks
that retirement and the exact Cleaning reservation in one transaction after
independent Docker absence. Old claims cannot regain a UID after cleanup;
another genuinely admitted session in the same sandbox/generation may.
Missing or corrupt session evidence denies admission. The generic finite-slot
repository remains an isolated state-machine component, not the production
Browser admission port. The bound Docker driver still has no PostgreSQL
authority.

The same existing Browser retirement entry also records the exact Cleaning
ticket and receipt and a monotonic `released` bit. CompleteCleanup sets that
bit in the same transaction that removes the slot reservation, only after
fresh exact Docker absence. A lost commit response or failed local tombstone
finalization can therefore be distinguished from still-Cleaning and from an
unproven missing reservation. A retry requires this exact released proof and
finalizes only the old allocation's local binding; a new claim already using
the UID is untouched. Missing proof or mismatched receipt remains Unknown.

The tagged real PostgreSQL plus pinned Browser/gateway Docker component gate
now crosses those atomic transitions, two independent PostgreSQL pools racing
one exact allocation with only one Docker dispatch,
actual high-UID Browser and gateway processes, CDP, exact cleanup, PostgreSQL
restart with reconstructed Provider adapters, committed-cleanup response-loss
recovery, retired claim rejection before Docker work, an old cleanup retry
while a different authorized session uses the freed UID, and that new
session's continued operation. It does not prove the
complete v3 process graph, issuer/broker
network path, Creating uncertainty recovery, all attach/drain races, or Slice
6 readiness. Phase 6 remains **5/15**.

### Single-run Slice 6 evidence identity (2026-09-27)

The not-yet-accepted Slice 6 internal manifest is explicitly versioned to v3.
One trusted full-topology harness generates one fresh 128-bit lowercase-hex
`run_id` at run start, uses it for run-owned resources and runtime receipts,
and binds a private canonical receipt-index digest in the manifest. Each
referenced runtime receipt has independently hashed bounded raw bytes and a
closed companion envelope binding the same run, logical kind/subject,
profile/config/source revision and tree, observation time and result.
Scenario raw results must match the frozen 16 names, participants and
assertions; cleanup raw results must describe zero remaining resources owned
by that run. The bundle verifier resolves all run-generated manifest digest
references to actual private files and rejects missing, duplicate, orphan,
cross-run and tampered entries. Manifest-only verification is structural and
cannot close the slice.

Pinned source and candidate build/archive/OCI receipts retain their original
immutable identities; a new run does not relabel or rebuild the same image.
Internal run-ID/digest consistency is not an independent attestation that the
commands actually executed, nor protection against an actor able to rewrite
the entire bundle. That origin remains the trusted gate's auditable live
capture and exact cleanup. This adds neither a second security authority nor
a Product/Provider Contract change. The complete live topology and all 16
scenarios are still open; Phase 6 remains **5/15**.

The v3 artifact inventory has exactly two local candidate types:
`repository_role` and `desktop_candidate`. A neutral evidence row carries
only shared manifest/source/archive/OCI identity, while each type's own
private manifest retains its non-interchangeable build inputs. The complete
admission verifier reopens the clean committed source, exact role and Desktop
manifests and archive bytes; it compares their typed projections to the
same-run profile and observed selected manifest/config/proof. The Browser
sandbox instead uses the exact historical locked signed publication and
platform manifest, not a registry fallback. A manifest digest by itself is
not a supply-chain or running-container proof.

The descriptor `ProofDigest` remains the established domain-separated hash
of original OCI index/manifest/config documents. It is not the SHA-256 of a
receipt file. V3 therefore separately records `DescriptorReceiptDigest`,
the SHA-256 of a bounded canonical payload file retaining those original
bytes. A third digest belongs to the run envelope. The receipt index uses
the content digest only; complete admission reopens that payload, recomputes
the semantic proof, compares exact local archive bytes and reparses the
running container/image inspect pair. External dependency images require
the same payload and running inspect binding. Other indexed runtime digests
name raw command/inspect/probe/result/inventory file contents; profile,
config, source, archive and semantic proof digests remain separate inputs.
This corrects the unaccepted v2 draft without upgrading historical v1/v2
diagnostics or changing the locked Provider Contract.

Three source identities must not be collapsed: C is each candidate's
original immutable build revision/tree; R is the declared runtime baseline;
E is the gate/recorder/verifier implementation revision/tree. This initial
admission path deliberately accepts local candidates only when C=R and
re-verifies each against that exact clean checkout. Evidence tooling E may
advance independently, but the verifier must reopen its exact clean source
as well. A candidate with C≠R is not silently promoted by HEAD or a
`compatible` assertion: it needs a separately reviewed byte-level
target-equivalence proof. Without that path, this strict C=R gate needs all
local candidates from the frozen R, even when only one target changed; a
future proven target-equivalence path could narrow rebuilding to affected
targets. Browser's
historical signed publication remains independent of the local C=R rule.
The final command also independently rebuilds its own executable from clean
E with one fixed offline Go 1.26.8 recipe and compares the executing bytes;
the current managed worktree's Go build did not emit VCS metadata even with
`-buildvcs=true`. That local observation is not a general claim about Go's
VCS stamping. Byte equivalence on the trusted host is not an independent
signature, unique historical build provenance or a substitute for trusted
gate execution.

### Local full-topology profile supply (2026-09-27)

The Slice 6 local gate uses a repository-owned, versioned reviewed desired
inventory, not a manually supplied operator profile and not the synthetic
`validProfile()` test fixture. Its fixed sequence is desired inventory and
bounded run parameters; one fresh run ID; controlled operator-owned Vault,
external-dependency and empty-network bootstrap; verification of immutable
source/build candidates and actual issuer/CA artifacts; canonical profile and
source-mapping freeze; strict preflight; real role launch and independent
observations; all 16 scenarios; exact cleanup; then evidence-bundle validation.
Application roles must not start with permissive temporary policy while this
profile is assembled.

Run IDs, private paths and resource names may be generated within reviewed
patterns. The network CIDR/endpoint plan, UID/GID partitions and limited
identity slots derive from reviewed ranges, not observed containers; a clash
fails this run rather than widening policy. Vault may create an issuer during
controlled bootstrap, but its actual constrained issuer UUID/DER and trust
mapping freeze before any workload certificate admission. Leaf serials,
rotation and CRLs are later observations, not profile rewrites. Image
descriptors derive only from locked external images or audited immutable local
candidates, never an arbitrary image present on the host.

For this reviewed same-host candidate inventory, all 58 deployment names map
explicitly to their executable build targets. Static Product, Gateway,
Provider, Guest, Browser/Desktop role processes, agents, controllers, brokers
and relay use current-source local role candidates; Desktop sandbox uses its
separate current-source local candidate. Browser **sandbox** alone reuses the
already signed Phase 5 Browser publication, with its original source and
provenance identity rather than a false current-HEAD label. Admission pins the
full registry repository and index digest, platform and selected manifest
from the repository-owned publication. This selection does not prohibit a
later separately reviewed local Browser candidate under the broader rule
above. Loaded-image
inspection and source/target labels are preflight checks only: the full gate
still independently verifies original OCI bytes, signature/provenance, the
running container and process identity, effective UID/slot/CDP, and cleanup.

The generator emits desired configuration and bootstrap records only. The
observer separately reads live Docker inspect, effective process identity,
certificate chains/handshakes, PostgreSQL HBA/roles/new connections and
positive/negative network requests. A profile-to-observation projection is
not evidence. Changing an expected rule after launch requires terminating
that candidate run and beginning a new full run; receipts are not spliced.
The reviewed inventory now fixes exact principals, isolated/NAT membership,
a deterministic local /24/endpoint plan, static UID/GID partitions and all
77 local, external and Unix trust boundaries. The pre-freeze binder derives
target addresses from that plan and recomputes canonical profile/ingress digests;
the reviewed ingress rule fixes loopback host publication and relay limits.
It does not accept a post-hoc observed IP as desired. External and Unix peer
edge behavior, real immutable artifacts, controlled bootstrap and the complete
live gate remain open. This is not an accepted Slice 6 result.
The local gate's additional preflight comparison requires every numeric mTLS
target to equal the preplanned recipient endpoint, not merely a valid IP in
the right network; actual endpoint and handshake observation remains separate.
The reviewed external-service boundary also fixes the five service names,
SPIFFE URIs, DNS SANs and permitted inbound edge IDs independently of the
profile digest. Their OCI descriptors and CA material remain separate real
candidate/bootstrap inputs, not values copied from a test fixture.
The five local egress policies additionally fix role/broker/authority ownership,
key identifiers, private socket/ledger mount identities, refresh/lease bounds
and exact alias/host/port/protocol targets. Real authority keys and active
policy ledgers remain separately verified run inputs and observations.
For the Product broker's read-only positive control, the reviewed alias is
`registry-probe` to `registry-1.docker.io:443` over HTTPS; the future live
probe must be bounded to unauthenticated `GET /v2/`, no request body,
redirects, credential retry or repository/image/user operation. The gate
must require a verified public DNS
answer, strict TLS identity and the expected Registry API response, then test
rebinding via its controlled DNS while preserving the same broker dial path.
This existing third-party endpoint is not a run-owned deployment or an image
whose provenance we can claim. A DNS answer in `198.18.0.0/15` (observed on
ordinary DNS paths on this host) is blocked, not a reason to widen
`netpolicy`. Authenticated DoH to an explicitly pinned public resolver can
supply fresh checked A/AAAA records to controlled bootstrap without becoming
an application resolver or broker bypass. This run's complete 16-address
A+AAAA answer led Sandbox to review Product's policy-level `DNSMaxAnswers=16`
(formerly 8); the four other policies remain at 8. Product currently has only
the `registry-probe` target. The broker still checks every answer before a
numeric dial, uses its existing connection bound and one shared deadline;
17 answers or any forbidden address in a 16-answer set fail before dialing.
The general maximum of 32, lease and TTL handling are unchanged. Every
answer must fit the reviewed count/freshness bounds; otherwise the positive
gate stays open. The five trust-anchor names,
uses, mount identities and consumers are also reviewed separately from actual
CA bundle bytes and issuer observations.
The reviewed TLS-identity inventory additionally fixes each deployment's
SPIFFE URI, server SAN/EKU allocation and rotation/drain timing. Actual
certificates, signer ownership, revocation and handshakes remain live proof.

### External-service physical transport and resource-policy clarification (2026-09-27)

The 17 existing external logical/egress trust edges map to 12 reviewed
physical dial paths. A logical role-to-service edge does not grant that role
an independent socket around its egress broker. Browser action ingress,
Gateway and Browser/Desktop Providers use only their respective brokers for
PostgreSQL, Valkey and DNS; Product's PostgreSQL and the certificate
controller's Vault edge are the two direct paths. Each actual dialer and
service are declared members of a dedicated internal/isolated service bridge;
the Vault path uses the certificate controller's existing dedicated isolated
bridge. No host gateway, new shared service mesh, undeclared Docker member,
NAT attachment for an application role or new forwarding authority follows.
The desired transport plan is now code-checked for exact edge coverage, but
the external-service network membership and live endpoint observations are
still implementation work. A disposable Docker diagnostic found no default
route on the existing controller-only isolated bridge, so the old inventory
alone cannot be cited as Vault reachability proof.
These 17/12 numbers describe the current reviewed table, not a proven
complete runtime-dependency inventory. The coding Provider command requires
its own PostgreSQL runtime registry and currently has no corresponding
external trust/network/PG client-purpose binding in that table. Slice 6 must
add its dedicated, isolated direct PostgreSQL path with exact database role,
server mTLS/HBA and client-signer purpose, then re-count and revalidate the
complete inventory before freezing R or building all candidates. Browser and
Desktop Providers remain brokered and cannot inherit the coding direct path.

Every one of the 58 deployments must also bind a finite repository-owned
resource/seccomp policy by actual duty, not simply by a shared binary target.
Equivalent syscall needs may share audited bytes, but a Browser policy is not
automatically a Go-service policy. Exact JSON, provenance/license, original
content digest, architecture, runtime application and effective positive and
negative probes are required. The Desktop local-candidate path currently
declares Docker runtime-default seccomp without a corresponding pinned policy
artifact or application proof; it must gain explicit proven policy binding
before the full profile is accepted. Representative real loads calibrate
bounded memory/CPU/PID classes with headroom; they do not establish universal
minimums, and operator overrides cannot widen the frozen table. Current
Docker Desktop resource settings must be respected without automatic host
reconfiguration. This decision does not silently alter the historical Browser
publication or public Provider Contract.
