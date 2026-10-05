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

For the already declared external PostgreSQL service only, the controlled
operator bootstrap creates a separate server-only role under this run's
general Vault issuer. Its allowed URI is exactly
`spiffe://sandbox-runtime.test/external/postgres`, its sole DNS name is
`postgres.sandbox-runtime.test`, and it permits only a P-256,
DigitalSignature, non-CA ServerAuth leaf with the fixed 30-second backdate
and a complete lifetime no greater than one hour. It does not enter the
workload/controller role inventory or broaden their token ACLs. The run-owned
PG private key is generated with its CSR by the transient operator
provisioner; only the CSR goes to Vault. A private temporary file is used
for controlled delivery, then the key resides only in a PostgreSQL-exclusive
read-only mount owned by the actual PG UID with mode 0600 and a private,
symlink-free parent. It is not a Vault KV value, image layer, command-line
argument, environment value or workload-owned key. The provisioner removes
its temporary copy; the gate must prove wrong-identity issuance refusal,
exact issuer/serial revocation and failure-path cleanup. This external
bootstrap exception does not authorize a runtime role to mint server leaves
or change the frozen nine-source HBA, and it is not rotation/drain evidence.
The finite, networkless Alpine volume provisioner alone may run as UID 0 with
only `CAP_CHOWN` after dropping all capabilities; it has exactly two fresh
run-labeled volumes and no host bind, daemon socket or published port. On
Docker Desktop, `docker cp` was observed preserving host file ownership,
so each fixed, type-checked file is first transferred to provisioner UID 0,
mode 0600 is set while UID 0 still owns it, and then its ownership is passed
to the pinned PostgreSQL UID:GID `70:70`; the two 0700 parent directories are
transferred last. No recursive chown, `CAP_FOWNER`, DAC bypass, root PostgreSQL
runtime or broadened fallback is allowed. A separate no-secret probe must
confirm this order and cancelled-context exact cleanup before the Vault/PG
gate. During normal service, PostgreSQL is the sole container mounting the
private config volume read-only; the trusted Docker daemon/operator remains
part of the supply boundary, so this is not absolute host unreadability.

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

The Slice 6 Vault PKI role is installed and read back with an exact 30-second
`not_before_duration`. Vault backdates `NotBefore` without subtracting that
interval from a caller's requested TTL. The Profile's `TLS.TTLSeconds` and
issuer policy `MaxTTLSeconds` remain ceilings on the *complete X.509 interval*
(`NotAfter-NotBefore`), not merely on the issuance request. For the current
private production TLS-agent v3/v4 and managed controller configurations, the
request is therefore exactly Profile TTL minus the audited 30-second backdate
and one conservative second for time granularity (900 becomes 869 seconds).
The one-second allowance is a safety budget, not a claim about Vault's
guaranteed rounding. A budget below 60 seconds or one that makes the frozen
rotation window exceed two thirds of the request fails closed; neither the
request nor Profile rotation is silently clamped. The credential controller's
one-shot bootstrap leaf is checked against the bound Profile total-lifetime
ceiling, not against the shorter managed issuance request, while its exact
identity, chain, key, usages, current validity and minimum remaining operation
time checks stay in force. Existing private historical protocol versions keep
their previous request binding; no Provider Contract, token, credential or
lease TTL semantics change. A differing operator PKI role backdate makes the
real role readback fail and cannot become release evidence.

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

The unpublished credential.v2 listener profile now has one exact issuer
socket binding per approved certificate-controller or material-agent client.
Each binding fixes only the client deployment, independent private directory,
socket path, storage ID and Unix edge; server/client UID/GID and principal
digests come from the existing principal registry. The credential controller
owns each directory, whose group is that one client's independent GID, with
mode 0710; its socket is server-UID-owned, mode 0666, without `chown` or a
shared identity. The server gets a writable mount, and only that client gets
a read-only mount. An omitted, duplicate, substituted or extra binding,
reverse edge, cross-client mount, path/UID/GID drift or additional reader is
invalid before startup. The reverse credential-controller CSR endpoint is a
different authority and cannot be reused for token issuance. The credential
controller opens only the certificate-controller bootstrap listener until its
managed Vault mTLS identity is active; profile completeness does not authorize
early exposure of the remaining listeners. Credential.v1 remains unchanged.

Both credential.v2 peers verify the restricted directory, socket and Unix
peer identity before sensitive frames. The server has a finite first-frame
deadline and closes tracked accepted connections before waiting on shutdown;
cleanup removes only its original inode. A real separate-UID/GID Linux
container component gate proves the transport boundary, but the full
two-controller, non-dev Vault, final-profile process gate remains required.

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

The controlled external DNS candidate has a narrower responsibility than a
repository-owned mTLS role. The frozen gate keeps these claims separate:

| Boundary | Required observation | Explicit non-claim |
| --- | --- | --- |
| Broker → DNS transport | The broker negotiates only TLS 1.3, authenticates the pinned DNS CA, exact server URI/DNS SAN/EKU, and cannot fall back to plaintext or an ambient resolver. | A successful broker connection does not show that the external DNS listener refuses TLS 1.2 to every other client. |
| DNS client admission | The external DNS server requires and verifies a client certificate from a fixed, limited broker-client CA; only declared broker networks can reach its listener. The issuer's actual signable principal set and operator authority are audited. | CA verification and network admission are not a native per-broker URI allowlist or per-serial client CRL check. |
| Broker local lifecycle | Its own identity, policy, agent and peer-revocation sources remain current; their loss/revocation stops new resolution and drains existing connections within the declared bound. | Broker fail-closure does not prove that the external DNS server independently rejects an arbitrary revoked raw client certificate. |

The stock CoreDNS candidate's `tls` plugin supports `require_and_verify` but
sets its server minimum to TLS 1.2 and exposes no native URI allowlist or CRL
option ([CoreDNS tls plugin](https://coredns.io/plugins/tls/)). It may be used
only with the measured broker-side TLS 1.3, limited client CA and isolated
network above. Do not silently add a proxy or custom DNS binary, and do not
describe this candidate as a TLS-1.3-only or URI/CRL-enforcing DNS server.

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

#### Provider Docker-control and artifact dependency correction (2026-10-05)

The old frozen Slice 6 Profile is an input candidate, not authority to claim
that three containerized Provider commands can run. Their current constructors
open Docker directly and need writable runtime roots, while the Profile bans
daemon sockets and arbitrary host mounts and declares neither a Docker-control
channel nor all required roots. The correction is an explicit Profile/source/
evidence revision, not an undocumented `DOCKER_HOST` setting or an exception
hidden inside the old 78-deployment count.

The approved implementation direction adds one operator-owned, daemon-facing
Docker-control principal with three separately authenticated, closed Provider
operation scopes. Provider remains the sole business, allocation, fencing,
recovery and PostgreSQL authority; the control principal performs only typed
physical operations against frozen image/network/resource templates and
retains a bounded execution/unknown-outcome receipt. It cannot expose generic
Docker HTTP, arbitrary daemon identifiers, host paths, mounts, privileges or
exec targets. Browser/Desktop media executors and the Desktop in-container
broker never receive Docker control. Only this explicitly inventoried control
principal may have an exact daemon endpoint; that endpoint is host-equivalent
TCB, not made safe by a non-root UID or read-only mount. Its usable socket
ownership, cross-container authentication, denial matrix, quotas and cleanup
must be proved on the selected daemon before activation. No daemon mount or
new privileged service is authorized by this paragraph alone.
For the observed local daemon socket (`root:root`, mode 0660 inside a
container), the preferred candidate keeps one unique high UID and primary
GID and gives **only** this control principal the socket's fixed supplementary
GID 0. This is an explicit Profile exception, not automatic group discovery
or a global relaxation of role IDs; actual ACL/access and wrong-principal
denial still require a controlled component gate. It does not reduce the
host-equivalent power of Docker control.

Each Provider requires separately inventoried writable state, and coding also
requires a bounded staging root. Coding sandbox workspaces move to isolated
daemon-managed allocation volumes with confined input/output transfer, not
host bind paths or a shared workspace root. Browser's existing mux remains
owner-only; Desktop's broker mux gains an explicit owner-only socket volume.
Persistent state and staging cannot be represented by tmpfs merely to make a
read-only root start. Unknown Docker execution retains its slot and run-owned
resources until externally proved quiescent; restart never blindly repeats it.

The coding Provider's mandatory active-content and malware checks must be
real before it advertises artifact acceptance. `/bin/true` is a component
fixture only. The selected candidate engine is ClamAV 1.4.6 LTS, fixed to
its verified platform digest before use; its whole rule set/config/engine
binding requires a real operator-side successful check no older than 72 hours.
Runtime updater/network access and an unauthenticated raw TCP listener are
forbidden. Skip, unsupported/encrypted content, oversize, stale/missing rules,
error and cancellation fail closed; an unchanged old rule set cannot become
fresh by copying or modifying timestamps. The candidate scanner has hard
limits of 4 GiB RAM, 2 CPU, 64 PIDs and one concurrent scan. A private
scanner cannot gain Docker, Provider PostgreSQL or Vault credentials.

The first active-content policy is `passive-json-v1`: only genuine UTF-8
`application/json` documents, fully parsed to EOF under explicit depth,
token, string and total-size bounds, with duplicate keys and malformed
Unicode rejected. Filename extension does not establish MIME. Text/plain,
HTML, SVG, PDF, Office, scripts, executables and archives are unsupported
initially. JSON content is data, not a guarantee of safe downstream rendering
or resistance to prompt injection. Raw EICAR needs a separate actual malware
observation; early JSON rejection is not malware evidence. The locked Provider
Contract and 16 scenario meanings remain unchanged. A revised exact inventory,
negative gates, source-bound R/F/E inputs and independent live evidence are
required before Slice 6 can advance from **5/15**.
The initial source component implements depth 64, 250,000 tokens, 1 MiB
decoded string/number and 6 MiB encoded string limits while retaining the
Contract's 64 MiB total-file maximum. MIME parsing inherits the staging
context and checks cancellation during long tokens/whitespace. An individual
bounded key decode is atomic with cancellation checked immediately before
and after; an injected policy checker currently repeats parsing after MIME
classification, so production CPU/memory admission must account for or
remove duplicate work without trusting an unverified external scanner. This source
component is not yet a production scanner wiring or a full artifact gate.
The [official ClamAV scanning guide](https://docs.clamav.net/manual/Usage/Scanning.html)
warns that its raw TCP listener has no authentication and that files above
`max-filesize` may be skipped as clean; the
[official Docker guide](https://docs.clamav.net/manual/Installing/Docker.html)
recommends at least 3 GiB RAM. The
[official EOL matrix](https://docs.clamav.net/faq/faq-eol.html) gives the
candidate LTS support window, and the
[official rules FAQ](https://docs.clamav.net/faq/faq-cvd.html) explains why
individual `main`/`bytecode` database timestamps are not themselves a
freshness clock. These are reasons for explicit admission,
complete-result and resource checks, not implicit scanner qualifications.

Scanner composition refinement (`S6-Scanner-v3-composition-review-20261005`):
only an explicit coding Provider v3 Profile may select the local
`passive-json-v1` checker and private scanner client. Missing or mixed legacy
scanner configuration must refuse v3 startup, without quietly falling back
to command checkers or changing the retained v2/root-serve compatibility
boundary. The new client must receive the existing Profile-bound guarded
transport and CRL peer monitor, not construct a second TLS dialer from a
copied `tls.Config`; the scanner server must likewise track established
connections and close them on peer revocation or authenticated-source loss.
The scanner's fixed numeric endpoint, principal, TLS agent, rule asset,
resource envelope, and one-concurrent-operation budget remain Profile work.

The first rule-manifest candidate briefly introduced a new Ed25519 operator
signer. That would have created an unreviewed additional private-key authority.
The selected boundary instead pins the canonical whole-set manifest digest in
the already reviewed frozen Profile, with exact engine-image/config digests,
three rule-file versions/size/digests, an operator-check time and receipt
digest. Runtime rehashes the actual read-only file inventory, enforces the
72-hour window, and latches an observed in-process wall-clock rollback. This
does not itself prove an official successful freshness check, official rule
signature validation, or that the running `clamd` loaded those exact bytes.
Those remain operator and real cold-start gates; copying, re-signing or
retimestamping old rules cannot satisfy them. A separate rule-signing
authority would need its own ownership, purpose/key-ID, rotation, revocation,
anti-rollback and private-key-isolation review before adoption. On loss or
drift, v3 admission closes; it never falls back to `/bin/true` or stale rules.

Private scan authority is bound to the original accepted request and the
earliest of its original deadline, current Stage context deadline, and the
operation timeout. Retention is not restarted at scan time. A late response,
partial-body timeout, rule loss, active-policy skip or malware-engine error
cannot become clean. Ready probes and scans share the one-operation permit
because rule rehashing is expensive. These are source component invariants,
not a completed Provider v3 composition or release claim.

The local ClamD adapter diagnostic must use one Linux container with a
source-built Go probe invoking the actual Unix adapter in that same kernel.
Docker Desktop host path sharing is not a guarantee that macOS can connect
to a socket created in its Linux VM. The image's rule database directory is
owned by numeric `1000:1000` and mode 0700, so using the host user's UID or
dropping to root without capabilities is not a valid read-access proof.
The opt-in probe keeps one fixed non-root identity, only private tmpfs for
its Unix socket/configuration, one read-only non-secret binary mount, and
strict image/resource/process/output/cleanup bounds. Two preceding local
attempts failed before verified benign/EICAR results. The separately
reviewed revised probe passed once in the same Linux container: the real
repository Unix adapter returned clean for benign bytes and infected for the
68-byte EICAR test string; exact test-owned container cleanup was verified.
This is a bounded adapter component, not a deployment. The image-embedded old
rules cannot satisfy the 72-hour current-rule gate or substitute for v3
Profile/CRL composition.

#### Security Profile v2 boundary for the revised Slice 6 topology (2026-10-05)

Sandbox ruling `S6-Security-Profile-v2-boundary-reviewed-20261005` keeps
`sandbox-runtime.phase6-security-profile.v1` and its canonical JSON bytes,
`sandbox-runtime/phase6-security-profile/v1` digest domain, forbidden Docker
socket and mount/identity/allowlist semantics intact for historical and
restricted component replay. The new authority is explicit
`sandbox-runtime.phase6-security-profile.v2`, version 2, with digest domain
`sandbox-runtime/phase6-security-profile/v2`. This is distinct from Provider
Process schema v3 and does not change the locked Provider Contract or
unchanged receipt protocols. Decoder/validator chooses the stated version
exactly; it never tries v1 after v2 failure, strips v2 fields to downgrade,
or accepts an unknown version. Shared pure validators may be reused, but new
permission types are gated behind v2-only closed fields and roster.

The version change is required by *new trust semantics*, not by changing the
number 78 to a provisional 82. V2 must bind the one fixed daemon endpoint and
single control owner (high UID/primary GID with the one explicitly fixed
socket supplementary GID), its typed operation/receipt ledger, three
mutually isolated Provider-control networks, one coding-scanner mTLS/CRL edge,
fixed scanner endpoint and agent, immutable whole-rule/config/image asset,
per-allocation whole coding volumes, dedicated Provider state/staging/mux
volumes, and complete static plus dynamic peak resource envelope. It may not
leave those as an optional scanner URL or a second external allowlist. The
existing identity wire model is retained, with exactly four new deployment
identities and dedicated TLS ownership to be frozen in the v2 roster; neither
scanner nor control reuses Provider's identity or a TLS/egress/break-glass
private key. The two existing issuers remain the only roots.

The new complete Slice 6 gate selects only v2 and derives its one-run
inventory from that same source. Provider v3 coding must reject v1, missing
v2 control/scanner/storage/rule/resource bindings, mismatched digest, or
mixed legacy checker commands **before** material/PG/Docker/scanner network
side effects. Browser/Desktop may use their own v2 control scope but cannot
obtain scanner authority. Old Provider v2/root-serve restricted compatibility
is neither deleted nor relabelled as v2 evidence. The four additional
long-lived deployments are a provisional delta only: coding's dynamic
allocation UID/volumes and load peaks must be explicitly accounted for, not
hidden to make 82 look complete. A partial v2 draft is never runnable.
Rollback closes new v3 admission and withdraws only the new candidate;
it neither converts v2 to v1 nor deletes old state, volumes or historical
evidence. Real daemon service activation, new issuer use and the full gate
remain separate review boundaries.

The first implementation step keeps the four approved control/scanner and
dedicated TLS-agent principal tuples in a v2-only registry. Its provisional
78+4 static identity/TLS-delegation check is deliberately not a complete
Profile v2 validator: coding allocation identities, whole volumes and peak
resources can enlarge the final inventory. Until the complete v2 authority
and guarded private scanner/Docker-control composition exist, coding Provider
v3 serve refuses startup before material, PostgreSQL or Docker side effects.
That fail-closed hold does not retire historical Provider v2 compatibility or
make the incomplete v2 fragment executable evidence.

The subsequent bounded-coding-allocation decision
`S6-Coding-allocation-v2-bounded-plan-reviewed-20261005` selects **two**
fixed allocation slots for the current local qualification candidate only.
This is a positive finite capacity/closed-set assertion, not a production
default derived from terminal session limits. A third concurrent allocation
must be rejected. Each slot has a distinct high UID/GID reserved against all
static and Browser/Desktop slot identities, one `network=none` workload,
and exactly three whole named volumes: inputs read-only, workspace and outputs
read-write. Two slots thus require six separate allocation data volumes;
control receipts, Provider state/staging/mux and other persistent stores are
distinct. No fake Browser/Desktop `sandboxidentity.Plan` SessionID/gateway
fields, extra coding network/agent, shared subdirectory, host bind or root
ownership helper may be introduced. Source-bound image ownership and
confined volume preparation need exact implementation evidence before use.

Provider's existing PostgreSQL atomic operation boundary reserves the slot
and retains tenant/allocation/generation/fence/request-digest truth. The
control service holds only exact peer/Profile/request-bound physical receipts.
Unknown create/cleanup outcome, cancellation or restart leaves the slot held;
timeout alone never frees it or redispatches the same physical operation.
Reuse requires verified exact container and all three volumes cleaned under
the existing lifecycle state machine; a new generation cannot consume old
receipts or volume data. The complete v2 resource envelope must account for
the actual concurrent migration, Browser/Desktop, two coding workloads,
scanner's 4 GiB limit, control and agents, staging/double-parse peak and
held-during-recovery states, without double-counting templates or tmpfs.
Docker local volumes do not provide an implicit hard disk quota. The current
VM shortage remains, and no full topology/daemon activation is authorized
by this offline design decision.
The initial `codingidentity` package is only the typed offline reservation
projection/model: it binds the owner, Profile/template/image/config digests,
finite capacity, per-slot high UID/GID, `network=none`, and three whole volume
prefixes; physical volume names are scoped by Profile, allocation and
generation. Its in-memory state preserves unknown `creating` and `cleaning`
occupancy. Actual Provider PostgreSQL atomic reservation, source-bound image
ownership preparation, physical absence proof and v2 Profile admission are
still separate required implementations. No test callback stands in for
Docker cleanup evidence. Cleanup deletes the active reservation, so the
Provider PG operation ledger must also refuse a released old Claim from
re-reserving; `Reserve` requires that exact, same-transaction authorization
callback. The offline callback test covers this shape but cannot attest PG
atomicity or prevent a caller from supplying a false result. No second
business-history ledger is introduced here.

The accepted origin mapping `S6-Coding-allocation-origin-approved-20261005`
derives the private allocation ID from canonical JSON of
`{provider_revision_id,tenant_id,sandbox_id,create_operation_id}` under the
fixed `sandbox-runtime/coding-allocation-id/v1` SHA-256 domain. All four
values must come from the same accepted Provider lifecycle state transaction;
the ID is not a bearer credential and never enters the Provider Contract.
Attempt, current fence/generation and rotating Profile digest are separate
authorization/receipt bindings, not identity inputs. The create request digest
comes from the unique existing idempotency record, not from an assumed
`Operation.RequestDigest`: `StartCreate` leaves that field empty. The creation
generation is frozen from the actual first create (currently one); later
Suspend/Resume generation changes do not rename the original three volumes
or reserve another slot. Running/Unknown with no reservation cannot be
promoted to a fresh allocation on restart. Terminal create replay remains
readable through the Contract but cannot reopen reservation or redispatch.
The pure state-to-Claim projection enforces these early rejection conditions.
A private PostgreSQL adapter now composes the accepted-create ledger,
two-slot reservation and first Reserved→Creating permit with the lifecycle
Running/Provisioning transition under the existing single-row lock. The
real PostgreSQL component integration observes one winner among concurrent
clients and no second first permit after database restart. It performs no
Docker I/O, and its synthetic empty-namespace initialization is only a
test fixture. The subsequent optional Coding coordinator path requires the
same-Store lifecycle/first-permit repository and a ticket-only dispatcher;
legacy `Driver.Create`/`Inspect` cannot satisfy it. The PG first-permit
transaction also commits the existing provisioning event, so event failure
yields no ticket. A nil dispatch acknowledgment leaves Running/Provisioning/
Creating, not Ready; Running/Unknown recovery holds the slot and does not
redispatch before exact control receipts exist. Tagged real-PG component
tests cover two allocations, third-slot denial, lock-wait expiry/cancel,
corrupt or absent reservation documents and event rollback. A contested
first-permit error gets one bounded read-only current-state observation,
never an old Accepted snapshot or an overwrite of the concurrent winner.
The dispatch probe is not a Docker/control receipt. Production composition,
complete v2 Profile-bound slot specs, real control receipts and exact physical cleanup
remain open; the coding v3 startup guard stays fail-closed.

The reviewed control boundary uses three separate internal isolated IPv4
networks: each Provider shares exactly one with the common Docker-control
service, and coding has one additional private scanner edge. Direct mTLS,
exact peer URI, CRL/expiry and ingress-interface binding authenticate requests;
no second application-message signing key is introduced. A strict typed
envelope includes owner/tenant digest, opaque allocation, sandbox/session,
generation/fence/revision, operation/request digest, request ID and expiry.
The private physical receipt binds peer, Profile/policy digest and physical
mapping. Same-ID/same-digest status or completed-result replay does not
redispatch; conflict, expired scope or ambiguous physical outcome fails closed.
Per-allocation coding inputs/workspace/outputs are three separate whole named
volumes, not subdirectories in a shared volume. Image UID/GID ownership,
confined transfer, persistence/restart and exact cleanup remain live gates.
The old 78 roles would become provisionally 82 by adding control, scanner and
one dedicated TLS agent each; only the final exact Profile may establish that
inventory. No new daemon-facing service is activated by this design decision.

The first Coding create-control subprotocol is now an **offline component**, not
an activated broker. Its typed authority separates a request replay key,
derived from the accepted attempt/fence/policy/peer, from a stable physical
create-effect key derived only from the original allocation and creation
generation. A changed request key cannot recreate the same effect. The
authority binds the accepted Provider revision, tenant digest, exact
allocation/sandbox/operation, plan/spec and three-volume mapping digests,
Profile/control policy, authenticated peer principal, generation/fence and
bounded original operation deadline. Strict canonical decoding rejects
unknown, duplicate, oversized, drifted and expired requests. It carries no
daemon ID, host path, socket, image override or credential. Before any
physical callback, the private receipt ledger durably records `Unknown` using
one-writer locking, a private bounded canonical file, atomic fsynced replace
and directory sync. `Unknown`, including after callback error or restart,
never restores the permit; read-only status lookup remains possible. An
explicit empty-namespace proof is required to initialize a new ledger, and
an initialized but missing ledger refuses reopening/reinitialization. The
local candidate holds at most two unreleased effects and at most 4096 retained
records, including release tombstones. No `Completed` or `Released` transition
is exposed yet: those require exact trusted physical observations and, for
absence, quiescence/fence proof. Unit race tests are component evidence only;
the daemon-facing process, Profile v2, mTLS/UID/socket containment, real
container/volume mapping and reconciliation gates remain open. The Coding v3
startup guard stays fail-closed.

The subsequent control review tightened this component before integration:
the Provider-side constructor now takes the Running `lifecycle.Operation`
returned by the *same* PostgreSQL first-permit transaction and verifies its
ID, attempt, sandbox, fence, create/running state, cancellation and original
deadline against the ticket. A historical empty `Operation.RequestDigest` is
permitted because the ticket's digest comes from the accepted idempotency
record; a nonempty operation digest must match. The Provider independently
re-derives allocation ID from revision/tenant/sandbox/create operation and
requires the plan owner to match the authenticated peer. The Control side
does **not** read PostgreSQL: it validates the received closed authority
against an independently configured frozen plan, exact per-slot spec digest,
three-volume mapping, policy and authenticated peer. The ledger refuses two
unreleased allocations for one physical slot. Its persisted spec-map digest
also prevents an unoccupied slot's frozen spec from drifting across reopen.
Its trusted local clock is
re-read after lock acquisition and after durable commit, while the physical
callback uses a context capped by authority expiry and the original operation
deadline. External work runs outside the state mutex; Close waits boundedly
for in-flight work and retains the writer lock if it cannot prove quiescence.
Deterministic pre-write and post-rename fault tests prove that no callback is
granted after ambiguous persistence. These checks do not turn the offline
component into a production Docker-control broker.

Every ordinary repository-owned container in the Slice 6 gate uses a unique numeric
UID/GID, non-root execution, a read-only root filesystem, only declared tmpfs
and role-private sockets, plus one narrowly scoped managed persistent ledger
volume per policy-state authority. Its ledger volume is writable only by that
authority, never by its broker or another role; arbitrary volumes, host-path
bind mounts and shared business storage remain forbidden. The separately
reviewed Provider state/staging/allocation and broker-mux volumes above and
the Guest-only storage addendum below are closed, purpose-specific revisions,
not a general volume exception. All Linux
capabilities are dropped,
`no-new-privileges`, a role-specific seccomp policy, bounded PIDs/memory/CPU,
no host devices, host mounts, daemon sockets or extra listeners. The sole
operator-owned Docker-control TCB above is an explicit, separately inventoried
exception to daemon-endpoint access, not a general exception to this policy;
its exact containment is pending implementation and observation. The gate
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

The not-yet-accepted Slice 6 internal manifest is explicitly versioned to v4
after adding source-bound DNS broker-client CA and two-issuer evidence; v3 is
not accepted by the current verifier.
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

The same-host gate may use a run-owned, short-lived operator bootstrap for its
isolated non-dev Vault, but Vault PKI remains the actual issuer and revocation
authority. Prefer Vault-internal issuer-key generation: export only the public
CA chain, then verify its issuer UUID, complete DER and complete CRL against
the existing observer before freezing source mappings. The five trust bundles
are purpose-specific inputs, not automatically five different roots; their
leaf, EKU, direction and issuer relationships must be checked against the
reviewed edges. A temporary first-Vault-start TLS identity is operator-only,
bound to the pinned isolated endpoint, and never accepted by business roles as
final issuer or peer-CRL evidence. Revoke the initial root token and destroy
bootstrap private material after the managed paths take over. Do not create a
parallel local signing authority, broaden trust bundles, import system roots,
weaken TLS verification or substitute generated PEM files for real Vault
issuer/leaf/CRL observations. A lost or rebuilt issuer invalidates that run's
candidate rather than preserving its old digest.

For the final Vault listener trust transition, the same controlled run uses
run-owned private native `file` storage from the **first** non-dev startup.
After the two internal issuers and final Vault/controller leaves are observed,
stop only the old Vault process and restart it on the same private storage
with the general issuer's final server leaf and final client-CA set. No
parallel Vault writer, in-memory migration, issuer rebuild or intermediate
business-role admission is allowed. SIGHUP alone is not this transition: the
pinned listener can reload its server certificate/key but not its client CA.
Securely unseal the restarted server without placing keys in argv/logs;
re-read both issuer UUIDs/DER, complete signed CRLs, role `issuer_ref` and ACLs
through the final mTLS endpoint. Prove a new client succeeds, the old
temporary client CA is rejected by a reachable listener, and a client that
trusts only the old temporary server CA rejects the final listener. Revoke
the bootstrap token and remove temporary private material only after the
managed path has taken over. Final Profile trust bundles exclude both
temporary CAs. File storage is single-node, run-owned gate state, not a new
HA claim or an alternative PKI authority.

Descriptor-bearing role images use the closed one-shot FD input table in
`docs/audits/product-phase-6-slice-6-fd-startup-inventory.md`. The trusted
same-host operator checks the immutable Docker create ID/image/entrypoint,
then closes one bounded non-TTY stdin envelope bound to run/target/new nonce.
A fixed, source-bound Alpine shell trampoline does only literal `/dev/null`
FD3…FD6 reservations before any Go runtime starts, then `exec`s the loader;
it never reads stdin or interprets a secret, variable or caller-supplied
command. The short-lived loader verifies those slots, creates sealed 0600
regular memfds for FD0 and only that target's declared FD3…FD6, then `exec`s
the original role at PID 1. It adds no listener, privilege, arbitrary path,
persistent secret mount or supervisor; non-FD targets keep their direct
entrypoint. Automatic Docker
restart is disabled, and every restarted instance requires a new ID/nonce.
Both loader and role executable bytes must be independently rebuilt and
matched to the selected OCI layers before a source-bound candidate is
accepted. This is runtime-entrypoint provenance, not a Provider Contract
change, additional scenario or release-gate waiver.

### Two immutable Vault issuer groups and DNS client admission (2026-09-30)

Stock CoreDNS has a fixed client-CA admission path; it cannot authorize an
individual egress-broker SPIFFE URI after a leaf chains to that CA. Therefore
the isolated non-dev Vault `/pki` mount must create two distinct real issuer
UUIDs and DER certificates. One broker-only issuer signs exactly the five
reviewed egress-broker deployments; the other issuer signs ordinary role and
external-service leaves. The five existing trust-anchor names are purposes,
not five roots. Internal and external bundles contain only the issuers needed
on their actual edges. The DNS client-CA mount contains **only** the broker
issuer, never a general, parent or backup root. An ordinary client leaf with
otherwise valid client authentication must be rejected by the reachable DNS
listener at certificate validation, while a broker leaf succeeds.

Controller policy configuration pins each Vault role to one fixed issuer
source ID; each Vault role's `issuer_ref` must equal that source's immutable
issuer UUID. Issuance verifies the returned immediate issuer DER, and v1
revocation requests use the authenticated policy's complete fixed-issuer CRL.
The mount-default CRL, per-issuer override signing paths, controller writes to
roles/issuers, and workload-selected issuer references are not production
authority. The finite two-group policy and peer-edge mapping fails closed if
a non-broker gets the broker issuer or the DNS bundle issuer differs from the
broker source. Actual Vault role ACLs and a wrong-subject issuance denial
remain required live observations.

The source-bound candidate composition input is v2 and requires the original
single-certificate broker-client CA file plus its issuer UUID. The final
Profile binds the exact PEM bundle digest, issuer DER digest, issuer UUID and
five broker subjects into the DNS external identity. Slice 6 evidence is v4
and additionally requires private same-run receipts for the actual mounted
read-only bytes, Vault issuer inspection, successful broker handshake, and
rejected general-client handshake through a controlled reachable ingress.
Synthetic unit receipts establish only verifier behavior; no real two-issuer
Vault/DNS gate or Phase 6 acceptance has yet been claimed.

The locked external **stock CoreDNS** image alone has a fixed privilege
exception: index `sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286`,
selected arm64 manifest `sha256:9a631b1e34491f93a35334bc02d8ae190f16224be41689c7f42cc1711a95fe3a`,
UID/GID 65532:65532, `CapDrop=ALL`, `CapAdd=NET_BIND_SERVICE` only. Keep
no-new-privileges, read-only root, seccomp, finite resource limits and private
network with no host-published port; no repository-owned Principal acquires
an added capability. The upstream 1.14.7 image build sets the executable's
`cap_net_bind_service` file capability. On this host, dropping all bounding
capabilities caused `exec /coredns: operation not permitted`; re-adding only
`NET_BIND_SERVICE` allowed the same pinned image to execute. Port 853 is
below 1024, though the network namespace's `ip_unprivileged_port_start`
also controls bind privilege. This one capability can affect other low ports
in that namespace, so the final gate must inspect the actual listener and
network set as well as all process `CapInh/Prm/Eff/Bnd/Amb` values; each set
may contain no capability bit beyond `0x400`. The Profile and same-run
evidence reject missing/extra CapAdd, image/UID drift and host publication.
This does not create a generic external capability escape hatch.
The candidate preflight also reopens the selected original OCI layers and
requires the effective `/coredns` file's Linux `security.capability` xattr to
grant only effective/permitted `NET_BIND_SERVICE`, with no inheritable or
high capability bits. A changed or absent xattr rejects the external DNS
image supply before profile freeze; this is image-byte evidence, separate from
the live process capability observation.

The final local gate may inspect stock CoreDNS PID 1 with one fixed-purpose,
statically built read-only status inspector mounted as a single file at
`/phase6-dns-status-inspector`. The inspector accepts no path or command
arguments, reads only `/proc/1/status`, and emits at most 64 KiB. Docker exec
runs it as UID/GID 65532:65532 with a short deadline; it does not obtain a
new capability, network endpoint, writable mount, host PID namespace or
sidecar. Before and after that exec, the observer compares the same container
ID, image/entrypoint, host PID, start time and restart count. The gate retains
the inspector source/build/binary digest, mounted-file/exec inspection and
actual process-status receipts. The mount remains until exact container
cleanup; there is no hot unmount or production-service instrumentation claim.
This is a gate-only observation method, not a substitute for the complete
CoreDNS listener, TLS and 82-principal deployment checks.

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

The subsequent command audit identifies 18 actual direct external dials,
of which the current table includes only Product→PostgreSQL and certificate-
controller→Vault. The other 16 comprise Gateway→Product PostgreSQL, coding
Provider→its own PostgreSQL, Product/Provider one-shot migration jobs→their
own PostgreSQL roles, eleven material-agent deployments→their own Vault KV
scopes, and workload-credential-controller→its restricted Vault issuer. These
are approved only as separate internal+isolated dialer/service bridges with
exact credential, signer, ACL and cleanup authority. Browser/Desktop Provider
database traffic and Browser action-ingress/Gateway capacity traffic remain
broker-only. The command audit at
`docs/audits/product-phase-6-slice-6-command-dependency-audit.md` is an
independent completeness guard, not a successful runtime observation.
The reviewed target inventory consequently has 28 physical paths and 33
logical/egress edge IDs. This target count does not replace the still partial
12/17 currently installed profile graph; those missing edges and network
members remain implementation work before profile freeze.
The 28 planned service bridges retain existing role CIDRs, reuse only the
certificate controller's already isolated network, and allocate new bridges
from a separate reviewed `172.31.128.0/24` range. Each has exactly one
actual dialer and one external service member with fixed .2/.3 endpoints;
this desired IPAM is not evidence of Docker assignment or reachability.

The material-agent executable now offers an explicit canonical v2 command
configuration and Principal-bound workload-credential.v2 client. The v2 path
pins the verified security profile, deployment identity and controller UID/GID;
it never falls back to v1. The frozen v1 command path remains historical
Slice 5 compatibility; the complete production profile/admission gate still
has to reject that v1 configuration as a selection. This is only component
evidence until the eleven real agents and controller complete their process
gate. At this audit checkpoint, the historical v1 material-agent path and the
v2 credential controller's Vault client provided server TLS only. Network
permission alone cannot bridge that mTLS gap. Slice 6
requires managed material-agent client signing. The v2 material-agent command
now fails closed unless its separate signer, complete service bridge, exact
Vault endpoint/identity and pinned client/server CA roots are present; the
current activated profile lacks the necessary Vault edges and anchor consumers
(a separate synthetic 33/28 target profile now models them),
so this has no positive production-startup or live mTLS evidence yet. The
credential controller may use one
short-lived, FD-only, exact-identity Vault TLS bootstrap before a managed
identity switch, following the certificate controller's audited pattern;
there is no general static client-key or v1 fallback. Thus the earlier
"sole bootstrap exception" covers the certificate controller's original
exception; this narrowly reviewed credential-controller exception is an
additional, separately gated case, not permission for every agent.
The eleven actual material-agent deployments each now have one distinct
TLS-agent deployment in the intermediate closed inventory. The signer is a
separate private key owner; the issued Vault client leaf's subject is the
material agent, not the TLS agent. The current intermediate inventory is 69
deployments, 29 TLS-agent bindings and 99 trust edges, with existing role
UID/GID and CIDR assignments held stable. These counts are not the final
R checkpoint: the direct external edges, client roots, exact Vault policies,
controller internal managed key owner and other PostgreSQL signers still have
to be represented and tested. The 11 signers reuse the single
`workload-tls-agent` build target, not 11 new image recipes.
The TLS agents have only their declared Unix/controller edges: they receive
no Vault network membership, KV token or secret path. Each material agent
holds its own narrow Vault token and direct isolated bridge, so a valid TLS
leaf alone never grants KV access. The credential controller's future managed
Vault TLS key is an explicitly owned component of that existing controller,
not a phantom TLS-agent principal or a second CA. Its startup chain is the
bounded Vault bootstrap, restricted credential issuance, certificate
controller readiness, managed-key issuance/switch and only then the other
agents; a cyclic wait or static-key fallback is invalid. Migration Vault
credentials and job authorization are short-lived and nonrenewable even if a
TLS certificate is rotated: task completion, revocation or expiry must close
connections and destroy the corresponding key without reopening authority.
The subsequently approved credential-controller path is a single additional
Unix peer edge from the existing credential-controller principal to the
certificate controller, with exactly two mounts, its own policy, Vault role,
request-key digest, UID/GID and socket binding. It adds no deployment, Vault
network privilege or generic certificate-issuance endpoint. The private PKI
protocol accepts self-delegation only for the existing certificate controller
and this named credential controller; all other controllers and cross-subject
delegation remain denied. The private v2
command now requires the complete verified profile, FD-only short-lived
P-256 bootstrap client identity and an exact managed CSR key; it initially
serves only the certificate-controller credential policy. After a managed
controller socket becomes available under a bounded, cancellable wait and a
managed certificate and CRL bootstrap complete, it selects the new TLS
identity, drains every
pre-switch HTTP response on a non-reusing transport, destroys the bootstrap
key and only then opens other credential listeners. A failed switch or drain
fails startup. This is source/component behavior, not a completed real Vault
bootstrap, live handshakes or acceptance gate.
The profile and raw-network observer now have a closed, bidirectional
service-bridge member shape: an external service's declared networks must
name the same sole-service isolated network that declares it, with one actual
dialer principal and an independently inspected external container endpoint.
The evidence validator consumes the external container ID from the separate
external-service record; a role-only network inspect is not sufficient. This
is only a schema/verification primitive until the 16 missing bridges, exact
paths and live observations are present in a complete candidate run.

Every deployment in the final closed inventory must also bind a finite repository-owned
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

The Slice 6 implementation order permits a complete, reviewed, finite arm64
*candidate* resource/seccomp table before every duty has a separate live
benchmark. The candidate must cite the original and applied policy bytes,
license, duty-specific syscall rationale, existing samples, unmeasured
assumptions and headroom; equal syscall needs may share bytes, but binary
reuse alone does not prove equal duty. Synthetic fixtures, implicit Docker
defaults, `unconfined`, broad permissions and placeholder limits are not
admissible. Once frozen, representative real commands and dependency loads
must calibrate startup/migration, PKI/credential rotation and revocation,
Browser/Desktop media/input, fault and pressure behavior. Record memory/PID
peaks, CPU throttling, OOM/kill, load and duration, deadline/revocation
budgets, and positive *and* negative applied-policy probes; EPERM alone is
not seccomp proof. Every actual deployment still needs individual UID/GID,
mount, network, applied-policy and cgroup observations. The host admission
budget covers the real concurrent role set, all five external services,
daemon/observer overhead and cleanup reserve; migration jobs leave after
their actual lifecycle, while simultaneously needed steady-state roles may
not be serialized to hide insufficient capacity.

Here “broad permissions” means an unreviewed, accessible sensitive capability
or an unqualified generic baseline presented as duty-level least privilege;
it is not a mechanical judgment from a policy file's name or syscall count.
An explicit original Moby profile may be a bounded *component-calibration*
candidate before all 23 duties are benchmarked, but source/digest/shape
validation is not approval to run the final topology or accept a gate.
Review actual behavior families and applied conditions: Moby's
`minKernel=4.8` `ptrace`/`process_vm_*` allowance is not conditioned on
`CAP_SYS_PTRACE`, so cap-drop alone does not remove it. A controller/agent
without process-inspection purpose must use derived bytes excluding that
allowance, retain necessary Go thread and `clone3` fallback behavior, and
pass real positive/negative application probes. Other families may share
audited bytes only when their actual needs and deployment observations
support the sharing. No new approval subsystem or production bypass follows
from admitting source-bound candidate inputs.

One run fixes its profile, policy and limits before any role starts. A
calibration change ends and exactly cleans that run; a new run ID and frozen
inputs must pass the entire final 16-scenario gate. Different configurations
or runs cannot be spliced into acceptance. An unchanged candidate that passes
the complete live gate may be accepted without a ceremonial rerun. This
remains bounded arm64/topology/load evidence, not general capacity, SLO,
publication or production readiness.

### Shared PostgreSQL and purpose-specific signer adjudication (2026-09-28)

Keep one shared main PostgreSQL service and one finite, deterministic,
service-owned HBA/CA policy. Do not merge the separate action-history witness
service into it. Product and Gateway share the same Product database/business
state but have distinct SQL logins, DSN bindings, client keys and grants;
Product migration targets that same database with its own short-lived role.
Coding, Browser and Desktop Provider databases and runtime roles remain
distinct. Each actual Provider migration job is bound only to its target
database, role and lifetime; no wildcard migration login is authorized.

The old `provider_databases_only` HBA is a historical component proof, not a
complete shared-service policy. The complete policy enumerates exact actual
dialer source hosts (a direct role or its raw-tunnel broker), database, SQL
login, migration/runtime purpose, client CA and `hostssl` SCRAM plus
`clientcert=verify-full clientname=CN`, followed by explicit IPv4/IPv6 deny.
It must compare original raw HBA/CA bytes, read-only mount and effective new
connections, then prove both permitted combinations and wrong source,
database, role, CN, certificate, SCRAM credential and SQL DDL/privilege
denials. A successful HBA reload or parsed rules view alone is insufficient.

Product, Gateway and coding Provider each need a separate PostgreSQL-purpose
TLS-agent. Product migration and every actual Provider migration job also
need separate job-bound PG signers that are revoked and destroyed on exit or
expiry. Existing Browser/Desktop PG-purpose signers retain their own keys.
Ordinary role TLS signers cannot issue PG leaves, and Vault material-agent
signers cannot be borrowed by migration jobs. The PostgreSQL client leaf's CN
equals the SQL login while its URI/subject binds the actual pool-owning
process. PostgreSQL's HBA checks the CN, not the URI; PKI issuance policy,
signer/socket binding and application checks enforce that additional identity
and purpose. The current seven-pool-owner signer/HBA target table and exact
`.2/32` bridge-source renderer are code-checked candidates only: actual
deployment inventory, SQL grants, PKI roles and live authentication are
still open, and Phase 6 remains 5/15.
The Browser/Desktop Provider databases also require their own real one-shot
migration jobs in the final gate. Each gains a separate job, material agent,
Vault-client signer, PG-purpose signer, target DB/SQL role, service bridges
and short nonrenewable credential scope; the current coding Provider
migration job cannot migrate all three databases. The two additional tuples
are separately reviewed as a pending expansion target and must be folded
into the full profile, HBA and evidence before R freezes. Admin-driven
schema initialization in component tests does not substitute for a real job
performing the first migration in the final gate.
The updated final *desired* table now has 32 physical external paths, 37
external edge IDs and nine pool-owner/PG-purpose signer/HBA tuples, including
the Browser/Desktop migrations; the existing 28/33 and seven-tuple tables
remain explicit intermediate artifacts. These counts attest only closed
source-level targets, not principal activation, PostgreSQL loading, live
connections or acceptance of Slice 6.

The final source-level Profile candidate now includes the two extra Provider
migration jobs, their material agents and Vault-client signers, all nine
PG-purpose signers, 32 one-dialer/one-service bridges and the exact reviewed
trust-edge inventory, including the credential issuer sockets. It selects
`shared_nine_roles` with a single raw HBA digest over nine
ordered, exact `/32` source/database/login rules and an explicit deny tail.
`provider_databases_only` remains an intermediate component scope and cannot
be substituted in that final candidate. This closes a *declared* policy
graph only. Issuer policies, actual SQL grants, HBA installation and reload,
new connection outcomes, 82 independent deployment processes, 16 scenarios
and exact cleanup still require their own observed gate before Phase 6 can
advance from 5/15.
An opt-in disposable PostgreSQL 16 diagnostic now loads those same raw nine
rules into one real service on nine isolated bridges. It observes exact
`.2/.3` endpoints and absent host gateways, all nine accepted source/login
combinations, wrong role/database/CN/SCRAM and missing-certificate denials,
read-only HBA/CA bytes, restart and exact run-owned cleanup. Test-local CA,
client credentials and SQL setup mean this is HBA/transport component proof,
not Vault-issued identity or least-privilege migration/application evidence.

### PostgreSQL command-version disposition (2026-09-28)

The Product, Gateway and Provider live-signer v3 configurations remain
unpublished Phase 6 drafts and are tightened explicitly, not mechanically
renamed v4. Each production PostgreSQL path must require its owner-specific
PG-purpose signer, exact profile/source path, SQL login and database, and
reject any old v3 snapshot lacking those fields. Product/Gateway/coding
Provider are direct isolated bridge clients; Browser/Desktop Provider retain
their broker-only path and may not fall back to direct dialing. Before any
database connection, listener or DDL, the command validates its profile,
static authority, exact owner and path; after secret resolution but before
dialing it checks the complete DSN target and TLS policy against that profile.

The accepted Product/Provider migration v1 commands keep their historical
semantics. Slice 6 adds explicit Product migration v2 and one Provider
migration v2 implementation specialized by the closed coding/Browser/Desktop
job/database/role tuple. Gateway shares Product's database and has no
Gateway migration job. V2 migration verifies the server, current database,
current user and bounded DDL privilege before executing its migration. The
final Slice 6 gate rejects old direct-DSN paths and v1 migration selection;
there is no default or runtime fallback. This version disposition does not
alter the accepted Slice 4/5 manifests or the locked public Provider Contract.

### PostgreSQL revocation responsibility (2026-09-28)

The nine client owners share one parameterized implementation, but two
different certificate directions must be proven. A pinned CA and finite
certificate lifetime alone do not satisfy this gate.

| Boundary | Source and enforcer | Required observed result |
| --- | --- | --- |
| Client observes PostgreSQL server leaf | Fixed Vault issuer/source, PostgreSQL-purpose role agent, peer CRL guard on the logical caller's external edge; the physical Browser/Desktop broker remains a separate outer guard | Revoked server leaf rejects new handshakes; source loss, expiry, rollback or revocation drains existing tracked connections within the declared budget |
| PostgreSQL observes client leaf | Original PostgreSQL-client issuer's complete CRL, installed by the controlled external-service operator through `ssl_crl_file` or `ssl_crl_dir`; runtime/migration SQL roles cannot administer it | A revoked client leaf fails a newly opened TLS connection while a non-revoked control succeeds; file presence or `reload=true` alone is not evidence |
| Client observes its own issued leaf | Dedicated PostgreSQL-purpose signer and revocation status for the exact leaf used by each connection | Rotation, client revocation and signer/controller loss close active and idle pooled connections within the bound; old connection serials are not replaced by the new signer serial |
| Connection cancellation | Runtime pool/connection registry and one-shot migration executor | Long query or migration is interrupted, readiness/new connections fail closed, no unknown-result transaction is replayed, and close/cleanup is exact |

This is a responsibility matrix, not evidence of an activated CRL or a
completed drain. The controlled PostgreSQL process needs a real, fixed Vault
issuer source; the disposable test-local CA diagnostic above is insufficient.
No generic external PKI service or unreviewed fallback is authorized.

For the nine client owners, the local Slice 6 connection-lifecycle policy is
conservative: each PostgreSQL TLS handshake records the actual client leaf
DER/issuer/serial, and a different live signer leaf closes the old connection
before the new leaf becomes ready. Normal rotation therefore interrupts old
connections and potentially in-flight transactions; no write or migration DDL
is automatically replayed after an unknown result. The role also closes old
connections when signer snapshot authority or its CRL-safe deadline is lost.
This is not zero-interruption rotation and cannot revoke a non-cooperating
client's PostgreSQL session; the service-side CRL gate independently rejects
new handshakes. The existing TLS-agent's own CRL path now rejects incomplete
CRLs, number/content rollback and disappearance of an observed unexpired
revocation. A full bounded Vault-publication-to-drain measurement remains
required before the Slice 6 gate can be accepted.

The PostgreSQL transport must explicitly complete the pgx TLS handshake with
the connection's cancellation context before tracking or sending its startup
packet. Component observations and remaining gate gaps are recorded in the
Slice 6 startup audit; they are not final Vault/topology evidence.

Go invokes a client's `tls.Config.VerifyConnection` after standard server
chain verification but before the handshake-complete bit is set. The direct
PostgreSQL server-identity check therefore has a distinct handshake-time
entry: it requires TLS 1.3, one verified chain with the presented leaf bound
to its verified first certificate and a nonempty issuer, no resumption, and
the same exact Subject/URI/DNS/EKU/KeyUsage predicate as established peers.
The existing post-handshake identity check continues to require the
handshake-complete bit. Neither entry can bypass standard CA verification,
the PostgreSQL peer-CRL check or the own-client guard. A controlled real-pgx
regression reproduced the former misuse before the peer guard and passed
after correcting only this callback boundary; a new real Vault migration and
the final Slice 6 release gate remain separate evidence requirements.

### Credential-controller Vault token-role authority (2026-09-28)

The approved v2 controller uses operator-created, fixed named Vault token
roles, one actual permission set per exact backend policy. Its role name is
derived locally from the backend policy by a domain-separated digest; neither
the requester nor controller JSON can select a Vault token-creation path. The
controller's limited management token has update on only those named
`auth/token/create/<role>` paths, read on the same `auth/token/roles/<role>`
paths for startup preflight, and update on
`auth/token/lookup-accessor`/`auth/token/revoke-accessor`. It has no generic
`auth/token/create`, root/sudo, PKI/Transit/KV business path, or caller-selected
policy authority. The initial Vault root token is revoked after issuing the
limited orphan management token; it is not a runtime credential.

Each named role must have exactly one `allowed_policies` value, no allowed or
denied globs or entity aliases, `default` and `root` explicitly disallowed,
`token_no_default_policy=true`, a fixed non-orphan, nonrenewable service child,
no period or path suffix, and a 15-minute explicit token TTL ceiling. The v2
controller reads and validates this exact role configuration before opening
its first credential listener. It requests only the policy, bounded TTL and
complete subject/policy/binding/purpose/lease metadata from that role, then
checks the real issued token and later accessor lookup against the fixed role,
single policy, metadata, expiry and non-orphan/nonrenewable service
semantics. Vault intentionally omits the child token ID from accessor lookup;
the controller does not pretend that lookup can recompare those bytes. V1's
historical generic token-create path remains v1-only; the v2
production command has no fallback to it. An operator role change after
startup is still an external configuration event: the runtime's exact issue
and lookup checks remain fail-closed for the token it observes, but the
preflight is not a continuous Vault configuration attestation.

Vault ACLs do not make accessor lookup/revocation ownership-specific. The v2
controller's protected ledger limits normal application calls to its own
leases, but compromise of its management token can inspect or revoke other
accessors permitted by the same Vault security domain. It therefore requires
a dedicated Vault security management domain without unrelated business
tenants; this is not a claim of safe sharing with an arbitrary Vault
namespace. The narrower role-specific create paths do not erase that
lookup/revoke blast radius. A pinned, real non-dev Vault component test proves
root revocation, limited role reads, generic-create and cross-role-policy
denial, business-read denial, fixed-role issue/verify/revoke and container
cleanup. It also observes that the same management token can look up and
revoke an unrelated orphan token's accessor despite lacking its business
policy, making the dedicated-domain requirement empirical rather than an ACL
assumption. Its loopback publication and test CA do not prove the final isolated
service bridge or two-controller startup chain.

Both controller Vault clients use the same non-reusing HTTP bootstrap
transport. A managed certificate is selected before the transport's switch
barrier; every request that might have selected a bootstrap leaf is counted
until its response body reaches EOF or closes. Destruction of either static
bootstrap key waits for that count to reach zero under a startup deadline.
The certificate controller also waits for its managed-agent loop to drain
before revoking the managed leaf and closes its leased PKI token on early
startup failures. The real Vault mTLS component test exercises this transport
switch and managed-certificate revocation, but does not establish the actual
two-controller process order or final network confinement.

### V3 material-consumer correction and exact KV authority (2026-10-01)

The Browser and Desktop v3 executor commands construct live TLS signer and
peer-CRL clients; they do not construct a material registry or read Vault KV.
Their historical `browser-agent` and `desktop-agent` material processes, and
the two TLS agents that existed solely to authenticate those processes to
Vault, are therefore retired from the unaccepted Slice 6 final inventory.
This is not a switch back to static V2 TLS material. The Browser/Desktop role,
executor backend, and their actual v3 TLS agents remain mandatory. The closed
desired inventory is now 78 deployments, 11 material agents and 12 credential
issuer sockets/policies. The original 82-deployment candidate remains
historical component work, not evidence for the revised topology. The 16
release scenarios and their security assertions are unchanged. Surviving
UID/GID and CIDR allocations retain their old values; the retired slots are
reserved, not reassigned to another principal or network.

For the 11 remaining agents, `slice6_material_access.go` defines 18 distinct
run-private KV v2 documents from actual v3 runtime/migration material
purposes. Each agent has one distinct backend policy and fixed token role;
each policy grants only `read` on its own exact `kv/data/<agent>/<purpose>`
paths. The finite mapping binds the owning deployment, agent principal,
UID/GID, credential socket, policy, binding version and purpose, paths and
configuration digest to the verified Profile. No agent receives a TLS private
key from KV, a wildcard/prefix or directory-list permission, another owner's
document, or PKI/token-management authority. The certificate controller's
separate `certificate-controller-pki` policy does not gain KV access.

Vault token-role validation checks the policy *name*, not its ACL contents.
The controlled operator must install and read back the exact ACL text and
fixed token-role restrictions before running the credential controller;
positive own-path reads and negative cross-owner, list, write, PKI and token
creation probes remain real-gate work. KV path ACLs do not restrict a caller
to one document version at the Vault service: the client must still request
and verify the exact binding version and returned metadata. The mapping and
readback verifier are configuration tests only at this point; no live
controller/agent or final Slice 6 acceptance is claimed.

### Slice 6 run-owned bootstrap and private startup inputs (2026-10-01)

The local gate may bootstrap only fresh, empty, exact run-owned named volumes.
Its one-shot filesystem-preparation container may run as UID 0 solely to
assign each private startup directory and 0600 file to its distinct reviewed
non-root principal. It has no network, host path, existing-volume access or
business migration duty; its root filesystem is read-only, privileges cannot
increase, all capabilities are dropped except narrowly required `CAP_CHOWN`,
and seccomp, resource and time limits are mandatory. It exits and is removed
before any non-root runtime starts. The public CA directory remains a separate
root-owned, read-only trust input. Private keys, Vault tokens, passwords and
DSNs never enter volume metadata, arguments, environment, logs, Git or public
evidence. Real PostgreSQL/Valkey accounts and short-lived keys may be created
only as same-run operator bootstrap; the first business DDL comes from the
actual migration job, and actual consumers and cross-owner denial must be
observed before acceptance.

The two live controllers have distinct exclusive `persistent_ledger` mounts
and fixed `ledger.json` paths. The bootstrap operator creates only empty
volumes; each controller creates and replaces its own ledger. A restart uses
that same volume; loss, corruption, aliasing, extra writer or a shared mount
fails closed. A declared `MaxBytes` is not proof of a filesystem hard quota:
for these named volumes it is a logical allowed-file-set budget, not a hard
device or per-volume quota. The 20 MiB ledger budget covers the 8 MiB current
file and at most one 8 MiB in-flight atomic replacement plus allowance; each
controller rejects unknown, unsafe or crash-leftover entries in its exclusive
directory before recovery and before another write. It does not silently
delete evidence. The 4 MiB private-config budget bounds a closed set of
individually size-limited files. The gate must measure actual file count,
logical bytes, ownership and modes, demonstrate read-only write denial with
no remaining writer, and record host/daemon disk headroom. None of this claims
kernel-level disk isolation against a compromised controller; tmpfs and
container memory, CPU and PID enforcement remain separate actual gates.

Every actual startup Profile reader has one dedicated, read-only
`private_config` directory with a closed filename/purpose manifest and unique
storage identity. The Profile file is per-principal and is pinned by its
launch digest, not by a self-referential hash in the Profile. Full peer-CRL
source documents go only to the controller and TLS-agent consumers; ordinary
and PostgreSQL-purpose role derivatives occupy different filenames and may
not be substituted. Browser/Desktop backends, ingress relay and Browser
action ingress use a fixed startup-authority filename there. Gateway, Guest,
Browser and Desktop roles use three separately named credential, dependency
and policy authority files. Dynamic secrets still use their existing
Unix/descriptor/in-memory boundaries; this decision does not create a
generic secret-output volume or relax the Provider Contract. The release
Profile is optional and may not be fabricated merely to satisfy a mount.

These are source-level corrections to an unaccepted v3 candidate. The final
78-principal topology, both controller processes, real material consumers,
first migrations, 16 scenarios and exact cleanup remain live release gates;
no static Profile or component test alone advances the 5/15 Phase 6 count.

The Product SQL bootstrap crosses two authorities in a fixed order. The
controlled operator first starts the external PostgreSQL server with its
original nine-source HBA, non-root image identity, dropped capabilities and
final server TLS configuration while the Vault bootstrap root still exists.
Client-certificate CRL installation and revoked-client rejection remain a
separate live gate. Over
the local PostgreSQL peer socket, that operator alone creates the `product`
database and `sandbox_runtime_product` schema, revokes PUBLIC database/schema
rights, creates separate short-lived, non-elevated SCRAM login roles, and
verifies exact attributes and negative privileges. Password setup must use
client-side encrypted native PostgreSQL tooling with statement, duration,
parameter and error-statement logging suppressed and read back *before* any
secret is sent. Plaintext SQL, argv, environment, logs and public evidence
are not acceptable password channels. Each independently generated role DSN
then goes to its exact, create-only Vault KVv2 purpose/owner/version binding;
scoped readback and cross-purpose/cross-owner denial precede root revocation.
No Product business DDL is an operator/bootstrap step.

After root revocation, only the independent Product migration v2 job may
perform the first Product DDL. Its SQL role has CONNECT on `product` and
USAGE/CREATE on the precreated Product schema, without database CREATE,
elevation, inheritance or membership. The runtime SQL role initially has
CONNECT only. After successful migration, the operator must grant and
read back only observed current-table DML, schema USAGE, and migration-ledger
SELECT; no blanket future-table defaults, ledger write, TRUNCATE,
REFERENCES, TRIGGER, GRANT OPTION, sequence or function rights are implied.
Migration, signer and material-agent jobs then exit. PostgreSQL remains a
controlled external dependency through the business-process checks and must
be stopped and removed before one-shot terminal certificate cleanup. This
ordering is necessary but does not itself qualify Product runtime SQL,
nine-source egress, the 78-principal topology or the 16 release scenarios.

### Slice 6 controller termination and one-shot operator cleanup (2026-10-01)

The two controllers form a terminal revocation dependency: credential
controller revokes its managed Vault TLS certificate through certificate
controller, while certificate controller revokes its PKI token through
credential controller. A sequential TERM order or simultaneous TERM is not a
proof of complete revocation. Shutdown first rejects new business work,
issuance, renewal and admission, waits within a fixed deadline for rotation
and in-flight operations, and preserves only the authenticated revocation and
necessary status/CRL paths. Local key destruction is distinct from remote
revocation confirmation. A failed remote call remains pending/unknown or
failed in the exclusive ledger or bounded non-secret cleanup receipt; repeated
Close must not turn the first failure into success. EOF, timeout, 403, 404 and
an unavailable peer are not evidence of revocation. An expired result needs
trusted issuer or token-state evidence for the exact identity and revision.

The terminal cycle requires an independent, one-shot operator cleanup task
for this run's dedicated Vault security domain. It is not a third resident
controller or another member of the 78-principal runtime inventory. Its
short-lived, nonrenewable, non-default, non-root orphan service token is
prepared during controlled bootstrap, delivered only to the operator through
an approved descriptor/in-memory boundary, and remains usable after the
initial root token is revoked and destroyed before managed runtime acceptance.
The cleanup identity and mTLS key are independent of both controllers and of
the temporary first-Vault-start client. Its exact allowed operations are
fixed-mount PKI revoke and two fixed-issuer certificate/complete-CRL readback,
token accessor lookup/revoke, and its own final revoke-self. It cannot sign,
create or renew tokens, read KV/Transit, alter roles/policies/issuers, list
all objects, or gain sudo/root. Vault's PKI-revoke and accessor-revoke ACLs
are not serial- or owner-scoped, so the operator must independently bind each
requested serial/accessor to the run ID, Profile, issuer, subject and exact
exclusive-ledger entry; unknown or cross-run entries fail closed. It records
actual remote revoke and independent readback before deleting the isolated
Vault. Deleting that Vault alone proves only resource cleanup. The operator
token then self-revokes, its mTLS key is destroyed, and any remaining
certificate lifetime/trust boundary is reported rather than concealed.

The original private terminal plan/receipt v1 retains exactly two controller
certificate targets and two token accessors. A run that signs the external
PostgreSQL server leaf requires explicit private input/plan/receipt v2,
advertised by the independently built operator before signing. V2 adds
exactly one `external-postgres-server` certificate target, not an arbitrary
serial list or a new Vault token/operator. The operator re-parses the frozen
public leaf and issuer, binds their DER digests and derived serial to the
run/Profile/general issuer and exact PostgreSQL URI/DNS, and compares the
independently observed PostgreSQL-mounted leaf digest. It checks all three
serials against the same issuer's signed complete CRL before the two token
accessors and final self-revocation. Missing or duplicate targets, v1
fallback, partial revoke and physical deletion never count as confirmation.
The PostgreSQL private key is not an operator input. This terminal path does
not substitute for running-service rotation, CRL-denial or drain evidence.

For the local Slice 6 diagnostic, the one-shot cleanup uses the already
locked Alpine arm64 image as a fixed carrier for a separate, clean-source,
statically built Go HTTP executable. The Vault image is unsuitable as this
carrier because it declares two `VOLUME` paths that Docker silently turns
into anonymous writable volumes. The finite task has a predeclared
UID:GID of `20090:30090`, disjoint from all 78 resident principals; it is
in the closed bootstrap/cleanup inventory, not a new resident Profile
workload. Its sole bridge has Vault and this one task as members. Docker
image inspect must bind the pinned OCI digest, platform, environment and
absence of declared volumes; container inspect must bind the non-root
identity, exact image/entrypoint and sole read-only executable bind. Before
any secret delivery, `docker cp` reads that actual created-container bind
and compares its SHA-256 with the clean-source build. The source revision,
tree, Go toolchain and fixed build flags are separate from Alpine's own OCI
identity; the binary is not claimed as an Alpine layer. Inspect also binds
the read-only rootfs, dropped capabilities,
no-new-privileges, seccomp and bounded memory/CPU/PIDs/time. It has no host
publication, daemon socket, business bridge, host network, HOME, named
volume, credential cache or log sink. The task receives its limited token,
independent mTLS key, prefrozen plan and two independently read ledgers only
through bounded stdin or an equally private in-memory/FD handoff, never
arguments, environment or stable API. The final observer inventories both
resident and finite tasks; unknown containers fail closed. A stock CLI
requiring privilege is not a reason to relax the boundary: a narrow HTTP
client with a fixed Vault host and operation set is preferred. An operator
response is accepted only after exact accessor and issuer/complete-CRL
readback, self-revocation and private receipt; source/controller ledgers
remain unmodified. This diagnostic does not establish production operator
acceptance in later slices.

This is the approved minimal local gate boundary, not proof that an
independent production operator, recovery or terminal-credential supply has
passed. Those remain named release gates. Earlier diagnostics retained the
initial root token; R21 and later revoke it before controller PID1 startup,
but that ordering alone is not final evidence. Ordinary and PostgreSQL
certificate signer delegation remains a separate finite Profile-bound policy:
all 38 policies must pass the production validator, the 9 dedicated
PostgreSQL signers cannot gain ordinary TLS issuance, and shared Provider
principal vocabulary does not erase per-instance digest, owner, SQL role,
key, socket, UID/GID and issuer binding.

### Slice 6 material-agent Unix correction (2026-10-02)

The reviewed 11 agent→owner material-access facts now derive 11 distinct
owner→agent Unix endpoints in the final draft Profile. Each endpoint fixes
agent/owner deployment and UID/GID, storage ID, directory/socket path,
agent-writable and owner-read-only mounts, a `0710` agent-owned directory
with the owner's directory GID, a `0666` socket, exact peer credentials,
first-frame and operation deadlines, bounded capacity and socket cleanup.
The final static gate rejects a missing, aliased, exchanged or extra reader
even if the Profile digest is recomputed. The historical same-UID `0600`
material-agent transport is retained only for Slice 5 compatibility; the
explicit cross-UID v2 transport uses inode checks, a bounded first frame,
tracked handler close and same-inode cleanup. A real Linux Docker component
test has crossed distinct UID/GID boundaries and rejected third parties.

The material agent checks the final Profile's exact listener/owner binding
before requesting a workload credential. A Slice 6 role must check its
Profile, own v2 material endpoint and exact binding inventory before the
first resolution; Guest v3 now performs that preflight before its signing
key read. This does **not** complete Slice 6: break-glass controller/agent
operator paths still need their own explicit cross-UID v2 binding and
persistent state, all remaining owners need live v2 configuration, and the
78-deployment/16-scenario evidence gate has not run. Profile v1 and the
material-agent v2 command remain unaccepted Slice 6 drafts and can be
tightened without a locked Provider Contract change. Phase 6 stays 5/15.

### Slice 6 break-glass transport and finite operator correction (2026-10-02)

The final draft Profile now binds one operator→controller control socket,
seven agent→controller target-specific consume sockets, and seven
operator→agent delivery sockets. All 15 have distinct storage/path/peer and
`0710` directory plus `0666` socket layout; every principal mount has one
server writer and only its designated non-task client reader. Eight finite,
one-shot operator tasks are a separate Profile section, not an additional
fixed deployment or a new business principal kind. Their reviewed identity
`20091:30091` is distinct from all 78 principals and the terminal-cleanup
operator `20090:30090`; they have one read-only executable-file bind plus
one read-only socket-directory mount per task,
network-none, non-root, read-only rootfs, dropped capabilities, NNP and
bounded resources/duration. The live runner must still verify each actual
task chooses exactly one authorized operation and the matching socket mount.

The explicit v2 Unix constructors reuse restricted socket inode, peer,
first-frame, drain and cleanup checks. They retain the existing signed v1
business payload, signature domains, capability, ledger and audit schemas;
the transport upgrade does not authorize an unsigned or wrong-target
consume. A real Linux different-UID/GID controller component test has
observed signed submit, wrong-endpoint/peer denial, drain and exact cleanup.
The break-glass controller now has its own exclusive persistent ledger/audit
allocation and private Profile input. The source-bound freeze uses 12 existing
credential identity private-key sources, of which seven runtime agents also
serve as target break-glass signers. It admits only four public external actor
files and one controller-signer private source in addition; actor private
keys stay outside the production Profile builder/controller. The closed
11-actor digest inventory is Profile-bound and each material agent checks its
own FD public key before credential issuance. This is **not** production
operator acceptance: the component issue→delivery→consume/replay/restart
observations below do not replace the full-topology release gate. No v1
same-UID production fallback is allowed. Phase 6 remains 5/15.

Sandbox's carrier correction keeps the fixed 78 deployments and 12 local role
image targets. The eight finite tasks share a separately clean-source-built
static Go operator executable, not an executable allegedly present in Alpine.
The Profile binds one artifact record: exact source revision/tree, Go version
and toolchain digest,
build parameters, Linux arm64 target, binary digest/size/path and pinned
Alpine OCI index/selected manifest/config/platform. Each task authorizes only
that read-only executable bind plus its designated read-only Unix socket
directory. The live runner must inspect the created container and read the
actual mounted executable bytes before sending a signed request or capability.
No requester/approver/operator private key is mounted; the operator receives
only bounded pre-signed input. This is a local gate packaging boundary, not a
self-contained published OCI or cross-platform deployment claim.

### Slice 6 live Guest break-glass component checkpoint (2026-10-02)

At clean test checkpoint `9511b44ad2b65421d78db239bad6309f85f9ad55`,
the source-bound real Docker component gate passes the signed Guest
`material.resolve` submit/two-distinct-approval/issue sequence through finite
networkless operator tasks. The controller has already been replaced once and
has recovered its persistent replay ledger. With the real Guest TLS signer and
material-agent PID1 online, a separate operator task delivers the newly
issued single-use capability to the exact Guest delivery socket. The agent
signs the online consume to its target-specific controller socket and resolves
its Profile-bound signing key through scoped real Vault KVv2. The controller
ledger changes from `issued`/zero uses to `consumed`/one use with exactly one
new audit entry. A second delivery before expiry is denied; ledger revision,
audit count/head and use count remain unchanged. Clean checkpoint
`f18c931d0652c5c5d2e61c5e0c42460420b317a3` then stops and removes that
controller, launches a third real PID1 against the same exclusive ledger,
and observes recovered `consumed`/one use before the still-online Guest agent
re-delivers the identical, unexpired capability. The replacement rejects it
without changing ledger revision, audit count/head or use count. Dirty and
clean-checkpoint Docker runs pass with exact container cleanup; full repository
race/shuffle, vet and Product Contract lock verification pass.

This is component evidence, not final Slice 6 evidence. The owner-side
material observer is not the formal Guest production PID1, and this gate does
not run the independent Product/Guest
security edge, all 78 principal processes, the frozen 16 scenarios or a
strict release manifest. Phase 6 remains **5/15**.

### Slice 6 core startup and material-registry correction (2026-10-03)

Sandbox selected the existing per-role `private_config` volume as the sole
carrier for a non-secret `startup-config.toml` in each of the twelve core
deployments (eight runtime roles and four migration jobs). Its file manifest
and 64 KiB per-file bound are closed by the same Profile/private-archive
validator as the other role files. The core entrypoint must read the exact
`/run/phase6/config/startup-config.toml` after validating its Profile and
actual process UID/GID, owner/file mode, role and command, before logger or
external work. It parses those same bytes without an environment override or
fallback; an alternate path, extra role/section or unknown key fails. Legacy
`config.Load` remains unchanged for non-Slice-6 deployments. No additional
volume, network, FD, generic configuration framework or secret-bearing TOML
is authorized by this decision.

The previously identified v2/v3 material-registry gap is corrected at each
confirmed production entry point: Product and Provider migration jobs,
Product/Provider/Gateway runtime, and Browser action ingress. Each receives
its already preflight-validated Profile, exact deployment owner and purpose
set; the explicit `unix-workload-material.v2` constructor checks owner and
agent socket/UID/GID/directory group, binding inventory and cache policy.
The older v1/v2 paths retain their prior constructor and cannot silently
gain cross-UID v2 transport. Guest was already on the explicit v2 path;
Browser/Desktop executor roles use only the TLS signer and do not gain a
material registry.

These source changes invalidate earlier local role candidates. Focused tests
and source checks are component checks only. A clean-source rebuild, actual
cross-UID process/SQL migration, exact SQL ledger/grant readback, terminal
cleanup and the full Slice 6 release scenarios remain necessary. Phase 6
remains **5/15** until those gates pass.

### Slice 6 certificate-controller cancellation admission (2026-10-03)

The first source-bound Product migration PID1 reached PostgreSQL peer-CRL
bootstrap and exited before a confirmed connection or DDL. That observed
stage does not identify a root cause. Offline inspection found a separate,
reproducible controller flaw: certificate issuance, ordinary revocation reads,
peer-CRL reads, revocation writes, ledger reaping and quiesce all used one
mutex, held across external PKI operations. A request canceled while waiting
for that mutex could still consume a replay nonce and invoke its authority
after admission. A controlled blocked-issuer test reproduced a canceled CRL
returning success with a fake authority that ignores cancellation. It does not
establish that production Vault behaved that way or that this caused the
observed migration failure.

The approved correction replaces that mutex with one context-aware,
single-slot permit. It retains the prior serialized replay persistence,
authority I/O, issuance/revocation ledger mutation, response signing and
quiesce ordering; it does not create parallel PKI operations, a queue worker,
cache, retry, or wider timeout. Request admission is bounded by its caller
context and a locally parseable, in-range claimed request deadline; exact signature,
peer and current-time validation still occur after admission. Cancellation
before transaction admission cannot consume a nonce, persist a ledger change
or call the authority. Cancellation after a nonce is persisted or an external
mutation begins is not rollback authorization: the existing replay and
compensation rules remain in force, and no automatic replay is introduced.

`BeginQuiesce` receives the existing operation/lifecycle context; server
reaping and handlers receive a context canceled by server stop as well as
caller stop. The production command stops and waits for all listeners,
handlers and reapers before clearing the controller's signing key and policy
map. Quiesce success remains the persisted receipt; failed persistence stays
sticky and fail-closed for issuance while valid revocation and CRL reads
remain available. The permit channel is not closed on shutdown. Reversal, if
needed, is a normal source commit reverting this admission correction, not a
ledger, wire-protocol or Profile schema rewrite.

This is a safety/cancellation repair, not a throughput optimization or proof
that the 2-second PostgreSQL peer-CRL bootstrap budget is adequate under the
full process graph. Source-bound builds, race/shuffle and vet, Contract lock,
real same-run gate, exact cleanup, and its strict evidence manifest remain
separate acceptance requirements. Phase 6 remains **5/15**.

## Slice 6 Product migration peer-CRL hot-path correction (2026-10-03)

The R10 real Product migration stopped at first peer-CRL bootstrap before any
confirmed SQL DDL. A no-new-issuer sample under the reviewed 50m TLS-agent
quota found that repeating full final-Profile/source validation in each
agent/controller source lookup could exceed the guard's two-second pull bound.
This is a component cost observation, not proof of the deleted run's cause.

Each agent and controller now privately copies the exact canonical Profile and
complete peer-source document, fully validates them once at construction, and
compiles a finite lookup for profile/mapping digest, edge, local principal,
direction, anchor, issuer digest and PostgreSQL owner. The controller derives
the owner independently from a copied, validated signer policy; ordinary
policies cannot read a PostgreSQL logical peer and a PostgreSQL-purpose policy
cannot read ordinary or another owner's peer. The index retains only opaque
source IDs and scalar bindings, not Vault coordinates or CRL evidence. The
existing mutable-document API continues full validation per call. Any new
Profile/source revision requires a new constructor and the existing restart
and source-reopen gates. Request signature, nonce, Unix peer, deadline, policy
purpose, CRL issuer/signature/number/time/freshness and every fail-closed
drain rule remain per request; no CRL cache or timeout increase is admitted.

First-pull failure diagnostics are local-only, closed classes. Parent
cancellation/deadline takes precedence over an internal deadline if both
fire; agent build, socket/peer, transport and generic error/unverifiable
response are distinct from guard binding and CRL semantic failures. An agent
error frame cannot be claimed as a controller denial. Error text remains
generic, raw causes are not unwrapped or serialized, and the one-shot
migration's exact stage/class output is accepted only by a bounded, strict
observer. This correction is not a successful release gate or a production
readiness claim. Phase 6 remains **5/15** until a new source-bound real gate
and strict evidence pass.

### Product migration first-connection failure boundary (2026-10-03)

The R11 real migration passed initial peer and own-client revocation guard
refresh but failed at its first `pgxpool.Ping`. Pool construction is lazy, so
that observation does not establish TCP, TLS, PostgreSQL authentication or
the pre-DDL `AfterConnect` SQL check. The prior generic readiness line cannot
identify which failed; no source change may retrospectively classify R11.

For the one-shot Product/Provider migration path only, the approved local
diagnostic wraps existing `BeforeConnect`, exact `DialFunc`, TLS/guard
`AfterNetConnect` and `AfterConnect` callbacks at their failure returns.
Each wrapper executes the original once and returns a private closed error
with generic text, no stored raw cause and preserved `errors.Is` sentinels.
The locked pgx v5.9.2 `Pool.Ping` implementation is expanded privately into
one `Acquire`, one `Release` and one connection `Ping`; no extra connection,
SQL query, retry or new network path is authorized. The caller's existing
60-second migration context takes priority over a pool constructor's
separate context. Typed PostgreSQL errors may only be classified as a server
rejection, not automatically as an HBA or SCRAM failure. TLS and guard
tracking failures remain a conservative combined class unless an existing
peer-CRL closed class survives wrapping. Anything not evidenced returns a
closed unknown/acquire class. The only outward projection is the migration
CLI's finite `stage=ping: class=...` line, checked by the separate bounded
E observer; Product/Provider runtime errors stay generic.

The R11 issue remains of unknown cause. Controlled, no-Vault PostgreSQL
components and this classifier's synthetic fault injection can reject a
candidate implementation error but cannot substitute for another reviewed
source-bound real gate. The same 45-second agent socket, 15-second agent
bootstrap, two-second peer pull and 60-second migration startup budgets,
Profile CPU/memory/PID limits, identities, CRL policy and SQL grants remain
unchanged. This local diagnostic can be reverted as ordinary source without
schema, wire or data migration. No new issuer run is authorized by its
implementation alone; Phase 6 remains **5/15**.

### Slice 6 Guest-only storage addendum (2026-10-03)

The formal production Guest cannot instantiate its real development service
on a read-only root filesystem or on its private configuration volume. Sandbox
approved a narrow exception to the generic no-business-volume rule above:
only `guest-runtime` receives three independently named, run-owned Docker
volumes. `/workspace` and `/var/lib/sandbox-runtime/guest-state` are writable
by its unique Guest UID:GID with mode 0700 and retain the same exact volume
identity across Guest process/container restart. `/inputs` is a separately
prepared, Guest-owned 0500 volume mounted read-only with a closed, non-secret
input manifest. No other role receives these volumes; paths cannot overlap
its configuration, trust, socket or other mount targets. The Profile binds
their exact paths, storage IDs, direction and logical candidate sizes of
3 GiB, 1 MiB and 1 MiB. A canonical run/storage receipt is checked before
Guest starts; Docker name and label are checked before container creation so
that Docker cannot silently create a missing volume. The one-shot preparation
writer has no network, exits before Guest, and owns no runtime authority.
The persistent state directory admits only its run/storage receipt and the
two existing bounded materialization documents. Each document is read through
a no-symlink descriptor with a size bound before allocation or JSON decoding;
regular-file type, Guest ownership and mode 0600 are required. An unknown
entry, oversized/corrupt document or crash-leftover atomic temporary file
fails startup and is retained for diagnosis, never silently reset to empty.
Successful commit, rollback and restart preserve the run/storage receipt.

`/outputs` and `/tmp` are separate 8 MiB tmpfs mounts, mode 0700, Guest-owned,
`noexec,nosuid,nodev`; their combined 16 MiB is inside the existing 128 MiB
Guest memory cgroup, not additional memory. The selected image's `/bin/sh`
must resolve to its root-owned regular BusyBox executable, mode 0755, with
the declared actual-file SHA-256 verified at Guest startup. A rebuilt
candidate must re-observe those bytes rather than inherit the old image's
digest. No private configuration path may substitute for business storage.

Docker local named volumes provide **no hard per-volume quota**. `MaxBytes`
here is an admission estimate and Profile intent, not hostile-Guest disk
isolation or proof of full Development capacity. Normal old-plus-staged
materialization can approach 2 GiB; the remaining nominal 1 GiB cannot be
called a proven filesystem-metadata ceiling because implicit parent
directories may exceed the explicit 10,000-entry manifest count. Deep-path,
inode, allocated-block, hard-quota and complete business-storage evidence
remain Slice 8 obligations. Until the existing 10 GiB topology growth
estimate is decomposed, the three Guest candidate budgets are added as
3 GiB + 2 MiB to both host and Docker admission/monitoring, without assuming
that the old estimate already includes them. Writers stop before cleanup on
low headroom. A no-secret Docker mount probe is component evidence only;
it does not establish Guest PID1, Product–Guest authentication, the 16-scenario
gate, an immutable evidence manifest or production readiness. Phase 6 remains
**5/15**.

The local gate may seed one initial Product-owned Guest binding only through a
separately digest-bound, finite, build-tag-only fixture process before formal
Product PID1 occupies its PostgreSQL source endpoint. The fixture borrows the
existing `product-runtime` UID:GID, fixed IP, runtime SQL role, material-agent
socket, PostgreSQL TLS signer, read-only Profile/peer-CRL/trust inputs and
strict v3 PostgreSQL connection path **sequentially**, never concurrently
with Product. It must use the real Product Store and GuestService to create
and read back the run-owned Workspace/binding/event/audit. A narrowly scoped
ready-slot seed may update only the exact run-owned tenant/workspace/slot and
expected generation with one-row CAS and readback; it is not Provider
provisioning evidence. The Guest public key must be the one corresponding to
the actual run-owned Vault Guest signing key; that private key never enters
the fixture. The fixture exits, closes its pool/guards/material registry and
releases its endpoint before formal Product starts. It has no migration/admin
SQL power, public test route, extra HBA source, new persistent volume or
production command. Failure forbids Product startup and enters independent
cleanup. This exception proves at most initial durable provisioning, not live
binding revocation while Product and Guest are running; that later mutation
path requires separate review. Removing the build-tag-only fixture/task and
discarding the run-owned database rolls back this local-gate exception without
an online schema or permission change.

For the separate **live revocation observation only**, Sandbox approved one
additional source/binary-digest-bound, build-tag-only, finite local-gate task.
It may share the **exact running Product container's network namespace** with
`--network=container:<same-run-Product-ID>` while Product and Guest retain
their original PID1 and start time **at admission**. After a denied reconnect,
the Guest may terminate; the gate must verify its exact
same-run container, original start time, no restart/OOM and expected exit
code without claiming that the exit cause was authorization denial, instead
of requiring it to remain running. It does not share PID, mount or IPC
namespaces, expose a listener/port, gain a Docker socket or host network, or
join another bridge as an endpoint. The task runs under Product's UID:GID,
read-only root, drop-ALL, no-new-privileges, the locked seccomp and a bounded
resource budget included in aggregate concurrent capacity admission. It
mounts only the Product runtime material and PostgreSQL signer sockets,
necessary read-only Profile/config/peer-CRL/trust inputs and its approved
executable; no public TLS signer, Guest signing key, Vault token, admin DSN
or migration authority is available. This is an explicit temporary trusted
gate-orchestrator exception to namespace independence, not a new production
principal or a general `container:` network allowance.

The task accepts only one run/Profile/artifact/target/initial-receipt-bound
revoke operation. It first reads back the exact real, unexpired, connected
binding and nonempty nonce. Its private PostgreSQL pool has exactly one
connection, despite Product's unchanged four-connection pool and the shared
SQL role's `CONNECTION LIMIT 4`. Admission counts all same-role sessions,
including idle ones, and requires spare capacity. Each helper backend PID is
tracked; replacement fails closed. The helper emits a bounded admission
receipt while holding that connection and waits for a one-shot run-bound
continuation. Before releasing it, the gate must observe a distinct Product
SQL connection and Product's independent authenticated TLS readiness; failure
closes the helper without mutation. It then calls the existing Product Store's
`RevokeGuest` for that tenant and Guest ID. It cannot issue arbitrary SQL
updates or target other tenants, IDs or generations. An unknown write result
requires readback classification, never a blind retry. Independent readback
must prove only that row became `revoked` with a null nonce, with unchanged
scope, and no replay resurrection. The gate must observe an already
authenticated Product–Guest challenge/welcome/connected session, measure
revocation-to-close conservatively while both real processes and their
dependencies remain healthy and the binding is unexpired, then reject old
binding reconnect. The fixture must close its pool/guards/material registry,
release its temporary process and leave no new bridge endpoint or SQL
connection; cleanup must not disconnect or delete Product. A stopped Product,
natural expiry or unrelated network fault cannot substitute for this gate.

The live negative observation must parse an actual bounded Guest `/readyz`
HTTP 503 (204 is ready) or independently inspect the exact Guest container's
post-mutation exit1; an arbitrary `docker exec`, timeout or network error is not
revocation evidence. An exited Guest is not by itself proof that the old
binding's reconnect authentication was denied; its cause remains unproven.
The component auth test
must deterministically witness a denied reconnect and `ErrUnauthorized`
termination; the real process gate still needs an attributable protocol or
equivalent redacted witness before it may claim the full reconnect scenario.
Continuous host/Docker capacity sampling starts before run-owned writers;
sampling loss or low headroom cancels and stops exact run-labeled writer
containers before zero-resource cleanup. These checks are preconditions, not
release evidence.
The emergency stop must not abandon later writers when an earlier enumerated
container is removed concurrently by a nested runner. Exact same-ID Docker
absence counts as already stopped; ambiguous inspection or target-specific
stop failures are retained while the loop attempts every other verified
same-run target. Bounded re-enumeration and a final no-active-writer readback
run before exact cleanup. Once the main runner has unwound, a final sweep uses
the remainder of the original 90-second stop budget as a lifecycle barrier:
no new writer may start after that point. A foreign run label is never a stop
target. This is a safety interlock, not a release-scenario result.

`Store.RevokeGuest` does not currently persist the reason or create a
`security_audit`/`workspace_event` row. This local-gate task therefore records
only private, run/source-bound test metadata and **does not establish
production Guest revocation audit**. The authenticated formal business
mutation entry point, generation/CAS/idempotency policy and transactional
audit remain Slice 8 obligations and a later full-product release gate. Both
tag-only tasks can be removed and their run-owned database discarded without
changing a production API, schema, network or HBA rule. Neither task alone
authorizes a Vault issuer run or advances Phase 6 beyond **5/15**.

### Slice 6 Guest v3 recording-authority and readiness correction (2026-10-04)

The outbound Guest v3 production role does not own a recording key. Its sole
accepted `recording_key_reference` is the exact role-config constant
`urn:sandbox-runtime:guest:no-recording`. This marker is not a secret URI and
must never be parsed or resolved as a `file://`, `secret://` or `kms://` key.
Startup configuration validation and live process readiness use the same
closed validator: empty or variant markers, arbitrary URNs, and fake key
references fail for Guest v3; the marker fails for every other role, schema
or deployment level. Older valid secret references retain their existing
behavior. Guest still requires its independent signing key, TLS signer,
peer-CRL, material and authenticated Product connection. Product/Gateway
recording ownership and fail-closed requirements in ADR 0046 are unchanged.

The real Guest PID1 gate now accepts readiness only from the existing bounded
HTTP probe's explicit 204; parsed 503 is negative, and command failure is
unavailable, not a successful body read. One fixed 45-second child deadline
starts before the first inspect/exec and bounds every sample. The retained
error is limited to redacted last status and sample count; exact stopped
container state is distinguished from an unavailable inspect. This is a
source-level correction, not proof of a live connected Guest or revocation.
It changes runtime code as well as gate code: old R4 role images cannot be
reused as the fixed runtime. Under the current strict C=R admission rule,
the next reviewed runtime revision requires a clean freeze and all local
role/Desktop candidates rebuilt from that source, independently reverified
with unchanged external Browser publication and unchanged selected external
OCI inputs. E-only observer and independent fixture deltas must be rechecked
against the new R; no cross-source exception is inferred. Candidate building
and another real Vault issuer attempt require separate Sandbox review.

### Slice 6 independent same-revision Guest fixture source pairing (2026-10-04)

Sandbox reviewed a source-pairing exception for the new clean R candidate:
the finite, build-tag-only Guest fixture may be built from a **different clean
checkout at the exact same R commit and tree**. The original strict-descendant
mode remains available only for a nonempty bounded diff in the existing
fixture/gate/docs allowlist. An older ancestor, unrelated history, ordinary
runtime or dependency drift, dirty tracked/untracked files, an incorrect
HEAD/tree, a non-top-level or aliased checkout, and a failed Git command are
all rejected. This is not an R/E compatibility assertion or a general
production-fixture exception.

Both fixture source files must retain the exact fixture-only build tag. With
the locked Go 1.26.8 target and cleared `GOFLAGS`, ordinary `go list` must
exclude them and tagged `go list` must include them. The actual Linux/arm64
binary is separately built with the locked flags and must match an externally
approved digest before even a no-issuer admission. This source-pair check
does not authorize Vault issuance, bypass a Gate observation, or advance
Phase 6 beyond **5/15**.

### Slice 6 Guest durable-revocation readback correction (2026-10-04)

One separately authorized real-issuer diagnostic reached a connected Guest
PID1, then failed the independent persisted-revocation readback. That run is
retained as **failed**; the fixture's confirmed mutation receipt and a
temporarily non-ready Guest do not substitute for the durable database check.
The readback SQL already tested the original conjunctive condition: exact
tenant and Guest row, `state=revoked`, empty connection nonce, and
`expires_at>clock_timestamp()` in PostgreSQL. Its boolean expression was
explicitly cast to text before concatenation, but the Gate compared the
result with PostgreSQL's *uncast* short boolean spelling `t`. The cast result
is `true`, so the comparison was inconsistent with its own SQL.

The E-only correction accepts exactly one canonical `revoked||true` row with
one newline. It does not relax the SQL condition, accept both spellings, trim
extra whitespace, or turn a missing/duplicate row, nonempty nonce, expired
row, command error or output overflow into success. A disposable networkless
arm64 PostgreSQL check executes the same read-only SQL and `psql` flags across
positive and negative rows. It uses the pinned upstream PostgreSQL index,
not the exact E6 selected OCI archive manifest, and is **not** evidence of a
successful live revocation. A scoped audit found the other explicit boolean
text-cast Product migration assertions compare `true`/`false` correctly;
integer text casts do not share this mismatch. A fresh real-issuer Gate needs
separate review and authorization. Phase 6 remains **5/15**.

### Slice 6 local-candidate Guest receipt observation (2026-10-04)

The E7 local issuer diagnostic established connected Guest PID1, durable
revoked-row readback and non-recovery, but not the cause of a fresh old-key
denial or the original upgraded socket's two-sided drain. Sandbox approved a
private, opt-in Product/Guest receipt to close that observability gap without
changing the Guest wire, Provider Contract, Product authorization, TLS/CRL
policy, database schema, or any production service endpoint.

The switch is `private_guest_receipt` in only the Product/Guest v3 typed
startup sections. Their existing `production` deployment level remains
unchanged; the switch defaults off and all other roles, older schemas and
disabled sections reject it. Before any receipt is emitted, each process
requires its exact FD-loaded startup document SHA-256, complete pinned
Profile, real `guest-product` boundary, and both runtime principals with
`ImageLocation=local`, `ImageReference=ImageDigest`, and the Profile's already
valid `oci_manifest` or `oci_index` shape. Runtime checks are configuration
admission, **not** provenance. E must separately verify the source-bound local
candidate archive, descriptor/config, Docker inspect, process launch and
actual attached container against the same Profile/config digests. Registry,
published, mixed-local/registry or `local_config` profiles cannot enable the
receipt. The switch is not placed in a release template.

Both endpoints derive the attempt correlation as SHA-256 of the fixed
`sandbox-runtime-phase6-guest-attempt-v1` domain plus the existing validated
canonical `AuthRequest.SigningBytes()`. That binds challenge, client nonce,
identity, generation, protocol and sorted capabilities without emitting raw
nonces, signing bytes, signature, key, identity or address. The optional
PostgreSQL `validated_revoked` path uses the original joined, locked row in
the same transaction and checks key digest, signature, signed tuple, protocol,
generation, DB-time expiry and intersecting capability before classifying a
revoked state. Missing row, wrong signature or tuple, expired row, capability
or generation mismatch, SQL/context uncertainty and dependency loss cannot
be reclassified as a verified revoke. With the switch off, the prior
authentication query/short-circuit path remains in use.

The closed receipt protocol is `sandbox-runtime.phase6-guest-receipt.v1`.
Product events are `product_auth_accepted`, `product_welcome_written`,
`product_peer_installed`, `product_authority_stale`,
`product_close_completed` and `product_validated_revoked`; Guest events are
`guest_hello_written`, `guest_welcome_accepted` and
`guest_read_terminated`. `begin` and `seal` delimit each role's stream.
`product_close_completed` is emitted only after the first actual `CloseNow`
returns successfully; Guest termination is emitted only after its read loop
and transport close return. `authority_stale` is not itself a revocation
claim. E must match an installed original attempt, its Product close result,
its Guest-side termination, and a distinct fresh signed revoked attempt;
one 503, exit 1, closed `done` channel or close intent is insufficient.

Only a Linux, non-TTY FIFO stdout can carry the optional stream. A single
writer reopens the exact already-open stdout FIFO through `/proc/self/fd`,
requires the same device/inode, a separately nonblocking open-file
description, unchanged original blocking flags and `CLOEXEC`; it does not
use `dup`, Docker access or another runtime mount. The callback performs only
a bounded local enqueue. Limits are 256 events, 64 queued records, 512 bytes
per line, 128 KiB total and 250 ms per nonblocking line write. The caller's
existing shutdown budget provides at most two seconds to seal/join; cancellation
actively stops and joins the writer. Overflow, invalid event, write error,
missing/truncated seal, nonzero dropped count, sequence/count mismatch,
unknown/duplicate/noncanonical JSON, wrong role/profile/config digest or
illegal per-attempt transition makes the evidence unavailable. E captures
stdout only into a 0700 private directory and 0600 file with Docker
`log-driver=none`, not shared logs. Sequence and elapsed time order events
within one process only; E uses its actual mutation/capture boundaries for
cross-process order. Failure to observe never grants authorization or changes
Guest reconnect policy. Other platforms or unsupported stdout fail the
opt-in startup closed. Removing the switch/emitter/collector is a bounded
rollback with no migration.

The actual non-TTY pinned arm64 container probe now passes healthy sealed
output and a deliberately unread attached-output stress case that confirms
the writer reports invalid completion and joins before the attach is released.
Pure Linux tests also check unchanged original flags, `CLOEXEC` across a real
child exec, exact fd closure, overflow, cancellation and blocked-pipe join.
These are carrier/component checks only. The original E7 result, R884/F884
artifacts and the 16-scenario issuer/release gate remain unchanged and
unpassed; Phase 6 stays **5/15**.

### Slice 6 Guest receipt producer join and persistent E evidence correction (2026-10-04)

Sandbox review rejected the first R checkpoint as a candidate for another
issuer run. A `seal` written while a hijacked Product Hub handler, authority
monitor, revocation-authentication callback or Guest Agent lifecycle remained
active could be followed by a dropped in-memory event invisible to the
external verifier. Product's transport shutdown alone did not join those
producers. The optional observation path now tracks actual Hub handlers,
monitor goroutines and explicit disconnects, denies new entries during
quiescence and joins them before Product seals. Guest joins its actual
`Agent.Run` graph before sealing. Both use the inherited 30-second shutdown
context with at most two seconds for the writer; cancellation, producer-join
failure or writer failure aborts without a complete seal. The default-off
paths retain their prior lifecycle behavior. An aborted stream is never
evidence even if earlier records reached stdout.

The E-only attached collector must observe the exact Guest container enter
`State.Running` with a positive PID1 before dependent readiness checks; this
wait consumes the existing 45-second readiness budget. `created`, early exit,
OOM, daemon/inspect error and attach loss do not become negative readiness
polls or successful evidence.

The approved E-only private component-evidence root is supplied explicitly
through `SANDBOX_RUNTIME_PHASE6_SLICE6_RUN_EVIDENCE_ROOT` when the receipt
switch is on. Before issuer allocation it must already be an absolute,
canonical, symlink-free, current-owner 0700 directory. E creates one
exclusive random-run-ID 0700 child and fixed 0600 Product/Guest PID1 raw
stdout files; no fallback directory, runtime mount, socket, endpoint or
formal evidence-manifest field is added. FD-relative no-follow operations
recheck root/run/file inode, owner and mode; writes and directory entries are
synced, bounded and independently reopened. Captures remain under the
operator-owned root after the test, including failed runs. Missing or
tampered bytes, replacement, overflow, interrupted attach, wrong exit/OOM,
write/sync failure or incomplete shutdown cannot publish an accepted binding.
A failed run retains an `incomplete.json` marker; any such extra file makes
the read-only complete verifier reject that run.

Only after both actual Docker stdout streams and the trusted fixture mutation
have been independently verified may E write its bounded canonical mutation
receipt and final component binding. The binding records distinct E/R/F
revisions and source-tree digests, the verified local candidate archive,
selected OCI manifest/config/image identity, run/Profile/startup-config
digests, exact Docker container/image/exit identities, raw byte counts and
SHA-256, and capture/fixture-verification UTC boundaries. An independent
read-only pass reopens exactly those four files, rejects extra/incomplete
files, checks canonical bytes, hashes, two closed receipt streams and their
same-attempt causal join. The fixture verification time is a trusted E
boundary, **not** a cross-process clock or database commit timestamp. No
credentials, nonce values, signatures, raw endpoints or daemon diagnostics
are retained. This is still partial component evidence; the formal closed
Slice 6 one-run recorder and final scenarios remain separate.

The clean `72ffa6d` R/F candidate rebuilds made before this review are
preserved as unaccepted diagnostic artifacts. No new issuer run is authorized
by these corrections; R/E must be committed, rebuilt from clean sources and
reviewed again first. Phase 6 remains **5/15**.

### Slice 6 E-only binding publication correction (2026-10-04)

The follow-up E observer gives the exact Guest PID1-running check, running-
network inspect and first connected readiness check one absolute 45-second
deadline. Its long-lived attached stdout capture remains on the lifecycle
context; a blocked network inspect cannot silently extend readiness.

The E-owned private evidence binding is first written as a fixed 0600
`binding.pending` in its exclusively created 0700 run directory. File and
directory sync plus exact readback precede no-replace publication to
`binding.json`; the new directory entry is synced, the pending name is
removed, and the directory is synced again before independent verification.
On failure, E rolls back only its own inode-checked pending/final entries and
keeps the raw captures, mutation receipt and best-effort incomplete marker.
An unlink, directory-sync or marker failure is reported as publication or
persistence uncertainty; it is never translated into successful evidence or
an assertion that no bytes can remain under a storage fault. The trusted
gate fails closed. The mutation digest covers the **exact on-disk bytes**,
including the trailing newline. The independent verifier also compares the
externally supplied Product/Guest candidate manifest, archive, selected OCI
manifest, config and actual image/container identities, not merely their
shapes or values repeated from the binding. These are E-only component-
evidence corrections, not a change to the formal Slice 6 manifest or an
issuer-run authorization. Phase 6 remains **5/15**.

### Slice 6 live temporary directory source-clean boundary (2026-10-04)

The receipt's final E/R/F clean-source check must remain strict while live
observer, fixture and Vault files still exist. Actual Gate-reachable private
temporary directories therefore reside as owner-only 0700 siblings of the
Docker-shared source checkouts, not inside any E/R/F source root or the
four-file receipt run directory. The build working directories and immutable
source revisions do not change. The selected sibling path must be canonical,
outside every configured source root and usable for the existing read-only,
non-root Docker bind. Missing or unshared siblings fail before issuer
allocation; there is no fallback into a checkout. Cleanup is bounded,
directory-FD-relative and no-follow, verifies the originally created inode
and refuses a replacement. An interrupted or uncertain cleanup fails the
Gate and is not evidence of zero residual bytes. Separate opt-in component
tests not reachable from this Gate are outside this correction. This is an
E-only observation-path change, not a change to Provider authority or the
formal release manifest. Phase 6 remains **5/15**.

### Slice 6 A′ operator-only PostgreSQL recovery readback (2026-10-04)

Sandbox authorized a narrow E/operator observation of the existing, same-run
PostgreSQL server for the Guest loss/recovery component. It is not a new
runtime role, network edge, credential, source of session authority or tenth
SQL witness. The observer uses PostgreSQL's existing local `postgres` peer
account through `docker exec` into the exact run-owned container; this is a
trusted operator-superuser read, **not** proof of a least-privilege SQL role.
No HBA, grant, database state, socket, mount or network configuration may be
changed to enable it.

Before and after a read, E must bind the exact run label, PostgreSQL container
ID, selected image and UID/GID, running PID/start time, approved network and
mounted config/data volumes. The formal E path must also recheck the
source-derived nine-network inventory and mounted HBA, not merely a nonempty
network map. The fixed query targets only one run-owned tenant, workspace,
slot, fixed slot profile, slot generation, Guest ID and binding generation in
the Product database. `psql -X -w` executes `BEGIN READ ONLY` with a
three-second statement limit under a five-second outer limit, one operator
session at a time. Its bounded output contains only state, whether the nonce
is null, DB-time expiry
status and expiry time; duplicate, missing, expired, malformed or unbounded
rows fail. A second fixed read-only query must confirm the named first backend
has exited. Each operation uses a distinct bounded run-bound application
name; a Docker/SQL error with uncertain exit stops later observations for
that run instead of opening a cleanup query or silently retrying. This
component now uses individual Docker exec IDs and checks each actual
`Running=false`/exit-code-zero result before advancing to the next fixed SQL;
an unconfirmed result poisons that run's E observer. The helper's own
identity, SQL and output digests belong only in private E evidence.
Source/target or process drift makes the observation incomplete, never a
successful fallback.
The bounded raw stdout from both fixed SQL executions and their individual
exec IDs/times can now be written once to fixed stage-specific 0600 files
inside the 0700 v2 E run, then independently reopened and hashed. A duplicate
stage, byte tamper, cross-stage target/expiry drift or exec/operation replay
fails. The final same-run merger and real source-bound nine-network positive still
remain open; a private raw file alone is not an accepted binding.

This readback can corroborate a Product receipt and actual transport closes;
it cannot alone prove the old-nonce `released` CAS or a Guest reconnect cause.
The current no-issuer Docker drill proves the local peer query, bounded
parser, backend exit and missing/duplicate/expired denial against a disposable
PostgreSQL process. A separate formal-only source constructor now requires
the selected Profile image and all nine exact isolated Docker networks with
PostgreSQL endpoint IDs/IPs and run labels. Bounded A′ has a closed
stage-membership table: Product runtime is started, Product migration has
successfully exited with its original ID and exact ledger, then its original
container is removed, and the other
seven PostgreSQL dialers have not started. The nine networks and HBA rules
remain fixed; an exited or not-started dialer must be absent from its bridge.
The full 78-deployment release gate has a separate complete-stage inventory.
Each present dialer additionally needs its source-derived IP and exact
run/role/image/lifecycle identity, the source-rendered mounted HBA, final
PostgreSQL PID1 and effective TLS/HBA settings. Its readback entry point also
requires a source proof, unchanged process/HBA fingerprint,
effective-settings/postmaster recheck and explicit initial-connected,
released, reconnected or final-released state with original expiry. The disposable
`network=none` component path cannot construct this proof. The formal path
has not yet been exercised against the complete nine-network Product/Guest
deployment or bound to the E recovery sequence, so neither constructor nor
component tests are a Slice 6 scenario receipt. The later
Slice 11/14 independent environment still requires its own deployment and
least-privilege review. No real issuer or accepted E/R/F binding follows from
this component drill; Phase 6 remains **5/15**.

### Slice 6 A′ bounded E reconnect-isolation window (2026-10-04)

The Guest Agent automatically reconnects after PostgreSQL recovery, so E
cannot assume it will sample a transient `disconnected`/null-nonce row before
the next accepted signed connection. Sandbox permits one explicit,
run-recorded E observation window: after the original Product/Guest streams
have both shown PostgreSQL-loss close and while Product's PostgreSQL edge is
still down, detach only Guest-A's existing run-owned Guest–Product network
edge. Keep Product-A, Guest-A, PostgreSQL, their other networks and the
retirement worker alive. Restore Product's original PostgreSQL edge and
read back the real released/null state within the inherited budget, then
reattach Guest-A to its original network ID and IP and observe its own fresh
signed reconnect and connected/non-null row. All detach/reattach actions,
identities and completion order must be in E evidence. Failure to detach,
restore or read within the original budget is incomplete, not a reason to
poll indefinitely, clear a nonce manually or rebuild a binding.

This is evidence of recovery **with an explicitly intervening E network
isolation window**, not uninterrupted natural reconnect. A later ordered
Product/Guest replacement requires a separate final old-nonce release and
zero-drop process seal; the intermediate null snapshot cannot be reused.
The isolation state machine and a source-bound real gate have not yet been
implemented or accepted. Phase 6 remains **5/15**.

The E-only network action now has a no-issuer Docker component drill: it
verifies two unchanged live PID1 identities, exact run-owned isolated
Guest–Product and Guest-runtime networks, a sole Guest detach, and an
original-IP reattach. It rejects wrong/duplicate actions and cleans the
run-labeled resources. The causal close prerequisite and full recovery
state machine remain unimplemented, so this does not amend the preceding
release boundary.

The E action registers the exact target before either Docker network command.
A lost disconnect response or first post-mutation inspect failure is classified
within one non-renewable cleanup deadline, capped at five seconds and by the
caller's remaining absolute deadline. Nested restore and post-restore inspect
inherit this same deadline. A proved detach is
restored only to its original IP and never counted as successful fault evidence.
A lost restore response can count as cleanup only after the exact original
edge is reread; any unclassifiable graph remains incomplete and requires
exact run-owned stop/cleanup. Disposable real Docker fault-injection drills
pass for both Guest–Product and Product–PostgreSQL edges. These drills do not
prove the real Product/Guest recovery sequence.

The attached E collector also has a bounded live v2-prefix trigger: a
complete canonical Product dependency-loss close and matching Guest read
termination for the original attempt are necessary before the edge action.
Its file snapshot is inode-checked under the bounded writer lock, and a
partial Docker chunk is pending rather than truncated into proof. A real
two-PID1 no-issuer drill verifies this mechanism. The trigger is explicitly
not a seal or release receipt; final acceptance must reread both complete
streams and join the actual PostgreSQL fault and network action in one run.
An E-only sealed-prefix checker now binds the live trigger's exact byte counts
and hashes to the beginning of final independently reread, zero-drop v2 PID1
files. The precleanup E merger reopens 23 bounded same-run source classes,
four SQL stages, a private E event journal and four sealed PID1 files. It
rechecks the frozen migration ledger and common core image with distinct role
configs, joins Product/PG PID and retained network facts back to source raw,
and requires the final old-nonce SQL NULL observation after both A seals and
before either B start. Synthetic journal sequence/monotonic-elapsed/reference
replay and paired identity-drift negatives pass; eight derived action
projections plus 32 whitelisted original Docker process/network/identity raws
are now private, bounded and independently replayed. No-issuer real Docker drills
exercise call/observed wiring at the network actions, SQL call before exec,
B start-call/observed with bounded live-start raw, and Guest-A
stop/exit/seal. A recovered-close observation is now required before the
normal Product-A stop: its private receipt binds the still-live Product v2
prefix, sealed Guest raw, recovered attempt/generation and both process
identities; a missing observation refuses normal stop. The exact prefix
must replay inside the final sealed Product original. The E journal now has
29 monotonic events. A pre-B guard and private admission digest require A seal,
all four SQL stages, original action replay and the first 25 monotonic events
before either B start, but no formal launcher invokes them yet. The complete
real E orchestration remains open. A real no-issuer Docker component proves
original Guest network IDs and Vault/anonymous-volume identities and their
post-cleanup absence; the private Docker-zero/exact-origin receipts are not terminal
proof of non-Docker resource classes. No real same-run E run, final cleanup
binding, E/R/F freeze or authorized issuer run has been accepted; Phase 6
remains **5/15**.

### Slice 6 terminal-zero private response evidence v3 (2026-10-04)

Sandbox ruled that a terminal summary receipt alone cannot independently
replay Vault cleanup after the operator has revoked its own token. The explicit
private terminal input v3 therefore wraps the **unchanged exact v2 plan**:
three certificate targets (including the external PostgreSQL server leaf),
two accessor targets, and the v2 receipt. There is no v2-to-v3 inference or
automatic downgrade. The one-shot operator captures only fixed projections
of its already-required authenticated Vault HTTP exchanges. It retains the
issuer DER and complete signed CRL DER, token lookup metadata or the exact
invalid-accessor error, certificate revocation state and timestamp, CRL
configuration, and empty-body 204 outcomes. It never copies a bearer token,
private key, raw accessor or whole Vault JSON response into the output.

The v3 operator emits one canonical, closed, bounded private line on its
existing restricted stdout. The host separates that output from bounded,
fixed-stage stderr, then stores it under the existing 0700 run directory as
0600 create-only files with inode checks. The binding also records the exact
operator process start/finish bracket and rejects a CRL-check timestamp
outside that bracket (with only five seconds of clock tolerance). No new
writable mount, sidecar,
probe, token or Vault request is introduced. The offline verifier replays the
exact event sequence against the v2 plan and receipt, checks both issuer
reads, validates the signed complete CRL and all three revoked serials, and
requires exact token absence and self-revoke observations. A projection or
stdout failure leaves the E run incomplete but does not prematurely stop
remote cleanup. Historical replay validates against the recorded CRL-check
time rather than incorrectly demanding that a short-lived leaf remain valid
at a later audit date.

The current implementation and synthetic response/negative tests are
component evidence only. The optional v3 terminal runner checks the exact
source-bound binary capability **before** any new issuer/signing step and can
persist a diagnostic binding, but the prior clean source binary does not yet
carry v3. No authorized new issuer run, real v3 Vault terminal observation,
formal E precleanup-to-terminal binding, same-run E/R/F gate or release
manifest has been accepted. A diagnostic binding with an empty precleanup
digest is explicitly ineligible for formal E replay. Phase 6 remains
**5/15**.

The formal sink constructor must first replay the sealed, same-run E
precleanup chain and cannot accept an operator-supplied digest. A separate
terminal-zero preflight reopens its v3 plan/stdout/binding and joins the
operator identity to exact Docker-zero and original network/Vault absence,
including process-exit ordering. It is intentionally not a release
disposition: the real E launcher and remaining non-Docker terminal classes
are still open.

Sandbox also ruled not to create a separate disposable Vault issuer merely
for v3 collector validation before source freeze. The first real v3 response
test belongs in the one planned source-bound formal run, after its complete
preflight and explicit issuer authorization. A response mismatch leaves that
run incomplete, preserves only bounded private failure evidence and invokes
the existing cleanup; it does not trigger automatic reissuance.

For formal E, the existing nested Product/Guest component runners remain
diagnostics, not authority-bearing wrappers. An E-only owner must use the
shared, reviewed create/config primitives with typed A/B process handles,
capture the first network allocator's original IDs before any join, and own
the entire source, 29-event fault/recovery, pre-B admission, replacement,
normal shutdown and exact cleanup sequence. B shutdown is outside the fixed
29-event journal; its zero-drop v2 seal and exact ID removal are nevertheless
required before terminal cleanup. No issuer is permitted merely to exercise
these orchestration primitives before the formal source freeze.

The shared bootstrap receives a typed run-scoped network source. Legacy
bootstrap keeps strict create-and-reject-existing semantics. Formal E first
allocates the closed full network inventory, then resolves only those original
IDs against frozen specs and live Docker identity; it cannot create an
alternative or use a same-named replacement. At each stage the existing
membership readback remains independent of the original empty allocation
observation. This network injection does not copy the Vault/Controller/PKI
bootstrap or change its token and root-revocation ownership.
The post-bootstrap E procedure must own one explicit A→fault/recovery→
pre-B→B lifecycle. It learns attempt digests only from both canonical live
v2 PID1 streams, records PG/network mutation calls and observations at their
actual sites, checks the fixed 29-event kind/count boundary after each
operation, and requires the 25-event sealed predecessor before creating B.
Product/Guest B normal shutdown and exact removal are outside that journal
but inside the same precleanup proof. A component callback or synthetic
prefix cannot replace the final four-stream replay.

The E-only opt-in top-level entry now uses that shared bootstrap. It checks
source-bound v3 operator capability and capacity before its one-time complete
network allocation, reuses original IDs for Vault/Controller/PostgreSQL and
agent joins, then runs typed Product/Guest A/B under the live signer window.
It joins a successfully replayed precleanup to a one-shot formal v3 terminal
call and then to Docker-zero and original-ID absence preflight. If business
precleanup fails, the same finite authority may be used once for v3
cleanup-only revocation; its private marker is incomplete and cannot enter
formal E replay. No silent v2 downgrade is permitted. The E environment
arming flag is only an operating guard, not issuer approval.

Sandbox's terminal-scope ruling distinguishes run-owned temporary sibling
directories, actual PID1/attach writer joins, private Unix sockets and
credential leases from intentionally retained evidence, clean E/R/F source
checkouts and frozen candidate artifacts. Existing test-end cleanup alone
cannot prove pre-binding host-file absence. The final E-only owner must
explicitly finish exact inode-pinned temporary resources and independently
recheck absence, close/sync retained evidence writers, replay the bounded
v3/ledger and Docker chain, and bind the external frozen expected identities
in a versioned private component verifier. Sticky Controller credential-
revoke faults remain separately open. No new issuer run is authorized until
that frozen package is reviewed. The connected top-level E entry has not
run; its current terminal preflight remains fail-closed and Phase 6 stays
**5/15**.

The current E candidate registers the seven reviewed host-private sibling
directories with one run owner. After exact Docker cleanup it can explicitly
finish FD-relative, no-follow, inode-pinned removal, include FD-close/sync
errors, and retain a bounded private receipt of the original names and
inode identities for independent absence replay. A replacement name is left
untouched and fails; test-end cleanup is only a fallback. This is a host-file
component checkpoint, not yet the all-class terminal binding: actual writer
joins, lease reconciliation and frozen external E/R/F expectations still
require a single read-only verifier. The E opt-in has not issued or run.
The terminal-zero preflight now requires that private sibling receipt digest
and rereads each original name's absence; a digest string alone is not proof.

The E candidate also has a versioned, pre-binding retained-file inventory.
It requires the exact 117 successful-path raw/source/SQL/process/action/
terminal/zero/private-sibling files, pins their owner-only regular-file
inodes, byte counts and SHA-256 digests, and independently reopens the private
run directory to reread the closed set. An additional file, missing file,
replacement inode, wrong externally supplied inventory digest or changed
content fails. A subsequent canonical v2 `incomplete.json` is recognized
only as retained failure evidence; inventory integrity is not an E success
disposition. The formal E entry invokes this replay after terminal-zero
preflight but still fails closed pending the remaining process/writer, lease
and E/R/F freeze bindings. No new issuer run was made for this component.

### Slice 6 E helper convergence and early process ownership (2026-10-04)

Sandbox's `S6-A1-helper-convergence-receipt-20261004` ruling permits only an
E-specific, fixed-stage convergence receipt. A helper returning without a
testing failure is insufficient. The final receipt must bind the frozen E
identity, exact run/Profile, named stage and slot, monotonic completion order,
closed result class and independently checkable proof references. Missing,
duplicate, wrong-run, causal-drift and unconsumed-attach stages fail closed;
reused helpers need distinct slots. A separate read-only verifier must reopen
the retained bytes and check the expected stage set rather than treating a
digest as historical proof that an OS process was joined.

The first narrow correction arms an exact-container failure owner immediately
after controller `docker create`, before inspect, FD envelope or readiness
checks. It cancels the attached `docker start`, stops, joins and removes that
one ID on early `Fatal`/Goexit. Break-glass tracks its initial and replacement
instances separately under one shared cleanup deadline; normal retirement
requires observed attach completion and exact removal. The ordinary TLS signer
now guards the same pre-readiness gap. A disposable, no-issuer Alpine PID1
drill exercised the controller owner with real Docker and zero labeled
residual resources. These checks do not prove the full E process inventory.

Certificate-controller `sticky_credential_revoke` is recorded as a typed
physical-convergence result, never as `clean_exit`. The finite Guest E
component may retain only that exact known sticky class if the physical
cleanup and independent v3 terminal binding both pass; it must carry an
explicit controller-drain OPEN/non-clean result. Unknown exits, missing joins
or unproved revocation still fail. A full Slice 6 controller-drain success
cannot be inferred from this limited E result. The E admission also joins the
capacity monitor before reading its cause and stop callback result, and checks
the credential controller's completed stop/drain/remove/socket/ledger sequence,
seven distinct role-bound TLS signer outcomes and three distinct exact
break-glass instances against the same run/Profile.
Fixed-stage receipt emission, all other actual PID1/writer joins, lease
reconciliation, frozen R/F/E binding, authorized real E and the release gate
remain open. Phase 6 remains **5/15**; no new issuer run is authorized by this
component correction.

### Slice 6 terminal ledger projection reuse (2026-10-04)

Under Sandbox ruling `S6-A1-reuse-terminal-ledger-capture-20261004`, the E
terminal path reuses the two already-required, bounded, read-only ledger
results passed to `BuildV2`; it does not open another observer or persist the
full certificate/credential ledgers. After `BuildV2` validates their canonical
quiesced state and exact target mapping, the same in-memory bytes yield one
closed, owner-only projection. It records the run/Profile/plan identity, both
original byte lengths and SHA-256 values, schema/revision/quiesce times and
the necessary per-record policy, digest, serial, state and time fields. Raw
replay nonce/JTI, lease IDs and backend/previous accessors are omitted; the
latter identifiers appear only as domain-separated digests. The projection
hash is bound into the existing private v3 terminal binding and the successful
E retained-file inventory now has 118 exact files. The independent verifier
checks canonical closed bytes, the projection-to-plan hashes and terminal
targets, nonterminal `revoked` states and the v3 binding. It cannot recompute
an original ledger hash after the original bytes have been cleared, and must
not claim otherwise.

Projection construction or persistence failure leaves the E component
incomplete but does not interrupt an already authorized one-shot remote
revocation. The exact sticky controller fault may remain local `active` only
for the frozen terminal targets and only with the separate complete v3 remote
CRL/accessor/self-revoke proof; it remains local non-clean/OPEN. Extra,
missing or wrongly bound actual issuance and the final E/R/F source freeze
still require the final component verifier. No issuer was run for this
projection component, and Phase 6 remains **5/15**.

The next fail-closed check rejects any credential record with either a
previous backend accessor or a nonzero previous-revoke timestamp, including
nonterminal revoked records. `BuildV2` therefore cannot plan only the current
accessor while an overlap target remains pending. The E projection replay
also compares its complete issued-record set against exactly the two
controller certificates, seven fixed E signer launch roles, one controller
PKI token and three E material-agent roles derived from the frozen Profile;
optional Profile roles are not silently counted as launched. This comparison
runs before remote revocation without suppressing that cleanup on component
failure, and again at terminal-zero replay. It is a component guard, not a
substitute for the still-missing fixed-stage OS-process/writer receipt or
formal E/R/F admission.

Sandbox froze the E helper scope in
`S6-A1-fixed-convergence-stage-set-20261004`: exactly 14 logical slots
(seven ordinary TLS signers; credential controller, certificate controller
and three-instance break-glass controller; three material agents; one joined
capacity monitor). The E-only closed receipt records exact run/Profile and
source/terminal identities, stage/slot, observed return order, typed result,
container IDs and outcome digest, then binds the existing precleanup, v3,
Docker exact-zero and private-sibling evidence by digest. Three material
outcomes are emitted only after their existing stop/drain/remove/socket guard
completes; the migration agent records natural exit, not a fabricated TERM.
The successful E file inventory consequently grows from 118 to 119 files.
An independent read-only opener checks the retained receipt bytes and fixed
slot set. This is source-bound control-flow evidence, not historical OS proof
from a digest alone. Existing Product/Guest writer, SQL/action, migration,
fixture, PG stop and terminal evidence remain separate referenced inputs;
there are no new slots for their synchronous probes or file writes. Sticky
certificate credential-revoke remains typed non-clean and full controller
drain remains OPEN. No issuer was run for this receipt component.

The candidate final E binding keeps E (executing checkout), R (runtime image
and terminal binary source) and F (fixture source) revisions and trees
separate. Its independent verifier requires the exact 119-file inventory,
the convergence receipt and the existing terminal v3/plan/projection replay;
an `incomplete.json` next to a final-looking file is never accepted. The
publisher is implemented as a synced pending file followed by exact-inode
publication and failure rollback, but the live E test still deliberately
stops before invoking it. No successful E or issuer result is inferred until
the frozen E/R/F identities and actual run receive separate review.

The subsequent `S6-A1-final-publisher-review-20261004` ruling required three
more closed boundaries before selecting a real run. E now freezes the clean
E/R/F revisions and source trees before issuer allocation and compares the
same identities after terminal-zero. One pure digest helper is used both by
the original terminal-zero preflight and by the final read-only verifier; it
binds precleanup, v3, Docker zero, exact original-resource zero and private
sibling zero without relabeling R as E. The publisher's success return is
delayed until its run and root directory descriptors have both closed and a
fresh independent verifier has reopened the retained run. A late close or
reopen failure rolls back only the original final-binding inode, writes an
incomplete marker where possible and returns failure or explicit uncertainty;
unknown/replacement inodes are never removed. The independent read checks
the exact publisher-selected final inode as well as canonical bytes and the
119-file inventory.

A no-issuer fixture exercises the positive path with a locally generated,
offline-verified v2 plan, complete v3 private response/CRL, sanitized ledger
projection and fixed 14-slot convergence receipt. Negative cases cover link
and no-replace race, post-link sync, pending unlink, independent reopen,
replacement inode, rollback unlink/sync uncertainty, late run/root close and
post-close reopen. The live E path now calls the bounded final publisher,
but neither these fixtures nor this code change constitute a new Vault issuer
observation, full controller-drain pass, 16-scenario gate or release result.
The E/R/F and issuer command package still requires separate Sandbox review
before any new issuer-consuming run; Phase 6 remains **5/15**.

Sandbox ruling `S6-E-mode-guard-20261005` corrected a deterministic
formal-E/legacy-receipt contradiction discovered while preparing that command.
The formal E path requires the private receipt and Product/Guest runtimes but
must not enable the old component live-revoke callback; the legacy receipt
path continues to require all three. One pure guard is invoked in formal E's
preissuer environment check and as the first shared Vault entry condition,
before root/network/issuer allocation. Receipt-off non-formal diagnostics
retain their old behavior. No-issuer mode truth-table and complete formal
environment/shared-dependency tests guard the split. The former shared
receipt check ran after Vault work and was not a safe early rejection.

This correction changes only the tagged E acceptance harness, not the
production binary inputs. The independently clean R/F source pair, its 12
role candidates, Desktop candidate, one-shot terminal command and F fixture
may be reused under their original source-bound identities; E needs a new
clean revision/tree and its own observer identity. Reuse is not a claim that
any issuer was run or that full Slice 6 has passed. Phase 6 remains **5/15**.

The same finite E package also requires an external expected digest for the
one-shot R terminal binary. Clean-source construction, capability probing
and mounted-byte verification previously compared only to the digest
calculated within that run, which was insufficient to bind the externally
reviewed binary. Formal E now requires canonical lower-case `sha256:` equality
with the preapproved R digest before allocating the Docker run, probing the
terminal container or starting Vault. The no-issuer external-temporary check
shares this strict validator. The E observer and F fixture already had their
own external expected-digest checks before issuer allocation. This is a
tagged acceptance check, not a new production authority or a real-run result.

The single formal E attempt at the frozen E/R/F package failed at the
`old-client-denied` probe: the pinned Vault CLI reported a TCP write
`broken pipe`, which alone is not a TLS trust decision. The exact original
Vault process was removed during successful run-owned cleanup, so the old
attempt has no server-side handshake record and remains failed/incomplete.
Sandbox ruling `S6-E-old-client-TLS-correlation-20261005` allows a narrow
E-only fallback for a *future*, separately approved run. It applies only
to the old **client** certificate after the final positive probe. A
non-explicit client error may be attributed to TLS refusal only when the
same exact run's pinned Vault process, exited probe container, network,
read-only mounted public certificate digest, unique client TCP source/target
socket, Docker start/finish times and one bounded Vault log line agree on
`tls: failed to verify certificate: x509: certificate signed by unknown
authority`. The server must retain its process identity before and after
the probe and log collection. The opposite `old-server-denied` direction
still requires an explicit *client-side* server-certificate verification
failure; a Vault server log cannot establish that direction. A bare
`broken pipe`, reset, EOF, missing/truncated log, ambiguous time or
identity still fails. This does not alter Vault trust configuration, the
three-attempt bound, any Provider Contract or the fixed 119-file business
evidence inventory.

An isolated internal-network diagnostic with the same pinned Vault
server/CLI image, static test certificates and an *uninitialized* Vault
instance reproduced a client `broken pipe` paired with the matching
server-side x509 unknown-authority handshake log. No Vault PKI issuer was
mounted. This demonstrates that the fallback is observable, not that the
earlier formal E failure was a certificate rejection. The diagnostic
container, network and anonymous volumes were removed by exact identity;
one-time test keys were deleted. The original E evidence remains
`incomplete` and Phase 6 remains **5/15**.

Sandbox ruling `S6-Coding-template-and-volume-prep-probe-reviewed-20261005`
requires a v2-only, closed Coding runtime-template projection before any
Docker-control create/inspect path. Both operations must derive from one
template that binds the published image descriptor and selected platform/
config, embedded manifest argv, fixed environment/workdir, per-slot UID:GID,
network `none`, three named volumes, read-only root, cap-drop ALL,
no-new-privileges, pinned seccomp, resource limits and the owner-only bounded
`/tmp` tmpfs. The template does not contain the final Profile digest; the
Profile freezes the template and the finite Coding Plan references its
digest. Neither the legacy bind-mount fixture nor the image's default UID
may be a v3 fallback.

For the known high-UID/named-volume ownership mismatch, the ruling permits
only a bounded daemon archive-put experiment against a unique, never-started
disposable container and exactly three owned volumes. The Control-generated
archive is a single zero-size directory metadata header for the mounted
workspace or outputs root, with slot-numeric owner and mode `0770`; inputs
and root stay read-only. `CopyUIDGID=false` and
`AllowOverwriteDirWithFile=false` preserve the tar owner and disallow a
directory-to-file overwrite. The experiment must observe actual inode
ownership before/after, then test high-UID workspace/outputs/tmp writes and
inputs/root denial, and prove exact resource cleanup. Ambiguous or partial
results never become a completion receipt or automatic retry/release.
The first physical invocation reached only stopped-container creation and
failed inspect/template equality before archive-put; its exact owned
container and volumes were removed. A new physical attempt requires review.
This is not a complete Profile v2 or production Control activation, and
Phase 6 remains **5/15**.

The corrected one-shot mechanism probe later disproved the proposed `.`
root-metadata archive path on the current daemon. After the existing OCI
descriptor-chain and Docker runtime-image observation checks passed,
`CopyToContainer` accepted the one-directory archive for the stopped
container's `/workspace`, but actual inode observation remained
`65532:65532 0770`, not the slot's `57000:58000`. The test stopped before
container start; exact owned container and three-volume cleanup passed.
An accepted copy call is not proof of ownership change. This archive shape
must not be used for production volume preparation or counted as a Slice 6
gate. No fallback to root helper, host bind or public mode is authorized;
the high-UID volume-preparation mechanism remains undecided and Phase 6
stays **5/15**.

Sandbox ruling `S6-Coding-stopped-preparation-carrier-probe-approved-20261005`
chooses a different bounded mechanism experiment after the `.` archive
failure. A uniquely owned, never-started/never-execed short-lived
preparation carrier may have a writable rootfs solely so the daemon archive
API can validate destination `/`; its argv is the inert `/bin/false`, its
user remains the slot's high UID:GID, and its network, seccomp, cap-drop,
no-new-privileges, resource limits and exactly three named mounts remain
closed. The archive contains only zero-data `workspace` and `outputs`
directory metadata entries with the slot's owner and mode `0770`. This
stopped-carrier writable-root exception is **not** a runtime permission or
new generic template option. After both actual volume roots are verified,
the carrier must be deleted and proved absent before a separate runtime
container is created. That runtime retains its original read-only root,
fixed command/environment, high-UID `/tmp` tmpfs and three mounts with
`NoCopy=true`; it alone may start. All two-container/three-volume resources
must be exactly cleaned. Partial, unknown or cleanup-uncertain outcomes hold
the allocation and never authorize retry/release. This ruling authorizes one
opt-in mechanism probe, not production Docker-control wiring or a Slice 6
gate; Phase 6 remains **5/15**.

The separately approved mechanism probe passed on Docker 29.7.2/API 1.55:
the stopped carrier's exact two-entry archive changed both mounted volume
roots from image-default `65532:65532 0770` to slot `57000:58000 0770`
without changing root or read-only inputs metadata. The carrier was removed
before the distinct read-only runtime was created with all three volumes
`NoCopy=true`. The runtime kept the owners; its high UID could write
workspace, outputs and the bounded `/tmp`, while actual inputs/root writes
were denied. Both containers and all three unique volumes were absent after
exact cleanup. This is positive evidence for a local mechanism, **not**
authority to turn the stopped-carrier exception into a generic runtime
option, a production Control service, or a completed Slice 6. The future
durable receipt must account for preparation carrier creation/deletion,
non-atomic dual-volume metadata changes, runtime creation/start and exact
cleanup under the same allocation effect. Until that and full Profile v2
admission pass, the Coding v3 guard remains active and Phase 6 is **5/15**.

Sandbox rulings `S6-Coding-stopped-preparation-component-accepted-20261005`
and `S6-Coding-single-effect-receipts-and-cleanup-reviewed-20261005`
accept the above run only as a current-daemon mechanism component and permit
production *source/model* work under one create effect. A deterministic,
closed inventory derives two container names and three generation-scoped
volume names from the same frozen authority, plan and template; labels bind
the authority, effect, Profile, plan, template, slot and object role. The
existing ledger commits `Unknown` before the first physical call. Per-command
durable phase flags are not required and cannot resolve a lost daemon reply.
Only a bounded, independently checkable observation of the original daemon,
all objects, stopped-carrier removal, exact runtime policy and actual volume
ownership/permissions may justify a private `Completed` receipt. It does not
change Provider business truth or resolve an `outcome_unknown` operation.

Cleanup needs a separately durable, Provider-PG-authorized fenced intent
before its first side effect. A `Creating` reservation cannot simply be
transitioned to `Cleaning`; an independent external quiescence/fence proof is
needed for uncertain effects. A local callback ending, client cancellation,
process exit, flock acquisition, a timeout or even two complete absent reads
do **not** prove that a previously timed-out Docker daemon call cannot create
later. Without that proof, retain `Unknown` and the UID/capacity claim. When
quiescence is established, deletion checks known IDs plus exact names,
labels and frozen configuration, then observes complete two-container/
three-volume absence twice including effect-label inventory. A persistent
released tombstone must bind the cleanup fence, receipt revision, original
daemon and resource set before Provider can CAS-release its PG reservation.
No old cleanup request may operate on a later occupant. These are required
source and gate conditions, **not** claims that production Control or Slice 6
has passed.

Sandbox ruling `S6-Control-daemon-identity-observation-reviewed-20261005`
separates daemon identity from compatibility environment. The private
identity digest binds bounded opaque Docker `Info.ID` to the operator-frozen
endpoint/deployment scope; Linux OS type, the explicit supported native
architecture mapping (`aarch64`→`linux/arm64/v8`, `x86_64`→`linux/amd64`),
root-directory digest and daemon version form a distinct environment digest.
Neither raw daemon ID nor root path is retained in receipt state. Both
digests must match before and after any read-only inventory; a changed
version/root/platform is a fail-closed environment drift, not automatically
a replacement daemon or permission to reset the ledger. A cloned daemon ID
and self-reported `Info` are not authentication or a late-call quiescence
fence. Production still requires the same operator-frozen client/transport
scope; an env-selected test client and fixture scope prove component behavior
only. Changed identity, drift, error or cancellation never becomes absence.

Sandbox rulings `S6-Control-daemon-projection-component-accepted-20261005`,
`S6-Control-readonly-inventory-source-component-accepted-20261005` and
`S6-Control-unix-only-bounded-observer-reviewed-20261005` keep this first
Control observation source strictly read-only and Unix-only. The exact socket
must come from the admitted Profile v2/operator deployment scope, not
`DOCKER_HOST`, a Docker context, a default or a caller-supplied path. It is a
canonical absolute Linux path with no symlink or untrusted-writable ancestor;
the socket itself is root:root mode `0660`. The sole Control principal may
hold the explicitly frozen supplementary GID 0. This is substantial Docker
authority despite a read-only mount and does not relax Provider/Control mTLS
and CRL boundaries on their separate network edge.

The private client freezes API v1.55 and one Unix dialer. Before any Docker
request, its transport admits only `GET /info`, the two exact container
inspects, three exact volume inspects and effect-filtered container/volume
lists; method, API version, query, endpoint and Host drift fail before dial.
All response bodies, including 404, are bounded to 1 MiB **before** SDK JSON
decoding. Truncation, mismatch, read/close error, cancellation and malformed
successful JSON fail as errors, never as observed absence. A Moby response
hook must not consume or close Body, so bounding is in the client's actual
`RoundTripper`. Each request has a five-second cap and an entire serialized
inventory a ten-second cap, both shortening rather than extending a caller's
deadline. An inspect `404` is usable as absence only after checking a
bounded, complete JSON error envelope with a nonempty string `message` and
the expected JSON media type; malformed/error-page 404 is an error. A
successful container list must be an array, and a successful volume list
must contain an array-valued `Volumes` field; a syntactically valid but
missing/null field is not an empty inventory. Concurrent inventory and
close admission is context-cancellable; a timed-out close is not reported
as drained. This source-only component does not authenticate the
Profile/operator endpoint, prove the complete runtime config or daemon
late-call quiescence, or issue a `Completed`/`Released` receipt. No new
physical mechanism run, formal gate or Phase 6 count follows from it.

Sandbox ruling `S6-Control-observer-response-and-budget-closeout-reviewed-20261005`
also requires JSON-field alias protection: `encoding/json` may match
`Volumes`/`Warnings` case-insensitively even though a preparser map uses
case-sensitive keys. Noncanonical aliases of those known fields are rejected,
while unrelated future top-level fields remain opaque. The same one absolute
ten-second deadline starts **before** serial client admission, covering queue
wait and every Info/inspect/list call; a caller's shorter deadline wins.
One specifically authorized no-retry read-only component batch may query a
new empty effect namespace on the already-used local Unix daemon through
the same bounded SDK transport. It cannot grant production endpoint scope,
daemon late-call quiescence, Completed, cleanup or release authority.

Sandbox ruling `S6-Control-complete-runtime-observation-scoped-reads-reviewed-20261005`
permits only two additional *typed* read classes toward a future private
physical-completion proof: inspect the exact template-pinned OCI index with
either no query or the fixed native platform query, and read a complete
bounded initial archive of `/inputs`, `/workspace` or `/outputs` from the
already verified runtime container ID. No arbitrary image, tag, object ID,
path, subpath, `CopyTo`, exec, list, pull or export is authorized. The
existing descriptor-chain verifier and the original stopped-carrier probe's
container-policy and ownership checks are the source of truth; this is not
a second runtime standard. The archive path requires a separate pre-SDK
32 KiB response cap, a constrained path-stat header and a complete single
directory tar with exact owner/mode and no user data or extra entry. It
applies only before tenant access while create remains Unknown. Nonempty,
oversized or ambiguous volumes retain Unknown and the UID claim, never
trigger automatic deletion. Docker's archive GET holds a container lock
until the stream closes, so client cancellation is not daemon quiescence.
This source-only extension neither activates Control nor authorizes a new
physical create probe. Its rollback is to disable the new observation
entry while retaining the existing Unknown receipt and owned resources.

The first unexported `observeCompleted` source skeleton spends one absolute
ten-second budget through serialized admission, the original daemon's Info
before/after, exact whole-effect inventory, runtime ID/state/policy,
descriptor-verified image index/selected platform/config, three initial
empty roots and final runtime/whole-effect remapping. It emits only a
Control-private proof bound to the create authority, effect, Profile, Plan,
template, receipt revision, original daemon and observed resource digests.
It does not accept a caller's completion digest or boolean. The durable
ledger has no production Completed transition or callback from this proof;
the source skeleton must pass a real approved full-chain observation and
independent review before any activation. A snapshot cannot by itself rule
out a daemon request that may still complete late.

Sandbox ruling `S6-Control-list-only-metadata-compatibility-and-retained-effect-review-20261005`
permits one Docker Desktop 29.7.2 container-list-only metadata key,
`desktop.docker.io/ports.scheme`, with an untrusted value bounded to 4,096
bytes. It is not an ownership label and is excluded from the proof.
Container inspect must still match the full exact inherited and binding
label set. The list must still match the inspected single container ID,
name and every expected label value; duplicate, missing, conflicting or
other extra effect metadata fails closed. This is a narrow compatibility
rule, not a generic allowance for unknown labels or partial inspect.

Under `S6-Control-retained-effect-proof-persistence-and-cleanup-approved-20261005`,
the retained single Unknown effect passed a same-process 23-GET full-chain
observation. A minimal private proof and trace were exclusively persisted,
fsynced, read back and rechecked before exact known-ID runtime/volume
cleanup. Two full post-delete inventories observed zero effect resources.
Sandbox accepted this as a component result under
`S6-Control-complete-observation-and-retained-cleanup-component-accepted-20261005`.
The original durable Unknown receipt and its failure history remain
unchanged. This is real component evidence for observation and cleanup,
not a durable Completed/Released transition, a Provider-PG CAS/fence or a
general late-effect quiescence proof. Production Control and the Slice 6
release gate remain closed.

Sandbox ruling `S6-Control-live-completion-CAS-and-historical-Unknown-boundary-20261005`
keeps the already-cleaned test effect permanently Unknown at revision 2;
its retained physical proof is component evidence, not a historical state
import. A generic Completed transition may only follow a current live
same-effect observation after an unambiguous, synchronous create callback
return, while the Control owner excludes its own concurrent physical
dispatch. It must recheck the same authority and ledger revision at commit,
persist the private full proof before the Completed state, and fail closed
on cancellation, close, stale revision, missing evidence or ambiguous
fsync/rename/response. The ledger mutex is not held across Docker I/O.
Reopen loses the ephemeral successful-callback qualification; an old
Unknown therefore cannot complete from a saved snapshot. Completed means
the create observation was durably confirmed at that time, not permanent
runtime readiness or authority to rewrite a Provider terminal outcome.
Docker and the file ledger do not form a cross-system atomic transaction.
An independent late-effect quiescence producer and a distinct Unknown
retirement design are still missing; neither local callback drain nor two
empty reads supplies them. The existing Completed-only cleanup-intent rule
is not relaxed for the historical test receipt. All production guards and
Slice 6 gates remain closed.

Review `S6-Control-live-Completed-aggregate-boundary-corrections-20261005`
requires three additional fail-closed details in that candidate path. The
normal live observation inherits the original create authority expiry and
operation deadline; a new caller context cannot refresh them. Time validity
is checked at admission, after observation, after private evidence write
and after receipt commit. Evidence fsync/readback can race cancellation:
before receipt commit it leaves Unknown and an unusable orphan file; after
commit it returns an uncertain response but does not roll back Completed.
The receipt retains separate digests for the physical proof and the entire
canonical private evidence envelope, including capture time and source
state digest. Active Completed reopen/Lookup rechecks both. Unknown/Reserved
omit the new private seal field, preserving their v2 canonical bytes;
old unsealed Completed prototypes reject rather than silently migrate.
The seal detects drift relative to the saved receipt, not a same-UID
attacker who can rewrite both files. These are source-only corrections;
they do not produce a late-effect fence or activate production Control.

Sandbox ruling `S6-Coding-current-terminate-and-historical-create-outcome-reviewed-20261005`
keeps termination independent of the old create operation's terminal result.
A historical create `outcome_unknown` is never rewritten to Succeeded, but a
new accepted terminate may proceed if the same allocation has a current,
durable Control Completed receipt with its full evidence seal and exact
authority/effect/slot/Profile binding. Control Unknown or an unresolved late
daemon effect remains occupied. Provider first persists the existing
termination intent, then a single current-state PG transaction binds the
accepted terminate and unique idempotency record to the current sandbox,
fence highwater, original claim, trusted Control Completed revision/digest,
Running operation, ObservedTerminating state and Cleaning reservation.
No Docker read occurs under the PG row lock, and no cleanup permit is
returned on partial failure. For a PG Creating reservation with trustworthy
Control Completed, the private transaction may advance the reservation
through Active to Cleaning without publishing an intermediate Ready state.
The old create outcome stays unchanged.

Current cleanup fence equality with birth is valid for certain legal
termination and lease-expiry paths; the cleanup fence must equal PG's
current highwater and be no lower than birth. Current generation is the
actual terminated-desired sandbox generation and is greater than birth,
but a repeat terminate need not increment it again. The PG retirement
binding must also identify exactly one current operation/attempt/request;
same-fence different operations are not interchangeable. Control must
persist its separate cleanup intent before deletion, then exact resource
absence and a Released tombstone before PG's precise slot-release CAS.
Unknown termination outcomes may gain cleanup evidence without being
rewritten Succeeded. Two empty reads, local callback drain and model-only
`ConfirmAbsence` never substitute for production late-effect quiescence.
This ruling authorizes source work only; no new Docker batch, v3 startup or
Phase 6 count change follows.

Review `S6-Coding-PG-current-cleanup-projection-reviewed-20261005` accepted
the source-only same-row PG projection but required preserving the caller's
shorter context deadline when constructing the cleanup envelope, checking
lease and operation value IDs against their map lookup keys, and treating a
post-commit cancellation or expired envelope as an uncertain response, not
a dispatch permit. The private retirement binding retains the exact
canonical cleanup envelope, including originally clamped issuance/expiry,
for read-only response-loss recovery; readback never refreshes its time or
substitutes for current Control/PG checks. A Control CompletedSnapshot
produced by the local ledger is only an in-process component input, not a
cross-process mTLS attestation or quiescence claim. Concurrent real PG row
locking, crash/restart response recovery, and final Control/PG release
remain separately gated.

The subsequent bounded PG-only final-release CAS component was accepted
under `S6-Coding-PG-final-release-bounded-component-accepted-20261005` after
one race/shuffle real-PG batch. Its synthetic Released input verifies PG
transaction behavior only: exactly one of two same-row contenders wins; an
old proof cannot release a genuine new occupant after the slot is freed.
Transaction-local higher-fence drift, rollback, row-lock deadline/cancel,
simulated lost-return readback and PG restart do not establish Control
cross-process attestation, actual COMMIT packet loss, a persisted competing
higher-fence operation or physical Docker absence. The current terminate
operation deadline must match the cleanup envelope; the Released timestamp
must have been committed inside that envelope even if Provider repairs its
PG state after the envelope expires. This is not permission to activate the
still-guarded Coding v3 profile.

The same review keeps the normal Control cleanup source fail-closed before
any real Coding DELETE: pre-delete inspection must recheck the completed
effect's full frozen runtime configuration, accepting an exited runtime only
when the configuration still matches. The three exact realized volumes and
at most one exact private `/tmp` tmpfs are checked before comparison; Docker
may omit that tmpfs from the exited realized view, but the configured tmpfs,
mount options and all other frozen fields remain bound. A close racing
preflight must be serialized before reading the mutable SDK client. The
separate deletion client has a cancellable admission gate and one absolute
five-second mutation budget. net/http-visible 204 framing plus two complete
post-delete inventories is the required local evidence, not a raw-wire or
late-daemon quiescence proof. Private evidence must omit Docker diagnostic
strings that might contain host paths. Active Completed evidence remains
checked on routine ledger reads; historical Released evidence is checked on
Open/reopen and target lookup/snapshot, so unrelated hot reads do not scan
all historical evidence files. None of these component rules replaces the
Provider↔Control authenticated wire or the fixed Slice 6 topology gate.

Decision `S6-Provider-Control-v2-wire-and-retirement-barrier-reviewed-20261005`
selects a durable Provider-PG retirement barrier, not a distributed lock.
The first current cleanup PG transaction already records `Cleaning` and
`Retirements` under the singleton `control_state` row lock. Every applicable
generic lifecycle write to that allocation must read and respect the same
record in that transaction, including separate generic repository instances
and create/mutation/sandbox/lease/operation/event/reconcile paths. A
conflicting higher fence committed first makes cleanup admission fail without
effects; retirement committed first makes the later conflicting write
temporarily unavailable without changing its lifecycle highwater. Read-only
status, exact idempotent replay, and the same terminate attempt's lawful
`OutcomeUnknown` plus matching event remain possible. Only the dedicated
Released→final CAS removes the barrier. Control uncertainty, expiry or CRL
loss does not release it. This protects safety at the cost of potentially
long-lived occupied capacity.

We reject a new higher-fence supersession protocol here because it would
introduce another authority transfer after irreversible physical deletion.
We also reject a cross-system PG/Control distributed abort or lock service:
the existing row transaction and retained retirement are enough for this
allocation boundary, and no SQL lock is held during network or Docker work.
An unaccepted conflicting request maps to existing retryable 503
`SANDBOX_PROVIDER_UNAVAILABLE`, not a fabricated stale-fence error; truly
stale requests and idempotency mismatches keep their existing mappings.
Admission JTI consumption is independent and never rolled back to recreate a
physical permit. If this inactive source integration must be rolled back,
keep Coding v3 guarded and withdraw only the unactivated composition;
persisted retirement and Control tombstones remain, never erased or
downgraded to free resources.

The approved wire direction is one full Profile v2 source with exactly
declared Provider↔Control private edges, dedicated TLS identities/agents,
issuer roots and directional CRL guards. It may reuse TLS primitives, but
not widen Browser/Desktop-specific attach helpers. Typed canonical
create/cleanup/status requests bind the authenticated peer and original
authority/effect; responses expose bounded status/revision/digests only,
not physical IDs, paths or private proof. Status can read a historical
completed effect after authority expiry, never renew authority to mutate.
This decision authorizes source/component development and a separately
bounded future two-client PG barrier test. It does not authorize real Coding
Docker deletion, v3 activation, the complete topology gate or a change from
Phase 6 **5/15**.

Follow-up `S6-retirement-barrier-corrections-and-bounded-PG-batch-reviewed-20261005`
accepted the source design and authorized one bounded PG component batch. The
generic lifecycle writer now validates finite, unique reservations and the
Cleaning/retirement bijection, canonical cleanup envelope, and original/current
operation, idempotency, sandbox, lease and fence bindings inside the same row
transaction. A historical create Unknown event uses birth generation/fence;
the existing State stale-fence rule is not widened. A single transaction clock
rejects future events without a hidden grace interval. The private wire maps
Completed plus durable cleanup intent to `cleanup_pending`; Released remains
bound to the original cleanup time window. A create-only status response is
observation, not an input to the trusted final PG release CAS. The approved
real-PG batch passed in one disposable pinned PostgreSQL container, using
two independent pools for the retirement-first path and one pool for the
higher-fence-first ordering. These are committed-order checks, not a new
simultaneous generic-mutation-versus-cleanup race. It covered retryable blocking,
admission JTI independence, Unknown/event replay, unrelated sandbox writes,
restart retention and the existing final release/new occupant path. Synthetic
Control receipts and pure malformed-binding tests remain component inputs;
this does not add a Control mTLS/CRL peer, physical deletion, or Slice 6 gate.

Decision `S6-Control-authenticated-observation-layering-reviewed-20261005`
keeps the local `CodingCompletedSnapshot` and `CodingReleasedSnapshot` as
Control-owner component types, not constructors from a private wire response.
For production, an application coordinator reads the current minimal Provider
binding through a repository port, calls one dedicated Control observation
port over the fixed Profile-v2 mTLS/CRL edge outside PG locks, then checks
the actual peer, configured edge/scope, canonical action/effect/authority and
freshness. Separate internal Completed and Released observations may then be
passed to typed PG entry points. Those entry points re-read the actual
reservation/retirement and lifecycle tuple under the existing row lock and
reuse the existing private cleanup/release CAS. The network client cannot
read PG; PG cannot authenticate over a callback while locked. Private Go
fields reduce accidental fabrication by ordinary callers, but do not make a
same-process malicious caller cryptographically impossible. The trust root is
the fixed production composition, authenticated connection and sealed Control
ledger. No bare response/digest/bool factory, local-ledger production fallback,
generic Doer, additional signing service or caller-supplied PG floor is
authorized. Before Begin there is no retirement floor; Finish uses the
persisted retirement's strictly older Control revision and changed state
digest. Loss, cancellation or pending status produces no consumable release
observation. Expired authority cannot renew a physical mutation permit, but
an authenticated historical status read may consume a sealed Released result
for the existing PG retirement. The v3 startup guard remains closed until this
vertical path, complete Profile v2 and its gates are actually composed.

Decision `S6-original-create-envelope-atomic-persistence-reviewed-20261005`
closes the restart gap between first PG permit and the historical Control
effect key. The production first-permit transaction must mint the originally
deadline-clamped create authority under the same singleton-row lock as
Creating/Running/Provisioning and save its exact canonical bytes/digest in
`coding_identity_state`, indexed by original allocation ID. A post-commit
mint or later re-sign is forbidden: even if effect/request IDs remained the
same, changed issuance bytes would alter the authority digest. The retained
record is immutable, bounded to 4 KiB per item and 4096 items, survives slot
release/reuse, and is read after expiry only for historical status. Missing
legacy Creating/Active/Cleaning records remain occupied and may be diagnosed
read-only, never guessed, renewed, redispatched or erased. Current first
permit, typed cleanup and typed release must recheck this original against
the local PG tuple. This source rule does not itself authenticate a Control
peer, change the existing Controller guard, or close Slice 6 Step 2.

Follow-up `S6-Coding-durable-authority-mode-marker-reviewed-20261005` closes
the cross-instance legacy entry-point bypass. The existing Coding-only PG
identity marker, not Browser/Desktop's shared marker type, freezes one exact
`atomic-original-envelope` mode and Control policy digest at a new, one-time
v3 initialization. A legacy initialized marker cannot be upgraded in place,
even with no live slots; a missing, partial, unknown or mismatched marker is
fail-closed. Every first-permit, cleanup and release wrapper checks the actual
marker under the singleton row lock. The generic lifecycle retirement guard
also uses that marker: each v3 live Coding reservation needs its exact
original envelope, and a retirement needs the same original digest. Old
component-only first-create and local-snapshot cleanup/release entry points
cannot be runtime fallbacks in a v3 PG, including through another pool or
after restart. Existing JTI/high-water commitments remain independent.
The v3 coordinator must pass the exact PG-persisted original authority to a
dedicated dispatcher; a ticket-only dispatcher or later re-signing cannot
recover the same effect bytes. Its historical readback never redispatches.
Until the dedicated Control/typed-PG lifecycle route is composed, that v3
coordinator also refuses to route terminate, suspend, resume or lease
reconciliation through the legacy Driver's Inspect/Remove/state-control
methods, even if that Driver implements them. A legacy marker mixed with v3
original records is invalid, and every v3 stateful PG entry rechecks the
current marker and all active originals before admitting another effect.
This is a source decision, not PG cross-instance proof, Control mTLS evidence,
v3 startup authorization or a Phase 6 count change.

The authorized PG aggregate component was accepted under
`S6-atomic-original-PG-aggregate-accepted-20261005` after retaining an
initial failed fixture attempt and one approved repair supplement. Its
two-pool, one-disposable-container run tested atomic first-permit original
retention, legacy/mixed-mode denial, exact row-lock queue orderings
(retirement-first against an otherwise-valid lease update;
higher-fence-first against an older cleanup), typed PG Completed→Released
with an explicitly synthetic Observer, slot reuse, PostgreSQL restart and
exact run-owned cleanup. This proves those local PG boundaries only. The
legacy cleanup/release probe used zero-value snapshots for marker pre-denial,
not valid old Control proofs; the queued cancellation was before commit, not
actual COMMIT-packet loss. It does not authenticate Control, attest physical
Coding Docker absence, provide a full Profile v2 or close any 16-scenario
Slice 6 gate. The v3 guard and Phase 6 **5/15** remain unchanged.

### Profile-v2 CRL document and Control status transport, 2026-10-05

Sandbox decision `S6-ProfileV2-CRL-typed-boundary-reviewed-20261005`
preserves the existing peer-CRL source/role wire identifiers, fields and
digest domains. Each document already binds a whole security-profile digest;
the independent Profile-v2 digest separates versions without a second CRL
wire migration. New entry points must explicitly accept `ProfileV2`, verify
its formal public validator and the operator-pinned mapping/role digests, and
must not strip v2 fields or invoke the v1 `Profile` admission path. The
certificate controller, dedicated TLS agent and consuming role independently
authorize the same exact edge, direction, local principal, peer anchor and
immediate issuer DER. The complete required mapping includes the three
Provider↔Control edges and Coding↔Scanner in both directions, plus the
closed existing PostgreSQL-purpose and DNS exceptions; neither Control nor
Scanner gains the broker-only DNS client issuer. Ordinary and PostgreSQL
purpose agents cannot exchange source rights.

The present source adds a package-private complete-field graph check,
minimal Control/Scanner role documents, strict canonical v2-entry decoders
with external expected digests, and an immutable scalar authorization index.
Synthetic tests cover exact positive tuple coverage and cross-profile,
missing/extra edge, wrong peer/issuer/purpose and canonical-wire failures.
The first synthetic source fixture incorrectly introduced a third
PostgreSQL issuer; Sandbox rejected that as incomplete two-issuer coverage.
The corrected field validator requires exactly the existing general and
five-broker-only sources in one `/pki` mount, distinct UUID/DER, with the
broker source matching the DNS client CA and each edge selected by the
verified peer's issuer group. PostgreSQL uses the general source. Controller
policy/agent enforcement and live Vault evidence remain separate gates.
All public v2 entry points still reject because `ProfileV2.Validate` retains
its final source/image admission hold. The package-private status transport
has a real localhost TLS 1.3 mutual-certificate round trip and reads a
single locked receipt/state projection; `not_found` never means Docker
absence. Its test TLS verification hook is not the production CRL guard.
Production Control/Scanner commands, source-bound images, fixed-source
CRL bootstrap/poll/drain, real daemon actions and the final 16-scenario gate
remain required before the hold may be reviewed. Phase 6 stays **5/15**.
