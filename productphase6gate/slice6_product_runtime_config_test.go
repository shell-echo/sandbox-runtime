//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/spf13/viper"
)

// The runtime receives only the two Product runtime bindings, distinct live
// TLS/PG signers, exact private Guest edge and two purpose-specific CRL roles.
// This is static input admission, not evidence that a Product PID1 started.
func slice6BuildProductRuntimeConfig(composed slice6VaultComposedInputs) ([]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		composed.PeerSources.Validate(profile) != nil {
		return nil, errors.New("Product runtime Profile unavailable")
	}
	postgres, err := profile.ResolveSlice6FinalPostgresAuthority("product-runtime")
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-runtime")
	tlsBinding, tlsAgent, subject, tlsErr := profile.TLSAgentForSubject("product-runtime")
	peerRole, peerErr := phase6security.DerivePeerCRLRoleDocument(profile, composed.PeerSources, subject.PrincipalDigest)
	postgresRole, postgresErr := phase6security.DerivePostgresPeerCRLRoleDocument(profile, composed.PeerSources, "product-runtime")
	plan, planErr := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	var bindings []secretref.Binding
	for _, access := range plan {
		if access.Owner == "product-runtime" && access.Agent == "product-runtime-agent" && !access.Migration {
			bindings = access.Bindings
		}
	}
	var publicAddress, guestAddress string
	for _, ingress := range profile.IngressBindings {
		if ingress.ID == "product-public" && ingress.Target == "product-runtime" {
			publicAddress = ingress.UpstreamAddress
		}
	}
	for _, edge := range profile.TrustEdges {
		if edge.ID == "guest-product" && edge.From == "guest-runtime" && edge.To == "product-runtime" {
			guestAddress = edge.TargetAddress
		}
	}
	publicEndpoint, publicParse := netip.ParseAddrPort(publicAddress)
	guestEndpoint, guestParse := netip.ParseAddrPort(guestAddress)
	if err != nil || materialErr != nil || tlsErr != nil || peerErr != nil || postgresErr != nil || planErr != nil ||
		publicParse != nil || guestParse != nil || !publicEndpoint.Addr().Is4() || !guestEndpoint.Addr().Is4() ||
		publicEndpoint.Port() != 8444 || guestEndpoint.Port() != 8449 ||
		postgres.BrokerOnly || postgres.Dialer != "product-runtime" ||
		postgres.Database != "product" || postgres.SQLRole != "product_runtime" || postgres.Migration ||
		postgres.Signer.SubjectDeployment != "product-runtime" ||
		postgres.Signer.AgentDeployment != "product-postgres-tls-agent" ||
		material.AgentDeployment != "product-runtime-agent" || material.OwnerDeployment != "product-runtime" ||
		material.MaxOperationSeconds < 15 || tlsAgent.Name != "product-tls-agent" || subject.Name != "product-runtime" ||
		len(bindings) != 2 || bindings[0].Purpose != secretref.PurposeIdentityKeyRing ||
		bindings[1].Purpose != secretref.PurposePostgresRuntimeDSN ||
		len(peerRole.Edges) == 0 || len(postgresRole.Edges) != 1 ||
		postgresRole.Edges[0].EdgeID != postgres.PeerEdgeID {
		return nil, errors.New("Product runtime source-bound authority drift")
	}
	const identityID = "product-identity-key-ring"
	const runtimeID = "product-runtime-dsn"
	if bindings[0].Validate() != nil || bindings[1].Validate() != nil ||
		bindings[0].Role != secretref.RoleProduct || bindings[1].Role != secretref.RoleProduct ||
		bindings[0].TenantID != secretref.SystemTenant || bindings[1].TenantID != secretref.SystemTenant {
		return nil, errors.New("Product runtime material binding drift")
	}
	identityDocument, err := json.Marshal(bindings[0])
	if err != nil {
		return nil, err
	}
	defer clear(identityDocument)
	runtimeDocument, err := json.Marshal(bindings[1])
	if err != nil {
		return nil, err
	}
	defer clear(runtimeDocument)
	document := []byte(fmt.Sprintf(`[application]
mode = "production"

[product_process]
schema_version = %q
enabled = true
deployment_level = "production"
guest_control_max_connections = 16

[product_process.api]
host = %q
port = %d

[product_process.guest_control]
host = %q
port = %d

[product_process.tls]
security_profile_path = "/run/phase6/config/profile.json"
security_profile_digest = %q
agent_socket = %q
agent_uid = %d
agent_gid = %d
operation_timeout_millis = 15000
peer_crl_role_file = "/run/phase6/config/peer-crl-role.json"
peer_crl_role_digest = %q
peer_crl_source_mapping_digest = %q

[product_process.postgres]
runtime_dsn_binding_id = %q
runtime_role = %q
client_agent_socket = %q
client_agent_uid = %d
client_agent_gid = %d
peer_crl_role_file = "/run/phase6/config/postgres-peer-crl-role.json"
peer_crl_role_digest = %q
peer_crl_source_mapping_digest = %q
startup_timeout_seconds = 60
operation_timeout_seconds = 15
max_connections = 4
min_connections = 1

[product_process.identity]
issuer = "https://identity.product.example.test"
audience = "urn:shell-echo:sandbox-runtime:product-api:production"
key_ring_binding_id = %q
clock_skew_seconds = 20
max_token_lifetime_seconds = 600

[product_process.materials.provider]
type = %q
alias = "product-runtime-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
directory_gid = %d
operation_timeout_seconds = 15
cache_seconds = 30

[[product_process.materials.bindings]]
id = %q
provider = "product-runtime-agent"
document = %q

[[product_process.materials.bindings]]
id = %q
provider = "product-runtime-agent"
document = %q
`, config.ProductProductionSchemaV3, publicEndpoint.Addr().String(), publicEndpoint.Port(),
		guestEndpoint.Addr().String(), guestEndpoint.Port(), profile.ProfileDigest,
		tlsBinding.SocketPath, tlsBinding.AgentUID, tlsBinding.AgentGID,
		peerRole.Digest(), composed.PeerSources.Digest(), runtimeID, postgres.SQLRole,
		postgres.Signer.SocketPath, postgres.Signer.AgentUID, postgres.Signer.AgentGID,
		postgresRole.Digest(), composed.PeerSources.Digest(), identityID,
		config.UnixWorkloadMaterialProviderV2, material.SocketPath, material.AgentUID,
		material.AgentGID, material.OwnerGID, identityID, string(identityDocument),
		runtimeID, string(runtimeDocument)))
	if len(document) == 0 || len(document) > 64<<10 ||
		bytes.Contains(document, []byte("postgres://")) || bytes.Contains(document, []byte("PRIVATE KEY")) ||
		strings.Contains(string(document), "SANDBOX_RUNTIME_") {
		clear(document)
		return nil, errors.New("Product runtime config is oversized or contains secret material")
	}
	parser := viper.New()
	parser.SetConfigType("toml")
	if parser.ReadConfig(bytes.NewReader(document)) != nil {
		clear(document)
		return nil, errors.New("Product runtime startup TOML invalid")
	}
	section := parser.Sub("product_process")
	var decoded config.ProductProcessConfig
	if section == nil || section.UnmarshalExact(&decoded) != nil || decoded.Validate() != nil ||
		decoded.TLS.SecurityProfileDigest != profile.ProfileDigest ||
		decoded.TLS.PeerCRLRoleDigest != peerRole.Digest() ||
		decoded.Postgres.PeerCRLRoleDigest != postgresRole.Digest() ||
		decoded.Materials.Provider.DirectoryGID != int64(material.OwnerGID) {
		clear(document)
		return nil, errors.New("Product runtime startup TOML does not decode to intended authority")
	}
	return document, nil
}
