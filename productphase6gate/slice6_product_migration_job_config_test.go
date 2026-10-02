//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/spf13/viper"
)

// The operator supplies only non-secret, source-bound references. The SQL
// password remains solely inside the purpose-scoped Vault KVv2 value.
func slice6BuildProductMigrationJobConfig(composed slice6VaultComposedInputs) ([]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		composed.PeerSources.Validate(profile) != nil {
		return nil, errors.New("Product migration job Profile unavailable")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("product-migration-job")
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-migration-job")
	role, roleErr := phase6security.DerivePostgresPeerCRLRoleDocument(profile, composed.PeerSources, "product-migration-job")
	plan, planErr := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil || materialErr != nil || roleErr != nil || planErr != nil ||
		authority.Database != "product" || authority.SQLRole != "product_migrator" || !authority.Migration ||
		authority.BrokerOnly || authority.Dialer != "product-migration-job" ||
		len(role.Edges) != 1 || role.Edges[0].EdgeID != authority.PeerEdgeID ||
		material.AgentDeployment != "product-migration-agent" || material.OwnerDeployment != "product-migration-job" ||
		material.OwnerGID == material.AgentGID || material.MaxOperationSeconds < 15 {
		return nil, errors.New("Product migration job authority drift")
	}
	var binding secretref.Binding
	for _, entry := range plan {
		if entry.Owner == "product-migration-job" && entry.Agent == "product-migration-agent" &&
			entry.Migration && len(entry.Bindings) == 1 {
			binding = entry.Bindings[0]
		}
	}
	if binding.Validate() != nil || binding.Purpose != secretref.PurposePostgresMigrationDSN ||
		binding.Role != secretref.RoleProduct || binding.TenantID != secretref.SystemTenant {
		return nil, errors.New("Product migration material binding unavailable")
	}
	bindingDocument, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	defer clear(bindingDocument)
	document := []byte(fmt.Sprintf(`[application]
mode = "production"

[product_migration]
schema_version = %q
enabled = true

[product_migration.postgres]
dsn_binding_id = "product-migration-dsn"
role = %q
security_profile_path = "/run/phase6/config/profile.json"
security_profile_digest = %q
client_agent_socket = %q
client_agent_uid = %d
client_agent_gid = %d
peer_crl_role_file = "/run/phase6/config/postgres-peer-crl-role.json"
peer_crl_role_digest = %q
peer_crl_source_mapping_digest = %q
startup_timeout_seconds = 60
max_connections = 1

[product_migration.materials.provider]
type = %q
alias = "product-migration-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
directory_gid = %d
operation_timeout_seconds = 15
cache_seconds = 0

[[product_migration.materials.bindings]]
id = "product-migration-dsn"
provider = "product-migration-agent"
document = %q
`, config.ProductMigrationSchemaV2, authority.SQLRole, profile.ProfileDigest,
		authority.Signer.SocketPath, authority.Signer.AgentUID, authority.Signer.AgentGID,
		role.Digest(), composed.PeerSources.Digest(), config.UnixWorkloadMaterialProviderV2,
		material.SocketPath, material.AgentUID, material.AgentGID, material.OwnerGID, string(bindingDocument)))
	if len(document) == 0 || len(document) > 64<<10 ||
		bytes.Contains(document, []byte("postgres://")) || bytes.Contains(document, []byte("PRIVATE KEY")) ||
		bytes.Contains(document, []byte("password =")) || strings.Contains(string(document), "SANDBOX_RUNTIME_") {
		clear(document)
		return nil, errors.New("Product migration startup config is oversized or contains secret material")
	}
	parser := viper.New()
	parser.SetConfigType("toml")
	if parser.ReadConfig(bytes.NewReader(document)) != nil {
		clear(document)
		return nil, errors.New("Product migration startup TOML invalid")
	}
	section := parser.Sub("product_migration")
	var decoded config.ProductMigrationConfig
	if section == nil || section.UnmarshalExact(&decoded) != nil || decoded.Validate() != nil ||
		decoded.Postgres.SecurityProfileDigest != profile.ProfileDigest ||
		decoded.Postgres.PeerCRLRoleDigest != role.Digest() ||
		decoded.Materials.Provider.DirectoryGID != int64(material.OwnerGID) {
		clear(document)
		return nil, errors.New("Product migration startup TOML does not decode to the intended authority")
	}
	return document, nil
}
