//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/spf13/viper"
)

// This is a gate-only file constructor. It neither starts a migration nor
// proves its server-side HBA, SQL role, signer or exact process exit.
func slice6BuildProviderMigrationInputs(composed slice6VaultComposedInputs, job string) (map[string][]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil || composed.PeerSources.Validate(profile) != nil {
		return nil, errors.New("Provider migration final Profile unavailable")
	}
	authority, authorityErr := profile.ResolveSlice6FinalPostgresAuthority(job)
	material, materialErr := profile.Slice6MaterialSocketForOwner(job)
	peerRole, roleErr := phase6security.DerivePostgresPeerCRLRoleDocument(profile, composed.PeerSources, job)
	access, accessErr := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	private, privateOK := phase6security.Slice6PrivateConfigMount(job)
	if authorityErr != nil || materialErr != nil || roleErr != nil || accessErr != nil || !privateOK ||
		!authority.Migration || authority.BrokerOnly || authority.Owner != job || authority.Dialer != job ||
		material.OwnerDeployment != job || material.AgentDeployment == "" || material.MaxOperationSeconds < 15 ||
		len(peerRole.Edges) != 1 || peerRole.Edges[0].EdgeID != authority.PeerEdgeID ||
		!slices.Equal(strings.Split(private.PrivateFiles, ","), []string{
			phase6security.Slice6PostgresPeerCRLRoleFile,
			phase6security.Slice6ProfileConfigFile,
			phase6security.Slice6StartupConfigFile,
		}) {
		return nil, errors.New("Provider migration Profile-bound authority drift")
	}
	var binding secretref.Binding
	for _, item := range access {
		if item.Owner == job && item.Agent == material.AgentDeployment && item.Migration &&
			item.Role == secretref.RoleProvider && len(item.Bindings) == 1 {
			binding = item.Bindings[0]
		}
	}
	if binding.Validate() != nil || binding.Purpose != secretref.PurposePostgresMigrationDSN ||
		binding.Role != secretref.RoleProvider || binding.TenantID != secretref.SystemTenant {
		return nil, errors.New("Provider migration material purpose unavailable")
	}
	bindingDocument, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	defer clear(bindingDocument)
	bindingID := job + "-dsn"
	startup := []byte(fmt.Sprintf(`[application]
mode = "production"

[provider_migration]
schema_version = %q
enabled = true

[provider_migration.postgres]
job = %q
dsn_binding_id = %q
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

[provider_migration.materials.provider]
type = %q
alias = %q
socket_path = %q
expected_uid = %d
expected_gid = %d
directory_gid = %d
operation_timeout_seconds = 15
cache_seconds = 0

[[provider_migration.materials.bindings]]
id = %q
provider = %q
document = %q
`, config.ProviderMigrationSchemaV2, job, bindingID, authority.SQLRole,
		profile.ProfileDigest, authority.Signer.SocketPath, authority.Signer.AgentUID,
		authority.Signer.AgentGID, peerRole.Digest(), composed.PeerSources.Digest(),
		config.UnixWorkloadMaterialProviderV2, material.AgentDeployment, material.SocketPath,
		material.AgentUID, material.AgentGID, material.OwnerGID, bindingID,
		material.AgentDeployment, string(bindingDocument)))
	if len(startup) == 0 || len(startup) > 64<<10 ||
		bytes.Contains(startup, []byte("postgres://")) || bytes.Contains(startup, []byte("PRIVATE KEY")) ||
		bytes.Contains(startup, []byte("password =")) || bytes.Contains(startup, []byte("SANDBOX_RUNTIME_")) {
		clear(startup)
		return nil, errors.New("Provider migration startup contains unsafe material")
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		clear(startup)
		return nil, err
	}
	peerBytes, err := json.Marshal(peerRole)
	if err != nil {
		clear(startup)
		return nil, err
	}
	files := map[string][]byte{
		phase6security.Slice6ProfileConfigFile:       profileBytes,
		phase6security.Slice6PostgresPeerCRLRoleFile: peerBytes,
		phase6security.Slice6StartupConfigFile:       startup,
	}
	if err := slice6VerifyProviderMigrationInputs(composed, job, files); err != nil {
		return nil, err
	}
	return files, nil
}

// Mirror the existing config decoder and migration preflight against the
// selected Profile before any archive is handed to a PID. The actual command
// still independently checks owned files, UID/GID, HBA and SQL privileges.
func slice6VerifyProviderMigrationInputs(composed slice6VaultComposedInputs, job string, files map[string][]byte) error {
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil || composed.PeerSources.Validate(profile) != nil ||
		len(files) != 3 {
		return errors.New("Provider migration input inventory unavailable")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority(job)
	if err != nil || !authority.Migration || authority.BrokerOnly || authority.Owner != job || authority.Dialer != job {
		return errors.New("Provider migration owner has no direct PostgreSQL authority")
	}
	material, err := profile.Slice6MaterialSocketForOwner(job)
	if err != nil {
		return errors.New("Provider migration material owner unavailable")
	}
	canonicalProfile, err := json.Marshal(profile)
	if err != nil || !bytes.Equal(files[phase6security.Slice6ProfileConfigFile], canonicalProfile) {
		return errors.New("Provider migration Profile bytes differ")
	}
	if phase6security.VerifySlice6PrivateConfigPath(profile, job, phase6security.Slice6StartupConfigFile,
		path.Join(phase6security.Slice6PrivateConfigDirectory, phase6security.Slice6StartupConfigFile)) != nil ||
		phase6security.VerifySlice6PrivateConfigPath(profile, job, phase6security.Slice6PostgresPeerCRLRoleFile,
			path.Join(phase6security.Slice6PrivateConfigDirectory, phase6security.Slice6PostgresPeerCRLRoleFile)) != nil {
		return errors.New("Provider migration private file purpose differs")
	}
	parser := viper.New()
	parser.SetConfigType("toml")
	startup := files[phase6security.Slice6StartupConfigFile]
	if len(startup) == 0 || len(startup) > 64<<10 || parser.ReadConfig(bytes.NewReader(startup)) != nil {
		return errors.New("Provider migration startup TOML invalid")
	}
	settings := parser.AllSettings()
	if len(settings) != 2 || parser.GetString("application.mode") != "production" {
		return errors.New("Provider migration application or section scope differs")
	}
	if _, ok := settings["provider_migration"]; !ok {
		return errors.New("Provider migration startup section missing")
	}
	section := parser.Sub("provider_migration")
	var decoded config.ProviderMigrationConfig
	if section == nil || section.UnmarshalExact(&decoded) != nil || decoded.Validate() != nil ||
		decoded.SchemaVersion != config.ProviderMigrationSchemaV2 || !decoded.Enabled ||
		decoded.Postgres.Job != job || decoded.Postgres.Role != authority.SQLRole ||
		decoded.Postgres.DSNBindingID != job+"-dsn" ||
		decoded.Postgres.SecurityProfilePath != path.Join(phase6security.Slice6PrivateConfigDirectory, phase6security.Slice6ProfileConfigFile) ||
		decoded.Postgres.SecurityProfileDigest != profile.ProfileDigest ||
		decoded.Postgres.ClientAgentSocket != authority.Signer.SocketPath ||
		decoded.Postgres.ClientAgentUID != authority.Signer.AgentUID ||
		decoded.Postgres.ClientAgentGID != authority.Signer.AgentGID ||
		decoded.Postgres.PeerCRLRoleFile != path.Join(phase6security.Slice6PrivateConfigDirectory, phase6security.Slice6PostgresPeerCRLRoleFile) ||
		decoded.Postgres.PeerCRLSourceMappingDigest != composed.PeerSources.Digest() ||
		decoded.Materials.Provider.Type != config.UnixWorkloadMaterialProviderV2 ||
		decoded.Materials.Provider.Alias != material.AgentDeployment ||
		decoded.Materials.Provider.SocketPath != material.SocketPath ||
		decoded.Materials.Provider.ExpectedUID != int64(material.AgentUID) ||
		decoded.Materials.Provider.ExpectedGID != int64(material.AgentGID) ||
		decoded.Materials.Provider.DirectoryGID != int64(material.OwnerGID) ||
		decoded.Materials.Provider.OperationTimeoutSeconds > material.MaxOperationSeconds {
		return errors.New("Provider migration startup authority differs")
	}
	var owner phase6security.Principal
	for _, principal := range profile.Principals {
		if principal.Name == job {
			owner = principal
		}
	}
	role, err := phase6security.DecodePeerCRLRoleDocument(files[phase6security.Slice6PostgresPeerCRLRoleFile],
		profile, composed.PeerSources.Digest(), decoded.Postgres.PeerCRLRoleDigest)
	if err != nil || role.ValidateForPrincipal(profile, composed.PeerSources.Digest(), owner.PrincipalDigest) != nil ||
		len(role.Edges) != 1 || role.Edges[0].EdgeID != authority.PeerEdgeID ||
		role.Edges[0].Direction != "outbound" || role.Edges[0].PeerAnchorID != authority.ServerAnchor.ID {
		return errors.New("Provider migration peer role differs")
	}
	access, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		return errors.New("Provider migration material access unavailable")
	}
	bindings, err := decoded.Materials.DecodeBindings(secretref.RoleProvider)
	if err != nil || len(bindings) != 1 {
		return errors.New("Provider migration material bindings invalid")
	}
	for _, item := range access {
		if item.Owner == job && item.Agent == material.AgentDeployment && item.Migration &&
			item.Role == secretref.RoleProvider && len(item.Bindings) == 1 &&
			bindings[decoded.Postgres.DSNBindingID] == item.Bindings[0] {
			return nil
		}
	}
	return errors.New("Provider migration material binding differs")
}
