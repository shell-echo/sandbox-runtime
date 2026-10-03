//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/shell-echo/sandbox-runtime/config"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/roleprocess"
	"github.com/spf13/viper"
)

// A live caller must build these inputs only after Product has durably
// provisioned the matching Guest binding. Offline tests use a synthetic ID
// without claiming that binding. This constructor creates no secret, Docker
// resource or issuer request; actual image bytes are checked at PID1.
func slice6BuildGuestRuntimeInputs(composed slice6VaultComposedInputs, runID, guestID string,
	bindingGeneration int64, toolchainDigest string) (map[string][]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil ||
		composed.PeerSources.Validate(profile) != nil ||
		len(runID) != 32 || !lowerHexSlice6(runID) || guestID == "" ||
		bindingGeneration < 1 || len(toolchainDigest) != len("sha256:")+64 ||
		!strings.HasPrefix(toolchainDigest, "sha256:") || !lowerHexSlice6(strings.TrimPrefix(toolchainDigest, "sha256:")) {
		return nil, errors.New("Guest runtime source or binding unavailable")
	}
	var guest phase6security.Principal
	for _, principal := range profile.Principals {
		if principal.Name == "guest-runtime" {
			guest = principal
		}
	}
	var origin string
	for _, candidate := range profile.TrustEdges {
		if candidate.ID == "guest-product" {
			origin = "wss://" + candidate.TargetAddress + candidate.RoutePath
		}
	}
	if _, _, _, _, _, err := profile.GuestProductBoundary(origin); err != nil ||
		guest.Name != "guest-runtime" ||
		phase6security.VerifySlice6GuestStorageMounts(profile) != nil {
		return nil, errors.New("Guest Product edge or storage unavailable")
	}
	peerRole, err := phase6security.DerivePeerCRLRoleDocument(profile, composed.PeerSources, guest.PrincipalDigest)
	material, materialErr := profile.Slice6MaterialSocketForOwner(guest.Name)
	tlsBinding, tlsAgent, tlsSubject, tlsErr := profile.TLSAgentForSubject(guest.Name)
	access, accessErr := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	var signing secretref.Binding
	for _, entry := range access {
		if entry.Agent == "guest-agent" && entry.Owner == guest.Name && len(entry.Bindings) == 1 {
			signing = entry.Bindings[0]
		}
	}
	if err != nil || materialErr != nil || tlsErr != nil || accessErr != nil ||
		len(peerRole.Edges) != 1 || peerRole.Edges[0].EdgeID != "guest-product" ||
		material.AgentDeployment != "guest-agent" || material.OwnerDeployment != guest.Name ||
		tlsAgent.Name != "guest-tls-agent" ||
		tlsSubject.Name != guest.Name || signing.Purpose != secretref.PurposeGuestSigningKey ||
		signing.Role != secretref.RoleGuest || signing.TenantID != secretref.SystemTenant || signing.Validate() != nil {
		return nil, errors.New("Guest signing, TLS or peer authority drift")
	}
	const signingID = "guest-signing-key"
	credential := roleprocess.GuestCredentialAuthority{Version: 3, Role: string(config.DataPlaneGuest),
		GuestID: guestID, BindingGeneration: bindingGeneration, PrivateKeyBindingID: signingID}
	dependency := roleprocess.GuestDependencyAuthority{Version: 3, Role: string(config.DataPlaneGuest),
		WorkspaceRoot: phase6security.Slice6GuestWorkspaceRoot,
		StateRoot:     phase6security.Slice6GuestStateRoot, StorageIdentity: runID,
		Mounts: []guestdevelopment.Mount{
			{Path: phase6security.Slice6GuestInputsRoot, Mode: "ro"},
			{Path: phase6security.Slice6GuestWorkspaceRoot, Mode: "rw"},
			{Path: phase6security.Slice6GuestOutputsRoot, Mode: "rw"},
			{Path: phase6security.Slice6GuestTempRoot, Mode: "rw"},
		},
		Toolchains: []guestdevelopment.Toolchain{{ID: "posix-shell", Version: "1.37.0",
			Executable: "/bin/sh", Digest: toolchainDigest}},
	}
	policy := roleprocess.GuestPolicyAuthority{Version: 3, Role: string(config.DataPlaneGuest), ReconnectBackoffMillis: 250}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	peerBytes, err := json.Marshal(peerRole)
	if err != nil {
		return nil, err
	}
	credentialBytes, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}
	dependencyBytes, err := json.Marshal(dependency)
	if err != nil {
		return nil, err
	}
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	signingBytes, err := json.Marshal(signing)
	if err != nil {
		return nil, err
	}
	startup := []byte(fmt.Sprintf(`[application]
mode = "production"

[guest_process]
schema_version = %q
enabled = true
deployment_level = "production"
outbound_url = %q

[guest_process.public]
host = "127.0.0.1"
port = 0

[guest_process.private]
host = "127.0.0.1"
port = 0

[guest_process.probe]
host = "127.0.0.1"
port = 8086

[guest_process.drain]
grace_seconds = 30
reconnect_seconds = 30
dependency_timeout_seconds = 5

[guest_process.authority]
credential_file = "/run/phase6/config/credential-authority.json"
dependency_file = "/run/phase6/config/dependency-authority.json"
policy_file = "/run/phase6/config/policy-authority.json"
recording_key_reference = %q

[guest_process.tls]
security_profile_path = "/run/phase6/config/profile.json"
security_profile_digest = %q
peer_crl_role_file = "/run/phase6/config/peer-crl-role.json"
peer_crl_role_digest = %q
peer_crl_source_mapping_digest = %q
agent_socket = %q
agent_uid = %d
agent_gid = %d
operation_timeout_millis = 15000

[guest_process.materials.provider]
type = %q
alias = "guest-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
directory_gid = %d
operation_timeout_seconds = 15
cache_seconds = 30

[[guest_process.materials.bindings]]
id = %q
provider = "guest-agent"
document = %q
`, config.DataPlaneProductionSchemaV3, origin, config.GuestV3NoRecordingReference, profile.ProfileDigest, peerRole.Digest(),
		composed.PeerSources.Digest(), tlsBinding.SocketPath, tlsBinding.AgentUID, tlsBinding.AgentGID,
		config.UnixWorkloadMaterialProviderV2, material.SocketPath, material.AgentUID,
		material.AgentGID, material.OwnerGID, signingID, string(signingBytes)))
	if len(startup) > 64<<10 || bytes.Contains(startup, []byte("PRIVATE KEY")) ||
		bytes.Contains(startup, []byte("postgres://")) {
		return nil, errors.New("Guest startup authority is oversized or contains secret material")
	}
	parser := viper.New()
	parser.SetConfigType("toml")
	if parser.ReadConfig(bytes.NewReader(startup)) != nil {
		return nil, errors.New("Guest startup TOML invalid")
	}
	var decoded config.DataPlaneProcessConfig
	section := parser.Sub("guest_process")
	if section == nil || section.UnmarshalExact(&decoded) != nil {
		return nil, errors.New("Guest startup TOML does not decode")
	}
	decoded.Role = config.DataPlaneGuest
	if decoded.Validate() != nil || decoded.OutboundURL != origin ||
		decoded.TLS.SecurityProfileDigest != profile.ProfileDigest ||
		decoded.TLS.PeerCRLRoleDigest != peerRole.Digest() {
		return nil, errors.New("Guest startup TOML authority mismatch")
	}
	files := map[string][]byte{
		phase6security.Slice6ProfileConfigFile:       profileBytes,
		phase6security.Slice6PeerCRLRoleFile:         peerBytes,
		phase6security.Slice6StartupConfigFile:       startup,
		phase6security.Slice6CredentialAuthorityFile: credentialBytes,
		phase6security.Slice6DependencyAuthorityFile: dependencyBytes,
		phase6security.Slice6PolicyAuthorityFile:     policyBytes,
	}
	if _, err := phase6security.BuildSlice6PrivateConfigArchive(profile, guest.Name, files); err != nil {
		return nil, errors.New("Guest private startup file inventory mismatch")
	}
	return files, nil
}
