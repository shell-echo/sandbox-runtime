//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

// The field order mirrors the production v2 material-agent decoder's closed
// canonical document. This is a private, source-derived startup input only.
type slice6GuestMaterialAgentConfig struct {
	Protocol                         string              `json:"protocol"`
	SocketPath                       string              `json:"socket_path"`
	SocketUID                        uint32              `json:"socket_uid"`
	SocketGID                        uint32              `json:"socket_gid"`
	ExpectedClientUID                uint32              `json:"expected_client_uid"`
	ExpectedClientGID                uint32              `json:"expected_client_gid"`
	Role                             secretref.Role      `json:"role"`
	MaxConnections                   int                 `json:"max_connections"`
	MaxResolutions                   int                 `json:"max_resolutions"`
	Migration                        bool                `json:"migration"`
	CredentialControllerSocket       string              `json:"credential_controller_socket"`
	CredentialControllerUID          uint32              `json:"credential_controller_uid"`
	CredentialControllerGID          uint32              `json:"credential_controller_gid"`
	CredentialAgentID                string              `json:"credential_agent_id"`
	CredentialPolicyID               string              `json:"credential_policy_id"`
	CredentialBackendID              string              `json:"credential_backend_id"`
	CredentialTTLSeconds             int                 `json:"credential_ttl_seconds"`
	CredentialBinding                secretref.Binding   `json:"credential_binding"`
	VaultEndpoint                    string              `json:"vault_endpoint"`
	VaultCABundle                    []byte              `json:"vault_ca_bundle"`
	VaultServerName                  string              `json:"vault_server_name"`
	VaultMount                       string              `json:"vault_mount"`
	VaultReferenceAuthority          string              `json:"vault_reference_authority"`
	OperationTimeoutSeconds          int                 `json:"operation_timeout_seconds"`
	Bindings                         []secretref.Binding `json:"bindings"`
	BreakGlassSocket                 string              `json:"break_glass_socket"`
	BreakGlassControllerSocket       string              `json:"break_glass_controller_socket"`
	BreakGlassControllerUID          uint32              `json:"break_glass_controller_uid"`
	BreakGlassControllerGID          uint32              `json:"break_glass_controller_gid"`
	ExpectedOperatorUID              uint32              `json:"expected_operator_uid"`
	ExpectedOperatorGID              uint32              `json:"expected_operator_gid"`
	SecurityProfilePath              string              `json:"security_profile_path"`
	SecurityProfileDigest            string              `json:"security_profile_digest"`
	CredentialBackendPolicy          string              `json:"credential_backend_policy"`
	CredentialMaxTTLSeconds          int                 `json:"credential_max_ttl_seconds"`
	VaultTLSAgentSocket              string              `json:"vault_tls_agent_socket"`
	VaultTLSAgentUID                 uint32              `json:"vault_tls_agent_uid"`
	VaultTLSAgentGID                 uint32              `json:"vault_tls_agent_gid"`
	BreakGlassSocketGID              uint32              `json:"break_glass_socket_gid"`
	BreakGlassControllerDirectoryGID uint32              `json:"break_glass_controller_directory_gid"`
}

// These allocations are the exact two private configuration readers and the
// two server-owned sockets needed before starting either Guest agent. Existing
// controller/break-glass directories are reused, never aliased or recreated.
func slice6PrepareGuestAgentInputs(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, existing map[string]string) map[string]string {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil || len(existing) != 65 {
		t.Fatal("Guest agent input preparation needs complete source-bound socket supply")
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal("encode Guest agent Profile")
	}
	peerBytes, err := json.Marshal(composed.PeerSources)
	if err != nil {
		clear(profileBytes)
		t.Fatal("encode Guest TLS-agent peer sources")
	}
	defer clear(profileBytes)
	defer clear(peerBytes)
	for _, target := range []struct {
		deployment string
		files      map[string][]byte
	}{
		{"guest-agent-tls-agent", map[string][]byte{
			phase6security.Slice6ProfileConfigFile:  profileBytes,
			phase6security.Slice6PeerCRLSourcesFile: peerBytes,
		}},
		{"guest-agent", map[string][]byte{phase6security.Slice6ProfileConfigFile: profileBytes}},
	} {
		archive, buildErr := phase6security.BuildSlice6PrivateConfigArchive(profile, target.deployment, target.files)
		if buildErr != nil {
			t.Fatalf("prepare %s private config: %v", target.deployment, buildErr)
		}
		slice6PrepareOneControllerPrivateConfig(t, ctx, run, profile, target.deployment, archive)
	}
	tlsBinding, signer, subject, err := profile.TLSAgentForSubject("guest-agent")
	material, materialErr := profile.Slice6MaterialSocketForOwner("guest-runtime")
	if err != nil || materialErr != nil || signer.Name != "guest-agent-tls-agent" ||
		subject.Name != "guest-agent" || material.AgentDeployment != subject.Name ||
		tlsBinding.AgentUID != signer.UID || tlsBinding.AgentGID != signer.GID ||
		tlsBinding.SubjectUID != subject.UID || tlsBinding.SubjectGID != subject.GID ||
		tlsBinding.DirectoryMode != 0o710 || material.DirectoryMode != 0o710 ||
		tlsBinding.SocketStorageID == material.SocketStorageID ||
		existing[tlsBinding.SocketStorageID] != "" || existing[material.SocketStorageID] != "" {
		t.Fatal("Guest signer/material socket authority drift")
	}
	result := make(map[string]string, len(existing)+2)
	for storageID, volume := range existing {
		result[storageID] = volume
	}
	result[tlsBinding.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		tlsBinding.SocketStorageID, tlsBinding.SocketDirectory,
		tlsBinding.AgentUID, tlsBinding.SubjectGID, tlsBinding.DirectoryMode)
	result[material.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		material.SocketStorageID, material.SocketDirectory,
		material.AgentUID, material.OwnerGID, material.DirectoryMode)
	if len(result) != 67 {
		t.Fatal("Guest agent socket allocation count drift")
	}
	return result
}

func slice6BuildGuestMaterialAgentConfig(composed slice6VaultComposedInputs) ([]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil {
		return nil, errors.New("Guest material-agent Profile unavailable")
	}
	var access phase6security.Slice6MaterialAccess
	plan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		return nil, err
	}
	for _, candidate := range plan {
		if candidate.Agent == "guest-agent" {
			access = candidate
		}
	}
	material, err := profile.Slice6MaterialSocketForOwner("guest-runtime")
	issuer, controller, agent, errIssuer := profile.CredentialIssuerSocketForClient("guest-agent")
	tlsBinding, signer, tlsSubject, errTLS := profile.TLSAgentForSubject("guest-agent")
	var delivery, consume phase6security.Slice6BreakGlassSocketBinding
	for _, binding := range profile.BreakGlassSockets {
		if binding.TargetAgent == "guest-agent" {
			switch binding.Kind {
			case "delivery":
				delivery = binding
			case "consume":
				consume = binding
			}
		}
	}
	address, errAddress := phase6security.Slice6DesiredServiceEndpointAddress("service-guest-agent-vault", "vault")
	if err != nil || errIssuer != nil || errTLS != nil || errAddress != nil ||
		access.Agent != agent.Name || access.Owner != "guest-runtime" || access.Migration ||
		access.Role != secretref.RoleGuest || len(access.Bindings) != 1 ||
		access.Bindings[0].Purpose != secretref.PurposeGuestSigningKey ||
		material.AgentDeployment != agent.Name || material.AgentUID != agent.UID ||
		material.AgentGID != agent.GID || material.OwnerGID == agent.GID ||
		issuer.SocketPath != access.CredentialSocket || controller.Name != "workload-credential-controller" ||
		tlsSubject.Name != agent.Name || signer.Name != "guest-agent-tls-agent" ||
		delivery.ServerDeployment != agent.Name || consume.ClientDeployment != agent.Name ||
		delivery.ClientUID == agent.UID || consume.ServerUID == agent.UID ||
		!slices.Contains(agent.Networks, "service-guest-agent-vault") {
		return nil, errors.New("Guest material-agent source authority drift")
	}
	credential := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://phase6/credential/guest_agent", Version: "v1",
		Purpose: secretref.PurposeWorkloadCredential, TenantID: secretref.SystemTenant, Role: secretref.RoleGuest}
	if credential.Validate() != nil {
		return nil, errors.New("Guest credential binding unavailable")
	}
	config := slice6GuestMaterialAgentConfig{
		Protocol:   "sandbox-runtime.workload-material-agent-config.v2",
		SocketPath: material.SocketPath, SocketUID: material.AgentUID, SocketGID: material.OwnerGID,
		ExpectedClientUID: material.OwnerUID, ExpectedClientGID: material.OwnerGID,
		Role: access.Role, MaxConnections: material.MaxConnections, MaxResolutions: 0, Migration: false,
		CredentialControllerSocket: issuer.SocketPath,
		CredentialControllerUID:    controller.UID, CredentialControllerGID: controller.GID,
		CredentialAgentID: agent.Name, CredentialPolicyID: access.CredentialPolicyID,
		CredentialBackendID: "vault-primary", CredentialTTLSeconds: 600,
		CredentialBinding: credential,
		VaultEndpoint:     "https://" + net.JoinHostPort(address, "8200"),
		VaultServerName:   "vault.sandbox-runtime.test", VaultMount: "kv", VaultReferenceAuthority: "phase6",
		OperationTimeoutSeconds: 15, Bindings: slices.Clone(access.Bindings),
		BreakGlassSocket: delivery.SocketPath, BreakGlassControllerSocket: consume.SocketPath,
		BreakGlassControllerUID: consume.ServerUID, BreakGlassControllerGID: consume.ServerGID,
		ExpectedOperatorUID: delivery.ClientUID, ExpectedOperatorGID: delivery.ClientGID,
		SecurityProfilePath: "/run/phase6/config/profile.json", SecurityProfileDigest: profile.ProfileDigest,
		CredentialBackendPolicy: access.BackendPolicy, CredentialMaxTTLSeconds: 900,
		VaultTLSAgentSocket: tlsBinding.SocketPath, VaultTLSAgentUID: tlsBinding.AgentUID,
		VaultTLSAgentGID: tlsBinding.AgentGID, BreakGlassSocketGID: delivery.ClientGID,
		BreakGlassControllerDirectoryGID: consume.ClientGID,
	}
	return json.Marshal(config)
}
