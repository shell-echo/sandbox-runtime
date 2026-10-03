//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

// The field order mirrors the production v2 material-agent decoder's closed
// canonical document. This is a private, source-derived startup input only.
type slice6MaterialAgentConfig struct {
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

// The Guest runtime owns a different signer from its material agent. This
// closed projection checks the complete prior 67-directory supply, then
// reserves only the existing Profile's guest-tls-agent subject socket.
func slice6GuestRuntimeTLSInputPlan(profile phase6security.Profile, runID string,
	existing map[string]string) (phase6security.TLSAgentBinding, error) {
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil ||
		len(runID) != 32 || !lowerHexSlice6(runID) {
		return phase6security.TLSAgentBinding{}, errors.New("Guest runtime TLS Profile unavailable")
	}
	plan, err := slice6BuildGuestRuntimeLaunchPlan(profile)
	binding, signer, subject, signerErr := profile.TLSAgentForSubject("guest-runtime")
	guestAgent, materialSigner, materialSubject, guestAgentErr := profile.TLSAgentForSubject("guest-agent")
	material, materialErr := profile.Slice6MaterialSocketForOwner("guest-runtime")
	if err != nil || signerErr != nil || guestAgentErr != nil || materialErr != nil ||
		signer.Name != "guest-tls-agent" || subject.Name != "guest-runtime" ||
		materialSigner.Name != "guest-agent-tls-agent" || materialSubject.Name != "guest-agent" ||
		material.AgentDeployment != materialSubject.Name || material.OwnerDeployment != subject.Name ||
		binding.SocketStorageID != plan.TLSSocketID || material.SocketStorageID != plan.MaterialSocketID ||
		binding.SocketStorageID == guestAgent.SocketStorageID ||
		binding.SocketStorageID == material.SocketStorageID ||
		binding.ControllerSocketStorageID == guestAgent.ControllerSocketStorageID ||
		binding.AgentUID != signer.UID || binding.AgentGID != signer.GID ||
		binding.SubjectUID != subject.UID || binding.SubjectGID != subject.GID ||
		binding.DirectoryMode != 0o710 || binding.ControllerDirectoryMode != 0o710 ||
		guestAgent.SocketStorageID == material.SocketStorageID ||
		len(existing) != 67 || existing[binding.SocketStorageID] != "" {
		return phase6security.TLSAgentBinding{}, errors.New("Guest runtime TLS signer boundary drift")
	}
	expected := make(map[string]bool, 67)
	add := func(id string) bool {
		if id == "" || expected[id] {
			return false
		}
		expected[id] = true
		return true
	}
	for _, issuer := range profile.CredentialIssuerSockets {
		if !add(issuer.SocketStorageID) {
			return phase6security.TLSAgentBinding{}, errors.New("Guest prior credential socket inventory drift")
		}
	}
	if !add(profile.CertificateController.CredentialController.SocketStorageID) ||
		!add(profile.CertificateController.SelfSocketStorageID) {
		return phase6security.TLSAgentBinding{}, errors.New("Guest prior controller socket inventory drift")
	}
	for _, agent := range profile.TLSAgentBindings {
		if !add(agent.ControllerSocketStorageID) {
			return phase6security.TLSAgentBinding{}, errors.New("Guest prior certificate socket inventory drift")
		}
	}
	for _, agent := range profile.PostgresClientAgents {
		if !add(agent.ControllerSocketStorageID) {
			return phase6security.TLSAgentBinding{}, errors.New("Guest prior PostgreSQL certificate socket inventory drift")
		}
	}
	for _, socket := range profile.BreakGlassSockets {
		if !add(socket.SocketStorageID) {
			return phase6security.TLSAgentBinding{}, errors.New("Guest prior break-glass socket inventory drift")
		}
	}
	if !add(guestAgent.SocketStorageID) || !add(material.SocketStorageID) ||
		len(expected) != 67 || !expected[binding.ControllerSocketStorageID] {
		return phase6security.TLSAgentBinding{}, errors.New("Guest prior agent socket inventory drift")
	}
	values := make(map[string]bool, 67)
	for id, volume := range existing {
		if !expected[id] || volume != "sr-p6-socket-"+id+"-"+runID || values[volume] {
			return phase6security.TLSAgentBinding{}, errors.New("Guest prior socket missing or aliased")
		}
		values[volume] = true
	}
	return binding, nil
}

func slice6PrepareGuestRuntimeTLSAgentInputs(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, existing map[string]string) map[string]string {
	t.Helper()
	binding, err := slice6GuestRuntimeTLSInputPlan(composed.Profile, run.id, existing)
	if err != nil {
		t.Fatal(err)
	}
	guestAgent, _, _, _ := composed.Profile.TLSAgentForSubject("guest-agent")
	material, _ := composed.Profile.Slice6MaterialSocketForOwner("guest-runtime")
	for _, storageID := range []string{binding.ControllerSocketStorageID, guestAgent.SocketStorageID, material.SocketStorageID} {
		if err := slice6VerifyGuestFixtureVolume(ctx, run, existing[storageID]); err != nil {
			t.Fatal("Guest runtime TLS prior exact socket volume unavailable")
		}
	}
	config, err := slice6BuildOrdinaryTLSAgentConfig(composed, "guest-runtime", "guest-tls-agent")
	if err != nil || len(config) == 0 {
		t.Fatal("Guest runtime TLS signer configuration unavailable")
	}
	clear(config)
	profileBytes, err := json.Marshal(composed.Profile)
	if err != nil {
		t.Fatal("Guest runtime TLS signer Profile unavailable")
	}
	peerBytes, err := json.Marshal(composed.PeerSources)
	if err != nil {
		clear(profileBytes)
		t.Fatal("Guest runtime TLS signer peer-CRL sources unavailable")
	}
	defer clear(profileBytes)
	defer clear(peerBytes)
	archive, err := phase6security.BuildSlice6PrivateConfigArchive(composed.Profile, "guest-tls-agent",
		map[string][]byte{phase6security.Slice6ProfileConfigFile: profileBytes,
			phase6security.Slice6PeerCRLSourcesFile: peerBytes})
	if err != nil {
		t.Fatal("Guest runtime TLS signer private config unavailable")
	}
	slice6PrepareOneControllerPrivateConfig(t, ctx, run, composed.Profile, "guest-tls-agent", archive)
	result := make(map[string]string, 68)
	for id, volume := range existing {
		result[id] = volume
	}
	result[binding.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		binding.SocketStorageID, binding.SocketDirectory, binding.AgentUID, binding.SubjectGID,
		binding.DirectoryMode)
	if len(result) != 68 || result[binding.SocketStorageID] == result[material.SocketStorageID] ||
		result[binding.SocketStorageID] == result[guestAgent.SocketStorageID] {
		t.Fatal("Guest runtime TLS signer socket was not independently allocated")
	}
	return result
}

func slice6BuildGuestMaterialAgentConfig(composed slice6VaultComposedInputs) ([]byte, error) {
	return slice6BuildRuntimeMaterialAgentConfig(composed, "guest-agent", "guest-runtime", secretref.RoleGuest,
		[]secretref.Purpose{secretref.PurposeGuestSigningKey})
}

func slice6BuildRuntimeMaterialAgentConfig(composed slice6VaultComposedInputs,
	agentDeployment, ownerDeployment string, role secretref.Role, purposes []secretref.Purpose) ([]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil {
		return nil, errors.New("material-agent Profile unavailable")
	}
	migration := agentDeployment == "product-migration-agent"
	if (agentDeployment != "guest-agent" || ownerDeployment != "guest-runtime" || role != secretref.RoleGuest ||
		!slices.Equal(purposes, []secretref.Purpose{secretref.PurposeGuestSigningKey})) &&
		(agentDeployment != "product-runtime-agent" || ownerDeployment != "product-runtime" || role != secretref.RoleProduct ||
			!slices.Equal(purposes, []secretref.Purpose{secretref.PurposeIdentityKeyRing, secretref.PurposePostgresRuntimeDSN})) &&
		(!migration || ownerDeployment != "product-migration-job" || role != secretref.RoleProduct ||
			!slices.Equal(purposes, []secretref.Purpose{secretref.PurposePostgresMigrationDSN})) {
		return nil, errors.New("unsupported runtime material-agent owner")
	}
	var access phase6security.Slice6MaterialAccess
	plan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		return nil, err
	}
	for _, candidate := range plan {
		if candidate.Agent == agentDeployment {
			access = candidate
		}
	}
	material, err := profile.Slice6MaterialSocketForOwner(ownerDeployment)
	issuer, controller, agent, errIssuer := profile.CredentialIssuerSocketForClient(agentDeployment)
	tlsBinding, signer, tlsSubject, errTLS := profile.TLSAgentForSubject(agentDeployment)
	var delivery, consume phase6security.Slice6BreakGlassSocketBinding
	for _, binding := range profile.BreakGlassSockets {
		if binding.TargetAgent == agentDeployment {
			switch binding.Kind {
			case "delivery":
				delivery = binding
			case "consume":
				consume = binding
			}
		}
	}
	serviceNetwork := "service-" + agentDeployment + "-vault"
	address, errAddress := phase6security.Slice6DesiredServiceEndpointAddress(serviceNetwork, "vault")
	if err != nil || errIssuer != nil || errTLS != nil || errAddress != nil ||
		access.Agent != agent.Name || access.Owner != ownerDeployment || access.Migration != migration ||
		access.Role != role || len(access.Bindings) != len(purposes) ||
		material.AgentDeployment != agent.Name || material.AgentUID != agent.UID ||
		material.AgentGID != agent.GID || material.OwnerGID == agent.GID ||
		issuer.SocketPath != access.CredentialSocket || controller.Name != "workload-credential-controller" ||
		tlsSubject.Name != agent.Name || signer.Name != agent.Name+"-tls-agent" ||
		!slices.Contains(agent.Networks, serviceNetwork) {
		return nil, errors.New("material-agent source authority drift")
	}
	if migration {
		if delivery.ID != "" || consume.ID != "" {
			return nil, errors.New("migration material-agent gained break-glass authority")
		}
	} else if delivery.ServerDeployment != agent.Name || consume.ClientDeployment != agent.Name ||
		delivery.ClientUID == agent.UID || consume.ServerUID == agent.UID {
		return nil, errors.New("runtime material-agent break-glass authority drift")
	}
	for index, purpose := range purposes {
		if access.Bindings[index].Purpose != purpose {
			return nil, errors.New("material-agent purpose ordering drift")
		}
	}
	credential := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: secretref.Reference("secret://phase6/credential/" + strings.ReplaceAll(agent.Name, "-", "_")), Version: "v1",
		Purpose: secretref.PurposeWorkloadCredential, TenantID: secretref.SystemTenant, Role: role}
	if credential.Validate() != nil {
		return nil, errors.New("material-agent credential binding unavailable")
	}
	config := slice6MaterialAgentConfig{
		Protocol:   "sandbox-runtime.workload-material-agent-config.v2",
		SocketPath: material.SocketPath, SocketUID: material.AgentUID, SocketGID: material.OwnerGID,
		ExpectedClientUID: material.OwnerUID, ExpectedClientGID: material.OwnerGID,
		Role: access.Role, MaxConnections: material.MaxConnections, MaxResolutions: 0, Migration: migration,
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
	if migration {
		config.MaxResolutions = 1
	}
	return json.Marshal(config)
}

func slice6BuildProductMigrationMaterialAgentConfig(composed slice6VaultComposedInputs) ([]byte, error) {
	return slice6BuildRuntimeMaterialAgentConfig(composed, "product-migration-agent",
		"product-migration-job", secretref.RoleProduct,
		[]secretref.Purpose{secretref.PurposePostgresMigrationDSN})
}
