//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ProductTLSSignerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_TLS_SIGNER"
const slice6ProductMaterialInputsEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_MATERIAL_INPUTS"

// This is a prerequisite component for the formal Product/Guest command gate,
// not a Product process or a Guest security-edge observation.
func slice6PrepareProductTLSAgentInputs(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, existing map[string]string) map[string]string {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil || len(existing) != 67 {
		t.Fatal("Product signer input preparation needs complete source-bound Guest socket supply")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject("product-runtime")
	if err != nil || agent.Name != "product-tls-agent" || subject.Name != "product-runtime" ||
		binding.AgentUID != agent.UID || binding.AgentGID != agent.GID ||
		binding.SubjectUID != subject.UID || binding.SubjectGID != subject.GID ||
		binding.DirectoryMode != 0o710 || existing[binding.SocketStorageID] != "" ||
		existing[binding.ControllerSocketStorageID] == "" ||
		!slices.Equal(agent.Networks, []string{"network-product-tls-agent"}) {
		t.Fatal("Product runtime TLS signer authority drift")
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	peerBytes, err := json.Marshal(composed.PeerSources)
	if err != nil {
		clear(profileBytes)
		t.Fatal(err)
	}
	defer clear(profileBytes)
	defer clear(peerBytes)
	archive, err := phase6security.BuildSlice6PrivateConfigArchive(profile, agent.Name,
		map[string][]byte{
			phase6security.Slice6ProfileConfigFile:  profileBytes,
			phase6security.Slice6PeerCRLSourcesFile: peerBytes,
		})
	if err != nil {
		t.Fatal("Product signer private config unavailable")
	}
	slice6PrepareOneControllerPrivateConfig(t, ctx, run, profile, agent.Name, archive)
	result := make(map[string]string, len(existing)+1)
	for storageID, volume := range existing {
		result[storageID] = volume
	}
	result[binding.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		binding.SocketStorageID, binding.SocketDirectory, binding.AgentUID,
		binding.SubjectGID, binding.DirectoryMode)
	if len(result) != 68 {
		t.Fatal("Product signer socket allocation count drift")
	}
	return result
}

// The Product material agent has its own managed TLS signer and owner-only
// material socket. Both are separate from the Product runtime signer and the
// Guest sockets; this preparation does not launch either process.
func slice6PrepareProductMaterialAgentInputs(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, existing map[string]string) map[string]string {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil || len(existing) != 68 {
		t.Fatal("Product material-agent input preparation needs complete source-bound socket supply")
	}
	tlsBinding, signer, agent, tlsErr := profile.TLSAgentForSubject("product-runtime-agent")
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-runtime")
	if tlsErr != nil || materialErr != nil || signer.Name != "product-runtime-agent-tls-agent" ||
		agent.Name != "product-runtime-agent" || material.AgentDeployment != agent.Name ||
		tlsBinding.AgentUID != signer.UID || tlsBinding.AgentGID != signer.GID ||
		tlsBinding.SubjectUID != agent.UID || tlsBinding.SubjectGID != agent.GID ||
		tlsBinding.DirectoryMode != 0o710 || material.DirectoryMode != 0o710 ||
		tlsBinding.SocketStorageID == material.SocketStorageID ||
		existing[tlsBinding.SocketStorageID] != "" || existing[material.SocketStorageID] != "" ||
		existing[tlsBinding.ControllerSocketStorageID] == "" ||
		!slices.Equal(signer.Networks, []string{"network-product-runtime-agent-tls-agent"}) {
		t.Fatal("Product material signer/socket authority drift")
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	peerBytes, err := json.Marshal(composed.PeerSources)
	if err != nil {
		clear(profileBytes)
		t.Fatal(err)
	}
	defer clear(profileBytes)
	defer clear(peerBytes)
	for _, target := range []struct {
		deployment string
		files      map[string][]byte
	}{
		{signer.Name, map[string][]byte{
			phase6security.Slice6ProfileConfigFile:  profileBytes,
			phase6security.Slice6PeerCRLSourcesFile: peerBytes,
		}},
		{agent.Name, map[string][]byte{phase6security.Slice6ProfileConfigFile: profileBytes}},
	} {
		archive, buildErr := phase6security.BuildSlice6PrivateConfigArchive(profile, target.deployment, target.files)
		if buildErr != nil {
			t.Fatal("Product material-agent private config unavailable")
		}
		slice6PrepareOneControllerPrivateConfig(t, ctx, run, profile, target.deployment, archive)
	}
	result := make(map[string]string, len(existing)+2)
	for storageID, volume := range existing {
		result[storageID] = volume
	}
	result[tlsBinding.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		tlsBinding.SocketStorageID, tlsBinding.SocketDirectory, tlsBinding.AgentUID,
		tlsBinding.SubjectGID, tlsBinding.DirectoryMode)
	result[material.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		material.SocketStorageID, material.SocketDirectory, material.AgentUID,
		material.OwnerGID, material.DirectoryMode)
	if len(result) != 70 {
		t.Fatal("Product material-agent socket allocation count drift")
	}
	return result
}
