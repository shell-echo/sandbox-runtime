//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ProductRuntimeInputsEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_RUNTIME_INPUTS"

// This extends the already prepared migration input set by exactly one
// purpose-specific runtime PostgreSQL signer socket. It does not launch the
// Product runtime or change the independent migration-job authority.
func slice6PrepareProductRuntimeInputs(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, existing map[string]string) map[string]string {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil || len(existing) != 73 {
		t.Fatal("Product runtime input preparation requires the complete migration socket supply")
	}
	binding, target, agent, owner, _, err := profile.PostgresClientSignerForOwner("product-runtime")
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-runtime")
	publicTLS, publicAgent, _, publicErr := profile.TLSAgentForSubject("product-runtime")
	if err != nil || materialErr != nil || publicErr != nil ||
		target.AgentDeployment != "product-postgres-tls-agent" || target.SubjectDeployment != "product-runtime" ||
		target.DatabaseName != "product" || target.SQLRole != "product_runtime" || target.Migration ||
		agent.Name != target.AgentDeployment || owner.Name != target.SubjectDeployment ||
		binding.SubjectUID != owner.UID || binding.SubjectGID != owner.GID ||
		binding.AgentUID != agent.UID || binding.AgentGID != agent.GID ||
		binding.DirectoryMode != 0o710 || existing[binding.SocketStorageID] != "" ||
		existing[binding.ControllerSocketStorageID] == "" ||
		existing[material.SocketStorageID] == "" || existing[publicTLS.SocketStorageID] == "" ||
		publicAgent.Name != "product-tls-agent" ||
		!slices.Equal(agent.Networks, []string{"network-product-postgres-tls-agent"}) {
		t.Fatal("Product runtime PostgreSQL signer or existing socket authority drift")
	}
	privateMount, present := phase6security.Slice6PrivateConfigMount(owner.Name)
	if !present || privateMount.Target != phase6security.Slice6PrivateConfigDirectory ||
		!slices.Equal(strings.Split(privateMount.PrivateFiles, ","), []string{
			phase6security.Slice6PeerCRLRoleFile,
			phase6security.Slice6PostgresPeerCRLRoleFile,
			phase6security.Slice6ProfileConfigFile,
			phase6security.Slice6StartupConfigFile,
		}) {
		t.Fatal("Product runtime private startup file purposes drift")
	}
	allowedSockets := map[string]bool{
		binding.SocketStorageID: true, material.SocketStorageID: true, publicTLS.SocketStorageID: true,
	}
	privateSocketCount := 0
	for _, mount := range owner.Mounts {
		if mount.Kind != "private_socket" {
			continue
		}
		if !allowedSockets[mount.StorageID] || !mount.ReadOnly || existing[mount.StorageID] == "" &&
			mount.StorageID != binding.SocketStorageID {
			t.Fatal("Product runtime private socket mount authority drift")
		}
		privateSocketCount++
	}
	if privateSocketCount != len(allowedSockets) {
		t.Fatal("Product runtime private socket count drift")
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
	peerRole, err := phase6security.DerivePeerCRLRoleDocument(profile, composed.PeerSources, owner.Name)
	if err != nil || len(peerRole.Edges) == 0 {
		clear(profileBytes)
		clear(peerBytes)
		t.Fatal("Product runtime private peer CRL role unavailable")
	}
	peerRoleBytes, err := json.Marshal(peerRole)
	if err != nil {
		clear(profileBytes)
		clear(peerBytes)
		t.Fatal(err)
	}
	postgresRole, err := phase6security.DerivePostgresPeerCRLRoleDocument(profile, composed.PeerSources, owner.Name)
	if err != nil || len(postgresRole.Edges) != 1 {
		clear(profileBytes)
		clear(peerBytes)
		clear(peerRoleBytes)
		t.Fatal("Product runtime PostgreSQL peer CRL role unavailable")
	}
	postgresRoleBytes, err := json.Marshal(postgresRole)
	if err != nil {
		clear(profileBytes)
		clear(peerBytes)
		clear(peerRoleBytes)
		t.Fatal(err)
	}
	config, err := slice6BuildProductRuntimeConfig(composed)
	if err != nil {
		clear(profileBytes)
		clear(peerBytes)
		clear(peerRoleBytes)
		clear(postgresRoleBytes)
		t.Fatal("Product runtime source-bound startup config unavailable")
	}
	defer clear(profileBytes)
	defer clear(peerBytes)
	defer clear(peerRoleBytes)
	defer clear(postgresRoleBytes)
	defer clear(config)
	for _, item := range []struct {
		deployment string
		files      map[string][]byte
	}{
		{agent.Name, map[string][]byte{
			phase6security.Slice6ProfileConfigFile:  profileBytes,
			phase6security.Slice6PeerCRLSourcesFile: peerBytes,
		}},
		{owner.Name, map[string][]byte{
			phase6security.Slice6ProfileConfigFile:       profileBytes,
			phase6security.Slice6PeerCRLRoleFile:         peerRoleBytes,
			phase6security.Slice6PostgresPeerCRLRoleFile: postgresRoleBytes,
			phase6security.Slice6StartupConfigFile:       config,
		}},
	} {
		archive, archiveErr := phase6security.BuildSlice6PrivateConfigArchive(profile, item.deployment, item.files)
		if archiveErr != nil {
			t.Fatal("Product runtime private config archive unavailable")
		}
		slice6PrepareOneControllerPrivateConfig(t, ctx, run, profile, item.deployment, archive)
	}
	result := make(map[string]string, len(existing)+1)
	for storageID, volume := range existing {
		result[storageID] = volume
	}
	result[binding.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		binding.SocketStorageID, binding.SocketDirectory, binding.AgentUID,
		binding.SubjectGID, binding.DirectoryMode)
	if len(result) != 74 {
		t.Fatal("Product runtime private socket count drift")
	}
	return result
}
