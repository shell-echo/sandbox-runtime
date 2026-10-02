//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ProductMigrationInputsEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_MIGRATION_INPUTS"
const slice6ProductMigrationSignersEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_MIGRATION_SIGNERS"

// Prepare the migration job's three new Unix listeners independently of the
// runtime sockets. The fourth private reader is the one-shot job itself.
// Neither preparation nor a canonical config proves a live SQL migration.
func slice6PrepareProductMigrationInputs(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, existing map[string]string) map[string]string {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		composed.PeerSources.Validate(profile) != nil || len(existing) != 70 {
		t.Fatal("Product migration input preparation needs complete source-bound socket supply")
	}
	materialTLS, materialSigner, materialAgent, err := profile.TLSAgentForSubject("product-migration-agent")
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-migration-job")
	postgresSigner, target, postgresAgent, job, _, postgresErr := profile.PostgresClientSignerForOwner("product-migration-job")
	if err != nil || materialErr != nil || postgresErr != nil ||
		materialSigner.Name != "product-migration-agent-tls-agent" ||
		materialAgent.Name != "product-migration-agent" || material.AgentDeployment != materialAgent.Name ||
		postgresAgent.Name != "product-migration-postgres-tls-agent" || job.Name != "product-migration-job" ||
		target.DatabaseName != "product" || target.SQLRole != "product_migrator" || !target.Migration ||
		materialTLS.SubjectUID != materialAgent.UID || materialTLS.SubjectGID != materialAgent.GID ||
		postgresSigner.SubjectUID != job.UID || postgresSigner.SubjectGID != job.GID ||
		material.OwnerUID != job.UID || material.OwnerGID != job.GID ||
		materialTLS.DirectoryMode != 0o710 || material.DirectoryMode != 0o710 ||
		postgresSigner.DirectoryMode != 0o710 ||
		!slices.Equal(materialSigner.Networks, []string{"network-product-migration-agent-tls-agent"}) ||
		!slices.Equal(postgresAgent.Networks, []string{"network-product-migration-postgres-tls-agent"}) {
		t.Fatal("Product migration signer, material or job authority drift")
	}
	storageIDs := []string{materialTLS.SocketStorageID, material.SocketStorageID, postgresSigner.SocketStorageID}
	for i, storageID := range storageIDs {
		if storageID == "" || existing[storageID] != "" || slices.Contains(storageIDs[:i], storageID) {
			t.Fatal("Product migration private socket alias or prior allocation")
		}
	}
	if existing[materialTLS.ControllerSocketStorageID] == "" ||
		existing[postgresSigner.ControllerSocketStorageID] == "" {
		t.Fatal("Product migration certificate-controller socket missing")
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
	role, err := phase6security.DerivePostgresPeerCRLRoleDocument(profile, composed.PeerSources, job.Name)
	if err != nil || len(role.Edges) != 1 {
		clear(profileBytes)
		clear(peerBytes)
		t.Fatal("Product migration PostgreSQL peer CRL role unavailable")
	}
	roleBytes, err := json.Marshal(role)
	if err != nil {
		clear(profileBytes)
		clear(peerBytes)
		t.Fatal(err)
	}
	defer clear(profileBytes)
	defer clear(peerBytes)
	defer clear(roleBytes)
	startupConfig, err := slice6BuildProductMigrationJobConfig(composed)
	if err != nil {
		t.Fatal("Product migration job source-bound startup config unavailable")
	}
	defer clear(startupConfig)
	for _, target := range []struct {
		deployment string
		files      map[string][]byte
	}{
		{materialSigner.Name, map[string][]byte{
			phase6security.Slice6ProfileConfigFile:  profileBytes,
			phase6security.Slice6PeerCRLSourcesFile: peerBytes,
		}},
		{materialAgent.Name, map[string][]byte{phase6security.Slice6ProfileConfigFile: profileBytes}},
		{postgresAgent.Name, map[string][]byte{
			phase6security.Slice6ProfileConfigFile:  profileBytes,
			phase6security.Slice6PeerCRLSourcesFile: peerBytes,
		}},
		{job.Name, map[string][]byte{
			phase6security.Slice6ProfileConfigFile:       profileBytes,
			phase6security.Slice6PostgresPeerCRLRoleFile: roleBytes,
			phase6security.Slice6StartupConfigFile:       startupConfig,
		}},
	} {
		archive, buildErr := phase6security.BuildSlice6PrivateConfigArchive(profile, target.deployment, target.files)
		if buildErr != nil {
			t.Fatalf("Product migration %s private config unavailable: %v", target.deployment, buildErr)
		}
		slice6PrepareOneControllerPrivateConfig(t, ctx, run, profile, target.deployment, archive)
	}
	result := make(map[string]string, len(existing)+3)
	for storageID, volume := range existing {
		result[storageID] = volume
	}
	for _, socket := range []struct {
		storageID, directory string
		uid, gid             uint32
		mode                 uint32
	}{
		{materialTLS.SocketStorageID, materialTLS.SocketDirectory, materialTLS.AgentUID, materialTLS.SubjectGID, materialTLS.DirectoryMode},
		{material.SocketStorageID, material.SocketDirectory, material.AgentUID, material.OwnerGID, material.DirectoryMode},
		{postgresSigner.SocketStorageID, postgresSigner.SocketDirectory, postgresSigner.AgentUID, postgresSigner.SubjectGID, postgresSigner.DirectoryMode},
	} {
		result[socket.storageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
			socket.storageID, socket.directory, socket.uid, socket.gid, socket.mode)
	}
	if len(result) != 73 {
		t.Fatal("Product migration private socket count drift")
	}
	return result
}
