//go:build phase6slice6gate

package productphase6gate

import (
	"strings"
	"testing"
)

func TestSlice6GuestRecoveryEPreludeRejectsMissingOriginalSource(t *testing.T) {
	if _, _, err := slice6RunGuestRecoveryEAfterBootstrap(t, t.Context(),
		slice6GuestRecoveryEBootstrap{}); err == nil {
		t.Fatal("E prelude could reach Docker without original network/source authority")
	}
}

func TestSlice6GuestRecoveryAStageMembersBindOriginalIDs(t *testing.T) {
	run := slice6DockerRun{id: strings.Repeat("a", 32)}
	postgresID := strings.Repeat("b", 64)
	productID := strings.Repeat("c", 64)
	migration := slice6ProductMigrationExitProof{RunID: run.id,
		PostgresID: postgresID, ContainerID: strings.Repeat("d", 64),
		RemovalRaw: []byte("original removal receipt")}
	members, err := slice6GuestRecoveryAStageMembers(run, postgresID, productID, &migration)
	if err != nil || len(members) != 9 || members["product-runtime"].ID != productID ||
		members["product-migration-job"].ID != migration.ContainerID ||
		members["provider-runtime"].ID != "" {
		t.Fatalf("E A-stage nine-network membership unavailable: %v", err)
	}
	migration.ContainerID = productID
	if _, err := slice6GuestRecoveryAStageMembers(run, postgresID, productID, &migration); err == nil {
		t.Fatal("E A-stage aliased migration and Product originals")
	}
}
