//go:build phase6slice6gate

package productphase6gate

import (
	"strings"
	"testing"
)

func TestSlice6OrdinaryTLSOutcomeRequiresExactRoleAndSocketNoIssuer(t *testing.T) {
	runID := strings.Repeat("a", 32)
	profile := "sha256:" + strings.Repeat("b", 64)
	role := "guest-tls-agent"
	valid := slice6OrdinaryTLSOutcome{RunID: runID, ProfileDigest: profile,
		AgentDeployment: role, ContainerID: strings.Repeat("c", 64),
		SocketStorageID: "socket-guest-tls-agent", PhysicalConverged: true}
	if !valid.validForRun(runID, profile, role) {
		t.Fatal("completed exact TLS helper was rejected")
	}
	for _, mutation := range []slice6OrdinaryTLSOutcome{
		{RunID: runID, ProfileDigest: profile, AgentDeployment: role,
			ContainerID: valid.ContainerID, SocketStorageID: valid.SocketStorageID},
		{RunID: strings.Repeat("d", 32), ProfileDigest: profile, AgentDeployment: role,
			ContainerID: valid.ContainerID, SocketStorageID: valid.SocketStorageID, PhysicalConverged: true},
		{RunID: runID, ProfileDigest: "sha256:" + strings.Repeat("e", 64), AgentDeployment: role,
			ContainerID: valid.ContainerID, SocketStorageID: valid.SocketStorageID, PhysicalConverged: true},
		{RunID: runID, ProfileDigest: profile, AgentDeployment: "other-agent",
			ContainerID: valid.ContainerID, SocketStorageID: valid.SocketStorageID, PhysicalConverged: true},
		{RunID: runID, ProfileDigest: profile, AgentDeployment: role,
			ContainerID: "backend-id", SocketStorageID: valid.SocketStorageID, PhysicalConverged: true},
		{RunID: runID, ProfileDigest: profile, AgentDeployment: role,
			ContainerID: valid.ContainerID, PhysicalConverged: true},
	} {
		if mutation.validForRun(runID, profile, role) {
			t.Fatal("unproved TLS helper completion accepted")
		}
	}
}

func TestSlice6ETLSOutcomeSlotsRejectMissingWrongAndDuplicateNoIssuer(t *testing.T) {
	runID := strings.Repeat("a", 32)
	profile := "sha256:" + strings.Repeat("b", 64)
	roles := slice6FormalETLSRoles()
	instanceDigits := [7]string{"c", "d", "e", "f", "1", "2", "3"}
	completed := make(map[string]*slice6OrdinaryTLSOutcome, len(roles))
	for index, role := range roles {
		completed[role] = &slice6OrdinaryTLSOutcome{RunID: runID, ProfileDigest: profile,
			AgentDeployment: role, ContainerID: strings.Repeat(instanceDigits[index], 64),
			SocketStorageID: "socket-" + role, PhysicalConverged: true}
	}
	if gap := slice6ETLSOutcomeGap(runID, profile, completed); gap != "" {
		t.Fatalf("complete fixed TLS slots rejected: %s", gap)
	}
	missing := make(map[string]*slice6OrdinaryTLSOutcome, len(completed)-1)
	for role, observed := range completed {
		if role != roles[0] {
			missing[role] = observed
		}
	}
	if slice6ETLSOutcomeGap(runID, profile, missing) != "slot_set" {
		t.Fatal("missing fixed TLS slot accepted")
	}
	wrong := make(map[string]*slice6OrdinaryTLSOutcome, len(completed))
	for role, observed := range completed {
		wrong[role] = observed
	}
	badRole := *wrong[roles[0]]
	badRole.AgentDeployment = roles[1]
	wrong[roles[0]] = &badRole
	if slice6ETLSOutcomeGap(runID, profile, wrong) != roles[0] {
		t.Fatal("wrong-role TLS slot accepted")
	}
	duplicate := make(map[string]*slice6OrdinaryTLSOutcome, len(completed))
	for role, observed := range completed {
		duplicate[role] = observed
	}
	badID := *duplicate[roles[1]]
	badID.ContainerID = completed[roles[0]].ContainerID
	duplicate[roles[1]] = &badID
	if slice6ETLSOutcomeGap(runID, profile, duplicate) != roles[1] {
		t.Fatal("duplicate exact TLS container identity accepted")
	}
}
