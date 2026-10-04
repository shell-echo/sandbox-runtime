//go:build phase6slice6gate

package productphase6gate

import (
	"strings"
	"testing"
)

func TestSlice6CredentialControllerOutcomeBindsRunProfileAndExactContainerNoIssuer(t *testing.T) {
	runID := strings.Repeat("a", 32)
	profile := "sha256:" + strings.Repeat("b", 64)
	valid := slice6CredentialControllerOutcome{RunID: runID, ProfileDigest: profile,
		ContainerID: strings.Repeat("c", 64), PhysicalConverged: true}
	if !valid.validForRun(runID, profile) {
		t.Fatal("exact credential controller convergence rejected")
	}
	for _, mutation := range []slice6CredentialControllerOutcome{
		{RunID: runID, ProfileDigest: profile, ContainerID: valid.ContainerID},
		{RunID: strings.Repeat("d", 32), ProfileDigest: profile, ContainerID: valid.ContainerID, PhysicalConverged: true},
		{RunID: runID, ProfileDigest: "sha256:" + strings.Repeat("e", 64), ContainerID: valid.ContainerID, PhysicalConverged: true},
		{RunID: runID, ProfileDigest: profile, ContainerID: "backend-id", PhysicalConverged: true},
	} {
		if mutation.validForRun(runID, profile) {
			t.Fatal("unproved credential controller convergence accepted")
		}
	}
	if valid.validForRun(runID, "not-a-profile-digest") {
		t.Fatal("noncanonical expected Profile identity accepted")
	}
}
