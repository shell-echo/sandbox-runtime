//go:build phase6slice6gate

package productphase6gate

import (
	"slices"
	"strings"
	"testing"
)

func TestSlice6BreakGlassOutcomeRequiresExactInstancesNoIssuer(t *testing.T) {
	runID := strings.Repeat("a", 32)
	profile := "sha256:" + strings.Repeat("b", 64)
	valid := slice6BreakGlassRunOutcome{
		RunID: runID, ProfileDigest: profile,
		InstanceIDs:       []string{strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)},
		PhysicalConverged: true,
	}
	if !valid.validForRun(runID, profile) {
		t.Fatal("three exact completed controller instances were rejected")
	}
	mutations := []slice6BreakGlassRunOutcome{}
	for _, mutate := range []func(*slice6BreakGlassRunOutcome){
		func(value *slice6BreakGlassRunOutcome) { value.RunID = strings.Repeat("f", 32) },
		func(value *slice6BreakGlassRunOutcome) { value.ProfileDigest = "sha256:" + strings.Repeat("f", 64) },
		func(value *slice6BreakGlassRunOutcome) { value.PhysicalConverged = false },
		func(value *slice6BreakGlassRunOutcome) { value.InstanceIDs = value.InstanceIDs[:2] },
		func(value *slice6BreakGlassRunOutcome) { value.InstanceIDs[2] = value.InstanceIDs[1] },
		func(value *slice6BreakGlassRunOutcome) { value.InstanceIDs[2] = "backend-id" },
	} {
		candidate := valid
		candidate.InstanceIDs = slices.Clone(valid.InstanceIDs)
		mutate(&candidate)
		mutations = append(mutations, candidate)
	}
	for index, candidate := range mutations {
		if candidate.validForRun(runID, profile) {
			t.Fatalf("unproved controller instance mutation %d accepted", index)
		}
	}
	if valid.validForRun(runID, "not-a-profile-digest") {
		t.Fatal("noncanonical frozen Profile identity accepted")
	}
}
