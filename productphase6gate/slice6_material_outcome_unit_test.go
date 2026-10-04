//go:build phase6slice6gate

package productphase6gate

import (
	"strings"
	"testing"
)

func TestSlice6EMaterialOutcomeRequiresExactExitClassAndIdentity(t *testing.T) {
	runID := strings.Repeat("a", 32)
	profile := "sha256:" + strings.Repeat("b", 64)
	for _, agent := range [...]string{"guest-agent", "product-runtime-agent", "product-migration-agent"} {
		class := "stopped"
		if agent == "product-migration-agent" {
			class = "natural_exit"
		}
		outcome := slice6EMaterialOutcome{RunID: runID, ProfileDigest: profile,
			AgentDeployment: agent, ContainerID: strings.Repeat("c", 64),
			ExitClass: class, PhysicalConverged: true}
		if !outcome.validForRun(runID, profile, agent) {
			t.Fatalf("exact material completion rejected: %s", agent)
		}
		wrong := outcome
		wrong.ExitClass = "stopped"
		if class == "stopped" {
			wrong.ExitClass = "natural_exit"
		}
		if wrong.validForRun(runID, profile, agent) {
			t.Fatalf("unobserved material exit class accepted: %s", agent)
		}
		wrong = outcome
		wrong.PhysicalConverged = false
		if wrong.validForRun(runID, profile, agent) {
			t.Fatalf("unjoined material process accepted: %s", agent)
		}
	}
}
