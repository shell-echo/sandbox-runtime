package phase6rolecandidate

import (
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestTargetInventoryRequiresOneSourceBoundImagePerReviewedCommand(t *testing.T) {
	names := phase6security.Slice6DesiredDeploymentNames()
	targets := phase6security.Slice6DesiredLocalRoleTargets()
	if len(names) != 78 || len(targets) != 12 {
		t.Fatalf("reviewed deployment/target inventory drifted: %d/%d", len(names), len(targets))
	}
	revision := strings.Repeat("a", 40)
	tree := "sha256:" + strings.Repeat("b", 64)
	manifests := make([]Manifest, 0, len(targets))
	for _, target := range targets {
		deployment := ""
		for _, name := range names {
			mapped, err := phase6security.Slice6DesiredImageTarget(name)
			if err == nil && mapped == target {
				deployment = name
				break
			}
		}
		if deployment == "" {
			t.Fatalf("reviewed target %s has no representative", target)
		}
		manifests = append(manifests, Manifest{Source: SourceInputs{
			Deployment: deployment, BuildTarget: target, Platform: "linux/arm64/v8",
			SourceRevision: revision, SourceTreeDigest: tree,
		}})
	}
	if err := matchTargetInventory(manifests, revision); err != nil {
		t.Fatalf("complete candidate target inventory rejected: %v", err)
	}
	mutate := func(change func([]Manifest)) []Manifest {
		copyOf := append([]Manifest(nil), manifests...)
		change(copyOf)
		return copyOf
	}
	for name, values := range map[string][]Manifest{
		"missing target":   manifests[1:],
		"duplicate target": mutate(func(values []Manifest) { values[0] = values[1] }),
		"wrong deployment": mutate(func(values []Manifest) { values[0].Source.Deployment = "browser-sandbox-runtime" }),
		"wrong target":     mutate(func(values []Manifest) { values[0].Source.BuildTarget = "core" }),
		"revision drift":   mutate(func(values []Manifest) { values[0].Source.SourceRevision = strings.Repeat("c", 40) }),
		"tree drift":       mutate(func(values []Manifest) { values[0].Source.SourceTreeDigest = "sha256:" + strings.Repeat("d", 64) }),
		"platform drift":   mutate(func(values []Manifest) { values[0].Source.Platform = "linux/amd64" }),
	} {
		if matchTargetInventory(values, revision) == nil {
			t.Errorf("%s admitted", name)
		}
	}
}
