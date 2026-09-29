package phase6security

import (
	"slices"
	"testing"
)

func TestSlice6DutyClassesCoverEveryReviewedDeployment(t *testing.T) {
	deployments := Slice6DesiredDeploymentNames()
	classes, err := Slice6DesiredDutyClasses()
	if err != nil || len(deployments) != 82 || len(classes) != 23 || !slices.IsSorted(classes) {
		t.Fatalf("incomplete duty inventory: deployments=%d classes=%d err=%v", len(deployments), len(classes), err)
	}
	for _, deployment := range deployments {
		duty, err := Slice6DesiredDutyClass(deployment)
		if err != nil || !slices.Contains(classes, duty) {
			t.Fatalf("unclassified deployment %s: %s, %v", deployment, duty, err)
		}
	}
	for _, item := range []struct{ deployment, duty string }{
		{"product-runtime", "product_runtime"},
		{"provider-browser-runtime", "provider_browser_runtime"},
		{"product-migration-agent", "migration_material_agent"},
		{"product-runtime-agent", "runtime_material_agent"},
		{"browser-sandbox-runtime", "chromium_sandbox"},
		{"desktop-sandbox-runtime", "desktop_x11_sandbox"},
		{"egress-policy-authority-product", "egress_policy_authority"},
	} {
		actual, err := Slice6DesiredDutyClass(item.deployment)
		if err != nil || actual != item.duty {
			t.Fatalf("duty class drift for %s: %s, %v", item.deployment, actual, err)
		}
	}
	if _, err := Slice6DesiredDutyClass("unreviewed-runtime"); err == nil {
		t.Fatal("unreviewed deployment acquired a duty class")
	}
}
