package phase6security

import (
	"slices"
	"testing"
)

func TestSlice6CandidateConcurrencyCoversCompleteLifecycleWithoutPermanentJobs(t *testing.T) {
	envelopes := Slice6CandidateConcurrencyEnvelopes()
	if len(envelopes) != len(slice6OneShotMigrationBundles)+2 {
		t.Fatal("incomplete Slice 6 concurrency envelope set")
	}
	approved := Slice6DesiredDeploymentNames()
	covered := make(map[string]bool, len(approved))
	expectedExternal := make([]string, 0, len(slice6DesiredExternalServices))
	for _, service := range slice6DesiredExternalServices {
		expectedExternal = append(expectedExternal, service.name)
	}
	for _, envelope := range envelopes {
		if !slices.Equal(envelope.ExternalServices, expectedExternal) ||
			!slices.IsSorted(envelope.Principals) || len(envelope.Principals) == 0 {
			t.Fatalf("invalid envelope %s", envelope.Name)
		}
		for index, name := range envelope.Principals {
			if index > 0 && envelope.Principals[index-1] == name || !slices.Contains(approved, name) {
				t.Fatalf("duplicate or unknown member %s in %s", name, envelope.Name)
			}
			covered[name] = true
		}
	}
	if len(covered) != len(approved) || len(envelopes[0].Principals) != len(approved)-4*len(slice6OneShotMigrationBundles)-len(slice6DynamicSandboxTemplates) {
		t.Fatal("Slice 6 identity not covered across lifecycle envelopes")
	}
	for _, bundle := range slice6OneShotMigrationBundles {
		members := []string{bundle.job, bundle.material, bundle.materialTLS, bundle.postgresTLS}
		for _, envelope := range envelopes {
			for _, member := range members {
				if slices.Contains(envelope.Principals, member) != (envelope.Name == bundle.name) {
					t.Fatalf("migration member %s lives outside its one-shot envelope", member)
				}
			}
		}
	}
	for _, envelope := range envelopes {
		for _, sandbox := range slice6DynamicSandboxTemplates {
			if slices.Contains(envelope.Principals, sandbox) != (envelope.Name == "browser_desktop_active") {
				t.Fatalf("dynamic sandbox %s treated as permanent in %s", sandbox, envelope.Name)
			}
		}
	}
}

func TestCalculateSlice6ResourceBudgetsRequiresExactCompleteLimits(t *testing.T) {
	// These identical minimum values exercise the calculator only; they are
	// not measured limits and cannot become a release policy.
	unit := Resources{MemoryBytes: 16 << 20, CPUMillis: 10, PIDs: 4}
	principals := make(map[string]Resources, len(slice6ApprovedDeploymentKinds))
	for _, name := range Slice6DesiredDeploymentNames() {
		principals[name] = unit
	}
	external := make(map[string]Resources, len(slice6DesiredExternalServices))
	for _, service := range slice6DesiredExternalServices {
		external[service.name] = unit
	}
	budgets, err := CalculateSlice6ResourceBudgets(principals, external)
	if err != nil || len(budgets) != len(Slice6CandidateConcurrencyEnvelopes()) {
		t.Fatalf("complete calculator inputs rejected: %v", err)
	}
	for index, envelope := range Slice6CandidateConcurrencyEnvelopes() {
		budget := budgets[index]
		count := int64(len(envelope.Principals) + len(envelope.ExternalServices))
		if budget.Envelope != envelope.Name || budget.ProcessCount != len(envelope.Principals) ||
			budget.ExternalCount != len(envelope.ExternalServices) || budget.MemoryBytes != count*unit.MemoryBytes ||
			budget.CPUMillis != count*unit.CPUMillis || budget.PIDs != count*unit.PIDs {
			t.Fatalf("incorrect lifecycle arithmetic for %s: %+v", envelope.Name, budget)
		}
	}
	delete(principals, "product-migration-job")
	if _, err := CalculateSlice6ResourceBudgets(principals, external); err == nil {
		t.Fatal("one-shot migration limit omission was admitted")
	}
	principals["product-migration-job"] = unit
	principals["unreviewed-role"] = unit
	if _, err := CalculateSlice6ResourceBudgets(principals, external); err == nil {
		t.Fatal("unreviewed role limit was admitted")
	}
	delete(principals, "unreviewed-role")
	principals["browser-sandbox-runtime"] = Resources{MemoryBytes: 0, CPUMillis: 10, PIDs: 4}
	if _, err := CalculateSlice6ResourceBudgets(principals, external); err == nil {
		t.Fatal("unbounded sandbox limit was admitted")
	}
	principals["browser-sandbox-runtime"] = unit
	delete(external, slice6DesiredExternalServices[0].name)
	if _, err := CalculateSlice6ResourceBudgets(principals, external); err == nil {
		t.Fatal("external service limit omission was admitted")
	}
}
