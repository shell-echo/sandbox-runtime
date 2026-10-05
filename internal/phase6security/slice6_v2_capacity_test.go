package phase6security

import (
	"slices"
	"testing"
)

func testSlice6V2CapacityInputs(t *testing.T) (Profile, CodingRuntimeTemplateV2, map[string]Resources, map[string]Resources) {
	t.Helper()
	p := testSlice6V2IdentityFragment(t)
	template, _ := testCodingTemplateV2(t)
	for index := range p.Principals {
		switch p.Principals[index].Name {
		case "provider-runtime":
			template.OwnerPrincipalDigest = p.Principals[index].PrincipalDigest
		case "provider-artifact-scanner":
			p.Principals[index].Resources = Resources{MemoryBytes: 4 << 30, CPUMillis: 2000, PIDs: 64}
		}
	}
	template.Slots = slices.Clone(template.Slots)
	template.Slots[0].WorkloadGID = 57500
	template.Slots[1].WorkloadGID = 57501
	gateways := map[string]Resources{
		"browser-sandbox-runtime": {MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16},
		"desktop-sandbox-runtime": {MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16},
	}
	external := make(map[string]Resources, len(slice6DesiredExternalServices))
	for _, service := range slice6DesiredExternalServices {
		external[service.name] = Resources{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16}
	}
	return p, template, gateways, external
}

func TestSlice6V2CapacityCountsAllDeclaredConcurrentLimits(t *testing.T) {
	p, template, gateways, external := testSlice6V2CapacityInputs(t)
	budget, err := CalculateSlice6V2ResourceBudget(p.Principals, p.SandboxIdentitySlots, template, gateways, external)
	if err != nil {
		t.Fatal(err)
	}
	if budget.StaticDeployments != 80 || budget.SandboxContainers != 2*len(p.SandboxIdentitySlots) ||
		budget.CodingContainers != 2 || budget.ExternalServices != 5 || budget.CodingWholeVolumeCount != 6 ||
		budget.DoubleParseMemoryBytes != 128<<20 {
		t.Fatalf("incomplete v2 arithmetic inventory: %+v", budget)
	}
	var expected Resources
	add := func(limit Resources) {
		expected.MemoryBytes += limit.MemoryBytes
		expected.CPUMillis += limit.CPUMillis
		expected.PIDs += limit.PIDs
	}
	for _, principal := range p.Principals {
		if principal.Kind != "sandbox" {
			add(principal.Resources)
		}
	}
	for _, slot := range p.SandboxIdentitySlots {
		for _, principal := range p.Principals {
			if principal.Name == slot.Template {
				add(principal.Resources)
			}
		}
		add(gateways[slot.Template])
	}
	for range template.Slots {
		add(Resources{MemoryBytes: template.Limits.MemoryBytes,
			CPUMillis: template.Limits.CPUMillis, PIDs: template.Limits.PIDs})
	}
	for _, limit := range external {
		add(limit)
	}
	expected.MemoryBytes += budget.DoubleParseMemoryBytes
	if budget.MemoryBytes != expected.MemoryBytes || budget.CPUMillis != expected.CPUMillis || budget.PIDs != expected.PIDs {
		t.Fatalf("budget %+v differs from independent sum %+v", budget, expected)
	}
	for name, change := range map[string]func(*Profile, *CodingRuntimeTemplateV2, map[string]Resources, map[string]Resources){
		"missing scanner limit": func(p *Profile, _ *CodingRuntimeTemplateV2, _, _ map[string]Resources) {
			for index := range p.Principals {
				if p.Principals[index].Name == "provider-artifact-scanner" {
					p.Principals[index].Resources.MemoryBytes--
				}
			}
		},
		"missing static": func(p *Profile, _ *CodingRuntimeTemplateV2, _, _ map[string]Resources) {
			p.Principals = p.Principals[1:]
		},
		"missing gateway": func(_ *Profile, _ *CodingRuntimeTemplateV2, gateways, _ map[string]Resources) {
			delete(gateways, "browser-sandbox-runtime")
		},
		"extra gateway": func(_ *Profile, _ *CodingRuntimeTemplateV2, gateways, _ map[string]Resources) {
			gateways["coding-sandbox-runtime"] = Resources{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16}
		},
		"missing external": func(_ *Profile, _ *CodingRuntimeTemplateV2, _, external map[string]Resources) {
			for name := range external {
				delete(external, name)
				break
			}
		},
		"coding identity collision": func(p *Profile, template *CodingRuntimeTemplateV2, _, _ map[string]Resources) {
			template.Slots[0].WorkloadGID = p.Principals[0].GID
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, coding, gatewayLimits, externalLimits := testSlice6V2CapacityInputs(t)
			change(&candidate, &coding, gatewayLimits, externalLimits)
			if _, err := CalculateSlice6V2ResourceBudget(candidate.Principals, candidate.SandboxIdentitySlots,
				coding, gatewayLimits, externalLimits); err == nil {
				t.Fatal("missing or unsafe resource entry accepted")
			}
		})
	}
}
