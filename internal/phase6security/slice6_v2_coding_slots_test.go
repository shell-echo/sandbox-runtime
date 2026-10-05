package phase6security

import (
	"slices"
	"testing"
)

func TestSlice6V2CodingSlotsBindCompleteIdentityInventory(t *testing.T) {
	baseline := testSlice6V2IdentityFragment(t)
	template, _ := testCodingTemplateV2(t)
	for _, principal := range baseline.Principals {
		if principal.Name == "provider-runtime" {
			template.OwnerPrincipalDigest = principal.PrincipalDigest
		}
	}
	if VerifySlice6V2CodingSlots(template, baseline.Principals, baseline.SandboxIdentitySlots) == nil {
		t.Fatal("provisional Coding GIDs collided with PostgreSQL TLS agents but were accepted")
	}
	template.Slots = slices.Clone(template.Slots)
	template.Slots[0].WorkloadGID = 57500
	template.Slots[1].WorkloadGID = 57501
	if err := VerifySlice6V2CodingSlots(template, baseline.Principals, baseline.SandboxIdentitySlots); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CodingRuntimeTemplateV2, *Profile){
		"missing static role": func(_ *CodingRuntimeTemplateV2, p *Profile) {
			p.Principals = p.Principals[1:]
		},
		"wrong owner digest": func(v *CodingRuntimeTemplateV2, _ *Profile) {
			v.OwnerPrincipalDigest = testCodingTemplateDigest("e")
		},
		"static uid collision": func(v *CodingRuntimeTemplateV2, p *Profile) {
			v.Slots[0].WorkloadUID = p.Principals[0].UID
		},
		"static gid collision": func(v *CodingRuntimeTemplateV2, p *Profile) {
			v.Slots[0].WorkloadGID = p.Principals[0].GID
		},
		"browser uid collision": func(v *CodingRuntimeTemplateV2, p *Profile) {
			v.Slots[0].WorkloadUID = p.SandboxIdentitySlots[0].WorkloadUID
		},
		"desktop gateway gid collision": func(v *CodingRuntimeTemplateV2, p *Profile) {
			v.Slots[0].WorkloadGID = p.SandboxIdentitySlots[len(p.SandboxIdentitySlots)-1].GatewayGID
		},
		"existing storage alias": func(v *CodingRuntimeTemplateV2, p *Profile) {
			for index := range p.Principals {
				if len(p.Principals[index].Mounts) != 0 {
					p.Principals[index].Mounts = slices.Clone(p.Principals[index].Mounts)
					p.Principals[index].Mounts[0].StorageID = v.Slots[0].InputsVolume
					return
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := baseline
			candidate.Principals = slices.Clone(baseline.Principals)
			candidate.SandboxIdentitySlots = slices.Clone(baseline.SandboxIdentitySlots)
			changed := template
			changed.Slots = slices.Clone(template.Slots)
			change(&changed, &candidate)
			if err := VerifySlice6V2CodingSlots(changed, candidate.Principals, candidate.SandboxIdentitySlots); err == nil {
				t.Fatal("identity or volume collision accepted")
			}
		})
	}
}
