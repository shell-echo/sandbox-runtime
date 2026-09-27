package phase6security

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSandboxIdentitySlotsRejectAuthorityAndIdentityDrift(t *testing.T) {
	for name, mutate := range map[string]func(*Profile){
		"missing desktop slot":  func(p *Profile) { p.SandboxIdentitySlots = p.SandboxIdentitySlots[:1] },
		"unknown template":      func(p *Profile) { p.SandboxIdentitySlots[0].Template = "guest-runtime" },
		"wrong template digest": func(p *Profile) { p.SandboxIdentitySlots[0].TemplateDigest = testDigest("other") },
		"executor owns allocation": func(p *Profile) {
			for _, principal := range p.Principals {
				if principal.Name == "browser-executor-backend" {
					p.SandboxIdentitySlots[0].OwnerDeployment = principal.Name
					p.SandboxIdentitySlots[0].OwnerPrincipalDigest = principal.PrincipalDigest
				}
			}
		},
		"owner digest drift": func(p *Profile) { p.SandboxIdentitySlots[0].OwnerPrincipalDigest = testDigest("other") },
		"duplicate slot ID":  func(p *Profile) { p.SandboxIdentitySlots[1].SlotID = p.SandboxIdentitySlots[0].SlotID },
		"unsorted slots": func(p *Profile) {
			p.SandboxIdentitySlots[0], p.SandboxIdentitySlots[1] = p.SandboxIdentitySlots[1], p.SandboxIdentitySlots[0]
		},
		"root workload":        func(p *Profile) { p.SandboxIdentitySlots[0].WorkloadUID = 0 },
		"out of range gateway": func(p *Profile) { p.SandboxIdentitySlots[0].GatewayGID = 65532 },
		"workload and gateway share UID": func(p *Profile) {
			p.SandboxIdentitySlots[0].GatewayUID = p.SandboxIdentitySlots[0].WorkloadUID
		},
		"different slots share GID": func(p *Profile) {
			p.SandboxIdentitySlots[1].GatewayGID = p.SandboxIdentitySlots[0].WorkloadGID
		},
		"slot reuses static principal": func(p *Profile) {
			p.SandboxIdentitySlots[0].WorkloadUID = p.Principals[0].UID
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if profile.Validate() == nil {
				t.Fatal("invalid sandbox identity plan was accepted")
			}
		})
	}
}

func TestSandboxSlotsForCapacityRejectsSilentClampAndCrossOwner(t *testing.T) {
	profile := validProfile()
	slots, err := profile.SandboxSlotsForCapacity("desktop-sandbox-runtime", "provider-desktop-runtime", 1)
	if err != nil || len(slots) != 1 || slots[0].SlotID != "desktop-0000" {
		t.Fatalf("bound slot lookup = %+v, %v", slots, err)
	}
	for _, request := range []struct {
		template, owner string
		capacity        int
	}{
		{"desktop-sandbox-runtime", "provider-desktop-runtime", 2},
		{"desktop-sandbox-runtime", "provider-browser-runtime", 1},
		{"unknown", "provider-desktop-runtime", 1},
		{"desktop-sandbox-runtime", "provider-desktop-runtime", 0},
		{"desktop-sandbox-runtime", "provider-desktop-runtime", 1001},
	} {
		if _, err := profile.SandboxSlotsForCapacity(request.template, request.owner, request.capacity); err == nil {
			t.Fatalf("capacity/owner drift accepted: %+v", request)
		}
	}
}

func TestSandboxPlanProjectionBindsTrustedOwnerDatabaseAndController(t *testing.T) {
	profile := validProfile()
	plan, err := profile.ProjectSandboxIdentityPlan("browser-sandbox-runtime", "provider-browser-runtime", 1)
	if err != nil || plan.Validate() != nil || plan.ProfileDigest != profile.ProfileDigest ||
		plan.OwnerDeployment != "provider-browser-runtime" || plan.ControllerID != "browser-provider-1" ||
		plan.DatabaseName != "provider_browser" || plan.RuntimeRole != "browser_provider_runtime" ||
		plan.MaterialBindingID != "browser-provider-runtime-dsn" || plan.ServiceName != "postgres" ||
		len(plan.Slots) != 1 || plan.Slots[0].ID != "browser-0000" {
		t.Fatalf("trusted owner projection = %+v, %v", plan, err)
	}
	plan.Slots[0].WorkloadUID++
	if profile.SandboxIdentitySlots[0].WorkloadUID == plan.Slots[0].WorkloadUID {
		t.Fatal("projection shared mutable profile slots")
	}
	for _, request := range []struct {
		template, owner string
		capacity        int
	}{
		{"browser-sandbox-runtime", "browser-executor-backend", 1},
		{"browser-sandbox-runtime", "provider-browser-runtime", 2},
		{"desktop-sandbox-runtime", "provider-browser-runtime", 1},
	} {
		if _, err := profile.ProjectSandboxIdentityPlan(request.template, request.owner, request.capacity); err == nil {
			t.Fatalf("invalid owner-local projection accepted: %+v", request)
		}
	}
}

func TestSandboxIdentitySlotsExpressConfiguredMaximumWithoutClaimingRuntimeCapacity(t *testing.T) {
	profile := validProfile()
	profile.SandboxIdentitySlots = make([]SandboxIdentitySlot, 0, 2*maxSandboxSlotsPerTemplate)
	for _, kind := range []struct {
		template, owner                                  string
		workloadUID, workloadGID, gatewayUID, gatewayGID uint32
	}{
		{"browser-sandbox-runtime", "provider-browser-runtime", 10000, 12000, 14000, 16000},
		{"desktop-sandbox-runtime", "provider-desktop-runtime", 40000, 42000, 44000, 46000},
	} {
		var template, owner Principal
		for _, principal := range profile.Principals {
			if principal.Name == kind.template {
				template = principal
			}
			if principal.Name == kind.owner {
				owner = principal
			}
		}
		for index := range maxSandboxSlotsPerTemplate {
			profile.SandboxIdentitySlots = append(profile.SandboxIdentitySlots, SandboxIdentitySlot{
				SlotID: fmt.Sprintf("%s-%04d", kind.template[:7], index), Template: kind.template,
				TemplateDigest: SandboxTemplateDigest(template), OwnerDeployment: kind.owner,
				OwnerPrincipalDigest: owner.PrincipalDigest,
				WorkloadUID:          kind.workloadUID + uint32(index), WorkloadGID: kind.workloadGID + uint32(index),
				GatewayUID: kind.gatewayUID + uint32(index), GatewayGID: kind.gatewayGID + uint32(index),
			})
		}
	}
	profile.ProfileDigest = profile.Digest()
	encoded, err := json.Marshal(profile)
	if err != nil || len(encoded) > maxBytes || profile.Validate() != nil {
		t.Fatalf("bounded 1000+1000 identity plan failed: bytes=%d error=%v", len(encoded), err)
	}
	for _, query := range []struct{ template, owner string }{
		{"browser-sandbox-runtime", "provider-browser-runtime"},
		{"desktop-sandbox-runtime", "provider-desktop-runtime"},
	} {
		selected, err := profile.SandboxSlotsForCapacity(query.template, query.owner, 1000)
		if err != nil || len(selected) != 1000 {
			t.Fatalf("1000-slot configured capacity rejected for %s: %v", query.template, err)
		}
	}
}
