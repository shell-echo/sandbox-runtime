package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
)

// SandboxIdentitySlot is a finite, deployment-owned pair of container
// identities. The workload and its restricted-egress gateway are separate
// containers; neither identity is supplied by a sandbox request or a public
// Provider DTO. Reservation and actual-container observation are separate
// requirements and are not established by this static profile record.
type SandboxIdentitySlot struct {
	SlotID               string `json:"slot_id"`
	Template             string `json:"template"`
	TemplateDigest       string `json:"template_digest"`
	OwnerDeployment      string `json:"owner_deployment"`
	OwnerPrincipalDigest string `json:"owner_principal_digest"`
	WorkloadUID          uint32 `json:"workload_uid"`
	WorkloadGID          uint32 `json:"workload_gid"`
	GatewayUID           uint32 `json:"gateway_uid"`
	GatewayGID           uint32 `json:"gateway_gid"`
}

const maxSandboxSlotsPerTemplate = 1000

var sandboxTemplateOwners = map[string]string{
	"browser-sandbox-runtime": "provider-browser-runtime",
	"desktop-sandbox-runtime": "provider-desktop-runtime",
}

// SandboxTemplateDigest binds the reviewed container policy independently
// from one runtime identity. It is private configuration authority, not an
// OCI image descriptor or proof of a running container.
func SandboxTemplateDigest(principal Principal) string {
	principal.UID, principal.GID = 0, 0
	encoded, _ := json.Marshal(principal)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-sandbox-template/v1\x00"), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateSandboxIdentitySlots(slots []SandboxIdentitySlot, principals map[string]Principal) error {
	if len(slots) < len(sandboxTemplateOwners) || len(slots) > len(sandboxTemplateOwners)*maxSandboxSlotsPerTemplate {
		return ErrInvalidProfile
	}
	uids := make(map[uint32]struct{}, len(principals)+len(slots)*2)
	gids := make(map[uint32]struct{}, len(principals)+len(slots)*2)
	for _, principal := range principals {
		uids[principal.UID] = struct{}{}
		gids[principal.GID] = struct{}{}
	}
	counts := map[string]int{}
	seenIDs := map[string]struct{}{}
	previousTemplate, previousID := "", ""
	for _, slot := range slots {
		ownerName, known := sandboxTemplateOwners[slot.Template]
		template, hasTemplate := principals[slot.Template]
		owner, hasOwner := principals[ownerName]
		if !known || !hasTemplate || !hasOwner || template.Kind != "sandbox" || owner.AuthorizationPrincipal == nil ||
			slot.OwnerDeployment != ownerName || slot.OwnerPrincipalDigest != owner.PrincipalDigest ||
			slot.TemplateDigest != SandboxTemplateDigest(template) || !namePattern.MatchString(slot.SlotID) ||
			(slot.Template < previousTemplate || slot.Template == previousTemplate && slot.SlotID <= previousID) ||
			!validSandboxNumericID(slot.WorkloadUID) || !validSandboxNumericID(slot.WorkloadGID) ||
			!validSandboxNumericID(slot.GatewayUID) || !validSandboxNumericID(slot.GatewayGID) ||
			slot.WorkloadUID == slot.GatewayUID || slot.WorkloadGID == slot.GatewayGID {
			return ErrInvalidProfile
		}
		if _, duplicate := seenIDs[slot.SlotID]; duplicate {
			return ErrInvalidProfile
		}
		seenIDs[slot.SlotID] = struct{}{}
		for _, value := range []uint32{slot.WorkloadUID, slot.GatewayUID} {
			if _, duplicate := uids[value]; duplicate {
				return ErrInvalidProfile
			}
			uids[value] = struct{}{}
		}
		for _, value := range []uint32{slot.WorkloadGID, slot.GatewayGID} {
			if _, duplicate := gids[value]; duplicate {
				return ErrInvalidProfile
			}
			gids[value] = struct{}{}
		}
		counts[slot.Template]++
		if counts[slot.Template] > maxSandboxSlotsPerTemplate {
			return ErrInvalidProfile
		}
		previousTemplate, previousID = slot.Template, slot.SlotID
	}
	for template := range sandboxTemplateOwners {
		if counts[template] == 0 {
			return ErrInvalidProfile
		}
	}
	return nil
}

func validSandboxNumericID(id uint32) bool { return id >= 10000 && id <= 60000 }

// SandboxSlotsForCapacity returns only the exact deployment-owned slots for
// one template. Callers must reject startup when the configured controller
// capacity exceeds this finite set; silently clamping would change Product
// admission semantics. This does not reserve or prove any slot is free.
func (p Profile) SandboxSlotsForCapacity(template, owner string, capacity int) ([]SandboxIdentitySlot, error) {
	if p.Validate() != nil || capacity < 1 || capacity > maxSandboxSlotsPerTemplate ||
		sandboxTemplateOwners[template] != owner {
		return nil, ErrInvalidProfile
	}
	selected := make([]SandboxIdentitySlot, 0, capacity)
	for _, slot := range p.SandboxIdentitySlots {
		if slot.Template == template {
			selected = append(selected, slot)
		}
	}
	if len(selected) < capacity {
		return nil, ErrInvalidProfile
	}
	return selected, nil
}

// ProjectSandboxIdentityPlan is the only conversion from complete deployment
// authority to the neutral Provider-private reservation model. The complete
// profile has already checked collisions across static principals and both
// owners; the resulting plan contains only one owner's exact finite pool.
func (p Profile) ProjectSandboxIdentityPlan(template, owner string, capacity int) (sandboxidentity.Plan, error) {
	slots, err := p.SandboxSlotsForCapacity(template, owner, capacity)
	if err != nil {
		return sandboxidentity.Plan{}, ErrInvalidProfile
	}
	var binding ProviderDatabaseBinding
	for _, candidate := range p.ProviderDatabases {
		if candidate.OwnerDeployment == owner {
			binding = candidate
			break
		}
	}
	if binding.Template != template {
		return sandboxidentity.Plan{}, ErrInvalidProfile
	}
	var ownerDigest string
	for _, principal := range p.Principals {
		if principal.Name == owner {
			ownerDigest = principal.PrincipalDigest
			break
		}
	}
	plan := sandboxidentity.Plan{ProfileDigest: p.ProfileDigest, OwnerDeployment: owner,
		OwnerPrincipalDigest: ownerDigest, Namespace: binding.Namespace, ControllerID: binding.ControllerID,
		ServiceName: binding.ServiceName, ServiceIdentityDigest: binding.ServiceIdentityDigest,
		TrustEdgeID: binding.TrustEdgeID, EgressPolicyID: binding.EgressPolicyID,
		BrokerDeployment: binding.BrokerDeployment, BrokerRoleEdgeID: binding.BrokerRoleEdgeID,
		BrokerExternalEdgeID: binding.BrokerExternalEdgeID, MaterialBindingID: binding.RuntimeDSNBindingID,
		DatabaseName: binding.DatabaseName, RuntimeRole: binding.RuntimeRole,
		Template: template, TemplateDigest: slots[0].TemplateDigest,
		Capacity: capacity, Slots: make([]sandboxidentity.Slot, 0, len(slots))}
	for _, slot := range slots {
		if slot.TemplateDigest != plan.TemplateDigest || slot.OwnerPrincipalDigest != ownerDigest {
			return sandboxidentity.Plan{}, ErrInvalidProfile
		}
		plan.Slots = append(plan.Slots, sandboxidentity.Slot{ID: slot.SlotID, WorkloadUID: slot.WorkloadUID,
			WorkloadGID: slot.WorkloadGID, GatewayUID: slot.GatewayUID, GatewayGID: slot.GatewayGID})
	}
	if plan.Validate() != nil {
		return sandboxidentity.Plan{}, ErrInvalidProfile
	}
	return plan, nil
}
