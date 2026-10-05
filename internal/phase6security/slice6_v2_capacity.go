package phase6security

import (
	"math"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

const slice6V2DoubleParseHeadroom = 2 * artifact.MaxArtifactBytes

// Slice6V2ResourceBudget is conservative limit arithmetic for the largest
// declared concurrent set. It counts all one-shot migration bundles together,
// every static non-template deployment, every Browser/Desktop workload and
// gateway slot, both Coding workloads, all external services, and a minimum
// double-parse artifact memory headroom. It does not measure actual use,
// Docker/kernel overhead, or unbounded local-volume disk consumption.
type Slice6V2ResourceBudget struct {
	MemoryBytes            int64 `json:"memory_bytes"`
	CPUMillis              int64 `json:"cpu_millis"`
	PIDs                   int64 `json:"pids"`
	StaticDeployments      int   `json:"static_deployments"`
	SandboxContainers      int   `json:"sandbox_containers"`
	CodingContainers       int   `json:"coding_containers"`
	ExternalServices       int   `json:"external_services"`
	DoubleParseMemoryBytes int64 `json:"double_parse_memory_bytes"`
	CodingWholeVolumeCount int   `json:"coding_whole_volume_count"`
}

// CalculateSlice6V2ResourceBudget rejects omitted or surplus limits. The
// final Profile v2 validator must bind these inputs to one canonical Profile
// and the real gate must independently prove host, cgroup and disk headroom.
func CalculateSlice6V2ResourceBudget(principals []Principal, sandboxSlots []SandboxIdentitySlot,
	template CodingRuntimeTemplateV2, sandboxGatewayLimits, externalLimits map[string]Resources,
) (Slice6V2ResourceBudget, error) {
	if VerifySlice6V2CodingSlots(template, principals, sandboxSlots) != nil ||
		len(sandboxGatewayLimits) != len(sandboxTemplateOwners) ||
		len(externalLimits) != len(slice6DesiredExternalServices) {
		return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
	}
	for name, limit := range sandboxGatewayLimits {
		if _, approved := sandboxTemplateOwners[name]; !approved || !validSlice6CapacityLimit(limit) {
			return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
		}
	}
	expectedExternal := make(map[string]bool, len(slice6DesiredExternalServices))
	for _, service := range slice6DesiredExternalServices {
		expectedExternal[service.name] = true
	}
	for name, limit := range externalLimits {
		if !expectedExternal[name] || !validSlice6CapacityLimit(limit) {
			return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
		}
	}
	byName := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		if !validSlice6CapacityLimit(principal.Resources) {
			return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
		}
		byName[principal.Name] = principal
	}
	// This exact scanner cap is part of the reviewed local candidate, not a
	// promise that the current host can run the complete topology.
	if byName["provider-artifact-scanner"].Resources != (Resources{
		MemoryBytes: 4 << 30, CPUMillis: 2000, PIDs: 64,
	}) {
		return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
	}
	result := Slice6V2ResourceBudget{DoubleParseMemoryBytes: slice6V2DoubleParseHeadroom,
		CodingContainers: len(template.Slots), CodingWholeVolumeCount: len(template.Slots) * 3,
		ExternalServices: len(externalLimits)}
	for _, principal := range principals {
		if principal.Kind == "sandbox" {
			continue
		}
		if !addV2Capacity(&result, principal.Resources) {
			return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
		}
		result.StaticDeployments++
	}
	for _, slot := range sandboxSlots {
		if !addV2Capacity(&result, byName[slot.Template].Resources) ||
			!addV2Capacity(&result, sandboxGatewayLimits[slot.Template]) {
			return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
		}
		result.SandboxContainers += 2
	}
	for range template.Slots {
		if !addV2Capacity(&result, Resources{MemoryBytes: template.Limits.MemoryBytes,
			CPUMillis: template.Limits.CPUMillis, PIDs: template.Limits.PIDs}) {
			return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
		}
	}
	for _, limit := range externalLimits {
		if !addV2Capacity(&result, limit) {
			return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
		}
	}
	if result.MemoryBytes > math.MaxInt64-result.DoubleParseMemoryBytes {
		return Slice6V2ResourceBudget{}, ErrInvalidSlice6CapacityPlan
	}
	result.MemoryBytes += result.DoubleParseMemoryBytes
	return result, nil
}

func addV2Capacity(budget *Slice6V2ResourceBudget, limit Resources) bool {
	if budget.MemoryBytes > math.MaxInt64-limit.MemoryBytes ||
		budget.CPUMillis > math.MaxInt64-limit.CPUMillis ||
		budget.PIDs > math.MaxInt64-limit.PIDs {
		return false
	}
	budget.MemoryBytes += limit.MemoryBytes
	budget.CPUMillis += limit.CPUMillis
	budget.PIDs += limit.PIDs
	return true
}
