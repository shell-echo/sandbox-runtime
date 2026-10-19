package codingidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	ExecutionResourcesProtocol = "sandbox-runtime.coding-execution-resources.v1"
	SharedScratchBytes         = int64(32 << 20)
)

// ExecutionResources is a prospective partition of ONE allocation's existing
// limit. It does not extend Plan v1 or authorize another container in that
// plan's two-container/three-volume resource set. A new complete Profile and
// resource/receipt protocol must adopt it before any production dispatch.
//
// The whole shared scratch size is counted in addition to both container
// memory limits: do not rely on which cgroup Docker/kernel charges for shared
// pages. Private /dev/shm and other private memory remain inside each container
// limit; daemon/kernel and Control output/storage need separate role budgets.
type ExecutionResources struct {
	Protocol            string `json:"protocol"`
	Total               Limits `json:"total"`
	Resident            Limits `json:"resident"`
	Command             Limits `json:"command"`
	ScratchBytes        int64  `json:"scratch_bytes"`
	MaxPossibleCommands int    `json:"max_possible_commands"`
}

func (r ExecutionResources) Validate() error {
	if r.Protocol != ExecutionResourcesProtocol || r.Total.Validate() != nil ||
		r.Resident.Validate() != nil || r.Command.Validate() != nil ||
		r.ScratchBytes != SharedScratchBytes || r.MaxPossibleCommands != 1 {
		return ErrInvalidPlan
	}
	// Compare by subtraction after validating positive bounds. This preserves
	// overflow safety even if a future limits range is increased.
	if r.Resident.MemoryBytes > r.Total.MemoryBytes ||
		r.Command.MemoryBytes > r.Total.MemoryBytes-r.Resident.MemoryBytes ||
		r.ScratchBytes > r.Total.MemoryBytes-r.Resident.MemoryBytes-r.Command.MemoryBytes ||
		r.Resident.CPUMillis > r.Total.CPUMillis ||
		r.Command.CPUMillis > r.Total.CPUMillis-r.Resident.CPUMillis ||
		r.Resident.PIDs > r.Total.PIDs || r.Command.PIDs > r.Total.PIDs-r.Resident.PIDs {
		return ErrInvalidPlan
	}
	return nil
}

// BindCeiling checks the old slot's ceiling without changing that Plan or
// treating this resource partition as a new physical resource authority.
func (r ExecutionResources) BindCeiling(p Plan) error {
	if p.Validate() != nil || r.Validate() != nil || p.Limits != r.Total {
		return ErrInvalidPlan
	}
	return nil
}

func (r ExecutionResources) Digest() (string, error) {
	if r.Validate() != nil {
		return "", ErrInvalidPlan
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", ErrInvalidPlan
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/coding-execution-resources/v1\x00"), b...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
