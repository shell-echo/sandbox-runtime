package phase6security

// CodingExecutionProfileBudget is the complete declared concurrency arithmetic
// for the new mode. Stopped preparation carriers have no running process charge;
// resident+command+scratch data+metadata stay within each frozen slot ceiling.
// Whole filesystem capacity is disk, not extra memory. Actual host/kernel,
// workload and filesystem headroom are separate gates, never inferred here.
type CodingExecutionProfileBudget struct {
	Topology                    Slice6V2ResourceBudget `json:"topology"`
	ResidentContainers          int                    `json:"resident_containers"`
	CommandContainers           int                    `json:"command_containers"`
	StoppedPreparationCarriers  int                    `json:"stopped_preparation_carriers"`
	ScratchDataBytes            int64                  `json:"scratch_data_bytes"`
	ScratchMetadataBytes        int64                  `json:"scratch_metadata_bytes"`
	ControlFilesystemMaxBytes   int64                  `json:"control_filesystem_max_bytes"`
	CodingStorageQuotaBytes     int64                  `json:"coding_storage_quota_bytes"`
	OtherScopesUnallocatedBytes int64                  `json:"other_scopes_unallocated_bytes"`
}

func CalculateCodingExecutionProfileBudget(principals []Principal, slots []SandboxIdentitySlot,
	template CodingCandidateExecutionTemplate, gateways, external map[string]Resources) (CodingExecutionProfileBudget, error) {
	if VerifyCodingExecutionProfileSlots(template, principals, slots) != nil || template.Scratch.BindResources(template.Resources) != nil {
		return CodingExecutionProfileBudget{}, ErrInvalidSlice6CapacityPlan
	}
	b, err := calculateV2NonCodingBudget(principals, slots, gateways, external)
	if err != nil {
		return CodingExecutionProfileBudget{}, err
	}
	n := len(template.Slots)
	b.CodingContainers = 3 * n // two running-capable roles and one stopped carrier
	b.CodingWholeVolumeCount = 4 * n
	for range template.Slots {
		r := template.Resources.Total
		if !addV2Capacity(&b, Resources{MemoryBytes: r.MemoryBytes, CPUMillis: r.CPUMillis, PIDs: r.PIDs}) {
			return CodingExecutionProfileBudget{}, ErrInvalidSlice6CapacityPlan
		}
	}
	return CodingExecutionProfileBudget{Topology: b, ResidentContainers: n, CommandContainers: n, StoppedPreparationCarriers: n,
		ScratchDataBytes: int64(n) * template.Scratch.Bytes, ScratchMetadataBytes: int64(n) * template.Scratch.MetadataBytes,
		ControlFilesystemMaxBytes: template.Storage.ControlVolumeBytes, CodingStorageQuotaBytes: template.Storage.CodingQuotaBytes,
		OtherScopesUnallocatedBytes: template.ControlStorage.OtherScopesUnallocatedBytes}, nil
}
