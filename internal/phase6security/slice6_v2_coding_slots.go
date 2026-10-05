package phase6security

// VerifySlice6V2CodingSlots binds the two Coding workload identities and six
// whole-volume prefixes to the complete static and Browser/Desktop slot
// inventory. It is a v2-only subcheck, not a runnable Profile or a proof of
// physical volume ownership, capacity, or cleanup.
func VerifySlice6V2CodingSlots(template CodingRuntimeTemplateV2, principals []Principal,
	sandboxSlots []SandboxIdentitySlot) error {
	if template.Validate() != nil || len(principals) != len(slice6ApprovedDeploymentKinds)+len(slice6V2IdentityDelta) {
		return ErrInvalidProfile
	}
	byName := make(map[string]Principal, len(principals))
	uids, gids, storage := map[uint32]bool{}, map[uint32]bool{}, map[string]bool{}
	for _, principal := range principals {
		if _, duplicate := byName[principal.Name]; duplicate || uids[principal.UID] || gids[principal.GID] {
			return ErrInvalidProfile
		}
		if _, added := slice6V2IdentityDelta[principal.Name]; !added {
			if kind, approved := slice6ApprovedDeploymentKinds[principal.Name]; !approved || principal.Kind != kind {
				return ErrInvalidProfile
			}
		}
		byName[principal.Name] = principal
		uids[principal.UID], gids[principal.GID] = true, true
		for _, mount := range principal.Mounts {
			if mount.StorageID != "" {
				storage[mount.StorageID] = true
			}
		}
	}
	for name := range slice6V2IdentityDelta {
		if _, exists := byName[name]; !exists {
			return ErrInvalidProfile
		}
	}
	provider := byName[template.OwnerDeployment]
	if provider.Kind != "runtime" || template.OwnerDeployment != "provider-runtime" ||
		provider.PrincipalDigest != template.OwnerPrincipalDigest ||
		validateSandboxIdentitySlots(sandboxSlots, byName) != nil {
		return ErrInvalidProfile
	}
	for _, slot := range sandboxSlots {
		for _, uid := range []uint32{slot.WorkloadUID, slot.GatewayUID} {
			if uids[uid] {
				return ErrInvalidProfile
			}
			uids[uid] = true
		}
		for _, gid := range []uint32{slot.WorkloadGID, slot.GatewayGID} {
			if gids[gid] {
				return ErrInvalidProfile
			}
			gids[gid] = true
		}
	}
	for _, slot := range template.Slots {
		if uids[slot.WorkloadUID] || gids[slot.WorkloadGID] ||
			storage[slot.InputsVolume] || storage[slot.WorkspaceVolume] || storage[slot.OutputsVolume] {
			return ErrInvalidProfile
		}
		uids[slot.WorkloadUID], gids[slot.WorkloadGID] = true, true
	}
	return nil
}
