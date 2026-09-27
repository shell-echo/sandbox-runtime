package phase6security

// Slice6DesiredUIDGID freezes each static container's non-root identity from
// the reviewed 20000/30000 partitions. Dynamic sandbox workload/gateway
// account slots are separately constrained by SandboxIdentitySlots and the
// actual Desktop image account allowlist before launch.
func Slice6DesiredUIDGID() map[string][2]uint32 {
	names := slice6ApprovedDeploymentNames()
	result := make(map[string][2]uint32, len(names))
	for index, name := range names {
		result[name] = [2]uint32{uint32(20000 + index), uint32(30000 + index)}
	}
	return result
}

func VerifySlice6DesiredPrincipalIDs(profile Profile) error {
	if profile.Validate() != nil {
		return errSlice6DesiredInventory
	}
	wanted := Slice6DesiredUIDGID()
	if len(profile.Principals) != len(wanted) {
		return errSlice6DesiredInventory
	}
	for _, principal := range profile.Principals {
		pair, ok := wanted[principal.Name]
		if !ok || principal.UID != pair[0] || principal.GID != pair[1] {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
