package phase6security

import (
	"slices"
	"strings"
)

const Slice6ControllerLedgerMaxBytes int64 = 20 << 20

// Slice6ControllerLedgerMount is the closed persistent state allocation for
// the two live issuers. The bootstrap operator creates only the empty volume;
// the corresponding non-root controller creates and replaces its ledger.
func Slice6ControllerLedgerMount(deployment string) (Mount, string, error) {
	var directory, storage string
	switch deployment {
	case "certificate-controller":
		directory, storage = "/var/lib/phase6-certificate-controller", "certificate-controller-ledger"
	case "workload-credential-controller":
		directory, storage = "/var/lib/phase6-credential-controller", "credential-controller-ledger"
	default:
		return Mount{}, "", errSlice6DesiredInventory
	}
	return Mount{Target: directory, Kind: "persistent_ledger", MaxBytes: Slice6ControllerLedgerMaxBytes,
		StorageID: storage}, directory + "/ledger.json", nil
}

// AttachSlice6ControllerLedgerMounts is used by both the synthetic final
// target and the source-bound finalizer, so neither can freeze a partial R.
func AttachSlice6ControllerLedgerMounts(principals []Principal) ([]Principal, error) {
	result := slices.Clone(principals)
	found := 0
	for index := range result {
		if result[index].Name != "certificate-controller" && result[index].Name != "workload-credential-controller" {
			continue
		}
		mount, _, err := Slice6ControllerLedgerMount(result[index].Name)
		if err != nil {
			return nil, err
		}
		result[index].Mounts = append(slices.Clone(result[index].Mounts), mount)
		found++
	}
	if found != 2 || VerifySlice6ControllerLedgerMounts(Profile{Principals: result}) != nil {
		return nil, errSlice6DesiredInventory
	}
	return result, nil
}

// VerifySlice6ControllerLedgerMounts rejects aliases and path nesting across
// every principal, not just a missing mount on the two owners.
func VerifySlice6ControllerLedgerMounts(profile Profile) error {
	owners := []string{"certificate-controller", "workload-credential-controller"}
	for _, principal := range profile.Principals {
		for _, mount := range principal.Mounts {
			if mount.Kind != "persistent_ledger" {
				continue
			}
			// Egress policy authorities have their own separately reviewed
			// ledger allocation. The two controller ledgers are otherwise
			// the entire approved persistent state surface for Slice 6.
			policyAuthority := false
			for _, spec := range slice6DesiredEgress {
				if spec.authority == principal.Name && mount.Target == spec.ledgerTarget &&
					mount.StorageID == spec.ledgerStorageID && mount.MaxBytes == 1<<20 && !mount.ReadOnly {
					policyAuthority = true
					break
				}
			}
			if policyAuthority {
				continue
			}
			want, _, err := Slice6ControllerLedgerMount(principal.Name)
			if err != nil || mount != want {
				return errSlice6DesiredInventory
			}
		}
	}
	for _, owner := range owners {
		want, _, err := Slice6ControllerLedgerMount(owner)
		if err != nil {
			return errSlice6DesiredInventory
		}
		found := 0
		for _, principal := range profile.Principals {
			for _, mount := range principal.Mounts {
				if mount.StorageID == want.StorageID || mount.Target == want.Target ||
					strings.HasPrefix(mount.Target, want.Target+"/") ||
					strings.HasPrefix(want.Target, mount.Target+"/") {
					if principal.Name != owner || mount != want {
						return errSlice6DesiredInventory
					}
					found++
				}
			}
		}
		if found != 1 {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
