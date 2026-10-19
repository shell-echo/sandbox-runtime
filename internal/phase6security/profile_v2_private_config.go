package phase6security

import (
	"path"
	"slices"
	"strings"
)

// File purposes are private startup inputs, not a grant to admit the draft
// roster. Public callers must still pass the complete Profile-v2 validator.
func slice6PrivateConfigMountV2(deployment string) (Mount, bool) {
	var purpose string
	switch deployment {
	case "provider-docker-control", "provider-artifact-scanner":
		purpose = Slice6PeerCRLRoleFile
	case "provider-docker-control-tls-agent", "provider-artifact-scanner-tls-agent":
		purpose = Slice6PeerCRLSourcesFile
	default:
		return Slice6PrivateConfigMount(deployment)
	}
	files := []string{Slice6ProfileConfigFile, purpose}
	slices.Sort(files)
	return Mount{Target: Slice6PrivateConfigDirectory, Kind: "private_config", ReadOnly: true,
		MaxBytes: Slice6PrivateConfigMaxBytes, StorageID: deployment + "-private-config", PrivateFiles: strings.Join(files, ",")}, true
}

func verifyPrivateConfigMountsV2Fields(p ProfileV2) error {
	return verifyPrivateConfigMountsFields(p.Principals, Slice6V2ProvisionalStaticInventoryNames(), slice6PrivateConfigMountV2)
}

func VerifySlice6PrivateConfigPathV2(profile ProfileV2, deployment, filename, actualPath string) error {
	if profile.Validate() != nil {
		return ErrInvalidProfile
	}
	return verifyPrivateConfigPathV2Fields(profile, deployment, filename, actualPath)
}

func verifyPrivateConfigPathV2Fields(profile ProfileV2, deployment, filename, actualPath string) error {
	if verifyPrivateConfigMountsV2Fields(profile) != nil || filename == "" || actualPath != path.Join(Slice6PrivateConfigDirectory, filename) {
		return ErrInvalidProfile
	}
	want, ok := slice6PrivateConfigMountV2(deployment)
	if !ok || !slices.Contains(strings.Split(want.PrivateFiles, ","), filename) {
		return ErrInvalidProfile
	}
	for _, principal := range profile.Principals {
		if principal.Name == deployment && slices.Contains(principal.Mounts, want) {
			return nil
		}
	}
	return ErrInvalidProfile
}

func VerifySlice6ControllerLedgerMountsV2(profile ProfileV2) error {
	if profile.Validate() != nil {
		return ErrInvalidProfile
	}
	return verifyControllerLedgerMountsV2Fields(profile)
}

func verifyControllerLedgerMountsV2Fields(profile ProfileV2) error {
	owners := controllerLedgerOwners()
	control := profile.DockerControl
	if control.Deployment != "provider-docker-control" || control.ReceiptTarget != v2ReceiptTarget ||
		control.ReceiptMaxBytes != v2ReceiptMaxBytes || !namePattern.MatchString(control.ReceiptStorageID) {
		return ErrInvalidProfile
	}
	owners[control.Deployment] = Mount{Target: control.ReceiptTarget, Kind: "persistent_ledger", MaxBytes: control.ReceiptMaxBytes, StorageID: control.ReceiptStorageID}
	return verifyControllerLedgerMountsFields(profile.Principals, owners)
}
