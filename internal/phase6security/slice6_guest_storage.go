package phase6security

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path"
	"slices"
	"strings"
)

const (
	Slice6GuestWorkspaceRoot          = "/workspace"
	Slice6GuestStateRoot              = "/var/lib/sandbox-runtime/guest-state"
	Slice6GuestInputsRoot             = "/inputs"
	Slice6GuestOutputsRoot            = "/outputs"
	Slice6GuestTempRoot               = "/tmp"
	Slice6GuestInputsManifestFileName = "input-manifest.json"
	Slice6GuestInputsManifest         = `{"protocol":"sandbox-runtime.guest-inputs.v1","entries":[]}`
)

type Slice6GuestStorageReceipt struct {
	Protocol  string `json:"protocol"`
	Identity  string `json:"identity"`
	StorageID string `json:"storage_id"`
}

func (r Slice6GuestStorageReceipt) Validate(identity, storageID string) error {
	decoded, err := hex.DecodeString(identity)
	if err != nil || len(identity) != 32 || hex.EncodeToString(decoded) != identity ||
		r.Protocol != "sandbox-runtime.guest-storage.v1" || r.Identity != identity ||
		r.StorageID != storageID || (storageID != "guest-workspace" && storageID != "guest-state" && storageID != "guest-inputs") {
		return errSlice6DesiredInventory
	}
	return nil
}

func DecodeSlice6GuestStorageReceipt(document []byte, identity, storageID string) error {
	var receipt Slice6GuestStorageReceipt
	if len(document) < 1 || len(document) > 256 || json.Unmarshal(document, &receipt) != nil ||
		receipt.Validate(identity, storageID) != nil {
		return errSlice6DesiredInventory
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, document) {
		return errSlice6DesiredInventory
	}
	return nil
}

// These bytes are local admission budgets, not Docker named-volume quotas.
// In particular, three GiB does not prove that every valid 10,000-entry
// materialization fits: implicit parent directories and filesystem metadata
// have no fixed bound in the current business protocol.
func Slice6GuestStorageMounts() []Mount {
	return []Mount{
		{Target: Slice6GuestWorkspaceRoot, Kind: "guest_storage", StorageID: "guest-workspace", MaxBytes: 3 << 30},
		{Target: Slice6GuestStateRoot, Kind: "guest_storage", StorageID: "guest-state", MaxBytes: 1 << 20},
		{Target: Slice6GuestInputsRoot, Kind: "guest_storage", StorageID: "guest-inputs", ReadOnly: true, MaxBytes: 1 << 20},
		{Target: Slice6GuestOutputsRoot, Kind: "tmpfs", MaxBytes: 8 << 20},
		{Target: Slice6GuestTempRoot, Kind: "tmpfs", MaxBytes: 8 << 20},
	}
}

func AttachSlice6GuestStorageMounts(principals []Principal) ([]Principal, error) {
	result := slices.Clone(principals)
	found := 0
	for index := range result {
		if result[index].Name != "guest-runtime" {
			continue
		}
		result[index].Mounts = append(slices.Clone(result[index].Mounts), Slice6GuestStorageMounts()...)
		found++
	}
	if found != 1 || VerifySlice6GuestStorageMounts(Profile{Principals: result}) != nil {
		return nil, errSlice6DesiredInventory
	}
	return result, nil
}

// VerifySlice6GuestStorageMounts freezes one Guest-only storage surface and
// rejects aliasing with every other role-owned socket, config, trust or state
// path. Ordinary Docker volumes have no hard physical quota by this check.
func VerifySlice6GuestStorageMounts(profile Profile) error {
	want := Slice6GuestStorageMounts()
	guestCount := 0
	for _, principal := range profile.Principals {
		if principal.Name == "guest-runtime" {
			guestCount++
		}
		for _, mount := range principal.Mounts {
			for _, expected := range want {
				storageAlias := mount.StorageID != "" && mount.StorageID == expected.StorageID
				pathAlias := principal.Name == "guest-runtime" &&
					(mount.Target == expected.Target ||
						strings.HasPrefix(mount.Target, expected.Target+"/") ||
						strings.HasPrefix(expected.Target, mount.Target+"/"))
				if storageAlias || pathAlias {
					if principal.Name != "guest-runtime" || mount != expected {
						return errSlice6DesiredInventory
					}
				}
			}
			if mount.Kind == "guest_storage" && (principal.Name != "guest-runtime" ||
				!slices.Contains(want, mount)) {
				return errSlice6DesiredInventory
			}
			if path.Clean(mount.Target) != mount.Target {
				return errSlice6DesiredInventory
			}
		}
	}
	if guestCount != 1 {
		return errSlice6DesiredInventory
	}
	for _, expected := range want {
		found := 0
		for _, principal := range profile.Principals {
			if principal.Name != "guest-runtime" {
				continue
			}
			for _, mount := range principal.Mounts {
				if mount == expected {
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
