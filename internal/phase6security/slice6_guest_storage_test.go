package phase6security

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestSlice6GuestStorageReceiptRejectsReplacementAndUnknownFields(t *testing.T) {
	identity := strings.Repeat("a", 32)
	receipt := Slice6GuestStorageReceipt{Protocol: "sandbox-runtime.guest-storage.v1",
		Identity: identity, StorageID: "guest-workspace"}
	document, err := json.Marshal(receipt)
	if err != nil || DecodeSlice6GuestStorageReceipt(document, identity, "guest-workspace") != nil {
		t.Fatal("canonical Guest volume identity rejected")
	}
	for _, candidate := range []string{
		`{"protocol":"sandbox-runtime.guest-storage.v1","identity":"` + identity + `","storage_id":"guest-state"}`,
		`{"protocol":"sandbox-runtime.guest-storage.v1","identity":"` + strings.Repeat("b", 32) + `","storage_id":"guest-workspace"}`,
		`{"protocol":"sandbox-runtime.guest-storage.v1","identity":"` + identity + `","storage_id":"guest-workspace","extra":true}`,
		`{"protocol":"sandbox-runtime.guest-storage.v1","identity":"` + identity + `","identity":"` + identity + `","storage_id":"guest-workspace"}`,
		string(document) + "\n",
	} {
		if DecodeSlice6GuestStorageReceipt([]byte(candidate), identity, "guest-workspace") == nil {
			t.Fatal("replaced, duplicated, unknown or noncanonical Guest volume identity accepted")
		}
	}
}

func TestSlice6GuestStorageIsExclusiveAndClosed(t *testing.T) {
	final, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil || VerifySlice6GuestStorageMounts(final) != nil {
		t.Fatalf("reviewed Guest storage unavailable: %v", err)
	}
	want := Slice6GuestStorageMounts()
	if len(want) != 5 || want[0].MaxBytes != 3<<30 || want[1].MaxBytes != 1<<20 ||
		want[2].MaxBytes != 1<<20 || !want[2].ReadOnly || want[3].MaxBytes != 8<<20 ||
		want[4].MaxBytes != 8<<20 {
		t.Fatal("Guest storage budget or read-only input drift")
	}
	clone := func() Profile {
		changed := final
		changed.Principals = slices.Clone(final.Principals)
		for index := range changed.Principals {
			changed.Principals[index].Mounts = slices.Clone(final.Principals[index].Mounts)
		}
		return changed
	}
	for name, change := range map[string]func(*Profile){
		"missing": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "guest-runtime" {
					p.Principals[index].Mounts = slices.DeleteFunc(p.Principals[index].Mounts,
						func(m Mount) bool { return m.StorageID == "guest-state" })
				}
			}
		},
		"duplicate": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "guest-runtime" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts, want[0])
				}
			}
		},
		"cross role": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "product-runtime" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts, want[0])
				}
			}
		},
		"nested": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "guest-runtime" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts,
						Mount{Target: Slice6GuestWorkspaceRoot + "/nested", Kind: "tmpfs", MaxBytes: 4096})
				}
			}
		},
		"read-only workspace": func(p *Profile) {
			for index := range p.Principals {
				for mount := range p.Principals[index].Mounts {
					if p.Principals[index].Mounts[mount].StorageID == "guest-workspace" {
						p.Principals[index].Mounts[mount].ReadOnly = true
					}
				}
			}
		},
		"writable inputs": func(p *Profile) {
			for index := range p.Principals {
				for mount := range p.Principals[index].Mounts {
					if p.Principals[index].Mounts[mount].StorageID == "guest-inputs" {
						p.Principals[index].Mounts[mount].ReadOnly = false
					}
				}
			}
		},
		"capacity": func(p *Profile) {
			for index := range p.Principals {
				for mount := range p.Principals[index].Mounts {
					if p.Principals[index].Mounts[mount].StorageID == "guest-state" {
						p.Principals[index].Mounts[mount].MaxBytes--
					}
				}
			}
		},
		"wrong tmpfs": func(p *Profile) {
			for index := range p.Principals {
				for mount := range p.Principals[index].Mounts {
					if p.Principals[index].Mounts[mount].Target == Slice6GuestTempRoot {
						p.Principals[index].Mounts[mount].MaxBytes++
					}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone()
			change(&changed)
			changed.ProfileDigest = changed.Digest()
			if VerifySlice6GuestStorageMounts(changed) == nil ||
				VerifySlice6DesiredFinalExternalProfile(changed) == nil {
				t.Fatal("Guest storage drift accepted")
			}
		})
	}
}
