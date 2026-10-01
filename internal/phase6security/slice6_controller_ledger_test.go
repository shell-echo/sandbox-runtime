package phase6security

import (
	"slices"
	"testing"
)

func TestSlice6ControllerLedgersAreSeparateClosedMounts(t *testing.T) {
	final, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil || VerifySlice6ControllerLedgerMounts(final) != nil {
		t.Fatalf("reviewed controller ledgers absent: %v", err)
	}
	for _, owner := range []string{"certificate-controller", "workload-credential-controller"} {
		mount, path, err := Slice6ControllerLedgerMount(owner)
		if err != nil || mount.ReadOnly || mount.MaxBytes != 20<<20 ||
			path != mount.Target+"/ledger.json" {
			t.Fatalf("invalid %s ledger authority", owner)
		}
	}
	if _, _, err := Slice6ControllerLedgerMount("provider-runtime"); err == nil {
		t.Fatal("unreviewed ledger owner admitted")
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
				if p.Principals[index].Name == "certificate-controller" {
					p.Principals[index].Mounts = slices.DeleteFunc(p.Principals[index].Mounts,
						func(m Mount) bool { return m.StorageID == "certificate-controller-ledger" })
				}
			}
		},
		"readonly": func(p *Profile) {
			for index := range p.Principals {
				for mount := range p.Principals[index].Mounts {
					if p.Principals[index].Mounts[mount].StorageID == "credential-controller-ledger" {
						p.Principals[index].Mounts[mount].ReadOnly = true
					}
				}
			}
		},
		"capacity": func(p *Profile) {
			for index := range p.Principals {
				for mount := range p.Principals[index].Mounts {
					if p.Principals[index].Mounts[mount].StorageID == "credential-controller-ledger" {
						p.Principals[index].Mounts[mount].MaxBytes--
					}
				}
			}
		},
		"shared": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "gateway-runtime" {
					mount, _, _ := Slice6ControllerLedgerMount("certificate-controller")
					p.Principals[index].Mounts = append(p.Principals[index].Mounts, mount)
				}
			}
		},
		"nested": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "certificate-controller" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts, Mount{
						Target: "/var/lib/phase6-certificate-controller/nested", Kind: "tmpfs", MaxBytes: 4096})
				}
			}
		},
		"extra controller ledger": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "certificate-controller" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts, Mount{
						Target: "/var/lib/phase6-extra", Kind: "persistent_ledger", MaxBytes: 4096,
						StorageID: "phase6-extra-ledger"})
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone()
			change(&changed)
			changed.ProfileDigest = changed.Digest()
			if VerifySlice6ControllerLedgerMounts(changed) == nil {
				t.Fatal("controller ledger drift accepted")
			}
		})
	}
}
