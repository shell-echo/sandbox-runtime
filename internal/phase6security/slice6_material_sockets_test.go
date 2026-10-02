package phase6security

import (
	"encoding/json"
	"testing"
)

func TestSlice6MaterialSocketsCloseElevenOwnerAgentBoundaries(t *testing.T) {
	base, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(base.MaterialSockets) != 11 || VerifySlice6MaterialSocketBindings(base) != nil || base.Validate() != nil {
		t.Fatal("final candidate lacks eleven verified material endpoints")
	}
	for name, mutate := range map[string]func(*Profile){
		"missing endpoint":     func(p *Profile) { p.MaterialSockets = p.MaterialSockets[1:] },
		"duplicate endpoint":   func(p *Profile) { p.MaterialSockets[1] = p.MaterialSockets[0] },
		"cross owner":          func(p *Profile) { p.MaterialSockets[0].OwnerDeployment = p.MaterialSockets[1].OwnerDeployment },
		"owner uid":            func(p *Profile) { p.MaterialSockets[0].OwnerUID++ },
		"agent gid":            func(p *Profile) { p.MaterialSockets[0].AgentGID++ },
		"directory group mode": func(p *Profile) { p.MaterialSockets[0].DirectoryMode = 0o750 },
		"socket mode":          func(p *Profile) { p.MaterialSockets[0].SocketMode = 0o660 },
		"first frame deadline": func(p *Profile) { p.MaterialSockets[0].FirstFrameSeconds = 0 },
		"operation deadline":   func(p *Profile) { p.MaterialSockets[0].MaxOperationSeconds = 300 },
		"capacity":             func(p *Profile) { p.MaterialSockets[0].MaxConnections = 256 },
		"cleanup class":        func(p *Profile) { p.MaterialSockets[0].CleanupClass = "files" },
		"socket path":          func(p *Profile) { p.MaterialSockets[0].SocketPath += "-other" },
		"storage alias":        func(p *Profile) { p.MaterialSockets[0].SocketStorageID = p.MaterialSockets[1].SocketStorageID },
		"owner writable": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == p.MaterialSockets[0].OwnerDeployment {
					for j := range p.Principals[i].Mounts {
						if p.Principals[i].Mounts[j].StorageID == p.MaterialSockets[0].SocketStorageID {
							p.Principals[i].Mounts[j].ReadOnly = false
						}
					}
				}
			}
		},
		"extra reader": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == "guest-runtime" {
					p.Principals[i].Mounts = append(p.Principals[i].Mounts, Mount{Target: p.MaterialSockets[0].SocketDirectory,
						Kind: "private_socket", StorageID: p.MaterialSockets[0].SocketStorageID, ReadOnly: true})
				}
			}
		},
		"parent mount": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == p.MaterialSockets[0].AgentDeployment {
					p.Principals[i].Mounts = append(p.Principals[i].Mounts, Mount{Target: slice6MaterialSocketRoot,
						Kind: "tmpfs", MaxBytes: 4096})
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			profile, err := Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if VerifySlice6MaterialSocketBindings(profile) == nil {
				t.Fatal("drifted material boundary admitted")
			}
		})
	}
}
