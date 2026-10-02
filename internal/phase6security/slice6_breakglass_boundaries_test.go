package phase6security

import (
	"encoding/json"
	"testing"
)

func TestSlice6BreakGlassFifteenSocketsAndEightFiniteTasks(t *testing.T) {
	base, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil || len(base.BreakGlassSockets) != 15 || len(base.BreakGlassOperatorTasks) != 8 ||
		VerifySlice6BreakGlassBoundaries(base) != nil || base.Validate() != nil {
		t.Fatalf("incomplete static break-glass authority: %v", err)
	}
	if base.BreakGlassSockets[0].Kind != "control" || base.BreakGlassSockets[0].OperationSet != "approve,issue,revoke,submit" ||
		base.BreakGlassSockets[1].Kind != "consume" || base.BreakGlassSockets[1].OperationSet != "consume" ||
		base.BreakGlassSockets[2].Kind != "delivery" || base.BreakGlassSockets[2].OperationSet != "deliver" {
		t.Fatal("break-glass operation directions are not closed")
	}
	for name, mutate := range map[string]func(*Profile){
		"missing consume socket":     func(p *Profile) { p.BreakGlassSockets = p.BreakGlassSockets[1:] },
		"duplicate socket":           func(p *Profile) { p.BreakGlassSockets[2] = p.BreakGlassSockets[1] },
		"control accepts consume":    func(p *Profile) { p.BreakGlassSockets[0].OperationSet += ",consume" },
		"consume accepts issue":      func(p *Profile) { p.BreakGlassSockets[1].OperationSet = "issue" },
		"cross agent target":         func(p *Profile) { p.BreakGlassSockets[1].TargetAgent = p.BreakGlassSockets[3].TargetAgent },
		"caller uid":                 func(p *Profile) { p.BreakGlassSockets[1].ClientUID++ },
		"directory mode":             func(p *Profile) { p.BreakGlassSockets[0].DirectoryMode = 0o750 },
		"socket mode":                func(p *Profile) { p.BreakGlassSockets[1].SocketMode = 0o660 },
		"storage alias":              func(p *Profile) { p.BreakGlassSockets[2].SocketStorageID = p.BreakGlassSockets[1].SocketStorageID },
		"operator task omitted":      func(p *Profile) { p.BreakGlassOperatorTasks = p.BreakGlassOperatorTasks[1:] },
		"operator task host network": func(p *Profile) { p.BreakGlassOperatorTasks[0].NetworkMode = "host" },
		"operator task root":         func(p *Profile) { p.BreakGlassOperatorTasks[0].UID = 0 },
		"operator task broad mount":  func(p *Profile) { p.BreakGlassOperatorTasks[0].Mount.Target = slice6BreakGlassRoot },
		"operator task more time":    func(p *Profile) { p.BreakGlassOperatorTasks[0].MaxExecutionSeconds = 900 },
		"extra principal reader": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == "guest-runtime" {
					p.Principals[i].Mounts = append(p.Principals[i].Mounts, Mount{Target: p.BreakGlassSockets[0].SocketDirectory,
						Kind: "private_socket", ReadOnly: true, StorageID: p.BreakGlassSockets[0].SocketStorageID})
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			changed.ProfileDigest = changed.Digest()
			if VerifySlice6BreakGlassBoundaries(changed) == nil {
				t.Fatal("drifted break-glass Profile boundary admitted")
			}
		})
	}
}
