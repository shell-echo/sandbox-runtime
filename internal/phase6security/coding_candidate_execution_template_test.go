package phase6security

import (
	"bytes"
	"encoding/json"
	"testing"

	codingcandidate "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/candidate"
)

func TestCodingCandidateExecutionTemplateHasNoLegacyAdmission(t *testing.T) {
	old, plan := testCodingTemplateV2(t)
	oldBytes, _ := EncodeCodingRuntimeTemplateV2(old)
	previous, err := NewCodingExecutionTemplate(old)
	if err != nil {
		t.Fatal(err)
	}
	previousBytes, _ := EncodeCodingExecutionTemplate(previous)
	for _, platform := range []string{"linux/arm64/v8", "linux/amd64"} {
		t.Run(platform, func(t *testing.T) {
			v, err := NewCodingCandidateExecutionTemplate(platform, old.OwnerPrincipalDigest, old.SeccompPolicyDigest, old.Slots)
			if err != nil || v.Validate() != nil || v.Image.Location != "local" || v.Image.SelectedManifestDigest != "" || v.Image.Reference != v.Candidate.ManifestDigest {
				t.Fatal("candidate not bound", err)
			}
			b, err := EncodeCodingCandidateExecutionTemplate(v)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeCodingCandidateExecutionTemplate(b)
			d, digestErr := decoded.Digest()
			if err != nil || digestErr != nil || d == "" || d == plan.TemplateDigest {
				t.Fatal("new identity roundtrip")
			}
			plan.TemplateDigest = d
			if old.BindPlan(plan) == nil {
				t.Fatal("v3 authorized old Plan")
			}
			if _, err := DecodeCodingRuntimeTemplateV2(b); err == nil {
				t.Fatal("v3 decoded as runtime v2")
			}
			if _, err := DecodeCodingExecutionTemplate(b); err == nil {
				t.Fatal("v3 decoded as execution v2")
			}
			for _, bad := range [][]byte{oldBytes, previousBytes, append([]byte(" "), b...), bytes.Replace(b, []byte(CodingCandidateExecutionTemplateProtocol), []byte(CodingExecutionTemplateProtocol), 1), append(append([]byte{}, b[:len(b)-1]...), []byte(`,"candidate":null}`)...), append(append([]byte{}, b[:len(b)-1]...), []byte(`,"admitted":true}`)...), bytes.Repeat([]byte("x"), MaxCodingExecutionTemplateBytes+1)} {
				if _, err := DecodeCodingCandidateExecutionTemplate(bad); err == nil {
					t.Fatal("old/noncanonical document admitted")
				}
			}
			v.Slots[0].Data.WorkloadUID++
			v.ResidentCommand[0] = "wrong"
			v.Environment[0] = "wrong"
			after, _ := EncodeCodingRuntimeTemplateV2(old)
			if !bytes.Equal(after, oldBytes) {
				t.Fatal("new template aliased legacy source")
			}
		})
	}
}

func TestCodingCandidateExecutionTemplateRejectsUnsafeOrReboundPolicy(t *testing.T) {
	old, _ := testCodingTemplateV2(t)
	base, err := NewCodingCandidateExecutionTemplate("linux/arm64/v8", old.OwnerPrincipalDigest, old.SeccompPolicyDigest, old.Slots)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(base)
	for name, change := range map[string]func(*CodingCandidateExecutionTemplate){
		"legacy image": func(v *CodingCandidateExecutionTemplate) { v.Image = old.Image },
		"platform swap": func(v *CodingCandidateExecutionTemplate) {
			v.Candidate, _ = codingcandidate.LockedIdentity("linux/amd64")
		},
		"manifest as config": func(v *CodingCandidateExecutionTemplate) { v.Image.ConfigDigest = v.Image.Descriptor.Digest },
		"config as store id": func(v *CodingCandidateExecutionTemplate) {
			v.Image.Reference = v.Image.ConfigDigest
			v.Image.Descriptor.Digest = v.Image.ConfigDigest
		},
		"manifest in selected":      func(v *CodingCandidateExecutionTemplate) { v.Image.SelectedManifestDigest = v.Image.Descriptor.Digest },
		"recipe relabeled as clean": func(v *CodingCandidateExecutionTemplate) { v.Candidate.RecipeDigest = v.Candidate.SourceArchive },
		"false signature":           func(v *CodingCandidateExecutionTemplate) { v.Candidate.Status = "signed" },
		"root workload":             func(v *CodingCandidateExecutionTemplate) { v.Slots[0].Data.WorkloadUID = 0 },
		"uid collision":             func(v *CodingCandidateExecutionTemplate) { v.Slots[1].Data.WorkloadUID = v.Slots[0].Data.WorkloadUID },
		"gid collision":             func(v *CodingCandidateExecutionTemplate) { v.Slots[1].Data.WorkloadGID = v.Slots[0].Data.WorkloadGID },
		"unsorted slots":            func(v *CodingCandidateExecutionTemplate) { v.Slots[0], v.Slots[1] = v.Slots[1], v.Slots[0] },
		"scratch alias":             func(v *CodingCandidateExecutionTemplate) { v.Slots[0].ScratchVolume = v.Slots[0].Data.WorkspaceVolume },
		"second command":            func(v *CodingCandidateExecutionTemplate) { v.Resources.MaxPossibleCommands++ },
		"resident full ceiling":     func(v *CodingCandidateExecutionTemplate) { v.Resources.Resident = v.Resources.Total },
		"scratch metadata":          func(v *CodingCandidateExecutionTemplate) { v.Scratch.MetadataBytes = 0 },
		"scratch inodes":            func(v *CodingCandidateExecutionTemplate) { v.Scratch.Inodes = 0 },
		"other storage spent":       func(v *CodingCandidateExecutionTemplate) { v.ControlStorage.OtherScopesUnallocatedBytes = 0 },
		"closure storage spent":     func(v *CodingCandidateExecutionTemplate) { v.Storage.ClosureReserveBytes = 0 },
		"writable inputs":           func(v *CodingCandidateExecutionTemplate) { v.DataMounts[0].ReadOnly = false },
		"writable root":             func(v *CodingCandidateExecutionTemplate) { v.RootFilesystemReadOnly = false },
		"capabilities":              func(v *CodingCandidateExecutionTemplate) { v.DropAllCapabilities = false },
		"privileges":                func(v *CodingCandidateExecutionTemplate) { v.NoNewPrivileges = false },
		"network":                   func(v *CodingCandidateExecutionTemplate) { v.NetworkMode = "host" },
		"host pid":                  func(v *CodingCandidateExecutionTemplate) { v.PrivatePID = false },
		"init shim":                 func(v *CodingCandidateExecutionTemplate) { v.UseInit = true },
		"logging":                   func(v *CodingCandidateExecutionTemplate) { v.LogDriver = "json-file" },
		"runtime command":           func(v *CodingCandidateExecutionTemplate) { v.ResidentCommand[0] = "/bin/false" },
		"environment":               func(v *CodingCandidateExecutionTemplate) { v.Environment = append(v.Environment, "TOKEN=x") },
	} {
		t.Run(name, func(t *testing.T) {
			var v CodingCandidateExecutionTemplate
			if json.Unmarshal(b, &v) != nil {
				t.Fatal("fixture clone")
			}
			change(&v)
			if v.Validate() == nil {
				t.Fatal("unsafe candidate accepted")
			}
			if d, err := v.Digest(); err == nil || d != "" {
				t.Fatal("invalid candidate acquired digest")
			}
		})
	}
}
