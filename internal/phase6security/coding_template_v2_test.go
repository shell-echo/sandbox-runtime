package phase6security

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

func testCodingTemplateV2(t *testing.T) (CodingRuntimeTemplateV2, codingidentity.Plan) {
	t.Helper()
	slots := []codingidentity.Slot{
		{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000,
			InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace", OutputsVolume: "coding-0000-outputs"},
		{ID: "coding-0001", WorkloadUID: 57001, WorkloadGID: 58001,
			InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace", OutputsVolume: "coding-0001-outputs"},
	}
	limits := codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64}
	template, err := NewCodingRuntimeTemplateV2("linux/arm64/v8", codingimage.PublishedARM64ConfigDigest,
		codingimage.PublishedDescriptorSize,
		testCodingTemplateDigest("b"), testCodingTemplateDigest("c"), slots, limits)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := template.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: testCodingTemplateDigest("d"), OwnerDeployment: "provider-runtime",
		OwnerPrincipalDigest: template.OwnerPrincipalDigest, Namespace: "provider-coding",
		ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: digest, ImageDigest: template.Image.Descriptor.Digest,
		ImageConfigDigest: template.Image.ConfigDigest, NetworkMode: "none", Limits: limits,
		Capacity: codingidentity.LocalCandidateCapacity, Slots: slices.Clone(slots)}
	return template, plan
}

func testCodingTemplateDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }

func TestCodingRuntimeTemplateV2ClosedAndPlanBound(t *testing.T) {
	template, plan := testCodingTemplateV2(t)
	if template.Validate() != nil || template.BindPlan(plan) != nil {
		t.Fatal("valid v2 template/plan rejected")
	}
	if template.Image.Reference == "" || template.Image.SelectedManifestDigest == "" ||
		template.TmpfsTarget != "/tmp" || template.TmpfsMode != 0o700 || template.VolumePrepMode != 0o770 {
		t.Fatal("template omitted a closed runtime input")
	}
	document, err := EncodeCodingRuntimeTemplateV2(template)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCodingRuntimeTemplateV2(document)
	if err != nil || decoded.BindPlan(plan) != nil {
		t.Fatalf("canonical v2 round trip = %v", err)
	}
	for name, changed := range map[string][]byte{
		"unknown":      append(append([]byte{}, document[:len(document)-1]...), []byte(`,"docker_host":"unix:///var/run/docker.sock"}`)...),
		"duplicate":    append(append([]byte{}, document[:len(document)-1]...), []byte(`,"version":2}`)...),
		"noncanonical": append([]byte(" "), document...),
		"oversized":    bytes.Repeat([]byte("x"), MaxCodingTemplateBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCodingRuntimeTemplateV2(changed); !errors.Is(err, ErrInvalidCodingTemplate) {
				t.Fatalf("unsafe template accepted: %v", err)
			}
		})
	}
	wrongPlan := plan
	wrongPlan.TemplateDigest = testCodingTemplateDigest("0")
	if !errors.Is(template.BindPlan(wrongPlan), ErrInvalidCodingTemplate) {
		t.Fatal("template digest mismatch accepted")
	}
}

func TestCodingRuntimeTemplateV2RejectsDrift(t *testing.T) {
	template, _ := testCodingTemplateV2(t)
	for name, mutate := range map[string]func(*CodingRuntimeTemplateV2){
		"downgrade": func(v *CodingRuntimeTemplateV2) { v.Protocol = ProtocolID },
		"wrong image": func(v *CodingRuntimeTemplateV2) {
			v.Image.Reference = "example.test/coding@" + v.Image.Descriptor.Digest
		},
		"index as config": func(v *CodingRuntimeTemplateV2) { v.Image.ConfigDigest = v.Image.Descriptor.Digest },
		"wrong config":    func(v *CodingRuntimeTemplateV2) { v.Image.ConfigDigest = testCodingTemplateDigest("e") },
		"index size":      func(v *CodingRuntimeTemplateV2) { v.Image.Descriptor.Size++ },
		"manifest size":   func(v *CodingRuntimeTemplateV2) { v.Image.SelectedManifestSize++ },
		"wrong platform":  func(v *CodingRuntimeTemplateV2) { v.Image.Platform = "linux/ppc64le" },
		"wrong command":   func(v *CodingRuntimeTemplateV2) { v.Command[0] = "/bin/bash" },
		"missing path":    func(v *CodingRuntimeTemplateV2) { v.Environment = v.Environment[1:] },
		"changed path":    func(v *CodingRuntimeTemplateV2) { v.Environment[0] = "PATH=/usr/bin" },
		"duplicate path":  func(v *CodingRuntimeTemplateV2) { v.Environment = append(v.Environment, v.Environment[0]) },
		"extra env":       func(v *CodingRuntimeTemplateV2) { v.Environment = append(v.Environment, "HOST=/var/run/docker.sock") },
		"host network":    func(v *CodingRuntimeTemplateV2) { v.NetworkMode = "host" },
		"root write":      func(v *CodingRuntimeTemplateV2) { v.RootFilesystemReadOnly = false },
		"tmpfs public":    func(v *CodingRuntimeTemplateV2) { v.TmpfsMode = 0o777 },
		"inputs write":    func(v *CodingRuntimeTemplateV2) { v.Mounts[0].ReadOnly = false },
		"new mount":       func(v *CodingRuntimeTemplateV2) { v.Mounts = append(v.Mounts, CodingTemplateMountV2{Target: "/host"}) },
		"wrong prep":      func(v *CodingRuntimeTemplateV2) { v.VolumePrep = "root_helper" },
		"duplicate uid":   func(v *CodingRuntimeTemplateV2) { v.Slots[1].WorkloadUID = v.Slots[0].WorkloadUID },
		"volume alias":    func(v *CodingRuntimeTemplateV2) { v.Slots[1].WorkspaceVolume = v.Slots[0].WorkspaceVolume },
	} {
		t.Run(name, func(t *testing.T) {
			changed := template
			changed.Command = slices.Clone(template.Command)
			changed.Environment = slices.Clone(template.Environment)
			changed.Mounts = slices.Clone(template.Mounts)
			changed.Slots = slices.Clone(template.Slots)
			mutate(&changed)
			if !errors.Is(changed.Validate(), ErrInvalidCodingTemplate) {
				t.Fatal("drifted v2 template accepted")
			}
		})
	}
}
