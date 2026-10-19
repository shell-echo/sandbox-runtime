package phase6security

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
)

func testCodingExecutionProfile(t *testing.T) ProfileV2 {
	t.Helper()
	p := testCompleteV2Fields(t)
	old := p.CodingTemplate
	template, err := NewCodingCandidateExecutionTemplate(old.Image.Platform, old.OwnerPrincipalDigest, old.SeccompPolicyDigest, old.Slots)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewCodingReceiptNamespaceV3(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	budget, err := CalculateCodingExecutionProfileBudget(p.Principals, p.SandboxIdentitySlots, template, p.SandboxGatewayLimits, p.ExternalResourceLimits)
	if err != nil {
		t.Fatal(err)
	}
	p.CodingExecution = &CodingExecutionProfileV3{Protocol: CodingExecutionProfileProtocol, Template: template, Receipt: receipt, Budget: budget}
	p.CodingTemplate = CodingRuntimeTemplateV2{}
	p.ResourceBudget = Slice6V2ResourceBudget{}
	oldID := p.DockerControl.ReceiptStorageID
	p.DockerControl.ReceiptStorageID = receipt.StorageID
	for i := range p.Principals {
		for j := range p.Principals[i].Mounts {
			if p.Principals[i].Mounts[j].StorageID == oldID {
				p.Principals[i].Mounts[j].StorageID = receipt.StorageID
			}
		}
	}
	p.ProfileDigest = p.Digest()
	return p
}

func TestCodingExecutionProfileCompleteFieldBindingAndPublicHold(t *testing.T) {
	p := testCodingExecutionProfile(t)
	b, err := p.codingExecutionStorageBindingFields()
	if err != nil {
		t.Fatal("complete synthetic candidate fields", err)
	}
	d, _ := p.CodingExecution.Template.Digest()
	if b.ProfileDigest != p.ProfileDigest || b.TemplateDigest != d || b.StorageID != p.DockerControl.ReceiptStorageID || b.UID < 10000 || b.GID < 10000 {
		t.Fatal("binding was not derived from whole Profile")
	}
	for _, v := range p.Principals {
		if v.Name == "provider-docker-control" && (b.UID != v.UID || b.GID != v.GID || b.ControlPrincipalDigest != v.PrincipalDigest) {
			t.Fatal("wrong source principal")
		}
	}
	data, _ := json.Marshal(p)
	if p.Validate() == nil {
		t.Fatal("public Profile hold opened")
	}
	if _, err := DecodeV2(data); err == nil {
		t.Fatal("decoder hold opened")
	}
	if got, err := p.CodingExecutionStorageBinding(); err == nil || got.ProfileDigest != "" {
		t.Fatal("public storage binding bypassed admission")
	}
	decoded, err := decodeV2Canonical(data)
	if err != nil || decoded.validateFields() != nil {
		t.Fatal("candidate canonical chain", err)
	}
	for _, bad := range [][]byte{append([]byte(" "), data...), bytes.Replace(data, []byte(`"coding_execution":{`), []byte(`"coding_execution":null,"coding_execution":{`), 1), bytes.Replace(data, []byte(`"coding_execution":{`), []byte(`"coding_execution":{"extra":true,`), 1)} {
		if _, err := decodeV2Canonical(bad); err == nil {
			t.Fatal("ambiguous candidate Profile accepted")
		}
	}
}

func TestCodingExecutionProfileRejectsSelfConsistentSourceDrift(t *testing.T) {
	base := testCodingExecutionProfile(t)
	data, _ := json.Marshal(base)
	old := testCompleteV2Fields(t)
	cases := map[string]func(*ProfileV2){
		"old mode plus new":     func(p *ProfileV2) { p.CodingTemplate = old.CodingTemplate },
		"old capacity plus new": func(p *ProfileV2) { p.ResourceBudget = old.ResourceBudget },
		"no new mode":           func(p *ProfileV2) { p.CodingExecution = nil },
		"wrong protocol":        func(p *ProfileV2) { p.CodingExecution.Protocol = CodingTemplateProtocolV2 },
		"wrong candidate platform": func(p *ProfileV2) {
			x := &p.CodingExecution.Template
			old := p.CodingExecution.Template
			slots := old.Slots
			v, err := NewCodingCandidateExecutionTemplate("linux/amd64", old.OwnerPrincipalDigest, old.SeccompPolicyDigest, []codingidentity.Slot{slots[0].Data, slots[1].Data})
			if err != nil {
				t.Fatal(err)
			}
			*x = v
		},
		"caller-picked candidate": func(p *ProfileV2) {
			p.CodingExecution.Template.Candidate.ManifestDigest = testCodingTemplateDigest("b")
		},
		"owner":                func(p *ProfileV2) { p.CodingExecution.Template.OwnerPrincipalDigest = testCodingTemplateDigest("b") },
		"uid static collision": func(p *ProfileV2) { p.CodingExecution.Template.Slots[0].Data.WorkloadUID = p.Principals[0].UID },
		"gid dynamic collision": func(p *ProfileV2) {
			p.CodingExecution.Template.Slots[0].Data.WorkloadGID = p.SandboxIdentitySlots[0].GatewayGID
		},
		"scratch storage collision": func(p *ProfileV2) {
			p.Principals[0].Mounts = append(p.Principals[0].Mounts, Mount{StorageID: p.CodingExecution.Template.Slots[0].ScratchVolume})
		},
		"missing static":               func(p *ProfileV2) { p.Principals = p.Principals[1:] },
		"unrelated network omitted":    func(p *ProfileV2) { p.Networks = p.Networks[1:] },
		"unrelated trust edge omitted": func(p *ProfileV2) { p.TrustEdges = p.TrustEdges[1:] },
		"bad source digest":            func(p *ProfileV2) { p.EnvironmentDigest = "bad" },
		"old receipt volume":           func(p *ProfileV2) { p.CodingExecution.Receipt.StorageID = "control-receipts" },
		"receipt path alias":           func(p *ProfileV2) { p.CodingExecution.Receipt.Target += "/child" },
		"quota declared as passed":     func(p *ProfileV2) { p.CodingExecution.Receipt.PhysicalMode = "admitted" },
		"other scope enabled":          func(p *ProfileV2) { p.CodingExecution.Receipt.OtherScopes = "browser" },
		"shared receipt mount": func(p *ProfileV2) {
			p.Principals[0].Mounts = append(p.Principals[0].Mounts, Mount{StorageID: p.CodingExecution.Receipt.StorageID, Target: "/alias"})
		},
		"missing gateway resource":      func(p *ProfileV2) { delete(p.SandboxGatewayLimits, "browser-sandbox-runtime") },
		"missing external resource":     func(p *ProfileV2) { delete(p.ExternalResourceLimits, "postgres") },
		"under-count memory":            func(p *ProfileV2) { p.CodingExecution.Budget.Topology.MemoryBytes-- },
		"old volume count":              func(p *ProfileV2) { p.CodingExecution.Budget.Topology.CodingWholeVolumeCount = 6 },
		"scratch metadata omitted":      func(p *ProfileV2) { p.CodingExecution.Budget.ScratchMetadataBytes = 0 },
		"other scope headroom borrowed": func(p *ProfileV2) { p.CodingExecution.Budget.CodingStorageQuotaBytes++ },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			var p ProfileV2
			if json.Unmarshal(data, &p) != nil {
				t.Fatal("clone")
			}
			change(&p)
			p.ProfileDigest = p.Digest()
			if _, err := p.codingExecutionStorageBindingFields(); err == nil {
				t.Fatal("drift admitted")
			}
		})
	}
	base.ProfileDigest = testCodingTemplateDigest("f")
	if _, err := base.codingExecutionStorageBindingFields(); err == nil {
		t.Fatal("syntactically valid arbitrary Profile digest admitted")
	}
}

func TestCodingExecutionProfileBudgetCountsEveryDeclaredCeiling(t *testing.T) {
	p := testCodingExecutionProfile(t)
	x := p.CodingExecution
	b := x.Budget
	var memory, cpu, pids int64
	add := func(r Resources) { memory += r.MemoryBytes; cpu += r.CPUMillis; pids += r.PIDs }
	for _, r := range p.Principals {
		if r.Kind != "sandbox" {
			add(r.Resources)
		}
	}
	for _, s := range p.SandboxIdentitySlots {
		for _, r := range p.Principals {
			if r.Name == s.Template {
				add(r.Resources)
			}
		}
		add(p.SandboxGatewayLimits[s.Template])
	}
	for _, r := range p.ExternalResourceLimits {
		add(r)
	}
	for range x.Template.Slots {
		r := x.Template.Resources.Total
		add(Resources{MemoryBytes: r.MemoryBytes, CPUMillis: r.CPUMillis, PIDs: r.PIDs})
	}
	memory += 128 << 20
	if b.Topology.MemoryBytes != memory || b.Topology.CPUMillis != cpu || b.Topology.PIDs != pids ||
		b.Topology.CodingWholeVolumeCount != 8 || b.Topology.CodingContainers != 6 || b.ResidentContainers != 2 || b.CommandContainers != 2 || b.StoppedPreparationCarriers != 2 ||
		b.ScratchDataBytes != 64<<20 || b.ScratchMetadataBytes != 64<<20 || b.ControlFilesystemMaxBytes != 1<<30 || b.CodingStorageQuotaBytes != 512<<20 || b.OtherScopesUnallocatedBytes != 512<<20 {
		t.Fatalf("incomplete budget: %+v", b)
	}
}
