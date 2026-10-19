package phase6security

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

func TestCodingExecutionStorageAccountsForEscapedInternalRequest(t *testing.T) {
	// A domain-model boundary case, not an assertion that this body fits the
	// separate 256 KiB public wire limit. Never inherit the old intent's
	// 256 KiB internal document cap as an encoding-size calculation.
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	r := providerexec.Request{SandboxID: "sandbox", OperationID: "operation", AttemptID: "attempt",
		FencingToken: 1, ExpectedGeneration: 1, IdempotencyKey: "key", RequestDigest: testCodingTemplateDigest("a"),
		Deadline: now.Add(time.Minute), WorkingDirectory: "/workspace", ResultRetention: time.Hour,
		CaptureStdout: true, CaptureStderr: true}
	for range providerexec.MaxCommandItems {
		r.Command = append(r.Command, strings.Repeat("\u2028", providerexec.MaxCommandItemRunes))
	}
	if err := r.Validate(now); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) <= 256<<10 {
		t.Fatal("fixture no longer exercises JSON expansion")
	}
	s := codingidentity.NewExecutionStorage()
	c, err := s.Charge(codingidentity.CaptureBudget{Stdout: r.CaptureStdout, Stderr: r.CaptureStderr,
		MaxBytes: r.CaptureMaxBytes, RequestBytes: int64(len(b))})
	if err != nil || c.LedgerBytes < int64(len(b))+s.RecordEnvelopeBytes || c.OutputBytes != 32<<20 {
		t.Fatal("internal encoding/default output peak under-accounted")
	}
}

func TestCodingExecutionTemplateIsSeparateFrozenCandidate(t *testing.T) {
	old, plan := testCodingTemplateV2(t)
	before, _ := EncodeCodingRuntimeTemplateV2(old)
	next, err := NewCodingExecutionTemplate(old)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCodingExecutionTemplate(next)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCodingExecutionTemplate(encoded)
	if err != nil || decoded.Validate() != nil {
		t.Fatal("new canonical candidate roundtrip failed")
	}
	oldDigest, _ := old.Digest()
	newDigest, _ := next.Digest()
	if newDigest == oldDigest || newDigest == "" || next.Storage.PerStreamBytes != providerexec.MaxCaptureBytes {
		t.Fatal("candidate identity/capture Contract drift")
	}
	if _, err := DecodeCodingRuntimeTemplateV2(encoded); err == nil {
		t.Fatal("new mode accepted as old template")
	}
	if _, err := DecodeCodingExecutionTemplate(before); err == nil {
		t.Fatal("old template upgraded implicitly")
	}
	plan.TemplateDigest = newDigest
	if old.BindPlan(plan) == nil {
		t.Fatal("new template authorized old Plan")
	}
	after, _ := EncodeCodingRuntimeTemplateV2(old)
	if !bytes.Equal(before, after) {
		t.Fatal("old source was modified")
	}
	next.ResidentCommand[0] = "wrong"
	next.Environment[0] = "wrong"
	next.Slots[0].Data.WorkloadUID++
	after, _ = EncodeCodingRuntimeTemplateV2(old)
	if !bytes.Equal(before, after) {
		t.Fatal("candidate aliases source slices")
	}
	for name, b := range map[string][]byte{
		"previous candidate": bytes.Replace(encoded, []byte(CodingExecutionTemplateProtocol), []byte("sandbox-runtime.phase6-coding-execution-template.v1"), 1),
		"whitespace":         append([]byte(" "), encoded...),
		"duplicate":          append(append([]byte{}, encoded[:len(encoded)-1]...), []byte(`,"use_init":false}`)...),
		"unknown":            append(append([]byte{}, encoded[:len(encoded)-1]...), []byte(`,"docker_host":"unix:///socket"}`)...),
		"oversize":           bytes.Repeat([]byte("x"), MaxCodingExecutionTemplateBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCodingExecutionTemplate(b); err == nil {
				t.Fatal("noncanonical input admitted")
			}
		})
	}
}

func TestCodingExecutionTemplateRejectsUnfrozenResources(t *testing.T) {
	old, _ := testCodingTemplateV2(t)
	base, err := NewCodingExecutionTemplate(old)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CodingExecutionTemplate){
		"other scopes spent":    func(v *CodingExecutionTemplate) { v.ControlStorage.OtherScopesUnallocatedBytes-- },
		"layout coding differs": func(v *CodingExecutionTemplate) { v.ControlStorage.Coding.CodingQuotaBytes++ },
		"old mode":              func(v *CodingExecutionTemplate) { v.ResourceMode = CodingTemplateProtocolV2 },
		"wrong image":           func(v *CodingExecutionTemplate) { v.Image.ConfigDigest = testCodingTemplateDigest("a") },
		"metadata omitted":      func(v *CodingExecutionTemplate) { v.Scratch.MetadataBytes = 0 },
		"unbounded inode":       func(v *CodingExecutionTemplate) { v.Scratch.Inodes = 0 },
		"second command":        func(v *CodingExecutionTemplate) { v.Resources.MaxPossibleCommands = 2 },
		"full old runtime":      func(v *CodingExecutionTemplate) { v.Resources.Resident = v.Resources.Total },
		"budget changed":        func(v *CodingExecutionTemplate) { v.Resources.Command.MemoryBytes-- },
		"closure spent":         func(v *CodingExecutionTemplate) { v.Storage.ClosureReserveBytes-- },
		"host pid":              func(v *CodingExecutionTemplate) { v.PrivatePID = false },
		"init shim":             func(v *CodingExecutionTemplate) { v.UseInit = true },
		"logging":               func(v *CodingExecutionTemplate) { v.LogDriver = "json-file" },
		"scratch alias":         func(v *CodingExecutionTemplate) { v.Slots[0].ScratchVolume = v.Slots[0].Data.WorkspaceVolume },
		"slot alias":            func(v *CodingExecutionTemplate) { v.Slots[1] = v.Slots[0] },
		"writable inputs":       func(v *CodingExecutionTemplate) { v.DataMounts[0].ReadOnly = false },
		"capabilities":          func(v *CodingExecutionTemplate) { v.DropAllCapabilities = false },
		"rootfs":                func(v *CodingExecutionTemplate) { v.RootFilesystemReadOnly = false },
	} {
		t.Run(name, func(t *testing.T) {
			encoded, _ := json.Marshal(base)
			var changed CodingExecutionTemplate
			if json.Unmarshal(encoded, &changed) != nil {
				t.Fatal("fixture clone")
			}
			change(&changed)
			if changed.Validate() == nil {
				t.Fatal("unsafe/unfrozen candidate accepted")
			}
			if d, err := changed.Digest(); err == nil || d != "" {
				t.Fatal("invalid candidate acquired identity")
			}
		})
	}
}
