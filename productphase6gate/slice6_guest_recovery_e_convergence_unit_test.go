//go:build phase6slice6gate

package productphase6gate

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func slice6EConvergenceFixture(t *testing.T) (*slice6EConvergenceCollector, slice6EConvergenceReceipt, []byte) {
	t.Helper()
	collector, err := slice6NewEConvergenceCollector(strings.Repeat("a", 32),
		"sha256:"+strings.Repeat("b", 64), strings.Repeat("c", 40),
		"sha256:"+strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	stages := [...]struct {
		kind, slot, result string
		count              int
	}{
		{"material", "product-migration-agent", "natural_exit", 1},
		{"tls", "product-migration-postgres-tls-agent", "physical_converged", 1},
		{"tls", "product-migration-agent-tls-agent", "physical_converged", 1},
		{"tls", "guest-tls-agent", "physical_converged", 1},
		{"material", "guest-agent", "stopped", 1},
		{"tls", "guest-agent-tls-agent", "physical_converged", 1},
		{"tls", "product-postgres-tls-agent", "physical_converged", 1},
		{"material", "product-runtime-agent", "stopped", 1},
		{"tls", "product-runtime-agent-tls-agent", "physical_converged", 1},
		{"tls", "product-tls-agent", "physical_converged", 1},
		{"controller", "breakglass", "physical_converged", 3},
		{"controller", "certificate", "sticky_credential_revoke", 1},
		{"controller", "credential", "physical_converged", 1},
		{"capacity", "monitor", "clean_join", 1},
	}
	index := 0
	for _, stage := range stages {
		ids := make([]string, 0, stage.count)
		for range stage.count {
			ids = append(ids, strings.Repeat(string("0123456789abcdef"[index]), 64))
			index++
		}
		if err := collector.record(stage.kind, stage.slot, stage.result, ids,
			struct{ Kind, Slot string }{stage.kind, stage.slot}); err != nil {
			t.Fatalf("record %s/%s: %v", stage.kind, stage.slot, err)
		}
	}
	refs := []string{"sha256:" + strings.Repeat("1", 64), "sha256:" + strings.Repeat("2", 64),
		"sha256:" + strings.Repeat("3", 64), "sha256:" + strings.Repeat("4", 64),
		"sha256:" + strings.Repeat("5", 64)}
	raw, receipt, err := collector.receipt(refs[0], refs[1], refs[2], refs[3], refs[4],
		"sticky_credential_revoke")
	if err != nil {
		t.Fatal(err)
	}
	return collector, receipt, raw
}

func TestSlice6EConvergenceFixedStageReplayRejectsDriftNoIssuer(t *testing.T) {
	collector, expected, raw := slice6EConvergenceFixture(t)
	if err := slice6VerifyEConvergenceReceipt(raw, expected); err != nil {
		t.Fatal(err)
	}
	if err := collector.record("tls", "guest-tls-agent", "physical_converged",
		[]string{strings.Repeat("f", 64)}, struct{}{}); err == nil {
		t.Fatal("duplicate slot accepted")
	}
	mutate := func(change func(*slice6EConvergenceReceipt)) []byte {
		copy := expected
		copy.Stages = append([]slice6EConvergenceStage(nil), expected.Stages...)
		for index := range copy.Stages {
			copy.Stages[index].ContainerIDs = append([]string(nil), copy.Stages[index].ContainerIDs...)
		}
		change(&copy)
		encoded, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for name, document := range map[string][]byte{
		"missing slot": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages = value.Stages[:13]
		}),
		"unknown slot": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages[0].Slot = "optional-agent"
		}),
		"duplicate slot": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages[1].Kind, value.Stages[1].Slot = value.Stages[0].Kind, value.Stages[0].Slot
		}),
		"wrong run": mutate(func(value *slice6EConvergenceReceipt) {
			value.RunID = strings.Repeat("f", 32)
		}),
		"reused container": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages[1].ContainerIDs[0] = value.Stages[0].ContainerIDs[0]
		}),
		"extra non-breakglass ID": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages[0].ContainerIDs = append(value.Stages[0].ContainerIDs, strings.Repeat("f", 64))
		}),
		"missing breakglass ID": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages[10].ContainerIDs = value.Stages[10].ContainerIDs[:2]
		}),
		"wrong exit class": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages[0].Result = "stopped"
		}),
		"unjoined outcome": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages[0].OutcomeDigest = ""
		}),
		"causal inversion": mutate(func(value *slice6EConvergenceReceipt) {
			first, second := value.Stages[0].ElapsedNanos, value.Stages[1].ElapsedNanos
			value.Stages[0], value.Stages[1] = value.Stages[1], value.Stages[0]
			value.Stages[0].Sequence, value.Stages[1].Sequence = 1, 2
			value.Stages[0].ElapsedNanos, value.Stages[1].ElapsedNanos = first, second
		}),
		"sticky washed green": mutate(func(value *slice6EConvergenceReceipt) {
			value.ControllerDrainClass = "clean_exit"
		}),
		"clock regression": mutate(func(value *slice6EConvergenceReceipt) {
			value.Stages[1].ElapsedNanos = value.Stages[0].ElapsedNanos - 1
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if slice6VerifyEConvergenceReceipt(document, expected) == nil {
				t.Fatal("invalid E helper convergence accepted")
			}
		})
	}
	unknown := append([]byte(`{"secret":"forbidden",`), raw[1:]...)
	if slice6VerifyEConvergenceReceipt(unknown, expected) == nil {
		t.Fatal("unknown field accepted")
	}
	equalTick := mutate(func(value *slice6EConvergenceReceipt) {
		value.Stages[1].ElapsedNanos = value.Stages[0].ElapsedNanos
	})
	if err := slice6VerifyEConvergenceReceipt(equalTick, expected); err != nil {
		t.Fatalf("equal observed clock tick with ordered Sequence rejected: %v", err)
	}
}

func TestSlice6EConvergenceIndependentFileReplayAndLateSyncFailureNoIssuer(t *testing.T) {
	collector, expected, raw := slice6EConvergenceFixture(t)
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	run, err := root.newRun(collector.runID)
	if err != nil {
		t.Fatal(err)
	}
	defer run.closeV2Incomplete()
	if err := run.writeV2BoundedPrivateFile(slice6EConvergenceFile, raw,
		slice6EConvergenceLimit, false); err != nil {
		t.Fatal(err)
	}
	digest := slice6ReceiptSHA256(raw)
	if err := slice6VerifyEConvergenceFile(rootPath, run.id, digest, expected); err != nil {
		t.Fatalf("independent reread failed: %v", err)
	}
	if slice6VerifyEConvergenceFile(rootPath, run.id, "sha256:"+strings.Repeat("0", 64), expected) == nil {
		t.Fatal("wrong externally supplied digest accepted")
	}
	secondID := strings.Repeat("e", 32)
	second, err := root.newRun(secondID)
	if err != nil {
		t.Fatal(err)
	}
	defer second.closeV2Incomplete()
	second.syncFile = func(*os.File) error { return errors.New("late sync failure") }
	if err := second.writeV2BoundedPrivateFile(slice6EConvergenceFile, raw,
		slice6EConvergenceLimit, false); err == nil {
		t.Fatal("late receipt sync failure published a success")
	}
	second.syncFile = (*os.File).Sync
}

func TestSlice6EConvergenceRecordRequiresFixedPerSlotIDCount(t *testing.T) {
	collector, err := slice6NewEConvergenceCollector(strings.Repeat("a", 32),
		"sha256:"+strings.Repeat("b", 64), strings.Repeat("c", 40),
		"sha256:"+strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{strings.Repeat("1", 64), strings.Repeat("2", 64)}
	if collector.record("tls", "guest-tls-agent", "physical_converged", ids, struct{}{}) == nil {
		t.Fatal("ordinary signer accepted two instance IDs")
	}
	if collector.record("controller", "breakglass", "physical_converged", ids, struct{}{}) == nil {
		t.Fatal("break-glass accepted fewer than three instance IDs")
	}
	if len(collector.stages) != 0 {
		t.Fatal("invalid fixed-slot attempt mutated convergence record")
	}
}
