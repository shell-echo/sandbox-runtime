package codingidentity

import (
	"encoding/json"
	"math"
	"testing"
)

func testExecutionResources() ExecutionResources {
	return ExecutionResources{Protocol: ExecutionResourcesProtocol, Total: testPlan().Limits,
		Resident:     Limits{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16},
		Command:      Limits{MemoryBytes: 928 << 20, CPUMillis: 900, PIDs: 48},
		ScratchBytes: SharedScratchBytes, MaxPossibleCommands: 1}
}

func TestExecutionResourcesKeepWholeSlotCeiling(t *testing.T) {
	r := testExecutionResources()
	plan := testPlan()
	before, _ := json.Marshal(plan)
	if r.Validate() != nil || r.BindCeiling(plan) != nil {
		t.Fatal("exact bounded partition rejected")
	}
	if r.Resident.MemoryBytes+r.Command.MemoryBytes+r.ScratchBytes != r.Total.MemoryBytes ||
		r.Resident.CPUMillis+r.Command.CPUMillis != r.Total.CPUMillis ||
		r.Resident.PIDs+r.Command.PIDs != r.Total.PIDs {
		t.Fatal("fixture no longer exercises the exact limits")
	}
	first, err := r.Digest()
	if err != nil || !digest.MatchString(first) {
		t.Fatal("partition digest unavailable")
	}
	changed := r
	changed.Resident.CPUMillis--
	second, err := changed.Digest()
	if err != nil || first == second {
		t.Fatal("resource change failed to change source identity")
	}
	after, _ := json.Marshal(plan)
	if string(before) != string(after) {
		t.Fatal("prospective partition rewrote old plan")
	}
	plan.Limits.MemoryBytes++
	if r.BindCeiling(plan) == nil || r.BindCeiling(Plan{}) == nil {
		t.Fatal("different or invalid slot ceiling accepted")
	}
}

func TestExecutionResourcesRejectUnaccountedRuntime(t *testing.T) {
	for name, mutate := range map[string]func(*ExecutionResources){
		"old full runtime plus command": func(r *ExecutionResources) { r.Resident = r.Total },
		"scratch not counted":           func(r *ExecutionResources) { r.Command.MemoryBytes += r.ScratchBytes },
		"one memory byte over":          func(r *ExecutionResources) { r.Command.MemoryBytes++ },
		"one CPU millis over":           func(r *ExecutionResources) { r.Command.CPUMillis++ },
		"one PID over":                  func(r *ExecutionResources) { r.Command.PIDs++ },
		"extra possible command":        func(r *ExecutionResources) { r.MaxPossibleCommands = 2 },
		"zero possible commands":        func(r *ExecutionResources) { r.MaxPossibleCommands = 0 },
		"missing scratch":               func(r *ExecutionResources) { r.ScratchBytes = 0 },
		"extra scratch":                 func(r *ExecutionResources) { r.ScratchBytes++ },
		"unbounded resident":            func(r *ExecutionResources) { r.Resident.PIDs = -1 },
		"invalid command":               func(r *ExecutionResources) { r.Command.MemoryBytes = 0 },
		"overflowing command":           func(r *ExecutionResources) { r.Command.MemoryBytes = math.MaxInt64 },
		"overflowing total":             func(r *ExecutionResources) { r.Total.PIDs = math.MaxInt64 },
		"unknown protocol":              func(r *ExecutionResources) { r.Protocol += "x" },
	} {
		t.Run(name, func(t *testing.T) {
			r := testExecutionResources()
			mutate(&r)
			if r.Validate() == nil || r.BindCeiling(testPlan()) == nil {
				t.Fatal("unaccounted partition accepted")
			}
			if d, err := r.Digest(); err == nil || d != "" {
				t.Fatal("invalid partition acquired source identity")
			}
		})
	}
}
