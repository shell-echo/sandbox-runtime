package usage

import (
	"errors"
	"testing"
	"time"
)

var usageTestNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func validUsageEvidence() Evidence {
	return Evidence{
		EvidenceID: "usage-evidence-1", SandboxID: "sandbox-1", OperationID: "exec-operation-1", AttemptID: "exec-attempt-1", FencingToken: 2,
		Entries: []Entry{
			{EntryID: "entry-wall", SandboxID: "sandbox-1", OperationID: "exec-operation-1", Meter: MeterWallTime, Quantity: 1250, Unit: "milliseconds", MeterSource: SourceRuntime, EvidenceReference: "ref:usage/wall", OccurredAt: usageTestNow},
			{EntryID: "entry-count", SandboxID: "sandbox-1", OperationID: "exec-operation-1", Meter: MeterExecCount, Quantity: 1, Unit: "count", MeterSource: SourceReconciled, EvidenceReference: "ref:usage/count", OccurredAt: usageTestNow},
		},
		ReconciliationStatus: ReconciliationComplete, ObservedAt: usageTestNow, RetainedUntil: usageTestNow.Add(time.Hour), EvidenceDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
}

func TestEvidenceValidateCorrelatesMetersAndExpiry(t *testing.T) {
	evidence := validUsageEvidence()
	if err := evidence.Validate(usageTestNow); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Evidence){
		"unit mismatch":               func(e *Evidence) { e.Entries[0].Unit = "bytes" },
		"tenant correlation mismatch": func(e *Evidence) { e.Entries[0].SandboxID = "sandbox-other" },
		"too many entries":            func(e *Evidence) { e.Entries = append(e.Entries, make([]Entry, MaxEntries)...) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validUsageEvidence()
			mutate(&candidate)
			if err := candidate.Validate(usageTestNow); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
	if !errors.Is(evidence.Validate(evidence.RetainedUntil), ErrEvidenceExpired) {
		t.Fatal("expired evidence was not rejected")
	}
}

func TestEvidenceCloneCopiesEntries(t *testing.T) {
	evidence := validUsageEvidence()
	clone := evidence.Clone()
	clone.Entries[0].Quantity = 999
	if evidence.Entries[0].Quantity == clone.Entries[0].Quantity {
		t.Fatal("clone shares entries")
	}
}

func TestBrowserSessionMeterRequiresMilliseconds(t *testing.T) {
	evidence := validUsageEvidence()
	evidence.OperationID = "browser-operation-1"
	evidence.AttemptID = "browser-attempt-1"
	evidence.Entries = []Entry{{
		EntryID: "browser-duration-1", SandboxID: evidence.SandboxID, OperationID: evidence.OperationID,
		Meter: MeterBrowserSession, Quantity: 180000, Unit: "milliseconds", MeterSource: SourceRuntime,
		EvidenceReference: "ref:usage/browser-session-1", OccurredAt: usageTestNow,
	}}
	if err := evidence.Validate(usageTestNow); err != nil {
		t.Fatalf("browser session meter is invalid: %v", err)
	}
	evidence.Entries[0].Unit = "seconds"
	if err := evidence.Validate(usageTestNow); err == nil {
		t.Fatal("browser session meter accepted a non-Contract unit")
	}
}
