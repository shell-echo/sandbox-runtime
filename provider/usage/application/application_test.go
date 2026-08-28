package application

import (
	"context"
	"errors"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	usagememory "github.com/shell-echo/sandbox-runtime/provider/usage/memory"
)

var usageApplicationTime = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

type usageExecSource struct {
	view      provideroperation.View
	viewErr   error
	result    providerexec.Result
	resultErr error
	reads     int
}

func (s *usageExecSource) ReadOperation(context.Context, string) (provideroperation.View, error) {
	s.reads++
	return s.view, s.viewErr
}

func (s *usageExecSource) GetResult(context.Context, string) (providerexec.Result, error) {
	return s.result, s.resultErr
}

func TestResultCollectorPersistsOnlyDefensiblePartialUsage(t *testing.T) {
	now := usageApplicationTime.Add(2 * time.Second)
	repository, _ := usagememory.NewRepository(usagememory.ClockFunc(func() time.Time { return now }))
	collector, _ := NewResultCollector(repository, ClockFunc(func() time.Time { return now }))
	result := usageResult(providerexec.ResultCompleted)
	if err := collector.ObserveResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if err := collector.ObserveResult(context.Background(), result); err != nil {
		t.Fatalf("idempotent result replay: %v", err)
	}
	evidence, err := repository.GetEvidence(context.Background(), result.OperationID, usageApplicationTime.Add(2*time.Second))
	if err != nil || evidence.ReconciliationStatus != usage.ReconciliationPartial || len(evidence.Entries) != 2 {
		t.Fatalf("usage evidence = %#v, %v", evidence, err)
	}
	if evidence.Entries[0].Meter != usage.MeterWallTime || evidence.Entries[0].Quantity != 1500 || evidence.Entries[1].Meter != usage.MeterExecCount || evidence.Entries[1].Quantity != 1 {
		t.Fatalf("usage entries = %#v", evidence.Entries)
	}
	unknown := usageResult(providerexec.ResultOutcomeUnknown)
	unknown.OperationID = "exec-operation-unknown"
	unknown.Error = &providerexec.ResultError{Code: "SANDBOX_EXEC_OUTCOME_UNKNOWN", Message: "execution outcome requires reconciliation", Retryable: true, Outcome: providerexec.ErrorOutcomeUnknown}
	if err := collector.ObserveResult(context.Background(), unknown); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetEvidence(context.Background(), unknown.OperationID, usageApplicationTime.Add(2*time.Second)); !errors.Is(err, usage.ErrEvidenceNotFound) {
		t.Fatalf("unknown result created usage evidence: %v", err)
	}
}

func TestReaderDistinguishesUnknownPendingAvailableAndExpired(t *testing.T) {
	for _, test := range []struct {
		name    string
		source  *usageExecSource
		readAt  time.Time
		wantErr error
		wantOK  bool
	}{
		{name: "unknown", source: &usageExecSource{viewErr: provideroperation.ErrNotFound}, readAt: usageApplicationTime.Add(2 * time.Second), wantErr: usage.ErrEvidenceNotFound},
		{name: "pending", source: &usageExecSource{view: usageView(provideroperation.StatusRunning)}, readAt: usageApplicationTime.Add(2 * time.Second), wantErr: usage.ErrEvidenceUnavailable},
		{name: "available", source: &usageExecSource{view: usageView(provideroperation.StatusSucceeded), result: usageResult(providerexec.ResultCompleted)}, readAt: usageApplicationTime.Add(2 * time.Second), wantOK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, _ := usagememory.NewRepository(usagememory.ClockFunc(func() time.Time { return usageApplicationTime.Add(2 * time.Second) }))
			collector, _ := NewResultCollector(repository, ClockFunc(func() time.Time { return usageApplicationTime.Add(2 * time.Second) }))
			reader, _ := NewReader(repository, test.source, collector)
			evidence, err := reader.GetEvidence(context.Background(), "exec-operation-1", test.readAt)
			if test.wantOK {
				if err != nil || evidence.OperationID != "exec-operation-1" {
					t.Fatalf("GetEvidence() = %#v, %v", evidence, err)
				}
				if _, err := reader.GetEvidence(context.Background(), "exec-operation-1", evidence.RetainedUntil); !errors.Is(err, usage.ErrEvidenceExpired) {
					t.Fatalf("expired GetEvidence() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("GetEvidence() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func usageResult(status providerexec.ResultStatus) providerexec.Result {
	exitCode := 0
	return providerexec.Result{
		OperationID: "exec-operation-1", AttemptID: "exec-attempt-1", FencingToken: 2, SandboxID: "sandbox-1",
		Status: status, ExitCode: &exitCode, StartedAt: usageApplicationTime,
		CompletedAt: usageApplicationTime.Add(1500 * time.Millisecond), RetainedUntil: usageApplicationTime.Add(time.Hour),
	}
}

func usageView(status provideroperation.Status) provideroperation.View {
	return provideroperation.View{
		OperationID: "exec-operation-1", AttemptID: "exec-attempt-1", FencingToken: 2, SandboxID: "sandbox-1",
		Type: provideroperation.TypeExec, Status: status, ProviderOperationID: "exec-operation-1",
		ResultReference: "ref:exec/exec-operation-1/result", ObservedAt: usageApplicationTime,
	}
}
