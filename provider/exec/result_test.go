package exec

import (
	"errors"
	"testing"
	"time"
)

func TestNewResultDerivesRetentionAndClonesEvidence(t *testing.T) {
	request := validRequest()
	code := 0
	resultError := &ResultError{Code: "SANDBOX_EXEC_OUTCOME_UNKNOWN", Message: "execution outcome requires reconciliation", Retryable: true, Outcome: ErrorOutcomeUnknown}
	result, err := NewResult(request, execTestNow, execTestNow.Add(time.Second), ResultOutcome{
		Status: ResultOutcomeUnknown, ExitCode: &code, StdoutReference: "ref:exec/stdout-1", Error: resultError,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.RetainedUntil.Equal(execTestNow.Add(time.Second + request.ResultRetention)) {
		t.Fatalf("retained until = %s", result.RetainedUntil)
	}
	code = 3
	resultError.Code = "MUTATED"
	resultError.Message = "mutated"
	if *result.ExitCode != 0 || result.Error.Code != "SANDBOX_EXEC_OUTCOME_UNKNOWN" || result.Error.Message != "execution outcome requires reconciliation" {
		t.Fatalf("NewResult() retained mutable evidence: %#v", result)
	}
}

func TestResultValidateRejectsUnsafeAndUnknownEvidence(t *testing.T) {
	request := validRequest()
	code := 0
	valid, err := NewResult(request, execTestNow, execTestNow.Add(time.Second), ResultOutcome{Status: ResultCompleted, ExitCode: &code, StdoutReference: "ref:exec/stdout-1"})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Result){
		"host path reference":   func(r *Result) { r.StdoutReference = "/var/lib/docker/stdout" },
		"invalid exit code":     func(r *Result) { value := 256; r.ExitCode = &value },
		"expired retention":     func(r *Result) { r.RetainedUntil = r.CompletedAt },
		"unknown without error": func(r *Result) { r.Status = ResultOutcomeUnknown; r.Error = nil },
		"unknown with known error": func(r *Result) {
			r.Status = ResultOutcomeUnknown
			r.Error = &ResultError{Code: "UNKNOWN", Message: "known failure", Outcome: ErrorOutcomeKnown}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := valid
			mutate(&result)
			if err := result.Validate(); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestCancellationIntentValidate(t *testing.T) {
	valid := CancellationIntent{
		SandboxID: "sandbox-1", OperationID: "cancel-1", AttemptID: "attempt-cancel-1", FencingToken: 2, ExpectedGeneration: 1,
		IdempotencyKey: "cancel-key", RequestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		Deadline: execTestNow.Add(time.Minute), TargetOperationID: "operation-1", TargetAttemptID: "attempt-1", Reason: CancellationCallerRequested,
	}
	if err := valid.Validate(execTestNow); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CancellationIntent){
		func(i *CancellationIntent) { i.Reason = "force_kill" },
		func(i *CancellationIntent) { i.Deadline = execTestNow },
		func(i *CancellationIntent) { i.TargetAttemptID = "bad/attempt" },
		func(i *CancellationIntent) { i.RequestDigest = "sha256:ABC" },
	} {
		intent := valid
		mutate(&intent)
		if err := intent.Validate(execTestNow); !errors.Is(err, ErrInvalidCancellation) {
			t.Fatalf("Validate() error = %v", err)
		}
	}
}
