package browser

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var modelTestTime = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

func validOpenRequest() OpenRequest {
	return OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "provider-revision-1", OperationID: "browser-operation-1", AttemptID: "browser-attempt-1", FencingToken: 2, IdempotencyKey: "browser-key-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: modelTestTime.Add(10 * time.Minute), ExpectedGeneration: 1, BrowserSessionID: "browser-session-1", CapabilityProfileID: CapabilityProfileID, ExpiresAt: modelTestTime.Add(5 * time.Minute)}
}

func validAllocationReceipt() AllocationReceipt {
	request := validOpenRequest()
	return AllocationReceipt{Reference: "ref:browser/11111111111111111111111111111111", SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration, ConnectionGeneration: 1, AllocatedAt: modelTestTime.Add(time.Second), ExpiresAt: request.ExpiresAt}
}

func beginRecord(t *testing.T) Record {
	t.Helper()
	record, err := NewRecord(validOpenRequest(), modelTestTime)
	if err != nil {
		t.Fatal(err)
	}
	running, err := AttachAllocation(record, validAllocationReceipt())
	if err != nil {
		t.Fatal(err)
	}
	return running
}

func TestOpenRequestRejectsNonBrowserProfile(t *testing.T) {
	request := validOpenRequest()
	request.CapabilityProfileID = "terminal-v1"
	if !errors.Is(request.Validate(modelTestTime), ErrInvalidRequest) {
		t.Fatalf("Validate() = %v", request.Validate(modelTestTime))
	}
}

func TestRunningRecordRequiresAttachedRunningAllocation(t *testing.T) {
	record, err := NewRecord(validOpenRequest(), modelTestTime)
	if err != nil {
		t.Fatal(err)
	}
	invalid := record.Clone()
	invalid.Status = StatusRunning
	invalid.ObservedAt = modelTestTime.Add(time.Second)
	if !errors.Is(invalid.Validate(), ErrInvalidRecord) {
		t.Fatalf("Validate() = %v", invalid.Validate())
	}
	if _, err := Transition(record, StatusRunning, modelTestTime.Add(time.Second), nil); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Transition() = %v", err)
	}
}

func TestRecordRejectsInconsistentAllocationAndHandoffState(t *testing.T) {
	running := beginRecord(t)
	acceptedWithAllocation := running.Clone()
	acceptedWithAllocation.Status = StatusAccepted
	if !errors.Is(acceptedWithAllocation.Validate(), ErrInvalidRecord) {
		t.Fatalf("accepted allocation Validate() = %v", acceptedWithAllocation.Validate())
	}
	succeeded, err := Transition(running, StatusSucceeded, modelTestTime.Add(2*time.Second), &EndpointEvidence{InternalEndpointReference: "ref:browser-session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	succeeded.Handoff.ConnectionGeneration++
	if !errors.Is(succeeded.Validate(), ErrInvalidRecord) {
		t.Fatalf("mismatched handoff Validate() = %v", succeeded.Validate())
	}
}

func TestBrowserRecordMintsOnlyOpaqueHandoffOnSuccess(t *testing.T) {
	record := beginRecord(t)
	succeeded, err := Transition(record, StatusSucceeded, modelTestTime.Add(2*time.Second), &EndpointEvidence{InternalEndpointReference: "ref:browser-session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if succeeded.Handoff == nil || succeeded.Handoff.BrowserSessionID != "browser-session-1" || succeeded.Handoff.CapabilityProfileID != CapabilityProfileID || succeeded.Handoff.Protocol != ProtocolWebSocket {
		t.Fatalf("handoff = %#v", succeeded.Handoff)
	}
	if err := succeeded.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOutcomeUnknownCannotReopen(t *testing.T) {
	record := beginRecord(t)
	unknown, err := Transition(record, StatusOutcomeUnknown, modelTestTime.Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Transition(unknown, StatusSucceeded, modelTestTime.Add(3*time.Second), &EndpointEvidence{InternalEndpointReference: "ref:browser-session:opaque-1", ConnectionGeneration: 1}); !errors.Is(err, ErrOperationTerminal) {
		t.Fatalf("reopen error = %v", err)
	}
}

func TestAllocationObservationIsIdentityBound(t *testing.T) {
	request := validOpenRequest()
	record, err := NewRecord(request, modelTestTime)
	if err != nil {
		t.Fatal(err)
	}
	receipt := validAllocationReceipt()
	running, err := AttachAllocation(record, receipt)
	if err != nil {
		t.Fatal(err)
	}
	changed := receipt
	changed.Reference = "ref:browser/22222222222222222222222222222222"
	if _, err := AttachAllocation(running, changed); !errors.Is(err, ErrAllocationConflict) {
		t.Fatalf("substituted receipt error = %v", err)
	}
	unknown, err := ObserveAllocation(running, AllocationEvidence{Receipt: receipt, State: AllocationOutcomeUnknown, ObservedAt: modelTestTime.Add(2 * time.Second)})
	if err != nil || unknown.Status != StatusOutcomeUnknown {
		t.Fatalf("unknown = %#v, %v", unknown, err)
	}
}
