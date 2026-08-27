package terminal

import (
	"strings"
	"testing"
	"time"
)

var terminalTestNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

func validAllocationRequest() AllocationRequest {
	return AllocationRequest{
		SandboxID: "sandbox-1", RuntimeSessionID: "session-1", OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 2, ExpectedGeneration: 3, RequestDigest: "sha256:" + strings.Repeat("a", 64),
		WorkingDirectory: "/workspace", ExpiresAt: terminalTestNow.Add(time.Hour),
	}
}

func validReceipt() Receipt {
	request := validAllocationRequest()
	return Receipt{
		Reference: "ref:terminal/0123456789abcdef0123456789abcdef",
		SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: terminalTestNow, ExpiresAt: request.ExpiresAt,
	}
}

func TestAllocationRequestValidation(t *testing.T) {
	valid := validAllocationRequest()
	if err := valid.Validate(terminalTestNow); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	tests := map[string]func(*AllocationRequest){
		"sandbox":     func(r *AllocationRequest) { r.SandboxID = "" },
		"session":     func(r *AllocationRequest) { r.RuntimeSessionID = "bad/session" },
		"fence":       func(r *AllocationRequest) { r.FencingToken = 0 },
		"generation":  func(r *AllocationRequest) { r.ExpectedGeneration = 0 },
		"digest":      func(r *AllocationRequest) { r.RequestDigest = "sha256:bad" },
		"working dir": func(r *AllocationRequest) { r.WorkingDirectory = "/etc" },
		"expired":     func(r *AllocationRequest) { r.ExpiresAt = terminalTestNow },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if err := request.Validate(terminalTestNow); err == nil {
				t.Fatal("invalid request was accepted")
			}
		})
	}
}

func TestReceiptAndObservationValidation(t *testing.T) {
	receipt := validReceipt()
	if err := receipt.Validate(); err != nil || !receipt.Matches(validAllocationRequest()) {
		t.Fatalf("receipt = %#v, %v", receipt, err)
	}
	invalid := receipt
	invalid.Reference = "ref:terminal/docker-container-id"
	if err := invalid.Validate(); err == nil {
		t.Fatal("backend-shaped receipt was accepted")
	}
	observation := Observation{Receipt: receipt, State: ObservationRunning, ObservedAt: terminalTestNow.Add(time.Second)}
	if err := observation.Validate(); err != nil {
		t.Fatalf("valid observation: %v", err)
	}
	observation.State = "unknown"
	if err := observation.Validate(); err == nil {
		t.Fatal("invalid observation state was accepted")
	}
}
