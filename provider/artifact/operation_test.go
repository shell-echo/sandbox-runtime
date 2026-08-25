package artifact

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

func TestArtifactDomainDoesNotImportRepositoryTransportOrRuntimePackages(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", entry.Name(), parseErr)
		}
		for _, importSpec := range file.Imports {
			path := strings.Trim(importSpec.Path.Value, "\"")
			if strings.Contains(path, "github.com/shell-echo/sandbox-runtime/") {
				t.Fatalf("%s imports forbidden repository package %q", entry.Name(), path)
			}
		}
	}
}

func TestArtifactOperationTransitions(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	request := validOperationRequest(now)
	accepted, err := NewOperation(request, now)
	if err != nil {
		t.Fatalf("NewOperation() error = %v", err)
	}
	running, err := Transition(accepted, OperationRunning, now.Add(time.Second), "", nil)
	if err != nil {
		t.Fatalf("Transition(running) error = %v", err)
	}
	evidence := validOperationEvidence(request, now.Add(2*time.Second), StatusStaged)
	succeeded, err := Transition(running, OperationSucceeded, now.Add(2*time.Second), "", &evidence)
	if err != nil {
		t.Fatalf("Transition(succeeded) error = %v", err)
	}
	if succeeded.Evidence == nil || succeeded.Evidence.Status != StatusStaged {
		t.Fatalf("succeeded evidence = %#v", succeeded.Evidence)
	}
	if _, err := Transition(succeeded, OperationRunning, now.Add(3*time.Second), "", nil); !errors.Is(err, ErrTerminalOperation) {
		t.Fatalf("terminal Transition() error = %v, want ErrTerminalOperation", err)
	}
}

func TestArtifactOperationRejectsCancelledAndMismatchedEvidence(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	request := validOperationRequest(now)
	accepted, _ := NewOperation(request, now)
	if _, err := Transition(accepted, OperationStatus("cancelled"), now.Add(time.Second), "", nil); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cancelled Transition() error = %v, want ErrInvalidTransition", err)
	}
	running, _ := Transition(accepted, OperationRunning, now.Add(time.Second), "", nil)
	evidence := validOperationEvidence(request, now.Add(2*time.Second), StatusStaged)
	evidence.AttemptID = "another-attempt"
	if _, err := Transition(running, OperationSucceeded, now.Add(2*time.Second), "", &evidence); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("mismatched Transition() error = %v, want ErrInvalidTransition", err)
	}
}

func validOperationRequest(now time.Time) Request {
	return Request{
		SandboxID: "sandbox-1", OperationID: "artifact-operation-1", AttemptID: "artifact-attempt-1",
		FencingToken: 3, ExpectedGeneration: 4, IdempotencyKey: "artifact-key-1",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      now.Add(2 * time.Hour), ArtifactReference: "artifact-ref:platform/artifact-1",
		SourcePath: "/outputs/report.json", ExpectedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedMediaType: "application/json", MaxBytes: 1024, Retention: time.Hour,
	}
}

func validOperationEvidence(request Request, observedAt time.Time, status Status) Evidence {
	evidence := Evidence{
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		SandboxID: request.SandboxID, ArtifactReference: request.ArtifactReference, Status: status,
		ContentDigest: request.ExpectedDigest, MediaType: request.ExpectedMediaType, SizeBytes: 512,
		TenantBindingCheck: Check{Status: CheckPassed, CheckedAt: observedAt},
		ActiveContentCheck: Check{Status: CheckPassed, CheckedAt: observedAt},
		MalwareCheck:       Check{Status: CheckPassed, CheckedAt: observedAt},
		ObservedAt:         observedAt, ExpiresAt: observedAt.Add(30 * time.Minute),
		EvidenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if status == StatusStaged {
		evidence.StagingReference = "ref:staging/artifact-1"
	}
	return evidence
}
