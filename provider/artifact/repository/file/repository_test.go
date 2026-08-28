package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	"github.com/shell-echo/sandbox-runtime/provider/artifact/application"
	"github.com/shell-echo/sandbox-runtime/provider/artifact/repository"
)

var fileTestTime = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestRepositoryRestartPreservesOperationAndPreventsDuplicateDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "artifact.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.PutSandboxAuthority(context.Background(), fileAuthority()); err != nil {
		t.Fatal(err)
	}
	request := fileRequest("operation-running", "key-running")
	reserved, err := r.ReserveStage(context.Background(), request, fileTestTime)
	if err != nil {
		t.Fatal(err)
	}
	running, _ := artifact.Transition(reserved.Operation, artifact.OperationRunning, fileTestTime.Add(time.Second), "", nil)
	if err := r.UpdateStage(context.Background(), running, artifact.OperationAccepted); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	stager := &countingStager{}
	app, err := application.New(r, stager, application.ClockFunc(func() time.Time { return fileTestTime.Add(2 * time.Second) }))
	if err != nil {
		t.Fatal(err)
	}
	operation, err := app.Reconcile(context.Background(), request.OperationID)
	if !errors.Is(err, artifact.ErrOutcomeUnknown) || operation.Status != artifact.OperationOutcomeUnknown || stager.calls != 0 {
		t.Fatalf("Reconcile() = %#v, %v; calls = %d", operation, err, stager.calls)
	}
	if _, err := NewRepository(path); err == nil {
		t.Fatal("second controller opened repository")
	}
}

func TestRepositoryPersistsEvidenceExpiryTombstone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.PutSandboxAuthority(context.Background(), fileAuthority())
	request := fileRequest("operation-evidence", "key-evidence")
	reserved, _ := r.ReserveStage(context.Background(), request, fileTestTime)
	running, _ := artifact.Transition(reserved.Operation, artifact.OperationRunning, fileTestTime.Add(time.Second), "", nil)
	_ = r.UpdateStage(context.Background(), running, artifact.OperationAccepted)
	evidence := fileEvidence(request)
	succeeded, _ := artifact.Transition(running, artifact.OperationSucceeded, fileTestTime.Add(2*time.Second), "", &evidence)
	_ = r.UpdateStage(context.Background(), succeeded, artifact.OperationRunning)
	if _, err := r.GetEvidence(context.Background(), request.OperationID, evidence.ExpiresAt); !errors.Is(err, artifact.ErrEvidenceExpired) {
		t.Fatalf("expired evidence = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.GetEvidence(context.Background(), request.OperationID, fileTestTime.Add(3*time.Second)); !errors.Is(err, artifact.ErrEvidenceExpired) {
		t.Fatalf("restarted tombstone = %v", err)
	}
}

func TestRepositoryRejectsCorruptPartialAndCanceledWrites(t *testing.T) {
	for name, contents := range map[string]string{
		"unsupported-version":   `{"version":99}`,
		"legacy-without-tenant": `{"version":1,"operations":[],"idempotency":[],"authorities":[]}`,
		"unknown-field":         `{"version":2,"operations":[],"idempotency":[],"authorities":[],"unknown":true}`,
		"trailing-json":         `{"version":2,"operations":[],"idempotency":[],"authorities":[]} {}`,
		"partial-state":         `{"version":2,"operations":[{}],"idempotency":[],"authorities":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artifact.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(path); !errors.Is(err, repository.ErrCorrupt) {
				t.Fatalf("NewRepository() error = %v, want ErrCorrupt", err)
			}
		})
	}
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "artifact.json")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maxFileSize + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRepository(path); !errors.Is(err, repository.ErrCorrupt) {
			t.Fatalf("oversized NewRepository() error = %v", err)
		}
	})
	path := filepath.Join(t.TempDir(), "canceled.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.PutSandboxAuthority(ctx, fileAuthority()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write = %v", err)
	}
	if _, err := r.GetSandboxAuthority(context.Background(), fileAuthority().SandboxID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("canceled write mutated state: %v", err)
	}
}

type countingStager struct{ calls int }

func (s *countingStager) Stage(context.Context, artifact.Request, time.Time) (artifact.Evidence, error) {
	s.calls++
	return artifact.Evidence{}, errors.New("unexpected staging")
}

func fileAuthority() artifact.SandboxAuthority {
	return artifact.SandboxAuthority{SandboxID: "sandbox-file", Generation: 4, FencingToken: 3}
}

func fileRequest(operationID, key string) artifact.Request {
	return artifact.Request{
		SandboxID: "sandbox-file", TenantID: "tenant-file", OperationID: operationID, AttemptID: "attempt-file", FencingToken: 3,
		ExpectedGeneration: 4, IdempotencyKey: key,
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      fileTestTime.Add(2 * time.Hour), ArtifactReference: "artifact-ref:platform/file",
		SourcePath: "/outputs/report.json", ExpectedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedMediaType: "application/json", MaxBytes: 1024, Retention: time.Hour,
	}
}

func fileEvidence(request artifact.Request) artifact.Evidence {
	observedAt := fileTestTime.Add(2 * time.Second)
	return artifact.Evidence{
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		SandboxID: request.SandboxID, ArtifactReference: request.ArtifactReference, StagingReference: "ref:staging/file",
		Status: artifact.StatusStaged, ContentDigest: request.ExpectedDigest, MediaType: request.ExpectedMediaType, SizeBytes: 512,
		TenantBindingCheck: artifact.Check{Status: artifact.CheckPassed, CheckedAt: observedAt},
		ActiveContentCheck: artifact.Check{Status: artifact.CheckPassed, CheckedAt: observedAt},
		MalwareCheck:       artifact.Check{Status: artifact.CheckPassed, CheckedAt: observedAt},
		ObservedAt:         observedAt, ExpiresAt: fileTestTime.Add(time.Hour),
		EvidenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
}
