package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	"github.com/shell-echo/sandbox-runtime/provider/artifact/repository"
)

var memoryTestTime = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestConcurrentReserveReturnsOneLogicalOperation(t *testing.T) {
	r := NewRepository()
	if err := r.PutSandboxAuthority(context.Background(), memoryAuthority()); err != nil {
		t.Fatal(err)
	}
	request := memoryRequest()
	const callers = 16
	var wg sync.WaitGroup
	wg.Add(callers)
	errorsSeen := make(chan error, callers)
	first := make(chan bool, callers)
	for range callers {
		go func() {
			defer wg.Done()
			reservation, err := r.ReserveStage(context.Background(), request, memoryTestTime)
			errorsSeen <- err
			first <- !reservation.Replayed
		}()
	}
	wg.Wait()
	close(errorsSeen)
	close(first)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("ReserveStage() error = %v", err)
		}
	}
	firstCount := 0
	for value := range first {
		if value {
			firstCount++
		}
	}
	if firstCount != 1 {
		t.Fatalf("new reservations = %d, want 1", firstCount)
	}
}

func TestSnapshotsContextAndClose(t *testing.T) {
	r := NewRepository()
	_ = r.PutSandboxAuthority(context.Background(), memoryAuthority())
	request := memoryRequest()
	_, _ = r.ReserveStage(context.Background(), request, memoryTestTime)
	operation, err := r.GetStage(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	operation.Request.OperationID = "mutated"
	again, _ := r.GetStage(context.Background(), request.OperationID)
	if again.Request.OperationID != request.OperationID {
		t.Fatalf("stored operation mutated: %#v", again)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.GetStage(ctx, request.OperationID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled GetStage() = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetStage(context.Background(), request.OperationID); !errors.Is(err, repository.ErrClosed) {
		t.Fatalf("closed GetStage() = %v", err)
	}
}

func memoryAuthority() artifact.SandboxAuthority {
	return artifact.SandboxAuthority{SandboxID: "sandbox-memory", Generation: 2, FencingToken: 5}
}

func memoryRequest() artifact.Request {
	return artifact.Request{
		SandboxID: "sandbox-memory", TenantID: "tenant-memory", OperationID: "operation-memory", AttemptID: "attempt-memory",
		FencingToken: 5, ExpectedGeneration: 2, IdempotencyKey: "key-memory",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      memoryTestTime.Add(2 * time.Hour), ArtifactReference: "artifact-ref:platform/memory",
		SourcePath: "/outputs/memory.json", ExpectedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedMediaType: "application/json", MaxBytes: 1024, Retention: time.Hour,
	}
}
