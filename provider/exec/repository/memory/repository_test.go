package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository"
)

var memoryTestTime = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func memoryExecution() (providerexec.Request, providerexec.Dispatch) {
	request := providerexec.Request{
		SandboxID: "sandbox-memory", OperationID: "operation-memory", AttemptID: "attempt-memory", FencingToken: 1, ExpectedGeneration: 1,
		IdempotencyKey: "memory-key", RequestDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline: memoryTestTime.Add(time.Minute), Command: []string{"true"}, WorkingDirectory: "/tmp", ResultRetention: time.Hour,
	}
	return request, providerexec.Dispatch{ExecutionReference: "ref:memory/1", AcceptedAt: memoryTestTime}
}

func TestRepositoryConcurrencyAndImmutability(t *testing.T) {
	r := NewRepository()
	request, dispatch := memoryExecution()
	if _, err := r.ReserveExecution(context.Background(), request, dispatch); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reservation, err := r.ReserveExecution(context.Background(), request, dispatch)
			if err != nil || !reservation.Replayed {
				errCh <- errors.New("concurrent replay failed")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	got, err := r.GetExecution(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	got.Request.Command[0] = "mutated"
	again, err := r.GetExecution(context.Background(), request.OperationID)
	if err != nil || again.Request.Command[0] != "true" {
		t.Fatalf("repository returned mutable record: %#v, %v", again, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetExecution(context.Background(), request.OperationID); !errors.Is(err, repository.ErrClosed) {
		t.Fatalf("read after close = %v", err)
	}
}

func TestRepositoryPreservesExplicitAcceptanceTimes(t *testing.T) {
	r := NewRepository()
	request, _ := memoryExecution()
	reserved, err := r.ReserveExecutionAt(context.Background(), request, memoryTestTime)
	if err != nil || !reserved.Execution.ReservedAt.Equal(memoryTestTime) {
		t.Fatalf("execution reservation = %#v, %v", reserved, err)
	}
	intent := providerexec.CancellationIntent{
		SandboxID: request.SandboxID, OperationID: "cancel-memory", AttemptID: "cancel-attempt", FencingToken: 2, ExpectedGeneration: request.ExpectedGeneration,
		IdempotencyKey: "cancel-memory-key", RequestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		Deadline: memoryTestTime.Add(time.Minute), TargetOperationID: request.OperationID, TargetAttemptID: request.AttemptID, Reason: providerexec.CancellationCallerRequested,
	}
	cancelled, err := r.ReserveCancellationAt(context.Background(), intent, memoryTestTime.Add(time.Second))
	if err != nil || !cancelled.ReservedAt.Equal(memoryTestTime.Add(time.Second)) {
		t.Fatalf("cancellation reservation = %#v, %v", cancelled, err)
	}
}
