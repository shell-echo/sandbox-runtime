package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
)

func TestConcurrentOpenReplayHasSingleDurableIdentity(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	store := NewRepository()
	authority := desktop.SandboxAuthority{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(time.Hour), FencingToken: 3, CapabilityProfileID: desktop.CapabilityProfileID,
		NetworkPolicyReference: "desktop-egress-policy-1",
	}
	if err := store.SynchronizeSandboxAuthority(context.Background(), authority); err != nil {
		t.Fatal(err)
	}
	request := desktop.OpenRequest{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 3, IdempotencyKey: "desktop-open-1",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      now.Add(30 * time.Minute), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1",
		CapabilityProfileID: desktop.CapabilityProfileID, ExpiresAt: now.Add(20 * time.Minute),
	}
	const workers = 32
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			reservation, err := store.ReserveOpen(context.Background(), request, now)
			if err == nil && reservation.Record.Request != request {
				err = errors.New("reservation identity drift")
			}
			errorsByWorker <- err
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.ListOpen(context.Background())
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %#v, %v", records, err)
	}
}

func TestConcurrentDigestConflictFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	store := NewRepository()
	if err := store.SynchronizeSandboxAuthority(context.Background(), desktop.SandboxAuthority{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(time.Hour), FencingToken: 3, CapabilityProfileID: desktop.CapabilityProfileID,
		NetworkPolicyReference: "desktop-egress-policy-1",
	}); err != nil {
		t.Fatal(err)
	}
	base := desktop.OpenRequest{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", FencingToken: 3, IdempotencyKey: "desktop-open-1",
		Deadline: now.Add(30 * time.Minute), ExpectedGeneration: 1, CapabilityProfileID: desktop.CapabilityProfileID,
		ExpiresAt: now.Add(20 * time.Minute),
	}
	left := base
	left.OperationID, left.AttemptID, left.DesktopSessionID = "operation-left", "attempt-left", "desktop-left"
	left.RequestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	right := base
	right.OperationID, right.AttemptID, right.DesktopSessionID = "operation-right", "attempt-right", "desktop-right"
	right.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	results := make(chan error, 2)
	go func() { _, err := store.ReserveOpen(context.Background(), left, now); results <- err }()
	go func() { _, err := store.ReserveOpen(context.Background(), right, now); results <- err }()
	var successes, conflicts int
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, repository.ErrIdempotencyConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}
