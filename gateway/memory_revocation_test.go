package gateway

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryRevocationsWatchAndCancel(t *testing.T) {
	revocations := NewMemoryRevocations()
	ctx, cancel := context.WithCancel(context.Background())
	watch, err := revocations.Watch(ctx, "grant-1")
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	if err := revocations.Revoke(context.Background(), "grant-1"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	select {
	case <-watch:
	case <-time.After(time.Second):
		t.Fatal("revocation watcher did not fire")
	}
	revoked, err := revocations.IsRevoked(context.Background(), "grant-1")
	if err != nil || !revoked {
		t.Fatalf("IsRevoked() = (%v, %v), want true", revoked, err)
	}
	cancel()
	if _, err := revocations.Watch(ctx, "grant-2"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestMemoryRevocationsAlreadyRevokedWatcherIsClosed(t *testing.T) {
	revocations := NewMemoryRevocations()
	if err := revocations.Revoke(context.Background(), "grant-1"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	watch, err := revocations.Watch(context.Background(), "grant-1")
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	select {
	case <-watch:
	case <-time.After(time.Second):
		t.Fatal("already revoked watcher is not closed")
	}
}
