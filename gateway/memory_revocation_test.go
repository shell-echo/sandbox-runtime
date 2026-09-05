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
	subject := RevocationSubject{GrantID: "grant-1", ExpiresAt: time.Now().Add(time.Minute)}
	watch, err := revocations.Watch(ctx, subject)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	if err := revocations.Revoke(context.Background(), subject); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	select {
	case <-watch.Done():
	case <-time.After(time.Second):
		t.Fatal("revocation watcher did not fire")
	}
	if err := watch.Err(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("watch error = %v, want ErrRevoked", err)
	}
	cancel()
	if _, err := revocations.Watch(ctx, RevocationSubject{GrantID: "grant-2", ExpiresAt: subject.ExpiresAt}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestMemoryRevocationsAlreadyRevokedWatcherIsClosed(t *testing.T) {
	revocations := NewMemoryRevocations()
	subject := RevocationSubject{GrantID: "grant-1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := revocations.Revoke(context.Background(), subject); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	watch, err := revocations.Watch(context.Background(), subject)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	select {
	case <-watch.Done():
	case <-time.After(time.Second):
		t.Fatal("already revoked watcher is not closed")
	}
	if err := watch.Err(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("watch error = %v, want ErrRevoked", err)
	}
}

func TestMemoryRevocationsCancellationRemovesActiveWatcher(t *testing.T) {
	revocations := NewMemoryRevocations()
	ctx, cancel := context.WithCancel(context.Background())
	subject := RevocationSubject{GrantID: "grant-cancel", ExpiresAt: time.Now().Add(time.Minute)}
	watch, err := revocations.Watch(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-watch.Done():
	case <-time.After(time.Second):
		t.Fatal("canceled watcher did not close")
	}
	if err := watch.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("watch error = %v; want context.Canceled", err)
	}
	revocations.mu.Lock()
	defer revocations.mu.Unlock()
	if watchers := revocations.watchers[subject.GrantID]; len(watchers) != 0 {
		t.Fatalf("canceled watcher remained registered: %d", len(watchers))
	}
}

func TestMemoryRevocationsSignalsEveryWatcherWithStableStatus(t *testing.T) {
	revocations := NewMemoryRevocations()
	subject := RevocationSubject{GrantID: "grant-many", ExpiresAt: time.Now().Add(time.Minute)}
	const watcherCount = 16
	watches := make([]RevocationWatch, 0, watcherCount)
	for index := 0; index < watcherCount; index++ {
		watch, err := revocations.Watch(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		watches = append(watches, watch)
	}
	if err := revocations.Revoke(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	for index, watch := range watches {
		select {
		case <-watch.Done():
		case <-time.After(time.Second):
			t.Fatalf("watcher %d did not close", index)
		}
		for attempt := 0; attempt < 3; attempt++ {
			if err := watch.Err(); err != ErrRevoked {
				t.Fatalf("watcher %d status = %v; want stable ErrRevoked", index, err)
			}
		}
	}
}
