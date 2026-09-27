package phase6egress

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestWitnessRoleGuardRejectsUnboundedBudget(t *testing.T) {
	if guard, err := NewWitnessRoleGuard(nil, "witness", "runtime",
		100*time.Millisecond, time.Second, time.Second, 10*time.Second); guard != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing pool accepted: %v", err)
	}
	if guard, err := NewWitnessRoleGuard(new(pgxpool.Pool), "witness", "runtime",
		5*time.Second, 5*time.Second, 5*time.Second, 10*time.Second); guard != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("insufficient drain budget accepted: %v", err)
	}
}

func TestWitnessRoleGuardLocalActionFreshnessAndTerminalFailure(t *testing.T) {
	now := time.Now()
	var queries, drains atomic.Int32
	guard := &WitnessRoleGuard{
		verify:   func(context.Context) error { queries.Add(1); return nil },
		interval: time.Second, timeout: time.Second, freshness: 5 * time.Second,
		now:   func() time.Time { return now },
		drain: func() { drains.Add(1) },
	}
	defer guard.Close()
	if guard.CheckReady() == nil {
		t.Fatal("uninitialized guard accepted")
	}
	if err := guard.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := &countingFenceAuthority{}
	authority := WitnessRoleGatedAuthority{Role: guard, Next: next}
	for range 3 {
		if _, err := authority.AuthorizeAction(context.Background(), gateway.DownstreamFenceSubject{},
			gateway.DownstreamFence{}, time.Second); err != nil {
			t.Fatalf("fresh local action refused: %v", err)
		}
	}
	if queries.Load() != 1 || next.calls != 3 {
		t.Fatalf("per-action ACL directory query occurred: checks=%d, next=%d", queries.Load(), next.calls)
	}
	now = now.Add(6 * time.Second)
	if _, err := authority.AuthorizeAction(context.Background(), gateway.DownstreamFenceSubject{},
		gateway.DownstreamFence{}, time.Second); !errors.Is(err, gateway.ErrDownstreamUnavailable) || next.calls != 3 {
		t.Fatalf("stale action = %v, next=%d", err, next.calls)
	}
	if err := guard.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) || drains.Load() != 1 {
		t.Fatalf("terminal failure unlocked: %v, drains=%d", err, drains.Load())
	}
}

func TestWitnessRoleGuardIdlePollFailureDrainsOnce(t *testing.T) {
	var queries, drains atomic.Int32
	guard := &WitnessRoleGuard{
		verify: func(context.Context) error {
			if queries.Add(1) > 1 {
				return ErrUnavailable
			}
			return nil
		},
		interval: 20 * time.Millisecond, timeout: 100 * time.Millisecond,
		freshness: 200 * time.Millisecond, now: time.Now,
	}
	defer guard.Close()
	if err := guard.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{}, 2)
	done, err := guard.StartPolling(ctx, func() { drains.Add(1); drained <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("idle ACL failure did not drain")
	}
	<-done
	if guard.CheckReady() == nil || drains.Load() != 1 || queries.Load() != 2 {
		t.Fatalf("idle failure state: drains=%d checks=%d", drains.Load(), queries.Load())
	}
}

func TestWitnessRoleGuardTimeoutAndOverlappingCheckFailClosed(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var drains atomic.Int32
	guard := &WitnessRoleGuard{
		verify: func(ctx context.Context) error {
			once.Do(func() { close(entered) })
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		interval: time.Second, timeout: 50 * time.Millisecond,
		freshness: 2 * time.Second, now: time.Now,
		drain: func() { drains.Add(1) },
	}
	defer guard.Close()
	first := make(chan error, 1)
	go func() { first <- guard.Refresh(context.Background()) }()
	<-entered
	if err := guard.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("overlapping ACL check accepted: %v", err)
	}
	close(release)
	if err := <-first; !errors.Is(err, ErrUnavailable) || drains.Load() != 1 {
		t.Fatalf("overlap did not latch: %v, drains=%d", err, drains.Load())
	}
}

func TestWitnessRoleGuardExpiryTimerDrainsWithoutFurtherActions(t *testing.T) {
	drained := make(chan struct{}, 1)
	guard := &WitnessRoleGuard{
		verify:   func(context.Context) error { return nil },
		interval: time.Second, timeout: time.Second, freshness: 200 * time.Millisecond,
		now: time.Now,
	}
	defer guard.Close()
	if err := guard.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, err := guard.StartPolling(ctx, func() { drained <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("stalled poll did not drain idle stream at freshness expiry")
	}
	cancel()
	<-done
	if guard.CheckReady() == nil {
		t.Fatal("expired observation regained readiness")
	}
}
