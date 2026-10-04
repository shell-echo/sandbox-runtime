package guestagent

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func retirementTestIdentity(t *testing.T) Identity {
	t.Helper()
	nonce, err := randomNonce()
	if err != nil {
		t.Fatal(err)
	}
	return Identity{TenantID: "tenant-test", WorkspaceID: "wrk-test", SlotKey: "primary-code",
		GuestID: "gst-test", SlotGeneration: 1, BindingGeneration: 1,
		ProtocolVersion: ProtocolVersion, ClientNonce: nonce, ExpiresAt: time.Now().Add(time.Minute)}
}

func retirementTestReadback(context.Context, Identity) (RetirementDisposition, error) {
	return RetirementStillOwned, nil
}

func TestRetirementPrecloseCapacityAndExactResolution(t *testing.T) {
	called := make(chan Identity, 1)
	m, err := newRetirementManager(RetirementPolicy{Capacity: 1, Readback: retirementTestReadback,
		Retire: func(_ context.Context, identity Identity) (RetirementDisposition, error) {
			called <- identity
			return RetirementReleased, nil
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = m.shutdown(ctx)
	})
	r, err := m.reserve()
	if err != nil {
		t.Fatal(err)
	}
	if m.ready() {
		t.Fatal("handshake reservation must count against capacity")
	}
	if _, err := m.reserve(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("over-capacity reserve = %v", err)
	}
	identity := retirementTestIdentity(t)
	if err := r.activate(identity); err != nil {
		t.Fatal(err)
	}
	if err := r.pending(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
		t.Fatal("retirement SQL ran before transport close completed")
	case <-time.After(30 * time.Millisecond):
	}
	if m.ready() {
		t.Fatal("pending cleanup must close admission")
	}
	r.closeCompleted(true)
	select {
	case got := <-called:
		if got.ClientNonce != identity.ClientNonce {
			t.Fatal("retirement changed the old nonce")
		}
	case <-time.After(time.Second):
		t.Fatal("closed transport did not trigger retirement")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.shutdown(ctx); err != nil {
		t.Fatalf("shutdown after exact release: %v", err)
	}
}

func TestRetirementResolvedCallbackRunsOutsideManagerLock(t *testing.T) {
	resolved := make(chan bool, 1)
	var manager *retirementManager
	var err error
	manager, err = newRetirementManager(RetirementPolicy{Capacity: 1,
		Readback: retirementTestReadback,
		Retire: func(context.Context, Identity) (RetirementDisposition, error) {
			return RetirementReleased, nil
		}}, func(value Observation) {
		if value.Event == ObservationProductDisconnectResolved {
			resolved <- manager.ready()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := manager.reserve()
	if err != nil {
		t.Fatal(err)
	}
	reservation.bindAttempt("sha256:"+strings.Repeat("a", 64), 1)
	if err := reservation.activate(retirementTestIdentity(t)); err != nil {
		t.Fatal(err)
	}
	if err := reservation.pending(); err != nil {
		t.Fatal(err)
	}
	reservation.closeCompleted(true)
	select {
	case ready := <-resolved:
		if !ready {
			t.Fatal("resolved callback observed an unreleased slot")
		}
	case <-time.After(time.Second):
		t.Fatal("resolved callback deadlocked on manager lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := manager.shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRetirementWaitsForActiveOwnerDuringShutdown(t *testing.T) {
	m, err := newRetirementManager(RetirementPolicy{Capacity: 2, Readback: retirementTestReadback,
		Retire: func(context.Context, Identity) (RetirementDisposition, error) { return RetirementReleased, nil }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.reserve()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.activate(retirementTestIdentity(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- m.shutdown(ctx) }()
	select {
	case err := <-finished:
		t.Fatalf("shutdown returned with active transport: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := r.pending(); err != nil {
		t.Fatal(err)
	}
	r.closeCompleted(true)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("shutdown after close = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not join cleanup")
	}
}

func TestRetirementCloseFailureAndUnknownNeverReleaseHold(t *testing.T) {
	for _, closeFailure := range []bool{false, true} {
		var calls atomic.Int64
		m, err := newRetirementManager(RetirementPolicy{Capacity: 1, Readback: retirementTestReadback,
			Retire: func(context.Context, Identity) (RetirementDisposition, error) {
				calls.Add(1)
				return RetirementReleased, nil
			}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := m.reserve()
		if err != nil {
			t.Fatal(err)
		}
		if closeFailure {
			if err := r.activate(retirementTestIdentity(t)); err != nil {
				t.Fatal(err)
			}
			if err := r.pending(); err != nil {
				t.Fatal(err)
			}
			r.closeCompleted(false)
		} else {
			r.holdUnknown()
		}
		if m.ready() || calls.Load() != 0 {
			t.Fatal("unresolved ownership opened admission or ran cleanup")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := m.shutdown(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unresolved shutdown = %v", err)
		}
		cancel()
	}
}

func TestRetirementRetriesOneWorkerAndClipsAtBindingExpiry(t *testing.T) {
	var calls atomic.Int64
	var concurrent atomic.Int64
	m, err := newRetirementManager(RetirementPolicy{Capacity: 2, Readback: retirementTestReadback,
		Retire: func(ctx context.Context, _ Identity) (RetirementDisposition, error) {
			if concurrent.Add(1) != 1 {
				t.Error("more than one retirement worker")
			}
			defer concurrent.Add(-1)
			calls.Add(1)
			return RetirementStillOwned, nil
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.reserve()
	if err != nil {
		t.Fatal(err)
	}
	identity := retirementTestIdentity(t)
	identity.ExpiresAt = time.Now().Add(120 * time.Millisecond)
	if err := r.activate(identity); err != nil {
		t.Fatal(err)
	}
	if err := r.pending(); err != nil {
		t.Fatal(err)
	}
	r.closeCompleted(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.shutdown(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unresolved expiry shutdown = %v", err)
	}
	if got := calls.Load(); got > 1 {
		t.Fatalf("expiry did not clip retry schedule, calls=%d", got)
	}
}

func TestRetirementAttemptLimitKeepsTerminalHold(t *testing.T) {
	var calls atomic.Int64
	m, err := newRetirementManager(RetirementPolicy{Capacity: 1, Readback: retirementTestReadback,
		Retire: func(context.Context, Identity) (RetirementDisposition, error) {
			calls.Add(1)
			return RetirementStillOwned, nil
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.reserve()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.activate(retirementTestIdentity(t)); err != nil {
		t.Fatal(err)
	}
	if err := r.pending(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	r.item.attempts = 15
	m.mu.Unlock()
	r.closeCompleted(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.shutdown(ctx); !errors.Is(err, ErrUnavailable) || calls.Load() != 1 {
		t.Fatalf("exhausted retirement = %v, calls=%d", err, calls.Load())
	}
	if m.ready() {
		t.Fatal("attempt exhaustion reopened admission")
	}
}

func TestRetirementOwnerPinSurvivesCloseAndResolutionRace(t *testing.T) {
	retired := make(chan struct{}, 1)
	m, err := newRetirementManager(RetirementPolicy{Capacity: 1, Readback: retirementTestReadback,
		Retire: func(context.Context, Identity) (RetirementDisposition, error) {
			retired <- struct{}{}
			return RetirementReleased, nil
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.reserve()
	if err != nil {
		t.Fatal(err)
	}
	identity := retirementTestIdentity(t)
	if err := r.activate(identity); err != nil {
		t.Fatal(err)
	}
	pin := m.pinLocalOwner(identity.GuestID, identity.BindingGeneration)
	if pin == nil || pin.identity.ClientNonce != identity.ClientNonce {
		t.Fatal("old local owner was not pinned before query")
	}
	if err := r.pending(); err != nil {
		t.Fatal(err)
	}
	r.closeCompleted(true)
	select {
	case <-retired:
	case <-time.After(time.Second):
		t.Fatal("retirement did not run")
	}
	// The cleanup worker may finish before the authentication query returns.
	// The pinned owner still consumes capacity until that query releases it.
	deadline := time.Now().Add(time.Second)
	for r.state() != retirementReleased && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.state() != retirementReleased || m.ready() {
		t.Fatal("pinned retired owner was prematurely forgotten")
	}
	if next := m.pinLocalOwner(identity.GuestID, identity.BindingGeneration); next != nil {
		next.release()
		t.Fatal("resolved owner remained pin-eligible")
	}
	pin.release()
	pin.release()
	if !m.ready() {
		t.Fatal("capacity was not released after last pinned query")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRetirementUnknownWriteRequiresReadbackBeforeRetry(t *testing.T) {
	var writes atomic.Int64
	var reads atomic.Int64
	readbackStarted := make(chan struct{}, 1)
	readbackRelease := make(chan struct{})
	m, err := newRetirementManager(RetirementPolicy{Capacity: 1,
		Retire: func(context.Context, Identity) (RetirementDisposition, error) {
			if writes.Add(1) == 1 {
				return "", ErrRetirementOutcomeUnknown
			}
			return RetirementReleased, nil
		},
		Readback: func(ctx context.Context, _ Identity) (RetirementDisposition, error) {
			reads.Add(1)
			readbackStarted <- struct{}{}
			select {
			case <-readbackRelease:
				return RetirementStillOwned, nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.reserve()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.activate(retirementTestIdentity(t)); err != nil {
		t.Fatal(err)
	}
	if err := r.pending(); err != nil {
		t.Fatal(err)
	}
	r.closeCompleted(true)
	select {
	case <-readbackStarted:
	case <-time.After(time.Second):
		t.Fatal("unknown UPDATE did not enter readback")
	}
	if writes.Load() != 1 || reads.Load() != 1 || m.ready() {
		t.Fatal("unknown UPDATE retried before scoped readback completed")
	}
	close(readbackRelease)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.shutdown(ctx); err != nil || writes.Load() != 2 || reads.Load() != 1 {
		t.Fatalf("reconciled retirement = %v writes=%d reads=%d", err, writes.Load(), reads.Load())
	}
}

func TestRetirementShutdownDeadlineKeepsAdmissionClosed(t *testing.T) {
	var calls atomic.Int64
	m, err := newRetirementManager(RetirementPolicy{Capacity: 1, Readback: retirementTestReadback,
		Retire: func(context.Context, Identity) (RetirementDisposition, error) {
			calls.Add(1)
			return RetirementReleased, nil
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.reserve()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.activate(retirementTestIdentity(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.shutdown(ctx); !errors.Is(err, ErrUnavailable) || calls.Load() != 0 || m.ready() {
		t.Fatalf("unclosed transport shutdown = %v, SQL calls=%d ready=%t", err, calls.Load(), m.ready())
	}
}

func TestRetirementTwoClosedOwnersUseOneWorker(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var concurrent atomic.Int64
	m, err := newRetirementManager(RetirementPolicy{Capacity: 2, Readback: retirementTestReadback,
		Retire: func(ctx context.Context, _ Identity) (RetirementDisposition, error) {
			if concurrent.Add(1) != 1 {
				t.Error("retirement acquired two concurrent workers")
			}
			defer concurrent.Add(-1)
			entered <- struct{}{}
			select {
			case <-release:
				return RetirementReleased, nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reservations := make([]*retirementReservation, 0, 2)
	for range 2 {
		r, err := m.reserve()
		if err != nil {
			t.Fatal(err)
		}
		identity := retirementTestIdentity(t)
		if err := r.activate(identity); err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, r)
	}
	for _, r := range reservations {
		if err := r.pending(); err != nil {
			t.Fatal(err)
		}
		r.closeCompleted(true)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first retirement did not enter")
	}
	select {
	case <-entered:
		t.Fatal("second retirement ran before the first released its worker")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if len(entered) != 1 {
		t.Fatalf("second retirement was not visited, pending entries=%d", len(entered))
	}
}
