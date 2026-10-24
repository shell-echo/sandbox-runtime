package process

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
)

func TestReconcilerClosesAndRecoversReadiness(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int64
	reconciler, err := NewReconciler(time.Second, time.Second, func(context.Context) error {
		calls.Add(1)
		if fail.Load() {
			return errTestDependency
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Ready(context.Background()); err == nil {
		t.Fatal("reconciler reported ready before its first complete pass")
	}
	startTestReconciler(t, reconciler)
	waitReconcilerReadiness(t, reconciler, nil)
	fail.Store(true)
	waitReconcilerReadiness(t, reconciler, errTestDependency)
	fail.Store(false)
	waitReconcilerReadiness(t, reconciler, nil)
	if calls.Load() < 3 {
		t.Fatalf("reconciliation calls = %d, want at least 3", calls.Load())
	}
}

func TestReconcilerStopsAfterFirstFailedStep(t *testing.T) {
	var second atomic.Int64
	reconciler, err := NewReconciler(time.Second, time.Second,
		func(context.Context) error { return errors.New("first failed") },
		func(context.Context) error { second.Add(1); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	reconciler.run(context.Background())
	if second.Load() != 0 {
		t.Fatal("reconciler continued after a failed step")
	}
}

var errTestDependency = errors.New("dependency unavailable")

func startTestReconciler(t *testing.T, reconciler *Reconciler) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- reconciler.Startup(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		awaitReconcilerStop(t, done)
	})
	return cancel, done
}

func awaitReconcilerStop(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("reconciler stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("reconciler did not stop")
	}
}

func waitReconcilerReadiness(t *testing.T, reconciler *Reconciler, want error) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		err := reconciler.Ready(t.Context())
		if (want == nil && err == nil) || (want != nil && errors.Is(err, want)) {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("readiness = %v, want %v", err, want)
		case <-tick.C:
		}
	}
}

func TestReconcilerStoppedWorkerRejectsReadiness(t *testing.T) {
	for _, stop := range []string{"parent_cancel", "shutdown"} {
		t.Run(stop, func(t *testing.T) {
			reconciler, err := NewReconciler(time.Second, time.Second, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			cancel, done := startTestReconciler(t, reconciler)
			waitReconcilerReadiness(t, reconciler, nil)
			if stop == "parent_cancel" {
				cancel()
			} else if err := reconciler.Shutdown(t.Context()); err != nil {
				t.Fatal(err)
			}
			awaitReconcilerStop(t, done)
			if err := reconciler.Ready(t.Context()); err == nil {
				t.Fatal("stopped reconciler retained successful readiness")
			}
			probe, err := NewServer(option.HTTP{Host: "127.0.0.1", Port: 8084}, reconciler)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			probe.http.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
				t.Fatalf("stopped worker readyz = %d %q", response.Code, response.Body.String())
			}
			if err := reconciler.Startup(t.Context()); err == nil {
				t.Fatal("stopped single-use worker restarted")
			}
		})
	}
}

func TestReconcilerShutdownRejectsLatePassSuccess(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var passes, second atomic.Int64
	reconciler, err := NewReconciler(time.Second, time.Second,
		func(ctx context.Context) error {
			if passes.Add(1) == 1 {
				return nil
			}
			close(entered)
			<-ctx.Done()
			<-release // A dependency returns nil only after shutdown has begun.
			return nil
		},
		func(context.Context) error { second.Add(1); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	_, done := startTestReconciler(t, reconciler)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	waitReconcilerReadiness(t, reconciler, nil)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("second pass did not enter")
	}
	// Shutdown cancels its worker before observing this caller's cancellation.
	// The unreleased dependency cannot finish yet, regardless of whether its
	// own pass deadline has already elapsed under scheduler load.
	shutdownContext, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reconciler.Shutdown(shutdownContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked shutdown did not preserve caller cancellation: %v", err)
	}
	if err := reconciler.Ready(t.Context()); err == nil {
		t.Error("shutdown left readiness open while dependency was blocked")
	}
	releaseOnce.Do(func() { close(release) })
	awaitReconcilerStop(t, done)
	if err := reconciler.Ready(t.Context()); err == nil || second.Load() != 1 {
		t.Fatalf("late nil revived readiness or entered next step: %v, calls %d", err, second.Load())
	}
}

func TestReconcilerRunRejectsCancelledOrExpiredPass(t *testing.T) {
	for _, cut := range []string{"before_step", "during_step", "pass_deadline"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var first, second int
			if cut == "before_step" {
				cancel()
			}
			reconciler, err := NewReconciler(time.Second, time.Second,
				func(stepContext context.Context) error {
					first++
					if cut == "during_step" {
						cancel()
					} else if cut == "pass_deadline" {
						<-stepContext.Done()
					}
					return nil
				},
				func(context.Context) error { second++; return nil },
			)
			if err != nil {
				t.Fatal(err)
			}
			reconciler.run(ctx)
			want := error(context.Canceled)
			if cut == "pass_deadline" {
				want = context.DeadlineExceeded
			}
			wantFirst := 1
			if cut == "before_step" {
				wantFirst = 0
			}
			if !reconciler.checked || !errors.Is(reconciler.lastErr, want) || first != wantFirst || second != 0 {
				t.Fatalf("cancelled pass = %v, checked %v, step calls %d/%d", reconciler.lastErr, reconciler.checked, first, second)
			}
		})
	}
}

func TestReconcilerPreCanceledStartupNeverRecovers(t *testing.T) {
	var calls int
	reconciler, err := NewReconciler(time.Second, time.Second, func(context.Context) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reconciler.Startup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Ready(t.Context()); err == nil || calls != 0 {
		t.Fatalf("pre-cancelled startup = %v, recovery calls %d", err, calls)
	}
}

func TestReconcilerExpiredActivePassRejectsReadiness(t *testing.T) {
	expired, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var passes, second atomic.Int64
	reconciler, err := NewReconciler(time.Second, time.Second,
		func(ctx context.Context) error {
			switch passes.Add(1) {
			case 1:
				return nil
			case 2:
				<-ctx.Done()
				close(expired)
				<-release
				return nil
			default:
				<-ctx.Done()
				return ctx.Err()
			}
		},
		func(context.Context) error { second.Add(1); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	startTestReconciler(t, reconciler)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	waitReconcilerReadiness(t, reconciler, nil)
	select {
	case <-expired:
	case <-time.After(5 * time.Second):
		t.Fatal("active pass did not reach its original deadline")
	}
	// The worker remains active, but the expired dependency has not returned.
	if err := reconciler.Ready(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expired active pass retained successful readiness: %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	waitReconcilerReadiness(t, reconciler, context.DeadlineExceeded)
	if second.Load() != 1 {
		t.Fatalf("expired pass entered next step: %d", second.Load())
	}
}
