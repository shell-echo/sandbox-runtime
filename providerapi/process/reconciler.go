package process

import (
	"context"
	"errors"
	"sync"
	"time"
)

type ReconcileFunc func(context.Context) error

// Reconciler repeatedly resumes retained Provider work with a per-pass
// deadline. A failed pass closes readiness but does not terminate the worker;
// the next bounded pass may recover after a dependency restart.
type Reconciler struct {
	interval time.Duration
	timeout  time.Duration
	steps    []ReconcileFunc

	mu      sync.RWMutex
	lastErr error
	checked bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewReconciler(interval, timeout time.Duration, steps ...ReconcileFunc) (*Reconciler, error) {
	if interval < time.Second || interval > time.Minute || timeout < time.Second || timeout > 30*time.Second || len(steps) == 0 {
		return nil, errors.New("invalid Provider reconciliation policy")
	}
	for _, step := range steps {
		if step == nil {
			return nil, errors.New("invalid Provider reconciliation step")
		}
	}
	return &Reconciler{interval: interval, timeout: timeout, steps: append([]ReconcileFunc(nil), steps...)}, nil
}

func (r *Reconciler) Startup(ctx context.Context) error {
	workerCtx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	if r.cancel != nil {
		r.mu.Unlock()
		cancel()
		return errors.New("Provider reconciler already started")
	}
	r.cancel = cancel
	r.done = make(chan struct{})
	done := r.done
	r.mu.Unlock()
	defer close(done)
	r.run(workerCtx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-workerCtx.Done():
			return nil
		case <-ticker.C:
			r.run(workerCtx)
		}
	}
}

func (r *Reconciler) run(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()
	var result error
	for _, step := range r.steps {
		if err := step(ctx); err != nil {
			result = errors.Join(result, err)
			break
		}
	}
	r.mu.Lock()
	r.lastErr = result
	r.checked = true
	r.mu.Unlock()
}

func (r *Reconciler) Ready(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.checked {
		return errors.New("Provider reconciliation has not completed")
	}
	return r.lastErr
}

func (r *Reconciler) Shutdown(ctx context.Context) error {
	r.mu.RLock()
	cancel, done := r.cancel, r.done
	r.mu.RUnlock()
	if cancel == nil || done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ Checker = (*Reconciler)(nil)
