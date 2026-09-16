package qualificationsupervisor

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	runExecutionLimit  = 1800 * time.Second
	caseExecutionLimit = 120 * time.Second
)

// runBudget binds the one parent context supplied during lexical preparation
// to a monotonic deadline that starts exactly once at the first supervisor
// preflight read. The resulting deadline is shared by both phase processes.
type runBudget struct {
	parent context.Context

	mu       sync.Mutex
	started  bool
	start    time.Time
	deadline time.Time
	ctx      context.Context
	cancel   context.CancelFunc
}

func newRunBudget(parent context.Context) *runBudget {
	return &runBudget{parent: parent}
}

// start immediately precedes the caller's first preflight read. Validation
// that performs no I/O remains outside this clock scope.
func (b *runBudget) startContext() (context.Context, error) {
	if b == nil || b.parent == nil {
		return nil, ErrConfiguration
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started {
		b.start = time.Now()
		b.ctx, b.cancel = context.WithDeadline(b.parent, b.start.Add(runExecutionLimit))
		b.deadline, _ = b.ctx.Deadline()
		b.started = true
	}
	if err := contextFailure(b.ctx); err != nil {
		return nil, err
	}
	return b.ctx, nil
}

func (b *runBudget) context() (context.Context, error) {
	if b == nil {
		return nil, ErrPreflight
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started || b.ctx == nil {
		return nil, ErrPreflight
	}
	if err := contextFailure(b.ctx); err != nil {
		return nil, err
	}
	return b.ctx, nil
}

func (b *runBudget) snapshot() (start, deadline time.Time, started bool) {
	if b == nil {
		return time.Time{}, time.Time{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.start, b.deadline, b.started
}

func (b *runBudget) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	cancel := b.cancel
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// clippedContext respects the immutable run context and a narrower operation
// context. Releasing it never cancels the shared run budget.
func clippedContext(base, operation context.Context) (context.Context, func(), error) {
	if base == nil || operation == nil {
		return nil, nil, ErrPreflight
	}
	deadline := time.Time{}
	if candidate, ok := base.Deadline(); ok {
		deadline = candidate
	}
	if candidate, ok := operation.Deadline(); ok && (deadline.IsZero() || candidate.Before(deadline)) {
		deadline = candidate
	}

	var deadlineContext context.Context
	var deadlineCancel context.CancelFunc
	if deadline.IsZero() {
		deadlineContext, deadlineCancel = context.WithCancel(base)
	} else {
		deadlineContext, deadlineCancel = context.WithDeadline(base, deadline)
	}
	merged, causeCancel := context.WithCancelCause(deadlineContext)
	stop := context.AfterFunc(operation, func() {
		cause := context.Cause(operation)
		if cause == nil {
			cause = context.Canceled
		}
		causeCancel(cause)
	})
	if cause := context.Cause(operation); cause != nil {
		causeCancel(cause)
	}
	release := func() {
		stop()
		causeCancel(context.Canceled)
		deadlineCancel()
	}
	if err := contextFailure(merged); err != nil {
		release()
		return nil, nil, err
	}
	return merged, release, nil
}

func contextFailure(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if cause := context.Cause(ctx); cause != nil {
		if errors.Is(cause, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return context.Canceled
	}
	return nil
}

func effectiveDeadline(run context.Context, caseDeadline time.Time) time.Time {
	deadline, _ := run.Deadline()
	if !caseDeadline.IsZero() && (deadline.IsZero() || caseDeadline.Before(deadline)) {
		return caseDeadline
	}
	return deadline
}

// deadlineFailure enforces deadline precedence even when a timer and an I/O
// event become ready in the same select operation.
func deadlineFailure(ctx context.Context, caseDeadline, observedAt time.Time) error {
	deadline := effectiveDeadline(ctx, caseDeadline)
	if !deadline.IsZero() && !observedAt.Before(deadline) {
		return context.DeadlineExceeded
	}
	return contextFailure(ctx)
}
