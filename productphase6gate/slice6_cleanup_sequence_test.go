//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

type slice6CleanupStage struct {
	name string
	run  func(context.Context) error
}

// Cleanup is single-shot, independent of the canceled business context, and
// continues through every independent stage. The first error is retained in
// order; a repeated call cannot retry a partially completed terminal action.
type slice6CleanupSequence struct {
	once   sync.Once
	stages []slice6CleanupStage
	err    error
}

// The ordinary exit and testing.T cleanup share one independent deadline.
// Exact run-labeled cleanup may get one fallback after a failed first pass,
// but the fallback cannot refresh the budget or erase the first failure.
type slice6BoundedRunCleanup struct {
	budget            time.Duration
	ctx               context.Context
	cancel            context.CancelFunc
	attempted         bool
	fallbackAttempted bool
	firstErr          error
	fallbackErr       error
}

func (guard *slice6BoundedRunCleanup) Context() context.Context {
	if guard.ctx == nil {
		guard.ctx, guard.cancel = context.WithTimeout(context.Background(), guard.budget)
	}
	return guard.ctx
}

func (guard *slice6BoundedRunCleanup) Run(cleanup func(context.Context) error) error {
	if guard.attempted {
		return guard.firstErr
	}
	guard.attempted = true
	if cleanup == nil || guard.budget <= 0 {
		guard.firstErr = errors.New("exact run cleanup unavailable")
		return guard.firstErr
	}
	guard.firstErr = cleanup(guard.Context())
	return guard.firstErr
}

func (guard *slice6BoundedRunCleanup) Finish(cleanup func(context.Context) error) error {
	if !guard.attempted {
		guard.Run(cleanup)
	} else if guard.firstErr != nil && !guard.fallbackAttempted && cleanup != nil {
		guard.fallbackAttempted = true
		guard.fallbackErr = cleanup(guard.Context())
	}
	return errors.Join(guard.firstErr, guard.fallbackErr)
}

func (guard *slice6BoundedRunCleanup) Close() {
	if guard.cancel != nil {
		guard.cancel()
	}
}

func (sequence *slice6CleanupSequence) Run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	return sequence.RunContext(ctx)
}

// Multiple exact owners in one invocation can share one finite cleanup
// deadline. A later owner must not reset the earlier owner's budget.
func (sequence *slice6CleanupSequence) RunContext(ctx context.Context) error {
	if sequence == nil || ctx == nil {
		return errors.New("cleanup sequence context unavailable")
	}
	sequence.once.Do(func() {
		for _, stage := range sequence.stages {
			if stage.name == "" || stage.run == nil {
				sequence.err = errors.Join(sequence.err, errors.New("invalid cleanup stage"))
				continue
			}
			if err := stage.run(ctx); err != nil {
				sequence.err = errors.Join(sequence.err, fmt.Errorf("%s: %w", stage.name, err))
			}
		}
	})
	return sequence.err
}

func TestSlice6CleanupSequenceSharedContextDoesNotRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := &slice6CleanupSequence{stages: []slice6CleanupStage{{"first", func(context.Context) error {
		cancel()
		return nil
	}}}}
	second := &slice6CleanupSequence{stages: []slice6CleanupStage{{"second", func(observed context.Context) error {
		if observed.Err() == nil {
			return errors.New("cleanup context silently refreshed")
		}
		return nil
	}}}}
	if first.RunContext(ctx) != nil || second.RunContext(ctx) != nil ||
		first.RunContext(ctx) != nil || second.RunContext(ctx) != nil {
		t.Fatal("shared exact-owner cleanup budget was refreshed or retried")
	}
}

func TestSlice6CleanupSequencePreservesFirstFailureAndRunsOnce(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	cancel()
	first := errors.New("first failure")
	second := errors.New("second failure")
	var order []string
	sequence := &slice6CleanupSequence{stages: []slice6CleanupStage{
		{"stop-dependent", func(ctx context.Context) error {
			if parent.Err() == nil || ctx.Err() != nil {
				t.Fatal("cleanup inherited canceled business context")
			}
			order = append(order, "stop-dependent")
			return first
		}},
		{"quiesce-controller", func(context.Context) error {
			order = append(order, "quiesce-controller")
			return second
		}},
		{"terminal", func(context.Context) error {
			order = append(order, "terminal")
			return nil
		}},
	}}
	got := sequence.Run()
	if !errors.Is(got, first) || !errors.Is(got, second) ||
		!slices.Equal(order, []string{"stop-dependent", "quiesce-controller", "terminal"}) ||
		!errors.Is(sequence.Run(), first) || len(order) != 3 {
		t.Fatal("cleanup sequence dropped, reordered or retried a stage")
	}
}

func TestSlice6CleanupSequenceRunsAfterGoexitStyleCallback(t *testing.T) {
	completed := make(chan error, 1)
	var order []string
	sequence := &slice6CleanupSequence{stages: []slice6CleanupStage{
		{"dependent", func(context.Context) error { order = append(order, "dependent"); return nil }},
		{"terminal", func(context.Context) error { order = append(order, "terminal"); return nil }},
	}}
	go func() {
		defer func() { completed <- sequence.Run() }()
		runtime.Goexit()
	}()
	select {
	case err := <-completed:
		if err != nil || !slices.Equal(order, []string{"dependent", "terminal"}) {
			t.Fatal("Goexit-style callback bypassed ordered cleanup")
		}
	case <-time.After(time.Second):
		t.Fatal("Goexit-style callback did not run cleanup")
	}
}

func TestSlice6BoundedRunCleanupPreservesFirstErrorAndDeadline(t *testing.T) {
	first := errors.New("first exact cleanup failed")
	callback := errors.New("original business failure")
	guard := &slice6BoundedRunCleanup{budget: time.Second}
	var deadline time.Time
	calls := 0
	cleanup := func(ctx context.Context) error {
		calls++
		observed, ok := ctx.Deadline()
		if !ok || calls > 1 && !observed.Equal(deadline) || ctx.Err() != nil {
			t.Fatal("cleanup refreshed or inherited a canceled deadline")
		}
		deadline = observed
		if calls == 1 {
			return first
		}
		return nil
	}
	if err := guard.Run(cleanup); !errors.Is(err, first) {
		t.Fatal("normal cleanup lost its first failure")
	}
	combined := errors.Join(callback, guard.Finish(cleanup))
	guard.Close()
	if calls != 2 || !errors.Is(combined, callback) || !errors.Is(combined, first) ||
		guard.Finish(cleanup) == nil || calls != 2 {
		t.Fatal("bounded fallback erased business/cleanup failure or ran more than once")
	}
}

func TestSlice6BoundedRunCleanupRunsAfterGoexitWithoutBusinessContext(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	cancel()
	guard := &slice6BoundedRunCleanup{budget: time.Second}
	completed := make(chan error, 1)
	go func() {
		defer func() {
			completed <- guard.Finish(func(ctx context.Context) error {
				if parent.Err() == nil || ctx.Err() != nil {
					return errors.New("cleanup inherited canceled business context")
				}
				return nil
			})
			guard.Close()
		}()
		runtime.Goexit()
	}()
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("Goexit cleanup failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Goexit cleanup did not complete")
	}
}
