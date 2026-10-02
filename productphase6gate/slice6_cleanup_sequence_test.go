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

func (sequence *slice6CleanupSequence) Run() error {
	sequence.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
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
