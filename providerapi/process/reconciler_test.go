package process

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestReconcilerClosesAndRecoversReadiness(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int64
	reconciler, err := NewReconciler(time.Second, time.Second, func(context.Context) error {
		calls.Add(1)
		if fail.Load() {
			return errors.New("dependency unavailable")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Ready(context.Background()); err == nil {
		t.Fatal("reconciler reported ready before its first complete pass")
	}
	reconciler.run(context.Background())
	if err := reconciler.Ready(context.Background()); err != nil {
		t.Fatalf("initial readiness: %v", err)
	}
	fail.Store(true)
	reconciler.run(context.Background())
	if err := reconciler.Ready(context.Background()); err == nil {
		t.Fatal("failed reconciliation remained ready")
	}
	fail.Store(false)
	reconciler.run(context.Background())
	if err := reconciler.Ready(context.Background()); err != nil {
		t.Fatalf("recovered readiness: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("reconciliation calls = %d, want 3", calls.Load())
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
