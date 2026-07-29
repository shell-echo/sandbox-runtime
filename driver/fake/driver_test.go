package fake

import (
	"context"
	"errors"
	"testing"

	"github.com/shell-echo/sandbox-runtime/instance"
)

func TestDriverLifecycle(t *testing.T) {
	driver := NewDriver()
	ctx := context.Background()
	spec := instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}
	if err := driver.Create(ctx, "one", spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if state, err := driver.Inspect(ctx, "one"); err != nil || state.State != instance.RuntimeStopped {
		t.Fatalf("Inspect after create = %+v, %v", state, err)
	}
	if err := driver.Start(ctx, "one"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if state, err := driver.Inspect(ctx, "one"); err != nil || state.State != instance.RuntimeRunning {
		t.Fatalf("Inspect after start = %+v, %v", state, err)
	}
	if err := driver.Stop(ctx, "one"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := driver.Remove(ctx, "one"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := driver.Inspect(ctx, "one"); !errors.Is(err, instance.ErrNotFound) {
		t.Fatalf("Inspect removed = %v", err)
	}
	if err := driver.Remove(ctx, "missing"); err != nil {
		t.Fatalf("idempotent Remove: %v", err)
	}
	if err := driver.Create(ctx, "two", spec); err != nil {
		t.Fatalf("Create second runtime: %v", err)
	}
	if err := driver.Start(ctx, "two"); err != nil {
		t.Fatalf("Start second runtime: %v", err)
	}
	if err := driver.Remove(ctx, "two"); err != nil {
		t.Fatalf("Remove running runtime: %v", err)
	}
}

func TestDriverErrorsAndCancellation(t *testing.T) {
	driver := NewDriver()
	ctx := context.Background()
	spec := instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}
	if err := driver.Start(ctx, "missing"); !errors.Is(err, instance.ErrNotFound) {
		t.Fatalf("Start missing = %v", err)
	}
	if err := driver.Create(ctx, "one", spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := driver.Create(ctx, "one", spec); !errors.Is(err, instance.ErrAlreadyExists) {
		t.Fatalf("duplicate Create = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := driver.Start(cancelled, "one"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start cancelled = %v", err)
	}
}
