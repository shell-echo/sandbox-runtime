package fake

import (
	"context"
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

func TestDriverIsIndependentAndBounded(t *testing.T) {
	driver := New()
	sandbox := lifecycle.Sandbox{ID: "sandbox-1"}
	if err := driver.Create(context.Background(), sandbox); err != nil {
		t.Fatal(err)
	}
	observation, err := driver.Inspect(context.Background(), sandbox.ID)
	if err != nil || observation.State != coordinator.RuntimeReady {
		t.Fatalf("Inspect() = %#v, %v", observation, err)
	}
	missing, err := driver.Inspect(context.Background(), "missing")
	if err != nil || missing.State != coordinator.RuntimeAbsent {
		t.Fatalf("missing Inspect() = %#v, %v", missing, err)
	}
}
