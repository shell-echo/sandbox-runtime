package memory

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/shell-echo/sandbox-runtime/instance"
)

func TestRepositoryCRUDAndSnapshots(t *testing.T) {
	repository := NewRepository()
	ctx := context.Background()
	a := &instance.Instance{ID: "b", Name: "second", State: instance.StateStopped}
	b := &instance.Instance{ID: "a", Name: "first", State: instance.StateStopped}
	for _, inst := range []*instance.Instance{a, b} {
		if err := repository.Create(ctx, inst); err != nil {
			t.Fatalf("Create(%s): %v", inst.ID, err)
		}
	}
	if err := repository.Create(ctx, a); !errors.Is(err, instance.ErrAlreadyExists) {
		t.Fatalf("duplicate Create = %v", err)
	}

	instances, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(instances) != 2 || instances[0].ID != "a" || instances[1].ID != "b" {
		t.Fatalf("List = %+v", instances)
	}
	instances[0].Name = "mutated"
	got, err := repository.Get(ctx, "a")
	if err != nil || got.Name != "first" {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	got.State = instance.StateRunning
	if err := repository.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := repository.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repository.Get(ctx, "a"); !errors.Is(err, instance.ErrNotFound) {
		t.Fatalf("Get deleted = %v", err)
	}
}

func TestRepositoryConcurrentAccess(t *testing.T) {
	repository := NewRepository()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := string(rune(i + 1))
			if err := repository.Create(ctx, &instance.Instance{ID: id, State: instance.StateStopped}); err != nil {
				t.Errorf("Create: %v", err)
			}
			if _, err := repository.Get(ctx, id); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()
	instances, err := repository.List(ctx)
	if err != nil || len(instances) != 100 {
		t.Fatalf("List instances=%+v err=%v", instances, err)
	}
}

func TestRepositoryHonorsCancelledContext(t *testing.T) {
	repository := NewRepository()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := repository.Create(ctx, &instance.Instance{ID: "a"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Create = %v, want context.Canceled", err)
	}
}

var _ instance.Repository = (*Repository)(nil)
