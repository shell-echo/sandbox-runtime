package file_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/instance"
	instancefile "github.com/shell-echo/sandbox-runtime/instance/file"
)

func TestRepositoryPersistsLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "instances.json")
	repository, err := instancefile.NewRepository(path)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	now := time.Now().UTC()
	inst := &instance.Instance{ID: "instance-one", Name: "shell", Workload: instance.WorkloadShell, State: instance.StateStopped, CreatedAt: now, UpdatedAt: now}
	if err := repository.Create(context.Background(), inst); err != nil {
		t.Fatalf("Create: %v", err)
	}
	inst.State = instance.StateRunning
	inst.UpdatedAt = now.Add(time.Second)
	if err := repository.Update(context.Background(), inst); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := instancefile.NewRepository(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := reopened.Get(context.Background(), inst.ID)
	if err != nil || got.State != instance.StateRunning {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if err := reopened.Delete(context.Background(), inst.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened: %v", err)
	}
	last, err := instancefile.NewRepository(path)
	if err != nil {
		t.Fatalf("reopen empty: %v", err)
	}
	if count, err := last.Count(context.Background()); err != nil || count != 0 {
		t.Fatalf("Count = %d, %v", count, err)
	}
	if err := last.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryRejectsConcurrentProcessOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instances.json")
	first, err := instancefile.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := instancefile.NewRepository(path); err == nil {
		t.Fatal("expected exclusive repository lock error")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := instancefile.NewRepository(path)
	if err != nil {
		t.Fatalf("reopen after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryRejectsCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instances.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"instances":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := instancefile.NewRepository(path); err == nil {
		t.Fatal("expected corrupt repository error")
	}
}

func TestRepositoryHonorsCanceledContext(t *testing.T) {
	repository, err := instancefile.NewRepository(filepath.Join(t.TempDir(), "instances.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.List(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("List = %v, want canceled", err)
	}
}

func TestRepositoryRejectsOversizedFailure(t *testing.T) {
	repository, err := instancefile.NewRepository(filepath.Join(t.TempDir(), "instances.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	now := time.Now().UTC()
	inst := &instance.Instance{
		ID: "instance-one", Name: "shell", Workload: instance.WorkloadShell,
		State: instance.StateFailed, CreatedAt: now, UpdatedAt: now,
		Failure: strings.Repeat("x", instance.MaxFailureLength+1),
	}
	if err := repository.Create(context.Background(), inst); err == nil {
		t.Fatal("expected oversized failure rejection")
	}
}

func TestRepositoryRollsBackUncommittedMutation(t *testing.T) {
	directory := t.TempDir()
	stateDirectory := filepath.Join(directory, "state")
	repository, err := instancefile.NewRepository(filepath.Join(stateDirectory, "instances.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stateDirectory, "instances.json.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stateDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateDirectory, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	inst := &instance.Instance{ID: "instance-one", Name: "shell", Workload: instance.WorkloadShell, State: instance.StateStopped, CreatedAt: now, UpdatedAt: now}
	if err := repository.Create(context.Background(), inst); err == nil {
		t.Fatal("expected persistence failure")
	}
	if count, err := repository.Count(context.Background()); err != nil || count != 0 {
		t.Fatalf("Count after failed create = %d, %v", count, err)
	}
}
