//go:build integration

package docker

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/instance"
	instancefile "github.com/shell-echo/sandbox-runtime/instance/file"
)

func TestDockerDriverIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_DOCKER_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 to run against Docker Engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	image := os.Getenv("SANDBOX_RUNTIME_DOCKER_TEST_IMAGE")
	if image == "" {
		image = "alpine:3.23"
	}
	driver, err := New(ctx, Options{
		Host:                    os.Getenv("DOCKER_HOST"),
		Image:                   image,
		PullPolicy:              PullIfNotPresent,
		MemoryBytes:             128 << 20,
		NanoCPUs:                250_000_000,
		PidsLimit:               64,
		OperationTimeoutSeconds: 30,
		PullTimeoutSeconds:      90,
		StopTimeoutSeconds:      5,
		User:                    "65532:65532",
		Command:                 []string{"/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"},
		Namespace:               "integration-test",
		ControllerID:            "integration-controller",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer driver.Close()

	id := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = driver.Remove(cleanupCtx, id)
	})
	if err := driver.Create(ctx, id, instance.Spec{Name: "integration", Workload: instance.WorkloadShell}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if state, err := driver.Inspect(ctx, id); err != nil || state.State != instance.RuntimeStopped {
		t.Fatalf("Inspect created = %+v, %v", state, err)
	}
	if err := driver.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if state, err := driver.Inspect(ctx, id); err != nil || state.State != instance.RuntimeRunning {
		t.Fatalf("Inspect running = %+v, %v", state, err)
	}
	if err := driver.Stop(ctx, id); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := driver.Remove(ctx, id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

func TestDockerServiceRestartIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_DOCKER_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 to run against Docker Engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	image := os.Getenv("SANDBOX_RUNTIME_DOCKER_TEST_IMAGE")
	if image == "" {
		image = "alpine:3.23"
	}
	id := fmt.Sprintf("restart-%d", time.Now().UnixNano())
	driver, err := New(ctx, Options{
		Host: os.Getenv("DOCKER_HOST"), Image: image, PullPolicy: PullIfNotPresent,
		MemoryBytes: 128 << 20, NanoCPUs: 250_000_000, PidsLimit: 64,
		OperationTimeoutSeconds: 30, PullTimeoutSeconds: 90, StopTimeoutSeconds: 5,
		User: "65532:65532", Command: []string{"/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"},
		Namespace: "integration-test", ControllerID: id,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer driver.Close()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = driver.Remove(cleanupCtx, id)
	})

	path := t.TempDir() + "/instances.json"
	repository, err := instancefile.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	service, err := instance.NewService(repository, driver, instance.WithIDGenerator(func() (string, error) { return id, nil }))
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(ctx, instance.Spec{Name: "restart-shell", Workload: instance.WorkloadShell})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = instance.StateStarting
	if err := repository.Update(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := instancefile.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := instance.NewService(reopened, driver)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	running, err := restarted.Inspect(ctx, created.ID)
	if err != nil || running.State != instance.StateRunning {
		t.Fatalf("Inspect after restart = %+v, %v", running, err)
	}
	if _, err := restarted.Stop(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Remove(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
}
