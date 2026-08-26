//go:build integration

package docker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

func TestProviderDockerLifecycleIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_DOCKER_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 to run against Docker Engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	image := integrationPinnedImage(ctx, t)
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid = 65532
	}
	if gid == 0 {
		gid = 65532
	}
	dataRoot, err := os.MkdirTemp(".", ".provider-docker-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataRoot) })
	options := Options{
		Host: os.Getenv("DOCKER_HOST"), Image: image, PullPolicy: PullIfNotPresent,
		MemoryBytes: 128 << 20, NanoCPUs: 250_000_000, PidsLimit: 64, TmpfsBytes: 32 << 20,
		OperationTimeoutSeconds: 30, PullTimeoutSeconds: 90, StopTimeoutSeconds: 5,
		User:     fmt.Sprintf("%d:%d", uid, gid),
		Command:  []string{"/bin/sh", "-c", "set -e; test -r /inputs; test ! -w /inputs; touch /workspace/ready; touch /outputs/ready; trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"},
		DataRoot: dataRoot, Namespace: "provider-integration", ControllerID: fmt.Sprintf("controller-%d", time.Now().UnixNano()),
	}
	driver, err := New(ctx, options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sandbox := testSandbox(time.Now().UTC())
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		cleanupDriver, cleanupErr := New(cleanupCtx, options)
		if cleanupErr == nil {
			_ = cleanupDriver.Remove(cleanupCtx, sandbox.ID)
			_ = cleanupDriver.Close()
		}
	})
	if err := driver.Create(ctx, sandbox); err != nil {
		info, inspectErr := driver.engine.inspect(ctx, containerName(sandbox.ID))
		t.Fatalf("Create: %v (bounded backend state: status=%q running=%t inspect_error=%v)", err, info.status, info.running, inspectErr)
	}
	observation, err := driver.Inspect(ctx, sandbox.ID)
	if err != nil || observation.State != coordinator.RuntimeReady {
		t.Fatalf("Inspect = %#v, %v", observation, err)
	}
	paths, err := driver.mountPaths(sandbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitForMountMarkers(t, driver, sandbox.ID, paths.workspace+"/ready", paths.outputs+"/ready")
	if err := driver.Close(); err != nil {
		t.Fatalf("Close before restart: %v", err)
	}

	restarted, err := New(ctx, options)
	if err != nil {
		t.Fatalf("New after restart: %v", err)
	}
	driver = restarted
	if observation, err := restarted.Inspect(ctx, sandbox.ID); err != nil || observation.State != coordinator.RuntimeReady {
		t.Fatalf("Inspect after restart = %#v, %v", observation, err)
	}
	if err := restarted.Create(ctx, sandbox); err != nil {
		t.Fatalf("idempotent Create after restart: %v", err)
	}
	if err := restarted.Remove(ctx, sandbox.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(paths.root); !os.IsNotExist(err) {
		t.Fatalf("mount root remains after Remove: %v", err)
	}
}

func waitForMountMarkers(t *testing.T, driver *Driver, sandboxID string, markers ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		allPresent := true
		for _, marker := range markers {
			if _, err := os.Stat(marker); err != nil {
				allPresent = false
				break
			}
		}
		if allPresent {
			return
		}
		if time.Now().After(deadline) {
			info, inspectErr := driver.engine.inspect(context.Background(), containerName(sandboxID))
			t.Fatalf("stable mount markers unavailable (bounded backend state: status=%q running=%t inspect_error=%v)", info.status, info.running, inspectErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func integrationPinnedImage(ctx context.Context, t *testing.T) string {
	t.Helper()
	configured := os.Getenv("SANDBOX_RUNTIME_PROVIDER_DOCKER_TEST_IMAGE")
	if configured != "" && isSHA256PinnedImage(configured) {
		return configured
	}
	mutable := configured
	if mutable == "" {
		mutable = "alpine:3.23"
	}
	apiClient, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatalf("create image preparation client: %v", err)
	}
	defer apiClient.Close()
	if _, err := apiClient.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		t.Fatalf("ping Docker Engine: %v", err)
	}
	pull, err := apiClient.ImagePull(ctx, mutable, client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull integration image %q: %v", mutable, err)
	}
	if err := pull.Wait(ctx); err != nil {
		_ = pull.Close()
		t.Fatalf("wait for integration image %q: %v", mutable, err)
	}
	if err := pull.Close(); err != nil {
		t.Fatalf("close integration image response: %v", err)
	}
	inspection, err := apiClient.ImageInspect(ctx, mutable)
	if err != nil {
		t.Fatalf("inspect integration image %q: %v", mutable, err)
	}
	for _, repoDigest := range inspection.RepoDigests {
		if strings.Contains(repoDigest, "@sha256:") && isSHA256PinnedImage(repoDigest) {
			return repoDigest
		}
	}
	t.Fatalf("image %q has no sha256 repository digest", mutable)
	return ""
}
