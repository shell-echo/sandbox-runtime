//go:build integration

package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
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
	execRequest := integrationExecRequest(sandbox.ID, "integration-exec", time.Now().UTC())
	reference, err := driver.Start(ctx, providerexec.Invocation{Request: execRequest, StartedAt: time.Now().UTC()})
	if err != nil || !strings.HasPrefix(string(reference), "ref:exec/") {
		t.Fatalf("Start exec = %q, %v", reference, err)
	}
	execObservation := waitForExecTerminal(t, driver, execRequest)
	if execObservation.Status != providerexec.ResultCompleted || execObservation.ExitCode == nil || *execObservation.ExitCode != 7 || execObservation.StdoutReference == "" || execObservation.StderrReference == "" {
		t.Fatalf("exec observation = %#v", execObservation)
	}
	execStatePath := driver.execStatePath(filepath.Join(paths.root, "exec"), execRequest.OperationID)
	execState, err := loadExecState(execStatePath)
	if err != nil || execState.StdoutBytes != 4 || execState.StderrBytes != 4 || !execState.StdoutTruncated || !execState.StderrTruncated {
		t.Fatalf("exec capture state = %#v, %v", execState, err)
	}
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
	restartedExec, err := restarted.Observe(ctx, execRequest)
	if err != nil || restartedExec.Status != providerexec.ResultCompleted || restartedExec.ExecutionReference != reference {
		t.Fatalf("Observe exec after restart = %#v, %v", restartedExec, err)
	}
	if err := restarted.CleanupResult(ctx, execRequest); err != nil {
		t.Fatalf("CleanupResult: %v", err)
	}
	for _, path := range []string{execState.StdoutPath, execState.StderrPath, execStatePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired exec evidence remains at %q: %v", path, err)
		}
	}

	cancelRequest := integrationExecRequest(sandbox.ID, "integration-cancel", time.Now().UTC())
	cancelRequest.Command = []string{"sh", "-c", "sleep 60"}
	cancelRequest.CaptureStdout, cancelRequest.CaptureStderr, cancelRequest.CaptureMaxBytes = false, false, 0
	cancelReference, err := restarted.Start(ctx, providerexec.Invocation{Request: cancelRequest, StartedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("Start cancellable exec: %v", err)
	}
	waitForExecRunning(t, restarted, cancelRequest)
	if err := restarted.Cancel(ctx, providerexec.ExecutionAttachment{
		OperationID: cancelRequest.OperationID, AttemptID: cancelRequest.AttemptID, SandboxID: cancelRequest.SandboxID,
		FencingToken: cancelRequest.FencingToken, ExpectedGeneration: cancelRequest.ExpectedGeneration,
		Dispatch: providerexec.Dispatch{ExecutionReference: cancelReference, AcceptedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("Cancel exec: %v", err)
	}
	cancelled, err := restarted.Observe(ctx, cancelRequest)
	if err != nil || cancelled.Status != providerexec.ResultCancelled {
		t.Fatalf("Observe cancelled exec = %#v, %v", cancelled, err)
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

func integrationExecRequest(sandboxID, operationID string, now time.Time) providerexec.Request {
	return providerexec.Request{
		SandboxID: sandboxID, OperationID: operationID, AttemptID: operationID + "-attempt",
		FencingToken: 2, ExpectedGeneration: 1, IdempotencyKey: operationID + "-key",
		RequestDigest: "sha256:" + strings.Repeat("d", 64), Deadline: now.Add(time.Minute),
		Command: []string{"sh", "-c", "printf abcdef; printf uvwxyz >&2; exit 7"}, WorkingDirectory: "/workspace",
		ResultRetention: time.Hour, CaptureStdout: true, CaptureStderr: true, CaptureMaxBytes: 4,
	}
}

func waitForExecRunning(t *testing.T, driver *Driver, request providerexec.Request) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		observation, err := driver.Observe(context.Background(), request)
		if err == nil && observation.Running {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("exec did not reach running state")
}

func waitForExecTerminal(t *testing.T, driver *Driver, request providerexec.Request) providerexec.Observation {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		observation, err := driver.Observe(context.Background(), request)
		if err == nil && !observation.Running {
			return observation
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("exec did not reach terminal state")
	return providerexec.Observation{}
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
