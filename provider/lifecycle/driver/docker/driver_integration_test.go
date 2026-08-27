//go:build integration

package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
	providerterminal "github.com/shell-echo/sandbox-runtime/provider/terminal"
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
	brokerGuestPath := "/workspace/.sandbox-runtime/bin/terminal-broker"
	buildIntegrationTerminalBroker(ctx, t, filepath.Join(paths.workspace, ".sandbox-runtime", "bin", "terminal-broker"))
	terminalOptions := TerminalOptions{
		BrokerPath: brokerGuestPath, ShellPath: "/bin/sh", MaxSessionsPerSandbox: 2, MaxSessionsPerController: 4,
		Clock: providerterminal.ClockFunc(func() time.Time { return time.Now().UTC() }),
	}
	terminalRuntime, err := NewTerminalRuntime(driver, terminalOptions)
	if err != nil {
		t.Fatalf("NewTerminalRuntime: %v", err)
	}
	terminalAllocation := integrationTerminalAllocation(sandbox.ID, time.Now().UTC())
	terminalReceipt, err := terminalRuntime.Allocate(ctx, terminalAllocation)
	if err != nil {
		t.Fatalf("Allocate terminal: %v", err)
	}
	terminalStream, err := terminalRuntime.Attach(ctx, terminalReceipt)
	if err != nil {
		t.Fatalf("Attach terminal: %v", err)
	}
	writeAndReadTerminalMarker(t, terminalStream, "SR_RECONNECT=preserved; printf 'TERMINAL-FIRST:%s\\n' \"$SR_RECONNECT\"\n", "TERMINAL-FIRST:preserved")
	if err := terminalStream.Close(); err != nil {
		t.Fatalf("Close first terminal stream: %v", err)
	}
	_, terminalStatePath, err := terminalRuntime.stateLocationForReceipt(terminalReceipt)
	if err != nil {
		t.Fatal(err)
	}
	privateBeforeRestart, err := loadTerminalState(terminalStatePath)
	if err != nil {
		t.Fatalf("load terminal private state: %v", err)
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
	restartedTerminal, err := NewTerminalRuntime(restarted, terminalOptions)
	if err != nil {
		t.Fatalf("NewTerminalRuntime after restart: %v", err)
	}
	terminalObservation, err := restartedTerminal.Observe(ctx, terminalReceipt)
	if err != nil || terminalObservation.State != providerterminal.ObservationRunning {
		t.Fatalf("Observe terminal after restart = %#v, %v", terminalObservation, err)
	}
	reconnectedTerminal, err := restartedTerminal.Attach(ctx, terminalReceipt)
	if err != nil {
		t.Fatalf("Attach terminal after restart: %v", err)
	}
	writeAndReadTerminalMarker(t, reconnectedTerminal, "printf 'TERMINAL-SECOND:%s\\n' \"$SR_RECONNECT\"\n", "TERMINAL-SECOND:preserved")
	if err := reconnectedTerminal.Close(); err != nil {
		t.Fatalf("Close reconnected terminal stream: %v", err)
	}
	privateAfterRestart, err := loadTerminalState(terminalStatePath)
	if err != nil || privateAfterRestart.BackendBrokerExecID != privateBeforeRestart.BackendBrokerExecID {
		t.Fatalf("terminal broker identity changed across restart: before=%q after=%q err=%v", privateBeforeRestart.BackendBrokerExecID, privateAfterRestart.BackendBrokerExecID, err)
	}
	if err := restartedTerminal.Cleanup(ctx, terminalReceipt); err != nil {
		t.Fatalf("Cleanup terminal: %v", err)
	}
	if _, err := os.Stat(terminalStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminal private state remains after cleanup: %v", err)
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

func integrationTerminalAllocation(sandboxID string, now time.Time) providerterminal.Allocation {
	return providerterminal.Allocation{
		AllocatedAt: now,
		Request: providerterminal.AllocationRequest{
			SandboxID: sandboxID, RuntimeSessionID: "integration-terminal",
			OperationID: "integration-terminal-operation", AttemptID: "integration-terminal-attempt",
			FencingToken: 3, ExpectedGeneration: 1,
			RequestDigest:    "sha256:" + strings.Repeat("e", 64),
			WorkingDirectory: "/workspace", ExpiresAt: now.Add(time.Minute),
		},
	}
}

func buildIntegrationTerminalBroker(ctx context.Context, t *testing.T, destination string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	moduleRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", destination, "./cmd/terminal-broker")
	command.Dir = moduleRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH, "GOCACHE="+filepath.Join(t.TempDir(), "go-cache"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Linux terminal broker: %v: %s", err, output)
	}
	if err := os.Chmod(destination, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeAndReadTerminalMarker(t *testing.T, stream providerterminal.Stream, command, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := stream.Write(ctx, []byte(command)); err != nil {
		t.Fatalf("write terminal command: %v", err)
	}
	buffer := make([]byte, 4096)
	var output strings.Builder
	for output.Len() < 64<<10 {
		count, err := stream.Read(ctx, buffer)
		if count > 0 {
			output.Write(buffer[:count])
			if strings.Contains(output.String(), marker) {
				return
			}
		}
		if err != nil {
			t.Fatalf("read terminal marker %q from %q: %v", marker, output.String(), err)
		}
	}
	t.Fatalf("terminal output exceeded bound without marker %q", marker)
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
