//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6FDLoaderEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_FD_LOADER"

// The fixture has no private data. It proves the one-shot loader's actual
// Linux PID1 exec and sealed FD layout in a restricted Docker container, not
// yet the full certificate-controller dependency chain or release gate.
func TestPhase6Slice6FDLoaderRestrictedDocker(t *testing.T) {
	if os.Getenv(slice6FDLoaderEnv) != "1" {
		t.Skip("set " + slice6FDLoaderEnv + "=1 for the real restricted Docker FD-loader component")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact FD-loader Docker cleanup: %v", err)
		}
	})
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(".", ".sr-fd-loader-")
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove exact FD-loader test binaries: %v", err)
		}
	})
	for _, build := range []struct{ packagePath, name string }{
		{"./cmd/phase6-fd-loader", "loader"},
		{"./internal/phase6fdloader/testdata/role", "role"},
	} {
		command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
			"-ldflags=-buildid=", "-o", filepath.Join(directory, build.name), build.packagePath)
		command.Dir = root
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
		if _, err := command.CombinedOutput(); err != nil {
			t.Fatal("cross-build fixed FD-loader test binary failed")
		}
	}
	nonce, err := phase6security.NewSlice6RunID()
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	create := func(suffix string, mountRole bool) string {
		t.Helper()
		arguments := []string{"create", "-i", "--pull=never", "--name", "sr-p6-fd-" + suffix + "-" + run.id,
			"--label", run.label(), "--network", "none", "--restart", "no",
			"--user", "65532:65532", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
			"--security-opt", "seccomp=" + seccomp, "--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
			"--mount", "type=bind,source=" + filepath.Join(directory, "loader") + ",target=/usr/local/bin/phase6-fd-loader,readonly",
		}
		if mountRole {
			arguments = append(arguments, "--mount", "type=bind,source="+filepath.Join(directory, "role")+",target=/usr/local/bin/phase6-role,readonly")
		}
		arguments = append(arguments,
			"-e", "SR_PHASE6_FD_RUN_ID="+run.id, "-e", "SR_PHASE6_FD_TARGET=certificate-controller",
			"-e", "SR_PHASE6_FD_NONCE="+nonce, "--entrypoint", "/bin/sh",
			"docker.io/library/alpine@sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c",
			"-ec", "exec 3</dev/null 4</dev/null 5</dev/null 6</dev/null; exec /usr/local/bin/phase6-fd-loader")
		response, err := run.docker(ctx, arguments...)
		id := strings.TrimSpace(string(response))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("restricted FD-loader container create failed")
		}
		observed, err := run.docker(ctx, "inspect", "--format", "{{.Config.Hostname}}|{{.HostConfig.RestartPolicy.Name}}|{{.Config.Entrypoint}}|{{.Config.Cmd}}", id)
		if err != nil || strings.TrimSpace(string(observed)) != id[:12]+"|no|[/bin/sh]|[-ec exec 3</dev/null 4</dev/null 5</dev/null 6</dev/null; exec /usr/local/bin/phase6-fd-loader]" {
			t.Fatal("FD-loader container ID, no-restart or entrypoint binding changed")
		}
		return id
	}
	envelope := func(id, suppliedNonce string) []byte {
		t.Helper()
		value := phase6fdloader.Envelope{Protocol: phase6fdloader.ProtocolID, RunID: run.id,
			Target: "certificate-controller", ContainerID: id, Nonce: suppliedNonce,
			Config: []byte(`{"protocol":"test"}`), Files: []phase6fdloader.PrivateFile{
				{FD: 3, Data: bytes.Repeat([]byte{1}, 64)},
				{FD: 4, Data: bytes.Repeat([]byte{2}, 64)},
				{FD: 5, Data: []byte("private-test-key")},
				{FD: 6, Data: bytes.Repeat([]byte{3}, 64)},
			}}
		response, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	start := func(id string, document []byte) ([]byte, error) {
		command := exec.CommandContext(ctx, "docker", "start", "-a", "-i", id)
		command.Stdin = bytes.NewReader(document)
		return command.CombinedOutput()
	}
	goodID := create("good", true)
	good, err := start(goodID, envelope(goodID, nonce))
	if err != nil || strings.TrimSpace(string(good)) != "fd-fixture: ok" {
		t.Fatalf("restricted PID1 sealed-FD exec failed: %v: %.512s", err, good)
	}
	staleID := create("stale", true)
	stale, err := start(staleID, envelope(staleID, strings.Repeat("f", 32)))
	if err == nil || !strings.Contains(string(stale), "phase6-fd-loader: input") || strings.Contains(string(stale), "fd-fixture: ok") {
		t.Fatalf("stale startup nonce was not rejected: %v: %.512s", err, stale)
	}
	truncatedID := create("truncated", true)
	truncatedInput := envelope(truncatedID, nonce)
	truncated, err := start(truncatedID, truncatedInput[:len(truncatedInput)-1])
	if err == nil || !strings.Contains(string(truncated), "phase6-fd-loader: input") {
		t.Fatalf("truncated startup envelope was not rejected: %v: %.512s", err, truncated)
	}
	missingRoleID := create("missing-role", false)
	missingRole, err := start(missingRoleID, envelope(missingRoleID, nonce))
	if err == nil || !strings.Contains(string(missingRole), "phase6-fd-loader: exec") ||
		strings.Contains(string(missingRole), "fd-fixture: ok") {
		t.Fatalf("missing fixed exec target was not rejected: %v: %.512s", err, missingRole)
	}
	createFault := func(suffix, entrypoint string, command []string, extraEnv string) string {
		t.Helper()
		arguments := []string{"create", "-i", "--pull=never", "--name", "sr-p6-fd-" + suffix + "-" + run.id,
			"--label", run.label(), "--network", "none", "--restart", "no",
			"--user", "65532:65532", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
			"--security-opt", "seccomp=" + seccomp, "--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
			"--mount", "type=bind,source=" + filepath.Join(directory, "loader") + ",target=/usr/local/bin/phase6-fd-loader,readonly",
			"--mount", "type=bind,source=" + filepath.Join(directory, "role") + ",target=/usr/local/bin/phase6-role,readonly",
			"-e", "SR_PHASE6_FD_RUN_ID=" + run.id, "-e", "SR_PHASE6_FD_TARGET=certificate-controller",
			"-e", "SR_PHASE6_FD_NONCE=" + nonce}
		if extraEnv != "" {
			arguments = append(arguments, "-e", extraEnv)
		}
		arguments = append(arguments, "--entrypoint", entrypoint,
			"docker.io/library/alpine@sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c")
		arguments = append(arguments, command...)
		response, err := run.docker(ctx, arguments...)
		id := strings.TrimSpace(string(response))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("negative FD-loader container create failed")
		}
		return id
	}
	for _, negative := range []struct {
		name       string
		entrypoint string
		command    []string
		extraEnv   string
	}{
		{"missing-reservation", "/usr/local/bin/phase6-fd-loader", nil, ""},
		{"forged-reservation", "/bin/sh", []string{"-ec", "exec 3</etc/passwd 4</dev/null 5</dev/null 6</dev/null; exec /usr/local/bin/phase6-fd-loader"}, ""},
		{"unsafe-env", "/bin/sh", []string{"-ec", phase6fdloader.FixedEntrypointCommand}, "ENV=/tmp/unreviewed"},
	} {
		id := createFault(negative.name, negative.entrypoint, negative.command, negative.extraEnv)
		output, err := start(id, envelope(id, nonce))
		if err == nil || !strings.Contains(string(output), "phase6-fd-loader: fd") || strings.Contains(string(output), "fd-fixture: ok") {
			t.Fatalf("%s was not rejected before exec: %v: %.512s", negative.name, err, output)
		}
	}
	termID := create("term", true)
	termCommand := exec.CommandContext(ctx, "docker", "start", "-a", "-i", termID)
	reader, writer := io.Pipe()
	termCommand.Stdin = reader
	var termOutput bytes.Buffer
	termCommand.Stdout, termCommand.Stderr = &termOutput, &termOutput
	if err := termCommand.Start(); err != nil {
		t.Fatal("start attached FD-loader TERM probe")
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		state, inspectErr := run.docker(ctx, "inspect", "--format", "{{.State.Running}}", termID)
		if inspectErr == nil && strings.TrimSpace(string(state)) == "true" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := run.docker(ctx, "stop", "-t", "2", termID); err != nil {
		t.Fatal("FD-loader pre-exec TERM did not stop")
	}
	_ = writer.Close()
	_ = termCommand.Wait()
	if strings.Contains(termOutput.String(), "fd-fixture: ok") {
		t.Fatal("TERM probe started the role despite startup cancellation")
	}
	termState, err := run.docker(ctx, "inspect", "--format", "{{.State.Running}}|{{.RestartCount}}", termID)
	if err != nil || strings.TrimSpace(string(termState)) != "false|0" {
		t.Fatal("FD-loader TERM probe left a running or automatically restarted container")
	}
	timeoutID := create("timeout", true)
	timeoutCommand := exec.CommandContext(ctx, "docker", "start", "-a", "-i", timeoutID)
	timeoutReader, timeoutWriter := io.Pipe()
	timeoutCommand.Stdin = timeoutReader
	var timeoutOutput bytes.Buffer
	timeoutCommand.Stdout, timeoutCommand.Stderr = &timeoutOutput, &timeoutOutput
	if err := timeoutCommand.Start(); err != nil {
		t.Fatal("start attached FD-loader held-open input probe")
	}
	defer timeoutWriter.Close()
	started := time.Now()
	running := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		state, inspectErr := run.docker(ctx, "inspect", "--format", "{{.State.Running}}", timeoutID)
		if inspectErr == nil && strings.TrimSpace(string(state)) == "true" {
			running = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !running {
		_ = timeoutWriter.Close()
		_ = timeoutCommand.Wait()
		t.Fatal("FD-loader held-open input probe never entered the running state")
	}
	exited := false
	for deadline := started.Add(38 * time.Second); time.Now().Before(deadline); {
		state, inspectErr := run.docker(ctx, "inspect", "--format", "{{.State.Running}}|{{.RestartCount}}", timeoutID)
		if inspectErr == nil && strings.TrimSpace(string(state)) == "false|0" {
			exited = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !exited {
		_, _ = run.docker(ctx, "stop", "-t", "2", timeoutID)
		_ = timeoutWriter.Close()
		_ = timeoutCommand.Wait()
		t.Fatal("FD-loader remained live past the 30-second startup deadline")
	}
	if elapsed := time.Since(started); elapsed < 25*time.Second || elapsed > 38*time.Second {
		t.Fatalf("FD-loader startup deadline elapsed outside bounded window: %v", elapsed)
	}
	if err := timeoutWriter.Close(); err != nil {
		t.Fatal("close held-open Docker input after container exit")
	}
	timeoutResult := make(chan error, 1)
	go func() { timeoutResult <- timeoutCommand.Wait() }()
	select {
	case err := <-timeoutResult:
		if err == nil || !strings.Contains(timeoutOutput.String(), "phase6-fd-loader: input") ||
			strings.Contains(timeoutOutput.String(), "fd-fixture: ok") {
			t.Fatalf("held-open startup input was not rejected: %v: %.512s", err, timeoutOutput.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Docker attach did not finish after closing the test input")
	}
	timeoutState, err := run.docker(ctx, "inspect", "--format", "{{.State.Running}}|{{.RestartCount}}", timeoutID)
	if err != nil || strings.TrimSpace(string(timeoutState)) != "false|0" {
		t.Fatal("FD-loader timeout left a running or automatically restarted container")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("exact FD-loader Docker cleanup: %v", err)
	}
	t.Log("restricted Docker fixture confirmed PID1 exec, 0600 sealed seekable FD0/FD3..6, stale/truncated, reservation/environment and exec-failure denials, pre-exec TERM and held-open-input timeout with exact cleanup; real controller launch remains open")
}
