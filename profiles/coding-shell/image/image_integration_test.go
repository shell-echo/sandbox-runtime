//go:build integration

package image

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const imageIntegrationEnv = "SANDBOX_RUNTIME_CODING_SHELL_IMAGE_INTEGRATION"

func TestCodingShellImageIntegration(t *testing.T) {
	if os.Getenv(imageIntegrationEnv) != "1" {
		t.Skip("set " + imageIntegrationEnv + "=1 to build and test the coding/shell image")
	}
	manifest, err := Load(ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	platform := integrationPlatform(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	suffix := fmt.Sprintf("%s-%d", runtime.GOARCH, time.Now().UnixNano())
	imageOne := "sandbox-runtime-coding-shell:integration-a-" + suffix
	imageTwo := "sandbox-runtime-coding-shell:integration-b-" + suffix
	containerName := "sandbox-runtime-coding-shell-integration-" + suffix
	mountRoot, err := os.MkdirTemp(".", ".coding-shell-image-integration-")
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{imageOne, imageTwo} {
		run(t, ctx, nil, "./build.sh", platform, image, "integration-test")
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", containerName).Run()
		_ = exec.CommandContext(cleanupCtx, "docker", "image", "rm", imageOne, imageTwo).Run()
		_ = os.Chmod(filepath.Join(mountRoot, "inputs"), 0o755)
		_ = os.Chmod(filepath.Join(mountRoot, "inputs", "input.txt"), 0o644)
		_ = os.RemoveAll(mountRoot)
	})

	idOne := strings.TrimSpace(run(t, ctx, nil, "docker", "image", "inspect", "--format", "{{.Id}}", imageOne))
	idTwo := strings.TrimSpace(run(t, ctx, nil, "docker", "image", "inspect", "--format", "{{.Id}}", imageTwo))
	if idOne == "" || idOne != idTwo {
		t.Fatalf("identical locked inputs produced different local image IDs: %q != %q", idOne, idTwo)
	}
	inspectImagePolicy(t, ctx, imageOne, manifest)

	inputs := filepath.Join(mountRoot, "inputs")
	workspace := filepath.Join(mountRoot, "workspace")
	outputs := filepath.Join(mountRoot, "outputs")
	for _, path := range []string{inputs, workspace, outputs} {
		if err := os.Mkdir(path, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(inputs, "input.txt"), []byte("locked-input\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inputs, 0o555); err != nil {
		t.Fatal(err)
	}

	run(t, ctx, nil, "docker", "run", "-d", "--name", containerName,
		"--label", "io.github.shell-echo.sandbox-runtime.managed=true",
		"--label", "io.github.shell-echo.sandbox-runtime.namespace=coding-shell-image-integration",
		"--platform", platform,
		"--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--network", "none", "--memory", "128m", "--cpus", "0.25", "--pids-limit", "64",
		"--mount", "type=bind,src="+inputs+",dst=/inputs,readonly",
		"--mount", "type=bind,src="+workspace+",dst=/workspace",
		"--mount", "type=bind,src="+outputs+",dst=/outputs",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
		imageOne)

	run(t, ctx, nil, "docker", "exec", containerName, "/bin/sh", "-c",
		"set -eu; test \"$(id -u):$(id -g)\" = 65532:65532; test \"$(cat /inputs/input.txt)\" = locked-input; test ! -w /inputs/input.txt; printf artifact-ok > /outputs/artifact.txt; printf workspace-ok > /workspace/workspace.txt; sleep 0")
	artifact, err := os.ReadFile(filepath.Join(outputs, "artifact.txt"))
	if err != nil || string(artifact) != "artifact-ok" {
		t.Fatalf("artifact mount result = %q, %v", artifact, err)
	}

	brokerCommand := "set -eu; broker='" + TerminalBrokerPath + "'; socket=/tmp/sandbox-runtime-terminal-0123456789abcdef0123456789abcdef.sock; " +
		"\"$broker\" serve --socket \"$socket\" --shell /bin/sh --working-directory /workspace >/tmp/broker.log 2>&1 & pid=$!; " +
		"ready=0; for attempt in 1 2 3 4 5 6 7 8 9 10; do if \"$broker\" probe --socket \"$socket\" >/dev/null 2>&1; then ready=1; break; fi; sleep 1; done; " +
		"test \"$ready\" = 1; (printf '%s\\n' 'printf BROKER-OK' 'sleep 1' 'exit'; sleep 3) | \"$broker\" connect --socket \"$socket\"; wait \"$pid\""
	brokerOutput := run(t, ctx, nil, "docker", "exec", containerName, "/bin/sh", "-c", brokerCommand)
	if !strings.Contains(brokerOutput, "BROKER-OK") {
		t.Fatalf("terminal broker did not complete a PTY shell round trip: %q", brokerOutput)
	}

	networkMode := strings.TrimSpace(run(t, ctx, nil, "docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", containerName))
	if networkMode != "none" {
		t.Fatalf("container network mode = %q, want none", networkMode)
	}
}

func integrationPlatform(t *testing.T) string {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return "linux/amd64"
	case "arm64":
		return "linux/arm64/v8"
	default:
		t.Fatalf("unsupported integration host architecture %q", runtime.GOARCH)
		return ""
	}
}

func inspectImagePolicy(t *testing.T, ctx context.Context, imageRef string, manifest Manifest) {
	t.Helper()
	output := run(t, ctx, nil, "docker", "image", "inspect", imageRef)
	var inspected []struct {
		Config struct {
			User       string            `json:"User"`
			WorkingDir string            `json:"WorkingDir"`
			Cmd        []string          `json:"Cmd"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal([]byte(output), &inspected); err != nil || len(inspected) != 1 {
		t.Fatalf("decode image inspection: %v", err)
	}
	config := inspected[0].Config
	if config.User != "65532:65532" || config.WorkingDir != "/workspace" || strings.Join(config.Cmd, "\x00") != strings.Join(manifest.Runtime.Command, "\x00") {
		t.Fatalf("unsafe image process identity: user=%q workdir=%q command=%v", config.User, config.WorkingDir, config.Cmd)
	}
	if config.Labels["io.github.shell-echo.sandbox-runtime.profile"] != ProfileID || config.Labels["io.github.shell-echo.sandbox-runtime.terminal-broker-path"] != TerminalBrokerPath {
		t.Fatalf("image labels do not match manifest: %v", config.Labels)
	}
}

func run(t *testing.T, ctx context.Context, stdin *strings.Reader, name string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		command.Stdin = stdin
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}
