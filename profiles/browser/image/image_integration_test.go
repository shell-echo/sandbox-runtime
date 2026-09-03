//go:build integration

package image

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const browserImageIntegrationEnv = "SANDBOX_RUNTIME_BROWSER_IMAGE_INTEGRATION"

func TestBrowserImageSandboxIntegration(t *testing.T) {
	if os.Getenv(browserImageIntegrationEnv) != "1" {
		t.Skip("set " + browserImageIntegrationEnv + "=1 to build and test the browser image")
	}
	manifest, err := Load(ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	seccompPath, err := filepath.Abs("chromium-seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySeccompProfile(seccompPath, manifest.Security.SeccompProfile.Digest); err != nil {
		t.Fatal(err)
	}
	platform, sourceDigest := integrationPlatform(t, manifest)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	suffix := fmt.Sprintf("%s-%d", runtime.GOARCH, time.Now().UnixNano())
	imageRef := "sandbox-runtime-browser:integration-" + suffix
	containerName := "sandbox-runtime-browser-integration-" + suffix
	runDocker(t, ctx, nil, "build", "--no-cache", "--provenance=false", "--platform", platform,
		"--build-arg", "BASE_IMAGE_DIGEST="+sourceDigest,
		"--build-arg", "SOURCE_DATE_EPOCH=0",
		"--build-arg", "VCS_REF=integration-test",
		"--tag", imageRef, ".")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", containerName).Run()
		_ = exec.CommandContext(cleanupCtx, "docker", "image", "rm", imageRef).Run()
	})

	inspectImagePolicy(t, ctx, imageRef, manifest)
	runDocker(t, ctx, nil, "run", "-d", "--name", containerName,
		"--label", "io.github.shell-echo.sandbox-runtime.managed=true",
		"--label", "io.github.shell-echo.sandbox-runtime.namespace=browser-image-integration",
		"--platform", platform,
		"--user", fmt.Sprintf("%d:%d", manifest.Security.UID, manifest.Security.GID),
		"--read-only", "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp="+seccompPath,
		"--network", "none", "--memory", "1g", "--cpus", "1", "--pids-limit", "256",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
		"--tmpfs", "/workspace:rw,noexec,nosuid,size=1g",
		imageRef)

	waitForDevTools(t, ctx, containerName)
	response := runDocker(t, ctx, nil, "exec", containerName, "/usr/bin/bash", "-c",
		"exec 3<>/dev/tcp/127.0.0.1/9222; printf 'GET /json/version HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3; /usr/bin/timeout 5 cat <&3; status=$?; [ \"$status\" -eq 0 ] || [ \"$status\" -eq 124 ]")
	wantCDPVersion := `"Browser": "Chrome/` + strings.TrimPrefix(manifest.Browser.Version, "Chromium ") + `"`
	if !strings.Contains(response, "HTTP/1.1 200") || !strings.Contains(response, wantCDPVersion) {
		t.Fatalf("unexpected private CDP response: %s", response)
	}
	processes := runDocker(t, ctx, nil, "top", containerName, "-eo", "pid,ppid,user,args")
	if strings.Contains(processes, "--no-sandbox") || !strings.Contains(processes, "--type=zygote --headless") {
		t.Fatalf("browser sandbox process tree is invalid:\n%s", processes)
	}
}

func integrationPlatform(t *testing.T, manifest Manifest) (string, string) {
	t.Helper()
	platform := os.Getenv("SANDBOX_RUNTIME_BROWSER_PLATFORM")
	if platform == "" {
		switch runtime.GOARCH {
		case "amd64":
			platform = "linux/amd64"
		case "arm64":
			platform = "linux/arm64/v8"
		default:
			t.Fatalf("unsupported integration host architecture %q", runtime.GOARCH)
		}
	}
	source, ok := manifest.Source.Manifests[platform]
	if !ok {
		t.Fatalf("platform %q is not authorized by the browser image manifest", platform)
	}
	return platform, source.Digest
}

func inspectImagePolicy(t *testing.T, ctx context.Context, imageRef string, manifest Manifest) {
	t.Helper()
	output := runDocker(t, ctx, nil, "image", "inspect", imageRef)
	var inspected []struct {
		Config struct {
			User       string            `json:"User"`
			Entrypoint []string          `json:"Entrypoint"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal([]byte(output), &inspected); err != nil || len(inspected) != 1 {
		t.Fatalf("decode image inspection: %v", err)
	}
	config := inspected[0].Config
	if config.User != fmt.Sprintf("%d:%d", manifest.Security.UID, manifest.Security.GID) || strings.Join(config.Entrypoint, "\x00") != "/usr/local/bin/browser-runtime" {
		t.Fatalf("image identity is unsafe: user=%q entrypoint=%v", config.User, config.Entrypoint)
	}
	if config.Labels["io.github.shell-echo.sandbox-runtime.browser-sandbox"] != "user-namespace" || config.Labels["io.github.shell-echo.sandbox-runtime.seccomp-profile-digest"] != manifest.Security.SeccompProfile.Digest {
		t.Fatalf("image sandbox labels do not match manifest: %v", config.Labels)
	}
}

func waitForDevTools(t *testing.T, ctx context.Context, containerName string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		logs := runDocker(t, ctx, nil, "logs", containerName)
		if strings.Contains(logs, "DevTools listening on ws://127.0.0.1:9222/") {
			return
		}
		state := runDocker(t, ctx, nil, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", containerName)
		if strings.HasPrefix(strings.TrimSpace(state), "exited:") {
			t.Fatalf("browser exited before private CDP became ready: %s\n%s", state, logs)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("private CDP did not become ready: %s", runDocker(t, ctx, nil, "logs", containerName))
}

func runDocker(t *testing.T, ctx context.Context, stdin io.Reader, args ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		command.Stdin = stdin
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
