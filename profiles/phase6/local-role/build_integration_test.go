//go:build integration

package localrole

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This is a source-bound local-image/real-command smoke, not a complete
// Slice 6 role inventory or a release-artifact qualification.
func TestLocalCoreCandidateRunsAsHighUID(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_LOCAL_ROLE_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_LOCAL_ROLE_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	architecture, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Arch}}").Output()
	platform := "linux/arm64/v8"
	wantArchitecture := "arm64"
	if strings.TrimSpace(string(architecture)) == "amd64" {
		platform, wantArchitecture = "linux/amd64", "amd64"
	} else if err != nil || strings.TrimSpace(string(architecture)) != "arm64" {
		t.Fatalf("unsupported Docker architecture: %q, %v", architecture, err)
	}
	output, err := exec.CommandContext(ctx, "./build.sh", platform, "core").CombinedOutput()
	if err != nil {
		t.Fatalf("build source-bound local role candidate: %v: %.2048s", err, output)
	}
	image, source := "", ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "image=sha256:") {
			image = strings.TrimPrefix(line, "image=")
		}
		if strings.HasPrefix(line, "source=") {
			source = strings.TrimPrefix(line, "source=")
		}
	}
	if len(image) != 71 || len(source) != 40 {
		t.Fatalf("candidate builder omitted immutable image digest: %.512s", output)
	}
	inspect, err := exec.CommandContext(ctx, "docker", "image", "inspect", image).Output()
	var images []struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Config       struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err != nil || json.Unmarshal(inspect, &images) != nil || len(images) != 1 ||
		images[0].ID != image || images[0].OS != "linux" || images[0].Architecture != wantArchitecture ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.phase6-candidate"] != "local-only-non-release" ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.source-revision"] != source ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.role-target"] != "core" {
		t.Fatal("local role candidate image identity or labels drifted")
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	container := "sr-p6-role-core-" + hex.EncodeToString(random)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanup, "docker", "rm", "-f", container).Run()
		if err := exec.CommandContext(cleanup, "docker", "inspect", container).Run(); err == nil {
			t.Errorf("test-owned local role container %s remains", container)
		}
	})
	args := []string{"run", "--rm", "--pull=never", "--name", container,
		"--network", "none", "--read-only", "--user", "21001:31001",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "32", "--memory", "128m", image, "--help"}
	output, err = exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "sandbox-runtime") {
		t.Fatalf("real high-UID role command failed: %v: %.1024s", err, output)
	}
}
