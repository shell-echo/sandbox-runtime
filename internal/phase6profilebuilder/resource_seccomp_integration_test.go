//go:build integration

package phase6profilebuilder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This real Docker A/B check isolates one syscall-policy difference. Its
// Alpine host and standalone probe are not a production controller/agent,
// and passing does not admit the Slice 6 deployment topology.
func TestPhase6ControllerAgentSeccompDeltaRealDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SECCOMP_DELTA_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SECCOMP_DELTA_INTEGRATION=1")
	}
	const image = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	if _, err := seccompDeltaDocker(ctx, "image", "inspect", image); err != nil {
		t.Fatalf("pinned arm64 probe image unavailable: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	// Docker Desktop cannot bind its VM to Go's /var/folders test directory.
	// Use one exact private, user-owned path under the already shared home.
	probeDir, err := os.MkdirTemp(filepath.Join(home, ".codex"), "phase6-seccomp-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(probeDir); err != nil {
			t.Errorf("remove exact private seccomp probe directory: %v", err)
		}
		if _, err := os.Lstat(probeDir); !os.IsNotExist(err) {
			t.Errorf("private seccomp probe directory remains or cleanup is unverified: %v", err)
		}
	})
	probe := filepath.Join(probeDir, "seccomp-probe")
	build := exec.CommandContext(ctx, "go", "build", "-o", probe, "./testdata/seccompprobe")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build self-process syscall probe: %v: %.2048s", err, output)
	}
	paths := []struct {
		name, path, digest string
		wantDenied         bool
	}{
		{"original", "../../profiles/phase6/security/originals/moby-default-seccomp-836ae4d3.json",
			"sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74", false},
		{"derived", "../../profiles/phase6/security/go-controller-agent-seccomp-arm64.json",
			"sha256:a7f79239f02d9326e74deb212d2022f4bb2db9e2316367e0d89c9e35f7893eaa", true},
	}
	created := make([]string, 0, len(paths))
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for _, name := range created {
			if _, err := seccompDeltaDocker(cleanup, "rm", "-f", "-v", name); err != nil {
				t.Errorf("exact seccomp probe cleanup %s: %v", name, err)
			}
			if output, err := seccompDeltaDocker(cleanup, "container", "inspect", name); err == nil ||
				!strings.Contains(output, "No such") {
				t.Errorf("seccomp probe container %s remains or cleanup is unverified: %v: %.512s", name, err, output)
			}
		}
	})
	for _, item := range paths {
		policyPath, err := filepath.Abs(item.path)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := os.ReadFile(policyPath)
		if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(policy)) != item.digest {
			t.Fatalf("%s policy source bytes drifted: %v", item.name, err)
		}
		name := fmt.Sprintf("p6-seccomp-delta-%s-%d", item.name, time.Now().UnixNano())
		args := []string{"create", "--pull=never", "--name", name, "--platform", "linux/arm64/v8",
			"--network", "none", "--ipc", "private", "--user", "59001:59011", "--read-only",
			"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
			"--security-opt", "seccomp=" + policyPath, "--pids-limit", "16",
			"--memory", "64m", "--memory-swap", "64m", "--cpus", "0.05",
			"--mount", "type=bind,src=" + probe + ",dst=/probe,readonly", image, "/probe"}
		if output, err := seccompDeltaDocker(ctx, args...); err != nil {
			t.Fatalf("create %s probe: %v: %.1024s", item.name, err, output)
		}
		created = append(created, name)
		optionsJSON, err := seccompDeltaDocker(ctx, "inspect", "--format", "{{json .HostConfig.SecurityOpt}}", name)
		var options []string
		if err != nil || json.Unmarshal([]byte(optionsJSON), &options) != nil || len(options) != 2 ||
			options[0] != "no-new-privileges:true" || !strings.HasPrefix(options[1], "seccomp=") {
			t.Fatalf("%s Docker applied security options drifted: %v: %.1024s", item.name, err, optionsJSON)
		}
		var wanted, applied bytes.Buffer
		if json.Compact(&wanted, policy) != nil ||
			json.Compact(&applied, []byte(strings.TrimPrefix(options[1], "seccomp="))) != nil ||
			!bytes.Equal(wanted.Bytes(), applied.Bytes()) {
			t.Fatalf("%s Docker did not retain exact normalized policy", item.name)
		}
		output, err := seccompDeltaDocker(ctx, "start", "-a", name)
		if err != nil {
			t.Fatalf("%s constrained probe failed: %v: %.1024s", item.name, err, output)
		}
		var result struct {
			UID         string `json:"uid"`
			GID         string `json:"gid"`
			CapEff      string `json:"cap_eff"`
			NoNewPrivs  string `json:"no_new_privs"`
			Seccomp     string `json:"seccomp"`
			ReadCount   int    `json:"read_count"`
			WriteCount  int    `json:"write_count"`
			ReadError   string `json:"read_error"`
			WriteError  string `json:"write_error"`
			PtraceError string `json:"ptrace_error"`
		}
		if json.Unmarshal([]byte(output), &result) != nil ||
			!strings.HasPrefix(result.UID, "59001\t59001\t59001\t59001") ||
			!strings.HasPrefix(result.GID, "59011\t59011\t59011\t59011") ||
			result.CapEff != "0000000000000000" || result.NoNewPrivs != "1" || result.Seccomp != "2" {
			t.Fatalf("%s active identity/capability/seccomp drift: %.1024s", item.name, output)
		}
		if item.wantDenied {
			if result.ReadError != "operation not permitted" || result.WriteError != "operation not permitted" ||
				result.PtraceError != "operation not permitted" ||
				result.ReadCount != -1 || result.WriteCount != -1 {
				t.Fatalf("%s policy did not deny self-process memory operations: %.1024s", item.name, output)
			}
		} else if result.ReadError != "" || result.WriteError != "" || result.PtraceError != "" ||
			result.ReadCount != 6 || result.WriteCount != 6 {
			t.Fatalf("%s baseline control did not allow self-process memory operations: %.1024s", item.name, output)
		}
		state, err := seccompDeltaDocker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", name)
		if err != nil || state != "exited:0" {
			t.Fatalf("%s probe did not exit cleanly: %s: %v", item.name, state, err)
		}
		t.Logf("%s policy %s: observed ptrace/process_vm_readv/writev differential under exact Docker seccomp bytes", item.name, item.digest)
	}
}

func seccompDeltaDocker(ctx context.Context, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(output)), err
}
