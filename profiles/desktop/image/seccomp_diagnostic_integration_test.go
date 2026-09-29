//go:build integration

package image

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
)

// This reuses an already loaded non-release Desktop candidate and the exact
// retained Moby source as a diagnostic baseline. It is not an approved
// Desktop duty policy, a final resource tier, or Slice 6 release evidence.
func TestDesktopExplicitSeccompBaselineDiagnostic(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_DESKTOP_SECCOMP_DIAGNOSTIC") != "1" {
		t.Skip("set SANDBOX_RUNTIME_DESKTOP_SECCOMP_DIAGNOSTIC=1")
	}
	image := os.Getenv("SANDBOX_RUNTIME_DESKTOP_SECCOMP_DIAGNOSTIC_IMAGE")
	revision := os.Getenv("SANDBOX_RUNTIME_DESKTOP_SECCOMP_DIAGNOSTIC_SOURCE")
	if !validDiagnosticDigest(image) || len(revision) != 40 || !lowerHexDiagnostic(revision) {
		t.Fatal("an exact retained Desktop candidate digest and source revision are required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	inspect := run(t, ctx, "docker", "image", "inspect", image)
	var loaded []struct {
		ID     string `json:"Id"`
		Config struct {
			User   string            `json:"User"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if json.Unmarshal([]byte(inspect), &loaded) != nil || len(loaded) != 1 || loaded[0].ID != image ||
		loaded[0].Config.User != "1000:1000" ||
		loaded[0].Config.Labels["io.github.shell-echo.sandbox-runtime.candidate-classification"] != "local-candidate-non-release" ||
		loaded[0].Config.Labels["org.opencontainers.image.revision"] != revision {
		t.Fatal("diagnostic image is not the exact retained local candidate")
	}
	policyPath, err := filepath.Abs("../../phase6/security/originals/moby-default-seccomp-836ae4d3.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(policyPath)
	if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(policy)) !=
		"sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74" {
		t.Fatal("pinned Moby diagnostic policy bytes are unavailable")
	}
	mode := os.Getenv("SANDBOX_RUNTIME_DESKTOP_SECCOMP_DIAGNOSTIC_MODE")
	if mode == "" {
		mode = "pinned_moby"
	}
	if mode != "pinned_moby" && mode != "builtin_control" && mode != "implicit_control" {
		t.Fatal("unsupported Desktop seccomp diagnostic mode")
	}
	identity := os.Getenv("SANDBOX_RUNTIME_DESKTOP_SECCOMP_DIAGNOSTIC_IDENTITY")
	if identity == "" {
		identity = "high_uid"
	}
	if identity != "high_uid" && identity != "image_default" {
		t.Fatal("unsupported Desktop seccomp diagnostic identity")
	}
	uid := os.Getenv("SANDBOX_RUNTIME_DESKTOP_SECCOMP_DIAGNOSTIC_UID")
	gid := os.Getenv("SANDBOX_RUNTIME_DESKTOP_SECCOMP_DIAGNOSTIC_GID")
	if identity == "image_default" {
		uid, gid = "1000", "1000"
	} else {
		uidNumber, uidErr := strconv.Atoi(uid)
		gidNumber, gidErr := strconv.Atoi(gid)
		if uidErr != nil || gidErr != nil || uidNumber < 10000 || uidNumber > 60000 || gidNumber < 10000 || gidNumber > 60000 ||
			strconv.Itoa(uidNumber) != uid || strconv.Itoa(gidNumber) != gid {
			t.Fatal("high-UID diagnostic requires canonical finite UID/GID")
		}
		accountCheck := "grep -q '^desktop-slot-" + uid + ":x:" + uid + ":" + gid + ":' /etc/passwd && grep -q '^desktop-slot-" + gid + ":x:" + gid + ":' /etc/group"
		run(t, ctx, "docker", "run", "--rm", "--pull=never", "--network", "none", "--entrypoint", "/bin/sh", image, "-c", accountCheck)
	}
	securityOptions := []string{"--security-opt", "no-new-privileges:true"}
	switch mode {
	case "pinned_moby":
		securityOptions = append(securityOptions, "--security-opt", "seccomp="+policyPath)
	case "builtin_control":
		securityOptions = append(securityOptions, "--security-opt", "seccomp=builtin")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("sandbox-runtime-desktop-seccomp-diagnostic-%d", time.Now().UnixNano())
	removed := false
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if t.Failed() {
			if observation, err := exec.CommandContext(cleanup, "docker", "inspect", "--format", "{{json .State}}", name).CombinedOutput(); err == nil {
				t.Logf("failed Desktop diagnostic Docker state: %s", strings.TrimSpace(string(observation)))
			}
			if state, err := exec.CommandContext(cleanup, "docker", "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", name).CombinedOutput(); err == nil {
				t.Logf("failed Desktop diagnostic state: %s", strings.TrimSpace(string(state)))
			}
			if logs, err := exec.CommandContext(cleanup, "docker", "logs", name).CombinedOutput(); err == nil {
				if len(logs) > 2048 {
					logs = logs[len(logs)-2048:]
				}
				t.Logf("failed Desktop diagnostic log tail: %s", logs)
			}
		}
		if !removed {
			if output, err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput(); err != nil && !desktopDiagnosticAbsent(output, err) {
				t.Errorf("Desktop seccomp diagnostic cleanup failed: %v: %s", err, output)
			}
		}
		if output, err := exec.CommandContext(cleanup, "docker", "container", "inspect", name).CombinedOutput(); !desktopDiagnosticAbsent(output, err) {
			t.Errorf("Desktop seccomp diagnostic container remains: %v: %s", err, output)
		}
	})
	runArgs := []string{"run", "-d", "--pull=never", "--name", name,
		"--label", "io.github.shell-echo.sandbox-runtime.managed=true",
		"--label", "io.github.shell-echo.sandbox-runtime.namespace=desktop-seccomp-diagnostic",
		"--user", uid + ":" + gid,
		"-e", "SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY=" + base64.RawStdEncoding.EncodeToString(publicKey),
		"-e", "SANDBOX_RUNTIME_DESKTOP_BRIDGE_KEY_ID=provider-desktop-v2",
		"-e", desktopbroker.SessionProtocolEnv + "=" + desktopbroker.SessionProtocolV2ID,
		"--platform", nativePlatform(t),
		"--read-only", "--cap-drop=ALL",
	}
	runArgs = append(runArgs, securityOptions...)
	runArgs = append(runArgs,
		"--network", "none", "--ipc", "private", "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777,uid="+uid+",gid="+gid,
		"--tmpfs", "/workspace:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid="+uid+",gid="+gid,
		"--tmpfs", "/outputs:rw,noexec,nosuid,nodev,size=128m,mode=0700,uid="+uid+",gid="+gid, image)
	run(t, ctx, "docker", runArgs...)
	var options []string
	if json.Unmarshal([]byte(run(t, ctx, "docker", "inspect", "--format", "{{json .HostConfig.SecurityOpt}}", name)), &options) != nil ||
		len(options) != len(securityOptions)/2 || options[0] != "no-new-privileges:true" {
		t.Fatal("Desktop explicit seccomp Docker options drifted")
	}
	var wanted, applied bytes.Buffer
	if mode == "pinned_moby" {
		if !strings.HasPrefix(options[1], "seccomp=") || json.Compact(&wanted, policy) != nil || json.Compact(&applied, []byte(strings.TrimPrefix(options[1], "seccomp="))) != nil ||
			!bytes.Equal(wanted.Bytes(), applied.Bytes()) {
			t.Fatal("Docker did not retain the exact normalized diagnostic policy")
		}
	} else if mode == "builtin_control" && options[1] != "seccomp=builtin" {
		t.Fatal("Docker builtin control did not select its own policy")
	}
	status := run(t, ctx, "docker", "exec", name, "/bin/sh", "-c", "cat /proc/1/status")
	if !strings.Contains(status, "Uid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid) ||
		!strings.Contains(status, "Gid:\t"+gid+"\t"+gid+"\t"+gid+"\t"+gid) ||
		!strings.Contains(status, "NoNewPrivs:\t1") || !strings.Contains(status, "Seccomp:\t2") {
		t.Fatalf("Desktop diagnostic process security drifted: %s", status)
	}
	waitForBroker(t, ctx, name)
	runV2Session(t, ctx, name, privateKey)
	if state := strings.TrimSpace(run(t, ctx, "docker", "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", name)); state != "running:0" {
		t.Fatalf("Desktop broker parent did not remain running after session: %s", state)
	}
	logDesktopCgroupV2Sample(t, ctx, name)
	if mode == "pinned_moby" {
		t.Logf("explicit Moby source-byte SHA-256 %s; Docker-inspected compact SHA-256 sha256:%x; %s real media/input passed",
			"536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74", sha256.Sum256(applied.Bytes()), identity)
	} else {
		t.Logf("Docker %s seccomp control passed %s real media/input; builtin bytes are not a pinned duty policy", mode, identity)
	}
	run(t, ctx, "docker", "rm", "-f", name)
	removed = true
}

func validDiagnosticDigest(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && lowerHexDiagnostic(strings.TrimPrefix(value, "sha256:"))
}

func lowerHexDiagnostic(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func desktopDiagnosticAbsent(output []byte, err error) bool {
	return err != nil && (strings.Contains(string(output), "No such object") || strings.Contains(string(output), "No such container"))
}
