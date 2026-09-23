//go:build integration

package egresspolicystate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This proves the Unix authority boundary with real distinct-UID containers.
// The fixture is not the production egress broker or the full Slice 6 gate.
func TestDockerDistinctUIDPolicyAuthorityAndRevocation(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_POLICY_AUTHORITY_DOCKER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_POLICY_AUTHORITY_DOCKER=1")
	}
	const image = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	architecture, err := dockerPolicy(ctx, "version", "--format", "{{.Server.Arch}}")
	if err != nil || (architecture != "arm64" && architecture != "amd64") {
		t.Fatalf("unsupported Docker architecture %q: %v", architecture, err)
	}
	if _, err := dockerPolicy(ctx, "image", "inspect", image); err != nil {
		t.Fatalf("pinned probe image unavailable: %v", err)
	}
	temporaryRoot, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	buildDirectory, err := os.MkdirTemp(temporaryRoot, "p6-policy-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(buildDirectory) })
	binary := filepath.Join(buildDirectory, "policy-processprobe")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./testdata/processprobe")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+architecture, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux policy fixture: %v: %.2048s", err, output)
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	volume, container := "p6-authority-volume-"+suffix, "p6-authority-"+suffix
	volumeCreated, containerCreated := false, false
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if containerCreated {
			_, _ = dockerPolicy(cleanupCtx, "rm", "-f", container)
			if _, err := dockerPolicy(cleanupCtx, "inspect", container); err == nil {
				t.Errorf("authority fixture container remained after cleanup")
			}
		}
		if volumeCreated {
			if _, err := dockerPolicy(cleanupCtx, "volume", "rm", volume); err != nil {
				t.Errorf("remove exact policy volume: %v", err)
			}
			if _, err := dockerPolicy(cleanupCtx, "volume", "inspect", volume); err == nil {
				t.Errorf("authority fixture volume remained after cleanup")
			}
		}
	})
	if _, err := dockerPolicy(ctx, "volume", "create", volume); err != nil {
		t.Fatal(err)
	}
	volumeCreated = true
	setup := "mkdir -p /state/ledger /state/socket && chown 20001:30001 /state/ledger && chmod 0700 /state/ledger && chown 20001:30000 /state/socket && chmod 0710 /state/socket"
	if _, err := dockerPolicy(ctx, "run", "--rm", "--network", "none", "-v", volume+":/state", image, "sh", "-c", setup); err != nil {
		t.Fatal(err)
	}
	binaryFile, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	copyCommand := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--network", "none", "-v", volume+":/state",
		image, "sh", "-c", "cat > /state/probe && chmod 0755 /state/probe")
	copyCommand.Stdin = binaryFile
	copyOutput, copyErr := copyCommand.CombinedOutput()
	_ = binaryFile.Close()
	if copyErr != nil {
		t.Fatalf("copy fixture binary into exact managed volume: %v: %.2048s", copyErr, copyOutput)
	}
	volumeMount := "type=volume,src=" + volume + ",dst=/state"
	if _, err := dockerPolicy(ctx, "run", "--rm", "--network", "none", "--user", "20001:30001", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", volumeMount,
		image, "/state/probe", "initialize"); err != nil {
		t.Fatal(err)
	}
	startAuthority := func() {
		t.Helper()
		if _, err := dockerPolicy(ctx, "run", "-d", "--name", container, "--network", "none", "--user", "20001:30001",
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", volumeMount,
			image, "/state/probe", "authority"); err != nil {
			t.Fatal(err)
		}
		containerCreated = true
	}
	client := func() (string, error) {
		return dockerPolicy(ctx, "run", "--rm", "--network", "none", "--user", "20002:30000", "--read-only",
			"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", volumeMount+",readonly",
			image, "/state/probe", "client")
	}
	awaitStatus := func(expected string) {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			status, err := client()
			if err == nil && status == expected {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		status, err := client()
		t.Fatalf("policy state %q not observed; last=%q err=%v", expected, status, err)
	}
	startAuthority()
	awaitStatus("active")
	if _, err := dockerPolicy(ctx, "run", "--rm", "--network", "none", "--user", "20002:30000", "--read-only",
		"--cap-drop", "ALL", "--mount", volumeMount+",readonly", image, "sh", "-c",
		"test ! -r /state/ledger/ledger.json && test ! -r /state/ledger/current.json"); err != nil {
		t.Fatalf("broker-side UID could read authority-private ledger: %v", err)
	}
	if _, err := dockerPolicy(ctx, "run", "--rm", "--network", "none", "--user", "20003:30000", "--read-only",
		"--cap-drop", "ALL", "--mount", volumeMount+",readonly", image, "/state/probe", "client"); err == nil {
		t.Fatal("same-group wrong UID queried authority")
	}
	if _, err := dockerPolicy(ctx, "kill", "--signal=KILL", container); err != nil {
		t.Fatal(err)
	}
	if status, err := client(); err == nil || status == "active" {
		t.Fatalf("crashed authority accepted by broker-side client: status=%q err=%v", status, err)
	}
	if _, err := dockerPolicy(ctx, "rm", container); err != nil {
		t.Fatal(err)
	}
	containerCreated = false
	startAuthority()
	awaitStatus("active") // safe stale-socket recovery after abrupt death
	// Preserve the old audit snapshot, then commit revocation. It is never a
	// broker authority even if an operator later restores it.
	copyOld := "cp /state/ledger/current.json /state/ledger/old.json && chown 20001:30001 /state/ledger/old.json && chmod 0600 /state/ledger/old.json"
	if _, err := dockerPolicy(ctx, "run", "--rm", "--network", "none", "-v", volume+":/state", image, "sh", "-c", copyOld); err != nil {
		t.Fatal(err)
	}
	if _, err := dockerPolicy(ctx, "kill", "--signal=USR1", container); err != nil {
		t.Fatal(err)
	}
	awaitStatus("revoked")
	if _, err := dockerPolicy(ctx, "stop", "-t", "2", container); err != nil {
		t.Fatal(err)
	}
	if _, err := dockerPolicy(ctx, "rm", container); err != nil {
		t.Fatal(err)
	}
	containerCreated = false
	restoreOld := "cp /state/ledger/old.json /state/ledger/current.json && chown 20001:30001 /state/ledger/current.json && chmod 0600 /state/ledger/current.json"
	if _, err := dockerPolicy(ctx, "run", "--rm", "--network", "none", "-v", volume+":/state", image, "sh", "-c", restoreOld); err != nil {
		t.Fatal(err)
	}
	startAuthority()
	awaitStatus("revoked")
	if _, err := dockerPolicy(ctx, "stop", "-t", "2", container); err != nil {
		t.Fatal(err)
	}
	if status, err := client(); err == nil || status == "active" {
		t.Fatalf("unavailable authority accepted by broker-side client: status=%q err=%v", status, err)
	}
	if _, err := dockerPolicy(ctx, "rm", container); err != nil {
		t.Fatal(err)
	}
	containerCreated = false
	t.Log("distinct-UID Docker authority: active, crash/restart with stale socket, signed revoked, revoked restart despite old audit snapshot, outage denial, exact cleanup")
}

func dockerPolicy(ctx context.Context, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if len(output) > 4096 {
		output = output[:4096]
	}
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(arguments[:min(len(arguments), 2)], " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}
