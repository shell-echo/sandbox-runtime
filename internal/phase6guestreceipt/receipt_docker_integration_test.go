//go:build integration

package phase6guestreceipt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dockerProbeImage = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"

func TestDockerNonTTYReceiptWriterAndBlockedAttach(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_GUEST_RECEIPT_DOCKER") != "1" {
		t.Skip("explicit disposable Docker receipt probe required")
	}
	root, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	privateRoot := filepath.Join(root, ".codex")
	if info, err := os.Stat(privateRoot); err != nil || !info.IsDir() {
		t.Fatal("private Docker-mountable probe root unavailable")
	}
	directory, err := os.MkdirTemp(privateRoot, "phase6-guest-receipt-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	binary := filepath.Join(directory, "receiptprobe")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./testdata/receiptprobe")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Linux arm64 receipt probe build failed: %v, %s", err, output)
	}
	statusDirectory := filepath.Join(directory, "status")
	if err := os.Mkdir(statusDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	// Only the disposable stress probe can write this non-secret completion
	// marker. It is not mounted into Product/Guest runtime candidates.
	if err := os.Chmod(statusDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	create := func(full bool) string {
		t.Helper()
		var random [5]byte
		if _, err := rand.Read(random[:]); err != nil {
			t.Fatal(err)
		}
		name := "sr-p6-guest-receipt-" + hex.EncodeToString(random[:])
		args := []string{"create", "--pull=never", "--platform=linux/arm64/v8", "--name", name,
			"--label", "io.github.shell-echo.sandbox-runtime.phase6-guest-receipt-probe=" + name,
			"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
			"--user=65532:65532", "--log-driver=none", "--mount", "type=bind,src=" + binary + ",dst=/receiptprobe,readonly",
			"--entrypoint=/receiptprobe"}
		if full {
			args = append(args, "--env", "PHASE6_RECEIPT_PROBE_FULL=1", "--mount",
				"type=bind,src="+statusDirectory+",dst=/status")
		}
		args = append(args, dockerProbeImage)
		command := exec.CommandContext(t.Context(), "docker", args...)
		output, err := command.Output()
		id := strings.TrimSpace(string(output))
		if err != nil || len(id) != 64 {
			t.Fatal("exact disposable receipt container could not be created")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = exec.CommandContext(ctx, "docker", "rm", "-f", id).Run()
		})
		return id
	}
	healthy := create(false)
	healthyCommand := exec.CommandContext(t.Context(), "docker", "start", "-a", healthy)
	document, err := healthyCommand.Output()
	if err != nil {
		t.Fatal("attached non-TTY receipt probe did not finish cleanly")
	}
	if records, err := Verify(document, "guest", testDigest, testDigest); err != nil || len(records) != 18 {
		t.Fatalf("actual Docker stdout receipt was not complete: records=%d err=%v", len(records), err)
	}

	blocked := create(true)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	attached := exec.CommandContext(ctx, "docker", "start", "-a", blocked)
	stdout, err := attached.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	attached.Stderr = &stderr
	if err := attached.Start(); err != nil {
		t.Fatal(err)
	}
	// Intentionally do not read the attached stdout pipe. This forces actual
	// Docker CLI backpressure, unlike closing the attach, which the daemon may
	// continue draining. The container must terminate its own bounded writer.
	status := ""
	for ctx.Err() == nil {
		if contents, err := os.ReadFile(filepath.Join(statusDirectory, "terminal")); err == nil {
			status = strings.TrimSpace(string(contents))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = stdout.Close()
	_ = attached.Wait()
	postContext, postCancel := context.WithTimeout(context.Background(), 2*time.Second)
	postOutput, _ := exec.CommandContext(postContext, "docker", "inspect", blocked,
		"--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}").Output()
	postCancel()
	postFields := strings.Fields(string(postOutput))
	containerExit := "unavailable"
	if len(postFields) == 3 && postFields[0] == "exited" && postFields[2] == "false" {
		switch postFields[1] {
		case "0":
			containerExit = "sealed_without_sustained_backpressure"
		case "2":
			containerExit = "writer_startup_rejected"
		case "3":
			containerExit = "writer_joined_invalid"
		case "4":
			containerExit = "backpressure_not_established"
		default:
			containerExit = "unexpected_exit"
		}
	} else if len(postFields) == 3 && postFields[2] == "true" {
		containerExit = "oom"
	} else if len(postFields) == 3 && postFields[0] == "running" {
		containerExit = "still_running"
	}
	if status != "writer_joined_invalid" || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		containerExit != "writer_joined_invalid" {
		t.Fatalf("actual Docker unread attach did not prove bounded writer: marker=%q deadline=%v container=%q stderr=%q",
			status, ctx.Err(), containerExit, strings.TrimSpace(stderr.String()))
	}
}
