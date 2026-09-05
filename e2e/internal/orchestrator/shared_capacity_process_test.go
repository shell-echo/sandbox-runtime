package orchestrator

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
)

func TestSharedCallerRequestTimeoutTerminatesAmbiguousPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell executable")
	}
	root := t.TempDir()
	fixture := filepath.Join(root, "blocking-caller")
	if err := os.WriteFile(fixture, []byte("#!/bin/sh\nwhile IFS= read -r line; do while :; do :; done; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	process, err := startSharedCaller(fixture, filepath.Join(root, "ignored.json"), filepath.Join(root, "caller.log"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = process.request(ctx, wire.Command{Action: wire.ActionShutdown})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request error = %v, want deadline exceeded", err)
	}
	select {
	case <-process.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed-out caller process was not terminated")
	}
	if _, err := process.request(context.Background(), wire.Command{Action: wire.ActionShutdown}); err == nil {
		t.Fatal("terminated caller process accepted another request")
	}
}

func TestWaitForSharedGatewayStoppedObservesProcessState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses POSIX process signals and ps")
	}
	command := exec.Command("sleep", "30")
	child := &childProcess{command: command, done: make(chan struct{})}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := command.Wait()
		child.mu.Lock()
		child.err = err
		child.mu.Unlock()
		close(child.done)
	}()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGCONT)
		_ = command.Process.Kill()
		select {
		case <-child.done:
		case <-time.After(2 * time.Second):
			t.Error("fixture process did not exit")
		}
	})

	if err := signalSharedGateway(child, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForSharedGatewayStopped(ctx, child, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := signalSharedGateway(child, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
}
