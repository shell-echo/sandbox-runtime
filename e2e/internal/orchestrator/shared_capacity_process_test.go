package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
