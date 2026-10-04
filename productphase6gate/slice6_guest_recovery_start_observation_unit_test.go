//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSlice6GuestRecoveryStartInspectOnlyExactCreatedIsPending(t *testing.T) {
	run := slice6DockerRun{id: strings.Repeat("a", 32)}
	capture := &slice6GuestRecoveryCapture{id: strings.Repeat("b", 64),
		image: "sha256:" + strings.Repeat("c", 64), imageRef: "pinned-image"}
	created := []string{capture.id, capture.image, capture.imageRef, run.id,
		"none", "false", "created", "false", "0", "0001-01-01T00:00:00Z", "false", "0", "false"}
	pending, pid, started, err := slice6ClassifyGuestRecoveryStartInspect(created, capture, run)
	if err != nil || !pending || pid != 0 || started != "" {
		t.Fatal("exact created/pid0 was not pending")
	}
	running := append([]string(nil), created...)
	running[6], running[7], running[8], running[9] = "running", "true", "123", "2026-10-05T00:00:00Z"
	pending, pid, started, err = slice6ClassifyGuestRecoveryStartInspect(running, capture, run)
	if err != nil || pending || pid != 123 || started != running[9] {
		t.Fatal("exact running PID1 identity was not observed")
	}
	for _, test := range []struct {
		name, value string
		index       int
	}{
		{"container", strings.Repeat("d", 64), 0},
		{"image", "sha256:" + strings.Repeat("d", 64), 1},
		{"image-ref", "other-image", 2},
		{"run-label", strings.Repeat("d", 32), 3},
		{"log-driver", "json-file", 4},
		{"tty", "true", 5},
		{"exited", "exited", 6},
		{"unexpected-running", "true", 7},
		{"unexpected-pid", "12", 8},
		{"unexpected-start", "2026-10-05T00:00:00Z", 9},
		{"oom", "true", 10},
		{"exit-code", "1", 11},
		{"state-error", "true", 12},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := append([]string(nil), created...)
			fields[test.index] = test.value
			if _, _, _, err := slice6ClassifyGuestRecoveryStartInspect(fields, capture, run); err == nil {
				t.Fatal("hard identity or state drift was treated as pending")
			}
		})
	}
	if _, _, _, err := slice6ClassifyGuestRecoveryStartInspect(created[:12], capture, run); err == nil {
		t.Fatal("truncated inspect was treated as pending")
	}
}

func TestSlice6GuestRecoveryStartWaitIsBoundedAndDoesNotRetryHardFailure(t *testing.T) {
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	attempts := 0
	err := slice6AwaitGuestRecoveryRunningProbe(ctx, done, func() (bool, error) {
		attempts++
		return attempts < 3, nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("same-start created-to-running observation failed: attempts=%d err=%v", attempts, err)
	}
	attempts = 0
	err = slice6AwaitGuestRecoveryRunningProbe(ctx, done, func() (bool, error) {
		attempts++
		return false, errors.New("private inspect detail")
	})
	if err == nil || attempts != 1 || strings.Contains(err.Error(), "private inspect detail") {
		t.Fatal("hard inspect failure was retried or raw detail escaped")
	}
	closed := make(chan struct{})
	close(closed)
	attempts = 0
	if slice6AwaitGuestRecoveryRunningProbe(ctx, closed, func() (bool, error) {
		attempts++
		return true, nil
	}) == nil || attempts != 0 {
		t.Fatal("completed docker start collector admitted a pending probe")
	}
	short, stop := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer stop()
	if slice6AwaitGuestRecoveryRunningProbe(short, done, func() (bool, error) {
		return true, nil
	}) == nil {
		t.Fatal("permanent pending escaped the original startup deadline")
	}
	cancelled, cancelNow := context.WithCancel(t.Context())
	if slice6AwaitGuestRecoveryRunningProbe(cancelled, done, func() (bool, error) {
		cancelNow()
		return true, nil
	}) == nil {
		t.Fatal("cancelled startup remained pending")
	}
	cancelledAfterInspect, cancelAfterInspect := context.WithCancel(t.Context())
	if slice6AwaitGuestRecoveryRunningProbe(cancelledAfterInspect, done, func() (bool, error) {
		cancelAfterInspect()
		return false, nil
	}) == nil {
		t.Fatal("running observation committed after cancellation")
	}
}
