package process

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDependencyMonitorClosesAndRecoversReadiness(t *testing.T) {
	var available atomic.Bool
	available.Store(true)
	monitor, err := NewDependencyMonitor(func(context.Context) error {
		if !available.Load() {
			return errors.New("lost")
		}
		return nil
	}, 10*time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewDependencyMonitor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- monitor.Startup(ctx) }()
	waitReady(t, monitor, true)
	available.Store(false)
	waitReady(t, monitor, false)
	available.Store(true)
	waitReady(t, monitor, true)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if monitor.Ready(context.Background()) == nil {
		t.Fatal("monitor remained ready after shutdown")
	}
}

func waitReady(t *testing.T, monitor *DependencyMonitor, want bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ready := monitor.Ready(context.Background()) == nil
		if ready == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("readiness did not become %v", want)
}
