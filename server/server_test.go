package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeServer is a controllable Server for exercising RunE. A non-nil startErr
// makes Startup fail immediately; otherwise Startup blocks until Shutdown.
type fakeServer struct {
	startErr        error
	stopImmediately bool
	down            chan struct{}
	downOnce        sync.Once
	onShutdown      func()
}

func newFakeServer(startErr error) *fakeServer {
	return &fakeServer{startErr: startErr, down: make(chan struct{})}
}

func (f *fakeServer) Startup(ctx context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	if f.stopImmediately {
		return nil
	}
	select {
	case <-f.down:
		return nil
	case <-ctx.Done():
		return nil
	}
}

func (f *fakeServer) Shutdown(context.Context) error {
	if f.onShutdown != nil {
		f.onShutdown()
	}
	f.downOnce.Do(func() { close(f.down) })
	return nil
}

// TestRunEEmpty confirms RunE errors when no servers are given.
func TestRunEEmpty(t *testing.T) {
	if err := RunE(map[string]Server{}); err == nil {
		t.Error("expected error for empty server set")
	}
}

func TestRunERejectsNilServer(t *testing.T) {
	if err := RunE(map[string]Server{"provider": nil}); err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("RunE() error = %v", err)
	}
	var typedNil *fakeServer
	if err := RunE(map[string]Server{"provider": typedNil}); err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("RunE() typed-nil error = %v", err)
	}
}

// TestRunEStartupFailureShutsDownOthers confirms that when one server fails to
// start, RunE shuts the others down and returns the startup error.
func TestRunEStartupFailureShutsDownOthers(t *testing.T) {
	bad := newFakeServer(errors.New("boom"))

	good := newFakeServer(nil)
	var goodShutDown bool
	good.onShutdown = func() { goodShutDown = true }

	err := RunE(map[string]Server{"bad": bad, "good": good})
	if err == nil {
		t.Fatal("expected error from failed startup")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error %v should mention the startup failure", err)
	}
	if !goodShutDown {
		t.Error("the healthy server was not shut down after the failure")
	}
}

func TestRunEUnexpectedCleanStopShutsDownOthers(t *testing.T) {
	stopped := newFakeServer(nil)
	stopped.stopImmediately = true

	other := newFakeServer(nil)
	var otherShutDown bool
	other.onShutdown = func() { otherShutDown = true }

	err := RunE(map[string]Server{"provider": stopped, "api": other})
	if err == nil || !strings.Contains(err.Error(), "provider startup: stopped unexpectedly") {
		t.Fatalf("RunE() error = %v", err)
	}
	if !otherShutDown {
		t.Fatal("the sibling server was not shut down after an unexpected clean stop")
	}
}

func TestRunECancelsServerWhoseStartupHasNotBound(t *testing.T) {
	failing := newFakeServer(errors.New("bind failed"))
	delayed := &delayedServer{entered: make(chan struct{}), returned: make(chan struct{})}

	err := RunE(map[string]Server{"provider": failing, "api": delayed})
	if err == nil || !strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("RunE() error = %v", err)
	}
	select {
	case <-delayed.returned:
	default:
		t.Fatal("startup cancellation did not release the delayed server")
	}
}

func TestRunEIgnoresCoordinatedStartupCancellation(t *testing.T) {
	failing := newFakeServer(errors.New("bind failed"))
	cancellable := contextErrorServer{}

	err := RunE(map[string]Server{"provider": failing, "api": cancellable})
	if err == nil || !strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("RunE() error = %v", err)
	}
	if strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("RunE() included coordinated cancellation: %v", err)
	}
}

type delayedServer struct {
	entered  chan struct{}
	returned chan struct{}
}

func (s *delayedServer) Startup(ctx context.Context) error {
	close(s.entered)
	<-ctx.Done()
	close(s.returned)
	return nil
}

func (*delayedServer) Shutdown(context.Context) error { return nil }

type contextErrorServer struct{}

func (contextErrorServer) Startup(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (contextErrorServer) Shutdown(context.Context) error { return nil }
