package server

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeServer is a controllable Server for exercising RunE. A non-nil startErr
// makes Startup fail immediately; otherwise Startup blocks until Shutdown.
type fakeServer struct {
	startErr   error
	down       chan struct{}
	onShutdown func()
}

func newFakeServer(startErr error) *fakeServer {
	return &fakeServer{startErr: startErr, down: make(chan struct{})}
}

func (f *fakeServer) Startup() error {
	if f.startErr != nil {
		return f.startErr
	}
	<-f.down
	return nil
}

func (f *fakeServer) Shutdown(context.Context) error {
	if f.onShutdown != nil {
		f.onShutdown()
	}
	close(f.down)
	return nil
}

// TestRunEEmpty confirms RunE errors when no servers are given.
func TestRunEEmpty(t *testing.T) {
	if err := RunE(map[string]Server{}); err == nil {
		t.Error("expected error for empty server set")
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
