package docker

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	providerterminal "github.com/shell-echo/sandbox-runtime/provider/terminal"
)

type fakeTerminalProcess struct {
	containerID string
	command     []string
	running     bool
	exitCode    int
}

type fakeTerminalBroker struct {
	serverExecID string
}

type fakeTerminalEngine struct {
	*fakeEngine
	mu                       sync.Mutex
	execs                    map[string]*fakeTerminalProcess
	brokers                  map[string]fakeTerminalBroker
	nextExec                 int
	serveStarts              int
	missingBroker            bool
	serveStartErrAfterEffect error
}

func newFakeTerminalEngine() *fakeTerminalEngine {
	return &fakeTerminalEngine{
		fakeEngine: newFakeEngine(), execs: make(map[string]*fakeTerminalProcess),
		brokers: make(map[string]fakeTerminalBroker),
	}
}

func (e *fakeTerminalEngine) execCreate(_ context.Context, containerID string, request execCreateRequest) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nextExec++
	id := "private-terminal-exec-" + strings.Repeat("x", e.nextExec)
	e.execs[id] = &fakeTerminalProcess{containerID: containerID, command: append([]string(nil), request.command...)}
	return id, nil
}

func (e *fakeTerminalEngine) execStart(_ context.Context, execID string, _ bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	process := e.execs[execID]
	if process == nil {
		return errors.New("exec missing")
	}
	command, socket := terminalTestCommand(process.command)
	if e.missingBroker {
		process.exitCode = terminalBrokerExitTool
		return nil
	}
	switch command {
	case "serve":
		e.serveStarts++
		process.running = true
		e.brokers[socket] = fakeTerminalBroker{serverExecID: execID}
		if e.serveStartErrAfterEffect != nil {
			err := e.serveStartErrAfterEffect
			e.serveStartErrAfterEffect = nil
			return err
		}
	case "probe":
		if _, ok := e.brokers[socket]; ok {
			process.exitCode = 0
		} else {
			process.exitCode = terminalBrokerExitGone
		}
	case "stop":
		broker, ok := e.brokers[socket]
		if !ok {
			process.exitCode = terminalBrokerExitGone
			break
		}
		delete(e.brokers, socket)
		if server := e.execs[broker.serverExecID]; server != nil {
			server.running = false
		}
		process.exitCode = 0
	default:
		process.exitCode = 2
	}
	return nil
}

func (e *fakeTerminalEngine) execInspect(_ context.Context, execID string) (execInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	process := e.execs[execID]
	if process == nil {
		return execInfo{}, errors.New("exec missing")
	}
	return execInfo{id: execID, containerID: process.containerID, running: process.running, exitCode: process.exitCode}, nil
}

func (e *fakeTerminalEngine) execAttachTerminal(_ context.Context, execID string) (terminalConnection, error) {
	e.mu.Lock()
	process := e.execs[execID]
	if process == nil {
		e.mu.Unlock()
		return nil, errors.New("exec missing")
	}
	command, socket := terminalTestCommand(process.command)
	if command != "connect" {
		e.mu.Unlock()
		return nil, errors.New("not a connect exec")
	}
	if _, ok := e.brokers[socket]; !ok {
		e.mu.Unlock()
		return nil, errors.New("broker missing")
	}
	process.running = true
	e.mu.Unlock()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

func terminalTestCommand(command []string) (string, string) {
	if len(command) < 2 {
		return "", ""
	}
	socket := ""
	for index := 2; index+1 < len(command); index++ {
		if command[index] == "--socket" {
			socket = command[index+1]
			break
		}
	}
	return command[1], socket
}

type mutableTerminalClock struct{ now time.Time }

func (c *mutableTerminalClock) Now() time.Time { return c.now }

func terminalAllocation(now time.Time, sessionID string) providerterminal.Allocation {
	return providerterminal.Allocation{
		AllocatedAt: now,
		Request: providerterminal.AllocationRequest{
			SandboxID: "sandbox-one", RuntimeSessionID: sessionID,
			OperationID: "operation-" + sessionID, AttemptID: "attempt-" + sessionID,
			FencingToken: 2, ExpectedGeneration: 1,
			RequestDigest:    "sha256:" + strings.Repeat("d", 64),
			WorkingDirectory: "/workspace", ExpiresAt: now.Add(time.Hour),
		},
	}
}

func newTerminalTestRuntime(t *testing.T, maxPerSandbox, maxPerController int) (*TerminalRuntime, *Driver, *fakeTerminalEngine, *mutableTerminalClock, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	backend := newFakeTerminalEngine()
	options := testOptions(t)
	runtime, err := newDriver(backend, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Create(context.Background(), testSandbox(now)); err != nil {
		t.Fatal(err)
	}
	clock := &mutableTerminalClock{now: now}
	terminalRuntime, err := NewTerminalRuntime(runtime, TerminalOptions{
		BrokerPath: "/workspace/.sandbox-runtime/terminal-broker", ShellPath: "/bin/sh",
		MaxSessionsPerSandbox: maxPerSandbox, MaxSessionsPerController: maxPerController, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return terminalRuntime, runtime, backend, clock, now
}

func TestDockerTerminalAllocateAttachRestartAndCleanup(t *testing.T) {
	terminalRuntime, runtime, backend, _, now := newTerminalTestRuntime(t, 2, 4)
	allocation := terminalAllocation(now, "session-one")
	receipt, err := terminalRuntime.Allocate(context.Background(), allocation)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if err := receipt.Validate(); err != nil || strings.Contains(string(receipt.Reference), "private") || backend.serveStarts != 1 {
		t.Fatalf("receipt/backend = %#v, %v, starts=%d", receipt, err, backend.serveStarts)
	}
	replay, err := terminalRuntime.Allocate(context.Background(), allocation)
	if err != nil || replay != receipt || backend.serveStarts != 1 {
		t.Fatalf("replayed Allocate = %#v, %v, starts=%d", replay, err, backend.serveStarts)
	}

	stream, err := terminalRuntime.Attach(context.Background(), receipt)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	assertTerminalEcho(t, stream, "first-connect\n")
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}

	restartedDriver, err := newDriver(backend, runtime.options)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewTerminalRuntime(restartedDriver, terminalRuntime.options)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := restarted.Observe(context.Background(), receipt)
	if err != nil || observation.State != providerterminal.ObservationRunning {
		t.Fatalf("restarted Observe = %#v, %v", observation, err)
	}
	reconnected, err := restarted.Attach(context.Background(), receipt)
	if err != nil {
		t.Fatalf("restarted Attach: %v", err)
	}
	assertTerminalEcho(t, reconnected, "second-connect\n")
	_ = reconnected.Close()
	if backend.serveStarts != 1 {
		t.Fatalf("restart created %d broker sessions", backend.serveStarts)
	}

	substituted := receipt
	substituted.OperationID = "operation-other"
	if err := restarted.Cleanup(context.Background(), substituted); !errors.Is(err, providerterminal.ErrTerminalConflict) {
		t.Fatalf("substituted Cleanup = %v", err)
	}
	if err := restarted.Cleanup(context.Background(), receipt); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if err := restarted.Cleanup(context.Background(), receipt); err != nil {
		t.Fatalf("idempotent Cleanup: %v", err)
	}
	observation, err = restarted.Observe(context.Background(), receipt)
	if err != nil || observation.State != providerterminal.ObservationAbsent {
		t.Fatalf("cleaned Observe = %#v, %v", observation, err)
	}
}

func TestDockerTerminalRecoversLostStartResponseWithoutDuplicateBroker(t *testing.T) {
	terminalRuntime, _, backend, _, now := newTerminalTestRuntime(t, 1, 2)
	allocation := terminalAllocation(now, "session-lost-response")
	backend.serveStartErrAfterEffect = errors.New("connection lost after start")
	if _, err := terminalRuntime.Allocate(context.Background(), allocation); !errors.Is(err, providerterminal.ErrAllocationUnknown) {
		t.Fatalf("first Allocate = %v", err)
	}
	receipt, err := terminalRuntime.Allocate(context.Background(), allocation)
	if err != nil {
		t.Fatalf("recovered Allocate: %v", err)
	}
	if receipt.RuntimeSessionID != allocation.Request.RuntimeSessionID || backend.serveStarts != 1 {
		t.Fatalf("receipt = %#v, starts=%d", receipt, backend.serveStarts)
	}
}

func TestDockerTerminalCapacityExpiryAndUnsupportedBroker(t *testing.T) {
	terminalRuntime, runtime, backend, clock, now := newTerminalTestRuntime(t, 1, 1)
	first := terminalAllocation(now, "session-capacity-one")
	receipt, err := terminalRuntime.Allocate(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := terminalAllocation(now, "session-capacity-two")
	if _, err := terminalRuntime.Allocate(context.Background(), second); !errors.Is(err, providerterminal.ErrTerminalCapacity) {
		t.Fatalf("capacity Allocate = %v", err)
	}
	secondSandbox := testSandbox(now)
	secondSandbox.ID = "sandbox-two"
	secondSandbox.SandboxSlotKey = "slots/sandbox-two"
	if err := runtime.Create(context.Background(), secondSandbox); err != nil {
		t.Fatal(err)
	}
	controllerLimited := terminalAllocation(now, "session-controller-capacity")
	controllerLimited.Request.SandboxID = secondSandbox.ID
	if _, err := terminalRuntime.Allocate(context.Background(), controllerLimited); !errors.Is(err, providerterminal.ErrTerminalCapacity) {
		t.Fatalf("controller capacity Allocate = %v", err)
	}
	clock.now = receipt.ExpiresAt
	if _, err := terminalRuntime.Attach(context.Background(), receipt); !errors.Is(err, providerterminal.ErrTerminalExpired) {
		t.Fatalf("expired Attach = %v", err)
	}
	if err := terminalRuntime.Cleanup(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	clock.now = now
	backend.missingBroker = true
	if _, err := terminalRuntime.Allocate(context.Background(), second); !errors.Is(err, providerterminal.ErrTerminalUnsupported) {
		t.Fatalf("unsupported Allocate = %v", err)
	}
}

func TestDockerTerminalStreamHonorsCancellation(t *testing.T) {
	terminalRuntime, _, _, _, now := newTerminalTestRuntime(t, 1, 1)
	receipt, err := terminalRuntime.Allocate(context.Background(), terminalAllocation(now, "session-cancel"))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := terminalRuntime.Attach(context.Background(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := stream.Read(ctx, make([]byte, 1)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Read = %v", err)
	}
}

func TestDockerTerminalSandboxRemovalMakesReceiptAbsent(t *testing.T) {
	terminalRuntime, runtime, _, _, now := newTerminalTestRuntime(t, 1, 1)
	receipt, err := terminalRuntime.Allocate(context.Background(), terminalAllocation(now, "session-removed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Remove(context.Background(), receipt.SandboxID); err != nil {
		t.Fatal(err)
	}
	observation, err := terminalRuntime.Observe(context.Background(), receipt)
	if err != nil || observation.State != providerterminal.ObservationAbsent {
		t.Fatalf("Observe after sandbox removal = %#v, %v", observation, err)
	}
	if err := terminalRuntime.Cleanup(context.Background(), receipt); err != nil {
		t.Fatalf("Cleanup after sandbox removal: %v", err)
	}
}

func TestDockerTerminalStateRejectsCorruption(t *testing.T) {
	terminalRuntime, runtime, _, _, now := newTerminalTestRuntime(t, 1, 1)
	allocation := terminalAllocation(now, "session-corrupt")
	receipt, err := terminalRuntime.Allocate(context.Background(), allocation)
	if err != nil {
		t.Fatal(err)
	}
	_, statePath, err := terminalRuntime.stateLocationForReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadTerminalState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	state.BrokerSocketPath = "/tmp/foreign.sock"
	if err := state.validate(); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("corrupt state validation = %v", err)
	}
	if err := os.WriteFile(statePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := terminalRuntime.Observe(context.Background(), receipt); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("corrupt Observe = %v", err)
	}
	_ = runtime
}

func assertTerminalEcho(t *testing.T, stream providerterminal.Stream, value string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := stream.Write(ctx, []byte(value)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(value))
	if _, err := io.ReadFull(terminalStreamReader{ctx: ctx, stream: stream}, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != value {
		t.Fatalf("terminal echo = %q, want %q", buffer, value)
	}
}

type terminalStreamReader struct {
	ctx    context.Context
	stream providerterminal.Stream
}

func (r terminalStreamReader) Read(value []byte) (int, error) {
	return r.stream.Read(r.ctx, value)
}

var _ terminalEngine = (*fakeTerminalEngine)(nil)
