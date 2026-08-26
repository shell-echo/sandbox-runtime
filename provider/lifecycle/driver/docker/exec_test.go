package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

type fakeExecProcess struct {
	containerID string
	running     bool
	exitCode    int
	stream      []byte
	streamErr   error
	streamGate  <-chan struct{}
	readStarted chan<- struct{}
	kill        bool
}

type fakeExecEngine struct {
	*fakeEngine
	execs           map[string]*fakeExecProcess
	nextExec        int
	lastOriginal    string
	nextStreamErr   error
	nextStreamGate  <-chan struct{}
	nextReadStarted chan<- struct{}
	killMisses      int
}

func newFakeExecEngine() *fakeExecEngine {
	return &fakeExecEngine{fakeEngine: newFakeEngine(), execs: make(map[string]*fakeExecProcess)}
}

func (e *fakeExecEngine) execCreate(_ context.Context, containerID string, request execCreateRequest) (string, error) {
	e.nextExec++
	id := "backend-exec-id-" + string(rune('a'+e.nextExec))
	kill := len(request.command) > 2 && strings.Contains(request.command[2], "kill -TERM")
	process := &fakeExecProcess{containerID: containerID, kill: kill}
	if !kill {
		process.stream = append(execFrame(1, []byte("stdout-long")), execFrame(2, []byte("stderr-long"))...)
		process.streamErr = e.nextStreamErr
		e.nextStreamErr = nil
		process.streamGate = e.nextStreamGate
		process.readStarted = e.nextReadStarted
		e.nextStreamGate = nil
		e.nextReadStarted = nil
		e.lastOriginal = id
	}
	e.execs[id] = process
	return id, nil
}

func (e *fakeExecEngine) execStart(_ context.Context, execID string, detach bool) error {
	process, ok := e.execs[execID]
	if !ok {
		return errors.New("exec missing")
	}
	if process.kill {
		if e.killMisses > 0 {
			e.killMisses--
			process.exitCode = 3
			return nil
		}
		process.exitCode = 0
		if target := e.execs[e.lastOriginal]; target != nil {
			target.running = false
			target.exitCode = 143
		}
		return nil
	}
	process.running = detach
	return nil
}

func (e *fakeExecEngine) execAttach(_ context.Context, execID string) (io.ReadCloser, error) {
	process, ok := e.execs[execID]
	if !ok {
		return nil, errors.New("exec missing")
	}
	process.running = true
	return &testExecStream{Reader: bytes.NewReader(process.stream), terminalErr: process.streamErr, gate: process.streamGate, readStarted: process.readStarted}, nil
}

func (e *fakeExecEngine) execInspect(_ context.Context, execID string) (execInfo, error) {
	process, ok := e.execs[execID]
	if !ok {
		return execInfo{}, errors.New("exec missing")
	}
	return execInfo{id: execID, containerID: process.containerID, running: process.running, exitCode: process.exitCode}, nil
}

type testExecStream struct {
	*bytes.Reader
	terminalErr error
	returnedErr bool
	gate        <-chan struct{}
	readStarted chan<- struct{}
	readBegun   bool
}

func (s *testExecStream) Read(value []byte) (int, error) {
	if !s.readBegun {
		s.readBegun = true
		if s.readStarted != nil {
			close(s.readStarted)
		}
		if s.gate != nil {
			<-s.gate
		}
	}
	n, err := s.Reader.Read(value)
	if errors.Is(err, io.EOF) && s.terminalErr != nil && !s.returnedErr {
		s.returnedErr = true
		return n, s.terminalErr
	}
	return n, err
}

func (s *testExecStream) Close() error { return nil }

func execFrame(stream byte, value []byte) []byte {
	frame := make([]byte, 8+len(value))
	frame[0] = stream
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(value)))
	copy(frame[8:], value)
	return frame
}

func dockerExecRequest(now time.Time) providerexec.Request {
	return providerexec.Request{
		SandboxID: "sandbox-one", OperationID: "operation-one", AttemptID: "attempt-one",
		FencingToken: 2, ExpectedGeneration: 1, IdempotencyKey: "exec-one",
		RequestDigest: "sha256:" + strings.Repeat("d", 64), Deadline: now.Add(time.Minute),
		Command: []string{"sh", "-c", "printf output"}, WorkingDirectory: "/workspace",
		ResultRetention: time.Hour, CaptureStdout: true, CaptureStderr: true, CaptureMaxBytes: 4,
	}
}

func newExecDriver(t *testing.T) (*Driver, *fakeExecEngine, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	backend := newFakeExecEngine()
	driver, err := newDriver(backend, testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Create(context.Background(), testSandbox(now)); err != nil {
		t.Fatal(err)
	}
	return driver, backend, now
}

func TestDockerExecCapturesBoundsAndReconcilesApplicationExit(t *testing.T) {
	driver, backend, now := newExecDriver(t)
	request := dockerExecRequest(now)
	reference, err := driver.Start(context.Background(), providerexec.Invocation{Request: request, StartedAt: now})
	if err != nil || !strings.HasPrefix(string(reference), "ref:exec/") || strings.Contains(string(reference), "backend") {
		t.Fatalf("Start = %q, %v", reference, err)
	}
	waitExecCapture(t, driver, request)
	backend.execs[backend.lastOriginal].running = false
	backend.execs[backend.lastOriginal].exitCode = 7
	observation, err := driver.Observe(context.Background(), request)
	if err != nil || observation.Running || observation.Status != providerexec.ResultCompleted || observation.ExitCode == nil || *observation.ExitCode != 7 {
		t.Fatalf("Observe = %#v, %v", observation, err)
	}
	paths, _ := driver.mountPaths(request.SandboxID)
	state, err := loadExecState(driver.execStatePath(paths.root+"/exec", request.OperationID))
	if err != nil {
		t.Fatal(err)
	}
	if state.StdoutBytes != 4 || state.StderrBytes != 4 || !state.StdoutTruncated || !state.StderrTruncated {
		t.Fatalf("capture state = %#v", state)
	}
	for _, path := range []string{state.StdoutPath, state.StderrPath} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() != 4 || info.Mode().Perm() != 0o600 {
			t.Fatalf("capture file %q = %#v, %v", path, info, statErr)
		}
	}

	restarted, err := newDriver(backend, driver.options)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Observe(context.Background(), request)
	if err != nil || recovered.Status != providerexec.ResultCompleted || recovered.ExecutionReference != reference {
		t.Fatalf("restarted Observe = %#v, %v", recovered, err)
	}
}

func TestDockerExecCancellationRequiresConfirmedStop(t *testing.T) {
	driver, backend, now := newExecDriver(t)
	request := dockerExecRequest(now)
	request.CaptureStdout, request.CaptureStderr, request.CaptureMaxBytes = false, false, 0
	reference, err := driver.Start(context.Background(), providerexec.Invocation{Request: request, StartedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	attachment := providerexec.ExecutionAttachment{
		OperationID: request.OperationID, AttemptID: request.AttemptID, SandboxID: request.SandboxID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		Dispatch: providerexec.Dispatch{ExecutionReference: reference, AcceptedAt: now},
	}
	if err := driver.Cancel(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	if backend.execs[backend.lastOriginal].running {
		t.Fatal("Cancel returned before the target stopped")
	}
	if err := driver.Cancel(context.Background(), attachment); !errors.Is(err, providerexec.ErrExecutionNotRunning) {
		t.Fatalf("second Cancel error = %v", err)
	}
}

func TestDockerExecCancellationRetriesUntilPIDFileIsReady(t *testing.T) {
	driver, backend, now := newExecDriver(t)
	request := dockerExecRequest(now)
	request.CaptureStdout, request.CaptureStderr, request.CaptureMaxBytes = false, false, 0
	reference, err := driver.Start(context.Background(), providerexec.Invocation{Request: request, StartedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	backend.killMisses = 1
	attachment := providerexec.ExecutionAttachment{
		OperationID: request.OperationID, AttemptID: request.AttemptID, SandboxID: request.SandboxID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		Dispatch: providerexec.Dispatch{ExecutionReference: reference, AcceptedAt: now},
	}
	if err := driver.Cancel(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	if backend.killMisses != 0 || backend.execs[backend.lastOriginal].running {
		t.Fatalf("kill misses = %d, target running = %t", backend.killMisses, backend.execs[backend.lastOriginal].running)
	}
}

func TestDockerExecCaptureFailureIsOutcomeUnknownAndReferencesStayOpaque(t *testing.T) {
	driver, backend, now := newExecDriver(t)
	request := dockerExecRequest(now)
	backend.nextExec = 10
	backend.nextStreamErr = errors.New("stream failed")
	reference, err := driver.Start(context.Background(), providerexec.Invocation{Request: request, StartedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	process := backend.execs[backend.lastOriginal]
	waitExecCapture(t, driver, request)
	paths, _ := driver.mountPaths(request.SandboxID)
	state, err := loadExecState(driver.execStatePath(paths.root+"/exec", request.OperationID))
	if err != nil {
		t.Fatal(err)
	}
	if state.CaptureComplete || !state.CaptureFailed {
		t.Fatalf("capture failure state = %#v", state)
	}
	process.running = false
	observation, err := driver.Observe(context.Background(), request)
	if err != nil || observation.Status != providerexec.ResultOutcomeUnknown || observation.Error == nil || observation.ExecutionReference != reference {
		t.Fatalf("Observe = %#v, %v", observation, err)
	}
	if strings.Contains(string(observation.ExecutionReference), process.containerID) || strings.Contains(string(observation.ExecutionReference), backend.lastOriginal) {
		t.Fatalf("observation leaked backend identity: %#v", observation)
	}
}

func TestDockerExecObserveWaitsForLiveCaptureBeforeTerminalProjection(t *testing.T) {
	driver, backend, now := newExecDriver(t)
	request := dockerExecRequest(now)
	gate := make(chan struct{})
	readStarted := make(chan struct{})
	backend.nextStreamGate = gate
	backend.nextReadStarted = readStarted
	if _, err := driver.Start(context.Background(), providerexec.Invocation{Request: request, StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	<-readStarted
	backend.execs[backend.lastOriginal].running = false
	backend.execs[backend.lastOriginal].exitCode = 0
	type observeResult struct {
		observation providerexec.Observation
		err         error
	}
	result := make(chan observeResult, 1)
	go func() {
		observation, err := driver.Observe(context.Background(), request)
		result <- observeResult{observation: observation, err: err}
	}()
	select {
	case early := <-result:
		t.Fatalf("Observe returned before capture completed: %#v, %v", early.observation, early.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(gate)
	select {
	case completed := <-result:
		if completed.err != nil || completed.observation.Status != providerexec.ResultCompleted || completed.observation.ExitCode == nil || *completed.observation.ExitCode != 0 {
			t.Fatalf("Observe after capture = %#v, %v", completed.observation, completed.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Observe did not resume after capture completed")
	}
}

func TestDockerExecCleanupResultIsIdentityBoundAndIdempotent(t *testing.T) {
	driver, _, now := newExecDriver(t)
	request := dockerExecRequest(now)
	if _, err := driver.Start(context.Background(), providerexec.Invocation{Request: request, StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	waitExecCapture(t, driver, request)
	paths, _ := driver.mountPaths(request.SandboxID)
	statePath := driver.execStatePath(paths.root+"/exec", request.OperationID)
	state, err := loadExecState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	substituted := request.Clone()
	substituted.RequestDigest = "sha256:" + strings.Repeat("e", 64)
	if err := driver.CleanupResult(context.Background(), substituted); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("substituted cleanup error = %v", err)
	}
	if err := driver.CleanupResult(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := driver.CleanupResult(context.Background(), request); err != nil {
		t.Fatalf("replayed CleanupResult error = %v", err)
	}
	for _, path := range []string{state.StdoutPath, state.StderrPath, statePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("private exec path %q remains: %v", path, err)
		}
	}
}

func TestDockerExecStateRejectsCrossOperationCapturePaths(t *testing.T) {
	driver, _, now := newExecDriver(t)
	request := dockerExecRequest(now)
	if _, err := driver.Start(context.Background(), providerexec.Invocation{Request: request, StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	waitExecCapture(t, driver, request)
	paths, _ := driver.mountPaths(request.SandboxID)
	directory := paths.root + "/exec"
	state, err := loadExecState(driver.execStatePath(directory, request.OperationID))
	if err != nil {
		t.Fatal(err)
	}
	state.StdoutPath = driver.execStatePath(directory, "operation-other")
	if err := validateExecState(state, directory); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("cross-operation capture path error = %v", err)
	}
	state.StdoutPath = directory + "/" + execToken(request.OperationID) + ".stdout"
	state.StdoutBytes = state.CaptureMaxBytes + 1
	if err := validateExecState(state, directory); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("oversized capture state error = %v", err)
	}
}

func TestDockerExecRejectsUnresolvedReferencesBeforeBackendDispatch(t *testing.T) {
	driver, backend, now := newExecDriver(t)
	request := dockerExecRequest(now)
	request.Environment = map[string]string{"HOME": "envref:grant/home"}
	if _, err := driver.Start(context.Background(), providerexec.Invocation{Request: request, StartedAt: now}); !errors.Is(err, providerexec.ErrUnsupportedRequest) {
		t.Fatalf("Start error = %v", err)
	}
	if len(backend.execs) != 0 {
		t.Fatalf("backend execs = %d, want 0", len(backend.execs))
	}
}

func waitExecCapture(t *testing.T, driver *Driver, request providerexec.Request) {
	t.Helper()
	paths, _ := driver.mountPaths(request.SandboxID)
	statePath := driver.execStatePath(paths.root+"/exec", request.OperationID)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state, err := loadExecState(statePath)
		if err == nil && (state.CaptureComplete || state.CaptureFailed) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("exec capture did not finish")
}
