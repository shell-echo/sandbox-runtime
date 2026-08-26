package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

const (
	execStateVersion   = 1
	maxExecStateBytes  = 64 << 10
	execObservePoll    = 50 * time.Millisecond
	execPrivateDirMode = 0o700
)

type execState struct {
	Version               int
	SandboxID             string
	OperationID           string
	AttemptID             string
	FencingToken          int64
	ExpectedGeneration    int64
	RequestDigest         string
	ExecutionReference    providerexec.ExecutionReference
	BackendExecID         string
	BackendContainerID    string
	StartedAt             time.Time
	CompletedAt           time.Time
	CaptureStdout         bool
	CaptureStderr         bool
	CaptureMaxBytes       int64
	StdoutPath            string
	StderrPath            string
	StdoutBytes           int64
	StderrBytes           int64
	StdoutTruncated       bool
	StderrTruncated       bool
	CaptureComplete       bool
	CaptureFailed         bool
	CancellationConfirmed bool
}

// Start creates a Docker exec only inside the exact Provider-owned sandbox.
// Secret, environment, and stdin references remain unsupported until a real
// resolver is composed; they are never treated as plaintext values.
func (d *Driver) Start(ctx context.Context, invocation providerexec.Invocation) (providerexec.ExecutionReference, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	if d == nil || d.engine == nil {
		return "", ErrInvalidDriver
	}
	backend, ok := d.engine.(execEngine)
	if !ok {
		return "", providerexec.ErrUnsupportedRequest
	}
	request := invocation.Request.Clone()
	if err := request.Validate(invocation.StartedAt); err != nil || invocation.StartedAt.IsZero() {
		return "", providerexec.ErrInvalidRequest
	}
	if err := d.CheckSupport(ctx, request); err != nil {
		return "", err
	}
	captureMaxBytes := request.CaptureMaxBytes
	if (request.CaptureStdout || request.CaptureStderr) && captureMaxBytes == 0 {
		captureMaxBytes = providerexec.MaxCaptureBytes
	}

	d.execMu.Lock()
	defer d.execMu.Unlock()
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	container, found, err := d.inspectOwnedID(operationCtx, request.SandboxID)
	if err != nil {
		return "", err
	}
	if !found || !container.running || container.status != "running" {
		return "", ErrInvalidRuntime
	}
	paths, err := d.mountPaths(request.SandboxID)
	if err != nil {
		return "", err
	}
	execDirectory := filepath.Join(paths.root, "exec")
	if err := ensureDirectory(execDirectory, execPrivateDirMode, -1, -1); err != nil {
		return "", fmt.Errorf("prepare Provider exec state: %w", err)
	}
	statePath := d.execStatePath(execDirectory, request.OperationID)
	if existing, loadErr := loadExecState(statePath); loadErr == nil {
		if !execStateMatchesRequest(existing, request) {
			return "", ErrOwnershipConflict
		}
		return existing.ExecutionReference, nil
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return "", loadErr
	}

	token := execToken(request.OperationID)
	pidFile := "/tmp/sandbox-runtime-exec-" + token + ".pid"
	command := []string{"/bin/sh", "-c", `pid_file="$1"; shift; "$@" & child=$!; printf '%s\n' "$child" > "$pid_file" || exit 125; wait "$child"; status=$?; rm -f "$pid_file"; exit "$status"`, "sandbox-runtime-exec", pidFile}
	command = append(command, request.Command...)
	backendExecID, err := backend.execCreate(operationCtx, container.id, execCreateRequest{
		user: d.options.User, workingDirectory: request.WorkingDirectory, command: command,
		attachStdout: request.CaptureStdout, attachStderr: request.CaptureStderr,
	})
	if err != nil || backendExecID == "" {
		return "", ErrInvalidRuntime
	}
	state := execState{
		Version: execStateVersion, SandboxID: request.SandboxID, OperationID: request.OperationID,
		AttemptID: request.AttemptID, FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		RequestDigest: request.RequestDigest, ExecutionReference: providerexec.ExecutionReference("ref:exec/" + token),
		BackendExecID: backendExecID, BackendContainerID: container.id, StartedAt: invocation.StartedAt.UTC(),
		CaptureStdout: request.CaptureStdout, CaptureStderr: request.CaptureStderr, CaptureMaxBytes: captureMaxBytes,
		CaptureComplete: !request.CaptureStdout && !request.CaptureStderr,
	}
	if request.CaptureStdout {
		state.StdoutPath = filepath.Join(execDirectory, token+".stdout")
	}
	if request.CaptureStderr {
		state.StderrPath = filepath.Join(execDirectory, token+".stderr")
	}
	if err := persistExecState(statePath, state); err != nil {
		return "", err
	}
	if state.CaptureComplete {
		if err := backend.execStart(operationCtx, backendExecID, true); err != nil {
			return "", errors.Join(providerexec.ErrDispatchUnknown, contextErrorOrNil(operationCtx))
		}
		return state.ExecutionReference, nil
	}
	stdout, stderr, err := openExecCaptureFiles(state)
	if err != nil {
		return "", err
	}
	stream, err := backend.execAttach(operationCtx, backendExecID)
	if err != nil {
		closeExecCaptureFiles(stdout, stderr)
		return "", errors.Join(providerexec.ErrDispatchUnknown, contextErrorOrNil(operationCtx))
	}
	captureDone := make(chan struct{})
	d.execCaptures[request.OperationID] = captureDone
	go d.captureExecOutput(statePath, request.OperationID, backendExecID, stream, stdout, stderr, captureDone)
	return state.ExecutionReference, nil
}

func (d *Driver) CheckSupport(ctx context.Context, request providerexec.Request) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || d.engine == nil {
		return ErrInvalidDriver
	}
	if _, ok := d.engine.(execEngine); !ok {
		return providerexec.ErrUnsupportedRequest
	}
	if len(request.Environment) != 0 || len(request.SecretReferenceIDs) != 0 || request.SecretGrantID != "" || request.SecretGrantDigest != "" || request.StdinReference != "" {
		return providerexec.ErrUnsupportedRequest
	}
	return nil
}

func (d *Driver) Observe(ctx context.Context, request providerexec.Request) (providerexec.Observation, error) {
	if err := contextError(ctx); err != nil {
		return providerexec.Observation{}, err
	}
	if d == nil || d.engine == nil {
		return providerexec.Observation{}, ErrInvalidDriver
	}
	backend, ok := d.engine.(execEngine)
	if !ok {
		return providerexec.Observation{}, providerexec.ErrUnsupportedRequest
	}
	d.execMu.Lock()
	defer d.execMu.Unlock()
	paths, err := d.mountPaths(request.SandboxID)
	if err != nil {
		return providerexec.Observation{}, err
	}
	statePath := d.execStatePath(filepath.Join(paths.root, "exec"), request.OperationID)
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	for {
		state, err := loadExecState(statePath)
		if errors.Is(err, os.ErrNotExist) {
			return providerexec.Observation{}, providerexec.ErrExecutionNotFound
		}
		if err != nil {
			return providerexec.Observation{}, err
		}
		if !execStateMatchesRequest(state, request) {
			return providerexec.Observation{}, ErrOwnershipConflict
		}
		container, found, err := d.inspectOwnedID(operationCtx, request.SandboxID)
		if err != nil || !found || container.id != state.BackendContainerID {
			return unknownExecObservation(state, d.observedCompletion(state)), nil
		}
		info, err := backend.execInspect(operationCtx, state.BackendExecID)
		if err != nil || info.id != state.BackendExecID || info.containerID != state.BackendContainerID {
			return unknownExecObservation(state, d.observedCompletion(state)), nil
		}
		if info.running {
			return providerexec.Observation{ExecutionReference: state.ExecutionReference, Running: true, StartedAt: state.StartedAt}, nil
		}
		if !state.CaptureComplete && !state.CaptureFailed {
			captureDone := d.execCaptures[state.OperationID]
			if captureDone != nil {
				d.execMu.Unlock()
				select {
				case <-captureDone:
					d.execMu.Lock()
					continue
				case <-operationCtx.Done():
					d.execMu.Lock()
					return providerexec.Observation{}, operationCtx.Err()
				}
			}
		}
		return d.terminalExecObservation(statePath, state, info)
	}
}

func (d *Driver) terminalExecObservation(statePath string, state execState, info execInfo) (providerexec.Observation, error) {
	if state.CompletedAt.IsZero() {
		state.CompletedAt = d.observedCompletion(state)
		if err := persistExecState(statePath, state); err != nil {
			return providerexec.Observation{}, err
		}
	}
	if state.CancellationConfirmed {
		return providerexec.Observation{
			ExecutionReference: state.ExecutionReference, Status: providerexec.ResultCancelled,
			StartedAt: state.StartedAt, CompletedAt: state.CompletedAt,
		}, nil
	}
	if state.CaptureFailed || !state.CaptureComplete || info.exitCode < -1 || info.exitCode > 255 {
		return unknownExecObservation(state, state.CompletedAt), nil
	}
	exitCode := info.exitCode
	observation := providerexec.Observation{
		ExecutionReference: state.ExecutionReference, Status: providerexec.ResultCompleted,
		StartedAt: state.StartedAt, CompletedAt: state.CompletedAt, ExitCode: &exitCode,
	}
	if state.CaptureStdout {
		observation.StdoutReference = "ref:exec/" + execToken(state.OperationID) + "/stdout"
	}
	if state.CaptureStderr {
		observation.StderrReference = "ref:exec/" + execToken(state.OperationID) + "/stderr"
	}
	return observation, observation.Validate()
}

func (d *Driver) Cancel(ctx context.Context, attachment providerexec.ExecutionAttachment) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || d.engine == nil {
		return ErrInvalidDriver
	}
	backend, ok := d.engine.(execEngine)
	if !ok {
		return providerexec.ErrUnsupportedRequest
	}
	d.execMu.Lock()
	defer d.execMu.Unlock()
	paths, err := d.mountPaths(attachment.SandboxID)
	if err != nil {
		return err
	}
	statePath := d.execStatePath(filepath.Join(paths.root, "exec"), attachment.OperationID)
	state, err := loadExecState(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return providerexec.ErrExecutionNotFound
		}
		return err
	}
	if !execStateMatchesAttachment(state, attachment) {
		return ErrOwnershipConflict
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	pidFile := "/tmp/sandbox-runtime-exec-" + execToken(state.OperationID) + ".pid"
	ticker := time.NewTicker(execObservePoll)
	defer ticker.Stop()
	for {
		info, inspectErr := backend.execInspect(operationCtx, state.BackendExecID)
		if inspectErr != nil {
			return errors.Join(providerexec.ErrDispatchUnknown, inspectErr)
		}
		if !info.running {
			return providerexec.ErrExecutionNotRunning
		}
		killID, createErr := backend.execCreate(operationCtx, state.BackendContainerID, execCreateRequest{
			user: d.options.User, workingDirectory: "/tmp",
			command: []string{"/bin/sh", "-c", `test -r "$1" || exit 3; pid=$(cat "$1") || exit 4; kill -TERM "$pid"`, "sandbox-runtime-cancel", pidFile},
		})
		if createErr != nil {
			return errors.Join(providerexec.ErrDispatchUnknown, createErr)
		}
		if startErr := backend.execStart(operationCtx, killID, false); startErr != nil {
			return errors.Join(providerexec.ErrDispatchUnknown, startErr)
		}
		killResult, inspectErr := backend.execInspect(operationCtx, killID)
		if inspectErr != nil {
			return errors.Join(providerexec.ErrDispatchUnknown, inspectErr)
		}
		if killResult.exitCode == 0 {
			break
		}
		select {
		case <-operationCtx.Done():
			return operationCtx.Err()
		case <-ticker.C:
		}
	}
	for {
		observed, inspectErr := backend.execInspect(operationCtx, state.BackendExecID)
		if inspectErr != nil {
			return providerexec.ErrExecutionNotRunning
		}
		if !observed.running {
			state.CancellationConfirmed = true
			state.CompletedAt = d.observedCompletion(state)
			if err := persistExecState(statePath, state); err != nil {
				return errors.Join(providerexec.ErrDispatchUnknown, err)
			}
			return nil
		}
		select {
		case <-operationCtx.Done():
			return operationCtx.Err()
		case <-ticker.C:
		}
	}
}

func (d *Driver) CleanupResult(ctx context.Context, request providerexec.Request) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || d.engine == nil {
		return ErrInvalidDriver
	}
	d.execMu.Lock()
	defer d.execMu.Unlock()
	paths, err := d.mountPaths(request.SandboxID)
	if err != nil {
		return err
	}
	directory := filepath.Join(paths.root, "exec")
	statePath := d.execStatePath(directory, request.OperationID)
	state, err := loadExecState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !execStateMatchesRequest(state, request) {
		return ErrOwnershipConflict
	}
	for _, path := range []string{state.StdoutPath, state.StderrPath, statePath} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(directoryFile.Sync(), directoryFile.Close())
}

func (d *Driver) captureExecOutput(statePath, operationID, backendExecID string, stream io.ReadCloser, stdout, stderr *os.File, done chan struct{}) {
	stdoutWriter := newBoundedCaptureWriter(stdout, d.captureLimit(statePath))
	stderrWriter := newBoundedCaptureWriter(stderr, d.captureLimit(statePath))
	_, copyErr := stdcopy.StdCopy(stdoutWriter, stderrWriter, stream)
	closeErr := errors.Join(syncCloseFile(stdout), syncCloseFile(stderr), stream.Close())
	d.execMu.Lock()
	state, err := loadExecState(statePath)
	if err == nil && state.BackendExecID == backendExecID {
		state.StdoutBytes, state.StderrBytes = stdoutWriter.written, stderrWriter.written
		state.StdoutTruncated, state.StderrTruncated = stdoutWriter.truncated, stderrWriter.truncated
		state.CaptureComplete = copyErr == nil && closeErr == nil
		state.CaptureFailed = !state.CaptureComplete
		_ = persistExecState(statePath, state)
	}
	if d.execCaptures[operationID] == done {
		delete(d.execCaptures, operationID)
	}
	d.execMu.Unlock()
	close(done)
}

func (d *Driver) captureLimit(statePath string) int64 {
	state, err := loadExecState(statePath)
	if err != nil {
		return 0
	}
	return state.CaptureMaxBytes
}

type boundedCaptureWriter struct {
	destination io.Writer
	limit       int64
	written     int64
	truncated   bool
}

func newBoundedCaptureWriter(destination io.Writer, limit int64) *boundedCaptureWriter {
	if destination == nil {
		destination = io.Discard
	}
	return &boundedCaptureWriter{destination: destination, limit: limit}
}

func (w *boundedCaptureWriter) Write(value []byte) (int, error) {
	original := len(value)
	remaining := w.limit - w.written
	if remaining <= 0 {
		w.truncated = w.truncated || original > 0
		return original, nil
	}
	if int64(len(value)) > remaining {
		value = value[:remaining]
		w.truncated = true
	}
	written, err := w.destination.Write(value)
	w.written += int64(written)
	if err != nil {
		return written, err
	}
	if written != len(value) {
		return written, io.ErrShortWrite
	}
	return original, nil
}

func openExecCaptureFiles(state execState) (*os.File, *os.File, error) {
	open := func(path string) (*os.File, error) {
		if path == "" {
			return nil, nil
		}
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
	stdout, err := open(state.StdoutPath)
	if err != nil {
		return nil, nil, err
	}
	stderr, err := open(state.StderrPath)
	if err != nil {
		_ = syncCloseFile(stdout)
		return nil, nil, err
	}
	return stdout, stderr, nil
}

func closeExecCaptureFiles(files ...*os.File) {
	for _, file := range files {
		_ = syncCloseFile(file)
	}
}

func syncCloseFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return errors.Join(file.Sync(), file.Close())
}

func (d *Driver) execStatePath(directory, operationID string) string {
	return filepath.Join(directory, execToken(operationID)+".json")
}

func execToken(operationID string) string {
	digest := sha256.Sum256([]byte(operationID))
	return hex.EncodeToString(digest[:16])
}

func execStateMatchesRequest(state execState, request providerexec.Request) bool {
	return state.SandboxID == request.SandboxID && state.OperationID == request.OperationID && state.AttemptID == request.AttemptID &&
		state.FencingToken == request.FencingToken && state.ExpectedGeneration == request.ExpectedGeneration && state.RequestDigest == request.RequestDigest
}

func execStateMatchesAttachment(state execState, attachment providerexec.ExecutionAttachment) bool {
	return state.OperationID == attachment.OperationID && state.AttemptID == attachment.AttemptID && state.SandboxID == attachment.SandboxID &&
		state.FencingToken == attachment.FencingToken && state.ExpectedGeneration == attachment.ExpectedGeneration &&
		state.ExecutionReference == attachment.Dispatch.ExecutionReference
}

func loadExecState(path string) (execState, error) {
	file, err := os.Open(path)
	if err != nil {
		return execState{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxExecStateBytes {
		return execState{}, ErrInvalidRuntime
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxExecStateBytes+1))
	decoder.DisallowUnknownFields()
	var state execState
	if err := decoder.Decode(&state); err != nil {
		return execState{}, ErrInvalidRuntime
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return execState{}, ErrInvalidRuntime
	}
	if err := validateExecState(state, filepath.Dir(path)); err != nil {
		return execState{}, err
	}
	return state, nil
}

func validateExecState(state execState, directory string) error {
	if state.Version != execStateVersion || state.SandboxID == "" || state.OperationID == "" || state.AttemptID == "" ||
		state.FencingToken < 1 || state.ExpectedGeneration < 1 || state.RequestDigest == "" || state.BackendExecID == "" || state.BackendContainerID == "" || state.StartedAt.IsZero() ||
		state.ExecutionReference.Validate() != nil || state.ExecutionReference != providerexec.ExecutionReference("ref:exec/"+execToken(state.OperationID)) ||
		state.CaptureMaxBytes < 0 || state.CaptureMaxBytes > providerexec.MaxCaptureBytes ||
		state.StdoutBytes < 0 || state.StderrBytes < 0 || state.StdoutBytes > state.CaptureMaxBytes || state.StderrBytes > state.CaptureMaxBytes ||
		(!state.CompletedAt.IsZero() && state.CompletedAt.Before(state.StartedAt)) || state.CaptureComplete && state.CaptureFailed {
		return ErrInvalidRuntime
	}
	token := execToken(state.OperationID)
	expectedStdout, expectedStderr := "", ""
	if state.CaptureStdout {
		expectedStdout = filepath.Join(directory, token+".stdout")
	}
	if state.CaptureStderr {
		expectedStderr = filepath.Join(directory, token+".stderr")
	}
	if state.StdoutPath != expectedStdout || state.StderrPath != expectedStderr {
		return ErrInvalidRuntime
	}
	if state.CaptureStdout || state.CaptureStderr {
		if state.CaptureMaxBytes == 0 {
			return ErrInvalidRuntime
		}
	} else if state.StdoutBytes != 0 || state.StderrBytes != 0 || state.StdoutTruncated || state.StderrTruncated || !state.CaptureComplete {
		return ErrInvalidRuntime
	}
	if !state.CaptureStdout && (state.StdoutBytes != 0 || state.StdoutTruncated) || !state.CaptureStderr && (state.StderrBytes != 0 || state.StderrTruncated) {
		return ErrInvalidRuntime
	}
	return nil
}

func persistExecState(path string, state execState) error {
	if err := validateExecState(state, filepath.Dir(path)); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".exec-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(state); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := errors.Join(temporary.Sync(), temporary.Close()); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func unknownExecObservation(state execState, completedAt time.Time) providerexec.Observation {
	return providerexec.Observation{
		ExecutionReference: state.ExecutionReference, Status: providerexec.ResultOutcomeUnknown,
		StartedAt: state.StartedAt, CompletedAt: completedAt,
		Error: &providerexec.ResultError{Code: "SANDBOX_EXEC_OUTCOME_UNKNOWN", Message: "execution outcome requires reconciliation", Retryable: true, Outcome: providerexec.ErrorOutcomeUnknown},
	}
}

func (d *Driver) observedCompletion(state execState) time.Time {
	now := time.Now().UTC()
	if now.Before(state.StartedAt) {
		return state.StartedAt
	}
	return now
}

func contextErrorOrNil(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var (
	_ providerexec.Executor       = (*Driver)(nil)
	_ providerexec.SupportChecker = (*Driver)(nil)
	_ providerexec.Observer       = (*Driver)(nil)
	_ providerexec.Canceler       = (*Driver)(nil)
	_ providerexec.ResultCleaner  = (*Driver)(nil)
)
