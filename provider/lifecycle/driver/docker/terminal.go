package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	providerterminal "github.com/shell-echo/sandbox-runtime/provider/terminal"
)

const (
	maxTerminalSessions    = 1_000
	terminalCommandPoll    = 25 * time.Millisecond
	terminalReadyPoll      = 50 * time.Millisecond
	terminalConnectionGen  = 1
	terminalBrokerExitGone = 1
	terminalBrokerExitTool = 127
)

// TerminalOptions are fixed development settings for the in-sandbox broker.
// BrokerPath and ShellPath are guest paths, never caller request fields.
type TerminalOptions struct {
	BrokerPath               string
	ShellPath                string
	MaxSessionsPerSandbox    int
	MaxSessionsPerController int
	Clock                    providerterminal.Clock
}

func (o TerminalOptions) validate() error {
	if !validGuestExecutable(o.BrokerPath) || !validGuestExecutable(o.ShellPath) {
		return fmt.Errorf("%w: invalid terminal executable path", ErrInvalidOptions)
	}
	if o.MaxSessionsPerSandbox < 1 || o.MaxSessionsPerSandbox > maxTerminalSessions ||
		o.MaxSessionsPerController < o.MaxSessionsPerSandbox || o.MaxSessionsPerController > maxTerminalSessions || o.Clock == nil {
		return fmt.Errorf("%w: invalid terminal capacity or clock", ErrInvalidOptions)
	}
	return nil
}

// TerminalRuntime is an optional Docker terminal capability. It shares the
// lifecycle driver's exact ownership checks but owns separate private state.
type TerminalRuntime struct {
	runtime *Driver
	engine  terminalEngine
	options TerminalOptions
	mu      sync.Mutex
}

func NewTerminalRuntime(runtime *Driver, options TerminalOptions) (*TerminalRuntime, error) {
	if runtime == nil || runtime.engine == nil {
		return nil, ErrInvalidDriver
	}
	backend, ok := runtime.engine.(terminalEngine)
	if !ok {
		return nil, providerterminal.ErrTerminalUnsupported
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &TerminalRuntime{runtime: runtime, engine: backend, options: options}, nil
}

func (r *TerminalRuntime) Allocate(ctx context.Context, allocation providerterminal.Allocation) (providerterminal.Receipt, error) {
	if err := contextError(ctx); err != nil {
		return providerterminal.Receipt{}, err
	}
	if r == nil || r.runtime == nil || r.engine == nil {
		return providerterminal.Receipt{}, ErrInvalidDriver
	}
	if err := allocation.Validate(); err != nil {
		return providerterminal.Receipt{}, err
	}
	now := r.options.Clock.Now().UTC()
	if now.IsZero() || !allocation.Request.ExpiresAt.After(now) {
		return providerterminal.Receipt{}, providerterminal.ErrTerminalExpired
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	operationCtx, cancel := r.runtime.operationContext(ctx)
	defer cancel()
	container, found, err := r.runtime.inspectOwnedID(operationCtx, allocation.Request.SandboxID)
	if err != nil {
		return providerterminal.Receipt{}, terminalUnknown(operationCtx, err)
	}
	if !found || !container.running || container.status != "running" {
		return providerterminal.Receipt{}, providerterminal.ErrTerminalNotFound
	}
	directory, statePath, err := r.stateLocation(allocation.Request)
	if err != nil {
		return providerterminal.Receipt{}, err
	}
	state, err := loadTerminalState(statePath)
	if err == nil {
		if !state.matchesAllocation(allocation) || state.BackendContainerID != container.id {
			return providerterminal.Receipt{}, providerterminal.ErrTerminalConflict
		}
		return r.recoverAllocation(operationCtx, statePath, state)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return providerterminal.Receipt{}, err
	}
	if err := ensureDirectory(directory, 0o700, -1, -1); err != nil {
		return providerterminal.Receipt{}, err
	}
	sandboxCount, err := countTerminalStates(directory)
	if err != nil {
		return providerterminal.Receipt{}, err
	}
	controllerCount, err := countControllerTerminalStates(r.runtime.dataRoot)
	if err != nil {
		return providerterminal.Receipt{}, err
	}
	if sandboxCount >= r.options.MaxSessionsPerSandbox || controllerCount >= r.options.MaxSessionsPerController {
		return providerterminal.Receipt{}, providerterminal.ErrTerminalCapacity
	}
	state = newTerminalState(allocation, container.id)
	if err := persistTerminalState(statePath, state); err != nil {
		return providerterminal.Receipt{}, err
	}

	execID, err := r.engine.execCreate(operationCtx, container.id, r.commandRequest(r.serveCommand(state), false))
	if err != nil || execID == "" {
		return providerterminal.Receipt{}, terminalUnknown(operationCtx, err)
	}
	state.BackendBrokerExecID = execID
	if err := persistTerminalState(statePath, state); err != nil {
		return providerterminal.Receipt{}, err
	}
	if err := r.engine.execStart(operationCtx, execID, true); err != nil {
		return providerterminal.Receipt{}, terminalUnknown(operationCtx, err)
	}
	return r.waitForBroker(operationCtx, statePath, state)
}

func (r *TerminalRuntime) recoverAllocation(ctx context.Context, statePath string, state terminalState) (providerterminal.Receipt, error) {
	if state.Ready {
		running, err := r.probe(ctx, state)
		if err == nil && running {
			return state.Receipt.Clone(), nil
		}
		info, inspectErr := r.engine.execInspect(ctx, state.BackendBrokerExecID)
		if inspectErr != nil || info.containerID != state.BackendContainerID {
			return providerterminal.Receipt{}, terminalUnknown(ctx, inspectErr)
		}
		if !info.running {
			return providerterminal.Receipt{}, providerterminal.ErrTerminalNotFound
		}
		return providerterminal.Receipt{}, providerterminal.ErrAllocationUnknown
	}
	if state.BackendBrokerExecID == "" {
		return providerterminal.Receipt{}, providerterminal.ErrAllocationUnknown
	}
	return r.waitForBroker(ctx, statePath, state)
}

func (r *TerminalRuntime) waitForBroker(ctx context.Context, statePath string, state terminalState) (providerterminal.Receipt, error) {
	for {
		running, err := r.probe(ctx, state)
		if err == nil && running {
			state.Ready = true
			if err := persistTerminalState(statePath, state); err != nil {
				return providerterminal.Receipt{}, err
			}
			return state.Receipt.Clone(), nil
		}
		if errors.Is(err, providerterminal.ErrTerminalUnsupported) {
			return providerterminal.Receipt{}, err
		}
		info, inspectErr := r.engine.execInspect(ctx, state.BackendBrokerExecID)
		if inspectErr != nil || info.containerID != state.BackendContainerID {
			return providerterminal.Receipt{}, terminalUnknown(ctx, inspectErr)
		}
		if !info.running {
			if info.exitCode == terminalBrokerExitTool {
				return providerterminal.Receipt{}, providerterminal.ErrTerminalUnsupported
			}
			return providerterminal.Receipt{}, providerterminal.ErrTerminalNotFound
		}
		if err := waitContext(ctx, terminalReadyPoll); err != nil {
			return providerterminal.Receipt{}, errors.Join(providerterminal.ErrAllocationUnknown, err)
		}
	}
}

func (r *TerminalRuntime) Observe(ctx context.Context, receipt providerterminal.Receipt) (providerterminal.Observation, error) {
	if err := contextError(ctx); err != nil {
		return providerterminal.Observation{}, err
	}
	if r == nil || r.runtime == nil || r.engine == nil {
		return providerterminal.Observation{}, ErrInvalidDriver
	}
	if err := receipt.Validate(); err != nil {
		return providerterminal.Observation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.observeLocked(ctx, receipt)
}

func (r *TerminalRuntime) observeLocked(ctx context.Context, receipt providerterminal.Receipt) (providerterminal.Observation, error) {
	now := r.options.Clock.Now().UTC()
	observation := providerterminal.Observation{Receipt: receipt.Clone(), ObservedAt: now}
	if now.IsZero() {
		return providerterminal.Observation{}, providerterminal.ErrInvalidObservation
	}
	if !receipt.ExpiresAt.After(now) {
		observation.State = providerterminal.ObservationExpired
		return observation, observation.Validate()
	}
	_, statePath, err := r.stateLocationForReceipt(receipt)
	if err != nil {
		return providerterminal.Observation{}, err
	}
	state, err := loadTerminalState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		observation.State = providerterminal.ObservationAbsent
		return observation, observation.Validate()
	}
	if err != nil {
		return providerterminal.Observation{}, err
	}
	if !state.matchesReceipt(receipt) {
		return providerterminal.Observation{}, providerterminal.ErrTerminalConflict
	}
	operationCtx, cancel := r.runtime.operationContext(ctx)
	defer cancel()
	container, found, err := r.runtime.inspectOwnedID(operationCtx, receipt.SandboxID)
	if err != nil {
		if contextErr := terminalContextError(operationCtx, err); contextErr != nil {
			return providerterminal.Observation{}, contextErr
		}
		observation.State = providerterminal.ObservationOutcomeUnknown
		return observation, observation.Validate()
	}
	if !found {
		observation.State = providerterminal.ObservationAbsent
		return observation, observation.Validate()
	}
	if container.id != state.BackendContainerID {
		return providerterminal.Observation{}, providerterminal.ErrTerminalConflict
	}
	info, err := r.engine.execInspect(operationCtx, state.BackendBrokerExecID)
	if err != nil || info.containerID != state.BackendContainerID {
		if contextErr := terminalContextError(operationCtx, err); contextErr != nil {
			return providerterminal.Observation{}, contextErr
		}
		observation.State = providerterminal.ObservationOutcomeUnknown
		return observation, observation.Validate()
	}
	if !info.running {
		observation.State = providerterminal.ObservationAbsent
		return observation, observation.Validate()
	}
	running, err := r.probe(operationCtx, state)
	if err != nil || !running {
		if contextErr := terminalContextError(operationCtx, err); contextErr != nil {
			return providerterminal.Observation{}, contextErr
		}
		observation.State = providerterminal.ObservationOutcomeUnknown
	} else {
		observation.State = providerterminal.ObservationRunning
	}
	return observation, observation.Validate()
}

func (r *TerminalRuntime) Attach(ctx context.Context, receipt providerterminal.Receipt) (providerterminal.Stream, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.runtime == nil || r.engine == nil {
		return nil, ErrInvalidDriver
	}
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	observation, err := r.observeLocked(ctx, receipt)
	if err != nil {
		return nil, err
	}
	switch observation.State {
	case providerterminal.ObservationExpired:
		return nil, providerterminal.ErrTerminalExpired
	case providerterminal.ObservationAbsent:
		return nil, providerterminal.ErrTerminalNotFound
	case providerterminal.ObservationOutcomeUnknown:
		return nil, providerterminal.ErrAllocationUnknown
	case providerterminal.ObservationRunning:
	default:
		return nil, providerterminal.ErrInvalidObservation
	}
	_, statePath, err := r.stateLocationForReceipt(receipt)
	if err != nil {
		return nil, err
	}
	state, err := loadTerminalState(statePath)
	if err != nil {
		return nil, err
	}
	operationCtx, cancel := r.runtime.operationContext(ctx)
	defer cancel()
	execID, err := r.engine.execCreate(operationCtx, state.BackendContainerID, r.commandRequest(r.connectCommand(state), true))
	if err != nil || execID == "" {
		return nil, terminalUnknown(operationCtx, err)
	}
	connection, err := r.engine.execAttachTerminal(operationCtx, execID)
	if err != nil {
		return nil, terminalUnknown(operationCtx, err)
	}
	return &dockerTerminalStream{connection: connection}, nil
}

func (r *TerminalRuntime) Cleanup(ctx context.Context, receipt providerterminal.Receipt) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if r == nil || r.runtime == nil || r.engine == nil {
		return ErrInvalidDriver
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	directory, statePath, err := r.stateLocationForReceipt(receipt)
	if err != nil {
		return err
	}
	state, err := loadTerminalState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !state.matchesReceipt(receipt) {
		return providerterminal.ErrTerminalConflict
	}
	operationCtx, cancel := r.runtime.operationContext(ctx)
	defer cancel()
	container, found, err := r.runtime.inspectOwnedID(operationCtx, receipt.SandboxID)
	if err != nil {
		return terminalUnknown(operationCtx, err)
	}
	if found {
		if container.id != state.BackendContainerID {
			return providerterminal.ErrTerminalConflict
		}
		exitCode, commandErr := r.runCommand(operationCtx, state.BackendContainerID, r.stopCommand(state))
		if commandErr != nil {
			return commandErr
		}
		if exitCode != 0 && exitCode != terminalBrokerExitGone {
			return providerterminal.ErrAllocationUnknown
		}
		if state.BackendBrokerExecID != "" {
			for {
				info, inspectErr := r.engine.execInspect(operationCtx, state.BackendBrokerExecID)
				if inspectErr != nil {
					return providerterminal.ErrAllocationUnknown
				}
				if !info.running {
					break
				}
				if err := waitContext(operationCtx, terminalCommandPoll); err != nil {
					return errors.Join(providerterminal.ErrAllocationUnknown, err)
				}
			}
		}
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(directoryFile.Sync(), directoryFile.Close())
}

func (r *TerminalRuntime) probe(ctx context.Context, state terminalState) (bool, error) {
	exitCode, err := r.runCommand(ctx, state.BackendContainerID, r.probeCommand(state))
	if err != nil {
		return false, err
	}
	switch exitCode {
	case 0:
		return true, nil
	case terminalBrokerExitGone:
		return false, nil
	case terminalBrokerExitTool:
		return false, providerterminal.ErrTerminalUnsupported
	default:
		return false, providerterminal.ErrAllocationUnknown
	}
}

func (r *TerminalRuntime) runCommand(ctx context.Context, containerID string, command []string) (int, error) {
	execID, err := r.engine.execCreate(ctx, containerID, r.commandRequest(command, false))
	if err != nil || execID == "" {
		return 0, terminalUnknown(ctx, err)
	}
	if err := r.engine.execStart(ctx, execID, true); err != nil {
		return 0, terminalUnknown(ctx, err)
	}
	for {
		info, err := r.engine.execInspect(ctx, execID)
		if err != nil || info.containerID != containerID {
			return 0, terminalUnknown(ctx, err)
		}
		if !info.running {
			return info.exitCode, nil
		}
		if err := waitContext(ctx, terminalCommandPoll); err != nil {
			return 0, err
		}
	}
}

func (r *TerminalRuntime) commandRequest(command []string, attached bool) execCreateRequest {
	return execCreateRequest{
		user: r.runtime.options.User, workingDirectory: "/workspace", command: append([]string(nil), command...),
		environment: []string{"HOME=/workspace", "SHELL=" + r.options.ShellPath, "TERM=xterm-256color"},
		attachStdin: attached, attachStdout: attached, attachStderr: attached, tty: attached,
	}
}

func (r *TerminalRuntime) serveCommand(state terminalState) []string {
	return []string{r.options.BrokerPath, "serve", "--socket", state.BrokerSocketPath, "--shell", r.options.ShellPath, "--working-directory", state.Request.WorkingDirectory}
}

func (r *TerminalRuntime) connectCommand(state terminalState) []string {
	return []string{r.options.BrokerPath, "connect", "--socket", state.BrokerSocketPath}
}

func (r *TerminalRuntime) probeCommand(state terminalState) []string {
	return []string{r.options.BrokerPath, "probe", "--socket", state.BrokerSocketPath}
}

func (r *TerminalRuntime) stopCommand(state terminalState) []string {
	return []string{r.options.BrokerPath, "stop", "--socket", state.BrokerSocketPath}
}

func (r *TerminalRuntime) stateLocation(request providerterminal.AllocationRequest) (string, string, error) {
	paths, err := r.runtime.mountPaths(request.SandboxID)
	if err != nil {
		return "", "", err
	}
	directory := filepath.Join(paths.root, "terminal")
	return directory, filepath.Join(directory, terminalToken(request.SandboxID, request.RuntimeSessionID)+".json"), nil
}

func (r *TerminalRuntime) stateLocationForReceipt(receipt providerterminal.Receipt) (string, string, error) {
	return r.stateLocation(providerterminal.AllocationRequest{SandboxID: receipt.SandboxID, RuntimeSessionID: receipt.RuntimeSessionID})
}

type dockerTerminalStream struct {
	connection terminalConnection
	readMu     sync.Mutex
	writeMu    sync.Mutex
	closeOnce  sync.Once
}

func (s *dockerTerminalStream) Read(ctx context.Context, value []byte) (int, error) {
	if s == nil || s.connection == nil {
		return 0, net.ErrClosed
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	stop, fired := interruptOnCancellation(ctx, s.connection.SetReadDeadline)
	count, err := s.connection.Read(value)
	stopAndClearDeadline(stop, fired, s.connection.SetReadDeadline)
	if normalized := terminalStreamContextError(ctx, err); normalized != nil {
		return count, normalized
	}
	return count, err
}

func (s *dockerTerminalStream) Write(ctx context.Context, value []byte) (int, error) {
	if s == nil || s.connection == nil {
		return 0, net.ErrClosed
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	stop, fired := interruptOnCancellation(ctx, s.connection.SetWriteDeadline)
	count, err := s.connection.Write(value)
	stopAndClearDeadline(stop, fired, s.connection.SetWriteDeadline)
	if normalized := terminalStreamContextError(ctx, err); normalized != nil {
		return count, normalized
	}
	return count, err
}

func (s *dockerTerminalStream) Close() error {
	if s == nil || s.connection == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() { err = s.connection.Close() })
	return err
}

func interruptOnCancellation(ctx context.Context, setDeadline func(time.Time) error) (func() bool, <-chan struct{}) {
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = setDeadline(time.Now())
		close(fired)
	})
	if deadline, ok := ctx.Deadline(); ok {
		_ = setDeadline(deadline)
	} else {
		_ = setDeadline(time.Time{})
	}
	return stop, fired
}

func stopAndClearDeadline(stop func() bool, fired <-chan struct{}, setDeadline func(time.Time) error) {
	if !stop() {
		<-fired
	}
	_ = setDeadline(time.Time{})
}

func terminalStreamContextError(ctx context.Context, streamErr error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var netErr net.Error
	if errors.As(streamErr, &netErr) && netErr.Timeout() {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return nil
}

func terminalUnknown(ctx context.Context, cause error) error {
	if contextErr := terminalContextError(ctx, cause); contextErr != nil {
		return errors.Join(providerterminal.ErrAllocationUnknown, contextErr)
	}
	return providerterminal.ErrAllocationUnknown
}

func terminalContextError(ctx context.Context, cause error) error {
	if errors.Is(cause, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return contextError(ctx)
}

func terminalToken(sandboxID, runtimeSessionID string) string {
	digest := sha256.Sum256([]byte(sandboxID + "\x00" + runtimeSessionID))
	return hex.EncodeToString(digest[:16])
}

func terminalSocketPath(token string) string {
	return "/tmp/sandbox-runtime-terminal-" + token + ".sock"
}

func validGuestExecutable(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
		for _, char := range component {
			if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ providerterminal.Runtime = (*TerminalRuntime)(nil)
