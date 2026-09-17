package qualificationsupervisor

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

var (
	ErrProcessStart       = errors.New("adapter process start failed")
	ErrProcessIO          = errors.New("adapter process output read failed")
	ErrProcessCleanup     = errors.New("adapter process cleanup failed")
	ErrProcessReapTimeout = errors.New("adapter process reap incomplete")
)

const processCleanupLimit = 5 * time.Second

type processCore struct {
	admission  *PhaseAdmission
	process    *os.Process
	pid        int
	identity   string
	parent     [3 + launchCredentialSlots]*os.File
	runContext context.Context

	protocolMu sync.Mutex
	lifecycle  sync.Mutex
	procMu     sync.Mutex
	stopping   chan struct{}
	done       chan struct{}

	cleanupStarted, finalized           bool
	cleanupErr                          error // protected by lifecycle; immutable after done
	reaped, exitSuccess                 bool  // protected by procMu
	protocolComplete                    bool  // protected by lifecycle
	backgroundReapOnce                  sync.Once
	stderrMu                            sync.Mutex
	stderrBytes                         int64
	stderrErr                           error
	stderrDone                          chan struct{}
	startupAttempted, startupValidated  bool
	startup                             protocol.StartupIdentity
	codec                               *protocol.Codec
	decoder                             *protocol.OutputDecoder
	deliveryAttempted, deliveryComplete bool
	delivery                            DeliveryStats
	invocationID                        string
	evidence                            PhaseEvidence
	evidenceReady                       bool
	terminalErrorCode                   string
}

// StartedProcess owns an actual local child, not qualification evidence. Copies
// share one lifetime. Close may race a blocked protocol operation; other
// preflight/phase APIs retain their single-owner restriction.
type StartedProcess struct{ core *processCore }

// ProcessIdentity returns the supervisor-minted opaque label for this started
// child. It is not an OS PID and becomes evidence only after successful
// terminal/EOF/exit supervision.
func (p *StartedProcess) ProcessIdentity() string {
	if p == nil || p.core == nil {
		return ""
	}
	return p.core.identity
}

// TerminalErrorCode returns the closed public adapter error classification
// after supervision has observed a valid protocol_error terminal.
func (p *StartedProcess) TerminalErrorCode() string {
	if p == nil || p.core == nil {
		return ""
	}
	p.core.protocolMu.Lock()
	defer p.core.protocolMu.Unlock()
	return p.core.terminalErrorCode
}

// StartProcess consumes a prepared topology exactly once. It rechecks custody,
// uses explicit argv/env/cwd/files (no shell or inherited environment), creates
// a new process group, starts bounded stderr drainage, and closes the parent's
// copies of all child endpoints. The run parent and immutable 1,800-second
// deadline were bound before the first preflight read; this method's context
// can shorten only process-start work and cannot reset the shared run budget.
// Exec/cwd resolution still relies on trusted namespace custody and healthy
// local filesystem syscalls; prechecks are not an atomic pathname/exec bind.
func StartProcess(ctx context.Context, launch *PreparedLaunch) (_ *StartedProcess, resultErr error) {
	if !supportedPlatform(runtime.GOOS) {
		return nil, ErrUnsupportedPlatform
	}
	if launch == nil || launch.core == nil || launch.core.closed {
		return nil, ErrProcessStart
	}
	l := launch.core
	defer func() {
		if resultErr != nil {
			_ = l.close()
			l.admission.owner.failure = resultErr
		}
	}()
	if ctx == nil {
		return nil, ErrProcessStart
	}
	runContext, err := l.admission.owner.budget.context()
	if err != nil {
		return nil, err
	}
	startContext, release, err := clippedContext(runContext, ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := launch.Recheck(startContext); err != nil {
		if failure := contextFailure(startContext); failure != nil {
			return nil, failure
		}
		return nil, ErrProcessStart
	}
	identity, err := newProcessIdentity()
	if err != nil {
		return nil, ErrProcessStart
	}
	child, err := spawnProcess(l)
	if err != nil {
		return nil, ErrProcessStart
	}
	p := &processCore{
		admission: l.admission, process: child, pid: child.Pid, identity: identity, parent: l.parent, runContext: runContext,
		stopping: make(chan struct{}), done: make(chan struct{}), stderrDone: make(chan struct{}),
	}
	// Transfer before any post-start failure: the frozen owner always retains
	// a recovery handle, including when bounded cleanup reports incomplete.
	l.admission.owner.process = p
	var handoffErr error
	for i, file := range l.child {
		if file.Close() != nil {
			handoffErr = ErrProcessCleanup
		}
		l.child[i], l.parent[i] = nil, nil
	}
	l.closed = true
	p.startStderrDrain()
	operationFailure := ctx.Err()
	if operationFailure == nil {
		operationFailure = contextFailure(startContext)
	}
	if handoffErr != nil || operationFailure != nil {
		cleanupErr := p.close()
		return nil, errors.Join(ErrProcessStart, handoffErr, operationFailure, cleanupErr)
	}
	go func() {
		select {
		case <-runContext.Done():
			_ = p.close()
		case <-p.done:
		}
	}()
	return &StartedProcess{core: p}, nil
}

func (p *processCore) startStderrDrain() {
	go func() {
		count, err := io.CopyN(io.Discard, processOutput{p.parent[2]}, protocol.MaxAdapterStderrBytes+1)
		if count > protocol.MaxAdapterStderrBytes {
			err = ErrProcessIO
		} else if errors.Is(err, io.EOF) {
			err = nil
		} else if p.isStopping() {
			// Supervisor-initiated close is the first cleanup action and is
			// therefore an expected way to unblock the private drain.
			err = nil
		} else if err != nil {
			err = ErrProcessIO
		}
		p.stderrMu.Lock()
		p.stderrBytes, p.stderrErr = count, err
		p.stderrMu.Unlock()
		close(p.stderrDone)
		if err != nil {
			_ = p.close()
		}
	}()
}

func (p *processCore) stderrResult() (int64, error, bool) {
	select {
	case <-p.stderrDone:
		p.stderrMu.Lock()
		defer p.stderrMu.Unlock()
		return p.stderrBytes, p.stderrErr, true
	default:
		return 0, nil, false
	}
}

func (p *processCore) isStopping() bool {
	select {
	case <-p.stopping:
		return true
	default:
		return false
	}
}

func (p *processCore) cleanlyReaped() bool {
	select {
	case <-p.done:
		p.lifecycle.Lock()
		complete := p.finalized && p.cleanupErr == nil && p.protocolComplete
		p.lifecycle.Unlock()
		p.procMu.Lock()
		reaped := p.reaped && p.exitSuccess
		p.procMu.Unlock()
		return complete && reaped
	default:
		return false
	}
}

func (p *processCore) pollExit() (bool, bool, error) {
	p.procMu.Lock()
	defer p.procMu.Unlock()
	if p.reaped {
		return true, p.exitSuccess, nil
	}
	exited, success, err := pollProcessExit(p.process, p.pid)
	if err != nil {
		return false, false, ErrProcessCleanup
	}
	if exited {
		p.reaped, p.exitSuccess = true, success
	}
	return exited, success, nil
}

func (p *processCore) beginCleanup() bool {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	if p.finalized || p.cleanupStarted {
		return false
	}
	p.cleanupStarted = true
	close(p.stopping)
	return true
}

func (p *processCore) publishCleanup(err error) {
	p.lifecycle.Lock()
	p.cleanupErr = err
	p.finalized = true
	close(p.done)
	p.lifecycle.Unlock()
}

func (p *processCore) finishProtocol(stderrBytes int64) bool {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	owner := p.admission.owner
	if p.finalized || p.cleanupStarted || owner == nil || p.identity == "" || p.invocationID == "" ||
		!p.startupValidated || !p.deliveryComplete || stderrBytes < 0 ||
		stderrBytes > protocol.MaxAdapterStderrBytes || owner.executable == nil ||
		!validDigest(owner.executable.digest) || !validDigest(owner.digest) ||
		p.admission.machine.State() != protocol.PhaseStateComplete {
		return false
	}
	if _, exists := owner.evidence[p.admission.phase]; exists {
		return false
	}
	evidence := PhaseEvidence{
		PhaseID:                p.admission.phase,
		InvocationID:           p.invocationID,
		ProcessIdentity:        p.identity,
		ExecutableDigest:       owner.executable.digest,
		ConfigurationDigest:    owner.digest,
		StartupIdentity:        protocol.CloneStartupIdentity(p.startup),
		Delivery:               p.delivery,
		AdapterStderrWireBytes: stderrBytes,
	}
	p.evidence = clonePhaseEvidence(evidence)
	p.evidenceReady = true
	owner.evidence[p.admission.phase] = clonePhaseEvidence(evidence)
	p.protocolComplete = true
	p.finalized = true
	close(p.done)
	return true
}

func (p *processCore) resultError() error {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	return p.cleanupErr
}

func (p *processCore) closeParentIOExceptStderr() error {
	var result error
	for index, file := range p.parent {
		// Keep the private stderr reader open until the child has been
		// terminated and its buffered output has reached EOF. Closing it here
		// races the drain goroutine and can silently discard already-written
		// evidence bytes.
		if index == 2 {
			continue
		}
		if file != nil {
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				result = ErrProcessCleanup
			}
		}
	}
	return result
}

func (p *processCore) closeStderr() error {
	file := p.parent[2]
	if file == nil {
		return nil
	}
	if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return ErrProcessCleanup
	}
	return nil
}

func (p *processCore) closeParentIO() error {
	return errors.Join(p.closeParentIOExceptStderr(), p.closeStderr())
}

func (p *processCore) close() error {
	if !p.beginCleanup() {
		<-p.done
		return p.resultError()
	}
	cleanup, cancel := context.WithTimeout(context.Background(), processCleanupLimit)
	defer cancel()
	deadline, _ := cleanup.Deadline()
	result := p.closeParentIOExceptStderr()

	p.procMu.Lock()
	needsGroupAbsence := false
	if !p.reaped {
		var terminateErr error
		needsGroupAbsence, terminateErr = terminateProcess(p.process, p.pid)
		if terminateErr != nil {
			result = errors.Join(result, ErrProcessCleanup)
		}
	}
	p.procMu.Unlock()

	for {
		exited, _, err := p.pollExit()
		now := time.Now()
		if !now.Before(deadline) {
			result = errors.Join(result, ErrProcessReapTimeout)
			p.startBackgroundReap()
			break
		}
		if err != nil {
			result = errors.Join(result, err)
			p.startBackgroundReap()
			break
		}
		if exited {
			if needsGroupAbsence && !processGroupAbsent(p.pid) {
				result = errors.Join(result, ErrProcessCleanup)
			}
			break
		}
		select {
		case <-cleanup.Done():
			result = errors.Join(result, ErrProcessReapTimeout)
			p.startBackgroundReap()
			goto complete
		case <-time.After(time.Millisecond):
		}
	}

complete:
	select {
	case <-p.stderrDone:
		if _, err, _ := p.stderrResult(); err != nil {
			result = errors.Join(result, err)
		}
	case <-cleanup.Done():
		result = errors.Join(result, ErrProcessReapTimeout)
	}
	result = errors.Join(result, p.closeStderr())
	p.publishCleanup(result)
	return result
}

func (p *processCore) startBackgroundReap() {
	p.backgroundReapOnce.Do(func() {
		go func() {
			p.procMu.Lock()
			defer p.procMu.Unlock()
			if p.reaped {
				return
			}
			state, err := p.process.Wait()
			if err == nil && state != nil {
				p.reaped, p.exitSuccess = true, state.Success()
			}
		}()
	})
}

type processOutput struct{ file *os.File }

func (r processOutput) Read(b []byte) (int, error) {
	if r.file == nil {
		return 0, ErrProcessIO
	}
	n, err := r.file.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, ErrProcessIO
	}
	return n, err
}

// Close closes I/O, kills the original group (and direct child if it escaped),
// then polls and reaps under a separate five-second bound. Nil means cleanup
// completed, not that the protocol completed. A later background Wait remains
// attached after a bounded reap timeout so the owned child is not abandoned.
// Process-group kill does not contain descendants that escape the group.
func (p *StartedProcess) Close() error {
	if p == nil || p.core == nil {
		return nil
	}
	return p.core.close()
}
