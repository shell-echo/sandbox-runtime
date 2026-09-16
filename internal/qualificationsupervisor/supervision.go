package qualificationsupervisor

import (
	"context"
	"errors"
	"time"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

var ErrSupervision = errors.New("adapter process supervision failed")

type outputReadResult struct {
	message protocol.DecodedMessage
	err     error
}

// ObserveCompletion exclusively consumes post-invocation stdout, applies the
// locked phase state machine and case deadlines, observes stdout EOF, and only
// then performs a bounded monotonic wait for the real child exit. Stderr is
// drained concurrently from process start and only its bounded byte count is
// retained. This returns protocol/process component evidence, not a scenario
// result or external-caller qualification outcome.
func (p *StartedProcess) ObserveCompletion(ctx context.Context) error {
	if p == nil || p.core == nil {
		return ErrSupervision
	}
	core := p.core
	core.protocolMu.Lock()
	defer core.protocolMu.Unlock()
	if ctx == nil || core.isStopping() || !core.deliveryComplete || core.decoder == nil || core.codec == nil ||
		core.admission.machine.State() != protocol.PhaseStateAwaitingInvocationAcceptance {
		return failSupervision(core, ErrSupervision)
	}
	operationContext, release, err := clippedContext(core.runContext, ctx)
	if err != nil {
		return failSupervision(core, err)
	}
	defer release()

	machine := core.admission.machine
	var caseDeadline time.Time
	stderrDone := core.stderrDone
	for machine.State() != protocol.PhaseStateTerminalObserved {
		result, failure := core.nextOutput(operationContext, caseDeadline, stderrDone)
		if failure != nil {
			return failSupervision(core, failure)
		}
		if _, stderrErr, done := core.stderrResult(); done {
			stderrDone = nil
			if stderrErr != nil {
				return failSupervision(core, stderrErr)
			}
		}
		if result.err != nil {
			return failSupervision(core, result.err)
		}
		if err := deadlineFailure(operationContext, caseDeadline, time.Now()); err != nil {
			return failSupervision(core, err)
		}

		state := machine.State()
		switch result.message.MessageType {
		case "invocation_accepted":
			if state != protocol.PhaseStateAwaitingInvocationAcceptance {
				return failSupervision(core, ErrSupervision)
			}
			err = machine.AcceptInvocationAccepted(result.message)
		case "scenario_started":
			err = machine.AcceptScenarioStarted(result.message)
		case "scenario_result":
			err = machine.AcceptScenarioResult(result.message)
		case "invocation_finished", "protocol_error":
			err = machine.AcceptTerminal(result.message)
		default:
			err = ErrSupervision
		}
		if err != nil {
			return failSupervision(core, err)
		}
		caseDeadline = advanceCaseDeadline(result.message.MessageType, machine.State(), caseDeadline, time.Now())
	}

	if err := core.observeEOF(operationContext, stderrDone); err != nil {
		return failSupervision(core, err)
	}
	if err := core.observeExit(operationContext, machine, stderrDone); err != nil {
		return failSupervision(core, err)
	}
	stderrBytes, stderrErr, stderrComplete := core.stderrResult()
	if !stderrComplete || stderrErr != nil || !core.finishProtocol(stderrBytes) {
		return failSupervision(core, ErrSupervision)
	}
	return nil
}

func advanceCaseDeadline(messageType string, state protocol.PhaseState, current, boundary time.Time) time.Time {
	switch messageType {
	case "invocation_accepted":
		return boundary.Add(caseExecutionLimit)
	case "scenario_result":
		if state == protocol.PhaseStateAwaitingNextScenario {
			return boundary.Add(caseExecutionLimit)
		}
		return time.Time{}
	case "invocation_finished", "protocol_error":
		return time.Time{}
	default:
		return current
	}
}

func (p *processCore) nextOutput(ctx context.Context, caseDeadline time.Time, stderrDone <-chan struct{}) (outputReadResult, error) {
	result := make(chan outputReadResult, 1)
	go func() {
		message, err := p.decoder.Next()
		result <- outputReadResult{message: message, err: err}
	}()
	deadline := effectiveDeadline(ctx, caseDeadline)
	timer, stop := deadlineTimer(deadline)
	defer stop()
	for {
		select {
		case observed := <-result:
			if err := deadlineFailure(ctx, caseDeadline, time.Now()); err != nil {
				return outputReadResult{}, err
			}
			return observed, nil
		case <-timer:
			return outputReadResult{}, context.DeadlineExceeded
		case <-ctx.Done():
			return outputReadResult{}, contextFailure(ctx)
		case <-p.stopping:
			return outputReadResult{}, p.stoppingFailure()
		case <-stderrDone:
			_, err, _ := p.stderrResult()
			if err != nil {
				return outputReadResult{}, err
			}
			stderrDone = nil
		}
	}
}

func (p *processCore) observeEOF(ctx context.Context, stderrDone <-chan struct{}) error {
	result := make(chan error, 1)
	go func() { result <- p.admission.machine.ObserveStdoutEOF() }()
	deadline, _ := ctx.Deadline()
	timer, stop := deadlineTimer(deadline)
	defer stop()
	for {
		select {
		case err := <-result:
			if failure := deadlineFailure(ctx, time.Time{}, time.Now()); failure != nil {
				return failure
			}
			return err
		case <-timer:
			return context.DeadlineExceeded
		case <-ctx.Done():
			return contextFailure(ctx)
		case <-p.stopping:
			return p.stoppingFailure()
		case <-stderrDone:
			_, err, _ := p.stderrResult()
			if err != nil {
				return err
			}
			stderrDone = nil
		}
	}
}

func (p *processCore) observeExit(ctx context.Context, machine *protocol.PhaseStateMachine, stderrDone <-chan struct{}) error {
	deadline, _ := ctx.Deadline()
	timer, stop := deadlineTimer(deadline)
	defer stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		exited, success, err := p.pollExit()
		observedAt := time.Now()
		if failure := deadlineFailure(ctx, time.Time{}, observedAt); failure != nil {
			return failure
		}
		if err != nil {
			return err
		}
		if exited {
			if err := machine.ObserveProcessExit(success); err != nil {
				return err
			}
			break
		}
		select {
		case <-ticker.C:
		case <-timer:
			return context.DeadlineExceeded
		case <-ctx.Done():
			return contextFailure(ctx)
		case <-p.stopping:
			return p.stoppingFailure()
		case <-stderrDone:
			_, err, _ := p.stderrResult()
			if err != nil {
				return err
			}
			stderrDone = nil
		}
	}

	if stderrDone != nil {
		select {
		case <-stderrDone:
		case <-timer:
			return context.DeadlineExceeded
		case <-ctx.Done():
			return contextFailure(ctx)
		case <-p.stopping:
			return p.stoppingFailure()
		}
	}
	if _, err, done := p.stderrResult(); !done || err != nil {
		if err != nil {
			return err
		}
		return ErrProcessIO
	}
	if err := p.closeParentIO(); err != nil {
		return err
	}
	return deadlineFailure(ctx, time.Time{}, time.Now())
}

func (p *processCore) stoppingFailure() error {
	if _, err, done := p.stderrResult(); done && err != nil {
		return err
	}
	if failure := contextFailure(p.runContext); failure != nil {
		return failure
	}
	return ErrSupervision
}

func failSupervision(core *processCore, cause error) error {
	if cause == nil {
		cause = ErrSupervision
	}
	result := errors.Join(ErrSupervision, cause)
	core.admission.owner.failure = result
	return errors.Join(result, core.close())
}

func deadlineTimer(deadline time.Time) (<-chan time.Time, func()) {
	if deadline.IsZero() {
		return make(chan time.Time), func() {}
	}
	timer := time.NewTimer(time.Until(deadline))
	return timer.C, func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}
