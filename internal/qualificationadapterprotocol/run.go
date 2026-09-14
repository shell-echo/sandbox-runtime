package qualificationadapterprotocol

import (
	"bytes"

	"github.com/gowebpki/jcs"
)

// RunStateMachine allocates exactly two fresh phase machines in profile order.
// It is single-owner, like PhaseStateMachine. A phase permit is a logical gate;
// the supervisor must obtain it before starting the corresponding process.
// Complete means protocol completion, including valid error terminals, not a
// passed qualification or proof that a real process ran.
type RunStateMachine struct {
	initial        *PhaseStateMachine
	reconstruction *PhaseStateMachine
	failure        error
}

func NewRunStateMachine() *RunStateMachine { return &RunStateMachine{} }

// BeginPhase grants each phase once. Reconstruction cannot be granted until
// initial has observed terminal, stdout EOF, and a supplied clean exit.
func (r *RunStateMachine) BeginPhase(phase string) (*PhaseStateMachine, error) {
	if r == nil {
		return nil, stateFailure(StateFailureInvalidOrder)
	}
	if err := r.firstFailure(); err != nil {
		return nil, err
	}
	if phase == "initial" && r.initial == nil {
		r.initial = NewPhaseStateMachine()
		r.initial.expectedPhase = phase
		return r.initial, nil
	}
	if phase == "reconstruction" && r.initial != nil && r.initial.State() == PhaseStateComplete && r.reconstruction == nil {
		r.reconstruction = NewPhaseStateMachine()
		r.reconstruction.expectedPhase = phase
		r.reconstruction.priorPhase = r.initial
		return r.reconstruction, nil
	}
	err := stateFailure(StateFailureInvalidOrder)
	if !r.Complete() {
		r.failure = err
		for _, m := range []*PhaseStateMachine{r.initial, r.reconstruction} {
			if m != nil && m.State() != PhaseStateComplete {
				m.fail(StateFailureInvalidOrder)
			}
		}
	}
	return nil, err
}

// Complete reports both protocol phases completed; it assigns no run outcome.
func (r *RunStateMachine) Complete() bool {
	return r != nil && r.firstFailure() == nil && r.initial != nil && r.reconstruction != nil &&
		r.initial.State() == PhaseStateComplete && r.reconstruction.State() == PhaseStateComplete
}

func (r *RunStateMachine) firstFailure() error {
	if r.failure != nil {
		return r.failure
	}
	for _, m := range []*PhaseStateMachine{r.initial, r.reconstruction} {
		if m != nil && m.failure != nil {
			r.failure = m.failure
			return r.failure
		}
	}
	return nil
}

func (m *PhaseStateMachine) startupMatchesPrior(message DecodedMessage) bool {
	if m.priorPhase == nil {
		return true
	}
	prior := m.priorPhase
	if prior.State() != PhaseStateComplete || message.outputDecoder == prior.decoder ||
		!decodedEnvelopeIntact(prior.startup) {
		return false
	}
	left, err := jcs.Transform(prior.startup.Document)
	if err != nil {
		return false
	}
	right, err := jcs.Transform(message.Document)
	return err == nil && bytes.Equal(left, right)
}
