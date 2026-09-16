package qualificationsupervisor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

var ErrEvidence = errors.New("adapter supervisor evidence unavailable or invalid")

// PhaseEvidence is a defensive, sanitized snapshot of one adapter process.
// It contains no OS PID, path, endpoint, credential, raw invocation, stdout or
// stderr. Release identities remain assertions made by the adapter process.
// This is component evidence, not an external-caller qualification result.
type PhaseEvidence struct {
	PhaseID                string
	InvocationID           string
	ProcessIdentity        string
	ExecutableDigest       string
	ConfigurationDigest    string
	StartupIdentity        protocol.StartupIdentity
	Delivery               DeliveryStats
	AdapterStderrWireBytes int64
}

// newProcessIdentity mints an opaque supervisor label which is retained and
// published only for an actually started and cleanly completed child. It
// deliberately cannot be reversed into an OS PID or backend ID.
func newProcessIdentity() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", ErrEvidence
	}
	return "adapter-process-" + hex.EncodeToString(entropy[:]), nil
}

func clonePhaseEvidence(value PhaseEvidence) PhaseEvidence {
	value.StartupIdentity = protocol.CloneStartupIdentity(value.StartupIdentity)
	return value
}

// Evidence returns a snapshot only after this exact child reached a valid
// terminal, stdout EOF, bounded stderr EOF and an observed zero exit/reap.
func (p *StartedProcess) Evidence() (PhaseEvidence, bool) {
	if p == nil || p.core == nil {
		return PhaseEvidence{}, false
	}
	p.core.protocolMu.Lock()
	defer p.core.protocolMu.Unlock()
	if !p.core.evidenceReady || !p.core.cleanlyReaped() {
		return PhaseEvidence{}, false
	}
	return clonePhaseEvidence(p.core.evidence), true
}

// FinalizeTranscript binds the actual adapter facts retained for both phases
// into the locked transcript projection. Provider, external-caller and Gateway
// facts in the arguments are supplied by the outer process supervisor; this
// adapter supervisor does not independently establish them. The adapter fields
// and byte counts cannot be overridden by those inputs.
//
// Finalization is one-shot, including a failed attempt, so one run cannot mint
// competing transcript narratives. The result is protocol/process component
// evidence only; scenario outcomes still require independent observers.
func (f *FrozenPreflight) FinalizeTranscript(initial, reconstruction protocol.TranscriptSupervisorPhase) (protocol.TranscriptProjection, error) {
	if f == nil || f.core == nil {
		return protocol.TranscriptProjection{}, ErrEvidence
	}
	c := f.core
	if c.transcriptAttempted || c.failure != nil || c.closed {
		return protocol.TranscriptProjection{}, ErrEvidence
	}
	c.transcriptAttempted = true
	initialEvidence, initialOK := c.evidence["initial"]
	reconstructionEvidence, reconstructionOK := c.evidence["reconstruction"]
	if !initialOK || !reconstructionOK || !matchesAdapterEvidence(initial, initialEvidence) ||
		!matchesAdapterEvidence(reconstruction, reconstructionEvidence) {
		c.failure = ErrEvidence
		return protocol.TranscriptProjection{}, ErrEvidence
	}
	projection, err := c.run.ProjectTranscript(&initial, &reconstruction)
	if err != nil {
		c.failure = ErrEvidence
		return protocol.TranscriptProjection{}, ErrEvidence
	}
	stored := cloneTranscriptProjection(projection)
	c.transcript = &stored
	return cloneTranscriptProjection(stored), nil
}

func matchesAdapterEvidence(input protocol.TranscriptSupervisorPhase, evidence PhaseEvidence) bool {
	return input.ProcessIdentities.QualificationAdapter == evidence.ProcessIdentity &&
		input.ExecutableDigests.QualificationAdapter == evidence.ExecutableDigest &&
		input.ConfigurationDigests.QualificationAdapter == evidence.ConfigurationDigest &&
		input.StderrWireBytes == evidence.AdapterStderrWireBytes &&
		input.CredentialPayloadTotalBytes == evidence.Delivery.CredentialPayloadBytes
}

func cloneTranscriptProjection(value protocol.TranscriptProjection) protocol.TranscriptProjection {
	value.Document = append([]byte(nil), value.Document...)
	return value
}

// Transcript returns the finalized canonical projection without exposing the
// stored byte slice. It is unavailable before successful finalization.
func (f *FrozenPreflight) Transcript() (protocol.TranscriptProjection, bool) {
	if f == nil || f.core == nil || f.core.transcript == nil {
		return protocol.TranscriptProjection{}, false
	}
	return cloneTranscriptProjection(*f.core.transcript), true
}
