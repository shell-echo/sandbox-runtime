package qualificationharness

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/evidencefiles"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

var ErrEvidenceFinalization = errors.New("qualification evidence finalization failed")

// EvidenceSnapshot is the complete sanitized d1-d6 state transferred to the
// evidence assembler after cleanup. It contains no state path, endpoint,
// credential, request, backend identifier, or caller correlation value.
type EvidenceSnapshot struct {
	RuntimeCommitmentDigest string
	ProfileID               string
	ProfileVersion          string
	ProfileDigest           string
	Runtime                 RuntimeObservation
	Limits                  qualificationprofile.RuntimeLimits
	CleanupPolicy           qualificationprofile.CleanupRequirements
	ReconstructionPolicy    qualificationprofile.ReconstructionRequirements
	ObservationPlan         []qualificationprofile.PhaseObservationPlan
	QueryScope              QueryScope
	Baseline                ResourceBaseline
	ExecutionStartedAt      time.Time
	ExecutionDeadlineAt     time.Time
	TotalDeadlineAt         time.Time
	Initial                 InitialPhaseResult
	Reconstruction          ReconstructionPhaseResult
	Observation             ExecutionObservationResult
	Cleanup                 CleanupResult
}

// EvidenceFinalizationResult is the bounded validator receipt projection that
// the harness cross-binds to its d1-d6 snapshot. Acceptance is a report/root
// consistency result, not external-caller independence or interoperability.
type EvidenceFinalizationResult struct {
	ReportID                   string
	InvocationID               string
	RuntimeCommitmentDigest    string
	ProfileID                  string
	ProfileVersion             string
	ProfileDigest              string
	InitialInvocationID        string
	ReconstructionInvocationID string
	ReportDigest               string
	PayloadInventoryDigest     string
	ReceiptFile                string
	RunOutcome                 string
	ValidationOutcome          string
	FileCount                  int
	TotalBytes                 int64
}

// EvidenceAssembler owns the local evidence-root write, closes its assembly
// descriptor, and invokes the locked validator as the only in-process writer
// during verification. The operator must separately stop every external writer
// before this call; an in-process interface cannot enforce same-UID exclusion.
type EvidenceAssembler interface {
	AssembleAndVerify(context.Context, EvidenceSnapshot) (EvidenceFinalizationResult, error)
}

// FinalizeEvidence consumes the sanitized d1-d6 state once and validates the
// assembler's receipt against that exact snapshot under the original total
// wall-clock deadline. It does not archive the root or attest provenance.
func FinalizeEvidence(ctx context.Context, prepared *PreparedRuntime, assembler EvidenceAssembler) (result EvidenceFinalizationResult, resultErr error) {
	if ctx == nil || prepared == nil || nilPort(assembler) {
		return EvidenceFinalizationResult{}, ErrEvidenceFinalization
	}
	if err := ctx.Err(); err != nil {
		return EvidenceFinalizationResult{}, errors.Join(ErrEvidenceFinalization, err)
	}
	snapshot, ok := prepared.beginEvidenceFinalization()
	if !ok {
		return EvidenceFinalizationResult{}, ErrEvidenceFinalization
	}
	defer func() { prepared.finishEvidenceFinalization(result) }()

	operationContext, cancel := context.WithDeadline(ctx, snapshot.TotalDeadlineAt)
	defer cancel()
	if err := operationContext.Err(); err != nil {
		return result, errors.Join(ErrEvidenceFinalization, err)
	}
	result, err := assembler.AssembleAndVerify(operationContext, cloneEvidenceSnapshot(snapshot))
	if err != nil || operationContext.Err() != nil {
		if operationContext.Err() != nil {
			return EvidenceFinalizationResult{}, errors.Join(ErrEvidenceFinalization, operationContext.Err())
		}
		return EvidenceFinalizationResult{}, ErrEvidenceFinalization
	}
	if !validEvidenceFinalizationResult(snapshot, result) {
		return EvidenceFinalizationResult{}, ErrEvidenceFinalization
	}
	return result, nil
}

func validEvidenceFinalizationResult(snapshot EvidenceSnapshot, result EvidenceFinalizationResult) bool {
	if !observerIDPattern.MatchString(result.ReportID) || !observerIDPattern.MatchString(result.InvocationID) ||
		result.RuntimeCommitmentDigest != snapshot.RuntimeCommitmentDigest || result.ProfileID != snapshot.ProfileID ||
		result.ProfileVersion != snapshot.ProfileVersion || result.ProfileDigest != snapshot.ProfileDigest ||
		result.InitialInvocationID != snapshot.Reconstruction.InitialInvocationID ||
		result.ReconstructionInvocationID != snapshot.Reconstruction.ReconstructionInvocationID ||
		!digestPattern.MatchString(result.ReportDigest) || !digestPattern.MatchString(result.PayloadInventoryDigest) ||
		result.ReceiptFile != "receipt.json" || result.ValidationOutcome != "accepted" || result.FileCount < 2 ||
		result.FileCount > evidencefiles.DefaultMaxFiles || result.TotalBytes <= 0 || result.TotalBytes > evidencefiles.DefaultMaxTotalBytes {
		return false
	}
	switch result.RunOutcome {
	case DerivedPassed:
		if snapshot.Cleanup.Outcome != CleanupOutcomeSucceeded {
			return false
		}
		for _, scenario := range snapshot.Observation.Scenarios {
			if scenario.Status != DerivedPassed {
				return false
			}
		}
	case DerivedFailed, DerivedIncomplete:
		// The report validator derives these from the assembled caller claims,
		// independent observations, identity completeness, and cleanup state.
	default:
		return false
	}
	return true
}

func (r *PreparedRuntime) beginEvidenceFinalization() (EvidenceSnapshot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.evidenceAttempted || r.evidenceActive || !r.closed || r.cleanupActive || r.cleanupResult == nil ||
		r.initialResult == nil || r.reconstructionResult == nil || r.executionObservation == nil ||
		!r.initialResult.TerminalObserved || !r.reconstructionResult.TerminalObserved ||
		len(r.initialResult.Scenarios) != 15 || len(r.reconstructionResult.Scenarios) != 5 ||
		len(r.executionObservation.Scenarios) != 20 || len(r.executionObservation.Observations) != 91 ||
		r.cleanupResult.Outcome == CleanupOutcomeNotRequired || r.cleanupResult.CleanupFinishedAt.IsZero() {
		return EvidenceSnapshot{}, false
	}
	r.evidenceAttempted = true
	r.evidenceActive = true
	return cloneEvidenceSnapshot(EvidenceSnapshot{
		RuntimeCommitmentDigest: r.digest, ProfileID: r.profileID, ProfileVersion: r.profileVersion, ProfileDigest: r.profileDigest,
		Runtime: cloneRuntimeObservation(r.observation), Limits: r.limits, CleanupPolicy: cloneCleanupRequirements(r.cleanup),
		ReconstructionPolicy: cloneReconstructionRequirements(r.reconstruction), ObservationPlan: cloneObservationPlan(r.observationPlan),
		QueryScope: cloneQueryScope(r.queryScope), Baseline: r.baseline, ExecutionStartedAt: r.executionStarted,
		ExecutionDeadlineAt: r.executionDeadline, TotalDeadlineAt: r.totalDeadline,
		Initial: cloneInitialResult(*r.initialResult), Reconstruction: cloneReconstructionResult(*r.reconstructionResult),
		Observation: cloneExecutionObservationResult(*r.executionObservation), Cleanup: cloneCleanupResult(*r.cleanupResult),
	}), true
}

func (r *PreparedRuntime) finishEvidenceFinalization(result EvidenceFinalizationResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := result
	r.evidenceResult = &copy
	r.evidenceActive = false
}

// EvidenceFinalization returns the immutable d7 result after its one-shot
// attempt. A zero result records a failed attempt without leaking diagnostics.
func (r *PreparedRuntime) EvidenceFinalization() (EvidenceFinalizationResult, bool) {
	if r == nil {
		return EvidenceFinalizationResult{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.evidenceActive || r.evidenceResult == nil {
		return EvidenceFinalizationResult{}, false
	}
	return *r.evidenceResult, true
}

func cloneEvidenceSnapshot(source EvidenceSnapshot) EvidenceSnapshot {
	result := source
	result.Runtime = cloneRuntimeObservation(source.Runtime)
	result.CleanupPolicy = cloneCleanupRequirements(source.CleanupPolicy)
	result.ReconstructionPolicy = cloneReconstructionRequirements(source.ReconstructionPolicy)
	result.ObservationPlan = cloneObservationPlan(source.ObservationPlan)
	result.QueryScope = cloneQueryScope(source.QueryScope)
	result.Initial = cloneInitialResult(source.Initial)
	result.Reconstruction = cloneReconstructionResult(source.Reconstruction)
	result.Observation = cloneExecutionObservationResult(source.Observation)
	result.Cleanup = cloneCleanupResult(source.Cleanup)
	return result
}
