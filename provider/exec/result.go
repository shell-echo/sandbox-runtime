package exec

import (
	"fmt"
	"regexp"
	"time"
)

var resultCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

// ResultStatus is the bounded terminal execution outcome exposed by the
// retained-result Contract. A cancellation intent alone never changes it.
type ResultStatus string

const (
	ResultCompleted      ResultStatus = "completed"
	ResultFailed         ResultStatus = "failed"
	ResultCancelled      ResultStatus = "cancelled"
	ResultOutcomeUnknown ResultStatus = "outcome_unknown"
)

// ErrorOutcome records whether a provider error establishes a known failure.
type ErrorOutcome string

const (
	ErrorOutcomeKnown   ErrorOutcome = "known_failed"
	ErrorOutcomeUnknown ErrorOutcome = "outcome_unknown"
)

// ResultError contains a bounded public-safe error projection. Message must be
// safe for the Provider wire; it never carries a backend path, endpoint,
// credential, or raw runtime error.
type ResultError struct {
	Code      string
	Message   string
	Retryable bool
	Outcome   ErrorOutcome
}

// ResultOutcome is trusted provider-local completion evidence. It is not a
// wire DTO and is only converted to a retained Result after validation.
type ResultOutcome struct {
	Status          ResultStatus
	ExitCode        *int
	Signal          string
	StdoutReference string
	StderrReference string
	Error           *ResultError
}

// Result is immutable provider-local retained execution evidence. Retention
// is derived from the accepted Request, never selected by a result caller.
type Result struct {
	OperationID     string
	AttemptID       string
	FencingToken    int64
	SandboxID       string
	Status          ResultStatus
	ExitCode        *int
	Signal          string
	StdoutReference string
	StderrReference string
	StartedAt       time.Time
	CompletedAt     time.Time
	RetainedUntil   time.Time
	Error           *ResultError
}

// TerminalSummary preserves operation truth after the retained result and its
// private output have expired. It deliberately excludes output references,
// exit details, and retention metadata.
type TerminalSummary struct {
	Status      ResultStatus
	CompletedAt time.Time
	Error       *ResultError
}

func NewTerminalSummary(result Result) (TerminalSummary, error) {
	if err := result.Validate(); err != nil {
		return TerminalSummary{}, err
	}
	return TerminalSummary{Status: result.Status, CompletedAt: result.CompletedAt.UTC(), Error: cloneResultError(result.Error)}, nil
}

func (s TerminalSummary) Validate() error {
	switch s.Status {
	case ResultCompleted, ResultFailed, ResultCancelled, ResultOutcomeUnknown:
	default:
		return ErrInvalidResult
	}
	if s.CompletedAt.IsZero() {
		return ErrInvalidResult
	}
	if s.Error != nil && (!resultCodePattern.MatchString(s.Error.Code) || !validBoundedString(s.Error.Message, 1, 512) || (s.Error.Outcome != ErrorOutcomeKnown && s.Error.Outcome != ErrorOutcomeUnknown)) {
		return ErrInvalidResult
	}
	if s.Status == ResultOutcomeUnknown && (s.Error == nil || s.Error.Outcome != ErrorOutcomeUnknown) {
		return ErrInvalidResult
	}
	return nil
}

func (s *TerminalSummary) Clone() *TerminalSummary {
	if s == nil {
		return nil
	}
	clone := *s
	clone.Error = cloneResultError(s.Error)
	return &clone
}

// UsageIdentity is the minimal correlation source a later usage collector may
// consume. It carries no output, error, billing, tenant, or backend detail.
type UsageIdentity struct {
	SandboxID    string
	OperationID  string
	AttemptID    string
	FencingToken int64
}

func (r Result) UsageIdentity() (UsageIdentity, error) {
	if err := r.Validate(); err != nil {
		return UsageIdentity{}, err
	}
	return UsageIdentity{
		SandboxID: r.SandboxID, OperationID: r.OperationID,
		AttemptID: r.AttemptID, FencingToken: r.FencingToken,
	}, nil
}

// NewResult binds trusted completion evidence to the immutable request and
// derives retention from its already-admitted retention duration.
func NewResult(request Request, startedAt, completedAt time.Time, outcome ResultOutcome) (Result, error) {
	result := Result{
		OperationID:     request.OperationID,
		AttemptID:       request.AttemptID,
		FencingToken:    request.FencingToken,
		SandboxID:       request.SandboxID,
		Status:          outcome.Status,
		ExitCode:        cloneExitCode(outcome.ExitCode),
		Signal:          outcome.Signal,
		StdoutReference: outcome.StdoutReference,
		StderrReference: outcome.StderrReference,
		StartedAt:       startedAt.UTC(),
		CompletedAt:     completedAt.UTC(),
		RetainedUntil:   completedAt.UTC().Add(request.ResultRetention),
		Error:           cloneResultError(outcome.Error),
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// Validate checks the retained-result Contract projection without performing
// I/O or deciding whether an execution has actually completed.
func (r Result) Validate() error {
	for name, value := range map[string]string{
		"operation_id": r.OperationID,
		"attempt_id":   r.AttemptID,
		"sandbox_id":   r.SandboxID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidResult, name)
		}
	}
	if r.FencingToken < 1 {
		return fmt.Errorf("%w: fencing token", ErrInvalidResult)
	}
	switch r.Status {
	case ResultCompleted, ResultFailed, ResultCancelled, ResultOutcomeUnknown:
	default:
		return fmt.Errorf("%w: status", ErrInvalidResult)
	}
	if r.ExitCode != nil && (*r.ExitCode < -1 || *r.ExitCode > 255) {
		return fmt.Errorf("%w: exit code", ErrInvalidResult)
	}
	if !validBoundedString(r.Signal, 0, 64) || (r.Signal != "" && !signalPattern.MatchString(r.Signal)) {
		return fmt.Errorf("%w: signal", ErrInvalidResult)
	}
	for name, reference := range map[string]string{"stdout reference": r.StdoutReference, "stderr reference": r.StderrReference} {
		if reference != "" && !referencePattern.MatchString(reference) {
			return fmt.Errorf("%w: %s", ErrInvalidResult, name)
		}
	}
	if r.StartedAt.IsZero() || r.CompletedAt.IsZero() || r.RetainedUntil.IsZero() || r.CompletedAt.Before(r.StartedAt) || !r.RetainedUntil.After(r.CompletedAt) {
		return fmt.Errorf("%w: retention times", ErrInvalidResult)
	}
	if r.Error != nil && (!resultCodePattern.MatchString(r.Error.Code) || !validBoundedString(r.Error.Message, 1, 512) || (r.Error.Outcome != ErrorOutcomeKnown && r.Error.Outcome != ErrorOutcomeUnknown)) {
		return fmt.Errorf("%w: error", ErrInvalidResult)
	}
	if r.Status == ResultOutcomeUnknown && (r.Error == nil || r.Error.Outcome != ErrorOutcomeUnknown) {
		return fmt.Errorf("%w: unknown outcome error", ErrInvalidResult)
	}
	return nil
}

// CancellationReason is a bounded caller intent reason from the locked Contract.
type CancellationReason string

const (
	CancellationCallerRequested  CancellationReason = "caller_requested"
	CancellationDeadlineExceeded CancellationReason = "deadline_exceeded"
	CancellationShutdown         CancellationReason = "shutdown"
	CancellationPolicy           CancellationReason = "policy"
)

// CancellationIntent records a protected cancellation request. It deliberately
// does not claim that an executor observed or completed the cancellation.
type CancellationIntent struct {
	SandboxID          string
	OperationID        string
	AttemptID          string
	FencingToken       int64
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestDigest      string
	Deadline           time.Time
	TargetOperationID  string
	TargetAttemptID    string
	Reason             CancellationReason
}

// Validate checks the cancellation-intent projection and its dispatch deadline.
func (i CancellationIntent) Validate(now time.Time) error {
	for name, value := range map[string]string{
		"sandbox_id":          i.SandboxID,
		"operation_id":        i.OperationID,
		"attempt_id":          i.AttemptID,
		"target_operation_id": i.TargetOperationID,
		"target_attempt_id":   i.TargetAttemptID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidCancellation, name)
		}
	}
	if !validBoundedString(i.IdempotencyKey, 1, MaxIdempotencyKeyRunes) || i.FencingToken < 1 || i.ExpectedGeneration < 1 || !digestPattern.MatchString(i.RequestDigest) {
		return ErrInvalidCancellation
	}
	if i.Deadline.IsZero() || !i.Deadline.After(now) {
		return ErrInvalidCancellation
	}
	switch i.Reason {
	case CancellationCallerRequested, CancellationDeadlineExceeded, CancellationShutdown, CancellationPolicy:
		return nil
	default:
		return ErrInvalidCancellation
	}
}

func cloneExitCode(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneResultError(value *ResultError) *ResultError {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
