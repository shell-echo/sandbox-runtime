// Package artifact contains the backend-neutral provider-local artifact
// staging boundary. It records evidence only; artifact publication remains a
// calling-platform responsibility.
package artifact

import (
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	MaxIdentifierRunes = 200
	MaxReferenceRunes  = 400
	MaxPathRunes       = 512
	MaxArtifactBytes   = 64 << 20
	MinRetention       = time.Second
	MaxRetention       = 24 * time.Hour
)

var (
	ErrInvalidRequest      = errors.New("invalid Provider artifact staging request")
	ErrDeadlineExpired     = errors.New("Provider artifact staging deadline has expired")
	ErrInvalidEvidence     = errors.New("invalid Provider artifact staging evidence")
	ErrEvidenceExpired     = errors.New("Provider artifact staging evidence has expired")
	ErrInvalidOperation    = errors.New("invalid Provider artifact staging operation")
	ErrInvalidTransition   = errors.New("invalid Provider artifact staging transition")
	ErrTerminalOperation   = errors.New("Provider artifact staging operation is terminal")
	ErrSourceMissing       = errors.New("Provider artifact staging source is missing")
	ErrEvidenceNotFound    = errors.New("Provider artifact staging evidence not found")
	ErrEvidencePending     = errors.New("Provider artifact staging evidence is pending")
	ErrOutcomeUnknown      = errors.New("Provider artifact staging outcome is unknown")
	ErrNotFound            = errors.New("Provider artifact staging operation not found")
	ErrConflict            = errors.New("Provider artifact staging authority conflict")
	ErrIdempotencyConflict = errors.New("Provider artifact staging idempotency conflict")
	ErrGenerationConflict  = errors.New("Provider artifact staging sandbox generation conflict")
	ErrStaleFencingToken   = errors.New("Provider artifact staging fencing token is stale")
	ErrSandboxNotReady     = errors.New("Provider artifact staging sandbox is not ready")
	ErrSandboxLeaseExpired = errors.New("Provider artifact staging sandbox lease has expired")
	ErrTenantBinding       = errors.New("Provider artifact staging tenant binding failed")
	ErrUnsupportedChecks   = errors.New("Provider artifact staging checks are unsupported")
	ErrDurability          = errors.New("Provider artifact staging authority durability failure")

	identifierPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	artifactReferencePattern = regexp.MustCompile(`^artifact-ref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)
	digestPattern            = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	outputPathPattern        = regexp.MustCompile(`^/outputs(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
	mediaTypePattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)
	referencePattern         = regexp.MustCompile(`^ref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)
)

// Request is the provider-local projection of the locked staging request.
// Sandbox identity is supplied by the admitted path/context, not trusted
// from a second body field.
type Request struct {
	SandboxID          string
	TenantID           string
	OperationID        string
	AttemptID          string
	FencingToken       int64
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestDigest      string
	Deadline           time.Time
	ArtifactReference  string
	SourcePath         string
	ExpectedDigest     string
	ExpectedMediaType  string
	MaxBytes           int64
	Retention          time.Duration
}

func (r Request) Clone() Request { return r }

func (r Request) Validate(now time.Time) error {
	for name, value := range map[string]string{
		"sandbox_id": r.SandboxID, "tenant_id": r.TenantID,
		"operation_id": r.OperationID, "attempt_id": r.AttemptID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if !validText(r.IdempotencyKey, 1, MaxIdentifierRunes) {
		return fmt.Errorf("%w: idempotency_key", ErrInvalidRequest)
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 {
		return fmt.Errorf("%w: fencing token and expected generation", ErrInvalidRequest)
	}
	if !digestPattern.MatchString(r.RequestDigest) || !digestPattern.MatchString(r.ExpectedDigest) {
		return fmt.Errorf("%w: digest", ErrInvalidRequest)
	}
	if r.Deadline.IsZero() || !r.Deadline.After(now) {
		return ErrDeadlineExpired
	}
	if !artifactReferencePattern.MatchString(r.ArtifactReference) {
		return fmt.Errorf("%w: artifact reference", ErrInvalidRequest)
	}
	if !validText(r.SourcePath, 1, MaxPathRunes) || !outputPathPattern.MatchString(r.SourcePath) {
		return fmt.Errorf("%w: source path", ErrInvalidRequest)
	}
	if !mediaTypePattern.MatchString(r.ExpectedMediaType) || !validText(r.ExpectedMediaType, 3, 127) {
		return fmt.Errorf("%w: media type", ErrInvalidRequest)
	}
	if r.MaxBytes < 1 || r.MaxBytes > MaxArtifactBytes {
		return fmt.Errorf("%w: max bytes", ErrInvalidRequest)
	}
	if r.Retention < MinRetention || r.Retention > MaxRetention || now.Add(r.Retention).After(r.Deadline) {
		return fmt.Errorf("%w: retention bound", ErrInvalidRequest)
	}
	return nil
}

func (r Request) ExpiresAt(now time.Time) time.Time { return now.Add(r.Retention).UTC() }

type OperationStatus string

const (
	OperationAccepted       OperationStatus = "accepted"
	OperationRunning        OperationStatus = "running"
	OperationSucceeded      OperationStatus = "succeeded"
	OperationFailed         OperationStatus = "failed"
	OperationOutcomeUnknown OperationStatus = "outcome_unknown"
)

func (s OperationStatus) valid() bool {
	switch s {
	case OperationAccepted, OperationRunning, OperationSucceeded, OperationFailed, OperationOutcomeUnknown:
		return true
	default:
		return false
	}
}

func (s OperationStatus) terminal() bool {
	return s == OperationSucceeded || s == OperationFailed || s == OperationOutcomeUnknown
}

type FailureReason string

const (
	FailureSourceMissing      FailureReason = "source_missing"
	FailureContentRejected    FailureReason = "content_rejected"
	FailureDeadlineExpired    FailureReason = "deadline_expired"
	FailureCancelledBeforeRun FailureReason = "cancelled_before_dispatch"
	FailureDispatchUnknown    FailureReason = "dispatch_outcome_unknown"
)

func (r FailureReason) validFor(status OperationStatus) bool {
	switch status {
	case OperationFailed:
		return r == FailureSourceMissing || r == FailureContentRejected || r == FailureDeadlineExpired || r == FailureCancelledBeforeRun
	case OperationOutcomeUnknown:
		return r == FailureDispatchUnknown
	default:
		return r == ""
	}
}

// SandboxAuthority is the provider-local generation and fencing snapshot used
// when accepting staging work. It does not own caller or tenant truth.
type SandboxAuthority struct {
	SandboxID    string `json:"sandbox_id"`
	Generation   int64  `json:"generation"`
	FencingToken int64  `json:"fencing_token"`
}

func (a SandboxAuthority) Validate() error {
	if !identifierPattern.MatchString(a.SandboxID) || a.Generation < 1 || a.FencingToken < 1 {
		return ErrInvalidOperation
	}
	return nil
}

func (a SandboxAuthority) Clone() SandboxAuthority { return a }

// Operation is immutable provider-local staging truth. Evidence is retained
// only for staged or content-rejected terminal outcomes.
type Operation struct {
	Request    Request         `json:"request"`
	Status     OperationStatus `json:"status"`
	Failure    FailureReason   `json:"failure,omitempty"`
	AcceptedAt time.Time       `json:"accepted_at"`
	ObservedAt time.Time       `json:"observed_at"`
	Evidence   *Evidence       `json:"evidence,omitempty"`
}

func NewOperation(request Request, acceptedAt time.Time) (Operation, error) {
	acceptedAt = acceptedAt.UTC()
	if err := request.Validate(acceptedAt); err != nil {
		return Operation{}, err
	}
	return Operation{Request: request.Clone(), Status: OperationAccepted, AcceptedAt: acceptedAt, ObservedAt: acceptedAt}, nil
}

func (o Operation) Clone() Operation {
	clone := o
	clone.Request = o.Request.Clone()
	if o.Evidence != nil {
		evidence := *o.Evidence
		clone.Evidence = &evidence
	}
	return clone
}

func (o Operation) Validate() error {
	if o.AcceptedAt.IsZero() || o.ObservedAt.IsZero() || o.ObservedAt.Before(o.AcceptedAt) || !o.Status.valid() {
		return ErrInvalidOperation
	}
	if err := o.Request.Validate(o.AcceptedAt); err != nil {
		return fmt.Errorf("%w: request: %v", ErrInvalidOperation, err)
	}
	if !o.Failure.validFor(o.Status) {
		return ErrInvalidOperation
	}
	switch o.Status {
	case OperationAccepted, OperationRunning, OperationOutcomeUnknown:
		if o.Evidence != nil {
			return ErrInvalidOperation
		}
	case OperationSucceeded:
		if o.Evidence == nil || o.Evidence.Status != StatusStaged {
			return ErrInvalidOperation
		}
	case OperationFailed:
		if o.Failure == FailureContentRejected {
			if o.Evidence == nil || o.Evidence.Status != StatusRejected {
				return ErrInvalidOperation
			}
		} else if o.Evidence != nil {
			return ErrInvalidOperation
		}
	}
	if o.Evidence != nil {
		if err := o.Evidence.Validate(o.Evidence.ObservedAt); err != nil || !evidenceMatchesRequest(*o.Evidence, o.Request) {
			return ErrInvalidOperation
		}
	}
	return nil
}

var operationTransitions = map[OperationStatus]map[OperationStatus]bool{
	OperationAccepted: {
		OperationRunning: true, OperationFailed: true, OperationOutcomeUnknown: true,
	},
	OperationRunning: {
		OperationSucceeded: true, OperationFailed: true, OperationOutcomeUnknown: true,
	},
}

// Transition returns a new immutable operation snapshot. This domain has no
// cancellation confirmation capability, so it never creates cancelled truth.
func Transition(operation Operation, next OperationStatus, observedAt time.Time, failure FailureReason, evidence *Evidence) (Operation, error) {
	if err := operation.Validate(); err != nil {
		return Operation{}, err
	}
	observedAt = observedAt.UTC()
	if !next.valid() || observedAt.IsZero() || observedAt.Before(operation.ObservedAt) {
		return Operation{}, ErrInvalidTransition
	}
	if operation.Status == next {
		if failure != operation.Failure || evidence != nil {
			return Operation{}, ErrTerminalOperation
		}
		return operation.Clone(), nil
	}
	if operation.Status.terminal() {
		return Operation{}, ErrTerminalOperation
	}
	if !operationTransitions[operation.Status][next] || !failure.validFor(next) {
		return Operation{}, ErrInvalidTransition
	}
	if next == OperationRunning && !operation.Request.Deadline.After(observedAt) {
		return Operation{}, ErrDeadlineExpired
	}
	updated := operation.Clone()
	updated.Status = next
	updated.Failure = failure
	updated.ObservedAt = observedAt
	updated.Evidence = nil
	if next == OperationSucceeded || (next == OperationFailed && failure == FailureContentRejected) {
		if evidence == nil || !observedAt.Before(operation.Request.Deadline) {
			return Operation{}, ErrInvalidTransition
		}
		copyEvidence := *evidence
		if err := copyEvidence.Validate(observedAt); err != nil || !evidenceMatchesRequest(copyEvidence, operation.Request) {
			return Operation{}, ErrInvalidTransition
		}
		if next == OperationSucceeded && copyEvidence.Status != StatusStaged {
			return Operation{}, ErrInvalidTransition
		}
		if next == OperationFailed && copyEvidence.Status != StatusRejected {
			return Operation{}, ErrInvalidTransition
		}
		updated.Evidence = &copyEvidence
	} else if evidence != nil {
		return Operation{}, ErrInvalidTransition
	}
	if err := updated.Validate(); err != nil {
		return Operation{}, err
	}
	return updated, nil
}

func evidenceMatchesRequest(evidence Evidence, request Request) bool {
	if evidence.OperationID != request.OperationID ||
		evidence.AttemptID != request.AttemptID ||
		evidence.FencingToken != request.FencingToken ||
		evidence.SandboxID != request.SandboxID ||
		evidence.ArtifactReference != request.ArtifactReference ||
		evidence.ExpiresAt.After(request.Deadline) {
		return false
	}
	return evidence.Status != StatusStaged ||
		(evidence.ContentDigest == request.ExpectedDigest && evidence.MediaType == request.ExpectedMediaType && evidence.SizeBytes <= request.MaxBytes)
}

type Status string

const (
	StatusStaged   Status = "staged"
	StatusRejected Status = "rejected"
)

type CheckStatus string

const (
	CheckPassed CheckStatus = "passed"
	CheckFailed CheckStatus = "failed"
	CheckNotRun CheckStatus = "not_run"
)

type Check struct {
	Status            CheckStatus
	CheckedAt         time.Time
	EvidenceReference string
}

func (c Check) validate() error {
	if c.Status != CheckPassed && c.Status != CheckFailed && c.Status != CheckNotRun {
		return ErrInvalidEvidence
	}
	if c.CheckedAt.IsZero() {
		return ErrInvalidEvidence
	}
	if c.EvidenceReference != "" && !referencePattern.MatchString(c.EvidenceReference) {
		return ErrInvalidEvidence
	}
	return nil
}

type Evidence struct {
	OperationID        string
	AttemptID          string
	FencingToken       int64
	SandboxID          string
	ArtifactReference  string
	StagingReference   string
	Status             Status
	ContentDigest      string
	MediaType          string
	SizeBytes          int64
	TenantBindingCheck Check
	ActiveContentCheck Check
	MalwareCheck       Check
	ObservedAt         time.Time
	ExpiresAt          time.Time
	EvidenceDigest     string
}

func (e Evidence) Validate(now time.Time) error {
	for _, value := range []string{e.OperationID, e.AttemptID, e.SandboxID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidEvidence
		}
	}
	if e.FencingToken < 1 || !artifactReferencePattern.MatchString(e.ArtifactReference) || !digestPattern.MatchString(e.ContentDigest) || !digestPattern.MatchString(e.EvidenceDigest) || !mediaTypePattern.MatchString(e.MediaType) || e.SizeBytes < 0 || e.SizeBytes > MaxArtifactBytes {
		return ErrInvalidEvidence
	}
	if e.Status != StatusStaged && e.Status != StatusRejected {
		return ErrInvalidEvidence
	}
	if e.Status == StatusStaged {
		if !referencePattern.MatchString(e.StagingReference) || e.TenantBindingCheck.Status != CheckPassed || e.ActiveContentCheck.Status != CheckPassed || e.MalwareCheck.Status != CheckPassed {
			return ErrInvalidEvidence
		}
	}
	if err := e.TenantBindingCheck.validate(); err != nil {
		return err
	}
	if err := e.ActiveContentCheck.validate(); err != nil {
		return err
	}
	if err := e.MalwareCheck.validate(); err != nil {
		return err
	}
	if e.ObservedAt.IsZero() || e.ExpiresAt.IsZero() || !e.ExpiresAt.After(e.ObservedAt) {
		return ErrInvalidEvidence
	}
	if !now.Before(e.ExpiresAt) {
		return ErrEvidenceExpired
	}
	return nil
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	runes := utf8.RuneCountInString(value)
	return runes >= minimum && runes <= maximum
}
