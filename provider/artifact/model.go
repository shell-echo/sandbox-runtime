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
	ErrInvalidRequest  = errors.New("invalid Provider artifact staging request")
	ErrDeadlineExpired = errors.New("Provider artifact staging deadline has expired")
	ErrInvalidEvidence = errors.New("invalid Provider artifact staging evidence")
	ErrEvidenceExpired = errors.New("Provider artifact staging evidence has expired")

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
		"sandbox_id": r.SandboxID, "operation_id": r.OperationID, "attempt_id": r.AttemptID,
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
