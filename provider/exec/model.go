// Package exec contains the backend-neutral Provider-local process execution
// boundary. It deliberately does not import transport DTOs, lifecycle
// repositories, instance models, or runtime drivers.
package exec

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxCommandItems          = 64
	MaxCommandItemRunes      = 4096
	MaxWorkingDirectoryRunes = 256
	MaxIdempotencyKeyRunes   = 200
	MaxEnvironmentValues     = 64
	MaxSecretReferences      = 64
	MaxCaptureBytes          = 8 << 20
	MinRetention             = time.Second
	MaxRetention             = 24 * time.Hour
)

var (
	ErrInvalidRequest       = errors.New("invalid Provider exec request")
	ErrDeadlineExpired      = errors.New("Provider exec request deadline has expired")
	ErrInvalidApplication   = errors.New("invalid Provider exec application")
	ErrDispatchUnknown      = errors.New("Provider exec dispatch outcome is unknown")
	ErrExecutionNotFound    = errors.New("Provider exec execution was not found")
	ErrExecutionNotRunning  = errors.New("Provider exec execution is not running")
	ErrUnsupportedRequest   = errors.New("Provider exec request uses an unsupported runtime feature")
	ErrInvalidDispatch      = errors.New("invalid Provider exec dispatch receipt")
	ErrInvalidObservation   = errors.New("invalid Provider exec runtime observation")
	ErrInvalidResult        = errors.New("invalid Provider exec retained result")
	ErrInvalidCancellation  = errors.New("invalid Provider exec cancellation intent")
	identifierPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	digestPattern           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	workingDirectoryPattern = regexp.MustCompile(`^/(workspace|tmp)(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
	environmentNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	environmentRefPattern   = regexp.MustCompile(`^envref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)
	grantPattern            = regexp.MustCompile(`^grant:[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)
	referencePattern        = regexp.MustCompile(`^ref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)
	signalPattern           = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Request is the provider-neutral projection of the Contract exec request.
// Its SandboxID is bound by admission/path context before this package is
// called; it is not read from the JSON body.
type Request struct {
	SandboxID          string
	OperationID        string
	AttemptID          string
	FencingToken       int64
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestDigest      string
	Deadline           time.Time
	Command            []string
	WorkingDirectory   string
	ResultRetention    time.Duration
	Environment        map[string]string
	SecretReferenceIDs []string
	SecretGrantID      string
	SecretGrantDigest  string
	StdinReference     string
	CaptureStdout      bool
	CaptureStderr      bool
	CaptureMaxBytes    int64
}

// Invocation is immutable input supplied to an Executor. StartedAt is chosen
// by the application clock, never by a backend.
type Invocation struct {
	Request   Request
	StartedAt time.Time
}

// Dispatch is the only result P2.1 exposes. The reference is opaque and
// provider-local; retained results and cancellation state are P2.2 work.
type Dispatch struct {
	ExecutionReference ExecutionReference
	AcceptedAt         time.Time
}

// Observation is backend-neutral execution evidence used for demand-driven
// and startup reconciliation. Backend identifiers, paths, endpoints, and raw
// errors are deliberately excluded.
type Observation struct {
	ExecutionReference ExecutionReference
	Status             ResultStatus
	Running            bool
	StartedAt          time.Time
	CompletedAt        time.Time
	ExitCode           *int
	Signal             string
	StdoutReference    string
	StderrReference    string
	Error              *ResultError
}

func (o Observation) Validate() error {
	if err := o.ExecutionReference.Validate(); err != nil || o.StartedAt.IsZero() {
		return ErrInvalidObservation
	}
	if o.Running {
		if o.Status != "" || !o.CompletedAt.IsZero() || o.ExitCode != nil || o.Signal != "" || o.Error != nil {
			return ErrInvalidObservation
		}
		return nil
	}
	if o.CompletedAt.IsZero() || o.CompletedAt.Before(o.StartedAt) {
		return ErrInvalidObservation
	}
	outcome := ResultOutcome{
		Status: o.Status, ExitCode: cloneExitCode(o.ExitCode), Signal: o.Signal,
		StdoutReference: o.StdoutReference, StderrReference: o.StderrReference,
		Error: cloneResultError(o.Error),
	}
	probe := Request{
		SandboxID: "probe", OperationID: "probe", AttemptID: "probe",
		FencingToken: 1, ResultRetention: time.Second,
	}
	_, err := NewResult(probe, o.StartedAt, o.CompletedAt, outcome)
	if err != nil {
		return ErrInvalidObservation
	}
	return nil
}

// Clone returns a deep copy suitable for crossing the application/port
// boundary. Callers cannot mutate a request after dispatch has begun.
func (r Request) Clone() Request {
	clone := r
	clone.Command = append([]string(nil), r.Command...)
	clone.SecretReferenceIDs = append([]string(nil), r.SecretReferenceIDs...)
	if r.Environment != nil {
		clone.Environment = make(map[string]string, len(r.Environment))
		for key, value := range r.Environment {
			clone.Environment[key] = value
		}
	}
	return clone
}

// Validate checks the bounded Contract projection and the deadline relative
// to now. It does not check sandbox state or caller authorization.
func (r Request) Validate(now time.Time) error {
	for name, value := range map[string]string{
		"sandbox_id":   r.SandboxID,
		"operation_id": r.OperationID,
		"attempt_id":   r.AttemptID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if !validBoundedString(r.IdempotencyKey, 1, MaxIdempotencyKeyRunes) {
		return fmt.Errorf("%w: idempotency_key", ErrInvalidRequest)
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 {
		return fmt.Errorf("%w: fencing token and expected generation must be positive", ErrInvalidRequest)
	}
	if !digestPattern.MatchString(r.RequestDigest) {
		return fmt.Errorf("%w: request digest", ErrInvalidRequest)
	}
	if r.Deadline.IsZero() {
		return fmt.Errorf("%w: deadline is required", ErrInvalidRequest)
	}
	if !r.Deadline.After(now) {
		return ErrDeadlineExpired
	}
	if len(r.Command) == 0 || len(r.Command) > MaxCommandItems {
		return fmt.Errorf("%w: command item count", ErrInvalidRequest)
	}
	for index, item := range r.Command {
		if !validBoundedString(item, 1, MaxCommandItemRunes) || strings.ContainsAny(item, "\x00\r\n") {
			return fmt.Errorf("%w: command item %d", ErrInvalidRequest, index)
		}
	}
	if !validBoundedString(r.WorkingDirectory, 1, MaxWorkingDirectoryRunes) || !workingDirectoryPattern.MatchString(r.WorkingDirectory) {
		return fmt.Errorf("%w: working directory", ErrInvalidRequest)
	}
	if r.ResultRetention < MinRetention || r.ResultRetention > MaxRetention {
		return fmt.Errorf("%w: result retention", ErrInvalidRequest)
	}
	if len(r.Environment) > MaxEnvironmentValues {
		return fmt.Errorf("%w: environment count", ErrInvalidRequest)
	}
	for name, value := range r.Environment {
		if !environmentNamePattern.MatchString(name) || !environmentRefPattern.MatchString(value) {
			return fmt.Errorf("%w: environment reference", ErrInvalidRequest)
		}
	}
	if len(r.SecretReferenceIDs) > MaxSecretReferences {
		return fmt.Errorf("%w: secret reference count", ErrInvalidRequest)
	}
	for index, reference := range r.SecretReferenceIDs {
		if !identifierPattern.MatchString(reference) {
			return fmt.Errorf("%w: secret reference %d", ErrInvalidRequest, index)
		}
	}
	if (r.SecretGrantID == "") != (r.SecretGrantDigest == "") || (r.SecretGrantID != "" && !grantPattern.MatchString(r.SecretGrantID)) || (r.SecretGrantDigest != "" && !digestPattern.MatchString(r.SecretGrantDigest)) {
		return fmt.Errorf("%w: secret grant", ErrInvalidRequest)
	}
	if r.StdinReference != "" && !referencePattern.MatchString(r.StdinReference) {
		return fmt.Errorf("%w: stdin reference", ErrInvalidRequest)
	}
	if r.CaptureMaxBytes < 0 || r.CaptureMaxBytes > MaxCaptureBytes {
		return fmt.Errorf("%w: capture byte limit", ErrInvalidRequest)
	}
	return nil
}

// ExecutionReference is an opaque provider-local receipt. It is not a
// container ID, host path, runtime endpoint, credential, or result reference.
type ExecutionReference string

// Validate ensures the adapter cannot return an unbounded backend identifier.
func (r ExecutionReference) Validate() error {
	if !referencePattern.MatchString(string(r)) {
		return ErrInvalidDispatch
	}
	return nil
}

// Validate ensures a dispatch receipt has only the bounded values P2.1 owns.
func (d Dispatch) Validate() error {
	if err := d.ExecutionReference.Validate(); err != nil || d.AcceptedAt.IsZero() {
		return ErrInvalidDispatch
	}
	return nil
}

func validBoundedString(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	count := utf8.RuneCountInString(value)
	return count >= minimum && count <= maximum
}
