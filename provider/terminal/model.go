// Package terminal defines the backend-neutral Provider terminal runtime
// boundary. It does not import transport DTOs, repositories, lifecycle models,
// Docker types, or Gateway policy.
package terminal

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	ErrInvalidRequest      = errors.New("invalid Provider terminal allocation request")
	ErrInvalidReceipt      = errors.New("invalid Provider terminal allocation receipt")
	ErrInvalidObservation  = errors.New("invalid Provider terminal observation")
	ErrAllocationUnknown   = errors.New("Provider terminal allocation outcome is unknown")
	ErrTerminalNotFound    = errors.New("Provider terminal resource was not found")
	ErrTerminalExpired     = errors.New("Provider terminal resource has expired")
	ErrTerminalConflict    = errors.New("Provider terminal resource identity conflict")
	ErrTerminalCapacity    = errors.New("Provider terminal capacity is exhausted")
	ErrTerminalUnsupported = errors.New("Provider terminal runtime is unsupported")

	identifierPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	digestPattern           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	workingDirectoryPattern = regexp.MustCompile(`^/(workspace|tmp)(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
	referencePattern        = regexp.MustCompile(`^ref:terminal/[0-9a-f]{32}$`)
)

// AllocationRequest is the immutable identity of one provider-local terminal
// allocation. Shell and broker commands are trusted adapter configuration,
// never caller-controlled fields in this request.
type AllocationRequest struct {
	SandboxID          string
	RuntimeSessionID   string
	OperationID        string
	AttemptID          string
	FencingToken       int64
	ExpectedGeneration int64
	RequestDigest      string
	WorkingDirectory   string
	ExpiresAt          time.Time
}

func (r AllocationRequest) Clone() AllocationRequest { return r }

func (r AllocationRequest) Validate(now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: current time", ErrInvalidRequest)
	}
	for name, value := range map[string]string{
		"sandbox_id":         r.SandboxID,
		"runtime_session_id": r.RuntimeSessionID,
		"operation_id":       r.OperationID,
		"attempt_id":         r.AttemptID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 {
		return fmt.Errorf("%w: fencing token and expected generation", ErrInvalidRequest)
	}
	if !digestPattern.MatchString(r.RequestDigest) {
		return fmt.Errorf("%w: request digest", ErrInvalidRequest)
	}
	if !workingDirectoryPattern.MatchString(r.WorkingDirectory) {
		return fmt.Errorf("%w: working directory", ErrInvalidRequest)
	}
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expiry", ErrInvalidRequest)
	}
	return nil
}

// Allocation binds an accepted request to the application-owned allocation
// time. Adapters do not choose or rewrite this time.
type Allocation struct {
	Request     AllocationRequest
	AllocatedAt time.Time
}

func (a Allocation) Validate() error {
	if a.AllocatedAt.IsZero() {
		return ErrInvalidRequest
	}
	return a.Request.Validate(a.AllocatedAt)
}

// Reference is an opaque provider-local terminal allocation receipt. It is
// not the Contract-visible ref:session handoff and never embeds backend data.
type Reference string

func (r Reference) Validate() error {
	if !referencePattern.MatchString(string(r)) {
		return ErrInvalidReceipt
	}
	return nil
}

// Receipt is provider-neutral durable allocation evidence. Backend container,
// process, socket, and transport identities remain in adapter-private state.
type Receipt struct {
	Reference            Reference
	SandboxID            string
	RuntimeSessionID     string
	OperationID          string
	AttemptID            string
	FencingToken         int64
	ExpectedGeneration   int64
	ConnectionGeneration int64
	AllocatedAt          time.Time
	ExpiresAt            time.Time
}

func (r Receipt) Clone() Receipt { return r }

func (r Receipt) Validate() error {
	if err := r.Reference.Validate(); err != nil {
		return err
	}
	for _, value := range []string{r.SandboxID, r.RuntimeSessionID, r.OperationID, r.AttemptID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidReceipt
		}
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 || r.ConnectionGeneration < 1 ||
		r.AllocatedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.AllocatedAt) {
		return ErrInvalidReceipt
	}
	return nil
}

func (r Receipt) Matches(request AllocationRequest) bool {
	return r.SandboxID == request.SandboxID && r.RuntimeSessionID == request.RuntimeSessionID &&
		r.OperationID == request.OperationID && r.AttemptID == request.AttemptID &&
		r.FencingToken == request.FencingToken && r.ExpectedGeneration == request.ExpectedGeneration &&
		r.ExpiresAt.Equal(request.ExpiresAt)
}

type ObservationState string

const (
	ObservationRunning        ObservationState = "running"
	ObservationAbsent         ObservationState = "absent"
	ObservationExpired        ObservationState = "expired"
	ObservationOutcomeUnknown ObservationState = "outcome_unknown"
)

// Observation is bounded runtime evidence. Raw backend errors and identities
// are intentionally excluded.
type Observation struct {
	Receipt    Receipt
	State      ObservationState
	ObservedAt time.Time
}

func (o Observation) Validate() error {
	if err := o.Receipt.Validate(); err != nil || o.ObservedAt.IsZero() || o.ObservedAt.Before(o.Receipt.AllocatedAt) {
		return ErrInvalidObservation
	}
	switch o.State {
	case ObservationRunning, ObservationAbsent, ObservationExpired, ObservationOutcomeUnknown:
		return nil
	default:
		return ErrInvalidObservation
	}
}
