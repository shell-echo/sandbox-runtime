package browser

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	allocationIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	allocationDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type AllocationRequest struct {
	SandboxID          string
	BrowserSessionID   string
	OperationID        string
	AttemptID          string
	FencingToken       int64
	ExpectedGeneration int64
	RequestDigest      string
	ExpiresAt          time.Time
}

func (r AllocationRequest) Validate(now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: current time", ErrInvalidRequest)
	}
	for name, value := range map[string]string{
		"sandbox_id": r.SandboxID, "browser_session_id": r.BrowserSessionID,
		"operation_id": r.OperationID, "attempt_id": r.AttemptID,
	} {
		if !allocationIdentifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 || !allocationDigestPattern.MatchString(r.RequestDigest) {
		return fmt.Errorf("%w: identity", ErrInvalidRequest)
	}
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expiry", ErrInvalidRequest)
	}
	return nil
}

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

type Allocator interface {
	Allocate(context.Context, Allocation) (AllocationReceipt, error)
}
type Observer interface {
	Observe(context.Context, AllocationReceipt) (AllocationObservation, error)
}
type Attacher interface {
	Attach(context.Context, AllocationReceipt) (Stream, error)
}
type Cleaner interface {
	Cleanup(context.Context, AllocationReceipt) error
}

type Runtime interface {
	Allocator
	Observer
	Attacher
	Cleaner
}

type Authority interface {
	ReserveOpen(context.Context, OpenRequest, time.Time) (Reservation, error)
	GetOpen(context.Context, string) (Record, error)
	UpdateOpen(context.Context, Record, Status) error
}

type CoordinationAuthority interface {
	Authority
	SynchronizeSandboxAuthority(context.Context, SandboxAuthority) error
	AttachAllocation(context.Context, AllocationReceipt) (Reservation, error)
	ObserveAllocation(context.Context, string, AllocationEvidence) (Record, error)
	ListOpen(context.Context) ([]Record, error)
}

type AllocationObservation struct {
	Receipt    AllocationReceipt
	State      AllocationState
	ObservedAt time.Time
}

func (o AllocationObservation) Validate() error {
	if err := o.Receipt.Validate(); err != nil || o.ObservedAt.IsZero() || o.ObservedAt.Before(o.Receipt.AllocatedAt) || !o.State.valid() {
		return ErrInvalidAllocation
	}
	return nil
}

// Stream is intentionally transport-neutral. WebSocket framing and caller
// authorization belong to a later Gateway composition.
type Stream interface {
	Read(context.Context, []byte) (int, error)
	Write(context.Context, []byte) (int, error)
	Close() error
}

var (
	ErrAllocationUnknown  = errors.New("Provider browser allocation outcome is unknown")
	ErrBrowserNotFound    = errors.New("Provider browser resource was not found")
	ErrBrowserExpired     = errors.New("Provider browser resource has expired")
	ErrBrowserConflict    = errors.New("Provider browser resource identity conflict")
	ErrBrowserUnsupported = errors.New("Provider browser runtime is unsupported")
)
