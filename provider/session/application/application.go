// Package application composes the provider-local terminal-session authority
// without exposing a repository, lifecycle model, instance, or runtime driver
// to the transport layer. It accepts and returns immutable session projections.
package application

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
)

var (
	ErrInvalidApplication = errors.New("invalid terminal session application")
	ErrHandoffPending     = errors.New("terminal session handoff is pending")
)

// Clock keeps acceptance and handoff expiry decisions deterministic in tests.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Operation is the bounded Provider operation projection returned after an
// open reservation. It contains no repository or backend details.
type Operation struct {
	OperationID  string
	AttemptID    string
	FencingToken int64
	SandboxID    string
	Status       session.Status
	ObservedAt   time.Time
}

// Handoff is the provider-local opaque handoff projection. The endpoint
// reference is validated by the domain and is never interpreted here.
type Handoff struct {
	OperationID               string
	AttemptID                 string
	FencingToken              int64
	SandboxID                 string
	RuntimeSessionID          string
	RuntimeType               session.RuntimeType
	CapabilityProfileID       string
	Protocol                  session.Protocol
	InternalEndpointReference string
	ConnectionGeneration      int64
	ExpiresAt                 time.Time
}

// Application is the narrow terminal-session application boundary. The
// authority remains responsible for transactional sandbox checks and durable
// idempotency; this layer only supplies time and state projections.
type Application struct {
	authority session.Authority
	clock     Clock
}

func New(authority session.Authority, clock Clock) (*Application, error) {
	if authority == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	return &Application{authority: authority, clock: clock}, nil
}

// Open records an accepted terminal-session operation. It never starts an
// allocator, process, WebSocket listener, or runtime driver.
func (a *Application) Open(ctx context.Context, request session.OpenRequest) (Operation, error) {
	if a == nil || a.authority == nil || a.clock == nil {
		return Operation{}, ErrInvalidApplication
	}
	if ctx == nil {
		return Operation{}, context.Canceled
	}
	now := a.clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return Operation{}, err
	}
	reservation, err := a.authority.ReserveOpen(ctx, request, now)
	if err != nil {
		return Operation{}, err
	}
	return operationProjection(reservation.Record)
}

// GetHandoff reads the successful opaque handoff. Accepted/running records
// are explicitly pending; failed, cancelled, and outcome-unknown records can
// never mint or reopen one.
func (a *Application) GetHandoff(ctx context.Context, operationID string) (Handoff, error) {
	if a == nil || a.authority == nil || a.clock == nil {
		return Handoff{}, ErrInvalidApplication
	}
	if ctx == nil {
		return Handoff{}, context.Canceled
	}
	now := a.clock.Now().UTC()
	if now.IsZero() || operationID == "" {
		return Handoff{}, session.ErrInvalidRequest
	}
	record, err := a.getOpen(ctx, operationID, now)
	if err != nil {
		return Handoff{}, err
	}
	if record.Status == session.StatusSucceeded && record.Handoff != nil && !now.Before(record.Handoff.ExpiresAt) {
		return Handoff{}, session.ErrHandoffExpired
	}
	if err := record.Validate(); err != nil {
		return Handoff{}, err
	}
	switch record.Status {
	case session.StatusAccepted, session.StatusRunning:
		return Handoff{}, ErrHandoffPending
	case session.StatusFailed, session.StatusCancelled, session.StatusOutcomeUnknown:
		return Handoff{}, session.ErrHandoffUnavailable
	case session.StatusSucceeded:
		if record.Handoff == nil {
			return Handoff{}, session.ErrHandoffUnavailable
		}
		if !now.Before(record.Handoff.ExpiresAt) {
			return Handoff{}, session.ErrHandoffExpired
		}
		return handoffProjection(*record.Handoff)
	default:
		return Handoff{}, session.ErrInvalidRecord
	}
}

func (a *Application) getOpen(ctx context.Context, operationID string, now time.Time) (session.Record, error) {
	if timed, ok := a.authority.(interface {
		GetOpenAt(context.Context, string, time.Time) (session.Record, error)
	}); ok {
		return timed.GetOpenAt(ctx, operationID, now)
	}
	return a.authority.GetOpen(ctx, operationID)
}

func operationProjection(record session.Record) (Operation, error) {
	if err := record.Validate(); err != nil {
		return Operation{}, err
	}
	return Operation{
		OperationID:  record.Request.OperationID,
		AttemptID:    record.Request.AttemptID,
		FencingToken: record.Request.FencingToken,
		SandboxID:    record.Request.SandboxID,
		Status:       record.Status,
		ObservedAt:   record.ObservedAt.UTC(),
	}, nil
}

func handoffProjection(handoff session.Handoff) (Handoff, error) {
	if err := handoff.Validate(); err != nil {
		return Handoff{}, err
	}
	return Handoff{
		OperationID:               handoff.OperationID,
		AttemptID:                 handoff.AttemptID,
		FencingToken:              handoff.FencingToken,
		SandboxID:                 handoff.SandboxID,
		RuntimeSessionID:          handoff.RuntimeSessionID,
		RuntimeType:               handoff.RuntimeType,
		CapabilityProfileID:       handoff.CapabilityProfileID,
		Protocol:                  handoff.Protocol,
		InternalEndpointReference: handoff.InternalEndpointReference,
		ConnectionGeneration:      handoff.ConnectionGeneration,
		ExpiresAt:                 handoff.ExpiresAt.UTC(),
	}, nil
}
