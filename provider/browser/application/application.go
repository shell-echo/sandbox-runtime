// Package application composes the provider-local browser session authority
// without exposing repositories, lifecycle models, runtime drivers, or
// transport DTOs to a caller.
package application

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

var (
	ErrInvalidApplication = errors.New("invalid browser session application")
	ErrHandoffPending     = errors.New("browser session handoff is pending")
)

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Operation struct {
	OperationID  string
	AttemptID    string
	FencingToken int64
	SandboxID    string
	Status       browser.Status
	ObservedAt   time.Time
}

type Handoff struct {
	OperationID               string
	AttemptID                 string
	FencingToken              int64
	SandboxID                 string
	BrowserSessionID          string
	CapabilityProfileID       string
	Protocol                  browser.Protocol
	InternalEndpointReference string
	ConnectionGeneration      int64
	ExpiresAt                 time.Time
}

type Application struct {
	authority browser.Authority
	clock     Clock
}

func New(authority browser.Authority, clock Clock) (*Application, error) {
	if authority == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	return &Application{authority: authority, clock: clock}, nil
}

func (a *Application) Open(ctx context.Context, request browser.OpenRequest) (Operation, error) {
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

func (a *Application) GetOperation(ctx context.Context, operationID string) (Operation, error) {
	if a == nil || a.authority == nil || a.clock == nil {
		return Operation{}, ErrInvalidApplication
	}
	if ctx == nil {
		return Operation{}, context.Canceled
	}
	now := a.clock.Now().UTC()
	if now.IsZero() || operationID == "" {
		return Operation{}, browser.ErrInvalidRequest
	}
	record, err := a.getOpen(ctx, operationID, now)
	if err != nil {
		return Operation{}, err
	}
	return operationProjection(record)
}

func (a *Application) GetHandoff(ctx context.Context, operationID string) (Handoff, error) {
	if a == nil || a.authority == nil || a.clock == nil {
		return Handoff{}, ErrInvalidApplication
	}
	if ctx == nil {
		return Handoff{}, context.Canceled
	}
	now := a.clock.Now().UTC()
	if now.IsZero() || operationID == "" {
		return Handoff{}, browser.ErrInvalidRequest
	}
	record, err := a.getOpen(ctx, operationID, now)
	if err != nil {
		return Handoff{}, err
	}
	if record.Status == browser.StatusSucceeded && record.Handoff != nil && !now.Before(record.Handoff.ExpiresAt) {
		return Handoff{}, browser.ErrHandoffExpired
	}
	if err := record.Validate(); err != nil {
		return Handoff{}, err
	}
	switch record.Status {
	case browser.StatusAccepted, browser.StatusRunning:
		return Handoff{}, ErrHandoffPending
	case browser.StatusFailed, browser.StatusCancelled, browser.StatusOutcomeUnknown:
		return Handoff{}, browser.ErrHandoffUnavailable
	case browser.StatusSucceeded:
		if record.Handoff == nil {
			return Handoff{}, browser.ErrHandoffUnavailable
		}
		return handoffProjection(*record.Handoff)
	default:
		return Handoff{}, browser.ErrInvalidRecord
	}
}

func (a *Application) getOpen(ctx context.Context, operationID string, now time.Time) (browser.Record, error) {
	if timed, ok := a.authority.(interface {
		GetOpenAt(context.Context, string, time.Time) (browser.Record, error)
	}); ok {
		return timed.GetOpenAt(ctx, operationID, now)
	}
	return a.authority.GetOpen(ctx, operationID)
}

func operationProjection(record browser.Record) (Operation, error) {
	if err := record.Validate(); err != nil {
		return Operation{}, err
	}
	return Operation{OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID, FencingToken: record.Request.FencingToken, SandboxID: record.Request.SandboxID, Status: record.Status, ObservedAt: record.ObservedAt.UTC()}, nil
}

func handoffProjection(handoff browser.Handoff) (Handoff, error) {
	if err := handoff.Validate(); err != nil {
		return Handoff{}, err
	}
	return Handoff{OperationID: handoff.OperationID, AttemptID: handoff.AttemptID, FencingToken: handoff.FencingToken, SandboxID: handoff.SandboxID, BrowserSessionID: handoff.BrowserSessionID, CapabilityProfileID: handoff.CapabilityProfileID, Protocol: handoff.Protocol, InternalEndpointReference: handoff.InternalEndpointReference, ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: handoff.ExpiresAt.UTC()}, nil
}

var _ interface {
	Open(context.Context, browser.OpenRequest) (Operation, error)
	GetOperation(context.Context, string) (Operation, error)
	GetHandoff(context.Context, string) (Handoff, error)
} = (*Application)(nil)
