// Package application composes the provider-local desktop session authority
// without exposing repositories, lifecycle models, runtime drivers, or
// transport DTOs to a caller.
package application

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

var (
	ErrInvalidApplication = errors.New("invalid desktop session application")
	ErrHandoffPending     = errors.New("desktop session handoff is pending")
)

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Operation struct {
	OperationID  string
	AttemptID    string
	FencingToken int64
	SandboxID    string
	Status       desktop.Status
	ObservedAt   time.Time
	Type         OperationType
}

type OperationType string

const (
	OperationOpenDesktopSession  OperationType = "open_desktop_session"
	OperationCloseDesktopSession OperationType = "close_desktop_session"
)

type Handoff struct {
	OperationID               string
	AttemptID                 string
	FencingToken              int64
	SandboxID                 string
	DesktopSessionID          string
	CapabilityProfileID       string
	Protocol                  desktop.Protocol
	MediaProfileID            string
	ControlProfileID          string
	InternalEndpointReference string
	ConnectionGeneration      int64
	ExpiresAt                 time.Time
}

type Application struct {
	authority desktop.Authority
	clock     Clock
}

func New(authority desktop.Authority, clock Clock) (*Application, error) {
	if authority == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	return &Application{authority: authority, clock: clock}, nil
}

func (a *Application) Open(ctx context.Context, request desktop.OpenRequest) (Operation, error) {
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
		return Operation{}, desktop.ErrInvalidRequest
	}
	record, err := a.getOpen(ctx, operationID, now)
	if err == nil {
		return operationProjection(record)
	}
	if !errors.Is(err, desktop.ErrAuthorityNotFound) {
		return Operation{}, err
	}
	closeAuthority, ok := a.authority.(interface {
		GetClose(context.Context, string) (desktop.CloseRecord, error)
	})
	if !ok {
		return Operation{}, err
	}
	closeRecord, closeErr := closeAuthority.GetClose(ctx, operationID)
	if closeErr != nil {
		return Operation{}, closeErr
	}
	return closeOperationProjection(closeRecord)
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
		return Handoff{}, desktop.ErrInvalidRequest
	}
	record, err := a.getOpen(ctx, operationID, now)
	if err != nil {
		return Handoff{}, err
	}
	if record.RevokedAt != nil {
		return Handoff{}, desktop.ErrHandoffRevoked
	}
	if record.Status == desktop.StatusSucceeded && record.Handoff != nil && !now.Before(record.Handoff.ExpiresAt) {
		return Handoff{}, desktop.ErrHandoffExpired
	}
	if err := record.Validate(); err != nil {
		return Handoff{}, err
	}
	switch record.Status {
	case desktop.StatusAccepted, desktop.StatusRunning:
		return Handoff{}, ErrHandoffPending
	case desktop.StatusFailed, desktop.StatusCancelled, desktop.StatusOutcomeUnknown:
		return Handoff{}, desktop.ErrHandoffUnavailable
	case desktop.StatusSucceeded:
		if record.Handoff == nil {
			return Handoff{}, desktop.ErrHandoffUnavailable
		}
		return handoffProjection(*record.Handoff)
	default:
		return Handoff{}, desktop.ErrInvalidRecord
	}
}

func (a *Application) getOpen(ctx context.Context, operationID string, now time.Time) (desktop.Record, error) {
	if timed, ok := a.authority.(interface {
		GetOpenAt(context.Context, string, time.Time) (desktop.Record, error)
	}); ok {
		return timed.GetOpenAt(ctx, operationID, now)
	}
	return a.authority.GetOpen(ctx, operationID)
}

func operationProjection(record desktop.Record) (Operation, error) {
	if err := record.Validate(); err != nil {
		return Operation{}, err
	}
	return Operation{OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID, FencingToken: record.Request.FencingToken, SandboxID: record.Request.SandboxID, Status: record.Status, ObservedAt: record.ObservedAt.UTC(), Type: OperationOpenDesktopSession}, nil
}

func closeOperationProjection(record desktop.CloseRecord) (Operation, error) {
	if err := record.Validate(); err != nil {
		return Operation{}, err
	}
	return Operation{OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID, FencingToken: record.Request.FencingToken, SandboxID: record.Request.SandboxID, Status: record.Status, ObservedAt: record.ObservedAt.UTC(), Type: OperationCloseDesktopSession}, nil
}

func handoffProjection(handoff desktop.Handoff) (Handoff, error) {
	if err := handoff.Validate(); err != nil {
		return Handoff{}, err
	}
	return Handoff{OperationID: handoff.OperationID, AttemptID: handoff.AttemptID, FencingToken: handoff.FencingToken, SandboxID: handoff.SandboxID, DesktopSessionID: handoff.DesktopSessionID, CapabilityProfileID: handoff.CapabilityProfileID, Protocol: handoff.Protocol, MediaProfileID: handoff.MediaProfileID, ControlProfileID: handoff.ControlProfileID, InternalEndpointReference: handoff.InternalEndpointReference, ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: handoff.ExpiresAt.UTC()}, nil
}

var _ interface {
	Open(context.Context, desktop.OpenRequest) (Operation, error)
	GetOperation(context.Context, string) (Operation, error)
	GetHandoff(context.Context, string) (Handoff, error)
} = (*Application)(nil)
