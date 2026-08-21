// Package application composes the bounded Provider-local exec port without
// exposing HTTP, repository, lifecycle, or backend-driver types.
package application

import (
	"context"
	"errors"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

// Clock makes deadline behavior deterministic in application tests.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Application struct {
	executor providerexec.Executor
	clock    Clock
}

func New(executor providerexec.Executor, clock Clock) (*Application, error) {
	if executor == nil || clock == nil {
		return nil, providerexec.ErrInvalidApplication
	}
	return &Application{executor: executor, clock: clock}, nil
}

// Start validates and dispatches one provider-local invocation. It is not a
// durable Provider operation acceptance boundary; persistence, result
// retention, cancellation, and reconciliation remain P2.2 responsibilities.
func (a *Application) Start(ctx context.Context, request providerexec.Request) (providerexec.Dispatch, error) {
	if a == nil || a.executor == nil || a.clock == nil {
		return providerexec.Dispatch{}, providerexec.ErrInvalidApplication
	}
	if ctx == nil {
		return providerexec.Dispatch{}, context.Canceled
	}
	now := a.clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return providerexec.Dispatch{}, err
	}
	operationContext, cancel := context.WithDeadline(ctx, request.Deadline)
	defer cancel()
	if err := operationContext.Err(); err != nil {
		return providerexec.Dispatch{}, err
	}
	reference, err := a.executor.Start(operationContext, providerexec.Invocation{
		Request:   request.Clone(),
		StartedAt: now,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return providerexec.Dispatch{}, providerexec.ErrDispatchUnknown
		}
		return providerexec.Dispatch{}, err
	}
	dispatch := providerexec.Dispatch{ExecutionReference: reference, AcceptedAt: now}
	if err := dispatch.Validate(); err != nil {
		return providerexec.Dispatch{}, providerexec.ErrInvalidDispatch
	}
	return dispatch, nil
}
