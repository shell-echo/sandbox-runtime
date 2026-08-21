// Package application composes the Provider-local lifecycle coordinator behind
// the narrow application port consumed by Provider transport.
package application

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var ErrInvalidApplication = errors.New("invalid lifecycle application")

// Application is the Provider-local lifecycle application. It does not own
// caller authorization or the aggregate operation ledger.
type Application struct {
	coordinator *coordinator.Coordinator
}

func New(repo repository.Repository, driver coordinator.Driver, clock coordinator.Clock) (*Application, error) {
	if repo == nil || driver == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	service, err := coordinator.New(repo, driver, clock)
	if err != nil {
		return nil, err
	}
	return &Application{coordinator: service}, nil
}

// Recover reconciles provider-local operations that survived a process
// restart. A non-nil error keeps startup fail-closed after retained evidence.
func (a *Application) Recover(ctx context.Context) error {
	if a == nil || a.coordinator == nil {
		return ErrInvalidApplication
	}
	_, err := a.coordinator.ReconcilePending(ctx)
	return err
}

func (a *Application) AcceptCreate(ctx context.Context, request lifecycle.CreateRequest) (repository.CreateResult, error) {
	if a == nil || a.coordinator == nil {
		return repository.CreateResult{}, ErrInvalidApplication
	}
	return a.coordinator.AcceptCreate(ctx, request)
}

func (a *Application) GetSandbox(ctx context.Context, id string) (lifecycle.Sandbox, error) {
	if a == nil || a.coordinator == nil {
		return lifecycle.Sandbox{}, ErrInvalidApplication
	}
	return a.coordinator.GetSandbox(ctx, id)
}

func (a *Application) GetOperation(ctx context.Context, id string) (lifecycle.Operation, error) {
	if a == nil || a.coordinator == nil {
		return lifecycle.Operation{}, ErrInvalidApplication
	}
	return a.coordinator.GetOperation(ctx, id)
}

var _ interface {
	AcceptCreate(context.Context, lifecycle.CreateRequest) (repository.CreateResult, error)
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
	GetOperation(context.Context, string) (lifecycle.Operation, error)
} = (*Application)(nil)
