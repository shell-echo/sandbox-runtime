// Package application composes the Provider-local lifecycle coordinator behind
// the narrow application port consumed by Provider transport.
package application

import (
	"context"
	"errors"
	"sync"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var ErrInvalidApplication = errors.New("invalid lifecycle application")

// Application is the Provider-local lifecycle application. It does not own
// caller authorization or the aggregate operation ledger.
type Application struct {
	coordinator *coordinator.Coordinator

	workerContext context.Context
	cancelWorkers context.CancelFunc
	workerMu      sync.Mutex
	workers       map[string]struct{}
	workerWait    sync.WaitGroup
	closed        bool
}

func New(repo repository.Repository, driver coordinator.Driver, clock coordinator.Clock) (*Application, error) {
	if repo == nil || driver == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	service, err := coordinator.New(repo, driver, clock)
	if err != nil {
		return nil, err
	}
	workerContext, cancel := context.WithCancel(context.Background())
	return &Application{
		coordinator: service, workerContext: workerContext, cancelWorkers: cancel,
		workers: make(map[string]struct{}),
	}, nil
}

// Recover reconciles provider-local operations that survived a process
// restart. A non-nil error keeps startup fail-closed after retained evidence.
func (a *Application) Recover(ctx context.Context) error {
	if err := a.ready(ctx); err != nil {
		return err
	}
	_, err := a.coordinator.ReconcilePending(ctx)
	return err
}

func (a *Application) AcceptCreate(ctx context.Context, request lifecycle.CreateRequest) (repository.CreateResult, error) {
	if err := a.ready(ctx); err != nil {
		return repository.CreateResult{}, err
	}
	result, err := a.coordinator.AcceptCreate(ctx, request)
	if err != nil {
		return repository.CreateResult{}, err
	}
	if result.Operation.State == lifecycle.OperationAccepted {
		a.schedule(result.Operation.ID)
	}
	return result, nil
}

func (a *Application) GetSandbox(ctx context.Context, id string) (lifecycle.Sandbox, error) {
	if err := a.ready(ctx); err != nil {
		return lifecycle.Sandbox{}, err
	}
	return a.coordinator.GetSandbox(ctx, id)
}

func (a *Application) GetOperation(ctx context.Context, id string) (lifecycle.Operation, error) {
	if err := a.ready(ctx); err != nil {
		return lifecycle.Operation{}, err
	}
	return a.coordinator.GetOperation(ctx, id)
}

// Close stops process-owned lifecycle work and waits for every in-flight
// reconciliation to retain its final known or unknown outcome.
func (a *Application) Close() error {
	if a == nil {
		return nil
	}
	a.workerMu.Lock()
	if !a.closed {
		a.closed = true
		a.cancelWorkers()
	}
	a.workerMu.Unlock()
	a.workerWait.Wait()
	return nil
}

func (a *Application) schedule(operationID string) {
	a.workerMu.Lock()
	if a.closed {
		a.workerMu.Unlock()
		return
	}
	if _, exists := a.workers[operationID]; exists {
		a.workerMu.Unlock()
		return
	}
	a.workers[operationID] = struct{}{}
	a.workerWait.Add(1)
	a.workerMu.Unlock()

	go func() {
		defer a.workerWait.Done()
		defer func() {
			a.workerMu.Lock()
			delete(a.workers, operationID)
			a.workerMu.Unlock()
		}()
		_, _ = a.coordinator.ReconcileOperation(a.workerContext, operationID)
	}()
}

func (a *Application) ready(ctx context.Context) error {
	if a == nil || a.coordinator == nil || a.workerContext == nil || a.cancelWorkers == nil {
		return ErrInvalidApplication
	}
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.workerMu.Lock()
	closed := a.closed
	a.workerMu.Unlock()
	if closed {
		return ErrInvalidApplication
	}
	return nil
}

var _ interface {
	AcceptCreate(context.Context, lifecycle.CreateRequest) (repository.CreateResult, error)
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
	GetOperation(context.Context, string) (lifecycle.Operation, error)
} = (*Application)(nil)
