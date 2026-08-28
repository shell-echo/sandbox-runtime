package application

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

// SandboxReader is the narrow trusted lifecycle projection used for staging
// readiness and tenant binding. Artifact and lifecycle persistence stay
// independent.
type SandboxReader interface {
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
}

type CoordinationAuthority interface {
	artifact.Authority
	SynchronizeSandboxAuthority(context.Context, artifact.SandboxAuthority) error
}

// Vertical composes lifecycle authority, durable artifact acceptance, and a
// process-owned asynchronous worker boundary. It stages provider-local bytes
// only; publication remains outside this service.
type Vertical struct {
	application *Application
	authority   CoordinationAuthority
	sandboxes   SandboxReader
	support     artifact.SupportChecker
	clock       Clock

	workerContext context.Context
	cancelWorkers context.CancelFunc
	workerMu      sync.Mutex
	workers       map[string]struct{}
	workerWait    sync.WaitGroup
	closed        bool
}

func NewVertical(authority CoordinationAuthority, stager artifact.Stager, sandboxes SandboxReader, support artifact.SupportChecker, clock Clock) (*Vertical, error) {
	if authority == nil || stager == nil || sandboxes == nil || support == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	base, err := New(authority, stager, clock)
	if err != nil {
		return nil, err
	}
	workerContext, cancel := context.WithCancel(context.Background())
	return &Vertical{
		application: base, authority: authority, sandboxes: sandboxes, support: support, clock: clock,
		workerContext: workerContext, cancelWorkers: cancel, workers: make(map[string]struct{}),
	}, nil
}

// Accept performs every fail-closed precondition before it durably reserves
// work, then schedules dispatch independently from the request context.
func (v *Vertical) Accept(ctx context.Context, request artifact.Request) (artifact.Reservation, error) {
	if err := v.ready(ctx); err != nil {
		return artifact.Reservation{}, err
	}
	now := v.clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return artifact.Reservation{}, err
	}
	if err := v.support.CheckSupport(ctx, request.Clone()); err != nil {
		return artifact.Reservation{}, errors.Join(artifact.ErrUnsupportedChecks, err)
	}
	if err := v.synchronizeSandbox(ctx, request, now); err != nil {
		return artifact.Reservation{}, err
	}
	reservation, err := v.application.Accept(ctx, request)
	if err != nil {
		return artifact.Reservation{}, err
	}
	if reservation.Operation.Status == artifact.OperationAccepted {
		v.schedule(reservation.Operation.Request.OperationID)
	}
	return reservation.Clone(), nil
}

func (v *Vertical) GetOperation(ctx context.Context, operationID string) (artifact.Operation, error) {
	if err := v.ready(ctx); err != nil {
		return artifact.Operation{}, err
	}
	return v.application.GetOperation(ctx, operationID)
}

func (v *Vertical) GetEvidence(ctx context.Context, operationID string) (artifact.Evidence, error) {
	if err := v.ready(ctx); err != nil {
		return artifact.Evidence{}, err
	}
	return v.application.GetEvidence(ctx, operationID)
}

// Recover safely dispatches retained accepted records and converts retained
// running records to outcome_unknown without repeating their side effect.
func (v *Vertical) Recover(ctx context.Context) ([]artifact.Operation, error) {
	if err := v.ready(ctx); err != nil {
		return nil, err
	}
	operations, err := v.application.Recover(ctx)
	if err == artifact.ErrOutcomeUnknown {
		err = nil
	}
	return operations, err
}

// Close stops process-owned work and waits until every worker has persisted its
// final known or unknown outcome. The composition root closes repositories only
// after this returns.
func (v *Vertical) Close() error {
	if v == nil {
		return nil
	}
	v.workerMu.Lock()
	if !v.closed {
		v.closed = true
		v.cancelWorkers()
	}
	v.workerMu.Unlock()
	v.workerWait.Wait()
	return nil
}

func (v *Vertical) synchronizeSandbox(ctx context.Context, request artifact.Request, now time.Time) error {
	sandbox, err := v.sandboxes.GetSandbox(ctx, request.SandboxID)
	if err != nil {
		return err
	}
	if err := sandbox.Validate(); err != nil {
		return err
	}
	if sandbox.ID != request.SandboxID || sandbox.Generation > math.MaxInt64 || int64(sandbox.Generation) != request.ExpectedGeneration {
		return artifact.ErrGenerationConflict
	}
	if sandbox.TenantID != request.TenantID {
		return artifact.ErrTenantBinding
	}
	if sandbox.DesiredState != lifecycle.DesiredReady || sandbox.ObservedState != lifecycle.ObservedReady || sandbox.ObservedGeneration != sandbox.Generation {
		return artifact.ErrSandboxNotReady
	}
	if !sandbox.LeaseExpiresAt.After(now) {
		return artifact.ErrSandboxLeaseExpired
	}
	return v.authority.SynchronizeSandboxAuthority(ctx, artifact.SandboxAuthority{
		SandboxID: sandbox.ID, Generation: int64(sandbox.Generation), FencingToken: request.FencingToken,
	})
}

func (v *Vertical) schedule(operationID string) {
	v.workerMu.Lock()
	if v.closed {
		v.workerMu.Unlock()
		return
	}
	if _, exists := v.workers[operationID]; exists {
		v.workerMu.Unlock()
		return
	}
	v.workers[operationID] = struct{}{}
	v.workerWait.Add(1)
	v.workerMu.Unlock()

	go func() {
		defer v.workerWait.Done()
		defer func() {
			v.workerMu.Lock()
			delete(v.workers, operationID)
			v.workerMu.Unlock()
		}()
		_, _ = v.application.Dispatch(v.workerContext, operationID)
	}()
}

func (v *Vertical) ready(ctx context.Context) error {
	if v == nil || v.application == nil || v.authority == nil || v.sandboxes == nil || v.support == nil || v.clock == nil || v.workerContext == nil || v.cancelWorkers == nil {
		return ErrInvalidApplication
	}
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.workerMu.Lock()
	closed := v.closed
	v.workerMu.Unlock()
	if closed {
		return ErrInvalidApplication
	}
	return nil
}

var _ interface {
	Accept(context.Context, artifact.Request) (artifact.Reservation, error)
	GetOperation(context.Context, string) (artifact.Operation, error)
	GetEvidence(context.Context, string) (artifact.Evidence, error)
} = (*Vertical)(nil)
