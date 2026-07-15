package instance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

const recoveryTimeout = 5 * time.Second

// Service is the application boundary shared by HTTP, CLI, and future control
// surfaces.
type Service interface {
	Create(context.Context, Spec) (*Instance, error)
	List(context.Context) ([]*Instance, error)
	Inspect(context.Context, string) (*Instance, error)
	Start(context.Context, string) (*Instance, error)
	Stop(context.Context, string) (*Instance, error)
	Remove(context.Context, string) error
}

type service struct {
	repository   Repository
	driver       Driver
	newID        func() (string, error)
	now          func() time.Time
	maxInstances int
	createMu     sync.Mutex
	locksMu      sync.Mutex
	locks        map[string]*instanceLock
}

type instanceLock struct {
	token chan struct{}
	refs  int
}

// ServiceOption customizes Service infrastructure. Production callers normally use
// the defaults; deterministic options are useful in tests.
type ServiceOption func(*service)

// WithIDGenerator replaces the cryptographically random default ID generator.
func WithIDGenerator(generator func() (string, error)) ServiceOption {
	return func(s *service) {
		if generator != nil {
			s.newID = generator
		}
	}
}

// WithClock replaces the system clock used for lifecycle timestamps.
func WithClock(clock func() time.Time) ServiceOption {
	return func(s *service) {
		if clock != nil {
			s.now = clock
		}
	}
}

// WithMaxInstances sets the process-wide instance quota enforced by Service.
func WithMaxInstances(limit int) ServiceOption {
	return func(s *service) {
		if limit > 0 {
			s.maxInstances = limit
		}
	}
}

// NewService creates an instance service backed by repository and driver.
func NewService(repository Repository, driver Driver, options ...ServiceOption) (Service, error) {
	if repository == nil {
		return nil, errors.New("instance repository is required")
	}
	if driver == nil {
		return nil, errors.New("instance driver is required")
	}
	s := &service{
		repository:   repository,
		driver:       driver,
		newID:        randomID,
		now:          time.Now,
		maxInstances: DefaultMaxInstances,
		locks:        make(map[string]*instanceLock),
	}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	return s, nil
}

func (s *service) Create(ctx context.Context, spec Spec) (*Instance, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	inst, release, err := s.reserve(ctx, spec)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.driver.Create(ctx, inst.ID, spec); err != nil {
		if err := s.recoverOperation(ctx, inst, StateStopped, "create", err); err != nil {
			return nil, err
		}
		return clone(inst), nil
	}
	if err := s.completeOperation(ctx, inst, StateStopped); err != nil {
		return nil, err
	}
	return clone(inst), nil
}

func (s *service) reserve(ctx context.Context, spec Spec) (*Instance, func(), error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	count, err := s.repository.Count(ctx)
	if err != nil {
		return nil, nil, err
	}
	if count >= s.maxInstances {
		return nil, nil, fmt.Errorf("%w: maximum %d", ErrLimitExceeded, s.maxInstances)
	}
	id, err := s.newID()
	if err != nil {
		return nil, nil, fmt.Errorf("generate instance id: %w", err)
	}
	release, err := s.acquire(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	inst := &Instance{ID: id, Name: spec.Name, Workload: spec.Workload, State: StateCreating, CreatedAt: now, UpdatedAt: now}
	if err := s.repository.Create(ctx, inst); err != nil {
		release()
		return nil, nil, err
	}
	return inst, release, nil
}

func (s *service) List(ctx context.Context) ([]*Instance, error) {
	return s.repository.List(ctx)
}

func (s *service) Inspect(ctx context.Context, id string) (*Instance, error) {
	release, err := s.acquire(ctx, id)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.load(ctx, id)
}

func (s *service) Start(ctx context.Context, id string) (*Instance, error) {
	release, err := s.acquire(ctx, id)
	if err != nil {
		return nil, err
	}
	defer release()

	inst, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.move(ctx, inst, StateStarting); err != nil {
		return nil, err
	}
	if err := s.driver.Start(ctx, id); err != nil {
		if err := s.recoverOperation(ctx, inst, StateRunning, "start", err); err != nil {
			return nil, err
		}
		return clone(inst), nil
	}
	if err := s.completeOperation(ctx, inst, StateRunning); err != nil {
		return nil, err
	}
	return clone(inst), nil
}

func (s *service) Stop(ctx context.Context, id string) (*Instance, error) {
	release, err := s.acquire(ctx, id)
	if err != nil {
		return nil, err
	}
	defer release()

	inst, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.move(ctx, inst, StateStopping); err != nil {
		return nil, err
	}
	if err := s.driver.Stop(ctx, id); err != nil {
		if err := s.recoverOperation(ctx, inst, StateStopped, "stop", err); err != nil {
			return nil, err
		}
		return clone(inst), nil
	}
	if err := s.completeOperation(ctx, inst, StateStopped); err != nil {
		return nil, err
	}
	return clone(inst), nil
}

func (s *service) Remove(ctx context.Context, id string) error {
	release, err := s.acquire(ctx, id)
	if err != nil {
		return err
	}
	defer release()

	inst, err := s.load(ctx, id)
	if err != nil {
		return err
	}
	if inst.State != StateRemoving {
		if inst.State != StateStopped && inst.State != StateFailed {
			return fmt.Errorf("%w: cannot remove instance in %s", ErrInvalidTransition, inst.State)
		}
		if err := s.move(ctx, inst, StateRemoving); err != nil {
			return err
		}
	}
	if err := s.driver.Remove(ctx, id); err != nil {
		return fmt.Errorf("remove runtime: %w", err)
	}
	recoveryCtx, cancel := s.recoveryContext(ctx)
	defer cancel()
	return s.repository.Delete(recoveryCtx, id)
}

func (s *service) move(ctx context.Context, inst *Instance, next State) error {
	if !inst.State.CanTransition(next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, inst.State, next)
	}
	candidate := clone(inst)
	candidate.State = next
	candidate.UpdatedAt = s.now()
	if err := s.repository.Update(ctx, candidate); err != nil {
		return err
	}
	*inst = *candidate
	return nil
}

// load returns an instance after lazily reconciling an interrupted transition
// with the runtime. Per-instance locking must be held by the caller.
func (s *service) load(ctx context.Context, id string) (*Instance, error) {
	inst, err := s.repository.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	switch inst.State {
	case StateCreating, StateStarting, StateStopping:
		if err := s.reconcile(ctx, inst); err != nil {
			return nil, err
		}
	}
	return inst, nil
}

// completeOperation persists a successful driver's terminal state. If that
// write fails, runtime inspection provides a second, bounded reconciliation
// attempt. A transient persistence failure is therefore transparent once the
// repository and runtime agree again.
func (s *service) completeOperation(ctx context.Context, inst *Instance, target State) error {
	recoveryCtx, cancel := s.recoveryContext(ctx)
	err := s.move(recoveryCtx, inst, target)
	cancel()
	if err == nil {
		return nil
	}

	recoveryCtx, cancel = s.recoveryContext(ctx)
	reconcileErr := s.reconcile(recoveryCtx, inst)
	cancel()
	if reconcileErr == nil && inst.State == target {
		return nil
	}
	if reconcileErr == nil {
		reconcileErr = fmt.Errorf("runtime reconciled to %s, want %s", inst.State, target)
	}
	return errors.Join(fmt.Errorf("persist %s state: %w", target, err), reconcileErr)
}

// recoverOperation reconciles the actual runtime after a driver reports an
// error. This handles drivers that performed the operation but lost the reply,
// as well as clean failures that left the previous runtime state unchanged.
func (s *service) recoverOperation(ctx context.Context, inst *Instance, target State, operation string, operationErr error) error {
	recoveryCtx, cancel := s.recoveryContext(ctx)
	reconcileErr := s.reconcile(recoveryCtx, inst)
	cancel()
	if reconcileErr == nil && inst.State == target {
		return nil
	}
	if reconcileErr == nil {
		reconcileErr = fmt.Errorf("runtime reconciled to %s, want %s", inst.State, target)
	}
	return fmt.Errorf("%s runtime: %w", operation, errors.Join(operationErr, reconcileErr))
}

func (s *service) reconcile(ctx context.Context, inst *Instance) error {
	runtimeState, inspectErr := s.driver.Inspect(ctx, inst.ID)
	if inspectErr != nil {
		if !errors.Is(inspectErr, ErrNotFound) {
			return fmt.Errorf("inspect runtime: %w", inspectErr)
		}
		return s.move(ctx, inst, StateFailed)
	}

	var target State
	switch inst.State {
	case StateCreating:
		if runtimeState == RuntimeStopped {
			target = StateStopped
		} else {
			target = StateFailed
		}
	case StateStarting, StateStopping:
		switch runtimeState {
		case RuntimeStopped:
			target = StateStopped
		case RuntimeRunning:
			target = StateRunning
		default:
			return fmt.Errorf("%w: %q", ErrInvalidRuntime, runtimeState)
		}
	default:
		return nil
	}
	return s.move(ctx, inst, target)
}

func (s *service) recoveryContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), recoveryTimeout)
}

func (s *service) acquire(ctx context.Context, id string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.locksMu.Lock()
	lock, exists := s.locks[id]
	if !exists {
		lock = &instanceLock{token: make(chan struct{}, 1)}
		lock.token <- struct{}{}
		s.locks[id] = lock
	}
	lock.refs++
	s.locksMu.Unlock()

	select {
	case <-ctx.Done():
		s.releaseRef(id, lock)
		return nil, ctx.Err()
	case <-lock.token:
		if err := ctx.Err(); err != nil {
			lock.token <- struct{}{}
			s.releaseRef(id, lock)
			return nil, err
		}
		return func() {
			lock.token <- struct{}{}
			s.releaseRef(id, lock)
		}, nil
	}
}

func (s *service) releaseRef(id string, lock *instanceLock) {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	lock.refs--
	if lock.refs == 0 {
		delete(s.locks, id)
	}
}

func clone(inst *Instance) *Instance {
	copy := *inst
	return &copy
}

func randomID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return "instance-" + hex.EncodeToString(bytes[:]), nil
}

var _ Service = (*service)(nil)
