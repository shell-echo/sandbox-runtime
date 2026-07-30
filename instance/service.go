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

const (
	recoveryTimeout        = 5 * time.Second
	startupRecoveryTimeout = 5 * time.Minute
)

// Service is the application boundary shared by HTTP, CLI, and future control
// surfaces.
type Service interface {
	Create(context.Context, Spec) (*Instance, error)
	List(context.Context) ([]*Instance, error)
	Inspect(context.Context, string) (*Instance, error)
	Recover(context.Context) error
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
	if err := s.finishOperation(ctx, inst, RuntimeStopped, StateStopped, "create"); err != nil {
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
	if err := ValidateID(id); err != nil {
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
	snapshots, err := s.repository.List(ctx)
	if err != nil {
		return nil, err
	}
	instances := make([]*Instance, 0, len(snapshots))
	for _, snapshot := range snapshots {
		inst, err := s.Inspect(ctx, snapshot.ID)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, ErrNotFound) {
				continue
			}
			// Listing is best effort: preserve the durable last-known state when
			// a single runtime inspection fails. Inspect remains the strict API.
			instances = append(instances, clone(snapshot))
			continue
		}
		instances = append(instances, inst)
	}
	return instances, nil
}

// Recover reconciles persisted instances after process startup and completes
// interrupted removals. It continues through all records and returns every
// recovery error so one damaged resource cannot hide the state of the others.
func (s *service) Recover(ctx context.Context) error {
	recoveryCtx, cancel := context.WithTimeout(ctx, startupRecoveryTimeout)
	defer cancel()
	ctx = recoveryCtx
	snapshots, err := s.repository.List(ctx)
	if err != nil {
		return err
	}
	known := make(map[string]*Instance, len(snapshots))
	if len(snapshots) > s.maxInstances {
		return fmt.Errorf("%w: repository contains %d instances, maximum %d", ErrLimitExceeded, len(snapshots), s.maxInstances)
	}
	for _, snapshot := range snapshots {
		known[snapshot.ID] = snapshot
	}
	resources, err := s.driver.List(ctx)
	if err != nil {
		return fmt.Errorf("list runtime resources: %w", err)
	}
	var recoveryErrors []error
	for _, resource := range resources {
		if persisted, exists := known[resource.ID]; exists {
			if persisted.Name != resource.Spec.Name || persisted.Workload != resource.Spec.Workload {
				recoveryErrors = append(recoveryErrors, fmt.Errorf(
					"runtime instance %s metadata conflicts with its repository record", resource.ID,
				))
			}
			continue
		}
		if len(known) >= s.maxInstances {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("adopt runtime instance %s: %w: maximum %d", resource.ID, ErrLimitExceeded, s.maxInstances))
			continue
		}
		if err := s.adopt(ctx, resource); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("adopt runtime instance %s: %w", resource.ID, err))
			continue
		}
		known[resource.ID] = &Instance{ID: resource.ID, Name: resource.Spec.Name, Workload: resource.Spec.Workload}
		snapshots = append(snapshots, &Instance{ID: resource.ID})
	}
	for _, snapshot := range snapshots {
		if err := s.recoverInstance(ctx, snapshot.ID); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("recover instance %s: %w", snapshot.ID, err))
		}
	}
	return errors.Join(recoveryErrors...)
}

func (s *service) adopt(ctx context.Context, resource RuntimeResource) error {
	if err := ValidateID(resource.ID); err != nil {
		return err
	}
	if err := resource.Spec.Validate(); err != nil {
		return err
	}
	release, err := s.acquire(ctx, resource.ID)
	if err != nil {
		return err
	}
	defer release()
	createdAt := resource.CreatedAt
	if createdAt.IsZero() {
		createdAt = s.now()
	}
	inst := &Instance{
		ID: resource.ID, Name: resource.Spec.Name, Workload: resource.Spec.Workload,
		State: StateStarting, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	if err := s.repository.Create(ctx, inst); err != nil {
		return err
	}
	return s.reconcile(ctx, inst)
}

func (s *service) recoverInstance(ctx context.Context, id string) error {
	release, err := s.acquire(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	inst, err := s.repository.Get(ctx, id)
	if err != nil {
		return err
	}
	if inst.State != StateRemoving {
		_, err = s.load(ctx, id)
		return err
	}
	if err := s.driver.Remove(ctx, id); err != nil {
		return fmt.Errorf("finish runtime removal: %w", err)
	}
	return s.repository.Delete(ctx, id)
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
	if err := s.finishOperation(ctx, inst, RuntimeRunning, StateRunning, "start"); err != nil {
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
	if err := s.finishOperation(ctx, inst, RuntimeStopped, StateStopped, "stop"); err != nil {
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
	return s.persistState(ctx, inst, next, "")
}

// load returns the runtime-reconciled instance. Per-instance locking must be
// held by the caller.
func (s *service) load(ctx context.Context, id string) (*Instance, error) {
	inst, err := s.repository.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if inst.State != StateRemoving && inst.State != StateFailed {
		if err := s.reconcile(ctx, inst); err != nil {
			return nil, err
		}
	}
	return inst, nil
}

// finishOperation confirms that a successful driver call reached its expected
// runtime state before committing the control-plane state.
func (s *service) finishOperation(ctx context.Context, inst *Instance, runtimeTarget RuntimeState, target State, operation string) error {
	recoveryCtx, cancel := s.recoveryContext(ctx)
	observation, err := s.driver.Inspect(recoveryCtx, inst.ID)
	cancel()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			failure := fmt.Sprintf("%s succeeded but runtime resource is missing", operation)
			persistCtx, persistCancel := s.recoveryContext(ctx)
			persistErr := s.fail(persistCtx, inst, failure)
			persistCancel()
			if persistErr != nil {
				return errors.Join(fmt.Errorf("confirm %s runtime: %w", operation, err), persistErr)
			}
		}
		return fmt.Errorf("confirm %s runtime: %w", operation, err)
	}
	if err := validateObservation(observation); err != nil {
		return err
	}
	if observation.State != runtimeTarget {
		failure := fmt.Sprintf("%s completed but runtime is %s", operation, observation.State)
		if detail := observationFailure(observation); detail != "" {
			failure += ": " + detail
		}
		persistCtx, persistCancel := s.recoveryContext(ctx)
		persistErr := s.fail(persistCtx, inst, failure)
		persistCancel()
		if persistErr != nil {
			return errors.Join(errors.New(failure), persistErr)
		}
		return errors.New(failure)
	}
	if err := s.move(ctx, inst, target); err != nil {
		recoveryCtx, cancel := s.recoveryContext(ctx)
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
	return nil
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
	observation, inspectErr := s.driver.Inspect(ctx, inst.ID)
	if inspectErr != nil {
		if !errors.Is(inspectErr, ErrNotFound) {
			return fmt.Errorf("inspect runtime: %w", inspectErr)
		}
		return s.fail(ctx, inst, "runtime resource is missing")
	}
	if err := validateObservation(observation); err != nil {
		return err
	}

	switch inst.State {
	case StateCreating:
		if observation.State == RuntimeStopped {
			return s.move(ctx, inst, StateStopped)
		}
		return s.fail(ctx, inst, "runtime was running while creation was incomplete")
	case StateStarting, StateStopping:
		switch observation.State {
		case RuntimeStopped:
			return s.move(ctx, inst, StateStopped)
		case RuntimeRunning:
			return s.move(ctx, inst, StateRunning)
		}
	case StateStopped:
		if observation.State == RuntimeRunning {
			return s.persistState(ctx, inst, StateRunning, "")
		}
	case StateRunning:
		if observation.State == RuntimeStopped {
			failure := "runtime stopped unexpectedly"
			if detail := observationFailure(observation); detail != "" {
				failure += ": " + detail
			}
			return s.fail(ctx, inst, failure)
		}
	default:
		return nil
	}
	return nil
}

func (s *service) fail(ctx context.Context, inst *Instance, failure string) error {
	if inst.State == StateFailed {
		return nil
	}
	return s.persistState(ctx, inst, StateFailed, failure)
}

func (s *service) persistState(ctx context.Context, inst *Instance, state State, failure string) error {
	candidate := clone(inst)
	candidate.State = state
	candidate.Failure = failure
	candidate.UpdatedAt = s.now()
	if candidate.UpdatedAt.Before(candidate.CreatedAt) {
		candidate.UpdatedAt = candidate.CreatedAt
	}
	if candidate.UpdatedAt.Before(inst.UpdatedAt) {
		candidate.UpdatedAt = inst.UpdatedAt
	}
	if err := s.repository.Update(ctx, candidate); err != nil {
		return err
	}
	*inst = *candidate
	return nil
}

func validateObservation(observation RuntimeObservation) error {
	switch observation.State {
	case RuntimeStopped, RuntimeRunning:
	default:
		return fmt.Errorf("%w: %q", ErrInvalidRuntime, observation.State)
	}
	switch observation.StopReason {
	case RuntimeStopReasonNone, RuntimeStopReasonOOMKilled, RuntimeStopReasonRuntimeError:
	default:
		return fmt.Errorf("%w: unknown stop reason %q", ErrInvalidRuntime, observation.StopReason)
	}
	if observation.State == RuntimeRunning && observation.StopReason != RuntimeStopReasonNone {
		return fmt.Errorf("%w: running runtime has stop reason %q", ErrInvalidRuntime, observation.StopReason)
	}
	return nil
}

func observationFailure(observation RuntimeObservation) string {
	switch {
	case observation.StopReason == RuntimeStopReasonOOMKilled:
		return fmt.Sprintf("out of memory (exit code %d)", observation.ExitCode)
	case observation.StopReason == RuntimeStopReasonRuntimeError:
		return fmt.Sprintf("runtime failure (exit code %d)", observation.ExitCode)
	case observation.ExitCode != 0:
		return fmt.Sprintf("exit code %d", observation.ExitCode)
	default:
		return ""
	}
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
