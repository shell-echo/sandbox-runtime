package application

import (
	"context"
	"errors"
	"math"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

const allocationPersistenceTimeout = 5 * time.Second

var profileIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

// SandboxReader is the narrow trusted lifecycle projection consumed by the
// session vertical. The lifecycle and session repositories remain separate.
type SandboxReader interface {
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
}

// TerminalProfile binds one configured lifecycle runtime profile to the
// terminal capability profile and its fixed guest working directory.
type TerminalProfile struct {
	RuntimeProfileID    string
	CapabilityProfileID string
	WorkingDirectory    string
}

func (p TerminalProfile) validate() error {
	if !profileIdentifierPattern.MatchString(p.RuntimeProfileID) ||
		!profileIdentifierPattern.MatchString(p.CapabilityProfileID) ||
		p.WorkingDirectory != "/workspace" {
		return ErrInvalidApplication
	}
	return nil
}

// Vertical composes lifecycle observation, durable session authority, and a
// reconnectable terminal runtime. It is a single-controller coordinator; it
// does not provide cross-repository atomicity or an opaque reference registry.
type Vertical struct {
	authority session.CoordinationAuthority
	runtime   terminal.Runtime
	sandboxes SandboxReader
	profile   TerminalProfile
	clock     Clock
}

func NewVertical(authority session.CoordinationAuthority, runtime terminal.Runtime, sandboxes SandboxReader, profile TerminalProfile, clock Clock) (*Vertical, error) {
	if authority == nil || runtime == nil || sandboxes == nil || clock == nil || profile.validate() != nil {
		return nil, ErrInvalidApplication
	}
	return &Vertical{authority: authority, runtime: runtime, sandboxes: sandboxes, profile: profile, clock: clock}, nil
}

// Open durably reserves before allocation. Replays reconcile the same
// immutable allocation identity and never intentionally create a replacement.
func (a *Vertical) Open(ctx context.Context, request session.OpenRequest) (Operation, error) {
	if err := a.ready(ctx); err != nil {
		return Operation{}, err
	}
	now := a.clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return Operation{}, err
	}
	reservation, err := a.synchronizeAndReserve(ctx, request, now)
	if err != nil {
		return Operation{}, err
	}
	record, err := a.progress(ctx, reservation.Record)
	if err != nil {
		return Operation{}, err
	}
	return operationProjection(record)
}

// Reconcile observes one retained operation without creating a replacement
// terminal for a running or outcome-unknown record.
func (a *Vertical) Reconcile(ctx context.Context, operationID string) (Operation, error) {
	if err := a.ready(ctx); err != nil {
		return Operation{}, err
	}
	record, err := a.authority.GetOpen(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	record, err = a.progress(ctx, record)
	if err != nil {
		return Operation{}, err
	}
	return operationProjection(record)
}

// Recover reconciles all nonterminal session operations after repository and
// runtime reconstruction. It fails closed on an unreadable lifecycle source.
func (a *Vertical) Recover(ctx context.Context) ([]Operation, error) {
	if err := a.ready(ctx); err != nil {
		return nil, err
	}
	records, err := a.authority.ListOpen(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]Operation, 0, len(records))
	for _, record := range records {
		if record.Status != session.StatusAccepted && record.Status != session.StatusRunning {
			if _, cleanupErr := a.cleanupTerminal(ctx, record); cleanupErr != nil {
				return results, cleanupErr
			}
			continue
		}
		reconciled, reconcileErr := a.progress(ctx, record)
		if reconcileErr != nil {
			return results, reconcileErr
		}
		operation, projectionErr := operationProjection(reconciled)
		if projectionErr != nil {
			return results, projectionErr
		}
		results = append(results, operation)
	}
	return results, nil
}

// CommitHandoff accepts only evidence minted by a later opaque-reference
// registry. It refreshes lifecycle authority and transactionally rechecks it
// before recording success; this method does not create or resolve a reference.
func (a *Vertical) CommitHandoff(ctx context.Context, operationID string, evidence session.EndpointEvidence) (Operation, error) {
	if err := a.ready(ctx); err != nil {
		return Operation{}, err
	}
	record, err := a.authority.GetOpen(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	if record.Status != session.StatusRunning || record.Allocation == nil || record.Allocation.State != session.AllocationRunning ||
		evidence.ConnectionGeneration != record.Allocation.Receipt.ConnectionGeneration {
		return Operation{}, session.ErrHandoffUnavailable
	}
	now := a.clock.Now().UTC()
	reservation, err := a.synchronizeAndReserve(ctx, record.Request, now)
	if err != nil {
		return Operation{}, err
	}
	record = reservation.Record
	if record.Status != session.StatusRunning || record.Allocation == nil || record.Allocation.State != session.AllocationRunning {
		return Operation{}, session.ErrHandoffUnavailable
	}
	succeeded, err := session.Transition(record, session.StatusSucceeded, now, &evidence)
	if err != nil {
		return Operation{}, err
	}
	if err := a.updateOpen(ctx, succeeded, session.StatusRunning, now); err != nil {
		return Operation{}, err
	}
	return operationProjection(succeeded)
}

func (a *Vertical) GetHandoff(ctx context.Context, operationID string) (Handoff, error) {
	if a == nil {
		return Handoff{}, ErrInvalidApplication
	}
	base := &Application{authority: a.authority, clock: a.clock}
	return base.GetHandoff(ctx, operationID)
}

func (a *Vertical) progress(ctx context.Context, record session.Record) (session.Record, error) {
	if record.Status != session.StatusAccepted && record.Status != session.StatusRunning {
		return a.cleanupTerminal(ctx, record)
	}
	now := a.clock.Now().UTC()
	if now.IsZero() {
		return session.Record{}, session.ErrInvalidRequest
	}
	if !record.Request.Deadline.After(now) || !record.Request.ExpiresAt.After(now) {
		return a.expire(ctx, record, now)
	}
	reservation, err := a.synchronizeAndReserve(ctx, record.Request, now)
	if err != nil {
		if authorityInvalid(err) {
			return a.invalidate(ctx, record, now)
		}
		return session.Record{}, err
	}
	record = reservation.Record
	switch record.Status {
	case session.StatusAccepted:
		return a.allocate(ctx, record)
	case session.StatusRunning:
		return a.observe(ctx, record)
	default:
		return record.Clone(), nil
	}
}

func (a *Vertical) allocate(ctx context.Context, record session.Record) (session.Record, error) {
	request := terminalRequest(record.Request, a.profile.WorkingDirectory)
	// AcceptedAt is the durable allocation identity. Reusing it after a crash
	// lets the runtime recover the same private resource instead of seeing a
	// different allocation timestamp and rejecting or replacing it.
	allocation := terminal.Allocation{Request: request, AllocatedAt: record.AcceptedAt.UTC()}
	if err := allocation.Validate(); err != nil {
		return a.persistStatus(ctx, record, session.StatusFailed, a.monotonicNow(record.ObservedAt))
	}
	operationCtx, cancel := context.WithDeadline(ctx, record.Request.Deadline)
	receipt, allocationErr := a.runtime.Allocate(operationCtx, allocation)
	cancel()
	if allocationErr != nil {
		status := session.StatusOutcomeUnknown
		if knownAllocationFailure(allocationErr) {
			status = session.StatusFailed
		}
		return a.persistStatus(ctx, record, status, a.monotonicNow(record.ObservedAt))
	}
	if err := receipt.Validate(); err != nil || !receipt.Matches(request) || !receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
		return a.persistStatus(ctx, record, session.StatusOutcomeUnknown, a.monotonicNow(record.ObservedAt))
	}
	writeCtx, writeCancel := persistenceContext(ctx)
	attached, err := a.authority.AttachAllocation(writeCtx, sessionReceipt(receipt))
	writeCancel()
	if err != nil {
		return session.Record{}, errors.Join(terminal.ErrAllocationUnknown, err)
	}
	return attached.Record.Clone(), nil
}

func (a *Vertical) observe(ctx context.Context, record session.Record) (session.Record, error) {
	receipt := terminalReceipt(record.Allocation.Receipt)
	observation, observeErr := a.runtime.Observe(ctx, receipt)
	if observeErr != nil {
		state := terminal.ObservationOutcomeUnknown
		if errors.Is(observeErr, terminal.ErrTerminalNotFound) {
			state = terminal.ObservationAbsent
		} else if errors.Is(observeErr, terminal.ErrTerminalExpired) {
			state = terminal.ObservationExpired
		}
		observation = terminal.Observation{Receipt: receipt, State: state, ObservedAt: a.monotonicNow(record.Allocation.ObservedAt)}
	}
	if err := observation.Validate(); err != nil || observation.Receipt != receipt || observation.ObservedAt.Before(record.Allocation.ObservedAt) {
		observation = terminal.Observation{
			Receipt: receipt, State: terminal.ObservationOutcomeUnknown,
			ObservedAt: a.monotonicNow(record.Allocation.ObservedAt),
		}
	}
	writeCtx, writeCancel := persistenceContext(ctx)
	updated, err := a.authority.ObserveAllocation(writeCtx, record.Request.OperationID, sessionObservation(observation))
	writeCancel()
	if err != nil {
		return session.Record{}, err
	}
	if updated.Allocation != nil && (updated.Allocation.State == session.AllocationAbsent || updated.Allocation.State == session.AllocationExpired) {
		if cleanupErr := a.runtime.Cleanup(ctx, receipt); cleanupErr != nil {
			return updated, cleanupErr
		}
	}
	return updated, nil
}

func (a *Vertical) expire(ctx context.Context, record session.Record, now time.Time) (session.Record, error) {
	if record.Allocation == nil {
		return a.persistStatus(ctx, record, session.StatusFailed, a.monotonicTime(now, record.ObservedAt))
	}
	observation := session.AllocationEvidence{
		Receipt: record.Allocation.Receipt, State: session.AllocationExpired,
		ObservedAt: a.monotonicTime(now, record.Allocation.ObservedAt),
	}
	writeCtx, writeCancel := persistenceContext(ctx)
	updated, err := a.authority.ObserveAllocation(writeCtx, record.Request.OperationID, observation)
	writeCancel()
	if err != nil {
		return session.Record{}, err
	}
	if cleanupErr := a.runtime.Cleanup(ctx, terminalReceipt(record.Allocation.Receipt)); cleanupErr != nil {
		return updated, cleanupErr
	}
	return updated, nil
}

func (a *Vertical) invalidate(ctx context.Context, record session.Record, now time.Time) (session.Record, error) {
	updated, err := a.persistStatus(ctx, record, session.StatusFailed, a.monotonicTime(now, record.ObservedAt))
	if err != nil || record.Allocation == nil {
		return updated, err
	}
	if cleanupErr := a.runtime.Cleanup(ctx, terminalReceipt(record.Allocation.Receipt)); cleanupErr != nil {
		return updated, cleanupErr
	}
	return updated, nil
}

func (a *Vertical) cleanupTerminal(ctx context.Context, record session.Record) (session.Record, error) {
	if record.Allocation == nil {
		return record.Clone(), nil
	}
	now := a.clock.Now().UTC()
	cleanup := record.Status == session.StatusFailed || record.Status == session.StatusCancelled || !record.Request.ExpiresAt.After(now)
	if !cleanup {
		return record.Clone(), nil
	}
	if err := a.runtime.Cleanup(ctx, terminalReceipt(record.Allocation.Receipt)); err != nil {
		return record.Clone(), err
	}
	return record.Clone(), nil
}

func (a *Vertical) persistStatus(ctx context.Context, record session.Record, status session.Status, observedAt time.Time) (session.Record, error) {
	if record.Status != session.StatusAccepted && record.Status != session.StatusRunning {
		return record.Clone(), nil
	}
	updated, err := session.Transition(record, status, observedAt, nil)
	if err != nil {
		return session.Record{}, err
	}
	writeCtx, writeCancel := persistenceContext(ctx)
	err = a.updateOpen(writeCtx, updated, record.Status, observedAt)
	writeCancel()
	if err != nil {
		return session.Record{}, err
	}
	return updated, nil
}

func (a *Vertical) synchronizeAndReserve(ctx context.Context, request session.OpenRequest, now time.Time) (session.Reservation, error) {
	sandbox, err := a.sandboxes.GetSandbox(ctx, request.SandboxID)
	if err != nil {
		return session.Reservation{}, err
	}
	if err := sandbox.Validate(); err != nil {
		return session.Reservation{}, err
	}
	if sandbox.ID != request.SandboxID || sandbox.Generation > math.MaxInt64 || sandbox.ObservedGeneration > math.MaxInt64 {
		return session.Reservation{}, session.ErrGenerationConflict
	}
	if sandbox.RuntimeProfile != a.profile.RuntimeProfileID || request.CapabilityProfileID != a.profile.CapabilityProfileID {
		return session.Reservation{}, session.ErrCapabilityUnsupported
	}
	authority := session.SandboxAuthority{
		SandboxID: sandbox.ID, ProviderRevisionID: sandbox.ProviderRevisionID,
		Ready:      sandbox.DesiredState == lifecycle.DesiredReady && sandbox.ObservedState == lifecycle.ObservedReady && sandbox.ObservedGeneration == sandbox.Generation,
		Generation: int64(sandbox.Generation), LeaseExpiresAt: sandbox.LeaseExpiresAt.UTC(),
		// Protected admission owns the operation fence. The lifecycle snapshot
		// supplies runtime readiness, generation, revision, and lease only.
		FencingToken: request.FencingToken, CapabilityProfileID: a.profile.CapabilityProfileID,
	}
	if err := a.authority.SynchronizeSandboxAuthority(ctx, authority); err != nil {
		return session.Reservation{}, err
	}
	return a.authority.ReserveOpen(ctx, request, now)
}

func (a *Vertical) ready(ctx context.Context) error {
	if a == nil || a.authority == nil || a.runtime == nil || a.sandboxes == nil || a.clock == nil || a.profile.validate() != nil {
		return ErrInvalidApplication
	}
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func (a *Vertical) updateOpen(ctx context.Context, record session.Record, expected session.Status, now time.Time) error {
	if timed, ok := a.authority.(interface {
		UpdateOpenAt(context.Context, session.Record, session.Status, time.Time) error
	}); ok {
		return timed.UpdateOpenAt(ctx, record, expected, now)
	}
	return a.authority.UpdateOpen(ctx, record, expected)
}

func (a *Vertical) monotonicNow(floor time.Time) time.Time {
	return a.monotonicTime(a.clock.Now().UTC(), floor)
}

func (a *Vertical) monotonicTime(value, floor time.Time) time.Time {
	if value.Before(floor) {
		return floor.UTC()
	}
	return value.UTC()
}

func terminalRequest(request session.OpenRequest, workingDirectory string) terminal.AllocationRequest {
	return terminal.AllocationRequest{
		SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		RequestDigest: request.RequestDigest, WorkingDirectory: workingDirectory,
		ExpiresAt: request.ExpiresAt.UTC(),
	}
}

func sessionReceipt(receipt terminal.Receipt) session.AllocationReceipt {
	return session.AllocationReceipt{
		Reference: string(receipt.Reference), SandboxID: receipt.SandboxID,
		RuntimeSessionID: receipt.RuntimeSessionID, OperationID: receipt.OperationID,
		AttemptID: receipt.AttemptID, FencingToken: receipt.FencingToken,
		ExpectedGeneration: receipt.ExpectedGeneration, ConnectionGeneration: receipt.ConnectionGeneration,
		AllocatedAt: receipt.AllocatedAt.UTC(), ExpiresAt: receipt.ExpiresAt.UTC(),
	}
}

func terminalReceipt(receipt session.AllocationReceipt) terminal.Receipt {
	return terminal.Receipt{
		Reference: terminal.Reference(receipt.Reference), SandboxID: receipt.SandboxID,
		RuntimeSessionID: receipt.RuntimeSessionID, OperationID: receipt.OperationID,
		AttemptID: receipt.AttemptID, FencingToken: receipt.FencingToken,
		ExpectedGeneration: receipt.ExpectedGeneration, ConnectionGeneration: receipt.ConnectionGeneration,
		AllocatedAt: receipt.AllocatedAt.UTC(), ExpiresAt: receipt.ExpiresAt.UTC(),
	}
}

func sessionObservation(observation terminal.Observation) session.AllocationEvidence {
	state := session.AllocationOutcomeUnknown
	switch observation.State {
	case terminal.ObservationRunning:
		state = session.AllocationRunning
	case terminal.ObservationAbsent:
		state = session.AllocationAbsent
	case terminal.ObservationExpired:
		state = session.AllocationExpired
	case terminal.ObservationOutcomeUnknown:
		state = session.AllocationOutcomeUnknown
	}
	return session.AllocationEvidence{Receipt: sessionReceipt(observation.Receipt), State: state, ObservedAt: observation.ObservedAt.UTC()}
}

func knownAllocationFailure(err error) bool {
	return errors.Is(err, terminal.ErrInvalidRequest) ||
		errors.Is(err, terminal.ErrTerminalNotFound) ||
		errors.Is(err, terminal.ErrTerminalExpired) ||
		errors.Is(err, terminal.ErrTerminalConflict) ||
		errors.Is(err, terminal.ErrTerminalCapacity) ||
		errors.Is(err, terminal.ErrTerminalUnsupported)
}

func authorityInvalid(err error) bool {
	return errors.Is(err, session.ErrDeadlineExpired) ||
		errors.Is(err, session.ErrInvalidExpiry) ||
		errors.Is(err, session.ErrSandboxNotReady) ||
		errors.Is(err, session.ErrProviderRevisionConflict) ||
		errors.Is(err, session.ErrGenerationConflict) ||
		errors.Is(err, session.ErrLeaseExpired) ||
		errors.Is(err, session.ErrStaleFencingToken) ||
		errors.Is(err, session.ErrCapabilityUnsupported)
}

func persistenceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), allocationPersistenceTimeout)
}

var _ interface {
	Open(context.Context, session.OpenRequest) (Operation, error)
	GetHandoff(context.Context, string) (Handoff, error)
} = (*Vertical)(nil)
