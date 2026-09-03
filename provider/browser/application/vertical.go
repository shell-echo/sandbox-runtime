package application

import (
	"context"
	"errors"
	"math"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

const allocationPersistenceTimeout = 5 * time.Second

var profileIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

type SandboxReader interface {
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
}

type HandoffRegistrar interface {
	RegisterHandoff(context.Context, browser.Record) (browser.EndpointEvidence, error)
}

type BrowserProfile struct {
	RuntimeProfileID    string
	CapabilityProfileID string
}

func (p BrowserProfile) validate() error {
	if !profileIdentifierPattern.MatchString(p.RuntimeProfileID) || p.CapabilityProfileID != browser.CapabilityProfileID {
		return ErrInvalidApplication
	}
	return nil
}

type Vertical struct {
	authority browser.CoordinationAuthority
	runtime   browser.Runtime
	sandboxes SandboxReader
	profile   BrowserProfile
	clock     Clock
	registrar HandoffRegistrar
}

func NewVertical(authority browser.CoordinationAuthority, runtime browser.Runtime, sandboxes SandboxReader, profile BrowserProfile, clock Clock) (*Vertical, error) {
	return NewVerticalWithHandoffRegistrar(authority, runtime, sandboxes, profile, nil, clock)
}

func NewVerticalWithHandoffRegistrar(authority browser.CoordinationAuthority, runtime browser.Runtime, sandboxes SandboxReader, profile BrowserProfile, registrar HandoffRegistrar, clock Clock) (*Vertical, error) {
	if authority == nil || runtime == nil || sandboxes == nil || clock == nil || profile.validate() != nil {
		return nil, ErrInvalidApplication
	}
	return &Vertical{authority: authority, runtime: runtime, sandboxes: sandboxes, profile: profile, registrar: registrar, clock: clock}, nil
}

func (a *Vertical) Open(ctx context.Context, request browser.OpenRequest) (Operation, error) {
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
	record, err = a.completeHandoff(ctx, record)
	if err != nil {
		return Operation{}, err
	}
	return operationProjection(record)
}

func (a *Vertical) Reconcile(ctx context.Context, operationID string) (Operation, error) {
	if err := a.ready(ctx); err != nil {
		return Operation{}, err
	}
	record, err := a.getOpen(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	record, err = a.progress(ctx, record)
	if err != nil {
		return Operation{}, err
	}
	record, err = a.completeHandoff(ctx, record)
	if err != nil {
		return Operation{}, err
	}
	return operationProjection(record)
}

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
		if record.Status != browser.StatusAccepted && record.Status != browser.StatusRunning {
			if _, cleanupErr := a.cleanupTerminal(ctx, record); cleanupErr != nil {
				return results, cleanupErr
			}
			continue
		}
		reconciled, reconcileErr := a.progress(ctx, record)
		if reconcileErr != nil {
			return results, reconcileErr
		}
		reconciled, reconcileErr = a.completeHandoff(ctx, reconciled)
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

// Cancel persists intent before cleaning the exact allocation. A cleanup error
// is outcome_unknown because the external action may have taken effect.
func (a *Vertical) Cancel(ctx context.Context, operationID string) (Operation, error) {
	if err := a.ready(ctx); err != nil {
		return Operation{}, err
	}
	record, err := a.getOpen(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	if record.Status != browser.StatusAccepted && record.Status != browser.StatusRunning {
		return operationProjection(record)
	}
	if !record.CancelRequested {
		now := a.monotonicNow(record.ObservedAt)
		requested, requestErr := browser.RequestCancellation(record, now)
		if requestErr != nil {
			return Operation{}, requestErr
		}
		writeCtx, cancel := persistenceContext(ctx)
		err = a.updateOpen(writeCtx, requested, record.Status, now)
		cancel()
		if err != nil {
			return Operation{}, err
		}
		record = requested
	}
	return a.finishCancellation(ctx, record)
}

func (a *Vertical) finishCancellation(ctx context.Context, record browser.Record) (Operation, error) {
	if record.Allocation != nil {
		if cleanupErr := a.runtime.Cleanup(ctx, record.Allocation.Receipt); cleanupErr != nil {
			unknown, err := a.persistStatus(ctx, record, browser.StatusOutcomeUnknown, a.monotonicNow(record.ObservedAt))
			if err != nil {
				return Operation{}, errors.Join(cleanupErr, err)
			}
			operation, _ := operationProjection(unknown)
			return operation, cleanupErr
		}
	}
	cancelled, err := a.persistStatus(ctx, record, browser.StatusCancelled, a.monotonicNow(record.ObservedAt))
	if err != nil {
		return Operation{}, err
	}
	return operationProjection(cancelled)
}

func (a *Vertical) GetOperation(ctx context.Context, operationID string) (Operation, error) {
	if a == nil {
		return Operation{}, ErrInvalidApplication
	}
	base := &Application{authority: a.authority, clock: a.clock}
	return base.GetOperation(ctx, operationID)
}
func (a *Vertical) GetHandoff(ctx context.Context, operationID string) (Handoff, error) {
	if a == nil {
		return Handoff{}, ErrInvalidApplication
	}
	base := &Application{authority: a.authority, clock: a.clock}
	return base.GetHandoff(ctx, operationID)
}

func (a *Vertical) completeHandoff(ctx context.Context, record browser.Record) (browser.Record, error) {
	if record.Status != browser.StatusRunning || a.registrar == nil {
		return record.Clone(), nil
	}
	evidence, err := a.registrar.RegisterHandoff(ctx, record)
	if err != nil {
		return record.Clone(), err
	}
	if _, err := a.CommitHandoff(ctx, record.Request.OperationID, evidence); err != nil {
		return record.Clone(), err
	}
	return a.getOpen(ctx, record.Request.OperationID)
}

func (a *Vertical) CommitHandoff(ctx context.Context, operationID string, evidence browser.EndpointEvidence) (Operation, error) {
	if err := a.ready(ctx); err != nil {
		return Operation{}, err
	}
	record, err := a.getOpen(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	if record.Status != browser.StatusRunning || record.Allocation == nil || record.Allocation.State != browser.AllocationRunning || evidence.ConnectionGeneration != record.Allocation.Receipt.ConnectionGeneration {
		return Operation{}, browser.ErrHandoffUnavailable
	}
	now := a.clock.Now().UTC()
	reservation, err := a.synchronizeAndReserve(ctx, record.Request, now)
	if err != nil {
		return Operation{}, err
	}
	record = reservation.Record
	if record.Status != browser.StatusRunning || record.Allocation == nil || record.Allocation.State != browser.AllocationRunning {
		return Operation{}, browser.ErrHandoffUnavailable
	}
	succeeded, err := browser.Transition(record, browser.StatusSucceeded, now, &evidence)
	if err != nil {
		return Operation{}, err
	}
	if err := a.updateOpen(ctx, succeeded, browser.StatusRunning, now); err != nil {
		return Operation{}, err
	}
	return operationProjection(succeeded)
}

func (a *Vertical) progress(ctx context.Context, record browser.Record) (browser.Record, error) {
	if record.Status != browser.StatusAccepted && record.Status != browser.StatusRunning {
		return a.cleanupTerminal(ctx, record)
	}
	now := a.clock.Now().UTC()
	if now.IsZero() {
		return browser.Record{}, browser.ErrInvalidRequest
	}
	if !record.Request.Deadline.After(now) || !record.Request.ExpiresAt.After(now) {
		return a.expire(ctx, record, now)
	}
	if record.CancelRequested {
		operation, err := a.finishCancellation(ctx, record)
		if err != nil {
			return browser.Record{}, err
		}
		return a.getOpen(ctx, operation.OperationID)
	}
	reservation, err := a.synchronizeAndReserve(ctx, record.Request, now)
	if err != nil {
		if authorityInvalid(err) {
			return a.invalidate(ctx, record, now)
		}
		return browser.Record{}, err
	}
	record = reservation.Record
	switch record.Status {
	case browser.StatusAccepted:
		return a.allocate(ctx, record)
	case browser.StatusRunning:
		return a.observe(ctx, record)
	default:
		return record.Clone(), nil
	}
}

func (a *Vertical) allocate(ctx context.Context, record browser.Record) (browser.Record, error) {
	authority, err := a.authority.GetSandboxAuthority(ctx, record.Request.SandboxID)
	if err != nil {
		return browser.Record{}, err
	}
	request := browser.AllocationRequest{SandboxID: record.Request.SandboxID, BrowserSessionID: record.Request.BrowserSessionID, OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID, FencingToken: record.Request.FencingToken, ExpectedGeneration: record.Request.ExpectedGeneration, RequestDigest: record.Request.RequestDigest, NetworkPolicyReference: authority.NetworkPolicyReference, ExpiresAt: record.Request.ExpiresAt.UTC()}
	allocation := browser.Allocation{Request: request, AllocatedAt: record.AcceptedAt.UTC()}
	if err := allocation.Validate(); err != nil {
		return a.persistStatus(ctx, record, browser.StatusFailed, a.monotonicNow(record.ObservedAt))
	}
	operationCtx, cancel := context.WithDeadline(ctx, record.Request.Deadline)
	receipt, allocationErr := a.runtime.Allocate(operationCtx, allocation)
	cancel()
	if allocationErr != nil {
		status := browser.StatusOutcomeUnknown
		if knownAllocationFailure(allocationErr) {
			status = browser.StatusFailed
		}
		return a.persistStatus(ctx, record, status, a.monotonicNow(record.ObservedAt))
	}
	if err := receipt.Validate(); err != nil || !receipt.Matches(request) || !receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
		return a.persistStatus(ctx, record, browser.StatusOutcomeUnknown, a.monotonicNow(record.ObservedAt))
	}
	writeCtx, writeCancel := persistenceContext(ctx)
	attached, err := a.authority.AttachAllocation(writeCtx, receipt)
	writeCancel()
	if err != nil {
		return browser.Record{}, errors.Join(browser.ErrAllocationUnknown, err)
	}
	return attached.Record.Clone(), nil
}

func (a *Vertical) observe(ctx context.Context, record browser.Record) (browser.Record, error) {
	receipt := record.Allocation.Receipt
	observation, observeErr := a.runtime.Observe(ctx, receipt)
	if observeErr != nil {
		state := browser.AllocationOutcomeUnknown
		if errors.Is(observeErr, browser.ErrBrowserNotFound) {
			state = browser.AllocationAbsent
		} else if errors.Is(observeErr, browser.ErrBrowserExpired) {
			state = browser.AllocationExpired
		}
		observation = browser.AllocationObservation{Receipt: receipt, State: state, ObservedAt: a.monotonicNow(record.Allocation.ObservedAt)}
	}
	if err := observation.Validate(); err != nil || observation.Receipt != receipt || observation.ObservedAt.Before(record.Allocation.ObservedAt) {
		observation = browser.AllocationObservation{Receipt: receipt, State: browser.AllocationOutcomeUnknown, ObservedAt: a.monotonicNow(record.Allocation.ObservedAt)}
	}
	evidence := browser.AllocationEvidence{Receipt: observation.Receipt, State: observation.State, ObservedAt: observation.ObservedAt}
	writeCtx, writeCancel := persistenceContext(ctx)
	updated, err := a.authority.ObserveAllocation(writeCtx, record.Request.OperationID, evidence)
	writeCancel()
	if err != nil {
		return browser.Record{}, err
	}
	if updated.Allocation != nil && (updated.Allocation.State == browser.AllocationAbsent || updated.Allocation.State == browser.AllocationExpired) {
		if cleanupErr := a.runtime.Cleanup(ctx, receipt); cleanupErr != nil {
			return updated, cleanupErr
		}
	}
	return updated, nil
}

func (a *Vertical) expire(ctx context.Context, record browser.Record, now time.Time) (browser.Record, error) {
	if record.Allocation == nil {
		return a.persistStatus(ctx, record, browser.StatusFailed, a.monotonicTime(now, record.ObservedAt))
	}
	evidence := browser.AllocationEvidence{Receipt: record.Allocation.Receipt, State: browser.AllocationExpired, ObservedAt: a.monotonicTime(now, record.Allocation.ObservedAt)}
	writeCtx, writeCancel := persistenceContext(ctx)
	updated, err := a.authority.ObserveAllocation(writeCtx, record.Request.OperationID, evidence)
	writeCancel()
	if err != nil {
		return browser.Record{}, err
	}
	if cleanupErr := a.runtime.Cleanup(ctx, record.Allocation.Receipt); cleanupErr != nil {
		return updated, cleanupErr
	}
	return updated, nil
}
func (a *Vertical) invalidate(ctx context.Context, record browser.Record, now time.Time) (browser.Record, error) {
	updated, err := a.persistStatus(ctx, record, browser.StatusFailed, a.monotonicTime(now, record.ObservedAt))
	if err != nil || record.Allocation == nil {
		return updated, err
	}
	if cleanupErr := a.runtime.Cleanup(ctx, record.Allocation.Receipt); cleanupErr != nil {
		return updated, cleanupErr
	}
	return updated, nil
}
func (a *Vertical) cleanupTerminal(ctx context.Context, record browser.Record) (browser.Record, error) {
	if record.Allocation == nil {
		return record.Clone(), nil
	}
	now := a.clock.Now().UTC()
	if record.Status != browser.StatusFailed && record.Status != browser.StatusCancelled && record.Request.ExpiresAt.After(now) {
		return record.Clone(), nil
	}
	if err := a.runtime.Cleanup(ctx, record.Allocation.Receipt); err != nil {
		return record.Clone(), err
	}
	return record.Clone(), nil
}
func (a *Vertical) persistStatus(ctx context.Context, record browser.Record, status browser.Status, observedAt time.Time) (browser.Record, error) {
	if record.Status != browser.StatusAccepted && record.Status != browser.StatusRunning {
		return record.Clone(), nil
	}
	updated, err := browser.Transition(record, status, observedAt, nil)
	if err != nil {
		return browser.Record{}, err
	}
	writeCtx, cancel := persistenceContext(ctx)
	err = a.updateOpen(writeCtx, updated, record.Status, observedAt)
	cancel()
	if err != nil {
		return browser.Record{}, err
	}
	return updated, nil
}

func (a *Vertical) synchronizeAndReserve(ctx context.Context, request browser.OpenRequest, now time.Time) (browser.Reservation, error) {
	sandbox, err := a.sandboxes.GetSandbox(ctx, request.SandboxID)
	if err != nil {
		return browser.Reservation{}, err
	}
	if err := sandbox.Validate(); err != nil {
		return browser.Reservation{}, err
	}
	if sandbox.ID != request.SandboxID || sandbox.Generation > math.MaxInt64 || sandbox.ObservedGeneration > math.MaxInt64 {
		return browser.Reservation{}, browser.ErrGenerationConflict
	}
	if sandbox.RuntimeProfile != a.profile.RuntimeProfileID {
		return browser.Reservation{}, browser.ErrCapabilityUnsupported
	}
	if sandbox.Network.Mode != lifecycle.NetworkRestricted || !sandbox.Network.EgressGatewayRequired || sandbox.Network.PolicyReference == "" {
		return browser.Reservation{}, browser.ErrCapabilityUnsupported
	}
	authority := browser.SandboxAuthority{SandboxID: sandbox.ID, ProviderRevisionID: sandbox.ProviderRevisionID, Ready: sandbox.DesiredState == lifecycle.DesiredReady && sandbox.ObservedState == lifecycle.ObservedReady && sandbox.ObservedGeneration == sandbox.Generation, Generation: int64(sandbox.Generation), LeaseExpiresAt: sandbox.LeaseExpiresAt.UTC(), FencingToken: request.FencingToken, CapabilityProfileID: a.profile.CapabilityProfileID, NetworkPolicyReference: sandbox.Network.PolicyReference}
	if err := a.authority.SynchronizeSandboxAuthority(ctx, authority); err != nil {
		return browser.Reservation{}, err
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
func (a *Vertical) updateOpen(ctx context.Context, record browser.Record, expected browser.Status, now time.Time) error {
	if timed, ok := a.authority.(interface {
		UpdateOpenAt(context.Context, browser.Record, browser.Status, time.Time) error
	}); ok {
		return timed.UpdateOpenAt(ctx, record, expected, now)
	}
	return a.authority.UpdateOpen(ctx, record, expected)
}
func (a *Vertical) getOpen(ctx context.Context, operationID string) (browser.Record, error) {
	now := a.clock.Now().UTC()
	if timed, ok := a.authority.(interface {
		GetOpenAt(context.Context, string, time.Time) (browser.Record, error)
	}); ok {
		return timed.GetOpenAt(ctx, operationID, now)
	}
	return a.authority.GetOpen(ctx, operationID)
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
func persistenceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), allocationPersistenceTimeout)
}
func knownAllocationFailure(err error) bool {
	return errors.Is(err, browser.ErrInvalidRequest) || errors.Is(err, browser.ErrBrowserNotFound) || errors.Is(err, browser.ErrBrowserExpired) || errors.Is(err, browser.ErrBrowserConflict) || errors.Is(err, browser.ErrBrowserUnsupported)
}
func authorityInvalid(err error) bool {
	return errors.Is(err, browser.ErrDeadlineExpired) || errors.Is(err, browser.ErrInvalidExpiry) || errors.Is(err, browser.ErrSandboxNotReady) || errors.Is(err, browser.ErrProviderRevisionConflict) || errors.Is(err, browser.ErrGenerationConflict) || errors.Is(err, browser.ErrLeaseExpired) || errors.Is(err, browser.ErrStaleFencingToken) || errors.Is(err, browser.ErrCapabilityUnsupported)
}

var _ interface {
	Open(context.Context, browser.OpenRequest) (Operation, error)
	GetHandoff(context.Context, string) (Handoff, error)
} = (*Vertical)(nil)
