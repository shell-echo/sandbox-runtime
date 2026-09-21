package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

const allocationPersistenceTimeout = 5 * time.Second

var profileIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

type SandboxReader interface {
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
}

type HandoffRegistrar interface {
	RegisterHandoff(context.Context, desktop.Record) (desktop.EndpointEvidence, error)
}

// HandoffRevoker is narrower than the later private resolver. RevokeHandoff
// is idempotent; ObserveHandoffRevoked is read-only and is the only method used
// after an uncertain close effect.
type HandoffRevoker interface {
	RevokeHandoff(context.Context, desktop.Record, time.Time) error
	ObserveHandoffRevoked(context.Context, desktop.Record) (bool, error)
}

type DesktopProfile struct {
	RuntimeProfileID    string
	CapabilityProfileID string
}

func (p DesktopProfile) validate() error {
	if !profileIdentifierPattern.MatchString(p.RuntimeProfileID) || p.CapabilityProfileID != desktop.CapabilityProfileID {
		return ErrInvalidApplication
	}
	return nil
}

type Vertical struct {
	authority desktop.CoordinationAuthority
	runtime   desktop.Runtime
	sandboxes SandboxReader
	profile   DesktopProfile
	clock     Clock
	registrar HandoffRegistrar
	revoker   HandoffRevoker
}

func NewVertical(authority desktop.CoordinationAuthority, runtime desktop.Runtime, sandboxes SandboxReader, profile DesktopProfile, clock Clock) (*Vertical, error) {
	return NewVerticalWithHandoffLifecycle(authority, runtime, sandboxes, profile, nil, nil, clock)
}

func NewVerticalWithHandoffRegistrar(authority desktop.CoordinationAuthority, runtime desktop.Runtime, sandboxes SandboxReader, profile DesktopProfile, registrar HandoffRegistrar, clock Clock) (*Vertical, error) {
	return NewVerticalWithHandoffLifecycle(authority, runtime, sandboxes, profile, registrar, nil, clock)
}

func NewVerticalWithHandoffLifecycle(authority desktop.CoordinationAuthority, runtime desktop.Runtime, sandboxes SandboxReader, profile DesktopProfile, registrar HandoffRegistrar, revoker HandoffRevoker, clock Clock) (*Vertical, error) {
	if authority == nil || runtime == nil || sandboxes == nil || clock == nil || profile.validate() != nil {
		return nil, ErrInvalidApplication
	}
	return &Vertical{authority: authority, runtime: runtime, sandboxes: sandboxes, profile: profile, registrar: registrar, revoker: revoker, clock: clock}, nil
}

func (a *Vertical) Open(ctx context.Context, request desktop.OpenRequest) (Operation, error) {
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
	record, err := a.progressOpen(ctx, reservation.Record, !reservation.Replayed)
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
	if closeRecord, err := a.authority.GetClose(ctx, operationID); err == nil {
		updated, progressErr := a.progressClose(ctx, closeRecord)
		if progressErr != nil {
			return Operation{}, progressErr
		}
		return closeOperationProjection(updated)
	} else if !errors.Is(err, desktop.ErrAuthorityNotFound) {
		return Operation{}, err
	}
	record, err := a.getOpen(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	record, err = a.progressOpen(ctx, record, false)
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
	result := make([]Operation, 0)
	closes, err := a.authority.ListClose(ctx)
	if err != nil {
		return nil, err
	}
	for _, record := range closes {
		if record.Status == desktop.StatusSucceeded || record.Status == desktop.StatusFailed {
			continue
		}
		updated, progressErr := a.progressClose(ctx, record)
		if progressErr != nil {
			return result, progressErr
		}
		operation, projectionErr := closeOperationProjection(updated)
		if projectionErr != nil {
			return result, projectionErr
		}
		result = append(result, operation)
	}
	opens, err := a.authority.ListOpen(ctx)
	if err != nil {
		return result, err
	}
	now := a.clock.Now().UTC()
	for _, record := range opens {
		if record.RevokedAt != nil || record.ClosedAt != nil {
			continue
		}
		if record.Status == desktop.StatusSucceeded {
			if !record.Request.ExpiresAt.After(now) {
				if _, expireErr := a.expire(ctx, record); expireErr != nil {
					return result, expireErr
				}
			}
			continue
		}
		if record.Status != desktop.StatusAccepted && record.Status != desktop.StatusRunning && record.Status != desktop.StatusOutcomeUnknown {
			if record.Allocation != nil {
				if cleanupErr := a.runtime.Cleanup(ctx, record.Allocation.Receipt); cleanupErr != nil {
					return result, cleanupErr
				}
			}
			continue
		}
		updated, progressErr := a.progressOpen(ctx, record, false)
		if progressErr != nil {
			return result, progressErr
		}
		updated, progressErr = a.completeHandoff(ctx, updated)
		if progressErr != nil {
			return result, progressErr
		}
		operation, projectionErr := operationProjection(updated)
		if projectionErr != nil {
			return result, projectionErr
		}
		result = append(result, operation)
	}
	return result, nil
}

func (a *Vertical) CloseDesktopSession(ctx context.Context, request desktop.CloseRequest) (Operation, error) {
	return a.close(ctx, request, false)
}

// Expire uses the identical revoke-clean-observe path as an admitted close,
// while retaining a distinct terminal lifecycle state.
func (a *Vertical) Expire(ctx context.Context, request desktop.CloseRequest) (Operation, error) {
	return a.close(ctx, request, true)
}

func (a *Vertical) close(ctx context.Context, request desktop.CloseRequest, expiration bool) (Operation, error) {
	if err := a.readyClose(ctx); err != nil {
		return Operation{}, err
	}
	now := a.clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return Operation{}, err
	}
	if err := a.synchronizeCloseAuthority(ctx, request); err != nil {
		return Operation{}, err
	}
	reservation, err := a.authority.ReserveClose(ctx, request, now, expiration)
	if err != nil {
		return Operation{}, err
	}
	record, err := a.progressClose(ctx, reservation.Record)
	if err != nil {
		return Operation{}, err
	}
	return closeOperationProjection(record)
}

func (a *Vertical) progressOpen(ctx context.Context, record desktop.Record, fresh bool) (desktop.Record, error) {
	now := a.clock.Now().UTC()
	if now.IsZero() {
		return desktop.Record{}, desktop.ErrInvalidRequest
	}
	if record.Status == desktop.StatusSucceeded || record.Status == desktop.StatusFailed || record.Status == desktop.StatusCancelled {
		return record.Clone(), nil
	}
	if !record.Request.Deadline.After(now) || !record.Request.ExpiresAt.After(now) {
		return a.persistOpenStatus(ctx, record, desktop.StatusFailed, a.monotonicTime(now, record.ObservedAt))
	}
	reservation, err := a.synchronizeAndReserve(ctx, record.Request, now)
	if err != nil {
		if authorityInvalid(err) {
			return a.persistOpenStatus(ctx, record, desktop.StatusFailed, a.monotonicTime(now, record.ObservedAt))
		}
		return desktop.Record{}, err
	}
	record = reservation.Record
	if record.Status == desktop.StatusAccepted {
		opening, transitionErr := desktop.Transition(record, desktop.StatusRunning, a.monotonicNow(record.ObservedAt), nil)
		if transitionErr != nil {
			return desktop.Record{}, transitionErr
		}
		writeCtx, cancel := persistenceContext(ctx)
		err = a.updateOpen(writeCtx, opening, desktop.StatusAccepted, opening.ObservedAt)
		cancel()
		if err != nil {
			return desktop.Record{}, err
		}
		record = opening
		fresh = true
	}
	if record.Status == desktop.StatusRunning && record.Allocation != nil {
		return record.Clone(), nil
	}
	if fresh && record.Status == desktop.StatusRunning {
		return a.dispatchOpen(ctx, record)
	}
	return a.observeOpen(ctx, record)
}

func (a *Vertical) dispatchOpen(ctx context.Context, record desktop.Record) (desktop.Record, error) {
	allocation, err := a.allocationFor(ctx, record)
	if err != nil {
		return desktop.Record{}, err
	}
	operationCtx, cancel := context.WithDeadline(ctx, record.Request.Deadline)
	receipt, allocationErr := a.runtime.Allocate(operationCtx, allocation)
	cancel()
	if allocationErr != nil {
		status := desktop.StatusOutcomeUnknown
		if knownAllocationFailure(allocationErr) {
			status = desktop.StatusFailed
		}
		return a.persistOpenStatus(ctx, record, status, a.monotonicNow(record.ObservedAt))
	}
	if err := receipt.Validate(); err != nil || !receipt.Matches(allocation.Request) || !receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
		return a.persistOpenStatus(ctx, record, desktop.StatusOutcomeUnknown, a.monotonicNow(record.ObservedAt))
	}
	return a.attachReceipt(ctx, receipt)
}

func (a *Vertical) observeOpen(ctx context.Context, record desktop.Record) (desktop.Record, error) {
	allocation, err := a.allocationFor(ctx, record)
	if err != nil {
		return desktop.Record{}, err
	}
	observation, observeErr := a.runtime.Observe(ctx, allocation)
	if observeErr != nil || observation.Validate(allocation) != nil {
		if record.Status == desktop.StatusOutcomeUnknown {
			return record.Clone(), nil
		}
		return a.persistOpenStatus(ctx, record, desktop.StatusOutcomeUnknown, a.monotonicNow(record.ObservedAt))
	}
	switch observation.State {
	case desktop.AllocationRunning:
		return a.attachReceipt(ctx, *observation.Receipt)
	case desktop.AllocationAbsent, desktop.AllocationExpired:
		return a.persistOpenStatus(ctx, record, desktop.StatusFailed, observation.ObservedAt)
	default:
		if record.Status == desktop.StatusOutcomeUnknown {
			return record.Clone(), nil
		}
		return a.persistOpenStatus(ctx, record, desktop.StatusOutcomeUnknown, observation.ObservedAt)
	}
}

func (a *Vertical) attachReceipt(ctx context.Context, receipt desktop.AllocationReceipt) (desktop.Record, error) {
	writeCtx, cancel := persistenceContext(ctx)
	reservation, err := a.authority.AttachAllocation(writeCtx, receipt)
	cancel()
	if err != nil {
		return desktop.Record{}, errors.Join(desktop.ErrAllocationUnknown, err)
	}
	return reservation.Record.Clone(), nil
}

func (a *Vertical) completeHandoff(ctx context.Context, record desktop.Record) (desktop.Record, error) {
	if record.Status != desktop.StatusRunning || record.Allocation == nil || a.registrar == nil {
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

func (a *Vertical) CommitHandoff(ctx context.Context, operationID string, evidence desktop.EndpointEvidence) (Operation, error) {
	if err := a.ready(ctx); err != nil {
		return Operation{}, err
	}
	record, err := a.getOpen(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	if record.Status != desktop.StatusRunning || record.Allocation == nil || record.Allocation.State != desktop.AllocationRunning ||
		evidence.ConnectionGeneration != record.Allocation.Receipt.ConnectionGeneration {
		return Operation{}, desktop.ErrHandoffUnavailable
	}
	now := a.clock.Now().UTC()
	reservation, err := a.synchronizeAndReserve(ctx, record.Request, now)
	if err != nil {
		return Operation{}, err
	}
	record = reservation.Record
	succeeded, err := desktop.Transition(record, desktop.StatusSucceeded, now, &evidence)
	if err != nil {
		return Operation{}, err
	}
	if err := a.updateOpen(ctx, succeeded, desktop.StatusRunning, now); err != nil {
		return Operation{}, err
	}
	return operationProjection(succeeded)
}

func (a *Vertical) progressClose(ctx context.Context, record desktop.CloseRecord) (desktop.CloseRecord, error) {
	if record.Status == desktop.StatusSucceeded || record.Status == desktop.StatusFailed {
		return record.Clone(), nil
	}
	if record.Status == desktop.StatusOutcomeUnknown {
		return a.observeUnknownClose(ctx, record)
	}
	if record.Status == desktop.StatusAccepted {
		running, err := desktop.TransitionClose(record, desktop.StatusRunning, a.monotonicNow(record.ObservedAt))
		if err != nil {
			return desktop.CloseRecord{}, err
		}
		source, err := a.retainedOpen(ctx, record.SourceOpenOperationID)
		if err != nil {
			return desktop.CloseRecord{}, err
		}
		var won bool
		running, won, err = a.persistCloseTransition(ctx, running, desktop.StatusAccepted, source)
		if err != nil {
			return desktop.CloseRecord{}, err
		}
		record = running
		if !won {
			// A concurrent Close or Recover owns the transition and its effects.
			// Return the exact durable projection without redispatching cleanup.
			return record.Clone(), nil
		}
	}
	source, err := a.retainedOpen(ctx, record.SourceOpenOperationID)
	if err != nil {
		return desktop.CloseRecord{}, err
	}
	if err := a.revoker.RevokeHandoff(ctx, source, a.monotonicNow(record.ObservedAt)); err != nil {
		return a.finishClose(ctx, record, desktop.StatusOutcomeUnknown)
	}
	if err := a.runtime.Cleanup(ctx, record.Receipt); err != nil {
		return a.finishClose(ctx, record, desktop.StatusOutcomeUnknown)
	}
	allocation, err := a.allocationFor(ctx, source)
	if err != nil {
		return a.finishClose(ctx, record, desktop.StatusOutcomeUnknown)
	}
	observation, observeErr := a.runtime.Observe(ctx, allocation)
	if observeErr != nil || observation.Validate(allocation) != nil ||
		(observation.State != desktop.AllocationAbsent && observation.State != desktop.AllocationExpired) {
		return a.finishClose(ctx, record, desktop.StatusOutcomeUnknown)
	}
	return a.finishCloseAt(ctx, record, desktop.StatusSucceeded, observation.ObservedAt)
}

func (a *Vertical) observeUnknownClose(ctx context.Context, record desktop.CloseRecord) (desktop.CloseRecord, error) {
	source, err := a.retainedOpen(ctx, record.SourceOpenOperationID)
	if err != nil {
		return record.Clone(), nil
	}
	revoked, revokeErr := a.revoker.ObserveHandoffRevoked(ctx, source)
	allocation, allocationErr := a.allocationFor(ctx, source)
	if revokeErr != nil || allocationErr != nil || !revoked {
		return record.Clone(), nil
	}
	observation, observeErr := a.runtime.Observe(ctx, allocation)
	if observeErr != nil || observation.Validate(allocation) != nil ||
		(observation.State != desktop.AllocationAbsent && observation.State != desktop.AllocationExpired) {
		return record.Clone(), nil
	}
	return a.finishCloseAt(ctx, record, desktop.StatusSucceeded, observation.ObservedAt)
}

func (a *Vertical) finishClose(ctx context.Context, record desktop.CloseRecord, status desktop.Status) (desktop.CloseRecord, error) {
	return a.finishCloseAt(ctx, record, status, a.monotonicNow(record.ObservedAt))
}

func (a *Vertical) finishCloseAt(ctx context.Context, record desktop.CloseRecord, status desktop.Status, observedAt time.Time) (desktop.CloseRecord, error) {
	updated, err := desktop.TransitionClose(record, status, a.monotonicTime(observedAt, record.ObservedAt))
	if err != nil {
		return desktop.CloseRecord{}, err
	}
	source, err := a.retainedOpen(ctx, record.SourceOpenOperationID)
	if err != nil {
		return desktop.CloseRecord{}, err
	}
	var updatedSource desktop.Record
	if status == desktop.StatusOutcomeUnknown {
		updatedSource, err = desktop.MarkCloseUnknown(source, updated.ObservedAt)
	} else {
		updatedSource, err = desktop.CompleteClose(source, updated.ObservedAt, record.Expiration)
	}
	if err != nil {
		return desktop.CloseRecord{}, err
	}
	persisted, _, err := a.persistCloseTransition(ctx, updated, record.Status, updatedSource)
	return persisted, err
}

// persistCloseTransition is shared by admitted Close and background Recover.
// A failed compare-and-swap gets one bounded re-read. It converges only when
// the persisted record is the exact same immutable close attempt and its state
// is a legal monotonic peer or successor of the attempted transition.
func (a *Vertical) persistCloseTransition(ctx context.Context, attempted desktop.CloseRecord, expected desktop.Status, source desktop.Record) (desktop.CloseRecord, bool, error) {
	writeCtx, cancel := persistenceContext(ctx)
	updateErr := a.authority.UpdateClose(writeCtx, attempted, expected, source)
	cancel()
	if updateErr == nil {
		return attempted, true, nil
	}
	readCtx, cancel := persistenceContext(ctx)
	persisted, readErr := a.authority.GetClose(readCtx, attempted.Request.OperationID)
	cancel()
	if readErr == nil && sameCloseAttempt(attempted, persisted) && closeStatusConverges(expected, attempted.Status, persisted.Status) {
		return persisted, false, nil
	}
	return desktop.CloseRecord{}, false, updateErr
}

func sameCloseAttempt(left, right desktop.CloseRecord) bool {
	return sameCloseRequest(left.Request, right.Request) &&
		left.SourceOpenOperationID == right.SourceOpenOperationID &&
		sameAllocationReceipt(left.Receipt, right.Receipt) &&
		left.Expiration == right.Expiration && left.AcceptedAt.Equal(right.AcceptedAt)
}

func sameCloseRequest(left, right desktop.CloseRequest) bool {
	return left.SandboxID == right.SandboxID && left.ProviderRevisionID == right.ProviderRevisionID &&
		left.OperationID == right.OperationID && left.AttemptID == right.AttemptID &&
		left.FencingToken == right.FencingToken && left.IdempotencyKey == right.IdempotencyKey &&
		left.RequestDigest == right.RequestDigest && left.Deadline.Equal(right.Deadline) &&
		left.ExpectedGeneration == right.ExpectedGeneration && left.DesktopSessionID == right.DesktopSessionID &&
		left.ConnectionGeneration == right.ConnectionGeneration && left.Reason == right.Reason
}

func sameAllocationReceipt(left, right desktop.AllocationReceipt) bool {
	return left.Reference == right.Reference && left.SandboxID == right.SandboxID &&
		left.DesktopSessionID == right.DesktopSessionID && left.OperationID == right.OperationID &&
		left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken &&
		left.ExpectedGeneration == right.ExpectedGeneration && left.ConnectionGeneration == right.ConnectionGeneration &&
		left.AllocatedAt.Equal(right.AllocatedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func closeStatusConverges(expected, attempted, persisted desktop.Status) bool {
	switch attempted {
	case desktop.StatusSucceeded, desktop.StatusFailed, desktop.StatusCancelled:
		return persisted == attempted
	}
	switch expected {
	case desktop.StatusAccepted:
		return persisted == desktop.StatusAccepted || persisted == desktop.StatusRunning ||
			persisted == desktop.StatusOutcomeUnknown || persisted == desktop.StatusSucceeded
	case desktop.StatusRunning:
		return persisted == desktop.StatusRunning || persisted == desktop.StatusOutcomeUnknown ||
			persisted == desktop.StatusSucceeded
	case desktop.StatusOutcomeUnknown:
		return persisted == desktop.StatusOutcomeUnknown || persisted == desktop.StatusSucceeded
	default:
		return false
	}
}

func (a *Vertical) expire(ctx context.Context, source desktop.Record) (Operation, error) {
	return a.close(ctx, expiryRequest(source, a.clock.Now().UTC()), true)
}

func expiryRequest(source desktop.Record, now time.Time) desktop.CloseRequest {
	digestBytes := sha256.Sum256([]byte(source.Request.OperationID + "\x00" + source.Request.DesktopSessionID + "\x00expiry"))
	digest := hex.EncodeToString(digestBytes[:])
	return desktop.CloseRequest{
		SandboxID: source.Request.SandboxID, ProviderRevisionID: source.Request.ProviderRevisionID,
		OperationID: "desktop-expiry-" + digest[:32], AttemptID: "desktop-expiry-attempt-" + digest[:24],
		FencingToken: source.Request.FencingToken, IdempotencyKey: "desktop-expiry-" + digest,
		RequestDigest: "sha256:" + digest, Deadline: now.Add(allocationPersistenceTimeout),
		ExpectedGeneration: source.Request.ExpectedGeneration, DesktopSessionID: source.Request.DesktopSessionID,
		ConnectionGeneration: source.Handoff.ConnectionGeneration, Reason: "session_expired",
	}
}

func (a *Vertical) allocationFor(ctx context.Context, record desktop.Record) (desktop.Allocation, error) {
	authority, err := a.authority.GetSandboxAuthority(ctx, record.Request.SandboxID)
	if err != nil {
		return desktop.Allocation{}, err
	}
	request := desktop.AllocationRequest{
		SandboxID: record.Request.SandboxID, DesktopSessionID: record.Request.DesktopSessionID,
		OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID,
		FencingToken: record.Request.FencingToken, ExpectedGeneration: record.Request.ExpectedGeneration,
		RequestDigest: record.Request.RequestDigest, NetworkPolicyReference: authority.NetworkPolicyReference,
		ExpiresAt: record.Request.ExpiresAt.UTC(),
	}
	allocation := desktop.Allocation{Request: request, AllocatedAt: record.AcceptedAt.UTC()}
	return allocation, allocation.Validate()
}

func (a *Vertical) retainedOpen(ctx context.Context, operationID string) (desktop.Record, error) {
	records, err := a.authority.ListOpen(ctx)
	if err != nil {
		return desktop.Record{}, err
	}
	for _, record := range records {
		if record.Request.OperationID == operationID {
			return record.Clone(), nil
		}
	}
	return desktop.Record{}, desktop.ErrHandoffUnavailable
}

func (a *Vertical) persistOpenStatus(ctx context.Context, record desktop.Record, status desktop.Status, observedAt time.Time) (desktop.Record, error) {
	if record.Status == status {
		return record.Clone(), nil
	}
	updated, err := desktop.Transition(record, status, observedAt, nil)
	if err != nil {
		return desktop.Record{}, err
	}
	writeCtx, cancel := persistenceContext(ctx)
	err = a.updateOpen(writeCtx, updated, record.Status, observedAt)
	cancel()
	if err != nil {
		return desktop.Record{}, err
	}
	return updated, nil
}

func (a *Vertical) synchronizeAndReserve(ctx context.Context, request desktop.OpenRequest, now time.Time) (desktop.Reservation, error) {
	sandbox, err := a.sandboxes.GetSandbox(ctx, request.SandboxID)
	if err != nil {
		return desktop.Reservation{}, err
	}
	if sandbox.ID != request.SandboxID {
		return desktop.Reservation{}, desktop.ErrGenerationConflict
	}
	if err := a.synchronizeAuthority(ctx, sandbox, request.FencingToken); err != nil {
		return desktop.Reservation{}, err
	}
	return a.authority.ReserveOpen(ctx, request, now)
}

func (a *Vertical) synchronizeCloseAuthority(ctx context.Context, request desktop.CloseRequest) error {
	sandbox, err := a.sandboxes.GetSandbox(ctx, request.SandboxID)
	if err != nil {
		return err
	}
	if sandbox.ID != request.SandboxID {
		return desktop.ErrGenerationConflict
	}
	return a.synchronizeAuthority(ctx, sandbox, request.FencingToken)
}

func (a *Vertical) synchronizeAuthority(ctx context.Context, sandbox lifecycle.Sandbox, fencingToken int64) error {
	if err := sandbox.Validate(); err != nil {
		return err
	}
	if sandbox.Generation > math.MaxInt64 || sandbox.ObservedGeneration > math.MaxInt64 || sandbox.RuntimeProfile != a.profile.RuntimeProfileID {
		return desktop.ErrCapabilityUnsupported
	}
	if sandbox.Network.Mode != lifecycle.NetworkRestricted || !sandbox.Network.EgressGatewayRequired || sandbox.Network.PolicyReference == "" {
		return desktop.ErrCapabilityUnsupported
	}
	authority := desktop.SandboxAuthority{
		SandboxID: sandbox.ID, ProviderRevisionID: sandbox.ProviderRevisionID,
		Ready:      sandbox.DesiredState == lifecycle.DesiredReady && sandbox.ObservedState == lifecycle.ObservedReady && sandbox.ObservedGeneration == sandbox.Generation,
		Generation: int64(sandbox.Generation), LeaseExpiresAt: sandbox.LeaseExpiresAt.UTC(), FencingToken: fencingToken,
		CapabilityProfileID: a.profile.CapabilityProfileID, NetworkPolicyReference: sandbox.Network.PolicyReference,
	}
	return a.authority.SynchronizeSandboxAuthority(ctx, authority)
}

func (a *Vertical) GetOperation(ctx context.Context, operationID string) (Operation, error) {
	if a == nil {
		return Operation{}, ErrInvalidApplication
	}
	return (&Application{authority: a.authority, clock: a.clock}).GetOperation(ctx, operationID)
}

func (a *Vertical) GetHandoff(ctx context.Context, operationID string) (Handoff, error) {
	if a == nil {
		return Handoff{}, ErrInvalidApplication
	}
	return (&Application{authority: a.authority, clock: a.clock}).GetHandoff(ctx, operationID)
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

func (a *Vertical) readyClose(ctx context.Context) error {
	if err := a.ready(ctx); err != nil {
		return err
	}
	if a.revoker == nil {
		return ErrInvalidApplication
	}
	return nil
}

func (a *Vertical) updateOpen(ctx context.Context, record desktop.Record, expected desktop.Status, now time.Time) error {
	if timed, ok := a.authority.(interface {
		UpdateOpenAt(context.Context, desktop.Record, desktop.Status, time.Time) error
	}); ok {
		return timed.UpdateOpenAt(ctx, record, expected, now)
	}
	return a.authority.UpdateOpen(ctx, record, expected)
}

func (a *Vertical) getOpen(ctx context.Context, operationID string) (desktop.Record, error) {
	if timed, ok := a.authority.(interface {
		GetOpenAt(context.Context, string, time.Time) (desktop.Record, error)
	}); ok {
		return timed.GetOpenAt(ctx, operationID, a.clock.Now().UTC())
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
	return errors.Is(err, desktop.ErrInvalidRequest) || errors.Is(err, desktop.ErrDesktopNotFound) ||
		errors.Is(err, desktop.ErrDesktopExpired) || errors.Is(err, desktop.ErrDesktopConflict) ||
		errors.Is(err, desktop.ErrDesktopCapacity) || errors.Is(err, desktop.ErrDesktopUnsupported)
}

func authorityInvalid(err error) bool {
	return errors.Is(err, desktop.ErrDeadlineExpired) || errors.Is(err, desktop.ErrInvalidExpiry) ||
		errors.Is(err, desktop.ErrSandboxNotReady) || errors.Is(err, desktop.ErrProviderRevisionConflict) ||
		errors.Is(err, desktop.ErrGenerationConflict) || errors.Is(err, desktop.ErrLeaseExpired) ||
		errors.Is(err, desktop.ErrStaleFencingToken) || errors.Is(err, desktop.ErrCapabilityUnsupported)
}

var _ interface {
	Open(context.Context, desktop.OpenRequest) (Operation, error)
	CloseDesktopSession(context.Context, desktop.CloseRequest) (Operation, error)
	GetOperation(context.Context, string) (Operation, error)
	GetHandoff(context.Context, string) (Handoff, error)
} = (*Vertical)(nil)
