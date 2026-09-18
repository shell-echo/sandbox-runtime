package application

import (
	"context"
	"errors"
	"math"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

// CloseRuntimeSession durably reserves a separate close attempt, revokes the
// connection handoff, removes the exact terminal allocation, and succeeds
// only after the runtime observes that allocation as absent.
func (a *Vertical) CloseRuntimeSession(ctx context.Context, request session.CloseRequest) (Operation, error) {
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
	authority := a.authority.(session.CloseAuthority)
	reservation, err := authority.ReserveClose(ctx, request, now)
	if err != nil {
		return Operation{}, err
	}
	record, err := a.progressClose(ctx, reservation.Record)
	if err != nil {
		return Operation{}, err
	}
	return closeOperationProjection(record)
}

func (a *Vertical) recoverCloses(ctx context.Context) ([]Operation, error) {
	if err := a.readyClose(ctx); err != nil {
		return nil, err
	}
	records, err := a.authority.(session.CloseAuthority).ListClose(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Operation, 0, len(records))
	for _, record := range records {
		if record.Status == session.StatusSucceeded || record.Status == session.StatusFailed {
			continue
		}
		updated, progressErr := a.progressClose(ctx, record)
		if progressErr != nil {
			return result, progressErr
		}
		projected, projectionErr := closeOperationProjection(updated)
		if projectionErr != nil {
			return result, projectionErr
		}
		result = append(result, projected)
	}
	return result, nil
}

func (a *Vertical) progressClose(ctx context.Context, record session.CloseRecord) (session.CloseRecord, error) {
	authority := a.authority.(session.CloseAuthority)
	immutableUnknown := record.Status == session.StatusOutcomeUnknown
	if record.Status == session.StatusAccepted {
		running, err := session.TransitionClose(record, session.StatusRunning, a.monotonicNow(record.ObservedAt))
		if err != nil {
			return session.CloseRecord{}, err
		}
		writeCtx, cancel := persistenceContext(ctx)
		err = authority.UpdateClose(writeCtx, running, session.StatusAccepted)
		cancel()
		if err != nil {
			return session.CloseRecord{}, err
		}
		record = running
	}
	if record.Status != session.StatusRunning && !immutableUnknown {
		return record.Clone(), nil
	}
	source, err := a.retainedOpen(ctx, record.SourceOpenOperationID)
	if err != nil {
		return a.finishClose(ctx, record, session.StatusOutcomeUnknown, immutableUnknown)
	}
	if err := a.revoker.RevokeHandoff(ctx, source, a.monotonicNow(record.ObservedAt)); err != nil {
		return a.finishClose(ctx, record, session.StatusOutcomeUnknown, immutableUnknown)
	}
	receipt := terminalReceipt(record.Receipt)
	if immutableUnknown {
		observation, observeErr := a.runtime.Observe(ctx, receipt)
		if observeErr == nil && observation.Receipt == receipt && observation.State == terminal.ObservationAbsent {
			return record.Clone(), nil
		}
		return record.Clone(), nil
	}
	if err := a.runtime.Cleanup(ctx, receipt); err != nil {
		status := session.StatusOutcomeUnknown
		if errors.Is(err, terminal.ErrTerminalConflict) || errors.Is(err, terminal.ErrTerminalUnsupported) || errors.Is(err, terminal.ErrInvalidReceipt) {
			status = session.StatusFailed
		}
		return a.finishClose(ctx, record, status, immutableUnknown)
	}
	observation, err := a.runtime.Observe(ctx, receipt)
	if err != nil || observation.Receipt != receipt || observation.State != terminal.ObservationAbsent {
		return a.finishClose(ctx, record, session.StatusOutcomeUnknown, immutableUnknown)
	}
	return a.finishClose(ctx, record, session.StatusSucceeded, immutableUnknown)
}

// retainedOpen deliberately reads the retained open-attempt set instead of
// the live-handoff lookup. Close recovery must still be able to revoke and
// clean an allocation after the handoff itself has expired.
func (a *Vertical) retainedOpen(ctx context.Context, operationID string) (session.Record, error) {
	records, err := a.authority.ListOpen(ctx)
	if err != nil {
		return session.Record{}, err
	}
	for _, record := range records {
		if record.Request.OperationID == operationID {
			return record, nil
		}
	}
	return session.Record{}, session.ErrHandoffUnavailable
}

func (a *Vertical) finishClose(ctx context.Context, record session.CloseRecord, status session.Status, immutable bool) (session.CloseRecord, error) {
	if immutable {
		return record.Clone(), nil
	}
	updated, err := session.TransitionClose(record, status, a.monotonicNow(record.ObservedAt))
	if err != nil {
		return session.CloseRecord{}, err
	}
	writeCtx, cancel := persistenceContext(ctx)
	err = a.authority.(session.CloseAuthority).UpdateClose(writeCtx, updated, record.Status)
	cancel()
	if err != nil {
		return session.CloseRecord{}, err
	}
	return updated, nil
}

func (a *Vertical) synchronizeCloseAuthority(ctx context.Context, request session.CloseRequest) error {
	sandbox, err := a.sandboxes.GetSandbox(ctx, request.SandboxID)
	if err != nil {
		return err
	}
	if err := sandbox.Validate(); err != nil {
		return err
	}
	if sandbox.ID != request.SandboxID || sandbox.Generation > math.MaxInt64 || sandbox.RuntimeProfile != a.profile.RuntimeProfileID {
		return session.ErrGenerationConflict
	}
	authority := session.SandboxAuthority{
		SandboxID: sandbox.ID, ProviderRevisionID: sandbox.ProviderRevisionID,
		Ready:      sandbox.DesiredState == lifecycle.DesiredReady && sandbox.ObservedState == lifecycle.ObservedReady && sandbox.ObservedGeneration == sandbox.Generation,
		Generation: int64(sandbox.Generation), LeaseExpiresAt: sandbox.LeaseExpiresAt.UTC(),
		FencingToken: request.FencingToken, CapabilityProfileID: a.profile.CapabilityProfileID,
	}
	return a.authority.SynchronizeSandboxAuthority(ctx, authority)
}

func (a *Vertical) readyClose(ctx context.Context) error {
	if err := a.ready(ctx); err != nil {
		return err
	}
	if _, ok := a.authority.(session.CloseAuthority); !ok || a.revoker == nil {
		return ErrInvalidApplication
	}
	return nil
}

func closeOperationProjection(record session.CloseRecord) (Operation, error) {
	if err := record.Validate(); err != nil {
		return Operation{}, err
	}
	return Operation{
		OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID,
		FencingToken: record.Request.FencingToken, SandboxID: record.Request.SandboxID,
		Status: record.Status, ObservedAt: record.ObservedAt.UTC(), Type: OperationCloseRuntimeSession,
	}, nil
}
