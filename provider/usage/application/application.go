// Package application derives bounded usage evidence from already-durable exec
// results. It does not own pricing, billing, tenant authorization, or aggregate
// accounting truth.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
)

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type ResultCollector struct {
	store usage.Store
	clock Clock
}

func NewResultCollector(store usage.Store, clock Clock) (*ResultCollector, error) {
	if store == nil || clock == nil {
		return nil, usage.ErrEvidenceUnavailable
	}
	return &ResultCollector{store: store, clock: clock}, nil
}

func (c *ResultCollector) ObserveResult(ctx context.Context, result providerexec.Result) error {
	if ctx == nil {
		return context.Canceled
	}
	if c == nil || c.store == nil || c.clock == nil {
		return usage.ErrEvidenceUnavailable
	}
	if err := result.Validate(); err != nil {
		return errors.Join(usage.ErrEvidenceUnavailable, err)
	}
	// Unknown dispatch and pre-dispatch provider failures do not prove that an
	// execution consumed runtime resources.
	if result.Status == providerexec.ResultOutcomeUnknown || (result.Status == providerexec.ResultFailed && result.ExitCode == nil && result.Signal == "") {
		return nil
	}
	now := c.clock.Now().UTC()
	if !now.Before(result.RetainedUntil) {
		return nil
	}
	// Evidence derived from an immutable result must be byte-for-byte stable on
	// recovery. Completion is the durable observation boundary; the collector's
	// current clock is used only to enforce retention.
	observedAt := result.CompletedAt.UTC()
	key := evidenceKey(result.OperationID, result.AttemptID)
	evidenceReference := "ref:usage/" + key
	evidence := usage.Evidence{
		EvidenceID: "usage-" + key, SandboxID: result.SandboxID, OperationID: result.OperationID,
		AttemptID: result.AttemptID, FencingToken: result.FencingToken,
		Entries: []usage.Entry{
			{EntryID: "wall-" + key, SandboxID: result.SandboxID, OperationID: result.OperationID, Meter: usage.MeterWallTime, Quantity: result.CompletedAt.Sub(result.StartedAt).Milliseconds(), Unit: "milliseconds", MeterSource: usage.SourceRuntime, EvidenceReference: evidenceReference + "/wall", OccurredAt: result.CompletedAt.UTC()},
			{EntryID: "count-" + key, SandboxID: result.SandboxID, OperationID: result.OperationID, Meter: usage.MeterExecCount, Quantity: 1, Unit: "count", MeterSource: usage.SourceReconciled, EvidenceReference: evidenceReference + "/count", OccurredAt: result.CompletedAt.UTC()},
		},
		ReconciliationStatus: usage.ReconciliationPartial, ObservedAt: observedAt,
		RetainedUntil: result.RetainedUntil.UTC(),
	}
	evidence.EvidenceDigest = digestEvidence(evidence)
	if err := evidence.Validate(observedAt); err != nil {
		return errors.Join(usage.ErrEvidenceUnavailable, err)
	}
	return c.store.Put(ctx, evidence)
}

type ExecEvidenceSource interface {
	ReadOperation(context.Context, string) (provideroperation.View, error)
	GetResult(context.Context, string) (providerexec.Result, error)
}

type Reader struct {
	store     usage.Store
	exec      ExecEvidenceSource
	collector *ResultCollector
}

func NewReader(store usage.Store, exec ExecEvidenceSource, collector *ResultCollector) (*Reader, error) {
	if store == nil || exec == nil || collector == nil {
		return nil, usage.ErrEvidenceUnavailable
	}
	return &Reader{store: store, exec: exec, collector: collector}, nil
}

func (r *Reader) GetEvidence(ctx context.Context, operationID string, now time.Time) (usage.Evidence, error) {
	if ctx == nil {
		return usage.Evidence{}, context.Canceled
	}
	if r == nil || r.store == nil || r.exec == nil || r.collector == nil || now.IsZero() {
		return usage.Evidence{}, usage.ErrEvidenceUnavailable
	}
	evidence, err := r.store.GetEvidence(ctx, operationID, now.UTC())
	if err == nil || errors.Is(err, usage.ErrEvidenceExpired) {
		return evidence, err
	}
	if !errors.Is(err, usage.ErrEvidenceNotFound) {
		return usage.Evidence{}, errors.Join(usage.ErrEvidenceUnavailable, err)
	}
	view, err := r.exec.ReadOperation(ctx, operationID)
	if errors.Is(err, provideroperation.ErrNotFound) {
		return usage.Evidence{}, usage.ErrEvidenceNotFound
	}
	if err != nil {
		return usage.Evidence{}, errors.Join(usage.ErrEvidenceUnavailable, err)
	}
	if view.Status == provideroperation.StatusAccepted || view.Status == provideroperation.StatusRunning {
		return usage.Evidence{}, usage.ErrEvidenceUnavailable
	}
	result, err := r.exec.GetResult(ctx, operationID)
	if err != nil {
		return usage.Evidence{}, errors.Join(usage.ErrEvidenceUnavailable, err)
	}
	if err := r.collector.ObserveResult(ctx, result); err != nil {
		return usage.Evidence{}, errors.Join(usage.ErrEvidenceUnavailable, err)
	}
	evidence, err = r.store.GetEvidence(ctx, operationID, now.UTC())
	if errors.Is(err, usage.ErrEvidenceNotFound) {
		return usage.Evidence{}, usage.ErrEvidenceUnavailable
	}
	return evidence, err
}

func evidenceKey(operationID, attemptID string) string {
	sum := sha256.Sum256([]byte(operationID + "\x00" + attemptID))
	return hex.EncodeToString(sum[:])
}

func digestEvidence(evidence usage.Evidence) string {
	evidence.EvidenceDigest = ""
	encoded, _ := json.Marshal(evidence)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var _ providerexec.ResultObserver = (*ResultCollector)(nil)
var _ usage.EvidenceReader = (*Reader)(nil)
