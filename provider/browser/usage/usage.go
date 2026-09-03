// Package usage projects bounded browser-session duration evidence. It is a
// Provider-local observation, never billing or pricing authority.
package usage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	providerusage "github.com/shell-echo/sandbox-runtime/provider/usage"
)

var (
	ErrInvalid     = errors.New("invalid browser usage request")
	ErrUnavailable = errors.New("browser usage evidence is unavailable")
)

// StopTimes are trusted Provider-local observations. Nil values mean that no
// earlier termination than the handoff expiry has been observed.
type StopTimes struct {
	EndpointTerminatedAt *time.Time
	SandboxTerminatedAt  *time.Time
}

func BuildEvidence(record browser.Record, now, retainedUntil time.Time) (providerusage.Evidence, error) {
	return BuildEvidenceWithStops(record, now, StopTimes{}, retainedUntil)
}

func BuildEvidenceWithStops(record browser.Record, now time.Time, stops StopTimes, retainedUntil time.Time) (providerusage.Evidence, error) {
	if err := record.Validate(); err != nil || record.Status != browser.StatusSucceeded || record.Handoff == nil || record.Allocation == nil || record.Allocation.State != browser.AllocationRunning {
		return providerusage.Evidence{}, ErrUnavailable
	}
	now = now.UTC()
	retainedUntil = retainedUntil.UTC()
	if now.IsZero() || now.Before(record.ObservedAt) || retainedUntil.IsZero() || !retainedUntil.After(record.ObservedAt) {
		return providerusage.Evidence{}, ErrInvalid
	}
	for _, endedAt := range []*time.Time{stops.EndpointTerminatedAt, stops.SandboxTerminatedAt} {
		if endedAt != nil && (endedAt.Before(record.ObservedAt) || endedAt.After(now)) {
			return providerusage.Evidence{}, ErrInvalid
		}
	}
	stopAt := record.Request.ExpiresAt.UTC()
	complete := !now.Before(record.Request.ExpiresAt)
	if now.Before(stopAt) {
		stopAt = now
	}
	if stops.EndpointTerminatedAt != nil && !stops.EndpointTerminatedAt.After(stopAt) {
		stopAt = stops.EndpointTerminatedAt.UTC()
		complete = true
	}
	if stops.SandboxTerminatedAt != nil && !stops.SandboxTerminatedAt.After(stopAt) {
		stopAt = stops.SandboxTerminatedAt.UTC()
		complete = true
	}
	status := providerusage.ReconciliationPartial
	if complete {
		status = providerusage.ReconciliationComplete
	}
	key := evidenceKey(record.Request.OperationID, record.Request.AttemptID)
	reference := "ref:usage/browser-" + key
	evidence := providerusage.Evidence{EvidenceID: "browser-usage-" + key, SandboxID: record.Request.SandboxID, OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID, FencingToken: record.Request.FencingToken, Entries: []providerusage.Entry{{EntryID: "browser-duration-" + key, SandboxID: record.Request.SandboxID, OperationID: record.Request.OperationID, Meter: providerusage.MeterBrowserSession, Quantity: stopAt.Sub(record.ObservedAt).Milliseconds(), Unit: "milliseconds", MeterSource: providerusage.SourceRuntime, EvidenceReference: reference, OccurredAt: stopAt}}, ReconciliationStatus: status, ObservedAt: stopAt, RetainedUntil: retainedUntil}
	evidence.EvidenceDigest = digestEvidence(evidence)
	if err := evidence.Validate(stopAt); err != nil {
		return providerusage.Evidence{}, errors.Join(ErrUnavailable, err)
	}
	return evidence, nil
}

type Store interface {
	Put(context.Context, providerusage.Evidence) error
}
type Collector struct {
	Store       Store
	Clock       interface{ Now() time.Time }
	RetainedFor time.Duration
}

func (c Collector) Collect(ctx context.Context, record browser.Record) (providerusage.Evidence, error) {
	return c.CollectWithStops(ctx, record, StopTimes{})
}

func (c Collector) CollectWithStops(ctx context.Context, record browser.Record, stops StopTimes) (providerusage.Evidence, error) {
	if c.Store == nil || c.Clock == nil || c.RetainedFor <= 0 {
		return providerusage.Evidence{}, ErrUnavailable
	}
	now := c.Clock.Now().UTC()
	evidence, err := BuildEvidenceWithStops(record, now, stops, now.Add(c.RetainedFor))
	if err != nil {
		return providerusage.Evidence{}, err
	}
	if evidence.ReconciliationStatus != providerusage.ReconciliationComplete {
		return providerusage.Evidence{}, ErrUnavailable
	}
	if err := c.Store.Put(ctx, evidence); err != nil {
		return providerusage.Evidence{}, errors.Join(ErrUnavailable, err)
	}
	return evidence, nil
}

func evidenceKey(operationID, attemptID string) string {
	sum := sha256.Sum256([]byte(operationID + "\x00" + attemptID))
	return hex.EncodeToString(sum[:])
}
func digestEvidence(evidence providerusage.Evidence) string {
	evidence.EvidenceDigest = ""
	encoded, _ := json.Marshal(evidence)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
