package session

import (
	"fmt"
	"time"
)

// CloseRequest is the immutable Provider-local projection of an admitted
// terminal-session close mutation.
type CloseRequest struct {
	SandboxID            string    `json:"sandbox_id"`
	ProviderRevisionID   string    `json:"provider_revision_id"`
	OperationID          string    `json:"operation_id"`
	AttemptID            string    `json:"attempt_id"`
	FencingToken         int64     `json:"fencing_token"`
	IdempotencyKey       string    `json:"idempotency_key"`
	RequestDigest        string    `json:"request_digest"`
	Deadline             time.Time `json:"deadline"`
	ExpectedGeneration   int64     `json:"expected_generation"`
	RuntimeSessionID     string    `json:"runtime_session_id"`
	ConnectionGeneration int64     `json:"connection_generation"`
	Reason               string    `json:"reason"`
}

func (r CloseRequest) Clone() CloseRequest { return r }

func (r CloseRequest) Validate(now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: current time", ErrInvalidRequest)
	}
	for name, value := range map[string]string{
		"sandbox_id": r.SandboxID, "provider_revision_id": r.ProviderRevisionID,
		"operation_id": r.OperationID, "attempt_id": r.AttemptID,
		"runtime_session_id": r.RuntimeSessionID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 || r.ConnectionGeneration < 1 ||
		!validBoundedString(r.IdempotencyKey, 1, MaxIdempotencyKeyRunes) ||
		!digestPattern.MatchString(r.RequestDigest) || !validBoundedString(r.Reason, 1, 256) {
		return ErrInvalidRequest
	}
	if r.Deadline.IsZero() || !r.Deadline.After(now) {
		return ErrDeadlineExpired
	}
	return nil
}

// CloseRecord is a separate immutable attempt. It never rewrites the open
// attempt and therefore preserves outcome_unknown immutability.
type CloseRecord struct {
	Request               CloseRequest      `json:"request"`
	SourceOpenOperationID string            `json:"source_open_operation_id"`
	Receipt               AllocationReceipt `json:"receipt"`
	Status                Status            `json:"status"`
	AcceptedAt            time.Time         `json:"accepted_at"`
	ObservedAt            time.Time         `json:"observed_at"`
}

func NewCloseRecord(request CloseRequest, source Record, acceptedAt time.Time) (CloseRecord, error) {
	acceptedAt = acceptedAt.UTC()
	if err := request.Validate(acceptedAt); err != nil {
		return CloseRecord{}, err
	}
	if err := source.Validate(); err != nil || source.Status != StatusSucceeded || source.Allocation == nil || source.Handoff == nil {
		return CloseRecord{}, ErrHandoffUnavailable
	}
	receipt := source.Allocation.Receipt
	if source.Request.SandboxID != request.SandboxID || source.Request.ProviderRevisionID != request.ProviderRevisionID ||
		source.Request.RuntimeSessionID != request.RuntimeSessionID || receipt.ConnectionGeneration != request.ConnectionGeneration ||
		source.Handoff.ConnectionGeneration != request.ConnectionGeneration {
		return CloseRecord{}, ErrConflict
	}
	record := CloseRecord{
		Request: request.Clone(), SourceOpenOperationID: source.Request.OperationID,
		Receipt: receipt, Status: StatusAccepted, AcceptedAt: acceptedAt, ObservedAt: acceptedAt,
	}
	if err := record.Validate(); err != nil {
		return CloseRecord{}, err
	}
	return record, nil
}

func (r CloseRecord) Clone() CloseRecord {
	r.Request = r.Request.Clone()
	return r
}

func (r CloseRecord) Validate() error {
	if r.AcceptedAt.IsZero() || r.ObservedAt.IsZero() || r.ObservedAt.Before(r.AcceptedAt) || !r.Status.valid() ||
		!identifierPattern.MatchString(r.SourceOpenOperationID) {
		return ErrInvalidRecord
	}
	if err := r.Request.Validate(r.AcceptedAt); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	if err := r.Receipt.Validate(); err != nil || r.Receipt.SandboxID != r.Request.SandboxID ||
		r.Receipt.RuntimeSessionID != r.Request.RuntimeSessionID || r.Receipt.ConnectionGeneration != r.Request.ConnectionGeneration ||
		r.Receipt.OperationID != r.SourceOpenOperationID {
		return ErrInvalidRecord
	}
	return nil
}

type CloseReservation struct {
	Record   CloseRecord
	Replayed bool
}

func TransitionClose(record CloseRecord, next Status, observedAt time.Time) (CloseRecord, error) {
	if err := record.Validate(); err != nil {
		return CloseRecord{}, err
	}
	if !next.valid() || observedAt.IsZero() || observedAt.Before(record.ObservedAt) {
		return CloseRecord{}, ErrInvalidTransition
	}
	if record.Status == next {
		return record.Clone(), nil
	}
	if record.Status.terminal() {
		return CloseRecord{}, ErrTerminalOperation
	}
	if record.Status == StatusAccepted && next != StatusRunning && next != StatusFailed && next != StatusOutcomeUnknown ||
		record.Status == StatusRunning && next != StatusSucceeded && next != StatusFailed && next != StatusOutcomeUnknown {
		return CloseRecord{}, ErrInvalidTransition
	}
	updated := record.Clone()
	updated.Status = next
	updated.ObservedAt = observedAt.UTC()
	if err := updated.Validate(); err != nil {
		return CloseRecord{}, err
	}
	return updated, nil
}
