package desktop

import (
	"fmt"
	"time"
)

// SessionState is the Provider-local desktop lifecycle. Operation status and
// session lifecycle remain separate so an outcome-unknown attempt is never
// rewritten even when later observation proves the session is absent.
type SessionState string

const (
	SessionRequested           SessionState = "requested"
	SessionOpening             SessionState = "opening"
	SessionActive              SessionState = "active"
	SessionOpenOutcomeUnknown  SessionState = "open_outcome_unknown"
	SessionClosing             SessionState = "closing"
	SessionCloseOutcomeUnknown SessionState = "close_outcome_unknown"
	SessionClosed              SessionState = "closed"
	SessionExpired             SessionState = "expired"
	SessionFailed              SessionState = "failed"
)

func (r Record) SessionState() SessionState {
	if r.ClosedAt != nil {
		if r.Expired {
			return SessionExpired
		}
		return SessionClosed
	}
	if r.CloseUnknown {
		return SessionCloseOutcomeUnknown
	}
	if r.RevokedAt != nil {
		return SessionClosing
	}
	switch r.Status {
	case StatusAccepted:
		return SessionRequested
	case StatusRunning:
		return SessionOpening
	case StatusSucceeded:
		return SessionActive
	case StatusOutcomeUnknown:
		return SessionOpenOutcomeUnknown
	default:
		return SessionFailed
	}
}

// CloseRequest is the immutable Provider-local projection of an admitted
// Desktop close mutation.
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
	DesktopSessionID     string    `json:"desktop_session_id"`
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
		"desktop_session_id": r.DesktopSessionID,
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

// CloseRecord is a distinct immutable attempt bound to the exact allocation
// receipt and connection generation of a successful open.
type CloseRecord struct {
	Request               CloseRequest      `json:"request"`
	SourceOpenOperationID string            `json:"source_open_operation_id"`
	Receipt               AllocationReceipt `json:"receipt"`
	Expiration            bool              `json:"expiration"`
	Status                Status            `json:"status"`
	AcceptedAt            time.Time         `json:"accepted_at"`
	ObservedAt            time.Time         `json:"observed_at"`
}

func NewCloseRecord(request CloseRequest, source Record, acceptedAt time.Time, expiration bool) (CloseRecord, Record, error) {
	acceptedAt = acceptedAt.UTC()
	if err := request.Validate(acceptedAt); err != nil {
		return CloseRecord{}, Record{}, err
	}
	if err := source.Validate(); err != nil || source.Status != StatusSucceeded || source.Allocation == nil || source.Handoff == nil || source.RevokedAt != nil {
		return CloseRecord{}, Record{}, ErrHandoffUnavailable
	}
	receipt := source.Allocation.Receipt
	if source.Request.SandboxID != request.SandboxID || source.Request.ProviderRevisionID != request.ProviderRevisionID ||
		source.Request.DesktopSessionID != request.DesktopSessionID || receipt.ConnectionGeneration != request.ConnectionGeneration ||
		source.Handoff.ConnectionGeneration != request.ConnectionGeneration {
		return CloseRecord{}, Record{}, ErrDesktopConflict
	}
	updatedSource := source.Clone()
	updatedSource.RevokedAt = &acceptedAt
	record := CloseRecord{
		Request: request.Clone(), SourceOpenOperationID: source.Request.OperationID, Receipt: receipt,
		Expiration: expiration, Status: StatusAccepted, AcceptedAt: acceptedAt, ObservedAt: acceptedAt,
	}
	if err := updatedSource.Validate(); err != nil {
		return CloseRecord{}, Record{}, err
	}
	if err := record.Validate(); err != nil {
		return CloseRecord{}, Record{}, err
	}
	return record, updatedSource, nil
}

func (r CloseRecord) Clone() CloseRecord { r.Request = r.Request.Clone(); return r }

func (r CloseRecord) Validate() error {
	if r.AcceptedAt.IsZero() || r.ObservedAt.IsZero() || r.ObservedAt.Before(r.AcceptedAt) || !r.Status.valid() ||
		!identifierPattern.MatchString(r.SourceOpenOperationID) {
		return ErrInvalidRecord
	}
	if err := r.Request.Validate(r.AcceptedAt); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	if err := r.Receipt.Validate(); err != nil || r.Receipt.SandboxID != r.Request.SandboxID ||
		r.Receipt.DesktopSessionID != r.Request.DesktopSessionID || r.Receipt.ConnectionGeneration != r.Request.ConnectionGeneration ||
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
		return CloseRecord{}, ErrOperationTerminal
	}
	if record.Status == StatusAccepted && next != StatusRunning && next != StatusOutcomeUnknown ||
		record.Status == StatusRunning && next != StatusSucceeded && next != StatusOutcomeUnknown ||
		record.Status == StatusOutcomeUnknown && next != StatusSucceeded {
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

func MarkCloseUnknown(source Record, observedAt time.Time) (Record, error) {
	if err := source.Validate(); err != nil || source.RevokedAt == nil || source.ClosedAt != nil ||
		observedAt.IsZero() || observedAt.Before(*source.RevokedAt) {
		return Record{}, ErrInvalidTransition
	}
	updated := source.Clone()
	updated.CloseUnknown = true
	return updated, updated.Validate()
}

func CompleteClose(source Record, observedAt time.Time, expiration bool) (Record, error) {
	if err := source.Validate(); err != nil || source.RevokedAt == nil || source.ClosedAt != nil ||
		observedAt.IsZero() || observedAt.Before(*source.RevokedAt) {
		return Record{}, ErrInvalidTransition
	}
	updated := source.Clone()
	closedAt := observedAt.UTC()
	updated.ClosedAt = &closedAt
	updated.Expired = expiration
	updated.CloseUnknown = false
	return updated, updated.Validate()
}
