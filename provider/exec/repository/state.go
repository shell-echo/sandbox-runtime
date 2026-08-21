package repository

import (
	"fmt"
	"reflect"
	"regexp"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

var attachmentIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

const snapshotVersion = 1

type State struct {
	Executions              map[string]providerexec.ExecutionRecord
	ExecutionIdempotency    map[string]IdempotencyRecord
	CancellationIntents     map[string]providerexec.CancellationIntent
	CancellationIdempotency map[string]IdempotencyRecord
}

type IdempotencyRecord struct {
	Key           string
	RequestDigest string
	OperationID   string
}

type PersistedState struct {
	Version                 int
	Executions              map[string]providerexec.ExecutionRecord
	ExecutionIdempotency    map[string]IdempotencyRecord
	CancellationIntents     map[string]providerexec.CancellationIntent
	CancellationIdempotency map[string]IdempotencyRecord
}

func NewState() State {
	return State{
		Executions:              make(map[string]providerexec.ExecutionRecord),
		ExecutionIdempotency:    make(map[string]IdempotencyRecord),
		CancellationIntents:     make(map[string]providerexec.CancellationIntent),
		CancellationIdempotency: make(map[string]IdempotencyRecord),
	}
}

func (s *State) ensureMaps() {
	if s.Executions == nil {
		s.Executions = make(map[string]providerexec.ExecutionRecord)
	}
	if s.ExecutionIdempotency == nil {
		s.ExecutionIdempotency = make(map[string]IdempotencyRecord)
	}
	if s.CancellationIntents == nil {
		s.CancellationIntents = make(map[string]providerexec.CancellationIntent)
	}
	if s.CancellationIdempotency == nil {
		s.CancellationIdempotency = make(map[string]IdempotencyRecord)
	}
}

func (s *State) ReserveExecution(request providerexec.Request, dispatch ...providerexec.Dispatch) (providerexec.ExecutionReservation, error) {
	acceptedAt := time.Now().UTC()
	if len(dispatch) == 1 {
		acceptedAt = dispatch[0].AcceptedAt
	}
	return s.reserveExecutionAt(request, acceptedAt, dispatch...)
}

// ReserveExecutionAt is the deterministic form used by repository adapters.
// With no dispatch it records only durable admission; a later AttachExecution
// must bind the executor receipt to this exact identity.
func (s *State) ReserveExecutionAt(request providerexec.Request, acceptedAt time.Time, dispatch ...providerexec.Dispatch) (providerexec.ExecutionReservation, error) {
	return s.reserveExecutionAt(request, acceptedAt, dispatch...)
}

func (s *State) reserveExecutionAt(request providerexec.Request, acceptedAt time.Time, dispatch ...providerexec.Dispatch) (providerexec.ExecutionReservation, error) {
	s.ensureMaps()
	if len(dispatch) > 1 {
		return providerexec.ExecutionReservation{}, fmt.Errorf("%w: multiple dispatch receipts", providerexec.ErrInvalidDispatch)
	}
	if acceptedAt.IsZero() {
		return providerexec.ExecutionReservation{}, fmt.Errorf("%w: acceptance time", providerexec.ErrInvalidRequest)
	}
	if err := request.Validate(acceptedAt); err != nil {
		return providerexec.ExecutionReservation{}, fmt.Errorf("validate execution request: %w", err)
	}
	if len(dispatch) == 1 {
		if err := dispatch[0].Validate(); err != nil {
			return providerexec.ExecutionReservation{}, err
		}
	}
	if existing, ok := s.ExecutionIdempotency[request.IdempotencyKey]; ok {
		if existing.RequestDigest != request.RequestDigest || existing.OperationID != request.OperationID {
			return providerexec.ExecutionReservation{}, ErrIdempotencyConflict
		}
		record, ok := s.Executions[existing.OperationID]
		if !ok {
			return providerexec.ExecutionReservation{}, fmt.Errorf("%w: idempotency record", ErrCorrupt)
		}
		if !sameExecutionIdentity(record.Request, request) {
			return providerexec.ExecutionReservation{}, ErrConflict
		}
		return providerexec.ExecutionReservation{Execution: record.Clone(), Replayed: true}, nil
	}
	if _, ok := s.Executions[request.OperationID]; ok {
		return providerexec.ExecutionReservation{}, ErrAlreadyExists
	}
	if len(dispatch) == 1 {
		for operationID, other := range s.Executions {
			if operationID != request.OperationID && other.Attached && other.Dispatch.ExecutionReference == dispatch[0].ExecutionReference {
				return providerexec.ExecutionReservation{}, ErrConflict
			}
		}
	}
	record := providerexec.ExecutionRecord{Request: request.Clone(), ReservedAt: acceptedAt.UTC()}
	if len(dispatch) == 1 {
		record.Dispatch = dispatch[0]
		record.Attached = true
	}
	s.Executions[request.OperationID] = record.Clone()
	s.ExecutionIdempotency[request.IdempotencyKey] = IdempotencyRecord{Key: request.IdempotencyKey, RequestDigest: request.RequestDigest, OperationID: request.OperationID}
	return providerexec.ExecutionReservation{Execution: record, Replayed: false}, nil
}

func (s *State) AttachExecution(attachment providerexec.ExecutionAttachment) (providerexec.ExecutionReservation, error) {
	if err := validateAttachment(attachment); err != nil {
		return providerexec.ExecutionReservation{}, err
	}
	s.ensureMaps()
	record, ok := s.Executions[attachment.OperationID]
	if !ok {
		return providerexec.ExecutionReservation{}, ErrNotFound
	}
	if !executionAttachmentMatches(record.Request, attachment) {
		return providerexec.ExecutionReservation{}, ErrConflict
	}
	if record.Attached {
		if record.Dispatch.ExecutionReference != attachment.Dispatch.ExecutionReference {
			return providerexec.ExecutionReservation{}, ErrConflict
		}
		return providerexec.ExecutionReservation{Execution: record.Clone(), Replayed: true}, nil
	}
	for operationID, other := range s.Executions {
		if operationID != attachment.OperationID && other.Attached && other.Dispatch.ExecutionReference == attachment.Dispatch.ExecutionReference {
			return providerexec.ExecutionReservation{}, ErrConflict
		}
	}
	record.Dispatch = attachment.Dispatch
	record.Attached = true
	s.Executions[attachment.OperationID] = record.Clone()
	return providerexec.ExecutionReservation{Execution: record.Clone(), Replayed: false}, nil
}

func (s *State) GetExecution(operationID string) (providerexec.ExecutionRecord, error) {
	s.ensureMaps()
	record, ok := s.Executions[operationID]
	if !ok {
		return providerexec.ExecutionRecord{}, fmt.Errorf("%w: operation %s", ErrNotFound, operationID)
	}
	return record.Clone(), nil
}

func (s *State) ReserveCancellation(intent providerexec.CancellationIntent, now time.Time) (providerexec.CancellationReservation, error) {
	s.ensureMaps()
	if err := intent.Validate(now); err != nil {
		return providerexec.CancellationReservation{}, err
	}
	if existing, ok := s.CancellationIdempotency[intent.IdempotencyKey]; ok {
		if existing.RequestDigest != intent.RequestDigest || existing.OperationID != intent.OperationID {
			return providerexec.CancellationReservation{}, ErrIdempotencyConflict
		}
		stored, ok := s.CancellationIntents[existing.OperationID]
		if !ok {
			return providerexec.CancellationReservation{}, fmt.Errorf("%w: cancellation idempotency record", ErrCorrupt)
		}
		return providerexec.CancellationReservation{Intent: stored, Replayed: true}, nil
	}
	target, ok := s.Executions[intent.TargetOperationID]
	if !ok {
		return providerexec.CancellationReservation{}, ErrNotFound
	}
	if target.Request.AttemptID != intent.TargetAttemptID || target.Request.SandboxID != intent.SandboxID || target.Request.ExpectedGeneration != intent.ExpectedGeneration {
		return providerexec.CancellationReservation{}, ErrConflict
	}
	if target.Result != nil || target.ResultExpired {
		return providerexec.CancellationReservation{}, ErrAlreadyExists
	}
	if _, ok := s.CancellationIntents[intent.OperationID]; ok {
		return providerexec.CancellationReservation{}, ErrAlreadyExists
	}
	s.CancellationIntents[intent.OperationID] = intent
	s.CancellationIdempotency[intent.IdempotencyKey] = IdempotencyRecord{Key: intent.IdempotencyKey, RequestDigest: intent.RequestDigest, OperationID: intent.OperationID}
	return providerexec.CancellationReservation{Intent: intent, Replayed: false}, nil
}

func (s *State) GetCancellation(operationID string) (providerexec.CancellationIntent, error) {
	s.ensureMaps()
	intent, ok := s.CancellationIntents[operationID]
	if !ok {
		return providerexec.CancellationIntent{}, fmt.Errorf("%w: cancellation %s", ErrNotFound, operationID)
	}
	return intent, nil
}

func (s *State) StoreResult(result providerexec.Result) error {
	s.ensureMaps()
	if err := result.Validate(); err != nil {
		return err
	}
	record, ok := s.Executions[result.OperationID]
	if !ok {
		return ErrNotFound
	}
	if record.Request.AttemptID != result.AttemptID || record.Request.SandboxID != result.SandboxID || record.Request.FencingToken != result.FencingToken {
		return ErrConflict
	}
	if !record.Attached {
		return ErrConflict
	}
	expectedRetention := result.CompletedAt.Add(record.Request.ResultRetention)
	if !result.RetainedUntil.Equal(expectedRetention) {
		return ErrConflict
	}
	if record.ResultExpired {
		return ErrExpired
	}
	if record.Result != nil {
		if reflect.DeepEqual(*record.Result, result) {
			return nil
		}
		return ErrConflict
	}
	record.Result = result.Clone()
	s.Executions[result.OperationID] = record
	return nil
}

func (s *State) ReadResult(operationID string, now time.Time) (providerexec.Result, error, bool) {
	s.ensureMaps()
	record, ok := s.Executions[operationID]
	if !ok {
		return providerexec.Result{}, ErrNotFound, false
	}
	if record.ResultExpired {
		return providerexec.Result{}, ErrExpired, false
	}
	if record.Result == nil {
		return providerexec.Result{}, ErrPending, false
	}
	if !now.Before(record.Result.RetainedUntil) {
		record.ResultExpired = true
		record.Result = nil
		s.Executions[operationID] = record
		return providerexec.Result{}, ErrExpired, true
	}
	return *record.Result.Clone(), nil, false
}

func (s State) Export() PersistedState {
	s.ensureMaps()
	result := PersistedState{
		Version:                 snapshotVersion,
		Executions:              make(map[string]providerexec.ExecutionRecord, len(s.Executions)),
		ExecutionIdempotency:    make(map[string]IdempotencyRecord, len(s.ExecutionIdempotency)),
		CancellationIntents:     make(map[string]providerexec.CancellationIntent, len(s.CancellationIntents)),
		CancellationIdempotency: make(map[string]IdempotencyRecord, len(s.CancellationIdempotency)),
	}
	for key, record := range s.Executions {
		result.Executions[key] = record.Clone()
	}
	for key, record := range s.ExecutionIdempotency {
		result.ExecutionIdempotency[key] = record
	}
	for key, intent := range s.CancellationIntents {
		result.CancellationIntents[key] = intent
	}
	for key, record := range s.CancellationIdempotency {
		result.CancellationIdempotency[key] = record
	}
	return result
}

func (s *State) Import(snapshot PersistedState) error {
	if snapshot.Version != snapshotVersion || snapshot.Executions == nil || snapshot.ExecutionIdempotency == nil || snapshot.CancellationIntents == nil || snapshot.CancellationIdempotency == nil {
		return ErrCorrupt
	}
	imported := NewState()
	for operationID, record := range snapshot.Executions {
		if operationID == "" || record.Request.OperationID != operationID || !validPersistedRequest(record.Request) {
			return ErrCorrupt
		}
		// Version-1 snapshots predate Attached and always carried a receipt.
		if !record.Attached && record.Dispatch.ExecutionReference != "" {
			record.Attached = true
		}
		if record.ReservedAt.IsZero() {
			if record.Attached {
				record.ReservedAt = record.Dispatch.AcceptedAt
			} else {
				return ErrCorrupt
			}
		}
		if record.Attached {
			if record.Dispatch.Validate() != nil {
				return ErrCorrupt
			}
		} else if record.Dispatch != (providerexec.Dispatch{}) {
			return ErrCorrupt
		}
		if record.Result != nil {
			if err := imported.validateStoredResult(record); err != nil {
				return err
			}
		}
		if record.ResultExpired && record.Result != nil {
			return ErrCorrupt
		}
		imported.Executions[operationID] = record.Clone()
	}
	for key, idempotency := range snapshot.ExecutionIdempotency {
		if key == "" || idempotency.Key != key || idempotency.RequestDigest == "" || idempotency.OperationID == "" {
			return ErrCorrupt
		}
		record, ok := imported.Executions[idempotency.OperationID]
		if !ok || record.Request.IdempotencyKey != key || record.Request.RequestDigest != idempotency.RequestDigest {
			return ErrCorrupt
		}
		imported.ExecutionIdempotency[key] = idempotency
	}
	for operationID, record := range imported.Executions {
		idempotency, ok := imported.ExecutionIdempotency[record.Request.IdempotencyKey]
		if !ok || idempotency.OperationID != operationID {
			return ErrCorrupt
		}
	}
	for operationID, intent := range snapshot.CancellationIntents {
		if operationID == "" || intent.OperationID != operationID || intent.Validate(time.Time{}) != nil {
			return ErrCorrupt
		}
		target, ok := imported.Executions[intent.TargetOperationID]
		if !ok || target.Request.AttemptID != intent.TargetAttemptID || target.Request.SandboxID != intent.SandboxID || target.Request.ExpectedGeneration != intent.ExpectedGeneration {
			return ErrCorrupt
		}
		imported.CancellationIntents[operationID] = intent
	}
	for key, idempotency := range snapshot.CancellationIdempotency {
		if key == "" || idempotency.Key != key || idempotency.RequestDigest == "" || idempotency.OperationID == "" {
			return ErrCorrupt
		}
		intent, ok := imported.CancellationIntents[idempotency.OperationID]
		if !ok || intent.IdempotencyKey != key || intent.RequestDigest != idempotency.RequestDigest {
			return ErrCorrupt
		}
		imported.CancellationIdempotency[key] = idempotency
	}
	for operationID, intent := range imported.CancellationIntents {
		idempotency, ok := imported.CancellationIdempotency[intent.IdempotencyKey]
		if !ok || idempotency.OperationID != operationID {
			return ErrCorrupt
		}
	}
	*s = imported
	return nil
}

func (s *State) validateStoredResult(record providerexec.ExecutionRecord) error {
	if record.Result == nil || !record.Attached {
		return ErrCorrupt
	}
	result := *record.Result
	if err := result.Validate(); err != nil || result.OperationID != record.Request.OperationID || result.AttemptID != record.Request.AttemptID || result.SandboxID != record.Request.SandboxID || result.FencingToken != record.Request.FencingToken || !result.RetainedUntil.Equal(result.CompletedAt.Add(record.Request.ResultRetention)) {
		return ErrCorrupt
	}
	return nil
}

func validateAttachment(attachment providerexec.ExecutionAttachment) error {
	if err := attachment.Dispatch.Validate(); err != nil {
		return err
	}
	request := providerexec.Request{
		OperationID: attachment.OperationID, AttemptID: attachment.AttemptID,
		SandboxID: attachment.SandboxID, FencingToken: attachment.FencingToken,
		ExpectedGeneration: attachment.ExpectedGeneration,
	}
	for name, value := range map[string]string{
		"operation_id": request.OperationID, "attempt_id": request.AttemptID, "sandbox_id": request.SandboxID,
	} {
		if !attachmentIdentifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", providerexec.ErrInvalidRequest, name)
		}
	}
	if request.FencingToken < 1 || request.ExpectedGeneration < 1 {
		return fmt.Errorf("%w: attachment fence", providerexec.ErrInvalidRequest)
	}
	return nil
}

func executionAttachmentMatches(request providerexec.Request, attachment providerexec.ExecutionAttachment) bool {
	return request.OperationID == attachment.OperationID && request.AttemptID == attachment.AttemptID && request.SandboxID == attachment.SandboxID && request.FencingToken == attachment.FencingToken && request.ExpectedGeneration == attachment.ExpectedGeneration
}

func validPersistedRequest(request providerexec.Request) bool {
	if request.Deadline.IsZero() {
		return false
	}
	return request.Validate(request.Deadline.Add(-time.Nanosecond)) == nil
}

func sameExecutionIdentity(left, right providerexec.Request) bool {
	return left.OperationID == right.OperationID && left.AttemptID == right.AttemptID && left.SandboxID == right.SandboxID && left.FencingToken == right.FencingToken && left.RequestDigest == right.RequestDigest
}
