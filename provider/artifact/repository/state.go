package repository

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

// Version 2 adds the admission-derived tenant binding to every persisted
// request. Version 1 cannot be migrated without inventing tenant authority.
const snapshotVersion = 2

type State struct {
	Operations      map[string]artifact.Operation
	Idempotency     map[string]IdempotencyRecord
	Authorities     map[string]artifact.SandboxAuthority
	ExpiredEvidence map[string]bool
}

type IdempotencyRecord struct {
	Scope         string `json:"scope"`
	Key           string `json:"key"`
	RequestDigest string `json:"request_digest"`
	OperationID   string `json:"operation_id"`
}

type PersistedState struct {
	Version         int                         `json:"version"`
	Operations      []artifact.Operation        `json:"operations"`
	Idempotency     []IdempotencyRecord         `json:"idempotency"`
	Authorities     []artifact.SandboxAuthority `json:"authorities"`
	ExpiredEvidence []string                    `json:"expired_evidence,omitempty"`
}

func NewState() State {
	return State{
		Operations: make(map[string]artifact.Operation), Idempotency: make(map[string]IdempotencyRecord),
		Authorities: make(map[string]artifact.SandboxAuthority), ExpiredEvidence: make(map[string]bool),
	}
}

func (s *State) ensureMaps() {
	if s.Operations == nil {
		s.Operations = make(map[string]artifact.Operation)
	}
	if s.Idempotency == nil {
		s.Idempotency = make(map[string]IdempotencyRecord)
	}
	if s.Authorities == nil {
		s.Authorities = make(map[string]artifact.SandboxAuthority)
	}
	if s.ExpiredEvidence == nil {
		s.ExpiredEvidence = make(map[string]bool)
	}
}

func (s *State) PutSandboxAuthority(authority artifact.SandboxAuthority) error {
	s.ensureMaps()
	if err := authority.Validate(); err != nil {
		return err
	}
	if existing, ok := s.Authorities[authority.SandboxID]; ok {
		if existing == authority {
			return nil
		}
		return ErrConflict
	}
	s.Authorities[authority.SandboxID] = authority.Clone()
	return nil
}

func (s *State) ReplaceSandboxAuthority(authority artifact.SandboxAuthority, expectedGeneration, fencingToken int64) error {
	s.ensureMaps()
	if err := authority.Validate(); err != nil {
		return err
	}
	current, ok := s.Authorities[authority.SandboxID]
	if !ok {
		return fmt.Errorf("%w: sandbox authority %s", ErrNotFound, authority.SandboxID)
	}
	if current.Generation != expectedGeneration || authority.Generation < current.Generation || authority.Generation > current.Generation+1 {
		return artifact.ErrGenerationConflict
	}
	if current.FencingToken != fencingToken || authority.FencingToken < current.FencingToken {
		return artifact.ErrStaleFencingToken
	}
	s.Authorities[authority.SandboxID] = authority.Clone()
	return nil
}

func (s *State) GetSandboxAuthority(sandboxID string) (artifact.SandboxAuthority, error) {
	s.ensureMaps()
	authority, ok := s.Authorities[sandboxID]
	if !ok {
		return artifact.SandboxAuthority{}, fmt.Errorf("%w: sandbox authority %s", ErrNotFound, sandboxID)
	}
	return authority.Clone(), nil
}

// SynchronizeSandboxAuthority upserts a trusted lifecycle generation while
// preserving this repository's operation-local fencing high-water mark.
func (s *State) SynchronizeSandboxAuthority(authority artifact.SandboxAuthority) error {
	s.ensureMaps()
	if err := authority.Validate(); err != nil {
		return err
	}
	current, ok := s.Authorities[authority.SandboxID]
	if !ok {
		s.Authorities[authority.SandboxID] = authority.Clone()
		return nil
	}
	if authority.Generation < current.Generation {
		return artifact.ErrGenerationConflict
	}
	if authority.FencingToken < current.FencingToken {
		return artifact.ErrStaleFencingToken
	}
	s.Authorities[authority.SandboxID] = authority.Clone()
	return nil
}

func (s *State) ReserveStageAt(request artifact.Request, acceptedAt time.Time) (artifact.Reservation, error) {
	s.ensureMaps()
	acceptedAt = acceptedAt.UTC()
	if err := request.Validate(acceptedAt); err != nil {
		return artifact.Reservation{}, err
	}
	authority, err := s.GetSandboxAuthority(request.SandboxID)
	if err != nil {
		return artifact.Reservation{}, err
	}
	if authority.Generation != request.ExpectedGeneration {
		return artifact.Reservation{}, artifact.ErrGenerationConflict
	}
	if authority.FencingToken != request.FencingToken {
		return artifact.Reservation{}, artifact.ErrStaleFencingToken
	}
	scope := idempotencyScope(request)
	if existing, ok := s.Idempotency[scope]; ok {
		if existing.RequestDigest != request.RequestDigest {
			return artifact.Reservation{}, ErrIdempotencyConflict
		}
		operation, ok := s.Operations[existing.OperationID]
		if !ok {
			return artifact.Reservation{}, fmt.Errorf("%w: idempotency references missing operation", ErrCorrupt)
		}
		if !sameRequest(operation.Request, request) {
			return artifact.Reservation{}, ErrConflict
		}
		return artifact.Reservation{Operation: operation.Clone(), Replayed: true}, nil
	}
	if _, exists := s.Operations[request.OperationID]; exists {
		return artifact.Reservation{}, ErrAlreadyExists
	}
	operation, err := artifact.NewOperation(request, acceptedAt)
	if err != nil {
		return artifact.Reservation{}, err
	}
	s.Operations[request.OperationID] = operation.Clone()
	s.Idempotency[scope] = IdempotencyRecord{Scope: scope, Key: request.IdempotencyKey, RequestDigest: request.RequestDigest, OperationID: request.OperationID}
	return artifact.Reservation{Operation: operation.Clone()}, nil
}

func (s *State) GetStage(operationID string) (artifact.Operation, error) {
	s.ensureMaps()
	operation, ok := s.Operations[operationID]
	if !ok {
		return artifact.Operation{}, fmt.Errorf("%w: operation %s", ErrNotFound, operationID)
	}
	if err := operation.Validate(); err != nil {
		return artifact.Operation{}, fmt.Errorf("%w: operation %s: %v", ErrCorrupt, operationID, err)
	}
	return operation.Clone(), nil
}

func (s *State) ListStages() ([]artifact.Operation, error) {
	s.ensureMaps()
	ids := make([]string, 0, len(s.Operations))
	for id := range s.Operations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]artifact.Operation, 0, len(ids))
	for _, id := range ids {
		operation, err := s.GetStage(id)
		if err != nil {
			return nil, err
		}
		result = append(result, operation)
	}
	return result, nil
}

func (s *State) UpdateStage(operation artifact.Operation, expectedStatus artifact.OperationStatus) error {
	s.ensureMaps()
	current, ok := s.Operations[operation.Request.OperationID]
	if !ok {
		return fmt.Errorf("%w: operation %s", ErrNotFound, operation.Request.OperationID)
	}
	if current.Status != expectedStatus || !sameRequest(current.Request, operation.Request) || !current.AcceptedAt.Equal(operation.AcceptedAt) {
		return ErrConflict
	}
	var evidence *artifact.Evidence
	if operation.Evidence != nil {
		copyEvidence := *operation.Evidence
		evidence = &copyEvidence
	}
	updated, err := artifact.Transition(current, operation.Status, operation.ObservedAt, operation.Failure, evidence)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(updated, operation) {
		return ErrConflict
	}
	s.Operations[operation.Request.OperationID] = operation.Clone()
	return nil
}

func (s *State) ReadEvidenceAt(operationID string, now time.Time) (artifact.Evidence, error, bool) {
	s.ensureMaps()
	operation, ok := s.Operations[operationID]
	if !ok {
		return artifact.Evidence{}, artifact.ErrEvidenceNotFound, false
	}
	if s.ExpiredEvidence[operationID] {
		return artifact.Evidence{}, artifact.ErrEvidenceExpired, false
	}
	switch operation.Status {
	case artifact.OperationAccepted, artifact.OperationRunning:
		return artifact.Evidence{}, artifact.ErrEvidencePending, false
	case artifact.OperationOutcomeUnknown:
		return artifact.Evidence{}, artifact.ErrOutcomeUnknown, false
	}
	if operation.Evidence == nil {
		return artifact.Evidence{}, artifact.ErrEvidenceNotFound, false
	}
	if now.IsZero() {
		return artifact.Evidence{}, artifact.ErrInvalidEvidence, false
	}
	if !now.UTC().Before(operation.Evidence.ExpiresAt) {
		s.ExpiredEvidence[operationID] = true
		return artifact.Evidence{}, artifact.ErrEvidenceExpired, true
	}
	return *operation.Evidence, nil, false
}

func (s State) Export() PersistedState {
	s.ensureMaps()
	result := PersistedState{Version: snapshotVersion}
	for _, operation := range s.Operations {
		result.Operations = append(result.Operations, operation.Clone())
	}
	for _, record := range s.Idempotency {
		result.Idempotency = append(result.Idempotency, record)
	}
	for _, authority := range s.Authorities {
		result.Authorities = append(result.Authorities, authority.Clone())
	}
	for operationID, expired := range s.ExpiredEvidence {
		if expired {
			result.ExpiredEvidence = append(result.ExpiredEvidence, operationID)
		}
	}
	sort.Slice(result.Operations, func(i, j int) bool {
		return result.Operations[i].Request.OperationID < result.Operations[j].Request.OperationID
	})
	sort.Slice(result.Idempotency, func(i, j int) bool { return result.Idempotency[i].Scope < result.Idempotency[j].Scope })
	sort.Slice(result.Authorities, func(i, j int) bool { return result.Authorities[i].SandboxID < result.Authorities[j].SandboxID })
	sort.Strings(result.ExpiredEvidence)
	return result
}

func (s *State) Import(snapshot PersistedState) error {
	if snapshot.Version != snapshotVersion {
		return fmt.Errorf("%w: unsupported state version %d", ErrCorrupt, snapshot.Version)
	}
	loaded := NewState()
	for _, authority := range snapshot.Authorities {
		if err := authority.Validate(); err != nil {
			return fmt.Errorf("%w: authority: %v", ErrCorrupt, err)
		}
		if _, exists := loaded.Authorities[authority.SandboxID]; exists {
			return fmt.Errorf("%w: duplicate authority %q", ErrCorrupt, authority.SandboxID)
		}
		loaded.Authorities[authority.SandboxID] = authority.Clone()
	}
	for _, operation := range snapshot.Operations {
		if err := operation.Validate(); err != nil {
			return fmt.Errorf("%w: operation: %v", ErrCorrupt, err)
		}
		operationID := operation.Request.OperationID
		if _, exists := loaded.Operations[operationID]; exists {
			return fmt.Errorf("%w: duplicate operation %q", ErrCorrupt, operationID)
		}
		if _, exists := loaded.Authorities[operation.Request.SandboxID]; !exists {
			return fmt.Errorf("%w: operation %q references missing authority", ErrCorrupt, operationID)
		}
		loaded.Operations[operationID] = operation.Clone()
	}
	for _, record := range snapshot.Idempotency {
		operation, exists := loaded.Operations[record.OperationID]
		if !exists || record.Scope == "" || record.Key != operation.Request.IdempotencyKey || record.RequestDigest != operation.Request.RequestDigest || record.Scope != idempotencyScope(operation.Request) {
			return fmt.Errorf("%w: invalid idempotency binding", ErrCorrupt)
		}
		if _, exists := loaded.Idempotency[record.Scope]; exists {
			return fmt.Errorf("%w: duplicate idempotency scope %q", ErrCorrupt, record.Scope)
		}
		loaded.Idempotency[record.Scope] = record
	}
	for operationID, operation := range loaded.Operations {
		if _, exists := loaded.Idempotency[idempotencyScope(operation.Request)]; !exists {
			return fmt.Errorf("%w: operation %q has no idempotency record", ErrCorrupt, operationID)
		}
	}
	for _, operationID := range snapshot.ExpiredEvidence {
		operation, exists := loaded.Operations[operationID]
		if !exists || operation.Evidence == nil || loaded.ExpiredEvidence[operationID] {
			return fmt.Errorf("%w: invalid expired evidence %q", ErrCorrupt, operationID)
		}
		loaded.ExpiredEvidence[operationID] = true
	}
	*s = loaded
	return nil
}

func idempotencyScope(request artifact.Request) string {
	return request.SandboxID + "\x00" + request.IdempotencyKey
}

func sameRequest(left, right artifact.Request) bool {
	return left.SandboxID == right.SandboxID && left.TenantID == right.TenantID && left.OperationID == right.OperationID && left.AttemptID == right.AttemptID &&
		left.FencingToken == right.FencingToken && left.ExpectedGeneration == right.ExpectedGeneration &&
		left.IdempotencyKey == right.IdempotencyKey && left.RequestDigest == right.RequestDigest && left.Deadline.Equal(right.Deadline) &&
		left.ArtifactReference == right.ArtifactReference && left.SourcePath == right.SourcePath && left.ExpectedDigest == right.ExpectedDigest &&
		left.ExpectedMediaType == right.ExpectedMediaType && left.MaxBytes == right.MaxBytes && left.Retention == right.Retention
}
