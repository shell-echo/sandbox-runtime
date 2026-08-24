package repository

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
)

const snapshotVersion = 1

// State is the adapter-independent mutable snapshot. Adapters must hold their
// own lock while calling its methods.
type State struct {
	Sessions    map[string]session.Record
	Idempotency map[string]IdempotencyRecord
	Authorities map[string]session.SandboxAuthority
}

type IdempotencyRecord struct {
	Scope         string `json:"scope"`
	Key           string `json:"key"`
	RequestDigest string `json:"request_digest"`
	OperationID   string `json:"operation_id"`
}

type PersistedState struct {
	Version     int                        `json:"version"`
	Sessions    []session.Record           `json:"sessions"`
	Idempotency []IdempotencyRecord        `json:"idempotency"`
	Authorities []session.SandboxAuthority `json:"authorities"`
}

func NewState() State {
	return State{
		Sessions:    make(map[string]session.Record),
		Idempotency: make(map[string]IdempotencyRecord),
		Authorities: make(map[string]session.SandboxAuthority),
	}
}

func (s *State) ensureMaps() {
	if s.Sessions == nil {
		s.Sessions = make(map[string]session.Record)
	}
	if s.Idempotency == nil {
		s.Idempotency = make(map[string]IdempotencyRecord)
	}
	if s.Authorities == nil {
		s.Authorities = make(map[string]session.SandboxAuthority)
	}
}

func (s *State) PutSandboxAuthority(authority session.SandboxAuthority) error {
	s.ensureMaps()
	if err := authority.Validate(); err != nil {
		return err
	}
	if existing, ok := s.Authorities[authority.SandboxID]; ok {
		if existing == authority {
			return nil
		}
		return ErrAuthorityConflict
	}
	s.Authorities[authority.SandboxID] = authority.Clone()
	return nil
}

// ReplaceSandboxAuthority updates a trusted observation with compare-and-set
// generation and fencing checks. The incoming generation may stay the same
// for a readiness or lease observation, or advance by one for a new state
// generation. A higher fencing token advances the high-water mark.
func (s *State) ReplaceSandboxAuthority(authority session.SandboxAuthority, expectedGeneration, fencingToken int64) error {
	s.ensureMaps()
	if err := authority.Validate(); err != nil {
		return err
	}
	current, ok := s.Authorities[authority.SandboxID]
	if !ok {
		return fmt.Errorf("%w: sandbox authority %s", ErrNotFound, authority.SandboxID)
	}
	if current.Generation != expectedGeneration || authority.Generation < current.Generation || authority.Generation > current.Generation+1 {
		return session.ErrGenerationConflict
	}
	if fencingToken != current.FencingToken {
		return session.ErrStaleFencingToken
	}
	if authority.FencingToken < current.FencingToken {
		return session.ErrStaleFencingToken
	}
	if authority.ProviderRevisionID != current.ProviderRevisionID {
		return session.ErrProviderRevisionConflict
	}
	s.Authorities[authority.SandboxID] = authority.Clone()
	return nil
}

func (s *State) GetSandboxAuthority(sandboxID string) (session.SandboxAuthority, error) {
	s.ensureMaps()
	authority, ok := s.Authorities[sandboxID]
	if !ok {
		return session.SandboxAuthority{}, fmt.Errorf("%w: sandbox authority %s", ErrNotFound, sandboxID)
	}
	return authority.Clone(), nil
}

func (s *State) ReserveOpenAt(request session.OpenRequest, acceptedAt time.Time) (session.Reservation, error) {
	s.ensureMaps()
	acceptedAt = acceptedAt.UTC()
	if acceptedAt.IsZero() {
		return session.Reservation{}, fmt.Errorf("%w: acceptance time", session.ErrInvalidRequest)
	}
	if err := request.Validate(acceptedAt); err != nil {
		return session.Reservation{}, err
	}
	authority, err := s.GetSandboxAuthority(request.SandboxID)
	if err != nil {
		return session.Reservation{}, err
	}
	if err := checkAuthority(authority, request, acceptedAt); err != nil {
		return session.Reservation{}, err
	}
	scope := idempotencyScope(request)
	if existing, ok := s.Idempotency[scope]; ok {
		if existing.RequestDigest != request.RequestDigest {
			return session.Reservation{}, ErrIdempotencyConflict
		}
		record, ok := s.Sessions[existing.OperationID]
		if !ok {
			return session.Reservation{}, fmt.Errorf("%w: idempotency references missing operation", ErrCorrupt)
		}
		if !sameOpenRequest(record.Request, request) {
			return session.Reservation{}, ErrConflict
		}
		return session.Reservation{Record: record.Clone(), Replayed: true}, nil
	}
	if _, exists := s.Sessions[request.OperationID]; exists {
		return session.Reservation{}, ErrAlreadyExists
	}
	record, err := session.NewRecord(request, acceptedAt)
	if err != nil {
		return session.Reservation{}, err
	}
	s.Sessions[request.OperationID] = record.Clone()
	s.Idempotency[scope] = IdempotencyRecord{
		Scope: scope, Key: request.IdempotencyKey, RequestDigest: request.RequestDigest, OperationID: request.OperationID,
	}
	return session.Reservation{Record: record.Clone()}, nil
}

func (s *State) GetOpen(operationID string) (session.Record, error) {
	return s.GetOpenAt(operationID, nowUTC())
}

func (s *State) GetOpenAt(operationID string, now time.Time) (session.Record, error) {
	s.ensureMaps()
	record, ok := s.Sessions[operationID]
	if !ok {
		return session.Record{}, fmt.Errorf("%w: operation %s", ErrNotFound, operationID)
	}
	if err := record.Validate(); err != nil {
		return session.Record{}, fmt.Errorf("%w: persisted operation: %v", ErrCorrupt, err)
	}
	if now.IsZero() {
		return session.Record{}, fmt.Errorf("%w: current time", session.ErrInvalidRecord)
	}
	if record.Status == session.StatusSucceeded && !now.Before(record.Request.ExpiresAt) {
		return session.Record{}, ErrExpired
	}
	return record.Clone(), nil
}

func (s *State) UpdateOpenAt(record session.Record, expectedStatus session.Status, now time.Time) error {
	s.ensureMaps()
	if now.IsZero() {
		return fmt.Errorf("%w: current time", session.ErrInvalidRecord)
	}
	current, ok := s.Sessions[record.Request.OperationID]
	if !ok {
		return fmt.Errorf("%w: operation %s", ErrNotFound, record.Request.OperationID)
	}
	if current.Status != expectedStatus {
		return ErrConflict
	}
	if !sameOpenRequest(current.Request, record.Request) || !sameTime(current.AcceptedAt, record.AcceptedAt) {
		return ErrConflict
	}
	if err := record.Validate(); err != nil {
		return err
	}
	var evidence *session.EndpointEvidence
	if record.Handoff != nil {
		evidence = &session.EndpointEvidence{
			InternalEndpointReference: record.Handoff.InternalEndpointReference,
			ConnectionGeneration:      record.Handoff.ConnectionGeneration,
		}
	}
	updated, err := session.Transition(current, record.Status, record.ObservedAt, evidence)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(updated, record) {
		return ErrConflict
	}
	if record.Status == session.StatusSucceeded && current.Status != session.StatusSucceeded {
		authority, err := s.GetSandboxAuthority(record.Request.SandboxID)
		if err != nil {
			return err
		}
		if err := checkAuthority(authority, record.Request, now); err != nil {
			return err
		}
	}
	s.Sessions[record.Request.OperationID] = record.Clone()
	return nil
}

func checkAuthority(authority session.SandboxAuthority, request session.OpenRequest, now time.Time) error {
	if err := authority.Validate(); err != nil {
		return fmt.Errorf("%w: authority: %v", ErrCorrupt, err)
	}
	if authority.ProviderRevisionID != request.ProviderRevisionID {
		return session.ErrProviderRevisionConflict
	}
	if !authority.Ready {
		return session.ErrSandboxNotReady
	}
	if authority.Generation != request.ExpectedGeneration {
		return session.ErrGenerationConflict
	}
	if !authority.LeaseExpiresAt.After(now) || request.ExpiresAt.After(authority.LeaseExpiresAt) {
		return session.ErrLeaseExpired
	}
	if authority.FencingToken != request.FencingToken {
		return session.ErrStaleFencingToken
	}
	if authority.CapabilityProfileID != request.CapabilityProfileID {
		return session.ErrCapabilityUnsupported
	}
	return nil
}

func idempotencyScope(request session.OpenRequest) string {
	return request.SandboxID + "\x00" + request.ProviderRevisionID + "\x00" + request.IdempotencyKey
}

func sameOpenRequest(left, right session.OpenRequest) bool {
	return left.SandboxID == right.SandboxID &&
		left.ProviderRevisionID == right.ProviderRevisionID &&
		left.OperationID == right.OperationID &&
		left.AttemptID == right.AttemptID &&
		left.FencingToken == right.FencingToken &&
		left.IdempotencyKey == right.IdempotencyKey &&
		left.RequestDigest == right.RequestDigest &&
		sameTime(left.Deadline, right.Deadline) &&
		left.ExpectedGeneration == right.ExpectedGeneration &&
		left.RuntimeSessionID == right.RuntimeSessionID &&
		left.RuntimeType == right.RuntimeType &&
		left.CapabilityProfileID == right.CapabilityProfileID &&
		sameTime(left.ExpiresAt, right.ExpiresAt)
}

func sameTime(left, right time.Time) bool { return left.Equal(right) }

func (s State) Export() PersistedState {
	result := PersistedState{Version: snapshotVersion}
	for _, record := range s.Sessions {
		result.Sessions = append(result.Sessions, record.Clone())
	}
	for _, record := range s.Idempotency {
		result.Idempotency = append(result.Idempotency, record)
	}
	for _, authority := range s.Authorities {
		result.Authorities = append(result.Authorities, authority.Clone())
	}
	sort.Slice(result.Sessions, func(i, j int) bool {
		return result.Sessions[i].Request.OperationID < result.Sessions[j].Request.OperationID
	})
	sort.Slice(result.Idempotency, func(i, j int) bool { return result.Idempotency[i].Scope < result.Idempotency[j].Scope })
	sort.Slice(result.Authorities, func(i, j int) bool { return result.Authorities[i].SandboxID < result.Authorities[j].SandboxID })
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
	for _, record := range snapshot.Sessions {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("%w: session: %v", ErrCorrupt, err)
		}
		operationID := record.Request.OperationID
		if _, exists := loaded.Sessions[operationID]; exists {
			return fmt.Errorf("%w: duplicate operation %q", ErrCorrupt, operationID)
		}
		authority, exists := loaded.Authorities[record.Request.SandboxID]
		if !exists || authority.ProviderRevisionID != record.Request.ProviderRevisionID {
			return fmt.Errorf("%w: session %q references missing authority", ErrCorrupt, operationID)
		}
		loaded.Sessions[operationID] = record.Clone()
	}
	for _, record := range snapshot.Idempotency {
		if record.Scope == "" || record.Key == "" || record.RequestDigest == "" || record.OperationID == "" {
			return fmt.Errorf("%w: invalid idempotency record", ErrCorrupt)
		}
		sessionRecord, exists := loaded.Sessions[record.OperationID]
		if !exists {
			return fmt.Errorf("%w: idempotency references missing operation %q", ErrCorrupt, record.OperationID)
		}
		if record.RequestDigest != sessionRecord.Request.RequestDigest || record.Key != sessionRecord.Request.IdempotencyKey || record.Scope != idempotencyScope(sessionRecord.Request) {
			return fmt.Errorf("%w: invalid idempotency binding", ErrCorrupt)
		}
		if _, exists := loaded.Idempotency[record.Scope]; exists {
			return fmt.Errorf("%w: duplicate idempotency scope %q", ErrCorrupt, record.Scope)
		}
		loaded.Idempotency[record.Scope] = record
	}
	for operationID, record := range loaded.Sessions {
		if _, exists := loaded.Idempotency[idempotencyScope(record.Request)]; !exists {
			return fmt.Errorf("%w: session %q has no idempotency record", ErrCorrupt, operationID)
		}
	}
	*s = loaded
	return nil
}
