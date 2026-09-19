package repository

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

const snapshotVersion = 3

type State struct {
	Sessions         map[string]desktop.Record
	Closes           map[string]desktop.CloseRecord
	Idempotency      map[string]IdempotencyRecord
	CloseIdempotency map[string]IdempotencyRecord
	Authorities      map[string]desktop.SandboxAuthority
}

type IdempotencyRecord struct {
	Scope         string `json:"scope"`
	Key           string `json:"key"`
	RequestDigest string `json:"request_digest"`
	OperationID   string `json:"operation_id"`
}

type PersistedState struct {
	Version          int                        `json:"version"`
	Sessions         []desktop.Record           `json:"sessions"`
	Closes           []desktop.CloseRecord      `json:"closes,omitempty"`
	Idempotency      []IdempotencyRecord        `json:"idempotency"`
	CloseIdempotency []IdempotencyRecord        `json:"close_idempotency,omitempty"`
	Authorities      []desktop.SandboxAuthority `json:"authorities"`
}

func NewState() State {
	return State{
		Sessions: make(map[string]desktop.Record), Closes: make(map[string]desktop.CloseRecord),
		Idempotency: make(map[string]IdempotencyRecord), CloseIdempotency: make(map[string]IdempotencyRecord),
		Authorities: make(map[string]desktop.SandboxAuthority),
	}
}

func (s *State) ensureMaps() {
	if s.Sessions == nil {
		s.Sessions = make(map[string]desktop.Record)
	}
	if s.Idempotency == nil {
		s.Idempotency = make(map[string]IdempotencyRecord)
	}
	if s.Closes == nil {
		s.Closes = make(map[string]desktop.CloseRecord)
	}
	if s.CloseIdempotency == nil {
		s.CloseIdempotency = make(map[string]IdempotencyRecord)
	}
	if s.Authorities == nil {
		s.Authorities = make(map[string]desktop.SandboxAuthority)
	}
}

func (s *State) SynchronizeSandboxAuthority(authority desktop.SandboxAuthority) error {
	s.ensureMaps()
	if err := authority.Validate(); err != nil {
		return err
	}
	current, ok := s.Authorities[authority.SandboxID]
	if !ok {
		s.Authorities[authority.SandboxID] = authority.Clone()
		return nil
	}
	if current.ProviderRevisionID != authority.ProviderRevisionID {
		return desktop.ErrProviderRevisionConflict
	}
	if current.CapabilityProfileID != authority.CapabilityProfileID {
		return desktop.ErrCapabilityUnsupported
	}
	if current.NetworkPolicyReference != authority.NetworkPolicyReference {
		return desktop.ErrNetworkPolicyConflict
	}
	if authority.Generation < current.Generation {
		return desktop.ErrGenerationConflict
	}
	if authority.FencingToken < current.FencingToken {
		return desktop.ErrStaleFencingToken
	}
	s.Authorities[authority.SandboxID] = authority.Clone()
	return nil
}

func (s *State) GetSandboxAuthority(sandboxID string) (desktop.SandboxAuthority, error) {
	s.ensureMaps()
	authority, ok := s.Authorities[sandboxID]
	if !ok {
		return desktop.SandboxAuthority{}, fmt.Errorf("%w: sandbox authority %s", ErrNotFound, sandboxID)
	}
	return authority.Clone(), nil
}

func (s *State) ReserveOpenAt(request desktop.OpenRequest, acceptedAt time.Time) (desktop.Reservation, error) {
	s.ensureMaps()
	acceptedAt = acceptedAt.UTC()
	if acceptedAt.IsZero() {
		return desktop.Reservation{}, fmt.Errorf("%w: acceptance time", desktop.ErrInvalidRequest)
	}
	if err := request.Validate(acceptedAt); err != nil {
		return desktop.Reservation{}, err
	}
	authority, err := s.GetSandboxAuthority(request.SandboxID)
	if err != nil {
		return desktop.Reservation{}, err
	}
	if err := checkAuthority(authority, request, acceptedAt); err != nil {
		return desktop.Reservation{}, err
	}
	scope := idempotencyScope(request)
	if _, exists := s.CloseIdempotency[scope]; exists {
		return desktop.Reservation{}, ErrIdempotencyConflict
	}
	if existing, ok := s.Idempotency[scope]; ok {
		if existing.RequestDigest != request.RequestDigest {
			return desktop.Reservation{}, ErrIdempotencyConflict
		}
		record, ok := s.Sessions[existing.OperationID]
		if !ok {
			return desktop.Reservation{}, fmt.Errorf("%w: idempotency references missing operation", ErrCorrupt)
		}
		if !sameOpenRequest(record.Request, request) {
			return desktop.Reservation{}, ErrConflict
		}
		return desktop.Reservation{Record: record.Clone(), Replayed: true}, nil
	}
	if _, exists := s.Sessions[request.OperationID]; exists {
		return desktop.Reservation{}, ErrAlreadyExists
	}
	if _, exists := s.Closes[request.OperationID]; exists {
		return desktop.Reservation{}, ErrAlreadyExists
	}
	record, err := desktop.NewRecord(request, acceptedAt)
	if err != nil {
		return desktop.Reservation{}, err
	}
	s.Sessions[request.OperationID] = record.Clone()
	s.Idempotency[scope] = IdempotencyRecord{Scope: scope, Key: request.IdempotencyKey, RequestDigest: request.RequestDigest, OperationID: request.OperationID}
	return desktop.Reservation{Record: record.Clone()}, nil
}

func (s *State) GetOpen(operationID string) (desktop.Record, error) {
	return s.GetOpenAt(operationID, time.Now().UTC())
}

func (s *State) GetOpenAt(operationID string, now time.Time) (desktop.Record, error) {
	s.ensureMaps()
	record, ok := s.Sessions[operationID]
	if !ok {
		return desktop.Record{}, fmt.Errorf("%w: operation %s", ErrNotFound, operationID)
	}
	if err := record.Validate(); err != nil {
		return desktop.Record{}, fmt.Errorf("%w: persisted operation: %v", ErrCorrupt, err)
	}
	if now.IsZero() {
		return desktop.Record{}, fmt.Errorf("%w: current time", desktop.ErrInvalidRecord)
	}
	return record.Clone(), nil
}

func (s *State) ListOpen() []desktop.Record {
	s.ensureMaps()
	ids := make([]string, 0, len(s.Sessions))
	for id := range s.Sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]desktop.Record, 0, len(ids))
	for _, id := range ids {
		result = append(result, s.Sessions[id].Clone())
	}
	return result
}

func (s *State) AttachAllocation(receipt desktop.AllocationReceipt) (desktop.Reservation, error) {
	s.ensureMaps()
	if err := receipt.Validate(); err != nil {
		return desktop.Reservation{}, err
	}
	current, ok := s.Sessions[receipt.OperationID]
	if !ok {
		return desktop.Reservation{}, fmt.Errorf("%w: operation %s", ErrNotFound, receipt.OperationID)
	}
	for id, record := range s.Sessions {
		if id != receipt.OperationID && record.Allocation != nil && record.Allocation.Receipt.Reference == receipt.Reference {
			return desktop.Reservation{}, desktop.ErrAllocationConflict
		}
	}
	if current.Allocation == nil {
		authority, err := s.GetSandboxAuthority(current.Request.SandboxID)
		if err != nil {
			return desktop.Reservation{}, err
		}
		if err := checkAuthority(authority, current.Request, receipt.AllocatedAt); err != nil {
			return desktop.Reservation{}, err
		}
	}
	updated, err := desktop.AttachAllocation(current, receipt)
	if err != nil {
		return desktop.Reservation{}, err
	}
	replayed := current.Allocation != nil
	s.Sessions[receipt.OperationID] = updated.Clone()
	return desktop.Reservation{Record: updated.Clone(), Replayed: replayed}, nil
}

func (s *State) ObserveAllocation(operationID string, observation desktop.AllocationEvidence) (desktop.Record, error) {
	s.ensureMaps()
	current, ok := s.Sessions[operationID]
	if !ok {
		return desktop.Record{}, fmt.Errorf("%w: operation %s", ErrNotFound, operationID)
	}
	updated, err := desktop.ObserveAllocation(current, observation)
	if err != nil {
		return desktop.Record{}, err
	}
	s.Sessions[operationID] = updated.Clone()
	return updated.Clone(), nil
}

func (s *State) UpdateOpenAt(record desktop.Record, expectedStatus desktop.Status, now time.Time) error {
	s.ensureMaps()
	if now.IsZero() {
		return fmt.Errorf("%w: current time", desktop.ErrInvalidRecord)
	}
	current, ok := s.Sessions[record.Request.OperationID]
	if !ok {
		return fmt.Errorf("%w: operation %s", ErrNotFound, record.Request.OperationID)
	}
	if current.Status != expectedStatus || !sameOpenRequest(current.Request, record.Request) || !current.AcceptedAt.Equal(record.AcceptedAt) || !reflect.DeepEqual(current.Allocation, record.Allocation) {
		return ErrConflict
	}
	if record.Status == desktop.StatusSucceeded && current.Allocation == nil {
		return desktop.ErrInvalidAllocation
	}
	if err := record.Validate(); err != nil {
		return err
	}
	if record.Status == current.Status {
		return ErrConflict
	}
	var evidence *desktop.EndpointEvidence
	if record.Handoff != nil {
		evidence = &desktop.EndpointEvidence{InternalEndpointReference: record.Handoff.InternalEndpointReference, ConnectionGeneration: record.Handoff.ConnectionGeneration}
	}
	updated, err := desktop.Transition(current, record.Status, record.ObservedAt, evidence)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(updated, record) {
		return ErrConflict
	}
	if record.Status == desktop.StatusSucceeded {
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

func (s *State) ReserveCloseAt(request desktop.CloseRequest, acceptedAt time.Time, expiration bool) (desktop.CloseReservation, error) {
	s.ensureMaps()
	acceptedAt = acceptedAt.UTC()
	if err := request.Validate(acceptedAt); err != nil {
		return desktop.CloseReservation{}, err
	}
	authority, err := s.GetSandboxAuthority(request.SandboxID)
	if err != nil {
		return desktop.CloseReservation{}, err
	}
	if err := checkCloseAuthority(authority, request); err != nil {
		return desktop.CloseReservation{}, err
	}
	scope := closeIdempotencyScope(request)
	if existing, ok := s.CloseIdempotency[scope]; ok {
		if existing.RequestDigest != request.RequestDigest || existing.OperationID != request.OperationID {
			return desktop.CloseReservation{}, ErrIdempotencyConflict
		}
		record, ok := s.Closes[existing.OperationID]
		if !ok || !sameCloseRequest(record.Request, request) || record.Expiration != expiration {
			return desktop.CloseReservation{}, ErrConflict
		}
		return desktop.CloseReservation{Record: record.Clone(), Replayed: true}, nil
	}
	if _, exists := s.Idempotency[scope]; exists {
		return desktop.CloseReservation{}, ErrIdempotencyConflict
	}
	if _, exists := s.Sessions[request.OperationID]; exists {
		return desktop.CloseReservation{}, ErrAlreadyExists
	}
	if _, exists := s.Closes[request.OperationID]; exists {
		return desktop.CloseReservation{}, ErrAlreadyExists
	}
	var source desktop.Record
	found := false
	for _, candidate := range s.Sessions {
		if candidate.Request.SandboxID == request.SandboxID && candidate.Request.DesktopSessionID == request.DesktopSessionID {
			if found {
				return desktop.CloseReservation{}, ErrConflict
			}
			source, found = candidate.Clone(), true
		}
	}
	if !found {
		return desktop.CloseReservation{}, fmt.Errorf("%w: desktop session %s", ErrNotFound, request.DesktopSessionID)
	}
	closeRecord, updatedSource, err := desktop.NewCloseRecord(request, source, acceptedAt, expiration)
	if err != nil {
		return desktop.CloseReservation{}, err
	}
	s.Sessions[source.Request.OperationID] = updatedSource
	s.Closes[request.OperationID] = closeRecord.Clone()
	s.CloseIdempotency[scope] = IdempotencyRecord{Scope: scope, Key: request.IdempotencyKey, RequestDigest: request.RequestDigest, OperationID: request.OperationID}
	return desktop.CloseReservation{Record: closeRecord.Clone()}, nil
}

func (s *State) GetClose(operationID string) (desktop.CloseRecord, error) {
	s.ensureMaps()
	record, ok := s.Closes[operationID]
	if !ok {
		return desktop.CloseRecord{}, fmt.Errorf("%w: close operation %s", ErrNotFound, operationID)
	}
	if err := record.Validate(); err != nil {
		return desktop.CloseRecord{}, fmt.Errorf("%w: persisted close operation: %v", ErrCorrupt, err)
	}
	return record.Clone(), nil
}

func (s *State) ListClose() []desktop.CloseRecord {
	s.ensureMaps()
	ids := make([]string, 0, len(s.Closes))
	for id := range s.Closes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]desktop.CloseRecord, 0, len(ids))
	for _, id := range ids {
		result = append(result, s.Closes[id].Clone())
	}
	return result
}

func (s *State) UpdateClose(record desktop.CloseRecord, expected desktop.Status, source desktop.Record) error {
	s.ensureMaps()
	current, ok := s.Closes[record.Request.OperationID]
	if !ok {
		return fmt.Errorf("%w: close operation %s", ErrNotFound, record.Request.OperationID)
	}
	currentSource, ok := s.Sessions[current.SourceOpenOperationID]
	if !ok || current.Status != expected || !sameCloseRequest(current.Request, record.Request) ||
		current.SourceOpenOperationID != record.SourceOpenOperationID || current.Receipt != record.Receipt ||
		!current.AcceptedAt.Equal(record.AcceptedAt) {
		return ErrConflict
	}
	updated, err := desktop.TransitionClose(current, record.Status, record.ObservedAt)
	if err != nil || updated != record {
		return ErrConflict
	}
	wantSource := currentSource.Clone()
	switch record.Status {
	case desktop.StatusOutcomeUnknown:
		wantSource, err = desktop.MarkCloseUnknown(currentSource, record.ObservedAt)
	case desktop.StatusSucceeded:
		wantSource, err = desktop.CompleteClose(currentSource, record.ObservedAt, record.Expiration)
	}
	if err != nil || !reflect.DeepEqual(wantSource, source) {
		return ErrConflict
	}
	s.Closes[record.Request.OperationID] = record.Clone()
	s.Sessions[current.SourceOpenOperationID] = source.Clone()
	return nil
}

// ResolveUnknownClose converges session lifecycle from observation while the
// outcome-unknown close operation itself remains immutable.
func (s *State) ResolveUnknownClose(operationID string, observedAt time.Time) (desktop.Record, error) {
	s.ensureMaps()
	closeRecord, ok := s.Closes[operationID]
	if !ok {
		return desktop.Record{}, fmt.Errorf("%w: close operation %s", ErrNotFound, operationID)
	}
	if closeRecord.Status != desktop.StatusOutcomeUnknown {
		return desktop.Record{}, ErrConflict
	}
	source, ok := s.Sessions[closeRecord.SourceOpenOperationID]
	if !ok {
		return desktop.Record{}, fmt.Errorf("%w: source operation", ErrCorrupt)
	}
	updated, err := desktop.CompleteClose(source, observedAt, closeRecord.Expiration)
	if err != nil {
		return desktop.Record{}, err
	}
	s.Sessions[closeRecord.SourceOpenOperationID] = updated.Clone()
	return updated, nil
}

func checkAuthority(authority desktop.SandboxAuthority, request desktop.OpenRequest, now time.Time) error {
	if err := authority.Validate(); err != nil {
		return fmt.Errorf("%w: authority: %v", ErrCorrupt, err)
	}
	if authority.ProviderRevisionID != request.ProviderRevisionID {
		return desktop.ErrProviderRevisionConflict
	}
	if !authority.Ready {
		return desktop.ErrSandboxNotReady
	}
	if authority.Generation != request.ExpectedGeneration {
		return desktop.ErrGenerationConflict
	}
	if !authority.LeaseExpiresAt.After(now) || request.ExpiresAt.After(authority.LeaseExpiresAt) {
		return desktop.ErrLeaseExpired
	}
	if authority.FencingToken != request.FencingToken {
		return desktop.ErrStaleFencingToken
	}
	if authority.CapabilityProfileID != request.CapabilityProfileID {
		return desktop.ErrCapabilityUnsupported
	}
	return nil
}

func checkCloseAuthority(authority desktop.SandboxAuthority, request desktop.CloseRequest) error {
	if err := authority.Validate(); err != nil {
		return fmt.Errorf("%w: authority: %v", ErrCorrupt, err)
	}
	if authority.ProviderRevisionID != request.ProviderRevisionID {
		return desktop.ErrProviderRevisionConflict
	}
	if authority.Generation != request.ExpectedGeneration {
		return desktop.ErrGenerationConflict
	}
	if authority.FencingToken != request.FencingToken {
		return desktop.ErrStaleFencingToken
	}
	if authority.CapabilityProfileID != desktop.CapabilityProfileID {
		return desktop.ErrCapabilityUnsupported
	}
	return nil
}

func idempotencyScope(request desktop.OpenRequest) string {
	return request.SandboxID + "\x00" + request.ProviderRevisionID + "\x00" + request.IdempotencyKey
}

func closeIdempotencyScope(request desktop.CloseRequest) string {
	return request.SandboxID + "\x00" + request.ProviderRevisionID + "\x00" + request.IdempotencyKey
}

func sameCloseRequest(left, right desktop.CloseRequest) bool {
	return left.SandboxID == right.SandboxID && left.ProviderRevisionID == right.ProviderRevisionID &&
		left.OperationID == right.OperationID && left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken &&
		left.IdempotencyKey == right.IdempotencyKey && left.RequestDigest == right.RequestDigest && left.Deadline.Equal(right.Deadline) &&
		left.ExpectedGeneration == right.ExpectedGeneration && left.DesktopSessionID == right.DesktopSessionID &&
		left.ConnectionGeneration == right.ConnectionGeneration && left.Reason == right.Reason
}

func sameOpenRequest(left, right desktop.OpenRequest) bool {
	return left.SandboxID == right.SandboxID && left.ProviderRevisionID == right.ProviderRevisionID && left.OperationID == right.OperationID && left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken && left.IdempotencyKey == right.IdempotencyKey && left.RequestDigest == right.RequestDigest && left.Deadline.Equal(right.Deadline) && left.ExpectedGeneration == right.ExpectedGeneration && left.DesktopSessionID == right.DesktopSessionID && left.CapabilityProfileID == right.CapabilityProfileID && left.ExpiresAt.Equal(right.ExpiresAt)
}

func (s State) Export() PersistedState {
	result := PersistedState{Version: snapshotVersion}
	for _, record := range s.Sessions {
		result.Sessions = append(result.Sessions, record.Clone())
	}
	for _, record := range s.Closes {
		result.Closes = append(result.Closes, record.Clone())
	}
	for _, idempotency := range s.Idempotency {
		result.Idempotency = append(result.Idempotency, idempotency)
	}
	for _, idempotency := range s.CloseIdempotency {
		result.CloseIdempotency = append(result.CloseIdempotency, idempotency)
	}
	for _, authority := range s.Authorities {
		result.Authorities = append(result.Authorities, authority.Clone())
	}
	sort.Slice(result.Sessions, func(i, j int) bool {
		return result.Sessions[i].Request.OperationID < result.Sessions[j].Request.OperationID
	})
	sort.Slice(result.Closes, func(i, j int) bool {
		return result.Closes[i].Request.OperationID < result.Closes[j].Request.OperationID
	})
	sort.Slice(result.Idempotency, func(i, j int) bool { return result.Idempotency[i].Scope < result.Idempotency[j].Scope })
	sort.Slice(result.CloseIdempotency, func(i, j int) bool { return result.CloseIdempotency[i].Scope < result.CloseIdempotency[j].Scope })
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
			return fmt.Errorf("%w: duplicate authority", ErrCorrupt)
		}
		loaded.Authorities[authority.SandboxID] = authority.Clone()
	}
	for _, record := range snapshot.Sessions {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("%w: session: %v", ErrCorrupt, err)
		}
		if _, exists := loaded.Sessions[record.Request.OperationID]; exists {
			return fmt.Errorf("%w: duplicate operation", ErrCorrupt)
		}
		if record.Allocation != nil {
			for _, other := range loaded.Sessions {
				if other.Allocation != nil && other.Allocation.Receipt.Reference == record.Allocation.Receipt.Reference {
					return fmt.Errorf("%w: duplicate allocation reference", ErrCorrupt)
				}
			}
		}
		authority, exists := loaded.Authorities[record.Request.SandboxID]
		if !exists || authority.ProviderRevisionID != record.Request.ProviderRevisionID {
			return fmt.Errorf("%w: session references missing authority", ErrCorrupt)
		}
		loaded.Sessions[record.Request.OperationID] = record.Clone()
	}
	for _, record := range snapshot.Closes {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("%w: close: %v", ErrCorrupt, err)
		}
		if _, exists := loaded.Closes[record.Request.OperationID]; exists {
			return fmt.Errorf("%w: duplicate close operation", ErrCorrupt)
		}
		source, exists := loaded.Sessions[record.SourceOpenOperationID]
		if !exists || source.Request.SandboxID != record.Request.SandboxID || source.Request.DesktopSessionID != record.Request.DesktopSessionID ||
			source.RevokedAt == nil || source.Allocation == nil || source.Allocation.Receipt != record.Receipt {
			return fmt.Errorf("%w: close references invalid source", ErrCorrupt)
		}
		loaded.Closes[record.Request.OperationID] = record.Clone()
	}
	for _, idempotency := range snapshot.Idempotency {
		record, exists := loaded.Sessions[idempotency.OperationID]
		if !exists || idempotency.Scope != idempotencyScope(record.Request) || idempotency.Key != record.Request.IdempotencyKey || idempotency.RequestDigest != record.Request.RequestDigest {
			return fmt.Errorf("%w: invalid idempotency record", ErrCorrupt)
		}
		if _, exists := loaded.Idempotency[idempotency.Scope]; exists {
			return fmt.Errorf("%w: duplicate idempotency", ErrCorrupt)
		}
		loaded.Idempotency[idempotency.Scope] = idempotency
	}
	for _, idempotency := range snapshot.CloseIdempotency {
		record, exists := loaded.Closes[idempotency.OperationID]
		if !exists || idempotency.Scope != closeIdempotencyScope(record.Request) || idempotency.Key != record.Request.IdempotencyKey || idempotency.RequestDigest != record.Request.RequestDigest {
			return fmt.Errorf("%w: invalid close idempotency record", ErrCorrupt)
		}
		if _, exists := loaded.CloseIdempotency[idempotency.Scope]; exists {
			return fmt.Errorf("%w: duplicate close idempotency", ErrCorrupt)
		}
		if _, exists := loaded.Idempotency[idempotency.Scope]; exists {
			return fmt.Errorf("%w: cross-family idempotency", ErrCorrupt)
		}
		loaded.CloseIdempotency[idempotency.Scope] = idempotency
	}
	for _, record := range loaded.Sessions {
		if _, exists := loaded.Idempotency[idempotencyScope(record.Request)]; !exists {
			return fmt.Errorf("%w: session missing idempotency record", ErrCorrupt)
		}
	}
	for _, record := range loaded.Closes {
		if _, exists := loaded.CloseIdempotency[closeIdempotencyScope(record.Request)]; !exists {
			return fmt.Errorf("%w: close missing idempotency record", ErrCorrupt)
		}
	}
	*s = loaded
	return nil
}
