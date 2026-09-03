package repository

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

const snapshotVersion = 2

type State struct {
	Sessions    map[string]browser.Record
	Idempotency map[string]IdempotencyRecord
	Authorities map[string]browser.SandboxAuthority
}

type IdempotencyRecord struct {
	Scope         string `json:"scope"`
	Key           string `json:"key"`
	RequestDigest string `json:"request_digest"`
	OperationID   string `json:"operation_id"`
}

type PersistedState struct {
	Version     int                        `json:"version"`
	Sessions    []browser.Record           `json:"sessions"`
	Idempotency []IdempotencyRecord        `json:"idempotency"`
	Authorities []browser.SandboxAuthority `json:"authorities"`
}

func NewState() State {
	return State{Sessions: make(map[string]browser.Record), Idempotency: make(map[string]IdempotencyRecord), Authorities: make(map[string]browser.SandboxAuthority)}
}

func (s *State) ensureMaps() {
	if s.Sessions == nil {
		s.Sessions = make(map[string]browser.Record)
	}
	if s.Idempotency == nil {
		s.Idempotency = make(map[string]IdempotencyRecord)
	}
	if s.Authorities == nil {
		s.Authorities = make(map[string]browser.SandboxAuthority)
	}
}

func (s *State) SynchronizeSandboxAuthority(authority browser.SandboxAuthority) error {
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
		return browser.ErrProviderRevisionConflict
	}
	if current.CapabilityProfileID != authority.CapabilityProfileID {
		return browser.ErrCapabilityUnsupported
	}
	if current.NetworkPolicyReference != authority.NetworkPolicyReference {
		return browser.ErrNetworkPolicyConflict
	}
	if authority.Generation < current.Generation {
		return browser.ErrGenerationConflict
	}
	if authority.FencingToken < current.FencingToken {
		return browser.ErrStaleFencingToken
	}
	s.Authorities[authority.SandboxID] = authority.Clone()
	return nil
}

func (s *State) GetSandboxAuthority(sandboxID string) (browser.SandboxAuthority, error) {
	s.ensureMaps()
	authority, ok := s.Authorities[sandboxID]
	if !ok {
		return browser.SandboxAuthority{}, fmt.Errorf("%w: sandbox authority %s", ErrNotFound, sandboxID)
	}
	return authority.Clone(), nil
}

func (s *State) ReserveOpenAt(request browser.OpenRequest, acceptedAt time.Time) (browser.Reservation, error) {
	s.ensureMaps()
	acceptedAt = acceptedAt.UTC()
	if acceptedAt.IsZero() {
		return browser.Reservation{}, fmt.Errorf("%w: acceptance time", browser.ErrInvalidRequest)
	}
	if err := request.Validate(acceptedAt); err != nil {
		return browser.Reservation{}, err
	}
	authority, err := s.GetSandboxAuthority(request.SandboxID)
	if err != nil {
		return browser.Reservation{}, err
	}
	if err := checkAuthority(authority, request, acceptedAt); err != nil {
		return browser.Reservation{}, err
	}
	scope := idempotencyScope(request)
	if existing, ok := s.Idempotency[scope]; ok {
		if existing.RequestDigest != request.RequestDigest {
			return browser.Reservation{}, ErrIdempotencyConflict
		}
		record, ok := s.Sessions[existing.OperationID]
		if !ok {
			return browser.Reservation{}, fmt.Errorf("%w: idempotency references missing operation", ErrCorrupt)
		}
		if !sameOpenRequest(record.Request, request) {
			return browser.Reservation{}, ErrConflict
		}
		return browser.Reservation{Record: record.Clone(), Replayed: true}, nil
	}
	if _, exists := s.Sessions[request.OperationID]; exists {
		return browser.Reservation{}, ErrAlreadyExists
	}
	record, err := browser.NewRecord(request, acceptedAt)
	if err != nil {
		return browser.Reservation{}, err
	}
	s.Sessions[request.OperationID] = record.Clone()
	s.Idempotency[scope] = IdempotencyRecord{Scope: scope, Key: request.IdempotencyKey, RequestDigest: request.RequestDigest, OperationID: request.OperationID}
	return browser.Reservation{Record: record.Clone()}, nil
}

func (s *State) GetOpen(operationID string) (browser.Record, error) {
	return s.GetOpenAt(operationID, time.Now().UTC())
}

func (s *State) GetOpenAt(operationID string, now time.Time) (browser.Record, error) {
	s.ensureMaps()
	record, ok := s.Sessions[operationID]
	if !ok {
		return browser.Record{}, fmt.Errorf("%w: operation %s", ErrNotFound, operationID)
	}
	if err := record.Validate(); err != nil {
		return browser.Record{}, fmt.Errorf("%w: persisted operation: %v", ErrCorrupt, err)
	}
	if now.IsZero() {
		return browser.Record{}, fmt.Errorf("%w: current time", browser.ErrInvalidRecord)
	}
	if record.Status == browser.StatusSucceeded && !now.Before(record.Request.ExpiresAt) {
		return browser.Record{}, ErrExpired
	}
	return record.Clone(), nil
}

func (s *State) ListOpen() []browser.Record {
	s.ensureMaps()
	ids := make([]string, 0, len(s.Sessions))
	for id := range s.Sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]browser.Record, 0, len(ids))
	for _, id := range ids {
		result = append(result, s.Sessions[id].Clone())
	}
	return result
}

func (s *State) AttachAllocation(receipt browser.AllocationReceipt) (browser.Reservation, error) {
	s.ensureMaps()
	if err := receipt.Validate(); err != nil {
		return browser.Reservation{}, err
	}
	current, ok := s.Sessions[receipt.OperationID]
	if !ok {
		return browser.Reservation{}, fmt.Errorf("%w: operation %s", ErrNotFound, receipt.OperationID)
	}
	for id, record := range s.Sessions {
		if id != receipt.OperationID && record.Allocation != nil && record.Allocation.Receipt.Reference == receipt.Reference {
			return browser.Reservation{}, browser.ErrAllocationConflict
		}
	}
	if current.Allocation == nil {
		authority, err := s.GetSandboxAuthority(current.Request.SandboxID)
		if err != nil {
			return browser.Reservation{}, err
		}
		if err := checkAuthority(authority, current.Request, receipt.AllocatedAt); err != nil {
			return browser.Reservation{}, err
		}
	}
	updated, err := browser.AttachAllocation(current, receipt)
	if err != nil {
		return browser.Reservation{}, err
	}
	replayed := current.Allocation != nil
	s.Sessions[receipt.OperationID] = updated.Clone()
	return browser.Reservation{Record: updated.Clone(), Replayed: replayed}, nil
}

func (s *State) ObserveAllocation(operationID string, observation browser.AllocationEvidence) (browser.Record, error) {
	s.ensureMaps()
	current, ok := s.Sessions[operationID]
	if !ok {
		return browser.Record{}, fmt.Errorf("%w: operation %s", ErrNotFound, operationID)
	}
	updated, err := browser.ObserveAllocation(current, observation)
	if err != nil {
		return browser.Record{}, err
	}
	s.Sessions[operationID] = updated.Clone()
	return updated.Clone(), nil
}

func (s *State) UpdateOpenAt(record browser.Record, expectedStatus browser.Status, now time.Time) error {
	s.ensureMaps()
	if now.IsZero() {
		return fmt.Errorf("%w: current time", browser.ErrInvalidRecord)
	}
	current, ok := s.Sessions[record.Request.OperationID]
	if !ok {
		return fmt.Errorf("%w: operation %s", ErrNotFound, record.Request.OperationID)
	}
	if record.Status == browser.StatusRunning && current.Status != browser.StatusRunning {
		return browser.ErrInvalidAllocation
	}
	if current.Status != expectedStatus || !sameOpenRequest(current.Request, record.Request) || !current.AcceptedAt.Equal(record.AcceptedAt) || !reflect.DeepEqual(current.Allocation, record.Allocation) {
		return ErrConflict
	}
	if record.Status == browser.StatusSucceeded && current.Allocation == nil {
		return browser.ErrInvalidAllocation
	}
	if err := record.Validate(); err != nil {
		return err
	}
	if record.Status == current.Status {
		cancelled, err := browser.RequestCancellation(current, record.ObservedAt)
		if err != nil || !reflect.DeepEqual(cancelled, record) {
			return ErrConflict
		}
		s.Sessions[record.Request.OperationID] = record.Clone()
		return nil
	}
	if current.CancelRequested != record.CancelRequested {
		return ErrConflict
	}
	var evidence *browser.EndpointEvidence
	if record.Handoff != nil {
		evidence = &browser.EndpointEvidence{InternalEndpointReference: record.Handoff.InternalEndpointReference, ConnectionGeneration: record.Handoff.ConnectionGeneration}
	}
	updated, err := browser.Transition(current, record.Status, record.ObservedAt, evidence)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(updated, record) {
		return ErrConflict
	}
	if record.Status == browser.StatusSucceeded {
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

func checkAuthority(authority browser.SandboxAuthority, request browser.OpenRequest, now time.Time) error {
	if err := authority.Validate(); err != nil {
		return fmt.Errorf("%w: authority: %v", ErrCorrupt, err)
	}
	if authority.ProviderRevisionID != request.ProviderRevisionID {
		return browser.ErrProviderRevisionConflict
	}
	if !authority.Ready {
		return browser.ErrSandboxNotReady
	}
	if authority.Generation != request.ExpectedGeneration {
		return browser.ErrGenerationConflict
	}
	if !authority.LeaseExpiresAt.After(now) || request.ExpiresAt.After(authority.LeaseExpiresAt) {
		return browser.ErrLeaseExpired
	}
	if authority.FencingToken != request.FencingToken {
		return browser.ErrStaleFencingToken
	}
	if authority.CapabilityProfileID != request.CapabilityProfileID {
		return browser.ErrCapabilityUnsupported
	}
	return nil
}

func idempotencyScope(request browser.OpenRequest) string {
	return request.SandboxID + "\x00" + request.ProviderRevisionID + "\x00" + request.IdempotencyKey
}

func sameOpenRequest(left, right browser.OpenRequest) bool {
	return left.SandboxID == right.SandboxID && left.ProviderRevisionID == right.ProviderRevisionID && left.OperationID == right.OperationID && left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken && left.IdempotencyKey == right.IdempotencyKey && left.RequestDigest == right.RequestDigest && left.Deadline.Equal(right.Deadline) && left.ExpectedGeneration == right.ExpectedGeneration && left.BrowserSessionID == right.BrowserSessionID && left.CapabilityProfileID == right.CapabilityProfileID && left.ExpiresAt.Equal(right.ExpiresAt)
}

func (s State) Export() PersistedState {
	result := PersistedState{Version: snapshotVersion}
	for _, record := range s.Sessions {
		result.Sessions = append(result.Sessions, record.Clone())
	}
	for _, idempotency := range s.Idempotency {
		result.Idempotency = append(result.Idempotency, idempotency)
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
	for _, record := range loaded.Sessions {
		if _, exists := loaded.Idempotency[idempotencyScope(record.Request)]; !exists {
			return fmt.Errorf("%w: session missing idempotency record", ErrCorrupt)
		}
	}
	*s = loaded
	return nil
}
