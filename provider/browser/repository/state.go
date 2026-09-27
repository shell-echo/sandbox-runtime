package repository

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

const snapshotVersion = 2

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type State struct {
	Sessions    map[string]browser.Record
	Idempotency map[string]IdempotencyRecord
	Authorities map[string]browser.SandboxAuthority
	Retirements map[string]IdentityRetirement
}

// IdentityRetirement is kept in the existing Browser session authority after
// the finite UID reservation is released. Released is committed in the same
// Provider transaction as CompleteCleanup and can distinguish a lost commit
// response from a still-Cleaning reservation on restart.
type IdentityRetirement struct {
	Ticket   sandboxidentity.Reservation `json:"ticket"`
	Receipt  browser.AllocationReceipt   `json:"receipt"`
	Released bool                        `json:"released"`
	// NeverDispatched proves the reservation was still Reserved under the
	// Provider row lock. No BeginCreate permit (and thus no Docker dispatch)
	// could have raced its release.
	NeverDispatched bool `json:"never_dispatched,omitempty"`
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
	Retirements []IdentityRetirement       `json:"retirements,omitempty"`
}

func NewState() State {
	return State{Sessions: make(map[string]browser.Record), Idempotency: make(map[string]IdempotencyRecord), Authorities: make(map[string]browser.SandboxAuthority), Retirements: make(map[string]IdentityRetirement)}
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
	if s.Retirements == nil {
		s.Retirements = make(map[string]IdentityRetirement)
	}
}

// AuthorizeIdentityCreate checks the Browser execution authority before a
// slot reservation or first Docker side effect. A succeeded open operation is
// deliberately not treated as a retired live Browser session.
func (s *State) AuthorizeIdentityCreate(allocation browser.Allocation, now time.Time) error {
	record, err := s.identityRecord(allocation, now)
	if err != nil {
		return err
	}
	if record.Status != browser.StatusAccepted || record.CancelRequested || record.Allocation != nil ||
		!record.Request.Deadline.After(now) {
		return ErrConflict
	}
	return nil
}

// AuthorizeIdentityRecovery is read-only permission for the already-Active
// exact allocation. It cannot turn an absent slot into a new dispatch permit.
func (s *State) AuthorizeIdentityRecovery(allocation browser.Allocation, now time.Time) error {
	record, err := s.identityRecord(allocation, now)
	if err != nil {
		return err
	}
	if record.CancelRequested || (record.Status != browser.StatusAccepted &&
		record.Status != browser.StatusRunning && record.Status != browser.StatusSucceeded) {
		return ErrConflict
	}
	if record.Allocation != nil && (!record.Allocation.Receipt.Matches(allocation.Request) ||
		!record.Allocation.Receipt.AllocatedAt.Equal(allocation.AllocatedAt)) {
		return ErrConflict
	}
	return nil
}

func (s *State) identityRecord(allocation browser.Allocation, now time.Time) (browser.Record, error) {
	s.ensureMaps()
	if allocation.Validate() != nil || now.IsZero() || !allocation.Request.ExpiresAt.After(now) {
		return browser.Record{}, ErrConflict
	}
	request := allocation.Request
	record, ok := s.Sessions[request.OperationID]
	if !ok || record.Validate() != nil || s.Retirements[request.OperationID].Ticket.Claim.OperationID != "" ||
		record.Request.SandboxID != request.SandboxID || record.Request.BrowserSessionID != request.BrowserSessionID ||
		record.Request.OperationID != request.OperationID || record.Request.AttemptID != request.AttemptID ||
		record.Request.RequestDigest != request.RequestDigest || record.Request.ExpectedGeneration != request.ExpectedGeneration ||
		record.Request.FencingToken != request.FencingToken || !record.Request.ExpiresAt.Equal(request.ExpiresAt) ||
		!record.AcceptedAt.Equal(allocation.AllocatedAt) {
		return browser.Record{}, ErrConflict
	}
	authority, ok := s.Authorities[request.SandboxID]
	if !ok || authority.NetworkPolicyReference != request.NetworkPolicyReference ||
		checkAuthority(authority, record.Request, now) != nil {
		return browser.Record{}, ErrConflict
	}
	return record, nil
}

// RetireIdentity is monotonic and remains in the existing Browser session
// document after the UID slot is released. It binds the full old claim, not
// just sandbox/generation, so another legitimate session is not prohibited.
func (s *State) RetireIdentity(ticket sandboxidentity.Reservation, receipt browser.AllocationReceipt) error {
	s.ensureMaps()
	claim := ticket.Claim
	record, ok := s.Sessions[claim.OperationID]
	if ticket.Status != sandboxidentity.Cleaning || ticket.Slot.Validate() != nil ||
		!digestPattern.MatchString(ticket.PlanDigest) || !digestPattern.MatchString(ticket.SpecDigest) ||
		claim.Validate() != nil || receipt.Validate() != nil || !ok || record.Validate() != nil ||
		!claimMatchesRecord(claim, record) || receipt.SandboxID != claim.SandboxID ||
		receipt.BrowserSessionID != claim.SessionID || receipt.OperationID != claim.OperationID ||
		receipt.AttemptID != claim.AttemptID || receipt.FencingToken != claim.Fence ||
		receipt.ExpectedGeneration != claim.Generation || !receipt.AllocatedAt.Equal(record.AcceptedAt) ||
		!receipt.ExpiresAt.Equal(record.Request.ExpiresAt) ||
		(record.Allocation != nil && record.Allocation.Receipt != receipt) {
		return ErrConflict
	}
	if old, exists := s.Retirements[claim.OperationID]; exists {
		if old.Ticket != ticket || old.Receipt != receipt {
			return ErrConflict
		}
		return nil
	}
	s.Retirements[claim.OperationID] = IdentityRetirement{Ticket: ticket, Receipt: receipt}
	return nil
}

func (s *State) IdentityRetired(ticket sandboxidentity.Reservation) bool {
	s.ensureMaps()
	retirement, ok := s.Retirements[ticket.Claim.OperationID]
	return ok && !retirement.NeverDispatched && retirement.Ticket == ticket
}

// RetireIdentityNeverDispatched records an exact terminal session in the
// existing Browser authority. Its caller must atomically prove that the slot
// was Reserved, before the unique BeginCreate side-effect permit.
func (s *State) RetireIdentityNeverDispatched(ticket sandboxidentity.Reservation) error {
	s.ensureMaps()
	claim := ticket.Claim
	record, ok := s.Sessions[claim.OperationID]
	if ticket.Status != sandboxidentity.Cleaning || ticket.Slot.Validate() != nil ||
		!digestPattern.MatchString(ticket.PlanDigest) || !digestPattern.MatchString(ticket.SpecDigest) ||
		claim.Validate() != nil || !ok || record.Validate() != nil || !claimMatchesRecord(claim, record) ||
		record.Allocation != nil || !unallocatedTerminal(record.Status) {
		return ErrConflict
	}
	if old, exists := s.Retirements[claim.OperationID]; exists {
		if old.Ticket != ticket || !old.NeverDispatched || !old.Released {
			return ErrConflict
		}
		return nil
	}
	s.Retirements[claim.OperationID] = IdentityRetirement{Ticket: ticket, Released: true, NeverDispatched: true}
	return nil
}

func unallocatedTerminal(status browser.Status) bool {
	return status == browser.StatusFailed || status == browser.StatusCancelled ||
		status == browser.StatusOutcomeUnknown
}

func (s *State) ReleaseIdentity(ticket sandboxidentity.Reservation) error {
	s.ensureMaps()
	retirement, ok := s.Retirements[ticket.Claim.OperationID]
	if !ok || retirement.NeverDispatched || retirement.Ticket != ticket || retirement.Released {
		return ErrConflict
	}
	retirement.Released = true
	s.Retirements[ticket.Claim.OperationID] = retirement
	return nil
}

func (s *State) CompletedIdentityRetirement(receipt browser.AllocationReceipt) (sandboxidentity.Reservation, error) {
	s.ensureMaps()
	if receipt.Validate() != nil {
		return sandboxidentity.Reservation{}, ErrConflict
	}
	retirement, ok := s.Retirements[receipt.OperationID]
	if !ok || retirement.NeverDispatched || !retirement.Released || retirement.Receipt != receipt {
		return sandboxidentity.Reservation{}, ErrConflict
	}
	return retirement.Ticket, nil
}

// CompletedTerminalIdentityRetirement is the existing Browser authority's
// proof for a terminal session whose allocation receipt was never attached.
// It permits exact local finalization after a lost cleanup commit response,
// including after the local tombstone has already been removed.
func (s *State) CompletedTerminalIdentityRetirement(record browser.Record) (
	sandboxidentity.Reservation, browser.AllocationReceipt, error) {
	s.ensureMaps()
	stored, ok := s.Sessions[record.Request.OperationID]
	if record.Validate() != nil || record.Allocation != nil || !unallocatedTerminal(record.Status) ||
		!ok || stored.Validate() != nil ||
		stored.Allocation != nil || !unallocatedTerminal(stored.Status) || stored.Status != record.Status ||
		!sameOpenRequest(stored.Request, record.Request) || !stored.AcceptedAt.Equal(record.AcceptedAt) {
		return sandboxidentity.Reservation{}, browser.AllocationReceipt{}, ErrConflict
	}
	retirement, ok := s.Retirements[record.Request.OperationID]
	if !ok || retirement.NeverDispatched || !retirement.Released ||
		!claimMatchesRecord(retirement.Ticket.Claim, stored) ||
		retirement.Ticket.Status != sandboxidentity.Cleaning || retirement.Receipt.Validate() != nil ||
		retirement.Receipt.OperationID != record.Request.OperationID ||
		!retirement.Receipt.AllocatedAt.Equal(stored.AcceptedAt) {
		return sandboxidentity.Reservation{}, browser.AllocationReceipt{}, ErrConflict
	}
	return retirement.Ticket, retirement.Receipt, nil
}

func claimMatchesRecord(claim sandboxidentity.Claim, record browser.Record) bool {
	request := record.Request
	return claim.SandboxID == request.SandboxID && claim.SessionID == request.BrowserSessionID &&
		claim.OperationID == request.OperationID && claim.AttemptID == request.AttemptID &&
		claim.RequestDigest == request.RequestDigest && claim.Generation == request.ExpectedGeneration &&
		claim.Fence == request.FencingToken
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
	for _, retirement := range s.Retirements {
		result.Retirements = append(result.Retirements, retirement)
	}
	sort.Slice(result.Sessions, func(i, j int) bool {
		return result.Sessions[i].Request.OperationID < result.Sessions[j].Request.OperationID
	})
	sort.Slice(result.Idempotency, func(i, j int) bool { return result.Idempotency[i].Scope < result.Idempotency[j].Scope })
	sort.Slice(result.Authorities, func(i, j int) bool { return result.Authorities[i].SandboxID < result.Authorities[j].SandboxID })
	sort.Slice(result.Retirements, func(i, j int) bool {
		return result.Retirements[i].Ticket.Claim.OperationID < result.Retirements[j].Ticket.Claim.OperationID
	})
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
	for _, retirement := range snapshot.Retirements {
		claim := retirement.Ticket.Claim
		record, ok := loaded.Sessions[claim.OperationID]
		if !ok || retirement.Ticket.Status != sandboxidentity.Cleaning ||
			retirement.Ticket.Slot.Validate() != nil ||
			!digestPattern.MatchString(retirement.Ticket.PlanDigest) ||
			!digestPattern.MatchString(retirement.Ticket.SpecDigest) ||
			claim.Validate() != nil || !claimMatchesRecord(claim, record) {
			return fmt.Errorf("%w: invalid retirement", ErrCorrupt)
		}
		if retirement.NeverDispatched {
			if !retirement.Released || retirement.Receipt != (browser.AllocationReceipt{}) ||
				record.Allocation != nil || !unallocatedTerminal(record.Status) {
				return fmt.Errorf("%w: invalid never-dispatched retirement", ErrCorrupt)
			}
		} else if retirement.Receipt.Validate() != nil || retirement.Receipt.SandboxID != claim.SandboxID ||
			retirement.Receipt.BrowserSessionID != claim.SessionID || retirement.Receipt.OperationID != claim.OperationID ||
			retirement.Receipt.AttemptID != claim.AttemptID || retirement.Receipt.FencingToken != claim.Fence ||
			retirement.Receipt.ExpectedGeneration != claim.Generation ||
			!retirement.Receipt.AllocatedAt.Equal(record.AcceptedAt) ||
			!retirement.Receipt.ExpiresAt.Equal(record.Request.ExpiresAt) ||
			(record.Allocation != nil && record.Allocation.Receipt != retirement.Receipt) {
			return fmt.Errorf("%w: invalid retirement", ErrCorrupt)
		}
		if _, exists := loaded.Retirements[claim.OperationID]; exists {
			return fmt.Errorf("%w: duplicate retirement", ErrCorrupt)
		}
		loaded.Retirements[claim.OperationID] = retirement
	}
	*s = loaded
	return nil
}
