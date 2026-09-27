package repository

import (
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

func connectionBinding(open browserhandoffv2.OpenRequest, expires time.Time) reference.Binding {
	return reference.Binding{Version: 2, Reference: open.HandoffReference,
		TenantBindingDigest: open.TenantBindingDigest, SandboxID: open.SandboxID,
		BrowserSessionID: open.BrowserSessionID, CapabilityProfileID: open.CapabilityProfileID,
		ConnectionGeneration: open.ConnectionGeneration, ExpiresAt: expires}
}

// BindConnection is the Provider-local atomic projection of an ingress-
// authorized private v2 open. Retained older claims never create a second
// active writer. A duplicate exact metadata registration is harmless, but
// only one later executor attempt can be reserved and consumed.
func (s *State) BindConnection(open browserhandoffv2.OpenRequest, source browser.Record,
	authority browser.SandboxAuthority, now time.Time) error {
	_, err := s.BindConnectionWithOwnership(open, source, authority, now)
	return err
}

// BindConnectionWithOwnership returns true only when this transaction created
// the claim. A duplicate identical registration is idempotent but must never
// tear down the stream owned by the first caller during its own error path.
func (s *State) BindConnectionWithOwnership(open browserhandoffv2.OpenRequest, source browser.Record,
	authority browser.SandboxAuthority, now time.Time) (bool, error) {
	s.ensureMap()
	if open.Validate(now) != nil {
		return false, reference.ErrInvalidRecord
	}
	record, ok := s.References[open.HandoffReference]
	if !ok {
		return false, reference.ErrNotFound
	}
	record = record.Clone()
	if open.ProviderRevisionID != record.ProviderRevisionID ||
		connectionBinding(open, record.ExpiresAt).Matches(record, source, authority, now) != nil ||
		open.HandoffExpiresAt != record.ExpiresAt.UTC().Format(time.RFC3339Nano) {
		return false, reference.ErrStale
	}
	claim, err := reference.ConnectionFromOpen(open, now)
	if err != nil {
		return false, err
	}
	if existing, found := record.ConnectionClaims[open.ConnectionEpoch]; found {
		if samePrivateClaim(existing, claim) {
			return false, nil
		}
		return false, reference.ErrConflict
	}
	for epoch, previous := range record.ConnectionClaims {
		if previous.Status == reference.ConnectionClosed {
			continue
		}
		if previous.AuthorityExpiresAt.After(now) {
			return false, reference.ErrConflict
		}
		previous.Status = reference.ConnectionClosed
		record.ConnectionClaims[epoch] = previous
	}
	if len(record.ConnectionClaims) >= reference.MaxConnectionClaims {
		return false, reference.ErrUnavailable
	}
	if record.ConnectionClaims == nil {
		record.ConnectionClaims = make(map[string]reference.ConnectionClaim)
	}
	if record.TenantBindingDigest == "" {
		record.TenantBindingDigest = open.TenantBindingDigest
	}
	record.ConnectionClaims[open.ConnectionEpoch] = claim
	if err := record.Validate(); err != nil {
		return false, err
	}
	s.References[open.HandoffReference] = record.Clone()
	return true, nil
}

func samePrivateClaim(left, right reference.ConnectionClaim) bool {
	return left.PrivateRequestID == right.PrivateRequestID &&
		left.PrivateRequestDigest == right.PrivateRequestDigest &&
		left.AuthorityDigest == right.AuthorityDigest &&
		left.ControlLeaseDigest == right.ControlLeaseDigest &&
		left.ControlFence == right.ControlFence &&
		left.AuthorityExpiresAt.Equal(right.AuthorityExpiresAt)
}

func executorBinding(open executorprotocol.Open, expires time.Time) reference.Binding {
	return reference.Binding{Version: 2, Reference: open.HandoffReference,
		TenantBindingDigest: open.TenantBindingDigest, SandboxID: open.SandboxID,
		BrowserSessionID: open.RuntimeSessionID, CapabilityProfileID: open.CapabilityProfileID,
		ConnectionGeneration: open.ConnectionGeneration, ExpiresAt: expires}
}

// ReserveExecutor fixes the one allowed downstream attempt before the
// Provider sends its authority to the executor. An uncertain send consumes
// the reservation; a fresh request ID cannot revive this connection.
func (s *State) ReserveExecutor(open executorprotocol.Open, source browser.Record,
	authority browser.SandboxAuthority, now time.Time) error {
	s.ensureMap()
	record, ok := s.References[open.HandoffReference]
	if !ok {
		return reference.ErrNotFound
	}
	record = record.Clone()
	claim, ok := record.ConnectionClaims[open.ConnectionEpoch]
	if !ok || claim.Status != reference.ConnectionPending ||
		executorBinding(open, record.ExpiresAt).Matches(record, source, authority, now) != nil ||
		claim.MatchesExecutor(record, open.ConnectionEpoch, open, now) != nil {
		return reference.ErrStale
	}
	for _, existing := range record.ConnectionClaims {
		if existing.ExecutorAttempt.RequestID == open.RequestID {
			return reference.ErrConflict
		}
	}
	claim.Status = reference.ConnectionReserved
	claim.ExecutorAttempt = reference.ExecutorAttempt{RequestID: open.RequestID, RequestDigest: open.RequestDigest}
	record.ConnectionClaims[open.ConnectionEpoch] = claim
	if err := record.Validate(); err != nil {
		return err
	}
	s.References[record.Reference] = record.Clone()
	return nil
}

// ClaimExecutor consumes the exact pre-registered attempt before Docker
// attach. The global replay record is retained for the handoff lifetime.
func (s *State) ClaimExecutorV2(open executorprotocol.Open, source browser.Record,
	authority browser.SandboxAuthority, now time.Time) error {
	s.ensureMap()
	record, ok := s.References[open.HandoffReference]
	if !ok {
		return reference.ErrNotFound
	}
	record = record.Clone()
	claim, ok := record.ConnectionClaims[open.ConnectionEpoch]
	if !ok || claim.Status != reference.ConnectionReserved ||
		claim.ExecutorAttempt.RequestID != open.RequestID || claim.ExecutorAttempt.RequestDigest != open.RequestDigest ||
		executorBinding(open, record.ExpiresAt).Matches(record, source, authority, now) != nil ||
		claim.MatchesExecutor(record, open.ConnectionEpoch, open, now) != nil {
		return reference.ErrStale
	}
	if _, replayed := record.ExecutorReplayClaims[open.RequestID]; replayed ||
		len(record.ExecutorReplayClaims) >= reference.MaxExecutorReplayClaims {
		return reference.ErrConflict
	}
	if record.ExecutorReplayClaims == nil {
		record.ExecutorReplayClaims = make(map[string]reference.ExecutorReplayClaim)
	}
	claim.Status = reference.ConnectionConsumed
	claim.Consumed = true
	record.ConnectionClaims[open.ConnectionEpoch] = claim
	record.ExecutorReplayClaims[open.RequestID] = reference.ExecutorReplayClaim{
		RequestDigest: open.RequestDigest, ExpiresAt: claim.AuthorityExpiresAt}
	if err := record.Validate(); err != nil {
		return err
	}
	s.References[record.Reference] = record.Clone()
	return nil
}

// CloseConnection is monotonic: closing an old epoch cannot modify a later
// claim, and close/revocation cannot reset a consumed executor attempt.
func (s *State) CloseConnection(referenceValue, epoch, authorityDigest string) error {
	s.ensureMap()
	record, ok := s.References[referenceValue]
	if !ok {
		return reference.ErrNotFound
	}
	record = record.Clone()
	claim, ok := record.ConnectionClaims[epoch]
	if !ok || claim.AuthorityDigest != authorityDigest {
		return reference.ErrStale
	}
	if claim.Status == reference.ConnectionClosed {
		return nil
	}
	claim.Status = reference.ConnectionClosed
	record.ConnectionClaims[epoch] = claim
	if err := record.Validate(); err != nil {
		return err
	}
	s.References[referenceValue] = record.Clone()
	return nil
}
