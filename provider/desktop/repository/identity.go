package repository

import (
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

var identityDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// IdentityRetirement stays in the existing Desktop session authority. Close
// retires the original Open allocation claim, never a second UID claim.
type IdentityRetirement struct {
	Ticket          sandboxidentity.Reservation `json:"ticket"`
	Receipt         desktop.AllocationReceipt   `json:"receipt"`
	Released        bool                        `json:"released"`
	NeverDispatched bool                        `json:"never_dispatched,omitempty"`
}

func desktopClaimMatchesRecord(claim sandboxidentity.Claim, record desktop.Record) bool {
	request := record.Request
	return claim.SandboxID == request.SandboxID && claim.SessionID == request.DesktopSessionID &&
		claim.OperationID == request.OperationID && claim.AttemptID == request.AttemptID &&
		claim.RequestDigest == request.RequestDigest && claim.Generation == request.ExpectedGeneration &&
		claim.Fence == request.FencingToken
}

func desktopReceiptMatchesRecord(receipt desktop.AllocationReceipt, record desktop.Record) bool {
	request := record.Request
	return receipt.Validate() == nil && receipt.SandboxID == request.SandboxID &&
		receipt.DesktopSessionID == request.DesktopSessionID && receipt.OperationID == request.OperationID &&
		receipt.AttemptID == request.AttemptID && receipt.ExpectedGeneration == request.ExpectedGeneration &&
		receipt.FencingToken == request.FencingToken && !receipt.AllocatedAt.Before(record.AcceptedAt) &&
		receipt.ExpiresAt.Equal(request.ExpiresAt) &&
		(record.Allocation == nil || record.Allocation.Receipt == receipt)
}

func (s *State) identityRecord(allocation desktop.Allocation, now time.Time) (desktop.Record, error) {
	s.ensureMaps()
	if allocation.Validate() != nil || now.IsZero() || !allocation.Request.ExpiresAt.After(now) {
		return desktop.Record{}, ErrConflict
	}
	request := allocation.Request
	record, ok := s.Sessions[request.OperationID]
	if !ok || record.Validate() != nil || s.Retirements[request.OperationID].Ticket.Claim.OperationID != "" ||
		!desktopClaimMatchesRecord(sandboxidentity.Claim{SandboxID: request.SandboxID,
			SessionID: request.DesktopSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
			RequestDigest: request.RequestDigest, Generation: request.ExpectedGeneration,
			Fence: request.FencingToken}, record) || !record.AcceptedAt.Equal(allocation.AllocatedAt) {
		return desktop.Record{}, ErrConflict
	}
	authority, ok := s.Authorities[request.SandboxID]
	if !ok || authority.NetworkPolicyReference != request.NetworkPolicyReference ||
		checkAuthority(authority, record.Request, now) != nil {
		return desktop.Record{}, ErrConflict
	}
	return record, nil
}

// AuthorizeIdentityCreate runs before Reserve or BeginCreate. Desktop's Open
// application has already transitioned Accepted to Running by this point.
func (s *State) AuthorizeIdentityCreate(allocation desktop.Allocation, now time.Time) error {
	record, err := s.identityRecord(allocation, now)
	if err != nil || (record.Status != desktop.StatusRunning && record.Status != desktop.StatusOutcomeUnknown) || record.Allocation != nil ||
		record.RevokedAt != nil || record.ClosedAt != nil || record.Expired || record.CloseUnknown ||
		!record.Request.Deadline.After(now) {
		return ErrConflict
	}
	return nil
}

// Active recovery is inspection only; a succeeded Open is still live until
// its original allocation is revoked/closed and exactly retired.
func (s *State) AuthorizeIdentityRecovery(allocation desktop.Allocation, now time.Time) error {
	record, err := s.identityRecord(allocation, now)
	if err != nil || (record.Status != desktop.StatusRunning && record.Status != desktop.StatusSucceeded &&
		record.Status != desktop.StatusOutcomeUnknown) ||
		record.RevokedAt != nil || record.ClosedAt != nil || record.Expired || record.CloseUnknown ||
		(record.Allocation != nil && !desktopReceiptMatchesRecord(record.Allocation.Receipt, record)) {
		return ErrConflict
	}
	return nil
}

func (s *State) validateIdentityRetirement(retirement IdentityRetirement) error {
	s.ensureMaps()
	ticket := retirement.Ticket
	claim := ticket.Claim
	record, ok := s.Sessions[claim.OperationID]
	if !ok || record.Validate() != nil || ticket.Status != sandboxidentity.Cleaning ||
		ticket.Slot.Validate() != nil || !identityDigestPattern.MatchString(ticket.PlanDigest) ||
		!identityDigestPattern.MatchString(ticket.SpecDigest) || claim.Validate() != nil ||
		!desktopClaimMatchesRecord(claim, record) {
		return ErrConflict
	}
	if retirement.NeverDispatched {
		if !retirement.Released || retirement.Receipt != (desktop.AllocationReceipt{}) ||
			record.Allocation != nil ||
			(record.Status != desktop.StatusFailed && record.Status != desktop.StatusCancelled) {
			return ErrConflict
		}
		return nil
	}
	if !desktopReceiptMatchesRecord(retirement.Receipt, record) ||
		(record.Status == desktop.StatusSucceeded && record.RevokedAt == nil) {
		return ErrConflict
	}
	return nil
}

func (s *State) RetireIdentity(ticket sandboxidentity.Reservation, receipt desktop.AllocationReceipt) error {
	s.ensureMaps()
	retirement := IdentityRetirement{Ticket: ticket, Receipt: receipt}
	if err := s.validateIdentityRetirement(retirement); err != nil {
		return err
	}
	if old, exists := s.Retirements[ticket.Claim.OperationID]; exists {
		if old.Ticket != ticket || old.Receipt != receipt || old.NeverDispatched {
			return ErrConflict
		}
		return nil
	}
	s.Retirements[ticket.Claim.OperationID] = retirement
	return nil
}

func (s *State) RetireIdentityNeverDispatched(ticket sandboxidentity.Reservation) error {
	s.ensureMaps()
	retirement := IdentityRetirement{Ticket: ticket, Released: true, NeverDispatched: true}
	if err := s.validateIdentityRetirement(retirement); err != nil {
		return err
	}
	if old, exists := s.Retirements[ticket.Claim.OperationID]; exists {
		if old != retirement {
			return ErrConflict
		}
		return nil
	}
	s.Retirements[ticket.Claim.OperationID] = retirement
	return nil
}

func (s *State) IdentityRetired(ticket sandboxidentity.Reservation) bool {
	s.ensureMaps()
	retirement, ok := s.Retirements[ticket.Claim.OperationID]
	return ok && !retirement.NeverDispatched && retirement.Ticket == ticket
}

func (s *State) ReleaseIdentity(ticket sandboxidentity.Reservation) error {
	s.ensureMaps()
	retirement, ok := s.Retirements[ticket.Claim.OperationID]
	if !ok || retirement.NeverDispatched || retirement.Released || retirement.Ticket != ticket {
		return ErrConflict
	}
	retirement.Released = true
	s.Retirements[ticket.Claim.OperationID] = retirement
	return nil
}

func (s *State) CompletedIdentityRetirement(receipt desktop.AllocationReceipt) (sandboxidentity.Reservation, error) {
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
