package codingidentity

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
)

const (
	// Kept equal to the Control receipt ledger's finite historical bound.
	MaxOriginalCreateEnvelopes = 4096
	MaxOriginalCreateBytes     = 4 << 10
)

type Status string

const (
	Reserved Status = "reserved"
	Creating Status = "creating"
	Active   Status = "active"
	Cleaning Status = "cleaning"
)

type Reservation struct {
	PlanDigest string `json:"plan_digest"`
	Slot       Slot   `json:"slot"`
	Claim      Claim  `json:"claim"`
	SpecDigest string `json:"spec_digest"`
	Status     Status `json:"status"`
}

func (r Reservation) sameIdentity(other Reservation) bool {
	return r.PlanDigest == other.PlanDigest && r.Slot == other.Slot &&
		r.Claim == other.Claim && r.SpecDigest == other.SpecDigest
}

// State is an offline model for a Provider-PG-owned reservation document.
// A zero value is uninitialized. The actual transactional repository and
// independent physical absence inspector are separate work, not implied by
// passing this model's tests.
type State struct {
	Version      int           `json:"version"`
	Initialized  bool          `json:"initialized"`
	PlanDigest   string        `json:"plan_digest"`
	Reservations []Reservation `json:"reservations"`
	// Only the private Provider-PG retirement transaction writes this map.
	// Nil/empty is omitted so existing initialized/Creating documents retain
	// their canonical bytes until a current cleanup is admitted.
	Retirements map[string]RetirementBinding `json:"retirements,omitempty"`
	// An immutable historical original-create envelope is keyed by allocation,
	// not slot. A released slot's old effect still needs read-only recovery.
	OriginalCreates map[string]OriginalCreateEnvelope `json:"original_creates,omitempty"`
}

type OriginalCreateEnvelope struct {
	Document string `json:"document"`
	Digest   string `json:"digest"`
}

func (e OriginalCreateEnvelope) Validate() error {
	if len(e.Document) == 0 || len(e.Document) > MaxOriginalCreateBytes ||
		!json.Valid([]byte(e.Document)) || !digest.MatchString(e.Digest) {
		return ErrInvalidState
	}
	return nil
}

// RetirementBinding is Provider-owned, not a Docker or caller capability.
// It ties one Cleaning slot to a current termination operation and the
// independently read Control Completed receipt snapshot used for admission.
type RetirementBinding struct {
	OriginalAllocationID      string `json:"original_allocation_id"`
	OriginalAuthorityDigest   string `json:"original_authority_digest"`
	OriginalGeneration        uint64 `json:"original_generation"`
	OriginalFence             uint64 `json:"original_fence"`
	OperationID               string `json:"operation_id"`
	AttemptID                 string `json:"attempt_id"`
	RequestDigest             string `json:"request_digest"`
	CurrentGeneration         uint64 `json:"current_generation"`
	CurrentFence              uint64 `json:"current_fence"`
	ControlReceiptRevision    uint64 `json:"control_receipt_revision"`
	ControlReceiptStateDigest string `json:"control_receipt_state_digest"`
	ControlCompletionDigest   string `json:"control_completion_digest"`
	ControlEvidenceDigest     string `json:"control_evidence_digest"`
	// Canonical private envelope retained exactly, including a parent-clamped
	// expiry. A readback is evidence of what committed, never a fresh permit.
	CleanupAuthorityDocument string `json:"cleanup_authority_document"`
	CleanupAuthorityDigest   string `json:"cleanup_authority_digest"`
}

func (b RetirementBinding) Validate(reservation Reservation) error {
	if reservation.Status != Cleaning || b.OriginalAllocationID != reservation.Claim.AllocationID ||
		!digest.MatchString(b.OriginalAuthorityDigest) ||
		b.OriginalGeneration != reservation.Claim.Generation ||
		b.OriginalFence != reservation.Claim.Fence ||
		!privateID.MatchString(b.OperationID) || b.OperationID == reservation.Claim.OperationID ||
		!privateID.MatchString(b.AttemptID) ||
		!digest.MatchString(b.RequestDigest) || b.CurrentGeneration <= b.OriginalGeneration ||
		b.CurrentFence < b.OriginalFence || b.ControlReceiptRevision == 0 ||
		!digest.MatchString(b.ControlReceiptStateDigest) ||
		!digest.MatchString(b.ControlCompletionDigest) ||
		!digest.MatchString(b.ControlEvidenceDigest) ||
		!digest.MatchString(b.CleanupAuthorityDigest) ||
		len(b.CleanupAuthorityDocument) == 0 || len(b.CleanupAuthorityDocument) > 4<<10 ||
		!json.Valid([]byte(b.CleanupAuthorityDocument)) {
		return ErrInvalidState
	}
	return nil
}

func NewState(plan Plan) (State, error) {
	planDigest, err := plan.Digest()
	if err != nil {
		return State{}, err
	}
	return State{Version: Version, Initialized: true, PlanDigest: planDigest, Reservations: []Reservation{}}, nil
}

func (s State) Validate(plan Plan) error {
	planDigest, err := plan.Digest()
	if err != nil || !s.Initialized || s.Version != Version || s.PlanDigest != planDigest ||
		s.Reservations == nil || len(s.Reservations) > plan.Capacity {
		return ErrInvalidState
	}
	byID := make(map[string]Slot, len(plan.Slots))
	for _, slot := range plan.Slots {
		byID[slot.ID] = slot
	}
	previous := ""
	sandboxes, allocations, operations := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, reservation := range s.Reservations {
		want, known := byID[reservation.Slot.ID]
		if !known || reservation.Slot != want || reservation.Slot.ID <= previous ||
			reservation.PlanDigest != planDigest || reservation.Claim.Validate() != nil ||
			!digest.MatchString(reservation.SpecDigest) || !validStatus(reservation.Status) ||
			sandboxes[reservation.Claim.SandboxID] || allocations[reservation.Claim.AllocationID] ||
			operations[reservation.Claim.OperationID] {
			return ErrInvalidState
		}
		sandboxes[reservation.Claim.SandboxID] = true
		allocations[reservation.Claim.AllocationID] = true
		operations[reservation.Claim.OperationID] = true
		previous = reservation.Slot.ID
	}
	if len(s.Retirements) > len(s.Reservations) {
		return ErrInvalidState
	}
	if len(s.OriginalCreates) > MaxOriginalCreateEnvelopes {
		return ErrInvalidState
	}
	for allocationKey, envelope := range s.OriginalCreates {
		if !allocationID.MatchString(allocationKey) || envelope.Validate() != nil {
			return ErrInvalidState
		}
	}
	for slotID, binding := range s.Retirements {
		found := false
		for _, reservation := range s.Reservations {
			if reservation.Slot.ID == slotID {
				found = binding.Validate(reservation) == nil
				break
			}
		}
		if !found {
			return ErrInvalidState
		}
	}
	return nil
}

func validStatus(status Status) bool {
	switch status {
	case Reserved, Creating, Active, Cleaning:
		return true
	default:
		return false
	}
}

func (s State) Clone() State {
	s.Reservations = slices.Clone(s.Reservations)
	s.Retirements = maps.Clone(s.Retirements)
	s.OriginalCreates = maps.Clone(s.OriginalCreates)
	return s
}

// Reserve is intended to run in one Provider PostgreSQL transaction. The
// required authorize callback must check the *existing* operation/allocation
// ledger in that same transaction, including terminal/replayed operation,
// tenant, generation, fence and request digest. This model never owns that
// business truth or dispatches physical work. After cleanup, the callback
// must refuse the old completed Claim; a mere syntactically valid Claim is
// not authority to reopen an allocation.
func (s *State) Reserve(plan Plan, claim Claim, specBySlot map[string]string, authorize func(Claim) error) (Reservation, error) {
	if s == nil || s.Validate(plan) != nil || claim.Validate() != nil ||
		len(specBySlot) != len(plan.Slots) || authorize == nil {
		return Reservation{}, ErrInvalidState
	}
	for _, slot := range plan.Slots {
		if !digest.MatchString(specBySlot[slot.ID]) {
			return Reservation{}, ErrInvalidPlan
		}
	}
	if err := authorize(claim); err != nil {
		return Reservation{}, ErrConflict
	}
	used := make(map[string]bool, len(s.Reservations))
	for _, current := range s.Reservations {
		used[current.Slot.ID] = true
		if current.Claim.SandboxID != claim.SandboxID && current.Claim.AllocationID != claim.AllocationID &&
			current.Claim.OperationID != claim.OperationID {
			continue
		}
		if current.Claim != claim || current.SpecDigest != specBySlot[current.Slot.ID] {
			return Reservation{}, ErrConflict
		}
		return current, nil
	}
	if len(s.Reservations) >= plan.Capacity {
		return Reservation{}, ErrExhausted
	}
	for _, slot := range plan.Slots {
		if used[slot.ID] {
			continue
		}
		reservation := Reservation{PlanDigest: s.PlanDigest, Slot: slot, Claim: claim,
			SpecDigest: specBySlot[slot.ID], Status: Reserved}
		s.Reservations = append(s.Reservations, reservation)
		slices.SortFunc(s.Reservations, func(a, b Reservation) int {
			if a.Slot.ID < b.Slot.ID {
				return -1
			}
			if a.Slot.ID > b.Slot.ID {
				return 1
			}
			return 0
		})
		return reservation, nil
	}
	return Reservation{}, ErrExhausted
}

// BeginCreate is the only modeled side-effect permit. An ambiguous create
// outcome remains Creating; expiry or cancellation does not free the slot.
func (s *State) BeginCreate(plan Plan, reservation Reservation) (Reservation, error) {
	return s.transition(plan, reservation, Reserved, Creating, false)
}

func (s *State) CompleteCreate(plan Plan, reservation Reservation) (Reservation, error) {
	return s.transition(plan, reservation, Creating, Active, false)
}

func (s *State) BeginCleanup(plan Plan, reservation Reservation) (Reservation, error) {
	if reservation.Status == Creating {
		return Reservation{}, ErrInProgress
	}
	return s.transition(plan, reservation, reservation.Status, Cleaning, true)
}

// AbsenceProof can only be obtained after an inspector callback succeeds.
// The production inspector must verify the exact container and three whole
// generation-scoped volumes. A test callback is only model evidence.
type AbsenceProof struct {
	reservation Reservation
	confirmed   bool
}

// ConfirmAbsence must run *outside* the Provider PostgreSQL row lock. It
// yields a ticket-bound proof for CompleteCleanup's later locked recheck.
func ConfirmAbsence(ctx context.Context, reservation Reservation,
	inspect func(context.Context, Reservation) error) (AbsenceProof, error) {
	if ctx == nil || ctx.Err() != nil || inspect == nil || reservation.Status != Cleaning ||
		!digest.MatchString(reservation.PlanDigest) || !digest.MatchString(reservation.SpecDigest) ||
		reservation.Slot.Validate() != nil || reservation.Claim.Validate() != nil {
		return AbsenceProof{}, ErrInvalidState
	}
	if err := inspect(ctx, reservation); err != nil {
		return AbsenceProof{}, err
	}
	if err := ctx.Err(); err != nil {
		return AbsenceProof{}, err
	}
	return AbsenceProof{reservation: reservation, confirmed: true}, nil
}

// CompleteCleanup performs no external I/O. A stale ticket/proof cannot
// release a slot reallocated or changed between absence check and row lock.
func (s *State) CompleteCleanup(plan Plan, reservation Reservation, proof AbsenceProof) error {
	if s == nil || s.Validate(plan) != nil || reservation.Status != Cleaning ||
		!proof.confirmed || proof.reservation != reservation {
		return ErrInvalidState
	}
	for index, current := range s.Reservations {
		if current.Slot.ID != reservation.Slot.ID {
			continue
		}
		if current != reservation {
			return ErrConflict
		}
		s.Reservations = slices.Delete(s.Reservations, index, index+1)
		delete(s.Retirements, reservation.Slot.ID)
		return nil
	}
	return ErrConflict
}

func (s *State) transition(plan Plan, reservation Reservation, from, to Status, idempotent bool) (Reservation, error) {
	if s == nil || s.Validate(plan) != nil || !validStatus(from) || !validStatus(to) {
		return Reservation{}, ErrInvalidState
	}
	for index, current := range s.Reservations {
		if current.Slot.ID != reservation.Slot.ID {
			continue
		}
		if !current.sameIdentity(reservation) {
			return Reservation{}, ErrConflict
		}
		if idempotent && current.Status == to {
			return current, nil
		}
		if current.Status != from || reservation.Status != from {
			if current.Status == Creating {
				return Reservation{}, ErrInProgress
			}
			return Reservation{}, ErrConflict
		}
		current.Status = to
		s.Reservations[index] = current
		return current, nil
	}
	return Reservation{}, ErrConflict
}
