package sandboxidentity

import (
	"slices"
)

// State is one owner's durable pool document. A zero value is deliberately
// uninitialized: loss of the document after first use cannot turn into an
// empty pool. Only an explicitly checked bootstrap may call NewState.
type State struct {
	Version      int           `json:"version"`
	Initialized  bool          `json:"initialized"`
	PlanDigest   string        `json:"plan_digest"`
	Reservations []Reservation `json:"reservations"`
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
	if err != nil {
		return err
	}
	if !s.Initialized || s.Version == 0 {
		return ErrUninitialized
	}
	if s.Version != Version || s.PlanDigest != planDigest || s.Reservations == nil ||
		len(s.Reservations) > len(plan.Slots) {
		return ErrInvalidState
	}
	byID := make(map[string]Slot, len(plan.Slots))
	for _, slot := range plan.Slots {
		byID[slot.ID] = slot
	}
	previous := ""
	seenSandboxes := make(map[string]struct{}, len(s.Reservations))
	for _, reservation := range s.Reservations {
		want, known := byID[reservation.Slot.ID]
		if !known || reservation.Slot != want || reservation.Slot.ID <= previous ||
			reservation.PlanDigest != planDigest || reservation.Claim.Validate() != nil ||
			!digest.MatchString(reservation.SpecDigest) || !validStatus(reservation.Status) {
			return ErrInvalidState
		}
		if _, exists := seenSandboxes[reservation.Claim.SandboxID]; exists {
			return ErrInvalidState
		}
		seenSandboxes[reservation.Claim.SandboxID] = struct{}{}
		previous = reservation.Slot.ID
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
	return s
}

// Reserve is called inside one Provider-owned PostgreSQL transaction. The
// selected slot is persisted before any Docker/network side effect. Exact
// retries receive the existing status; a new session in the same sandbox is
// excluded until complete cleanup of the previous allocation.
func (s *State) Reserve(plan Plan, claim Claim, specBySlot map[string]string) (Reservation, error) {
	if s == nil || s.Validate(plan) != nil || claim.Validate() != nil || len(specBySlot) != len(plan.Slots) {
		return Reservation{}, ErrInvalidState
	}
	for _, slot := range plan.Slots {
		if !digest.MatchString(specBySlot[slot.ID]) {
			return Reservation{}, ErrInvalidPlan
		}
	}
	used := make(map[string]struct{}, len(s.Reservations))
	for _, current := range s.Reservations {
		used[current.Slot.ID] = struct{}{}
		if current.Claim.SandboxID != claim.SandboxID {
			continue
		}
		if current.Claim != claim || specBySlot[current.Slot.ID] != current.SpecDigest {
			return Reservation{}, ErrConflict
		}
		return current, nil
	}
	if len(s.Reservations) >= plan.Capacity {
		return Reservation{}, ErrExhausted
	}
	for _, slot := range plan.Slots {
		if _, occupied := used[slot.ID]; occupied {
			continue
		}
		result := Reservation{PlanDigest: s.PlanDigest, Slot: slot, Claim: claim,
			SpecDigest: specBySlot[slot.ID], Status: Reserved}
		s.Reservations = append(s.Reservations, result)
		slices.SortFunc(s.Reservations, func(a, b Reservation) int {
			if a.Slot.ID < b.Slot.ID {
				return -1
			}
			if a.Slot.ID > b.Slot.ID {
				return 1
			}
			return 0
		})
		return result, nil
	}
	return Reservation{}, ErrExhausted
}

// BeginCreate is the only side-effect permit. It atomically excludes cleanup
// and another create; unknown create outcomes remain Creating indefinitely
// until independently reconciled, never freed by a time-based expiry.
func (s *State) BeginCreate(plan Plan, reservation Reservation) (Reservation, error) {
	return s.transition(plan, reservation, Reserved, Creating, false)
}

// CompleteCreate is legal only after a returned create and exact owned
// resource inspection. It does not imply that media or egress is ready.
func (s *State) CompleteCreate(plan Plan, reservation Reservation) (Reservation, error) {
	return s.transition(plan, reservation, Creating, Active, false)
}

// BeginCleanup atomically fences later creates. A Creating reservation is
// unresolved; an external caller must not infer absence from one observation.
func (s *State) BeginCleanup(plan Plan, reservation Reservation) (Reservation, error) {
	if reservation.Status == Creating {
		return Reservation{}, ErrInProgress
	}
	return s.transition(plan, reservation, reservation.Status, Cleaning, true)
}

// CompleteCleanup may only be called after exact workload, gateway, network
// and session absence was checked outside the PostgreSQL row lock. Cleaning
// prevents a new create between that check and this transaction.
func (s *State) CompleteCleanup(plan Plan, reservation Reservation) error {
	if s == nil || s.Validate(plan) != nil || reservation.Status != Cleaning {
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
		if !current.SameIdentity(reservation) {
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
