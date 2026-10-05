package dockercontrol

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
)

const (
	CodingReceiptSchema  = "sandbox-runtime.docker-control-coding-receipts.v2"
	CodingReceiptVersion = 2
	MaxRetainedReceipts  = 4096
)

var (
	ErrInvalidReceiptState = errors.New("invalid private Docker-control receipt state")
	ErrReceiptConflict     = errors.New("private Docker-control receipt conflict")
	ErrReceiptCapacity     = errors.New("private Docker-control receipt capacity exhausted")
)

type ReceiptStatus string

const (
	ReceiptReserved  ReceiptStatus = "reserved"
	ReceiptUnknown   ReceiptStatus = "unknown"
	ReceiptCompleted ReceiptStatus = "completed"
	ReceiptReleased  ReceiptStatus = "released"
)

// CodingReceipt is control-private. It contains no physical IDs or host
// paths, but its retained authority still must never be exposed on stable
// Provider APIs. Released is a tombstone, not permission to forget/replay.
type CodingReceipt struct {
	Authority        CodingCreateAuthority `json:"authority"`
	AuthorityDigest  string                `json:"authority_digest"`
	Status           ReceiptStatus         `json:"status"`
	CompletionDigest string                `json:"completion_digest"`
	// Unknown/Reserved omit this field, preserving their existing canonical
	// v2 bytes. Older Completed prototypes without an envelope seal reject.
	CompletionEvidenceDigest string                 `json:"completion_evidence_digest,omitempty"`
	CleanupAuthority         CodingCleanupAuthority `json:"cleanup_authority"`
	AbsenceDigest            string                 `json:"absence_digest"`
	AbsenceEvidenceDigest    string                 `json:"absence_evidence_digest,omitempty"`
	UpdatedAt                time.Time              `json:"updated_at"`
}

type CodingReceiptBinding struct {
	Plan                    codingidentity.Plan
	SpecBySlot              map[string]string
	ProfileDigest           string
	DaemonDigest            string
	DaemonEnvironmentDigest string
	EndpointScopeDigest     string
	RuntimePlatform         string
	ControlPolicyDigest     string
	PeerPrincipalDigest     string
	PlanDigest              string
	Capacity                int
}

func (b CodingReceiptBinding) specMapDigest() string {
	type entry struct {
		SlotID     string `json:"slot_id"`
		SpecDigest string `json:"spec_digest"`
	}
	entries := make([]entry, 0, len(b.Plan.Slots))
	for _, slot := range b.Plan.Slots {
		entries = append(entries, entry{SlotID: slot.ID, SpecDigest: b.SpecBySlot[slot.ID]})
	}
	document, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-spec-map/v1\x00"), document...))
}

func (b CodingReceiptBinding) clone() CodingReceiptBinding {
	b.Plan.Slots = slices.Clone(b.Plan.Slots)
	b.SpecBySlot = maps.Clone(b.SpecBySlot)
	return b
}

func (b CodingReceiptBinding) Validate() error {
	planDigest, err := b.Plan.Digest()
	if !controlDigest.MatchString(b.ProfileDigest) || !controlDigest.MatchString(b.DaemonDigest) ||
		!controlDigest.MatchString(b.DaemonEnvironmentDigest) ||
		!controlDigest.MatchString(b.EndpointScopeDigest) ||
		(b.RuntimePlatform != "linux/arm64/v8" && b.RuntimePlatform != "linux/amd64") ||
		!controlDigest.MatchString(b.ControlPolicyDigest) ||
		!controlDigest.MatchString(b.PeerPrincipalDigest) || !controlDigest.MatchString(b.PlanDigest) ||
		b.Capacity != 2 || err != nil || planDigest != b.PlanDigest ||
		b.Plan.Capacity != b.Capacity || b.Plan.ProfileDigest != b.ProfileDigest ||
		b.Plan.OwnerPrincipalDigest != b.PeerPrincipalDigest || len(b.SpecBySlot) != len(b.Plan.Slots) {
		return ErrInvalidReceiptState
	}
	for _, slot := range b.Plan.Slots {
		if !controlDigest.MatchString(b.SpecBySlot[slot.ID]) {
			return ErrInvalidReceiptState
		}
	}
	return nil
}

type CodingReceiptState struct {
	Schema                  string          `json:"schema"`
	Version                 int             `json:"version"`
	ProfileDigest           string          `json:"profile_digest"`
	DaemonDigest            string          `json:"daemon_digest"`
	DaemonEnvironmentDigest string          `json:"daemon_environment_digest"`
	EndpointScopeDigest     string          `json:"endpoint_scope_digest"`
	RuntimePlatform         string          `json:"runtime_platform"`
	ControlPolicyDigest     string          `json:"control_policy_digest"`
	PeerPrincipalDigest     string          `json:"peer_principal_digest"`
	PlanDigest              string          `json:"plan_digest"`
	SpecMapDigest           string          `json:"spec_map_digest"`
	Capacity                int             `json:"capacity"`
	Revision                uint64          `json:"revision"`
	Records                 []CodingReceipt `json:"records"`
	StateDigest             string          `json:"state_digest"`
}

func NewCodingReceiptState(binding CodingReceiptBinding) (CodingReceiptState, error) {
	if binding.Validate() != nil {
		return CodingReceiptState{}, ErrInvalidReceiptState
	}
	state := CodingReceiptState{Schema: CodingReceiptSchema, Version: CodingReceiptVersion,
		ProfileDigest: binding.ProfileDigest, DaemonDigest: binding.DaemonDigest,
		DaemonEnvironmentDigest: binding.DaemonEnvironmentDigest,
		EndpointScopeDigest:     binding.EndpointScopeDigest, RuntimePlatform: binding.RuntimePlatform,
		ControlPolicyDigest: binding.ControlPolicyDigest,
		PeerPrincipalDigest: binding.PeerPrincipalDigest, PlanDigest: binding.PlanDigest,
		SpecMapDigest: binding.specMapDigest(),
		Capacity:      binding.Capacity, Revision: 1, Records: []CodingReceipt{}}
	state.StateDigest = state.digest()
	return state, nil
}

func (s CodingReceiptState) Clone() CodingReceiptState {
	s.Records = slices.Clone(s.Records)
	return s
}

func (s CodingReceiptState) Validate(binding CodingReceiptBinding) error {
	if binding.Validate() != nil || s.Schema != CodingReceiptSchema || s.Version != CodingReceiptVersion ||
		s.ProfileDigest != binding.ProfileDigest || s.DaemonDigest != binding.DaemonDigest ||
		s.DaemonEnvironmentDigest != binding.DaemonEnvironmentDigest ||
		s.EndpointScopeDigest != binding.EndpointScopeDigest || s.RuntimePlatform != binding.RuntimePlatform ||
		s.ControlPolicyDigest != binding.ControlPolicyDigest ||
		s.PeerPrincipalDigest != binding.PeerPrincipalDigest || s.PlanDigest != binding.PlanDigest ||
		s.SpecMapDigest != binding.specMapDigest() ||
		s.Capacity != binding.Capacity || s.Revision == 0 || s.Records == nil ||
		len(s.Records) > MaxRetainedReceipts || s.StateDigest != s.digest() {
		return ErrInvalidReceiptState
	}
	previous := ""
	allocations := make(map[string]bool, len(s.Records))
	effects := make(map[string]bool, len(s.Records))
	slots := make(map[string]bool, len(s.Records))
	active := 0
	for _, receipt := range s.Records {
		a := receipt.Authority
		if a.RequestID <= previous || allocations[a.AllocationID] || effects[a.EffectID] ||
			a.BindControl(binding.Plan, binding.ControlPolicyDigest, binding.PeerPrincipalDigest,
				binding.SpecBySlot[a.SlotID], a.IssuedAt) != nil ||
			a.ProfileDigest != binding.ProfileDigest ||
			a.ControlPolicyDigest != binding.ControlPolicyDigest ||
			a.PeerPrincipalDigest != binding.PeerPrincipalDigest || a.PlanDigest != binding.PlanDigest ||
			receipt.AuthorityDigest != a.Digest() || receipt.UpdatedAt.Before(a.IssuedAt) ||
			receipt.UpdatedAt.IsZero() || !validReceiptStatus(receipt) {
			return ErrInvalidReceiptState
		}
		if receipt.CleanupAuthority != (CodingCleanupAuthority{}) &&
			(receipt.UpdatedAt.Before(receipt.CleanupAuthority.IssuedAt) ||
				receipt.CleanupAuthority.BindControl(a, binding.Plan, binding.ControlPolicyDigest,
					binding.PeerPrincipalDigest, binding.SpecBySlot[a.SlotID],
					receipt.CleanupAuthority.IssuedAt) != nil) {
			return ErrInvalidReceiptState
		}
		if receipt.Status != ReceiptReleased {
			if slots[a.SlotID] {
				return ErrInvalidReceiptState
			}
			slots[a.SlotID] = true
			active++
		}
		allocations[a.AllocationID] = true
		effects[a.EffectID] = true
		previous = a.RequestID
	}
	if active > binding.Capacity {
		return ErrInvalidReceiptState
	}
	return nil
}

func validReceiptStatus(receipt CodingReceipt) bool {
	switch receipt.Status {
	case ReceiptReserved, ReceiptUnknown:
		return receipt.CompletionDigest == "" && receipt.CompletionEvidenceDigest == "" &&
			receipt.AbsenceDigest == "" && receipt.AbsenceEvidenceDigest == "" &&
			receipt.CleanupAuthority == (CodingCleanupAuthority{})
	case ReceiptCompleted:
		return controlDigest.MatchString(receipt.CompletionDigest) &&
			controlDigest.MatchString(receipt.CompletionEvidenceDigest) &&
			receipt.AbsenceDigest == "" && receipt.AbsenceEvidenceDigest == ""
	case ReceiptReleased:
		return receipt.CleanupAuthority != (CodingCleanupAuthority{}) &&
			controlDigest.MatchString(receipt.AbsenceDigest) &&
			controlDigest.MatchString(receipt.AbsenceEvidenceDigest) &&
			controlDigest.MatchString(receipt.CompletionDigest) &&
			controlDigest.MatchString(receipt.CompletionEvidenceDigest)
	default:
		return false
	}
}

// releaseObserved is a private state transition, not an API accepting a
// caller's absence assertion. Only the ledger's bounded exact-cleanup path
// may supply the internally persisted and rechecked proof/evidence digests.
func (s CodingReceiptState) releaseObserved(binding CodingReceiptBinding,
	createRequestID string, intent CodingCleanupAuthority, absenceDigest,
	evidenceDigest string, sourceRevision uint64, now time.Time) (CodingReceiptState, CodingReceipt, error) {
	if s.Validate(binding) != nil || !controlDigest.MatchString(createRequestID) ||
		!controlDigest.MatchString(absenceDigest) || !controlDigest.MatchString(evidenceDigest) ||
		s.Revision != sourceRevision || s.Revision == ^uint64(0) || now.IsZero() {
		return CodingReceiptState{}, CodingReceipt{}, ErrInvalidReceiptState
	}
	for index, receipt := range s.Records {
		if receipt.Authority.RequestID != createRequestID {
			continue
		}
		if receipt.Status != ReceiptCompleted || receipt.CleanupAuthority != intent ||
			intent.BindControl(receipt.Authority, binding.Plan, binding.ControlPolicyDigest,
				binding.PeerPrincipalDigest, binding.SpecBySlot[receipt.Authority.SlotID], now) != nil ||
			now.Before(receipt.UpdatedAt) || receipt.AbsenceDigest != "" ||
			receipt.AbsenceEvidenceDigest != "" {
			return CodingReceiptState{}, CodingReceipt{}, ErrReceiptConflict
		}
		next := s.Clone()
		receipt.Status = ReceiptReleased
		receipt.AbsenceDigest = absenceDigest
		receipt.AbsenceEvidenceDigest = evidenceDigest
		receipt.UpdatedAt = now.UTC()
		next.Records[index] = receipt
		next.Revision++
		next.StateDigest = next.digest()
		if next.Validate(binding) != nil {
			return CodingReceiptState{}, CodingReceipt{}, ErrInvalidReceiptState
		}
		return next, receipt, nil
	}
	return CodingReceiptState{}, CodingReceipt{}, ErrReceiptConflict
}

// completeObserved records one internally produced, current-revision live
// observation. It deliberately does not accept a caller-provided digest or
// turn an old Unknown/absent effect into a successful create.
func (s CodingReceiptState) completeObserved(binding CodingReceiptBinding,
	requestID string, proof codingCompletionObservation, evidenceDigest string,
	now time.Time) (CodingReceiptState, CodingReceipt, error) {
	if s.Validate(binding) != nil || !controlDigest.MatchString(requestID) ||
		proof.ReceiptRevision != s.Revision || !controlDigest.MatchString(proof.CompletionDigest) ||
		!controlDigest.MatchString(evidenceDigest) ||
		s.Revision == ^uint64(0) || now.IsZero() {
		return CodingReceiptState{}, CodingReceipt{}, ErrInvalidReceiptState
	}
	for index, receipt := range s.Records {
		if receipt.Authority.RequestID != requestID {
			continue
		}
		if receipt.Status != ReceiptUnknown || receipt.CleanupAuthority != (CodingCleanupAuthority{}) ||
			receipt.AuthorityDigest != proof.AuthorityDigest ||
			receipt.Authority.EffectID != proof.EffectID || now.Before(receipt.UpdatedAt) {
			return CodingReceiptState{}, CodingReceipt{}, ErrReceiptConflict
		}
		next := s.Clone()
		receipt.Status = ReceiptCompleted
		receipt.CompletionDigest = proof.CompletionDigest
		receipt.CompletionEvidenceDigest = evidenceDigest
		receipt.UpdatedAt = now.UTC()
		next.Records[index] = receipt
		next.Revision++
		next.StateDigest = next.digest()
		if next.Validate(binding) != nil {
			return CodingReceiptState{}, CodingReceipt{}, ErrInvalidReceiptState
		}
		return next, receipt, nil
	}
	return CodingReceiptState{}, CodingReceipt{}, ErrReceiptConflict
}

// beginCleanup records a separate fenced retirement intent while the one
// create effect remains occupied. This offline transition is reachable only
// from an independently completed physical receipt; Unknown/Creating cannot
// be converted to cleanup merely by presenting a new Provider operation.
// Its durable adapter must commit the returned state before any deletion.
func (s CodingReceiptState) beginCleanup(binding CodingReceiptBinding,
	createRequestID string, intent CodingCleanupAuthority, now time.Time) (CodingReceiptState, CodingReceipt, bool, error) {
	if s.Validate(binding) != nil || !controlDigest.MatchString(createRequestID) {
		return CodingReceiptState{}, CodingReceipt{}, false, ErrInvalidReceiptState
	}
	for index, receipt := range s.Records {
		if receipt.Authority.RequestID != createRequestID {
			continue
		}
		if intent.BindControl(receipt.Authority, binding.Plan, binding.ControlPolicyDigest,
			binding.PeerPrincipalDigest, binding.SpecBySlot[receipt.Authority.SlotID], now) != nil {
			return CodingReceiptState{}, CodingReceipt{}, false, ErrInvalidAuthority
		}
		if receipt.CleanupAuthority != (CodingCleanupAuthority{}) {
			if receipt.CleanupAuthority == intent {
				return s, receipt, false, nil
			}
			return CodingReceiptState{}, CodingReceipt{}, false, ErrReceiptConflict
		}
		if receipt.Status != ReceiptCompleted || intent.IssuedAt.Before(receipt.UpdatedAt) ||
			s.Revision == ^uint64(0) {
			return CodingReceiptState{}, CodingReceipt{}, false, ErrReceiptConflict
		}
		next := s.Clone()
		receipt.CleanupAuthority = intent
		receipt.UpdatedAt = now.UTC()
		next.Records[index] = receipt
		next.Revision++
		next.StateDigest = next.digest()
		if next.Validate(binding) != nil {
			return CodingReceiptState{}, CodingReceipt{}, false, ErrInvalidReceiptState
		}
		return next, receipt, true, nil
	}
	return CodingReceiptState{}, CodingReceipt{}, false, ErrReceiptConflict
}

func (s CodingReceiptState) digest() string {
	s.StateDigest = ""
	document, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-receipts/v2\x00"), document...))
}

// beginUnknown is an in-memory transition only. The durable adapter must
// atomically commit its result before invoking any physical side effect.
// A crash after that commit but before the side effect conservatively holds
// the allocation Unknown and never recreates a dispatch permit on reopen.
func (s CodingReceiptState) beginUnknown(binding CodingReceiptBinding,
	a CodingCreateAuthority, now time.Time) (CodingReceiptState, CodingReceipt, bool, error) {
	if s.Validate(binding) != nil || a.BindControl(binding.Plan, binding.ControlPolicyDigest,
		binding.PeerPrincipalDigest, binding.SpecBySlot[a.SlotID], now) != nil ||
		a.ProfileDigest != binding.ProfileDigest || a.ControlPolicyDigest != binding.ControlPolicyDigest ||
		a.PeerPrincipalDigest != binding.PeerPrincipalDigest || a.PlanDigest != binding.PlanDigest {
		return CodingReceiptState{}, CodingReceipt{}, false, ErrInvalidReceiptState
	}
	authorityDigest := a.Digest()
	active := 0
	for _, existing := range s.Records {
		if existing.Authority.RequestID == a.RequestID {
			if existing.AuthorityDigest == authorityDigest && existing.Authority == a {
				return s, existing, false, nil
			}
			return CodingReceiptState{}, CodingReceipt{}, false, ErrReceiptConflict
		}
		if existing.Authority.AllocationID == a.AllocationID || existing.Authority.EffectID == a.EffectID ||
			(existing.Status != ReceiptReleased && existing.Authority.SlotID == a.SlotID) {
			// Retain this create-effect tombstone even after physical release.
			// A new request ID, attempt, fence or Profile cannot create again.
			return CodingReceiptState{}, CodingReceipt{}, false, ErrReceiptConflict
		}
		if existing.Status != ReceiptReleased {
			active++
		}
	}
	if active >= binding.Capacity || len(s.Records) >= MaxRetainedReceipts || s.Revision == ^uint64(0) {
		return CodingReceiptState{}, CodingReceipt{}, false, ErrReceiptCapacity
	}
	receipt := CodingReceipt{Authority: a, AuthorityDigest: authorityDigest,
		Status: ReceiptUnknown, UpdatedAt: now.UTC()}
	next := s.Clone()
	next.Records = append(next.Records, receipt)
	slices.SortFunc(next.Records, func(left, right CodingReceipt) int {
		if left.Authority.RequestID < right.Authority.RequestID {
			return -1
		}
		if left.Authority.RequestID > right.Authority.RequestID {
			return 1
		}
		return 0
	})
	next.Revision++
	next.StateDigest = next.digest()
	if next.Validate(binding) != nil {
		return CodingReceiptState{}, CodingReceipt{}, false, ErrInvalidReceiptState
	}
	return next, receipt, true, nil
}
