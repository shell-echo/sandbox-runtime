package dockercontrol

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
)

const (
	executionUnknown            = "unknown"
	executionCompleted          = "completed"
	executionClosedBeforeEffect = "closed_before_effect"
)

type executionRetirement struct {
	BindingDigest string    `json:"binding_digest"`
	CreateDigest  string    `json:"create_digest"`
	OperationID   string    `json:"operation_id"`
	Generation    uint64    `json:"generation"`
	Fence         uint64    `json:"fence"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (r executionRetirement) validate(b executionBinding, a executionCreate, now time.Time) error {
	if r.BindingDigest != b.digest() || r.CreateDigest != a.digest() || !controlID.MatchString(r.OperationID) ||
		r.Generation <= a.Generation || r.OperationID == a.OperationID || r.Fence < a.Fence || r.Generation > 1<<63-1 || r.Fence > 1<<63-1 ||
		r.IssuedAt.Before(a.IssuedAt) || !executionWindow(r.IssuedAt, r.ExpiresAt, now) {
		return ErrInvalidAuthority
	}
	return nil
}

type executionAllocationRecord struct {
	Create         executionCreate                 `json:"create"`
	CreateStatus   string                          `json:"create_status"`
	Completion     *executionCompletionObservation `json:"completion"`
	Retirement     *executionRetirement            `json:"retirement"`
	CleanupUnknown bool                            `json:"cleanup_unknown"`
	HighFence      uint64                          `json:"high_fence"`
	UpdatedAt      time.Time                       `json:"updated_at"`
}
type executionRecord struct {
	Claim      executionClaim `json:"claim"`
	Status     string         `json:"status"`
	RecordedAt time.Time      `json:"recorded_at"`
}
type executionState struct {
	Protocol      string                      `json:"protocol"`
	BindingDigest string                      `json:"binding_digest"`
	Revision      uint64                      `json:"revision"`
	Allocations   []executionAllocationRecord `json:"allocations"`
	Executions    []executionRecord           `json:"executions"`
}

func newExecutionState(b executionBinding) executionState {
	return executionState{Protocol: executionReceiptProtocol, BindingDigest: b.digest(), Revision: 1,
		Allocations: []executionAllocationRecord{}, Executions: []executionRecord{}}
}
func (s executionState) clone() executionState {
	d, _ := json.Marshal(s)
	var out executionState
	_ = json.Unmarshal(d, &out)
	return out
}
func (s executionState) digest() string { return executionDigest("state", s) }
func (s executionState) allocation(create string) int {
	for i, a := range s.Allocations {
		if a.Create.digest() == create {
			return i
		}
	}
	return -1
}
func (s executionState) existing(c executionClaim) (int, error) {
	for i, e := range s.Executions {
		if e.Claim.Request.OperationID == c.Request.OperationID || e.Claim.Request.IdempotencyKey == c.Request.IdempotencyKey {
			if e.Claim.digest() != c.digest() {
				return -1, ErrReceiptConflict
			}
			return i, nil
		}
	}
	return -1, nil
}
func (s executionState) possible(create string) bool {
	for _, e := range s.Executions {
		if e.Claim.CreateDigest == create && e.Status == executionUnknown {
			return true
		}
	}
	return false
}

// Recompute retained budgets from the complete state on every transition and
// reopen. Closed-before-effect records keep metadata/history but have never
// reserved physical/output occupancy. Unknown never relinquishes its charge.
func (s executionState) validate(b executionBinding, now time.Time) error {
	if b.validate() != nil || s.Protocol != executionReceiptProtocol || s.BindingDigest != b.digest() || s.Revision == 0 || now.IsZero() ||
		s.Allocations == nil || s.Executions == nil || len(s.Allocations) > b.Template.Storage.MaxAllocationRecords || len(s.Executions) > b.Template.Storage.MaxExecutionRecords {
		return ErrInvalidReceiptState
	}
	u := codingidentity.ExecutionStorageUsage{Allocations: len(s.Allocations), LedgerBytes: b.Template.Storage.AllocationUnitBytes}
	slots, ids, sandboxes, creates := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range s.Allocations {
		c := a.Create
		if c.validate(b, c.IssuedAt) != nil || a.UpdatedAt.Before(c.IssuedAt) || a.UpdatedAt.After(now) || a.HighFence < c.Fence || a.HighFence > 1<<63-1 ||
			slots[c.SlotID] || ids[c.AllocationID] || sandboxes[c.SandboxID] || creates[c.OperationID] {
			return ErrInvalidReceiptState
		}
		// No Released transition exists yet: all allocated slots remain held.
		slots[c.SlotID], ids[c.AllocationID], sandboxes[c.SandboxID], creates[c.OperationID] = true, true, true, true
		switch a.CreateStatus {
		case executionUnknown:
			if a.Completion != nil {
				return ErrInvalidReceiptState
			}
		case executionCompleted:
			if a.Completion == nil || a.Completion.validate(b, c, a.UpdatedAt) != nil || a.Completion.SourceRevision >= s.Revision {
				return ErrInvalidReceiptState
			}
		case executionClosedBeforeEffect:
			if a.Completion != nil || a.Retirement == nil {
				return ErrInvalidReceiptState
			}
		default:
			return ErrInvalidReceiptState
		}
		if a.Retirement != nil && (a.Retirement.validate(b, c, a.Retirement.IssuedAt) != nil || a.Retirement.IssuedAt.After(a.UpdatedAt) || a.Retirement.Fence != a.HighFence) {
			return ErrInvalidReceiptState
		}
		if a.CleanupUnknown && (a.Retirement == nil || a.CreateStatus != executionCompleted || s.possible(c.digest())) {
			return ErrInvalidReceiptState
		}
		u.LedgerBytes += b.Template.Storage.AllocationUnitBytes
	}
	ops, keys, possible := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range s.Executions {
		c := e.Claim
		i := s.allocation(c.CreateDigest)
		if i < 0 {
			return ErrInvalidReceiptState
		}
		a := s.Allocations[i]
		if c.validate(b, a.Create, c.AcceptedAt) != nil || e.RecordedAt.Before(c.AcceptedAt) || e.RecordedAt.After(now) ||
			a.Completion == nil || c.CompletionDigest != a.Completion.digest() || a.Completion.ObservedAt.After(c.AcceptedAt) ||
			ops[c.Request.OperationID] || keys[c.Request.IdempotencyKey] || uint64(c.Request.FencingToken) > a.HighFence {
			return ErrInvalidReceiptState
		}
		ops[c.Request.OperationID], keys[c.Request.IdempotencyKey] = true, true
		charge, err := c.charge(b)
		if err != nil {
			return ErrInvalidReceiptState
		}
		u.Executions++
		u.LedgerBytes += charge.LedgerBytes
		switch e.Status {
		case executionUnknown:
			if possible[c.CreateDigest] || a.CleanupUnknown ||
				(a.Retirement != nil && e.RecordedAt.After(a.UpdatedAt)) {
				return ErrInvalidReceiptState
			}
			possible[c.CreateDigest] = true
			u.OutputBytes += charge.OutputBytes
			u.OutputFiles += charge.OutputFiles
		case executionClosedBeforeEffect:
		default:
			return ErrInvalidReceiptState
		}
	}
	encoded, err := json.Marshal(s)
	if err != nil || b.Template.Storage.CheckStateEncoding(u, int64(len(encoded))) != nil ||
		u.OutputBytes > b.Template.Storage.OutputPeakBytes || u.OutputFiles > 4*b.Template.Storage.MaxExecutionRecords {
		return ErrReceiptCapacity
	}
	return nil
}
func decodeExecutionState(d []byte, b executionBinding, now time.Time) (executionState, error) {
	var s executionState
	if len(d) == 0 || int64(len(d)) > b.Template.Storage.LedgerBytes || json.Unmarshal(d, &s) != nil || s.validate(b, now) != nil {
		return executionState{}, ErrInvalidReceiptState
	}
	c, _ := json.Marshal(s)
	if !bytes.Equal(d, c) {
		return executionState{}, ErrInvalidReceiptState
	}
	return s, nil
}
