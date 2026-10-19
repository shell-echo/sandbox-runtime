package codingidentity

import (
	"errors"
	"fmt"
)

const (
	ExecutionStorageProtocol = "sandbox-runtime.coding-execution-storage.v1"
	SharedScratchInodes      = int64(4096)
	ScratchMetadataReserve   = int64(32 << 20)
)

var ErrExecutionStorageExhausted = errors.New("coding execution storage capacity exhausted")

// ExecutionScratch is a new-template input, not an extension of Plan v1.
// MetadataBytes is conservative reserved headroom, NOT a measured kernel bound.
type ExecutionScratch struct {
	Bytes         int64 `json:"bytes"`
	Inodes        int64 `json:"inodes"`
	MetadataBytes int64 `json:"metadata_bytes"`
}

func NewExecutionScratch() ExecutionScratch {
	return ExecutionScratch{SharedScratchBytes, SharedScratchInodes, ScratchMetadataReserve}
}

func (s ExecutionScratch) Validate() error {
	if s != NewExecutionScratch() {
		return ErrInvalidPlan
	}
	return nil
}

// BindResources includes the separate metadata allowance in the slot ceiling.
// Real pressure/charging and full topology headroom remain admission gates.
func (s ExecutionScratch) BindResources(r ExecutionResources) error {
	if s.Validate() != nil || r.Validate() != nil || r.ScratchBytes != s.Bytes ||
		s.MetadataBytes > r.Total.MemoryBytes-r.Resident.MemoryBytes-r.Command.MemoryBytes-r.ScratchBytes {
		return ErrInvalidPlan
	}
	return nil
}

// VolumeOptions derives the complete local-tmpfs options. No caller-provided
// paths, filesystem type, mount flags or free-form driver options are accepted.
func (s ExecutionScratch) VolumeOptions(uid, gid uint32) (map[string]string, error) {
	if s.Validate() != nil || uid < 10000 || uid > 60000 || gid < 10000 || gid > 60000 {
		return nil, ErrInvalidPlan
	}
	return map[string]string{"type": "tmpfs", "device": "tmpfs", "o": fmt.Sprintf(
		"size=%d,nr_inodes=%d,uid=%d,gid=%d,mode=0700,nosuid,nodev,noexec", s.Bytes, s.Inodes, uid, gid)}, nil
}

// ExecutionStorage is the prospective Coding partition of the SHARED Control
// volume. The other 512 MiB still needs a complete Profile allocation. No old
// receipt namespace, browser/desktop ledger or existing files may be mixed in.
// Values are fixed for this new mode; changing them requires a new reviewed
// template. Validate is arithmetic, not physical quota or admission evidence.
type ExecutionStorage struct {
	Protocol              string `json:"protocol"`
	ControlVolumeBytes    int64  `json:"control_volume_bytes"`
	CodingQuotaBytes      int64  `json:"coding_quota_bytes"`
	OutputPeakBytes       int64  `json:"output_peak_bytes"`
	LedgerBytes           int64  `json:"ledger_bytes"`
	MaxAllocationRecords  int    `json:"max_allocation_records"`
	MaxExecutionRecords   int    `json:"max_execution_records"`
	EvidenceDocumentBytes int64  `json:"evidence_document_bytes"`
	ClosureReserveBytes   int64  `json:"closure_reserve_bytes"`
	PhysicalHeadroomBytes int64  `json:"physical_headroom_bytes"`
	MaxRequestBytes       int64  `json:"max_request_bytes"`
	RecordEnvelopeBytes   int64  `json:"record_envelope_bytes"`
	PerStreamBytes        int64  `json:"per_stream_bytes"`
	AllocationUnitBytes   int64  `json:"allocation_unit_bytes"`
	MaxCodingFiles        int    `json:"max_coding_files"`
}

func NewExecutionStorage() ExecutionStorage {
	return ExecutionStorage{Protocol: ExecutionStorageProtocol,
		ControlVolumeBytes: 1 << 30, CodingQuotaBytes: 512 << 20, OutputPeakBytes: 192 << 20,
		LedgerBytes: 32 << 20, MaxAllocationRecords: 32, MaxExecutionRecords: 64,
		EvidenceDocumentBytes: 1 << 20, ClosureReserveBytes: 64 << 20, PhysicalHeadroomBytes: 64 << 20,
		MaxRequestBytes: 2 << 20, RecordEnvelopeBytes: 32 << 10, PerStreamBytes: 8 << 20,
		AllocationUnitBytes: 64 << 10, MaxCodingFiles: 1024}
}

func (s ExecutionStorage) Validate() error {
	if s != NewExecutionStorage() {
		return ErrInvalidPlan
	}
	return nil
}

// CaptureBudget must be derived from the same validated immutable request
// and its canonical encoding. It grants no authorization or durable occupancy.
type CaptureBudget struct {
	Stdout, Stderr         bool
	MaxBytes, RequestBytes int64
}

type ExecutionStorageCharge struct {
	LedgerBytes int64
	OutputBytes int64
	OutputFiles int
}

func (s ExecutionStorage) Charge(c CaptureBudget) (ExecutionStorageCharge, error) {
	if s.Validate() != nil || c.RequestBytes < 1 || c.RequestBytes > s.MaxRequestBytes ||
		c.MaxBytes < 0 || c.MaxBytes > s.PerStreamBytes {
		return ExecutionStorageCharge{}, ErrInvalidPlan
	}
	limit := c.MaxBytes
	if limit == 0 {
		limit = s.PerStreamBytes
	}
	// Round every possible file conservatively. A future writer must verify
	// the admitted filesystem allocation unit, file count and actual bytes.
	round := func(n int64) int64 {
		return (n + s.AllocationUnitBytes - 1) / s.AllocationUnitBytes * s.AllocationUnitBytes
	}
	result := ExecutionStorageCharge{LedgerBytes: round(c.RequestBytes + s.RecordEnvelopeBytes)}
	for _, enabled := range []bool{c.Stdout, c.Stderr} {
		if enabled {
			result.OutputBytes += 2 * round(limit) // live/staged plus sealed copy
			result.OutputFiles += 2
		}
	}
	return result, nil
}

// ExecutionStorageUsage is supplied by a future durable authority; this
// arithmetic helper is neither that authority nor a release/expiry API.
// LedgerBytes includes all retained records/tombstones and the state envelope.
type ExecutionStorageUsage struct {
	Allocations, Executions int
	LedgerBytes             int64
	OutputBytes             int64
	OutputFiles             int
}

func (s ExecutionStorage) Reserve(u ExecutionStorageUsage, c CaptureBudget) (ExecutionStorageUsage, error) {
	charge, err := s.Charge(c)
	if err != nil || u.Allocations < 0 || u.Allocations > s.MaxAllocationRecords ||
		u.Executions < 0 || u.Executions > s.MaxExecutionRecords || u.LedgerBytes < 0 || u.LedgerBytes > s.LedgerBytes ||
		u.OutputBytes < 0 || u.OutputBytes > s.OutputPeakBytes || u.OutputFiles < 0 || u.OutputFiles > 4*s.MaxExecutionRecords {
		return ExecutionStorageUsage{}, ErrInvalidPlan
	}
	if u.Executions == s.MaxExecutionRecords || charge.LedgerBytes > s.LedgerBytes-u.LedgerBytes ||
		charge.OutputBytes > s.OutputPeakBytes-u.OutputBytes || charge.OutputFiles > 4*s.MaxExecutionRecords-u.OutputFiles {
		return ExecutionStorageUsage{}, ErrExecutionStorageExhausted
	}
	u.Executions++
	u.LedgerBytes += charge.LedgerBytes
	u.OutputBytes += charge.OutputBytes
	u.OutputFiles += charge.OutputFiles
	return u, nil
}

// CheckStateEncoding must run for EVERY candidate transition before dispatch
// acceptance/commit, in addition to per-record reservations. It reserves one
// full replacement copy and rejects under-accounted candidate state bytes.
func (s ExecutionStorage) CheckStateEncoding(u ExecutionStorageUsage, encodedBytes int64) error {
	if s.Validate() != nil || u.LedgerBytes < 0 || u.LedgerBytes > s.LedgerBytes || encodedBytes < 1 ||
		encodedBytes > u.LedgerBytes || encodedBytes > s.LedgerBytes {
		return ErrInvalidPlan
	}
	return nil
}
