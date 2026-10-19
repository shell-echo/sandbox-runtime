package codingidentity

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestExecutionScratchHasSeparateMetadataAndInodeBounds(t *testing.T) {
	s := NewExecutionScratch()
	r := testExecutionResources()
	if s.BindResources(r) == nil {
		t.Fatal("old exact data-only split silently acquired metadata headroom")
	}
	r.Command.MemoryBytes -= s.MetadataBytes
	if s.BindResources(r) != nil {
		t.Fatal("bounded metadata allowance rejected")
	}
	o, err := s.VolumeOptions(57000, 58000)
	if err != nil || len(o) != 3 || o["type"] != "tmpfs" || o["device"] != "tmpfs" ||
		o["o"] != "size=33554432,nr_inodes=4096,uid=57000,gid=58000,mode=0700,nosuid,nodev,noexec" {
		t.Fatal("scratch options not completely source derived")
	}
	o["o"] = "unsafe"
	again, _ := s.VolumeOptions(57000, 58000)
	if strings.Contains(again["o"], "unsafe") {
		t.Fatal("caller mutated subsequent options")
	}
	for _, ids := range [][2]uint32{{0, 58000}, {57000, 0}, {60001, 58000}} {
		if _, err := s.VolumeOptions(ids[0], ids[1]); err == nil {
			t.Fatal("out-of-range identity accepted")
		}
	}
	for _, mutate := range []func(*ExecutionScratch){
		func(v *ExecutionScratch) { v.Bytes++ }, func(v *ExecutionScratch) { v.Inodes++ },
		func(v *ExecutionScratch) { v.MetadataBytes = 0 }, func(v *ExecutionScratch) { v.Inodes = math.MaxInt64 },
	} {
		bad := s
		mutate(&bad)
		if bad.BindResources(r) == nil {
			t.Fatal("unfrozen scratch accepted")
		}
	}
}

func TestExecutionStoragePartitionLeavesIndependentClosureAndHeadroom(t *testing.T) {
	s := NewExecutionStorage()
	if s.Validate() != nil || s.OutputPeakBytes+2*s.LedgerBytes+
		int64(2*s.MaxAllocationRecords+s.MaxExecutionRecords)*s.EvidenceDocumentBytes+
		s.ClosureReserveBytes+s.PhysicalHeadroomBytes != s.CodingQuotaBytes ||
		s.CodingQuotaBytes*2 != s.ControlVolumeBytes || s.ClosureReserveBytes != int64(s.MaxExecutionRecords)*s.EvidenceDocumentBytes {
		t.Fatal("shared volume/atomic copies/evidence/closure/headroom partition is not complete")
	}
	// File budget includes two output copies, allocation evidence, command
	// evidence, closures, ledger+replacement+lock, temporary evidence and dirs.
	objects := 4*s.MaxExecutionRecords + 2*s.MaxAllocationRecords + 2*s.MaxExecutionRecords + 8 + s.MaxExecutionRecords + s.MaxAllocationRecords
	if objects >= s.MaxCodingFiles {
		t.Fatal("metadata object margin exhausted")
	}
	for _, mutate := range []func(*ExecutionStorage){
		func(v *ExecutionStorage) { v.OutputPeakBytes++ }, func(v *ExecutionStorage) { v.ClosureReserveBytes-- },
		func(v *ExecutionStorage) { v.MaxExecutionRecords = 4096 }, func(v *ExecutionStorage) { v.PhysicalHeadroomBytes = 0 },
		func(v *ExecutionStorage) { v.LedgerBytes = math.MaxInt64 }, func(v *ExecutionStorage) { v.MaxCodingFiles++ },
	} {
		bad := s
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("silent storage policy relaxation")
		}
	}
}

func TestExecutionStorageDefaultPerStreamAndAtomicPeak(t *testing.T) {
	s := NewExecutionStorage()
	for _, tc := range []struct {
		c     CaptureBudget
		bytes int64
		files int
	}{
		{CaptureBudget{RequestBytes: 1}, 0, 0},
		{CaptureBudget{Stdout: true, RequestBytes: 1}, 16 << 20, 2},
		{CaptureBudget{Stderr: true, RequestBytes: 1}, 16 << 20, 2},
		{CaptureBudget{Stdout: true, Stderr: true, RequestBytes: 1}, 32 << 20, 4},
		{CaptureBudget{Stdout: true, Stderr: true, MaxBytes: 1, RequestBytes: 1}, 4 * (64 << 10), 4},
	} {
		v, err := s.Charge(tc.c)
		if err != nil || v.OutputBytes != tc.bytes || v.OutputFiles != tc.files || v.LedgerBytes != 64<<10 {
			t.Fatalf("wrong per-stream/default/rounded charge: %+v %v", v, err)
		}
	}
	for _, c := range []CaptureBudget{{RequestBytes: 0}, {RequestBytes: math.MaxInt64}, {RequestBytes: 1, MaxBytes: -1}, {RequestBytes: 1, MaxBytes: (8 << 20) + 1}} {
		if _, err := s.Charge(c); err == nil {
			t.Fatal("unbounded request charge")
		}
	}
}

func TestExecutionStorageAdmissionBoundsAreIndependent(t *testing.T) {
	s := NewExecutionStorage()
	u := ExecutionStorageUsage{Allocations: 2, LedgerBytes: 64 << 10} // state envelope
	full := CaptureBudget{Stdout: true, Stderr: true, RequestBytes: 4096}
	for range 6 {
		var err error
		u, err = s.Reserve(u, full)
		if err != nil {
			t.Fatal(err)
		}
	}
	if u.OutputBytes != s.OutputPeakBytes {
		t.Fatal("six full captures did not fill output partition")
	}
	if _, err := s.Reserve(u, full); !errors.Is(err, ErrExecutionStorageExhausted) {
		t.Fatal("seventh full capture accepted")
	}
	if s.CheckStateEncoding(u, u.LedgerBytes) != nil || s.CheckStateEncoding(u, u.LedgerBytes+1) == nil {
		t.Fatal("actual state encoding must fit its reservation")
	}
	// Output exhaustion does not spend the separate closure pool; commands
	// requesting no output still consume ledger/evidence/count reservations.
	for u.Executions < s.MaxExecutionRecords {
		var err error
		u, err = s.Reserve(u, CaptureBudget{RequestBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Reserve(u, CaptureBudget{RequestBytes: 1}); !errors.Is(err, ErrExecutionStorageExhausted) {
		t.Fatal("retained tombstone count ignored")
	}
	u = ExecutionStorageUsage{LedgerBytes: 64 << 10}
	for {
		next, err := s.Reserve(u, CaptureBudget{RequestBytes: s.MaxRequestBytes})
		if errors.Is(err, ErrExecutionStorageExhausted) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		u = next
	}
	if u.Executions >= s.MaxExecutionRecords || u.Executions < 1 {
		t.Fatal("count cap was mistaken for byte capacity")
	}
	for _, invalid := range []ExecutionStorageUsage{{LedgerBytes: math.MaxInt64}, {OutputBytes: -1}, {Executions: -1}, {Allocations: 33}, {OutputFiles: 257}} {
		if _, err := s.Reserve(invalid, full); err == nil {
			t.Fatal("invalid durable usage accepted")
		}
	}
}
