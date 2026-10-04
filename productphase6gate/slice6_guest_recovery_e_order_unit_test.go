//go:build phase6slice6gate

package productphase6gate

import (
	"strings"
	"testing"
)

func TestSlice6GuestRecoveryEActionCountAndOrderBoundaries(t *testing.T) {
	runID := strings.Repeat("a", 32)
	digest := "sha256:" + strings.Repeat("b", 64)
	expected := slice6GuestRecoveryExpectedEvents(slice6GuestRecoveryPrecleanupInput{})
	recorder, err := newSlice6GuestRecoveryERecorder(runID)
	if err != nil || slice6RequireGuestRecoveryEOrder(recorder, 0) != nil {
		t.Fatal("empty E journal unavailable")
	}
	for index, kind := range slice6GuestRecoveryEOrder {
		if kind != expected[index].kind || recorder.record(kind, digest) != nil ||
			slice6RequireGuestRecoveryEOrder(recorder, index+1) != nil {
			t.Fatalf("E action boundary %d does not match frozen 29-event order", index+1)
		}
	}
	if slice6RequireGuestRecoveryEOrder(recorder, 28) == nil {
		t.Fatal("E boundary accepted a missing event")
	}
	wrong, err := newSlice6GuestRecoveryERecorder(runID)
	if err != nil || wrong.record("source_complete", digest) != nil ||
		wrong.record("pg_down_call", digest) != nil ||
		slice6RequireGuestRecoveryEOrder(wrong, 2) == nil {
		t.Fatal("E boundary accepted an out-of-order call")
	}
}
