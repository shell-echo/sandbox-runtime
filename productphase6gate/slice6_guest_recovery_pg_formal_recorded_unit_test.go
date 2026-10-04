//go:build phase6slice6gate

package productphase6gate

import (
	"strings"
	"testing"
)

func TestSlice6GuestRecoveryFormalPGActionCannotRecordWithoutSource(t *testing.T) {
	runID := strings.Repeat("a", 32)
	edge := slice6ProductPGFaultEdge{Run: slice6DockerRun{id: runID}}
	recorder, err := newSlice6GuestRecoveryERecorder(runID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slice6DisconnectProductPGEdgeFormalRecorded(t.Context(), edge,
		slice6GuestOperatorTarget{}, slice6GuestOperatorFormalSource{}, "", nil); err == nil {
		t.Fatal("formal PG disconnect accepted missing E recorder")
	}
	if _, err := slice6DisconnectProductPGEdgeFormalRecorded(t.Context(), edge,
		slice6GuestOperatorTarget{}, slice6GuestOperatorFormalSource{}, "", recorder); err == nil {
		t.Fatal("formal PG disconnect accepted missing source")
	}
	if _, err := slice6RestoreProductPGEdgeFormalRecorded(t.Context(), edge,
		slice6GuestOperatorTarget{}, slice6GuestOperatorFormalSource{}, "",
		slice6ProductPGFaultAction{}, recorder); err == nil {
		t.Fatal("formal PG restore accepted missing source")
	}
	if len(recorder.events) != 0 {
		t.Fatal("failed formal PG source check mutated E journal")
	}
}
