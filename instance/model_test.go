package instance

import (
	"errors"
	"strings"
	"testing"
)

func TestSpecValidate(t *testing.T) {
	tests := []struct {
		name    string
		spec    Spec
		wantErr bool
	}{
		{"shell", Spec{Name: "terminal", Workload: WorkloadShell}, false},
		{"missing name", Spec{Workload: WorkloadShell}, true},
		{"blank name", Spec{Name: "  ", Workload: WorkloadShell}, true},
		{"surrounding whitespace", Spec{Name: " terminal ", Workload: WorkloadShell}, true},
		{"name too long", Spec{Name: strings.Repeat("界", MaxNameLength+1), Workload: WorkloadShell}, true},
		{"invalid workload", Spec{Name: "bad", Workload: "job"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("error = %v, want ErrInvalidSpec", err)
			}
		})
	}
}

func TestStateTransitions(t *testing.T) {
	valid := map[State][]State{
		StateCreating: {StateStopped, StateFailed},
		StateStopped:  {StateStarting, StateRemoving},
		StateStarting: {StateRunning, StateStopped, StateFailed},
		StateRunning:  {StateStopping, StateFailed},
		StateStopping: {StateStopped, StateRunning, StateFailed},
		StateFailed:   {StateRemoving},
	}
	states := []State{StateCreating, StateStopped, StateStarting, StateRunning, StateStopping, StateRemoving, StateFailed}

	for _, from := range states {
		for _, to := range states {
			want := containsState(valid[from], to)
			if got := from.CanTransition(to); got != want {
				t.Errorf("%s.CanTransition(%s) = %v, want %v", from, to, got, want)
			}
		}
	}
}

func containsState(states []State, target State) bool {
	for _, state := range states {
		if state == target {
			return true
		}
	}
	return false
}
