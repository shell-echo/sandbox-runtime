package coordinator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type terminationRouteRepository struct{ *codingTrapRepository }

func (*terminationRouteRepository) GetSandbox(context.Context, string) (lifecycle.Sandbox, error) {
	panic("typed termination must not mix generic sandbox reads")
}

type terminationRouteProbe struct {
	calls int
	err   error
}

func (p *terminationRouteProbe) ReconcileCodingTermination(_ context.Context, id string) (lifecycle.Operation, lifecycle.Sandbox, bool, error) {
	p.calls++
	return lifecycle.Operation{ID: id}, lifecycle.Sandbox{ID: "typed-snapshot"}, true, p.err
}
func TestCodingTerminationRoutesBeforeGenericTerminalShortcut(t *testing.T) {
	for _, state := range []lifecycle.OperationState{lifecycle.OperationAccepted, lifecycle.OperationRunning, lifecycle.OperationOutcomeUnknown, lifecycle.OperationSucceeded, lifecycle.OperationFailed, lifecycle.OperationCancelled} {
		t.Run(string(state), func(t *testing.T) {
			repo := &terminationRouteRepository{&codingTrapRepository{operation: lifecycle.Operation{ID: "termination-1", Type: lifecycle.OperationTerminate, State: state}}}
			driver := &codingTrapDriver{}
			probe := &terminationRouteProbe{err: errors.New("typed rejection preserved")}
			s, err := NewWithCodingOriginalAuthorityAndTermination(repo, driver, &codingReadbackProbe{}, probe, &testClock{now: time.Now().UTC()})
			if err != nil {
				t.Fatal(err)
			}
			r, err := s.ReconcileOperation(t.Context(), repo.operation.ID)
			if !errors.Is(err, probe.err) || probe.calls != 1 || driver.calls != 0 || !r.Dispatched || r.Sandbox.ID != "typed-snapshot" {
				t.Fatalf("typed terminal routing: %#v %v", r, err)
			}
		})
	}
}
func TestCodingTerminationCompositionKeepsOtherRuntimePortsHeld(t *testing.T) {
	repo := &codingTrapRepository{sandbox: lifecycle.Sandbox{ID: "sandbox-1"}}
	driver := &codingTrapDriver{}
	probe := &terminationRouteProbe{}
	s, err := NewWithCodingOriginalAuthorityAndTermination(repo, driver, &codingReadbackProbe{}, probe, &testClock{now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []lifecycle.OperationType{lifecycle.OperationExtendLease, lifecycle.OperationSuspend, lifecycle.OperationResume} {
		repo.operation = lifecycle.Operation{ID: "operation-1", SandboxID: repo.sandbox.ID, Type: kind, State: lifecycle.OperationAccepted}
		if _, err := s.ReconcileOperation(t.Context(), repo.operation.ID); !errors.Is(err, ErrUnknownRuntime) {
			t.Fatalf("%s no longer held: %v", kind, err)
		}
	}
	if driver.calls != 0 || probe.calls != 0 {
		t.Fatal("held ports reached a runtime")
	}
}
