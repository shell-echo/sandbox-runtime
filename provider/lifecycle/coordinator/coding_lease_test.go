package coordinator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type leaseRouteProbe struct {
	calls int
	err   error
}

func (p *leaseRouteProbe) ReconcileCodingLease(_ context.Context, id string) (lifecycle.Operation, lifecycle.Sandbox, error) {
	p.calls++
	return lifecycle.Operation{ID: id}, lifecycle.Sandbox{ID: "typed-lease-snapshot"}, p.err
}
func TestCodingLeaseRoutesBeforeGenericTerminalShortcut(t *testing.T) {
	for _, state := range []lifecycle.OperationState{lifecycle.OperationAccepted, lifecycle.OperationRunning, lifecycle.OperationSucceeded, lifecycle.OperationOutcomeUnknown, lifecycle.OperationFailed, lifecycle.OperationCancelled} {
		repo := &terminationRouteRepository{&codingTrapRepository{operation: lifecycle.Operation{ID: "lease-1", Type: lifecycle.OperationExtendLease, State: state}}}
		driver := &codingTrapDriver{}
		probe := &leaseRouteProbe{err: errors.New("typed lease rejection")}
		term := &terminationRouteProbe{}
		c, err := NewWithCodingOriginalAuthorityAndLease(repo, driver, &codingReadbackProbe{}, term, probe, &testClock{now: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		result, err := c.ReconcileOperation(t.Context(), repo.operation.ID)
		if !errors.Is(err, probe.err) || probe.calls != 1 || term.calls != 0 || driver.calls != 0 || result.Dispatched || result.Sandbox.ID != "typed-lease-snapshot" {
			t.Fatalf("route %s: %#v %v", state, result, err)
		}
	}
}

func TestCodingLeaseAdmissionReplayRejectsWrongKindDeadlineAndInvalidRequest(t *testing.T) {
	for _, name := range []string{"kind", "deadline", "invalid extension", "expired"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			req := lifecycle.LeaseRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "lease-op", AttemptID: "lease-attempt", IdempotencyKey: "lease-key",
				RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", FencingToken: 1, ExpectedGeneration: 1, Deadline: now.Add(time.Minute)}, ExtendSeconds: 60}
			op := lifecycle.Operation{ID: req.OperationID, AttemptID: req.AttemptID, IdempotencyKey: req.IdempotencyKey, RequestDigest: req.RequestDigest,
				FencingToken: req.FencingToken, Deadline: req.Deadline, SandboxID: "sandbox-1", Type: lifecycle.OperationExtendLease, State: lifecycle.OperationSucceeded}
			switch name {
			case "kind":
				op.Type = lifecycle.OperationTerminate
			case "deadline":
				req.Deadline = req.Deadline.Add(time.Second)
			case "invalid extension":
				req.ExtendSeconds = 0
			case "expired":
				req.Deadline = now
				op.Deadline = now
			}
			repo := &codingTrapRepository{operation: op, sandbox: lifecycle.Sandbox{ID: op.SandboxID}}
			probe := &leaseRouteProbe{}
			c, err := NewWithCodingOriginalAuthorityAndLease(repo, &codingTrapDriver{}, &codingReadbackProbe{}, &terminationRouteProbe{}, probe, &testClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := c.AcceptLease(t.Context(), op.SandboxID, req, 7200); err == nil || probe.calls != 0 {
				t.Fatalf("%s replay bypassed typed request checks: %#v %v", name, result, err)
			}
		})
	}
}
