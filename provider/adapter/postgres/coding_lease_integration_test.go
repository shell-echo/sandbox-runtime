//go:build integration

package providerpostgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

type codingPGLeaseGateRepository struct {
	*CodingLifecycleRepository
	gate *codingPGReadGate
}

func (r *codingPGLeaseGateRepository) GetSandbox(ctx context.Context, id string) (lifecycle.Sandbox, error) {
	sb, err := r.CodingLifecycleRepository.GetSandbox(ctx, id)
	n := r.gate.calls.Add(1)
	if n <= 2 {
		if n == 2 {
			close(r.gate.ready)
		}
		select {
		case <-r.gate.ready:
		case <-ctx.Done():
			return lifecycle.Sandbox{}, ctx.Err()
		}
	}
	return sb, err
}

// Real disposable PG, synthetic create/termination Control. Lease completion
// itself requires no Control call. Two pools race one exact request.
func exerciseCodingLeasePG(t *testing.T, ctx context.Context, store *Store, plan codingidentity.Plan, specs map[string]string, policy string) {
	t.Helper()
	pool, err := pgxpool.NewWithConfig(ctx, store.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	other, err := New(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewCodingLifecycleRepositoryWithPolicy(store, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCodingLifecycleRepositoryWithPolicy(other, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	control := &codingPGTerminationControl{}
	makeCoordinator := func(repo lifecyclecoordinator.CodingOriginalCreateRepository, owner *CodingLifecycleRepository) *lifecyclecoordinator.Coordinator {
		expected := codingcontrol.Expected{ProfileDigest: plan.ProfileDigest, ControlPolicyDigest: policy, ProviderPrincipalDigest: plan.OwnerPrincipalDigest}
		read, err := codingcontrol.NewCreateReadback(owner, control, codingPGRealClock{}, expected)
		if err != nil {
			t.Fatal(err)
		}
		term, err := codingcontrol.NewTerminationReconciler(owner, control, control, codingPGRealClock{}, expected)
		if err != nil {
			t.Fatal(err)
		}
		c, err := lifecyclecoordinator.NewWithCodingOriginalAuthorityAndLease(repo, codingPGNoLegacyDriver{}, read, term, owner, codingPGRealClock{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := makeCoordinator(a, a)
	now := time.Now().UTC()
	request := codingIntegrationRequest(now, 94)
	if _, err := c.AcceptCreate(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := a.BeginCodingFirstCreateWithAuthority(ctx, request.OperationID); err != nil {
		t.Fatal(err)
	}
	ready, err := c.ReconcileOperation(ctx, request.OperationID)
	if err != nil || ready.Operation.State != lifecycle.OperationSucceeded {
		t.Fatalf("ready: %#v %v", ready, err)
	}
	sb := ready.Sandbox
	lease := lifecycle.LeaseRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "lease-pg-94", AttemptID: "lease-pg-attempt-94", IdempotencyKey: "lease-pg-key-94",
		RequestDigest: codingTestDigest("3"), ExpectedGeneration: sb.Generation, FencingToken: request.FencingToken + 1, Deadline: time.Now().UTC().Add(time.Minute)}, ExtendSeconds: 60}
	gate := &codingPGReadGate{ready: make(chan struct{})}
	ca := makeCoordinator(&codingPGLeaseGateRepository{a, gate}, a)
	cb := makeCoordinator(&codingPGLeaseGateRepository{b, gate}, b)
	_, revision := codingPGSnapshot(t, ctx, store)
	observes := control.observes.Load()
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, caller := range []*lifecyclecoordinator.Coordinator{ca, cb} {
		wg.Add(1)
		go func(caller *lifecyclecoordinator.Coordinator) {
			defer wg.Done()
			result, err := caller.AcceptLease(ctx, sb.ID, lease, 7200)
			if err == nil && (result.Operation.State != lifecycle.OperationSucceeded || result.Sandbox.Generation != sb.Generation || !result.Sandbox.LeaseExpiresAt.Equal(sb.LeaseExpiresAt.Add(time.Minute))) {
				t.Error("atomic lease result not complete")
			}
			errs <- err
		}(caller)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	state, after := codingPGSnapshot(t, ctx, store)
	if after != revision+1 {
		t.Fatalf("one admission/completion committed %d revisions", after-revision)
	}
	// A fresh repository/coordinator proves reconstruction from durable state.
	reopened, err := NewCodingLifecycleRepositoryWithPolicy(other, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, caller := range []*lifecyclecoordinator.Coordinator{ca, cb, makeCoordinator(reopened, reopened)} {
		replay, replayErr := caller.AcceptLease(ctx, sb.ID, lease, 7200)
		if replayErr != nil || !replay.Replayed || replay.Operation.State != lifecycle.OperationSucceeded {
			t.Fatalf("typed POST replay: %#v %v", replay, replayErr)
		}
		result, err := caller.ReconcileOperation(ctx, lease.OperationID)
		if err != nil || result.Dispatched || result.Operation.State != lifecycle.OperationSucceeded {
			t.Fatalf("lease readback: %#v %v", result, err)
		}
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != after || control.sends.Load() != 0 || control.observes.Load() != observes {
		t.Fatal("lease recovery wrote PG or invoked Control")
	}
	term := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "lease-terminate-94", AttemptID: "lease-terminate-attempt-94", IdempotencyKey: "lease-terminate-key-94",
		RequestDigest: codingTestDigest("4"), ExpectedGeneration: sb.Generation, FencingToken: lease.FencingToken + 1, Deadline: time.Now().UTC().Add(time.Minute)}, Reason: "lease component cleanup"}
	if _, err := c.AcceptTerminate(ctx, sb.ID, term); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReconcileOperation(ctx, term.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReconcileOperation(ctx, term.OperationID); err != nil {
		t.Fatal(err)
	}
	state, after = codingPGSnapshot(t, ctx, store)
	observes = control.observes.Load()
	if result, err := c.ReconcileOperation(ctx, lease.OperationID); err != nil || result.Operation.State != lifecycle.OperationSucceeded || result.Sandbox.ObservedState != lifecycle.ObservedTerminated {
		t.Fatalf("released lease history: %#v %v", result, err)
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != after || control.observes.Load() != observes {
		t.Fatal("historical lease read rewrote released state")
	}
}
