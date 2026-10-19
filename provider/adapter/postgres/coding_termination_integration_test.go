//go:build integration

package providerpostgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

type codingPGTerminationControl struct{ sends, observes atomic.Int64 }

func (c *codingPGTerminationControl) Observe(ctx context.Context, q codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	c.observes.Add(1)
	return (codingPGFakeObserver{}).Observe(ctx, q)
}
func (c *codingPGTerminationControl) DispatchCodingCleanupAuthority(context.Context, dockercontrol.CodingCreateAuthority, dockercontrol.CodingCleanupAuthority) error {
	c.sends.Add(1)
	return nil
}

type codingPGNoLegacyDriver struct{}

func (codingPGNoLegacyDriver) Create(context.Context, lifecycle.Sandbox) error {
	return errors.New("unexpected legacy Create")
}
func (codingPGNoLegacyDriver) Inspect(context.Context, string) (lifecyclecoordinator.RuntimeObservation, error) {
	return lifecyclecoordinator.RuntimeObservation{}, errors.New("unexpected legacy Inspect")
}
func (codingPGNoLegacyDriver) DispatchCodingCreateAuthority(context.Context, dockercontrol.CodingCreateAuthority) error {
	return errors.New("unexpected create redispatch")
}

type codingPGReadGate struct {
	calls atomic.Int64
	ready chan struct{}
}
type codingPGGatedTerminationRepository struct {
	*CodingLifecycleRepository
	gate *codingPGReadGate
}

func (r *codingPGGatedTerminationRepository) ReadTermination(ctx context.Context, id string) (lifecycle.Operation, lifecycle.Sandbox, error) {
	op, sb, err := r.CodingLifecycleRepository.ReadTermination(ctx, id)
	n := r.gate.calls.Add(1)
	if n <= 2 {
		if n == 2 {
			close(r.gate.ready)
		}
		select {
		case <-r.gate.ready:
		case <-ctx.Done():
			return lifecycle.Operation{}, lifecycle.Sandbox{}, ctx.Err()
		}
	}
	return op, sb, err
}

// Disposable real PG, but synthetic Control responses/dispatch. This does not
// claim production TLS/CRL, physical cleanup or actual COMMIT packet loss.
func exerciseCodingTerminationPG(t *testing.T, ctx context.Context, store *Store, plan codingidentity.Plan, specs map[string]string, policy string) {
	t.Helper()
	// A separate connection pool is opened with the same disposable runtime
	// identity; no shared/production database configuration is accepted here.
	pool, err := pgxpool.NewWithConfig(ctx, store.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	other, err := New(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ownerA, err := NewCodingLifecycleRepositoryWithPolicy(store, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := NewCodingLifecycleRepositoryWithPolicy(other, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	control := &codingPGTerminationControl{}
	gate := &codingPGReadGate{ready: make(chan struct{})}
	makeCoordinator := func(owner *CodingLifecycleRepository) *lifecyclecoordinator.Coordinator {
		expected := codingcontrol.Expected{ProfileDigest: plan.ProfileDigest, ControlPolicyDigest: policy, ProviderPrincipalDigest: plan.OwnerPrincipalDigest}
		readback, err := codingcontrol.NewCreateReadback(owner, control, codingPGRealClock{}, expected)
		if err != nil {
			t.Fatal(err)
		}
		termination, err := codingcontrol.NewTerminationReconciler(&codingPGGatedTerminationRepository{owner, gate}, control, control, codingPGRealClock{}, expected)
		if err != nil {
			t.Fatal(err)
		}
		c, err := lifecyclecoordinator.NewWithCodingOriginalAuthorityAndTermination(owner, codingPGNoLegacyDriver{}, readback, termination, codingPGRealClock{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a, b := makeCoordinator(ownerA), makeCoordinator(ownerB)
	now := time.Now().UTC()
	request := codingIntegrationRequest(now, 93)
	if _, err := a.AcceptCreate(ctx, request); err != nil {
		t.Fatal(err)
	}
	_, _, sb, original, err := ownerA.BeginCodingFirstCreateWithAuthority(ctx, request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	term := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "coding-termination-route-93", AttemptID: "coding-termination-route-attempt-93", IdempotencyKey: "coding-termination-route-key-93", RequestDigest: codingTestDigest("3"), FencingToken: original.Fence, ExpectedGeneration: sb.Generation, Deadline: now.Add(time.Minute)}, Reason: "typed route PG component"}
	if _, err := a.AcceptTerminate(ctx, sb.ID, term); err != nil {
		t.Fatal(err)
	}
	_, before := codingPGSnapshot(t, ctx, store)
	var wg sync.WaitGroup
	for _, c := range []*lifecyclecoordinator.Coordinator{a, b} {
		wg.Add(1)
		go func(c *lifecyclecoordinator.Coordinator) {
			defer wg.Done()
			_, _ = c.ReconcileOperation(ctx, term.OperationID)
		}(c)
	}
	wg.Wait()
	if control.sends.Load() != 1 {
		t.Fatalf("fresh admission dispatched %d times", control.sends.Load())
	}
	_, after := codingPGSnapshot(t, ctx, store)
	if after != before+2 {
		t.Fatalf("admission + ACK committed %d revisions", after-before)
	}
	for _, c := range []*lifecyclecoordinator.Coordinator{a, b} {
		wg.Add(1)
		go func(c *lifecyclecoordinator.Coordinator) {
			defer wg.Done()
			_, _ = c.ReconcileOperation(ctx, term.OperationID)
		}(c)
	}
	wg.Wait()
	state, finalRevision := codingPGSnapshot(t, ctx, store)
	if finalRevision != after+1 {
		t.Fatalf("release committed %d revisions", finalRevision-after)
	}
	observes := control.observes.Load()
	for _, c := range []*lifecyclecoordinator.Coordinator{a, b} {
		got, err := c.ReconcileOperation(ctx, term.OperationID)
		if err != nil || got.Dispatched || got.Operation.State != lifecycle.OperationSucceeded || got.Sandbox.ObservedState != lifecycle.ObservedTerminated {
			t.Fatalf("retained termination: %#v %v", got, err)
		}
	}
	if current, revision := codingPGSnapshot(t, ctx, store); current != state || revision != finalRevision || control.sends.Load() != 1 || control.observes.Load() != observes {
		t.Fatal("terminal read changed PG or called Control")
	}
}
