//go:build integration

package providerpostgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
)

// Runs inside the existing owned disposable PG harness. The observation is
// synthetic; only real transaction/concurrency/restart behavior is claimed.
func exerciseCodingReadyPG(t *testing.T, ctx context.Context, a, b *Store, plan codingidentity.Plan, specs map[string]string, policy string, original dockercontrol.CodingCreateAuthority) {
	t.Helper()
	ownerA, err := NewCodingLifecycleRepositoryWithPolicy(a, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := NewCodingLifecycleRepositoryWithPolicy(b, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	makeService := func(repo *CodingLifecycleRepository) *codingcontrol.CreateCoordinator {
		s, err := codingcontrol.NewCreateReadback(repo, codingPGFakeObserver{}, codingPGRealClock{}, codingcontrol.Expected{ProfileDigest: plan.ProfileDigest, ControlPolicyDigest: policy, ProviderPrincipalDigest: plan.OwnerPrincipalDigest})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	serviceA, serviceB := makeService(ownerA), makeService(ownerB)
	before, revision := codingPGSnapshot(t, ctx, a)
	sb, err := ownerA.GetSandbox(ctx, original.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := lifecycle.ApplyObservedTransition(sb, lifecycle.ObservedReady, sb.Generation, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if ownerA.UpdateSandbox(ctx, ready, sb.Generation, original.Fence) == nil {
		t.Fatal("generic PG readiness bypass")
	}
	if after, next := codingPGSnapshot(t, ctx, b); after != before || next != revision {
		t.Fatal("denied generic Ready changed PG")
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, service := range []*codingcontrol.CreateCoordinator{serviceA, serviceB} {
		wait.Add(1)
		go func(s *codingcontrol.CreateCoordinator) {
			defer wait.Done()
			<-start
			op, sandbox, err := s.ReconcileCodingCreate(ctx, original.OperationID)
			if err == nil && (op.State != lifecycle.OperationSucceeded || sandbox.ObservedState != lifecycle.ObservedReady) {
				t.Error("wrong committed readiness")
			}
			results <- err
		}(service)
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	after, next := codingPGSnapshot(t, ctx, a)
	if after == before || next != revision+1 {
		t.Fatalf("Ready race committed %d revisions", next-revision)
	}
	if _, _, err := serviceB.ReconcileCodingCreate(ctx, original.OperationID); err != nil {
		t.Fatal(err)
	}
	if repeated, repeatRevision := codingPGSnapshot(t, ctx, a); repeated != after || repeatRevision != next {
		t.Fatal("repeat Ready wrote PG revision")
	}
	slots, err := readState(ctx, a, codingIdentityStateDocument, func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || slots.Validate(plan) != nil || slots.Reservations[0].Status != codingidentity.Active || slots.CreateCompletions[original.AllocationID].AuthorityDigest != original.Digest() {
		t.Fatalf("PG readiness evidence: %v", err)
	}
	// The parent harness next terminates, cleans, restarts PG and reuses the
	// slot. This history must survive all those existing real-row checks.
}
