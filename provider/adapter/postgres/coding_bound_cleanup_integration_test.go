//go:build integration

package providerpostgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

type codingCleanupPGOutcome struct {
	create        dockercontrol.CodingCreateAuthority
	authority     dockercontrol.CodingCleanupAuthority
	terminationID string
}

// This is one PG-only batch in the existing disposable PostgreSQL container.
// The Completed receipt is explicitly synthetic test input: it does not
// authenticate a production Control process or authorize any Docker action.
func exerciseCodingCurrentCleanupPG(t *testing.T, ctx context.Context,
	storeA, storeB *Store, ticket codingidentity.Reservation) codingCleanupPGOutcome {
	t.Helper()
	plan := codingBoundTestPlan()
	specs := codingBoundSpecs(plan)
	ownerA, err := NewCodingLifecycleRepository(storeA, plan, specs)
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := NewCodingLifecycleRepository(storeB, plan, specs)
	if err != nil {
		t.Fatal(err)
	}
	createOperation, err := ownerA.GetOperation(ctx, ticket.Claim.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err := ownerA.GetSandbox(ctx, ticket.Claim.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Now().UTC()
	create, err := dockercontrol.NewCodingCreateAuthority(ctx, ticket, createOperation,
		provisioning, plan, codingTestDigest("f"), plan.OwnerPrincipalDigest, issuedAt)
	if err != nil {
		t.Fatalf("construct original PG-bound create authority: %v", err)
	}
	unknown, err := lifecycle.MarkOutcomeUnknown(createOperation, time.Now().UTC(),
		lifecycle.Failure{Code: "create_result_lost", Retryable: true, Outcome: lifecycle.FailureUnknown})
	if err != nil || ownerA.UpdateOperation(ctx, unknown) != nil {
		t.Fatalf("retain historical Unknown create: %v", err)
	}
	accepted := make([]lifecycle.Operation, 0, 2)
	current := provisioning
	for index := 1; index <= 2; index++ {
		at := time.Now().UTC()
		request := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{
			OperationID:  fmt.Sprintf("coding-cleanup-operation-%d", index),
			AttemptID:    fmt.Sprintf("coding-cleanup-attempt-%d", index),
			FencingToken: create.Fence, IdempotencyKey: fmt.Sprintf("coding-cleanup-key-%d", index),
			RequestDigest: codingTestDigest(fmt.Sprintf("%d", index)), Deadline: at.Add(time.Minute),
			ExpectedGeneration: current.Generation}, Reason: "PG-only current cleanup witness"}
		updated, operation, startErr := lifecycle.StartTerminate(current, request, at)
		if startErr != nil {
			t.Fatal(startErr)
		}
		event := lifecycle.Event{ID: fmt.Sprintf("coding-cleanup-requested-%d", index),
			SandboxID: updated.ID, OperationID: operation.ID, Generation: updated.Generation,
			FencingToken: operation.FencingToken, Kind: "termination-requested",
			DataDigest: request.RequestDigest, OccurredAt: at}
		if _, err := ownerA.ReserveMutation(ctx, request.IdempotencyKey, request.RequestDigest,
			request.ExpectedGeneration, updated, operation, event); err != nil {
			t.Fatalf("reserve current terminate %d: %v", index, err)
		}
		accepted = append(accepted, operation)
		current = updated
	}
	if current.Generation <= create.CreationGeneration || accepted[0].FencingToken != create.Fence ||
		accepted[1].FencingToken != create.Fence {
		t.Fatal("same-fence repeated terminate fixture is invalid")
	}
	completed := dockercontrol.CodingReceipt{Authority: create, AuthorityDigest: create.Digest(),
		Status: dockercontrol.ReceiptCompleted, CompletionDigest: codingTestDigest("8"),
		CompletionEvidenceDigest: codingTestDigest("9"), UpdatedAt: time.Now().UTC()}
	base := codingCleanupAdmission{Create: create, Completed: completed, ControlRevision: 3,
		ControlStateDigest: codingTestDigest("a"), ControlPolicyDigest: create.ControlPolicyDigest,
		PeerPrincipalDigest: plan.OwnerPrincipalDigest, SpecBySlot: specs}
	first, second := base, base
	first.TerminationID = accepted[0].ID
	second.TerminationID = accepted[1].ID
	beforeSlots, err := readState(ctx, storeA, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil {
		t.Fatal(err)
	}
	bad := first
	bad.Completed.Status = dockercontrol.ReceiptUnknown
	if _, err := attemptCodingCleanupPG(ctx, storeA, plan, bad, nil); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("Control Unknown obtained PG permit: %v", err)
	}
	bad = first
	bad.Create.AllocationID = "codingalloc-" + codingTestDigest("0")[7:]
	if _, err := attemptCodingCleanupPG(ctx, storeB, plan, bad, nil); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("stale/new-occupant allocation obtained PG permit: %v", err)
	}
	// Inject a failure after the terminating event was appended to the
	// transaction-local ledger. Neither the event nor Cleaning may commit.
	injected := errors.New("injected post-event PG write abort")
	if _, err := attemptCodingCleanupPG(ctx, storeA, plan, first,
		func() error { return injected }); !errors.Is(err, injected) {
		t.Fatalf("post-event rollback did not surface: %v", err)
	}
	unchanged, err := readState(ctx, storeB, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || len(unchanged.Retirements) != 0 ||
		unchanged.Reservations[0].Status != beforeSlots.Reservations[0].Status {
		t.Fatalf("aborted PG write retained a cleanup slot: %#v, %v", unchanged, err)
	}
	if events, err := ownerB.ListEvents(ctx, create.SandboxID, 0, 20); err != nil || len(events) != 3 {
		t.Fatalf("aborted PG write retained a terminating event: %#v, %v", events, err)
	}
	// A separate client holds the single authority row. The shorter caller
	// deadline must win over Store's normal operation timeout, without writes.
	lockTx, err := storeA.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		_ = lockTx.Rollback(ctx)
		t.Fatal(err)
	}
	shortCtx, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	_, lockedErr := attemptCodingCleanupPG(shortCtx, storeB, plan, first, nil)
	cancel()
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(lockedErr, context.DeadlineExceeded) {
		t.Fatalf("PG row-lock wait ignored caller deadline: %v", lockedErr)
	}
	var wait sync.WaitGroup
	type result struct {
		id        string
		authority dockercontrol.CodingCleanupAuthority
		err       error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for _, candidate := range []struct {
		store *Store
		input codingCleanupAdmission
	}{{storeA, first}, {storeB, second}} {
		wait.Add(1)
		go func(store *Store, input codingCleanupAdmission) {
			defer wait.Done()
			<-start
			authority, err := attemptCodingCleanupPG(ctx, store, plan, input, nil)
			results <- result{input.TerminationID, authority, err}
		}(candidate.store, candidate.input)
	}
	close(start)
	wait.Wait()
	close(results)
	var winner result
	successes := 0
	for candidate := range results {
		if candidate.err == nil {
			successes++
			winner = candidate
		} else if !errors.Is(candidate.err, codingidentity.ErrConflict) {
			t.Fatalf("same-fence competing PG client failed unexpectedly: %v", candidate.err)
		}
	}
	if successes != 1 || winner.authority.CleanupFence != create.Fence {
		t.Fatalf("same-fence PG permits=%d, winner=%#v", successes, winner)
	}
	if _, err := attemptCodingCleanupPG(ctx, storeB, plan, first, nil); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("replay opened a second PG permit: %v", err)
	}
	if original, err := ownerB.GetOperation(ctx, create.OperationID); err != nil ||
		original.State != lifecycle.OperationOutcomeUnknown {
		t.Fatalf("cleanup rewrote historical create outcome: %#v, %v", original, err)
	}
	if events, err := ownerA.ListEvents(ctx, create.SandboxID, 0, 20); err != nil ||
		len(events) != 4 || events[3].Kind != "terminating" || events[3].OperationID != winner.id {
		t.Fatalf("PG terminating event not exactly once: %#v, %v", events, err)
	}
	// Simulate a lost success response: the second client gets only the
	// durable exact envelope, never a newly issued authority/expiry.
	readback, err := ownerB.ReadCodingCleanupEnvelope(ctx, create, winner.id, create.ControlPolicyDigest)
	if err != nil || readback != winner.authority {
		t.Fatalf("PG response-loss readback changed authority: %#v, %v", readback, err)
	}
	return codingCleanupPGOutcome{create: create, authority: readback, terminationID: winner.id}
}

func attemptCodingCleanupPG(ctx context.Context, store *Store, plan codingidentity.Plan,
	input codingCleanupAdmission, afterEvent func() error) (dockercontrol.CodingCleanupAuthority, error) {
	planDigest, err := plan.Digest()
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	var authority dockercontrol.CodingCleanupAuthority
	err = mutateStateTriple(ctx, store,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() identityMarker { return identityMarker{} }, importIdentityMarker,
		func(marker identityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *identityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			if !marker.Initialized || marker.PlanDigest != planDigest {
				return codingidentity.ErrInvalidState
			}
			var beginErr error
			authority, _, _, _, beginErr = beginCodingCurrentCleanup(ctx, slots, ledger,
				plan, input, time.Now().UTC())
			if beginErr != nil {
				return beginErr
			}
			if afterEvent != nil {
				return afterEvent()
			}
			return nil
		})
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	return authority, nil
}
