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

type codingFinalReleasePGOutcome struct {
	newTicket     codingidentity.Reservation
	terminationID string
	createID      string
}

// One more PG-only scenario group runs inside the already-started disposable
// PostgreSQL container. The Released receipt is synthetic test input, not a
// Control mTLS attestation or evidence of a real Coding Docker deletion.
func exerciseCodingFinalReleasePG(t *testing.T, ctx context.Context,
	storeA, storeB *Store, cleanup codingCleanupPGOutcome) codingFinalReleasePGOutcome {
	t.Helper()
	plan := codingBoundTestPlan()
	specs := codingBoundSpecs(plan)
	released := dockercontrol.CodingReceipt{Authority: cleanup.create,
		AuthorityDigest: cleanup.create.Digest(), Status: dockercontrol.ReceiptReleased,
		CompletionDigest: codingTestDigest("8"), CompletionEvidenceDigest: codingTestDigest("9"),
		CleanupAuthority: cleanup.authority, AbsenceDigest: codingTestDigest("4"),
		AbsenceEvidenceDigest: codingTestDigest("5"),
		UpdatedAt:             cleanup.authority.IssuedAt.Add(time.Millisecond)}
	input := codingReleaseAdmission{Create: cleanup.create, Cleanup: cleanup.authority,
		Released: released, ControlRevision: 5, ControlStateDigest: codingTestDigest("b"),
		SpecBySlot: specs}
	before, err := readState(ctx, storeA, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || before.Reservations[0].Status != codingidentity.Cleaning {
		t.Fatalf("PG release fixture is not Cleaning: %#v, %v", before, err)
	}
	// A genuinely higher current highwater in a transaction-local PG copy
	// rejects the old permit. The deliberate abort rolls the temporary drift
	// back, allowing the later valid release to use the same disposable row.
	err = mutateStateTriple(ctx, storeA,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() identityMarker { return identityMarker{} }, importIdentityMarker,
		func(marker identityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(_ *identityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			scope := cleanup.create.ProviderRevisionID + "\x00" + cleanup.create.SandboxID
			ledger.Fencing[scope]++
			lease := ledger.Leases[cleanup.create.SandboxID]
			lease.FencingToken++
			ledger.Leases[cleanup.create.SandboxID] = lease
			if _, _, releaseErr := finishCodingCurrentCleanup(ctx, slots, ledger, plan,
				input, time.Now().UTC()); !errors.Is(releaseErr, codingidentity.ErrConflict) {
				return fmt.Errorf("higher-fence old intent was admitted: %v", releaseErr)
			}
			return codingidentity.ErrConflict
		})
	if !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("higher-fence PG transaction did not abort: %v", err)
	}
	// Inject an error after the terminated event is appended to decoded
	// transaction-local documents. The SQL row must retain Cleaning/Running.
	injected := errors.New("injected post-event final-release abort")
	if err := attemptCodingFinalReleasePG(ctx, storeA, plan, input,
		func() error { return injected }); !errors.Is(err, injected) {
		t.Fatalf("final-release event rollback did not surface: %v", err)
	}
	unchanged, err := readState(ctx, storeB, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || unchanged.Reservations[0].Status != codingidentity.Cleaning ||
		len(unchanged.Retirements) != 1 {
		t.Fatalf("failed final PG commit released slot: %#v, %v", unchanged, err)
	}
	// Hold the single authority row from one real connection. The other
	// connection must obey its shorter parent deadline and not mutate state.
	lockTx, err := storeA.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		_ = lockTx.Rollback(ctx)
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	lockedErr := attemptCodingFinalReleasePG(short, storeB, plan, input, nil)
	cancel()
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(lockedErr, context.DeadlineExceeded) {
		t.Fatalf("final PG CAS row-lock wait ignored caller deadline: %v", lockedErr)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := attemptCodingFinalReleasePG(canceled, storeB, plan, input, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled final PG CAS admitted: %v", err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, store := range []*Store{storeA, storeB} {
		wait.Add(1)
		go func(store *Store) {
			defer wait.Done()
			<-start
			results <- attemptCodingFinalReleasePG(ctx, store, plan, input, nil)
		}(store)
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result == nil {
			successes++
		} else if !errors.Is(result, codingidentity.ErrConflict) {
			t.Fatalf("final release contender failed unexpectedly: %v", result)
		}
	}
	if successes != 1 {
		t.Fatalf("final PG release permits=%d, want exactly one", successes)
	}
	// Simulate a lost successful response by discarding it and reading only
	// durable PG state from the other connection. This is not COMMIT packet
	// loss or an injected network fault.
	identity, err := readState(ctx, storeB, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || len(identity.Retirements) != 0 || len(identity.Reservations) != 1 ||
		identity.Reservations[0].Slot.ID == cleanup.create.SlotID {
		t.Fatalf("final release response-loss PG readback: %#v, %v", identity, err)
	}
	ledger, err := readState(ctx, storeB, lifecycleDocument, newLifecycleState, importLifecycleState)
	if err != nil {
		t.Fatal(err)
	}
	terminated, err := ledger.GetSandbox(cleanup.create.SandboxID)
	if err != nil || terminated.ObservedState != lifecycle.ObservedTerminated {
		t.Fatalf("final release did not atomically terminate: %#v, %v", terminated, err)
	}
	current, err := ledger.GetOperation(cleanup.terminationID)
	if err != nil || current.State != lifecycle.OperationOutcomeUnknown {
		t.Fatalf("final release did not retain terminate result: %#v, %v", current, err)
	}
	original, err := ledger.GetOperation(cleanup.create.OperationID)
	if err != nil || original.State != lifecycle.OperationOutcomeUnknown {
		t.Fatalf("final release rewrote historical create Unknown: %#v, %v", original, err)
	}
	if err := attemptCodingFinalReleasePG(ctx, storeA, plan, input, nil); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("final release replayed: %v", err)
	}
	// A genuine later PG occupant of the released finite slot is created by
	// the normal first-create transaction. The old Released proof must fail
	// against that new claim, not merely against a tampered input document.
	request := codingIntegrationRequest(time.Now().UTC(), 3)
	sandbox, operation, err := lifecycle.StartCreate(request, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	lifecycleRepo, _ := NewLifecycleRepository(storeA)
	if _, err := lifecycleRepo.ReserveCreate(ctx, request.IdempotencyKey,
		request.RequestDigest, sandbox, operation); err != nil {
		t.Fatal(err)
	}
	bound, err := NewCodingBoundCreateRepository(storeA, plan)
	if err != nil {
		t.Fatal(err)
	}
	newTicket, _, _, err := bound.BeginFirstCreate(ctx, request.OperationID, specs)
	if err != nil || newTicket.Slot.ID != cleanup.create.SlotID ||
		newTicket.Claim.AllocationID == cleanup.create.AllocationID {
		t.Fatalf("new PG occupant not on released slot: %#v, %v", newTicket, err)
	}
	if err := attemptCodingFinalReleasePG(ctx, storeB, plan, input, nil); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("old release proof displaced genuine new occupant: %v", err)
	}
	return codingFinalReleasePGOutcome{newTicket: newTicket,
		terminationID: cleanup.terminationID, createID: cleanup.create.OperationID}
}

func attemptCodingFinalReleasePG(ctx context.Context, store *Store, plan codingidentity.Plan,
	input codingReleaseAdmission, afterEvent func() error) error {
	planDigest, err := plan.Digest()
	if err != nil {
		return err
	}
	return mutateStateTriple(ctx, store,
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
			if _, _, err := finishCodingCurrentCleanup(ctx, slots, ledger,
				plan, input, time.Now().UTC()); err != nil {
				return err
			}
			if afterEvent != nil {
				return afterEvent()
			}
			return nil
		})
}
