//go:build integration

package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

func codingPGSnapshot(t *testing.T, ctx context.Context, store *Store) (string, int64) {
	t.Helper()
	var document string
	var revision int64
	if err := store.pool.QueryRow(ctx, `SELECT documents::text,revision FROM sandbox_runtime_provider.control_state WHERE singleton`).
		Scan(&document, &revision); err != nil {
		t.Fatal(err)
	}
	return document, revision
}

// This is one matrix inside the already-owned disposable PG harness. No
// Control process, Docker workload, or physical absence is inferred here.
func exerciseCodingRetirementBarrierPG(t *testing.T, ctx context.Context,
	storeA, storeB *Store, cleanup codingCleanupPGOutcome) {
	t.Helper()
	ownerA, err := NewLifecycleRepository(storeA)
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := NewLifecycleRepository(storeB)
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := ownerB.GetSandbox(ctx, cleanup.create.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ownerB.GetOperation(ctx, cleanup.terminationID)
	if err != nil || current.State != lifecycle.OperationRunning {
		t.Fatalf("retirement-first fixture operation: %#v, %v", current, err)
	}
	now := time.Now().UTC()
	guard, err := NewAdmissionGuard(storeA, fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	guardRequest := admission.MutationGuardRequest{
		ProviderRevisionID: sandbox.ProviderRevisionID, SandboxID: sandbox.ID,
		OperationID: "coding-barrier-higher-fence", AttemptID: "coding-barrier-higher-attempt",
		FencingToken:   int64(current.FencingToken + 1),
		JTIFingerprint: sha256.Sum256([]byte("coding-barrier-consumed-jti")),
		ExpiresAt:      now.Add(time.Minute)}
	if decision, err := guard.Reserve(ctx, guardRequest); err != nil || decision != admission.MutationGuardAccepted {
		t.Fatalf("independent higher-fence JTI admission: %v, %v", decision, err)
	}
	before, revision := codingPGSnapshot(t, ctx, storeB)
	request := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{
		OperationID: guardRequest.OperationID, AttemptID: guardRequest.AttemptID,
		FencingToken: uint64(guardRequest.FencingToken), IdempotencyKey: "coding-barrier-higher-key",
		RequestDigest: codingTestDigest("d"), Deadline: now.Add(time.Minute),
		ExpectedGeneration: sandbox.Generation}, Reason: "barrier conflict"}
	updated, accepted, err := lifecycle.StartTerminate(sandbox, request, now)
	if err != nil {
		t.Fatal(err)
	}
	event := lifecycle.Event{ID: "coding-barrier-higher-event", SandboxID: sandbox.ID,
		OperationID: accepted.ID, Generation: updated.Generation,
		FencingToken: accepted.FencingToken, Kind: "termination-requested", OccurredAt: now}
	if _, err := ownerB.ReserveMutation(ctx, request.IdempotencyKey, request.RequestDigest,
		request.ExpectedGeneration, updated, accepted, event); !errors.Is(err, lifecyclerepository.ErrRetirementBlocked) {
		t.Fatalf("retirement-first higher fence advanced: %v", err)
	}
	if after, nextRevision := codingPGSnapshot(t, ctx, storeA); after != before || nextRevision != revision {
		t.Fatal("blocked higher fence changed durable PG row")
	}
	if decision, err := guard.Reserve(ctx, guardRequest); err != nil || decision != admission.MutationGuardReplayed {
		t.Fatalf("blocked lifecycle write rewound consumed JTI: %v, %v", decision, err)
	}
	staleJTI := guardRequest
	staleJTI.JTIFingerprint = sha256.Sum256([]byte("coding-barrier-stale-jti"))
	staleJTI.FencingToken--
	if decision, err := guard.Reserve(ctx, staleJTI); err != nil || decision != admission.MutationGuardStaleFencing {
		t.Fatalf("blocked lifecycle write lowered admission highwater: %v, %v", decision, err)
	}
	lease, err := ownerA.GetLease(ctx, sandbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	lease.ExpiresAt = lease.ExpiresAt.Add(time.Minute)
	if err := ownerB.ReplaceLease(ctx, lease, current.FencingToken); !errors.Is(err, lifecyclerepository.ErrRetirementBlocked) {
		t.Fatalf("retirement-first lease advanced: %v", err)
	}
	succeeded, err := lifecycle.SucceedOperation(current, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ownerA.UpdateOperation(ctx, succeeded); !errors.Is(err, lifecyclerepository.ErrRetirementBlocked) {
		t.Fatalf("retirement-first terminal flip advanced: %v", err)
	}
	if replay, err := ownerB.ReserveMutation(ctx, current.IdempotencyKey, current.RequestDigest,
		sandbox.Generation, sandbox, func() lifecycle.Operation { copy := current; copy.State = lifecycle.OperationAccepted; return copy }(),
		lifecycle.Event{ID: "coding-barrier-replay-event", SandboxID: sandbox.ID,
			OperationID: current.ID, Generation: sandbox.Generation,
			FencingToken: current.FencingToken, Kind: "termination-requested", OccurredAt: now}); err != nil || !replay.Replayed {
		t.Fatalf("exact same-attempt replay blocked: %#v, %v", replay, err)
	}
	unknown, err := lifecycle.MarkOutcomeUnknown(current, now,
		lifecycle.Failure{Code: "control_response_lost", Retryable: true, Outcome: lifecycle.FailureUnknown})
	if err != nil || ownerA.UpdateOperation(ctx, unknown) != nil {
		t.Fatalf("same terminate Unknown blocked: %v", err)
	}
	sum := sha256.Sum256([]byte(unknown.ID + "\x00" + string(unknown.State) + "\x00outcome-unknown"))
	unknownEvent := lifecycle.Event{ID: "event-" + hex.EncodeToString(sum[:]),
		SandboxID: sandbox.ID, OperationID: unknown.ID, Generation: sandbox.Generation,
		FencingToken: unknown.FencingToken, Kind: "outcome-unknown", OccurredAt: now}
	if _, err := ownerB.AppendEvent(ctx, unknownEvent); err != nil {
		t.Fatalf("matching current Unknown event blocked: %v", err)
	}
	if _, err := ownerA.AppendEvent(ctx, unknownEvent); err != nil {
		t.Fatalf("identical current Unknown event replay blocked: %v", err)
	}
	// The other Coding allocation has no retirement and remains writable.
	other, err := ownerB.GetSandbox(ctx, "coding-sandbox-2")
	if err != nil {
		t.Fatal(err)
	}
	otherLease, err := ownerA.GetLease(ctx, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherLease.ExpiresAt = otherLease.ExpiresAt.Add(time.Minute)
	if err := ownerB.ReplaceLease(ctx, otherLease, otherLease.FencingToken); err != nil {
		t.Fatalf("unrelated sandbox was blocked: %v", err)
	}
	retained, err := readState(ctx, storeA, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || retained.Retirements[cleanup.create.SlotID].OperationID != cleanup.terminationID {
		t.Fatalf("retirement binding drifted: %#v, %v", retained, err)
	}
}

func exerciseCodingHigherFenceBeforeCleanupPG(t *testing.T, ctx context.Context,
	store *Store, ticket codingidentity.Reservation) {
	t.Helper()
	owner, err := NewLifecycleRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	createOperation, err := owner.GetOperation(ctx, ticket.Claim.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := owner.GetSandbox(ctx, ticket.Claim.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	plan := codingBoundTestPlan()
	issued := time.Now().UTC()
	create, err := dockercontrol.NewCodingCreateAuthority(ctx, ticket, createOperation,
		sandbox, plan, codingTestDigest("f"), plan.OwnerPrincipalDigest, issued)
	if err != nil {
		t.Fatal(err)
	}
	var oldOperation lifecycle.Operation
	for index, fence := range []uint64{ticket.Claim.Fence, ticket.Claim.Fence + 1} {
		at := time.Now().UTC()
		request := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{
			OperationID:  fmt.Sprintf("coding-barrier-order-operation-%d", index),
			AttemptID:    fmt.Sprintf("coding-barrier-order-attempt-%d", index),
			FencingToken: fence, IdempotencyKey: fmt.Sprintf("coding-barrier-order-key-%d", index),
			RequestDigest: codingTestDigest("e"), Deadline: at.Add(time.Minute),
			ExpectedGeneration: sandbox.Generation}, Reason: "higher fence before cleanup"}
		updated, operation, err := lifecycle.StartTerminate(sandbox, request, at)
		if err != nil {
			t.Fatal(err)
		}
		_, err = owner.ReserveMutation(ctx, request.IdempotencyKey, request.RequestDigest,
			request.ExpectedGeneration, updated, operation,
			lifecycle.Event{ID: fmt.Sprintf("coding-barrier-order-event-%d", index),
				SandboxID: sandbox.ID, OperationID: operation.ID, Generation: updated.Generation,
				FencingToken: operation.FencingToken, Kind: "termination-requested", OccurredAt: at})
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			oldOperation = operation
		}
		sandbox = updated
	}
	completed := dockercontrol.CodingReceipt{Authority: create, AuthorityDigest: create.Digest(),
		Status: dockercontrol.ReceiptCompleted, CompletionDigest: codingTestDigest("8"),
		CompletionEvidenceDigest: codingTestDigest("9"), UpdatedAt: time.Now().UTC()}
	input := codingCleanupAdmission{Create: create, Completed: completed, ControlRevision: 3,
		ControlStateDigest: codingTestDigest("a"), TerminationID: oldOperation.ID,
		ControlPolicyDigest: create.ControlPolicyDigest, PeerPrincipalDigest: plan.OwnerPrincipalDigest,
		SpecBySlot: codingBoundSpecs(plan)}
	before, revision := codingPGSnapshot(t, ctx, store)
	if _, err := attemptCodingCleanupPG(ctx, store, plan, input, nil); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("higher-fence-first old cleanup obtained permit: %v", err)
	}
	if after, nextRevision := codingPGSnapshot(t, ctx, store); after != before || nextRevision != revision {
		t.Fatal("rejected old cleanup changed durable PG row")
	}
}
