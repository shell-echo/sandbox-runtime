//go:build integration

package providerpostgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

type codingPGRealClock struct{}

func (codingPGRealClock) Now() time.Time { return time.Now().UTC() }

// This fake proves only Provider PG transaction behavior. It has no mTLS
// identity, Control sealed ledger, or Docker daemon and is not release-gate
// evidence for the production observation port.
type codingPGFakeObserver struct{}

func (codingPGFakeObserver) Observe(ctx context.Context,
	request codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	if err := ctx.Err(); err != nil {
		return codingcontrolprotocol.Response{}, err
	}
	response := codingcontrolprotocol.Response{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: request.Action,
		CreateAuthorityDigest: request.Create.Digest(), EffectID: request.Create.EffectID,
		CompletionDigest:         codingTestDigest("8"),
		CompletionEvidenceDigest: codingTestDigest("9"), UpdatedAt: time.Now().UTC()}
	if request.Cleanup == nil {
		response.Status = codingcontrolprotocol.StatusCompleted
		response.ControlRevision = 3
		response.ControlStateDigest = codingTestDigest("a")
	} else {
		response.Status = codingcontrolprotocol.StatusReleased
		response.CleanupAuthorityDigest = request.Cleanup.Digest()
		response.ControlRevision = 4
		response.ControlStateDigest = codingTestDigest("b")
		response.AbsenceDigest = codingTestDigest("4")
		response.AbsenceEvidenceDigest = codingTestDigest("5")
	}
	if err := response.Validate(request); err != nil {
		return codingcontrolprotocol.Response{}, err
	}
	return response, nil
}

func exerciseCodingAtomicOriginalPG(t *testing.T, ctx context.Context,
	container, currentPort string) {
	t.Helper()
	const database = "provider_coding_atomic"
	adminDSN := "postgres://postgres:provider-admin@127.0.0.1:" + currentPort + "/provider?sslmode=disable"
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `CREATE DATABASE provider_coding_atomic OWNER provider_migrator`); err != nil {
		t.Fatal(err)
	}
	migrationDSN := "postgres://provider_migrator:migration-secret@127.0.0.1:" + currentPort + "/" + database + "?sslmode=disable"
	migrationPool, err := pgxpool.New(ctx, migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationPool.Close()
	if err := ApplyMigrations(ctx, migrationPool); err != nil {
		t.Fatal(err)
	}
	adminAtomicDSN := "postgres://postgres:provider-admin@127.0.0.1:" + currentPort + "/" + database + "?sslmode=disable"
	adminAtomic, err := pgxpool.New(ctx, adminAtomicDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer adminAtomic.Close()
	if _, err := adminAtomic.Exec(ctx, `GRANT USAGE ON SCHEMA sandbox_runtime_provider TO provider_runtime;
GRANT SELECT ON sandbox_runtime_provider.schema_migrations TO provider_runtime;
GRANT SELECT,UPDATE ON sandbox_runtime_provider.control_state TO provider_runtime`); err != nil {
		t.Fatal(err)
	}
	runtimeDSN := "postgres://provider_runtime:runtime-secret@127.0.0.1:" + currentPort + "/" + database + "?sslmode=disable"
	poolA, err := pgxpool.New(ctx, runtimeDSN+"&application_name=coding_atomic_A")
	if err != nil {
		t.Fatal(err)
	}
	defer poolA.Close()
	poolB, err := pgxpool.New(ctx, runtimeDSN+"&application_name=coding_atomic_B")
	if err != nil {
		t.Fatal(err)
	}
	defer poolB.Close()
	storeA, _ := New(poolA, time.Second)
	storeB, _ := New(poolB, time.Second)
	plan := codingBoundTestPlan()
	specs := codingBoundSpecs(plan)
	policy := codingTestDigest("f")
	boundA, err := NewCodingBoundCreateRepositoryWithPolicy(storeA, plan, policy)
	if err != nil {
		t.Fatal(err)
	}
	boundB, err := NewCodingBoundCreateRepositoryWithPolicy(storeB, plan, policy)
	if err != nil {
		t.Fatal(err)
	}
	legacyB, err := NewCodingBoundCreateRepository(storeB, plan)
	if err != nil {
		t.Fatal(err)
	}
	beforeBootstrap, bootstrapRevision := codingPGSnapshot(t, ctx, storeA)
	cleanRejected := errors.New("injected independent clean-namespace denial")
	if err := boundA.InitializeAtomicOriginal(ctx,
		func(context.Context, codingidentity.Plan) error { return cleanRejected }); !errors.Is(err, cleanRejected) {
		t.Fatalf("failed clean check was not surfaced: %v", err)
	}
	if after, revision := codingPGSnapshot(t, ctx, storeB); after != beforeBootstrap || revision != bootstrapRevision {
		t.Fatal("failed clean-namespace check partially initialized PG marker or slots")
	}
	// Component fixture only: no Coding Docker allocation exists in this
	// disposable PG database. Production bootstrap needs independent physical
	// namespace absence, not this synthetic callback.
	if err := boundA.InitializeAtomicOriginal(ctx,
		func(context.Context, codingidentity.Plan) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := boundB.InitializeAtomicOriginal(ctx,
		func(context.Context, codingidentity.Plan) error { return nil }); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("second v3 initialization changed marker: %v", err)
	}
	if err := legacyB.Initialize(ctx,
		func(context.Context, codingidentity.Plan) error { return nil }); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("legacy initialization upgraded v3: %v", err)
	}
	legacyLifecycle, err := NewCodingLifecycleRepository(storeB, plan, specs)
	if err != nil {
		t.Fatal(err)
	}
	beforeLegacyCleanup, beforeLegacyCleanupRevision := codingPGSnapshot(t, ctx, storeA)
	if _, _, _, _, err := legacyLifecycle.BeginCodingCurrentCleanup(ctx,
		"coding-atomic-terminate-90", dockercontrol.CodingCreateAuthority{},
		dockercontrol.CodingCompletedSnapshot{}, policy); !errors.Is(err, codingidentity.ErrInvalidState) {
		t.Fatalf("legacy local-snapshot cleanup did not reject v3 marker first: %v", err)
	}
	if _, _, err := legacyLifecycle.FinishCodingCurrentCleanup(ctx,
		dockercontrol.CodingCreateAuthority{}, dockercontrol.CodingCleanupAuthority{},
		dockercontrol.CodingReleasedSnapshot{}); !errors.Is(err, codingidentity.ErrInvalidState) {
		t.Fatalf("legacy local-snapshot release did not reject v3 marker first: %v", err)
	}
	if after, revision := codingPGSnapshot(t, ctx, storeB); after != beforeLegacyCleanup || revision != beforeLegacyCleanupRevision {
		t.Fatal("legacy cleanup/release denial changed v3 PG documents or revision")
	}
	lifecycleA, err := NewLifecycleRepository(storeA)
	if err != nil {
		t.Fatal(err)
	}
	request := codingIntegrationRequest(time.Now().UTC(), 90)
	sandbox, operation, err := lifecycle.StartCreate(request, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycleA.ReserveCreate(ctx, request.IdempotencyKey,
		request.RequestDigest, sandbox, operation); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := legacyB.BeginFirstCreate(ctx, request.OperationID, specs); !errors.Is(err, codingidentity.ErrInvalidState) {
		t.Fatalf("zero-record v3 marker admitted legacy first permit: %v", err)
	}
	beforeCanceledPermit, canceledRevision := codingPGSnapshot(t, ctx, storeA)
	cancelLock, err := adminAtomic.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBounded(cancelLock, time.Second)
	if _, err := cancelLock.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	queuedCtx, cancelQueued := context.WithCancel(ctx)
	queuedResult := make(chan error, 1)
	go func() {
		_, _, _, _, err := boundA.BeginFirstCreateWithAuthority(queuedCtx,
			request.OperationID, specs)
		queuedResult <- err
	}()
	if err := waitCodingPGRowLock(ctx, adminAtomic, "coding_atomic_A"); err != nil {
		cancelQueued()
		t.Fatalf("first permit did not queue on PG row before cancellation: %v", err)
	}
	cancelQueued()
	if err := <-queuedResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation returned a permit or wrong result: %v", err)
	}
	if err := cancelLock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if after, revision := codingPGSnapshot(t, ctx, storeB); after != beforeCanceledPermit || revision != canceledRevision {
		t.Fatal("cancelled queued first permit committed PG state")
	}
	results := make(chan struct {
		authority dockercontrol.CodingCreateAuthority
		err       error
	}, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for _, bound := range []*CodingBoundCreateRepository{boundA, boundB} {
		wait.Add(1)
		go func(bound *CodingBoundCreateRepository) {
			defer wait.Done()
			<-start
			_, _, _, authority, err := bound.BeginFirstCreateWithAuthority(ctx,
				request.OperationID, specs)
			results <- struct {
				authority dockercontrol.CodingCreateAuthority
				err       error
			}{authority, err}
		}(bound)
	}
	close(start)
	wait.Wait()
	close(results)
	var original dockercontrol.CodingCreateAuthority
	successes := 0
	for result := range results {
		if result.err == nil {
			successes++
			original = result.authority
		} else if !errors.Is(result.err, codingidentity.ErrConflict) {
			t.Fatalf("two-pool v3 first-permit contender: %v", result.err)
		}
	}
	if successes != 1 {
		t.Fatalf("atomic original permits=%d, want exactly one", successes)
	}
	if retained, err := boundB.ReadOriginalCreateAuthority(ctx, original.AllocationID); err != nil || retained != original {
		t.Fatalf("other PG pool lost exact original: %#v, %v", retained, err)
	}
	wrong, err := NewCodingBoundCreateRepositoryWithPolicy(storeB, plan, codingTestDigest("0"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.ReadOriginalCreateAuthority(ctx, original.AllocationID); err == nil {
		t.Fatal("wrong Control policy read original")
	}
	active, err := lifecycleA.GetSandbox(ctx, original.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	terminate := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{
		OperationID: "coding-atomic-terminate-90", AttemptID: "coding-atomic-terminate-attempt-90",
		FencingToken: original.Fence, IdempotencyKey: "coding-atomic-terminate-key-90",
		RequestDigest: codingTestDigest("2"), Deadline: at.Add(time.Minute),
		ExpectedGeneration: active.Generation}, Reason: "PG-only typed observation"}
	terminating, termination, err := lifecycle.StartTerminate(active, terminate, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycleA.ReserveMutation(ctx, terminate.IdempotencyKey,
		terminate.RequestDigest, terminate.ExpectedGeneration, terminating, termination,
		lifecycle.Event{ID: "event-coding-atomic-terminate-90", SandboxID: active.ID,
			OperationID: termination.ID, Generation: terminating.Generation,
			FencingToken: termination.FencingToken, Kind: "termination-requested",
			OccurredAt: at}); err != nil {
		t.Fatal(err)
	}
	owner, err := NewCodingLifecycleRepositoryWithPolicy(storeB, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	service, err := codingcontrol.New(owner, codingPGFakeObserver{}, codingPGRealClock{},
		codingcontrol.Expected{ProfileDigest: plan.ProfileDigest,
			ControlPolicyDigest: policy, ProviderPrincipalDigest: plan.OwnerPrincipalDigest})
	if err != nil {
		t.Fatal(err)
	}
	originalOperation, err := lifecycleA.GetOperation(ctx, original.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	leaseBefore, err := lifecycleA.GetLease(ctx, original.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	leaseAttempt := leaseBefore
	leaseAttempt.ExpiresAt = leaseAttempt.ExpiresAt.Add(time.Minute)
	beforeOverlap, beforeOverlapRevision := codingPGSnapshot(t, ctx, storeA)
	lockTx, err := adminAtomic.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBounded(lockTx, time.Second)
	if _, err := lockTx.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	racing, stopRace := context.WithTimeout(ctx, 15*time.Second)
	defer stopRace()
	cleanupResult := make(chan struct {
		authority dockercontrol.CodingCleanupAuthority
		err       error
	}, 1)
	go func() {
		authority, err := service.Begin(racing, termination.ID)
		cleanupResult <- struct {
			authority dockercontrol.CodingCleanupAuthority
			err       error
		}{authority, err}
	}()
	if err := waitCodingPGRowLock(racing, adminAtomic, "coding_atomic_B"); err != nil {
		t.Fatalf("typed cleanup never queued on PG row: %v", err)
	}
	leaseResult := make(chan error, 1)
	go func() {
		leaseResult <- lifecycleA.ReplaceLease(racing, leaseAttempt, leaseBefore.FencingToken)
	}()
	if err := waitCodingPGRowLock(racing, adminAtomic, "coding_atomic_A"); err != nil {
		t.Fatalf("generic lease writer never queued behind cleanup: %v", err)
	}
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	beginResult := <-cleanupResult
	cleanup, err := beginResult.authority, beginResult.err
	if err != nil {
		t.Fatalf("retirement-first typed cleanup admission: %v", err)
	}
	if err := <-leaseResult; !errors.Is(err, lifecyclerepository.ErrRetirementBlocked) {
		t.Fatalf("queued generic lease write passed committed retirement: %v", err)
	}
	if afterOverlap, afterRevision := codingPGSnapshot(t, ctx, storeB); afterOverlap == beforeOverlap || afterRevision != beforeOverlapRevision+1 {
		t.Fatalf("row overlap committed more than one state change: revision %d -> %d",
			beforeOverlapRevision, afterRevision)
	}
	if retainedLease, err := lifecycleA.GetLease(ctx, original.SandboxID); err != nil || retainedLease != leaseBefore {
		t.Fatalf("rejected lease write changed PG lease: %#v, %v", retainedLease, err)
	}
	if retainedCreate, err := lifecycleA.GetOperation(ctx, original.OperationID); err != nil || retainedCreate != originalOperation {
		t.Fatalf("lease race changed historical create: %#v, %v", retainedCreate, err)
	}
	lockedSlots, err := readState(ctx, storeA, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || lockedSlots.Retirements[original.SlotID].OperationID != termination.ID ||
		lockedSlots.Retirements[original.SlotID].OriginalAuthorityDigest != original.Digest() {
		t.Fatalf("lease race lost exact retirement: %#v, %v", lockedSlots, err)
	}
	lockedLedger, err := readState(ctx, storeA, lifecycleDocument, newLifecycleState, importLifecycleState)
	if err != nil || lockedLedger.Fencing[original.ProviderRevisionID+"\x00"+original.SandboxID] != original.Fence {
		t.Fatalf("rejected lease write changed fencing highwater: %#v, %v", lockedLedger.Fencing, err)
	}
	if cleanup.OriginalAuthorityDigest != original.Digest() {
		t.Fatal("typed cleanup lost original authority digest")
	}
	if err := service.Finish(ctx, termination.ID); err != nil {
		t.Fatalf("typed Released PG final CAS: %v", err)
	}
	if retained, err := boundA.ReadOriginalCreateAuthority(ctx, original.AllocationID); err != nil || retained != original {
		t.Fatalf("released original was erased: %#v, %v", retained, err)
	}
	request2 := codingIntegrationRequest(time.Now().UTC(), 91)
	sandbox2, operation2, err := lifecycle.StartCreate(request2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycleA.ReserveCreate(ctx, request2.IdempotencyKey,
		request2.RequestDigest, sandbox2, operation2); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := legacyB.BeginFirstCreate(ctx, request2.OperationID, specs); !errors.Is(err, codingidentity.ErrInvalidState) {
		t.Fatalf("post-release v3 marker admitted legacy first permit: %v", err)
	}
	beforeWrongPolicy, wrongPolicyRevision := codingPGSnapshot(t, ctx, storeA)
	if _, _, _, _, err := wrong.BeginFirstCreateWithAuthority(ctx, request2.OperationID, specs); err == nil {
		t.Fatal("wrong Control policy obtained PG first permit")
	}
	if after, revision := codingPGSnapshot(t, ctx, storeB); after != beforeWrongPolicy || revision != wrongPolicyRevision {
		t.Fatal("wrong-policy first permit changed PG documents or revision")
	}
	newTicket, _, _, newOriginal, err := boundB.BeginFirstCreateWithAuthority(ctx,
		request2.OperationID, specs)
	if err != nil || newTicket.Slot.ID != original.SlotID ||
		newOriginal.AllocationID == original.AllocationID {
		t.Fatalf("slot reuse did not keep distinct original: %#v, %v", newTicket, err)
	}
	current2, err := lifecycleA.GetSandbox(ctx, newOriginal.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	firstAt := time.Now().UTC()
	firstRequest := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{
		OperationID: "coding-atomic-terminate-91", AttemptID: "coding-atomic-terminate-attempt-91",
		FencingToken: newOriginal.Fence, IdempotencyKey: "coding-atomic-terminate-key-91",
		RequestDigest: codingTestDigest("5"), Deadline: firstAt.Add(time.Minute),
		ExpectedGeneration: current2.Generation}, Reason: "higher-fence-first row overlap"}
	firstSandbox, firstOperation, err := lifecycle.StartTerminate(current2, firstRequest, firstAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycleA.ReserveMutation(ctx, firstRequest.IdempotencyKey,
		firstRequest.RequestDigest, firstRequest.ExpectedGeneration, firstSandbox, firstOperation,
		lifecycle.Event{ID: "event-coding-atomic-terminate-91", SandboxID: current2.ID,
			OperationID: firstOperation.ID, Generation: firstSandbox.Generation,
			FencingToken: firstOperation.FencingToken, Kind: "termination-requested",
			OccurredAt: firstAt}); err != nil {
		t.Fatal(err)
	}
	secondAt := time.Now().UTC()
	secondRequest := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{
		OperationID: "coding-atomic-higher-91", AttemptID: "coding-atomic-higher-attempt-91",
		FencingToken: newOriginal.Fence + 1, IdempotencyKey: "coding-atomic-higher-key-91",
		RequestDigest: codingTestDigest("6"), Deadline: secondAt.Add(time.Minute),
		ExpectedGeneration: firstSandbox.Generation}, Reason: "higher-fence-first row overlap"}
	secondSandbox, secondOperation, err := lifecycle.StartTerminate(firstSandbox, secondRequest, secondAt)
	if err != nil {
		t.Fatal(err)
	}
	secondEvent := lifecycle.Event{ID: "event-coding-atomic-higher-91", SandboxID: current2.ID,
		OperationID: secondOperation.ID, Generation: secondSandbox.Generation,
		FencingToken: secondOperation.FencingToken, Kind: "termination-requested",
		OccurredAt: secondAt}
	beforeHigherFirst, beforeHigherFirstRevision := codingPGSnapshot(t, ctx, storeA)
	secondLockTx, err := adminAtomic.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBounded(secondLockTx, time.Second)
	if _, err := secondLockTx.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	secondRace, stopSecondRace := context.WithTimeout(ctx, 15*time.Second)
	defer stopSecondRace()
	secondHigherResult := make(chan error, 1)
	go func() {
		_, err := lifecycleA.ReserveMutation(secondRace, secondRequest.IdempotencyKey,
			secondRequest.RequestDigest, secondRequest.ExpectedGeneration,
			secondSandbox, secondOperation, secondEvent)
		secondHigherResult <- err
	}()
	if err := waitCodingPGRowLock(secondRace, adminAtomic, "coding_atomic_A"); err != nil {
		t.Fatalf("higher-fence-first mutation never queued: %v", err)
	}
	staleCleanupResult := make(chan struct {
		authority dockercontrol.CodingCleanupAuthority
		err       error
	}, 1)
	go func() {
		authority, err := service.Begin(secondRace, firstOperation.ID)
		staleCleanupResult <- struct {
			authority dockercontrol.CodingCleanupAuthority
			err       error
		}{authority, err}
	}()
	if err := waitCodingPGRowLock(secondRace, adminAtomic, "coding_atomic_B"); err != nil {
		t.Fatalf("old cleanup never queued behind higher fence: %v", err)
	}
	if err := secondLockTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-secondHigherResult; err != nil {
		t.Fatalf("higher-fence-first generic mutation rejected: %v", err)
	}
	stale := <-staleCleanupResult
	if stale.err == nil || stale.authority != (dockercontrol.CodingCleanupAuthority{}) {
		t.Fatalf("old cleanup obtained permit after higher fence: %#v, %v", stale.authority, stale.err)
	}
	if afterHigherFirst, revision := codingPGSnapshot(t, ctx, storeB); afterHigherFirst == beforeHigherFirst || revision != beforeHigherFirstRevision+1 {
		t.Fatalf("higher-fence-first overlap committed extra PG state: revision %d -> %d",
			beforeHigherFirstRevision, revision)
	}
	identityAfter, err := readState(ctx, storeA, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || len(identityAfter.Retirements) != 0 {
		t.Fatalf("higher-fence-first old cleanup created retirement: %#v, %v", identityAfter, err)
	}
	ledgerAfter, err := readState(ctx, storeA, lifecycleDocument, newLifecycleState, importLifecycleState)
	if err != nil || ledgerAfter.Fencing[newOriginal.ProviderRevisionID+"\x00"+newOriginal.SandboxID] != newOriginal.Fence+1 ||
		ledgerAfter.Operations[firstOperation.ID].State != lifecycle.OperationAccepted {
		t.Fatalf("higher-fence-first PG result drifted: %#v, %v", ledgerAfter.Fencing, err)
	}
	if output, err := exec.CommandContext(ctx, "docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatalf("restart PG with v3 marker: %v: %s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, restartedPort, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	restartedDSN := fmt.Sprintf("postgres://provider_runtime:runtime-secret@127.0.0.1:%s/%s?sslmode=disable", restartedPort, database)
	waitForProviderPostgres(t, ctx, restartedDSN)
	restartedPool, err := pgxpool.New(ctx, restartedDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedPool.Close()
	restartedStore, _ := New(restartedPool, time.Second)
	restarted, err := NewCodingBoundCreateRepositoryWithPolicy(restartedStore, plan, policy)
	if err != nil {
		t.Fatal(err)
	}
	if retained, err := restarted.ReadOriginalCreateAuthority(ctx, original.AllocationID); err != nil || retained != original {
		t.Fatalf("PG restart erased historical original: %#v, %v", retained, err)
	}
	if retained, err := restarted.ReadOriginalCreateAuthority(ctx, newOriginal.AllocationID); err != nil || retained != newOriginal {
		t.Fatalf("PG restart changed current occupant original: %#v, %v", retained, err)
	}
	legacyRestarted, err := NewCodingBoundCreateRepository(restartedStore, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := legacyRestarted.BeginFirstCreate(ctx, request2.OperationID, specs); !errors.Is(err, codingidentity.ErrInvalidState) {
		t.Fatalf("PG restart reopened legacy first permit: %v", err)
	}
	restartLifecycle, err := NewLifecycleRepository(restartedStore)
	if err != nil {
		t.Fatal(err)
	}
	request3 := codingIntegrationRequest(time.Now().UTC(), 92)
	sandbox3, operation3, err := lifecycle.StartCreate(request3, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartLifecycle.ReserveCreate(ctx, request3.IdempotencyKey,
		request3.RequestDigest, sandbox3, operation3); err != nil {
		t.Fatal(err)
	}
	stateBeforeDrift, err := readState(ctx, restartedStore, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil {
		t.Fatal(err)
	}
	currentRecord := stateBeforeDrift.OriginalCreates[newOriginal.AllocationID]
	if currentRecord.Digest != newOriginal.Digest() {
		t.Fatal("current occupant original was not retained before corruption test")
	}
	// Deliberate test-only persisted damage is isolated to this disposable DB.
	// It must not grant a new first permit for another Accepted allocation.
	if err := mutateStatePair(ctx, restartedStore,
		codingIdentityMarkerDocument, codingIdentityStateDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		func(_ *codingIdentityMarker, slots *codingidentity.State) error {
			delete(slots.OriginalCreates, newOriginal.AllocationID)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	corruptBefore, corruptRevision := codingPGSnapshot(t, ctx, restartedStore)
	if _, _, _, _, err := restarted.BeginFirstCreateWithAuthority(ctx,
		request3.OperationID, specs); err == nil {
		t.Fatal("missing active original admitted another v3 first permit")
	}
	if after, revision := codingPGSnapshot(t, ctx, restartedStore); after != corruptBefore || revision != corruptRevision {
		t.Fatal("missing-original rejection changed PG documents or revision")
	}
	if err := mutateStatePair(ctx, restartedStore,
		codingIdentityMarkerDocument, codingIdentityStateDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		func(_ *codingIdentityMarker, slots *codingidentity.State) error {
			slots.OriginalCreates[newOriginal.AllocationID] = currentRecord
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if err := mutateStatePair(ctx, restartedStore,
		codingIdentityMarkerDocument, codingIdentityStateDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		func(marker *codingIdentityMarker, _ *codingidentity.State) error {
			marker.AuthorityMode = ""
			marker.ControlPolicyDigest = ""
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	mixedBefore, mixedRevision := codingPGSnapshot(t, ctx, restartedStore)
	if _, _, _, err := legacyRestarted.BeginFirstCreate(ctx,
		request3.OperationID, specs); err == nil {
		t.Fatal("legacy marker mixed with originals admitted first permit")
	}
	if after, revision := codingPGSnapshot(t, ctx, restartedStore); after != mixedBefore || revision != mixedRevision {
		t.Fatal("mixed marker/original rejection changed PG documents or revision")
	}
}

// waitCodingPGRowLock observes an actual PostgreSQL lock wait for the named
// independent pool. The ticker polls evidence; it does not choose an ordering
// by sleeping for a guessed duration. The holder transaction starts each
// contender only after the previous contender is visibly queued.
func waitCodingPGRowLock(ctx context.Context, admin *pgxpool.Pool,
	applicationName string) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		err := admin.QueryRow(waitCtx, `SELECT count(*) FROM pg_stat_activity
WHERE datname=current_database() AND application_name=$1
AND wait_event_type='Lock' AND query LIKE '%control_state%'`, applicationName).Scan(&waiting)
		if err != nil {
			return err
		}
		if waiting != 0 {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return waitCtx.Err()
		case <-ticker.C:
		}
	}
}
