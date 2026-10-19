//go:build integration

package providerpostgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

func exerciseCodingExecIntentBootstrapPG(t *testing.T, ctx context.Context, store *Store, plan codingidentity.Plan, specs map[string]string, policy string) {
	t.Helper()
	owner, err := NewCodingLifecycleRepositoryWithPolicy(store, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	// This hook runs immediately after the independently initialized disposable
	// Coding fixture, before any accepted create. It is not production bootstrap.
	before, beforeRev := codingPGSnapshot(t, ctx, store)
	for _, key := range []string{codingExecIntentDocument, execDocument, lifecycleDocument} {
		if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(documents,ARRAY[$1]::text[],'null'::jsonb,true) WHERE singleton`, key); err != nil {
			t.Fatal(err)
		}
		damaged, revision := codingPGSnapshot(t, ctx, store)
		if err := owner.InitializeCodingExecIntents(ctx); err == nil {
			t.Fatal("present JSON null silently replaced during initialization", key)
		}
		if got, rev := codingPGSnapshot(t, ctx, store); got != damaged || rev != revision {
			t.Fatal("corrupt bootstrap changed state")
		}
		if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=documents-$1 WHERE singleton`, key); err != nil {
			t.Fatal(err)
		}
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != before || rev != beforeRev {
		t.Fatal("null-document fixture altered pre-bootstrap state")
	}

	if err := owner.InitializeCodingExecIntents(ctx); err != nil {
		t.Fatal(err)
	}
	state, rev := codingPGSnapshot(t, ctx, store)
	if err := owner.InitializeCodingExecIntents(ctx); err != nil {
		t.Fatal(err)
	}
	if got, after := codingPGSnapshot(t, ctx, store); got != state || after != rev {
		t.Fatal("initialization recovery rewrote mode")
	}
	// Corruption injection is confined to the owned disposable database. Preserve
	// exact document bytes; missing state must not be silently reinitialized.
	var saved []byte
	if err := store.pool.QueryRow(ctx, `SELECT documents->$1 FROM sandbox_runtime_provider.control_state WHERE singleton`, codingExecIntentDocument).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=documents-$1 WHERE singleton`, codingExecIntentDocument); err != nil {
		t.Fatal(err)
	}
	if err := owner.InitializeCodingExecIntents(ctx); err == nil {
		t.Fatal("missing initialized ledger was repaired")
	}
	if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(documents,ARRAY[$1]::text[],$2::jsonb,true) WHERE singleton`, codingExecIntentDocument, saved); err != nil {
		t.Fatal(err)
	}
	if got, after := codingPGSnapshot(t, ctx, store); got != state || after != rev {
		t.Fatal("corruption fixture failed to preserve exact state")
	}
}

// Only PG is real. Control create/termination are synthetic fixtures. No exec
// command, mTLS/CRL check, physical exec cancellation or output is exercised.
func exerciseCodingExecIntentPG(t *testing.T, ctx context.Context, store *Store, plan codingidentity.Plan, specs map[string]string, policy string) {
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
	expected := codingcontrol.Expected{ProfileDigest: plan.ProfileDigest, ControlPolicyDigest: policy, ProviderPrincipalDigest: plan.OwnerPrincipalDigest}
	read, err := codingcontrol.NewCreateReadback(a, control, codingPGRealClock{}, expected)
	if err != nil {
		t.Fatal(err)
	}
	term, err := codingcontrol.NewTerminationReconciler(a, control, control, codingPGRealClock{}, expected)
	if err != nil {
		t.Fatal(err)
	}
	c, err := lifecyclecoordinator.NewWithCodingOriginalAuthorityAndLease(a, codingPGNoLegacyDriver{}, read, term, a, codingPGRealClock{})
	if err != nil {
		t.Fatal(err)
	}
	create := codingIntegrationRequest(time.Now().UTC(), 97)
	if _, err := c.AcceptCreate(ctx, create); err != nil {
		t.Fatal(err)
	}
	ticket, _, _, _, err := a.BeginCodingFirstCreateWithAuthority(ctx, create.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	request := providerexec.Request{SandboxID: create.Spec.SandboxID, OperationID: "intent-pg-97", AttemptID: "intent-pg-attempt-97", IdempotencyKey: "intent-pg-key-97", RequestDigest: codingTestDigest("3"), ExpectedGeneration: 1, FencingToken: int64(create.FencingToken) + 100, Deadline: time.Now().UTC().Add(time.Minute), Command: []string{"/bin/echo", "no-dispatch"}, WorkingDirectory: "/workspace", ResultRetention: time.Minute}
	state, revision := codingPGSnapshot(t, ctx, store)
	if _, err := a.ReserveCodingExecIntent(ctx, request); err == nil {
		t.Fatal("Creating admitted intent")
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision {
		t.Fatal("failed intent modified database")
	}
	ready, err := c.ReconcileOperation(ctx, create.OperationID)
	if err != nil || ready.Sandbox.ObservedState != lifecycle.ObservedReady {
		t.Fatal(err)
	}
	// Admission must wait for the same lifecycle row lock and honor the shorter
	// caller deadline. It cannot use the previously successful read-only check.
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBounded(tx, time.Second)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	state, revision = codingPGSnapshot(t, ctx, store)
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	got, err := b.ReserveCodingExecIntent(short, request)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || got != (codingcontrol.ExecIntentReceipt{}) {
		t.Fatalf("lock cancellation returned receipt: %#v %v", got, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision {
		t.Fatal("cancelled transaction changed intent or lifecycle")
	}
	observes, sends := control.observes.Load(), control.sends.Load()
	start := make(chan struct{})
	results := make(chan codingcontrol.ExecIntentReceipt, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, owner := range []*CodingLifecycleRepository{a, b} {
		wg.Add(1)
		go func(owner *CodingLifecycleRepository) {
			defer wg.Done()
			<-start
			receipt, err := owner.ReserveCodingExecIntent(ctx, request)
			results <- receipt
			errs <- err
		}(owner)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	replayed := 0
	for result := range results {
		if result.Replayed {
			replayed++
		}
		if result.OperationID != request.OperationID {
			t.Fatal("wrong receipt")
		}
	}
	state, after := codingPGSnapshot(t, ctx, store)
	if replayed != 1 || after != revision+1 {
		t.Fatalf("concurrent admission: replays %d revisions %d", replayed, after-revision)
	}
	// Fresh repository + ignored first return is recovery from the durable PG
	// record. This models a lost result, not actual COMMIT packet loss.
	reopened, err := NewCodingLifecycleRepositoryWithPolicy(other, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := reopened.ReserveCodingExecIntent(ctx, request); err != nil || !receipt.Replayed {
		t.Fatalf("reopened replay %#v %v", receipt, err)
	}
	if err := reopened.InitializeCodingExecIntents(ctx); err != nil {
		t.Fatal(err)
	}
	changed := request.Clone()
	changed.Command[1] = "changed-same-digest"
	if _, err := b.ReserveCodingExecIntent(ctx, changed); !errors.Is(err, codingcontrol.ErrExecIntentConflict) {
		t.Fatal(err)
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != after || control.observes.Load() != observes || control.sends.Load() != sends {
		t.Fatal("intent/replay called Control or rewrote state")
	}
	// Current lower fence remains available to lease and terminate; the held
	// intent's prospective high fence has not been promoted to authority.
	lease := lifecycle.LeaseRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "intent-lease-97", AttemptID: "intent-lease-attempt-97", IdempotencyKey: "intent-lease-key-97", RequestDigest: codingTestDigest("4"), ExpectedGeneration: 1, FencingToken: create.FencingToken + 1, Deadline: time.Now().UTC().Add(time.Minute)}, ExtendSeconds: 60}
	blocked := t.Run("legacy exec cannot enter intent mode", func(t *testing.T) {
		legacy, err := NewExecRepository(other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := legacy.ReserveExecution(ctx, request); err == nil {
			t.Error("generic execution bypassed Coding intent mode")
		}
	})
	blocked = t.Run("typed lease cannot reuse exec operation", func(t *testing.T) {
		collision := lease
		collision.OperationID = request.OperationID
		if _, err := c.AcceptLease(ctx, request.SandboxID, collision, 7200); err == nil {
			t.Error("typed lifecycle admission reused retained exec operation ID")
		}
	}) && blocked
	if !blocked {
		t.Fatal("exec isolation regression; disposable database will be removed")
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != after {
		t.Fatal("rejected cross-document admissions changed state")
	}
	if _, err := c.AcceptLease(ctx, request.SandboxID, lease, 7200); err != nil {
		t.Fatal(err)
	}
	exerciseCodingExecIsolationPG(t, ctx, store, other, a, b, c, request, lease)
	stale := request.Clone()
	stale.OperationID, stale.IdempotencyKey = "intent-stale-97", "intent-stale-key-97"
	stale.FencingToken = int64(create.FencingToken)
	if _, err := a.ReserveCodingExecIntent(ctx, stale); err == nil {
		t.Fatal("stale fence admitted after lease won row lock")
	}
	fenceRequest := exerciseCodingExecFencePG(t, ctx, store, a, b, c, control, request)
	terminate := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "intent-term-97", AttemptID: "intent-term-attempt-97", IdempotencyKey: "intent-term-key-97", RequestDigest: codingTestDigest("5"), ExpectedGeneration: 1, FencingToken: uint64(fenceRequest.FencingToken), Deadline: time.Now().UTC().Add(time.Minute)}, Reason: "intent component cleanup"}
	terminate = exerciseCodingExecFenceTerminateRacePG(t, ctx, store, a, b, c, fenceRequest, terminate)
	if _, err := c.AcceptTerminate(ctx, request.SandboxID, terminate); err != nil {
		t.Fatalf("intent post-isolation step: %v", err)
	}
	newRequest := request.Clone()
	newRequest.OperationID, newRequest.IdempotencyKey = "intent-after-term", "intent-after-term-key"
	if _, err := a.ReserveCodingExecIntent(ctx, newRequest); err == nil {
		t.Fatal("terminated allocation admitted new intent")
	}
	for step := range 2 {
		if _, err := c.ReconcileOperation(ctx, terminate.OperationID); err != nil {
			t.Fatalf("reconcile %s step %d: %v", terminate.OperationID, step, err)
		}
	}
	replacement := codingIntegrationRequest(time.Now().UTC(), 98)
	if _, err := c.AcceptCreate(ctx, replacement); err != nil {
		t.Fatalf("intent post-isolation step: %v", err)
	}
	replacementTicket, _, _, _, err := a.BeginCodingFirstCreateWithAuthority(ctx, replacement.OperationID)
	if err != nil {
		t.Fatalf("intent post-isolation step: %v", err)
	}
	if replacementTicket.Slot.ID != ticket.Slot.ID || replacementTicket.Claim.AllocationID == ticket.Claim.AllocationID {
		t.Fatal("slot was not reused")
	}
	if _, err := c.ReconcileOperation(ctx, replacement.OperationID); err != nil {
		t.Fatalf("intent post-isolation step: %v", err)
	}
	state, revision = codingPGSnapshot(t, ctx, store)
	observes, sends = control.observes.Load(), control.sends.Load()
	if receipt, err := b.ReadCodingExecFence(ctx, fenceRequest.OperationID); err != nil || !receipt.Replayed || receipt.FencingToken != uint64(fenceRequest.FencingToken) {
		t.Fatalf("released fence history: %#v %v", receipt, err)
	}
	if receipt, err := b.ReserveCodingExecFence(ctx, fenceRequest); err != nil || !receipt.Replayed {
		t.Fatalf("released fence replay: %#v %v", receipt, err)
	}
	if receipt, err := b.ReserveCodingExecIntent(ctx, request); err != nil || !receipt.Replayed {
		t.Fatalf("released history read %#v %v", receipt, err)
	}
	if _, err := b.ReserveCodingExecIntent(ctx, newRequest); err == nil {
		t.Fatal("old sandbox inherited new occupant authority")
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision || control.observes.Load() != observes || control.sends.Load() != sends {
		t.Fatal("historical intent replay had effects")
	}
	terminate.OperationID, terminate.AttemptID, terminate.IdempotencyKey = "intent-term-98", "intent-term-attempt-98", "intent-term-key-98"
	terminate.FencingToken = replacement.FencingToken
	if _, err := c.AcceptTerminate(ctx, replacement.Spec.SandboxID, terminate); err != nil {
		t.Fatalf("intent post-isolation step: %v", err)
	}
	for step := range 2 {
		if _, err := c.ReconcileOperation(ctx, terminate.OperationID); err != nil {
			t.Fatalf("reconcile %s step %d: %v", terminate.OperationID, step, err)
		}
	}
}
