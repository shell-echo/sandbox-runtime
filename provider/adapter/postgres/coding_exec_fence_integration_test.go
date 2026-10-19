//go:build integration

package providerpostgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

func exerciseCodingExecFenceBootstrapPG(t *testing.T, ctx context.Context, store *Store, plan codingidentity.Plan, specs map[string]string, policy string) {
	t.Helper()
	owner, err := NewCodingLifecycleRepositoryWithPolicy(store, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	before, beforeRev := codingPGSnapshot(t, ctx, store)
	for _, value := range []any{"null", string(isolationStored(t, codingExecFenceState{Version: 1, Mode: codingExecFenceMode, PlanDigest: owner.bound.digest, Records: []codingExecFenceRecord{}}))} {
		if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(documents,ARRAY[$1]::text[],$2::jsonb,true) WHERE singleton`, codingExecFenceDocument, value); err != nil {
			t.Fatal(err)
		}
		if err := owner.InitializeCodingExecFences(ctx); err == nil {
			t.Fatal("orphan fence doc repaired during bootstrap")
		}
		if err := owner.InitializeCodingExecIntents(ctx); err == nil {
			t.Fatal("intent initialization replay ignored orphan fence doc")
		}
		if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=$1::jsonb WHERE singleton`, before); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.InitializeCodingExecFences(ctx); err != nil {
		t.Fatal(err)
	}
	state, rev := codingPGSnapshot(t, ctx, store)
	if rev != beforeRev+1 {
		t.Fatal("fence bootstrap did not commit once")
	}
	if err := owner.InitializeCodingExecFences(ctx); err != nil {
		t.Fatal(err)
	}
	if err := owner.InitializeCodingExecIntents(ctx); err != nil {
		t.Fatal(err)
	}
	if got, after := codingPGSnapshot(t, ctx, store); got != state || after != rev {
		t.Fatal("bootstrap replay wrote state")
	}
	for _, missing := range []bool{true, false} {
		query := `UPDATE sandbox_runtime_provider.control_state SET documents=documents-$1 WHERE singleton`
		if !missing {
			query = `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(documents,ARRAY[$1]::text[],'null'::jsonb,true) WHERE singleton`
		}
		if _, err := store.pool.Exec(ctx, query, codingExecFenceDocument); err != nil {
			t.Fatal(err)
		}
		damaged, revision := codingPGSnapshot(t, ctx, store)
		if err := owner.InitializeCodingExecFences(ctx); err == nil {
			t.Fatal("missing initialized fence doc repaired")
		}
		if err := owner.InitializeCodingExecIntents(ctx); err == nil {
			t.Fatal("intent replay ignored missing fence doc")
		}
		if got, after := codingPGSnapshot(t, ctx, store); got != damaged || after != revision {
			t.Fatal("corruption rejection wrote state")
		}
		if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=$1::jsonb WHERE singleton`, state); err != nil {
			t.Fatal(err)
		}
	}
}

// Runs within the fresh locked PostgreSQL fixture. Control is synthetic and
// never called here: this is PG transactional evidence, not physical exec.
func exerciseCodingExecFencePG(t *testing.T, ctx context.Context, store *Store, a, b *CodingLifecycleRepository, c *lifecyclecoordinator.Coordinator, control *codingPGTerminationControl, old providerexec.Request) providerexec.Request {
	t.Helper()
	state, revision := codingPGSnapshot(t, ctx, store)
	if got, err := a.ReserveCodingExecFence(ctx, old); err == nil || got != (codingcontrol.ExecFenceReceipt{}) {
		t.Fatal("old intent survived lease tuple change")
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision {
		t.Fatal("stale intent changed state")
	}
	request := old.Clone()
	request.OperationID, request.AttemptID, request.IdempotencyKey = "fence-pg-97", "fence-attempt-97", "fence-key-97"
	request.Deadline = time.Now().UTC().Add(time.Minute)
	if _, err := a.ReserveCodingExecIntent(ctx, request); err != nil {
		t.Fatal(err)
	}
	state, revision = codingPGSnapshot(t, ctx, store)
	observes, sends := control.observes.Load(), control.sends.Load()
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBounded(tx, time.Second)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	got, err := b.ReserveCodingExecFence(short, request)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || got != (codingcontrol.ExecFenceReceipt{}) {
		t.Fatalf("fence lock cancellation: %#v %v", got, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision {
		t.Fatal("cancelled fence wrote state")
	}
	start := make(chan struct{})
	results := make(chan codingcontrol.ExecFenceReceipt, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, repo := range []*CodingLifecycleRepository{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			receipt, err := repo.ReserveCodingExecFence(ctx, request)
			results <- receipt
			errs <- err
		}()
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
	var receipt codingcontrol.ExecFenceReceipt
	for result := range results {
		if result.Replayed {
			replayed++
		}
		result.Replayed = true
		if receipt != (codingcontrol.ExecFenceReceipt{}) && result != receipt {
			t.Fatal("two pools returned different fence history")
		}
		receipt = result
	}
	if replayed != 1 {
		t.Fatal("same reservation committed more than once")
	}
	_, rev := codingPGSnapshot(t, ctx, store)
	if rev != revision+1 {
		t.Fatal("fence plus ledger did not commit in one revision")
	}
	snapshot, err := b.ReadCodingRuntime(ctx, request.SandboxID)
	if err != nil || snapshot.Lease.FencingToken != uint64(request.FencingToken) {
		t.Fatalf("committed fence missing: %#v %v", snapshot, err)
	}
	// Reconstructing a repository after a potentially lost caller response only
	// reads the committed historical binding. It does not authorize dispatch.
	reopened, err := NewCodingLifecycleRepositoryWithPolicy(b.bound.store, b.bound.plan, b.specBySlot, b.bound.controlPolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	state, revision = codingPGSnapshot(t, ctx, store)
	if got, err := reopened.ReadCodingExecFence(ctx, request.OperationID); err != nil || got != receipt {
		t.Fatalf("reopened history: %#v %v", got, err)
	}
	exerciseCodingExecFenceCorruptionPG(t, ctx, store, a, b, c, request)
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision {
		t.Fatal("read or corruption checks changed state")
	}
	if control.observes.Load() != observes || control.sends.Load() != sends {
		t.Fatal("PG reservation invoked Control")
	}
	// A second intent competes with a real typed lease on the same row. If
	// lease wins the tuple changes; if fence wins the old lease token is stale.
	race := request.Clone()
	race.OperationID, race.AttemptID, race.IdempotencyKey = "fence-race-97", "fence-race-attempt-97", "fence-race-key-97"
	race.FencingToken += 2
	if _, err := a.ReserveCodingExecIntent(ctx, race); err != nil {
		t.Fatal(err)
	}
	lease := lifecycle.LeaseRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "fence-race-lease-97", AttemptID: "fence-race-lease-attempt-97", IdempotencyKey: "fence-race-lease-key-97", RequestDigest: codingTestDigest("6"), ExpectedGeneration: 1, FencingToken: uint64(request.FencingToken), Deadline: request.Deadline}, ExtendSeconds: 60}
	_, revision = codingPGSnapshot(t, ctx, store)
	start = make(chan struct{})
	outcomes := make(chan bool, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := b.ReserveCodingExecFence(ctx, race)
		outcomes <- err == nil
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := c.AcceptLease(ctx, request.SandboxID, lease, 7200)
		outcomes <- err == nil
	}()
	close(start)
	wg.Wait()
	close(outcomes)
	wins := 0
	for won := range outcomes {
		if won {
			wins++
		}
	}
	if wins != 1 {
		t.Fatal("fence/lease competing tuple had wrong number of winners", wins)
	}
	if _, rev := codingPGSnapshot(t, ctx, store); rev != revision+1 {
		t.Fatal("fence/lease race was not atomic")
	}
	// Whichever operation won, record a new intent from the resulting current
	// tuple and reserve the final floor used by later termination tests.
	final := race.Clone()
	final.OperationID, final.AttemptID, final.IdempotencyKey = "fence-final-97", "fence-final-attempt-97", "fence-final-key-97"
	if _, err := a.ReserveCodingExecIntent(ctx, final); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ReserveCodingExecFence(ctx, final); err != nil {
		t.Fatal(err)
	}
	staleTerm := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "fence-stale-term-97", AttemptID: "fence-stale-term-attempt-97", IdempotencyKey: "fence-stale-term-key-97", RequestDigest: codingTestDigest("7"), ExpectedGeneration: 1, FencingToken: uint64(request.FencingToken), Deadline: request.Deadline}, Reason: "stale fence rejection"}
	state, revision = codingPGSnapshot(t, ctx, store)
	if _, err := c.AcceptTerminate(ctx, request.SandboxID, staleTerm); err == nil {
		t.Fatal("stale termination ignored reserved fence")
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision {
		t.Fatal("stale terminate changed state")
	}
	return final
}

func exerciseCodingExecFenceCorruptionPG(t *testing.T, ctx context.Context, store *Store, a, b *CodingLifecycleRepository, c *lifecyclecoordinator.Coordinator, request providerexec.Request) {
	t.Helper()
	original, revision := codingPGSnapshot(t, ctx, store)
	for _, missing := range []bool{true, false} {
		query := `UPDATE sandbox_runtime_provider.control_state SET documents=documents-$1 WHERE singleton`
		if !missing {
			query = `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(documents,ARRAY[$1]::text[],'null'::jsonb,true) WHERE singleton`
		}
		if _, err := store.pool.Exec(ctx, query, codingExecFenceDocument); err != nil {
			t.Fatal(err)
		}
		damaged, _ := codingPGSnapshot(t, ctx, store)
		if _, err := a.ReserveCodingExecIntent(ctx, request); err == nil {
			t.Fatal("historical intent replay ignored fence corruption")
		}
		if _, err := a.ReserveCodingExecFence(ctx, request); err == nil {
			t.Fatal("historical fence replay ignored fence corruption")
		}
		if _, err := b.ReadCodingExecFence(ctx, request.OperationID); err == nil {
			t.Fatal("historical read ignored fence corruption")
		}
		if _, err := b.ReadCodingRuntime(ctx, request.SandboxID); err == nil {
			t.Fatal("runtime preflight ignored fence corruption")
		}
		if err := a.InitializeCodingExecFences(ctx); err == nil {
			t.Fatal("bootstrap repaired damaged history")
		}
		lease := lifecycle.LeaseRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "fence-corrupt-lease", AttemptID: "fence-corrupt-attempt", IdempotencyKey: "fence-corrupt-key", RequestDigest: codingTestDigest("8"), ExpectedGeneration: 1, FencingToken: uint64(request.FencingToken), Deadline: request.Deadline}, ExtendSeconds: 60}
		if _, err := c.AcceptLease(ctx, request.SandboxID, lease, 7200); err == nil {
			t.Fatal("typed lifecycle write ignored fence corruption")
		}
		if got, rev := codingPGSnapshot(t, ctx, store); got != damaged || rev != revision {
			t.Fatal("rejected corrupted state changed")
		}
		if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=$1::jsonb WHERE singleton`, original); err != nil {
			t.Fatal(err)
		}
	}
}

func exerciseCodingExecFenceTerminateRacePG(t *testing.T, ctx context.Context, store *Store, a, b *CodingLifecycleRepository, c *lifecyclecoordinator.Coordinator, previous providerexec.Request, terminate lifecycle.TerminateRequest) lifecycle.TerminateRequest {
	t.Helper()
	request := previous.Clone()
	request.OperationID, request.AttemptID, request.IdempotencyKey = "fence-term-race-97", "fence-term-race-attempt-97", "fence-term-race-key-97"
	request.FencingToken++
	if _, err := a.ReserveCodingExecIntent(ctx, request); err != nil {
		t.Fatal(err)
	}
	_, revision := codingPGSnapshot(t, ctx, store)
	type outcome struct {
		fence bool
		err   error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	go func() { <-start; _, err := b.ReserveCodingExecFence(ctx, request); results <- outcome{true, err} }()
	go func() {
		<-start
		_, err := c.AcceptTerminate(ctx, request.SandboxID, terminate)
		results <- outcome{false, err}
	}()
	close(start)
	wins, fenceWon := 0, false
	for range 2 {
		got := <-results
		if got.err == nil {
			wins++
			fenceWon = got.fence
		}
	}
	if wins != 1 {
		t.Fatal("fence/terminate competing tuple had wrong number of winners", wins)
	}
	if _, rev := codingPGSnapshot(t, ctx, store); rev != revision+1 {
		t.Fatal("fence/terminate race was not atomic")
	}
	if fenceWon {
		terminate.OperationID, terminate.AttemptID, terminate.IdempotencyKey = "fence-final-term-97", "fence-final-term-attempt-97", "fence-final-term-key-97"
		terminate.FencingToken = uint64(request.FencingToken)
	} else {
		state, rev := codingPGSnapshot(t, ctx, store)
		if got, err := a.ReserveCodingExecFence(ctx, request); err == nil || got != (codingcontrol.ExecFenceReceipt{}) {
			t.Fatal("termination winner left intent admissible")
		}
		if got, after := codingPGSnapshot(t, ctx, store); got != state || after != rev {
			t.Fatal("post-terminate fence attempt changed state")
		}
	}
	return terminate
}
