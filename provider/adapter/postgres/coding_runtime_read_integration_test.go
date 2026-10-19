//go:build integration

package providerpostgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

// The database is real and owned by the parent disposable test. Control is
// synthetic; no exec process, runtime bytes or live TLS/CRL is exercised here.
func exerciseCodingRuntimePreflightPG(t *testing.T, ctx context.Context, store *Store, plan codingidentity.Plan, specs map[string]string, policy string) {
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
	owner, err := NewCodingLifecycleRepositoryWithPolicy(store, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewCodingLifecycleRepositoryWithPolicy(other, plan, specs, policy)
	if err != nil {
		t.Fatal(err)
	}
	expected := codingcontrol.Expected{ProfileDigest: plan.ProfileDigest, ControlPolicyDigest: policy, ProviderPrincipalDigest: plan.OwnerPrincipalDigest}
	control := &codingPGTerminationControl{}
	readback, err := codingcontrol.NewCreateReadback(owner, control, codingPGRealClock{}, expected)
	if err != nil {
		t.Fatal(err)
	}
	termination, err := codingcontrol.NewTerminationReconciler(owner, control, control, codingPGRealClock{}, expected)
	if err != nil {
		t.Fatal(err)
	}
	c, err := lifecyclecoordinator.NewWithCodingOriginalAuthorityAndLease(owner, codingPGNoLegacyDriver{}, readback, termination, owner, codingPGRealClock{})
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := codingcontrol.NewExecPreflight(reader, codingPGRealClock{}, expected)
	if err != nil {
		t.Fatal(err)
	}
	request := codingIntegrationRequest(time.Now().UTC(), 95)
	if _, err := c.AcceptCreate(ctx, request); err != nil {
		t.Fatal(err)
	}
	originalTicket, _, _, _, err := owner.BeginCodingFirstCreateWithAuthority(ctx, request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadCodingRuntime(ctx, request.Spec.SandboxID); err == nil {
		t.Fatal("Creating runtime became eligible")
	}
	ready, err := c.ReconcileOperation(ctx, request.OperationID)
	if err != nil || ready.Sandbox.ObservedState != lifecycle.ObservedReady {
		t.Fatalf("Ready fixture: %#v %v", ready, err)
	}
	sb := ready.Sandbox
	execRequest := providerexec.Request{SandboxID: sb.ID, OperationID: "preflight-exec-95", AttemptID: "preflight-attempt-95", IdempotencyKey: "preflight-key-95", RequestDigest: codingTestDigest("3"),
		ExpectedGeneration: int64(sb.Generation), FencingToken: int64(request.FencingToken), Deadline: time.Now().UTC().Add(time.Minute),
		Command: []string{"/bin/echo", "preflight-only"}, WorkingDirectory: "/workspace", ResultRetention: time.Minute}
	state, revision := codingPGSnapshot(t, ctx, store)
	sends, observes := control.sends.Load(), control.observes.Load()
	// A SELECT on the other pool must finish while a writer holds the row lock.
	// This would block if preflight silently reserved work or bumped a revision.
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBounded(tx, time.Second)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	for _, fence := range []int64{execRequest.FencingToken, execRequest.FencingToken + 100} {
		probe := execRequest.Clone()
		probe.FencingToken = fence
		if err := preflight.CheckSupport(ctx, probe); err != nil {
			t.Fatalf("read-only eligibility while writer holds lock: %v", err)
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision || control.sends.Load() != sends || control.observes.Load() != observes {
		t.Fatal("preflight changed PG revision/fence or called Control")
	}
	lease := lifecycle.LeaseRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "preflight-lease-95", AttemptID: "preflight-lease-attempt-95", IdempotencyKey: "preflight-lease-key-95", RequestDigest: codingTestDigest("4"),
		ExpectedGeneration: sb.Generation, FencingToken: request.FencingToken + 1, Deadline: time.Now().UTC().Add(time.Minute)}, ExtendSeconds: 60}
	if _, err := c.AcceptLease(ctx, sb.ID, lease, 7200); err != nil {
		t.Fatal(err)
	}
	if err := preflight.CheckSupport(ctx, execRequest); err == nil {
		t.Fatal("old fence passed after renewed current lease")
	}
	execRequest.FencingToken = int64(lease.FencingToken)
	if err := preflight.CheckSupport(ctx, execRequest); err != nil {
		t.Fatal(err)
	}
	term := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "preflight-terminate-95", AttemptID: "preflight-terminate-attempt-95", IdempotencyKey: "preflight-terminate-key-95", RequestDigest: codingTestDigest("5"),
		ExpectedGeneration: sb.Generation, FencingToken: lease.FencingToken, Deadline: time.Now().UTC().Add(time.Minute)}, Reason: "close runtime eligibility before cleanup"}
	if _, err := c.AcceptTerminate(ctx, sb.ID, term); err != nil {
		t.Fatal(err)
	}
	state, revision = codingPGSnapshot(t, ctx, store)
	if err := preflight.CheckSupport(ctx, execRequest); err == nil {
		t.Fatal("accepted termination left preflight open before cleanup")
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision {
		t.Fatal("rejected preflight changed PG")
	}
	for range 2 {
		if _, err := c.ReconcileOperation(ctx, term.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	replacement := codingIntegrationRequest(time.Now().UTC(), 96)
	if _, err := c.AcceptCreate(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	replacementTicket, _, _, _, err := owner.BeginCodingFirstCreateWithAuthority(ctx, replacement.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if originalTicket.Slot.ID != replacementTicket.Slot.ID || originalTicket.Claim.AllocationID == replacementTicket.Claim.AllocationID {
		t.Fatal("fixture did not reuse the exact slot with a new allocation")
	}
	if _, err := c.ReconcileOperation(ctx, replacement.OperationID); err != nil {
		t.Fatal(err)
	}
	state, revision = codingPGSnapshot(t, ctx, store)
	if _, err := reader.ReadCodingRuntime(ctx, sb.ID); err == nil {
		t.Fatal("released historical sandbox inherited replacement readiness")
	}
	if snapshot, err := reader.ReadCodingRuntime(ctx, replacement.Spec.SandboxID); err != nil || snapshot.Sandbox.ID != replacement.Spec.SandboxID {
		t.Fatalf("replacement read: %#v %v", snapshot, err)
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != state || rev != revision {
		t.Fatal("replacement/historical reads changed PG")
	}
	// Leave the bounded slot free for the parent test's subsequent scenarios.
	term.OperationID, term.AttemptID, term.IdempotencyKey = "preflight-terminate-96", "preflight-terminate-attempt-96", "preflight-terminate-key-96"
	term.ExpectedGeneration, term.FencingToken = 1, replacement.FencingToken
	if _, err := c.AcceptTerminate(ctx, replacement.Spec.SandboxID, term); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := c.ReconcileOperation(ctx, term.OperationID); err != nil {
			t.Fatal(err)
		}
	}
}
