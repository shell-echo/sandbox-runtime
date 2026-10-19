//go:build integration

package providerpostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

// Uses the parent's exact disposable PG database; there are no exec effects.
func exerciseCodingExecIsolationPG(t *testing.T, ctx context.Context, store, other *Store, a, b *CodingLifecycleRepository, c *lifecyclecoordinator.Coordinator, request providerexec.Request, lease lifecycle.LeaseRequest) {
	t.Helper()
	legacy, err := NewExecRepository(other)
	if err != nil {
		t.Fatal(err)
	}
	before, revision := codingPGSnapshot(t, ctx, store)
	for name, call := range map[string]func() error{
		"reserve":                      func() error { _, err := legacy.ReserveExecution(ctx, request); return err },
		"attach":                       func() error { _, err := legacy.AttachExecution(ctx, providerexec.ExecutionAttachment{}); return err },
		"cancel":                       func() error { _, err := legacy.ReserveCancellation(ctx, providerexec.CancellationIntent{}); return err },
		"store result":                 func() error { return legacy.StoreResult(ctx, providerexec.Result{}) },
		"get":                          func() error { _, err := legacy.GetExecution(ctx, request.OperationID); return err },
		"list":                         func() error { _, err := legacy.ListExecutions(ctx); return err },
		"get cancellation":             func() error { _, err := legacy.GetCancellation(ctx, request.OperationID); return err },
		"get cancellation reservation": func() error { _, err := legacy.GetCancellationReservation(ctx, request.OperationID); return err },
		"get result":                   func() error { _, err := legacy.GetResult(ctx, request.OperationID, time.Now().UTC()); return err },
	} {
		t.Run("isolated generic exec "+name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrCodingExecIsolation) {
				t.Fatal("generic exec entry point not isolated", err)
			}
		})
	}
	// Reverse order: the earlier successful lease retains the operation ID.
	conflict := request.Clone()
	conflict.OperationID, conflict.IdempotencyKey = lease.OperationID, "isolation-lease-first"
	if got, err := b.ReserveCodingExecIntent(ctx, conflict); !errors.Is(err, codingcontrol.ErrExecIntentConflict) || got != (codingcontrol.ExecIntentReceipt{}) {
		t.Fatalf("lease-first ID not protected: %#v %v", got, err)
	}
	// Generic lifecycle paths must check the same namespace as typed lease.
	create := codingIntegrationRequest(time.Now().UTC(), 99)
	create.OperationID = request.OperationID
	if got, err := c.AcceptCreate(ctx, create); !errors.Is(err, codingcontrol.ErrExecIntentConflict) || got.Operation.ID != "" {
		t.Fatalf("generic create reused exec ID: %#v %v", got, err)
	}
	terminate := lifecycle.TerminateRequest{MutationRequest: lease.MutationRequest, Reason: "collision rejection"}
	terminate.OperationID, terminate.IdempotencyKey = request.OperationID, "isolation-term-conflict"
	if got, err := c.AcceptTerminate(ctx, request.SandboxID, terminate); !errors.Is(err, codingcontrol.ErrExecIntentConflict) || got.Operation.ID != "" {
		t.Fatalf("generic terminate reused exec ID: %#v %v", got, err)
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != before || rev != revision {
		t.Fatal("rejected generic operations changed documents or revision")
	}
	// A separate connection already owns the row. Neither a generic exec
	// writer nor a typed replay may bypass that lock using an earlier read.
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBounded(tx, time.Second)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	reservation, err := legacy.ReserveExecution(short, request)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || reservation.Execution.Request.OperationID != "" {
		t.Fatal("generic exec lock cancellation exposed a result", err)
	}
	short, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
	op, _, err := b.ReconcileCodingLease(short, lease.OperationID)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || op.ID != "" {
		t.Fatal("typed replay bypassed row lock", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got, rev := codingPGSnapshot(t, ctx, store); got != before || rev != revision {
		t.Fatal("cancelled transactions changed documents or revision")
	}

	// Two different pools contend for the same operation ID. Exactly one
	// transaction may commit; the loser cannot expose an uncommitted receipt.
	start, done := make(chan struct{}), make(chan error, 2)
	race := request.Clone()
	race.OperationID, race.IdempotencyKey = "isolation-race", "isolation-exec-race"
	raceLease := lease
	raceLease.OperationID, raceLease.AttemptID, raceLease.IdempotencyKey = race.OperationID, "isolation-lease-attempt", "isolation-lease-race"
	go func() {
		<-start
		got, err := b.ReserveCodingExecIntent(ctx, race)
		if err != nil && got != (codingcontrol.ExecIntentReceipt{}) {
			t.Error("rejected race exposed receipt")
		}
		done <- err
	}()
	go func() {
		<-start
		got, err := c.AcceptLease(ctx, request.SandboxID, raceLease, 7200)
		if err != nil && got.Operation.ID != "" {
			t.Error("rejected race exposed operation")
		}
		done <- err
	}()
	close(start)
	e1, e2 := <-done, <-done
	if (e1 == nil) == (e2 == nil) || (e1 != nil && !errors.Is(e1, codingcontrol.ErrExecIntentConflict)) || (e2 != nil && !errors.Is(e2, codingcontrol.ErrExecIntentConflict)) {
		t.Fatalf("race did not admit exactly one identity: %v / %v", e1, e2)
	}
	if _, rev := codingPGSnapshot(t, ctx, store); rev != revision+1 {
		t.Fatal("losing race changed revision")
	}

	// In-place corruption belongs only to this disposable fixture. Restore the
	// entire exact document map after each case, including on assertion failure.
	for _, key := range []string{codingIdentityMarkerDocument, codingExecIntentDocument, lifecycleDocument, codingIdentityStateDocument, execDocument} {
		for _, damage := range []string{"missing", "null", "invalid"} {
			if key == execDocument && damage == "missing" {
				continue
			}
			t.Run(key+" "+damage+" rejects replay", func(t *testing.T) {
				original, rev := codingPGSnapshot(t, ctx, store)
				t.Cleanup(func() {
					if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=$1::jsonb WHERE singleton`, original); err != nil {
						t.Fatal(err)
					}
					if got, after := codingPGSnapshot(t, ctx, store); got != original || after != rev {
						t.Fatal("fixture failed exact restoration")
					}
				})
				if damage == "missing" {
					_, err = store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=documents-$1 WHERE singleton`, key)
				} else {
					document := []byte("null")
					if damage == "invalid" {
						document = []byte(`"not-base64"`)
					}
					_, err = store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(documents,ARRAY[$1]::text[],$2::jsonb,true) WHERE singleton`, key, document)
				}
				if err != nil {
					t.Fatal(err)
				}
				damaged, _ := codingPGSnapshot(t, ctx, store)
				if op, _, err := a.ReconcileCodingLease(ctx, lease.OperationID); err == nil || op.ID != "" {
					t.Fatal("typed unchanged replay bypassed corrupt state", err)
				}
				if got, err := b.ReserveCodingExecIntent(ctx, request); err == nil || got != (codingcontrol.ExecIntentReceipt{}) {
					t.Fatal("intent replay bypassed corrupt state", err)
				}
				if err := a.InitializeCodingExecIntents(ctx); err == nil {
					t.Fatal("initialization replay bypassed corrupt state")
				}
				if got, err := legacy.ListExecutions(ctx); err == nil || got != nil {
					t.Fatal("generic read bypassed corrupt state", err)
				}
				if got, after := codingPGSnapshot(t, ctx, store); got != damaged || after != rev {
					t.Fatal("rejected replay changed corrupt state")
				}
			})
		}
	}
	// Orphan intents must also block marker/slot bootstrap after both markers
	// are lost. The independent-empty callback is synthetic, not physical proof.
	t.Run("orphan blocks rebootstrap", func(t *testing.T) {
		original, rev := codingPGSnapshot(t, ctx, store)
		t.Cleanup(func() {
			if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=$1::jsonb WHERE singleton`, original); err != nil {
				t.Fatal(err)
			}
		})
		if _, err := store.pool.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state SET documents=documents-$1-$2 WHERE singleton`, codingIdentityMarkerDocument, codingIdentityStateDocument); err != nil {
			t.Fatal(err)
		}
		damaged, _ := codingPGSnapshot(t, ctx, store)
		if err := a.InitializeCodingAtomicOriginal(ctx, func(context.Context, codingidentity.Plan) error { return nil }); err == nil {
			t.Fatal("orphan intent history reinitialized")
		}
		if got, after := codingPGSnapshot(t, ctx, store); got != damaged || after != rev {
			t.Fatal("orphan initialization changed state")
		}
	})
}
