package dockercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testReceiptPath(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "receipts.json")
}

func testCleanNamespace(context.Context) error { return nil }

// These cleanup-only tests need an already Completed fixture. Construct
// matching private evidence explicitly in test code; this is not a trusted
// physical observer or a production completion entry point.
func testPersistSyntheticCompleted(t *testing.T, ledger *CodingReceiptLedger) CodingReceiptState {
	t.Helper()
	source := ledger.current.Clone()
	completed := source.Clone()
	receipt := completed.Records[0]
	proof := codingCompletionObservation{AuthorityDigest: receipt.AuthorityDigest,
		EffectID: receipt.Authority.EffectID, ReceiptRevision: source.Revision}
	proofDocument, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	proof.CompletionDigest = digest(append(
		[]byte("sandbox-runtime/docker-control-coding-completion/v1\x00"), proofDocument...))
	evidence := codingCompletionEvidence{Schema: codingCompletionEvidenceSchema,
		EffectID: receipt.Authority.EffectID, AuthorityDigest: receipt.AuthorityDigest,
		SourceRevision: source.Revision, SourceStateDigest: source.StateDigest,
		CapturedAt: time.Now().UTC(), Proof: proof}
	receipt.Status = ReceiptCompleted
	receipt.CompletionDigest = proof.CompletionDigest
	receipt.CompletionEvidenceDigest = evidence.digest()
	completed.Records[0] = receipt
	completed.Revision++
	completed.StateDigest = completed.digest()
	if completed.Validate(ledger.binding) != nil {
		t.Fatal("invalid synthetic Completed fixture")
	}
	path, err := completionEvidencePath(ledger.path, receipt.Authority.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(document); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeReceiptState(ledger.path, completed); err != nil {
		t.Fatal(err)
	}
	ledger.current = completed
	return completed
}

func TestCodingReceiptLedgerCommitBeforeDispatchAndReopenUnknown(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	path := testReceiptPath(t)
	if _, err := OpenCodingReceiptLedger(path, binding); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("uninitialized ledger opened: %v", err)
	}
	ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("ledger reinitialized: %v", err)
	}
	if _, err := OpenCodingReceiptLedger(path, binding); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("second writer opened: %v", err)
	}
	var calls atomic.Int32
	callback := func(_ context.Context, got CodingCreateAuthority) error {
		calls.Add(1)
		if got != a {
			t.Fatal("callback received altered authority")
		}
		if lookedUp, err := ledger.Lookup(a.RequestID); err != nil || lookedUp.Status != ReceiptUnknown {
			t.Fatalf("callback could not read committed status: %#v, %v", lookedUp, err)
		}
		projected, revision, stateDigest, err := ledger.LookupProjection(a.RequestID)
		if err != nil || projected.Status != ReceiptUnknown || revision != 2 ||
			stateDigest == "" {
			t.Fatalf("callback could not read one sealed state: %#v, %d, %q, %v",
				projected, revision, stateDigest, err)
		}
		stored, err := readReceiptState(path, binding)
		if err != nil || stored.Revision != 2 || len(stored.Records) != 1 ||
			stored.Records[0].Status != ReceiptUnknown {
			t.Fatalf("callback ran before durable Unknown: %#v, %v", stored, err)
		}
		return nil
	}
	receipt, err := ledger.DispatchCodingCreate(context.Background(), a, callback)
	if err != nil || receipt.Status != ReceiptUnknown || calls.Load() != 1 {
		t.Fatalf("dispatch = %#v, %v, callbacks=%d", receipt, err, calls.Load())
	}
	if _, err := ledger.DispatchCodingCreate(context.Background(), a, callback); !errors.Is(err, ErrReceiptReplay) || calls.Load() != 1 {
		t.Fatalf("same-process replay = %v, callbacks=%d", err, calls.Load())
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	changedSpec := binding.clone()
	changedSpec.SpecBySlot[plan.Slots[1].ID] = testControlDigest("0")
	if _, err := OpenCodingReceiptLedger(path, changedSpec); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("unoccupied slot spec-map drift reopened ledger: %v", err)
	}
	wrongDaemon := binding
	wrongDaemon.DaemonDigest = testControlDigest("0")
	if _, err := OpenCodingReceiptLedger(path, wrongDaemon); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("different Docker daemon reopened original receipt ledger: %v", err)
	}
	reopened, err := OpenCodingReceiptLedger(path, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.DispatchCodingCreate(context.Background(), a, callback); !errors.Is(err, ErrReceiptReplay) || calls.Load() != 1 {
		t.Fatalf("reopen replay = %v, callbacks=%d", err, calls.Load())
	}
	lookedUp, err := reopened.Lookup(a.RequestID)
	if err != nil || lookedUp != receipt {
		t.Fatalf("read-only recovery = %#v, %v", lookedUp, err)
	}
	projected, revision, stateDigest, err := reopened.LookupProjection(a.RequestID)
	if err != nil || projected != receipt || revision != reopened.current.Revision ||
		stateDigest != reopened.current.StateDigest {
		t.Fatalf("reopened sealed projection = %#v, %d, %q, %v", projected, revision, stateDigest, err)
	}
	projected, revision, stateDigest, err = reopened.LookupBoundProjection(a,
		binding.PeerPrincipalDigest, a.ExpiresAt.Add(time.Second))
	if err != nil || projected != receipt || revision != reopened.current.Revision ||
		stateDigest != reopened.current.StateDigest {
		t.Fatalf("expired authority was not available for historical status: %#v, %d, %q, %v",
			projected, revision, stateDigest, err)
	}
	if _, _, _, err := reopened.LookupBoundProjection(a, testControlDigest("0"),
		a.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("different authenticated peer read status: %v", err)
	}
	changed := a
	changed.ControlPolicyDigest = testControlDigest("0")
	if _, _, _, err := reopened.LookupBoundProjection(changed, binding.PeerPrincipalDigest,
		a.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("different Control policy read status: %v", err)
	}
	if _, err := reopened.Lookup(testControlDigest("0")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown request lookup = %v", err)
	}
	if projected, revision, stateDigest, err := reopened.LookupProjection(testControlDigest("0")); !errors.Is(err, os.ErrNotExist) || projected != (CodingReceipt{}) || revision != 0 || stateDigest != "" {
		t.Fatalf("missing projection fabricated state = %#v, %d, %q, %v", projected, revision, stateDigest, err)
	}
}

func TestCodingReceiptLedgerFailClosedAfterErrorAndMissingState(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	physicalError := errors.New("ambiguous physical result")
	var calls atomic.Int32
	callback := func(context.Context, CodingCreateAuthority) error {
		calls.Add(1)
		return physicalError
	}
	if _, err := ledger.DispatchCodingCreate(context.Background(), a, callback); !errors.Is(err, physicalError) {
		t.Fatalf("physical error = %v", err)
	}
	if _, err := ledger.DispatchCodingCreate(context.Background(), a, callback); !errors.Is(err, ErrReceiptReplay) || calls.Load() != 1 {
		t.Fatalf("ambiguous operation replay = %v, calls=%d", err, calls.Load())
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCodingReceiptLedger(path, binding); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("missing initialized state opened: %v", err)
	}
	if _, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("missing ledger silently reinitialized: %v", err)
	}
}

// A client timeout is not a daemon fence. Two empty inventories after the
// local callback returns can precede a delayed physical create. Until a
// separate external quiescence proof exists, the Unknown ledger holds the
// effect and its slot instead of turning those reads into Release authority.
func TestCodingReceiptLedgerLateDaemonEffectSurvivesTwoEmptyReads(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	ledger, err := InitializeCodingReceiptLedger(context.Background(), testReceiptPath(t), binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	late := make(chan struct{})
	done := make(chan struct{})
	var present atomic.Bool
	physical := func(context.Context, CodingCreateAuthority) error {
		go func() {
			<-late
			present.Store(true)
			close(done)
		}()
		return context.DeadlineExceeded // lost client-side result, daemon work in flight
	}
	if receipt, err := ledger.DispatchCodingCreate(context.Background(), a, physical); !errors.Is(err, context.DeadlineExceeded) || receipt.Status != ReceiptUnknown {
		t.Fatalf("ambiguous dispatch = %#v, %v", receipt, err)
	}
	for observation := 0; observation < 2; observation++ {
		if present.Load() {
			t.Fatal("fixture unexpectedly created before absent observation")
		}
		if receipt, err := ledger.Lookup(a.RequestID); err != nil || receipt.Status != ReceiptUnknown {
			t.Fatalf("absent observation %d released receipt: %#v, %v", observation, receipt, err)
		}
	}
	close(late)
	<-done
	if !present.Load() {
		t.Fatal("late daemon effect did not arrive")
	}
	if receipt, err := ledger.Lookup(a.RequestID); err != nil || receipt.Status != ReceiptUnknown {
		t.Fatalf("late create changed receipt: %#v, %v", receipt, err)
	}
	if _, err := ledger.DispatchCodingCreate(context.Background(), a, physical); !errors.Is(err, ErrReceiptReplay) {
		t.Fatalf("late-effect replay granted: %v", err)
	}
}

func TestCodingReceiptLedgerCleanupIntentCommitsBeforeCallback(t *testing.T) {
	create, ticket, operation, sandbox, plan, _ := testCodingCleanup(t)
	binding := testReceiptBinding(create, plan)
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if _, err := ledger.DispatchCodingCreate(context.Background(), create,
		func(context.Context, CodingCreateAuthority) error { return nil }); err != nil {
		t.Fatal(err)
	}
	intent, err := NewCodingCleanupAuthority(context.Background(), create, ticket,
		operation, sandbox, plan, binding.ControlPolicyDigest, binding.PeerPrincipalDigest, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.DispatchCodingCleanup(context.Background(), create.RequestID, intent,
		func(context.Context, CodingCleanupAuthority) error {
			t.Fatal("Unknown receipt granted deletion callback")
			return nil
		}); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("Unknown cleanup attempt = %v", err)
	}
	// Only a trusted physical observer may eventually produce Completed. This
	// test-only fixture exercises the independent persistence ordering while
	// that observer/production adapter remains intentionally unimplemented.
	ledger.mu.Lock()
	completed := testPersistSyntheticCompleted(t, ledger)
	ledger.mu.Unlock()
	var calls atomic.Int32
	receipt, err := ledger.DispatchCodingCleanup(context.Background(), create.RequestID, intent,
		func(_ context.Context, got CodingCleanupAuthority) error {
			calls.Add(1)
			if got != intent {
				t.Fatal("altered cleanup intent reached callback")
			}
			stored, readErr := readReceiptState(path, binding)
			if readErr != nil || stored.Revision != completed.Revision+1 ||
				stored.Records[0].CleanupAuthority != intent || stored.Records[0].Status != ReceiptCompleted {
				t.Fatalf("cleanup callback ran before durable intent: %#v, %v", stored, readErr)
			}
			return nil
		})
	if err != nil || receipt.CleanupAuthority != intent || calls.Load() != 1 {
		t.Fatalf("cleanup dispatch = %#v, %v, calls=%d", receipt, err, calls.Load())
	}
	if _, err := ledger.DispatchCodingCleanup(context.Background(), create.RequestID, intent,
		func(context.Context, CodingCleanupAuthority) error {
			calls.Add(1)
			return nil
		}); !errors.Is(err, ErrReceiptReplay) || calls.Load() != 1 {
		t.Fatalf("cleanup replay = %v, calls=%d", err, calls.Load())
	}
	if receipt, err := ledger.Lookup(create.RequestID); err != nil || receipt.Status != ReceiptCompleted ||
		receipt.AbsenceDigest != "" {
		t.Fatalf("cleanup callback forged release: %#v, %v", receipt, err)
	}
}

func TestCodingReceiptLedgerCleanupPersistenceFaultNeverDeletes(t *testing.T) {
	for _, stage := range []string{"before-write", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			create, ticket, operation, sandbox, plan, _ := testCodingCleanup(t)
			binding := testReceiptBinding(create, plan)
			path := testReceiptPath(t)
			ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.DispatchCodingCreate(context.Background(), create,
				func(context.Context, CodingCreateAuthority) error { return nil }); err != nil {
				t.Fatal(err)
			}
			ledger.mu.Lock()
			testPersistSyntheticCompleted(t, ledger)
			ledger.mu.Unlock()
			intent, err := NewCodingCleanupAuthority(context.Background(), create, ticket,
				operation, sandbox, plan, binding.ControlPolicyDigest, binding.PeerPrincipalDigest, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			ledger.writeFault = func(at string) error {
				if at == stage {
					return errors.New("injected cleanup sync ambiguity")
				}
				return nil
			}
			var calls atomic.Int32
			if _, err := ledger.DispatchCodingCleanup(context.Background(), create.RequestID, intent,
				func(context.Context, CodingCleanupAuthority) error {
					calls.Add(1)
					return nil
				}); !errors.Is(err, ErrInvalidReceiptState) || calls.Load() != 0 {
				t.Fatalf("%s cleanup granted callback: %v, calls=%d", stage, err, calls.Load())
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenCodingReceiptLedger(path, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			receipt, err := reopened.Lookup(create.RequestID)
			if err != nil || receipt.Status != ReceiptCompleted {
				t.Fatalf("%s cleanup receipt = %#v, %v", stage, receipt, err)
			}
			if stage == "before-write" && receipt.CleanupAuthority != (CodingCleanupAuthority{}) {
				t.Fatal("pre-write failure unexpectedly stored cleanup intent")
			}
			if stage == "after-rename" {
				if receipt.CleanupAuthority != intent {
					t.Fatal("ambiguous post-rename cleanup intent missing")
				}
				if _, err := reopened.DispatchCodingCleanup(context.Background(), create.RequestID, intent,
					func(context.Context, CodingCleanupAuthority) error { calls.Add(1); return nil }); !errors.Is(err, ErrReceiptReplay) || calls.Load() != 0 {
					t.Fatalf("ambiguous cleanup replay = %v, calls=%d", err, calls.Load())
				}
			}
		})
	}
}

func TestCodingReceiptLedgerRejectsDriftCapacityAndTamper(t *testing.T) {
	a, plan, now := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	callback := func(context.Context, CodingCreateAuthority) error { return nil }
	if _, err := ledger.DispatchCodingCreate(context.Background(), a, callback); err != nil {
		t.Fatal(err)
	}
	drift := a
	drift.Fence++
	drift.RequestID = codingRequestID(drift)
	if _, err := ledger.DispatchCodingCreate(context.Background(), drift, callback); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("fence drift = %v", err)
	}
	second := otherReceiptAuthority(t, "b", 1, now)
	if _, err := ledger.DispatchCodingCreate(context.Background(), second, callback); err != nil {
		t.Fatal(err)
	}
	third := otherReceiptAuthority(t, "c", 1, now)
	if _, err := ledger.DispatchCodingCreate(context.Background(), third, callback); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("third create on occupied physical slot = %v", err)
	}
	wrongBinding := binding
	wrongBinding.PlanDigest = testControlDigest("0")
	if _, err := OpenCodingReceiptLedger(path, wrongBinding); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("different Profile binding opened: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Lookup(a.RequestID); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("tampered state read = %v", err)
	}
}

func TestCodingReceiptLedgerCancellationAndPrivatePath(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ledger.DispatchCodingCreate(ctx, a, func(context.Context, CodingCreateAuthority) error {
		t.Fatal("cancelled dispatch invoked physical callback")
		return nil
	}); err == nil {
		t.Fatal("cancelled dispatch accepted")
	}
	stored, err := ledger.Lookup(a.RequestID)
	if !errors.Is(err, os.ErrNotExist) || stored != (CodingReceipt{}) {
		t.Fatalf("cancelled request recorded: %#v, %v", stored, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Lookup(a.RequestID); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("public ledger read = %v", err)
	}
	if _, err := InitializeCodingReceiptLedger(context.Background(), filepath.Join(path, "nested"), binding, testCleanNamespace); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("unsafe parent accepted: %v", err)
	}
}

func TestCodingReceiptLedgerInitializationRequiresCleanNamespaceProof(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	path := testReceiptPath(t)
	var called atomic.Int32
	if _, err := InitializeCodingReceiptLedger(context.Background(), path, binding,
		func(context.Context) error {
			called.Add(1)
			return errors.New("physical namespace not proven empty")
		}); !errors.Is(err, ErrInvalidReceiptState) || called.Load() != 1 {
		t.Fatalf("unproved initialization = %v, checks=%d", err, called.Load())
	}
	if _, err := OpenCodingReceiptLedger(path, binding); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("partial initialization opened: %v", err)
	}
	if _, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("partial initialization silently retried: %v", err)
	}
}

func TestCodingReceiptLedgerFaultWindowsNeverGrantPermit(t *testing.T) {
	for _, stage := range []string{"before-write", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			a, plan, _ := testReceiptAuthority(t)
			binding := testReceiptBinding(a, plan)
			path := testReceiptPath(t)
			ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
			if err != nil {
				t.Fatal(err)
			}
			ledger.writeFault = func(at string) error {
				if at == stage {
					return errors.New("injected ambiguous durable-write failure")
				}
				return nil
			}
			var calls atomic.Int32
			callback := func(context.Context, CodingCreateAuthority) error {
				calls.Add(1)
				return nil
			}
			if _, err := ledger.DispatchCodingCreate(context.Background(), a, callback); !errors.Is(err, ErrInvalidReceiptState) || calls.Load() != 0 {
				t.Fatalf("%s granted callback: %v, calls=%d", stage, err, calls.Load())
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenCodingReceiptLedger(path, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if stage == "before-write" {
				if _, err := reopened.Lookup(a.RequestID); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("pre-write fault persisted intent: %v", err)
				}
			} else {
				if receipt, err := reopened.Lookup(a.RequestID); err != nil || receipt.Status != ReceiptUnknown {
					t.Fatalf("post-rename Unknown missing: %#v, %v", receipt, err)
				}
				if _, err := reopened.DispatchCodingCreate(context.Background(), a, callback); !errors.Is(err, ErrReceiptReplay) || calls.Load() != 0 {
					t.Fatalf("post-rename replay dispatched: %v, calls=%d", err, calls.Load())
				}
			}
		})
	}
}

func TestCodingReceiptLedgerTrustedClockRechecksAfterCommit(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	current := a.IssuedAt.Add(time.Second)
	ledger.clock = func() time.Time { return current }
	ledger.writeFault = func(stage string) error {
		if stage == "after-rename" {
			current = a.ExpiresAt
		}
		return nil
	}
	var calls atomic.Int32
	if receipt, err := ledger.DispatchCodingCreate(context.Background(), a,
		func(context.Context, CodingCreateAuthority) error {
			calls.Add(1)
			return nil
		}); !errors.Is(err, ErrInvalidAuthority) || receipt.Status != ReceiptUnknown || calls.Load() != 0 {
		t.Fatalf("expired after commit = %#v, %v, calls=%d", receipt, err, calls.Load())
	}
	if receipt, err := ledger.Lookup(a.RequestID); err != nil || receipt.Status != ReceiptUnknown {
		t.Fatalf("committed expired Unknown = %#v, %v", receipt, err)
	}
}

func TestCodingReceiptLedgerQueuedExpiryAndPostCommitCancellation(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	var calls atomic.Int32
	callback := func(context.Context, CodingCreateAuthority) error {
		calls.Add(1)
		return nil
	}
	ledger.mu.Lock()
	started := make(chan struct{})
	queued := make(chan error, 1)
	go func() {
		close(started)
		_, err := ledger.DispatchCodingCreate(context.Background(), a, callback)
		queued <- err
	}()
	<-started
	ledger.clock = func() time.Time { return a.ExpiresAt }
	ledger.mu.Unlock()
	if err := <-queued; !errors.Is(err, ErrInvalidReceiptState) || calls.Load() != 0 {
		t.Fatalf("queued expired request = %v, callbacks=%d", err, calls.Load())
	}
	if _, err := ledger.Lookup(a.RequestID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("queued expiry left an intent: %v", err)
	}
	ledger.clock = func() time.Time { return a.IssuedAt.Add(time.Second) }
	ctx, cancel := context.WithCancel(context.Background())
	ledger.writeFault = func(stage string) error {
		if stage == "after-rename" {
			cancel()
		}
		return nil
	}
	if receipt, err := ledger.DispatchCodingCreate(ctx, a, callback); !errors.Is(err, context.Canceled) ||
		receipt.Status != ReceiptUnknown || calls.Load() != 0 {
		t.Fatalf("post-commit cancelled request = %#v, %v, callbacks=%d", receipt, err, calls.Load())
	}
	if receipt, err := ledger.Lookup(a.RequestID); err != nil || receipt.Status != ReceiptUnknown {
		t.Fatalf("post-cancel Unknown missing: %#v, %v", receipt, err)
	}
}

func TestCodingReceiptLedgerCloseWaitsForCallbackWithoutBlockingLookup(t *testing.T) {
	a, plan, _ := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(context.Background(), path, binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	dispatched := make(chan error, 1)
	go func() {
		_, err := ledger.DispatchCodingCreate(context.Background(), a,
			func(context.Context, CodingCreateAuthority) error {
				close(started)
				<-release
				return nil
			})
		dispatched <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not start")
	}
	if receipt, err := ledger.Lookup(a.RequestID); err != nil || receipt.Status != ReceiptUnknown {
		t.Fatalf("lookup blocked by callback: %#v, %v", receipt, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := ledger.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close claimed quiescence during callback: %v", err)
	}
	if _, err := OpenCodingReceiptLedger(path, binding); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("writer lock released during callback: %v", err)
	}
	close(release)
	if err := <-dispatched; err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCodingReceiptLedger(path, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}
