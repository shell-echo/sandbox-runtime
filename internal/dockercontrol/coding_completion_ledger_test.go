package dockercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testLiveCodingCompletionLedger(t *testing.T, fixture codingCompletionFixture) (*CodingReceiptLedger, string) {
	t.Helper()
	path := testReceiptPath(t)
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := InitializeCodingReceiptLedger(t.Context(), path,
		fixture.observer.binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	if _, err := ledger.DispatchCodingCreate(t.Context(), fixture.receipt.Authority,
		func(context.Context, CodingCreateAuthority) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return ledger, path
}

func TestCodingLiveCompletionPersistsPrivateProofBeforeReceipt(t *testing.T) {
	fixture := testCodingCompletionFixture(t)
	ledger, path := testLiveCodingCompletionLedger(t, fixture)
	completed, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID, fixture.observer)
	if err != nil || completed.Status != ReceiptCompleted ||
		!controlDigest.MatchString(completed.CompletionDigest) {
		t.Fatalf("live completion: %v, calls=%d", err, len(*fixture.calls))
	}
	stored, err := readReceiptState(path, fixture.observer.binding)
	if err != nil || stored.Revision != fixture.revision+1 ||
		len(stored.Records) != 1 || stored.Records[0] != completed {
		t.Fatalf("durable completion: %#v, %v", stored, err)
	}
	evidencePath, err := ledger.completionEvidencePath(fixture.receipt.Authority.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(evidencePath)
	if err != nil || !validReceiptRegular(info) {
		t.Fatalf("private evidence mode: %v", err)
	}
	document, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence codingCompletionEvidence
	if json.Unmarshal(document, &evidence) != nil ||
		evidence.Proof.CompletionDigest != completed.CompletionDigest ||
		evidence.digest() != completed.CompletionEvidenceDigest ||
		evidence.SourceRevision != fixture.revision ||
		evidence.SourceStateDigest == "" || len(*fixture.calls) != 23 {
		t.Fatal("private proof is not bound to the original state and full observation")
	}
	if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
		fixture.observer); !errors.Is(err, ErrReceiptConflict) || len(*fixture.calls) != 23 {
		t.Fatalf("completion replay performed physical reads: %v", err)
	}
	snapshot, err := ledger.ReadCompletedSnapshot(fixture.receipt.Authority.RequestID)
	if err != nil || snapshot.Validate(fixture.receipt.Authority) != nil ||
		snapshot.Revision() != stored.Revision || snapshot.StateDigest() != stored.StateDigest ||
		snapshot.Receipt() != completed {
		t.Fatalf("Control-private completed snapshot mismatch: %v", err)
	}
	wrong := fixture.receipt.Authority
	wrong.RequestID = testControlDigest("0")
	if snapshot.Validate(wrong) == nil {
		t.Fatal("completed snapshot accepted different create authority")
	}
}

func TestCodingLiveCompletionRejectsReopenedUnknownAndAmbiguousCreate(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(map[bool]string{false: "reopened", true: "ambiguous"}[ambiguous], func(t *testing.T) {
			fixture := testCodingCompletionFixture(t)
			path := testReceiptPath(t)
			ledger, err := InitializeCodingReceiptLedger(t.Context(), path,
				fixture.observer.binding, testCleanNamespace)
			if err != nil {
				t.Fatal(err)
			}
			physicalResult := error(nil)
			if ambiguous {
				physicalResult = context.DeadlineExceeded
			}
			_, dispatchErr := ledger.DispatchCodingCreate(t.Context(), fixture.receipt.Authority,
				func(context.Context, CodingCreateAuthority) error { return physicalResult })
			if !errors.Is(dispatchErr, physicalResult) && ambiguous || dispatchErr != nil && !ambiguous {
				t.Fatalf("dispatch: %v", dispatchErr)
			}
			if !ambiguous {
				if err := ledger.Close(); err != nil {
					t.Fatal(err)
				}
				ledger, err = OpenCodingReceiptLedger(path, fixture.observer.binding)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer ledger.Close()
			if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
				fixture.observer); !errors.Is(err, ErrReceiptConflict) || len(*fixture.calls) != 0 {
				t.Fatalf("historical/ambiguous Unknown was completed or read: %v", err)
			}
		})
	}
}

func TestCodingLiveCompletionRejectsStaleRevisionAndAlreadyCompleted(t *testing.T) {
	fixture := testCodingCompletionFixture(t)
	proof, err := fixture.observer.observeCompleted(t.Context(), fixture.receipt, fixture.revision)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewCodingReceiptState(fixture.observer.binding)
	if err != nil {
		t.Fatal(err)
	}
	state, _, _, err = state.beginUnknown(fixture.observer.binding,
		fixture.receipt.Authority, fixture.receipt.Authority.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	stale := state.Clone()
	stale.Revision++
	stale.StateDigest = stale.digest()
	if _, _, err := stale.completeObserved(fixture.observer.binding,
		fixture.receipt.Authority.RequestID, proof, testControlDigest("7"), time.Now()); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("stale proof revision accepted: %v", err)
	}
	cleaning := state.Clone()
	cleaning.Records[0].Status = ReceiptCompleted
	cleaning.Records[0].CompletionDigest = proof.CompletionDigest
	cleaning.Records[0].CompletionEvidenceDigest = testControlDigest("7")
	cleaning.Revision++
	cleaning.StateDigest = cleaning.digest()
	if _, _, err := cleaning.completeObserved(fixture.observer.binding,
		fixture.receipt.Authority.RequestID, proof, testControlDigest("7"), time.Now()); err == nil {
		t.Fatal("already completed receipt accepted a second completion")
	}
}

func TestCodingLiveCompletionRejectsCreateCanceledBeforeReturn(t *testing.T) {
	fixture := testCodingCompletionFixture(t)
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(t.Context(), path,
		fixture.observer.binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	ctx, cancel := context.WithCancel(t.Context())
	if _, err := ledger.DispatchCodingCreate(ctx, fixture.receipt.Authority,
		func(context.Context, CodingCreateAuthority) error {
			cancel()
			return nil
		}); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("canceled create callback appeared unambiguous: %v", err)
	}
	if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
		fixture.observer); !errors.Is(err, ErrReceiptConflict) || len(*fixture.calls) != 0 {
		t.Fatalf("canceled create qualified for completion: %v", err)
	}
}

func TestCodingLiveCompletionExpiresBeforeObservationWithoutGET(t *testing.T) {
	fixture := testCodingCompletionFixture(t)
	ledger, path := testLiveCodingCompletionLedger(t, fixture)
	ledger.clock = func() time.Time { return fixture.receipt.Authority.ExpiresAt.Add(time.Nanosecond) }
	if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
		fixture.observer); !errors.Is(err, ErrInvalidAuthority) || len(*fixture.calls) != 0 {
		t.Fatalf("expired authority observed Docker: %v", err)
	}
	stored, err := readReceiptState(path, fixture.observer.binding)
	if err != nil || stored.Records[0].Status != ReceiptUnknown {
		t.Fatalf("expired authority changed durable receipt: %v", err)
	}
}

func TestCodingLiveCompletionEvidenceToCommitBoundary(t *testing.T) {
	for _, mode := range []string{"cancel-after-evidence", "expire-after-evidence", "cancel-after-commit"} {
		t.Run(mode, func(t *testing.T) {
			fixture := testCodingCompletionFixture(t)
			ledger, path := testLiveCodingCompletionLedger(t, fixture)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fakeNow := time.Now().UTC()
			ledger.clock = func() time.Time { return fakeNow }
			ledger.completionStage = func(stage string) {
				if stage == "after-evidence" && mode == "cancel-after-evidence" ||
					stage == "after-commit" && mode == "cancel-after-commit" {
					cancel()
				}
				if stage == "after-evidence" && mode == "expire-after-evidence" {
					fakeNow = fixture.receipt.Authority.ExpiresAt.Add(time.Nanosecond)
				}
			}
			if _, err := ledger.completeCodingCreate(ctx, fixture.receipt.Authority.RequestID,
				fixture.observer); err == nil {
				t.Fatal("canceled/expired boundary reported successful completion")
			}
			stored, err := readReceiptState(path, fixture.observer.binding)
			if err != nil || len(*fixture.calls) != 23 {
				t.Fatalf("boundary proof/receipt missing: %v", err)
			}
			want := ReceiptUnknown
			if mode == "cancel-after-commit" {
				want = ReceiptCompleted
			}
			if stored.Records[0].Status != want {
				t.Fatalf("boundary durable status = %s, want %s", stored.Records[0].Status, want)
			}
			evidencePath, err := ledger.completionEvidencePath(fixture.receipt.Authority.EffectID)
			if err != nil {
				t.Fatal(err)
			}
			if info, err := os.Lstat(evidencePath); err != nil || !validReceiptRegular(info) {
				t.Fatalf("boundary evidence not durable before receipt decision: %v", err)
			}
			if want == ReceiptUnknown {
				if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
					fixture.observer); err == nil || len(*fixture.calls) != 23 {
					t.Fatalf("orphan evidence imported by retry: %v", err)
				}
			}
		})
	}
}

func TestCodingLiveCompletionPersistenceAmbiguityFailsClosed(t *testing.T) {
	for _, stage := range []string{"before-write", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			fixture := testCodingCompletionFixture(t)
			ledger, path := testLiveCodingCompletionLedger(t, fixture)
			ledger.writeFault = func(at string) error {
				if at == stage {
					return errors.New("injected completion persistence ambiguity")
				}
				return nil
			}
			if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
				fixture.observer); !errors.Is(err, ErrInvalidReceiptState) {
				t.Fatalf("ambiguous completion returned success: %v", err)
			}
			if len(*fixture.calls) != 23 {
				t.Fatalf("physical observation count = %d", len(*fixture.calls))
			}
			evidencePath, err := ledger.completionEvidencePath(fixture.receipt.Authority.EffectID)
			if err != nil {
				t.Fatal(err)
			}
			if info, err := os.Lstat(evidencePath); err != nil || !validReceiptRegular(info) {
				t.Fatalf("evidence was not persisted before ambiguous receipt write: %v", err)
			}
			if stage == "before-write" {
				if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
					fixture.observer); !errors.Is(err, ErrInvalidReceiptState) || len(*fixture.calls) != 23 {
					t.Fatalf("orphan evidence allowed repeat observation: %v", err)
				}
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenCodingReceiptLedger(path, fixture.observer.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			stored, err := reopened.Lookup(fixture.receipt.Authority.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			want := ReceiptUnknown
			if stage == "after-rename" {
				want = ReceiptCompleted
			}
			if stored.Status != want {
				t.Fatalf("ambiguous durable state = %s, want %s", stored.Status, want)
			}
			if _, err := reopened.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
				fixture.observer); err == nil || len(*fixture.calls) != 23 {
				t.Fatalf("response loss replayed physical observation: %v", err)
			}
		})
	}
}

func TestCodingLiveCompletionCancelDrainAndCloseOrdering(t *testing.T) {
	fixture := testCodingCompletionFixture(t)
	ledger, path := testLiveCodingCompletionLedger(t, fixture)
	// Hold the observer's own bounded admission gate, not the ledger mutex.
	<-fixture.observer.gate
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := ledger.completeCodingCreate(ctx, fixture.receipt.Authority.RequestID, fixture.observer)
		done <- err
	}()
	deadline := time.After(2 * time.Second)
	for {
		ledger.mu.Lock()
		active := ledger.completionInFlight
		ledger.mu.Unlock()
		if active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("completion never entered bounded observer wait")
		case <-time.After(time.Millisecond):
		}
	}
	if receipt, err := ledger.Lookup(fixture.receipt.Authority.RequestID); err != nil ||
		receipt.Status != ReceiptUnknown {
		t.Fatalf("ledger mutex held across Docker admission: %#v, %v", receipt, err)
	}
	var dispatched bool
	if _, err := ledger.DispatchCodingCreate(t.Context(), fixture.receipt.Authority,
		func(context.Context, CodingCreateAuthority) error { dispatched = true; return nil }); !errors.Is(err, ErrInvalidReceiptState) || dispatched {
		t.Fatalf("create dispatched during completion: %v", err)
	}
	short, stop := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer stop()
	if err := ledger.CloseContext(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close reported drain while observer in flight: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, ErrInvalidCodingCompletionObservation) {
		t.Fatalf("canceled observation: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	stored, err := readReceiptState(path, fixture.observer.binding)
	if err != nil || stored.Records[0].Status != ReceiptUnknown || len(*fixture.calls) != 0 {
		t.Fatalf("cancellation changed durable receipt or queried Docker: %v", err)
	}
}

func TestCodingLiveCompletionRejectsWrongAuthorityBeforeObservation(t *testing.T) {
	fixture := testCodingCompletionFixture(t)
	ledger, _ := testLiveCodingCompletionLedger(t, fixture)
	wrong := *fixture.observer
	wrong.authority.RequestID = testControlDigest("0")
	if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
		&wrong); !errors.Is(err, ErrReceiptConflict) || len(*fixture.calls) != 0 {
		t.Fatalf("wrong authority reached Docker observation: %v", err)
	}
}

func TestCodingCompletedReopenRequiresBoundPrivateEvidence(t *testing.T) {
	for _, mutation := range []string{"missing", "digest-drift", "noncanonical", "captured-at", "source-state-drift"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := testCodingCompletionFixture(t)
			ledger, path := testLiveCodingCompletionLedger(t, fixture)
			if _, err := ledger.completeCodingCreate(t.Context(),
				fixture.receipt.Authority.RequestID, fixture.observer); err != nil {
				t.Fatal(err)
			}
			evidencePath, err := ledger.completionEvidencePath(fixture.receipt.Authority.EffectID)
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing":
				if err := os.Remove(evidencePath); err != nil {
					t.Fatal(err)
				}
			case "digest-drift", "noncanonical", "captured-at", "source-state-drift":
				document, err := os.ReadFile(evidencePath)
				if err != nil {
					t.Fatal(err)
				}
				if mutation != "noncanonical" {
					var evidence codingCompletionEvidence
					if err := json.Unmarshal(document, &evidence); err != nil {
						t.Fatal(err)
					}
					switch mutation {
					case "digest-drift":
						evidence.Proof.CompletionDigest = testControlDigest("0")
					case "captured-at":
						evidence.CapturedAt = evidence.CapturedAt.Add(time.Second)
					case "source-state-drift":
						evidence.SourceStateDigest = testControlDigest("0")
					}
					document, err = json.Marshal(evidence)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					document = append(document, '\n')
				}
				if err := os.WriteFile(evidencePath, document, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := OpenCodingReceiptLedger(path, fixture.observer.binding); !errors.Is(err, ErrInvalidReceiptState) {
				t.Fatalf("Completed reopened without bound evidence: %v", err)
			}
		})
	}
}
