package qualificationharness

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type evidenceAssemblerFunc func(context.Context, EvidenceSnapshot) (EvidenceFinalizationResult, error)

func (f evidenceAssemblerFunc) AssembleAndVerify(ctx context.Context, snapshot EvidenceSnapshot) (EvidenceFinalizationResult, error) {
	return f(ctx, snapshot)
}

func TestFinalizeEvidenceTransfersOneShotDefensiveSnapshotAndBindsReceipt(t *testing.T) {
	prepared := preparedEvidenceFixture(t)
	calls := 0
	var observed EvidenceSnapshot
	assembler := evidenceAssemblerFunc(func(ctx context.Context, snapshot EvidenceSnapshot) (EvidenceFinalizationResult, error) {
		calls++
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(prepared.totalDeadline) {
			t.Fatalf("assembly context deadline = %v, %t", deadline, ok)
		}
		observed = cloneEvidenceSnapshot(snapshot)
		result := passingEvidenceFinalization(snapshot)
		snapshot.Runtime.Artifacts[0].ArtifactID = "changed"
		snapshot.Observation.Observations[0].ObservationID = "changed"
		snapshot.Cleanup.Baseline.SampledAt[0] = time.Time{}
		return result, nil
	})

	result, err := FinalizeEvidence(context.Background(), prepared, assembler)
	if err != nil {
		t.Fatalf("FinalizeEvidence() error = %v", err)
	}
	if calls != 1 || result.ValidationOutcome != "accepted" || result.RunOutcome != DerivedPassed || observed.RuntimeCommitmentDigest != prepared.Digest() || len(observed.Observation.Observations) != 91 {
		t.Fatalf("FinalizeEvidence() result = %+v, calls=%d", result, calls)
	}
	if prepared.Observation().Artifacts[0].ArtifactID == "changed" {
		t.Fatal("assembler mutated the stored runtime observation")
	}
	storedObservation, ok := prepared.ExecutionObservation()
	if !ok || storedObservation.Observations[0].ObservationID == "changed" {
		t.Fatal("assembler mutated the stored execution observation")
	}
	storedCleanup, ok := prepared.CleanupResult()
	if !ok || storedCleanup.Baseline.SampledAt[0].IsZero() {
		t.Fatal("assembler mutated the stored cleanup result")
	}
	stored, ok := prepared.EvidenceFinalization()
	if !ok || stored != result {
		t.Fatalf("stored evidence result = %+v, %t", stored, ok)
	}
	if _, err := FinalizeEvidence(context.Background(), prepared, assembler); !errors.Is(err, ErrEvidenceFinalization) || calls != 1 {
		t.Fatalf("second FinalizeEvidence() error = %v, calls=%d", err, calls)
	}
}

func TestFinalizeEvidenceFailsClosedBeforeCleanupAndRedactsAssemblerError(t *testing.T) {
	_, _, _, early := prepareRuntimeFixture(t)
	called := 0
	assembler := evidenceAssemblerFunc(func(context.Context, EvidenceSnapshot) (EvidenceFinalizationResult, error) {
		called++
		return EvidenceFinalizationResult{}, nil
	})
	if _, err := FinalizeEvidence(context.Background(), early, assembler); !errors.Is(err, ErrEvidenceFinalization) || called != 0 {
		t.Fatalf("early FinalizeEvidence() error = %v, calls=%d", err, called)
	}

	prepared := preparedEvidenceFixture(t)
	secret := "private credential at /Users/example/runtime"
	_, err := FinalizeEvidence(context.Background(), prepared, evidenceAssemblerFunc(func(context.Context, EvidenceSnapshot) (EvidenceFinalizationResult, error) {
		return EvidenceFinalizationResult{}, errors.New(secret)
	}))
	if !errors.Is(err, ErrEvidenceFinalization) || strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "/Users/") {
		t.Fatalf("FinalizeEvidence() leaked assembler error: %v", err)
	}
	if stored, ok := prepared.EvidenceFinalization(); !ok || stored != (EvidenceFinalizationResult{}) {
		t.Fatalf("failed finalization state = %+v, %t", stored, ok)
	}

	var typedNil *fakeEvidenceAssembler
	if _, err := FinalizeEvidence(context.Background(), preparedEvidenceFixture(t), typedNil); !errors.Is(err, ErrEvidenceFinalization) {
		t.Fatalf("typed-nil FinalizeEvidence() error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FinalizeEvidence(canceled, preparedEvidenceFixture(t), assembler); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled FinalizeEvidence() error = %v", err)
	}
}

type fakeEvidenceAssembler struct{}

func (*fakeEvidenceAssembler) AssembleAndVerify(context.Context, EvidenceSnapshot) (EvidenceFinalizationResult, error) {
	return EvidenceFinalizationResult{}, nil
}

func preparedEvidenceFixture(t *testing.T) *PreparedRuntime {
	t.Helper()
	_, _, _, prepared := prepareRuntimeFixture(t)
	runObservationPhases(t, prepared, false)
	fixture := observationFixture(t, prepared)
	directives := []ObservationDirective{}
	if _, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives)); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	observation, ok := prepared.ExecutionObservation()
	if !ok {
		t.Fatal("missing execution observation")
	}
	clock := &fakeCleanupClock{now: observation.ObservedAt.Add(time.Nanosecond)}
	inspector := inspectorFunc(func(_ context.Context, scope QueryScope) (Inspection, error) {
		return Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: []ResourceEntry{}}, nil
	})
	result, err := runCleanup(context.Background(), prepared, successfulTeardown(prepared, nil), inspector, clock)
	if err != nil || result.Outcome != CleanupOutcomeSucceeded {
		t.Fatalf("cleanup fixture = %+v, %v", result, err)
	}
	return prepared
}

func passingEvidenceFinalization(snapshot EvidenceSnapshot) EvidenceFinalizationResult {
	return EvidenceFinalizationResult{
		ReportID: "qualification-report-test", InvocationID: "qualification-run-test", RuntimeCommitmentDigest: snapshot.RuntimeCommitmentDigest,
		ProfileID: snapshot.ProfileID, ProfileVersion: snapshot.ProfileVersion, ProfileDigest: snapshot.ProfileDigest,
		InitialInvocationID: snapshot.Reconstruction.InitialInvocationID, ReconstructionInvocationID: snapshot.Reconstruction.ReconstructionInvocationID,
		ReportDigest: digestOf("d"), PayloadInventoryDigest: digestOf("e"), ReceiptFile: "receipt.json", RunOutcome: DerivedPassed,
		ValidationOutcome: "accepted", FileCount: 7, TotalBytes: 1024,
	}
}
