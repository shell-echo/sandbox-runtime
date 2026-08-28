package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

var stateTestTime = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestStateReserveReplayAndAuthorityConflicts(t *testing.T) {
	state := NewState()
	if err := state.PutSandboxAuthority(stateAuthority()); err != nil {
		t.Fatal(err)
	}
	request := stateRequest("operation-1", "key-1")
	reserved, err := state.ReserveStageAt(request, stateTestTime)
	if err != nil || reserved.Replayed || reserved.Operation.Status != artifact.OperationAccepted {
		t.Fatalf("ReserveStageAt() = %#v, %v", reserved, err)
	}
	replayed, err := state.ReserveStageAt(request, stateTestTime.Add(time.Second))
	if err != nil || !replayed.Replayed || replayed.Operation.Request.OperationID != request.OperationID {
		t.Fatalf("replay = %#v, %v", replayed, err)
	}
	digestConflict := request
	digestConflict.RequestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := state.ReserveStageAt(digestConflict, stateTestTime); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest conflict = %v", err)
	}
	identityConflict := request
	identityConflict.AttemptID = "attempt-2"
	if _, err := state.ReserveStageAt(identityConflict, stateTestTime); !errors.Is(err, ErrConflict) {
		t.Fatalf("identity conflict = %v", err)
	}
	staleGeneration := stateRequest("operation-generation", "key-generation")
	staleGeneration.ExpectedGeneration--
	if _, err := state.ReserveStageAt(staleGeneration, stateTestTime); !errors.Is(err, artifact.ErrGenerationConflict) {
		t.Fatalf("generation conflict = %v", err)
	}
	staleFence := stateRequest("operation-fence", "key-fence")
	staleFence.FencingToken--
	if _, err := state.ReserveStageAt(staleFence, stateTestTime); !errors.Is(err, artifact.ErrStaleFencingToken) {
		t.Fatalf("fencing conflict = %v", err)
	}
}

func TestStateSynchronizeSandboxAuthorityPreservesFencingHighWater(t *testing.T) {
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(stateAuthority()); err != nil {
		t.Fatal(err)
	}
	advanced := stateAuthority()
	advanced.Generation++
	advanced.FencingToken++
	if err := state.SynchronizeSandboxAuthority(advanced); err != nil {
		t.Fatalf("advance authority: %v", err)
	}
	staleGeneration := advanced
	staleGeneration.Generation--
	if err := state.SynchronizeSandboxAuthority(staleGeneration); !errors.Is(err, artifact.ErrGenerationConflict) {
		t.Fatalf("stale generation error = %v", err)
	}
	staleFence := advanced
	staleFence.FencingToken--
	if err := state.SynchronizeSandboxAuthority(staleFence); !errors.Is(err, artifact.ErrStaleFencingToken) {
		t.Fatalf("stale fencing error = %v", err)
	}
}

func TestStateTransitionsEvidenceExpiryAndRoundTrip(t *testing.T) {
	state := NewState()
	_ = state.PutSandboxAuthority(stateAuthority())
	request := stateRequest("operation-evidence", "key-evidence")
	reserved, _ := state.ReserveStageAt(request, stateTestTime)
	if _, err, _ := state.ReadEvidenceAt(request.OperationID, stateTestTime); !errors.Is(err, artifact.ErrEvidencePending) {
		t.Fatalf("accepted evidence error = %v", err)
	}
	running, _ := artifact.Transition(reserved.Operation, artifact.OperationRunning, stateTestTime.Add(time.Second), "", nil)
	if err := state.UpdateStage(running, artifact.OperationAccepted); err != nil {
		t.Fatal(err)
	}
	evidence := stateEvidence(request, artifact.StatusStaged)
	succeeded, _ := artifact.Transition(running, artifact.OperationSucceeded, stateTestTime.Add(2*time.Second), "", &evidence)
	if err := state.UpdateStage(succeeded, artifact.OperationRunning); err != nil {
		t.Fatal(err)
	}
	read, err, changed := state.ReadEvidenceAt(request.OperationID, stateTestTime.Add(3*time.Second))
	if err != nil || changed || read.OperationID != request.OperationID {
		t.Fatalf("ReadEvidenceAt() = %#v, %v, %t", read, err, changed)
	}
	read.OperationID = "mutated"
	again, _, _ := state.ReadEvidenceAt(request.OperationID, stateTestTime.Add(3*time.Second))
	if again.OperationID != request.OperationID {
		t.Fatalf("evidence snapshot mutated: %#v", again)
	}
	if _, err, changed := state.ReadEvidenceAt(request.OperationID, evidence.ExpiresAt); !errors.Is(err, artifact.ErrEvidenceExpired) || !changed {
		t.Fatalf("expiry = %v, %t", err, changed)
	}
	snapshot := state.Export()
	loaded := NewState()
	if err := loaded.Import(snapshot); err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if _, err, changed := loaded.ReadEvidenceAt(request.OperationID, stateTestTime.Add(3*time.Second)); !errors.Is(err, artifact.ErrEvidenceExpired) || changed {
		t.Fatalf("persisted tombstone = %v, %t", err, changed)
	}
}

func TestStateSourceMissingUnknownAndCAS(t *testing.T) {
	state := NewState()
	_ = state.PutSandboxAuthority(stateAuthority())
	missingRequest := stateRequest("operation-missing", "key-missing")
	missing, _ := state.ReserveStageAt(missingRequest, stateTestTime)
	running, _ := artifact.Transition(missing.Operation, artifact.OperationRunning, stateTestTime.Add(time.Second), "", nil)
	_ = state.UpdateStage(running, artifact.OperationAccepted)
	failed, _ := artifact.Transition(running, artifact.OperationFailed, stateTestTime.Add(2*time.Second), artifact.FailureSourceMissing, nil)
	if err := state.UpdateStage(failed, artifact.OperationAccepted); !errors.Is(err, ErrConflict) {
		t.Fatalf("CAS error = %v", err)
	}
	if err := state.UpdateStage(failed, artifact.OperationRunning); err != nil {
		t.Fatal(err)
	}
	if _, err, _ := state.ReadEvidenceAt(missingRequest.OperationID, stateTestTime.Add(3*time.Second)); !errors.Is(err, artifact.ErrEvidenceNotFound) {
		t.Fatalf("source-missing evidence = %v", err)
	}

	unknownRequest := stateRequest("operation-unknown", "key-unknown")
	unknown, _ := state.ReserveStageAt(unknownRequest, stateTestTime)
	unknownRunning, _ := artifact.Transition(unknown.Operation, artifact.OperationRunning, stateTestTime.Add(time.Second), "", nil)
	_ = state.UpdateStage(unknownRunning, artifact.OperationAccepted)
	unknownTerminal, _ := artifact.Transition(unknownRunning, artifact.OperationOutcomeUnknown, stateTestTime.Add(2*time.Second), artifact.FailureDispatchUnknown, nil)
	_ = state.UpdateStage(unknownTerminal, artifact.OperationRunning)
	if _, err, _ := state.ReadEvidenceAt(unknownRequest.OperationID, stateTestTime.Add(3*time.Second)); !errors.Is(err, artifact.ErrOutcomeUnknown) {
		t.Fatalf("unknown evidence = %v", err)
	}
}

func TestStateImportRejectsInvalidSnapshots(t *testing.T) {
	state := NewState()
	for _, snapshot := range []PersistedState{
		{Version: 99},
		{Version: snapshotVersion, Authorities: []artifact.SandboxAuthority{stateAuthority(), stateAuthority()}},
		{Version: snapshotVersion, ExpiredEvidence: []string{"missing"}},
	} {
		if err := state.Import(snapshot); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Import(%#v) error = %v", snapshot, err)
		}
	}
}

func stateAuthority() artifact.SandboxAuthority {
	return artifact.SandboxAuthority{SandboxID: "sandbox-1", Generation: 4, FencingToken: 3}
}

func stateRequest(operationID, key string) artifact.Request {
	return artifact.Request{
		SandboxID: "sandbox-1", TenantID: "tenant-1", OperationID: operationID, AttemptID: "attempt-1", FencingToken: 3,
		ExpectedGeneration: 4, IdempotencyKey: key,
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      stateTestTime.Add(2 * time.Hour), ArtifactReference: "artifact-ref:platform/artifact-1",
		SourcePath: "/outputs/report.json", ExpectedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedMediaType: "application/json", MaxBytes: 1024, Retention: time.Hour,
	}
}

func stateEvidence(request artifact.Request, status artifact.Status) artifact.Evidence {
	evidence := artifact.Evidence{
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		SandboxID: request.SandboxID, ArtifactReference: request.ArtifactReference, Status: status,
		ContentDigest: request.ExpectedDigest, MediaType: request.ExpectedMediaType, SizeBytes: 512,
		TenantBindingCheck: artifact.Check{Status: artifact.CheckPassed, CheckedAt: stateTestTime.Add(2 * time.Second)},
		ActiveContentCheck: artifact.Check{Status: artifact.CheckPassed, CheckedAt: stateTestTime.Add(2 * time.Second)},
		MalwareCheck:       artifact.Check{Status: artifact.CheckPassed, CheckedAt: stateTestTime.Add(2 * time.Second)},
		ObservedAt:         stateTestTime.Add(2 * time.Second), ExpiresAt: stateTestTime.Add(time.Hour),
		EvidenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if status == artifact.StatusStaged {
		evidence.StagingReference = "ref:staging/artifact-1"
	}
	return evidence
}
