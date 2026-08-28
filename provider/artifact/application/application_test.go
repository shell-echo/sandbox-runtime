package application

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

var applicationTestTime = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestApplicationDoesNotImportTransportRepositoryOrRuntimePackages(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "application.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse application.go: %v", err)
	}
	for _, importSpec := range file.Imports {
		path := strings.Trim(importSpec.Path.Value, "\"")
		if strings.Contains(path, "/providerapi") || strings.Contains(path, "/instance") || strings.Contains(path, "/driver") || strings.Contains(path, "/repository") || strings.Contains(path, "gin-gonic") {
			t.Fatalf("application.go imports forbidden package %q", path)
		}
	}
}

func TestAcceptIsDurableBeforeExplicitDispatchAndReplayDoesNotRedispatch(t *testing.T) {
	authority := newFakeAuthority()
	stager := &fakeStager{stage: func(_ context.Context, request artifact.Request) (artifact.Evidence, error) {
		return applicationEvidence(request, artifact.StatusStaged), nil
	}}
	app, err := New(authority, stager, ClockFunc(func() time.Time { return applicationTestTime }))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := applicationRequest("operation-1", "key-1")
	reserved, err := app.Accept(context.Background(), request)
	if err != nil || reserved.Replayed || reserved.Operation.Status != artifact.OperationAccepted {
		t.Fatalf("Accept() = %#v, %v", reserved, err)
	}
	if stager.calls != 0 {
		t.Fatalf("Stage calls after Accept = %d, want 0", stager.calls)
	}
	replayed, err := app.Accept(context.Background(), request)
	if err != nil || !replayed.Replayed || replayed.Operation.Request.OperationID != request.OperationID {
		t.Fatalf("replayed Accept() = %#v, %v", replayed, err)
	}
	completed, err := app.Dispatch(context.Background(), request.OperationID)
	if err != nil || completed.Status != artifact.OperationSucceeded || stager.calls != 1 {
		t.Fatalf("Dispatch() = %#v, %v; calls = %d", completed, err, stager.calls)
	}
	again, err := app.Dispatch(context.Background(), request.OperationID)
	if err != nil || again.Status != artifact.OperationSucceeded || stager.calls != 1 {
		t.Fatalf("replayed Dispatch() = %#v, %v; calls = %d", again, err, stager.calls)
	}
}

func TestConcurrentDispatchCallsStagerOnce(t *testing.T) {
	authority := newFakeAuthority()
	stager := &fakeStager{stage: func(_ context.Context, request artifact.Request) (artifact.Evidence, error) {
		return applicationEvidence(request, artifact.StatusStaged), nil
	}}
	app, _ := New(authority, stager, ClockFunc(func() time.Time { return applicationTestTime }))
	request := applicationRequest("operation-concurrent", "key-concurrent")
	_, _ = app.Accept(context.Background(), request)
	const callers = 16
	var wg sync.WaitGroup
	wg.Add(callers)
	errorsSeen := make(chan error, callers)
	for range callers {
		go func() {
			defer wg.Done()
			operation, err := app.Dispatch(context.Background(), request.OperationID)
			if err == nil && operation.Status != artifact.OperationSucceeded {
				err = errors.New("dispatch did not return succeeded operation")
			}
			errorsSeen <- err
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent Dispatch() error = %v", err)
		}
	}
	if stager.calls != 1 {
		t.Fatalf("Stage calls = %d, want 1", stager.calls)
	}
}

func TestDispatchRecordsRejectedAndSourceMissingTruth(t *testing.T) {
	for _, test := range []struct {
		name       string
		id         string
		stage      func(context.Context, artifact.Request) (artifact.Evidence, error)
		wantStatus artifact.OperationStatus
		wantReason artifact.FailureReason
		wantErr    error
		wantProof  bool
	}{
		{name: "content rejected", id: "rejected", stage: func(_ context.Context, request artifact.Request) (artifact.Evidence, error) {
			return applicationEvidence(request, artifact.StatusRejected), nil
		}, wantStatus: artifact.OperationFailed, wantReason: artifact.FailureContentRejected, wantProof: true},
		{name: "source missing", id: "missing", stage: func(context.Context, artifact.Request) (artifact.Evidence, error) {
			return artifact.Evidence{}, artifact.ErrSourceMissing
		}, wantStatus: artifact.OperationFailed, wantReason: artifact.FailureSourceMissing, wantErr: artifact.ErrSourceMissing},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := newFakeAuthority()
			app, _ := New(authority, &fakeStager{stage: test.stage}, ClockFunc(func() time.Time { return applicationTestTime }))
			request := applicationRequest("operation-"+test.id, "key-"+test.id)
			if _, err := app.Accept(context.Background(), request); err != nil {
				t.Fatalf("Accept() error = %v", err)
			}
			operation, err := app.Dispatch(context.Background(), request.OperationID)
			if !errors.Is(err, test.wantErr) || operation.Status != test.wantStatus || operation.Failure != test.wantReason || (operation.Evidence != nil) != test.wantProof {
				t.Fatalf("Dispatch() = %#v, %v", operation, err)
			}
			_, evidenceErr := app.GetEvidence(context.Background(), request.OperationID)
			if test.wantProof && evidenceErr != nil {
				t.Fatalf("GetEvidence() error = %v", evidenceErr)
			}
			if !test.wantProof && !errors.Is(evidenceErr, artifact.ErrEvidenceNotFound) {
				t.Fatalf("GetEvidence() error = %v, want ErrEvidenceNotFound", evidenceErr)
			}
		})
	}
}

func TestDispatchCancellationBeforeAndAfterRunningNeverClaimsCancelled(t *testing.T) {
	t.Run("before dispatch", func(t *testing.T) {
		authority := newFakeAuthority()
		stager := &fakeStager{}
		app, _ := New(authority, stager, ClockFunc(func() time.Time { return applicationTestTime }))
		request := applicationRequest("operation-before", "key-before")
		if _, err := app.Accept(context.Background(), request); err != nil {
			t.Fatalf("Accept() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		operation, err := app.Dispatch(ctx, request.OperationID)
		if !errors.Is(err, context.Canceled) || operation.Status != artifact.OperationFailed || operation.Failure != artifact.FailureCancelledBeforeRun || stager.calls != 0 {
			t.Fatalf("Dispatch() = %#v, %v; calls = %d", operation, err, stager.calls)
		}
	})

	t.Run("after running", func(t *testing.T) {
		authority := newFakeAuthority()
		stager := &fakeStager{stage: func(context.Context, artifact.Request) (artifact.Evidence, error) {
			return artifact.Evidence{}, context.DeadlineExceeded
		}}
		app, _ := New(authority, stager, ClockFunc(func() time.Time { return applicationTestTime }))
		request := applicationRequest("operation-after", "key-after")
		_, _ = app.Accept(context.Background(), request)
		operation, err := app.Dispatch(context.Background(), request.OperationID)
		if !errors.Is(err, artifact.ErrOutcomeUnknown) || !errors.Is(err, context.DeadlineExceeded) || operation.Status != artifact.OperationOutcomeUnknown || stager.calls != 1 {
			t.Fatalf("Dispatch() = %#v, %v; calls = %d", operation, err, stager.calls)
		}
		reconciled, err := app.Reconcile(context.Background(), request.OperationID)
		if !errors.Is(err, artifact.ErrOutcomeUnknown) || reconciled.Status != artifact.OperationOutcomeUnknown || stager.calls != 1 {
			t.Fatalf("Reconcile() = %#v, %v; calls = %d", reconciled, err, stager.calls)
		}
	})
}

func TestRecoverDispatchesAcceptedAndDoesNotRedispatchRunning(t *testing.T) {
	authority := newFakeAuthority()
	stager := &fakeStager{stage: func(_ context.Context, request artifact.Request) (artifact.Evidence, error) {
		return applicationEvidence(request, artifact.StatusStaged), nil
	}}
	app, _ := New(authority, stager, ClockFunc(func() time.Time { return applicationTestTime }))
	accepted := applicationRequest("operation-z-accepted", "key-accepted")
	runningRequest := applicationRequest("operation-a-running", "key-running")
	_, _ = app.Accept(context.Background(), accepted)
	reservation, _ := app.Accept(context.Background(), runningRequest)
	running, _ := artifact.Transition(reservation.Operation, artifact.OperationRunning, applicationTestTime, "", nil)
	_ = authority.UpdateStage(context.Background(), running, artifact.OperationAccepted)
	results, err := app.Recover(context.Background())
	if !errors.Is(err, artifact.ErrOutcomeUnknown) {
		t.Fatalf("Recover() error = %v, want ErrOutcomeUnknown", err)
	}
	if len(results) != 2 || stager.calls != 1 {
		t.Fatalf("Recover() results = %#v; calls = %d", results, stager.calls)
	}
	stored, _ := authority.GetStage(context.Background(), runningRequest.OperationID)
	if stored.Status != artifact.OperationOutcomeUnknown {
		t.Fatalf("running recovery status = %q", stored.Status)
	}
}

func TestRecoverDoesNotHideDispatchFailureJoinedWithUnknownOutcome(t *testing.T) {
	authority := newFakeAuthority()
	dispatchFailure := errors.New("scanner unavailable")
	stager := &fakeStager{stage: func(context.Context, artifact.Request) (artifact.Evidence, error) {
		return artifact.Evidence{}, dispatchFailure
	}}
	app, _ := New(authority, stager, ClockFunc(func() time.Time { return applicationTestTime }))
	request := applicationRequest("operation-recover-failure", "key-recover-failure")
	if _, err := app.Accept(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	results, err := app.Recover(context.Background())
	if len(results) != 1 || !errors.Is(err, artifact.ErrOutcomeUnknown) || !errors.Is(err, dispatchFailure) {
		t.Fatalf("Recover() = %#v, %v", results, err)
	}
}

func TestDispatchRejectsExpiredEvidenceRetentionBeforeStaging(t *testing.T) {
	now := applicationTestTime
	authority := newFakeAuthority()
	stager := &fakeStager{stage: func(_ context.Context, request artifact.Request) (artifact.Evidence, error) {
		return applicationEvidence(request, artifact.StatusStaged), nil
	}}
	app, _ := New(authority, stager, ClockFunc(func() time.Time { return now }))
	request := applicationRequest("operation-expired-retention", "key-expired-retention")
	if _, err := app.Accept(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	now = now.Add(request.Retention)
	operation, err := app.Dispatch(context.Background(), request.OperationID)
	if !errors.Is(err, artifact.ErrDeadlineExpired) || operation.Status != artifact.OperationFailed || operation.Failure != artifact.FailureDeadlineExpired || stager.calls != 0 {
		t.Fatalf("Dispatch() = %#v, %v; calls=%d", operation, err, stager.calls)
	}
}

type fakeStager struct {
	mu    sync.Mutex
	calls int
	stage func(context.Context, artifact.Request) (artifact.Evidence, error)
}

func (s *fakeStager) Stage(ctx context.Context, request artifact.Request, _ time.Time) (artifact.Evidence, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.stage == nil {
		return artifact.Evidence{}, errors.New("unexpected staging call")
	}
	return s.stage(ctx, request.Clone())
}

type fakeAuthority struct {
	mu          sync.Mutex
	operations  map[string]artifact.Operation
	idempotency map[string]string
}

func newFakeAuthority() *fakeAuthority {
	return &fakeAuthority{operations: make(map[string]artifact.Operation), idempotency: make(map[string]string)}
}

func (a *fakeAuthority) ReserveStage(_ context.Context, request artifact.Request, acceptedAt time.Time) (artifact.Reservation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if operationID, ok := a.idempotency[request.IdempotencyKey]; ok {
		operation := a.operations[operationID]
		if operation.Request.RequestDigest != request.RequestDigest || operation.Request.OperationID != request.OperationID || operation.Request.AttemptID != request.AttemptID {
			return artifact.Reservation{}, artifact.ErrIdempotencyConflict
		}
		return artifact.Reservation{Operation: operation.Clone(), Replayed: true}, nil
	}
	operation, err := artifact.NewOperation(request, acceptedAt)
	if err != nil {
		return artifact.Reservation{}, err
	}
	a.operations[request.OperationID] = operation.Clone()
	a.idempotency[request.IdempotencyKey] = request.OperationID
	return artifact.Reservation{Operation: operation}, nil
}

func (a *fakeAuthority) GetStage(_ context.Context, operationID string) (artifact.Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	operation, ok := a.operations[operationID]
	if !ok {
		return artifact.Operation{}, artifact.ErrNotFound
	}
	return operation.Clone(), nil
}

func (a *fakeAuthority) ListStages(context.Context) ([]artifact.Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ids := make([]string, 0, len(a.operations))
	for id := range a.operations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]artifact.Operation, 0, len(ids))
	for _, id := range ids {
		result = append(result, a.operations[id].Clone())
	}
	return result, nil
}

func (a *fakeAuthority) UpdateStage(_ context.Context, operation artifact.Operation, expected artifact.OperationStatus) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	current, ok := a.operations[operation.Request.OperationID]
	if !ok {
		return artifact.ErrNotFound
	}
	if current.Status != expected {
		return artifact.ErrConflict
	}
	a.operations[operation.Request.OperationID] = operation.Clone()
	return nil
}

func (a *fakeAuthority) GetEvidence(_ context.Context, operationID string, now time.Time) (artifact.Evidence, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	operation, ok := a.operations[operationID]
	if !ok {
		return artifact.Evidence{}, artifact.ErrEvidenceNotFound
	}
	switch operation.Status {
	case artifact.OperationAccepted, artifact.OperationRunning:
		return artifact.Evidence{}, artifact.ErrEvidencePending
	case artifact.OperationOutcomeUnknown:
		return artifact.Evidence{}, artifact.ErrOutcomeUnknown
	}
	if operation.Evidence == nil {
		return artifact.Evidence{}, artifact.ErrEvidenceNotFound
	}
	if !now.Before(operation.Evidence.ExpiresAt) {
		return artifact.Evidence{}, artifact.ErrEvidenceExpired
	}
	return *operation.Evidence, nil
}

func applicationRequest(operationID, key string) artifact.Request {
	return artifact.Request{
		SandboxID: "sandbox-1", TenantID: "tenant-1", OperationID: operationID, AttemptID: "attempt-1", FencingToken: 3,
		ExpectedGeneration: 4, IdempotencyKey: key,
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      applicationTestTime.Add(2 * time.Hour), ArtifactReference: "artifact-ref:platform/artifact-1",
		SourcePath: "/outputs/report.json", ExpectedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedMediaType: "application/json", MaxBytes: 1024, Retention: time.Hour,
	}
}

func applicationEvidence(request artifact.Request, status artifact.Status) artifact.Evidence {
	evidence := artifact.Evidence{
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		SandboxID: request.SandboxID, ArtifactReference: request.ArtifactReference, Status: status,
		ContentDigest: request.ExpectedDigest, MediaType: request.ExpectedMediaType, SizeBytes: 512,
		TenantBindingCheck: artifact.Check{Status: artifact.CheckPassed, CheckedAt: applicationTestTime},
		ActiveContentCheck: artifact.Check{Status: artifact.CheckPassed, CheckedAt: applicationTestTime},
		MalwareCheck:       artifact.Check{Status: artifact.CheckPassed, CheckedAt: applicationTestTime},
		ObservedAt:         applicationTestTime, ExpiresAt: applicationTestTime.Add(time.Hour),
		EvidenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if status == artifact.StatusStaged {
		evidence.StagingReference = "ref:staging/artifact-1"
	}
	return evidence
}
