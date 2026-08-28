package memory

import (
	"context"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

var adapterTestNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func adapterRequest() artifact.Request {
	content := []byte(`{"ok":true}`)
	return artifact.Request{
		SandboxID: "sandbox-1", TenantID: "tenant-1", OperationID: "artifact-operation-1", AttemptID: "artifact-attempt-1", FencingToken: 3, ExpectedGeneration: 4,
		IdempotencyKey: "artifact-idempotency-1", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Deadline: adapterTestNow.Add(time.Hour),
		ArtifactReference: "artifact-ref:platform/artifact-1", SourcePath: "/outputs/report.json", ExpectedDigest: digest(content), ExpectedMediaType: "application/json", MaxBytes: 1 << 20, Retention: 30 * time.Minute,
	}
}

func passingCheck(_ context.Context, _ []byte) (artifact.CheckStatus, error) {
	return artifact.CheckPassed, nil
}

func newAdapter(t *testing.T, tenantBound bool) *Adapter {
	t.Helper()
	request := adapterRequest()
	adapter, err := NewAdapter(ClockFunc(func() time.Time { return adapterTestNow }), map[string][]byte{request.SourcePath: []byte(`{"ok":true}`)}, tenantBound, passingCheck, passingCheck)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestStageComputesBoundedEvidenceAndReplays(t *testing.T) {
	adapter := newAdapter(t, true)
	request := adapterRequest()
	first, err := adapter.Stage(context.Background(), request, adapterTestNow)
	if err != nil || first.Status != artifact.StatusStaged || first.StagingReference == "" {
		t.Fatalf("first Stage() = %#v, %v", first, err)
	}
	second, err := adapter.Stage(context.Background(), request, adapterTestNow)
	if err != nil || second != first {
		t.Fatalf("replayed Stage() = %#v, %v", second, err)
	}
	read, err := adapter.Get(context.Background(), request.OperationID)
	if err != nil || read != first {
		t.Fatalf("Get() = %#v, %v", read, err)
	}
	request.RequestDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if _, err := adapter.Stage(context.Background(), request, adapterTestNow); err != ErrConflict {
		t.Fatalf("substituted request error = %v, want %v", err, ErrConflict)
	}
}

func TestStageFailsClosedForTenantOrContentChecks(t *testing.T) {
	adapter := newAdapter(t, false)
	evidence, err := adapter.Stage(context.Background(), adapterRequest(), adapterTestNow)
	if err != nil || evidence.Status != artifact.StatusRejected || evidence.StagingReference != "" {
		t.Fatalf("tenant-unbound Stage() = %#v, %v", evidence, err)
	}
}

func TestStageRetainsRejectedContentEvidence(t *testing.T) {
	adapter := newAdapter(t, true)
	request := adapterRequest()
	request.ExpectedDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	evidence, err := adapter.Stage(context.Background(), request, adapterTestNow)
	if err != nil || evidence.Status != artifact.StatusRejected {
		t.Fatalf("digest-mismatch Stage() = %#v, %v", evidence, err)
	}
	if _, err := adapter.Get(context.Background(), request.OperationID); err != nil {
		t.Fatalf("rejected evidence was not retained: %v", err)
	}
}

func TestStageRejectsMissingOutputAndHonorsExpiry(t *testing.T) {
	adapter := newAdapter(t, true)
	request := adapterRequest()
	request.SourcePath = "/outputs/missing.json"
	if _, err := adapter.Stage(context.Background(), request, adapterTestNow); err != ErrNotFound {
		t.Fatalf("missing output error = %v, want %v", err, ErrNotFound)
	}
	request = adapterRequest()
	request.Retention = time.Second
	request.Deadline = adapterTestNow.Add(time.Second)
	if _, err := adapter.Stage(context.Background(), request, adapterTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Get(context.Background(), request.OperationID); err != nil {
		t.Fatalf("Get before expiry error = %v", err)
	}
}

func TestCloseRejectsFurtherAccess(t *testing.T) {
	adapter := newAdapter(t, true)
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Stage(context.Background(), adapterRequest(), adapterTestNow); err != ErrClosed {
		t.Fatalf("Stage after close error = %v, want %v", err, ErrClosed)
	}
}
