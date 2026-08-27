package file

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

var fileTestTime = time.Date(2026, 8, 27, 7, 0, 0, 0, time.UTC)

func fileRecord(t *testing.T) reference.Record {
	t.Helper()
	request := session.OpenRequest{
		SandboxID: "sandbox-reference-file", ProviderRevisionID: "provider-revision-reference-file",
		OperationID: "operation-reference-file", AttemptID: "attempt-reference-file", FencingToken: 1,
		IdempotencyKey: "reference-file-key", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline: fileTestTime.Add(30 * time.Minute), ExpectedGeneration: 1,
		RuntimeSessionID: "session-reference-file", RuntimeType: session.RuntimeTerminal,
		CapabilityProfileID: "terminal-v1", ExpiresAt: fileTestTime.Add(10 * time.Minute),
	}
	running, err := session.NewRecord(request, fileTestTime)
	if err != nil {
		t.Fatal(err)
	}
	running, err = session.AttachAllocation(running, session.AllocationReceipt{
		Reference: "ref:terminal/22222222222222222222222222222222", SandboxID: request.SandboxID,
		RuntimeSessionID: request.RuntimeSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: fileTestTime, ExpiresAt: request.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := reference.NewRecord("ref:session:cccccccccccccccccccccccccccccccc", running, fileTestTime)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestRegistryPersistsReferenceAndRevocationAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "references.json")
	registry, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	record := fileRecord(t)
	if err := registry.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistry(path); err == nil {
		t.Fatal("second controller opened registry")
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}

	registry, err = NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := registry.Get(context.Background(), record.Reference); err != nil || got != record {
		t.Fatalf("Get() = %#v, %v", got, err)
	}
	if err := registry.Revoke(context.Background(), record.Reference, fileTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}

	registry, err = NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	got, err := registry.Get(context.Background(), record.Reference)
	if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(fileTestTime.Add(time.Second)) {
		t.Fatalf("revoked reference after restart = %#v, %v", got, err)
	}
}

func TestRegistryRejectsCorruptionAndCanceledWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "references.json")
	registry, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistry(path); !errors.Is(err, reference.ErrUnavailable) {
		t.Fatalf("corrupt registry error = %v", err)
	}

	registry, err = NewRegistry(filepath.Join(t.TempDir(), "cancelled.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := registry.Create(ctx, fileRecord(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Create(cancelled) error = %v", err)
	}
}

type fileClock struct{ now time.Time }

func (c fileClock) Now() time.Time { return c.now }

type fileSessionReader struct{ record session.Record }

func (r fileSessionReader) GetOpen(context.Context, string) (session.Record, error) {
	return r.record.Clone(), nil
}

func (r fileSessionReader) GetOpenAt(ctx context.Context, operationID string, _ time.Time) (session.Record, error) {
	return r.GetOpen(ctx, operationID)
}

type fileAttacher struct {
	mu      sync.Mutex
	receipt terminal.Receipt
}

func (a *fileAttacher) Attach(ctx context.Context, receipt terminal.Receipt) (terminal.Stream, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.receipt = receipt
	a.mu.Unlock()
	return fileStream{}, nil
}

func (a *fileAttacher) Receipt() terminal.Receipt {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.receipt
}

type fileStream struct{}

func (fileStream) Read(context.Context, []byte) (int, error) { return 0, io.EOF }
func (fileStream) Write(_ context.Context, value []byte) (int, error) {
	return len(value), nil
}
func (fileStream) Close() error { return nil }

func TestRegistryRestartReconstructsFreshTerminalDial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "references.json")
	registry, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	running := fileRecordSession(t)
	record, err := reference.NewRecord("ref:session:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", running, fileTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	evidence := record.Evidence()
	succeeded, err := session.Transition(running, session.StatusSucceeded, fileTestTime.Add(time.Second), &evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err = NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	attacher := &fileAttacher{}
	resolver, err := reference.NewResolver(registry, fileSessionReader{record: succeeded}, attacher, fileClock{now: fileTestTime.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := resolver.Resolve(context.Background(), record.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Dial(context.Background()); err != nil {
		t.Fatalf("Dial() = %v", err)
	}
	got := attacher.Receipt()
	if string(got.Reference) != record.Receipt.Reference || got.OperationID != record.OperationID || got.ConnectionGeneration != record.ConnectionGeneration {
		t.Fatalf("reattached receipt = %#v", got)
	}
}

func fileRecordSession(t *testing.T) session.Record {
	t.Helper()
	request := session.OpenRequest{
		SandboxID: "sandbox-reference-file", ProviderRevisionID: "provider-revision-reference-file",
		OperationID: "operation-reference-file", AttemptID: "attempt-reference-file", FencingToken: 1,
		IdempotencyKey: "reference-file-key", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline: fileTestTime.Add(30 * time.Minute), ExpectedGeneration: 1,
		RuntimeSessionID: "session-reference-file", RuntimeType: session.RuntimeTerminal,
		CapabilityProfileID: "terminal-v1", ExpiresAt: fileTestTime.Add(10 * time.Minute),
	}
	record, err := session.NewRecord(request, fileTestTime)
	if err != nil {
		t.Fatal(err)
	}
	running, err := session.AttachAllocation(record, session.AllocationReceipt{
		Reference: "ref:terminal/22222222222222222222222222222222", SandboxID: request.SandboxID,
		RuntimeSessionID: request.RuntimeSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: fileTestTime, ExpiresAt: request.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return running
}
