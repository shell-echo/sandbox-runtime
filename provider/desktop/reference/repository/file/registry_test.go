package file

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
)

func TestRegistryPersistsReferenceAndRevocation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	request := desktop.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: now.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1", CapabilityProfileID: desktop.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute)}
	record, err := desktop.NewRecord(request, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt := desktop.AllocationReceipt{Reference: "ref:desktop/11111111111111111111111111111111", SandboxID: request.SandboxID, DesktopSessionID: request.DesktopSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1, AllocatedAt: now.Add(time.Second), ExpiresAt: request.ExpiresAt}
	record, err = desktop.AttachAllocation(record, receipt)
	if err != nil {
		t.Fatal(err)
	}
	handoffReference := "ref:desktop-session:11111111111111111111111111111111"
	stored, err := reference.NewRecord(handoffReference, record, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/references.json"
	registry, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Create(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.Get(context.Background(), handoffReference)
	if err != nil || loaded.Reference != handoffReference {
		t.Fatalf("loaded = %#v, %v", loaded, err)
	}
	if err := restarted.Revoke(context.Background(), handoffReference, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Get(context.Background(), handoffReference); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}
