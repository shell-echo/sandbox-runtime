package file

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/session/repository"
)

var fileTestTime = time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)

func fileAuthority() session.SandboxAuthority {
	return session.SandboxAuthority{
		SandboxID:           "sandbox-file",
		ProviderRevisionID:  "provider-revision-file",
		Ready:               true,
		Generation:          1,
		LeaseExpiresAt:      fileTestTime.Add(time.Hour),
		FencingToken:        1,
		CapabilityProfileID: "terminal-v1",
	}
}

func fileRequest() session.OpenRequest {
	return session.OpenRequest{
		SandboxID:           "sandbox-file",
		ProviderRevisionID:  "provider-revision-file",
		OperationID:         "operation-file",
		AttemptID:           "attempt-file",
		FencingToken:        1,
		IdempotencyKey:      "session-file-key",
		RequestDigest:       "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline:            fileTestTime.Add(30 * time.Minute),
		ExpectedGeneration:  1,
		RuntimeSessionID:    "session-file",
		RuntimeType:         session.RuntimeTerminal,
		CapabilityProfileID: "terminal-v1",
		ExpiresAt:           fileTestTime.Add(10 * time.Minute),
	}
}

func TestRepositoryPersistsAuthorityAndSessionAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "session.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.PutSandboxAuthority(context.Background(), fileAuthority()); err != nil {
		t.Fatal(err)
	}
	request := fileRequest()
	reserved, err := r.ReserveOpen(context.Background(), request, fileTestTime)
	if err != nil || reserved.Replayed {
		t.Fatalf("reserve = %#v, %v", reserved, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReserveOpen(context.Background(), request, fileTestTime.Add(time.Second)); err != nil {
		t.Fatalf("replay after restart = %v", err)
	}
	got, err := r.GetOpenAt(context.Background(), request.OperationID, fileTestTime.Add(time.Second))
	if err != nil || got.Request != request {
		t.Fatalf("record after restart = %#v, %v", got, err)
	}
	authority, err := r.GetSandboxAuthority(context.Background(), request.SandboxID)
	if err != nil || authority != fileAuthority() {
		t.Fatalf("authority after restart = %#v, %v", authority, err)
	}
	if _, err := NewRepository(path); err == nil {
		t.Fatal("second controller opened repository")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryRejectsCorruptionAndCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(path); !errors.Is(err, repository.ErrCorrupt) {
		t.Fatalf("corrupt snapshot = %v", err)
	}

	path = filepath.Join(t.TempDir(), "canceled.json")
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.PutSandboxAuthority(ctx, fileAuthority()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authority write = %v", err)
	}
}

func TestRepositoryRechecksAuthorityBeforeSuccessfulHandoff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "success.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.PutSandboxAuthority(context.Background(), fileAuthority()); err != nil {
		t.Fatal(err)
	}
	request := fileRequest()
	_, err = r.ReserveOpen(context.Background(), request, fileTestTime)
	if err != nil {
		t.Fatal(err)
	}
	attached, err := r.AttachAllocation(context.Background(), session.AllocationReceipt{
		Reference: "ref:terminal/33333333333333333333333333333333", SandboxID: request.SandboxID,
		RuntimeSessionID: request.RuntimeSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: fileTestTime.Add(time.Second), ExpiresAt: request.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	running := attached.Record
	authority := fileAuthority()
	authority.Ready = false
	if err := r.ReplaceSandboxAuthority(context.Background(), authority, 1, 1); err != nil {
		t.Fatal(err)
	}
	succeeded, err := session.Transition(running, session.StatusSucceeded, fileTestTime.Add(2*time.Second), &session.EndpointEvidence{InternalEndpointReference: "ref:session:file", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateOpenAt(context.Background(), succeeded, session.StatusRunning, fileTestTime.Add(2*time.Second)); !errors.Is(err, session.ErrSandboxNotReady) {
		t.Fatalf("stale authority success = %v", err)
	}
	got, err := r.GetOpenAt(context.Background(), request.OperationID, fileTestTime.Add(2*time.Second))
	if err != nil || got.Status != session.StatusRunning {
		t.Fatalf("record after rejected success = %#v, %v", got, err)
	}
}

func TestRepositoryMigratesVersionOneSnapshotOnNextMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	state := repository.NewState()
	if err := state.PutSandboxAuthority(fileAuthority()); err != nil {
		t.Fatal(err)
	}
	request := fileRequest()
	if _, err := state.ReserveOpenAt(request, fileTestTime); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Export()
	snapshot.Version = 1
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewRepository(path)
	if err != nil {
		t.Fatalf("open version 1 repository: %v", err)
	}
	if got, err := r.GetOpenAt(context.Background(), request.OperationID, fileTestTime.Add(time.Second)); err != nil || got.Status != session.StatusAccepted {
		t.Fatalf("migrated accepted operation = %#v, %v", got, err)
	}
	updatedAuthority := fileAuthority()
	updatedAuthority.LeaseExpiresAt = updatedAuthority.LeaseExpiresAt.Add(time.Minute)
	if err := r.SynchronizeSandboxAuthority(context.Background(), updatedAuthority); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rewritten repository.PersistedState
	if err := json.Unmarshal(content, &rewritten); err != nil || rewritten.Version != 2 || len(rewritten.Sessions) != 1 {
		t.Fatalf("rewritten snapshot = %#v, %v", rewritten, err)
	}
}
