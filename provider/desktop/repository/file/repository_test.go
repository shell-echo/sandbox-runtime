package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
)

func TestRepositoryRestartAndExclusiveLock(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "desktop-authority.json")
	store, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(path); err == nil {
		t.Fatal("second writer acquired desktop authority lock")
	}
	authority := desktop.SandboxAuthority{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(time.Hour), FencingToken: 3, CapabilityProfileID: desktop.CapabilityProfileID,
		NetworkPolicyReference: "desktop-egress-policy-1",
	}
	if err := store.SynchronizeSandboxAuthority(context.Background(), authority); err != nil {
		t.Fatal(err)
	}
	request := desktop.OpenRequest{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 3, IdempotencyKey: "desktop-open-1",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      now.Add(30 * time.Minute), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1",
		CapabilityProfileID: desktop.CapabilityProfileID, ExpiresAt: now.Add(20 * time.Minute),
	}
	if _, err := store.ReserveOpen(context.Background(), request, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.ReserveOpen(context.Background(), request, now.Add(time.Second))
	if err != nil || !replay.Replayed {
		t.Fatalf("restart replay = %#v, %v", replay, err)
	}
	_ = restarted.Close()
}

func TestRepositoryRejectsUnknownAndOversizedSnapshots(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"version":3,"sessions":[],"idempotency":[],"authorities":[],"unknown":true}`},
		{name: "trailing document", data: `{"version":3,"sessions":[],"idempotency":[],"authorities":[]} {}`},
		{name: "oversized", data: strings.Repeat("x", maxFileSize+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "desktop-authority.json")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(path); !errors.Is(err, repository.ErrCorrupt) {
				t.Fatalf("NewRepository() = %v", err)
			}
		})
	}
}
