package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/session/repository"
)

func TestRepositoryHonorsContextAndClose(t *testing.T) {
	r := NewRepository()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	authority := session.SandboxAuthority{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Generation: 1, LeaseExpiresAt: time.Now().Add(time.Hour), FencingToken: 1, CapabilityProfileID: "terminal-v1"}
	if err := r.PutSandboxAuthority(ctx, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSandboxAuthority(context.Background(), authority.SandboxID); !errors.Is(err, repository.ErrClosed) {
		t.Fatalf("closed read = %v", err)
	}
}
