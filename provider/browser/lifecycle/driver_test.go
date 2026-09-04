package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	providerlifecycle "github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

type readinessSpy struct {
	calls int
	err   error
}

func (r *readinessSpy) Ready(context.Context) error {
	r.calls++
	return r.err
}

func browserSandbox() providerlifecycle.Sandbox {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	return providerlifecycle.Sandbox{
		ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
		ProviderRevisionID: "revision-1", RuntimeProfile: providerlifecycle.BrowserRuntimeProfile,
		Network:        providerlifecycle.NetworkPolicy{Mode: providerlifecycle.NetworkRestricted, PolicyReference: "browser-egress-policy-1", EgressGatewayRequired: true},
		SandboxSlotKey: "browser", DesiredState: providerlifecycle.DesiredReady, ObservedState: providerlifecycle.ObservedProvisioning,
		Generation: 1, LeaseExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
}

func TestDriverBindsBrowserProfileAndRuntimeReadiness(t *testing.T) {
	runtime := &readinessSpy{}
	driver, err := New(runtime, "browser-egress-policy-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Create(context.Background(), browserSandbox()); err != nil {
		t.Fatal(err)
	}
	observation, err := driver.Inspect(context.Background(), "sandbox-1")
	if err != nil || observation.State != coordinator.RuntimeReady || runtime.calls != 2 {
		t.Fatalf("observation=%#v calls=%d err=%v", observation, runtime.calls, err)
	}
}

func TestDriverFailsClosedOnPolicyAndReadiness(t *testing.T) {
	runtime := &readinessSpy{}
	driver, err := New(runtime, "browser-egress-policy-1")
	if err != nil {
		t.Fatal(err)
	}
	wrong := browserSandbox()
	wrong.Network.PolicyReference = "browser-egress-policy-other"
	if err := driver.Create(context.Background(), wrong); !errors.Is(err, ErrInvalidDriver) || runtime.calls != 0 {
		t.Fatalf("policy substitution = %v calls=%d", err, runtime.calls)
	}
	runtime.err = errors.New("private runtime detail")
	if err := driver.Create(context.Background(), browserSandbox()); !errors.Is(err, coordinator.ErrUnknownRuntime) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("create readiness = %v", err)
	}
	if _, err := driver.Inspect(context.Background(), "sandbox-1"); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private runtime detail") {
		t.Fatalf("inspect readiness = %v", err)
	}
	if _, err := driver.Inspect(nil, "sandbox-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context = %v", err)
	}
}

func TestDriverRejectsTypedNilRuntime(t *testing.T) {
	var runtime *readinessSpy
	if _, err := New(runtime, "browser-egress-policy-1"); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("typed nil = %v", err)
	}
}
