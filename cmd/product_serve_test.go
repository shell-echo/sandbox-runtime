package cmd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
	productprocess "github.com/shell-echo/sandbox-runtime/productapi/process"
)

func TestProductionKernelCapabilitySnapshotIsExplicitlyUnavailable(t *testing.T) {
	capabilities, err := (productionKernelCapabilities{}).Snapshot(context.Background(), productapi.Principal{})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(capabilities) != 1 || capabilities[0].CapabilityID != "product.workspace" || capabilities[0].Readiness != "unavailable" || capabilities[0].ProtocolProfiles == nil {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (productionKernelCapabilities{}).Snapshot(ctx, productapi.Principal{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Snapshot error = %v", err)
	}
}

func TestUnavailablePrimarySlotPolicyPreservesCancellation(t *testing.T) {
	policy := unavailablePrimarySlotPolicy{}
	if err := policy.AuthorizePrimarySlot(context.Background(), product.SlotSpec{}); !errors.Is(err, product.ErrCapabilityUnsupported) {
		t.Fatalf("AuthorizePrimarySlot error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := policy.AuthorizePrimarySlot(ctx, product.SlotSpec{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled AuthorizePrimarySlot error = %v", err)
	}
}

func TestProductGuestAdmissionCombinesDependencyAndCleanupState(t *testing.T) {
	var dependencyReady atomic.Bool
	var cleanupReady atomic.Bool
	var admitted atomic.Int64
	dependencies := productprocess.ReadinessFunc(func(context.Context) error {
		if !dependencyReady.Load() {
			return errors.New("dependency unavailable")
		}
		return nil
	})
	handler := productGuestAdmission(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		admitted.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}), func() productprocess.Readiness { return dependencies }, cleanupReady.Load)
	for _, tc := range []struct {
		dependency, cleanup bool
		want                int
	}{
		{false, false, http.StatusServiceUnavailable},
		{true, false, http.StatusServiceUnavailable},
		{false, true, http.StatusServiceUnavailable},
		{true, true, http.StatusNoContent},
	} {
		dependencyReady.Store(tc.dependency)
		cleanupReady.Store(tc.cleanup)
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/agent", nil))
		if writer.Code != tc.want {
			t.Fatalf("dependency=%t cleanup=%t status=%d want=%d", tc.dependency, tc.cleanup, writer.Code, tc.want)
		}
	}
	if admitted.Load() != 1 {
		t.Fatalf("handler admitted %d times", admitted.Load())
	}
	hub, err := guestagent.NewHub(guestagent.HubOptions{Authenticator: &blockedReceiptAuth{},
		Retirement: &guestagent.RetirementPolicy{Capacity: 1,
			Retire: func(context.Context, guestagent.Identity) (guestagent.RetirementDisposition, error) {
				return guestagent.RetirementReleased, nil
			},
			Readback: func(context.Context, guestagent.Identity) (guestagent.RetirementDisposition, error) {
				return guestagent.RetirementStillOwned, nil
			}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := productGuestReadiness(context.Background(), dependencies, hub); err != nil {
		t.Fatalf("healthy combined readiness = %v", err)
	}
	if err := hub.ShutdownRetirement(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := productGuestReadiness(context.Background(), dependencies, hub); err == nil {
		t.Fatal("closed cleanup manager remained ready")
	}
}
