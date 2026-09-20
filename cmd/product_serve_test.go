package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
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
