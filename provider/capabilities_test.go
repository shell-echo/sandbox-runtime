package provider

import (
	"context"
	"strings"
	"testing"
)

func testLimits() Limits {
	return Limits{
		MaxCPUMillis: 1000, MaxMemoryBytes: 512 << 20,
		MaxEphemeralStorageBytes: 64 << 20, MaxLeaseSeconds: 3600,
		MaxExecSeconds: 30,
	}
}

func TestStaticCapabilityServiceReturnsDefensiveCopies(t *testing.T) {
	service, err := NewStaticCapabilityService("spr_test", testLimits())
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.SnapshotRestoreProfile[0].ProfileID = "changed"
	second, err := service.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.SnapshotRestoreProfile[0].ProfileID != WorkspaceSnapshotProfileID {
		t.Fatal("capability service returned mutable shared state")
	}
	if first.Capabilities == nil || first.RuntimeProfiles == nil {
		t.Fatal("empty advertised collections must encode as arrays, not null")
	}
}

func TestStaticCapabilityServiceHonorsCancellation(t *testing.T) {
	service, err := NewStaticCapabilityService("spr_test", testLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Capabilities(ctx); err == nil {
		t.Fatal("expected cancelled context error")
	}
}

func TestCapabilitiesValidateRejectsUnsafeValues(t *testing.T) {
	service, err := NewStaticCapabilityService("spr_test", testLimits())
	if err != nil {
		t.Fatal(err)
	}
	valid, err := service.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Capabilities)
	}{
		{"revision", func(c *Capabilities) { c.ProviderRevisionID = strings.Repeat("x", 201) }},
		{"api version", func(c *Capabilities) { c.APIVersion = "v2" }},
		{"limit", func(c *Capabilities) { c.Limits.MaxCPUMillis = 0 }},
		{"capability", func(c *Capabilities) {
			c.Capabilities = []Capability{{ID: "sandbox.unknown", Versions: []string{"1.0"}}}
		}},
		{"snapshot profile", func(c *Capabilities) { c.SnapshotRestoreProfile[0].SuiteDigest = "sha256:wrong" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneCapabilities(valid)
			tc.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
