package productgateway

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
)

func browserBindingFixture() BrowserTenantBindingInput {
	return BrowserTenantBindingInput{
		CallerAuthorityScope: "product-alpha", ProviderInstanceAudience: "provider-browser-a",
		TenantID: "tenant-a", SandboxID: "sandbox-a", BrowserSessionID: "browser-a",
		ProviderRevisionID: "revision-a", CapabilityProfileID: "browser-v1", ConnectionGeneration: 7,
		HandoffReference: "ref:browser-session:" + strings.Repeat("1", 32),
	}
}

func TestBrowserTenantBindingV2GoldenAndExactScope(t *testing.T) {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	base := browserBindingFixture()
	got, err := DeriveBrowserTenantBinding(key, base)
	const golden = "hmac-sha256:v2:55c4fb034159f2adbe6afc3cf8d81b1183fd46843c50ae5bcb8473939848cb58"
	if err != nil || got != golden || browserbinding.ValidateDigest(got) != nil {
		t.Fatalf("Browser v2 golden = %q, %v", got, err)
	}
	// A new one-use grant, capacity claim or connection epoch is deliberately
	// absent from the input; reconnecting to this exact handoff cannot drift.
	if repeated, err := DeriveBrowserTenantBinding(key, base); err != nil || repeated != golden {
		t.Fatalf("same handoff reconnect = %q, %v", repeated, err)
	}
	for _, test := range []struct {
		name string
		edit func(*BrowserTenantBindingInput)
	}{
		{"caller scope", func(i *BrowserTenantBindingInput) { i.CallerAuthorityScope = "product-beta" }},
		{"provider instance", func(i *BrowserTenantBindingInput) { i.ProviderInstanceAudience = "provider-browser-b" }},
		{"tenant", func(i *BrowserTenantBindingInput) { i.TenantID = "tenant-b" }},
		{"sandbox", func(i *BrowserTenantBindingInput) { i.SandboxID = "sandbox-b" }},
		{"session", func(i *BrowserTenantBindingInput) { i.BrowserSessionID = "browser-b" }},
		{"provider revision", func(i *BrowserTenantBindingInput) { i.ProviderRevisionID = "revision-b" }},
		{"generation", func(i *BrowserTenantBindingInput) { i.ConnectionGeneration++ }},
		{"handoff", func(i *BrowserTenantBindingInput) {
			i.HandoffReference = "ref:browser-session:" + strings.Repeat("2", 32)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.edit(&changed)
			derived, err := DeriveBrowserTenantBinding(key, changed)
			if err != nil || derived == golden || browserbinding.ValidateDigest(derived) != nil {
				t.Fatalf("changed binding = %q, %v", derived, err)
			}
		})
	}
	otherKey := bytes.Repeat([]byte{0x42}, 32)
	if derived, err := DeriveBrowserTenantBinding(otherKey, base); err != nil || derived == golden {
		t.Fatalf("key rotation reused digest: %q, %v", derived, err)
	}
}

func TestBrowserTenantBindingV2RejectsInvalidInputsAndHistoricalDigest(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	base := browserBindingFixture()
	if digest, err := DeriveBrowserTenantBinding(key[:31], base); err == nil || digest != "" {
		t.Fatalf("short key = %q, %v", digest, err)
	}
	for _, edit := range []func(*BrowserTenantBindingInput){
		func(i *BrowserTenantBindingInput) { i.CallerAuthorityScope = "" },
		func(i *BrowserTenantBindingInput) { i.TenantID = " tenant-a" },
		func(i *BrowserTenantBindingInput) { i.CapabilityProfileID = "desktop-v1" },
		func(i *BrowserTenantBindingInput) { i.ConnectionGeneration = 0 },
		func(i *BrowserTenantBindingInput) { i.ConnectionGeneration = maxBrowserBindingGeneration + 1 },
		func(i *BrowserTenantBindingInput) { i.HandoffReference = "https://example.invalid" },
	} {
		invalid := base
		edit(&invalid)
		if digest, err := DeriveBrowserTenantBinding(key, invalid); err == nil || digest != "" {
			t.Fatalf("invalid input = %#v, %q, %v", invalid, digest, err)
		}
	}
	if browserbinding.ValidateDigest("sha256:v1:"+strings.Repeat("a", 64)) == nil ||
		browserbinding.ValidateDigest("hmac-sha256:v2:"+strings.Repeat("A", 64)) == nil {
		t.Fatal("Browser v2 accepted a historical or noncanonical digest")
	}
}
