package browserhandoff

import (
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func validOpen(now time.Time) OpenRequest {
	return OpenRequest{Protocol: ProtocolID, RequestID: "request-1", Resource: ResourceBrowser,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), SandboxID: "sandbox-1",
		BrowserSessionID: "browser-1", CapabilityProfileID: "browser-v1", HandoffReference: "ref:browser-session:opaque",
		ConnectionGeneration: 2, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Fence: strings.Repeat("b", handoff.MinFenceBytes)}
}

func TestOpenRequestRequiresOpaqueTenantBinding(t *testing.T) {
	now := time.Now().UTC()
	if err := validOpen(now).Validate(now); err != nil {
		t.Fatal(err)
	}
	invalid := validOpen(now)
	invalid.TenantBindingDigest = "tenant-plaintext"
	if err := invalid.Validate(now); err == nil {
		t.Fatal("plaintext tenant binding accepted")
	}
}

func TestCodecRejectsDuplicateAndUnknownMembers(t *testing.T) {
	for name, document := range map[string][]byte{
		"duplicate": []byte(`{"protocol":"sandbox-runtime.browser-handoff.v1","protocol":"sandbox-runtime.browser-handoff.v1"}`),
		"unknown":   []byte(`{"protocol":"sandbox-runtime.browser-handoff.v1","unknown":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			var request OpenRequest
			if err := handoff.Decode(document, &request); err == nil {
				t.Fatal("invalid Browser private document accepted")
			}
		})
	}
}
