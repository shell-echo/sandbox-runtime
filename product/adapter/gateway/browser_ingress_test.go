package productgateway

import (
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/product"
)

func ingressBindingFixture() product.GatewayBinding {
	now := time.Now().UTC().Truncate(time.Second)
	return product.GatewayBinding{
		ConnectionID: "connection-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
		SessionID: "browser-1", ProtocolProfile: product.SessionProfileBrowserAutomation,
		AccessMode: product.GrantAccessControl, ControlLeaseID: "lease-private-1", ControlFence: 7,
		ExpiresAt: now.Add(time.Minute), HandoffExpiresAt: now.Add(2 * time.Minute),
		HandoffReference: "ref:browser-session:" + strings.Repeat("a", 32), ConnectionGeneration: 2,
		ProviderRevisionID: "revision-1", BrowserProviderAudience: "browser-provider-1",
		BrowserTenantBindingDigest: browserbinding.Prefix + strings.Repeat("b", 64), BrowserKeyVersion: "v1",
	}
}

func TestBrowserIngressOpenProjectsCommittedGrantWithoutLeaseSecret(t *testing.T) {
	binding := ingressBindingFixture()
	request, grant := browserGatewayValues(binding)
	if request.CapabilityProfileID != browserhandoffv2.CapabilityProfileID ||
		grant.CapabilityProfileID != browserhandoffv2.CapabilityProfileID ||
		binding.ProtocolProfile != product.SessionProfileBrowserAutomation {
		t.Fatal("Product wire protocol and Provider capability profile must remain separate")
	}
	subject := gateway.DownstreamFenceSubject{TenantID: binding.TenantID, SandboxID: binding.SandboxID,
		BrowserSessionID: binding.SessionID, CapabilityProfileID: browserhandoffv2.CapabilityProfileID,
		ConnectionGeneration: binding.ConnectionGeneration, ExpiresAt: binding.ExpiresAt}
	fence, err := gateway.NewDownstreamFence("v1.opaque-capacity-claim")
	if err != nil {
		t.Fatal(err)
	}
	open, err := browserIngressOpen(binding, binding.HandoffReference, subject, fence, "request-1")
	if err != nil {
		t.Fatal(err)
	}
	if open.TenantBindingDigest != binding.BrowserTenantBindingDigest ||
		open.ProviderAudience != binding.BrowserProviderAudience ||
		open.ControlLeaseDigest == "" || strings.Contains(open.ControlLeaseDigest, binding.ControlLeaseID) ||
		open.GrantConnectionID != binding.ConnectionID || open.CapabilityProfileID != browserhandoffv2.CapabilityProfileID {
		t.Fatal("private ingress projection lost binding or exposed raw lease")
	}
	for name, mutate := range map[string]func(*product.GatewayBinding, *gateway.DownstreamFenceSubject){
		"uncommitted digest": func(b *product.GatewayBinding, _ *gateway.DownstreamFenceSubject) { b.BrowserTenantBindingDigest = "" },
		"uncommitted key":    func(b *product.GatewayBinding, _ *gateway.DownstreamFenceSubject) { b.BrowserKeyVersion = "" },
		"wrong audience":     func(b *product.GatewayBinding, _ *gateway.DownstreamFenceSubject) { b.BrowserProviderAudience = "" },
		"tenant drift":       func(_ *product.GatewayBinding, s *gateway.DownstreamFenceSubject) { s.TenantID = "tenant-2" },
		"profile drift": func(_ *product.GatewayBinding, s *gateway.DownstreamFenceSubject) {
			s.CapabilityProfileID = product.SessionProfileBrowserAutomation
		},
		"expiry drift": func(_ *product.GatewayBinding, s *gateway.DownstreamFenceSubject) {
			s.ExpiresAt = s.ExpiresAt.Add(time.Second)
		},
		"no control lease": func(b *product.GatewayBinding, _ *gateway.DownstreamFenceSubject) { b.ControlLeaseID = "" },
		"view grant": func(b *product.GatewayBinding, _ *gateway.DownstreamFenceSubject) {
			b.AccessMode = product.GrantAccessView
		},
	} {
		t.Run(name, func(t *testing.T) {
			badBinding, badSubject := binding, subject
			mutate(&badBinding, &badSubject)
			if _, err := browserIngressOpen(badBinding, binding.HandoffReference, badSubject, fence, "request-2"); err == nil {
				t.Fatal("inconsistent or uncommitted grant projected")
			}
		})
	}
}
