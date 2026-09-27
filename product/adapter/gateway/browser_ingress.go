package productgateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/browseringress"
	"github.com/shell-echo/sandbox-runtime/product"
)

// browserIngressOpen projects only a consumed, caller-authorized Browser
// grant. Product's HMAC key and raw control-lease ID never leave the Gateway.
// The separate action ingress still has to authorize the exact Redis claim.
func browserIngressOpen(binding product.GatewayBinding, reference string,
	subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, requestID string,
) (browseringress.Open, error) {
	if binding.ProtocolProfile != product.SessionProfileBrowserAutomation ||
		binding.AccessMode != product.GrantAccessControl ||
		!browserBindingIdentifier.MatchString(binding.BrowserKeyVersion) ||
		!browserBindingIdentifier.MatchString(binding.ControlLeaseID) ||
		binding.ControlFence < 1 ||
		binding.TenantID != subject.TenantID || binding.SandboxID != subject.SandboxID ||
		binding.SessionID != subject.BrowserSessionID || subject.CapabilityProfileID != browserhandoffv2.CapabilityProfileID ||
		binding.ConnectionGeneration != subject.ConnectionGeneration ||
		binding.HandoffReference != reference ||
		!subject.ExpiresAt.Equal(minTime(binding.ExpiresAt, binding.HandoffExpiresAt)) ||
		fence.Validate() != nil {
		return browseringress.Open{}, gateway.ErrDownstreamUnavailable
	}
	digest := browserControlLeaseDigest(binding)
	open := browseringress.Open{
		Protocol: browseringress.ProtocolID, RequestID: requestID,
		CapacityClaim: fence.Opaque(), TenantID: binding.TenantID, SandboxID: binding.SandboxID,
		BrowserSessionID: binding.SessionID, CapabilityProfileID: subject.CapabilityProfileID,
		ConnectionGeneration: binding.ConnectionGeneration,
		AuthorityExpiresAt:   subject.ExpiresAt.UTC().Format(time.RFC3339Nano),
		HandoffReference:     reference, HandoffExpiresAt: binding.HandoffExpiresAt.UTC().Format(time.RFC3339Nano),
		ProviderAudience: binding.BrowserProviderAudience, ProviderRevisionID: binding.ProviderRevisionID,
		TenantBindingDigest: binding.BrowserTenantBindingDigest, GrantConnectionID: binding.ConnectionID,
		ControlLeaseDigest: digest, ControlFence: binding.ControlFence,
	}
	if open.Validate(time.Now().UTC()) != nil {
		return browseringress.Open{}, gateway.ErrDownstreamUnavailable
	}
	return open, nil
}

func browserControlLeaseDigest(binding product.GatewayBinding) string {
	projection := struct {
		Domain, Tenant, Sandbox, Session, Lease string
		Fence                                   int64
	}{"sandbox-runtime/browser-control-lease/v2", binding.TenantID, binding.SandboxID,
		binding.SessionID, binding.ControlLeaseID, binding.ControlFence}
	document, _ := json.Marshal(projection)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/browser-control-lease/v2\x00"), document...))
	return fmt.Sprintf("sha256:%x", sum[:])
}
