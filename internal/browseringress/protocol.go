// Package browseringress defines the closed Gateway-to-action-ingress Browser
// activation document. It is not a Provider contract or an end-user token.
package browseringress

import (
	"bytes"
	"errors"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const ProtocolID = "sandbox-runtime.browser-action-ingress.v2"

const (
	StatusAccepted = "accepted"
	StatusRejected = "rejected"
)

var (
	ErrInvalid        = errors.New("invalid private Browser action-ingress open")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	referencePattern  = regexp.MustCompile(`^ref:browser-session:[0-9a-f]{32}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Open carries a caller-owned projection of a consumed Product grant and
// committed handoff binding, plus the exact bearer-like Redis capacity claim.
// The full document is secret: never log, audit, or persist it. The mTLS
// Gateway peer, not any field in this document, authenticates its issuer.
// The action ingress must authorize the capacity claim before deriving a
// separate Provider v2 Open with its own per-attempt connection epoch.
type Open struct {
	Protocol             string `json:"protocol"`
	RequestID            string `json:"request_id"`
	CapacityClaim        string `json:"capacity_claim"`
	TenantID             string `json:"tenant_id"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	ConnectionGeneration int64  `json:"connection_generation"`
	AuthorityExpiresAt   string `json:"authority_expires_at"`
	HandoffReference     string `json:"handoff_reference"`
	HandoffExpiresAt     string `json:"handoff_expires_at"`
	ProviderAudience     string `json:"provider_audience"`
	ProviderRevisionID   string `json:"provider_revision_id"`
	TenantBindingDigest  string `json:"tenant_binding_digest"`
	GrantConnectionID    string `json:"grant_connection_id"`
	ControlLeaseDigest   string `json:"control_lease_digest"`
	ControlFence         int64  `json:"control_fence"`
}

type OpenResponse struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (r OpenResponse) Validate() error {
	if r.Protocol != ProtocolID || !requestPattern.MatchString(r.RequestID) ||
		!(r.Status == StatusAccepted && r.ErrorCode == "" ||
			r.Status == StatusRejected && r.ErrorCode == "unavailable") {
		return ErrInvalid
	}
	return nil
}

func AcceptedResponse(requestID string) OpenResponse {
	return OpenResponse{Protocol: ProtocolID, RequestID: requestID, Status: StatusAccepted}
}

func RejectedResponse(requestID string) OpenResponse {
	if !requestPattern.MatchString(requestID) {
		requestID = "invalid"
	}
	return OpenResponse{Protocol: ProtocolID, RequestID: requestID, Status: StatusRejected, ErrorCode: "unavailable"}
}

func DecodeResponse(document []byte) (OpenResponse, error) {
	var response OpenResponse
	if handoff.Decode(document, &response) != nil || response.Validate() != nil {
		return OpenResponse{}, ErrInvalid
	}
	canonical, err := handoff.Encode(response)
	if err != nil || !bytes.Equal(canonical, document) {
		return OpenResponse{}, ErrInvalid
	}
	return response, nil
}

// Validate closes all private fields and the cross-field expiry relation.
// Product grant consumption and lease liveness are still Gateway-owned; this
// structural check is never a substitute for them or for Redis admission.
func (o Open) Validate(now time.Time) error {
	if o.Protocol != ProtocolID || !requestPattern.MatchString(o.RequestID) ||
		!identifierPattern.MatchString(o.TenantID) || !identifierPattern.MatchString(o.SandboxID) ||
		!identifierPattern.MatchString(o.BrowserSessionID) || o.CapabilityProfileID != browserhandoffv2.CapabilityProfileID ||
		o.ConnectionGeneration < 1 || o.ConnectionGeneration > browserhandoffv2.MaxGeneration ||
		!referencePattern.MatchString(o.HandoffReference) ||
		!identifierPattern.MatchString(o.ProviderAudience) ||
		!identifierPattern.MatchString(o.ProviderRevisionID) ||
		browserbinding.ValidateDigest(o.TenantBindingDigest) != nil ||
		!identifierPattern.MatchString(o.GrantConnectionID) ||
		!digestPattern.MatchString(o.ControlLeaseDigest) || o.ControlFence < 1 ||
		now.IsZero() {
		return ErrInvalid
	}
	if _, err := gateway.NewDownstreamFence(o.CapacityClaim); err != nil {
		return ErrInvalid
	}
	authorityExpiry, err := canonicalTime(o.AuthorityExpiresAt)
	if err != nil || !authorityExpiry.After(now) ||
		authorityExpiry.After(now.Add(gateway.MaxDownstreamClaimLifetime)) {
		return ErrInvalid
	}
	handoffExpiry, err := canonicalTime(o.HandoffExpiresAt)
	if err != nil || !handoffExpiry.After(now) || authorityExpiry.After(handoffExpiry) ||
		handoffExpiry.After(now.Add(handoff.MaxAuthorityWindow)) {
		return ErrInvalid
	}
	return nil
}

func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

func (o Open) Subject(now time.Time) (gateway.DownstreamFenceSubject, gateway.DownstreamFence, error) {
	if o.Validate(now) != nil {
		return gateway.DownstreamFenceSubject{}, gateway.DownstreamFence{}, ErrInvalid
	}
	expires, _ := canonicalTime(o.AuthorityExpiresAt)
	fence, _ := gateway.NewDownstreamFence(o.CapacityClaim)
	return gateway.DownstreamFenceSubject{
		TenantID: o.TenantID, SandboxID: o.SandboxID,
		BrowserSessionID: o.BrowserSessionID, CapabilityProfileID: o.CapabilityProfileID,
		ConnectionGeneration: o.ConnectionGeneration, ExpiresAt: expires,
	}, fence, nil
}

// DecodeOpen rejects unknown, duplicate, omitted and noncanonical members.
func DecodeOpen(document []byte, now time.Time) (Open, error) {
	var open Open
	if handoff.Decode(document, &open) != nil || open.Validate(now) != nil {
		return Open{}, ErrInvalid
	}
	canonical, err := handoff.Encode(open)
	if err != nil || !bytes.Equal(canonical, document) {
		return Open{}, ErrInvalid
	}
	return open, nil
}
