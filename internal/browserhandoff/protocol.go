// Package browserhandoff defines the Provider-private Browser attach wire.
// It is separate from the locked Provider Contract and carries no tenant
// plaintext, backend coordinate, endpoint, or credential.
package browserhandoff

import (
	"errors"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const (
	ProtocolID       = "sandbox-runtime.browser-handoff.v1"
	ResourceBrowser  = "browser"
	StatusAccepted   = "accepted"
	StatusRejected   = "rejected"
	MaxDocumentBytes = handoff.MaxDocumentBytes
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	fencePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)
	ErrInvalid        = errors.New("invalid private Browser handoff")
	ErrExpired        = errors.New("private Browser handoff authority expired")
	ErrReplay         = errors.New("private Browser handoff request replayed")
)

type OpenRequest struct {
	Protocol             string `json:"protocol"`
	RequestID            string `json:"request_id"`
	Resource             string `json:"resource"`
	TenantBindingDigest  string `json:"tenant_binding_digest"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	HandoffReference     string `json:"handoff_reference"`
	ConnectionGeneration int64  `json:"connection_generation"`
	ExpiresAt            string `json:"expires_at"`
	Fence                string `json:"fence"`
	RequestDigest        string `json:"request_digest,omitempty"`
}

type OpenResponse struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (r OpenRequest) Validate(now time.Time) error {
	if r.Protocol != ProtocolID || r.Resource != ResourceBrowser || !requestPattern.MatchString(r.RequestID) ||
		!identifierPattern.MatchString(r.SandboxID) || !identifierPattern.MatchString(r.BrowserSessionID) ||
		!identifierPattern.MatchString(r.CapabilityProfileID) || r.HandoffReference == "" ||
		!identifierPattern.MatchString(r.HandoffReference) || r.ConnectionGeneration < 1 ||
		!fencePattern.MatchString(r.Fence) || len(r.Fence) < handoff.MinFenceBytes ||
		handoff.ValidateTenantBindingDigest(r.TenantBindingDigest) != nil {
		return ErrInvalid
	}
	if r.RequestDigest != "" && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(r.RequestDigest) {
		return ErrInvalid
	}
	expires, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if err != nil || now.IsZero() || !expires.After(now) || expires.After(now.Add(handoff.MaxAuthorityWindow)) {
		return ErrExpired
	}
	return nil
}

func (r OpenResponse) Validate() error {
	if r.Protocol != ProtocolID || !requestPattern.MatchString(r.RequestID) {
		return ErrInvalid
	}
	if r.Status == StatusAccepted && r.ErrorCode == "" {
		return nil
	}
	if r.Status == StatusRejected && r.ErrorCode != "" && len(r.ErrorCode) <= 64 {
		return nil
	}
	return ErrInvalid
}

func AcceptedResponse(requestID string) OpenResponse {
	return OpenResponse{Protocol: ProtocolID, RequestID: requestID, Status: StatusAccepted}
}

func RejectResponse(requestID, code string) OpenResponse {
	if !requestPattern.MatchString(requestID) {
		requestID = "invalid"
	}
	if code == "" || len(code) > 64 {
		code = "unavailable"
	}
	return OpenResponse{Protocol: ProtocolID, RequestID: requestID, Status: StatusRejected, ErrorCode: code}
}
