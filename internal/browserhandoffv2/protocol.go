// Package browserhandoffv2 defines the closed, Provider-private Browser
// connection binding. It carries no raw capacity claim, grant ticket,
// tenant plaintext, backend coordinate or credential. The independent CDP
// action ingress remains the sole interpreter of the capacity claim.
package browserhandoffv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const (
	ProtocolID          = "sandbox-runtime.browser-handoff.v2"
	PrivatePath         = "/private/browser"
	BindingVersion      = 2
	BindingIssuer       = "browser-action-ingress"
	ResourceBrowser     = "browser"
	CapabilityProfileID = "browser-v1"
	MediaProfileID      = "browser-cdp-v1"
	ControlProfileID    = "browser-control-v1"
	StatusAccepted      = "accepted"
	StatusRejected      = "rejected"
	MaxGeneration       = int64(9_007_199_254_740_991)
)

var (
	ErrInvalid        = errors.New("invalid private Browser v2 handoff")
	ErrExpired        = errors.New("private Browser v2 handoff expired")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	referencePattern  = regexp.MustCompile(`^ref:browser-session:[0-9a-f]{32}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// OpenRequest separates Product control-lease evidence from Provider
// allocation generation and per-connection epoch. A digest is a consistency
// binding, not a substitute for Product grant or Redis action authorization.
type OpenRequest struct {
	BindingVersion       int    `json:"binding_version"`
	BindingIssuer        string `json:"binding_issuer"`
	Protocol             string `json:"protocol"`
	RequestID            string `json:"request_id"`
	Resource             string `json:"resource"`
	TenantBindingDigest  string `json:"tenant_binding_digest"`
	ProviderRevisionID   string `json:"provider_revision_id"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	MediaProfileID       string `json:"media_profile_id"`
	ControlProfileID     string `json:"control_profile_id"`
	HandoffReference     string `json:"handoff_reference"`
	HandoffDigest        string `json:"handoff_reference_digest"`
	ConnectionGeneration int64  `json:"connection_generation"`
	ConnectionEpoch      string `json:"connection_epoch"`
	ControlLeaseDigest   string `json:"control_lease_digest"`
	ControlFence         int64  `json:"control_fence"`
	AuthorityExpiresAt   string `json:"authority_expires_at"`
	HandoffExpiresAt     string `json:"handoff_expires_at"`
	AuthorityDigest      string `json:"authority_digest"`
	RequestDigest        string `json:"request_digest"`
}

type OpenResponse struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (r OpenRequest) Validate(now time.Time) error {
	if r.BindingVersion != BindingVersion || r.BindingIssuer != BindingIssuer || r.Protocol != ProtocolID ||
		r.Resource != ResourceBrowser || !requestPattern.MatchString(r.RequestID) ||
		browserbinding.ValidateDigest(r.TenantBindingDigest) != nil ||
		!identifierPattern.MatchString(r.ProviderRevisionID) || !identifierPattern.MatchString(r.SandboxID) ||
		!identifierPattern.MatchString(r.BrowserSessionID) || r.CapabilityProfileID != CapabilityProfileID ||
		r.MediaProfileID != MediaProfileID || r.ControlProfileID != ControlProfileID ||
		!referencePattern.MatchString(r.HandoffReference) || r.HandoffDigest != ReferenceDigest(r.HandoffReference) ||
		r.ConnectionGeneration < 1 || r.ConnectionGeneration > MaxGeneration || !identifierPattern.MatchString(r.ConnectionEpoch) ||
		!digestPattern.MatchString(r.ControlLeaseDigest) || r.ControlFence < 1 ||
		!digestPattern.MatchString(r.AuthorityDigest) || !digestPattern.MatchString(r.RequestDigest) ||
		r.AuthorityDigest != AuthorityDigest(r) || r.RequestDigest != RequestDigest(r) {
		return ErrInvalid
	}
	authorityExpiry, authorityErr := canonicalTime(r.AuthorityExpiresAt)
	handoffExpiry, handoffErr := canonicalTime(r.HandoffExpiresAt)
	if authorityErr != nil || handoffErr != nil || now.IsZero() || !authorityExpiry.After(now) ||
		!handoffExpiry.After(now) || authorityExpiry.After(handoffExpiry) ||
		handoffExpiry.After(now.Add(handoff.MaxAuthorityWindow)) {
		return ErrExpired
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

func ReferenceDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum[:])
}

// ExecutorFence is an opaque equality binding between the complete private
// Browser v2 authority and the fixed Browser executor role/profiles. It is
// not a sortable control fence or a substitute for Product grant checks.
func ExecutorFence(authorityDigest string) (string, error) {
	if !digestPattern.MatchString(authorityDigest) {
		return "", ErrInvalid
	}
	projection := struct {
		Domain, Authority, Role, Media, Control string
	}{"sandbox-runtime/browser-executor-fence/v2", authorityDigest, ResourceBrowser, MediaProfileID, ControlProfileID}
	document, _ := json.Marshal(projection)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/browser-executor-fence/v2\x00"), document...))
	return hex.EncodeToString(sum[:]), nil
}

// AuthorityDigest deliberately excludes RequestID and RequestDigest, so the
// same immutable authority tuple can be identified independently of one
// attach attempt. RequestDigest separately binds that attempt to the tuple.
func AuthorityDigest(r OpenRequest) string {
	value := struct {
		Domain, Issuer, Tenant, Provider, Sandbox, Session, Profile, Reference, ReferenceDigest, Epoch, LeaseDigest, AuthorityExpiry, HandoffExpiry string
		Generation, ControlFence                                                                                                                    int64
	}{"sandbox-runtime/browser-private-authority/v2", r.BindingIssuer, r.TenantBindingDigest, r.ProviderRevisionID,
		r.SandboxID, r.BrowserSessionID, r.CapabilityProfileID, r.HandoffReference, r.HandoffDigest,
		r.ConnectionEpoch, r.ControlLeaseDigest, r.AuthorityExpiresAt, r.HandoffExpiresAt,
		r.ConnectionGeneration, r.ControlFence}
	return digest(value)
}

func RequestDigest(r OpenRequest) string {
	value := struct {
		Domain, RequestID, Authority, Resource, Media, Control string
	}{"sandbox-runtime/browser-private-request/v2", r.RequestID, r.AuthorityDigest,
		r.Resource, r.MediaProfileID, r.ControlProfileID}
	return digest(value)
}

func digest(value any) string {
	document, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/browser-private-digest/v2\x00"), document...))
	return fmt.Sprintf("sha256:%x", sum[:])
}

// DecodeOpen accepts only one canonical closed document. This also rejects
// duplicate, unknown, omitted and noncanonical-but-equivalent JSON members.
func DecodeOpen(document []byte, now time.Time) (OpenRequest, error) {
	var open OpenRequest
	if handoff.Decode(document, &open) != nil || open.Validate(now) != nil {
		return OpenRequest{}, ErrInvalid
	}
	canonical, err := handoff.Encode(open)
	if err != nil || !bytes.Equal(canonical, document) {
		return OpenRequest{}, ErrInvalid
	}
	return open, nil
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

func RejectResponse(requestID string) OpenResponse {
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
