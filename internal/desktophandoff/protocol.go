// Package desktophandoff defines the closed Provider-private Desktop bridge
// handshake. Media and input channels are separate at the frame layer; this
// document carries only opaque authority and bounded media policy.
package desktophandoff

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const (
	ProtocolID       = "sandbox-runtime.desktop-handoff.v1"
	ResourceDesktop  = "desktop"
	StatusAccepted   = "accepted"
	StatusRejected   = "rejected"
	MaxDocumentBytes = handoff.MaxDocumentBytes
	MediaProfileID   = "desktop-media-v1"
	ControlProfileID = "desktop-control-v1"
	BindingVersion   = 1
	BindingIssuer    = "product-gateway"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	fencePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	ErrInvalid        = errors.New("invalid private Desktop handoff")
	ErrExpired        = errors.New("private Desktop handoff authority expired")
)

type OpenRequest struct {
	BindingVersion       int                      `json:"binding_version"`
	BindingIssuer        string                   `json:"binding_issuer"`
	Protocol             string                   `json:"protocol"`
	RequestID            string                   `json:"request_id"`
	Resource             string                   `json:"resource"`
	TenantBindingDigest  string                   `json:"tenant_binding_digest"`
	ProviderRevisionID   string                   `json:"provider_revision_id"`
	SandboxID            string                   `json:"sandbox_id"`
	DesktopSessionID     string                   `json:"desktop_session_id"`
	CapabilityProfileID  string                   `json:"capability_profile_id"`
	MediaProfileID       string                   `json:"media_profile_id"`
	ControlProfileID     string                   `json:"control_profile_id"`
	HandoffReference     string                   `json:"handoff_reference"`
	HandoffDigest        string                   `json:"handoff_reference_digest"`
	ConnectionGeneration int64                    `json:"connection_generation"`
	ConnectionEpoch      string                   `json:"connection_epoch"`
	AuthorityExpiresAt   string                   `json:"authority_expires_at"`
	HandoffExpiresAt     string                   `json:"handoff_expires_at"`
	ControllerFence      string                   `json:"controller_fence"`
	AuthorityDigest      string                   `json:"authority_digest"`
	RequestDigest        string                   `json:"request_digest"`
	MediaPolicy          desktopmedia.MediaPolicy `json:"media_policy"`
}

// Binding is the private, opaque registration authority persisted by the
// Provider before a media session is attached. It never contains tenant
// plaintext, backend coordinates, host paths or credentials.
type Binding struct {
	Version              int                      `json:"version"`
	Issuer               string                   `json:"issuer"`
	TenantBindingDigest  string                   `json:"tenant_binding_digest"`
	ProviderRevisionID   string                   `json:"provider_revision_id"`
	SandboxID            string                   `json:"sandbox_id"`
	DesktopSessionID     string                   `json:"desktop_session_id"`
	HandoffReference     string                   `json:"handoff_reference"`
	ConnectionGeneration int64                    `json:"connection_generation"`
	ConnectionEpoch      string                   `json:"connection_epoch"`
	ControllerFence      string                   `json:"controller_fence"`
	AuthorityExpiresAt   time.Time                `json:"authority_expires_at"`
	HandoffExpiresAt     time.Time                `json:"handoff_expires_at"`
	AuthorityDigest      string                   `json:"authority_digest"`
	RequestDigest        string                   `json:"request_digest"`
	MediaPolicy          desktopmedia.MediaPolicy `json:"media_policy"`
}

type OpenResponse struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (r OpenRequest) Validate(now time.Time) error {
	if r.BindingVersion != BindingVersion || r.BindingIssuer != BindingIssuer || r.Protocol != ProtocolID || r.Resource != ResourceDesktop || !requestPattern.MatchString(r.RequestID) ||
		handoff.ValidateTenantBindingDigest(r.TenantBindingDigest) != nil || !identifierPattern.MatchString(r.ProviderRevisionID) ||
		!identifierPattern.MatchString(r.SandboxID) ||
		!identifierPattern.MatchString(r.DesktopSessionID) || !identifierPattern.MatchString(r.CapabilityProfileID) ||
		r.MediaProfileID != MediaProfileID || r.ControlProfileID != ControlProfileID ||
		!identifierPattern.MatchString(r.HandoffReference) || !digestPattern.MatchString(r.HandoffDigest) ||
		r.HandoffDigest != ReferenceDigest(r.HandoffReference) || r.ConnectionGeneration < 1 ||
		!identifierPattern.MatchString(r.ConnectionEpoch) ||
		!fencePattern.MatchString(r.ControllerFence) || len(r.ControllerFence) < handoff.MinFenceBytes ||
		!digestPattern.MatchString(r.AuthorityDigest) || !digestPattern.MatchString(r.RequestDigest) ||
		!r.MediaPolicy.Validate() {
		return ErrInvalid
	}
	authorityExpires, authorityErr := time.Parse(time.RFC3339Nano, r.AuthorityExpiresAt)
	handoffExpires, handoffErr := time.Parse(time.RFC3339Nano, r.HandoffExpiresAt)
	if authorityErr != nil || handoffErr != nil || now.IsZero() || !authorityExpires.After(now) ||
		!handoffExpires.After(now) || authorityExpires.After(handoffExpires) ||
		authorityExpires.After(now.Add(handoff.MaxAuthorityWindow)) || handoffExpires.After(now.Add(handoff.MaxAuthorityWindow)) {
		return ErrExpired
	}
	if r.AuthorityDigest != AuthorityDigest(r) || r.RequestDigest != RequestDigest(r) {
		return ErrInvalid
	}
	return nil
}

func (r OpenRequest) Binding() Binding {
	authorityExpires, _ := time.Parse(time.RFC3339Nano, r.AuthorityExpiresAt)
	handoffExpires, _ := time.Parse(time.RFC3339Nano, r.HandoffExpiresAt)
	return Binding{Version: r.BindingVersion, Issuer: r.BindingIssuer, TenantBindingDigest: r.TenantBindingDigest,
		ProviderRevisionID: r.ProviderRevisionID, SandboxID: r.SandboxID, DesktopSessionID: r.DesktopSessionID,
		HandoffReference: r.HandoffReference, ConnectionGeneration: r.ConnectionGeneration, ConnectionEpoch: r.ConnectionEpoch,
		ControllerFence: r.ControllerFence, AuthorityExpiresAt: authorityExpires, HandoffExpiresAt: handoffExpires,
		AuthorityDigest: r.AuthorityDigest, RequestDigest: r.RequestDigest, MediaPolicy: r.MediaPolicy}
}

func (b Binding) Validate(now time.Time) error {
	open := OpenRequest{BindingVersion: b.Version, BindingIssuer: b.Issuer, Protocol: ProtocolID, RequestID: "binding-validate", Resource: ResourceDesktop,
		TenantBindingDigest: b.TenantBindingDigest, ProviderRevisionID: b.ProviderRevisionID, SandboxID: b.SandboxID,
		DesktopSessionID: b.DesktopSessionID, CapabilityProfileID: "desktop-v1", MediaProfileID: MediaProfileID, ControlProfileID: ControlProfileID,
		HandoffReference: b.HandoffReference, HandoffDigest: ReferenceDigest(b.HandoffReference), ConnectionGeneration: b.ConnectionGeneration,
		ConnectionEpoch: b.ConnectionEpoch, AuthorityExpiresAt: b.AuthorityExpiresAt.UTC().Format(time.RFC3339Nano), HandoffExpiresAt: b.HandoffExpiresAt.UTC().Format(time.RFC3339Nano),
		ControllerFence: b.ControllerFence, AuthorityDigest: b.AuthorityDigest, RequestDigest: b.RequestDigest, MediaPolicy: b.MediaPolicy}
	if err := open.Validate(now); err != nil {
		return err
	}
	if b.AuthorityExpiresAt.IsZero() || b.HandoffExpiresAt.IsZero() || b.AuthorityDigest != AuthorityDigest(open) || b.RequestDigest != RequestDigest(open) {
		return ErrInvalid
	}
	return nil
}

func AuthorityDigest(r OpenRequest) string {
	value := struct {
		Domain          string `json:"domain"`
		Version         int    `json:"version"`
		Issuer          string `json:"issuer"`
		Tenant          string `json:"tenant_binding_digest"`
		Provider        string `json:"provider_revision_id"`
		Sandbox         string `json:"sandbox_id"`
		Session         string `json:"desktop_session_id"`
		Reference       string `json:"handoff_reference"`
		Generation      int64  `json:"connection_generation"`
		Epoch           string `json:"connection_epoch"`
		Fence           string `json:"controller_fence"`
		AuthorityExpiry string `json:"authority_expires_at"`
		HandoffExpiry   string `json:"handoff_expires_at"`
	}{"sandbox-runtime/desktop-private-binding", BindingVersion, r.BindingIssuer, r.TenantBindingDigest, r.ProviderRevisionID, r.SandboxID, r.DesktopSessionID, r.HandoffReference, r.ConnectionGeneration, r.ConnectionEpoch, r.ControllerFence, r.AuthorityExpiresAt, r.HandoffExpiresAt}
	return digestDocument(value)
}

func RequestDigest(r OpenRequest) string {
	value := struct {
		Domain    string                   `json:"domain"`
		Version   int                      `json:"version"`
		Authority string                   `json:"authority_digest"`
		Media     desktopmedia.MediaPolicy `json:"media_policy"`
	}{"sandbox-runtime/desktop-private-request", BindingVersion, AuthorityDigest(r), r.MediaPolicy}
	return digestDocument(value)
}

func digestDocument(value any) string {
	document, _ := json.Marshal(value)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/desktop-private-digest/v1\x00"), document...))
	return fmt.Sprintf("sha256:%x", digest[:])
}

func ReferenceDigest(reference string) string {
	digest := sha256.Sum256([]byte(reference))
	return fmt.Sprintf("sha256:%x", digest[:])
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
