// Package handoff defines the private Gateway-to-Provider handoff wire
// contract. It is deliberately separate from the locked Provider Contract:
// it carries only an opaque reference and the exact authority binding needed
// by one private attach.
package handoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	ProtocolID         = "sandbox-runtime.handoff.v1"
	ResourceTerminal   = "terminal"
	StatusAccepted     = "accepted"
	StatusRejected     = "rejected"
	MaxDocumentBytes   = 8 << 10
	MaxFrameBytes      = 64 << 10
	MaxReferenceBytes  = 512
	MaxFenceBytes      = 512
	MaxAuthorityWindow = 24 * time.Hour
	MinFenceBytes      = 32
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	fencePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)
	ErrInvalid        = errors.New("invalid private handoff")
	ErrExpired        = errors.New("private handoff authority expired")
	ErrReplay         = errors.New("private handoff request replayed")
	ErrUnavailable    = errors.New("private handoff unavailable")
)

// OpenRequest is the closed schema exchanged as the first private WebSocket
// message. The fence is an opaque per-attach nonce and is never interpreted
// by the public Gateway.
type OpenRequest struct {
	Protocol             string `json:"protocol"`
	RequestID            string `json:"request_id"`
	Resource             string `json:"resource"`
	TenantID             string `json:"tenant_id"`
	SandboxID            string `json:"sandbox_id"`
	RuntimeSessionID     string `json:"runtime_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	HandoffReference     string `json:"handoff_reference"`
	ConnectionGeneration int64  `json:"connection_generation"`
	ExpiresAt            string `json:"expires_at"`
	Fence                string `json:"fence"`
}

// OpenResponse is intentionally generic. It never includes resolver errors,
// backend IDs, host paths, endpoints, or Provider diagnostics.
type OpenResponse struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (r OpenRequest) Validate(now time.Time) error {
	if r.Protocol != ProtocolID || r.Resource != ResourceTerminal || !requestPattern.MatchString(r.RequestID) ||
		!identifierPattern.MatchString(r.TenantID) || !identifierPattern.MatchString(r.SandboxID) ||
		!identifierPattern.MatchString(r.RuntimeSessionID) || !identifierPattern.MatchString(r.CapabilityProfileID) ||
		!opaqueReference(r.HandoffReference) || r.ConnectionGeneration < 1 || !fencePattern.MatchString(r.Fence) || len(r.Fence) < MinFenceBytes {
		return ErrInvalid
	}
	expires, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if err != nil || now.IsZero() || !expires.After(now) || expires.After(now.Add(MaxAuthorityWindow)) {
		return ErrExpired
	}
	return nil
}

func (r OpenResponse) Validate() error {
	if r.Protocol != ProtocolID || !requestPattern.MatchString(r.RequestID) {
		return ErrInvalid
	}
	switch r.Status {
	case StatusAccepted:
		if r.ErrorCode != "" {
			return ErrInvalid
		}
	case StatusRejected:
		if r.ErrorCode == "" || len(r.ErrorCode) > 64 || strings.ContainsAny(r.ErrorCode, " \t\r\n") {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func Decode(document []byte, target any) error {
	if len(document) == 0 || len(document) > MaxDocumentBytes || target == nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func Encode(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil || len(document) > MaxDocumentBytes {
		return nil, ErrInvalid
	}
	return document, nil
}

func opaqueReference(value string) bool {
	return len(value) >= len("ref:")+1 && len(value) <= MaxReferenceBytes && strings.HasPrefix(value, "ref:") && !strings.ContainsAny(value, " \t\r\n\x00")
}

func RejectResponse(requestID, code string) OpenResponse {
	if !requestPattern.MatchString(requestID) {
		requestID = "invalid"
	}
	if code == "" || len(code) > 64 || strings.ContainsAny(code, " \t\r\n") {
		code = "unavailable"
	}
	return OpenResponse{Protocol: ProtocolID, RequestID: requestID, Status: StatusRejected, ErrorCode: code}
}

func AcceptedResponse(requestID string) OpenResponse {
	return OpenResponse{Protocol: ProtocolID, RequestID: requestID, Status: StatusAccepted}
}

func AuthorityExpiry(value string) (time.Time, error) {
	expires, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: expiry", ErrInvalid)
	}
	return expires.UTC(), nil
}
