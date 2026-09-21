// Package executorprotocol defines the private Provider-to-role executor wire.
// It is separate from both the locked Provider Contract and the Product
// Gateway handoff protocols. Executors receive only short-lived opaque
// authority and never receive backend coordinates or credentials.
package executorprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const (
	LegacyProtocolID = "sandbox-runtime.executor.v1"
	ProtocolID       = "sandbox-runtime.executor.v2"
	RoleBrowser      = "browser"
	RoleDesktop      = "desktop"
	StatusAccepted   = "accepted"
	StatusRejected   = "rejected"
	MaxDocumentBytes = 16 << 10
	MaxMessageBytes  = 256 << 10
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	fencePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)
	ErrInvalid        = errors.New("invalid private executor authority")
	ErrExpired        = errors.New("private executor authority expired")
	ErrReplay         = errors.New("private executor request replayed")
)

// Open is the sole authority document sent to an executor. Every field is
// bound to the Provider-owned handoff/reference record; an executor cannot
// derive or change any of these values.
type Open struct {
	Protocol             string                    `json:"protocol"`
	Role                 string                    `json:"role"`
	RequestID            string                    `json:"request_id"`
	TenantBindingDigest  string                    `json:"tenant_binding_digest"`
	ProviderRevisionID   string                    `json:"provider_revision_id"`
	SandboxID            string                    `json:"sandbox_id"`
	RuntimeSessionID     string                    `json:"runtime_session_id"`
	CapabilityProfileID  string                    `json:"capability_profile_id"`
	MediaProfileID       string                    `json:"media_profile_id"`
	ControlProfileID     string                    `json:"control_profile_id"`
	AllocationReference  string                    `json:"allocation_reference,omitempty"`
	MediaPolicy          *desktopmedia.MediaPolicy `json:"media_policy,omitempty"`
	MediaPolicyDigest    string                    `json:"media_policy_digest,omitempty"`
	Bridge               *desktopbridge.Envelope   `json:"bridge,omitempty"`
	HandoffReference     string                    `json:"handoff_reference"`
	HandoffDigest        string                    `json:"handoff_reference_digest"`
	ConnectionGeneration int64                     `json:"connection_generation"`
	ConnectionEpoch      string                    `json:"connection_epoch"`
	Fence                string                    `json:"fence"`
	AuthorityExpiresAt   string                    `json:"authority_expires_at"`
	HandoffExpiresAt     string                    `json:"handoff_expires_at"`
	AuthorityDigest      string                    `json:"authority_digest"`
	RequestDigest        string                    `json:"request_digest"`
	Codec                string                    `json:"codec"`
}

type Response struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (o Open) Validate(now time.Time) error {
	if o.Protocol != ProtocolID || (o.Role != RoleBrowser && o.Role != RoleDesktop) ||
		!requestPattern.MatchString(o.RequestID) || handoff.ValidateTenantBindingDigest(o.TenantBindingDigest) != nil ||
		!identifierPattern.MatchString(o.ProviderRevisionID) || !identifierPattern.MatchString(o.SandboxID) ||
		!identifierPattern.MatchString(o.RuntimeSessionID) || !identifierPattern.MatchString(o.CapabilityProfileID) ||
		!identifierPattern.MatchString(o.MediaProfileID) || !identifierPattern.MatchString(o.ControlProfileID) ||
		!opaqueReference(o.HandoffReference) || !digestPattern.MatchString(o.HandoffDigest) ||
		o.ConnectionGeneration < 1 || !identifierPattern.MatchString(o.ConnectionEpoch) ||
		!fencePattern.MatchString(o.Fence) || !digestPattern.MatchString(o.AuthorityDigest) ||
		!digestPattern.MatchString(o.RequestDigest) || strings.TrimSpace(o.Codec) != o.Codec ||
		o.Codec == "" || len(o.Codec) > 128 {
		return ErrInvalid
	}
	if o.Role == RoleBrowser && (o.CapabilityProfileID != "browser-v1" || o.MediaProfileID != "browser-cdp-v1" || o.ControlProfileID != "browser-control-v1" || o.AllocationReference != "" || o.MediaPolicy != nil || o.MediaPolicyDigest != "" || o.Bridge != nil) {
		return ErrInvalid
	}
	if o.Role == RoleDesktop {
		if !allocationReference(o.AllocationReference) || o.MediaPolicy == nil || !o.MediaPolicy.Validate() || o.MediaPolicyDigest != PolicyDigest(*o.MediaPolicy) || o.Codec != o.MediaPolicy.VideoCodec || o.Bridge == nil || o.Bridge.Validate(now) != nil || !bridgeMatchesOpen(*o.Bridge, o) {
			return ErrInvalid
		}
	}
	if o.Role == RoleDesktop && (o.CapabilityProfileID != "desktop-v1" || o.MediaProfileID != "desktop-media-v1" || o.ControlProfileID != "desktop-control-v1") {
		return ErrInvalid
	}
	if o.HandoffDigest != ReferenceDigest(o.HandoffReference) || o.AuthorityDigest != o.CalculateAuthorityDigest() || o.RequestDigest != o.CalculateRequestDigest() {
		return ErrInvalid
	}
	authorityExpiry, authorityErr := time.Parse(time.RFC3339Nano, o.AuthorityExpiresAt)
	handoffExpiry, handoffErr := time.Parse(time.RFC3339Nano, o.HandoffExpiresAt)
	if authorityErr != nil || handoffErr != nil || now.IsZero() || !authorityExpiry.After(now) ||
		!handoffExpiry.After(now) || authorityExpiry.After(handoffExpiry) ||
		handoffExpiry.After(now.Add(handoff.MaxAuthorityWindow)) {
		return ErrExpired
	}
	return nil
}

func bridgeMatchesOpen(bridge desktopbridge.Envelope, open Open) bool {
	s := bridge.Statement
	return s.ExecutorAuthorityDigest == open.AuthorityDigest && s.ExecutorRequestDigest == open.RequestDigest &&
		s.ProviderRevisionID == open.ProviderRevisionID && s.TenantBindingDigest == open.TenantBindingDigest &&
		s.SandboxID == open.SandboxID && s.RuntimeSessionID == open.RuntimeSessionID &&
		s.HandoffReferenceDigest == open.HandoffDigest && s.AllocationReference == open.AllocationReference && s.MediaPolicy == *open.MediaPolicy &&
		s.ConnectionGeneration == open.ConnectionGeneration && s.ConnectionEpoch == open.ConnectionEpoch && s.Fence == open.Fence &&
		s.AuthorityExpiresAt == open.AuthorityExpiresAt && s.HandoffExpiresAt == open.HandoffExpiresAt
}

func ReferenceDigest(value string) string { return referenceDigest(value) }

func (o Open) CalculateAuthorityDigest() string {
	value := struct {
		Domain, Role, Tenant, Provider, Sandbox, Session, Allocation, Reference, Epoch, Fence, AuthorityExpiry, HandoffExpiry string
		Policy                                                                                                                *desktopmedia.MediaPolicy
		Generation                                                                                                            int64
	}{"sandbox-runtime/executor-authority/v2", o.Role, o.TenantBindingDigest, o.ProviderRevisionID, o.SandboxID, o.RuntimeSessionID, o.AllocationReference, o.HandoffReference, o.ConnectionEpoch, o.Fence, o.AuthorityExpiresAt, o.HandoffExpiresAt, o.MediaPolicy, o.ConnectionGeneration}
	return digestDocument(value)
}

func (o Open) CalculateRequestDigest() string {
	value := struct {
		Domain, Authority, MediaProfile, ControlProfile, Codec, PolicyDigest string
	}{"sandbox-runtime/executor-request/v2", o.AuthorityDigest, o.MediaProfileID, o.ControlProfileID, o.Codec, o.MediaPolicyDigest}
	return digestDocument(value)
}

func PolicyDigest(value desktopmedia.MediaPolicy) string {
	return digestDocument(struct {
		Domain string
		Policy desktopmedia.MediaPolicy
	}{"sandbox-runtime/executor-media-policy/v2", value})
}

func (r Response) Validate() error {
	if r.Protocol != ProtocolID || !requestPattern.MatchString(r.RequestID) {
		return ErrInvalid
	}
	switch r.Status {
	case StatusAccepted:
		if r.ErrorCode != "" {
			return ErrInvalid
		}
	case StatusRejected:
		if r.ErrorCode == "" || len(r.ErrorCode) > 64 || strings.ContainsAny(r.ErrorCode, " \t\r\n\x00") {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func Accepted(requestID string) Response {
	return Response{Protocol: ProtocolID, RequestID: requestID, Status: StatusAccepted}
}

func Rejected(requestID, code string) Response {
	if !requestPattern.MatchString(requestID) {
		requestID = "invalid"
	}
	if code == "" || len(code) > 64 || strings.ContainsAny(code, " \t\r\n\x00") {
		code = "unavailable"
	}
	return Response{Protocol: ProtocolID, RequestID: requestID, Status: StatusRejected, ErrorCode: code}
}

func Encode(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil || len(document) > MaxDocumentBytes {
		return nil, ErrInvalid
	}
	return document, nil
}

func Decode(document []byte, target any) error {
	if len(document) == 0 || len(document) > MaxDocumentBytes || target == nil || rejectDuplicates(document) != nil {
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

func rejectDuplicates(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return ErrInvalid
				}
				if _, exists := seen[name]; exists {
					return ErrInvalid
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalid
		}
	}
	if err := walk(); err != nil {
		return err
	}
	var trailing any
	return func() error {
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return ErrInvalid
		}
		return nil
	}()
}

func opaqueReference(value string) bool {
	return len(value) > 4 && len(value) <= 512 && strings.HasPrefix(value, "ref:") && !strings.ContainsAny(value, " \t\r\n\x00")
}

func referenceDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", digest[:])
}

func allocationReference(value string) bool {
	if len(value) != len("ref:desktop/")+32 || !strings.HasPrefix(value, "ref:desktop/") {
		return false
	}
	for _, character := range value[len("ref:desktop/"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func digestDocument(value any) string {
	document, _ := json.Marshal(value)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/executor-digest/v2\x00"), document...))
	return fmt.Sprintf("sha256:%x", digest[:])
}
