// Package wire defines the bounded private Gateway-to-ingress protocol used
// only by the downstream-fencing E2E deployment.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	ProtocolVersion    = 1
	ProtocolName       = "sandbox-runtime.downstream-fencing.v1"
	ActionACKPayload   = "sandbox-runtime-downstream-action-v1"
	ResolvePath        = "/private/v1/browser/downstream-fence/resolve"
	ConnectPath        = "/private/v1/browser/downstream-fence/connect"
	MaxResolutionBytes = 4 << 10
	MaxActivationBytes = 4 << 10
	MaxMessageBytes    = 64 << 10

	IngressRoleURI  = "spiffe://downstream-fencing/ingress"
	GatewayARoleURI = "spiffe://downstream-fencing/gateway-a"
	GatewayBRoleURI = "spiffe://downstream-fencing/gateway-b"

	StatusReady    = "ready"
	StatusRejected = "rejected"

	ErrorInvalidActivation = "invalid_activation"
	ErrorUnavailable       = "downstream_unavailable"
	ErrorFenceLost         = "downstream_fence_lost"
)

var ErrInvalidMessage = errors.New("invalid private downstream-fencing message")

// ResolutionRequest carries only the opaque handoff needed for read-only
// Provider resolution. It never carries a subject or action-fence claim.
type ResolutionRequest struct {
	Version          int    `json:"version"`
	HandoffReference string `json:"handoff_reference"`
}

// Activation is the only message that carries the subject and opaque
// action-fence claim. It is sent as the first WebSocket text message, never as
// URL or HTTP-header material.
type Activation struct {
	Version          int     `json:"version"`
	HandoffReference string  `json:"handoff_reference"`
	Subject          Subject `json:"subject"`
	Fence            string  `json:"fence"`
}

func NewResolutionRequest(reference string) (ResolutionRequest, error) {
	request := ResolutionRequest{Version: ProtocolVersion, HandoffReference: reference}
	if _, err := request.Values(); err != nil {
		return ResolutionRequest{}, err
	}
	return request, nil
}

func (r ResolutionRequest) Values() (string, error) {
	if r.Version != ProtocolVersion || !validReference(r.HandoffReference) {
		return "", ErrInvalidMessage
	}
	return r.HandoffReference, nil
}

func EncodeResolutionRequest(request ResolutionRequest) ([]byte, error) {
	if _, err := request.Values(); err != nil {
		return nil, ErrInvalidMessage
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > MaxResolutionBytes {
		return nil, ErrInvalidMessage
	}
	return encoded, nil
}

func DecodeResolutionRequest(encoded []byte) (ResolutionRequest, error) {
	if len(encoded) == 0 || len(encoded) > MaxResolutionBytes || !uniqueJSONFields(encoded) {
		return ResolutionRequest{}, ErrInvalidMessage
	}
	var request ResolutionRequest
	if err := decodeStrict(encoded, &request); err != nil {
		return ResolutionRequest{}, ErrInvalidMessage
	}
	if _, err := request.Values(); err != nil {
		return ResolutionRequest{}, ErrInvalidMessage
	}
	return request, nil
}

type Subject struct {
	TenantID             string `json:"tenant_id"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	ConnectionGeneration int64  `json:"connection_generation"`
	ExpiresAt            string `json:"expires_at"`
}

type ActivationResponse struct {
	Version   int    `json:"version"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

// ResolutionResponse returns only the Provider's public-to-Gateway handoff
// metadata. Resolve never activates a fence or opens a Chromium stream.
type ResolutionResponse struct {
	Version   int               `json:"version"`
	Status    string            `json:"status"`
	Endpoint  *EndpointMetadata `json:"endpoint,omitempty"`
	ErrorCode string            `json:"error_code,omitempty"`
}

type EndpointMetadata struct {
	Reference            string `json:"reference"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	ConnectionGeneration int64  `json:"connection_generation"`
	ExpiresAt            string `json:"expires_at"`
}

func NewActivation(reference string, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence) (Activation, error) {
	activation := Activation{
		Version: ProtocolVersion, HandoffReference: reference, Fence: fence.Opaque(),
		Subject: Subject{
			TenantID: subject.TenantID, SandboxID: subject.SandboxID,
			BrowserSessionID: subject.BrowserSessionID, CapabilityProfileID: subject.CapabilityProfileID,
			ConnectionGeneration: subject.ConnectionGeneration,
			ExpiresAt:            subject.ExpiresAt.UTC().Format(time.RFC3339Nano),
		},
	}
	if _, _, _, err := activation.Values(); err != nil {
		return Activation{}, err
	}
	return activation, nil
}

// Values validates and reconstructs the domain values without including any
// private value in a returned error.
func (a Activation) Values() (string, gateway.DownstreamFenceSubject, gateway.DownstreamFence, error) {
	if a.Version != ProtocolVersion {
		return "", gateway.DownstreamFenceSubject{}, gateway.DownstreamFence{}, ErrInvalidMessage
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, a.Subject.ExpiresAt)
	if err != nil || expiresAt.IsZero() || expiresAt.UTC().Format(time.RFC3339Nano) != a.Subject.ExpiresAt {
		return "", gateway.DownstreamFenceSubject{}, gateway.DownstreamFence{}, ErrInvalidMessage
	}
	subject := gateway.DownstreamFenceSubject{
		TenantID: a.Subject.TenantID, SandboxID: a.Subject.SandboxID,
		BrowserSessionID: a.Subject.BrowserSessionID, CapabilityProfileID: a.Subject.CapabilityProfileID,
		ConnectionGeneration: a.Subject.ConnectionGeneration, ExpiresAt: expiresAt.UTC(),
	}
	if err := subject.Validate(); err != nil {
		return "", gateway.DownstreamFenceSubject{}, gateway.DownstreamFence{}, ErrInvalidMessage
	}
	fence, err := gateway.NewDownstreamFence(a.Fence)
	if err != nil || !validReference(a.HandoffReference) {
		return "", gateway.DownstreamFenceSubject{}, gateway.DownstreamFence{}, ErrInvalidMessage
	}
	return a.HandoffReference, subject, fence, nil
}

func EncodeActivation(activation Activation) ([]byte, error) {
	if _, _, _, err := activation.Values(); err != nil {
		return nil, ErrInvalidMessage
	}
	encoded, err := json.Marshal(activation)
	if err != nil || len(encoded) > MaxResolutionBytes {
		return nil, ErrInvalidMessage
	}
	return encoded, nil
}

func DecodeActivation(encoded []byte) (Activation, error) {
	if len(encoded) == 0 || len(encoded) > MaxResolutionBytes || !uniqueJSONFields(encoded) {
		return Activation{}, ErrInvalidMessage
	}
	var activation Activation
	if err := decodeStrict(encoded, &activation); err != nil {
		return Activation{}, ErrInvalidMessage
	}
	if _, _, _, err := activation.Values(); err != nil {
		return Activation{}, ErrInvalidMessage
	}
	return activation, nil
}

func EncodeResponse(response ActivationResponse) ([]byte, error) {
	if !validResponse(response) {
		return nil, ErrInvalidMessage
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > MaxActivationBytes {
		return nil, ErrInvalidMessage
	}
	return encoded, nil
}

func DecodeResponse(encoded []byte) (ActivationResponse, error) {
	if len(encoded) == 0 || len(encoded) > MaxActivationBytes || !uniqueJSONFields(encoded) {
		return ActivationResponse{}, ErrInvalidMessage
	}
	var response ActivationResponse
	if err := decodeStrict(encoded, &response); err != nil || !validResponse(response) {
		return ActivationResponse{}, ErrInvalidMessage
	}
	return response, nil
}

func EncodeResolution(response ResolutionResponse) ([]byte, error) {
	if !validResolution(response) {
		return nil, ErrInvalidMessage
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > MaxActivationBytes {
		return nil, ErrInvalidMessage
	}
	return encoded, nil
}

func DecodeResolution(encoded []byte) (ResolutionResponse, error) {
	if len(encoded) == 0 || len(encoded) > MaxActivationBytes || !uniqueJSONFields(encoded) {
		return ResolutionResponse{}, ErrInvalidMessage
	}
	var response ResolutionResponse
	if err := decodeStrict(encoded, &response); err != nil || !validResolution(response) {
		return ResolutionResponse{}, ErrInvalidMessage
	}
	return response, nil
}

func validResolution(response ResolutionResponse) bool {
	if response.Version != ProtocolVersion {
		return false
	}
	switch response.Status {
	case StatusReady:
		return response.ErrorCode == "" && response.Endpoint != nil && validEndpoint(*response.Endpoint)
	case StatusRejected:
		return response.Endpoint == nil && (response.ErrorCode == ErrorInvalidActivation ||
			response.ErrorCode == ErrorUnavailable || response.ErrorCode == ErrorFenceLost)
	default:
		return false
	}
}

func validEndpoint(endpoint EndpointMetadata) bool {
	expiresAt, err := time.Parse(time.RFC3339Nano, endpoint.ExpiresAt)
	if err != nil || expiresAt.IsZero() || expiresAt.UTC().Format(time.RFC3339Nano) != endpoint.ExpiresAt ||
		!validReference(endpoint.Reference) {
		return false
	}
	subject := gateway.DownstreamFenceSubject{
		TenantID: "transport", SandboxID: endpoint.SandboxID, BrowserSessionID: endpoint.BrowserSessionID,
		CapabilityProfileID: endpoint.CapabilityProfileID, ConnectionGeneration: endpoint.ConnectionGeneration,
		ExpiresAt: expiresAt.UTC(),
	}
	return subject.Validate() == nil
}

func validResponse(response ActivationResponse) bool {
	if response.Version != ProtocolVersion {
		return false
	}
	switch response.Status {
	case StatusReady:
		return response.ErrorCode == ""
	case StatusRejected:
		return response.ErrorCode == ErrorInvalidActivation || response.ErrorCode == ErrorUnavailable ||
			response.ErrorCode == ErrorFenceLost
	default:
		return false
	}
}

func validReference(value string) bool {
	const prefix = "ref:browser-session:"
	if len(value) <= len(prefix) || len(value) > 220 || !bytes.HasPrefix([]byte(value), []byte(prefix)) {
		return false
	}
	for index := len(prefix); index < len(value); index++ {
		character := value[index]
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func decodeStrict(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidMessage
	}
	return nil
}

func uniqueJSONFields(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if !uniqueJSONValue(decoder) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func uniqueJSONValue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return false
			}
			if _, exists := seen[key]; exists {
				return false
			}
			seen[key] = struct{}{}
			if !uniqueJSONValue(decoder) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !uniqueJSONValue(decoder) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	default:
		return false
	}
}
