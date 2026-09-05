package wire

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestActivationRoundTrip(t *testing.T) {
	expiresAt := time.Date(2026, 9, 5, 12, 30, 0, 123, time.UTC)
	subject := gateway.DownstreamFenceSubject{
		TenantID: "tenant-1", SandboxID: "sandbox-1", BrowserSessionID: "browser-1",
		CapabilityProfileID: "browser-v1", ConnectionGeneration: 4, ExpiresAt: expiresAt,
	}
	fence, err := gateway.NewDownstreamFence("v1.opaque_claim")
	if err != nil {
		t.Fatal(err)
	}
	activation, err := NewActivation("ref:browser-session:opaque-1", subject, fence)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeActivation(activation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeActivation(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reference, gotSubject, gotFence, err := decoded.Values()
	if err != nil {
		t.Fatal(err)
	}
	if reference != "ref:browser-session:opaque-1" || gotSubject != subject || gotFence.Opaque() != fence.Opaque() {
		t.Fatalf("decoded activation binding mismatch")
	}
}

func TestResolutionRequestCarriesOnlyReference(t *testing.T) {
	request, err := NewResolutionRequest("ref:browser-session:opaque-1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeResolutionRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "fence") || strings.Contains(string(encoded), "subject") {
		t.Fatalf("resolution request contains activation-only material")
	}
	decoded, err := DecodeResolutionRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := decoded.Values()
	if err != nil || reference != request.HandoffReference {
		t.Fatalf("resolution request = %q, %v", reference, err)
	}

	for name, invalid := range map[string]string{
		"unknown field":     `{"version":1,"handoff_reference":"ref:browser-session:opaque-1","fence":"v1.secret"}`,
		"duplicate field":   `{"version":1,"version":1,"handoff_reference":"ref:browser-session:opaque-1"}`,
		"trailing document": string(encoded) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeResolutionRequest([]byte(invalid)); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("DecodeResolutionRequest() error = %v", err)
			}
		})
	}
}

func TestActivationRejectsNonCanonicalDocuments(t *testing.T) {
	valid := `{"version":1,"handoff_reference":"ref:browser-session:opaque-1","subject":{"tenant_id":"tenant-1","sandbox_id":"sandbox-1","browser_session_id":"browser-1","capability_profile_id":"browser-v1","connection_generation":4,"expires_at":"2026-09-05T12:30:00Z"},"fence":"v1.opaque_claim"}`
	tests := map[string]string{
		"unknown field":     strings.Replace(valid, `"version":1`, `"version":1,"extra":true`, 1),
		"duplicate field":   strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"trailing document": valid + `{}`,
		"wrong version":     strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"noncanonical time": strings.Replace(valid, `2026-09-05T12:30:00Z`, `2026-09-05T12:30:00+00:00`, 1),
		"invalid reference": strings.Replace(valid, `ref:browser-session:opaque-1`, `https://secret.invalid/opaque`, 1),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeActivation([]byte(encoded)); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("DecodeActivation() error = %v", err)
			}
		})
	}
	oversized := make([]byte, MaxActivationBytes+1)
	if _, err := DecodeActivation(oversized); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("oversized DecodeActivation() error = %v", err)
	}
}

func TestWireErrorsDoNotExposePrivateValues(t *testing.T) {
	private := "v1.secret_claim"
	_, err := DecodeActivation([]byte(`{"version":1,"fence":"` + private + `"}`))
	if !errors.Is(err, ErrInvalidMessage) || strings.Contains(err.Error(), private) {
		t.Fatalf("DecodeActivation() error = %q", err)
	}
}

func TestActivationResponseStrictRoundTrip(t *testing.T) {
	for _, response := range []ActivationResponse{
		{Version: ProtocolVersion, Status: StatusReady},
		{Version: ProtocolVersion, Status: StatusRejected, ErrorCode: ErrorUnavailable},
	} {
		encoded, err := EncodeResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeResponse(encoded)
		if err != nil || decoded != response {
			t.Fatalf("DecodeResponse() = %#v, %v", decoded, err)
		}
	}
	if _, err := DecodeResponse([]byte(`{"version":1,"status":"ready","unknown":true}`)); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unknown response field error = %v", err)
	}
}

func TestResolutionResponseStrictRoundTrip(t *testing.T) {
	response := ResolutionResponse{
		Version: ProtocolVersion, Status: StatusReady,
		Endpoint: &EndpointMetadata{
			Reference: "ref:browser-session:opaque-1", SandboxID: "sandbox-1",
			BrowserSessionID: "browser-1", CapabilityProfileID: "browser-v1",
			ConnectionGeneration: 4, ExpiresAt: "2026-09-05T12:30:00Z",
		},
	}
	encoded, err := EncodeResolution(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResolution(encoded)
	if err != nil || decoded.Endpoint == nil || *decoded.Endpoint != *response.Endpoint {
		t.Fatalf("DecodeResolution() = %#v, %v", decoded, err)
	}
	if _, err := DecodeResolution([]byte(`{"version":1,"status":"ready","endpoint":null}`)); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("nil endpoint error = %v", err)
	}
}
