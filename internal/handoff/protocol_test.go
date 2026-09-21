package handoff

import (
	"strings"
	"testing"
	"time"
)

func validOpen(now time.Time) OpenRequest {
	return OpenRequest{
		Protocol: ProtocolID, RequestID: "request-1", Resource: ResourceTerminal,
		TenantID: "tenant-1", SandboxID: "sandbox-1", RuntimeSessionID: "session-1",
		CapabilityProfileID: "terminal-v1", HandoffReference: "ref:session:opaque",
		ConnectionGeneration: 3, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Fence: strings.Repeat("a", MinFenceBytes), TenantBindingDigest: TenantBindingDigestPrefix + strings.Repeat("b", 64),
	}
}

func TestOpenRequestValidationBindsAllAuthorityFields(t *testing.T) {
	now := time.Now().UTC()
	if err := validOpen(now).Validate(now); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*OpenRequest){
		"unknown protocol": func(r *OpenRequest) { r.Protocol = "other" },
		"empty tenant":     func(r *OpenRequest) { r.TenantID = "" },
		"raw endpoint":     func(r *OpenRequest) { r.HandoffReference = "wss://10.0.0.1" },
		"zero generation":  func(r *OpenRequest) { r.ConnectionGeneration = 0 },
		"short fence":      func(r *OpenRequest) { r.Fence = "short" },
		"expired":          func(r *OpenRequest) { r.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validOpen(now)
			mutate(&request)
			if err := request.Validate(now); err == nil {
				t.Fatal("invalid handoff was accepted")
			}
		})
	}
}

func TestCodecRejectsUnknownTrailingAndOversizedDocuments(t *testing.T) {
	for name, document := range map[string][]byte{
		"unknown":   []byte(`{"protocol":"sandbox-runtime.handoff.v1","request_id":"x","status":"accepted","extra":true}`),
		"trailing":  []byte(`{"protocol":"sandbox-runtime.handoff.v1","request_id":"x","status":"accepted"}{}`),
		"oversized": []byte(strings.Repeat("x", MaxDocumentBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			var response OpenResponse
			if err := Decode(document, &response); err == nil {
				t.Fatal("invalid handoff document was accepted")
			}
		})
	}
}

func TestResponseValidationIsClosedAndGeneric(t *testing.T) {
	accepted := AcceptedResponse("request-1")
	document, err := Encode(accepted)
	if err != nil {
		t.Fatal(err)
	}
	var decoded OpenResponse
	if err := Decode(document, &decoded); err != nil || decoded.Validate() != nil {
		t.Fatalf("accepted response=%#v err=%v", decoded, err)
	}
	if response := RejectResponse("request-1", "private_failure"); response.Validate() != nil || response.ErrorCode != "private_failure" {
		t.Fatalf("rejection response=%#v", response)
	}
}
