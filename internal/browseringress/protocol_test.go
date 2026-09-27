package browseringress

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func testOpen(now time.Time) Open {
	return Open{
		Protocol: ProtocolID, RequestID: "ingress-request-1", CapacityClaim: "v1.opaque-capacity-claim",
		TenantID: "tenant-1", SandboxID: "sandbox-1", BrowserSessionID: "browser-1",
		CapabilityProfileID: "browser-v1", ConnectionGeneration: 2,
		AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		HandoffReference:   "ref:browser-session:" + strings.Repeat("a", 32),
		HandoffExpiresAt:   now.Add(2 * time.Minute).Format(time.RFC3339Nano),
		ProviderAudience:   "browser-provider-1", ProviderRevisionID: "revision-1", TenantBindingDigest: browserbinding.Prefix + strings.Repeat("b", 64),
		GrantConnectionID: "connection-1", ControlLeaseDigest: "sha256:" + strings.Repeat("c", 64),
		ControlFence: 7,
	}
}

func TestOpenClosedCanonicalProjection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	open := testOpen(now)
	document, err := handoff.Encode(open)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOpen(document, now)
	if err != nil || decoded != open {
		t.Fatalf("canonical decode: %+v, %v", decoded, err)
	}
	subject, fence, err := decoded.Subject(now)
	if err != nil || subject.TenantID != open.TenantID || subject.BrowserSessionID != open.BrowserSessionID ||
		subject.ConnectionGeneration != open.ConnectionGeneration || fence.Opaque() != open.CapacityClaim {
		t.Fatalf("exact capacity projection: %+v, %v", subject, err)
	}
	for name, mutate := range map[string]func(*Open){
		"claim":             func(o *Open) { o.CapacityClaim = "wrong" },
		"tenant digest":     func(o *Open) { o.TenantBindingDigest = "sha256:" + strings.Repeat("b", 64) },
		"reference":         func(o *Open) { o.HandoffReference = "ref:browser-session:guess" },
		"audience":          func(o *Open) { o.ProviderAudience = "" },
		"generation":        func(o *Open) { o.ConnectionGeneration = 0 },
		"grant":             func(o *Open) { o.GrantConnectionID = "" },
		"control digest":    func(o *Open) { o.ControlLeaseDigest = "" },
		"control fence":     func(o *Open) { o.ControlFence = 0 },
		"expiry order":      func(o *Open) { o.HandoffExpiresAt = now.Add(30 * time.Second).Format(time.RFC3339Nano) },
		"expired authority": func(o *Open) { o.AuthorityExpiresAt = now.Format(time.RFC3339Nano) },
		"noncanonical time": func(o *Open) { o.AuthorityExpiresAt = now.Add(time.Minute).Format(time.RFC3339) + ".000Z" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := open
			mutate(&bad)
			document, err := handoff.Encode(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeOpen(document, now); err == nil {
				t.Fatal("invalid private projection accepted")
			}
		})
	}
}

func TestOpenRejectsUnknownDuplicateOmittedAndNoncanonicalJSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	document, err := handoff.Encode(testOpen(now))
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(document, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "control_fence")
	omitted, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"unknown":       bytes.Replace(document, []byte(`{"protocol":`), []byte(`{"unknown":true,"protocol":`), 1),
		"duplicate":     bytes.Replace(document, []byte(`{"protocol":`), []byte(`{"protocol":"wrong","protocol":`), 1),
		"omitted":       omitted,
		"reordered":     append([]byte(" "), document...),
		"trailing data": append(append([]byte(nil), document...), []byte(" {}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeOpen(candidate, now); err == nil {
				t.Fatal("noncanonical or incomplete private Open accepted")
			}
		})
	}
}

func TestResponseRequiresCanonicalClosedDocument(t *testing.T) {
	accepted := AcceptedResponse("request-1")
	document, err := handoff.Encode(accepted)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeResponse(document); err != nil || decoded != accepted {
		t.Fatalf("canonical response: %+v, %v", decoded, err)
	}
	for _, malformed := range [][]byte{
		append([]byte(" "), document...),
		[]byte(`{"protocol":"sandbox-runtime.browser-action-ingress.v2","request_id":"request-1","status":"accepted","error_code":""}`),
		[]byte(`{"protocol":"sandbox-runtime.browser-action-ingress.v2","request_id":"request-1","status":"accepted","unknown":true}`),
	} {
		if _, err := DecodeResponse(malformed); err == nil {
			t.Fatalf("noncanonical response accepted: %s", malformed)
		}
	}
}
