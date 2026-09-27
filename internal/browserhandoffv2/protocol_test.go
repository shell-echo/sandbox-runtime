package browserhandoffv2

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func testOpen(now time.Time) OpenRequest {
	open := OpenRequest{BindingVersion: BindingVersion, BindingIssuer: BindingIssuer, Protocol: ProtocolID,
		RequestID: "browser-request-1", Resource: ResourceBrowser,
		TenantBindingDigest: browserbinding.Prefix + strings.Repeat("a", 64),
		ProviderRevisionID:  "provider-revision-1", SandboxID: "sandbox-1", BrowserSessionID: "browser-1",
		CapabilityProfileID: "browser-v1", MediaProfileID: MediaProfileID, ControlProfileID: ControlProfileID,
		HandoffReference: "ref:browser-session:" + strings.Repeat("1", 32), ConnectionGeneration: 2,
		ConnectionEpoch: "connection-1", ControlLeaseDigest: "sha256:" + strings.Repeat("b", 64), ControlFence: 7,
		AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt:   now.Add(2 * time.Minute).Format(time.RFC3339Nano)}
	open.HandoffDigest = ReferenceDigest(open.HandoffReference)
	open.AuthorityDigest = AuthorityDigest(open)
	open.RequestDigest = RequestDigest(open)
	return open
}

func TestClosedBrowserHandoffV2CanonicalAndBound(t *testing.T) {
	now := time.Now().UTC()
	open := testOpen(now)
	if err := open.Validate(now); err != nil {
		t.Fatal(err)
	}
	document, err := handoff.Encode(open)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOpen(document, now)
	if err != nil || decoded != open {
		t.Fatalf("Browser v2 decode = %#v, %v", decoded, err)
	}
	for _, invalid := range [][]byte{
		append([]byte(" "), document...),
		bytes.Replace(document, []byte(`"request_id":"browser-request-1"`), []byte(`"request_id":"browser-request-1","request_id":"browser-request-2"`), 1),
		bytes.Replace(document, []byte(`"resource":"browser"`), []byte(`"resource":"browser","raw_endpoint":"ws://localhost"`), 1),
		bytes.Replace(document, []byte(`"binding_version":2`), []byte(`"binding_version":1`), 1),
	} {
		if _, err := DecodeOpen(invalid, now); err == nil {
			t.Fatalf("noncanonical Browser v2 document accepted: %s", invalid)
		}
	}
	for _, test := range []struct {
		name string
		edit func(*OpenRequest)
	}{
		{"old tenant digest", func(r *OpenRequest) { r.TenantBindingDigest = "sha256:v1:" + strings.Repeat("a", 64) }},
		{"other provider", func(r *OpenRequest) { r.ProviderRevisionID = "provider-revision-2" }},
		{"other handoff", func(r *OpenRequest) { r.HandoffReference = "ref:browser-session:" + strings.Repeat("2", 32) }},
		{"other epoch", func(r *OpenRequest) { r.ConnectionEpoch = "connection-2" }},
		{"generation overflow", func(r *OpenRequest) { r.ConnectionGeneration = MaxGeneration + 1 }},
		{"other control fence", func(r *OpenRequest) { r.ControlFence++ }},
		{"expired", func(r *OpenRequest) { r.AuthorityExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano) }},
		{"timezone", func(r *OpenRequest) {
			r.HandoffExpiresAt = now.Add(2 * time.Minute).In(time.FixedZone("east", 3600)).Format(time.RFC3339Nano)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := open
			test.edit(&changed)
			if err := changed.Validate(now); err == nil {
				t.Fatal("changed authority passed without a matching canonical digest/expiry")
			}
		})
	}
	// A matching digest must not make an alternate timezone representation
	// canonical. The wire uses UTC RFC3339Nano byte-for-byte.
	zoneShifted := open
	zoneShifted.HandoffExpiresAt = now.Add(2 * time.Minute).In(time.FixedZone("east", 3600)).Format(time.RFC3339Nano)
	zoneShifted.AuthorityDigest = AuthorityDigest(zoneShifted)
	zoneShifted.RequestDigest = RequestDigest(zoneShifted)
	if err := zoneShifted.Validate(now); err == nil {
		t.Fatal("noncanonical timezone accepted with matching digests")
	}
	if response := AcceptedResponse(open.RequestID); response.Validate() != nil {
		t.Fatal("accepted Browser v2 response is invalid")
	}
	if response := RejectResponse("bad request"); response.Validate() != nil || response.RequestID != "invalid" {
		t.Fatal("rejected Browser v2 response is invalid")
	}
}

func TestExecutorFenceBindsCompleteAuthorityNotAttemptID(t *testing.T) {
	now := time.Now().UTC()
	open := testOpen(now)
	fence, err := ExecutorFence(open.AuthorityDigest)
	if err != nil || len(fence) != 64 {
		t.Fatalf("executor fence=%q err=%v", fence, err)
	}
	if _, err := ExecutorFence("sha256:invalid"); err == nil {
		t.Fatal("malformed Browser authority admitted")
	}
	for _, change := range []func(*OpenRequest){
		func(r *OpenRequest) { r.TenantBindingDigest = browserbinding.Prefix + strings.Repeat("c", 64) },
		func(r *OpenRequest) { r.ProviderRevisionID = "provider-revision-2" },
		func(r *OpenRequest) {
			r.HandoffReference = "ref:browser-session:" + strings.Repeat("2", 32)
			r.HandoffDigest = ReferenceDigest(r.HandoffReference)
		},
		func(r *OpenRequest) { r.ConnectionGeneration++ },
		func(r *OpenRequest) { r.ConnectionEpoch = "connection-2" },
		func(r *OpenRequest) { r.ControlLeaseDigest = "sha256:" + strings.Repeat("c", 64) },
		func(r *OpenRequest) { r.ControlFence++ },
		func(r *OpenRequest) { r.AuthorityExpiresAt = now.Add(30 * time.Second).Format(time.RFC3339Nano) },
	} {
		changed := open
		change(&changed)
		changed.AuthorityDigest = AuthorityDigest(changed)
		other, err := ExecutorFence(changed.AuthorityDigest)
		if err != nil || other == fence {
			t.Fatal("Browser executor fence did not bind authority change")
		}
	}
	changed := open
	changed.RequestID = "browser-request-2"
	changed.RequestDigest = RequestDigest(changed)
	same, err := ExecutorFence(changed.AuthorityDigest)
	if err != nil || same != fence || changed.RequestDigest == open.RequestDigest {
		t.Fatal("attempt identity changed the authority fence or failed to change request digest")
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
		[]byte(`{"protocol":"sandbox-runtime.browser-handoff.v2","request_id":"request-1","status":"accepted","error_code":""}`),
		[]byte(`{"protocol":"sandbox-runtime.browser-handoff.v2","request_id":"request-1","status":"accepted","unknown":true}`),
	} {
		if _, err := DecodeResponse(malformed); err == nil {
			t.Fatalf("noncanonical response accepted: %s", malformed)
		}
	}
}
