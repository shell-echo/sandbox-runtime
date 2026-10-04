package phase6terminalcleanup

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestVaultEvidenceV3ProjectsOnlyExistingFixedResponses(t *testing.T) {
	plan, expected := terminalV3SyntheticEvidence(t)
	now, err := time.Parse(time.RFC3339Nano, expected.CRLVerifiedUTC)
	if err != nil {
		t.Fatal(err)
	}
	collector := newVaultEvidenceV3Collector(plan, func() time.Time { return now })
	const canary = "secret-vault-response-canary"
	encode := func(value any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	lookupTarget := func(digest string) TokenTarget {
		for _, target := range plan.Tokens {
			if targetDigest("token", target.Accessor) == digest {
				return target
			}
		}
		t.Fatal("unknown token target")
		return TokenTarget{}
	}
	certificateTarget := func(digest string) CertificateTarget {
		for _, target := range plan.Certificates {
			kind := "certificate"
			if target.Kind == externalPostgresKind {
				kind = externalPostgresKind
			}
			if targetDigest(kind, target.Serial) == digest {
				return target
			}
		}
		t.Fatal("unknown certificate target")
		return CertificateTarget{}
	}
	for _, event := range expected.Events {
		method, path, media := http.MethodGet, "", event.MediaType
		var request, response []byte
		switch event.Kind {
		case "lookup-preflight", "lookup-post-revoke":
			target := lookupTarget(event.TargetDigest)
			method, path = http.MethodPost, "/v1/auth/token/lookup-accessor"
			request = encode(map[string]string{"accessor": target.Accessor})
			if event.Status == 400 {
				response = encode(map[string]any{"errors": []string{event.InvalidAccessorError}})
			} else {
				response = encode(map[string]any{"data": map[string]any{
					"accessor": target.Accessor, "policies": event.Token.Policies,
					"meta": event.Token.Metadata, "role": event.Token.Role,
					"type": event.Token.Type, "orphan": event.Token.Orphan,
					"renewable": event.Token.Renewable, "ttl": event.Token.TTLSeconds,
				}, "auth": map[string]string{"token": canary}})
			}
		case "certificate-revoke":
			target := certificateTarget(event.TargetDigest)
			method, path = http.MethodPost, "/v1/pki/revoke"
			request = encode(map[string]string{"serial_number": target.Serial})
			response = encode(map[string]any{"data": map[string]any{
				"revocation_time":         event.RevocationUnix,
				"revocation_time_rfc3339": event.RevocationRFC3339,
				"state":                   event.RevocationState,
			}, "auth": map[string]string{"token": canary}})
		case "issuer-read", "issuer-reread":
			path = "/v1/pki/issuer/" + plan.GeneralIssuerID + "/der"
			response = expected.IssuerDER
		case "crl-config":
			path = "/v1/pki/config/crl"
			response = encode(map[string]any{"data": map[string]any{
				"disable": false, "auto_rebuild": false, "enable_delta": false,
				"other_unrelated": canary}})
		case "crl-read":
			path = "/v1/pki/issuer/" + plan.GeneralIssuerID + "/crl/der"
			response = expected.CRLDER
		case "accessor-revoke":
			target := lookupTarget(event.TargetDigest)
			method, path = http.MethodPost, "/v1/auth/token/revoke-accessor"
			request = encode(map[string]string{"accessor": target.Accessor})
		case "self-revoke":
			method, path = http.MethodPost, "/v1/auth/token/revoke-self"
			request = []byte("{}")
		default:
			t.Fatal("unexpected synthetic operation")
		}
		collector.observe(t.Context(), method, path, request, event.Status, media, response)
	}
	remote := &VaultRemote{evidence: collector}
	actual, err := remote.PrivateEvidenceV3(expected.Receipt)
	if err != nil || VerifyEvidenceV3(plan, actual) != nil || len(actual.Events) != len(expected.Events) {
		t.Fatalf("actual-response projection did not replay: %v", err)
	}
	raw, err := json.Marshal(actual)
	if err != nil || bytes.Contains(raw, []byte(canary)) ||
		bytes.Contains(raw, []byte(plan.Tokens[0].Accessor)) ||
		bytes.Contains(raw, []byte(plan.Tokens[1].Accessor)) {
		t.Fatal("private projection copied a token/accessor/irrelevant Vault field")
	}
	collector.clear()
	if _, err := remote.PrivateEvidenceV3(expected.Receipt); err == nil {
		t.Fatal("closed collector still supplied evidence")
	}
}

func TestVaultEvidenceV3TransportReplaysOriginalResponseWithoutLogging(t *testing.T) {
	plan, _ := terminalV3SyntheticEvidence(t)
	now := time.Now().UTC()
	collector := newVaultEvidenceV3Collector(plan, func() time.Time { return now })
	const response = `{"errors":["invalid accessor"]}`
	transport := &vaultEvidenceV3Transport{collector: collector,
		next: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil || !bytes.Equal(body, []byte(`{"accessor":"accessor-management"}`)) {
				t.Fatal("operator transport changed exact request")
			}
			return &http.Response{StatusCode: 400,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   io.NopCloser(strings.NewReader(response))}, nil
		})}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://vault.sandbox-runtime.test:8200/v1/auth/token/lookup-accessor",
		strings.NewReader(`{"accessor":"accessor-management"}`))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	readback, err := io.ReadAll(observed.Body)
	closeErr := observed.Body.Close()
	if err != nil || string(readback) != response || closeErr != nil ||
		len(collector.events) != 1 || collector.events[0].InvalidAccessorError != "invalid accessor" {
		t.Fatalf("transport changed Vault response or projection: read=%q err=%v close=%v events=%+v failed=%v",
			readback, err, closeErr, collector.events, collector.failed)
	}
}

func TestVaultEvidenceV3RejectsUnexpectedNoContentBody(t *testing.T) {
	plan, _ := terminalV3SyntheticEvidence(t)
	collector := newVaultEvidenceV3Collector(plan, time.Now)
	collector.observe(t.Context(), http.MethodPost, "/v1/auth/token/revoke-accessor",
		[]byte(`{"accessor":"accessor-management"}`), http.StatusNoContent, "", []byte("unexpected"))
	if !collector.failed || len(collector.events) != 0 {
		t.Fatal("nonempty 204 response became revocation evidence")
	}
}

func TestVaultEvidenceV3TransportPreservesOversizedResponseForCleanup(t *testing.T) {
	plan, _ := terminalV3SyntheticEvidence(t)
	collector := newVaultEvidenceV3Collector(plan, time.Now)
	body := bytes.Repeat([]byte{'x'}, maxVaultReply+2)
	transport := &vaultEvidenceV3Transport{collector: collector,
		next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   io.NopCloser(bytes.NewReader(body))}, nil
		})}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://vault.sandbox-runtime.test:8200/v1/pki/config/crl", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	readback, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || !bytes.Equal(readback, body) || !collector.failed {
		t.Fatal("oversized projection was not rejected or changed the original response")
	}
}
