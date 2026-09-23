package workloadpki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type staticVaultTokenSource struct {
	token VaultToken
	err   error
}

func (s staticVaultTokenSource) Token(context.Context) (VaultToken, error) {
	return VaultToken{Value: append([]byte(nil), s.token.Value...), ExpiresAt: s.token.ExpiresAt, Revision: s.token.Revision}, s.err
}

func TestVaultClientIssuesRevokesAndLoadsFreshCRL(t *testing.T) {
	fixture := newProtocolFixture(t)
	var mu sync.Mutex
	issueCalls, crlCalls, crlConfigCalls, revokeCalls := 0, 0, 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Header.Get("X-Vault-Token") != "scoped-pki-token" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case "/v1/pki/config/crl":
			crlConfigCalls++
			if request.Method != http.MethodGet || request.Header.Get("Accept") != "application/json" {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(vaultData(map[string]any{"disable": false, "auto_rebuild": false, "enable_delta": false}))
		case "/v1/pki/sign/product-runtime":
			issueCalls++
			if request.Method != http.MethodPost || request.Header.Get("Accept") != "application/json" || request.Header.Get("Content-Type") != "application/json" {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			var body struct {
				CSR                  string `json:"csr"`
				TTL                  string `json:"ttl"`
				Format               string `json:"format"`
				RemoveRootsFromChain bool   `json:"remove_roots_from_chain"`
				ExcludeCNFromSANs    bool   `json:"exclude_cn_from_sans"`
			}
			decoder := json.NewDecoder(request.Body)
			decoder.DisallowUnknownFields()
			if decoder.Decode(&body) != nil || body.CSR != string(fixture.csr) || body.TTL != "600s" || body.Format != "pem" || body.RemoveRootsFromChain || !body.ExcludeCNFromSANs {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			certificateBlock, _ := pemDecodeCertificate(t, fixture.certificate)
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(vaultData(map[string]any{
				"authority_key_id": fixture.serial, "ca_chain": []string{string(fixture.ca)}, "certificate": string(fixture.certificate), "expiration": certificateBlock.NotAfter.Unix(),
				"issuing_ca": string(fixture.ca), "private_key": "", "private_key_type": "", "serial_number": fixture.serial,
			}))
		case "/v1/pki/crl":
			crlCalls++
			if request.Method != http.MethodGet || request.Header.Get("Accept") != "application/pkix-crl" {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			response.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = response.Write(fixture.crl)
		case "/v1/pki/revoke":
			revokeCalls++
			var body struct {
				Serial string `json:"serial_number"`
			}
			decoder := json.NewDecoder(request.Body)
			decoder.DisallowUnknownFields()
			if request.Method != http.MethodPost || decoder.Decode(&body) != nil || body.Serial != fixture.serial {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(vaultData(map[string]any{
				"revocation_time": fixture.now.Unix(), "revocation_time_rfc3339": fixture.now.Format(time.RFC3339Nano), "state": "revoked",
			}))
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewVaultClient(VaultConfig{Endpoint: server.URL, Mount: "pki", AllowedPolicies: map[string]string{fixture.policy.ID: fixture.policy.VaultRole},
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return fixture.now }, RequireImmediateCompleteCRL: true}, server.Client(),
		staticVaultTokenSource{token: VaultToken{Value: []byte("scoped-pki-token"), ExpiresAt: fixture.now.Add(time.Minute), Revision: "vault-token-1"}})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := client.Issue(context.Background(), fixture.policy, fixture.csr, 10*time.Minute)
	if err != nil || issued.Serial != fixture.serial || !issued.NotAfter.Equal(fixture.notAfter) || issued.IssuerRevision == "" {
		t.Fatalf("Issue() = %#v, %v", issued, err)
	}
	defer issued.Destroy()
	snapshot, err := client.Revocations(context.Background())
	if err != nil || !snapshot.ThisUpdate.Equal(fixture.crlThis) || !snapshot.NextUpdate.Equal(fixture.crlNext) || snapshot.IssuerRevision == "" {
		t.Fatalf("Revocations() = %#v, %v", snapshot, err)
	}
	defer snapshot.Destroy()
	if err := client.Revoke(context.Background(), fixture.serial); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if issueCalls != 1 || crlCalls != 1 || crlConfigCalls != 1 || revokeCalls != 1 {
		t.Fatalf("Vault calls issue=%d crl=%d config=%d revoke=%d", issueCalls, crlCalls, crlConfigCalls, revokeCalls)
	}
}

func TestVaultImmediateCompleteCRLConfigFailsClosed(t *testing.T) {
	fixture := newProtocolFixture(t)
	for name, payload := range map[string]string{
		"disabled":      `{"disable":true,"auto_rebuild":false,"enable_delta":false}`,
		"auto rebuild":  `{"disable":false,"auto_rebuild":true,"enable_delta":false}`,
		"delta":         `{"disable":false,"auto_rebuild":false,"enable_delta":true}`,
		"missing field": `{"disable":false,"auto_rebuild":false}`,
		"wrong type":    `{"disable":false,"auto_rebuild":"false","enable_delta":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			var crlCalls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/v1/pki/config/crl":
					response.Header().Set("Content-Type", "application/json")
					_, _ = response.Write([]byte(`{"data":` + payload + `}`))
				case "/v1/pki/crl":
					crlCalls.Add(1)
					response.Header().Set("Content-Type", "application/pkix-crl")
					_, _ = response.Write(fixture.crl)
				default:
					response.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			client, err := NewVaultClient(VaultConfig{Endpoint: server.URL, Mount: "pki",
				AllowedPolicies:  map[string]string{fixture.policy.ID: fixture.policy.VaultRole},
				OperationTimeout: time.Second, Now: func() time.Time { return fixture.now }, RequireImmediateCompleteCRL: true},
				server.Client(), staticVaultTokenSource{token: VaultToken{Value: []byte("scoped-pki-token"),
					ExpiresAt: fixture.now.Add(time.Minute), Revision: "vault-token-1"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Revocations(context.Background()); err == nil || crlCalls.Load() != 0 {
				t.Fatalf("unsafe Vault CRL policy admitted or CRL fetched: err=%v calls=%d", err, crlCalls.Load())
			}
		})
	}
}

func TestVaultClientFailsClosedOnExpiredTokenRedirectAndMalformedResponse(t *testing.T) {
	fixture := newProtocolFixture(t)
	tests := map[string]struct {
		handler http.HandlerFunc
		token   VaultToken
	}{
		"expired token": {
			handler: func(response http.ResponseWriter, request *http.Request) {
				t.Fatal("Vault must not be called with an expired token")
			},
			token: VaultToken{Value: []byte("scoped-pki-token"), ExpiresAt: fixture.now, Revision: "vault-token-1"},
		},
		"redirect": {
			handler: func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Location", "/v1/pki/sign/product-runtime")
				response.WriteHeader(http.StatusTemporaryRedirect)
			},
			token: VaultToken{Value: []byte("scoped-pki-token"), ExpiresAt: fixture.now.Add(time.Minute), Revision: "vault-token-1"},
		},
		"unknown response": {
			handler: func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(`{"request_id":"request-1","lease_id":"","renewable":false,"lease_duration":0,"data":{"unknown":true},"wrap_info":null,"warnings":null,"auth":null,"mount_type":"pki"}`))
			},
			token: VaultToken{Value: []byte("scoped-pki-token"), ExpiresAt: fixture.now.Add(time.Minute), Revision: "vault-token-1"},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			defer server.Close()
			client, err := NewVaultClient(VaultConfig{Endpoint: server.URL, Mount: "pki", AllowedPolicies: map[string]string{fixture.policy.ID: fixture.policy.VaultRole},
				OperationTimeout: 3 * time.Second, Now: func() time.Time { return fixture.now }}, server.Client(), staticVaultTokenSource{token: test.token})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Issue(context.Background(), fixture.policy, fixture.csr, 10*time.Minute); err == nil {
				t.Fatal("unsafe Vault response was accepted")
			}
		})
	}
}

func TestVaultPeerIssuerSourceIsFixedAndNeverFallsBackToDefault(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	material := newCRLTestMaterial(t, now, 83, true)
	other := newCRLTestMaterial(t, now, 83, false)
	issuerHash := sha256.Sum256(material.issuerDER)
	issuerDigest := "sha256:" + hex.EncodeToString(issuerHash[:])
	const issuerID = "3d24b01e-81e2-42ac-a6d6-6203166d15ad"
	var defaultCalls atomic.Int32
	var wrongIssuer, wrongCRL, missingIssuer atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/pki/config/crl":
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(vaultData(map[string]any{"disable": false, "auto_rebuild": false, "enable_delta": false}))
		case "/v1/pki/issuer/" + issuerID + "/der":
			if missingIssuer.Load() {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			response.Header().Set("Content-Type", "application/pkix-cert")
			if wrongIssuer.Load() {
				_, _ = response.Write(other.issuerDER)
			} else {
				_, _ = response.Write(material.issuerDER)
			}
		case "/v1/pki/issuer/" + issuerID + "/crl/der":
			response.Header().Set("Content-Type", "application/pkix-crl")
			if wrongCRL.Load() {
				_, _ = response.Write(other.snapshot.DER)
			} else {
				_, _ = response.Write(material.snapshot.DER)
			}
		case "/v1/pki/crl":
			defaultCalls.Add(1)
			response.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = response.Write(other.snapshot.DER)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	fixture := newProtocolFixture(t)
	base := VaultConfig{Endpoint: server.URL, Mount: "pki", AllowedPolicies: map[string]string{fixture.policy.ID: fixture.policy.VaultRole},
		OperationTimeout: time.Second, Now: func() time.Time { return now }, RequireImmediateCompleteCRL: true,
		PeerIssuerSources: []VaultPeerIssuerSource{{SourceID: "peer-source", Mount: "pki", IssuerID: issuerID, IssuerDigest: issuerDigest}}}
	token := staticVaultTokenSource{token: VaultToken{Value: []byte("scoped-pki-token"), ExpiresAt: now.Add(time.Minute), Revision: "vault-token-1"}}
	client, err := NewVaultClient(base, server.Client(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ValidatePeerSources([]phase6security.PeerCRLSource{{ID: "peer-source", Mount: "pki",
		IssuerID: issuerID, IssuerDigest: issuerDigest}}); err != nil {
		t.Fatalf("fixed source mapping rejected: %v", err)
	}
	if err := client.ValidatePeerSources([]phase6security.PeerCRLSource{{ID: "peer-source", Mount: "other",
		IssuerID: issuerID, IssuerDigest: issuerDigest}}); err == nil {
		t.Fatal("controller/Vault mount drift accepted")
	}
	issuerDER, err := client.PeerIssuerCertificate(context.Background(), "peer-source")
	if err != nil || !bytes.Equal(issuerDER, material.issuerDER) {
		t.Fatalf("fixed issuer certificate read = %v", err)
	}
	clear(issuerDER)
	snapshot, err := client.PeerRevocations(context.Background(), "peer-source", material.issuerDER)
	if err != nil {
		t.Fatalf("fixed issuer read failed: %v", err)
	}
	verified, err := VerifyCRLForIssuer(snapshot, material.issuerDER, now)
	snapshot.Destroy()
	if err != nil || verified.CheckPeer(material.leafDER, material.issuerDER, now) != ErrPeerRevoked {
		t.Fatalf("fixed issuer revocation was not enforced: %v", err)
	}
	if _, err := client.PeerRevocations(context.Background(), "unknown", material.issuerDER); err == nil {
		t.Fatal("unknown source accepted")
	}
	if _, err := client.PeerRevocations(context.Background(), "peer-source", other.issuerDER); err == nil {
		t.Fatal("wrong issuer DER accepted")
	}
	if defaultCalls.Load() != 0 {
		t.Fatal("peer source fell back to default CRL")
	}
	for name, flag := range map[string]*atomic.Bool{
		"issuer mapping drift": &wrongIssuer, "wrong signed CRL": &wrongCRL, "source disappeared": &missingIssuer,
	} {
		t.Run(name, func(t *testing.T) {
			flag.Store(true)
			defer flag.Store(false)
			if _, err := client.PeerRevocations(context.Background(), "peer-source", material.issuerDER); err == nil || defaultCalls.Load() != 0 {
				t.Fatalf("unsafe source admitted or default fallback used: %v", err)
			}
		})
	}
	for name, invalidID := range map[string]string{
		"default alias": "default", "path injection": "../crl", "encoded slash": "%2f", "query": issuerID + "?x=1",
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			config.PeerIssuerSources = []VaultPeerIssuerSource{{SourceID: "peer-source", Mount: "pki", IssuerID: invalidID, IssuerDigest: issuerDigest}}
			if _, err := NewVaultClient(config, server.Client(), token); err == nil {
				t.Fatal("unsafe issuer reference accepted")
			}
		})
	}
	config := base
	config.RequireImmediateCompleteCRL = false
	if _, err := NewVaultClient(config, server.Client(), token); err == nil {
		t.Fatal("peer source admitted without complete-CRL policy gate")
	}
}

func vaultData(data any) map[string]any {
	return map[string]any{"request_id": "request-1", "lease_id": "", "renewable": false, "lease_duration": 0, "data": data,
		"wrap_info": nil, "warnings": nil, "auth": nil, "mount_type": "pki"}
}

func pemDecodeCertificate(t *testing.T, document []byte) (*x509.Certificate, []byte) {
	t.Helper()
	block, trailing := pem.Decode(document)
	if block == nil {
		t.Fatal("certificate PEM did not decode")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, trailing
}
