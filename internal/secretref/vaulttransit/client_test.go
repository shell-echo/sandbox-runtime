package vaulttransit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type tokenProvider struct {
	binding secretref.Binding
	now     time.Time
	token   string
	err     error
	calls   int
	last    []byte
}

func (p *tokenProvider) ResolveSecret(context.Context, secretref.Binding) (secretref.SecretMaterial, error) {
	p.calls++
	p.last = []byte(p.token)
	digest := sha256.Sum256(p.last)
	return secretref.SecretMaterial{
		Binding: p.binding,
		Bytes:   p.last,
		Digest:  "sha256:" + hex.EncodeToString(digest[:]),
		Window: secretref.RotationWindow{
			NotBefore: p.now.Add(-time.Minute),
			NotAfter:  p.now.Add(time.Hour),
			State:     secretref.KeyActive,
		},
		Revision: "token-revision-1",
	}, p.err
}

func testTokenBinding() secretref.Binding {
	return secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/product/transit-token", Version: "v1",
		Purpose: secretref.PurposeWorkloadCredential, TenantID: secretref.SystemTenant,
		Role: secretref.RoleProduct,
	}
}

func testRecordingBinding(version string) secretref.Binding {
	return secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindEnvelopeKey,
		Reference: "kms://vault/transit/recording-primary", Version: version,
		KeyID: "recording-primary", Purpose: secretref.PurposeRecordingEnvelopeKey,
		TenantID: "tenant-a", Role: secretref.RoleProduct,
	}
}

type transitServer struct {
	mu          sync.Mutex
	values      map[string]transitValue
	encrypts    int
	decrypts    int
	lastVersion int
}

type transitValue struct {
	plaintext []byte
	aad       []byte
}

func (s *transitServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	if request.Method != http.MethodPost || request.Header.Get("X-Vault-Token") != "scoped-token" || request.Header.Get("Content-Type") != "application/json" {
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(`{"errors":["denied"]}`))
		return
	}
	switch request.URL.Path {
	case "/v1/transit/encrypt/recording-primary":
		var payload encryptRequest
		if json.NewDecoder(request.Body).Decode(&payload) != nil || len(payload.Plaintext) == 0 || len(payload.AssociatedData) == 0 || payload.KeyVersion < 1 {
			response.WriteHeader(http.StatusBadRequest)
			_, _ = response.Write([]byte(`{"errors":["invalid"]}`))
			return
		}
		digest := sha256.Sum256(append(append([]byte(nil), payload.Plaintext...), payload.AssociatedData...))
		ciphertext := "vault:v" + string(rune('0'+payload.KeyVersion)) + ":" + base64.StdEncoding.EncodeToString(digest[:])
		s.mu.Lock()
		if s.values == nil {
			s.values = make(map[string]transitValue)
		}
		s.values[ciphertext] = transitValue{plaintext: append([]byte(nil), payload.Plaintext...), aad: append([]byte(nil), payload.AssociatedData...)}
		s.encrypts++
		s.lastVersion = payload.KeyVersion
		s.mu.Unlock()
		_ = json.NewEncoder(response).Encode(map[string]any{
			"request_id": "request-1", "lease_id": "", "renewable": false,
			"lease_duration": 0, "data": map[string]any{"ciphertext": ciphertext},
			"wrap_info": nil, "warnings": nil, "auth": nil, "mount_type": "transit",
		})
	case "/v1/transit/decrypt/recording-primary":
		var payload decryptRequest
		if json.NewDecoder(request.Body).Decode(&payload) != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		value, ok := s.values[payload.Ciphertext]
		if ok && !strings.EqualFold(base64.StdEncoding.EncodeToString(value.aad), base64.StdEncoding.EncodeToString(payload.AssociatedData)) {
			ok = false
		}
		if ok {
			s.decrypts++
		}
		s.mu.Unlock()
		if !ok {
			response.WriteHeader(http.StatusBadRequest)
			_, _ = response.Write([]byte(`{"errors":["invalid ciphertext"]}`))
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"request_id": "request-2", "lease_id": "", "renewable": false,
			"lease_duration": 0, "data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(value.plaintext)},
			"wrap_info": nil, "warnings": nil, "auth": nil, "mount_type": "transit",
		})
	default:
		response.WriteHeader(http.StatusNotFound)
	}
}

func testClient(t *testing.T, server *httptest.Server, now time.Time, tokens *tokenProvider) *Client {
	t.Helper()
	client, err := New(Config{
		Endpoint: server.URL, Mount: "transit", ReferenceAuthority: "vault",
		OperationTimeout: time.Second, Now: func() time.Time { return now },
	}, server.Client(), tokens, tokens.binding)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestClientSealsAndOpensExactVersionWithAADAndClearsToken(t *testing.T) {
	now := time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)
	backend := &transitServer{}
	server := httptest.NewTLSServer(backend)
	defer server.Close()
	tokens := &tokenProvider{binding: testTokenBinding(), now: now, token: "scoped-token"}
	client := testClient(t, server, now, tokens)
	binding := testRecordingBinding("v1")
	aad := []byte("canonical recording binding")
	envelope, err := client.SealEnvelope(context.Background(), binding, []byte("data-key"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.BindingDigest != binding.Digest() || envelope.KeyID != binding.KeyID || envelope.KeyVersion != "v1" || !validCiphertext(string(envelope.Ciphertext), "v1") {
		t.Fatalf("envelope = %#v", envelope)
	}
	if !allZero(tokens.last) {
		t.Fatal("Vault token was not cleared after encrypt")
	}
	plaintext, err := client.OpenEnvelope(context.Background(), binding, envelope, aad)
	if err != nil || string(plaintext) != "data-key" {
		t.Fatalf("OpenEnvelope() = %q, %v", plaintext, err)
	}
	if !allZero(tokens.last) || tokens.calls != 2 || backend.encrypts != 1 || backend.decrypts != 1 || backend.lastVersion != 1 {
		t.Fatalf("calls/clear = token %d encrypt %d decrypt %d version %d", tokens.calls, backend.encrypts, backend.decrypts, backend.lastVersion)
	}
	if _, err := client.OpenEnvelope(context.Background(), binding, envelope, []byte("different aad")); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("AAD mismatch error = %v", err)
	}
}

func TestClientRejectsScopeVersionCancellationAndCredentialFailure(t *testing.T) {
	now := time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)
	backend := &transitServer{}
	server := httptest.NewTLSServer(backend)
	defer server.Close()
	tokens := &tokenProvider{binding: testTokenBinding(), now: now, token: "scoped-token"}
	client := testClient(t, server, now, tokens)
	binding := testRecordingBinding("v1")

	invalid := map[string]secretref.Binding{
		"reference": func() secretref.Binding {
			b := binding
			b.Reference = "kms://other/transit/recording-primary"
			return b
		}(),
		"purpose":      func() secretref.Binding { b := binding; b.Purpose = secretref.PurposeTicketEnvelopeKey; return b }(),
		"role":         func() secretref.Binding { b := binding; b.Role = secretref.RoleProvider; return b }(),
		"version":      func() secretref.Binding { b := binding; b.Version = "latest"; return b }(),
		"leading zero": func() secretref.Binding { b := binding; b.Version = "v01"; return b }(),
	}
	for name, candidate := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := client.SealEnvelope(context.Background(), candidate, []byte("key"), []byte("aad")); !errors.Is(err, secretref.ErrUnavailable) {
				t.Fatalf("SealEnvelope() error = %v", err)
			}
		})
	}
	if backend.encrypts != 0 || tokens.calls != 0 {
		t.Fatal("invalid binding reached token provider or Vault")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.SealEnvelope(ctx, binding, []byte("key"), []byte("aad")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled seal error = %v", err)
	}
	if tokens.calls != 0 {
		t.Fatal("cancelled request reached token provider")
	}

	tokens.err = errors.New("private credential backend details")
	if _, err := client.SealEnvelope(context.Background(), binding, []byte("key"), []byte("aad")); !errors.Is(err, secretref.ErrUnavailable) || strings.Contains(err.Error(), "credential") {
		t.Fatalf("credential error = %v", err)
	}
	if !allZero(tokens.last) {
		t.Fatal("credential returned with error was not cleared")
	}
}

func TestClientRejectsRedirectMalformedOversizedAndLeakyResponses(t *testing.T) {
	now := time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)
	binding := testRecordingBinding("v1")
	var redirected atomic.Int32
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer redirectTarget.Close()

	tests := map[string]http.HandlerFunc{
		"redirect": func(response http.ResponseWriter, request *http.Request) {
			http.Redirect(response, request, redirectTarget.URL, http.StatusTemporaryRedirect)
		},
		"wrong content type": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "text/plain")
			_, _ = response.Write([]byte(`{"data":{"ciphertext":"vault:v1:QQ=="}}`))
		},
		"unknown member": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"data":{"ciphertext":"vault:v1:QQ=="},"private_endpoint":"do-not-leak"}`))
		},
		"duplicate member": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"data":{"ciphertext":"vault:v1:QQ==","ciphertext":"vault:v1:Qg=="}}`))
		},
		"wrong version": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"data":{"ciphertext":"vault:v2:QQ=="}}`))
		},
		"oversized": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			tokens := &tokenProvider{binding: testTokenBinding(), now: now, token: "scoped-token"}
			client := testClient(t, server, now, tokens)
			if _, err := client.SealEnvelope(context.Background(), binding, []byte("key"), []byte("aad")); !errors.Is(err, secretref.ErrUnavailable) || strings.Contains(err.Error(), "endpoint") {
				t.Fatalf("SealEnvelope() error = %v", err)
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("Vault token-bearing request followed a redirect")
	}
}

func TestNewRequiresHTTPSClosedEndpointAndScopedProductToken(t *testing.T) {
	now := time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)
	tokens := &tokenProvider{binding: testTokenBinding(), now: now, token: "scoped-token"}
	httpClient := &http.Client{}
	base := Config{Endpoint: "https://vault.example", Mount: "transit", ReferenceAuthority: "vault", OperationTimeout: time.Second, Now: func() time.Time { return now }}
	invalid := map[string]Config{
		"plaintext":   func() Config { c := base; c.Endpoint = "http://vault.example"; return c }(),
		"credentials": func() Config { c := base; c.Endpoint = "https://user@vault.example"; return c }(),
		"path":        func() Config { c := base; c.Endpoint = "https://vault.example/api"; return c }(),
		"query":       func() Config { c := base; c.Endpoint = "https://vault.example?x=1"; return c }(),
		"mount":       func() Config { c := base; c.Mount = "Transit"; return c }(),
		"timeout":     func() Config { c := base; c.OperationTimeout = 0; return c }(),
	}
	for name, config := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := New(config, httpClient, tokens, tokens.binding); !errors.Is(err, secretref.ErrUnavailable) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
	wrongToken := tokens.binding
	wrongToken.TenantID = "tenant-a"
	if _, err := New(base, httpClient, tokens, wrongToken); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("wrong token scope error = %v", err)
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
