package vaultkv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type tokenProvider struct {
	material secretref.SecretMaterial
}

func (p tokenProvider) ResolveSecret(_ context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	if p.material.Binding != binding {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	material := p.material
	material.Bytes = append([]byte(nil), material.Bytes...)
	return material, nil
}

func TestClientResolvesExactVaultKVVersionAndScope(t *testing.T) {
	now := time.Now().UTC()
	binding := testBinding(secretref.PurposeTLSCertificate, secretref.RoleProduct, "v2")
	value := []byte("certificate material")
	body := testVaultResponse(t, binding, 2, "revision-2", secretref.KeyActive, now, value)
	var mu sync.Mutex
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if request.Method != http.MethodGet || request.URL.Path != "/v1/kv/data/product-tls-certificate" || request.URL.Query().Get("version") != "2" || request.Header.Get("X-Vault-Token") != "scoped-token" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(body)
	}))
	defer server.Close()
	client := testClient(t, server, now, binding.Purpose)
	material, err := client.ResolveSecret(context.Background(), binding)
	if err != nil || string(material.Bytes) != string(value) || material.Revision != "revision-2" || material.Binding != binding {
		t.Fatalf("ResolveSecret() = %#v, %v", material, err)
	}
	material.Destroy()
	for name, mutate := range map[string]func(secretref.Binding) secretref.Binding{
		"role": func(value secretref.Binding) secretref.Binding { value.Role = secretref.RoleProvider; return value },
		"purpose": func(value secretref.Binding) secretref.Binding {
			value.Purpose = secretref.PurposePostgresRuntimeDSN
			return value
		},
		"authority": func(value secretref.Binding) secretref.Binding {
			value.Reference = "secret://other/kv/product-tls-certificate"
			return value
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.ResolveSecret(context.Background(), mutate(binding)); !errors.Is(err, secretref.ErrUnavailable) {
				t.Fatalf("ResolveSecret() error = %v", err)
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("scope substitutions reached Vault, requests=%d", requests)
	}
}

func TestClientMapsRevocationAndRejectsMalformedResponses(t *testing.T) {
	now := time.Now().UTC()
	binding := testBinding(secretref.PurposeTLSCertificate, secretref.RoleProduct, "v1")
	value := []byte("certificate material")
	valid := testVaultResponse(t, binding, 1, "revision-1", secretref.KeyActive, now, value)
	revoked := testVaultResponse(t, binding, 1, "revision-1", secretref.KeyRevoked, now, value)
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"unknown":true}`)...)
	duplicate := []byte(strings.Replace(string(valid), `"request_id":"request-1"`, `"request_id":"request-1","request_id":"request-2"`, 1))
	wrongVersion := bytesReplaceOnce(t, valid, `"version":1`, `"version":2`)
	tests := map[string]struct {
		body []byte
		want error
	}{
		"revoked":          {body: revoked, want: secretref.ErrRevoked},
		"unknown":          {body: unknown, want: secretref.ErrUnavailable},
		"duplicate":        {body: duplicate, want: secretref.ErrUnavailable},
		"metadata version": {body: wrongVersion, want: secretref.ErrUnavailable},
		"oversized":        {body: []byte(strings.Repeat("x", maxResponseBytes+1)), want: secretref.ErrUnavailable},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write(test.body)
			}))
			defer server.Close()
			client := testClient(t, server, now, binding.Purpose)
			if _, err := client.ResolveSecret(context.Background(), binding); !errors.Is(err, test.want) {
				t.Fatalf("ResolveSecret() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestClientPreservesCancellationAndRejectsRedirect(t *testing.T) {
	now := time.Now().UTC()
	binding := testBinding(secretref.PurposeTLSCertificate, secretref.RoleProduct, "v1")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Redirect(response, &http.Request{}, "https://example.invalid/private", http.StatusFound)
	}))
	defer server.Close()
	client := testClient(t, server, now, binding.Purpose)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ResolveSecret(ctx, binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ResolveSecret() error = %v", err)
	}
	if _, err := client.ResolveSecret(context.Background(), binding); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("redirect ResolveSecret() error = %v", err)
	}
}

func TestClientRequiresExactJSONContentType(t *testing.T) {
	if validJSONContentType("application/json.evil") || validJSONContentType("application/json; charset=latin1") || !validJSONContentType("application/json; charset=utf-8") {
		t.Fatal("Vault KV JSON content-type validation is not exact")
	}
}

func testClient(t *testing.T, server *httptest.Server, now time.Time, purpose secretref.Purpose) *Client {
	t.Helper()
	tokenBinding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://fixture/product-vault-token", Version: "v1",
		Purpose: secretref.PurposeWorkloadCredential, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct,
	}
	token := []byte("scoped-token")
	tokenDigest := sha256.Sum256(token)
	provider := tokenProvider{material: secretref.SecretMaterial{
		Binding: tokenBinding, Bytes: token, Digest: "sha256:" + hex.EncodeToString(tokenDigest[:]), Revision: "token-revision-1",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: secretref.KeyActive},
	}}
	client, err := New(Config{
		Endpoint: server.URL, Mount: "kv", ReferenceAuthority: "vault", Role: secretref.RoleProduct,
		AllowedPurposes: []secretref.Purpose{purpose}, OperationTimeout: time.Second, Now: func() time.Time { return now },
	}, server.Client(), provider, tokenBinding)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testBinding(purpose secretref.Purpose, role secretref.Role, version string) secretref.Binding {
	return secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-tls-certificate", Version: version,
		Purpose: purpose, TenantID: secretref.SystemTenant, Role: role,
	}
}

func testVaultResponse(t *testing.T, binding secretref.Binding, version int, revision string, state secretref.KeyState, now time.Time, value []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(value)
	response := vaultResponse{
		RequestID: "request-1", Data: kvResponseData{
			Data: materialDocument{
				Schema: materialSchema, BindingDigest: binding.Digest(), Version: binding.Version, Revision: revision,
				Digest: "sha256:" + hex.EncodeToString(digest[:]), State: string(state),
				NotBefore: now.Add(-time.Minute).Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano), Material: append([]byte(nil), value...),
			},
			Metadata: kvMetadata{CreatedTime: now.Format(time.RFC3339Nano), CustomMetadata: json.RawMessage("null"), Version: version},
		},
		WrapInfo: json.RawMessage("null"), Warnings: json.RawMessage("null"), Auth: json.RawMessage("null"), MountType: "kv",
	}
	document, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func bytesReplaceOnce(t *testing.T, document []byte, old, replacement string) []byte {
	t.Helper()
	updated := strings.Replace(string(document), old, replacement, 1)
	if updated == string(document) {
		t.Fatalf("test mutation %q did not match", old)
	}
	return []byte(updated)
}
