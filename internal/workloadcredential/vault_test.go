package workloadcredential

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestVaultIssuerIssuesVerifiesAndRevokesExactScopedToken(t *testing.T) {
	now := time.Now().UTC()
	var mu sync.Mutex
	issued, verified, revoked := 0, 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/auth/token/create":
			issued++
			if request.Method != http.MethodPost || request.Header.Get("X-Vault-Token") != "management-token" {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			var body struct {
				Policies        []string          `json:"policies"`
				TTL             string            `json:"ttl"`
				Renewable       bool              `json:"renewable"`
				NoDefaultPolicy bool              `json:"no_default_policy"`
				DisplayName     string            `json:"display_name"`
				Metadata        map[string]string `json:"meta"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil || len(body.Policies) != 1 || body.Policies[0] != "product-runtime-vault" ||
				body.TTL != "20s" || body.Renewable || !body.NoDefaultPolicy || body.Metadata["agent_id"] != "product-runtime-agent" {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"request_id": "request-1", "lease_id": "", "renewable": false,
				"lease_duration": 0, "data": nil, "wrap_info": nil, "warnings": nil, "mount_type": "token",
				"auth": map[string]any{"client_token": "scoped-token", "accessor": "accessor123", "policies": []string{"product-runtime-vault"}, "lease_duration": 20, "renewable": false}})
		case "/v1/auth/token/lookup-accessor":
			verified++
			if request.Method != http.MethodPost || request.Header.Get("X-Vault-Token") != "management-token" {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"request_id": "request-2", "lease_id": "", "renewable": false,
				"lease_duration": 0, "data": map[string]any{"accessor": "accessor123", "ttl": 19}, "wrap_info": nil, "warnings": nil, "auth": nil, "mount_type": "token"})
		case "/v1/auth/token/revoke-accessor":
			revoked++
			if request.Method != http.MethodPost || request.Header.Get("X-Vault-Token") != "management-token" {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			response.Header().Del("Content-Type")
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	issuer, err := NewVaultIssuer(VaultIssuerConfig{Endpoint: server.URL, BackendID: "vault-primary",
		Policies: map[string]string{"product-runtime": "product-runtime-vault"}, ManagementToken: []byte("management-token"),
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return now }}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	spec := IssueSpec{AgentID: "product-runtime-agent", Role: secretref.RoleProduct, Purpose: secretref.PurposeWorkloadCredential,
		PolicyID: "product-runtime", BindingDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BackendID: "vault-primary", LeaseID: "lease_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TTL: 20 * time.Second}
	credential, err := issuer.Issue(context.Background(), spec)
	if err != nil || string(credential.Credential) != "scoped-token" || credential.BackendLeaseID != "accessor123" {
		t.Fatalf("Issue()=%#v, %v", credential, err)
	}
	defer credential.Destroy()
	if err := issuer.Verify(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	if err := issuer.Revoke(context.Background(), credential.BackendLeaseID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if issued != 1 || verified != 1 || revoked != 1 {
		t.Fatalf("Vault calls issue=%d verify=%d revoke=%d", issued, verified, revoked)
	}
}
