package workloadcredential

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/credentialbackend"
)

func TestPhase6VaultIssuerUsesOneFixedRoleAndVerifiesBinding(t *testing.T) {
	now := time.Now().UTC()
	policy := "certificate-controller-pki"
	role := Phase6TokenRole(policy)
	if role == "" || role == Phase6TokenRole("product-runtime") || Phase6TokenRole("../root") != "" {
		t.Fatal("phase 6 token role derivation is not exact")
	}
	spec := credentialbackend.IssueSpec{SubjectID: "certificate_controller", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Purpose: "workload_credential", PolicyID: "certificate-credential", PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		BindingDigest: "sha256:" + strings.Repeat("c", 64), BackendID: "vault-primary", BackendPolicy: policy,
		LeaseID: "lease2_" + strings.Repeat("d", 32), TTL: 20 * time.Second}
	metadata := map[string]string{"subject_id": spec.SubjectID, "subject_digest": spec.SubjectDigest,
		"purpose": spec.Purpose, "policy_id": spec.PolicyID, "policy_digest": spec.PolicyDigest,
		"binding_digest": spec.BindingDigest, "lease_id": spec.LeaseID}
	roleCalls, createCalls, verifyCalls, revokeCalls := 0, 0, 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Header.Get("X-Vault-Token") != "limited-controller-token" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case "/v1/auth/token/roles/" + role:
			roleCalls++
			if request.Method != http.MethodGet {
				response.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_ = json.NewEncoder(response).Encode(scopedRoleResponse(role, policy))
		case "/v1/auth/token/create/" + role:
			createCalls++
			var body struct {
				Policies        []string          `json:"policies"`
				NoDefaultPolicy bool              `json:"no_default_policy"`
				Renewable       bool              `json:"renewable"`
				Meta            map[string]string `json:"meta"`
			}
			if request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&body) != nil ||
				len(body.Policies) != 1 || body.Policies[0] != policy || !body.NoDefaultPolicy || body.Renewable ||
				!equalVaultMetadata(body.Meta, metadata) {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"request_id": "create-1", "lease_id": "", "renewable": false,
				"lease_duration": 0, "data": nil, "wrap_info": nil, "warnings": nil, "mount_type": "token",
				"auth": map[string]any{"client_token": "child-token", "accessor": "accessor123", "policies": []string{policy},
					"token_policies": []string{policy}, "metadata": metadata, "lease_duration": 20,
					"renewable": false, "orphan": false, "token_type": "service", "num_uses": 0}})
		case "/v1/auth/token/lookup-accessor":
			verifyCalls++
			_ = json.NewEncoder(response).Encode(map[string]any{"request_id": "lookup-1", "lease_id": "", "renewable": false,
				"lease_duration": 0, "wrap_info": nil, "warnings": nil, "auth": nil, "mount_type": "token",
				"data": map[string]any{"accessor": "accessor123", "id": "child-token", "creation_ttl": 20, "ttl": 19,
					"meta": metadata, "path": "auth/token/create/" + role, "policies": []string{policy},
					"orphan": false, "renewable": false, "type": "service", "num_uses": 0, "role": role}})
		case "/v1/auth/token/revoke-accessor":
			revokeCalls++
			response.Header().Del("Content-Type")
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	issuer, err := NewVaultIssuer(VaultIssuerConfig{Endpoint: server.URL, BackendID: spec.BackendID,
		Policies: map[string]string{spec.PolicyID: policy}, ManagementToken: []byte("limited-controller-token"),
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return now }, RequireScopedTokenRoles: true}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	if err := issuer.ValidateScopedRoles(context.Background()); err != nil || roleCalls != 1 {
		t.Fatalf("fixed Vault role preflight = %v, calls=%d", err, roleCalls)
	}
	issued, err := issuer.IssueScoped(context.Background(), spec)
	if err != nil || issued.TokenRole != role || issued.PolicyDigest != spec.PolicyDigest {
		t.Fatalf("role-scoped issue = %+v, %v", issued, err)
	}
	defer issued.Destroy()
	if err := issuer.Verify(context.Background(), issued); err != nil {
		t.Fatalf("role-scoped verification: %v", err)
	}
	if err := issuer.Revoke(context.Background(), issued.BackendLeaseID); err != nil {
		t.Fatalf("exact accessor revoke: %v", err)
	}
	if createCalls != 1 || verifyCalls != 1 || revokeCalls != 1 {
		t.Fatalf("scoped Vault calls create=%d verify=%d revoke=%d", createCalls, verifyCalls, revokeCalls)
	}
	changed := issued
	changed.TokenRole = "root"
	if issuer.Verify(context.Background(), changed) == nil || verifyCalls != 1 {
		t.Fatal("caller-controlled or mismatched role reached Vault")
	}
}

func scopedRoleResponse(role, policy string) map[string]any {
	return map[string]any{"request_id": "role-1", "lease_id": "", "renewable": false,
		"lease_duration": 0, "wrap_info": nil, "warnings": nil, "auth": nil, "mount_type": "token",
		"data": map[string]any{"name": role, "allowed_policies": []string{policy}, "allowed_policies_glob": []string{},
			"disallowed_policies": []string{"default", "root"}, "disallowed_policies_glob": []string{},
			"allowed_entity_aliases": nil, "token_no_default_policy": true, "token_type": "service",
			"token_explicit_max_ttl": 900, "explicit_max_ttl": 0, "renewable": false, "orphan": false,
			"period": 0, "token_period": 0, "path_suffix": ""}}
}

func TestVaultScopedRoleValidationRejectsDrift(t *testing.T) {
	role := Phase6TokenRole("certificate-controller-pki")
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{name: "wrong policy", change: func(data map[string]any) { data["allowed_policies"] = []string{"root"} }},
		{name: "additional policy", change: func(data map[string]any) { data["allowed_policies"] = []string{"certificate-controller-pki", "root"} }},
		{name: "policy glob", change: func(data map[string]any) { data["allowed_policies_glob"] = []string{"*"} }},
		{name: "default policy", change: func(data map[string]any) { data["token_no_default_policy"] = false }},
		{name: "orphan child", change: func(data map[string]any) { data["orphan"] = true }},
		{name: "renewable child", change: func(data map[string]any) { data["renewable"] = true }},
		{name: "batch token", change: func(data map[string]any) { data["token_type"] = "batch" }},
		{name: "unbounded ttl", change: func(data map[string]any) { data["token_explicit_max_ttl"] = 0 }},
		{name: "extra field", change: func(data map[string]any) { data["unexpected"] = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				if request.Method != http.MethodGet || request.URL.Path != "/v1/auth/token/roles/"+role {
					response.WriteHeader(http.StatusForbidden)
					return
				}
				body := scopedRoleResponse(role, "certificate-controller-pki")
				data := body["data"].(map[string]any)
				test.change(data)
				_ = json.NewEncoder(response).Encode(body)
			}))
			defer server.Close()
			issuer, err := NewVaultIssuer(VaultIssuerConfig{Endpoint: server.URL, BackendID: "vault-primary",
				Policies:        map[string]string{"certificate-credential": "certificate-controller-pki"},
				ManagementToken: []byte("limited-controller-token"), OperationTimeout: 3 * time.Second,
				Now: time.Now, RequireScopedTokenRoles: true}, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer issuer.Close()
			if err := issuer.ValidateScopedRoles(context.Background()); err == nil {
				t.Fatal("drifted Vault token role accepted")
			}
		})
	}
}

func TestVaultScopedIssueRejectsOverflowLeaseDuration(t *testing.T) {
	policy := "certificate-controller-pki"
	role := Phase6TokenRole(policy)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodPost || request.URL.Path != "/v1/auth/token/create/"+role {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"request_id": "create-1", "lease_id": "", "renewable": false,
			"lease_duration": 0, "data": nil, "wrap_info": nil, "warnings": nil, "mount_type": "token",
			"auth": map[string]any{"client_token": "child-token", "accessor": "accessor123", "policies": []string{policy},
				"token_policies": []string{policy}, "metadata": map[string]string{}, "lease_duration": int64(1<<63 - 1),
				"renewable": false, "orphan": false, "token_type": "service", "num_uses": 0}})
	}))
	defer server.Close()
	issuer, err := NewVaultIssuer(VaultIssuerConfig{Endpoint: server.URL, BackendID: "vault-primary",
		Policies: map[string]string{"certificate-credential": policy}, ManagementToken: []byte("limited-controller-token"),
		OperationTimeout: 3 * time.Second, Now: time.Now, RequireScopedTokenRoles: true}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	spec := credentialbackend.IssueSpec{SubjectID: "certificate_controller", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Purpose: "workload_credential", PolicyID: "certificate-credential", PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		BindingDigest: "sha256:" + strings.Repeat("c", 64), BackendID: "vault-primary", BackendPolicy: policy,
		LeaseID: "lease2_" + strings.Repeat("d", 32), TTL: 20 * time.Second}
	if issued, err := issuer.IssueScoped(context.Background(), spec); err == nil {
		issued.Destroy()
		t.Fatal("overflowing Vault lease duration accepted")
	}
}
