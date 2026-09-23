package workloadcredentialv2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

type protocolFixture struct {
	now      time.Time
	registry *securityprincipal.Registry
	policy   Policy
	private  ed25519.PrivateKey
}

func newProtocolFixture(t *testing.T, kind securityprincipal.Kind, name string, role securityprincipal.Role, renewable bool) protocolFixture {
	t.Helper()
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	registry, err := securityprincipal.NewRegistry(digest("a"), digest("b"), map[string]securityprincipal.Role{"product_egress_broker": securityprincipal.RoleProduct})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.New(kind, name, role, digest("c"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backendPolicy := strings.ReplaceAll(name, "_", "-")
	if name == "certificate_controller" {
		backendPolicy = "certificate-controller-pki"
	}
	if name == "break_glass_controller" {
		backendPolicy = "break-glass-controller"
	}
	return protocolFixture{now: time.Now().UTC(), registry: registry, private: privateKey,
		policy: Policy{ID: "policy-" + strings.ReplaceAll(name, "_", "-"), Registry: registry, Principal: principal,
			Purpose: secretref.PurposeWorkloadCredential, BackendID: "vault-primary", BackendPolicy: backendPolicy,
			MaxTTL: 10 * time.Minute, Renewable: renewable, PublicKey: publicKey}}
}

func TestProtocolBindsPrincipalPolicyAndV2Domain(t *testing.T) {
	fixture := newProtocolFixture(t, securityprincipal.KindMaterialAgent, "product_runtime_agent", securityprincipal.RoleProduct, true)
	jti := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	request, err := NewSignedRequest(fixture.policy, IssueType, "", 0, 5*time.Minute, fixture.now.Add(30*time.Second), jti, fixture.private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	document, err := EncodeRequest(request, fixture.policy, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, policy, err := DecodeRequest(document, map[string]Policy{fixture.policy.ID: fixture.policy}, fixture.now)
	if err != nil || decoded.Principal.Digest() != fixture.policy.Principal.Digest() || policy.Digest() != fixture.policy.Digest() {
		t.Fatalf("DecodeRequest() = %#v, %#v, %v", decoded, policy, err)
	}
	response := Response{Protocol: ProtocolID, Type: ResponseType, Status: StatusOK, RequestDigest: request.RequestDigest,
		PrincipalDigest: request.Principal.Digest(), PolicyDigest: request.PolicyDigest, LeaseID: "lease2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Revision: 1, IssuedAt: fixture.now.Format(time.RFC3339Nano), ExpiresAt: fixture.now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		Renewable: true, Credential: []byte("scoped-token")}
	responseDocument, err := EncodeResponse(response, request, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(responseDocument, request, fixture.now); err != nil {
		t.Fatal(err)
	}

	v1Downgrade := append([]byte(nil), document...)
	v1Downgrade = bytes.Replace(v1Downgrade, []byte(ProtocolID), []byte("sandbox-runtime.workload-credential.v1"), 1)
	if _, _, err := DecodeRequest(v1Downgrade, map[string]Policy{fixture.policy.ID: fixture.policy}, fixture.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("v1 downgrade error = %v", err)
	}
	mixed, err := NewSignedRequest(fixture.policy, RenewType, "lease_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 5*time.Minute, fixture.now.Add(30*time.Second),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), fixture.private, fixture.now)
	if err == nil || mixed.Protocol != "" {
		t.Fatal("v1 lease was reinterpreted as v2")
	}
}

func TestPolicyEnforcesClosedIssuanceMatrix(t *testing.T) {
	valid := []struct {
		kind      securityprincipal.Kind
		name      string
		role      securityprincipal.Role
		renewable bool
	}{
		{securityprincipal.KindMaterialAgent, "product_runtime_agent", securityprincipal.RoleProduct, true},
		{securityprincipal.KindMaterialAgent, "product_migration_agent", securityprincipal.RoleProduct, false},
		{securityprincipal.KindController, "certificate_controller", "", true},
		{securityprincipal.KindController, "break_glass_controller", "", true},
	}
	for _, test := range valid {
		fixture := newProtocolFixture(t, test.kind, test.name, test.role, test.renewable)
		if err := fixture.policy.Validate(); err != nil {
			t.Fatalf("valid %s/%s rejected: %v", test.kind, test.name, err)
		}
	}
	invalid := []struct {
		kind securityprincipal.Kind
		name string
		role securityprincipal.Role
	}{
		{securityprincipal.KindRuntimeRole, "product", securityprincipal.RoleProduct},
		{securityprincipal.KindMigrationJob, "product_migration", securityprincipal.RoleProduct},
		{securityprincipal.KindExecutorBackend, "browser_executor", securityprincipal.RoleBrowser},
		{securityprincipal.KindEgressBroker, "product_egress_broker", securityprincipal.RoleProduct},
		{securityprincipal.KindTLSAgent, "product_tls_agent", securityprincipal.RoleProduct},
		{securityprincipal.KindTLSAgent, "product_egress_broker_tls_agent", securityprincipal.RoleProduct},
		{securityprincipal.KindController, "credential_controller", ""},
	}
	for _, test := range invalid {
		fixture := newProtocolFixture(t, test.kind, test.name, test.role, false)
		if fixture.policy.Validate() == nil {
			t.Fatalf("invalid %s/%s accepted", test.kind, test.name)
		}
	}
	migration := newProtocolFixture(t, securityprincipal.KindMaterialAgent, "product_migration_agent", securityprincipal.RoleProduct, true)
	if migration.policy.Validate() == nil {
		t.Fatal("renewable migration agent accepted")
	}
	controller := newProtocolFixture(t, securityprincipal.KindController, "certificate_controller", "", true)
	controller.policy.BackendPolicy = "product-runtime-agent"
	if controller.policy.Validate() == nil {
		t.Fatal("certificate controller accepted a business policy")
	}
	tlsAgent := newProtocolFixture(t, securityprincipal.KindTLSAgent, "product_tls_agent", securityprincipal.RoleProduct, true)
	tlsAgent.policy.BackendPolicy = "product-runtime-agent"
	if tlsAgent.policy.Validate() == nil {
		t.Fatal("TLS agent received Vault issuance despite configured backend policy")
	}
}

func TestProtocolRejectsPrincipalPolicyReplayDomainAndCanonicalDrift(t *testing.T) {
	fixture := newProtocolFixture(t, securityprincipal.KindMaterialAgent, "product_runtime_agent", securityprincipal.RoleProduct, true)
	request, err := NewSignedRequest(fixture.policy, IssueType, "", 0, 5*time.Minute, fixture.now.Add(30*time.Second),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), fixture.private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Request){
		"principal": func(value *Request) { value.Principal.PrincipalDigest = "sha256:" + strings.Repeat("d", 64) },
		"policy":    func(value *Request) { value.PolicyDigest = "sha256:" + strings.Repeat("d", 64) },
		"backend":   func(value *Request) { value.BackendID = "other-vault" },
		"signature": func(value *Request) {
			value.AgentSignature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if candidate.Validate(fixture.policy, fixture.now) == nil {
				t.Fatal("substitution was accepted")
			}
		})
	}
	document, _ := json.Marshal(request)
	unknown := append([]byte(`{"unknown":true,`), document[1:]...)
	duplicate := append([]byte(`{"protocol":"sandbox-runtime.workload-credential.v2",`), document[1:]...)
	for _, candidate := range [][]byte{unknown, duplicate, append(document, '\n')} {
		if _, _, err := DecodeRequest(candidate, map[string]Policy{fixture.policy.ID: fixture.policy}, fixture.now); !errors.Is(err, ErrDenied) {
			t.Fatalf("noncanonical error = %v", err)
		}
	}
}
