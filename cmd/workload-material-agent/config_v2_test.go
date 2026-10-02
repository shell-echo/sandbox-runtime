package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
)

func TestV2ConfigIsCanonicalAndDoesNotAliasV1(t *testing.T) {
	value := configDocumentV2{configDocument: configDocument{Protocol: configProtocolV2,
		CredentialAgentID: "gateway-agent", CredentialPolicyID: "gateway-agent-kv"},
		SecurityProfilePath: "/run/profile.json", SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
		CredentialBackendPolicy: "gateway-agent-kv", CredentialMaxTTLSeconds: 300,
		VaultTLSAgentSocket: "/run/tls/gateway-agent-tls-agent/signer.sock",
		VaultTLSAgentUID:    55000, VaultTLSAgentGID: 57000}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded configDocumentV2
	if err := decodeCanonicalConfig(document, &decoded); err != nil || decoded.Protocol != configProtocolV2 ||
		decoded.CredentialAgentID != value.CredentialAgentID || decoded.CredentialBackendPolicy != value.CredentialBackendPolicy ||
		decoded.VaultTLSAgentSocket != value.VaultTLSAgentSocket {
		t.Fatalf("v2 promoted fields were not decoded canonically: %v", err)
	}
	var legacy configDocument
	if decodeCanonicalConfig(document, &legacy) == nil {
		t.Fatal("v2 document was admitted by the v1 schema")
	}
	for _, invalid := range [][]byte{
		append(append([]byte(nil), document...), '\n'),
		bytes.Replace(document, []byte(`"credential_max_ttl_seconds":300`), []byte(`"credential_max_ttl_seconds":300,"credential_max_ttl_seconds":300`), 1),
		bytes.Replace(document, []byte(`"credential_backend_policy":"gateway-agent-kv"`), []byte(`"credential_backend_policy":"gateway-agent-kv","unexpected":true`), 1),
	} {
		if decodeCanonicalConfig(invalid, &configDocumentV2{}) == nil {
			t.Fatal("noncanonical or unknown v2 configuration was admitted")
		}
	}
}

func TestV2MaterialAccessConfigRequiresExactProfilePlan(t *testing.T) {
	binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://phase6/kv/gateway-agent/gateway-grant-key", Version: "v1",
		Purpose: secretref.PurposeGatewayGrantKey, TenantID: secretref.SystemTenant, Role: secretref.RoleGateway}
	entry := phase6security.Slice6MaterialAccess{Agent: "gateway-agent", Role: secretref.RoleGateway,
		CredentialSocket:   "/run/workload-credential-controller/gateway-agent/issuer.sock",
		CredentialPolicyID: "credential-gateway-agent", BackendPolicy: "gateway-agent-kv",
		Bindings: []secretref.Binding{binding}}
	config := configDocument{CredentialAgentID: entry.Agent, Role: entry.Role,
		CredentialControllerSocket: entry.CredentialSocket, CredentialPolicyID: entry.CredentialPolicyID,
		VaultMount: "kv", VaultReferenceAuthority: "phase6", Bindings: []secretref.Binding{binding}}
	v2 := configDocumentV2{CredentialBackendPolicy: entry.BackendPolicy}
	if !validV2MaterialAccessConfig(entry, config, v2) {
		t.Fatal("exact material access plan rejected")
	}
	for name, drift := range map[string]func(*configDocument, *configDocumentV2){
		"agent":          func(c *configDocument, _ *configDocumentV2) { c.CredentialAgentID = "product-runtime-agent" },
		"policy":         func(c *configDocument, _ *configDocumentV2) { c.CredentialPolicyID = "other" },
		"backend policy": func(_ *configDocument, v *configDocumentV2) { v.CredentialBackendPolicy = "other" },
		"cross-owner KV": func(c *configDocument, _ *configDocumentV2) {
			c.Bindings = []secretref.Binding{binding}
			c.Bindings[0].Reference = "secret://phase6/kv/other/gateway-grant-key"
		},
		"extra KV":  func(c *configDocument, _ *configDocumentV2) { c.Bindings = append(c.Bindings, binding) },
		"migration": func(c *configDocument, _ *configDocumentV2) { c.Migration = true },
		"mount":     func(c *configDocument, _ *configDocumentV2) { c.VaultMount = "secret" },
		"authority": func(c *configDocument, _ *configDocumentV2) { c.VaultReferenceAuthority = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changedConfig, changedV2 := config, v2
			drift(&changedConfig, &changedV2)
			if validV2MaterialAccessConfig(entry, changedConfig, changedV2) {
				t.Fatal("material authority drift admitted")
			}
		})
	}
}

func TestV2MaterialSocketConfigRequiresDistinctOwnerAndAgent(t *testing.T) {
	binding := phase6security.Slice6MaterialSocketBinding{AgentDeployment: "guest-agent", OwnerDeployment: "guest-runtime",
		AgentUID: 20010, AgentGID: 30010, OwnerUID: 20011, OwnerGID: 30011,
		SocketPath: "/run/phase6/material/guest-agent/agent.sock", MaxConnections: 4, MaxOperationSeconds: 30}
	config := configDocument{CredentialAgentID: binding.AgentDeployment, SocketPath: binding.SocketPath,
		SocketUID: binding.AgentUID, SocketGID: binding.OwnerGID, ExpectedClientUID: binding.OwnerUID,
		ExpectedClientGID: binding.OwnerGID, MaxConnections: 4, OperationTimeoutSeconds: 3}
	if !validV2MaterialSocketConfig(binding, config) {
		t.Fatal("exact cross-UID material endpoint rejected")
	}
	for name, mutate := range map[string]func(*configDocument){
		"path":          func(c *configDocument) { c.SocketPath += "-other" },
		"socket uid":    func(c *configDocument) { c.SocketUID++ },
		"directory gid": func(c *configDocument) { c.SocketGID = binding.AgentGID },
		"peer uid":      func(c *configDocument) { c.ExpectedClientUID++ },
		"peer gid":      func(c *configDocument) { c.ExpectedClientGID++ },
		"capacity":      func(c *configDocument) { c.MaxConnections = 256 },
		"deadline":      func(c *configDocument) { c.OperationTimeoutSeconds = 60 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := config
			mutate(&changed)
			if validV2MaterialSocketConfig(binding, changed) {
				t.Fatal("cross-UID material endpoint drift admitted")
			}
		})
	}
}

func TestHistoricalV1ConfigRemainsSeparate(t *testing.T) {
	value := configDocument{Protocol: configProtocol, CredentialAgentID: "gateway-agent"}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded configDocument
	if err := decodeCanonicalConfig(document, &decoded); err != nil || decoded.Protocol != configProtocol {
		t.Fatalf("historical v1 configuration changed: %v", err)
	}
	var v2 configDocumentV2
	if decodeCanonicalConfig(document, &v2) == nil {
		t.Fatal("v1 document was admitted as v2 without explicit fields")
	}
}

func TestV2CredentialLeaseAdapterPreservesRevocationIdentity(t *testing.T) {
	now := time.Now().UTC()
	original := workloadcredentialv2.Lease{ID: "lease2_" + strings.Repeat("a", 32), Revision: 7,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), Renewable: false, Credential: []byte("secret")}
	converted := fromPrincipalLease(original)
	roundTrip := toPrincipalLease(converted)
	if roundTrip.ID != original.ID || roundTrip.Revision != original.Revision || roundTrip.Renewable ||
		!bytes.Equal(roundTrip.Credential, original.Credential) {
		t.Fatal("v2 lease identity or material changed across the agent adapter")
	}
	converted.Destroy()
	if len(converted.Credential) != 0 || !bytes.Equal(original.Credential, make([]byte, 6)) {
		t.Fatal("v2 lease material was not cleared")
	}
	legacy := workloadcredential.Lease{ID: "lease_" + strings.Repeat("b", 32), Revision: 1, Credential: []byte("old")}
	if toLegacyLease(fromLegacyLease(legacy)).ID != legacy.ID {
		t.Fatal("historical v1 lease identity drifted")
	}
}

func TestV2IssuerCannotDowngradeWithoutProfile(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := configDocument{Protocol: configProtocolV2, CredentialAgentID: "gateway-agent",
		CredentialTTLSeconds: 60}
	if _, err := newCredentialIssuer(base, nil, privateKey); err == nil {
		t.Fatal("v2 protocol selected historical v1 issuance without v2 configuration")
	}
	_, err = newCredentialIssuer(base, &configDocumentV2{configDocument: base,
		SecurityProfilePath: "/missing/security-profile.json", CredentialMaxTTLSeconds: 60}, privateKey)
	if err == nil {
		t.Fatal("v2 issuer downgraded to the historical v1 client when its profile was absent")
	}
	if _, err := newV2VaultHTTPClient(base, configDocumentV2{configDocument: base,
		SecurityProfilePath: "/missing/security-profile.json"}); err == nil {
		t.Fatal("v2 Vault transport fell back to server-only TLS without a profile and signer")
	}
}
