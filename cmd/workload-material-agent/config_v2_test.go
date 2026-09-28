package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
)

func TestV2ConfigIsCanonicalAndDoesNotAliasV1(t *testing.T) {
	value := configDocumentV2{configDocument: configDocument{Protocol: configProtocolV2,
		CredentialAgentID: "gateway-agent", CredentialPolicyID: "gateway-agent-kv"},
		SecurityProfilePath: "/run/profile.json", SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
		CredentialBackendPolicy: "gateway-agent-kv", CredentialMaxTTLSeconds: 300}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded configDocumentV2
	if err := decodeCanonicalConfig(document, &decoded); err != nil || decoded.Protocol != configProtocolV2 ||
		decoded.CredentialAgentID != value.CredentialAgentID || decoded.CredentialBackendPolicy != value.CredentialBackendPolicy {
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
}
