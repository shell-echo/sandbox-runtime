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
	"sync/atomic"
	"testing"
	"time"
)

func TestVaultPolicyIssuerSelectionRejectsDefaultDriftAndCrossIssuerCRL(t *testing.T) {
	general, broker := newProtocolFixture(t), newProtocolFixture(t)
	general.policy.IssuerSourceID = "general-source"
	broker.policy.ID, broker.policy.VaultRole, broker.policy.IssuerSourceID = "broker-policy", "broker-role", "broker-source"
	generalBlock, rest := pem.Decode(general.ca)
	if generalBlock == nil || len(rest) != 0 {
		t.Fatal("general CA fixture")
	}
	brokerBlock, rest := pem.Decode(broker.ca)
	if brokerBlock == nil || len(rest) != 0 {
		t.Fatal("broker CA fixture")
	}
	generalDigest, brokerDigest := sha256.Sum256(generalBlock.Bytes), sha256.Sum256(brokerBlock.Bytes)
	sources := []VaultPeerIssuerSource{
		{SourceID: "general-source", Mount: "pki", IssuerID: "11111111-1111-4111-8111-111111111111",
			IssuerDigest: "sha256:" + hex.EncodeToString(generalDigest[:])},
		{SourceID: "broker-source", Mount: "pki", IssuerID: "22222222-2222-4222-8222-222222222222",
			IssuerDigest: "sha256:" + hex.EncodeToString(brokerDigest[:])},
	}
	var wrongRole, wrongIssue, wrongCRL atomic.Bool
	var defaultCRLCalls, signCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != "scoped-pki-token" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/pki/config/crl":
			_ = json.NewEncoder(response).Encode(vaultData(map[string]any{
				"disable": false, "auto_rebuild": false, "enable_delta": false}))
		case "/v1/pki/roles/product-runtime", "/v1/pki/roles/broker-role":
			issuer := sources[0].IssuerID
			if request.URL.Path == "/v1/pki/roles/broker-role" {
				issuer = sources[1].IssuerID
				if wrongRole.Load() {
					issuer = "default"
				}
			}
			_ = json.NewEncoder(response).Encode(vaultData(map[string]any{"issuer_ref": issuer}))
		case "/v1/pki/issuer/" + sources[0].IssuerID + "/der", "/v1/pki/issuer/" + sources[1].IssuerID + "/der":
			response.Header().Set("Content-Type", "application/pkix-cert")
			if request.URL.Path == "/v1/pki/issuer/"+sources[0].IssuerID+"/der" {
				_, _ = response.Write(generalBlock.Bytes)
			} else {
				_, _ = response.Write(brokerBlock.Bytes)
			}
		case "/v1/pki/issuer/" + sources[0].IssuerID + "/crl/der", "/v1/pki/issuer/" + sources[1].IssuerID + "/crl/der":
			response.Header().Set("Content-Type", "application/pkix-crl")
			if request.URL.Path == "/v1/pki/issuer/"+sources[0].IssuerID+"/crl/der" || wrongCRL.Load() {
				_, _ = response.Write(general.crl)
			} else {
				_, _ = response.Write(broker.crl)
			}
		case "/v1/pki/sign/product-runtime", "/v1/pki/sign/broker-role":
			signCalls.Add(1)
			selected := general
			if request.URL.Path == "/v1/pki/sign/broker-role" {
				selected = broker
			}
			issuer := selected.ca
			if wrongIssue.Load() {
				issuer = general.ca
			}
			leaf, _ := pem.Decode(selected.certificate)
			certificate, _ := x509.ParseCertificate(leaf.Bytes)
			_ = json.NewEncoder(response).Encode(vaultData(map[string]any{
				"authority_key_id": selected.serial, "ca_chain": []string{string(issuer)},
				"certificate": string(selected.certificate), "expiration": certificate.NotAfter.Unix(),
				"issuing_ca": string(issuer), "private_key": "", "private_key_type": "",
				"serial_number": selected.serial}))
		case "/v1/pki/crl":
			defaultCRLCalls.Add(1)
			response.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = response.Write(general.crl)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := NewVaultClient(VaultConfig{Endpoint: server.URL, Mount: "pki",
		AllowedPolicies: map[string]string{general.policy.ID: general.policy.VaultRole,
			broker.policy.ID: broker.policy.VaultRole},
		OperationTimeout: 3 * time.Second, Now: time.Now, RequireImmediateCompleteCRL: true,
		PeerIssuerSources: sources}, server.Client(), staticVaultTokenSource{token: VaultToken{
		Value: []byte("scoped-pki-token"), ExpiresAt: time.Now().Add(time.Minute), Revision: "vault-token-1"}})
	if err != nil || client.ValidatePolicyIssuers([]Policy{general.policy, broker.policy}) != nil {
		t.Fatalf("pinned policy sources: %v", err)
	}
	for name, mutate := range map[string]func(*Policy){
		"missing source": func(p *Policy) { p.IssuerSourceID = "" },
		"unknown source": func(p *Policy) { p.IssuerSourceID = "unknown-source" },
		"wrong role":     func(p *Policy) { p.VaultRole = "other-role" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := broker.policy
			mutate(&changed)
			if client.ValidatePolicyIssuers([]Policy{general.policy, changed}) == nil {
				t.Fatal("policy issuer drift admitted")
			}
		})
	}
	if client.ValidatePolicyIssuers([]Policy{general.policy, general.policy}) == nil {
		t.Fatal("duplicate policy source admitted")
	}
	original := client.peerIssuerSources["broker-source"]
	changed := original
	changed.Mount = "other-pki"
	client.peerIssuerSources["broker-source"] = changed
	if client.ValidatePolicyIssuers([]Policy{general.policy, broker.policy}) == nil {
		t.Fatal("cross-mount policy source admitted")
	}
	client.peerIssuerSources["broker-source"] = original
	for _, item := range []struct {
		policy Policy
		csr    []byte
		crl    []byte
	}{
		{general.policy, general.csr, general.crl}, {broker.policy, broker.csr, broker.crl},
	} {
		issued, err := client.Issue(context.Background(), item.policy, item.csr, 10*time.Minute)
		if err != nil || issued.Serial == "" {
			t.Fatalf("policy issuance %s: %v", item.policy.ID, err)
		}
		issued.Destroy()
		snapshot, err := client.PolicyRevocations(context.Background(), item.policy)
		if err != nil || !bytes.Equal(snapshot.DER, item.crl) {
			t.Fatalf("policy CRL %s: %v", item.policy.ID, err)
		}
		snapshot.Destroy()
	}
	if _, err := client.Revocations(context.Background()); err == nil || defaultCRLCalls.Load() != 0 {
		t.Fatal("production authority fell back to default CRL")
	}
	wrongRole.Store(true)
	before := signCalls.Load()
	if _, err := client.Issue(context.Background(), broker.policy, broker.csr, 10*time.Minute); err == nil ||
		signCalls.Load() != before {
		t.Fatal("drifted Vault role issuer reached signing endpoint")
	}
	wrongRole.Store(false)
	wrongIssue.Store(true)
	if _, err := client.Issue(context.Background(), broker.policy, broker.csr, 10*time.Minute); err == nil {
		t.Fatal("wrong immediate issuing CA accepted")
	}
	wrongIssue.Store(false)
	wrongCRL.Store(true)
	if _, err := client.PolicyRevocations(context.Background(), broker.policy); err == nil {
		t.Fatal("cross-issuer CRL accepted")
	}
	if defaultCRLCalls.Load() != 0 {
		t.Fatal("default CRL endpoint was used")
	}
}
