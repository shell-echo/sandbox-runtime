package workloadpki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

func postgresPolicyFixture(t *testing.T) (Policy, ed25519.PrivateKey) {
	t.Helper()
	identifier := postgresIdentityFixture()
	digest := "sha256:" + strings.Repeat("a", 64)
	registry, err := securityprincipal.NewRegistry(digest, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	requester, err := registry.New(securityprincipal.KindTLSAgent, "provider_tls_agent", securityprincipal.RoleProvider, digest)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := registry.New(securityprincipal.KindRuntimeRole, "provider", securityprincipal.RoleProvider, digest)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{ID: "provider-browser-postgres-client", Registry: registry,
		Requester: requester, Subject: subject, TrustDomain: "sandbox-runtime.test",
		URI: identifier.URI, Usages: []string{"client_auth"},
		VaultRole: "provider-browser-postgres-client", MaxTTLSeconds: 3600,
		ExpectedUID: 20001, ExpectedGID: 30001, PublicKey: public,
		Purpose: PostgresClientPurpose, Postgres: identifier}
	if err := policy.Validate(); err != nil {
		t.Fatalf("PostgreSQL purpose policy: %v", err)
	}
	return policy, private
}

func TestPostgresCertificatePurposeHasIndependentSignedWireDomain(t *testing.T) {
	policy, private := postgresPolicyFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	csr, key := testPostgresCSR(t, pkix.Name{CommonName: policy.Postgres.CommonName}, policy.URI, nil)
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	request, err := NewIssueRequest(policy, "postgres-issue-1", nonce, now.Add(time.Minute),
		30*time.Minute, csr, private)
	if err != nil || request.Protocol != PostgresClientProtocolID {
		t.Fatalf("dedicated issue request = %+v, %v", request, err)
	}
	document, err := EncodeRequest(request, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeRequest(document, map[string]Policy{policy.ID: policy}, now); err != nil {
		t.Fatalf("dedicated decoder: %v", err)
	}
	wrongVersion := request
	wrongVersion.Protocol = ProtocolID
	wrongVersion.RequestDigest = requestDigest(wrongVersion)
	wrongVersion.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(wrongVersion.RequestDigest)))
	if wrongVersion.Validate(policy, now) == nil {
		t.Fatal("PostgreSQL certificate was downgraded into ordinary workload protocol")
	}
	ordinary := policy
	ordinary.Purpose = ""
	ordinary.Postgres = PostgresClientIdentity{}
	if ordinary.Validate() != nil || validateCSR(csr, ordinary) == nil {
		t.Fatal("ordinary workload purpose accepted PostgreSQL CN")
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PG purpose test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(policy.URI)
	leafSerial := new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	leafTemplate := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: policy.Postgres.CommonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response, err := NewResponse(request, Response{Type: CertificateType, Status: StatusOK,
		IssuerRevision: "postgres-issuer-1", CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		IssuingCAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}),
		CAChainPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}),
		Serial:       serialString(leafSerial.Bytes()), NotBefore: leafTemplate.NotBefore.UTC().Format(time.RFC3339Nano),
		NotAfter: leafTemplate.NotAfter.UTC().Format(time.RFC3339Nano)}, "controller-1", controllerPrivate)
	if err != nil || response.Protocol != PostgresClientProtocolID || response.Validate(request, policy, "controller-1", controllerPublic, now) != nil {
		t.Fatalf("dedicated signed response = %v, %v", err, response.Validate(request, policy, "controller-1", controllerPublic, now))
	}
	wrongResponse := response
	wrongResponse.Protocol = ProtocolID
	if wrongResponse.Validate(request, policy, "controller-1", controllerPublic, now) == nil {
		t.Fatal("ordinary response protocol accepted for PostgreSQL purpose")
	}
}
