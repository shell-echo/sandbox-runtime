package workloadpki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

type protocolFixture struct {
	now            time.Time
	policy         Policy
	agentPrivate   ed25519.PrivateKey
	controllerID   string
	controllerPriv ed25519.PrivateKey
	controllerPub  ed25519.PublicKey
	csr            []byte
	certificate    []byte
	ca             []byte
	serial         string
	notBefore      time.Time
	notAfter       time.Time
	crl            []byte
	crlThis        time.Time
	crlNext        time.Time
}

func newProtocolFixture(t *testing.T) protocolFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	agentPublic, agentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse("spiffe://sandbox-runtime.test/product-runtime")
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	registry, err := securityprincipal.NewRegistry(digest("a"), digest("b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	requester, err := registry.New(securityprincipal.KindTLSAgent, "product_tls_agent", securityprincipal.RoleProduct, digest("c"))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := registry.New(securityprincipal.KindRuntimeRole, "product", securityprincipal.RoleProduct, digest("d"))
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{ID: "product-runtime-tls", Registry: registry, Requester: requester, Subject: subject, TrustDomain: "sandbox-runtime.test", URI: identity.String(),
		DNSNames: []string{"product.example.test"}, Usages: []string{"client_auth", "server_auth"}, VaultRole: "product-runtime", MaxTTLSeconds: 900,
		ExpectedUID: 20001, ExpectedGID: 30001, PublicKey: agentPublic}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: policy.DNSNames, URIs: []*url.URL{identity}}, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Slice 6 Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := now.Add(-time.Minute), now.Add(10*time.Minute)
	serialNumber := new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	certificateTemplate := &x509.Certificate{SerialNumber: serialNumber, NotBefore: notBefore, NotAfter: notAfter, DNSNames: policy.DNSNames, URIs: []*url.URL{identity},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, ca, &tlsKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	crlThis, crlNext := now.Add(-time.Minute), now.Add(5*time.Minute)
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: crlThis, NextUpdate: crlNext}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return protocolFixture{now: now, policy: policy, agentPrivate: agentPrivate, controllerID: "slice6-certificate-controller", controllerPriv: controllerPrivate, controllerPub: controllerPublic,
		csr: csr, certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		serial: serialString(serialNumber.Bytes()), notBefore: notBefore, notAfter: notAfter, crl: crl, crlThis: crlThis, crlNext: crlNext}
}

func TestPrincipalDelegationIsOneTLSAgentPerExactSubject(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	registry, err := securityprincipal.NewRegistry(digest, digest,
		map[string]securityprincipal.Role{"product_egress_broker": securityprincipal.RoleProduct})
	if err != nil {
		t.Fatal(err)
	}
	principal := func(kind securityprincipal.Kind, name string, role securityprincipal.Role) securityprincipal.Principal {
		t.Helper()
		value, err := registry.New(kind, name, role, digest)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	product := principal(securityprincipal.KindRuntimeRole, "product", securityprincipal.RoleProduct)
	productTLS := principal(securityprincipal.KindTLSAgent, "product_tls_agent", securityprincipal.RoleProduct)
	browser := principal(securityprincipal.KindRuntimeRole, "browser", securityprincipal.RoleBrowser)
	browserExecutor := principal(securityprincipal.KindExecutorBackend, "browser_executor", securityprincipal.RoleBrowser)
	browserTLS := principal(securityprincipal.KindTLSAgent, "browser_tls_agent", securityprincipal.RoleBrowser)
	browserExecutorTLS := principal(securityprincipal.KindTLSAgent, "browser_executor_tls_agent", securityprincipal.RoleBrowser)
	broker := principal(securityprincipal.KindEgressBroker, "product_egress_broker", securityprincipal.RoleProduct)
	brokerTLS := principal(securityprincipal.KindTLSAgent, "product_egress_broker_tls_agent", securityprincipal.RoleProduct)
	material := principal(securityprincipal.KindMaterialAgent, "product_runtime_agent", securityprincipal.RoleProduct)
	if !validPrincipalDelegation(productTLS, product) || !validPrincipalDelegation(browserTLS, browser) ||
		!validPrincipalDelegation(browserExecutorTLS, browserExecutor) || !validPrincipalDelegation(brokerTLS, broker) {
		t.Fatal("exact TLS agent delegation rejected")
	}
	for _, pair := range [][2]securityprincipal.Principal{
		{material, product}, {browserTLS, browserExecutor}, {browserExecutorTLS, browser},
		{productTLS, broker}, {brokerTLS, product}, {productTLS, productTLS}, {product, product},
	} {
		if validPrincipalDelegation(pair[0], pair[1]) {
			t.Fatalf("cross-scope delegation accepted: %s -> %s", pair[0].Name, pair[1].Name)
		}
	}
}

func TestIssueProtocolBindsSignedCSRAndCertificate(t *testing.T) {
	fixture := newProtocolFixture(t)
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	request, err := NewIssueRequest(fixture.policy, "request-issue-1", nonce, fixture.now.Add(30*time.Second), 10*time.Minute, fixture.csr, fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	document, err := EncodeRequest(request, fixture.policy, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, policy, err := DecodeRequest(document, map[string]Policy{fixture.policy.ID: fixture.policy}, fixture.now)
	if err != nil || policy.ID != fixture.policy.ID {
		t.Fatalf("DecodeRequest() = %#v, %#v, %v", decoded, policy, err)
	}
	response, err := NewResponse(request, Response{Type: CertificateType, Status: StatusOK, IssuerRevision: "vault-pki-1", CertificatePEM: fixture.certificate,
		IssuingCAPEM: fixture.ca, CAChainPEM: fixture.ca, Serial: fixture.serial, NotBefore: fixture.notBefore.Format(time.RFC3339Nano), NotAfter: fixture.notAfter.Format(time.RFC3339Nano)}, fixture.controllerID, fixture.controllerPriv)
	if err != nil {
		t.Fatal(err)
	}
	responseDocument, err := EncodeResponse(response, request)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := DecodeResponse(responseDocument, request, fixture.policy, fixture.controllerID, fixture.controllerPub, fixture.now)
	if err != nil || accepted.Serial != fixture.serial {
		t.Fatalf("DecodeResponse() = %#v, %v", accepted, err)
	}
}

func TestRevocationProtocolBindsSnapshotAndSerial(t *testing.T) {
	fixture := newProtocolFixture(t)
	nonce := func(value byte) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	request, err := NewRevocationsRequest(fixture.policy, "request-crl-1", nonce(1), fixture.now.Add(30*time.Second), fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	response, err := NewResponse(request, Response{Type: RevocationSnapshotType, Status: StatusOK, IssuerRevision: "vault-pki-1", CRLDER: fixture.crl,
		CRLThisUpdate: fixture.crlThis.Format(time.RFC3339Nano), CRLNextUpdate: fixture.crlNext.Format(time.RFC3339Nano)}, fixture.controllerID, fixture.controllerPriv)
	if err != nil || response.Validate(request, fixture.policy, fixture.controllerID, fixture.controllerPub, fixture.now) != nil {
		t.Fatalf("revocation snapshot = %#v, %v", response, err)
	}
	revoke, err := NewRevokeRequest(fixture.policy, "request-revoke-1", nonce(2), fixture.now.Add(30*time.Second), fixture.serial, fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := NewResponse(revoke, Response{Type: RevokedType, Status: StatusOK, IssuerRevision: "vault-pki-2", Serial: fixture.serial, Revoked: true}, fixture.controllerID, fixture.controllerPriv)
	if err != nil || revoked.Validate(revoke, fixture.policy, fixture.controllerID, fixture.controllerPub, fixture.now) != nil {
		t.Fatalf("revoke response = %#v, %v", revoked, err)
	}
}

func TestProtocolRejectsSubstitutionAndNonCanonicalDocuments(t *testing.T) {
	fixture := newProtocolFixture(t)
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	request, err := NewIssueRequest(fixture.policy, "request-issue-1", nonce, fixture.now.Add(30*time.Second), 10*time.Minute, fixture.csr, fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Request){
		"agent":            func(value *Request) { value.AgentID = "provider_tls_agent" },
		"requester digest": func(value *Request) { value.RequesterDigest = "sha256:" + strings.Repeat("0", 64) },
		"policy":           func(value *Request) { value.PolicyID = "provider-runtime-tls" },
		"principal":        func(value *Request) { value.Principal = "provider" },
		"subject digest":   func(value *Request) { value.SubjectDigest = "sha256:" + strings.Repeat("0", 64) },
		"ttl":              func(value *Request) { value.RequestedTTLSeconds = fixture.policy.MaxTTLSeconds + 1 },
		"digest":           func(value *Request) { value.RequestDigest = "sha256:" + strings.Repeat("0", 64) },
		"signature": func(value *Request) {
			value.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.CSRPEM = append([]byte(nil), request.CSRPEM...)
			mutate(&candidate)
			if candidate.Validate(fixture.policy, fixture.now) == nil {
				t.Fatal("substitution was accepted")
			}
		})
	}
	document, _ := json.Marshal(request)
	duplicate := append([]byte(`{"protocol":"sandbox-runtime.workload-certificate.v1",`), document[1:]...)
	unknown := append([]byte(`{"unknown":true,`), document[1:]...)
	for _, candidate := range [][]byte{duplicate, unknown, append(document, '\n')} {
		if _, _, err := DecodeRequest(candidate, map[string]Policy{fixture.policy.ID: fixture.policy}, fixture.now); err == nil {
			t.Fatal("non-canonical request was accepted")
		}
	}
}

func TestPolicyRejectsWildcardIdentityAndBroadTTL(t *testing.T) {
	fixture := newProtocolFixture(t)
	for name, mutate := range map[string]func(*Policy){
		"wildcard": func(policy *Policy) { policy.DNSNames = []string{"*.example.test"} },
		"ttl":      func(policy *Policy) { policy.MaxTTLSeconds = 3601 },
		"uri":      func(policy *Policy) { policy.URI = "spiffe://other.test/product-runtime" },
		"usage":    func(policy *Policy) { policy.Usages = []string{"any"} },
		"key":      func(policy *Policy) { policy.PublicKey = nil },
		"controller impersonation": func(policy *Policy) {
			policy.Requester, _ = policy.Registry.New(securityprincipal.KindController, "certificate_controller", "", "sha256:"+strings.Repeat("e", 64))
		},
		"migration job requester": func(policy *Policy) {
			policy.Requester, _ = policy.Registry.New(securityprincipal.KindMigrationJob, "product_migration", securityprincipal.RoleProduct, "sha256:"+strings.Repeat("e", 64))
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := fixture.policy
			mutate(&policy)
			if policy.Validate() == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}
}
