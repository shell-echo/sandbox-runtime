package workloadtlsagent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func bootstrapPolicy(t *testing.T) workloadpki.Policy {
	t.Helper()
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	registry, err := securityprincipal.NewRegistry(digest("a"), digest("b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.New(securityprincipal.KindController, "certificate_controller", "", digest("c"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return workloadpki.Policy{ID: "certificate-controller-vault-tls", Registry: registry, Requester: principal, Subject: principal,
		TrustDomain: "sandbox-runtime.test", URI: "spiffe://sandbox-runtime.test/certificate-controller",
		DNSNames: []string{"certificate-controller.internal.test"}, Usages: []string{"client_auth"}, VaultRole: "certificate-controller",
		MaxTTLSeconds: 3600, PublicKey: publicKey}
}

func TestValidateBootstrapCertificateAcceptsExactIdentityAndDestroysKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	policy := bootstrapPolicy(t)
	certificatePEM, keyPEM, roots := issueBootstrap(t, now, policy, func(*x509.Certificate) {})
	pair, err := ValidateBootstrapCertificate(certificatePEM, keyPEM, roots, policy, now)
	if err != nil || pair.Leaf == nil {
		t.Fatalf("ValidateBootstrapCertificate() = %#v, %v", pair, err)
	}
	DestroyTLSCertificate(&pair)
	if pair.PrivateKey != nil || pair.Leaf != nil || len(pair.Certificate) != 0 {
		t.Fatal("bootstrap certificate was not destroyed")
	}
}

func TestValidateBootstrapCertificateRejectsIdentityTrustUsageTimeAndKeyMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	policy := bootstrapPolicy(t)
	tests := map[string]func(*x509.Certificate){
		"wrong-uri": func(value *x509.Certificate) {
			value.URIs = []*url.URL{{Scheme: "spiffe", Host: "sandbox-runtime.test", Path: "/other"}}
		},
		"wrong-dns":       func(value *x509.Certificate) { value.DNSNames = []string{"other.internal.test"} },
		"wrong-subject":   func(value *x509.Certificate) { value.Subject = pkix.Name{CommonName: "not-empty"} },
		"wrong-eku":       func(value *x509.Certificate) { value.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"wrong-key-usage": func(value *x509.Certificate) { value.KeyUsage |= x509.KeyUsageKeyEncipherment },
		"not-yet-valid":   func(value *x509.Certificate) { value.NotBefore = now.Add(time.Minute) },
		"expired":         func(value *x509.Certificate) { value.NotAfter = now },
		"ttl-too-long":    func(value *x509.Certificate) { value.NotAfter = value.NotBefore.Add(time.Hour + time.Second) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			certificatePEM, keyPEM, roots := issueBootstrap(t, now, policy, mutate)
			if _, err := ValidateBootstrapCertificate(certificatePEM, keyPEM, roots, policy, now); err == nil {
				t.Fatal("invalid bootstrap certificate accepted")
			}
		})
	}
	certificatePEM, _, roots := issueBootstrap(t, now, policy, func(*x509.Certificate) {})
	_, mismatchedKeyPEM, _ := issueBootstrap(t, now, policy, func(*x509.Certificate) {})
	if _, err := ValidateBootstrapCertificate(certificatePEM, mismatchedKeyPEM, roots, policy, now); err == nil {
		t.Fatal("mismatched private key accepted")
	}
	_, _, wrongRoots := issueBootstrap(t, now, policy, func(*x509.Certificate) {})
	_, keyPEM, _ := issueBootstrap(t, now, policy, func(*x509.Certificate) {})
	if _, err := ValidateBootstrapCertificate(certificatePEM, keyPEM, wrongRoots, policy, now); err == nil {
		t.Fatal("wrong CA or mismatched key accepted")
	}
	if _, err := ValidateBootstrapCertificate(append(certificatePEM, []byte("garbage")...), keyPEM, roots, policy, now); err == nil {
		t.Fatal("trailing certificate data accepted")
	}
}

func issueBootstrap(t *testing.T, now time.Time, policy workloadpki.Policy, mutate func(*x509.Certificate)) ([]byte, []byte, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bootstrap test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse(policy.URI)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Second), NotAfter: now.Add(30 * time.Minute),
		DNSNames: append([]string(nil), policy.DNSNames...), URIs: []*url.URL{identity}, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	mutate(template)
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certificatePEM, keyPEM, roots
}
