package workloadpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func postgresIdentityFixture() PostgresClientIdentity {
	return PostgresClientIdentity{
		OwnerDeployment: "provider-browser-runtime", DatabaseName: "provider_browser",
		RuntimeRole: "browser_provider_runtime", ServiceName: "postgres",
		URI:        "spiffe://sandbox-runtime.test/provider-browser-runtime",
		CommonName: PostgresClientCommonName("browser_provider_runtime"),
		MaxTTL:     time.Hour,
	}
}

func testPostgresCSR(t *testing.T, subject pkix.Name, uri string, dns []string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject, URIs: []*url.URL{parsed}, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func TestPostgresClientIdentityRejectsCrossOwnerAndCallerChosenName(t *testing.T) {
	identity := postgresIdentityFixture()
	if err := identity.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PostgresClientIdentity){
		"owner":    func(i *PostgresClientIdentity) { i.OwnerDeployment = "provider-runtime" },
		"database": func(i *PostgresClientIdentity) { i.DatabaseName = "other-db" },
		"role":     func(i *PostgresClientIdentity) { i.RuntimeRole = "owner*" },
		"service":  func(i *PostgresClientIdentity) { i.ServiceName = "other" },
		"URI":      func(i *PostgresClientIdentity) { i.URI = "spiffe://sandbox-runtime.test/provider-desktop-runtime" },
		"CN":       func(i *PostgresClientIdentity) { i.CommonName = "other_runtime" },
		"TTL":      func(i *PostgresClientIdentity) { i.MaxTTL = 24 * time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := identity
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid PostgreSQL client authority accepted")
			}
		})
	}
}

func TestPostgresClientIdentityRecognizesOnlyNineSharedPoolOwners(t *testing.T) {
	for _, owner := range []string{
		"product-runtime", "gateway-runtime", "provider-runtime",
		"provider-browser-runtime", "provider-desktop-runtime",
		"product-migration-job", "provider-migration-job",
		"provider-browser-migration-job", "provider-desktop-migration-job",
	} {
		identity := postgresIdentityFixture()
		identity.OwnerDeployment = owner
		identity.URI = "spiffe://sandbox-runtime.test/" + owner
		if err := identity.Validate(); err != nil {
			t.Fatalf("reviewed pool owner %s denied: %v", owner, err)
		}
	}
	identity := postgresIdentityFixture()
	identity.OwnerDeployment = "other-migration-job"
	identity.URI = "spiffe://sandbox-runtime.test/other-migration-job"
	if identity.Validate() == nil {
		t.Fatal("unreviewed PostgreSQL pool owner accepted")
	}
}

func TestPostgresClientCSRHasOnlyBoundCNAndURISAN(t *testing.T) {
	identity := postgresIdentityFixture()
	valid, _ := testPostgresCSR(t, pkix.Name{CommonName: identity.CommonName}, identity.URI, nil)
	if err := ValidatePostgresClientCSR(valid, identity); err != nil {
		t.Fatalf("valid PostgreSQL CSR: %v", err)
	}
	for name, input := range map[string]struct {
		subject pkix.Name
		uri     string
		dns     []string
	}{
		"wrong owner URI": {pkix.Name{CommonName: identity.CommonName},
			"spiffe://sandbox-runtime.test/provider-desktop-runtime", nil},
		"wrong CN": {pkix.Name{CommonName: "desktop_provider_runtime"}, identity.URI, nil},
		"extra DN": {pkix.Name{CommonName: identity.CommonName, Organization: []string{"hidden"}}, identity.URI, nil},
		"DNS SAN":  {pkix.Name{CommonName: identity.CommonName}, identity.URI, []string{"example.test"}},
	} {
		t.Run(name, func(t *testing.T) {
			csr, _ := testPostgresCSR(t, input.subject, input.uri, input.dns)
			if ValidatePostgresClientCSR(csr, identity) == nil {
				t.Fatal("CSR authority drift accepted")
			}
		})
	}
	if ValidatePostgresClientCSR(append(valid, []byte("trailing")...), identity) == nil {
		t.Fatal("trailing CSR bytes accepted")
	}
}

func TestPostgresClientLeafRejectsOrdinaryWorkloadCertificate(t *testing.T) {
	identity := postgresIdentityFixture()
	now := time.Now().UTC().Truncate(time.Second)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PG test issuer"},
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
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(identity.URI)
	issue := func(subject pkix.Name, usages []x509.ExtKeyUsage) *x509.Certificate {
		t.Helper()
		template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: subject,
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(20 * time.Minute),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: usages, URIs: []*url.URL{uri}}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, &leafKey.PublicKey, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	if err := ValidatePostgresClientLeaf(issue(pkix.Name{CommonName: identity.CommonName},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}), identity, now); err != nil {
		t.Fatalf("valid dedicated leaf: %v", err)
	}
	for name, leaf := range map[string]*x509.Certificate{
		"ordinary empty Subject": issue(pkix.Name{}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}),
		"server EKU":             issue(pkix.Name{CommonName: identity.CommonName}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
		"extra EKU":              issue(pkix.Name{CommonName: identity.CommonName}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}),
	} {
		t.Run(name, func(t *testing.T) {
			if ValidatePostgresClientLeaf(leaf, identity, now) == nil {
				t.Fatal("non-PG-purpose leaf accepted")
			}
		})
	}
}
