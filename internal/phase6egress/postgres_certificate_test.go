package phase6egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func postgresCertificateFixture(t *testing.T, now time.Time, commonName, uri string,
	usage x509.ExtKeyUsage) (tls.Certificate, *x509.CertPool, workloadpki.PostgresClientIdentity) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "postgres-client-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsedURI, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(9 * time.Minute), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{parsedURI}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	identity := workloadpki.PostgresClientIdentity{OwnerDeployment: "provider-browser-runtime", DatabaseName: "provider_browser",
		RuntimeRole: "browser_provider_runtime", ServiceName: "postgres",
		URI:        "spiffe://sandbox-runtime.test/provider-browser-runtime",
		CommonName: workloadpki.PostgresClientCommonName("browser_provider_runtime"), MaxTTL: 15 * time.Minute}
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}, roots, identity
}

func TestPostgresClientCertificateRequiresExactPurposeIssuerAndLiveSigner(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	identity := workloadpki.PostgresClientIdentity{OwnerDeployment: "provider-browser-runtime", DatabaseName: "provider_browser",
		RuntimeRole: "browser_provider_runtime", ServiceName: "postgres",
		URI:        "spiffe://sandbox-runtime.test/provider-browser-runtime",
		CommonName: workloadpki.PostgresClientCommonName("browser_provider_runtime"), MaxTTL: 15 * time.Minute}
	valid, roots, _ := postgresCertificateFixture(t, now, identity.CommonName, identity.URI, x509.ExtKeyUsageClientAuth)
	if err := validatePostgresClientCertificate(valid, roots, identity, now); err != nil {
		t.Fatalf("valid PostgreSQL client certificate: %v", err)
	}
	callback, err := newPostgresClientCertificate(context.Background(), roots, identity,
		func(context.Context) (tls.Certificate, error) { return valid, nil }, func() time.Time { return now })
	if err != nil || callback == nil {
		t.Fatalf("PostgreSQL certificate bootstrap: %v", err)
	}
	if _, err := callback(nil); err == nil {
		t.Fatal("missing TLS certificate request accepted")
	}
	type candidate struct {
		certificate tls.Certificate
		roots       *x509.CertPool
	}
	for name, value := range map[string]candidate{
		"wrong common name": func() candidate {
			item, ownRoots, _ := postgresCertificateFixture(t, now, "ordinary-provider", identity.URI, x509.ExtKeyUsageClientAuth)
			return candidate{item, ownRoots}
		}(),
		"cross owner URI": func() candidate {
			item, ownRoots, _ := postgresCertificateFixture(t, now, identity.CommonName,
				"spiffe://sandbox-runtime.test/provider-desktop-runtime", x509.ExtKeyUsageClientAuth)
			return candidate{item, ownRoots}
		}(),
		"server purpose": func() candidate {
			item, ownRoots, _ := postgresCertificateFixture(t, now, identity.CommonName, identity.URI, x509.ExtKeyUsageServerAuth)
			return candidate{item, ownRoots}
		}(),
		"missing signer": func() candidate {
			item := valid
			item.PrivateKey = nil
			return candidate{item, roots}
		}(),
		"wrong signer": func() candidate {
			item := valid
			key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			item.PrivateKey = key
			return candidate{item, roots}
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if validatePostgresClientCertificate(value.certificate, value.roots, identity, now) == nil {
				t.Fatal("unbound PostgreSQL certificate accepted")
			}
		})
	}
	other, _, _ := postgresCertificateFixture(t, now, identity.CommonName, identity.URI, x509.ExtKeyUsageClientAuth)
	if validatePostgresClientCertificate(other, roots, identity, now) == nil {
		t.Fatal("certificate from an unpinned issuer accepted")
	}
	if validatePostgresClientCertificate(valid, roots, identity, now.Add(16*time.Minute)) == nil {
		t.Fatal("expired PostgreSQL certificate accepted")
	}
}
