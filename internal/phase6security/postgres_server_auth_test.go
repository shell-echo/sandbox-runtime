package phase6security

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestPostgresServerAuthBindsOneClosedProviderHBA(t *testing.T) {
	profile := validProfile()
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	document, err := profile.PostgresServerAuth.RenderProviderHBA(profile.ProviderDatabases)
	if err != nil {
		t.Fatal(err)
	}
	expected := "local all postgres peer\n" +
		"hostssl provider_browser browser_provider_runtime 172.17.0.1/32 scram-sha-256 clientcert=verify-full clientname=CN\n" +
		"hostssl provider_desktop desktop_provider_runtime 172.17.0.1/32 scram-sha-256 clientcert=verify-full clientname=CN\n" +
		"host all all 0.0.0.0/0 reject\n" +
		"host all all ::/0 reject\n"
	if !bytes.Equal(document, []byte(expected)) {
		t.Fatalf("controlled PostgreSQL HBA differs from exact ordered policy:\n%s", document)
	}
	sum := sha256.Sum256(document)
	if profile.PostgresServerAuth.HBADigest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("controlled PostgreSQL HBA raw digest differs")
	}
	for name, mutate := range map[string]func(*Profile){
		"missing policy reference": func(p *Profile) { p.ProviderDatabases[0].ServerAuthPolicyID = "" },
		"other policy reference":   func(p *Profile) { p.ProviderDatabases[1].ServerAuthPolicyID = "other" },
		"wrong HBA digest":         func(p *Profile) { p.PostgresServerAuth.HBADigest = testDigest("other-hba") },
		"wrong HBA artifact":       func(p *Profile) { p.PostgresServerAuth.HBAArtifactID = "../other" },
		"wrong client CA":          func(p *Profile) { p.PostgresServerAuth.ClientCAAnchorID = "internal-client-ca" },
		"wrong server identity":    func(p *Profile) { p.PostgresServerAuth.ServiceIdentityDigest = testDigest("other-pg") },
		"wrong scope":              func(p *Profile) { p.PostgresServerAuth.Scope = "full_service" },
		"broad ingress":            func(p *Profile) { p.PostgresServerAuth.IngressCIDR = "0.0.0.0/0" },
		"unmasked ingress":         func(p *Profile) { p.PostgresServerAuth.IngressCIDR = "172.17.0.3/24" },
		"database drift":           func(p *Profile) { p.ProviderDatabases[0].DatabaseName = "other_browser" },
		"role drift":               func(p *Profile) { p.ProviderDatabases[0].RuntimeRole = "other_browser_role" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validProfile()
			mutate(&candidate)
			candidate.ProfileDigest = candidate.Digest()
			if candidate.Validate() == nil {
				t.Fatal("PostgreSQL server authentication drift was accepted")
			}
		})
	}
	for _, disallowed := range []string{"include", "trust", "verify-ca", "map=", "hostnossl"} {
		if strings.Contains(string(document), disallowed) {
			t.Fatalf("controlled PostgreSQL HBA contains %s", disallowed)
		}
	}
}

func TestPostgresServerAuthChecksActualRawArtifacts(t *testing.T) {
	profile := validProfile()
	hba, err := profile.PostgresServerAuth.RenderProviderHBA(profile.ProviderDatabases)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{CommonName: "postgres-client-ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	var anchor TrustAnchor
	for _, item := range profile.TrustAnchors {
		if item.ID == profile.PostgresServerAuth.ClientCAAnchorID {
			anchor = item
			break
		}
	}
	caSum := sha256.Sum256(ca)
	anchor.BundleDigest = "sha256:" + hex.EncodeToString(caSum[:])
	if err := profile.PostgresServerAuth.VerifyRawServerArtifacts(profile.ProviderDatabases, anchor, hba, ca, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*PostgresServerAuthPolicy, *TrustAnchor, *[]byte, *[]byte, *time.Time){
		"changed HBA": func(_ *PostgresServerAuthPolicy, _ *TrustAnchor, hba, _ *[]byte, _ *time.Time) {
			*hba = append(*hba, ' ')
		},
		"changed CA": func(_ *PostgresServerAuthPolicy, _ *TrustAnchor, _, ca *[]byte, _ *time.Time) {
			*ca = append(*ca, ' ')
		},
		"wrong CA identity": func(_ *PostgresServerAuthPolicy, anchor *TrustAnchor, _, _ *[]byte, _ *time.Time) {
			anchor.ID = "internal-client-ca"
		},
		"expired CA": func(_ *PostgresServerAuthPolicy, _ *TrustAnchor, _, _ *[]byte, now *time.Time) {
			*now = now.Add(2 * time.Hour)
		},
		"wrong policy digest": func(policy *PostgresServerAuthPolicy, _ *TrustAnchor, _, _ *[]byte, _ *time.Time) {
			policy.HBADigest = testDigest("other-hba")
		},
	} {
		t.Run(name, func(t *testing.T) {
			policyCopy, anchorCopy := profile.PostgresServerAuth, anchor
			hbaCopy, caCopy := bytes.Clone(hba), bytes.Clone(ca)
			nowCopy := now
			change(&policyCopy, &anchorCopy, &hbaCopy, &caCopy, &nowCopy)
			if policyCopy.VerifyRawServerArtifacts(profile.ProviderDatabases, anchorCopy, hbaCopy, caCopy, nowCopy) == nil {
				t.Fatal("drifted PostgreSQL server artifact admitted")
			}
		})
	}
}
