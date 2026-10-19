package phase6security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test-only bridge: complete field validation never changes public admission.
// The emitted local fixture is not an operator permit or production issuer.
func TestHeldPeerTLSFixture(t *testing.T) {
	out := os.Getenv("PEER_FIXTURE_OUTPUT")
	if out == "" {
		t.Skip("explicit private fixture")
	}
	write := func(name string, v any) {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	hash := func(b []byte) string { v := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(v[:]) }
	now := time.Now().UTC().Truncate(time.Second)
	type ca struct {
		PEM, Key, DER []byte
		Cert          *x509.Certificate
		Private       *ecdsa.PrivateKey
	}
	makeCA := func(name string) ca {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256([]byte(name + now.String()))
		x := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "diagnostic-" + name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: h[:20]}
		der, e := x509.CreateCertificate(rand.Reader, x, x, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		kb, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		return ca{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), der, cert, key}
	}
	general, broker := makeCA("general"), makeCA("broker")
	ns := os.Getenv("PEER_FIXTURE_NAMESPACE")
	if len(ns) != 32 {
		t.Fatal("namespace")
	}
	p := testControlSourceProfile(t, ns, "", "", testDigest("unused-diagnostic-source-seal-"+ns))
	p.DockerControl.OperatorBootstrap = testControlTrust(t).DockerControl.OperatorBootstrap
	testControlTrustDirectories(&p, hash(general.PEM))
	for i := range p.External {
		if p.External[i].Name == "dns" {
			p.External[i].DNSClientCA.IssuerDigest = hash(broker.DER)
			p.External[i].DNSClientCA.BundleDigest = hash(broker.PEM)
			p.External[i].IdentityDigest = p.External[i].Digest()
			for j := range p.TrustEdges {
				if p.TrustEdges[j].To == "dns" {
					p.TrustEdges[j].ExternalIdentityDigest = p.External[i].IdentityDigest
				}
			}
		}
	}
	p.ProfileDigest = p.Digest()
	doc, _ := json.Marshal(p)
	if p.validateFields() != nil {
		t.Fatal("profile fields")
	}
	if _, e := ReviewControlBootstrap(doc); e != nil {
		t.Fatal(e)
	}
	if p.Validate() == nil {
		t.Fatal("public hold")
	}
	sources := testPeerCRLSourcesV2(t, p)
	for i := range sources.Sources {
		if sources.Sources[i].ID == "general-peer" {
			sources.Sources[i].IssuerDigest = hash(general.DER)
		}
	}
	if sources.validateV2Fields(p) != nil {
		t.Fatal("complete sources")
	}
	sourceBytes, _ := json.Marshal(sources)
	if _, e := decodePeerCRLSourcesV2Fields(sourceBytes, p, sources.Digest()); e != nil {
		t.Fatal(e)
	}
	authorizer, e := compilePeerCRLAuthorizerV2Fields(p, sources)
	if e != nil {
		t.Fatal(e)
	}
	type pin struct {
		ProfileBytes, SourceBytes, MappingDigest string
		Roles                                    map[string]string
		RoleBytes                                map[string]string
	}
	pins := pin{hash(doc), hash(sourceBytes), sources.Digest(), map[string]string{}, map[string]string{}}
	for _, name := range []string{"provider-runtime", "provider-docker-control"} {
		var local Principal
		for _, v := range p.Principals {
			if v.Name == name {
				local = v
			}
		}
		role, e := derivePeerCRLRoleDocumentV2Fields(p, sources, local.PrincipalDigest)
		if e != nil || role.validateV2Fields(p, sources.Digest()) != nil {
			t.Fatal("role", e)
		}
		for _, b := range role.Edges {
			if _, e := authorizer.AuthorizedSourceID(p.ProfileDigest, sources.Digest(), b.EdgeID, local.PrincipalDigest, b.Direction, b.PeerAnchorID, b.IssuerDigest, ""); e != nil {
				t.Fatal(e)
			}
		}
		b, _ := json.Marshal(role)
		pins.Roles[name] = role.Digest()
		pins.RoleBytes[name] = hash(b)
		write(name+"-role.json", role)
	}
	write("profile.json", p)
	write("sources.json", sources)
	write("pins.json", pins)
	for name, b := range map[string][]byte{"general.pem": general.PEM, "general.key": general.Key, "broker.pem": broker.PEM, "broker.key": broker.Key} {
		if e := os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	makeCRL := func(number int64, expired bool) []byte {
		this, next := now.Add(-time.Second), now.Add(3*time.Hour)
		if expired {
			this, next = now.Add(-2*time.Hour), now.Add(-time.Hour)
		}
		b, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: this, NextUpdate: next}, general.Cert, general.Private)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	for name, b := range map[string][]byte{"baseline.crl": makeCRL(10, false), "rollback.crl": makeCRL(9, false), "expired.crl": makeCRL(11, true)} {
		if e := os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("validation.json", map[string]any{"profile_fields": true, "canonical_sources": true, "complete_two_issuer_edges": true, "role_fields": true, "public_hold": true, "source_kind": "test-only broker/general X509; not Vault", "namespace": ns})
}

func TestHeldPeerTLSRevokedFixture(t *testing.T) {
	dir := os.Getenv("PEER_CRL_OUTPUT")
	if dir == "" {
		t.Skip("explicit fixture")
	}
	cp, e := os.ReadFile(filepath.Join(dir, "general.pem"))
	if e != nil {
		t.Fatal(e)
	}
	cb, _ := pem.Decode(cp)
	cert, e := x509.ParseCertificate(cb.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	kp, e := os.ReadFile(filepath.Join(dir, "general.key"))
	if e != nil {
		t.Fatal(e)
	}
	kb, _ := pem.Decode(kp)
	key, e := x509.ParseECPrivateKey(kb.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	serial, ok := new(big.Int).SetString(strings.ReplaceAll(os.Getenv("PEER_REVOKED_SERIAL"), ":", ""), 16)
	if !ok {
		t.Fatal("serial")
	}
	now := time.Now().UTC().Truncate(time.Second)
	b, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(11), ThisUpdate: now.Add(-time.Second), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: serial, RevocationTime: now.Add(-time.Second)}}}, cert, key)
	if e != nil {
		t.Fatal(e)
	}
	name := os.Getenv("PEER_REVOKED_FILE")
	if filepath.Base(name) != name || name == "" {
		t.Fatal("file")
	}
	if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
		t.Fatal(e)
	}
}
