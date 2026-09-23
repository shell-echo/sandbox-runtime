package workloadpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

type crlTestMaterial struct {
	issuerDER []byte
	leafDER   []byte
	snapshot  RevocationSnapshot
}

func newCRLTestMaterial(t *testing.T, now time.Time, serial int64, revoked bool) crlTestMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(serial + 1000),
		Subject: pkix.Name{CommonName: "CRL issuer"}, SubjectKeyId: []byte{1, 2, 3, byte(serial)},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &key.PublicKey, key)
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
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "peer"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	list := &x509.RevocationList{Number: big.NewInt(7), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(5 * time.Minute)}
	if revoked {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(serial), RevocationTime: now.Add(-time.Second)}}
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, list, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	return crlTestMaterial{issuerDER: issuerDER, leafDER: leafDER,
		snapshot: RevocationSnapshot{IssuerRevision: "vault-crl-untrusted-label", DER: crlDER,
			ThisUpdate: parsed.ThisUpdate, NextUpdate: parsed.NextUpdate}}
}

func TestVerifiedCRLBindsIssuerSignatureSerialAndValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := newCRLTestMaterial(t, now, 42, true)
	verified, err := VerifyCRLForIssuer(first.snapshot, first.issuerDER, now)
	if err != nil {
		t.Fatalf("verify correct issuer CRL: %v", err)
	}
	if verified.IssuerDigest() == "" || verified.CRLDigest() == "" || verified.Number().Cmp(big.NewInt(7)) != 0 {
		t.Fatal("verified CRL did not preserve full issuer/content/number binding")
	}
	if err := verified.CheckPeer(first.leafDER, first.issuerDER, now); !errors.Is(err, ErrPeerRevoked) {
		t.Fatalf("revoked peer accepted: %v", err)
	}
	second := newCRLTestMaterial(t, now, 42, false)
	if _, err := VerifyCRLForIssuer(first.snapshot, second.issuerDER, now); err == nil {
		t.Fatal("CRL accepted under a different issuer with the same serial")
	}
	if err := verified.CheckPeer(second.leafDER, second.issuerDER, now); err == nil {
		t.Fatal("same serial under another issuer inherited the first issuer's status")
	}
	other, err := VerifyCRLForIssuer(second.snapshot, second.issuerDER, now)
	if err != nil || other.CheckPeer(second.leafDER, second.issuerDER, now) != nil {
		t.Fatalf("correct independent issuer rejected: %v", err)
	}
	if _, err := VerifyCRLForIssuer(first.snapshot, first.issuerDER, first.snapshot.NextUpdate); err == nil {
		t.Fatal("expired CRL accepted")
	}
	changedTime := first.snapshot
	changedTime.ThisUpdate = changedTime.ThisUpdate.Add(time.Second)
	if _, err := VerifyCRLForIssuer(changedTime, first.issuerDER, now); err == nil {
		t.Fatal("metadata/CRL time mismatch accepted")
	}
}
