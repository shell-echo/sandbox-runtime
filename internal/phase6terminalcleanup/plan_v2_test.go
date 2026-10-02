package phase6terminalcleanup

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func terminalV2Fixture(t *testing.T) (Plan, *fakeRemote, ExternalPostgresRecord, time.Time, *ecdsa.PrivateKey) {
	t.Helper()
	runID, profile, sources, certificateLedger, credentialLedger, now := terminalPlanFixture(t)
	profile.External = []phase6security.ExternalService{{Name: "postgres", URI: externalPostgresURI,
		DNSNames: []string{externalPostgresDNS}}}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "terminal-v2-test-general"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4}}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate,
		&issuerKey.PublicKey, issuerKey)
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
	uri, err := url.Parse(externalPostgresURI)
	if err != nil {
		t.Fatal(err)
	}
	leafSerial := new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	leafTemplate := &x509.Certificate{SerialNumber: leafSerial,
		NotBefore: now.Add(-2 * time.Minute), NotAfter: now.Add(28 * time.Minute),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{uri}, DNSNames: []string{externalPostgresDNS}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerHash, leafHash := sha256.Sum256(issuerDER), sha256.Sum256(leafDER)
	sources.Sources[0].IssuerDigest = "sha256:" + hex.EncodeToString(issuerHash[:])
	record, err := SealExternalPostgresRecord(ExternalPostgresRecord{
		Protocol: ExternalPostgresRecordProtocol, RunID: runID, ProfileDigest: profile.ProfileDigest,
		IssuerID: sources.Sources[0].IssuerID, IssuerDigest: sources.Sources[0].IssuerDigest,
		URI: externalPostgresURI, DNSName: externalPostgresDNS,
		Serial: "01:02:03:04:05:06:07:08", LeafDigest: "sha256:" + hex.EncodeToString(leafHash[:]),
		MountedLeafDigest: "sha256:" + hex.EncodeToString(leafHash[:]),
		CertificatePEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		IssuerPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}),
		SignedAt:          now.Add(-time.Minute),
	})
	if err != nil || record.Validate(profile, sources, now) != nil {
		t.Fatal("construct exact external PostgreSQL fixture")
	}
	certificateJSON, _ := json.Marshal(certificateLedger)
	credentialJSON, _ := json.Marshal(credentialLedger)
	plan, err := buildVerifiedV2(runID, profile, sources, certificateJSON, credentialJSON,
		"accessor-management", record, now)
	if err != nil || plan.Validate() != nil {
		t.Fatal("build exact v2 terminal plan")
	}
	_, remote, _ := executeFixture(t)
	remote.issuerDER = issuerDER
	remote.crlDER = terminalV2CRL(t, now, issuer, issuerKey, true)
	return plan, remote, record, now, issuerKey
}

func terminalV2CRL(t *testing.T, now time.Time, issuer *x509.Certificate,
	key *ecdsa.PrivateKey, includeExternal bool) []byte {
	t.Helper()
	serials := [][]byte{{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
		{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}}
	if includeExternal {
		serials = append(serials, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	}
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, serial := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: new(big.Int).SetBytes(serial),
			RevocationTime: now.Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(10 * time.Minute),
		RevokedCertificateEntries: entries}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestTerminalV2RequiresExactExternalCertificateAndCRL(t *testing.T) {
	plan, remote, _, now, _ := terminalV2Fixture(t)
	receipt, err := Execute(context.Background(), plan, remote, func() time.Time { return now })
	if err != nil || !receipt.Complete || !receipt.SelfRevoked ||
		receipt.Protocol != "sandbox-runtime.phase6-terminal-cleanup-receipt.v2" ||
		len(receipt.Certificates) != 3 || receipt.Certificates[2].Kind != externalPostgresKind ||
		!receipt.Certificates[2].Confirmed || remote.certCalls != 3 ||
		remote.tokenCalls != 2 || remote.selfCalls != 1 || VerifyReceipt(plan, receipt) != nil {
		t.Fatalf("terminal v2 receipt/calls = %+v, %v, %d/%d/%d", receipt, err,
			remote.certCalls, remote.tokenCalls, remote.selfCalls)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	canonicalLine := append(encoded, '\n')
	decoded, err := DecodeReceipt(canonicalLine)
	if err != nil || VerifyReceipt(plan, decoded) != nil {
		t.Fatal("exact v2 operator receipt line rejected")
	}
	for name, document := range map[string][]byte{
		"missing newline": encoded,
		"trailing line":   append(append([]byte(nil), canonicalLine...), '\n'),
		"unknown field":   append(bytes.Replace(encoded, []byte(`"protocol":`), []byte(`"unknown":1,"protocol":`), 1), '\n'),
		"duplicate field": append(bytes.Replace(encoded, []byte(`"protocol":`), []byte(`"protocol":"duplicate","protocol":`), 1), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReceipt(document); err == nil {
				t.Fatal("noncanonical v2 receipt line accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Receipt){
		"downgrade receipt":            func(r *Receipt) { r.Protocol = "sandbox-runtime.phase6-terminal-cleanup-receipt.v1" },
		"missing external receipt":     func(r *Receipt) { r.Certificates = r.Certificates[:2] },
		"duplicate external receipt":   func(r *Receipt) { r.Certificates[2] = r.Certificates[0] },
		"unconfirmed external receipt": func(r *Receipt) { r.Certificates[2].Confirmed = false },
		"wrong external digest":        func(r *Receipt) { r.Certificates[2].TargetDigest = r.Certificates[1].TargetDigest },
	} {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			changed.Certificates = append([]TargetResult(nil), receipt.Certificates...)
			mutate(&changed)
			if VerifyReceipt(plan, changed) == nil {
				t.Fatal("inexact v2 receipt accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Plan){
		"downgrade":        func(p *Plan) { p.Protocol = ProtocolID },
		"missing external": func(p *Plan) { p.ExternalPostgres = nil },
		"missing target":   func(p *Plan) { p.Certificates = p.Certificates[:2] },
		"duplicate target": func(p *Plan) { p.Certificates[2] = p.Certificates[0] },
		"wrong kind":       func(p *Plan) { p.Certificates[2].Kind = "certificate" },
		"wrong serial":     func(p *Plan) { p.ExternalPostgres.Serial = strings.Repeat("ab:", 7) + "ab" },
		"wrong issuer":     func(p *Plan) { p.ExternalPostgres.IssuerID = "00000000-0000-0000-0000-000000000002" },
		"wrong leaf":       func(p *Plan) { p.ExternalPostgres.LeafDigest = "sha256:" + strings.Repeat("a", 64) },
		"wrong URI":        func(p *Plan) { p.ExternalPostgres.URI = "spiffe://sandbox-runtime.test/external/vault" },
		"wrong DNS":        func(p *Plan) { p.ExternalPostgres.DNSName = "wrong.sandbox-runtime.test" },
		"wrong mount":      func(p *Plan) { p.ExternalPostgres.MountedLeafDigest = "sha256:" + strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			mutated, _, _, _, _ := terminalV2Fixture(t)
			mutate(&mutated)
			if mutated.Validate() == nil {
				t.Fatal("invalid v2 plan accepted")
			}
		})
	}
	// Even a valid signed target cannot be confirmed by physical removal or a
	// CRL that contains only the original two controller serials.
	plan, remote, _, now, issuerKey := terminalV2Fixture(t)
	issuer, err := x509.ParseCertificate(remote.issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	// The complete issuer signs a CRL containing only the original two
	// controller serials; v2 must refuse to self-revoke without the third.
	remote.crlDER = terminalV2CRL(t, now, issuer, issuerKey, false)
	receipt, err = Execute(context.Background(), plan, remote, func() time.Time { return now })
	if !errors.Is(err, ErrInvalid) || receipt.Complete || receipt.FailureStage != "crl-target" || remote.selfCalls != 0 {
		t.Fatalf("unverified third CRL target accepted: %+v, %v", receipt, err)
	}
}

func TestExternalPostgresRecordRejectsResealedSemanticDrift(t *testing.T) {
	plan, _, record, now, _ := terminalV2Fixture(t)
	profile := phase6security.Profile{ProfileDigest: plan.ProfileDigest,
		External: []phase6security.ExternalService{{Name: "postgres", URI: externalPostgresURI,
			DNSNames: []string{externalPostgresDNS}}}}
	sources := phase6security.PeerCRLSources{Sources: []phase6security.PeerCRLSource{{
		ID: "general", Mount: "pki", IssuerID: plan.GeneralIssuerID,
		IssuerDigest: plan.GeneralIssuerDigest}}}
	for name, mutate := range map[string]func(*ExternalPostgresRecord){
		"wrong profile":     func(r *ExternalPostgresRecord) { r.ProfileDigest = "sha256:" + strings.Repeat("d", 64) },
		"wrong issuer id":   func(r *ExternalPostgresRecord) { r.IssuerID = "00000000-0000-0000-0000-000000000002" },
		"wrong issuer der":  func(r *ExternalPostgresRecord) { r.IssuerPEM = r.CertificatePEM },
		"wrong serial":      func(r *ExternalPostgresRecord) { r.Serial = "01:02:03:04:05:06:07:09" },
		"wrong leaf digest": func(r *ExternalPostgresRecord) { r.LeafDigest = "sha256:" + strings.Repeat("a", 64) },
		"wrong mount":       func(r *ExternalPostgresRecord) { r.MountedLeafDigest = "sha256:" + strings.Repeat("a", 64) },
		"wrong uri":         func(r *ExternalPostgresRecord) { r.URI = "spiffe://sandbox-runtime.test/external/vault" },
		"wrong dns":         func(r *ExternalPostgresRecord) { r.DNSName = "other.sandbox-runtime.test" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := record
			mutate(&changed)
			changed.Digest = ""
			sealed, err := SealExternalPostgresRecord(changed)
			if err != nil {
				// A malformed record can fail even before semantic validation.
				return
			}
			if sealed.Validate(profile, sources, now) == nil {
				t.Fatal("resealed foreign PostgreSQL record accepted")
			}
		})
	}
}
