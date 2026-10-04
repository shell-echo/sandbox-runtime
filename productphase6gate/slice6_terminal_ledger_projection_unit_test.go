//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func slice6TerminalProjectionFixture(t *testing.T) (phase6terminalcleanup.Plan, []byte, []byte, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	now := time.Now().UTC()
	runID := strings.Repeat("a", 32)
	profileDigest := "sha256:" + strings.Repeat("b", 64)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "projection-test"},
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
	uri, err := url.Parse("spiffe://sandbox-runtime.test/external/postgres")
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		NotBefore: now.Add(-2 * time.Minute), NotAfter: now.Add(28 * time.Minute),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{uri}, DNSNames: []string{"postgres.sandbox-runtime.test"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerSHA, leafSHA := sha256.Sum256(issuerDER), sha256.Sum256(leafDER)
	issuerDigest := "sha256:" + hex.EncodeToString(issuerSHA[:])
	leafDigest := "sha256:" + hex.EncodeToString(leafSHA[:])
	record, err := phase6terminalcleanup.SealExternalPostgresRecord(phase6terminalcleanup.ExternalPostgresRecord{
		Protocol: phase6terminalcleanup.ExternalPostgresRecordProtocol,
		RunID:    runID, ProfileDigest: profileDigest,
		IssuerID: "00000000-0000-0000-0000-000000000001", IssuerDigest: issuerDigest,
		URI: uri.String(), DNSName: "postgres.sandbox-runtime.test",
		Serial: "01:02:03:04:05:06:07:08", LeafDigest: leafDigest,
		MountedLeafDigest: leafDigest,
		CertificatePEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		IssuerPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}),
		SignedAt:          now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	quiesced := now.Add(-20 * time.Second)
	issued := now.Add(-2 * time.Minute)
	revoked := now.Add(-30 * time.Second)
	serial := func(digit string) string { return strings.TrimSuffix(strings.Repeat(digit+digit+":", 8), ":") }
	certificate := workloadpki.Ledger{Schema: workloadpki.LedgerSchema, Revision: 5, QuiescedAt: &quiesced,
		Certificates: []workloadpki.CertificateRecord{
			{PolicyID: "certificate-controller-vault", AgentID: "certificate-controller",
				RequesterDigest: "sha256:" + strings.Repeat("c", 64), Principal: "certificate-controller",
				SubjectDigest: "sha256:" + strings.Repeat("c", 64), Serial: serial("a"),
				CertificateDigest: "sha256:" + strings.Repeat("1", 64), IssuedAt: issued,
				NotBefore: issued.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), State: "active"},
			{PolicyID: "credential-controller-vault", AgentID: "workload-credential-controller",
				RequesterDigest: "sha256:" + strings.Repeat("d", 64), Principal: "workload-credential-controller",
				SubjectDigest: "sha256:" + strings.Repeat("d", 64), Serial: serial("b"),
				CertificateDigest: "sha256:" + strings.Repeat("2", 64), IssuedAt: issued,
				NotBefore: issued.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), State: "active"},
			{PolicyID: "guest-tls", AgentID: "guest-tls-agent",
				RequesterDigest: "sha256:" + strings.Repeat("e", 64), Principal: "guest-runtime",
				SubjectDigest: "sha256:" + strings.Repeat("f", 64), Serial: serial("c"),
				CertificateDigest: "sha256:" + strings.Repeat("3", 64), IssuedAt: issued,
				NotBefore: issued.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
				RevokedAt: revoked, State: "revoked"},
		}}
	credential := workloadcredentialv2.Ledger{Schema: workloadcredentialv2.LedgerSchema,
		Revision: 4, QuiescedAt: &quiesced,
		Leases: []workloadcredentialv2.LeaseRecord{
			{PolicyID: "credential-certificate-controller", PrincipalDigest: "sha256:" + strings.Repeat("c", 64),
				PolicyDigest: "sha256:" + strings.Repeat("4", 64), BindingDigest: "sha256:" + strings.Repeat("5", 64),
				CredentialDigest: "sha256:" + strings.Repeat("6", 64),
				LeaseID:          "lease2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BackendLeaseID: "accessor-certificate",
				IssuedAt: issued, ExpiresAt: now.Add(10 * time.Minute), Revision: 1, State: "active"},
			{PolicyID: "other-credential", PrincipalDigest: "sha256:" + strings.Repeat("e", 64),
				PolicyDigest: "sha256:" + strings.Repeat("7", 64), BindingDigest: "sha256:" + strings.Repeat("8", 64),
				CredentialDigest: "sha256:" + strings.Repeat("9", 64),
				LeaseID:          "lease2_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", BackendLeaseID: "accessor-other-sensitive",
				IssuedAt: issued, ExpiresAt: now.Add(10 * time.Minute), RevokedAt: revoked,
				Revision: 2, State: "revoked"},
		}}
	certificateRaw, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	credentialRaw, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	plan := phase6terminalcleanup.Plan{Protocol: phase6terminalcleanup.ProtocolV2ID,
		RunID: runID, ProfileDigest: profileDigest,
		CertificateLedgerSHA: slice6ReceiptSHA256(certificateRaw),
		CredentialLedgerSHA:  slice6ReceiptSHA256(credentialRaw),
		GeneralIssuerID:      record.IssuerID, GeneralIssuerDigest: record.IssuerDigest,
		Certificates: []phase6terminalcleanup.CertificateTarget{
			{PolicyID: "certificate-controller-vault", Serial: serial("a"),
				SubjectDigest: "sha256:" + strings.Repeat("c", 64), State: "active"},
			{PolicyID: "credential-controller-vault", Serial: serial("b"),
				SubjectDigest: "sha256:" + strings.Repeat("d", 64), State: "active"},
			{Kind: "external-postgres-server", PolicyID: "external-postgres-server",
				Serial: record.Serial, SubjectDigest: record.LeafDigest, State: "active"},
		},
		Tokens: []phase6terminalcleanup.TokenTarget{
			{Kind: "certificate-controller", Accessor: "accessor-certificate",
				PrincipalDigest: "sha256:" + strings.Repeat("c", 64),
				LeaseID:         credential.Leases[0].LeaseID, PolicyDigest: credential.Leases[0].PolicyDigest,
				BindingDigest: credential.Leases[0].BindingDigest,
				BackendPolicy: "certificate-controller-pki", State: "active"},
			{Kind: "credential-management", Accessor: "accessor-management",
				PrincipalDigest: "sha256:" + strings.Repeat("d", 64),
				BackendPolicy:   "phase6-credential-management", State: "active"},
		}, ExternalPostgres: &record}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-terminal-cleanup-plan/v2\x00"), encoded...))
	plan.Digest = "sha256:" + hex.EncodeToString(digest[:])
	if err := plan.Validate(); err != nil {
		t.Fatalf("synthetic exact v2 projection plan invalid: %v", err)
	}
	return plan, certificateRaw, credentialRaw, issuerKey, issuerDER
}

func TestSlice6TerminalLedgerProjectionBindsTwoOriginalReadsNoIssuer(t *testing.T) {
	plan, certificateRaw, credentialRaw, _, _ := slice6TerminalProjectionFixture(t)
	projectionRaw, err := slice6ProjectTerminalLedgers(plan, certificateRaw, credentialRaw)
	if err != nil || slice6VerifyTerminalLedgerProjection(plan, projectionRaw) != nil {
		t.Fatalf("terminal ledger projection unavailable: %v", err)
	}
	for _, sensitive := range []string{"accessor-certificate", "accessor-other-sensitive",
		"lease2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "lease2_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"} {
		if bytes.Contains(projectionRaw, []byte(sensitive)) {
			t.Fatal("private ledger identifier copied to retained projection")
		}
	}
	var projection slice6TerminalLedgerProjection
	if json.Unmarshal(projectionRaw, &projection) != nil || len(projection.Certificate.Records) != 3 ||
		len(projection.Credential.Records) != 2 ||
		projection.Certificate.RawSHA256 != plan.CertificateLedgerSHA ||
		projection.Credential.RawSHA256 != plan.CredentialLedgerSHA {
		t.Fatal("projection dropped source-bound lease or certificate state")
	}
	mutate := func(change func(*slice6TerminalLedgerProjection)) []byte {
		copy := projection
		copy.Certificate.Records = append([]slice6ProjectedCertificate(nil), projection.Certificate.Records...)
		copy.Credential.Records = append([]slice6ProjectedCredential(nil), projection.Credential.Records...)
		change(&copy)
		encoded, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for name, raw := range map[string][]byte{
		"nonterminal certificate active": mutate(func(value *slice6TerminalLedgerProjection) {
			value.Certificate.Records[2].State = "active"
			value.Certificate.Records[2].RevokedAt = time.Time{}
		}),
		"nonterminal lease active": mutate(func(value *slice6TerminalLedgerProjection) {
			value.Credential.Records[1].State = "active"
			value.Credential.Records[1].RevokedAt = time.Time{}
		}),
		"original certificate SHA drift": mutate(func(value *slice6TerminalLedgerProjection) {
			value.Certificate.RawSHA256 = "sha256:" + strings.Repeat("0", 64)
		}),
		"original credential SHA drift": mutate(func(value *slice6TerminalLedgerProjection) {
			value.Credential.RawSHA256 = "sha256:" + strings.Repeat("0", 64)
		}),
		"plan binding drift": mutate(func(value *slice6TerminalLedgerProjection) {
			value.PlanDigest = "sha256:" + strings.Repeat("0", 64)
		}),
		"terminal accessor drift": mutate(func(value *slice6TerminalLedgerProjection) {
			value.Credential.Records[0].BackendAccessorDigest = "sha256:" + strings.Repeat("0", 64)
		}),
		"pending previous accessor": mutate(func(value *slice6TerminalLedgerProjection) {
			value.Credential.Records[1].PreviousAccessorDigest = "sha256:" + strings.Repeat("0", 64)
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if slice6VerifyTerminalLedgerProjection(plan, raw) == nil {
				t.Fatal("terminal ledger projection drift accepted")
			}
		})
	}
	unknown := append([]byte(`{"extra_sensitive_accessor":"forbidden",`), projectionRaw[1:]...)
	if slice6VerifyTerminalLedgerProjection(plan, unknown) == nil {
		t.Fatal("unknown sensitive projection field accepted")
	}
	if _, err := slice6ProjectTerminalLedgers(plan, certificateRaw, []byte(`{"leak":"sensitive"}`)); err == nil {
		t.Fatal("credential ledger byte mismatch accepted")
	}
}

func TestSlice6TerminalEIssuedSetRejectsMissingExtraAndWrongLaunchRole(t *testing.T) {
	plan, certificateRaw, credentialRaw, _, _ := slice6TerminalProjectionFixture(t)
	projectionRaw, err := slice6ProjectTerminalLedgers(plan, certificateRaw, credentialRaw)
	if err != nil {
		t.Fatal(err)
	}
	var projection slice6TerminalLedgerProjection
	if err := json.Unmarshal(projectionRaw, &projection); err != nil {
		t.Fatal(err)
	}
	expected := slice6ExpectedEIssuedSet{certificates: make(map[string]slice6ExpectedECertificate),
		credentials: make(map[string]string)}
	for _, record := range projection.Certificate.Records {
		expected.certificates[record.PolicyID] = slice6ExpectedECertificate{
			agent: record.AgentID, requesterDigest: record.RequesterDigest,
			principal: record.Principal, subjectDigest: record.SubjectDigest}
	}
	for _, record := range projection.Credential.Records {
		expected.credentials[record.PolicyID] = record.PrincipalDigest
	}
	if err := slice6VerifyTerminalEIssuedSetCore(projection, expected); err != nil {
		t.Fatalf("exact synthetic issued set rejected: %v", err)
	}
	for name, change := range map[string]func(*slice6TerminalLedgerProjection){
		"missing certificate": func(value *slice6TerminalLedgerProjection) {
			value.Certificate.Records = value.Certificate.Records[:2]
		},
		"extra credential": func(value *slice6TerminalLedgerProjection) {
			value.Credential.Records = append(value.Credential.Records, value.Credential.Records[1])
		},
		"wrong launch role": func(value *slice6TerminalLedgerProjection) {
			value.Certificate.Records[2].AgentID = "optional-tls-agent"
		},
		"wrong material principal": func(value *slice6TerminalLedgerProjection) {
			value.Credential.Records[1].PrincipalDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"unrevoked ordinary signer": func(value *slice6TerminalLedgerProjection) {
			value.Certificate.Records[2].State = "active"
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := projection
			copy.Certificate.Records = append([]slice6ProjectedCertificate(nil), projection.Certificate.Records...)
			copy.Credential.Records = append([]slice6ProjectedCredential(nil), projection.Credential.Records...)
			change(&copy)
			if slice6VerifyTerminalEIssuedSetCore(copy, expected) == nil {
				t.Fatal("E accepted a record outside the fixed launch set")
			}
		})
	}
}
