package phase6terminalcleanup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

type fakeRemote struct {
	observed        map[string]TokenObservation
	absent          map[string]bool
	issuerDER       []byte
	crlDER          []byte
	lookupErr       error
	certErr         error
	tokenErr        error
	selfErr         error
	certCalls       int
	tokenCalls      int
	selfCalls       int
	missingReadback bool
}

func (f *fakeRemote) LookupAccessor(_ context.Context, accessor string) (TokenObservation, error) {
	if f.lookupErr != nil {
		return TokenObservation{}, f.lookupErr
	}
	if f.absent[accessor] {
		if f.missingReadback {
			return TokenObservation{}, errors.New("404 is not revocation proof")
		}
		return TokenObservation{}, ErrAccessorAbsent
	}
	return f.observed[accessor], nil
}
func (f *fakeRemote) RevokeAccessor(_ context.Context, accessor string) error {
	f.tokenCalls++
	if f.tokenErr == nil {
		f.absent[accessor] = true
	}
	return f.tokenErr
}
func (f *fakeRemote) RevokeCertificate(context.Context, string) error {
	f.certCalls++
	return f.certErr
}
func (f *fakeRemote) ReadCompleteCRL(context.Context, string) ([]byte, []byte, error) {
	return append([]byte(nil), f.issuerDER...), append([]byte(nil), f.crlDER...), nil
}
func (f *fakeRemote) RevokeSelf(context.Context) error {
	f.selfCalls++
	return f.selfErr
}

func executeFixture(t *testing.T) (Plan, *fakeRemote, time.Time) {
	t.Helper()
	runID, profile, sources, certificateLedger, credentialLedger, now := terminalPlanFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "terminal-test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]x509.RevocationListEntry, 0, len(certificateLedger.Certificates))
	for _, record := range certificateLedger.Certificates {
		value, decodeErr := hex.DecodeString(strings.ReplaceAll(record.Serial, ":", ""))
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: new(big.Int).SetBytes(value), RevocationTime: now.Add(-time.Minute)})
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(10 * time.Minute), RevokedCertificateEntries: entries}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(issuerDER)
	sources.Sources[0].IssuerDigest = "sha256:" + hex.EncodeToString(digest[:])
	certificateDocument, _ := json.Marshal(certificateLedger)
	credentialDocument, _ := json.Marshal(credentialLedger)
	plan, err := buildVerified(runID, profile, sources, certificateDocument, credentialDocument, "accessor-management", now)
	if err != nil || plan.Validate() != nil {
		t.Fatalf("test plan = %v", err)
	}
	certificateToken := plan.Tokens[0]
	managementToken := plan.Tokens[1]
	remote := &fakeRemote{issuerDER: issuerDER, crlDER: crlDER, absent: make(map[string]bool),
		observed: map[string]TokenObservation{
			certificateToken.Accessor: {Accessor: certificateToken.Accessor, Policies: []string{certificateToken.BackendPolicy},
				Role: workloadcredential.Phase6TokenRole(certificateToken.BackendPolicy), Type: "service", TTLSeconds: 300,
				Metadata: map[string]string{"subject_id": "certificate_controller", "subject_digest": certificateToken.PrincipalDigest,
					"policy_id": "credential-certificate-controller", "policy_digest": certificateToken.PolicyDigest,
					"binding_digest": certificateToken.BindingDigest, "purpose": "workload_credential", "lease_id": certificateToken.LeaseID}},
			managementToken.Accessor: {Accessor: managementToken.Accessor, Policies: []string{managementToken.BackendPolicy},
				Type: "service", Orphan: true, TTLSeconds: 300,
				Metadata: map[string]string{"run_id": plan.RunID, "profile_digest": plan.ProfileDigest,
					"owner_digest": managementToken.PrincipalDigest}},
		}}
	return plan, remote, now
}

func TestExecuteRequiresEveryRemoteReadbackBeforeSelfRevoke(t *testing.T) {
	plan, remote, now := executeFixture(t)
	receipt, err := Execute(context.Background(), plan, remote, func() time.Time { return now })
	if err != nil || !receipt.Complete || !receipt.SelfRevoked || receipt.IssuerCRLSHA == "" ||
		remote.certCalls != 2 || remote.tokenCalls != 2 || remote.selfCalls != 1 {
		t.Fatalf("terminal execution = %+v, %v; calls=%d/%d/%d", receipt, err, remote.certCalls, remote.tokenCalls, remote.selfCalls)
	}
	for _, value := range append(receipt.Certificates, receipt.Tokens...) {
		if !value.Confirmed || !digestPattern.MatchString(value.TargetDigest) {
			t.Fatalf("unconfirmed target = %+v", value)
		}
	}
	for name, mutate := range map[string]func(*fakeRemote){
		"lookup forbidden":        func(f *fakeRemote) { f.lookupErr = errors.New("403") },
		"wrong metadata":          func(f *fakeRemote) { f.observed[plan.Tokens[0].Accessor].Metadata["lease_id"] = "other" },
		"certificate revoke loss": func(f *fakeRemote) { f.certErr = errors.New("timeout") },
		"CRL missing serial":      func(f *fakeRemote) { f.crlDER = nil },
		"token revoke loss":       func(f *fakeRemote) { f.tokenErr = errors.New("timeout") },
		"404 readback":            func(f *fakeRemote) { f.missingReadback = true },
		"self revoke loss":        func(f *fakeRemote) { f.selfErr = errors.New("timeout") },
	} {
		t.Run(name, func(t *testing.T) {
			value, fake, moment := executeFixture(t)
			mutate(fake)
			observed, executeErr := Execute(context.Background(), value, fake, func() time.Time { return moment })
			if !errors.Is(executeErr, ErrInvalid) || observed.Complete || observed.SelfRevoked ||
				(name != "self revoke loss" && fake.selfCalls != 0) {
				t.Fatalf("failed cleanup falsely accepted: %+v, %v, self=%d", observed, executeErr, fake.selfCalls)
			}
		})
	}
}
