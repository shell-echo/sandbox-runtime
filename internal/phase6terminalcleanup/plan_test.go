package phase6terminalcleanup

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func terminalPlanFixture(t *testing.T) (string, phase6security.Profile, phase6security.PeerCRLSources,
	workloadpki.Ledger, workloadcredentialv2.Ledger, time.Time) {
	t.Helper()
	runID := strings.Repeat("a", 32)
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	profile := phase6security.Profile{ProfileDigest: "sha256:" + strings.Repeat("c", 64),
		EnvironmentDigest:      "sha256:" + strings.Repeat("d", 64),
		PrincipalProfileDigest: "sha256:" + strings.Repeat("e", 64)}
	identities, err := phase6security.Slice6DesiredAuthorizationPrincipals(runID,
		profile.EnvironmentDigest, profile.PrincipalProfileDigest)
	if err != nil {
		t.Fatal(err)
	}
	certificate := identities["certificate-controller"]
	credential := identities["workload-credential-controller"]
	profile.Principals = []phase6security.Principal{
		{Name: "certificate-controller", AuthorizationPrincipal: &certificate},
		{Name: "workload-credential-controller", AuthorizationPrincipal: &credential},
	}
	profile.CertificateController = phase6security.CertificateControllerAuthority{
		ManagedPolicyID: "certificate-controller-vault", CredentialController: phase6security.CredentialControllerManagedAuthority{
			PolicyID: "credential-controller-vault"}}
	sources := phase6security.PeerCRLSources{Sources: []phase6security.PeerCRLSource{{ID: "general", Mount: "pki",
		IssuerID: "00000000-0000-0000-0000-000000000001", IssuerDigest: "sha256:" + strings.Repeat("f", 64)}}}
	quiesced := now.Add(-time.Minute)
	issueTime := quiesced.Add(-time.Minute)
	serial := func(character string) string {
		return strings.TrimSuffix(strings.Repeat(character+character+":", 8), ":")
	}
	certificateLedger := workloadpki.Ledger{Schema: workloadpki.LedgerSchema, Revision: 5, QuiescedAt: &quiesced,
		Certificates: []workloadpki.CertificateRecord{
			{Serial: serial("a"), AgentID: certificate.Name, RequesterDigest: certificate.Digest(),
				PolicyID: profile.CertificateController.ManagedPolicyID, Principal: certificate.Name,
				SubjectDigest: certificate.Digest(), IssuerRevision: "vault-pki-1",
				CertificateDigest: "sha256:" + strings.Repeat("1", 64),
				NotBefore:         issueTime.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), IssuedAt: issueTime, State: "active"},
			{Serial: serial("b"), AgentID: credential.Name, RequesterDigest: credential.Digest(),
				PolicyID: profile.CertificateController.CredentialController.PolicyID, Principal: credential.Name,
				SubjectDigest: credential.Digest(), IssuerRevision: "vault-pki-1",
				CertificateDigest: "sha256:" + strings.Repeat("2", 64),
				NotBefore:         issueTime.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), IssuedAt: issueTime, State: "active"},
		}}
	credentialLedger := workloadcredentialv2.Ledger{Schema: workloadcredentialv2.LedgerSchema, Revision: 4, QuiescedAt: &quiesced,
		Leases: []workloadcredentialv2.LeaseRecord{{LeaseID: "lease2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Principal: certificate, PrincipalDigest: certificate.Digest(), Purpose: secretref.PurposeWorkloadCredential,
			PolicyID: "credential-certificate-controller", PolicyDigest: "sha256:" + strings.Repeat("3", 64),
			BackendID: "vault-primary", BackendPolicy: "certificate-controller-pki",
			BindingDigest: "sha256:" + strings.Repeat("4", 64), BackendLeaseID: "accessor-certificate",
			CredentialDigest: "sha256:" + strings.Repeat("5", 64), IssuedAt: issueTime,
			ExpiresAt: now.Add(10 * time.Minute), Revision: 1, Renewable: true, State: "active"}}}
	return runID, profile, sources, certificateLedger, credentialLedger, now
}

func TestBuildTerminalPlanBindsRunLedgersAndExactTargets(t *testing.T) {
	runID, profile, sources, certificateLedger, credentialLedger, now := terminalPlanFixture(t)
	certificateDocument, err := json.Marshal(certificateLedger)
	if err != nil {
		t.Fatal(err)
	}
	credentialDocument, err := json.Marshal(credentialLedger)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := buildVerified(runID, profile, sources, certificateDocument, credentialDocument, "accessor-management", now)
	if err != nil || plan.Validate() != nil || plan.RunID != runID || plan.ProfileDigest != profile.ProfileDigest ||
		len(plan.Certificates) != 2 || len(plan.Tokens) != 2 || plan.Digest == "" ||
		plan.GeneralIssuerID != sources.Sources[0].IssuerID {
		t.Fatalf("terminal plan = %+v, %v", plan, err)
	}
	for name, mutate := range map[string]func(){
		"wrong run":                func() { runID = strings.Repeat("b", 32) },
		"missing certificate hold": func() { certificateLedger.QuiescedAt = nil },
		"missing credential hold":  func() { credentialLedger.QuiescedAt = nil },
		"unknown certificate":      func() { certificateLedger.Certificates[0].PolicyID = "unknown" },
		"cross owner": func() {
			certificateLedger.Certificates[0].SubjectDigest = profile.Principals[1].AuthorizationPrincipal.Digest()
		},
		"duplicate serial":    func() { certificateLedger.Certificates[1].Serial = certificateLedger.Certificates[0].Serial },
		"new post-hold issue": func() { certificateLedger.Certificates[0].IssuedAt = now },
		"unknown accessor":    func() { credentialLedger.Leases[0].BackendLeaseID = "accessor-management" },
		"unbound token":       func() { credentialLedger.Leases[0].PolicyID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			id, p, s, certificates, credentials, moment := terminalPlanFixture(t)
			runID, profile, sources, certificateLedger, credentialLedger, now = id, p, s, certificates, credentials, moment
			mutate()
			certificateDocument, _ := json.Marshal(certificateLedger)
			credentialDocument, _ := json.Marshal(credentialLedger)
			if _, err := buildVerified(runID, profile, sources, certificateDocument, credentialDocument, "accessor-management", now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid plan accepted: %v", err)
			}
		})
	}
	runID, profile, sources, certificateLedger, credentialLedger, now = terminalPlanFixture(t)
	certificateDocument, _ = json.Marshal(certificateLedger)
	credentialDocument, _ = json.Marshal(credentialLedger)
	if _, err := buildVerified(runID, profile, sources, append(certificateDocument, ' '), credentialDocument,
		"accessor-management", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("noncanonical ledger accepted: %v", err)
	}
}
