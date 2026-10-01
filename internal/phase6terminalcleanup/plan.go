package phase6terminalcleanup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

var ErrInvalid = errors.New("invalid Phase 6 terminal cleanup plan")

var (
	runPattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	serialPattern   = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){7,31}$`)
	accessorPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,256}$`)
)

const ProtocolID = "sandbox-runtime.phase6-terminal-cleanup-plan.v1"

// Plan is private run-owned input, not a Provider API or a claim that Vault
// has revoked anything. The operator must independently read back each target.
type Plan struct {
	Protocol             string              `json:"protocol"`
	RunID                string              `json:"run_id"`
	ProfileDigest        string              `json:"profile_digest"`
	CertificateLedgerSHA string              `json:"certificate_ledger_sha"`
	CredentialLedgerSHA  string              `json:"credential_ledger_sha"`
	GeneralIssuerID      string              `json:"general_issuer_id"`
	GeneralIssuerDigest  string              `json:"general_issuer_digest"`
	Certificates         []CertificateTarget `json:"certificates"`
	Tokens               []TokenTarget       `json:"tokens"`
	Digest               string              `json:"digest"`
}

type CertificateTarget struct {
	PolicyID      string `json:"policy_id"`
	Serial        string `json:"serial"`
	SubjectDigest string `json:"subject_digest"`
	State         string `json:"ledger_state"`
}

type TokenTarget struct {
	Kind            string `json:"kind"`
	Accessor        string `json:"accessor"`
	PrincipalDigest string `json:"principal_digest"`
	LeaseID         string `json:"lease_id,omitempty"`
	PolicyDigest    string `json:"policy_digest,omitempty"`
	BindingDigest   string `json:"binding_digest,omitempty"`
	BackendPolicy   string `json:"backend_policy"`
	State           string `json:"ledger_state"`
}

type expectedCertificate struct {
	requester securityprincipal.Principal
	subject   securityprincipal.Principal
}

// Build accepts only the two terminal controller certificate records and the
// certificate-controller's PKI token. Every other retained record must already
// be terminal; no arbitrary serial or accessor supplied by the cleanup caller
// becomes a Vault target. The management accessor is frozen at bootstrap.
func Build(runID string, profile phase6security.Profile, sources phase6security.PeerCRLSources,
	certificateLedgerJSON, credentialLedgerJSON []byte, managementAccessor string, now time.Time) (Plan, error) {
	if !runPattern.MatchString(runID) || now.IsZero() ||
		phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil || sources.Validate(profile) != nil ||
		!accessorPattern.MatchString(managementAccessor) {
		return Plan{}, ErrInvalid
	}
	return buildVerified(runID, profile, sources, certificateLedgerJSON, credentialLedgerJSON, managementAccessor, now)
}

// buildVerified is separated so negative/positive mapping tests can use a
// small frozen inventory. The public entry point alone performs full Profile
// and peer-source admission before this private derivation.
func buildVerified(runID string, profile phase6security.Profile, sources phase6security.PeerCRLSources,
	certificateLedgerJSON, credentialLedgerJSON []byte, managementAccessor string, now time.Time) (Plan, error) {
	if !runPattern.MatchString(runID) || now.IsZero() || !accessorPattern.MatchString(managementAccessor) {
		return Plan{}, ErrInvalid
	}
	identities, err := phase6security.Slice6DesiredAuthorizationPrincipals(runID,
		profile.EnvironmentDigest, profile.PrincipalProfileDigest)
	if err != nil {
		return Plan{}, ErrInvalid
	}
	byName := make(map[string]phase6security.Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		byName[principal.Name] = principal
		if expected, found := identities[principal.Name]; found &&
			(principal.AuthorizationPrincipal == nil || *principal.AuthorizationPrincipal != expected) {
			return Plan{}, ErrInvalid
		}
	}
	certificateController, credentialController := byName["certificate-controller"], byName["workload-credential-controller"]
	if certificateController.AuthorizationPrincipal == nil || credentialController.AuthorizationPrincipal == nil {
		return Plan{}, ErrInvalid
	}
	var general phase6security.PeerCRLSource
	for _, source := range sources.Sources {
		if source.ID == "general" {
			general = source
		}
	}
	if general.Mount != "pki" || !phase6security.ValidSlice6IssuerID(general.IssuerID) || general.IssuerDigest == "" {
		return Plan{}, ErrInvalid
	}
	certLedger, err := decodeCanonical[workloadpki.Ledger](certificateLedgerJSON, 8<<20)
	if err != nil || certLedger.Schema != workloadpki.LedgerSchema || certLedger.Revision < 2 ||
		certLedger.QuiescedAt == nil || certLedger.QuiescedAt.IsZero() || certLedger.QuiescedAt.After(now) {
		return Plan{}, ErrInvalid
	}
	credentialLedger, err := decodeCanonical[workloadcredentialv2.Ledger](credentialLedgerJSON, 8<<20)
	if err != nil || credentialLedger.Schema != workloadcredentialv2.LedgerSchema || credentialLedger.Revision < 2 ||
		credentialLedger.QuiescedAt == nil || credentialLedger.QuiescedAt.IsZero() || credentialLedger.QuiescedAt.After(now) {
		return Plan{}, ErrInvalid
	}
	expected := make(map[string]expectedCertificate, len(profile.TLSAgentBindings)+len(profile.PostgresClientAgents)+2)
	add := func(policyID, requester, subject string) bool {
		requesterValue, requesterFound := byName[requester]
		subjectValue, subjectFound := byName[subject]
		if policyID == "" || !requesterFound || !subjectFound ||
			requesterValue.AuthorizationPrincipal == nil || subjectValue.AuthorizationPrincipal == nil {
			return false
		}
		if _, duplicate := expected[policyID]; duplicate {
			return false
		}
		expected[policyID] = expectedCertificate{*requesterValue.AuthorizationPrincipal, *subjectValue.AuthorizationPrincipal}
		return true
	}
	authority := profile.CertificateController
	if !add(authority.ManagedPolicyID, "certificate-controller", "certificate-controller") ||
		!add(authority.CredentialController.PolicyID, "workload-credential-controller", "workload-credential-controller") {
		return Plan{}, ErrInvalid
	}
	for _, binding := range profile.TLSAgentBindings {
		if !add(binding.IssuerPolicyID, binding.AgentDeployment, binding.SubjectDeployment) {
			return Plan{}, ErrInvalid
		}
	}
	for _, binding := range profile.PostgresClientAgents {
		if !add(binding.IssuerPolicyID, binding.AgentDeployment, binding.SubjectDeployment) {
			return Plan{}, ErrInvalid
		}
	}
	seenSerials := make(map[string]bool, len(certLedger.Certificates))
	seenPolicies := make(map[string]bool, 2)
	certificateTargets := make([]CertificateTarget, 0, 2)
	for _, record := range certLedger.Certificates {
		binding, found := expected[record.PolicyID]
		if !found || !serialPattern.MatchString(record.Serial) || seenSerials[record.Serial] ||
			record.AgentID != binding.requester.Name || record.RequesterDigest != binding.requester.Digest() ||
			record.Principal != binding.subject.Name || record.SubjectDigest != binding.subject.Digest() ||
			!digestPattern.MatchString(record.CertificateDigest) || record.IssuerRevision == "" ||
			record.NotBefore.IsZero() || !record.NotAfter.After(record.NotBefore) ||
			record.IssuedAt.IsZero() || record.IssuedAt.After(*certLedger.QuiescedAt) ||
			(record.State == "revoked") != !record.RevokedAt.IsZero() ||
			(record.State != "active" && record.State != "revoked") {
			return Plan{}, ErrInvalid
		}
		seenSerials[record.Serial] = true
		terminal := record.PolicyID == authority.ManagedPolicyID || record.PolicyID == authority.CredentialController.PolicyID
		if !terminal && record.State != "revoked" {
			return Plan{}, ErrInvalid
		}
		if terminal {
			if seenPolicies[record.PolicyID] {
				return Plan{}, ErrInvalid
			}
			seenPolicies[record.PolicyID] = true
			certificateTargets = append(certificateTargets, CertificateTarget{PolicyID: record.PolicyID,
				Serial: record.Serial, SubjectDigest: record.SubjectDigest, State: record.State})
		}
	}
	if !seenPolicies[authority.ManagedPolicyID] || !seenPolicies[authority.CredentialController.PolicyID] {
		return Plan{}, ErrInvalid
	}
	slices.SortFunc(certificateTargets, func(a, b CertificateTarget) int { return bytes.Compare([]byte(a.PolicyID), []byte(b.PolicyID)) })
	seenAccessors := map[string]bool{managementAccessor: true}
	seenCertificateToken := false
	tokenTargets := make([]TokenTarget, 0, 2)
	for _, record := range credentialLedger.Leases {
		if !accessorPattern.MatchString(record.BackendLeaseID) || seenAccessors[record.BackendLeaseID] ||
			!digestPattern.MatchString(record.PolicyDigest) || !digestPattern.MatchString(record.BindingDigest) ||
			!digestPattern.MatchString(record.CredentialDigest) || record.Revision < 1 ||
			record.IssuedAt.IsZero() || !record.ExpiresAt.After(record.IssuedAt) ||
			record.IssuedAt.After(*credentialLedger.QuiescedAt) ||
			(record.State == "revoked") != !record.RevokedAt.IsZero() ||
			(record.State != "active" && record.State != "revoked") {
			return Plan{}, ErrInvalid
		}
		seenAccessors[record.BackendLeaseID] = true
		if record.PolicyID == "credential-certificate-controller" {
			if seenCertificateToken || record.Principal != *certificateController.AuthorizationPrincipal ||
				record.PrincipalDigest != certificateController.AuthorizationPrincipal.Digest() ||
				record.Purpose != secretref.PurposeWorkloadCredential || record.LeaseID == "" || !record.Renewable ||
				record.BackendID != "vault-primary" || record.BackendPolicy != "certificate-controller-pki" {
				return Plan{}, ErrInvalid
			}
			seenCertificateToken = true
			tokenTargets = append(tokenTargets, TokenTarget{Kind: "certificate-controller",
				Accessor: record.BackendLeaseID, PrincipalDigest: record.PrincipalDigest,
				LeaseID: record.LeaseID, PolicyDigest: record.PolicyDigest,
				BindingDigest: record.BindingDigest,
				BackendPolicy: record.BackendPolicy, State: record.State})
		} else if record.State != "revoked" {
			return Plan{}, ErrInvalid
		}
	}
	if !seenCertificateToken {
		return Plan{}, ErrInvalid
	}
	tokenTargets = append(tokenTargets, TokenTarget{Kind: "credential-management", Accessor: managementAccessor,
		PrincipalDigest: credentialController.AuthorizationPrincipal.Digest(),
		BackendPolicy:   "phase6-credential-management", State: "active"})
	certHash := sha256.Sum256(certificateLedgerJSON)
	credentialHash := sha256.Sum256(credentialLedgerJSON)
	plan := Plan{Protocol: ProtocolID, RunID: runID, ProfileDigest: profile.ProfileDigest,
		CertificateLedgerSHA: "sha256:" + hex.EncodeToString(certHash[:]),
		CredentialLedgerSHA:  "sha256:" + hex.EncodeToString(credentialHash[:]),
		GeneralIssuerID:      general.IssuerID, GeneralIssuerDigest: general.IssuerDigest,
		Certificates: certificateTargets, Tokens: tokenTargets}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, ErrInvalid
	}
	defer clear(encoded)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-terminal-cleanup-plan/v1\x00"), encoded...))
	plan.Digest = "sha256:" + hex.EncodeToString(digest[:])
	return plan, nil
}

func decodeCanonical[T any](document []byte, maximum int) (T, error) {
	var value T
	if len(document) < 1 || len(document) > maximum {
		return value, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return value, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return value, ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) {
		clear(canonical)
		return value, ErrInvalid
	}
	clear(canonical)
	return value, nil
}
