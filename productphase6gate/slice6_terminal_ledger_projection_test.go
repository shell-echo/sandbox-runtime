//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

const slice6TerminalLedgerProjectionFile = "guest-e-terminal-ledger-projection.json"
const slice6TerminalLedgerProjectionLimit = 128 << 10
const slice6TerminalLedgerProjectionProtocol = "sandbox-runtime.phase6-guest-e-terminal-ledger-projection.v1"

// This is a bounded projection of the two exact ledger reads already used by
// BuildV2. It is not a copy of the ledgers or a substitute for their hashes.
type slice6TerminalLedgerProjection struct {
	Protocol, RunID, ProfileDigest, PlanDigest string
	ProjectedAt                                time.Time
	Certificate                                slice6ProjectedCertificateLedger
	Credential                                 slice6ProjectedCredentialLedger
}

type slice6ProjectedCertificateLedger struct {
	Schema, RawSHA256 string
	Revision          int64
	QuiescedAt        time.Time
	RawBytes          int
	Records           []slice6ProjectedCertificate
}

type slice6ProjectedCredentialLedger struct {
	Schema, RawSHA256 string
	Revision          int64
	QuiescedAt        time.Time
	RawBytes          int
	Records           []slice6ProjectedCredential
}

type slice6ProjectedCertificate struct {
	PolicyID, AgentID, RequesterDigest, Principal, SubjectDigest string
	Serial, CertificateDigest, State                             string
	IssuedAt, NotAfter, RevokedAt                                time.Time
}

type slice6ProjectedCredential struct {
	PolicyID, PrincipalDigest, PolicyDigest, BindingDigest string
	CredentialDigest, LeaseIDDigest, BackendAccessorDigest string
	PreviousAccessorDigest, State                          string
	Revision                                               int64
	IssuedAt, ExpiresAt, RevokedAt                         time.Time
}

func slice6TerminalPrivateDigest(domain, value string) string {
	sum := sha256.Sum256([]byte("sandbox-runtime/phase6-guest-e/" + domain + "/v1\x00" + value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func slice6ProjectTerminalLedgers(plan phase6terminalcleanup.Plan,
	certificateRaw, credentialRaw []byte) ([]byte, error) {
	if plan.Protocol != phase6terminalcleanup.ProtocolV2ID || plan.Validate() != nil ||
		len(certificateRaw) < 1 || len(certificateRaw) > 8<<20 ||
		len(credentialRaw) < 1 || len(credentialRaw) > 8<<20 ||
		plan.CertificateLedgerSHA != slice6ReceiptSHA256(certificateRaw) ||
		plan.CredentialLedgerSHA != slice6ReceiptSHA256(credentialRaw) {
		return nil, phase6terminalcleanup.ErrInvalid
	}
	var certificates workloadpki.Ledger
	var credentials workloadcredentialv2.Ledger
	if json.Unmarshal(certificateRaw, &certificates) != nil ||
		json.Unmarshal(credentialRaw, &credentials) != nil {
		return nil, phase6terminalcleanup.ErrInvalid
	}
	projection := slice6TerminalLedgerProjection{
		Protocol: slice6TerminalLedgerProjectionProtocol, RunID: plan.RunID,
		ProfileDigest: plan.ProfileDigest, PlanDigest: plan.Digest,
		ProjectedAt: time.Now().UTC(),
		Certificate: slice6ProjectedCertificateLedger{Schema: certificates.Schema,
			RawSHA256: plan.CertificateLedgerSHA, Revision: certificates.Revision,
			QuiescedAt: certificates.QuiescedAt.UTC(), RawBytes: len(certificateRaw),
			Records: make([]slice6ProjectedCertificate, 0, len(certificates.Certificates))},
		Credential: slice6ProjectedCredentialLedger{Schema: credentials.Schema,
			RawSHA256: plan.CredentialLedgerSHA, Revision: credentials.Revision,
			QuiescedAt: credentials.QuiescedAt.UTC(), RawBytes: len(credentialRaw),
			Records: make([]slice6ProjectedCredential, 0, len(credentials.Leases))},
	}
	for _, record := range certificates.Certificates {
		projection.Certificate.Records = append(projection.Certificate.Records, slice6ProjectedCertificate{
			PolicyID: record.PolicyID, AgentID: record.AgentID,
			RequesterDigest: record.RequesterDigest, Principal: record.Principal,
			SubjectDigest: record.SubjectDigest, Serial: record.Serial,
			CertificateDigest: record.CertificateDigest, State: record.State,
			IssuedAt: record.IssuedAt.UTC(), NotAfter: record.NotAfter.UTC(),
			RevokedAt: record.RevokedAt.UTC(),
		})
	}
	for _, record := range credentials.Leases {
		projected := slice6ProjectedCredential{
			PolicyID: record.PolicyID, PrincipalDigest: record.PrincipalDigest,
			PolicyDigest: record.PolicyDigest, BindingDigest: record.BindingDigest,
			CredentialDigest:      record.CredentialDigest,
			LeaseIDDigest:         slice6TerminalPrivateDigest("lease-id", record.LeaseID),
			BackendAccessorDigest: slice6TerminalPrivateDigest("backend-accessor", record.BackendLeaseID),
			State:                 record.State, Revision: record.Revision,
			IssuedAt: record.IssuedAt.UTC(), ExpiresAt: record.ExpiresAt.UTC(),
			RevokedAt: record.RevokedAt.UTC(),
		}
		if record.PreviousBackendLeaseID != "" {
			projected.PreviousAccessorDigest = slice6TerminalPrivateDigest("previous-backend-accessor", record.PreviousBackendLeaseID)
		}
		projection.Credential.Records = append(projection.Credential.Records, projected)
	}
	document, err := json.Marshal(projection)
	if err != nil || len(document) < 2 || len(document) > slice6TerminalLedgerProjectionLimit ||
		slice6VerifyTerminalLedgerProjection(plan, document) != nil {
		clear(document)
		return nil, phase6terminalcleanup.ErrInvalid
	}
	return document, nil
}

// Replays only the retained, closed projection against the already verified
// plan. It cannot independently recompute the original ledger-byte hashes.
func slice6VerifyTerminalLedgerProjection(plan phase6terminalcleanup.Plan, document []byte) error {
	if plan.Protocol != phase6terminalcleanup.ProtocolV2ID ||
		len(document) < 2 || len(document) > slice6TerminalLedgerProjectionLimit {
		return phase6terminalcleanup.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var projection slice6TerminalLedgerProjection
	if decoder.Decode(&projection) != nil {
		return phase6terminalcleanup.ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return phase6terminalcleanup.ErrInvalid
	}
	canonical, err := json.Marshal(projection)
	if err != nil || !bytes.Equal(canonical, document) ||
		projection.Protocol != slice6TerminalLedgerProjectionProtocol ||
		projection.ProjectedAt.IsZero() || plan.ValidateAt(projection.ProjectedAt) != nil ||
		projection.RunID != plan.RunID || projection.ProfileDigest != plan.ProfileDigest ||
		projection.PlanDigest != plan.Digest ||
		projection.Certificate.RawSHA256 != plan.CertificateLedgerSHA ||
		projection.Credential.RawSHA256 != plan.CredentialLedgerSHA ||
		projection.Certificate.Schema != workloadpki.LedgerSchema ||
		projection.Credential.Schema != workloadcredentialv2.LedgerSchema ||
		projection.Certificate.Revision < 2 || projection.Credential.Revision < 2 ||
		projection.Certificate.QuiescedAt.IsZero() || projection.Credential.QuiescedAt.IsZero() ||
		projection.Certificate.RawBytes < 1 || projection.Certificate.RawBytes > 8<<20 ||
		projection.Credential.RawBytes < 1 || projection.Credential.RawBytes > 8<<20 {
		return phase6terminalcleanup.ErrInvalid
	}
	terminalCertificates := make(map[string]phase6terminalcleanup.CertificateTarget, 2)
	for _, target := range plan.Certificates {
		if target.Kind == "" {
			terminalCertificates[target.PolicyID] = target
		}
	}
	seenSerials, seenTerminal := make(map[string]bool), make(map[string]bool)
	for _, record := range projection.Certificate.Records {
		if record.PolicyID == "" || record.AgentID == "" || record.Principal == "" ||
			!guestRevokeFixtureDigestGate(record.RequesterDigest) ||
			!guestRevokeFixtureDigestGate(record.SubjectDigest) ||
			!guestRevokeFixtureDigestGate(record.CertificateDigest) ||
			record.Serial == "" || seenSerials[record.Serial] ||
			record.IssuedAt.IsZero() || !record.NotAfter.After(record.IssuedAt) ||
			record.IssuedAt.After(projection.Certificate.QuiescedAt) ||
			(record.State == "revoked") != !record.RevokedAt.IsZero() {
			return phase6terminalcleanup.ErrInvalid
		}
		seenSerials[record.Serial] = true
		if target, terminal := terminalCertificates[record.PolicyID]; terminal {
			if seenTerminal[record.PolicyID] || target.Serial != record.Serial ||
				target.SubjectDigest != record.SubjectDigest || target.State != record.State {
				return phase6terminalcleanup.ErrInvalid
			}
			seenTerminal[record.PolicyID] = true
		} else if record.State != "revoked" {
			return phase6terminalcleanup.ErrInvalid
		}
	}
	if len(seenTerminal) != len(terminalCertificates) {
		return phase6terminalcleanup.ErrInvalid
	}
	var terminalToken phase6terminalcleanup.TokenTarget
	for _, target := range plan.Tokens {
		if target.Kind == "certificate-controller" {
			terminalToken = target
		}
	}
	if terminalToken.Kind == "" {
		return phase6terminalcleanup.ErrInvalid
	}
	seenLeases, seenToken := make(map[string]bool), false
	for _, record := range projection.Credential.Records {
		if record.PolicyID == "" || !guestRevokeFixtureDigestGate(record.PrincipalDigest) ||
			!guestRevokeFixtureDigestGate(record.PolicyDigest) ||
			!guestRevokeFixtureDigestGate(record.BindingDigest) ||
			!guestRevokeFixtureDigestGate(record.CredentialDigest) ||
			!guestRevokeFixtureDigestGate(record.LeaseIDDigest) ||
			!guestRevokeFixtureDigestGate(record.BackendAccessorDigest) ||
			record.PreviousAccessorDigest != "" ||
			seenLeases[record.LeaseIDDigest] || record.Revision < 1 ||
			record.IssuedAt.IsZero() || !record.ExpiresAt.After(record.IssuedAt) ||
			record.IssuedAt.After(projection.Credential.QuiescedAt) ||
			(record.State == "revoked") != !record.RevokedAt.IsZero() {
			return phase6terminalcleanup.ErrInvalid
		}
		seenLeases[record.LeaseIDDigest] = true
		if record.PolicyID == "credential-certificate-controller" {
			if seenToken || record.PrincipalDigest != terminalToken.PrincipalDigest ||
				record.PolicyDigest != terminalToken.PolicyDigest ||
				record.BindingDigest != terminalToken.BindingDigest ||
				record.LeaseIDDigest != slice6TerminalPrivateDigest("lease-id", terminalToken.LeaseID) ||
				record.BackendAccessorDigest != slice6TerminalPrivateDigest("backend-accessor", terminalToken.Accessor) ||
				record.State != terminalToken.State {
				return phase6terminalcleanup.ErrInvalid
			}
			seenToken = true
		} else if record.State != "revoked" {
			return phase6terminalcleanup.ErrInvalid
		}
	}
	if !seenToken {
		return phase6terminalcleanup.ErrInvalid
	}
	return nil
}

type slice6ExpectedECertificate struct {
	agent, requesterDigest, principal, subjectDigest string
}

type slice6ExpectedEIssuedSet struct {
	certificates map[string]slice6ExpectedECertificate
	credentials  map[string]string
}

// The E inventory is derived from the seven fixed signer launch slots and
// three material-agent launch slots, not every optional Profile binding.
func slice6ExpectedEIssuedSetFromProfile(profile phase6security.Profile) (slice6ExpectedEIssuedSet, error) {
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil {
		return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
	}
	principals := make(map[string]phase6security.Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		principals[principal.Name] = principal
	}
	expected := slice6ExpectedEIssuedSet{
		certificates: make(map[string]slice6ExpectedECertificate, 9),
		credentials:  make(map[string]string, 4),
	}
	addCertificate := func(policy, agent, subject string) bool {
		requester, okRequester := principals[agent]
		principal, okSubject := principals[subject]
		if policy == "" || !okRequester || !okSubject || requester.AuthorizationPrincipal == nil ||
			principal.AuthorizationPrincipal == nil || expected.certificates[policy].agent != "" {
			return false
		}
		expected.certificates[policy] = slice6ExpectedECertificate{agent: agent,
			requesterDigest: requester.AuthorizationPrincipal.Digest(), principal: subject,
			subjectDigest: principal.AuthorizationPrincipal.Digest()}
		return true
	}
	if !addCertificate(profile.CertificateController.ManagedPolicyID, "certificate-controller", "certificate-controller") ||
		!addCertificate(profile.CertificateController.CredentialController.PolicyID,
			"workload-credential-controller", "workload-credential-controller") {
		return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
	}
	for _, role := range slice6FormalETLSRoles() {
		found := false
		for _, binding := range profile.TLSAgentBindings {
			if binding.AgentDeployment == role {
				if found || !addCertificate(binding.IssuerPolicyID, role, binding.SubjectDeployment) {
					return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
				}
				found = true
			}
		}
		for _, binding := range profile.PostgresClientAgents {
			if binding.AgentDeployment == role {
				if found || !addCertificate(binding.IssuerPolicyID, role, binding.SubjectDeployment) {
					return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
				}
				found = true
			}
		}
		if !found {
			return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
		}
	}
	controller := principals["certificate-controller"]
	if controller.AuthorizationPrincipal == nil {
		return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
	}
	expected.credentials["credential-certificate-controller"] = controller.AuthorizationPrincipal.Digest()
	access, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
	}
	for _, agent := range [...]string{"guest-agent", "product-runtime-agent", "product-migration-agent"} {
		found := false
		for _, entry := range access {
			if entry.Agent == agent {
				principal := principals[agent]
				if found || entry.CredentialPolicyID == "" || principal.AuthorizationPrincipal == nil ||
					expected.credentials[entry.CredentialPolicyID] != "" {
					return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
				}
				expected.credentials[entry.CredentialPolicyID] = principal.AuthorizationPrincipal.Digest()
				found = true
			}
		}
		if !found {
			return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
		}
	}
	if len(expected.certificates) != 9 || len(expected.credentials) != 4 {
		return slice6ExpectedEIssuedSet{}, phase6terminalcleanup.ErrInvalid
	}
	return expected, nil
}

func slice6VerifyTerminalEIssuedSet(projectionRaw []byte, profile phase6security.Profile) error {
	expected, err := slice6ExpectedEIssuedSetFromProfile(profile)
	if err != nil {
		return err
	}
	var projection slice6TerminalLedgerProjection
	if json.Unmarshal(projectionRaw, &projection) != nil {
		return phase6terminalcleanup.ErrInvalid
	}
	return slice6VerifyTerminalEIssuedSetCore(projection, expected)
}

func slice6VerifyTerminalEIssuedSetCore(projection slice6TerminalLedgerProjection,
	expected slice6ExpectedEIssuedSet) error {
	if len(projection.Certificate.Records) != len(expected.certificates) ||
		len(projection.Credential.Records) != len(expected.credentials) {
		return phase6terminalcleanup.ErrInvalid
	}
	seenCertificates := make(map[string]bool, len(expected.certificates))
	for _, record := range projection.Certificate.Records {
		want, found := expected.certificates[record.PolicyID]
		if !found || seenCertificates[record.PolicyID] || record.AgentID != want.agent ||
			record.RequesterDigest != want.requesterDigest || record.Principal != want.principal ||
			record.SubjectDigest != want.subjectDigest ||
			(record.AgentID != "certificate-controller" && record.AgentID != "workload-credential-controller" &&
				record.State != "revoked") {
			return phase6terminalcleanup.ErrInvalid
		}
		seenCertificates[record.PolicyID] = true
	}
	seenCredentials := make(map[string]bool, len(expected.credentials))
	for _, record := range projection.Credential.Records {
		want, found := expected.credentials[record.PolicyID]
		if !found || seenCredentials[record.PolicyID] || record.PrincipalDigest != want ||
			(record.PolicyID != "credential-certificate-controller" && record.State != "revoked") {
			return phase6terminalcleanup.ErrInvalid
		}
		seenCredentials[record.PolicyID] = true
	}
	return nil
}
