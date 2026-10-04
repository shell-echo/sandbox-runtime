package phase6terminalcleanup

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// ErrAccessorAbsent may only mean Vault returned its exact documented invalid
// accessor response after a successful authenticated lookup/revoke sequence.
// Transport loss, 403, 404 and generic 400 are never mapped to this sentinel.
var ErrAccessorAbsent = errors.New("Vault accessor explicitly absent")

type TokenObservation struct {
	Accessor   string
	Policies   []string
	Metadata   map[string]string
	Role       string
	Type       string
	Orphan     bool
	Renewable  bool
	TTLSeconds int64
}

// Remote is the narrow one-shot Vault capability. Its production adapter may
// access only the fixed Vault endpoint; it never receives a caller path.
type Remote interface {
	LookupAccessor(context.Context, string) (TokenObservation, error)
	RevokeAccessor(context.Context, string) error
	RevokeCertificate(context.Context, string) error
	ReadCompleteCRL(context.Context, string) (issuerDER, crlDER []byte, err error)
	RevokeSelf(context.Context) error
}

type TargetResult struct {
	Kind         string `json:"kind"`
	TargetDigest string `json:"target_digest"`
	Confirmed    bool   `json:"confirmed"`
}

// Receipt intentionally omits raw serials, accessors, token and PEM bytes.
// The run's private raw evidence must retain the underlying Vault responses.
type Receipt struct {
	Protocol      string         `json:"protocol"`
	RunID         string         `json:"run_id"`
	ProfileDigest string         `json:"profile_digest"`
	PlanDigest    string         `json:"plan_digest"`
	IssuerCRLSHA  string         `json:"issuer_crl_sha"`
	Certificates  []TargetResult `json:"certificates"`
	Tokens        []TargetResult `json:"tokens"`
	SelfRevoked   bool           `json:"self_revoked"`
	Complete      bool           `json:"complete"`
	FailureStage  string         `json:"failure_stage,omitempty"`
}

// DecodeReceipt accepts the one canonical JSON line emitted by the finite
// operator, rejecting unknown, duplicate, oversized or trailing fields.
func DecodeReceipt(document []byte) (Receipt, error) {
	if len(document) < 2 || len(document) > 16<<10 || document[len(document)-1] != '\n' {
		return Receipt{}, ErrInvalid
	}
	return decodeCanonical[Receipt](document[:len(document)-1], 16<<10)
}

// VerifyReceipt binds a private completion claim to every exact plan target.
// A count-only check cannot distinguish a missing PostgreSQL revocation from
// a duplicate controller result.
func VerifyReceipt(plan Plan, receipt Receipt) error {
	return verifyReceiptAt(plan, receipt, time.Now().UTC())
}

func verifyReceiptAt(plan Plan, receipt Receipt, observedAt time.Time) error {
	if plan.ValidateAt(observedAt) != nil || !receipt.Complete || !receipt.SelfRevoked ||
		receipt.FailureStage != "" || !digestPattern.MatchString(receipt.IssuerCRLSHA) ||
		receipt.RunID != plan.RunID || receipt.ProfileDigest != plan.ProfileDigest ||
		receipt.PlanDigest != plan.Digest || len(receipt.Certificates) != len(plan.Certificates) ||
		len(receipt.Tokens) != len(plan.Tokens) {
		return ErrInvalid
	}
	wantProtocol := "sandbox-runtime.phase6-terminal-cleanup-receipt.v1"
	if plan.Protocol == ProtocolV2ID {
		wantProtocol = "sandbox-runtime.phase6-terminal-cleanup-receipt.v2"
	}
	if receipt.Protocol != wantProtocol {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(plan.Certificates)+len(plan.Tokens))
	for index, target := range plan.Certificates {
		kind := "certificate"
		if target.Kind == externalPostgresKind {
			kind = externalPostgresKind
		}
		result := receipt.Certificates[index]
		if !result.Confirmed || result.Kind != kind ||
			result.TargetDigest != targetDigest(kind, target.Serial) || seen[result.TargetDigest] {
			return ErrInvalid
		}
		seen[result.TargetDigest] = true
	}
	for index, target := range plan.Tokens {
		result := receipt.Tokens[index]
		if !result.Confirmed || result.Kind != target.Kind ||
			result.TargetDigest != targetDigest("token", target.Accessor) || seen[result.TargetDigest] {
			return ErrInvalid
		}
		seen[result.TargetDigest] = true
	}
	return nil
}

func (p Plan) Validate() error {
	return p.ValidateAt(time.Now().UTC())
}

// ValidateAt is for immutable historical evidence replay only. Admission and
// execution continue to use Validate's current-time check.
func (p Plan) ValidateAt(observedAt time.Time) error {
	if observedAt.IsZero() {
		return ErrInvalid
	}
	certificateCount := 2
	digestDomain := "sandbox-runtime/phase6-terminal-cleanup-plan/v1\x00"
	if p.Protocol == ProtocolV2ID {
		certificateCount = 3
		digestDomain = "sandbox-runtime/phase6-terminal-cleanup-plan/v2\x00"
	} else if p.Protocol != ProtocolID || p.ExternalPostgres != nil {
		return ErrInvalid
	}
	if !runPattern.MatchString(p.RunID) || !digestPattern.MatchString(p.ProfileDigest) ||
		!digestPattern.MatchString(p.CertificateLedgerSHA) || !digestPattern.MatchString(p.CredentialLedgerSHA) ||
		!digestPattern.MatchString(p.GeneralIssuerDigest) || !digestPattern.MatchString(p.Digest) ||
		!phase6security.ValidSlice6IssuerID(p.GeneralIssuerID) || len(p.Certificates) != certificateCount || len(p.Tokens) != 2 {
		return ErrInvalid
	}
	if p.Protocol == ProtocolV2ID {
		if p.ExternalPostgres == nil || p.ExternalPostgres.RunID != p.RunID ||
			p.ExternalPostgres.ProfileDigest != p.ProfileDigest ||
			p.ExternalPostgres.IssuerID != p.GeneralIssuerID ||
			p.ExternalPostgres.IssuerDigest != p.GeneralIssuerDigest {
			return ErrInvalid
		}
		minimalProfile := phase6security.Profile{ProfileDigest: p.ProfileDigest,
			External: []phase6security.ExternalService{{Name: "postgres", URI: externalPostgresURI,
				DNSNames: []string{externalPostgresDNS}}}}
		minimalSources := phase6security.PeerCRLSources{Sources: []phase6security.PeerCRLSource{{
			ID: "general", Mount: "pki", IssuerID: p.GeneralIssuerID, IssuerDigest: p.GeneralIssuerDigest}}}
		if p.ExternalPostgres.Validate(minimalProfile, minimalSources, observedAt.UTC()) != nil {
			return ErrInvalid
		}
	}
	seenSerial, seenAccessor := map[string]bool{}, map[string]bool{}
	for index, target := range p.Certificates {
		if target.PolicyID == "" || !serialPattern.MatchString(target.Serial) || seenSerial[target.Serial] ||
			!digestPattern.MatchString(target.SubjectDigest) || (target.State != "active" && target.State != "revoked") {
			return ErrInvalid
		}
		if index < 2 && target.Kind != "" || index == 2 &&
			(target.Kind != externalPostgresKind || target.PolicyID != externalPostgresKind ||
				target.State != "active" || target.Serial != p.ExternalPostgres.Serial ||
				target.SubjectDigest != p.ExternalPostgres.LeafDigest) {
			return ErrInvalid
		}
		seenSerial[target.Serial] = true
	}
	if p.Certificates[0].PolicyID >= p.Certificates[1].PolicyID {
		return ErrInvalid
	}
	for index, target := range p.Tokens {
		if !accessorPattern.MatchString(target.Accessor) || seenAccessor[target.Accessor] ||
			!digestPattern.MatchString(target.PrincipalDigest) ||
			(target.State != "active" && target.State != "revoked") ||
			(index == 0 && (target.Kind != "certificate-controller" || target.BackendPolicy != "certificate-controller-pki" ||
				target.LeaseID == "" || !digestPattern.MatchString(target.PolicyDigest) || !digestPattern.MatchString(target.BindingDigest))) ||
			(index == 1 && (target.Kind != "credential-management" || target.BackendPolicy != "phase6-credential-management" ||
				target.State != "active" || target.LeaseID != "" || target.PolicyDigest != "" || target.BindingDigest != "")) {
			return ErrInvalid
		}
		seenAccessor[target.Accessor] = true
	}
	copy := p
	copy.Digest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return ErrInvalid
	}
	defer clear(encoded)
	digest := sha256.Sum256(append([]byte(digestDomain), encoded...))
	if p.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		return ErrInvalid
	}
	return nil
}

func Execute(ctx context.Context, plan Plan, remote Remote, now func() time.Time) (Receipt, error) {
	receiptProtocol := "sandbox-runtime.phase6-terminal-cleanup-receipt.v1"
	if plan.Protocol == ProtocolV2ID {
		receiptProtocol = "sandbox-runtime.phase6-terminal-cleanup-receipt.v2"
	}
	receipt := Receipt{Protocol: receiptProtocol,
		RunID: plan.RunID, ProfileDigest: plan.ProfileDigest, PlanDigest: plan.Digest,
		Certificates: make([]TargetResult, len(plan.Certificates)), Tokens: make([]TargetResult, len(plan.Tokens))}
	if ctx == nil || remote == nil || now == nil || now().IsZero() || plan.Validate() != nil {
		return Receipt{}, ErrInvalid
	}
	fail := func(stage string) (Receipt, error) {
		receipt.FailureStage = stage
		return receipt, ErrInvalid
	}
	for index, target := range plan.Certificates {
		kind := "certificate"
		if target.Kind == externalPostgresKind {
			kind = externalPostgresKind
		}
		receipt.Certificates[index] = TargetResult{Kind: kind, TargetDigest: targetDigest(kind, target.Serial)}
	}
	for index, target := range plan.Tokens {
		receipt.Tokens[index] = TargetResult{Kind: target.Kind, TargetDigest: targetDigest("token", target.Accessor)}
		observed, err := remote.LookupAccessor(ctx, target.Accessor)
		if target.State == "revoked" {
			if !errors.Is(err, ErrAccessorAbsent) {
				return fail("token-preflight-absent")
			}
			continue
		}
		if err != nil || !tokenMatches(plan, target, observed) {
			return fail("token-preflight-bound")
		}
	}
	for _, target := range plan.Certificates {
		if target.State == "active" && remote.RevokeCertificate(ctx, target.Serial) != nil {
			return fail("certificate-revoke")
		}
	}
	issuerDER, crlDER, err := remote.ReadCompleteCRL(ctx, plan.GeneralIssuerID)
	if err != nil || len(issuerDER) == 0 || len(crlDER) == 0 {
		clear(issuerDER)
		clear(crlDER)
		return fail("crl-read")
	}
	issuerHash := sha256.Sum256(issuerDER)
	issuerDigest := "sha256:" + hex.EncodeToString(issuerHash[:])
	list, parseErr := x509.ParseRevocationList(crlDER)
	if parseErr != nil || issuerDigest != plan.GeneralIssuerDigest {
		clear(issuerDER)
		clear(crlDER)
		return fail("crl-issuer")
	}
	snapshot := workloadpki.RevocationSnapshot{DER: crlDER, ThisUpdate: list.ThisUpdate, NextUpdate: list.NextUpdate}
	verified, verifyErr := workloadpki.VerifyCRLForIssuer(snapshot, issuerDER, now().UTC())
	clear(issuerDER)
	clear(crlDER)
	if verifyErr != nil || verified.IssuerDigest() != plan.GeneralIssuerDigest {
		return fail("crl-signature")
	}
	for index, target := range plan.Certificates {
		serialBytes, decodeErr := hex.DecodeString(strings.ReplaceAll(target.Serial, ":", ""))
		if decodeErr != nil || !verified.RevokesSerial(new(big.Int).SetBytes(serialBytes)) {
			clear(serialBytes)
			return fail("crl-target")
		}
		clear(serialBytes)
		receipt.Certificates[index].Confirmed = true
	}
	receipt.IssuerCRLSHA = verified.CRLDigest()
	for index, target := range plan.Tokens {
		if target.State == "active" {
			if remote.RevokeAccessor(ctx, target.Accessor) != nil {
				return fail("token-revoke")
			}
			if _, err := remote.LookupAccessor(ctx, target.Accessor); !errors.Is(err, ErrAccessorAbsent) {
				return fail("token-readback")
			}
		}
		receipt.Tokens[index].Confirmed = true
	}
	if remote.RevokeSelf(ctx) != nil {
		return fail("operator-self-revoke")
	}
	receipt.SelfRevoked, receipt.Complete = true, true
	return receipt, nil
}

func tokenMatches(plan Plan, target TokenTarget, observed TokenObservation) bool {
	if observed.Accessor != target.Accessor || observed.Type != "service" || observed.Renewable ||
		observed.TTLSeconds < 1 || !slices.Equal(observed.Policies, []string{target.BackendPolicy}) {
		return false
	}
	if target.Kind == "certificate-controller" {
		return !observed.Orphan && observed.Role == workloadcredential.Phase6TokenRole(target.BackendPolicy) &&
			len(observed.Metadata) == 7 && observed.Metadata["subject_id"] == "certificate_controller" &&
			observed.Metadata["subject_digest"] == target.PrincipalDigest &&
			observed.Metadata["policy_id"] == "credential-certificate-controller" &&
			observed.Metadata["policy_digest"] == target.PolicyDigest &&
			observed.Metadata["binding_digest"] == target.BindingDigest &&
			observed.Metadata["purpose"] == "workload_credential" && observed.Metadata["lease_id"] == target.LeaseID
	}
	return observed.Orphan && observed.Role == "" && len(observed.Metadata) == 3 &&
		observed.Metadata["run_id"] == plan.RunID && observed.Metadata["profile_digest"] == plan.ProfileDigest &&
		observed.Metadata["owner_digest"] == target.PrincipalDigest
}

func targetDigest(kind, value string) string {
	digest := sha256.Sum256([]byte("sandbox-runtime/phase6-terminal-cleanup-target/v1\x00" + kind + "\x00" + value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
