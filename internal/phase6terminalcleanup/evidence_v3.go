package phase6terminalcleanup

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

const EvidenceV3Protocol = "sandbox-runtime.phase6-terminal-cleanup-private-evidence.v3"
const MaxEvidenceV3Bytes = 2 << 20

// EvidenceV3 is private operator stdout, never a Provider or public API DTO.
// The response fields are intentionally whitelisted projections, not complete
// Vault JSON or bearer credentials. Issuer/CRL DER are the only raw responses.
type EvidenceV3 struct {
	Protocol, RunID, ProfileDigest, PlanDigest string
	CRLVerifiedUTC                             string
	IssuerDER, CRLDER                          []byte
	Events                                     []EvidenceV3Event
	Receipt                                    Receipt
}

type EvidenceV3Event struct {
	Kind, TargetDigest, ObservedDigest string
	Status                             int
	MediaType                          string
	Token                              *EvidenceV3Token
	InvalidAccessorError               string
	RevocationState                    string
	RevocationUnix                     int64
	RevocationRFC3339                  string
	CRLConfig                          *EvidenceV3CRLConfig
}

type EvidenceV3Token struct {
	Policies   []string
	Metadata   map[string]string
	Role       string
	Type       string
	Orphan     bool
	Renewable  bool
	TTLSeconds int64
}

type EvidenceV3CRLConfig struct {
	Disable, AutoRebuild, EnableDelta bool
}

// DecodeEvidenceV3 rejects unknown, duplicate, noncanonical, truncated and
// trailing fields before any offline semantic replay.
func DecodeEvidenceV3(document []byte) (EvidenceV3, error) {
	if len(document) < 2 || len(document) > MaxEvidenceV3Bytes || document[len(document)-1] != '\n' {
		return EvidenceV3{}, ErrInvalid
	}
	return decodeCanonical[EvidenceV3](document[:len(document)-1], MaxEvidenceV3Bytes-1)
}

func VerifyEvidenceV3(plan Plan, evidence EvidenceV3) error {
	if plan.Protocol != ProtocolV2ID ||
		evidence.Protocol != EvidenceV3Protocol || evidence.RunID != plan.RunID ||
		evidence.ProfileDigest != plan.ProfileDigest || evidence.PlanDigest != plan.Digest ||
		len(evidence.IssuerDER) < 1 || len(evidence.IssuerDER) > 64<<10 ||
		len(evidence.CRLDER) < 1 || len(evidence.CRLDER) > 512<<10 ||
		len(evidence.Events) < 1 || len(evidence.Events) > 32 {
		return ErrInvalid
	}
	verifiedAt, err := time.Parse(time.RFC3339Nano, evidence.CRLVerifiedUTC)
	if err != nil || evidence.CRLVerifiedUTC != verifiedAt.UTC().Format(time.RFC3339Nano) {
		return ErrInvalid
	}
	if plan.ValidateAt(verifiedAt) != nil || verifyReceiptAt(plan, evidence.Receipt, verifiedAt) != nil {
		return ErrInvalid
	}
	issuerHash := sha256.Sum256(evidence.IssuerDER)
	issuerDigest := "sha256:" + hex.EncodeToString(issuerHash[:])
	list, err := x509.ParseRevocationList(evidence.CRLDER)
	if err != nil || issuerDigest != plan.GeneralIssuerDigest {
		return ErrInvalid
	}
	verified, err := workloadpki.VerifyCRLForIssuer(workloadpki.RevocationSnapshot{
		DER: evidence.CRLDER, ThisUpdate: list.ThisUpdate, NextUpdate: list.NextUpdate,
	}, evidence.IssuerDER, verifiedAt)
	if err != nil || verified.IssuerDigest() != plan.GeneralIssuerDigest ||
		verified.CRLDigest() != evidence.Receipt.IssuerCRLSHA {
		return ErrInvalid
	}
	for _, target := range plan.Certificates {
		serial, err := hex.DecodeString(strings.ReplaceAll(target.Serial, ":", ""))
		if err != nil || !verified.RevokesSerial(new(big.Int).SetBytes(serial)) {
			return ErrInvalid
		}
	}
	position := 0
	next := func(kind, target string) (EvidenceV3Event, error) {
		if position >= len(evidence.Events) {
			return EvidenceV3Event{}, ErrInvalid
		}
		event := evidence.Events[position]
		position++
		if event.Kind != kind || event.TargetDigest != target || !digestPattern.MatchString(target) {
			return EvidenceV3Event{}, ErrInvalid
		}
		return event, nil
	}
	for _, target := range plan.Tokens {
		digest := targetDigest("token", target.Accessor)
		event, err := next("lookup-preflight", digest)
		if err != nil {
			return err
		}
		if target.State == "revoked" {
			if !evidenceAbsent(event) {
				return ErrInvalid
			}
		} else if !evidenceBoundToken(plan, target, event) {
			return ErrInvalid
		}
	}
	for _, target := range plan.Certificates {
		if target.State != "active" {
			continue
		}
		kind := "certificate"
		if target.Kind == externalPostgresKind {
			kind = externalPostgresKind
		}
		event, err := next("certificate-revoke", targetDigest(kind, target.Serial))
		if err != nil || !evidenceCertificateRevoke(event, verifiedAt) {
			return ErrInvalid
		}
	}
	issuer, err := next("issuer-read", plan.GeneralIssuerDigest)
	if err != nil || !evidenceDER(issuer, issuerDigest, "application/pkix-cert", "application/octet-stream") {
		return ErrInvalid
	}
	config, err := next("crl-config", plan.GeneralIssuerDigest)
	if err != nil || config.Status != 200 || config.MediaType != "application/json" ||
		config.CRLConfig == nil || *config.CRLConfig != (EvidenceV3CRLConfig{}) ||
		!evidenceNoOtherFields(config, true) {
		return ErrInvalid
	}
	issuerAgain, err := next("issuer-reread", plan.GeneralIssuerDigest)
	if err != nil || !evidenceDER(issuerAgain, issuerDigest, "application/pkix-cert", "application/octet-stream") {
		return ErrInvalid
	}
	crl, err := next("crl-read", plan.GeneralIssuerDigest)
	if err != nil || !evidenceDER(crl, verified.CRLDigest(),
		"application/pkix-crl", "application/x-pkcs7-crl", "application/octet-stream") {
		return ErrInvalid
	}
	for _, target := range plan.Tokens {
		if target.State != "active" {
			continue
		}
		digest := targetDigest("token", target.Accessor)
		revoke, err := next("accessor-revoke", digest)
		if err != nil || revoke.Status != 204 || revoke.MediaType != "" ||
			!evidenceNoOtherFields(revoke, false) {
			return ErrInvalid
		}
		readback, err := next("lookup-post-revoke", digest)
		if err != nil || !evidenceAbsent(readback) {
			return ErrInvalid
		}
	}
	self, err := next("self-revoke", plan.Digest)
	if err != nil || self.Status != 204 || self.MediaType != "" ||
		!evidenceNoOtherFields(self, false) || position != len(evidence.Events) {
		return ErrInvalid
	}
	return nil
}

func evidenceNoOtherFields(event EvidenceV3Event, allowConfig bool) bool {
	return event.ObservedDigest == "" &&
		event.Token == nil && event.InvalidAccessorError == "" &&
		event.RevocationState == "" && event.RevocationUnix == 0 &&
		event.RevocationRFC3339 == "" && (allowConfig || event.CRLConfig == nil)
}

func evidenceAbsent(event EvidenceV3Event) bool {
	return event.Status == 400 && event.MediaType == "application/json" &&
		(event.InvalidAccessorError == "invalid accessor" ||
			event.InvalidAccessorError == "1 error occurred:\n\t* invalid accessor\n\n") &&
		event.ObservedDigest == "" && event.Token == nil && event.CRLConfig == nil &&
		event.RevocationState == "" && event.RevocationUnix == 0 && event.RevocationRFC3339 == ""
}

func evidenceBoundToken(plan Plan, target TokenTarget, event EvidenceV3Event) bool {
	if event.Status != 200 || event.MediaType != "application/json" || event.Token == nil ||
		event.ObservedDigest != targetDigest("token", target.Accessor) ||
		event.InvalidAccessorError != "" || event.RevocationState != "" ||
		event.RevocationUnix != 0 || event.RevocationRFC3339 != "" || event.CRLConfig != nil ||
		len(event.Token.Policies) != 1 || len(event.Token.Metadata) > 7 {
		return false
	}
	value := event.Token
	return tokenMatches(plan, target, TokenObservation{Accessor: target.Accessor,
		Policies: value.Policies, Metadata: value.Metadata, Role: value.Role,
		Type: value.Type, Orphan: value.Orphan, Renewable: value.Renewable,
		TTLSeconds: value.TTLSeconds})
}

func evidenceCertificateRevoke(event EvidenceV3Event, verifiedAt time.Time) bool {
	if event.Status != 200 || event.MediaType != "application/json" ||
		event.RevocationState != "revoked" || event.RevocationUnix < 1 ||
		event.ObservedDigest != "" || event.Token != nil || event.InvalidAccessorError != "" ||
		event.CRLConfig != nil {
		return false
	}
	stamp, err := time.Parse(time.RFC3339Nano, event.RevocationRFC3339)
	return err == nil && event.RevocationRFC3339 == stamp.UTC().Format(time.RFC3339Nano) &&
		stamp.Unix() == event.RevocationUnix && !stamp.After(verifiedAt.Add(time.Minute))
}

func evidenceDER(event EvidenceV3Event, digest string, media ...string) bool {
	if event.Status != 200 || event.ObservedDigest != digest || event.Token != nil ||
		event.InvalidAccessorError != "" || event.RevocationState != "" ||
		event.RevocationUnix != 0 || event.RevocationRFC3339 != "" || event.CRLConfig != nil {
		return false
	}
	for _, value := range media {
		if event.MediaType == value {
			return true
		}
	}
	return false
}
