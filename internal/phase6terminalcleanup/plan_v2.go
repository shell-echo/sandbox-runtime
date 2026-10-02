package phase6terminalcleanup

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const (
	ExternalPostgresRecordProtocol = "sandbox-runtime.phase6-external-postgres-leaf.v1"
	externalPostgresKind           = "external-postgres-server"
	externalPostgresURI            = "spiffe://sandbox-runtime.test/external/postgres"
	externalPostgresDNS            = "postgres.sandbox-runtime.test"
)

// ExternalPostgresRecord is a private, public-certificate-only signing and
// mount witness. It is frozen before PostgreSQL is stopped; the cleanup task
// re-parses it independently and never receives the PostgreSQL private key.
type ExternalPostgresRecord struct {
	Protocol          string    `json:"protocol"`
	RunID             string    `json:"run_id"`
	ProfileDigest     string    `json:"profile_digest"`
	IssuerID          string    `json:"issuer_id"`
	IssuerDigest      string    `json:"issuer_digest"`
	URI               string    `json:"uri"`
	DNSName           string    `json:"dns_name"`
	Serial            string    `json:"serial"`
	LeafDigest        string    `json:"leaf_digest"`
	MountedLeafDigest string    `json:"mounted_leaf_digest"`
	CertificatePEM    []byte    `json:"certificate_pem"`
	IssuerPEM         []byte    `json:"issuer_pem"`
	SignedAt          time.Time `json:"signed_at"`
	Digest            string    `json:"digest"`
}

func (r ExternalPostgresRecord) Validate(profile phase6security.Profile,
	sources phase6security.PeerCRLSources, now time.Time) error {
	if r.Protocol != ExternalPostgresRecordProtocol || !runPattern.MatchString(r.RunID) ||
		r.ProfileDigest != profile.ProfileDigest || !digestPattern.MatchString(r.ProfileDigest) ||
		!phase6security.ValidSlice6IssuerID(r.IssuerID) ||
		!digestPattern.MatchString(r.IssuerDigest) ||
		r.URI != externalPostgresURI || r.DNSName != externalPostgresDNS ||
		!serialPattern.MatchString(r.Serial) || !digestPattern.MatchString(r.LeafDigest) ||
		r.MountedLeafDigest != r.LeafDigest || !digestPattern.MatchString(r.Digest) ||
		r.SignedAt.IsZero() || now.IsZero() || r.SignedAt.After(now) ||
		len(r.CertificatePEM) < 1 || len(r.CertificatePEM) > 16<<10 ||
		len(r.IssuerPEM) < 1 || len(r.IssuerPEM) > 16<<10 {
		return ErrInvalid
	}
	var serviceFound bool
	for _, service := range profile.External {
		if service.Name == "postgres" {
			serviceFound = service.URI == r.URI && reflect.DeepEqual(service.DNSNames, []string{r.DNSName})
		}
	}
	var generalFound bool
	for _, source := range sources.Sources {
		if source.ID == "general" {
			generalFound = source.Mount == "pki" && source.IssuerID == r.IssuerID &&
				source.IssuerDigest == r.IssuerDigest
		}
	}
	if !serviceFound || !generalFound {
		return ErrInvalid
	}
	leaf, err := parseExactCertificate(r.CertificatePEM)
	if err != nil {
		return ErrInvalid
	}
	issuer, err := parseExactCertificate(r.IssuerPEM)
	if err != nil || leaf.CheckSignatureFrom(issuer) != nil {
		return ErrInvalid
	}
	issuerHash, leafHash := sha256.Sum256(issuer.Raw), sha256.Sum256(leaf.Raw)
	if r.IssuerDigest != "sha256:"+hex.EncodeToString(issuerHash[:]) ||
		r.LeafDigest != "sha256:"+hex.EncodeToString(leafHash[:]) ||
		!serialMatchesCertificate(r.Serial, leaf.SerialNumber) ||
		leaf.IsCA || !leaf.BasicConstraintsValid || leaf.Subject.String() != "" ||
		len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != r.URI ||
		!reflect.DeepEqual(leaf.DNSNames, []string{r.DNSName}) ||
		len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 ||
		len(leaf.UnhandledCriticalExtensions) != 0 ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
		len(leaf.UnknownExtKeyUsage) != 0 || leaf.PublicKeyAlgorithm != x509.ECDSA ||
		!isP256PublicKey(leaf.PublicKey) ||
		!leaf.NotBefore.Before(leaf.NotAfter) || r.SignedAt.Before(leaf.NotBefore) ||
		!r.SignedAt.Before(leaf.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) > time.Hour {
		return ErrInvalid
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: r.DNSName,
		CurrentTime: r.SignedAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return ErrInvalid
	}
	copy := r
	copy.Digest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return ErrInvalid
	}
	hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-external-postgres-leaf/v1\x00"), encoded...))
	clear(encoded)
	if r.Digest != "sha256:"+hex.EncodeToString(hash[:]) {
		return ErrInvalid
	}
	return nil
}

// SealExternalPostgresRecord is used after an independently observed exact
// PostgreSQL-mounted certificate digest has been inserted into the record.
func SealExternalPostgresRecord(record ExternalPostgresRecord) (ExternalPostgresRecord, error) {
	if record.Digest != "" || record.MountedLeafDigest == "" {
		return ExternalPostgresRecord{}, ErrInvalid
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return ExternalPostgresRecord{}, ErrInvalid
	}
	hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-external-postgres-leaf/v1\x00"), encoded...))
	clear(encoded)
	record.Digest = "sha256:" + hex.EncodeToString(hash[:])
	return record, nil
}

// BuildV2 retains the two-controller v1 derivation, then adds exactly one
// independently verified external PostgreSQL server leaf. It never falls back
// to the v1 plan when the record is absent or invalid.
func BuildV2(runID string, profile phase6security.Profile, sources phase6security.PeerCRLSources,
	certificateLedgerJSON, credentialLedgerJSON []byte, managementAccessor string,
	record ExternalPostgresRecord, now time.Time) (Plan, error) {
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		sources.Validate(profile) != nil {
		return Plan{}, ErrInvalid
	}
	return buildVerifiedV2(runID, profile, sources, certificateLedgerJSON, credentialLedgerJSON,
		managementAccessor, record, now)
}

func buildVerifiedV2(runID string, profile phase6security.Profile, sources phase6security.PeerCRLSources,
	certificateLedgerJSON, credentialLedgerJSON []byte, managementAccessor string,
	record ExternalPostgresRecord, now time.Time) (Plan, error) {
	plan, err := buildVerified(runID, profile, sources, certificateLedgerJSON, credentialLedgerJSON,
		managementAccessor, now)
	if err != nil || record.RunID != runID || record.Validate(profile, sources, now) != nil {
		return Plan{}, ErrInvalid
	}
	for _, target := range plan.Certificates {
		if target.Serial == record.Serial || target.PolicyID == externalPostgresKind {
			return Plan{}, ErrInvalid
		}
	}
	plan.Protocol = ProtocolV2ID
	plan.ExternalPostgres = &record
	plan.Certificates = append(plan.Certificates, CertificateTarget{Kind: externalPostgresKind,
		PolicyID: externalPostgresKind, Serial: record.Serial,
		SubjectDigest: record.LeafDigest, State: "active"})
	plan.Digest = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, ErrInvalid
	}
	hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-terminal-cleanup-plan/v2\x00"), encoded...))
	clear(encoded)
	plan.Digest = "sha256:" + hex.EncodeToString(hash[:])
	if plan.Validate() != nil {
		return Plan{}, ErrInvalid
	}
	return plan, nil
}

func parseExactCertificate(document []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(document)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(document,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})) {
		return nil, ErrInvalid
	}
	return x509.ParseCertificate(block.Bytes)
}

func serialMatchesCertificate(serial string, number *big.Int) bool {
	if number == nil || number.Sign() <= 0 || !serialPattern.MatchString(serial) {
		return false
	}
	value, err := hex.DecodeString(strings.ReplaceAll(serial, ":", ""))
	return err == nil && new(big.Int).SetBytes(value).Cmp(number) == 0
}

func isP256PublicKey(value any) bool {
	key, ok := value.(*ecdsa.PublicKey)
	return ok && key.Curve == elliptic.P256()
}
