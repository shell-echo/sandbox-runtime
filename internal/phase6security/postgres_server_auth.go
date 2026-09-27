package phase6security

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/netip"
	"strings"
	"time"
)

const (
	postgresServerAuthPolicyID = "provider-postgres-auth"
	postgresServerAuthScope    = "provider_databases_only"
)

// PostgresServerAuthPolicy binds one PostgreSQL instance's controlled HBA
// artifact for the explicitly limited Provider-database gate. The referenced
// client CA is the existing trust-anchor record, not a second CA authority.
// A full shared-service gate must expand the declared scope and complete rule
// inventory before it can include other roles on the same PostgreSQL instance.
type PostgresServerAuthPolicy struct {
	ID                    string `json:"id"`
	Scope                 string `json:"scope"`
	ServiceName           string `json:"service_name"`
	ServiceIdentityDigest string `json:"service_identity_digest"`
	HBAArtifactID         string `json:"hba_artifact_id"`
	HBADigest             string `json:"hba_digest"`
	ClientCAAnchorID      string `json:"client_ca_anchor_id"`
	IngressCIDR           string `json:"ingress_cidr"`
}

// RenderProviderHBA returns the only raw HBA byte sequence approved for the
// current Provider-only component scope. It includes both Provider database
// roles in one file, then explicit IPv4 and IPv6 rejection. The production
// gate must compare these exact bytes with the PostgreSQL read-only mount and
// prove newly opened connections use them; a parsed file view is insufficient.
func (p PostgresServerAuthPolicy) RenderProviderHBA(databases []ProviderDatabaseBinding) ([]byte, error) {
	prefix, err := netip.ParsePrefix(p.IngressCIDR)
	if err != nil || prefix.String() != p.IngressCIDR || prefix.Masked().String() != p.IngressCIDR ||
		prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
		prefix.Bits() < 1 || prefix.Addr().Is4() && prefix.Bits() < 24 ||
		prefix.Addr().Is6() && prefix.Bits() < 64 || len(databases) != 2 ||
		databases[0].OwnerDeployment != "provider-browser-runtime" ||
		databases[1].OwnerDeployment != "provider-desktop-runtime" ||
		databases[0].DatabaseName == databases[1].DatabaseName ||
		databases[0].RuntimeRole == databases[1].RuntimeRole {
		return nil, ErrInvalidProfile
	}
	var document strings.Builder
	document.WriteString("local all postgres peer\n")
	for _, database := range databases {
		if !postgresAuthorityID.MatchString(database.DatabaseName) ||
			!postgresAuthorityID.MatchString(database.RuntimeRole) || database.ServerAuthPolicyID != p.ID {
			return nil, ErrInvalidProfile
		}
		document.WriteString("hostssl ")
		document.WriteString(database.DatabaseName)
		document.WriteByte(' ')
		document.WriteString(database.RuntimeRole)
		document.WriteByte(' ')
		document.WriteString(p.IngressCIDR)
		document.WriteString(" scram-sha-256 clientcert=verify-full clientname=CN\n")
	}
	document.WriteString("host all all 0.0.0.0/0 reject\n")
	document.WriteString("host all all ::/0 reject\n")
	return []byte(document.String()), nil
}

func (p PostgresServerAuthPolicy) validate(databases []ProviderDatabaseBinding,
	external map[string]ExternalService, anchors []TrustAnchor) error {
	service, known := external[p.ServiceName]
	if p.ID != postgresServerAuthPolicyID || p.Scope != postgresServerAuthScope ||
		p.ServiceName != "postgres" || !known || p.ServiceIdentityDigest != service.IdentityDigest ||
		!namePattern.MatchString(p.HBAArtifactID) || !digestPattern.MatchString(p.HBADigest) ||
		p.ClientCAAnchorID != postgresClientIssuerAnchorID {
		return ErrInvalidProfile
	}
	var anchor TrustAnchor
	for _, candidate := range anchors {
		if candidate.ID == p.ClientCAAnchorID {
			anchor = candidate
			break
		}
	}
	if anchor.ID == "" || anchor.Purpose != "client_verification" ||
		!namePattern.MatchString(anchor.ArtifactID) || !digestPattern.MatchString(anchor.BundleDigest) {
		return ErrInvalidProfile
	}
	document, err := p.RenderProviderHBA(databases)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(document)
	if p.HBADigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return ErrInvalidProfile
	}
	return nil
}

// VerifyRawServerArtifacts compares the actual bytes read from a controlled
// PostgreSQL configuration mount with the profile's single approved HBA and
// existing client-CA anchor. File provenance, read-only mounting, process
// identity and successful enforcement are separate live-gate requirements.
func (p PostgresServerAuthPolicy) VerifyRawServerArtifacts(databases []ProviderDatabaseBinding,
	anchor TrustAnchor, hbaBytes, clientCABytes []byte, now time.Time) error {
	expectedHBA, err := p.RenderProviderHBA(databases)
	if err != nil || now.IsZero() || len(hbaBytes) < 1 || len(hbaBytes) > 64<<10 ||
		len(clientCABytes) < 1 || len(clientCABytes) > 256<<10 ||
		!bytes.Equal(hbaBytes, expectedHBA) || anchor.ID != p.ClientCAAnchorID ||
		anchor.Purpose != "client_verification" {
		return ErrInvalidProfile
	}
	hbaSum, caSum := sha256.Sum256(hbaBytes), sha256.Sum256(clientCABytes)
	if p.HBADigest != "sha256:"+hex.EncodeToString(hbaSum[:]) ||
		anchor.BundleDigest != "sha256:"+hex.EncodeToString(caSum[:]) {
		return ErrInvalidProfile
	}
	block, trailing := pem.Decode(clientCABytes)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(trailing)) != 0 {
		return ErrInvalidProfile
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return ErrInvalidProfile
	}
	return nil
}
