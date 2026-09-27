package workloadpki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"time"
)

const PostgresClientPurpose = "postgres_client"

var postgresIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var postgresClientSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
var certificateExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// PostgresClientIdentity is a separate, closed certificate purpose. Its CN is
// exactly the profile-bound SQL runtime role, never a CSR input. PostgreSQL
// checks that CN directly during SCRAM plus clientcert=verify-full; it cannot
// inspect the owner URI SAN and cannot use pg_ident map with SCRAM.
type PostgresClientIdentity struct {
	OwnerDeployment string
	DatabaseName    string
	RuntimeRole     string
	ServiceName     string
	URI             string
	CommonName      string
	MaxTTL          time.Duration
}

func PostgresClientCommonName(runtimeRole string) string {
	return runtimeRole
}

func (identity PostgresClientIdentity) Validate() error {
	if identity.OwnerDeployment != "provider-browser-runtime" &&
		identity.OwnerDeployment != "provider-desktop-runtime" {
		return ErrInvalid
	}
	parsed, err := url.Parse(identity.URI)
	if err != nil || parsed == nil || parsed.Scheme != "spiffe" || parsed.Host == "" ||
		parsed.Path != "/"+identity.OwnerDeployment || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != identity.URI ||
		identity.ServiceName != "postgres" || !postgresIdentifier.MatchString(identity.DatabaseName) ||
		!postgresIdentifier.MatchString(identity.RuntimeRole) ||
		identity.CommonName != PostgresClientCommonName(identity.RuntimeRole) ||
		len(identity.CommonName) > 64 || identity.MaxTTL < time.Minute || identity.MaxTTL > time.Hour {
		return ErrInvalid
	}
	return nil
}

func postgresSubject(commonName string) ([]byte, error) {
	return asn1.Marshal(pkix.Name{CommonName: commonName}.ToRDNSequence())
}

func postgresSAN(uri string) ([]byte, error) {
	return asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}})
}

// ValidatePostgresClientCSR accepts exactly one CN and one URI SAN. Other
// Subject attributes, requested extensions, alternate SAN types and keys are
// rejected before a controller may submit the CSR to Vault.
func ValidatePostgresClientCSR(document []byte, identity PostgresClientIdentity) error {
	if identity.Validate() != nil {
		return ErrInvalid
	}
	block, trailing := pem.Decode(document)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(trailing)) != 0 {
		return ErrDenied
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		return ErrDenied
	}
	return validatePostgresClientRequest(request, identity)
}

func validatePostgresClientRequest(request *x509.CertificateRequest, identity PostgresClientIdentity) error {
	expectedSubject, subjectErr := postgresSubject(identity.CommonName)
	expectedSAN, sanErr := postgresSAN(identity.URI)
	key, keyOK := request.PublicKey.(*ecdsa.PublicKey)
	if subjectErr != nil || sanErr != nil || !keyOK || key.Curve != elliptic.P256() ||
		!bytes.Equal(request.RawSubject, expectedSubject) ||
		len(request.URIs) != 1 || request.URIs[0] == nil || request.URIs[0].String() != identity.URI ||
		len(request.DNSNames) != 0 || len(request.IPAddresses) != 0 || len(request.EmailAddresses) != 0 ||
		len(request.Attributes) != 1 || !request.Attributes[0].Type.Equal(certificateExtensionRequest) ||
		len(request.Attributes[0].Value) != 1 || len(request.Attributes[0].Value[0]) != 1 ||
		!request.Attributes[0].Value[0][0].Type.Equal(postgresClientSAN) ||
		len(request.Extensions) != 1 || !request.Extensions[0].Id.Equal(postgresClientSAN) ||
		request.Extensions[0].Critical || !bytes.Equal(request.Extensions[0].Value, expectedSAN) {
		return ErrDenied
	}
	return nil
}

// ValidatePostgresClientLeaf is the client-side and issuance-time identity
// check. Chain, issuer, CRL and private-signer checks remain separate and
// mandatory; passing this leaf check alone is never admission evidence.
func ValidatePostgresClientLeaf(leaf *x509.Certificate, identity PostgresClientIdentity, now time.Time) error {
	if identity.Validate() != nil || leaf == nil || now.IsZero() {
		return ErrInvalid
	}
	expectedSubject, subjectErr := postgresSubject(identity.CommonName)
	expectedSAN, sanErr := postgresSAN(identity.URI)
	key, keyOK := leaf.PublicKey.(*ecdsa.PublicKey)
	if subjectErr != nil || sanErr != nil || !keyOK || key.Curve != elliptic.P256() ||
		leaf.IsCA || !bytes.Equal(leaf.RawSubject, expectedSubject) ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		len(leaf.UnknownExtKeyUsage) != 0 ||
		len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != identity.URI ||
		len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.NotAfter.Sub(leaf.NotBefore) <= 0 || leaf.NotAfter.Sub(leaf.NotBefore) > identity.MaxTTL {
		return errors.New("PostgreSQL client certificate identity is invalid")
	}
	var foundSAN bool
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(postgresClientSAN) {
			if foundSAN || extension.Critical || !bytes.Equal(extension.Value, expectedSAN) {
				return ErrDenied
			}
			foundSAN = true
		}
	}
	if !foundSAN {
		return ErrDenied
	}
	return nil
}
