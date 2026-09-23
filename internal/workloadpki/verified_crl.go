package workloadpki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"time"
)

var ErrPeerRevoked = errors.New("workload peer certificate revoked")

var (
	deltaCRLIndicatorOID        = asn1.ObjectIdentifier{2, 5, 29, 27}
	issuingDistributionPointOID = asn1.ObjectIdentifier{2, 5, 29, 28}
	certificateIssuerOID        = asn1.ObjectIdentifier{2, 5, 29, 29}
	authorityKeyIdentifierOID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	crlNumberOID                = asn1.ObjectIdentifier{2, 5, 29, 20}
)

// VerifiedCRL binds one complete, signed CRL to the full DER digest of its
// issuing CA. An issuer-revision label from Vault is not an issuer identity.
// The caller must also bind issuerDER to the exact profile peer anchor and
// take it from the TLS verified chain, not from an HTTP field.
type VerifiedCRL struct {
	issuerDigest string
	crlDigest    string
	number       *big.Int
	thisUpdate   time.Time
	nextUpdate   time.Time
	revoked      map[string]struct{}
}

func VerifyCRLForIssuer(snapshot RevocationSnapshot, issuerDER []byte, now time.Time) (VerifiedCRL, error) {
	if len(snapshot.DER) == 0 || len(snapshot.DER) > maxVaultResponseBytes || len(issuerDER) == 0 ||
		len(issuerDER) > 64<<10 || now.IsZero() || snapshot.ThisUpdate.IsZero() || snapshot.NextUpdate.IsZero() {
		return VerifiedCRL{}, ErrUnavailable
	}
	issuer, issuerErr := x509.ParseCertificate(issuerDER)
	list, listErr := x509.ParseRevocationList(snapshot.DER)
	if issuerErr != nil || listErr != nil || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 ||
		len(issuer.SubjectKeyId) == 0 || len(list.AuthorityKeyId) == 0 ||
		!bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId) ||
		!bytes.Equal(list.RawIssuer, issuer.RawSubject) || list.CheckSignatureFrom(issuer) != nil ||
		list.Number == nil || list.Number.Sign() < 1 ||
		!list.ThisUpdate.Equal(snapshot.ThisUpdate) || !list.NextUpdate.Equal(snapshot.NextUpdate) ||
		now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) ||
		now.Before(list.ThisUpdate) || !now.Before(list.NextUpdate) || !list.NextUpdate.After(list.ThisUpdate) {
		return VerifiedCRL{}, ErrUnavailable
	}
	// A valid signature alone is not enough to prove absence from a *complete*
	// CRL. Delta, distribution-point-scoped and indirect CRLs can legitimately
	// omit a revoked serial, so they must never satisfy peer admission.
	for _, extension := range list.Extensions {
		if extension.Id.Equal(deltaCRLIndicatorOID) || extension.Id.Equal(issuingDistributionPointOID) ||
			(extension.Critical && !extension.Id.Equal(authorityKeyIdentifierOID) && !extension.Id.Equal(crlNumberOID)) {
			return VerifiedCRL{}, ErrUnavailable
		}
	}
	revoked := make(map[string]struct{}, len(list.RevokedCertificateEntries))
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() < 1 || entry.RevocationTime.After(now) {
			return VerifiedCRL{}, ErrUnavailable
		}
		for _, extension := range entry.Extensions {
			if extension.Id.Equal(certificateIssuerOID) || extension.Critical {
				return VerifiedCRL{}, ErrUnavailable
			}
		}
		serial := serialString(entry.SerialNumber.Bytes())
		if _, duplicate := revoked[serial]; duplicate {
			return VerifiedCRL{}, ErrUnavailable
		}
		revoked[serial] = struct{}{}
	}
	issuerHash, crlHash := sha256.Sum256(issuerDER), sha256.Sum256(snapshot.DER)
	return VerifiedCRL{issuerDigest: "sha256:" + hex.EncodeToString(issuerHash[:]),
		crlDigest: "sha256:" + hex.EncodeToString(crlHash[:]), number: new(big.Int).Set(list.Number),
		thisUpdate: list.ThisUpdate, nextUpdate: list.NextUpdate, revoked: revoked}, nil
}

func (c VerifiedCRL) IssuerDigest() string { return c.issuerDigest }
func (c VerifiedCRL) CRLDigest() string    { return c.crlDigest }
func (c VerifiedCRL) Number() *big.Int {
	if c.number == nil {
		return nil
	}
	return new(big.Int).Set(c.number)
}
func (c VerifiedCRL) ThisUpdate() time.Time { return c.thisUpdate }
func (c VerifiedCRL) NextUpdate() time.Time { return c.nextUpdate }

// CheckPeer is only valid after TLS has verified the leaf and issuer against
// the profile's exact peer-verification root and identity policy.
func (c VerifiedCRL) CheckPeer(leafDER, issuerDER []byte, now time.Time) error {
	if c.number == nil || now.IsZero() || now.Before(c.thisUpdate) || !now.Before(c.nextUpdate) ||
		len(leafDER) == 0 || len(leafDER) > 64<<10 || len(issuerDER) == 0 || len(issuerDER) > 64<<10 {
		return ErrUnavailable
	}
	issuerHash := sha256.Sum256(issuerDER)
	if "sha256:"+hex.EncodeToString(issuerHash[:]) != c.issuerDigest {
		return ErrUnavailable
	}
	issuer, issuerErr := x509.ParseCertificate(issuerDER)
	leaf, leafErr := x509.ParseCertificate(leafDER)
	if issuerErr != nil || leafErr != nil || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() < 1 ||
		!bytes.Equal(leaf.RawIssuer, issuer.RawSubject) || leaf.CheckSignatureFrom(issuer) != nil ||
		(len(leaf.AuthorityKeyId) != 0 && !bytes.Equal(leaf.AuthorityKeyId, issuer.SubjectKeyId)) ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return ErrUnavailable
	}
	if _, exists := c.revoked[serialString(leaf.SerialNumber.Bytes())]; exists {
		return ErrPeerRevoked
	}
	return nil
}
