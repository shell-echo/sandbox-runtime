package phase6profilebuilder

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidDNSClientCA = errors.New("invalid Phase 6 DNS broker-client CA supply")

type DNSClientCAInput struct {
	BundlePath string
	IssuerID   string
}

// DNSClientCASupply holds the sole exact public CA that the external DNS
// listener may load for client authentication. It cannot attest that Vault
// owns the corresponding private key or that a running listener mounted it.
type DNSClientCASupply struct {
	path       string
	bundle     []byte
	issuerID   string
	issuerHash string
}

func LoadSlice6DNSClientCASupply(input DNSClientCAInput, now time.Time) (DNSClientCASupply, error) {
	if now.IsZero() || !phase6security.ValidSlice6IssuerID(input.IssuerID) {
		return DNSClientCASupply{}, ErrInvalidDNSClientCA
	}
	bundle, err := readSlice6OperatorCABundle(input.BundlePath, now)
	if err != nil {
		return DNSClientCASupply{}, ErrInvalidDNSClientCA
	}
	block, rest := pem.Decode(bundle)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		clear(bundle)
		return DNSClientCASupply{}, ErrInvalidDNSClientCA
	}
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !issuer.IsCA || !issuer.BasicConstraintsValid ||
		issuer.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		clear(bundle)
		return DNSClientCASupply{}, ErrInvalidDNSClientCA
	}
	sum := sha256.Sum256(block.Bytes)
	return DNSClientCASupply{path: input.BundlePath, bundle: bundle, issuerID: input.IssuerID,
		issuerHash: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func (s DNSClientCASupply) VerifySources(now time.Time) error {
	if s.path == "" || s.issuerHash == "" || !phase6security.ValidSlice6IssuerID(s.issuerID) {
		return ErrInvalidDNSClientCA
	}
	current, err := LoadSlice6DNSClientCASupply(DNSClientCAInput{BundlePath: s.path, IssuerID: s.issuerID}, now)
	if err != nil || !bytes.Equal(s.bundle, current.bundle) || s.issuerHash != current.issuerHash {
		return ErrInvalidDNSClientCA
	}
	return nil
}

func (s DNSClientCASupply) Binding() (phase6security.DNSClientCA, error) {
	if len(s.bundle) == 0 || s.issuerHash == "" || !phase6security.ValidSlice6IssuerID(s.issuerID) {
		return phase6security.DNSClientCA{}, ErrInvalidDNSClientCA
	}
	sum := sha256.Sum256(s.bundle)
	return phase6security.DNSClientCA{ArtifactID: "dns-broker-client-ca",
		BundleDigest: "sha256:" + hex.EncodeToString(sum[:]), IssuerID: s.issuerID,
		IssuerDigest: s.issuerHash, AllowedSubjects: phase6security.Slice6DNSBrokerSubjects()}, nil
}
