package workloadtlsagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"reflect"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// ValidateBootstrapCertificate validates the narrowly scoped, operator-
// provisioned certificate used for the certificate controller's first Vault
// operation. The returned private key remains process-local and must be
// destroyed immediately after the managed certificate has replaced it.
func ValidateBootstrapCertificate(certificatePEM, keyPEM []byte, roots *x509.CertPool, policy workloadpki.Policy, now time.Time) (tls.Certificate, error) {
	if len(certificatePEM) < 1 || len(certificatePEM) > 256<<10 || len(keyPEM) < 1 || len(keyPEM) > 64<<10 ||
		roots == nil || policy.Validate() != nil || now.IsZero() || !slices.Equal(policy.Usages, []string{"client_auth"}) ||
		!strictPEM(keyPEM, 1, map[string]bool{"EC PRIVATE KEY": true, "PRIVATE KEY": true}) {
		return tls.Certificate{}, ErrUnavailable
	}
	chainCount, ok := strictCertificatePEM(certificatePEM)
	if !ok || chainCount < 2 || chainCount > 9 {
		return tls.Certificate{}, ErrUnavailable
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) != chainCount {
		return tls.Certificate{}, ErrUnavailable
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.PublicKeyAlgorithm != x509.ECDSA ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature || !reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 ||
		!leaf.NotBefore.Before(leaf.NotAfter) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.NotAfter.Sub(leaf.NotBefore) > time.Hour || leaf.Subject.String() != "" || len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() != policy.URI || !slices.Equal(leaf.DNSNames, policy.DNSNames) {
		return tls.Certificate{}, ErrUnavailable
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return tls.Certificate{}, ErrUnavailable
	}
	identity, err := url.Parse(policy.URI)
	if err != nil || leaf.URIs[0].Scheme != identity.Scheme || leaf.URIs[0].Host != identity.Host || leaf.URIs[0].Path != identity.Path {
		return tls.Certificate{}, ErrUnavailable
	}
	intermediates := x509.NewCertPool()
	parsedChain := make([]*x509.Certificate, 0, len(pair.Certificate))
	parsedChain = append(parsedChain, leaf)
	for _, document := range pair.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(document)
		if parseErr != nil || !certificate.IsCA {
			return tls.Certificate{}, ErrUnavailable
		}
		intermediates.AddCert(certificate)
		parsedChain = append(parsedChain, certificate)
	}
	verified, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(verified) != 1 || len(verified[0]) != len(parsedChain) {
		return tls.Certificate{}, ErrUnavailable
	}
	for index := range parsedChain {
		if !bytes.Equal(verified[0][index].Raw, parsedChain[index].Raw) {
			return tls.Certificate{}, ErrUnavailable
		}
	}
	pair.Leaf = leaf
	return pair, nil
}

func DestroyTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	if key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey); ok {
		destroyPrivateKey(key)
	}
	for _, document := range certificate.Certificate {
		clear(document)
	}
	certificate.Certificate, certificate.PrivateKey, certificate.Leaf = nil, nil, nil
}

func strictCertificatePEM(document []byte) (int, bool) {
	remaining, count := document, 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return 0, false
		}
		count++
		remaining = rest
	}
	return count, count > 0
}

func strictPEM(document []byte, expected int, allowed map[string]bool) bool {
	remaining, count := document, 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || !allowed[block.Type] || len(block.Headers) != 0 {
			return false
		}
		count++
		remaining = rest
	}
	return count == expected
}

// BootstrapWithinProfileLifetime checks the complete X.509 interval after
// ValidateBootstrapCertificate verifies identity, chain, key and usages. The
// ceiling is the bound Profile policy, not the shorter managed request TTL.
func BootstrapWithinProfileLifetime(leaf *x509.Certificate, maxTTLSeconds int64,
	minimumRemaining time.Duration, now time.Time) bool {
	return leaf != nil && maxTTLSeconds >= 60 && maxTTLSeconds <= 3600 && minimumRemaining > 0 && !now.IsZero() &&
		leaf.NotBefore.Before(leaf.NotAfter) && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) &&
		leaf.NotAfter.Sub(leaf.NotBefore) <= time.Duration(maxTTLSeconds)*time.Second &&
		leaf.NotAfter.Sub(now) > minimumRemaining
}
