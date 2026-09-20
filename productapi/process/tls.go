package process

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const (
	maxCertificateBytes = 64 << 10
	maxPrivateKeyBytes  = 64 << 10
)

// LoadTLSConfig reads one bounded private server key pair and returns a TLS
// 1.3-only immutable startup configuration.
func LoadTLSConfig(certificatePath, privateKeyPath string) (*tls.Config, error) {
	certificatePEM, err := secretfile.Read(certificatePath, maxCertificateBytes)
	if err != nil {
		return nil, errors.New("load Product TLS certificate")
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := secretfile.Read(privateKeyPath, maxPrivateKeyBytes)
	if err != nil {
		return nil, errors.New("load Product TLS private key")
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("invalid Product TLS key pair")
	}
	certificates, ok := exactCertificateChain(certificatePEM)
	if !ok || len(certificates) != len(certificate.Certificate) || !exactPrivateKey(privateKeyPEM) {
		return nil, errors.New("invalid Product TLS PEM material")
	}
	now := time.Now()
	for _, parsed := range certificates {
		if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
			return nil, errors.New("invalid Product TLS certificate validity")
		}
	}
	if !explicitServerAuth(certificates[0]) {
		return nil, errors.New("invalid Product TLS server certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, nil
}

func exactCertificateChain(document []byte) ([]*x509.Certificate, bool) {
	remaining := document
	certificates := make([]*x509.Certificate, 0, 2)
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certificates) >= 8 {
			return nil, false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, false
		}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	return certificates, len(certificates) > 0
}

func exactPrivateKey(document []byte) bool {
	block, rest := pem.Decode(document)
	return block != nil && block.Type == "PRIVATE KEY" && len(block.Headers) == 0 && len(bytes.TrimSpace(rest)) == 0
}

func explicitServerAuth(certificate *x509.Certificate) bool {
	found := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return false
		}
		if usage == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	return found
}
