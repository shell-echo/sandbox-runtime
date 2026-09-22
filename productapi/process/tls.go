package process

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
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
	return parseServerTLSConfig(certificatePEM, privateKeyPEM, "", time.Now())
}

// LoadTLSConfigFromRegistry resolves one atomically versioned Product server
// certificate/key bundle. Raw material is cleared after parsing; rotation uses
// a new matching revision and process replacement.
func LoadTLSConfigFromRegistry(ctx context.Context, registry *secretref.Registry, certificateBindingID, privateKeyBindingID, expectedServerName string, now func() time.Time) (*tls.Config, error) {
	if ctx == nil || registry == nil || now == nil || now().IsZero() || strings.TrimSpace(expectedServerName) != expectedServerName || expectedServerName == "" || len(expectedServerName) > 253 || strings.ContainsAny(expectedServerName, "\x00\r\n\t /\\") {
		return nil, errors.New("invalid Product TLS material configuration")
	}
	certificate, err := registry.Resolve(ctx, certificateBindingID, secretref.PurposeTLSCertificate, secretref.SystemTenant)
	if err != nil {
		certificate.Destroy()
		return nil, tlsMaterialError(err, "load Product TLS certificate material")
	}
	defer certificate.Destroy()
	privateKey, err := registry.Resolve(ctx, privateKeyBindingID, secretref.PurposeTLSPrivateKey, secretref.SystemTenant)
	if err != nil {
		privateKey.Destroy()
		return nil, tlsMaterialError(err, "load Product TLS private key material")
	}
	defer privateKey.Destroy()
	if certificate.Binding.Version != privateKey.Binding.Version || certificate.Revision != privateKey.Revision ||
		certificate.Window.State != privateKey.Window.State || !certificate.Window.NotBefore.Equal(privateKey.Window.NotBefore) ||
		!certificate.Window.NotAfter.Equal(privateKey.Window.NotAfter) {
		return nil, errors.New("invalid Product TLS material revision")
	}
	return parseServerTLSConfig(certificate.Bytes, privateKey.Bytes, expectedServerName, now())
}

func tlsMaterialError(err error, message string) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New(message)
}

func parseServerTLSConfig(certificatePEM, privateKeyPEM []byte, expectedServerName string, now time.Time) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("invalid Product TLS key pair")
	}
	certificates, ok := exactCertificateChain(certificatePEM)
	if !ok || len(certificates) != len(certificate.Certificate) || !exactPrivateKey(privateKeyPEM) {
		return nil, errors.New("invalid Product TLS PEM material")
	}
	for _, parsed := range certificates {
		if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
			return nil, errors.New("invalid Product TLS certificate validity")
		}
	}
	if !explicitServerAuth(certificates[0]) {
		return nil, errors.New("invalid Product TLS server certificate")
	}
	if expectedServerName != "" && certificates[0].VerifyHostname(expectedServerName) != nil {
		return nil, errors.New("invalid Product TLS server identity")
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
