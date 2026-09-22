// Package tlsmaterial resolves and freezes TLS configurations from one
// role-owned scoped material registry.
package tlsmaterial

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/providerapi"
)

const (
	maxCertificateBytes = 64 << 10
	maxPrivateKeyBytes  = 64 << 10
	maxCABundleBytes    = 256 << 10
	maxCACertificates   = 32
)

func ResolveServer(ctx context.Context, registry *secretref.Registry, certificateID, privateKeyID, expectedServerName string, now func() time.Time) (*tls.Config, error) {
	certificate, privateKey, instant, err := resolveIdentity(ctx, registry, certificateID, privateKeyID, secretref.PurposeTLSPrivateKey, expectedServerName, now)
	if err != nil {
		return nil, err
	}
	defer certificate.Destroy()
	defer privateKey.Destroy()
	pair, leaf, err := parseIdentity(certificate.Bytes, privateKey.Bytes, x509.ExtKeyUsageServerAuth, instant)
	if err != nil || leaf.VerifyHostname(expectedServerName) != nil {
		return nil, errors.New("invalid TLS server identity material")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, nil
}

func ResolveMutualServer(ctx context.Context, registry *secretref.Registry, certificateID, privateKeyID, clientCAID, expectedServerName string, allowedIdentities []string, now func() time.Time) (*tls.Config, error) {
	certificate, privateKey, instant, err := resolveIdentity(ctx, registry, certificateID, privateKeyID, secretref.PurposeTLSPrivateKey, expectedServerName, now)
	if err != nil {
		return nil, err
	}
	defer certificate.Destroy()
	defer privateKey.Destroy()
	clientCA, err := registry.Resolve(ctx, clientCAID, secretref.PurposeCABundle, secretref.SystemTenant)
	if err != nil {
		clientCA.Destroy()
		return nil, materialError(err)
	}
	defer clientCA.Destroy()
	if len(certificate.Bytes) > maxCertificateBytes || len(privateKey.Bytes) > maxPrivateKeyBytes || len(clientCA.Bytes) > maxCABundleBytes {
		return nil, errors.New("TLS material exceeds its bound")
	}
	tlsConfig, err := providerapi.LoadMTLSConfigMaterial(certificate.Bytes, privateKey.Bytes, clientCA.Bytes, allowedIdentities, instant)
	if err != nil {
		return nil, errors.New("invalid mutual TLS server material")
	}
	leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil || leaf.VerifyHostname(expectedServerName) != nil {
		return nil, errors.New("invalid mutual TLS server identity")
	}
	tlsConfig.MaxVersion = tls.VersionTLS13
	return tlsConfig, nil
}

func ResolveClient(ctx context.Context, registry *secretref.Registry, caID, certificateID, privateKeyID, serverName string, now func() time.Time) (*tls.Config, error) {
	return ResolveClientWithKeyPurpose(ctx, registry, caID, certificateID, privateKeyID, secretref.PurposeTLSPrivateKey, serverName, now)
}

func ResolveClientWithKeyPurpose(ctx context.Context, registry *secretref.Registry, caID, certificateID, privateKeyID string, privateKeyPurpose secretref.Purpose, serverName string, now func() time.Time) (*tls.Config, error) {
	certificate, privateKey, instant, err := resolveIdentity(ctx, registry, certificateID, privateKeyID, privateKeyPurpose, serverName, now)
	if err != nil {
		return nil, err
	}
	defer certificate.Destroy()
	defer privateKey.Destroy()
	ca, err := registry.Resolve(ctx, caID, secretref.PurposeCABundle, secretref.SystemTenant)
	if err != nil {
		ca.Destroy()
		return nil, materialError(err)
	}
	defer ca.Destroy()
	if len(certificate.Bytes) > maxCertificateBytes || len(privateKey.Bytes) > maxPrivateKeyBytes || len(ca.Bytes) > maxCABundleBytes {
		return nil, errors.New("TLS material exceeds its bound")
	}
	pair, _, err := parseIdentity(certificate.Bytes, privateKey.Bytes, x509.ExtKeyUsageClientAuth, instant)
	if err != nil {
		return nil, errors.New("invalid TLS client identity material")
	}
	roots, err := parseCABundle(ca.Bytes, instant)
	if err != nil {
		return nil, errors.New("invalid TLS trust material")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: serverName}, nil
}

func resolveIdentity(ctx context.Context, registry *secretref.Registry, certificateID, privateKeyID string, privateKeyPurpose secretref.Purpose, serverName string, now func() time.Time) (secretref.SecretMaterial, secretref.SecretMaterial, time.Time, error) {
	if ctx == nil || registry == nil || now == nil || strings.TrimSpace(serverName) != serverName || serverName == "" || len(serverName) > 253 || strings.ContainsAny(serverName, "\x00\r\n\t /\\") {
		return secretref.SecretMaterial{}, secretref.SecretMaterial{}, time.Time{}, errors.New("invalid TLS material configuration")
	}
	instant := now()
	if instant.IsZero() {
		return secretref.SecretMaterial{}, secretref.SecretMaterial{}, time.Time{}, errors.New("invalid TLS material clock")
	}
	certificate, err := registry.Resolve(ctx, certificateID, secretref.PurposeTLSCertificate, secretref.SystemTenant)
	if err != nil {
		certificate.Destroy()
		return secretref.SecretMaterial{}, secretref.SecretMaterial{}, time.Time{}, materialError(err)
	}
	privateKey, err := registry.Resolve(ctx, privateKeyID, privateKeyPurpose, secretref.SystemTenant)
	if err != nil {
		certificate.Destroy()
		privateKey.Destroy()
		return secretref.SecretMaterial{}, secretref.SecretMaterial{}, time.Time{}, materialError(err)
	}
	if certificate.Binding.Version != privateKey.Binding.Version || certificate.Revision != privateKey.Revision ||
		certificate.Window.State != privateKey.Window.State || !certificate.Window.NotBefore.Equal(privateKey.Window.NotBefore) || !certificate.Window.NotAfter.Equal(privateKey.Window.NotAfter) {
		certificate.Destroy()
		privateKey.Destroy()
		return secretref.SecretMaterial{}, secretref.SecretMaterial{}, time.Time{}, errors.New("TLS identity material revision mismatch")
	}
	return certificate, privateKey, instant, nil
}

func parseIdentity(certificatePEM, privateKeyPEM []byte, required x509.ExtKeyUsage, now time.Time) (tls.Certificate, *x509.Certificate, error) {
	if len(certificatePEM) == 0 || len(certificatePEM) > maxCertificateBytes || len(privateKeyPEM) == 0 || len(privateKeyPEM) > maxPrivateKeyBytes {
		return tls.Certificate{}, nil, errors.New("invalid TLS identity size")
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(pair.Certificate) == 0 || !exactPrivateKey(privateKeyPEM) {
		return tls.Certificate{}, nil, errors.New("invalid TLS key pair")
	}
	chain, ok := exactCertificateChain(certificatePEM)
	if !ok || len(chain) != len(pair.Certificate) {
		return tls.Certificate{}, nil, errors.New("invalid TLS certificate chain")
	}
	for index, certificate := range chain {
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return tls.Certificate{}, nil, errors.New("TLS certificate is outside its validity period")
		}
		if index == 0 && !explicitUsage(certificate, required) {
			return tls.Certificate{}, nil, errors.New("TLS leaf usage is invalid")
		}
	}
	return pair, chain[0], nil
}

func parseCABundle(document []byte, now time.Time) (*x509.CertPool, error) {
	if len(document) == 0 || len(document) > maxCABundleBytes {
		return nil, errors.New("invalid CA bundle size")
	}
	pool := x509.NewCertPool()
	remaining := document
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || count >= maxCACertificates {
			return nil, errors.New("invalid CA bundle")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return nil, errors.New("invalid CA certificate")
		}
		pool.AddCert(certificate)
		count++
		remaining = rest
	}
	if count == 0 {
		return nil, errors.New("empty CA bundle")
	}
	return pool, nil
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

func explicitUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) bool {
	found := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return false
		}
		if usage == required {
			found = true
		}
	}
	return found
}

func materialError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New("TLS material is unavailable")
}
