package providerapi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/provideridentity"
)

const (
	maxServerCertificateBytes = 64 << 10
	maxServerPrivateKeyBytes  = 64 << 10
	maxClientCABundleBytes    = 256 << 10
	maxClientCACertificates   = 32
)

// loadMTLSConfig loads and freezes the Provider listener's mTLS material.
//
// Each allowed identity must be an absolute URI in its exact canonical string
// representation: parsing the value as a URI and serializing it again must not
// change it. Admission compares that string byte-for-byte with URI SANs in the
// verified client leaf. Callers must treat the returned tls.Config as immutable.
func loadMTLSConfig(certPath, keyPath, clientCAPath string, allowedURIIdentities []string) (*tls.Config, error) {
	tlsConfig, _, err := loadMTLSConfigWithIdentity(certPath, keyPath, clientCAPath, allowedURIIdentities)
	return tlsConfig, err
}

func loadMTLSConfigWithIdentity(certPath, keyPath, clientCAPath string, allowedURIIdentities []string) (*tls.Config, *clientIdentityAdmission, error) {
	if certPath == "" || keyPath == "" || clientCAPath == "" {
		return nil, nil, errors.New("provider mTLS certificate, key, and client CA paths are required")
	}

	certificatePEM, err := readBoundedTLSMaterial(certPath, maxServerCertificateBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read provider mTLS server certificate: %w", err)
	}
	privateKeyPEM, err := readBoundedPrivateTLSMaterial(keyPath, maxServerPrivateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read provider mTLS server private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load provider mTLS server key pair: %w", err)
	}
	if err := validateServerCertificate(certificate, time.Now()); err != nil {
		return nil, nil, fmt.Errorf("validate provider mTLS server certificate: %w", err)
	}

	clientCAs, err := loadCertPool(clientCAPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load provider mTLS client CA bundle: %w", err)
	}

	identityAdmission, err := newClientIdentityAdmission(allowedURIIdentities)
	if err != nil {
		return nil, nil, err
	}

	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		Certificates:     []tls.Certificate{certificate},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCAs,
		VerifyConnection: identityAdmission.VerifyConnection,
	}, identityAdmission, nil
}

func validateServerCertificate(certificate tls.Certificate, now time.Time) error {
	if len(certificate.Certificate) == 0 {
		return errors.New("server certificate chain is empty")
	}
	for index, raw := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse certificate %d: %w", index, err)
		}
		if now.Before(parsed.NotBefore) {
			return fmt.Errorf("certificate %d is not valid yet", index)
		}
		if now.After(parsed.NotAfter) {
			return fmt.Errorf("certificate %d is expired", index)
		}
		if index == 0 && !hasExplicitExtKeyUsage(parsed, x509.ExtKeyUsageServerAuth) {
			return errors.New("server leaf certificate lacks explicit server-auth usage")
		}
	}
	return nil
}

func hasExplicitExtKeyUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) bool {
	if certificate == nil {
		return false
	}
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

func loadCertPool(path string) (*x509.CertPool, error) {
	contents, err := readBoundedTLSMaterial(path, maxClientCABundleBytes)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(contents))) == 0 {
		return nil, errors.New("client CA bundle is empty")
	}

	pool := x509.NewCertPool()
	certificates := 0
	remaining := contents
	for len(strings.TrimSpace(string(remaining))) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("client CA bundle contains malformed PEM data")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("client CA bundle contains a non-certificate PEM block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("client CA bundle contains an invalid certificate")
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("client CA bundle contains a certificate that is not a certificate authority")
		}
		now := time.Now()
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return nil, errors.New("client CA bundle contains a certificate outside its validity period")
		}
		if certificates >= maxClientCACertificates {
			return nil, fmt.Errorf("client CA bundle contains more than %d certificates", maxClientCACertificates)
		}
		pool.AddCert(certificate)
		certificates++
		remaining = rest
	}
	if certificates == 0 {
		return nil, errors.New("client CA bundle contains no certificates")
	}

	return pool, nil
}

func newClientIdentityAdmission(identities []string) (*clientIdentityAdmission, error) {
	if err := provideridentity.ValidateAllowlist(identities); err != nil {
		return nil, fmt.Errorf("provider mTLS client URI identity allowlist: %w", err)
	}

	allowed := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		allowed[identity] = struct{}{}
	}

	return &clientIdentityAdmission{allowed: allowed}, nil
}

func readBoundedTLSMaterial(path string, maxBytes int) ([]byte, error) {
	return readBoundedTLSMaterialWithPrivacy(path, maxBytes, false)
}

func readBoundedPrivateTLSMaterial(path string, maxBytes int) ([]byte, error) {
	return readBoundedTLSMaterialWithPrivacy(path, maxBytes, true)
}

func readBoundedTLSMaterialWithPrivacy(path string, maxBytes int, private bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}
	if maxBytes < 1 {
		return nil, errors.New("positive file size limit is required")
	}
	file, err := openRegularTLSFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if private {
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("private key file permissions are too broad")
		}
	}
	contents, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return contents, nil
}
