package providerapi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// loadMTLSConfig loads and freezes the Provider listener's mTLS material.
//
// Each allowed identity must be an absolute URI in its exact canonical string
// representation: parsing the value as a URI and serializing it again must not
// change it. Admission compares that string byte-for-byte with URI SANs in the
// verified client leaf. Callers must treat the returned tls.Config as immutable.
func loadMTLSConfig(certPath, keyPath, clientCAPath string, allowedURIIdentities []string) (*tls.Config, error) {
	if certPath == "" || keyPath == "" || clientCAPath == "" {
		return nil, errors.New("provider mTLS certificate, key, and client CA paths are required")
	}

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load provider mTLS server key pair: %w", err)
	}
	if err := validateServerCertificate(certificate, time.Now()); err != nil {
		return nil, fmt.Errorf("validate provider mTLS server certificate: %w", err)
	}

	clientCAs, err := loadCertPool(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("load provider mTLS client CA bundle: %w", err)
	}

	allowed, err := freezeAllowedURIIdentities(allowedURIIdentities)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
				return errors.New("provider mTLS client has no verified certificate chain")
			}

			leaf := state.VerifiedChains[0][0]
			if leaf == nil {
				return errors.New("provider mTLS client has no verified leaf certificate")
			}
			if !hasExplicitExtKeyUsage(leaf, x509.ExtKeyUsageClientAuth) {
				return errors.New("provider mTLS client certificate lacks explicit client-auth usage")
			}
			for _, identity := range leaf.URIs {
				if identity != nil {
					if _, ok := allowed[identity.String()]; ok {
						return nil
					}
				}
			}

			return errors.New("provider mTLS client URI identity is not allowed")
		},
	}, nil
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
	contents, err := os.ReadFile(path)
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
		pool.AddCert(certificate)
		certificates++
		remaining = rest
	}
	if certificates == 0 {
		return nil, errors.New("client CA bundle contains no certificates")
	}

	return pool, nil
}

func freezeAllowedURIIdentities(identities []string) (map[string]struct{}, error) {
	if len(identities) == 0 {
		return nil, errors.New("provider mTLS client URI identity allowlist is required")
	}

	allowed := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		if identity == "" {
			return nil, errors.New("provider mTLS client URI identity must not be empty")
		}
		parsed, err := url.Parse(identity)
		if err != nil || !parsed.IsAbs() || parsed.Scheme == "" || parsed.String() != identity {
			return nil, errors.New("provider mTLS client URI identity must be an absolute canonical URI")
		}
		if _, duplicate := allowed[identity]; duplicate {
			return nil, errors.New("provider mTLS client URI identity allowlist contains a duplicate")
		}
		allowed[identity] = struct{}{}
	}

	return allowed, nil
}
