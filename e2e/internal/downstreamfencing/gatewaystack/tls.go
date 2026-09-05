package gatewaystack

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
)

const (
	maxCertificateBytes = 128 << 10
	maxPrivateKeyBytes  = 64 << 10
	maxCABundleBytes    = 256 << 10
)

func loadPrivateClientTLSConfig(config PrivateIngressConfig) (*tls.Config, error) {
	certificatePEM, err := readBoundedRegularFile(config.ClientCertificateFile, maxCertificateBytes, false)
	if err != nil {
		return nil, errors.New("read private client certificate")
	}
	privateKeyPEM, err := readBoundedRegularFile(config.ClientPrivateKeyFile, maxPrivateKeyBytes, true)
	if err != nil {
		return nil, errors.New("read private client key")
	}
	caPEM, err := readBoundedRegularFile(config.ServerCAFile, maxCABundleBytes, false)
	if err != nil {
		return nil, errors.New("read private ingress CA")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, errors.New("load private client key pair")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("load private ingress CA")
	}
	tlsConfig, err := transport.NewClientTLSConfig(certificate, roots, config.ServerName, config.GatewayRoleURI)
	if err != nil {
		return nil, errors.New("construct private ingress TLS policy")
	}
	return tlsConfig, nil
}

func loadPublicServerTLSConfig(config Config) (*tls.Config, error) {
	certificatePEM, err := readBoundedRegularFile(config.ServerCertificateFile, maxCertificateBytes, false)
	if err != nil {
		return nil, errors.New("read public server certificate")
	}
	privateKeyPEM, err := readBoundedRegularFile(config.ServerPrivateKeyFile, maxPrivateKeyBytes, true)
	if err != nil {
		return nil, errors.New("read public server private key")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("load public server key pair")
	}
	now := time.Now()
	for index, raw := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil || now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
			return nil, errors.New("validate public server certificate")
		}
		if index == 0 && !hasExactServerAuth(parsed) {
			return nil, errors.New("validate public server certificate usage")
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{certificate},
	}, nil
}

func hasExactServerAuth(certificate *x509.Certificate) bool {
	return certificate != nil && len(certificate.ExtKeyUsage) == 1 && certificate.ExtKeyUsage[0] == x509.ExtKeyUsageServerAuth
}
