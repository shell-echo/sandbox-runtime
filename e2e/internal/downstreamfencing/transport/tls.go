package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
)

var ErrInvalidConfiguration = errors.New("invalid private downstream-fencing configuration")

// NewServerTLSConfig freezes the ingress server certificate and admits only
// the explicitly selected Gateway URI-SAN roles over TLS 1.3 and HTTP/1.1.
func NewServerTLSConfig(certificate tls.Certificate, clientRoots *x509.CertPool, gatewayRoles ...string) (*tls.Config, error) {
	frozen, leaf, err := freezeCertificate(certificate)
	if err != nil || clientRoots == nil || !certificateHasExactUsageAndRole(leaf, x509.ExtKeyUsageServerAuth, wire.IngressRoleURI) {
		return nil, ErrInvalidConfiguration
	}
	roles, err := exactGatewayRoles(gatewayRoles)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{frozen},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots.Clone(),
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := verifyPeerRole(state, x509.ExtKeyUsageClientAuth, roles)
			return err
		},
	}, nil
}

// NewClientTLSConfig freezes one exact Gateway client-only identity and pins
// both the ingress hostname and its URI-SAN role.
func NewClientTLSConfig(certificate tls.Certificate, roots *x509.CertPool, serverName, gatewayRole string) (*tls.Config, error) {
	frozen, leaf, err := freezeCertificate(certificate)
	if err != nil || roots == nil || !validServerName(serverName) || !isGatewayRole(gatewayRole) ||
		!certificateHasExactUsageAndRole(leaf, x509.ExtKeyUsageClientAuth, gatewayRole) {
		return nil, ErrInvalidConfiguration
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, RootCAs: roots.Clone(), ServerName: serverName,
		Certificates: []tls.Certificate{frozen},
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := verifyPeerRole(state, x509.ExtKeyUsageServerAuth, map[string]struct{}{wire.IngressRoleURI: {}})
			return err
		},
	}, nil
}

// GatewayPeerRole binds an HTTP request's already verified TLS state to one
// explicitly admitted Gateway role. It is suitable for defense-in-depth at
// the ingress handler boundary.
func GatewayPeerRole(state *tls.ConnectionState, gatewayRoles ...string) (string, error) {
	if state == nil {
		return "", ErrInvalidConfiguration
	}
	roles, err := exactGatewayRoles(gatewayRoles)
	if err != nil {
		return "", err
	}
	return verifyPeerRole(*state, x509.ExtKeyUsageClientAuth, roles)
}

func verifyPeerRole(state tls.ConnectionState, usage x509.ExtKeyUsage, allowed map[string]struct{}) (string, error) {
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" ||
		len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return "", ErrInvalidConfiguration
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != usage || len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return "", ErrInvalidConfiguration
	}
	role := leaf.URIs[0].String()
	if _, ok := allowed[role]; !ok {
		return "", ErrInvalidConfiguration
	}
	return role, nil
}

func exactGatewayRoles(values []string) (map[string]struct{}, error) {
	if len(values) == 0 || len(values) > 2 {
		return nil, ErrInvalidConfiguration
	}
	roles := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !isGatewayRole(value) {
			return nil, ErrInvalidConfiguration
		}
		if _, exists := roles[value]; exists {
			return nil, ErrInvalidConfiguration
		}
		roles[value] = struct{}{}
	}
	return roles, nil
}

func isGatewayRole(value string) bool {
	return value == wire.GatewayARoleURI || value == wire.GatewayBRoleURI
}

func certificateHasExactUsageAndRole(certificate *x509.Certificate, usage x509.ExtKeyUsage, role string) bool {
	return certificate != nil && len(certificate.ExtKeyUsage) == 1 && certificate.ExtKeyUsage[0] == usage &&
		len(certificate.URIs) == 1 && certificate.URIs[0] != nil && certificate.URIs[0].String() == role
}

func freezeCertificate(certificate tls.Certificate) (tls.Certificate, *x509.Certificate, error) {
	if len(certificate.Certificate) == 0 || nilDependency(certificate.PrivateKey) {
		return tls.Certificate{}, nil, ErrInvalidConfiguration
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return tls.Certificate{}, nil, ErrInvalidConfiguration
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(encodedKey)
	if err != nil {
		return tls.Certificate{}, nil, ErrInvalidConfiguration
	}
	frozen := certificate
	frozen.PrivateKey = privateKey
	frozen.Certificate = make([][]byte, len(certificate.Certificate))
	for index, encoded := range certificate.Certificate {
		frozen.Certificate[index] = append([]byte(nil), encoded...)
	}
	frozen.OCSPStaple = append([]byte(nil), certificate.OCSPStaple...)
	frozen.SignedCertificateTimestamps = make([][]byte, len(certificate.SignedCertificateTimestamps))
	for index, encoded := range certificate.SignedCertificateTimestamps {
		frozen.SignedCertificateTimestamps[index] = append([]byte(nil), encoded...)
	}
	frozen.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), certificate.SupportedSignatureAlgorithms...)
	leaf, err := x509.ParseCertificate(frozen.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, ErrInvalidConfiguration
	}
	frozen.Leaf = leaf
	return frozen, leaf, nil
}

func validServerName(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/:@[]") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	parsed, err := url.Parse("https://" + value)
	return err == nil && parsed.Hostname() == value
}
