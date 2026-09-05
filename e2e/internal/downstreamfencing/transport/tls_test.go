package transport

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
)

func TestTLSConfigsEnforceExactTLS13Roles(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	roots := loadTestRoots(t, material.CAFile)
	serverCertificate, err := tls.LoadX509KeyPair(material.IngressCertificateFile, material.IngressPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := tls.LoadX509KeyPair(material.GatewayA.CertificateFile, material.GatewayA.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := NewServerTLSConfig(serverCertificate, roots, wire.GatewayARoleURI, wire.GatewayBRoleURI)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientTLSConfig(clientCertificate, roots, "localhost", wire.GatewayARoleURI)
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 ||
		clientConfig.MinVersion != tls.VersionTLS13 || clientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatal("TLS policy is not frozen to TLS 1.3")
	}

	serverState, clientState := handshakeTestTLS(t, serverConfig, clientConfig)
	role, err := GatewayPeerRole(&serverState, wire.GatewayARoleURI, wire.GatewayBRoleURI)
	if err != nil || role != wire.GatewayARoleURI {
		t.Fatalf("GatewayPeerRole() = %q, %v", role, err)
	}
	if clientState.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("ALPN = %q", clientState.NegotiatedProtocol)
	}
}

func TestTLSConfigsRejectWrongOrAmbiguousRoles(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	roots := loadTestRoots(t, material.CAFile)
	ingress, _ := tls.LoadX509KeyPair(material.IngressCertificateFile, material.IngressPrivateKeyFile)
	gatewayA, _ := tls.LoadX509KeyPair(material.GatewayA.CertificateFile, material.GatewayA.PrivateKeyFile)
	controller, _ := tls.LoadX509KeyPair(material.ControllerA.CertificateFile, material.ControllerA.PrivateKeyFile)
	provider, _ := tls.LoadX509KeyPair(material.ProviderCertificateFile, material.ProviderPrivateKeyFile)
	publicGateway, _ := tls.LoadX509KeyPair(material.GatewayCertificateFile, material.GatewayPrivateKeyFile)

	if _, err := NewServerTLSConfig(ingress, roots); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("empty roles error = %v", err)
	}
	if _, err := NewServerTLSConfig(ingress, roots, wire.GatewayARoleURI, wire.GatewayARoleURI); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("duplicate roles error = %v", err)
	}
	if _, err := NewClientTLSConfig(gatewayA, roots, "localhost", wire.GatewayBRoleURI); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("mismatched client role error = %v", err)
	}
	if _, err := NewServerTLSConfig(provider, roots, wire.GatewayARoleURI); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Provider certificate as ingress error = %v", err)
	}
	if _, err := NewServerTLSConfig(publicGateway, roots, wire.GatewayARoleURI); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("public Gateway certificate as ingress error = %v", err)
	}
	if _, err := NewClientTLSConfig(controller, roots, "localhost", wire.GatewayARoleURI); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("controller certificate as Gateway error = %v", err)
	}
	serverConfig, err := NewServerTLSConfig(ingress, roots, wire.GatewayARoleURI, wire.GatewayBRoleURI)
	if err != nil {
		t.Fatal(err)
	}
	unsafeClient := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, RootCAs: roots, ServerName: "localhost",
		Certificates: []tls.Certificate{controller},
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	serverTLS := tls.Server(server, serverConfig)
	clientTLS := tls.Client(client, unsafeClient)
	serverResult := make(chan error, 1)
	go func() { serverResult <- serverTLS.Handshake() }()
	clientErr := clientTLS.Handshake()
	_ = client.Close()
	serverErr := <-serverResult
	if clientErr == nil && serverErr == nil {
		t.Fatal("unallowlisted client URI completed TLS")
	}
}

func TestTLSConfigFreezesCertificateMaterial(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	roots := loadTestRoots(t, material.CAFile)
	certificate, err := tls.LoadX509KeyPair(material.GatewayA.CertificateFile, material.GatewayA.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	certificate.OCSPStaple = []byte("ocsp")
	certificate.SignedCertificateTimestamps = [][]byte{[]byte("sct")}
	certificate.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.Ed25519}
	config, err := NewClientTLSConfig(certificate, roots, "localhost", wire.GatewayARoleURI)
	if err != nil {
		t.Fatal(err)
	}
	frozen := config.Certificates[0]
	if reflect.ValueOf(frozen.PrivateKey).Pointer() == reflect.ValueOf(certificate.PrivateKey).Pointer() {
		t.Fatal("private key was not copied")
	}
	certificate.Certificate[0][0] ^= 0xff
	certificate.OCSPStaple[0] ^= 0xff
	certificate.SignedCertificateTimestamps[0][0] ^= 0xff
	certificate.SupportedSignatureAlgorithms[0] = tls.PKCS1WithSHA256
	if _, err := x509.ParseCertificate(frozen.Certificate[0]); err != nil || string(frozen.OCSPStaple) != "ocsp" ||
		string(frozen.SignedCertificateTimestamps[0]) != "sct" || frozen.SupportedSignatureAlgorithms[0] != tls.Ed25519 {
		t.Fatal("TLS configuration aliases caller-owned certificate material")
	}
}

func TestTLSConfigRejectsTypedNilPrivateKey(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	roots := loadTestRoots(t, material.CAFile)
	certificate, err := tls.LoadX509KeyPair(material.GatewayA.CertificateFile, material.GatewayA.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	var typedNil *rsa.PrivateKey
	certificate.PrivateKey = typedNil
	if _, err := NewClientTLSConfig(certificate, roots, "localhost", wire.GatewayARoleURI); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("typed-nil private key error = %v", err)
	}
}

func handshakeTestTLS(t *testing.T, serverConfig, clientConfig *tls.Config) (tls.ConnectionState, tls.ConnectionState) {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	serverTLS := tls.Server(server, serverConfig)
	clientTLS := tls.Client(client, clientConfig)
	type result struct {
		state tls.ConnectionState
		err   error
	}
	serverResult := make(chan result, 1)
	go func() {
		err := serverTLS.Handshake()
		serverResult <- result{state: serverTLS.ConnectionState(), err: err}
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	serverHandshake := <-serverResult
	if serverHandshake.err != nil {
		t.Fatal(serverHandshake.err)
	}
	return serverHandshake.state, clientTLS.ConnectionState()
}

func loadTestRoots(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		t.Fatal("failed to load test roots")
	}
	return roots
}
