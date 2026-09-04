package edge

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewTLSServerFailsClosed(t *testing.T) {
	certificate, privateKey, _ := newPublicEdgeTLSMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	valid := validServerOptions(certificate, privateKey)
	var typedNil *nilHandler

	tests := []struct {
		name   string
		mutate func(*ServerOptions)
	}{
		{name: "empty address", mutate: func(o *ServerOptions) { o.Address = "" }},
		{name: "missing host", mutate: func(o *ServerOptions) { o.Address = ":8443" }},
		{name: "zero port", mutate: func(o *ServerOptions) { o.Address = "127.0.0.1:0" }},
		{name: "nil handler", mutate: func(o *ServerOptions) { o.Handler = nil }},
		{name: "typed nil handler", mutate: func(o *ServerOptions) { o.Handler = typedNil }},
		{name: "zero connections", mutate: func(o *ServerOptions) { o.MaxConnections = 0 }},
		{name: "too many connections", mutate: func(o *ServerOptions) { o.MaxConnections = MaxAcceptedConnections + 1 }},
		{name: "short header timeout", mutate: func(o *ServerOptions) { o.ReadHeaderTimeout = MinHTTPTimeout - time.Nanosecond }},
		{name: "long read timeout", mutate: func(o *ServerOptions) { o.ReadTimeout = MaxHTTPTimeout + time.Nanosecond }},
		{name: "read shorter than header", mutate: func(o *ServerOptions) { o.ReadTimeout = o.ReadHeaderTimeout - time.Nanosecond }},
		{name: "small header budget", mutate: func(o *ServerOptions) { o.MaxHeaderBytes = MinHTTPHeaderBytes - 1 }},
		{name: "large header budget", mutate: func(o *ServerOptions) { o.MaxHeaderBytes = MaxHTTPHeaderBytes + 1 }},
		{name: "missing certificate", mutate: func(o *ServerOptions) { o.ServerCertificateFile = "" }},
		{name: "missing private key", mutate: func(o *ServerOptions) { o.ServerPrivateKeyFile = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid

			test.mutate(&options)
			if _, err := NewTLSServer(options); !errors.Is(err, ErrInvalidServerOptions) {
				t.Fatalf("NewTLSServer() error = %v, want invalid options", err)
			}
		})
	}
}

type nilHandler struct{}

func (h *nilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestNewTLSServerFreezesTLSAndHTTPPolicy(t *testing.T) {
	certificate, privateKey, _ := newPublicEdgeTLSMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	options := validServerOptions(certificate, privateKey)
	server, err := NewTLSServer(options)
	if err != nil {
		t.Fatal(err)
	}
	if server.http.TLSConfig.MinVersion != tls.VersionTLS13 || len(server.http.TLSConfig.Certificates) != 1 {
		t.Fatalf("TLS policy = %#v", server.http.TLSConfig)
	}
	if len(server.http.TLSConfig.NextProtos) != 1 || server.http.TLSConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("TLS ALPN = %v", server.http.TLSConfig.NextProtos)
	}
	if server.http.Protocols == nil || !server.http.Protocols.HTTP1() || server.http.Protocols.HTTP2() || server.http.Protocols.UnencryptedHTTP2() {
		t.Fatalf("HTTP protocols = %v", server.http.Protocols)
	}
	if server.http.ReadHeaderTimeout != options.ReadHeaderTimeout || server.http.ReadTimeout != options.ReadTimeout ||
		server.http.WriteTimeout != options.WriteTimeout || server.http.IdleTimeout != options.IdleTimeout ||
		server.http.MaxHeaderBytes != options.MaxHeaderBytes || server.maxConnections != options.MaxConnections {
		t.Fatalf("HTTP limits do not match options: %#v", server.http)
	}
}

func TestNewTLSServerRejectsUnsafeTLSMaterial(t *testing.T) {
	t.Run("non regular certificate", func(t *testing.T) {
		_, privateKey, _ := newPublicEdgeTLSMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		options := validServerOptions(t.TempDir(), privateKey)
		if _, err := NewTLSServer(options); !errors.Is(err, ErrInvalidServerOptions) || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("NewTLSServer() error = %v", err)
		}
	})

	t.Run("oversized certificate", func(t *testing.T) {
		_, privateKey, _ := newPublicEdgeTLSMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		path := filepath.Join(t.TempDir(), "oversized.pem")
		if err := os.WriteFile(path, make([]byte, maxPublicCertificateBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		options := validServerOptions(path, privateKey)
		if _, err := NewTLSServer(options); !errors.Is(err, ErrInvalidServerOptions) || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("NewTLSServer() error = %v", err)
		}
	})

	t.Run("missing server auth", func(t *testing.T) {
		certificate, privateKey, _ := newPublicEdgeTLSMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		if _, err := NewTLSServer(validServerOptions(certificate, privateKey)); !errors.Is(err, ErrInvalidServerOptions) || !strings.Contains(err.Error(), "server-auth") {
			t.Fatalf("NewTLSServer() error = %v", err)
		}
	})
}

func TestTLSServerEnforcesProtocolAndHTTPBoundsBeforeHandler(t *testing.T) {
	t.Run("TLS and ALPN policy", func(t *testing.T) {
		var calls atomic.Int64
		server, address, roots := startPublicEdgeTestServer(t, func(options *ServerOptions) {
			options.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				response.WriteHeader(http.StatusNoContent)
			})
		}, nil)
		_ = server

		oldTLS := clientPublicEdgeTLSConfig(roots)
		oldTLS.MinVersion, oldTLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		if connection, err := tls.Dial("tcp", address, oldTLS); err == nil {
			_ = connection.Close()
			t.Fatal("TLS 1.2 unexpectedly reached the public edge")
		}

		config := clientPublicEdgeTLSConfig(roots)
		config.NextProtos = []string{"h2", "http/1.1"}
		connection, err := tls.Dial("tcp", address, config)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		state := connection.ConnectionState()
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" {
			t.Fatalf("negotiated TLS=%x ALPN=%q", state.Version, state.NegotiatedProtocol)
		}
		if _, err := io.WriteString(connection, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent || calls.Load() != 1 {
			t.Fatalf("status=%d handler calls=%d", response.StatusCode, calls.Load())
		}
	})

	t.Run("slow request header", func(t *testing.T) {
		var calls atomic.Int64
		_, address, roots := startPublicEdgeTestServer(t, func(options *ServerOptions) {
			options.ReadHeaderTimeout = 150 * time.Millisecond
			options.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })
		}, nil)
		connection, err := tls.Dial("tcp", address, clientPublicEdgeTLSConfig(roots))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if _, err := io.WriteString(connection, "GET /healthz HTTP/1.1\r\nHost: local"); err != nil {
			t.Fatal(err)
		}
		if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Read(make([]byte, 1)); err == nil {
			t.Fatal("slow request header connection remained open")
		}
		if calls.Load() != 0 {
			t.Fatalf("slow request reached handler %d times", calls.Load())
		}
	})

	t.Run("oversized request header", func(t *testing.T) {
		var calls atomic.Int64
		_, address, roots := startPublicEdgeTestServer(t, func(options *ServerOptions) {
			options.MaxHeaderBytes = MinHTTPHeaderBytes
			options.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })
		}, nil)
		connection, err := tls.Dial("tcp", address, clientPublicEdgeTLSConfig(roots))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		request := "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Oversized: " + strings.Repeat("x", 16<<10) + "\r\nConnection: close\r\n\r\n"
		if _, err := io.WriteString(connection, request); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge || calls.Load() != 0 {
			t.Fatalf("status=%d handler calls=%d", response.StatusCode, calls.Load())
		}
	})
}

func TestTLSServerBoundsAcceptedConnectionsAndRecovers(t *testing.T) {
	accepted := make(chan struct{}, 4)
	_, address, roots := startPublicEdgeTestServer(t, func(options *ServerOptions) {
		options.MaxConnections = 1
		options.ReadHeaderTimeout = 2 * time.Second
		options.ReadTimeout = 2 * time.Second
	}, func(listener net.Listener) net.Listener {
		return &observingListener{Listener: listener, accepted: accepted}
	})

	first, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("first connection was not accepted")
	}

	second, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	secondTLS := tls.Client(second, clientPublicEdgeTLSConfig(roots))
	if err := secondTLS.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := secondTLS.Handshake(); err == nil {
		_ = secondTLS.Close()
		t.Fatal("connection beyond listener capacity completed TLS")
	}
	_ = secondTLS.Close()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientPublicEdgeTLSConfig(roots), DisableKeepAlives: true},
		Timeout:   time.Second,
	}
	defer client.CloseIdleConnections()
	var response *http.Response
	for attempt := 0; attempt < 20; attempt++ {
		response, err = client.Get("https://" + address + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("public edge did not recover: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("recovery status = %d", response.StatusCode)
	}
}

func TestTLSServerStartupHonorsCanceledContext(t *testing.T) {
	certificate, privateKey, _ := newPublicEdgeTLSMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	server, err := NewTLSServer(validServerOptions(certificate, privateKey))
	if err != nil {
		t.Fatal(err)
	}
	server.listen = func(ctx context.Context, _, _ string) (net.Listener, error) { return nil, ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.Startup(ctx); err != nil {
		t.Fatalf("Startup() = %v, want nil after cancellation", err)
	}
	if err := server.Shutdown(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Shutdown(nil) = %v, want unavailable", err)
	}
}

type observingListener struct {
	net.Listener
	accepted chan<- struct{}
}

func (l *observingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		select {
		case l.accepted <- struct{}{}:
		default:
		}
	}
	return connection, err
}

func startPublicEdgeTestServer(t *testing.T, mutate func(*ServerOptions), wrap func(net.Listener) net.Listener) (*TLSServer, string, *x509.CertPool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	certificate, privateKey, roots := newPublicEdgeTLSMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	options := validServerOptions(certificate, privateKey)
	options.Address = listener.Addr().String()
	if mutate != nil {
		mutate(&options)
	}
	server, err := NewTLSServer(options)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if wrap != nil {
		listener = wrap(listener)
	}
	server.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Startup(ctx) }()
	t.Cleanup(func() {
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := server.Shutdown(shutdown); err != nil {
			t.Errorf("Shutdown() = %v", err)
		}
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("Startup() = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("public-edge server did not stop")
		}
	})
	return server, listener.Addr().String(), roots
}

func validServerOptions(certificate, privateKey string) ServerOptions {
	return ServerOptions{
		Address: "127.0.0.1:8443", Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}),
		ServerCertificateFile: certificate, ServerPrivateKeyFile: privateKey,
		MaxConnections: 8, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}

func clientPublicEdgeTLSConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost",
		NextProtos: []string{"http/1.1"},
	}
}

func newPublicEdgeTLSMaterial(t *testing.T, usages []x509.ExtKeyUsage) (string, string, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public-edge-test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	certificatePath := filepath.Join(root, "server.pem")
	privateKeyPath := filepath.Join(root, "server-key.pem")
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certificatePath, privateKeyPath, roots
}

var _ http.Handler = (*nilHandler)(nil)
var _ net.Listener = (*observingListener)(nil)
