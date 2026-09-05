package stack

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
	"golang.org/x/sys/unix"
)

func TestPrivateServerStartsWithExactMutualTLSAndStops(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config := validConfig(t)
	config.Ingress.Address = availableAddress(t)
	config.Ingress.ServerCertificateFile = material.IngressCertificateFile
	config.Ingress.ServerPrivateKeyFile = material.IngressPrivateKeyFile
	config.Ingress.ClientCAFile = material.CAFile
	server, err := newPrivateServer(config.Ingress, config.Authority.CapacityPolicy, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if server.tlsConfig.MinVersion != tls.VersionTLS13 || server.tlsConfig.MaxVersion != tls.VersionTLS13 ||
		server.http.Protocols == nil || !server.http.Protocols.HTTP1() || server.http.Protocols.HTTP2() {
		t.Fatal("private server did not freeze TLS 1.3 and HTTP/1.1")
	}

	roots := x509.NewCertPool()
	caPEM, err := os.ReadFile(material.CAFile)
	if err != nil || !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("load test CA")
	}
	certificate, err := tls.LoadX509KeyPair(material.GatewayA.CertificateFile, material.GatewayA.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := transport.NewClientTLSConfig(certificate, roots, "localhost", wire.GatewayARoleURI)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS, ForceAttemptHTTP2: false}, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- server.Startup(ctx) }()
	var response *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err = client.Get("https://" + config.Ingress.Address + "/ready")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("private ingress did not accept exact Gateway mTLS: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("private ingress did not stop after cancellation")
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateServerRejectsUnsafeTLSMaterial(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config := validConfig(t)
	config.Ingress.ServerCertificateFile = material.IngressCertificateFile
	config.Ingress.ServerPrivateKeyFile = material.IngressPrivateKeyFile
	config.Ingress.ClientCAFile = material.CAFile
	if err := os.Chmod(material.IngressPrivateKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if server, err := newPrivateServer(config.Ingress, config.Authority.CapacityPolicy, http.NotFoundHandler()); server != nil || err == nil {
		t.Fatalf("world-readable private key accepted: %#v, %v", server, err)
	}
	if err := os.Chmod(material.IngressPrivateKeyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	config.Ingress.ServerCertificateFile = material.ProviderCertificateFile
	config.Ingress.ServerPrivateKeyFile = material.ProviderPrivateKeyFile
	if server, err := newPrivateServer(config.Ingress, config.Authority.CapacityPolicy, http.NotFoundHandler()); server != nil || err == nil {
		t.Fatalf("non-ingress server identity accepted: %#v, %v", server, err)
	}
}

func TestOpenRejectsReadableProviderPrivateKeyBeforeExternalWork(t *testing.T) {
	config := validConfig(t)
	if err := os.WriteFile(config.Provider.ProviderPrivateKeyFile, []byte("private-key-canary"), 0o644); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(t.Context(), config)
	if opened != nil || err == nil || err.Error() != "validate Provider private key" {
		t.Fatalf("Open() = %#v, %v", opened, err)
	}
}

func TestReadTLSFileRejectsSymlinkAndFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.pem")
	if err := os.WriteFile(target, []byte("material"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "material-link.pem")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSFile(symlink, maxPrivateKeyBytes, true); err == nil {
		t.Fatal("readTLSFile() accepted a symbolic link")
	}

	fifo := filepath.Join(root, "material.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := readTLSFile(fifo, maxPrivateKeyBytes, true)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("readTLSFile() accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("readTLSFile() blocked opening a FIFO")
	}
}

func TestPrivateServerShutdownClosesHijackedWebSocketAndWaitsForHandler(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config := validConfig(t)
	config.Ingress.Address = availableAddress(t)
	config.Ingress.ServerCertificateFile = material.IngressCertificateFile
	config.Ingress.ServerPrivateKeyFile = material.IngressPrivateKeyFile
	config.Ingress.ClientCAFile = material.CAFile
	upgrader := ws.HTTPUpgrader{}
	active := make(chan struct{})
	handlerDone := make(chan error, 1)
	server, err := newPrivateServer(config.Ingress, config.Authority.CapacityPolicy, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, _, _, upgradeErr := upgrader.Upgrade(request, response)
		if upgradeErr != nil {
			handlerDone <- upgradeErr
			return
		}
		close(active)
		defer connection.Close()
		buffer := make([]byte, 1)
		_, readErr := connection.Read(buffer)
		handlerDone <- readErr
	}))
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	caPEM, err := os.ReadFile(material.CAFile)
	if err != nil || !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("load test CA")
	}
	certificate, err := tls.LoadX509KeyPair(material.GatewayA.CertificateFile, material.GatewayA.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := transport.NewClientTLSConfig(certificate, roots, "localhost", wire.GatewayARoleURI)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Startup(ctx) }()

	var client *tls.Conn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
		client, err = tls.DialWithDialer(dialer, "tcp", config.Ingress.Address, clientTLS)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial private ingress: %v", err)
	}
	defer client.Close()
	_, err = client.Write([]byte("GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", response.StatusCode)
	}
	select {
	case <-active:
	case <-time.After(time.Second):
		t.Fatal("WebSocket handler did not become active")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-handlerDone:
		if err == nil {
			t.Fatal("hijacked WebSocket read completed without shutdown error")
		}
	default:
		t.Fatal("Shutdown returned before the hijacked WebSocket handler exited")
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("private server did not stop after Shutdown")
	}
}

func TestPrivateServerShutdownForceClosesActiveHTTPConnectionAtDeadline(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config := validConfig(t)
	config.Ingress.Address = availableAddress(t)
	config.Ingress.ServerCertificateFile = material.IngressCertificateFile
	config.Ingress.ServerPrivateKeyFile = material.IngressPrivateKeyFile
	config.Ingress.ClientCAFile = material.CAFile
	active := make(chan struct{})
	handlerDone := make(chan struct{})
	server, err := newPrivateServer(config.Ingress, config.Authority.CapacityPolicy, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(active)
		_, _ = io.Copy(io.Discard, request.Body)
		close(handlerDone)
	}))
	if err != nil {
		t.Fatal(err)
	}

	clientTLS := gatewayClientTLS(t, material)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Startup(ctx) }()
	var connection *tls.Conn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
		connection, err = tls.DialWithDialer(dialer, "tcp", config.Ingress.Address, clientTLS)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial private ingress: %v", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("POST /blocked HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-active:
	case <-time.After(2 * time.Second):
		t.Fatal("active HTTP handler did not start")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("forced server close did not cancel the active HTTP handler")
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("forced server close left the active HTTP connection readable")
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("private server did not stop after forced close")
	}
}

func gatewayClientTLS(t *testing.T, material testenv.Material) *tls.Config {
	t.Helper()
	roots := x509.NewCertPool()
	caPEM, err := os.ReadFile(material.CAFile)
	if err != nil || !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("load test CA")
	}
	certificate, err := tls.LoadX509KeyPair(material.GatewayA.CertificateFile, material.GatewayA.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := transport.NewClientTLSConfig(certificate, roots, "localhost", wire.GatewayARoleURI)
	if err != nil {
		t.Fatal(err)
	}
	return clientTLS
}

func availableAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
