package providerapi

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
)

func TestNewPrivateServerFailsClosedBeforeBind(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	valid := PrivateTransportOptions{
		Address:               option.HTTP{Host: "127.0.0.1", Port: 9554},
		ServerCertificateFile: material.serverCert, ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.clientCA,
		AllowedClientURIIdentities: []string{testAllowedIdentity}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}
	for name, candidate := range map[string]PrivateTransportOptions{
		"nil context":      valid,
		"missing handler":  func() PrivateTransportOptions { value := valid; value.Handler = nil; return value }(),
		"invalid address":  func() PrivateTransportOptions { value := valid; value.Address.Port = 0; return value }(),
		"missing identity": func() PrivateTransportOptions { value := valid; value.AllowedClientURIIdentities = nil; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if name == "nil context" {
				ctx = nil
			}
			if _, err := NewPrivateServer(ctx, candidate); err == nil {
				t.Fatal("invalid private server was accepted")
			}
		})
	}
}

func TestPrivateServerShutdownClosesHijackedTerminalConnection(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	listener, port := reserveProviderListener(t)
	server, err := NewPrivateServer(context.Background(), PrivateTransportOptions{
		Address: option.HTTP{Host: "127.0.0.1", Port: port}, ServerCertificateFile: material.serverCert,
		ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.clientCA,
		AllowedClientURIIdentities: []string{testAllowedIdentity}, ConnectionMaxAge: time.Minute,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			connection, buffered, hijackErr := writer.(http.Hijacker).Hijack()
			if hijackErr != nil {
				return
			}
			_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
			_ = buffered.Flush()
			_ = connection
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	server.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }
	startupContext, cancelStartup := context.WithCancel(context.Background())
	defer cancelStartup()
	startupResult := make(chan error, 1)
	go func() { startupResult <- server.Startup(startupContext) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), clientTLSConfig(material, &material.client))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(connection, "GET /private/terminal HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101 Switching Protocols") {
		t.Fatalf("Terminal upgrade response = %q, %v", status, err)
	}
	if server.connections.Active() != 1 {
		t.Fatalf("hijacked Terminal socket not tracked: %d", server.connections.Active())
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if server.connections.Active() != 0 {
		t.Fatalf("Terminal socket remained after shutdown: %d", server.connections.Active())
	}
	for {
		if _, err := reader.ReadByte(); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("Terminal socket close = %v", err)
			}
			break
		}
	}
	select {
	case err := <-startupResult:
		if err != nil {
			t.Fatalf("private server startup = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("private server did not exit")
	}
}

func TestPrivateServerWrapsBodyLimit(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	server, err := NewPrivateServer(context.Background(), PrivateTransportOptions{
		Address: option.HTTP{Host: "127.0.0.1", Port: 9555}, ServerCertificateFile: material.serverCert,
		ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.clientCA,
		AllowedClientURIIdentities: []string{testAllowedIdentity}, Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			body := make([]byte, 16)
			_, readErr := request.Body.Read(body)
			if readErr != nil {
				writer.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		}), MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.http.Handler == nil || server.http.MaxHeaderBytes == 0 {
		t.Fatal("private server did not freeze transport limits")
	}
	server.listen = func(context.Context, string, string) (net.Listener, error) { return nil, context.Canceled }
	if err := server.Startup(context.Background()); err != nil {
		t.Fatalf("cancelled private server startup = %v", err)
	}
}
