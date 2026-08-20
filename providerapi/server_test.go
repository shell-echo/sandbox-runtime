package providerapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func TestNewServerFailsClosedBeforeStartup(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	source := validCapabilitySource(t)
	valid := validTransportOptions(material, 8443)

	tests := []struct {
		name    string
		ctx     context.Context
		options TransportOptions
		source  provider.CapabilityReader
	}{
		{name: "nil context", options: valid, source: source},
		{name: "empty host", ctx: context.Background(), options: withProviderHost(valid, ""), source: source},
		{name: "invalid port", ctx: context.Background(), options: withProviderPort(valid, 0), source: source},
		{name: "nil source", ctx: context.Background(), options: valid},
		{name: "missing TLS material", ctx: context.Background(), options: withProviderCertificate(valid, "missing.crt"), source: source},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewServer(test.ctx, test.options, test.source); err == nil {
				t.Fatal("NewServer() error = nil")
			}
		})
	}
}

func TestNewServerAllocatesProtectedHeaderBudget(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	options := validTransportOptions(material, 8443)
	source := validCapabilitySource(t)

	discovery, err := NewServer(context.Background(), options, source)
	if err != nil {
		t.Fatal(err)
	}
	if discovery.http.MaxHeaderBytes != providerMaxHeaderBytes {
		t.Fatalf("discovery header budget = %d, want %d", discovery.http.MaxHeaderBytes, providerMaxHeaderBytes)
	}

	options.Protected = &ProtectedTransportOptions{Gate: newTestProtectedGate(t, &testAdmissionGuard{})}
	protected, err := NewServer(context.Background(), options, source)
	if err != nil {
		t.Fatal(err)
	}
	if protected.http.MaxHeaderBytes != providerProtectedMaxHeaderBytes {
		t.Fatalf("protected header budget = %d, want %d", protected.http.MaxHeaderBytes, providerProtectedMaxHeaderBytes)
	}
	minimum := admission.MaxAdmissionContextBytes + maxCompactBearerBytes
	if protected.http.MaxHeaderBytes <= minimum {
		t.Fatalf("protected header budget = %d, must exceed required security headers %d", protected.http.MaxHeaderBytes, minimum)
	}
}

func TestServerShutdownTreatsClosedListenerAsComplete(t *testing.T) {
	if err := normalizeProviderShutdownError(net.ErrClosed); err != nil {
		t.Fatalf("normalizeProviderShutdownError(net.ErrClosed) = %v, want nil", err)
	}
	original := errors.New("shutdown failed")
	if err := normalizeProviderShutdownError(original); !errors.Is(err, original) {
		t.Fatalf("normalizeProviderShutdownError(%v) = %v, want original", original, err)
	}
}

func TestServerServesCapabilitiesOnlyAfterMTLSAdmission(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	listener, port := reserveProviderListener(t)
	srv, err := NewServer(context.Background(), validTransportOptions(material, port), validCapabilitySource(t))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }

	startupResult := make(chan error, 1)
	startupResultConsumed := false
	startupContext, cancelStartup := context.WithCancel(context.Background())
	go func() { startupResult <- srv.Startup(startupContext) }()
	t.Cleanup(func() {
		cancelStartup()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownContext); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if startupResultConsumed {
			return
		}
		select {
		case err := <-startupResult:
			if err != nil {
				t.Errorf("Startup returned: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Provider server did not stop")
		}
	})

	authenticatedTransport := &http.Transport{TLSClientConfig: clientTLSConfig(material, &material.client)}
	t.Cleanup(authenticatedTransport.CloseIdleConnections)
	client := &http.Client{
		Transport: authenticatedTransport,
		Timeout:   5 * time.Second,
	}
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d%s", port, capabilitiesPath), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer ignored-for-discovery")
	response := doProviderRequestWithRetry(t, client, request, startupResult, &startupResultConsumed)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	var document providerv1.Capabilities
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if document.ProviderRevisionID != "revision-1" {
		t.Fatalf("provider revision ID = %q", document.ProviderRevisionID)
	}

	unauthenticatedTransport := &http.Transport{TLSClientConfig: clientTLSConfig(material, nil)}
	t.Cleanup(unauthenticatedTransport.CloseIdleConnections)
	unauthenticated := &http.Client{
		Transport: unauthenticatedTransport,
		Timeout:   5 * time.Second,
	}
	if response, err := unauthenticated.Get(fmt.Sprintf("https://127.0.0.1:%d%s", port, capabilitiesPath)); err == nil {
		_ = response.Body.Close()
		t.Fatal("request without a client certificate unexpectedly reached HTTP")
	}

	plaintextTransport := &http.Transport{}
	t.Cleanup(plaintextTransport.CloseIdleConnections)
	plaintext := &http.Client{Transport: plaintextTransport, Timeout: 5 * time.Second}
	plaintextResponse, err := plaintext.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, capabilitiesPath))
	if err == nil {
		defer plaintextResponse.Body.Close()
		body, readErr := io.ReadAll(plaintextResponse.Body)
		if readErr != nil {
			t.Fatalf("read plaintext rejection: %v", readErr)
		}
		if plaintextResponse.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "Client sent an HTTP request to an HTTPS server") {
			t.Fatalf("plaintext request was not rejected by TLS transport: status=%d body=%q", plaintextResponse.StatusCode, body)
		}
	}
}

func validCapabilitySource(t *testing.T) *provider.StaticCapabilitySource {
	t.Helper()
	source, err := provider.NewStaticCapabilitySource(validSnapshot(t, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func validTransportOptions(material testMTLSMaterial, port int) TransportOptions {
	return TransportOptions{
		Address:                    option.HTTP{Host: "127.0.0.1", Port: port},
		ServerCertificateFile:      material.serverCert,
		ServerPrivateKeyFile:       material.serverKey,
		ClientCABundleFile:         material.clientCA,
		AllowedClientURIIdentities: []string{testAllowedIdentity},
	}
}

func withProviderHost(options TransportOptions, host string) TransportOptions {
	options.Address.Host = host
	return options
}

func withProviderPort(options TransportOptions, port int) TransportOptions {
	options.Address.Port = port
	return options
}

func withProviderCertificate(options TransportOptions, path string) TransportOptions {
	options.ServerCertificateFile = path
	return options
}

func reserveProviderListener(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, listener.Addr().(*net.TCPAddr).Port
}

func doProviderRequestWithRetry(t *testing.T, client *http.Client, request *http.Request, startupResult <-chan error, startupResultConsumed *bool) *http.Response {
	t.Helper()
	var lastError error
	for attempt := 0; attempt < 100; attempt++ {
		response, err := client.Do(request.Clone(request.Context()))
		if err == nil {
			return response
		}
		lastError = err
		select {
		case startupError := <-startupResult:
			*startupResultConsumed = true
			t.Fatalf("Provider server exited before becoming ready: %v", startupError)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Provider server never became ready: %v", lastError)
	return nil
}
