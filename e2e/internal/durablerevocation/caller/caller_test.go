package caller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
)

const (
	testToken     = "sensitive-token-value-000000000000"
	testGrant     = "sensitive-grant-value"
	testCaller    = "caller-a"
	testTenant    = "tenant-a"
	testSandbox   = "sandbox-a"
	testSession   = "browser-session-a"
	testProfile   = "sandbox-browser-v1"
	testReference = "ref:browser-session:11111111111111111111111111111111"
)

func TestOpenUsesOneAuthoritativeGrantBinding(t *testing.T) {
	caFile, certificate := testPKI(t)
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testToken || request.Header.Get("Origin") != "https://reference-caller.invalid" {
			t.Errorf("request authentication was not binding-derived")
		}
		want := map[string]string{
			"grant_id": testGrant, "expires_at": expiresAt, "caller_id": testCaller,
			"tenant_id": testTenant, "sandbox_id": testSandbox, "browser_session_id": testSession,
			"capability_profile_id": testProfile, "handoff_reference": testReference, "connection_generation": "7",
		}
		query := request.URL.Query()
		if request.URL.Path != "/v1/browser/connect" || len(query) != len(want) {
			t.Errorf("unexpected Gateway request shape")
		}
		for name, value := range want {
			if query.Get(name) != value {
				t.Errorf("query %s was not binding-derived", name)
			}
		}
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		for {
			messageType, payload, err := connection.Read(request.Context())
			if err != nil {
				return
			}
			if err := connection.Write(request.Context(), messageType, payload); err != nil {
				return
			}
		}
	})
	defer server.Close()
	caller, err := New(testConfig(caFile, server.URL, expiresAt))
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()

	opened := caller.Execute(context.Background(), openCommand(1))
	if !opened.OK || !opened.Upgraded || opened.Outcome != wire.OutcomeOpened {
		t.Fatalf("open response = %#v", opened)
	}
	echoed := caller.Execute(context.Background(), wire.Command{
		Version: wire.ProtocolVersion, Sequence: 2, Action: wire.ActionRoundTrip,
		ConnectionID: "connection-a", TimeoutMillis: 2000,
	})
	if !echoed.OK || echoed.Outcome != wire.OutcomeEchoed {
		t.Fatalf("round-trip response = %#v", echoed)
	}
	released := caller.Execute(context.Background(), wire.Command{
		Version: wire.ProtocolVersion, Sequence: 3, Action: wire.ActionClose,
		ConnectionID: "connection-a", TimeoutMillis: 2000,
	})
	if !released.OK || released.Outcome != wire.OutcomeReleased {
		t.Fatalf("close response = %#v", released)
	}
	assertResponseSanitized(t, opened, testConfig(caFile, server.URL, expiresAt))
}

func TestConfigAndControlInputAreStrict(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443", time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339Nano))
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	validPath := writePrivateFile(t, "caller.json", encoded)
	if _, err := LoadConfig(validPath); err != nil {
		t.Fatal(err)
	}

	invalid := map[string][]byte{
		"unknown":          bytes.Replace(encoded, []byte(`"ca_file"`), []byte(`"unknown":true,"ca_file"`), 1),
		"duplicate nested": bytes.Replace(encoded, []byte(`"grant_id":"`+testGrant+`"`), []byte(`"grant_id":"`+testGrant+`","grant_id":"other"`), 1),
		"trailing":         append(append([]byte(nil), encoded...), []byte(` {}`)...),
	}
	for name, content := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writePrivateFile(t, "caller.json", content)); err == nil {
				t.Fatal("LoadConfig accepted invalid input")
			}
		})
	}

	for _, line := range []string{
		`{"version":1,"sequence":1,"action":"open","connection_id":"c","gateway_id":"gateway-a","grant_binding_id":"binding-a","timeout_millis":100,"grant_id":"` + testGrant + `"}`,
		`{"version":1,"sequence":1,"sequence":2,"action":"shutdown"}`,
	} {
		if _, ok := decodeCommand([]byte(line)); ok {
			t.Fatalf("decodeCommand accepted secret-bearing or duplicate input: %s", line)
		}
	}
}

func TestCommandProjectionNeverEchoesConfigValues(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443", time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339Nano))
	caller, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()

	responses := []wire.Response{
		caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 1, Action: wire.ActionOpen, ConnectionID: "connection-a", GatewayID: "missing", GrantBindingID: "binding-a", TimeoutMillis: 100}),
		caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 2, Action: wire.ActionOpen, ConnectionID: "connection-a", GatewayID: "gateway-a", GrantBindingID: "missing", TimeoutMillis: 100}),
		caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 3, Action: wire.ActionShutdown}),
	}
	if responses[0].ErrorCode != wire.ErrorUnknownGateway || responses[1].ErrorCode != wire.ErrorUnknownGrantBinding || !responses[2].OK {
		t.Fatalf("responses = %#v", responses)
	}
	for _, response := range responses {
		assertResponseSanitized(t, response, config)
	}
}

func testConfig(caFile, gatewayURL, expiresAt string) wire.CallerConfig {
	return wire.CallerConfig{
		CAFile: caFile, Gateways: map[string]string{"gateway-a": gatewayURL},
		Principals: []wire.Principal{{ID: "principal-a", Token: testToken, CallerID: testCaller, TenantID: testTenant}},
		Endpoints: []wire.Endpoint{{
			ID: "endpoint-a", TenantID: testTenant, SandboxID: testSandbox, BrowserSessionID: testSession,
			CapabilityProfileID: testProfile, HandoffReference: testReference, ConnectionGeneration: 7,
		}},
		GrantBindings: []wire.GrantBinding{{
			ID: "binding-a", GrantID: testGrant, PrincipalID: "principal-a", EndpointID: "endpoint-a", ExpiresAt: expiresAt,
		}},
	}
}

func openCommand(sequence uint64) wire.Command {
	return wire.Command{
		Version: wire.ProtocolVersion, Sequence: sequence, Action: wire.ActionOpen,
		ConnectionID: "connection-a", GatewayID: "gateway-a", GrantBindingID: "binding-a", TimeoutMillis: 2000,
	}
}

func assertResponseSanitized(t *testing.T, response wire.Response, config wire.CallerConfig) {
	t.Helper()
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{testToken, testGrant, testCaller, testTenant, testSandbox, testSession, testProfile, testReference, config.GrantBindings[0].ExpiresAt} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, encoded)
		}
	}
}

func writePrivateFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTLSServer(t *testing.T, certificate tls.Certificate, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	return server
}

func testPKI(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "durable revocation test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, serverKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, serverKey)}),
	)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile, certificate
}

func mustPKCS8(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
