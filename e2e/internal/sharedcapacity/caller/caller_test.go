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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
)

const (
	testToken     = "sensitive-token-value"
	testCaller    = "sensitive-caller-value"
	testTenant    = "sensitive-tenant-value"
	testSandbox   = "sensitive-sandbox-value"
	testSession   = "sensitive-session-value"
	testProfile   = "sensitive-profile-value"
	testReference = "ref:sensitive-handoff-value"
)

func TestLoadConfigStrictValidation(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	configFile := writeJSONFile(t, config)
	loaded, err := LoadConfig(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CAFile != caFile || loaded.Gateways["gateway-a"] != config.Gateways["gateway-a"] {
		t.Fatalf("loaded config = %#v", loaded)
	}

	validJSON, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"unknown field":       bytes.Replace(validJSON, []byte(`"ca_file"`), []byte(`"unknown":true,"ca_file"`), 1),
		"trailing value":      append(append([]byte(nil), validJSON...), []byte(` {}`)...),
		"duplicate top-level": bytes.Replace(validJSON, []byte(`"ca_file"`), []byte(`"ca_file":"duplicate","ca_file"`), 1),
		"duplicate gateway":   bytes.Replace(validJSON, []byte(`"gateway-a":"https://127.0.0.1:18443"`), []byte(`"gateway-a":"https://127.0.0.1:18443","gateway-a":"https://127.0.0.1:18444"`), 1),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "caller.json")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("LoadConfig accepted invalid input")
			}
		})
	}
}

func TestConfigRejectsUnsafeValuesWithoutLeakingThem(t *testing.T) {
	caFile, _ := testPKI(t)
	base := testConfig(caFile, "https://127.0.0.1:18443")
	tests := map[string]wire.CallerConfig{
		"non-loopback gateway": cloneConfig(base, func(config *wire.CallerConfig) { config.Gateways["gateway-a"] = "https://example.com:443" }),
		"gateway path":         cloneConfig(base, func(config *wire.CallerConfig) { config.Gateways["gateway-a"] += "/private" }),
		"duplicate principal": cloneConfig(base, func(config *wire.CallerConfig) {
			config.Principals = append(config.Principals, config.Principals[0])
		}),
		"duplicate endpoint": cloneConfig(base, func(config *wire.CallerConfig) {
			config.Endpoints = append(config.Endpoints, config.Endpoints[0])
		}),
		"control character": cloneConfig(base, func(config *wire.CallerConfig) {
			config.Principals[0].Token += "\n"
		}),
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(config)
			if err == nil {
				t.Fatal("New accepted invalid config")
			}
			assertNoSensitiveText(t, err.Error(), config)
		})
	}

	badCA := filepath.Join(t.TempDir(), "sensitive-ca-name.pem")
	if err := os.WriteFile(badCA, []byte("sensitive-ca-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := cloneConfig(base, func(config *wire.CallerConfig) { config.CAFile = badCA })
	_, err := New(config)
	if err == nil {
		t.Fatal("New accepted malformed CA")
	}
	for _, forbidden := range []string{badCA, "sensitive-ca-name", "sensitive-ca-payload"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked %q: %q", forbidden, err)
		}
	}
}

func TestCommandValidationAndState(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	caller, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()

	assertErrorCode(t, caller.Execute(nil, wire.Command{Version: wire.ProtocolVersion, Sequence: 1, Action: wire.ActionShutdown}), errorInternal)
	assertErrorCode(t, caller.Execute(context.Background(), wire.Command{Version: 99, Sequence: 1, Action: wire.ActionShutdown}), errorInvalidCommand)
	assertErrorCode(t, caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 1, Action: "invalid"}), errorInvalidCommand)
	assertErrorCode(t, caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 1, Action: wire.ActionShutdown}), errorInvalidCommand)
	assertErrorCode(t, caller.Execute(context.Background(), openCommand(2, "missing", "principal-a", "endpoint-a")), errorUnknownGateway)
	assertErrorCode(t, caller.Execute(context.Background(), openCommand(3, "gateway-a", "missing", "endpoint-a")), errorUnknownPrincipal)
	assertErrorCode(t, caller.Execute(context.Background(), openCommand(4, "gateway-a", "principal-a", "missing")), errorUnknownEndpoint)
	assertErrorCode(t, caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 5, Action: wire.ActionClose, ConnectionID: "unknown", TimeoutMillis: 100}), errorConnectionNotFound)
	assertErrorCode(t, caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 6, Action: wire.ActionClose, ConnectionID: "unknown", GatewayID: "forbidden", TimeoutMillis: 100}), errorInvalidCommand)
	shutdown := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 7, Action: wire.ActionShutdown})
	if !shutdown.OK || shutdown.Outcome != wire.OutcomeTerminated {
		t.Fatalf("shutdown response = %#v", shutdown)
	}
	assertErrorCode(t, caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 8, Action: wire.ActionShutdown}), errorInvalidCommand)
}

func TestOpenRoundTripCloseAndDuplicateConnection(t *testing.T) {
	caFile, certificate := testPKI(t)
	var sawTLS13 atomic.Bool
	server := newTLSServer(t, certificate, func(w http.ResponseWriter, request *http.Request) {
		if request.TLS != nil && request.TLS.Version == tls.VersionTLS13 {
			sawTLS13.Store(true)
		}
		assertGatewayRequest(t, request)
		connection, err := websocket.Accept(w, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
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
	caller := mustNewCaller(t, testConfig(caFile, server.URL))
	defer caller.Close()

	opened := caller.Execute(context.Background(), openCommand(1, "gateway-a", "principal-a", "endpoint-a"))
	if !opened.OK || opened.Outcome != wire.OutcomeOpened || !opened.Upgraded {
		t.Fatalf("open response = %#v", opened)
	}
	assertErrorCode(t, caller.Execute(context.Background(), openCommand(2, "gateway-a", "principal-a", "endpoint-a")), errorConnectionExists)
	echoed := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 3, Action: wire.ActionRoundTrip, ConnectionID: "connection-a", TimeoutMillis: 2000})
	if !echoed.OK || echoed.Outcome != wire.OutcomeEchoed {
		t.Fatalf("round-trip response = %#v", echoed)
	}
	released := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 4, Action: wire.ActionClose, ConnectionID: "connection-a", TimeoutMillis: 2000})
	if !released.OK || released.Outcome != wire.OutcomeReleased {
		t.Fatalf("close response = %#v", released)
	}
	if !sawTLS13.Load() {
		t.Fatal("server did not observe TLS 1.3")
	}
}

func TestPostUpgradeNormalCloseIsProjected(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(w http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(w, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		_ = connection.Close(websocket.StatusNormalClosure, "capacity")
	})
	defer server.Close()
	caller := mustNewCaller(t, testConfig(caFile, server.URL))
	defer caller.Close()

	opened := caller.Execute(context.Background(), openCommand(1, "gateway-a", "principal-a", "endpoint-a"))
	if !opened.OK || !opened.Upgraded {
		t.Fatalf("open response = %#v", opened)
	}
	closed := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 2, Action: wire.ActionExpectClosed, ConnectionID: "connection-a", TimeoutMillis: 2000})
	if !closed.OK || closed.Outcome != wire.OutcomeClosed || closed.CloseCode != int(websocket.StatusNormalClosure) {
		t.Fatalf("close response = %#v", closed)
	}
}

func TestRoundTripPreservesObservedNormalCloseForLaterProjection(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(w http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(w, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		_ = connection.Close(websocket.StatusNormalClosure, "capacity")
	})
	defer server.Close()
	caller := mustNewCaller(t, testConfig(caFile, server.URL))
	defer caller.Close()

	if opened := caller.Execute(context.Background(), openCommand(1, "gateway-a", "principal-a", "endpoint-a")); !opened.OK || !opened.Upgraded {
		t.Fatalf("open response = %#v", opened)
	}
	probe := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 2, Action: wire.ActionRoundTrip, ConnectionID: "connection-a", TimeoutMillis: 2000})
	assertErrorCode(t, probe, errorRoundTripFailed)
	closed := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 3, Action: wire.ActionExpectClosed, ConnectionID: "connection-a", TimeoutMillis: 2000})
	if !closed.OK || closed.Outcome != wire.OutcomeClosed || closed.CloseCode != int(websocket.StatusNormalClosure) {
		t.Fatalf("close response = %#v", closed)
	}
}

func TestPostUpgradeTransportEOFIsProjectedAsAbnormalClose(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(w http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(w, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		_ = connection.CloseNow()
	})
	defer server.Close()
	caller := mustNewCaller(t, testConfig(caFile, server.URL))
	defer caller.Close()

	opened := caller.Execute(context.Background(), openCommand(1, "gateway-a", "principal-a", "endpoint-a"))
	if !opened.OK || !opened.Upgraded {
		t.Fatalf("open response = %#v", opened)
	}
	closed := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 2, Action: wire.ActionExpectClosed, ConnectionID: "connection-a", TimeoutMillis: 2000})
	if !closed.OK || closed.Outcome != wire.OutcomeClosed || closed.CloseCode != int(websocket.StatusAbnormalClosure) {
		t.Fatalf("close response = %#v", closed)
	}
}

func TestExpectClosedTimeoutUsesStableCode(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, echoHandler(t))
	defer server.Close()
	caller := mustNewCaller(t, testConfig(caFile, server.URL))
	defer caller.Close()
	if response := caller.Execute(context.Background(), openCommand(1, "gateway-a", "principal-a", "endpoint-a")); !response.OK {
		t.Fatalf("open response = %#v", response)
	}
	response := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 2, Action: wire.ActionExpectClosed, ConnectionID: "connection-a", TimeoutMillis: 50})
	assertErrorCode(t, response, errorCloseTimeout)
}

func TestTLSFailuresAreStableAndDoNotLeak(t *testing.T) {
	caFile, certificate := testPKI(t)
	wrongCAFile, _ := testPKI(t)
	tests := []struct {
		name      string
		callerCA  string
		serverTLS *tls.Config
	}{
		{name: "fixed CA", callerCA: wrongCAFile, serverTLS: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}},
		{name: "TLS downgrade", callerCA: caFile, serverTLS: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(echoHandler(t))
			server.TLS = test.serverTLS
			server.StartTLS()
			defer server.Close()
			config := testConfig(test.callerCA, server.URL)
			caller := mustNewCaller(t, config)
			defer caller.Close()
			response := caller.Execute(context.Background(), openCommand(1, "gateway-a", "principal-a", "endpoint-a"))
			assertErrorCode(t, response, errorUpgradeFailed)
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			assertNoSensitiveText(t, string(encoded), config)
			if strings.Contains(string(encoded), server.URL) || strings.Contains(string(encoded), "/v1/browser/connect") {
				t.Fatalf("response leaked endpoint: %s", encoded)
			}
		})
	}
}

func TestHTTPRejectionIsNotReportedAsAnUpgrade(t *testing.T) {
	caFile, certificate := testPKI(t)
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "sensitive upstream diagnostic", http.StatusServiceUnavailable)
	})
	defer server.Close()
	config := testConfig(caFile, server.URL)
	caller := mustNewCaller(t, config)
	defer caller.Close()
	response := caller.Execute(context.Background(), openCommand(1, "gateway-a", "principal-a", "endpoint-a"))
	assertErrorCode(t, response, errorNotUpgraded)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "sensitive upstream diagnostic") {
		t.Fatalf("response leaked upstream diagnostic: %s", encoded)
	}
}

func TestShutdownClosesHeldConnections(t *testing.T) {
	caFile, certificate := testPKI(t)
	closed := make(chan struct{})
	var once sync.Once
	server := newTLSServer(t, certificate, func(w http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(w, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		_, _, _ = connection.Read(request.Context())
		once.Do(func() { close(closed) })
	})
	defer server.Close()
	caller := mustNewCaller(t, testConfig(caFile, server.URL))
	if response := caller.Execute(context.Background(), openCommand(1, "gateway-a", "principal-a", "endpoint-a")); !response.OK {
		t.Fatalf("open response = %#v", response)
	}
	response := caller.Execute(context.Background(), wire.Command{Version: wire.ProtocolVersion, Sequence: 2, Action: wire.ActionShutdown})
	if !response.OK || response.Outcome != wire.OutcomeTerminated || len(caller.connections) != 0 {
		t.Fatalf("shutdown response = %#v, connections = %d", response, len(caller.connections))
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe caller shutdown")
	}
}

func TestRunEmitsOneBoundedResponsePerProcessedLine(t *testing.T) {
	caFile, _ := testPKI(t)
	config := testConfig(caFile, "https://127.0.0.1:18443")
	input := strings.Join([]string{
		`{"version":1,"sequence":1,"action":"close","connection_id":"missing","timeout_millis":100,"secret":"do-not-echo"}`,
		`{"version":1,"sequence":1,"action":"close","connection_id":"missing","timeout_millis":100}`,
		`{"version":1,"sequence":2,"action":"shutdown"}`,
		`{"version":1,"sequence":3,"action":"shutdown"}`,
	}, "\n")
	var output bytes.Buffer
	if err := Run(context.Background(), config, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("response lines = %d, want 3: %q", len(lines), output.String())
	}
	wantCodes := []string{errorInvalidCommand, errorConnectionNotFound, ""}
	for index, line := range lines {
		var response wire.Response
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatal(err)
		}
		if response.ErrorCode != wantCodes[index] {
			t.Fatalf("response %d = %#v", index, response)
		}
	}
	if strings.Contains(output.String(), "do-not-echo") {
		t.Fatalf("output leaked rejected input: %q", output.String())
	}
}

func echoHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(w, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
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
	}
}

func testConfig(caFile, gatewayURL string) wire.CallerConfig {
	return wire.CallerConfig{
		CAFile:     caFile,
		Gateways:   map[string]string{"gateway-a": gatewayURL},
		Principals: []wire.Principal{{ID: "principal-a", Token: testToken, CallerID: testCaller, TenantID: testTenant}},
		Endpoints: []wire.Endpoint{{
			ID: "endpoint-a", TenantID: testTenant, SandboxID: testSandbox,
			BrowserSessionID: testSession, CapabilityProfileID: testProfile,
			HandoffReference: testReference, ConnectionGeneration: 1,
		}},
	}
}

func cloneConfig(config wire.CallerConfig, change func(*wire.CallerConfig)) wire.CallerConfig {
	clone := wire.CallerConfig{CAFile: config.CAFile, Gateways: make(map[string]string, len(config.Gateways))}
	for id, endpoint := range config.Gateways {
		clone.Gateways[id] = endpoint
	}
	clone.Principals = append([]wire.Principal(nil), config.Principals...)
	clone.Endpoints = append([]wire.Endpoint(nil), config.Endpoints...)
	change(&clone)
	return clone
}

func openCommand(sequence uint64, gatewayID, principalID, endpointID string) wire.Command {
	return wire.Command{
		Version: wire.ProtocolVersion, Sequence: sequence, Action: wire.ActionOpen,
		ConnectionID: "connection-a", GatewayID: gatewayID, PrincipalID: principalID, EndpointID: endpointID,
		GrantTTLMillis: 5000, TimeoutMillis: 2000,
	}
}

func mustNewCaller(t *testing.T, config wire.CallerConfig) *Caller {
	t.Helper()
	caller, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return caller
}

func assertErrorCode(t *testing.T, response wire.Response, want string) {
	t.Helper()
	if response.OK || response.ErrorCode != want || response.Outcome != "" || response.Upgraded || response.CloseCode != 0 {
		t.Fatalf("response = %#v, want error code %q", response, want)
	}
}

func assertNoSensitiveText(t *testing.T, text string, config wire.CallerConfig) {
	t.Helper()
	values := []string{testToken, testCaller, testTenant, testSandbox, testSession, testProfile, testReference}
	for _, principal := range config.Principals {
		values = append(values, principal.Token, principal.CallerID, principal.TenantID)
	}
	for _, endpoint := range config.Endpoints {
		values = append(values, endpoint.TenantID, endpoint.SandboxID, endpoint.BrowserSessionID, endpoint.CapabilityProfileID, endpoint.HandoffReference)
	}
	for _, forbidden := range values {
		if forbidden != "" && strings.Contains(text, forbidden) {
			t.Fatalf("text leaked sensitive value %q: %q", forbidden, text)
		}
	}
}

func assertGatewayRequest(t *testing.T, request *http.Request) {
	t.Helper()
	if request.URL.Path != "/v1/browser/connect" || request.Header.Get("Authorization") != "Bearer "+testToken || request.Header.Get("Origin") != "https://reference-caller.invalid" {
		t.Errorf("Gateway request metadata was invalid")
	}
	query := request.URL.Query()
	want := map[string]string{
		"caller_id": testCaller, "tenant_id": testTenant, "sandbox_id": testSandbox,
		"browser_session_id": testSession, "capability_profile_id": testProfile,
		"handoff_reference": testReference, "connection_generation": "1",
	}
	for key, value := range want {
		if query.Get(key) != value {
			t.Errorf("Gateway query field %s was invalid", key)
		}
	}
	if query.Get("grant_id") == "" || query.Get("expires_at") == "" {
		t.Errorf("Gateway generated fields were absent")
	}
}

func writeJSONFile(t *testing.T, value any) string {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "caller.json")
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
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "shared-capacity test CA"},
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
