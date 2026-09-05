package caller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	providercaller "github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
	"golang.org/x/sys/unix"
)

const bootstrapOpaqueReference = "ref:browser-session:opaque-bootstrap-1"

func TestLoadBootstrapCallerConfigRequiresStrictPrivateRegularFile(t *testing.T) {
	config := testBootstrapCallerConfig(t)
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	validPath := writeFile(t, "bootstrap-caller.json", encoded, 0o600)
	loaded, err := LoadBootstrapCallerConfig(validPath)
	if err != nil || loaded.Endpoint != config.Endpoint || loaded.Gateways["gateway-b"] != config.Gateways["gateway-b"] {
		t.Fatalf("LoadBootstrapCallerConfig() = (%#v, %v)", loaded, err)
	}
	loaded.Gateways["gateway-a"] = "https://127.0.0.1:19999"
	if config.Gateways["gateway-a"] == loaded.Gateways["gateway-a"] {
		t.Fatal("loaded configuration retained the caller's Gateway map")
	}

	invalid := map[string][]byte{
		"null":               []byte("null"),
		"unknown":            bytes.Replace(encoded, []byte(`"ca_file"`), []byte(`"unknown":true,"ca_file"`), 1),
		"duplicate":          bytes.Replace(encoded, []byte(`"ca_file"`), []byte(`"ca_file":"private","ca_file"`), 1),
		"trailing":           append(append([]byte(nil), encoded...), []byte(" {}")...),
		"handoff field":      bytes.Replace(encoded, []byte(`"endpoint":{`), []byte(`"endpoint":{"handoff_reference":"private",`), 1),
		"generation field":   bytes.Replace(encoded, []byte(`"endpoint":{`), []byte(`"endpoint":{"connection_generation":1,`), 1),
		"oversized document": bytes.Repeat([]byte(" "), maxConfigBytes+1),
	}
	for name, contents := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBootstrapCallerConfig(writeFile(t, "bootstrap-caller.json", contents, 0o600)); err == nil {
				t.Fatal("LoadBootstrapCallerConfig accepted unsafe JSON")
			}
		})
	}
	if _, err := LoadBootstrapCallerConfig(filepath.Base(validPath)); err == nil {
		t.Fatal("LoadBootstrapCallerConfig accepted a relative path")
	}
	if _, err := LoadBootstrapCallerConfig(writeFile(t, "public.json", encoded, 0o640)); err == nil {
		t.Fatal("LoadBootstrapCallerConfig accepted a group-readable configuration")
	}

	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBootstrapCallerConfig(link); err == nil {
		t.Fatal("LoadBootstrapCallerConfig accepted a symlink")
	}
	fifo := filepath.Join(root, "bootstrap-caller.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadBootstrapCallerConfig(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("LoadBootstrapCallerConfig accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("LoadBootstrapCallerConfig blocked on a FIFO")
	}
}

func TestBootstrapCallerConfigurationRejectsIdentityAndTopologyDrift(t *testing.T) {
	base := testBootstrapCallerConfig(t)
	tests := map[string]func(*BootstrapCallerConfig){
		"missing Gateway":  func(config *BootstrapCallerConfig) { delete(config.Gateways, "gateway-b") },
		"aliased Gateway":  func(config *BootstrapCallerConfig) { config.Gateways["gateway-b"] = config.Gateways["gateway-a"] },
		"principal tenant": func(config *BootstrapCallerConfig) { config.Principal.TenantID = "tenant-drift" },
		"profile":          func(config *BootstrapCallerConfig) { config.Endpoint.CapabilityProfileID = "browser-v2" },
		"principal":        func(config *BootstrapCallerConfig) { config.GrantBinding.PrincipalID = "principal-drift" },
		"endpoint":         func(config *BootstrapCallerConfig) { config.GrantBinding.EndpointID = "endpoint-drift" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := cloneBootstrapCallerConfig(base)
			mutate(&config)
			if err := validateBootstrapCallerConfig(config); !errors.Is(err, errBootstrappedCaller) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestBootstrapGrantLifetimeBounds(t *testing.T) {
	for _, test := range []struct {
		value int64
		valid bool
	}{
		{value: minBootstrapGrantLifetimeMillis - 1},
		{value: minBootstrapGrantLifetimeMillis, valid: true},
		{value: maxBootstrapGrantLifetimeMillis, valid: true},
		{value: maxBootstrapGrantLifetimeMillis + 1},
		{value: math.MaxInt64},
	} {
		config := testBootstrapCallerConfig(t)
		config.GrantBinding.LifetimeMillis = test.value
		if got := validateBootstrapCallerConfig(config) == nil; got != test.valid {
			t.Fatalf("lifetime %d validity = %t, want %t", test.value, got, test.valid)
		}
	}
}

func TestRunBootstrappedCorrelatesEndpointAndProcessesShutdown(t *testing.T) {
	config := testBootstrapCallerConfig(t)
	providerConfig := testProviderBootstrapIdentity(config)
	input := strings.NewReader(`{"version":1,"sequence":1,"action":"shutdown"}` + "\n")
	var output bytes.Buffer
	bootstrapCalls := 0
	bootstrap := func(_ context.Context, _ providercaller.BrowserBootstrapConfig, sink providercaller.BrowserBootstrapEndpointSink) error {
		bootstrapCalls++
		return sink.BindBrowserBootstrapEndpoint(
			config.Endpoint.TenantID,
			config.Endpoint.SandboxID,
			config.Endpoint.BrowserSessionID,
			config.Endpoint.CapabilityProfileID,
			bootstrapOpaqueReference,
			7,
			time.Now().UTC().Add(10*time.Minute),
		)
	}
	if err := runBootstrapped(context.Background(), config, providerConfig, input, &output, bootstrap); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response); err != nil || !response.OK || response.Outcome != OutcomeTerminated {
		t.Fatalf("shutdown response = %#v, error = %v", response, err)
	}
	if bootstrapCalls != 1 {
		t.Fatalf("bootstrap calls = %d", bootstrapCalls)
	}
	for _, private := range append(bootstrapPrivateValues(config), bootstrapOpaqueReference) {
		if strings.Contains(output.String(), private) {
			t.Fatalf("stdout leaked %q", private)
		}
	}
}

func TestRunBootstrappedRejectsProviderIdentityDriftBeforeMutation(t *testing.T) {
	config := testBootstrapCallerConfig(t)
	base := testProviderBootstrapIdentity(config)
	tests := map[string]func(*providercaller.BrowserBootstrapConfig){
		"tenant":  func(provider *providercaller.BrowserBootstrapConfig) { provider.TenantID = "tenant-drift" },
		"sandbox": func(provider *providercaller.BrowserBootstrapConfig) { provider.SandboxID = "sandbox-drift" },
		"session": func(provider *providercaller.BrowserBootstrapConfig) { provider.BrowserSessionID = "session-drift" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			providerConfig := base
			mutate(&providerConfig)
			called := false
			bootstrap := func(context.Context, providercaller.BrowserBootstrapConfig, providercaller.BrowserBootstrapEndpointSink) error {
				called = true
				return nil
			}
			var output bytes.Buffer
			err := runBootstrapped(context.Background(), config, providerConfig, strings.NewReader(""), &output, bootstrap)
			assertBootstrappedCallerFailure(t, err, config, bootstrapOpaqueReference)
			if called || output.Len() != 0 {
				t.Fatalf("invalid identity reached bootstrap=%t or stdout=%q", called, output.String())
			}
		})
	}
}

func TestRunBootstrappedRejectsInvalidGrantLifetimeBeforeProviderMutation(t *testing.T) {
	config := testBootstrapCallerConfig(t)
	config.GrantBinding.LifetimeMillis = 0
	providerConfig := testProviderBootstrapIdentity(config)
	called := false
	bootstrap := func(context.Context, providercaller.BrowserBootstrapConfig, providercaller.BrowserBootstrapEndpointSink) error {
		called = true
		return nil
	}
	var output bytes.Buffer
	err := runBootstrapped(context.Background(), config, providerConfig, strings.NewReader(""), &output, bootstrap)
	assertBootstrappedCallerFailure(t, err, config, bootstrapOpaqueReference)
	if called || output.Len() != 0 {
		t.Fatalf("invalid grant lifetime reached bootstrap=%t or stdout=%q", called, output.String())
	}
}

func TestRunBootstrappedFreezesGatewayMapBeforeBootstrap(t *testing.T) {
	config := testBootstrapCallerConfig(t)
	providerConfig := testProviderBootstrapIdentity(config)
	bootstrap := func(_ context.Context, _ providercaller.BrowserBootstrapConfig, sink providercaller.BrowserBootstrapEndpointSink) error {
		config.Gateways["gateway-a"] = "https://127.0.0.1:18444"
		return sink.BindBrowserBootstrapEndpoint(
			config.Endpoint.TenantID, config.Endpoint.SandboxID, config.Endpoint.BrowserSessionID,
			config.Endpoint.CapabilityProfileID, bootstrapOpaqueReference, 7, time.Now().UTC().Add(10*time.Minute),
		)
	}
	var output bytes.Buffer
	err := runBootstrapped(
		context.Background(), config, providerConfig,
		strings.NewReader(`{"version":1,"sequence":1,"action":"shutdown"}`+"\n"), &output, bootstrap,
	)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response); err != nil || !response.OK || response.Outcome != OutcomeTerminated {
		t.Fatalf("shutdown response = %#v, error = %v", response, err)
	}
}

func TestBootstrapEndpointBindingRejectsDriftExpiryAndReuse(t *testing.T) {
	base := testBootstrapCallerConfig(t)
	now := time.Now().UTC()
	tests := map[string]struct {
		tenantID, sandboxID, sessionID, profileID, reference string
		generation                                           int64
		expiresAt                                            time.Time
		mutate                                               func(*BootstrapCallerConfig)
	}{
		"tenant":          {tenantID: "tenant-drift"},
		"sandbox":         {sandboxID: "sandbox-drift"},
		"session":         {sessionID: "session-drift"},
		"profile":         {profileID: "browser-v2"},
		"reference":       {reference: "ref:browser-session:bad/value"},
		"generation":      {generation: -1},
		"expired handoff": {expiresAt: now.Add(-time.Second)},
		"short handoff":   {expiresAt: now.Add(minBootstrapGrantRemaining / 2)},
		"invalid lifetime": {
			expiresAt: now.Add(10 * time.Minute),
			mutate:    func(config *BootstrapCallerConfig) { config.GrantBinding.LifetimeMillis = 0 },
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := cloneBootstrapCallerConfig(base)
			if test.mutate != nil {
				test.mutate(&config)
			}
			tenantID, sandboxID := test.tenantID, test.sandboxID
			sessionID, profileID := test.sessionID, test.profileID
			reference, generation, expiresAt := test.reference, test.generation, test.expiresAt
			if tenantID == "" {
				tenantID = config.Endpoint.TenantID
			}
			if sandboxID == "" {
				sandboxID = config.Endpoint.SandboxID
			}
			if sessionID == "" {
				sessionID = config.Endpoint.BrowserSessionID
			}
			if profileID == "" {
				profileID = config.Endpoint.CapabilityProfileID
			}
			if reference == "" {
				reference = bootstrapOpaqueReference
			}
			if generation == 0 {
				generation = 7
			}
			if expiresAt.IsZero() {
				expiresAt = now.Add(10 * time.Minute)
			}
			binding := &bootstrapEndpointBinding{template: config}
			err := binding.BindBrowserBootstrapEndpoint(tenantID, sandboxID, sessionID, profileID, reference, generation, expiresAt)
			assertBootstrappedCallerFailure(t, err, config, reference)
			if binding.bound {
				t.Fatal("invalid endpoint was bound")
			}
		})
	}

	binding := &bootstrapEndpointBinding{template: base}
	expiresAt := now.Add(10 * time.Minute)
	if err := binding.BindBrowserBootstrapEndpoint(
		base.Endpoint.TenantID, base.Endpoint.SandboxID, base.Endpoint.BrowserSessionID,
		base.Endpoint.CapabilityProfileID, bootstrapOpaqueReference, 7, expiresAt,
	); err != nil {
		t.Fatal(err)
	}
	if !binding.bound || binding.config.Endpoints[0].HandoffReference != bootstrapOpaqueReference || binding.config.Endpoints[0].ConnectionGeneration != 7 ||
		binding.handoffExpiry != expiresAt.UTC().Format(time.RFC3339Nano) ||
		binding.config.GrantBindings[0].ExpiresAt > binding.handoffExpiry {
		t.Fatal("valid non-hex Contract reference was not materialized")
	}
	err := binding.BindBrowserBootstrapEndpoint(
		base.Endpoint.TenantID, base.Endpoint.SandboxID, base.Endpoint.BrowserSessionID,
		base.Endpoint.CapabilityProfileID, "ref:browser-session:second", 8, expiresAt,
	)
	assertBootstrappedCallerFailure(t, err, base, "ref:browser-session:second")
	if binding.config.Endpoints[0].HandoffReference != bootstrapOpaqueReference || binding.config.Endpoints[0].ConnectionGeneration != 7 {
		t.Fatal("duplicate bind changed the first endpoint")
	}

	clamped := &bootstrapEndpointBinding{template: base}
	clamped.template.GrantBinding.LifetimeMillis = maxBootstrapGrantLifetimeMillis
	shortExpiry := now.Add(2 * time.Minute)
	if err := clamped.BindBrowserBootstrapEndpoint(
		base.Endpoint.TenantID, base.Endpoint.SandboxID, base.Endpoint.BrowserSessionID,
		base.Endpoint.CapabilityProfileID, bootstrapOpaqueReference, 7, shortExpiry,
	); err != nil {
		t.Fatal(err)
	}
	if clamped.config.GrantBindings[0].ExpiresAt != shortExpiry.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("clamped grant expiry = %q", clamped.config.GrantBindings[0].ExpiresAt)
	}
}

func TestRunBootstrappedSuppressesProviderHandoffExpiryFromCDPOutput(t *testing.T) {
	caFile, certificate := testPKI(t)
	handoffExpiry := time.Now().UTC().Add(10 * time.Minute)
	handoffExpiryText := handoffExpiry.Format(time.RFC3339Nano)
	server := newTLSServer(t, certificate, func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{OriginPatterns: []string{"reference-caller.invalid"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		if _, _, err := connection.Read(request.Context()); err == nil {
			_ = connection.Write(request.Context(), websocket.MessageText, []byte(`{"id":1,"result":{"value":"`+handoffExpiryText+`"}}`))
		}
	})
	defer server.Close()

	config := testBootstrapCallerConfigWithCA(caFile)
	config.Gateways["gateway-a"] = server.URL
	providerConfig := testProviderBootstrapIdentity(config)
	bootstrap := func(_ context.Context, _ providercaller.BrowserBootstrapConfig, sink providercaller.BrowserBootstrapEndpointSink) error {
		return sink.BindBrowserBootstrapEndpoint(
			config.Endpoint.TenantID, config.Endpoint.SandboxID, config.Endpoint.BrowserSessionID,
			config.Endpoint.CapabilityProfileID, bootstrapOpaqueReference, 7, handoffExpiry,
		)
	}
	request := []byte(`{"id":1,"method":"Runtime.evaluate"}`)
	input := strings.NewReader(
		`{"version":1,"sequence":1,"action":"open","connection_id":"connection-a","gateway_id":"gateway-a","grant_binding_id":"binding-a","timeout_millis":2000}` + "\n" +
			`{"version":1,"sequence":2,"action":"call_cdp","connection_id":"connection-a","message_type":"text","payload_base64":"` +
			base64.StdEncoding.EncodeToString(request) + `","timeout_millis":2000}` + "\n" +
			`{"version":1,"sequence":3,"action":"shutdown"}` + "\n",
	)
	var output bytes.Buffer
	if err := runBootstrapped(context.Background(), config, providerConfig, input, &output, bootstrap); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var opened, suppressed, shutdown Response
	if err := decoder.Decode(&opened); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&suppressed); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&shutdown); err != nil {
		t.Fatal(err)
	}
	if !opened.OK || suppressed.ErrorCode != ErrorUnsafeResponse || suppressed.PayloadBase64 != "" || !shutdown.OK {
		t.Fatalf("responses = %#v %#v %#v", opened, suppressed, shutdown)
	}
	if strings.Contains(output.String(), handoffExpiryText) {
		t.Fatal("stdout leaked Provider handoff expiry")
	}
}

func TestRunBootstrappedFailureDoesNotEnterControlLoopOrLeak(t *testing.T) {
	config := testBootstrapCallerConfig(t)
	providerConfig := testProviderBootstrapIdentity(config)
	privateFailure := errors.New("bootstrap failed for " + bootstrapOpaqueReference)
	bootstrap := func(context.Context, providercaller.BrowserBootstrapConfig, providercaller.BrowserBootstrapEndpointSink) error {
		return privateFailure
	}
	var output bytes.Buffer
	err := runBootstrapped(
		context.Background(), config, providerConfig,
		strings.NewReader(`{"version":1,"sequence":1,"action":"shutdown"}`+"\n"), &output, bootstrap,
	)
	assertBootstrappedCallerFailure(t, err, config, bootstrapOpaqueReference)
	if output.Len() != 0 {
		t.Fatalf("bootstrap failure wrote stdout: %q", output.String())
	}
}

func TestBootstrapCallerFormattingAndErrorsAreSanitized(t *testing.T) {
	config := testBootstrapCallerConfig(t)
	for _, projection := range []string{
		config.String(), config.GoString(), fmt.Sprintf("%v", config), fmt.Sprintf("%+v", config), fmt.Sprintf("%#v", config),
		config.LogValue().String(), slog.AnyValue(config).Resolve().String(),
	} {
		for _, private := range bootstrapPrivateValues(config) {
			if strings.Contains(projection, private) {
				t.Fatalf("formatted configuration leaked %q: %s", private, projection)
			}
		}
	}
	err := errBootstrappedCaller
	assertBootstrappedCallerFailure(t, err, config, bootstrapOpaqueReference)
}

func testBootstrapCallerConfig(t *testing.T) BootstrapCallerConfig {
	t.Helper()
	caFile, _ := testPKI(t)
	return testBootstrapCallerConfigWithCA(caFile)
}

func testBootstrapCallerConfigWithCA(caFile string) BootstrapCallerConfig {
	return BootstrapCallerConfig{
		CAFile: caFile,
		Gateways: map[string]string{
			"gateway-a": "https://127.0.0.1:18443",
			"gateway-b": "https://127.0.0.1:18444",
		},
		Principal: Principal{
			ID: "principal-sensitive", Token: testToken, CallerID: testCaller, TenantID: testTenant,
		},
		Endpoint: BootstrapEndpointTemplate{
			ID: "endpoint-sensitive", TenantID: testTenant, SandboxID: testSandbox,
			BrowserSessionID: testSession, CapabilityProfileID: lockedCapabilityProfileID,
		},
		GrantBinding: BootstrapGrantBinding{
			ID: "binding-a", GrantID: testGrant, PrincipalID: "principal-sensitive", EndpointID: "endpoint-sensitive",
			LifetimeMillis: int64((5 * time.Minute) / time.Millisecond),
		},
	}
}

func testProviderBootstrapIdentity(config BootstrapCallerConfig) providercaller.BrowserBootstrapConfig {
	return providercaller.BrowserBootstrapConfig{
		TenantID:         config.Endpoint.TenantID,
		SandboxID:        config.Endpoint.SandboxID,
		BrowserSessionID: config.Endpoint.BrowserSessionID,
	}
}

func bootstrapPrivateValues(config BootstrapCallerConfig) []string {
	return []string{
		config.CAFile, config.Gateways["gateway-a"], config.Gateways["gateway-b"],
		config.Principal.ID, config.Principal.Token, config.Principal.CallerID, config.Principal.TenantID,
		config.Endpoint.ID, config.Endpoint.SandboxID, config.Endpoint.BrowserSessionID,
		config.GrantBinding.ID, config.GrantBinding.GrantID,
	}
}

func assertBootstrappedCallerFailure(t *testing.T, err error, config BootstrapCallerConfig, extra string) {
	t.Helper()
	if !errors.Is(err, errBootstrappedCaller) {
		t.Fatalf("error = %v", err)
	}
	message := err.Error()
	for _, private := range append(bootstrapPrivateValues(config), extra) {
		if private != "" && strings.Contains(message, private) {
			t.Fatalf("error leaked %q: %s", private, message)
		}
	}
}
