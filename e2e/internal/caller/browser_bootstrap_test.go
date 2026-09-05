package caller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const bootstrapTestHandoff = "ref:browser-session:opaque-bootstrap-1"

type browserBootstrapTestMaterial struct {
	config            BrowserBootstrapConfig
	serverCertificate tls.Certificate
	clientRoots       *x509.CertPool
	jwsPublic         ed25519.PublicKey
}

type browserBootstrapProvider struct {
	t                   *testing.T
	config              BrowserBootstrapConfig
	jwsPublic           ed25519.PublicKey
	dropMutations       bool
	transientReads      bool
	invalidReadPath     string
	invalidReadStatus   int
	invalidCreateStatus int
	mu                  sync.Mutex
	createRequests      int
	openRequests        int
	protectedRequests   int
	openExpiry          string
	jti                 map[string]bool
	readAttempts        map[string]int
}

type browserBootstrapEndpointCapture struct {
	tenantID             string
	sandboxID            string
	browserSessionID     string
	capabilityProfileID  string
	handoffReference     string
	connectionGeneration int64
	expiresAt            time.Time
	calls                int
	err                  error
}

func (s *browserBootstrapEndpointCapture) BindBrowserBootstrapEndpoint(
	tenantID string,
	sandboxID string,
	browserSessionID string,
	capabilityProfileID string,
	handoffReference string,
	connectionGeneration int64,
	expiresAt time.Time,
) error {
	if s == nil {
		panic("typed-nil Browser bootstrap endpoint sink invoked")
	}
	s.tenantID = tenantID
	s.sandboxID = sandboxID
	s.browserSessionID = browserSessionID
	s.capabilityProfileID = capabilityProfileID
	s.handoffReference = handoffReference
	s.connectionGeneration = connectionGeneration
	s.expiresAt = expiresAt
	s.calls++
	return s.err
}

func TestBrowserBootstrapResultBindsOneCorrelatedPrivateEndpoint(t *testing.T) {
	expiresAt := time.Now().UTC().Add(time.Minute)
	result := BrowserBootstrapResult{endpoint: browserBootstrapEndpoint{
		tenantID: "tenant-private", sandboxID: "sandbox-private", browserSessionID: "browser-session-private",
		capabilityProfileID: "browser-v1", handoffReference: bootstrapTestHandoff,
		connectionGeneration: 7, expiresAt: expiresAt,
	}}
	sink := &browserBootstrapEndpointCapture{}
	if err := result.BindEndpoint(sink); err != nil {
		t.Fatal(err)
	}
	if sink.calls != 1 || sink.tenantID != result.endpoint.tenantID || sink.sandboxID != result.endpoint.sandboxID ||
		sink.browserSessionID != result.endpoint.browserSessionID || sink.capabilityProfileID != result.endpoint.capabilityProfileID ||
		sink.handoffReference != result.endpoint.handoffReference || sink.connectionGeneration != result.endpoint.connectionGeneration ||
		!sink.expiresAt.Equal(expiresAt) {
		t.Fatalf("bound endpoint = %#v", sink)
	}
	encoded, err := json.Marshal(result)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("ordinary JSON projection = %s, error = %v", encoded, err)
	}
	for _, projection := range []string{
		result.String(), result.GoString(), fmt.Sprintf("%v", result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result),
		result.LogValue().String(), slog.AnyValue(result).Resolve().String(),
	} {
		if strings.Contains(projection, bootstrapTestHandoff) || strings.Contains(projection, result.endpoint.sandboxID) {
			t.Fatalf("formatted result leaked private bootstrap state: %s", projection)
		}
	}
}

func TestBrowserBootstrapResultRejectsEmptyAndNilEndpointSinks(t *testing.T) {
	valid := BrowserBootstrapResult{endpoint: browserBootstrapEndpoint{handoffReference: bootstrapTestHandoff}}
	var typedNil *browserBootstrapEndpointCapture
	for name, test := range map[string]struct {
		result BrowserBootstrapResult
		sink   BrowserBootstrapEndpointSink
	}{
		"empty result": {result: BrowserBootstrapResult{}, sink: &browserBootstrapEndpointCapture{}},
		"nil sink":     {result: valid, sink: nil},
		"typed nil":    {result: valid, sink: typedNil},
	} {
		t.Run(name, func(t *testing.T) {
			err := test.result.BindEndpoint(test.sink)
			assertBrowserBootstrapError(t, err, BrowserBootstrapEndpointBindingFailed)
		})
	}
}

func TestBrowserBootstrapResultRedactsEndpointSinkFailure(t *testing.T) {
	result := BrowserBootstrapResult{endpoint: browserBootstrapEndpoint{
		sandboxID: "sandbox-private", handoffReference: bootstrapTestHandoff,
	}}
	sink := &browserBootstrapEndpointCapture{
		err: fmt.Errorf("sink failed for %s at %s", result.endpoint.sandboxID, result.endpoint.handoffReference),
	}
	err := result.BindEndpoint(sink)
	assertBrowserBootstrapError(t, err, BrowserBootstrapEndpointBindingFailed)
	if sink.calls != 1 || strings.Contains(err.Error(), result.endpoint.sandboxID) ||
		strings.Contains(err.Error(), result.endpoint.handoffReference) || strings.Contains(err.Error(), "sink failed") {
		t.Fatalf("sink failure was not redacted: %v", err)
	}
}

func TestBootstrapBrowserUsesOneMTLSJWSIdentityAndReturnsPrivateHandoff(t *testing.T) {
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
	provider := &browserBootstrapProvider{t: t, config: material.config, jwsPublic: material.jwsPublic, jti: map[string]bool{}}
	server := newBrowserBootstrapTestServer(t, material, provider.serveHTTP)
	defer server.Close()
	material.config.ProviderBaseURL = server.URL
	provider.config = material.config

	result, err := BootstrapBrowser(context.Background(), material.config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := result.endpoint
	if endpoint.tenantID != material.config.TenantID || endpoint.sandboxID != material.config.SandboxID ||
		endpoint.browserSessionID != material.config.BrowserSessionID || endpoint.capabilityProfileID != "browser-v1" ||
		endpoint.handoffReference != bootstrapTestHandoff || endpoint.connectionGeneration != 1 || !endpoint.expiresAt.After(time.Now().UTC()) {
		t.Fatal("bootstrap endpoint did not match the expected private state")
	}
	encoded, err := json.Marshal(result)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("ordinary JSON projection = %s, error = %v", encoded, err)
	}
	for _, projection := range []string{
		result.String(), result.GoString(), fmt.Sprintf("%v", result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result),
		result.LogValue().String(), slog.AnyValue(result).Resolve().String(),
	} {
		if strings.Contains(projection, bootstrapTestHandoff) || strings.Contains(projection, material.config.SandboxID) {
			t.Fatalf("formatted result leaked private bootstrap state: %s", projection)
		}
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.createRequests != 1 || provider.openRequests != 1 || provider.protectedRequests != 6 || len(provider.jti) != 6 {
		t.Fatalf("Provider requests = create:%d open:%d protected:%d unique-jti:%d", provider.createRequests, provider.openRequests, provider.protectedRequests, len(provider.jti))
	}
}

func TestBootstrapBrowserReconcilesUnknownMutationTransportWithoutResend(t *testing.T) {
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
	provider := &browserBootstrapProvider{
		t: t, config: material.config, jwsPublic: material.jwsPublic,
		dropMutations: true, jti: map[string]bool{},
	}
	server := newBrowserBootstrapTestServer(t, material, provider.serveHTTP)
	defer server.Close()
	material.config.ProviderBaseURL = server.URL
	provider.config = material.config

	if _, err := BootstrapBrowser(context.Background(), material.config); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.createRequests != 1 || provider.openRequests != 1 {
		t.Fatalf("unknown mutations were resent: create=%d open=%d", provider.createRequests, provider.openRequests)
	}
}

func TestBootstrapBrowserRecoversBoundedOperationAndHandoffReads(t *testing.T) {
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
	provider := &browserBootstrapProvider{
		t: t, config: material.config, jwsPublic: material.jwsPublic,
		transientReads: true, jti: map[string]bool{}, readAttempts: map[string]int{},
	}
	server := newBrowserBootstrapTestServer(t, material, provider.serveHTTP)
	defer server.Close()
	material.config.ProviderBaseURL = server.URL
	material.config.PollTimeoutMillis = 1500
	provider.config = material.config

	if _, err := BootstrapBrowser(context.Background(), material.config); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.createRequests != 1 || provider.openRequests != 1 ||
		provider.readAttempts["/v1/operations/"+material.config.CreateOperationID] != 3 ||
		provider.readAttempts["/v1/operations/"+material.config.OpenOperationID] != 3 ||
		provider.readAttempts["/v1/operations/"+material.config.OpenOperationID+"/browser-session"] != 3 {
		t.Fatalf("bounded recovery attempts = %#v, create=%d open=%d", provider.readAttempts, provider.createRequests, provider.openRequests)
	}
}

func TestBootstrapBrowserRejectsInvalidTransientErrorBeforeLaterSuccess(t *testing.T) {
	for _, test := range []struct {
		name     string
		path     func(BrowserBootstrapConfig) string
		status   int
		wantCode string
	}{
		{
			name: "operation read", status: http.StatusNotFound, wantCode: BrowserBootstrapCreateFailed,
			path: func(config BrowserBootstrapConfig) string { return "/v1/operations/" + config.CreateOperationID },
		},
		{
			name: "handoff read", status: http.StatusServiceUnavailable, wantCode: BrowserBootstrapHandoffInvalid,
			path: func(config BrowserBootstrapConfig) string {
				return "/v1/operations/" + config.OpenOperationID + "/browser-session"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
			path := test.path(material.config)
			provider := &browserBootstrapProvider{
				t: t, config: material.config, jwsPublic: material.jwsPublic, jti: map[string]bool{},
				invalidReadPath: path, invalidReadStatus: test.status, readAttempts: map[string]int{},
			}
			server := newBrowserBootstrapTestServer(t, material, provider.serveHTTP)
			defer server.Close()
			material.config.ProviderBaseURL = server.URL
			provider.config = material.config

			_, err := BootstrapBrowser(context.Background(), material.config)
			assertBrowserBootstrapError(t, err, test.wantCode)
			provider.mu.Lock()
			defer provider.mu.Unlock()
			if provider.readAttempts[path] != 1 {
				t.Fatalf("invalid transient response was retried: attempts=%d", provider.readAttempts[path])
			}
		})
	}
}

func TestBootstrapBrowserDoesNotTreatReceivedInvalidMutationResponseAsTransportLoss(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		wantCode string
	}{
		{name: "accepted", status: http.StatusAccepted, wantCode: BrowserBootstrapCreateInvalid},
		{name: "rejected", status: http.StatusConflict, wantCode: BrowserBootstrapCreateRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
			provider := &browserBootstrapProvider{
				t: t, config: material.config, jwsPublic: material.jwsPublic, jti: map[string]bool{},
				invalidCreateStatus: test.status,
			}
			server := newBrowserBootstrapTestServer(t, material, provider.serveHTTP)
			defer server.Close()
			material.config.ProviderBaseURL = server.URL
			provider.config = material.config

			_, err := BootstrapBrowser(context.Background(), material.config)
			assertBrowserBootstrapError(t, err, test.wantCode)
			provider.mu.Lock()
			defer provider.mu.Unlock()
			if provider.createRequests != 1 || provider.openRequests != 0 {
				t.Fatalf("mutation classification requests: create=%d open=%d", provider.createRequests, provider.openRequests)
			}
		})
	}
}

func TestBrowserBootstrapMutationOutcomeClassification(t *testing.T) {
	for _, test := range []struct {
		name          string
		mutationCode  int
		mutationBody  any
		operationBody func(BrowserBootstrapConfig) Operation
		wantCode      string
		wantPoll      bool
	}{
		{name: "definitive rejection is not polled", mutationCode: http.StatusConflict, mutationBody: StandardError{Code: "SANDBOX_CONFLICT"}, wantCode: BrowserBootstrapCreateRejected},
		{name: "invalid accepted projection is reconciled", mutationCode: http.StatusAccepted, mutationBody: map[string]any{}, operationBody: func(config BrowserBootstrapConfig) Operation {
			return browserBootstrapTestOperation(config, true, "succeeded")
		}, wantCode: BrowserBootstrapCreateInvalid, wantPoll: true},
		{name: "failed operation stops", mutationCode: http.StatusAccepted, operationBody: func(config BrowserBootstrapConfig) Operation {
			return browserBootstrapTestOperation(config, true, "failed")
		}, wantCode: BrowserBootstrapCreateFailed, wantPoll: true},
		{name: "outcome unknown stops", mutationCode: http.StatusAccepted, operationBody: func(config BrowserBootstrapConfig) Operation {
			return browserBootstrapTestOperation(config, true, "outcome_unknown")
		}, wantCode: BrowserBootstrapCreateFailed, wantPoll: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
			var mutations, polls int
			server := newBrowserBootstrapTestServer(t, material, func(writer http.ResponseWriter, request *http.Request) {
				switch {
				case request.URL.Path == "/v1/capabilities":
					writeBrowserBootstrapTestJSON(t, writer, http.StatusOK, browserBootstrapTestCapabilities(material.config))
				case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes":
					mutations++
					body := test.mutationBody
					if body == nil {
						body = browserBootstrapTestOperation(material.config, true, "accepted")
					}
					writeBrowserBootstrapTestJSON(t, writer, test.mutationCode, body)
				case request.Method == http.MethodGet && request.URL.Path == "/v1/operations/"+material.config.CreateOperationID:
					polls++
					writeBrowserBootstrapTestJSON(t, writer, http.StatusOK, test.operationBody(material.config))
				default:
					http.NotFound(writer, request)
				}
			})
			defer server.Close()
			material.config.ProviderBaseURL = server.URL
			_, err := BootstrapBrowser(context.Background(), material.config)
			assertBrowserBootstrapError(t, err, test.wantCode)
			if mutations != 1 || (polls > 0) != test.wantPoll {
				t.Fatalf("mutation requests=%d polls=%d", mutations, polls)
			}
		})
	}
}

func TestBrowserBootstrapPollingIsBoundedAndCancelable(t *testing.T) {
	for _, test := range []struct {
		name     string
		cancel   bool
		wantCode string
	}{
		{name: "timeout", wantCode: BrowserBootstrapTimedOut},
		{name: "cancel", cancel: true, wantCode: BrowserBootstrapCanceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
			material.config.PollTimeoutMillis = 150
			polled := make(chan struct{}, 1)
			var createRequests int
			server := newBrowserBootstrapTestServer(t, material, func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/v1/capabilities" {
					writeBrowserBootstrapTestJSON(t, writer, http.StatusOK, browserBootstrapTestCapabilities(material.config))
					return
				}
				if request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes" {
					createRequests++
					writeBrowserBootstrapTestJSON(t, writer, http.StatusAccepted, browserBootstrapTestOperation(material.config, true, "accepted"))
					return
				}
				if request.Method == http.MethodGet && request.URL.Path == "/v1/operations/"+material.config.CreateOperationID {
					select {
					case polled <- struct{}{}:
					default:
					}
					writeBrowserBootstrapTestJSON(t, writer, http.StatusOK, browserBootstrapTestOperation(material.config, true, "running"))
					return
				}
				http.NotFound(writer, request)
			})
			defer server.Close()
			material.config.ProviderBaseURL = server.URL
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancel {
				go func() {
					<-polled
					cancel()
				}()
			}
			_, err := BootstrapBrowser(ctx, material.config)
			assertBrowserBootstrapError(t, err, test.wantCode)
			if createRequests != 1 {
				t.Fatalf("create requests = %d, want 1", createRequests)
			}
		})
	}
}

func TestLoadBrowserBootstrapConfigRequiresStrictPrivateRegularFile(t *testing.T) {
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
	material.config.ProviderBaseURL = "https://127.0.0.1:10443"
	document, err := json.Marshal(material.config)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	validPath := filepath.Join(root, "bootstrap.json")
	if err := os.WriteFile(validPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBrowserBootstrapConfig(validPath); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	worldReadable := filepath.Join(root, "world-readable.json")
	if err := os.WriteFile(worldReadable, document, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadBrowserBootstrapConfig(worldReadable)
	assertBrowserBootstrapError(t, err, BrowserBootstrapInvalidConfiguration)

	symlink := filepath.Join(root, "bootstrap-link.json")
	if err := os.Symlink(validPath, symlink); err != nil {
		t.Fatal(err)
	}
	_, err = LoadBrowserBootstrapConfig(symlink)
	assertBrowserBootstrapError(t, err, BrowserBootstrapInvalidConfiguration)

	duplicate := bytes.Replace(document, []byte("{"), []byte(`{"provider_base_url":"https://127.0.0.1:10444",`), 1)
	duplicatePath := filepath.Join(root, "duplicate.json")
	if err := os.WriteFile(duplicatePath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadBrowserBootstrapConfig(duplicatePath)
	assertBrowserBootstrapError(t, err, BrowserBootstrapInvalidConfiguration)
}

func TestBrowserBootstrapRejectsUnsafeOrMismatchedIdentityMaterial(t *testing.T) {
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
	material.config.ProviderBaseURL = "https://127.0.0.1:10443"

	wrongSubject := material.config
	wrongSubject.Controller.ControllerSubject = "spiffe://downstream-caller/controller-b"
	_, err := newBrowserBootstrapClient(wrongSubject)
	assertBrowserBootstrapError(t, err, BrowserBootstrapInvalidConfiguration)

	unsafeKey := filepath.Join(t.TempDir(), "unsafe-client-key.pem")
	keyContents, err := os.ReadFile(material.config.Controller.PrivateKeyFile)
	if err != nil || os.WriteFile(unsafeKey, keyContents, 0o644) != nil {
		t.Fatal("write unsafe key")
	}
	unsafe := material.config
	unsafe.Controller.PrivateKeyFile = unsafeKey
	_, err = newBrowserBootstrapClient(unsafe)
	assertBrowserBootstrapError(t, err, BrowserBootstrapInvalidConfiguration)
	if strings.Contains(err.Error(), unsafeKey) || strings.Contains(err.Error(), string(keyContents)) {
		t.Fatalf("identity error leaked private material: %v", err)
	}
}

func TestBrowserBootstrapStrictResponseDecoderRejectsDuplicatesAndOversize(t *testing.T) {
	var target map[string]any
	if decodeBrowserBootstrapDocument([]byte(`{"value":1,"value":2}`), &target) {
		t.Fatal("duplicate response field was accepted")
	}
	if decodeBrowserBootstrapDocument(bytes.Repeat([]byte("x"), maxBrowserBootstrapResponse+1), &target) {
		t.Fatal("oversized response was accepted")
	}
	if decodeBrowserBootstrapDocument([]byte(`{"value":null}`), &target) {
		t.Fatal("JSON null was accepted")
	}
}

func TestBrowserBootstrapRequiresExactBrowserCapabilitySnapshot(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Capabilities)
	}{
		{name: "extra capability", mutate: func(capabilities *Capabilities) {
			capabilities.Capabilities = append(capabilities.Capabilities, Capability{ID: "sandbox.exec", Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}})
		}},
		{name: "GPU capacity", mutate: func(capabilities *Capabilities) {
			one := int64(1)
			capabilities.Limits.MaxGPUCount = &one
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
			server := newBrowserBootstrapTestServer(t, material, func(writer http.ResponseWriter, request *http.Request) {
				capabilities := browserBootstrapTestCapabilities(material.config)
				test.mutate(&capabilities)
				writeBrowserBootstrapTestJSON(t, writer, http.StatusOK, capabilities)
			})
			defer server.Close()
			material.config.ProviderBaseURL = server.URL
			_, err := BootstrapBrowser(context.Background(), material.config)
			assertBrowserBootstrapError(t, err, BrowserBootstrapCapabilityInvalid)
		})
	}
}

func TestBrowserBootstrapErrorsDoNotProjectProviderOrPrivateMaterial(t *testing.T) {
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
	const privateResponse = "provider-private-response-secret"
	server := newBrowserBootstrapTestServer(t, material, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, `{"code":"`+privateResponse+`"}`)
	})
	defer server.Close()
	material.config.ProviderBaseURL = server.URL
	_, err := BootstrapBrowser(context.Background(), material.config)
	assertBrowserBootstrapError(t, err, BrowserBootstrapCapabilityRejected)
	for _, privateValue := range []string{
		privateResponse, material.config.CAFile, material.config.Controller.PrivateKeyFile,
		material.config.Controller.JWSPrivateKeyFile, material.config.Controller.ControllerSubject,
	} {
		if strings.Contains(err.Error(), privateValue) {
			t.Fatalf("bootstrap error leaked %q: %v", privateValue, err)
		}
	}
}

func TestBrowserBootstrapConfigurationBindsCallerFencing(t *testing.T) {
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
	maxSubject := "spiffe://downstream-caller/" + strings.Repeat("a", 200-len("spiffe://downstream-caller/"))
	boundary := material.config
	boundary.Controller.ControllerSubject = maxSubject
	boundary.CreateFencingToken = maxBrowserBootstrapSafeInteger - 1
	boundary.OpenFencingToken = maxBrowserBootstrapSafeInteger
	if err := validateBrowserBootstrapConfig(boundary); err != nil {
		t.Fatalf("valid configuration boundary rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*BrowserBootstrapConfig)
	}{
		{name: "zero create fence", mutate: func(config *BrowserBootstrapConfig) { config.CreateFencingToken = 0 }},
		{name: "non-increasing open fence", mutate: func(config *BrowserBootstrapConfig) { config.OpenFencingToken = config.CreateFencingToken }},
		{name: "unsafe create fence", mutate: func(config *BrowserBootstrapConfig) {
			config.CreateFencingToken = maxBrowserBootstrapSafeInteger + 1
			config.OpenFencingToken = maxBrowserBootstrapSafeInteger + 2
		}},
		{name: "unsafe open fence", mutate: func(config *BrowserBootstrapConfig) {
			config.CreateFencingToken = maxBrowserBootstrapSafeInteger - 1
			config.OpenFencingToken = maxBrowserBootstrapSafeInteger + 1
		}},
		{name: "oversized Controller subject", mutate: func(config *BrowserBootstrapConfig) {
			config.Controller.ControllerSubject = maxSubject + "a"
		}},
		{name: "duplicate operation identity", mutate: func(config *BrowserBootstrapConfig) { config.OpenOperationID = config.CreateOperationID }},
		{name: "non-loopback Provider", mutate: func(config *BrowserBootstrapConfig) { config.ProviderBaseURL = "https://example.com:443" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := material.config
			test.mutate(&config)
			err := validateBrowserBootstrapConfig(config)
			assertBrowserBootstrapError(t, err, BrowserBootstrapInvalidConfiguration)
		})
	}
}

func TestBrowserBootstrapOperationAndSandboxCorrelation(t *testing.T) {
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-a")
	reference := browserBootstrapReference{
		operationID: material.config.CreateOperationID, attemptID: material.config.CreateAttemptID,
		fencingToken: material.config.CreateFencingToken, operation: "create",
	}
	for _, operation := range []Operation{
		func() Operation {
			operation := browserBootstrapTestOperation(material.config, true, "succeeded")
			operation.ProviderOperationID = ""
			return operation
		}(),
		func() Operation {
			operation := browserBootstrapTestOperation(material.config, true, "succeeded")
			operation.ProviderOperationID = "provider-operation:other"
			operation.ResultReference = "ref:result/other"
			operation.ObservedAt = "2026-08-26T17:30:45.123456789+08:00"
			return operation
		}(),
	} {
		if !validBrowserBootstrapOperation(operation, material.config.SandboxID, reference, "succeeded") {
			t.Fatal("schema-valid optional operation fields or date-time rejected")
		}
	}
	for _, field := range []string{"provider_operation_id", "result_reference"} {
		operation := browserBootstrapTestOperation(material.config, true, "succeeded")
		document, err := json.Marshal(operation)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if json.Unmarshal(document, &raw) != nil {
			t.Fatal("decode optional operation field test document")
		}
		raw[field] = ""
		document, err = json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Operation
		if decodeBrowserBootstrapOperation(document, &decoded) {
			t.Fatalf("explicit empty %s accepted", field)
		}
	}
	validFailure := browserBootstrapTestOperation(material.config, true, "failed")
	validFailure.Error = &ProviderError{
		Code: "RUNTIME_FAILED", Message: "runtime failed", Outcome: "known_failed", ProviderCode: "ENGINE_FAILED",
		Details: map[string]any{"reason": "exited"},
	}
	if !validBrowserBootstrapOperation(validFailure, material.config.SandboxID, reference, "failed") {
		t.Fatal("schema-valid Provider error rejected")
	}
	for _, mutate := range []func(*ProviderError){
		func(operationError *ProviderError) { operationError.Code = "invalid" },
		func(operationError *ProviderError) { operationError.Message = strings.Repeat("a", 513) },
		func(operationError *ProviderError) { operationError.ProviderCode = "invalid" },
		func(operationError *ProviderError) { operationError.Details["reason"] = 1 },
		func(operationError *ProviderError) { operationError.Details["reason"] = strings.Repeat("a", 257) },
		func(operationError *ProviderError) {
			for index := 0; index < 17; index++ {
				operationError.Details[fmt.Sprintf("key-%d", index)] = "value"
			}
		},
	} {
		operation := validFailure
		copyError := *validFailure.Error
		copyError.Details = maps.Clone(validFailure.Error.Details)
		operation.Error = &copyError
		mutate(operation.Error)
		if validBrowserBootstrapOperation(operation, material.config.SandboxID, reference, "failed") {
			t.Fatal("schema-invalid Provider error accepted")
		}
	}
	document, err := json.Marshal(validFailure)
	if err != nil {
		t.Fatal(err)
	}
	var rawOperation map[string]any
	if json.Unmarshal(document, &rawOperation) != nil {
		t.Fatal("decode Provider error test document")
	}
	delete(rawOperation["error"].(map[string]any), "retryable")
	document, err = json.Marshal(rawOperation)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Operation
	if decodeBrowserBootstrapOperation(document, &decoded) {
		t.Fatal("Provider error without required retryable field accepted")
	}
	for _, mutate := range []func(*Operation){
		func(operation *Operation) { operation.ProviderOperationID = "invalid/provider-operation" },
		func(operation *Operation) { operation.ProviderOperationID = strings.Repeat("a", 201) },
		func(operation *Operation) { operation.ResultReference = "invalid result reference" },
		func(operation *Operation) { operation.ResultReference = strings.Repeat("a", 401) },
		func(operation *Operation) {
			operation.Error = &ProviderError{Code: "INVALID", Message: "invalid", Outcome: "known_failed"}
		},
		func(operation *Operation) { operation.ObservedAt = "not-a-date-time" },
	} {
		operation := browserBootstrapTestOperation(material.config, true, "succeeded")
		mutate(&operation)
		if validBrowserBootstrapOperation(operation, material.config.SandboxID, reference, "succeeded") {
			t.Fatal("schema-invalid operation accepted")
		}
	}
	now := time.Now().UTC()
	valid := SandboxStatus{
		LeaseExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		CreatedAt:      now.Add(-time.Minute).Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
	}
	if !validBrowserBootstrapSandboxTimes(valid, now) {
		t.Fatal("valid sandbox times rejected")
	}
	invalid := valid
	invalid.CreatedAt, invalid.UpdatedAt = invalid.UpdatedAt, invalid.CreatedAt
	if validBrowserBootstrapSandboxTimes(invalid, now) {
		t.Fatal("sandbox time reversal accepted")
	}
	offset := valid
	offset.LeaseExpiresAt = now.Add(time.Minute).In(time.FixedZone("east-eight", 8*60*60)).Format(time.RFC3339Nano)
	offset.CreatedAt = now.Add(-time.Minute).In(time.FixedZone("west-five", -5*60*60)).Format(time.RFC3339Nano)
	offset.UpdatedAt = now.In(time.FixedZone("east-eight", 8*60*60)).Format(time.RFC3339Nano)
	if !validBrowserBootstrapSandboxTimes(offset, now) {
		t.Fatal("schema-valid offset sandbox date-time rejected")
	}
	statusWithOptional := valid
	statusWithOptional.RuntimeEndpointReference = "ref:runtime/opaque"
	statusWithOptional.SnapshotReference = "ref:snapshot/opaque"
	statusWithOptional.AgentRunID = "agent-run-1"
	statusWithOptional.ProviderStateReference = "ref:provider-state/opaque"
	statusWithOptional.LastError = &ProviderError{Code: "RUNTIME_FAILED", Message: "runtime failed", Outcome: "known_failed"}
	document, err = json.Marshal(statusWithOptional)
	if err != nil {
		t.Fatal(err)
	}
	var decodedStatus SandboxStatus
	if !decodeBrowserBootstrapSandbox(document, &decodedStatus) {
		t.Fatal("schema-valid SandboxStatus optional fields rejected")
	}
	for _, field := range []string{"runtime_endpoint_reference", "snapshot_reference", "agent_run_id", "provider_state_reference"} {
		var raw map[string]any
		if json.Unmarshal(document, &raw) != nil {
			t.Fatal("decode optional sandbox field test document")
		}
		raw[field] = ""
		invalidDocument, marshalErr := json.Marshal(raw)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if decodeBrowserBootstrapSandbox(invalidDocument, &decodedStatus) {
			t.Fatalf("explicit empty %s accepted", field)
		}
	}
}

func TestBrowserBootstrapJSONMediaTypeIsExact(t *testing.T) {
	for value, want := range map[string]bool{
		"application/json":                true,
		"application/json; charset=utf-8": true,
		"application/json-seq":            false,
		"application/json trailing":       false,
		"text/json":                       false,
		"":                                false,
	} {
		if got := isBrowserBootstrapJSON(value); got != want {
			t.Fatalf("isBrowserBootstrapJSON(%q) = %t, want %t", value, got, want)
		}
	}
}

func TestBrowserBootstrapPackageHasNoProviderImplementationDependency(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "./internal/caller")
	command.Dir = filepath.Clean(filepath.Join("..", ".."))
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dependency := range strings.Fields(string(output)) {
		if dependency == "github.com/shell-echo/sandbox-runtime" || strings.HasPrefix(dependency, "github.com/shell-echo/sandbox-runtime/") {
			t.Fatalf("caller imports Provider repository package %q", dependency)
		}
	}
}

func (p *browserBootstrapProvider) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	p.t.Helper()
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 || len(request.TLS.PeerCertificates[0].URIs) != 1 ||
		request.TLS.PeerCertificates[0].URIs[0].String() != p.config.Controller.ControllerSubject {
		p.t.Errorf("request did not use the exact Controller mTLS identity")
	}
	if request.URL.Path == "/v1/capabilities" {
		if request.Header.Get("Authorization") != "" || request.Header.Get(admissionContextHeader) != "" {
			p.t.Errorf("capability discovery unexpectedly used protected admission")
		}
		writeBrowserBootstrapTestJSON(p.t, writer, http.StatusOK, browserBootstrapTestCapabilities(p.config))
		return
	}
	expectedAdmission := ""
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes":
		expectedAdmission = "create"
	case request.Method == http.MethodGet && request.URL.Path == "/v1/operations/"+p.config.CreateOperationID:
		expectedAdmission = "read_operation"
	case request.Method == http.MethodGet && request.URL.Path == "/v1/sandboxes/"+p.config.SandboxID:
		expectedAdmission = "read_sandbox"
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes/"+p.config.SandboxID+"/browser-sessions":
		expectedAdmission = "open_browser_session"
	case request.Method == http.MethodGet && request.URL.Path == "/v1/operations/"+p.config.OpenOperationID:
		expectedAdmission = "read_operation"
	case request.Method == http.MethodGet && request.URL.Path == "/v1/operations/"+p.config.OpenOperationID+"/browser-session":
		expectedAdmission = "read_browser_session"
	default:
		http.NotFound(writer, request)
		return
	}
	document, claims := p.verifyProtectedRequest(request, expectedAdmission)
	p.mu.Lock()
	p.protectedRequests++
	if p.jti[claims.JTI] {
		p.t.Errorf("JTI was reused")
	}
	p.jti[claims.JTI] = true
	p.mu.Unlock()
	if (p.transientReads || request.URL.Path == p.invalidReadPath) && (expectedAdmission == "read_operation" || expectedAdmission == "read_browser_session") {
		p.mu.Lock()
		p.readAttempts[request.URL.Path]++
		attempt := p.readAttempts[request.URL.Path]
		p.mu.Unlock()
		if request.URL.Path == p.invalidReadPath && attempt == 1 {
			writeBrowserBootstrapTestJSON(p.t, writer, p.invalidReadStatus, StandardError{Code: "SANDBOX_NOT_FOUND", Message: "not found"})
			return
		}
		if attempt == 1 {
			writeBrowserBootstrapTestJSON(p.t, writer, http.StatusNotFound, StandardError{Code: "SANDBOX_NOT_FOUND", Message: "not found", TraceID: "trace-transient-1"})
			return
		}
		if attempt == 2 {
			writeBrowserBootstrapTestJSON(p.t, writer, http.StatusServiceUnavailable, StandardError{Code: "SANDBOX_PROVIDER_UNAVAILABLE", Message: "unavailable", Retryable: true, TraceID: "trace-transient-2"})
			return
		}
	}

	switch expectedAdmission {
	case "create":
		p.mu.Lock()
		p.createRequests++
		p.mu.Unlock()
		if p.invalidCreateStatus != 0 {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(p.invalidCreateStatus)
			_, _ = writer.Write([]byte(`{"status":"invalid-media-type"}`))
			return
		}
		if p.dropMutations {
			dropBrowserBootstrapResponse(p.t, writer)
			return
		}
		writeBrowserBootstrapTestJSON(p.t, writer, http.StatusAccepted, browserBootstrapTestOperation(p.config, true, "accepted"))
	case "read_operation":
		create := claims.OperationID == p.config.CreateOperationID
		writeBrowserBootstrapTestJSON(p.t, writer, http.StatusOK, browserBootstrapTestOperation(p.config, create, "succeeded"))
	case "read_sandbox":
		now := time.Now().UTC()
		writeBrowserBootstrapTestJSON(p.t, writer, http.StatusOK, SandboxStatus{
			SandboxID: p.config.SandboxID, TenantID: p.config.TenantID, WorkOrderID: p.config.WorkOrderID,
			WorkspaceID: p.config.WorkspaceID, ProviderRevisionID: p.config.ProviderRevisionID,
			DesiredState: "ready", ObservedState: "ready", Generation: 1, ObservedGeneration: 1,
			RuntimeProfile: "sandbox-runtime-browser-v1", LeaseExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
			CreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), SandboxSlotKey: "browser",
		})
	case "open_browser_session":
		var body map[string]any
		if err := json.Unmarshal(document, &body); err != nil {
			p.t.Error(err)
		}
		expiresAt, _ := body["expires_at"].(string)
		p.mu.Lock()
		p.openRequests++
		p.openExpiry = expiresAt
		p.mu.Unlock()
		if p.dropMutations {
			dropBrowserBootstrapResponse(p.t, writer)
			return
		}
		writeBrowserBootstrapTestJSON(p.t, writer, http.StatusAccepted, browserBootstrapTestOperation(p.config, false, "accepted"))
	case "read_browser_session":
		p.mu.Lock()
		expiresAt := p.openExpiry
		p.mu.Unlock()
		writeBrowserBootstrapTestJSON(p.t, writer, http.StatusOK, BrowserSessionHandoff{
			OperationID: p.config.OpenOperationID, AttemptID: p.config.OpenAttemptID,
			FencingToken: p.config.OpenFencingToken, SandboxID: p.config.SandboxID,
			BrowserSessionID: p.config.BrowserSessionID, CapabilityProfileID: "browser-v1", Protocol: "websocket",
			InternalEndpointReference: bootstrapTestHandoff, ConnectionGeneration: 1, ExpiresAt: expiresAt,
		})
	}
}

func (p *browserBootstrapProvider) verifyProtectedRequest(request *http.Request, expectedOperation string) ([]byte, tokenClaims) {
	p.t.Helper()
	document, err := io.ReadAll(io.LimitReader(request.Body, 128<<10))
	if err != nil {
		p.t.Error(err)
	}
	compact := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		p.t.Fatalf("invalid compact JWS")
	}
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil || !ed25519.Verify(p.jwsPublic, []byte(segments[0]+"."+segments[1]), signature) {
		p.t.Fatalf("JWS signature did not verify")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		p.t.Fatal(err)
	}
	var header jwsHeader
	if err := decodeStrict(headerJSON, &header); err != nil || header.Algorithm != "EdDSA" || header.KeyID != p.config.Controller.JWSKeyID || header.Type != jwsType {
		p.t.Fatalf("JWS header = %#v, error = %v", header, err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		p.t.Fatal(err)
	}
	var claims tokenClaims
	if err := decodeStrict(payload, &claims); err != nil {
		p.t.Fatal(err)
	}
	contextJSON, err := base64.RawURLEncoding.DecodeString(request.Header.Get(admissionContextHeader))
	if err != nil {
		p.t.Fatal(err)
	}
	var admitted admissionContext
	if err := decodeStrict(contextJSON, &admitted); err != nil {
		p.t.Fatal(err)
	}
	wantContextDigest, err := contextDigest(admitted)
	if err != nil || admitted.ContextDigest != wantContextDigest || claims.AdmissionContextDigest != wantContextDigest ||
		claims.Operation != expectedOperation || admitted.Operation != expectedOperation || claims.Subject != p.config.Controller.ControllerSubject ||
		claims.Audience != p.config.ProviderInstanceAudience || claims.ProviderRevisionID != p.config.ProviderRevisionID ||
		claims.TenantID != p.config.TenantID || claims.WorkOrderID != p.config.WorkOrderID ||
		admitted.HTTPTarget.Method != request.Method || admitted.HTTPTarget.Path != request.URL.Path {
		p.t.Fatalf("protected admission binding differs from request")
	}
	var digestDocumentBytes []byte
	if len(document) != 0 {
		digestDocumentBytes = document
	} else {
		digestDocumentBytes, err = json.Marshal(map[string]any{
			"operation": claims.Operation, "sandbox_id": claims.SandboxID, "operation_id": claims.OperationID,
			"attempt_id": claims.AttemptID, "fencing_token": claims.FencingToken,
		})
		if err != nil {
			p.t.Fatal(err)
		}
	}
	wantRequestDigest, err := digestDocument(claims.RequestDigestProfile, digestDocumentBytes)
	if err != nil || claims.RequestDigest != wantRequestDigest || admitted.RequestDigest != wantRequestDigest {
		p.t.Fatalf("request digest binding is invalid")
	}
	return document, claims
}

func newBrowserBootstrapTestMaterial(t *testing.T, controllerSubject string) browserBootstrapTestMaterial {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC()
	_, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bootstrap test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPrivate.Public(), caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile := writeBrowserBootstrapTestFile(t, root, "ca.pem", caPEM, 0o644)
	clientURI, err := url.Parse(controllerSubject)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, clientCertificateFile, clientPrivateFile := issueBrowserBootstrapTestCertificate(
		t, root, "client", big.NewInt(2), caCertificate, caPrivate,
		&x509.Certificate{
			Subject: pkix.Name{CommonName: "bootstrap client"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{clientURI},
		},
	)
	_ = clientCertificate
	serverCertificate, _, _ := issueBrowserBootstrapTestCertificate(
		t, root, "server", big.NewInt(3), caCertificate, caPrivate,
		&x509.Certificate{
			Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		},
	)
	jwsPublic, jwsPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwsDER, err := x509.MarshalPKCS8PrivateKey(jwsPrivate)
	if err != nil {
		t.Fatal(err)
	}
	jwsFile := writeBrowserBootstrapTestFile(t, root, "jws-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: jwsDER}), 0o600)
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return browserBootstrapTestMaterial{
		serverCertificate: serverCertificate, clientRoots: roots, jwsPublic: jwsPublic,
		config: BrowserBootstrapConfig{
			ProviderBaseURL: "https://127.0.0.1:10443", CAFile: caFile,
			ProviderRevisionID:       "provider-revision-downstream-v1",
			ProviderInstanceAudience: "urn:shell-echo:sandbox-runtime:provider-instance:downstream-e2e",
			RuntimeImageReference:    "ghcr.io/shell-echo/browser", RuntimeImageDigest: "sha256:" + strings.Repeat("d", 64), RuntimeArchitecture: "arm64",
			Controller: BrowserBootstrapController{
				ControllerSubject: controllerSubject, CertificateFile: clientCertificateFile,
				PrivateKeyFile: clientPrivateFile, JWSPrivateKeyFile: jwsFile, JWSKeyID: "downstream-controller-a-key",
			},
			TenantID: "tenant-downstream-a", WorkOrderID: "work-order-downstream-a", SandboxID: "sandbox-downstream-a",
			WorkspaceID: "workspace-downstream-a", WorkspaceRevisionID: "workspace-revision-downstream-a",
			WorkspaceRevisionDigest: "sha256:" + strings.Repeat("e", 64), BranchID: "branch-downstream-a",
			ProviderResolutionID: "provider-resolution-downstream-a", NetworkPolicyReference: "browser-egress-policy-1",
			CreateOperationID: "operation-create-downstream-a", CreateAttemptID: "attempt-create-downstream-a",
			CreateFencingToken: 11, CreateIdempotencyKey: "idempotency-create-downstream-a",
			OpenOperationID: "operation-open-downstream-a", OpenAttemptID: "attempt-open-downstream-a",
			OpenFencingToken: 12, OpenIdempotencyKey: "idempotency-open-downstream-a",
			BrowserSessionID: "browser-session-downstream-a", PollTimeoutMillis: 1000,
		},
	}
}

func issueBrowserBootstrapTestCertificate(t *testing.T, root, name string, serial *big.Int, ca *x509.Certificate, caPrivate ed25519.PrivateKey, template *x509.Certificate) (tls.Certificate, string, string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, template, ca, private.Public(), caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificateFile := writeBrowserBootstrapTestFile(t, root, name+".pem", certificatePEM, 0o644)
	privateFile := writeBrowserBootstrapTestFile(t, root, name+"-key.pem", privatePEM, 0o600)
	certificate, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certificateFile, privateFile
}

func newBrowserBootstrapTestServer(t *testing.T, material browserBootstrapTestMaterial, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{material.serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: material.clientRoots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	return server
}

func browserBootstrapTestCapabilities(config BrowserBootstrapConfig) Capabilities {
	workspace := int64(1073741824)
	return Capabilities{
		ProviderRevisionID: config.ProviderRevisionID, APIVersion: "v1",
		Capabilities: []Capability{{ID: "sandbox.browser", Versions: []string{"1.0.0"}, Profiles: []string{"browser-v1"}}},
		RuntimeProfiles: []RuntimeProfile{{
			ID: "sandbox-runtime-browser-v1", IsolationClass: "container", RuntimeClassName: "sandbox-runtime-browser",
			Architecture: []string{config.RuntimeArchitecture}, CapabilityProfileIDs: []string{"browser-v1"},
		}},
		SnapshotRestoreProfiles: []SnapshotRestoreProfile{{
			ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider",
			SuiteVersion: "1.0.0", SuiteDigest: "sha256:" + strings.Repeat("a", 64),
		}},
		Limits: ProviderLimits{
			MaxCPUMillis: 2000, MaxMemoryBytes: 2147483648, MaxEphemeralStorageBytes: 2147483648,
			MaxWorkspaceBytes: &workspace, MaxLeaseSeconds: 3600, MaxExecSeconds: 300,
		},
	}
}

func browserBootstrapTestOperation(config BrowserBootstrapConfig, create bool, status string) Operation {
	operation := Operation{
		OperationID: config.OpenOperationID, AttemptID: config.OpenAttemptID, FencingToken: config.OpenFencingToken,
		SandboxID: config.SandboxID, Type: "open_browser_session", Status: status,
		ProviderOperationID: config.OpenOperationID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if create {
		operation.OperationID, operation.AttemptID, operation.FencingToken, operation.Type =
			config.CreateOperationID, config.CreateAttemptID, config.CreateFencingToken, "create"
		operation.ProviderOperationID = config.CreateOperationID
	}
	return operation
}

func writeBrowserBootstrapTestJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Error(err)
	}
}

func dropBrowserBootstrapResponse(t *testing.T, writer http.ResponseWriter) {
	t.Helper()
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		t.Fatal("response writer cannot hijack")
	}
	connection, _, err := hijacker.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
}

func writeBrowserBootstrapTestFile(t *testing.T, root, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertBrowserBootstrapError(t *testing.T, err error, want string) {
	t.Helper()
	var bootstrapError *BrowserBootstrapError
	if !errors.As(err, &bootstrapError) || bootstrapError.Code != want || err.Error() != "browser bootstrap failed: "+want {
		t.Fatalf("bootstrap error = %v, want code %q", err, want)
	}
}
