package caller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxBrowserBootstrapConfigBytes = 128 << 10
	maxBrowserBootstrapCABytes     = 256 << 10
	maxBrowserBootstrapPEMBytes    = 64 << 10
	maxBrowserBootstrapResponse    = 64 << 10
	minBrowserBootstrapPoll        = 25 * time.Millisecond
	maxBrowserBootstrapPoll        = 330 * time.Second
	maxBrowserBootstrapRequest     = 20 * time.Second
	maxBrowserBootstrapSafeInteger = int64(9007199254740991)
	browserBootstrapPollInterval   = 100 * time.Millisecond
	minBrowserBootstrapPollMillis  = int64(minBrowserBootstrapPoll / time.Millisecond)
	maxBrowserBootstrapPollMillis  = int64(maxBrowserBootstrapPoll / time.Millisecond)
)

const (
	BrowserBootstrapInvalidConfiguration  = "invalid_configuration"
	BrowserBootstrapTransportFailed       = "transport_failed"
	BrowserBootstrapCapabilityRejected    = "capability_rejected"
	BrowserBootstrapCapabilityInvalid     = "capability_invalid"
	BrowserBootstrapCreateRejected        = "create_rejected"
	BrowserBootstrapCreateInvalid         = "create_invalid"
	BrowserBootstrapCreateFailed          = "create_failed"
	BrowserBootstrapSandboxRejected       = "sandbox_rejected"
	BrowserBootstrapSandboxInvalid        = "sandbox_invalid"
	BrowserBootstrapOpenRejected          = "open_rejected"
	BrowserBootstrapOpenInvalid           = "open_invalid"
	BrowserBootstrapOpenFailed            = "open_failed"
	BrowserBootstrapHandoffRejected       = "handoff_rejected"
	BrowserBootstrapHandoffInvalid        = "handoff_invalid"
	BrowserBootstrapEndpointBindingFailed = "endpoint_binding_failed"
	BrowserBootstrapTimedOut              = "timed_out"
	BrowserBootstrapCanceled              = "canceled"
)

var (
	browserBootstrapReferencePattern = regexp.MustCompile(`^ref:browser-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	browserBootstrapIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	browserBootstrapResultPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)
	browserBootstrapErrorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	browserBootstrapAudiencePattern  = regexp.MustCompile(`^urn:shell-echo:sandbox-runtime:provider-instance:[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

// BrowserBootstrapError exposes only a stable code. Provider response bodies,
// transport diagnostics, configuration values, and private file paths remain
// inside the caller process.
type BrowserBootstrapError struct {
	Code string
}

func (e *BrowserBootstrapError) Error() string {
	if e == nil {
		return "browser bootstrap failed"
	}
	return "browser bootstrap failed: " + e.Code
}

type BrowserBootstrapController struct {
	ControllerSubject string `json:"controller_subject"`
	CertificateFile   string `json:"certificate_file"`
	PrivateKeyFile    string `json:"private_key_file"`
	JWSPrivateKeyFile string `json:"jws_private_key_file"`
	JWSKeyID          string `json:"jws_key_id"`
}

// BrowserBootstrapConfig is deliberately independent from Config: one caller
// process owns one Provider mTLS/JWS Controller identity. Every durable
// operation and resource identity is supplied by the caller and must be unique
// for the run.
type BrowserBootstrapConfig struct {
	ProviderBaseURL          string                     `json:"provider_base_url"`
	CAFile                   string                     `json:"ca_file"`
	ProviderRevisionID       string                     `json:"provider_revision_id"`
	ProviderInstanceAudience string                     `json:"provider_instance_audience"`
	RuntimeImageReference    string                     `json:"runtime_image_reference"`
	RuntimeImageDigest       string                     `json:"runtime_image_digest"`
	RuntimeArchitecture      string                     `json:"runtime_architecture"`
	Controller               BrowserBootstrapController `json:"controller"`
	TenantID                 string                     `json:"tenant_id"`
	WorkOrderID              string                     `json:"work_order_id"`
	SandboxID                string                     `json:"sandbox_id"`
	WorkspaceID              string                     `json:"workspace_id"`
	WorkspaceRevisionID      string                     `json:"workspace_revision_id"`
	WorkspaceRevisionDigest  string                     `json:"workspace_revision_digest"`
	BranchID                 string                     `json:"branch_id"`
	ProviderResolutionID     string                     `json:"provider_resolution_id"`
	NetworkPolicyReference   string                     `json:"network_policy_reference"`
	CreateOperationID        string                     `json:"create_operation_id"`
	CreateAttemptID          string                     `json:"create_attempt_id"`
	CreateFencingToken       int64                      `json:"create_fencing_token"`
	CreateIdempotencyKey     string                     `json:"create_idempotency_key"`
	OpenOperationID          string                     `json:"open_operation_id"`
	OpenAttemptID            string                     `json:"open_attempt_id"`
	OpenFencingToken         int64                      `json:"open_fencing_token"`
	OpenIdempotencyKey       string                     `json:"open_idempotency_key"`
	BrowserSessionID         string                     `json:"browser_session_id"`
	PollTimeoutMillis        int64                      `json:"poll_timeout_millis"`
}

// browserBootstrapEndpoint is private orchestration material. A later,
// separately reviewed private-manifest step may translate these fields
// explicitly for Gateway startup.
type browserBootstrapEndpoint struct {
	tenantID             string
	sandboxID            string
	browserSessionID     string
	capabilityProfileID  string
	handoffReference     string
	connectionGeneration int64
	expiresAt            time.Time
}

type BrowserBootstrapResult struct {
	endpoint browserBootstrapEndpoint
}

// BrowserBootstrapEndpointSink receives one correlated, private endpoint in
// memory. Implementations must not project its arguments into ordinary output,
// logs, metrics, URLs, or public protocols.
type BrowserBootstrapEndpointSink interface {
	BindBrowserBootstrapEndpoint(
		tenantID string,
		sandboxID string,
		browserSessionID string,
		capabilityProfileID string,
		handoffReference string,
		connectionGeneration int64,
		expiresAt time.Time,
	) error
}

func (r BrowserBootstrapResult) String() string {
	return "BrowserBootstrapResult{ready:" + strconv.FormatBool(r.ready()) + "}"
}
func (r BrowserBootstrapResult) GoString() string { return r.String() }
func (r BrowserBootstrapResult) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("ready", r.ready()))
}
func (r BrowserBootstrapResult) ready() bool { return r.endpoint.handoffReference != "" }

// BindEndpoint passes the complete bootstrap result to one trusted in-process
// sink without introducing an exported endpoint DTO. Sink failures are reduced
// to a stable code so private arguments and implementation errors cannot escape.
func (r BrowserBootstrapResult) BindEndpoint(sink BrowserBootstrapEndpointSink) error {
	if !r.ready() || nilBrowserBootstrapEndpointSink(sink) {
		return browserBootstrapFailure(BrowserBootstrapEndpointBindingFailed)
	}
	endpoint := r.endpoint
	if err := sink.BindBrowserBootstrapEndpoint(
		endpoint.tenantID,
		endpoint.sandboxID,
		endpoint.browserSessionID,
		endpoint.capabilityProfileID,
		endpoint.handoffReference,
		endpoint.connectionGeneration,
		endpoint.expiresAt,
	); err != nil {
		return browserBootstrapFailure(BrowserBootstrapEndpointBindingFailed)
	}
	return nil
}

func nilBrowserBootstrapEndpointSink(sink BrowserBootstrapEndpointSink) bool {
	if sink == nil {
		return true
	}
	value := reflect.ValueOf(sink)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}

type browserBootstrapClient struct {
	config    BrowserBootstrapConfig
	http      *http.Client
	transport *http.Transport
	private   ed25519.PrivateKey
}

type browserBootstrapMutationOutcome int

const (
	browserBootstrapMutationAccepted browserBootstrapMutationOutcome = iota
	browserBootstrapMutationUnknown
	browserBootstrapMutationInvalidResponse
)

type browserBootstrapResponse struct {
	status   int
	body     []byte
	received bool
}

type browserBootstrapStandardError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable *bool  `json:"retryable"`
	TraceID   string `json:"trace_id"`
}

type browserBootstrapReference struct {
	operationID  string
	attemptID    string
	fencingToken int64
	operation    string
}

// LoadBrowserBootstrapConfig reads one strict, bounded, private regular JSON
// file without following symlinks.
func LoadBrowserBootstrapConfig(path string) (BrowserBootstrapConfig, error) {
	if !filepath.IsAbs(path) {
		return BrowserBootstrapConfig{}, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	document, err := readBrowserBootstrapFile(path, maxBrowserBootstrapConfigBytes, true)
	if err != nil || validateBootstrapUniqueJSON(document) != nil {
		return BrowserBootstrapConfig{}, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var config BrowserBootstrapConfig
	if err := decoder.Decode(&config); err != nil {
		return BrowserBootstrapConfig{}, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return BrowserBootstrapConfig{}, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	if err := validateBrowserBootstrapConfig(config); err != nil {
		return BrowserBootstrapConfig{}, err
	}
	return config, nil
}

// BootstrapBrowser performs only the locked Provider Browser control-plane
// flow. It has no Gateway, Provider implementation, runtime model, or test
// helper dependency and returns the opaque handoff only in memory. Cleanup of
// a sandbox accepted before a later bootstrap failure belongs to the future
// caller lifecycle coordinator; this helper adds no uncontracted mutation.
func BootstrapBrowser(ctx context.Context, config BrowserBootstrapConfig) (BrowserBootstrapResult, error) {
	if ctx == nil {
		return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	client, err := newBrowserBootstrapClient(config)
	if err != nil {
		return BrowserBootstrapResult{}, err
	}
	defer client.close()

	if err := client.verifyCapabilities(ctx); err != nil {
		return BrowserBootstrapResult{}, err
	}
	createReference := browserBootstrapReference{
		operationID: config.CreateOperationID, attemptID: config.CreateAttemptID,
		fencingToken: config.CreateFencingToken, operation: "create",
	}
	createOutcome, err := client.createSandbox(ctx, createReference)
	if err != nil {
		return BrowserBootstrapResult{}, err
	}
	if err := client.waitOperation(ctx, createReference, BrowserBootstrapCreateFailed); err != nil {
		return BrowserBootstrapResult{}, err
	}
	if createOutcome == browserBootstrapMutationInvalidResponse {
		return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapCreateInvalid)
	}
	if err := client.verifySandbox(ctx, createReference); err != nil {
		return BrowserBootstrapResult{}, err
	}
	openReference := browserBootstrapReference{
		operationID: config.OpenOperationID, attemptID: config.OpenAttemptID,
		fencingToken: config.OpenFencingToken, operation: "open_browser_session",
	}
	expiresAt, openOutcome, err := client.openBrowserSession(ctx, openReference)
	if err != nil {
		return BrowserBootstrapResult{}, err
	}
	if err := client.waitOperation(ctx, openReference, BrowserBootstrapOpenFailed); err != nil {
		return BrowserBootstrapResult{}, err
	}
	if openOutcome == browserBootstrapMutationInvalidResponse {
		return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapOpenInvalid)
	}
	return client.waitHandoff(ctx, openReference, expiresAt)
}

func newBrowserBootstrapClient(config BrowserBootstrapConfig) (*browserBootstrapClient, error) {
	if err := validateBrowserBootstrapConfig(config); err != nil {
		return nil, err
	}
	caPEM, err := readBrowserBootstrapFile(config.CAFile, maxBrowserBootstrapCABytes, false)
	if err != nil {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	certificatePEM, err := readBrowserBootstrapFile(config.Controller.CertificateFile, maxBrowserBootstrapPEMBytes, false)
	if err != nil {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	privateKeyPEM, err := readBrowserBootstrapFile(config.Controller.PrivateKeyFile, maxBrowserBootstrapPEMBytes, true)
	if err != nil {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range certificate.Certificate[1:] {
		intermediate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
		}
		intermediates.AddCert(intermediate)
	}
	if len(certificate.Leaf.URIs) != 1 || certificate.Leaf.URIs[0].String() != config.Controller.ControllerSubject {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	if _, err := certificate.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: time.Now().UTC(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	jwsPEM, err := readBrowserBootstrapFile(config.Controller.JWSPrivateKeyFile, maxBrowserBootstrapPEMBytes, true)
	if err != nil || bytes.Equal(privateKeyPEM, jwsPEM) {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	block, trailing := pem.Decode(jwsPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(trailing) != 0 {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(private) != ed25519.PrivateKeySize {
		return nil, browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 10 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: maxBrowserBootstrapRequest,
		MaxResponseHeaderBytes: maxBrowserBootstrapResponse,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: roots, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"},
		},
	}
	return &browserBootstrapClient{
		config: config, transport: transport,
		http:    &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		private: private,
	}, nil
}

func (c *browserBootstrapClient) close() {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

func (c *browserBootstrapClient) verifyCapabilities(ctx context.Context) error {
	result, err := c.request(ctx, http.MethodGet, "/v1/capabilities", nil)
	if result.received && result.status != http.StatusOK {
		return browserBootstrapFailure(BrowserBootstrapCapabilityRejected)
	}
	if err != nil {
		if result.received {
			return browserBootstrapFailure(BrowserBootstrapCapabilityInvalid)
		}
		return err
	}
	var capabilities Capabilities
	if !decodeBrowserBootstrapDocument(result.body, &capabilities) || checkNoBackendDisclosure(result.body) != nil {
		return browserBootstrapFailure(BrowserBootstrapCapabilityInvalid)
	}
	wantCapabilities := []Capability{{ID: "sandbox.browser", Versions: []string{"1.0.0"}, Profiles: []string{"browser-v1"}}}
	wantRuntimeProfiles := []RuntimeProfile{{
		ID: "sandbox-runtime-browser-v1", IsolationClass: "container", RuntimeClassName: "sandbox-runtime-browser",
		Architecture: []string{c.config.RuntimeArchitecture}, CapabilityProfileIDs: []string{"browser-v1"},
	}}
	wantSnapshotProfiles := []SnapshotRestoreProfile{{
		ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider",
		SuiteVersion: "1.0.0", SuiteDigest: "sha256:" + strings.Repeat("a", 64),
	}}
	limits := capabilities.Limits
	if capabilities.ProviderRevisionID != c.config.ProviderRevisionID || capabilities.APIVersion != "v1" ||
		!reflect.DeepEqual(capabilities.Capabilities, wantCapabilities) ||
		!reflect.DeepEqual(capabilities.RuntimeProfiles, wantRuntimeProfiles) ||
		!reflect.DeepEqual(capabilities.SnapshotRestoreProfiles, wantSnapshotProfiles) ||
		limits.MaxCPUMillis < 1000 || limits.MaxMemoryBytes < 1073741824 || limits.MaxEphemeralStorageBytes < 1073741824 ||
		limits.MaxWorkspaceBytes == nil || *limits.MaxWorkspaceBytes < 268435456 || (limits.MaxGPUCount != nil && *limits.MaxGPUCount != 0) ||
		limits.MaxLeaseSeconds < 900 || limits.MaxExecSeconds < 1 {
		return browserBootstrapFailure(BrowserBootstrapCapabilityInvalid)
	}
	return nil
}

func (c *browserBootstrapClient) createSandbox(ctx context.Context, reference browserBootstrapReference) (browserBootstrapMutationOutcome, error) {
	now := time.Now().UTC()
	deadline := now.Add(5 * time.Minute)
	body := mutationEnvelope(reference.operationID, reference.attemptID, reference.fencingToken, c.config.CreateIdempotencyKey, deadline)
	body["protocol_version"] = "v1"
	body["spec"] = map[string]any{
		"sandbox_id": c.config.SandboxID, "tenant_id": c.config.TenantID,
		"work_order_id": c.config.WorkOrderID, "workspace_id": c.config.WorkspaceID,
		"branch_id": c.config.BranchID, "provider_resolution_id": c.config.ProviderResolutionID,
		"provider_revision_id": c.config.ProviderRevisionID,
		"image": map[string]any{
			"reference": c.config.RuntimeImageReference, "digest": c.config.RuntimeImageDigest,
			"architecture": c.config.RuntimeArchitecture,
		},
		"runtime_profile": "sandbox-runtime-browser-v1",
		"resources": map[string]any{
			"cpu_millis": 1000, "memory_bytes": int64(1073741824), "ephemeral_storage_bytes": int64(1073741824),
			"workspace_bytes": int64(268435456), "pids_limit": 256,
		},
		"required_capabilities": []any{
			map[string]any{"id": "sandbox.browser", "version": "1.0.0", "profile": "browser-v1"},
		},
		"network": map[string]any{
			"mode": "restricted", "policy_reference": c.config.NetworkPolicyReference, "egress_gateway_required": true,
		},
		"workspace": map[string]any{
			"mode": "ephemeral", "base_revision_id": c.config.WorkspaceRevisionID,
			"base_revision_digest": c.config.WorkspaceRevisionDigest, "base_workspace_head_version": 0,
			"commit_mode": "read_only", "mount_path": "/workspace",
		},
		"lease": map[string]any{
			"expires_at": now.Add(15 * time.Minute).Format(time.RFC3339Nano), "max_extension_seconds": 3600,
		},
		"placement_constraints": map[string]any{"resource_class": "browser", "architecture": c.config.RuntimeArchitecture},
		"security": map[string]any{
			"privilege_level": "unprivileged", "root_filesystem": "read_only", "service_account_mode": "none",
			"allow_privilege_escalation": false, "host_namespace_access": false, "seccomp_profile": "runtime-default",
		},
		"sandbox_slot_key": "browser",
	}
	prepared, err := c.prepare(http.MethodPost, "/v1/sandboxes", body, "create", reference, deadline)
	if err != nil {
		return browserBootstrapMutationInvalidResponse, browserBootstrapFailure(BrowserBootstrapCreateInvalid)
	}
	result, err := c.request(ctx, prepared.Method, prepared.Path, &prepared)
	if err != nil {
		if result.received {
			if result.status == http.StatusAccepted {
				return browserBootstrapMutationInvalidResponse, nil
			}
			return browserBootstrapMutationAccepted, browserBootstrapFailure(BrowserBootstrapCreateRejected)
		}
		if ctx.Err() != nil {
			return browserBootstrapMutationUnknown, browserBootstrapContextFailure(ctx, ctx)
		}
		return browserBootstrapMutationUnknown, nil
	}
	if result.status != http.StatusAccepted {
		return browserBootstrapMutationAccepted, browserBootstrapFailure(BrowserBootstrapCreateRejected)
	}
	var operation Operation
	if !decodeBrowserBootstrapOperation(result.body, &operation) || checkNoBackendDisclosure(result.body) != nil ||
		!validBrowserBootstrapOperation(operation, c.config.SandboxID, reference, "") ||
		!validBrowserBootstrapMutationProgress(operation.Status) {
		return browserBootstrapMutationInvalidResponse, nil
	}
	return browserBootstrapMutationAccepted, nil
}

func (c *browserBootstrapClient) verifySandbox(ctx context.Context, reference browserBootstrapReference) error {
	prepared, err := c.prepare(http.MethodGet, "/v1/sandboxes/"+c.config.SandboxID, nil, "read_sandbox", reference, time.Now().UTC().Add(time.Minute))
	if err != nil {
		return browserBootstrapFailure(BrowserBootstrapSandboxInvalid)
	}
	result, err := c.request(ctx, prepared.Method, prepared.Path, &prepared)
	if result.received && result.status != http.StatusOK {
		return browserBootstrapFailure(BrowserBootstrapSandboxRejected)
	}
	if err != nil {
		if result.received {
			return browserBootstrapFailure(BrowserBootstrapSandboxInvalid)
		}
		return err
	}
	var status SandboxStatus
	if !decodeBrowserBootstrapSandbox(result.body, &status) || checkNoBackendDisclosure(result.body) != nil ||
		status.SandboxID != c.config.SandboxID || status.TenantID != c.config.TenantID || status.WorkOrderID != c.config.WorkOrderID ||
		status.WorkspaceID != c.config.WorkspaceID || status.ProviderRevisionID != c.config.ProviderRevisionID ||
		status.DesiredState != "ready" || status.ObservedState != "ready" || status.Generation != 1 || status.ObservedGeneration != 1 ||
		status.RuntimeProfile != "sandbox-runtime-browser-v1" || status.SandboxSlotKey != "browser" ||
		!validBrowserBootstrapSandboxTimes(status, time.Now().UTC()) {
		return browserBootstrapFailure(BrowserBootstrapSandboxInvalid)
	}
	return nil
}

func (c *browserBootstrapClient) openBrowserSession(ctx context.Context, reference browserBootstrapReference) (time.Time, browserBootstrapMutationOutcome, error) {
	now := time.Now().UTC()
	deadline := now.Add(5 * time.Minute)
	expiresAt := now.Add(4 * time.Minute)
	body := mutationEnvelope(reference.operationID, reference.attemptID, reference.fencingToken, c.config.OpenIdempotencyKey, deadline)
	body["expected_generation"] = 1
	body["browser_session_id"] = c.config.BrowserSessionID
	body["capability_profile_id"] = "browser-v1"
	body["expires_at"] = expiresAt.Format(time.RFC3339Nano)
	prepared, err := c.prepare(http.MethodPost, "/v1/sandboxes/"+c.config.SandboxID+"/browser-sessions", body, "open_browser_session", reference, deadline)
	if err != nil {
		return time.Time{}, browserBootstrapMutationInvalidResponse, browserBootstrapFailure(BrowserBootstrapOpenInvalid)
	}
	result, err := c.request(ctx, prepared.Method, prepared.Path, &prepared)
	if err != nil {
		if result.received {
			if result.status == http.StatusAccepted {
				return expiresAt, browserBootstrapMutationInvalidResponse, nil
			}
			return time.Time{}, browserBootstrapMutationAccepted, browserBootstrapFailure(BrowserBootstrapOpenRejected)
		}
		if ctx.Err() != nil {
			return time.Time{}, browserBootstrapMutationUnknown, browserBootstrapContextFailure(ctx, ctx)
		}
		return expiresAt, browserBootstrapMutationUnknown, nil
	}
	if result.status != http.StatusAccepted {
		return time.Time{}, browserBootstrapMutationAccepted, browserBootstrapFailure(BrowserBootstrapOpenRejected)
	}
	var operation Operation
	if !decodeBrowserBootstrapOperation(result.body, &operation) || checkNoBackendDisclosure(result.body) != nil ||
		!validBrowserBootstrapOperation(operation, c.config.SandboxID, reference, "") ||
		!validBrowserBootstrapMutationProgress(operation.Status) {
		return expiresAt, browserBootstrapMutationInvalidResponse, nil
	}
	return expiresAt, browserBootstrapMutationAccepted, nil
}

func (c *browserBootstrapClient) waitOperation(ctx context.Context, reference browserBootstrapReference, failureCode string) error {
	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(c.config.PollTimeoutMillis)*time.Millisecond)
	defer cancel()
	for {
		prepared, err := c.prepare(http.MethodGet, "/v1/operations/"+reference.operationID, nil, "read_operation", reference, time.Now().UTC().Add(time.Minute))
		if err != nil {
			return browserBootstrapFailure(failureCode)
		}
		result, requestErr := c.request(pollCtx, prepared.Method, prepared.Path, &prepared)
		if requestErr != nil && result.received {
			return browserBootstrapFailure(failureCode)
		}
		if requestErr == nil && result.status == http.StatusOK {
			var operation Operation
			if !decodeBrowserBootstrapOperation(result.body, &operation) || checkNoBackendDisclosure(result.body) != nil ||
				!validBrowserBootstrapOperation(operation, c.config.SandboxID, reference, "") {
				return browserBootstrapFailure(failureCode)
			}
			switch operation.Status {
			case "succeeded":
				return nil
			case "accepted", "running":
			case "failed", "cancelled", "outcome_unknown":
				return browserBootstrapFailure(failureCode)
			default:
				return browserBootstrapFailure(failureCode)
			}
		} else if requestErr == nil {
			switch result.status {
			case http.StatusNotFound, http.StatusServiceUnavailable:
				if !validBrowserBootstrapStandardError(result.body) {
					return browserBootstrapFailure(failureCode)
				}
			default:
				return browserBootstrapFailure(failureCode)
			}
		}
		if err := waitBrowserBootstrapPoll(pollCtx); err != nil {
			return browserBootstrapContextFailure(ctx, pollCtx)
		}
	}
}

func (c *browserBootstrapClient) waitHandoff(ctx context.Context, reference browserBootstrapReference, requestedExpiry time.Time) (BrowserBootstrapResult, error) {
	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(c.config.PollTimeoutMillis)*time.Millisecond)
	defer cancel()
	path := "/v1/operations/" + reference.operationID + "/browser-session"
	for {
		prepared, err := c.prepare(http.MethodGet, path, nil, "read_browser_session", reference, time.Now().UTC().Add(time.Minute))
		if err != nil {
			return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapHandoffInvalid)
		}
		result, requestErr := c.request(pollCtx, prepared.Method, prepared.Path, &prepared)
		if requestErr != nil && result.received {
			return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapHandoffInvalid)
		}
		if requestErr == nil && result.status == http.StatusOK {
			var handoff BrowserSessionHandoff
			if !decodeBrowserBootstrapDocument(result.body, &handoff) || checkNoBackendDisclosure(result.body) != nil {
				return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapHandoffInvalid)
			}
			expiresAt, expiryOK := parseBrowserBootstrapTime(handoff.ExpiresAt)
			if handoff.OperationID != reference.operationID || handoff.AttemptID != reference.attemptID ||
				handoff.FencingToken != reference.fencingToken || handoff.SandboxID != c.config.SandboxID ||
				handoff.BrowserSessionID != c.config.BrowserSessionID || handoff.CapabilityProfileID != "browser-v1" ||
				handoff.Protocol != "websocket" || !browserBootstrapReferencePattern.MatchString(handoff.InternalEndpointReference) ||
				handoff.ConnectionGeneration < 1 || !expiryOK || !expiresAt.After(time.Now().UTC()) || expiresAt.After(requestedExpiry) {
				return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapHandoffInvalid)
			}
			return BrowserBootstrapResult{endpoint: browserBootstrapEndpoint{
				tenantID: c.config.TenantID, sandboxID: c.config.SandboxID, browserSessionID: c.config.BrowserSessionID,
				capabilityProfileID: "browser-v1", handoffReference: handoff.InternalEndpointReference,
				connectionGeneration: handoff.ConnectionGeneration, expiresAt: expiresAt,
			}}, nil
		}
		if requestErr == nil {
			switch result.status {
			case http.StatusNotFound, http.StatusServiceUnavailable:
				if !validBrowserBootstrapStandardError(result.body) {
					return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapHandoffInvalid)
				}
			default:
				return BrowserBootstrapResult{}, browserBootstrapFailure(BrowserBootstrapHandoffRejected)
			}
		}
		if err := waitBrowserBootstrapPoll(pollCtx); err != nil {
			return BrowserBootstrapResult{}, browserBootstrapContextFailure(ctx, pollCtx)
		}
	}
}

func (c *browserBootstrapClient) prepare(method, path string, body map[string]any, admissionOperation string, reference browserBootstrapReference, deadline time.Time) (preparedRequest, error) {
	return prepareAdmission(admissionAuthority{
		ControllerSubject: c.config.Controller.ControllerSubject, JWSKeyID: c.config.Controller.JWSKeyID,
		ProviderRevisionID: c.config.ProviderRevisionID, ProviderInstanceAudience: c.config.ProviderInstanceAudience,
	}, c.private, method, path, body, admissionBinding{
		Operation: admissionOperation, SandboxID: c.config.SandboxID,
		OperationID: reference.operationID, AttemptID: reference.attemptID, FencingToken: reference.fencingToken,
		TenantID: c.config.TenantID, WorkOrderID: c.config.WorkOrderID, Deadline: deadline,
	})
}

func (c *browserBootstrapClient) request(ctx context.Context, method, path string, prepared *preparedRequest) (browserBootstrapResponse, error) {
	requestCtx, cancel := context.WithTimeout(ctx, maxBrowserBootstrapRequest)
	defer cancel()
	var body io.Reader
	if prepared != nil && prepared.Body != nil {
		body = bytes.NewReader(prepared.Body)
	}
	request, err := http.NewRequestWithContext(requestCtx, method, c.config.ProviderBaseURL+path, body)
	if err != nil {
		return browserBootstrapResponse{}, browserBootstrapFailure(BrowserBootstrapTransportFailed)
	}
	request.Header.Set("Accept", "application/json")
	if prepared != nil {
		request.Header.Set("Authorization", prepared.Authorization)
		request.Header.Set(admissionContextHeader, prepared.AdmissionContext)
		if prepared.Body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	response, err := c.http.Do(request)
	if err != nil {
		if response != nil {
			response.Body.Close()
			return browserBootstrapResponse{status: response.StatusCode, received: true}, browserBootstrapFailure(BrowserBootstrapTransportFailed)
		}
		return browserBootstrapResponse{}, browserBootstrapContextFailure(ctx, requestCtx)
	}
	defer response.Body.Close()
	result := browserBootstrapResponse{status: response.StatusCode, received: true}
	if response.ContentLength > maxBrowserBootstrapResponse {
		return result, browserBootstrapFailure(BrowserBootstrapTransportFailed)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maxBrowserBootstrapResponse+1))
	if err != nil || len(document) > maxBrowserBootstrapResponse || (len(document) > 0 && !isBrowserBootstrapJSON(response.Header.Get("Content-Type"))) {
		return result, browserBootstrapFailure(BrowserBootstrapTransportFailed)
	}
	result.body = document
	return result, nil
}

func validateBrowserBootstrapConfig(config BrowserBootstrapConfig) error {
	if _, err := validateBrowserBootstrapURL(config.ProviderBaseURL); err != nil ||
		!filepath.IsAbs(config.CAFile) || !filepath.IsAbs(config.Controller.CertificateFile) ||
		!filepath.IsAbs(config.Controller.PrivateKeyFile) || !filepath.IsAbs(config.Controller.JWSPrivateKeyFile) {
		return browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	paths := []string{config.CAFile, config.Controller.CertificateFile, config.Controller.PrivateKeyFile, config.Controller.JWSPrivateKeyFile}
	seenPaths := make(map[string]bool, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if seenPaths[clean] {
			return browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
		}
		seenPaths[clean] = true
	}
	if !validBrowserBootstrapSPIFFE(config.Controller.ControllerSubject) || !browserBootstrapIDPattern.MatchString(config.Controller.JWSKeyID) ||
		!browserBootstrapAudiencePattern.MatchString(config.ProviderInstanceAudience) || !browserBootstrapIDPattern.MatchString(config.ProviderRevisionID) ||
		!validBrowserBootstrapImage(config.RuntimeImageReference) || !isDigest(config.RuntimeImageDigest) ||
		(config.RuntimeArchitecture != "amd64" && config.RuntimeArchitecture != "arm64") || !isDigest(config.WorkspaceRevisionDigest) ||
		config.CreateFencingToken < 1 || config.CreateFencingToken > maxBrowserBootstrapSafeInteger ||
		config.OpenFencingToken <= config.CreateFencingToken || config.OpenFencingToken > maxBrowserBootstrapSafeInteger {
		return browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	identifiers := []string{
		config.TenantID, config.WorkOrderID, config.SandboxID, config.WorkspaceID, config.WorkspaceRevisionID,
		config.BranchID, config.ProviderResolutionID, config.NetworkPolicyReference, config.CreateOperationID,
		config.CreateAttemptID, config.CreateIdempotencyKey, config.OpenOperationID, config.OpenAttemptID,
		config.OpenIdempotencyKey, config.BrowserSessionID,
	}
	for _, identifier := range identifiers {
		if !browserBootstrapIDPattern.MatchString(identifier) {
			return browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
		}
	}
	unique := []string{
		config.SandboxID, config.WorkspaceID, config.WorkspaceRevisionID, config.BranchID, config.ProviderResolutionID,
		config.CreateOperationID, config.CreateAttemptID, config.CreateIdempotencyKey,
		config.OpenOperationID, config.OpenAttemptID, config.OpenIdempotencyKey, config.BrowserSessionID,
	}
	seen := make(map[string]bool, len(unique))
	for _, value := range unique {
		if seen[value] {
			return browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
		}
		seen[value] = true
	}
	if config.PollTimeoutMillis < minBrowserBootstrapPollMillis || config.PollTimeoutMillis > maxBrowserBootstrapPollMillis {
		return browserBootstrapFailure(BrowserBootstrapInvalidConfiguration)
	}
	return nil
}

func validateBrowserBootstrapURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 256 || strings.TrimSpace(raw) != raw {
		return nil, errors.New("invalid URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, errors.New("invalid URL")
	}
	if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
		return nil, errors.New("invalid URL")
	}
	portText := parsed.Port()
	if portText == "" {
		return nil, errors.New("invalid URL")
	}
	for index := 0; index < len(portText); index++ {
		if portText[index] < '0' || portText[index] > '9' {
			return nil, errors.New("invalid URL")
		}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port < 1 {
		return nil, errors.New("invalid URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("invalid URL")
		}
	}
	return parsed, nil
}

func validBrowserBootstrapSPIFFE(raw string) bool {
	if len(raw) == 0 || len(raw) > 200 {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "spiffe" && parsed.Host != "" && parsed.Path != "" && parsed.RawPath == "" &&
		parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && parsed.Opaque == ""
}

func validBrowserBootstrapImage(value string) bool {
	if len(value) == 0 || len(value) > 500 || strings.TrimSpace(value) != value {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validBrowserBootstrapOperation(operation Operation, sandboxID string, reference browserBootstrapReference, requiredStatus string) bool {
	if operation.OperationID != reference.operationID || operation.AttemptID != reference.attemptID ||
		operation.FencingToken != reference.fencingToken || operation.SandboxID != sandboxID || operation.Type != reference.operation ||
		(operation.ProviderOperationID != "" && !browserBootstrapIDPattern.MatchString(operation.ProviderOperationID)) ||
		(operation.ResultReference != "" && !browserBootstrapResultPattern.MatchString(operation.ResultReference)) ||
		!canonicalTime(operation.ObservedAt) {
		return false
	}
	if requiredStatus != "" && operation.Status != requiredStatus {
		return false
	}
	switch operation.Status {
	case "accepted", "running", "succeeded", "cancelled":
		return operation.Error == nil
	case "failed":
		return operation.Error == nil || validBrowserBootstrapOperationError(operation.Error, "known_failed")
	case "outcome_unknown":
		return operation.Error == nil || validBrowserBootstrapOperationError(operation.Error, "outcome_unknown")
	default:
		return false
	}
}

func validBrowserBootstrapMutationProgress(status string) bool {
	switch status {
	case "accepted", "running", "succeeded":
		return true
	default:
		return false
	}
}

func validBrowserBootstrapOperationError(operationError *ProviderError, outcome string) bool {
	if operationError == nil || !browserBootstrapErrorCodePattern.MatchString(operationError.Code) ||
		(operationError.ProviderCode != "" && !browserBootstrapErrorCodePattern.MatchString(operationError.ProviderCode)) ||
		utf8.RuneCountInString(operationError.Message) < 1 || utf8.RuneCountInString(operationError.Message) > 512 ||
		(operationError.Outcome != "known_failed" && operationError.Outcome != "outcome_unknown") ||
		(outcome != "" && operationError.Outcome != outcome) || len(operationError.Details) > 16 {
		return false
	}
	for _, value := range operationError.Details {
		text, ok := value.(string)
		if !ok || utf8.RuneCountInString(text) > 256 {
			return false
		}
	}
	return true
}

func validBrowserBootstrapSandboxTimes(status SandboxStatus, now time.Time) bool {
	lease, leaseOK := parseBrowserBootstrapTime(status.LeaseExpiresAt)
	created, createdOK := parseBrowserBootstrapTime(status.CreatedAt)
	updated, updatedOK := parseBrowserBootstrapTime(status.UpdatedAt)
	return leaseOK && createdOK && updatedOK && !created.After(updated) && !updated.After(now.Add(time.Minute)) && lease.After(updated) && lease.After(now)
}

func isBrowserBootstrapJSON(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func decodeBrowserBootstrapDocument(document []byte, target any) bool {
	return len(document) > 0 && len(document) <= maxBrowserBootstrapResponse && validateBootstrapUniqueJSON(document) == nil && decodeStrict(document, target) == nil
}

func decodeBrowserBootstrapOperation(document []byte, operation *Operation) bool {
	if !decodeBrowserBootstrapDocument(document, operation) {
		return false
	}
	var envelope struct {
		ProviderOperationID json.RawMessage `json:"provider_operation_id"`
		ResultReference     json.RawMessage `json:"result_reference"`
		Error               json.RawMessage `json:"error"`
	}
	if json.Unmarshal(document, &envelope) != nil {
		return false
	}
	if (len(envelope.ProviderOperationID) > 0 && !browserBootstrapIDPattern.MatchString(operation.ProviderOperationID)) ||
		(len(envelope.ResultReference) > 0 && !browserBootstrapResultPattern.MatchString(operation.ResultReference)) {
		return false
	}
	if len(envelope.Error) == 0 {
		return operation.Error == nil
	}
	if operation.Error == nil {
		return false
	}
	return validBrowserBootstrapProviderErrorDocument(envelope.Error, operation.Error, operation.Error.Outcome)
}

func decodeBrowserBootstrapSandbox(document []byte, status *SandboxStatus) bool {
	if !decodeBrowserBootstrapDocument(document, status) {
		return false
	}
	var envelope struct {
		RuntimeEndpointReference json.RawMessage `json:"runtime_endpoint_reference"`
		SnapshotReference        json.RawMessage `json:"snapshot_reference"`
		LastError                json.RawMessage `json:"last_error"`
		AgentRunID               json.RawMessage `json:"agent_run_id"`
		ProviderStateReference   json.RawMessage `json:"provider_state_reference"`
	}
	if json.Unmarshal(document, &envelope) != nil ||
		(len(envelope.RuntimeEndpointReference) > 0 && !browserBootstrapResultPattern.MatchString(status.RuntimeEndpointReference)) ||
		(len(envelope.SnapshotReference) > 0 && !browserBootstrapResultPattern.MatchString(status.SnapshotReference)) ||
		(len(envelope.AgentRunID) > 0 && !browserBootstrapIDPattern.MatchString(status.AgentRunID)) ||
		(len(envelope.ProviderStateReference) > 0 && !browserBootstrapResultPattern.MatchString(status.ProviderStateReference)) {
		return false
	}
	if len(envelope.LastError) == 0 {
		return status.LastError == nil
	}
	return status.LastError != nil && validBrowserBootstrapProviderErrorDocument(envelope.LastError, status.LastError, "")
}

func validBrowserBootstrapProviderErrorDocument(document []byte, operationError *ProviderError, outcome string) bool {
	var errorPresence struct {
		Code         string         `json:"code"`
		Message      string         `json:"message"`
		Retryable    *bool          `json:"retryable"`
		Outcome      string         `json:"outcome"`
		ProviderCode *string        `json:"provider_code,omitempty"`
		Details      map[string]any `json:"details,omitempty"`
	}
	return decodeStrict(document, &errorPresence) == nil && errorPresence.Retryable != nil &&
		(errorPresence.ProviderCode == nil || browserBootstrapErrorCodePattern.MatchString(*errorPresence.ProviderCode)) &&
		validBrowserBootstrapOperationError(operationError, outcome)
}

func validBrowserBootstrapStandardError(document []byte) bool {
	var standardError browserBootstrapStandardError
	return decodeBrowserBootstrapDocument(document, &standardError) && checkNoBackendDisclosure(document) == nil &&
		browserBootstrapErrorCodePattern.MatchString(standardError.Code) && utf8.RuneCountInString(standardError.Message) >= 1 &&
		utf8.RuneCountInString(standardError.Message) <= 512 && standardError.Retryable != nil &&
		utf8.RuneCountInString(standardError.TraceID) >= 1 && utf8.RuneCountInString(standardError.TraceID) <= 200
}

func parseBrowserBootstrapTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func canonicalTime(value string) bool {
	_, ok := parseBrowserBootstrapTime(value)
	return ok
}

func canonicalFutureTime(value string, now time.Time) bool {
	parsed, ok := parseBrowserBootstrapTime(value)
	return ok && parsed.After(now)
}

func browserBootstrapFailure(code string) error {
	return &BrowserBootstrapError{Code: code}
}

func browserBootstrapContextFailure(parent, operation context.Context) error {
	if parent != nil {
		switch parent.Err() {
		case context.Canceled:
			return browserBootstrapFailure(BrowserBootstrapCanceled)
		case context.DeadlineExceeded:
			return browserBootstrapFailure(BrowserBootstrapTimedOut)
		}
	}
	if operation != nil {
		switch operation.Err() {
		case context.Canceled:
			return browserBootstrapFailure(BrowserBootstrapCanceled)
		case context.DeadlineExceeded:
			return browserBootstrapFailure(BrowserBootstrapTimedOut)
		}
	}
	return browserBootstrapFailure(BrowserBootstrapTransportFailed)
}

func waitBrowserBootstrapPoll(ctx context.Context) error {
	timer := time.NewTimer(browserBootstrapPollInterval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validateBootstrapUniqueJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := validateBootstrapUniqueValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON input")
	}
	return nil
}

func validateBootstrapUniqueValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("JSON null is not allowed")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] {
				return errors.New("invalid JSON object")
			}
			seen[key] = true
			if err := validateBootstrapUniqueValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("incomplete JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateBootstrapUniqueValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("incomplete JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
