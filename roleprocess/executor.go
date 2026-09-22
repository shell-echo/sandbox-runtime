package roleprocess

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/rolematerials"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/sessiontermination"
	"github.com/shell-echo/sandbox-runtime/internal/tlsmaterial"
)

const (
	executorAuthorityVersion = 1
	maxExecutorAuthoritySize = 64 << 10
	maxExecutorSessions      = 256
)

type ExecutorCredentialAuthority struct {
	Version        int    `json:"version"`
	Role           string `json:"role"`
	ExecutorID     string `json:"executor_id"`
	ProviderOrigin string `json:"provider_origin"`
}

type ExecutorDependencyAuthority struct {
	Version    int    `json:"version"`
	Role       string `json:"role"`
	BackendURL string `json:"backend_url"`
}

type ExecutorPolicyAuthority struct {
	Version                int    `json:"version"`
	Role                   string `json:"role"`
	OperationTimeoutMillis int    `json:"operation_timeout_millis"`
	MaxSessions            int    `json:"max_sessions"`
}

type ExecutorAuthority struct {
	Credential ExecutorCredentialAuthority
	Dependency ExecutorDependencyAuthority
	Policy     ExecutorPolicyAuthority
	Backend    ExecutorBackend
	TLS        *tls.Config
	Registry   *secretref.Registry
}

func LoadExecutorAuthority(ctx context.Context, cfg *config.DataPlaneProcessConfig) (ExecutorAuthority, error) {
	if ctx == nil || cfg == nil || !cfg.Enabled || (cfg.Role != config.DataPlaneBrowser && cfg.Role != config.DataPlaneDesktop) {
		return ExecutorAuthority{}, errors.New("enabled Browser or Desktop executor configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return ExecutorAuthority{}, err
	}
	var credential ExecutorCredentialAuthority
	var dependency ExecutorDependencyAuthority
	var policy ExecutorPolicyAuthority
	if err := readExecutorAuthority(cfg.Authority.CredentialFile, &credential); err != nil {
		return ExecutorAuthority{}, fmt.Errorf("load executor credential authority: %w", err)
	}
	if err := readExecutorAuthority(cfg.Authority.DependencyFile, &dependency); err != nil {
		return ExecutorAuthority{}, fmt.Errorf("load executor dependency authority: %w", err)
	}
	if err := readExecutorAuthority(cfg.Authority.PolicyFile, &policy); err != nil {
		return ExecutorAuthority{}, fmt.Errorf("load executor policy authority: %w", err)
	}
	role := string(cfg.Role)
	if credential.Version != executorAuthorityVersion || credential.Role != role || !validExecutorID(credential.ExecutorID) || !validPrivateOrigin(credential.ProviderOrigin) {
		return ExecutorAuthority{}, errors.New("invalid executor credential authority")
	}
	if dependency.Version != executorAuthorityVersion || dependency.Role != role || !validBackendURL(dependency.BackendURL) {
		return ExecutorAuthority{}, errors.New("invalid executor dependency authority")
	}
	if policy.Version != executorAuthorityVersion || policy.Role != role || policy.OperationTimeoutMillis < 100 || policy.OperationTimeoutMillis > 30_000 || policy.MaxSessions < 1 || policy.MaxSessions > maxExecutorSessions {
		return ExecutorAuthority{}, errors.New("invalid executor policy authority")
	}
	var backend ExecutorBackend
	var transportTLS *tls.Config
	var registry *secretref.Registry
	var err error
	timeout := time.Duration(policy.OperationTimeoutMillis) * time.Millisecond
	if cfg.SchemaVersion == config.DataPlaneProductionSchemaV2 {
		role := secretref.RoleBrowser
		if cfg.Role == config.DataPlaneDesktop {
			role = secretref.RoleDesktop
		}
		registry, err = rolematerials.New(cfg.Materials, role, []secretref.Purpose{secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey, secretref.PurposeCABundle}, true, time.Now)
		if err != nil {
			return ExecutorAuthority{}, errors.New("construct executor material registry")
		}
		closeRegistry := true
		defer func() {
			if closeRegistry {
				registry.Close()
			}
		}()
		if bindings, decodeErr := cfg.Materials.DecodeBindings(role); decodeErr != nil || len(bindings) != 5 {
			return ExecutorAuthority{}, errors.New("executor material registry must contain exactly five bindings")
		}
		transportTLS, err = tlsmaterial.ResolveMutualServer(ctx, registry,
			cfg.TLS.CertificateBindingID, cfg.TLS.PrivateKeyBindingID, cfg.TLS.ClientCABundleBindingID,
			cfg.TLS.ExpectedServerName, cfg.TLS.AllowedClientIdentity, time.Now)
		if err != nil {
			return ExecutorAuthority{}, errors.New("load executor server TLS material")
		}
		parsed, _ := url.Parse(dependency.BackendURL)
		clientTLS, tlsErr := tlsmaterial.ResolveClient(ctx, registry,
			cfg.TLS.ClientCABundleBindingID, cfg.TLS.ClientCertificateBindingID, cfg.TLS.ClientPrivateKeyBindingID,
			parsed.Hostname(), time.Now)
		if tlsErr != nil {
			return ExecutorAuthority{}, errors.New("load executor backend TLS material")
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}, Timeout: timeout}
		if cfg.Role == config.DataPlaneBrowser {
			backend, err = newCDPBackendWithClient(dependency.BackendURL, timeout, client)
		} else {
			backend, err = newWebsocketBackendWithClient(dependency.BackendURL, timeout, client)
		}
		closeRegistry = false
	} else if cfg.Role == config.DataPlaneBrowser {
		backend, err = newCDPBackend(cfg, dependency.BackendURL, timeout)
	} else {
		backend, err = newWebsocketBackend(cfg, dependency.BackendURL, timeout)
	}
	if err != nil {
		return ExecutorAuthority{}, err
	}
	return ExecutorAuthority{Credential: credential, Dependency: dependency, Policy: policy, Backend: backend, TLS: transportTLS, Registry: registry}, nil
}

func NewExecutorApplicationGraph(ctx context.Context, cfg *config.DataPlaneProcessConfig) (ApplicationGraph, error) {
	if ctx == nil {
		return ApplicationGraph{}, errors.New("executor construction context is required")
	}
	authority, err := LoadExecutorAuthority(ctx, cfg)
	if err != nil {
		return ApplicationGraph{}, err
	}
	handler, err := NewExecutorHandler(ExecutorHandlerOptions{Role: string(cfg.Role), Backend: authority.Backend, OperationTimeout: time.Duration(authority.Policy.OperationTimeoutMillis) * time.Millisecond, MaxSessions: authority.Policy.MaxSessions})
	if err != nil {
		return ApplicationGraph{}, err
	}
	return ApplicationGraph{
		Private: handler,
		TLS:     authority.TLS,
		Ready: func(checkContext context.Context) error {
			if authority.Registry != nil {
				if err := verifyExecutorMaterials(checkContext, authority.Registry, cfg.TLS); err != nil {
					return err
				}
			}
			return authority.Backend.Ready(checkContext)
		},
		Shutdown: func(context.Context) error {
			if authority.Registry != nil {
				authority.Registry.Close()
			}
			return nil
		},
	}, nil
}

func verifyExecutorMaterials(ctx context.Context, registry *secretref.Registry, tlsConfig config.DataPlaneTLSConfig) error {
	checks := []struct {
		id      string
		purpose secretref.Purpose
	}{
		{tlsConfig.CertificateBindingID, secretref.PurposeTLSCertificate},
		{tlsConfig.PrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
		{tlsConfig.ClientCABundleBindingID, secretref.PurposeCABundle},
		{tlsConfig.ClientCertificateBindingID, secretref.PurposeTLSCertificate},
		{tlsConfig.ClientPrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
	}
	for _, check := range checks {
		material, err := registry.Resolve(ctx, check.id, check.purpose, secretref.SystemTenant)
		material.Destroy()
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return errors.New("executor material dependency is unavailable")
		}
	}
	return nil
}

type ExecutorSession interface {
	Read(context.Context) (websocket.MessageType, []byte, error)
	Write(context.Context, websocket.MessageType, []byte) error
	Close() error
}

type ExecutorBackend interface {
	Ready(context.Context) error
	Open(context.Context, executorprotocol.Open) (ExecutorSession, error)
}

type ExecutorHandlerOptions struct {
	Role             string
	Backend          ExecutorBackend
	OperationTimeout time.Duration
	MaxSessions      int
}

type ExecutorHandler struct {
	role        string
	backend     ExecutorBackend
	operation   time.Duration
	maxSessions int
	mu          sync.Mutex
	active      int
	replayMu    sync.Mutex
	replayed    map[string]time.Time
}

func NewExecutorHandler(options ExecutorHandlerOptions) (*ExecutorHandler, error) {
	if options.Role != executorprotocol.RoleBrowser && options.Role != executorprotocol.RoleDesktop || options.Backend == nil || options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > 30*time.Second || options.MaxSessions < 1 || options.MaxSessions > maxExecutorSessions {
		return nil, errors.New("invalid executor handler options")
	}
	return &ExecutorHandler{role: options.Role, backend: options.Backend, operation: options.OperationTimeout, maxSessions: options.MaxSessions, replayed: make(map[string]time.Time)}, nil
}

func (h *ExecutorHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet || request.TLS == nil || request.Header.Get("Sec-WebSocket-Protocol") != executorprotocol.ProtocolID {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{executorprotocol.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(executorprotocol.MaxDocumentBytes)
	kind, document, err := connection.Read(request.Context())
	if err != nil || kind != websocket.MessageText {
		return
	}
	var open executorprotocol.Open
	now := time.Now().UTC()
	if executorprotocol.Decode(document, &open) != nil || open.Role != h.role || open.Validate(now) != nil || !h.claim(open.RequestID, now, openExpiry(open)) || !h.acquire() {
		response, _ := executorprotocol.Encode(executorprotocol.Rejected(open.RequestID, "unavailable"))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
		return
	}
	defer h.release()
	connection.SetReadLimit(executorprotocol.MaxMessageBytes)
	operationContext, cancel := context.WithTimeout(request.Context(), h.operation)
	session, err := h.backend.Open(operationContext, open)
	cancel()
	if err != nil || session == nil {
		response, _ := executorprotocol.Encode(executorprotocol.Rejected(open.RequestID, "unavailable"))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
		return
	}
	defer session.Close()
	response, _ := executorprotocol.Encode(executorprotocol.Accepted(open.RequestID))
	if err := connection.Write(request.Context(), websocket.MessageText, response); err != nil {
		return
	}
	ctx, cancelBridge := context.WithDeadline(request.Context(), openExpiry(open))
	defer cancelBridge()
	var termination sessiontermination.First
	results := make(chan struct{}, 2)
	go func() {
		err := copyExecutorToBackend(ctx, connection, session)
		record := sessiontermination.FromError(err, sessiontermination.StageInputWriter, sessiontermination.CauseTransportClosed)
		termination.Observe(record.Stage, record.Cause)
		results <- struct{}{}
	}()
	go func() {
		err := copyBackendToExecutor(ctx, session, connection)
		record := sessiontermination.FromError(err, sessiontermination.StageExecutorTransport, sessiontermination.CauseTransportClosed)
		termination.Observe(record.Stage, record.Cause)
		results <- struct{}{}
	}()
	<-results
	cancelBridge()
	_ = session.Close()
	<-results
	if record, ok := termination.Load(); ok {
		log.Printf("%s_role_session_terminal %s", h.role, record.String())
	}
}

func (h *ExecutorHandler) claim(requestID string, now, expires time.Time) bool {
	if requestID == "" || expires.IsZero() || !expires.After(now) {
		return false
	}
	h.replayMu.Lock()
	defer h.replayMu.Unlock()
	for id, until := range h.replayed {
		if !until.After(now) {
			delete(h.replayed, id)
		}
	}
	if _, exists := h.replayed[requestID]; exists {
		return false
	}
	h.replayed[requestID] = expires
	return true
}

func (h *ExecutorHandler) acquire() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active >= h.maxSessions {
		return false
	}
	h.active++
	return true
}

func (h *ExecutorHandler) release() { h.mu.Lock(); h.active--; h.mu.Unlock() }

func copyExecutorToBackend(ctx context.Context, source *websocket.Conn, target ExecutorSession) error {
	for {
		kind, payload, err := source.Read(ctx)
		if err != nil {
			return err
		}
		if len(payload) == 0 || len(payload) > executorprotocol.MaxMessageBytes {
			return sessiontermination.Error{Record: sessiontermination.Record{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseProtocolViolation}}
		}
		if err := target.Write(ctx, kind, payload); err != nil {
			return err
		}
	}
}

func copyBackendToExecutor(ctx context.Context, source ExecutorSession, target *websocket.Conn) error {
	for {
		kind, payload, err := source.Read(ctx)
		if err != nil {
			return err
		}
		if len(payload) == 0 || len(payload) > executorprotocol.MaxMessageBytes {
			return sessiontermination.Error{Record: sessiontermination.Record{Stage: sessiontermination.StageExecutorTransport, Cause: sessiontermination.CauseProtocolViolation}}
		}
		if err := target.Write(ctx, kind, payload); err != nil {
			return err
		}
	}
}

type websocketBackend struct {
	url      string
	readyURL string
	client   *http.Client
	timeout  time.Duration
}

func newWebsocketBackend(cfg *config.DataPlaneProcessConfig, endpoint string, timeout time.Duration) (*websocketBackend, error) {
	if cfg == nil || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, errors.New("invalid executor backend")
	}
	client, err := executorHTTPClient(cfg, endpoint)
	if err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(endpoint)
	parsed.Scheme = "https"
	parsed.Path = "/readyz"
	parsed.RawPath = ""
	return &websocketBackend{url: endpoint, readyURL: parsed.String(), client: client, timeout: timeout}, nil
}

func newWebsocketBackendWithClient(endpoint string, timeout time.Duration, client *http.Client) (*websocketBackend, error) {
	if !validBackendURL(endpoint) || timeout < 100*time.Millisecond || timeout > 30*time.Second || client == nil {
		return nil, errors.New("invalid executor backend")
	}
	parsed, _ := url.Parse(endpoint)
	parsed.Scheme = "https"
	parsed.Path = "/readyz"
	parsed.RawPath = ""
	return &websocketBackend{url: endpoint, readyURL: parsed.String(), client: client, timeout: timeout}, nil
}

func (b *websocketBackend) Ready(ctx context.Context) error {
	if b == nil || b.client == nil || ctx == nil {
		return errors.New("executor backend is unavailable")
	}
	probeContext, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, b.readyURL, nil)
	if err != nil {
		return errors.New("executor backend is unavailable")
	}
	response, err := b.client.Do(request)
	if err != nil {
		return errors.New("executor backend is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("executor backend is unavailable")
	}
	return nil
}

func (b *websocketBackend) Open(ctx context.Context, open executorprotocol.Open) (ExecutorSession, error) {
	if b == nil || b.client == nil || ctx == nil {
		return nil, errors.New("executor backend is unavailable")
	}
	if err := open.Validate(time.Now().UTC()); err != nil {
		return nil, err
	}
	connection, _, err := websocket.Dial(ctx, b.url, &websocket.DialOptions{HTTPClient: b.client, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		return nil, errors.New("executor backend is unavailable")
	}
	document, _ := executorprotocol.Encode(open)
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		_ = connection.Close(websocket.StatusInternalError, "write")
		return nil, errors.New("executor backend is unavailable")
	}
	kind, responseDocument, err := connection.Read(ctx)
	if err != nil || kind != websocket.MessageText {
		_ = connection.Close(websocket.StatusInternalError, "handshake")
		return nil, errors.New("executor backend is unavailable")
	}
	var response executorprotocol.Response
	if executorprotocol.Decode(responseDocument, &response) != nil || response.Validate() != nil || response.RequestID != open.RequestID || response.Status != executorprotocol.StatusAccepted {
		_ = connection.Close(websocket.StatusPolicyViolation, "rejected")
		return nil, errors.New("executor backend rejected authority")
	}
	return websocketSession{connection: connection}, nil
}

type websocketSession struct{ connection *websocket.Conn }

func (s websocketSession) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	return s.connection.Read(ctx)
}
func (s websocketSession) Write(ctx context.Context, kind websocket.MessageType, payload []byte) error {
	return s.connection.Write(ctx, kind, payload)
}
func (s websocketSession) Close() error {
	if s.connection == nil {
		return nil
	}
	s.connection.CloseNow()
	return nil
}

func openExpiry(open executorprotocol.Open) time.Time {
	expires, _ := time.Parse(time.RFC3339Nano, open.HandoffExpiresAt)
	return expires
}

func readExecutorAuthority(path string, value any) error {
	document, err := secretfile.Read(path, maxExecutorAuthoritySize)
	if err != nil {
		return err
	}
	defer clear(document)
	if err := executorprotocol.Decode(document, value); err != nil {
		return errors.New("authority document is invalid")
	}
	return nil
}

func executorHTTPClient(cfg *config.DataPlaneProcessConfig, endpoint string) (*http.Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("executor backend URL is invalid")
	}
	caDocument, err := secretfile.Read(cfg.TLS.ClientCABundleFile, 256<<10)
	if err != nil {
		return nil, errors.New("load executor backend trust bundle")
	}
	defer clear(caDocument)
	pool := x509.NewCertPool()
	remaining := bytes.TrimSpace(caDocument)
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid executor backend trust bundle")
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("invalid executor backend CA certificate")
		}
		pool.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, errors.New("executor backend trust bundle is empty")
	}
	certificatePEM, err := secretfile.Read(cfg.TLS.ClientCertificateFile, 64<<10)
	if err != nil {
		return nil, errors.New("load executor backend client certificate")
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := secretfile.Read(cfg.TLS.ClientPrivateKeyFile, 64<<10)
	if err != nil {
		return nil, errors.New("load executor backend client key")
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, errors.New("load executor backend client identity")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}, ServerName: parsed.Hostname()}}}, nil
}

func validPrivateOrigin(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "spiffe" && parsed.Host != "" && parsed.Path != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validBackendURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "wss" && parsed.Host != "" && parsed.Path != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validExecutorID(value string) bool {
	return value != "" && len(value) <= 200 && !strings.ContainsAny(value, " \t\r\n\x00")
}
