//go:build phase4browsergate

package productphase4gate

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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
)

const (
	phase4NodeRole = "PRODUCT_PHASE4_NODE_ROLE"
	phase4NodeFile = "PRODUCT_PHASE4_NODE_CONFIG"
	phase4Ticket   = "phase4-automation-ticket-000000000000000000001"
)

type nodeConfig struct {
	ProviderAddress string    `json:"provider_address"`
	ProviderAPI     string    `json:"provider_api_address,omitempty"`
	GatewayAddress  string    `json:"gateway_address"`
	EdgeAddress     string    `json:"edge_address"`
	ProductAddress  string    `json:"product_address,omitempty"`
	DSN             string    `json:"dsn,omitempty"`
	RedisAddress    string    `json:"redis_address,omitempty"`
	ProviderSigning string    `json:"provider_signing_key,omitempty"`
	GrantKey        string    `json:"grant_key,omitempty"`
	RecordingKey    string    `json:"recording_key,omitempty"`
	RecordingRoot   string    `json:"recording_root,omitempty"`
	GateKey         string    `json:"gate_key,omitempty"`
	CACertificate   string    `json:"ca_certificate"`
	ProviderCert    string    `json:"provider_certificate"`
	ProviderKey     string    `json:"provider_key"`
	GatewayCert     string    `json:"gateway_certificate"`
	GatewayKey      string    `json:"gateway_key"`
	EdgeCert        string    `json:"edge_certificate"`
	EdgeKey         string    `json:"edge_key"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type childNode struct {
	role    string
	cmd     *exec.Cmd
	log     bytes.Buffer
	done    chan struct{}
	waitMu  sync.Mutex
	waitErr error
}

func TestPhase4AutomationNode(t *testing.T) {
	role := os.Getenv(phase4NodeRole)
	if role == "" {
		t.Skip("separate-process node helper")
	}
	document, err := os.ReadFile(os.Getenv(phase4NodeFile))
	if err != nil {
		t.Fatal(err)
	}
	var config nodeConfig
	if err := json.Unmarshal(document, &config); err != nil {
		t.Fatal(err)
	}
	switch role {
	case "provider":
		err = runProviderNode(config)
	case "gateway":
		err = runGatewayNode(config)
	case "edge":
		err = runEdgeNode(config)
	case "release-provider":
		err = runReleaseProviderNode(config)
	case "release-product":
		err = runReleaseProductNode(config)
	case "release-gateway":
		err = runReleaseGatewayNode(config)
	case "release-browser":
		err = runReleaseBrowserNode(config)
	default:
		err = fmt.Errorf("unknown phase 4 node role %q", role)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestPhase4BrowserAutomationSeparateProcessGate(t *testing.T) {
	if os.Getenv(phase4NodeRole) != "" {
		t.Skip("parent-only gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	directory := t.TempDir()
	config := nodeConfig{
		ProviderAddress: freeAddress(t), GatewayAddress: freeAddress(t), EdgeAddress: freeAddress(t),
		ExpiresAt: time.Now().UTC().Add(2 * time.Minute),
	}
	writeNodeCertificates(t, directory, &config)
	configPath := filepath.Join(directory, "nodes.json")
	document, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, document, 0o600); err != nil {
		t.Fatal(err)
	}

	nodes := make([]*childNode, 0, 3)
	defer func() {
		for index := len(nodes) - 1; index >= 0; index-- {
			stopNode(nodes[index])
		}
	}()
	provider := startNode(t, "provider", configPath)
	nodes = append(nodes, provider)
	providerClient := mutualTLSClient(t, config.CACertificate, config.GatewayCert, config.GatewayKey, "phase4-provider")
	waitHTTP(t, ctx, providerClient, "https://"+config.ProviderAddress+"/healthz", http.StatusOK, provider)
	gatewayNode := startNode(t, "gateway", configPath)
	nodes = append(nodes, gatewayNode)
	waitHTTP(t, ctx, http.DefaultClient, "http://"+config.GatewayAddress+"/healthz", http.StatusOK, gatewayNode)
	edgeNode := startNode(t, "edge", configPath)
	nodes = append(nodes, edgeNode)
	edgeClient := tlsClient(t, config.CACertificate, "phase4-edge")
	waitHTTP(t, ctx, edgeClient, "https://"+config.EdgeAddress+"/healthz", http.StatusOK, edgeNode)

	connection, response, err := websocket.Dial(ctx, "wss://"+config.EdgeAddress+"/browser/automation", &websocket.DialOptions{
		HTTPClient: edgeClient, HTTPHeader: http.Header{"Authorization": []string{"Ticket " + phase4Ticket}},
		Subprotocols: []string{productgateway.BrowserAutomationSubprotocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		t.Fatalf("public WSS dial err=%v response=%v", err, response)
	}
	defer connection.CloseNow()
	waitHTTP(t, ctx, http.DefaultClient, "http://"+config.GatewayAddress+"/reconnectz", http.StatusOK, gatewayNode)
	action := `{"type":"action","action_id":"gate-action","sequence":1,"name":"page.info","parameters":{}}`
	if err := connection.Write(ctx, websocket.MessageText, []byte(action)); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText || !strings.Contains(string(payload), `"action_id":"gate-action"`) ||
		!strings.Contains(string(payload), `"title":"phase4"`) || strings.Contains(string(payload), "Runtime.evaluate") ||
		strings.Contains(string(payload), "ref:browser-session:") {
		t.Fatalf("closed result type=%v payload=%s err=%v", messageType, payload, err)
	}
	_ = connection.Close(websocket.StatusNormalClosure, "")
	_, replayResponse, replayErr := websocket.Dial(ctx, "wss://"+config.EdgeAddress+"/browser/automation", &websocket.DialOptions{
		HTTPClient: edgeClient, HTTPHeader: http.Header{"Authorization": []string{"Ticket " + phase4Ticket}},
		Subprotocols: []string{productgateway.BrowserAutomationSubprotocol},
	})
	if replayErr == nil || replayResponse == nil || replayResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ticket replay response=%v err=%v", replayResponse, replayErr)
	}
}

func runProviderNode(config nodeConfig) error {
	authority := &nodeFenceAuthority{}
	ingress, err := cdpfence.New(cdpfence.Options{Authority: authority, ActionTimeout: 2 * time.Second, CloseTimeout: 2 * time.Second})
	if err != nil {
		return err
	}
	resolver := &nodeProviderResolver{expiresAt: config.ExpiresAt}
	handler, err := cdpfence.NewNetworkHandler(cdpfence.NetworkOptions{
		Ingress: ingress, Resolver: resolver,
		PeerAuthorizer: cdpfence.PeerAuthorizerFunc(func(_ context.Context, state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != "phase4-gateway" {
				return gateway.ErrDownstreamUnavailable
			}
			return nil
		}),
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/private/browser", handler)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	tlsConfig, err := serverTLSConfig(config.ProviderCert, config.ProviderKey, config.CACertificate, true)
	if err != nil {
		return err
	}
	return serveUntilSignal(config.ProviderAddress, mux, tlsConfig)
}

func runGatewayNode(config nodeConfig) error {
	client := mutualTLSClientFromConfig(config.CACertificate, config.GatewayCert, config.GatewayKey, "phase4-provider")
	privateResolver, err := productgateway.NewPrivateBrowserResolver(productgateway.PrivateBrowserResolverOptions{
		Origin: "wss://" + config.ProviderAddress + "/private/browser", HTTPClient: client,
	})
	if err != nil {
		return err
	}
	counting := &countingFencedResolver{next: privateResolver}
	store := &nodeGrantStore{ticket: phase4Ticket, binding: nodeBinding(config.ExpiresAt)}
	fence, err := gateway.NewDownstreamFence("v1." + strings.Repeat("g", 32))
	if err != nil {
		return err
	}
	handler, err := productgateway.NewBrowserAutomationHandler(productgateway.BrowserAutomationOptions{
		Grants: store, FencedResolver: counting, Audit: nodeAudit{}, Capacity: nodeCapacity{fence: fence},
		AuthorityPollInterval: 20 * time.Millisecond, MaxReconnects: 2, ReconnectBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/browser/automation", handler)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/reconnectz", func(writer http.ResponseWriter, _ *http.Request) {
		if counting.calls.Load() < 2 {
			http.Error(writer, "not ready", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	return serveUntilSignal(config.GatewayAddress, mux, nil)
}

func runEdgeNode(config nodeConfig) error {
	target, _ := url.Parse("http://" + config.GatewayAddress)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(writer, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
	mux := http.NewServeMux()
	mux.Handle("/browser/automation", proxy)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	tlsConfig, err := serverTLSConfig(config.EdgeCert, config.EdgeKey, "", false)
	if err != nil {
		return err
	}
	return serveUntilSignal(config.EdgeAddress, mux, tlsConfig)
}

type nodeGrantStore struct {
	mu       sync.Mutex
	ticket   string
	binding  product.GatewayBinding
	consumed bool
	active   bool
}

func (s *nodeGrantStore) MintConnectionGrant(context.Context, product.ConnectionGrantCommand) (product.ConnectionGrant, bool, error) {
	return product.ConnectionGrant{}, false, product.ErrStoreUnavailable
}
func (s *nodeGrantStore) ConsumeConnectionGrant(_ context.Context, ticket string) (product.GatewayBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ticket != s.ticket || s.consumed {
		return product.GatewayBinding{}, product.ErrNotFound
	}
	s.consumed, s.active = true, true
	return s.binding, nil
}
func (s *nodeGrantStore) CheckGatewayAuthority(context.Context, product.GatewayBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return product.ErrControlStale
	}
	return nil
}

func nodeBinding(expiresAt time.Time) product.GatewayBinding {
	return product.GatewayBinding{
		ConnectionID: "con-phase4", TenantID: "tenant-phase4", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-phase4"},
		WorkspaceID: "wrk-phase4", SlotKey: "browser-main", SlotGeneration: 1,
		SessionID: "ses-phase4", ProtocolProfile: productgateway.BrowserAutomationSubprotocol,
		ControlLeaseID: "ctl-phase4", ControlFence: 1, AccessMode: product.GrantAccessControl,
		ExpiresAt: expiresAt.Add(-time.Minute), ProviderRevisionID: strings.Repeat("a", 40), SandboxID: "sandbox-phase4",
		HandoffReference: "ref:browser-session:phase4-gate", ConnectionGeneration: 1, HandoffExpiresAt: expiresAt,
	}
}

type nodeCapacity struct{ fence gateway.DownstreamFence }

func (c nodeCapacity) Acquire(context.Context, gateway.CapacitySubject) (gateway.ConnectionLease, error) {
	return &nodeLease{fence: c.fence, events: make(chan gateway.CapacityEvent)}, nil
}

type nodeLease struct {
	fence  gateway.DownstreamFence
	events chan gateway.CapacityEvent
	once   sync.Once
}

func (l *nodeLease) Events() <-chan gateway.CapacityEvent              { return l.events }
func (l *nodeLease) DownstreamFence() (gateway.DownstreamFence, error) { return l.fence, nil }
func (l *nodeLease) Release(context.Context) error {
	l.once.Do(func() { close(l.events) })
	return nil
}

type nodeAudit struct{}

func (nodeAudit) RecordGatewayEvent(context.Context, product.GatewayBinding, gateway.AuditEvent) error {
	return nil
}

type countingFencedResolver struct {
	next  gateway.FencedReferenceResolver
	calls atomic.Int64
}

func (r *countingFencedResolver) ResolveFenced(ctx context.Context, reference string, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence) (gateway.Endpoint, error) {
	r.calls.Add(1)
	return r.next.ResolveFenced(ctx, reference, subject, fence)
}

type nodeFenceAuthority struct {
	mu      sync.Mutex
	current string
}

func (a *nodeFenceAuthority) AuthorizeAction(_ context.Context, _ gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current == "" {
		a.current = fence.Opaque()
		return gateway.DownstreamFenceDecision{Activated: true}, nil
	}
	if a.current != fence.Opaque() {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamFenceLost
	}
	return gateway.DownstreamFenceDecision{}, nil
}

type nodeProviderResolver struct {
	expiresAt time.Time
	calls     atomic.Int64
}

func (r *nodeProviderResolver) Resolve(_ context.Context, reference string) (gateway.Endpoint, error) {
	if reference != "ref:browser-session:phase4-gate" {
		return gateway.Endpoint{}, gateway.ErrReferenceUnavailable
	}
	call := r.calls.Add(1)
	return gateway.Endpoint{
		Reference: reference, SandboxID: "sandbox-phase4", BrowserSessionID: "ses-phase4",
		CapabilityProfileID: productgateway.BrowserAutomationSubprotocol, ConnectionGeneration: 1, ExpiresAt: r.expiresAt,
		Dial: func(context.Context) (gateway.Stream, error) {
			stream := newNodeBrowserStream()
			if call == 1 {
				stream.close()
			}
			return stream, nil
		},
	}, nil
}

type nodeBrowserStream struct {
	frames chan gateway.Frame
	done   chan struct{}
	once   sync.Once
}

func newNodeBrowserStream() *nodeBrowserStream {
	return &nodeBrowserStream{frames: make(chan gateway.Frame, 1), done: make(chan struct{})}
}
func (s *nodeBrowserStream) Receive(ctx context.Context) (gateway.Frame, error) {
	select {
	case frame := <-s.frames:
		return frame, nil
	case <-s.done:
		return gateway.Frame{}, io.EOF
	case <-ctx.Done():
		return gateway.Frame{}, ctx.Err()
	}
}
func (s *nodeBrowserStream) Send(ctx context.Context, frame gateway.Frame) error {
	var request struct {
		ID int64 `json:"id"`
	}
	if frame.Type != gateway.TextFrame || json.Unmarshal(frame.Payload, &request) != nil || request.ID < 1 {
		return gateway.ErrDownstreamUnavailable
	}
	response, _ := json.Marshal(map[string]any{"id": request.ID, "result": map[string]any{"result": map[string]any{"type": "object", "value": map[string]any{"title": "phase4", "url": "https://example.test/"}}}})
	select {
	case s.frames <- gateway.Frame{Type: gateway.TextFrame, Payload: response}:
		return nil
	case <-s.done:
		return io.ErrClosedPipe
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *nodeBrowserStream) Close(context.Context) error { s.close(); return nil }
func (s *nodeBrowserStream) close()                      { s.once.Do(func() { close(s.done) }) }

func serveUntilSignal(address string, handler http.Handler, tlsConfig *tls.Config) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func startNode(t *testing.T, role, configPath string) *childNode {
	t.Helper()
	node := &childNode{role: role, done: make(chan struct{})}
	node.cmd = exec.Command(os.Args[0], "-test.run=^TestPhase4AutomationNode$")
	node.cmd.Env = append(os.Environ(), phase4NodeRole+"="+role, phase4NodeFile+"="+configPath)
	node.cmd.Stdout, node.cmd.Stderr = &node.log, &node.log
	if err := node.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := node.cmd.Wait()
		node.waitMu.Lock()
		node.waitErr = err
		node.waitMu.Unlock()
		close(node.done)
	}()
	return node
}

func stopNode(node *childNode) {
	if node == nil || node.cmd == nil || node.cmd.Process == nil {
		return
	}
	select {
	case <-node.done:
		return
	default:
	}
	_ = node.cmd.Process.Signal(os.Interrupt)
	select {
	case <-node.done:
	case <-time.After(3 * time.Second):
		_ = node.cmd.Process.Kill()
		<-node.done
	}
}

func waitHTTP(t *testing.T, ctx context.Context, client *http.Client, target string, status int, node *childNode) {
	t.Helper()
	for {
		if node != nil && node.done != nil {
			select {
			case <-node.done:
				node.waitMu.Lock()
				err := node.waitErr
				node.waitMu.Unlock()
				t.Fatalf("%s exited before %s became healthy: %v; log=%s", node.role, target, err, node.log.String())
			default:
			}
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == status {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait %s for %s: %v; log=%s", target, node.role, ctx.Err(), node.log.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func writeNodeCertificates(t *testing.T, directory string, config *nodeConfig) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "phase4-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	config.CACertificate = filepath.Join(directory, "ca.pem")
	writePEM(t, config.CACertificate, "CERTIFICATE", caDER)
	config.ProviderCert, config.ProviderKey = issueCertificate(t, directory, "provider", "phase4-provider", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ca, private, now, 2)
	config.GatewayCert, config.GatewayKey = issueCertificate(t, directory, "gateway", "phase4-gateway", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ca, private, now, 3)
	config.EdgeCert, config.EdgeKey = issueCertificate(t, directory, "edge", "phase4-edge", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ca, private, now, 4)
}

func issueCertificate(t *testing.T, directory, name, commonName string, usages []x509.ExtKeyUsage, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time, serial int64) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{commonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, name+".pem")
	keyPath := filepath.Join(directory, name+"-key.pem")
	writePEM(t, certificatePath, "CERTIFICATE", der)
	encodedKey, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", encodedKey)
	return certificatePath, keyPath
}

func writePEM(t *testing.T, path, kind string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: value}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func serverTLSConfig(certificatePath, keyPath, caPath string, requireClient bool) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, err
	}
	configuration := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	if requireClient {
		caDocument, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caDocument) {
			return nil, errors.New("invalid client CA")
		}
		configuration.ClientAuth, configuration.ClientCAs = tls.RequireAndVerifyClientCert, pool
	}
	return configuration, nil
}

func mutualTLSClient(t *testing.T, caPath, certificatePath, keyPath, serverName string) *http.Client {
	t.Helper()
	client := mutualTLSClientFromConfig(caPath, certificatePath, keyPath, serverName)
	if client == nil {
		t.Fatal("create mutual TLS client")
	}
	return client
}

func mutualTLSClientFromConfig(caPath, certificatePath, keyPath, serverName string) *http.Client {
	document, err := os.ReadFile(caPath)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(document) {
		return nil
	}
	pair, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}, ServerName: serverName}}}
}

func tlsClient(t *testing.T, caPath, serverName string) *http.Client {
	t.Helper()
	document, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(document) {
		t.Fatal("append CA")
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName}}}
}

var _ product.ConnectionGrantStore = (*nodeGrantStore)(nil)
var _ productgateway.AuditStore = nodeAudit{}
var _ gateway.ConnectionCapacity = nodeCapacity{}
var _ gateway.FencedConnectionLease = (*nodeLease)(nil)
var _ gateway.FencedReferenceResolver = (*countingFencedResolver)(nil)
var _ gateway.DownstreamFenceAuthority = (*nodeFenceAuthority)(nil)
var _ gateway.ReferenceResolver = (*nodeProviderResolver)(nil)
var _ gateway.Stream = (*nodeBrowserStream)(nil)
