// Package executorbackend implements the operator-owned Browser executor
// backend. It terminates private mTLS, validates the opaque authority, and
// relays frames to an already-running CDP endpoint. Its production path does
// not access Provider state or Docker; the historical static TLS component
// helper still imports the Provider transport loader.
package executorbackend

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
)

const (
	maxSessions     = 256
	maxReplayClaims = 4096
)

var (
	browserMuxSocketPattern  = regexp.MustCompile(`^browser-mux-[0-9a-f]{32}\.sock$`)
	errBrowserMuxUnavailable = errors.New("Browser Provider mux is unavailable")
)

type Config struct {
	Role                    string
	ListenAddress           string
	UpstreamURL             string
	MuxSocketPath           string
	MuxLayout               restrictedunix.Layout
	ServerCertificateFile   string
	ServerPrivateKeyFile    string
	ClientCABundleFile      string
	AllowedClientIdentities []string
	RemoteTLSConfig         *tls.Config
	PeerRevocationMonitor   connectiondrain.PeerMonitor
	SignerProbe             func(context.Context) error
	ConnectionMaxAge        time.Duration
	MaxSessions             int
	OperationTimeout        time.Duration
}

type Backend struct {
	config      Config
	tls         *tls.Config
	transport   *http.Transport
	server      *http.Server
	connections *connectiondrain.Registry
	mu          sync.Mutex
	active      int
	replayMu    sync.Mutex
	replayed    map[string]time.Time
}

func New(config Config) (*Backend, error) {
	if config.Role != executorprotocol.RoleBrowser || config.ListenAddress == "" ||
		config.OperationTimeout < 100*time.Millisecond || config.OperationTimeout > 30*time.Second ||
		config.MaxSessions < 1 || config.MaxSessions > maxSessions {
		return nil, errors.New("invalid Browser executor backend configuration")
	}
	if config.MuxSocketPath == "" {
		parsed, err := url.Parse(config.UpstreamURL)
		if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" {
			return nil, errors.New("invalid Browser CDP upstream URL")
		}
	} else if config.UpstreamURL != "" || !filepath.IsAbs(config.MuxSocketPath) ||
		filepath.Clean(config.MuxSocketPath) != config.MuxSocketPath ||
		!browserMuxSocketPattern.MatchString(filepath.Base(config.MuxSocketPath)) ||
		!restrictedunix.ValidateParent(config.MuxSocketPath, config.MuxLayout) {
		return nil, errors.New("invalid Browser Provider mux socket")
	}
	tlsConfig, err := executorServerTLS(config.RemoteTLSConfig, config.ServerCertificateFile,
		config.ServerPrivateKeyFile, config.ClientCABundleFile, config.AllowedClientIdentities)
	if err != nil {
		return nil, err
	}
	connections, err := newExecutorPeerRegistry(config.RemoteTLSConfig, config.PeerRevocationMonitor,
		config.SignerProbe, config.ConnectionMaxAge)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	if config.MuxSocketPath != "" {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			if !restrictedunix.ValidateSocket(config.MuxSocketPath, config.MuxLayout) {
				return nil, errBrowserMuxUnavailable
			}
			return (&net.Dialer{}).DialContext(ctx, "unix", config.MuxSocketPath)
		}
	}
	return &Backend{
		config: config, tls: tlsConfig, transport: transport, connections: connections,
		server: &http.Server{Addr: config.ListenAddress, Handler: nil, TLSConfig: tlsConfig,
			ConnState:         connectiondrain.PeerConnState(config.PeerRevocationMonitor),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10},
		replayed: make(map[string]time.Time),
	}, nil
}

func (b *Backend) Ready(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("Browser executor backend is unavailable")
	}
	probeContext, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	defer cancel()
	if err := executorPeerReady(probeContext, b.config.PeerRevocationMonitor, b.config.SignerProbe); err != nil {
		return err
	}
	if b.config.MuxSocketPath != "" {
		request, err := http.NewRequestWithContext(probeContext, http.MethodGet, "http://browser-mux/readyz", nil)
		if err != nil {
			return errors.New("Browser Provider mux is unavailable")
		}
		client := &http.Client{Transport: b.transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Browser mux redirect denied")
		}}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("Browser Provider mux is unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return errors.New("Browser Provider mux is unavailable")
		}
		return nil
	}
	connection, _, err := b.dialUpstream(probeContext, executorprotocol.Open{})
	if err != nil {
		return errors.New("Browser CDP upstream is unavailable")
	}
	return connection.Close(websocket.StatusNormalClosure, "probe")
}

func (b *Backend) Serve(ctx context.Context) error {
	if b == nil || ctx == nil || b.server == nil {
		return errors.New("Browser executor backend is not initialized")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", b.config.ListenAddress)
	if err != nil {
		return errors.New("bind Browser executor backend")
	}
	defer listener.Close()
	listener, err = wrapExecutorPeerListener(listener, b.connections)
	if err != nil {
		return errors.New("track Browser executor connections")
	}
	if b.connections != nil {
		defer b.connections.Drain()
	}
	if b.config.PeerRevocationMonitor != nil {
		defer b.config.PeerRevocationMonitor.Close()
	}
	stopPeerPoll := connectiondrain.StartPeerPoll(ctx, b.config.PeerRevocationMonitor)
	defer stopPeerPoll()
	b.server.Handler = http.HandlerFunc(b.handle)
	stop := context.AfterFunc(ctx, func() { _ = b.server.Shutdown(context.Background()) })
	defer stop()
	if err := b.server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		return errors.New("serve Browser executor backend")
	}
	return nil
}

func (b *Backend) Close() error {
	if b == nil {
		return nil
	}
	if b.server != nil {
		_ = b.server.Close()
	}
	if b.connections != nil {
		b.connections.Drain()
	}
	if b.config.PeerRevocationMonitor != nil {
		b.config.PeerRevocationMonitor.Close()
	}
	if b.transport != nil {
		b.transport.CloseIdleConnections()
	}
	return nil
}

func (b *Backend) handle(writer http.ResponseWriter, request *http.Request) {
	if request != nil && request.Method == http.MethodGet && request.URL.Path == "/readyz" && request.TLS != nil {
		writer.Header().Set("Cache-Control", "no-store")
		if err := b.Ready(request.Context()); err != nil {
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if request == nil || request.Method != http.MethodGet || request.URL.Path != "/executor" || request.TLS == nil || request.Header.Get("Sec-WebSocket-Protocol") != executorprotocol.ProtocolID {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if b.config.PeerRevocationMonitor != nil {
		probeContext, cancel := context.WithTimeout(request.Context(), b.config.OperationTimeout)
		err := executorPeerReady(probeContext, b.config.PeerRevocationMonitor, b.config.SignerProbe)
		cancel()
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{executorprotocol.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(executorprotocol.MaxMessageBytes)

	openContext, cancelOpen := context.WithTimeout(request.Context(), b.config.OperationTimeout)
	defer cancelOpen()
	kind, document, err := connection.Read(openContext)
	var open executorprotocol.Open
	now := time.Now().UTC()
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(document, &open) != nil || open.Role != b.config.Role || open.Validate(now) != nil || !b.acquire() {
		b.reject(connection, "unavailable")
		return
	}
	defer b.release()
	if !b.claim(open.RequestID, now, openExpiry(open)) {
		b.reject(connection, "unavailable")
		return
	}
	upstream, _, err := b.dialUpstream(openContext, open)
	if err != nil {
		b.reject(connection, "unavailable")
		return
	}
	defer upstream.CloseNow()
	response, _ := executorprotocol.Encode(executorprotocol.Accepted(open.RequestID))
	if err := connection.Write(request.Context(), websocket.MessageText, response); err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), openExpiry(open))
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- bridge(ctx, connection, upstream) }()
	go func() { results <- bridge(ctx, upstream, connection) }()
	<-results
	cancel()
	_ = connection.CloseNow()
	_ = upstream.CloseNow()
	<-results
}

func (b *Backend) reject(connection *websocket.Conn, code string) {
	response, _ := executorprotocol.Encode(executorprotocol.Rejected("invalid", code))
	_ = connection.Write(context.Background(), websocket.MessageText, response)
}

func (b *Backend) claim(requestID string, now, expires time.Time) bool {
	if requestID == "" || expires.IsZero() || !expires.After(now) {
		return false
	}
	b.replayMu.Lock()
	defer b.replayMu.Unlock()
	for id, until := range b.replayed {
		if !until.After(now) {
			delete(b.replayed, id)
		}
	}
	if _, exists := b.replayed[requestID]; exists || len(b.replayed) >= maxReplayClaims {
		return false
	}
	b.replayed[requestID] = expires
	return true
}

func (b *Backend) acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active >= b.config.MaxSessions {
		return false
	}
	b.active++
	return true
}

func (b *Backend) release() {
	b.mu.Lock()
	if b.active > 0 {
		b.active--
	}
	b.mu.Unlock()
}

func (b *Backend) dialUpstream(ctx context.Context, open executorprotocol.Open) (*websocket.Conn, *http.Response, error) {
	client := &http.Client{Transport: b.transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Browser CDP redirect denied")
	}}
	if b.config.MuxSocketPath == "" {
		return websocket.Dial(ctx, b.config.UpstreamURL, &websocket.DialOptions{HTTPClient: client})
	}
	connection, response, err := websocket.Dial(ctx, "ws://browser-mux/session", &websocket.DialOptions{
		HTTPClient: client, Subprotocols: []string{executorprotocol.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return nil, response, err
	}
	connection.SetReadLimit(executorprotocol.MaxMessageBytes)
	document, err := executorprotocol.Encode(open)
	if err == nil {
		err = connection.Write(ctx, websocket.MessageText, document)
	}
	if err != nil {
		connection.CloseNow()
		return nil, response, errBrowserMuxUnavailable
	}
	kind, acceptedDocument, err := connection.Read(ctx)
	var accepted executorprotocol.Response
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(acceptedDocument, &accepted) != nil ||
		accepted.Validate() != nil || accepted.RequestID != open.RequestID || accepted.Status != executorprotocol.StatusAccepted {
		connection.CloseNow()
		return nil, response, errBrowserMuxUnavailable
	}
	return connection, response, nil
}

func bridge(ctx context.Context, source, target *websocket.Conn) error {
	for {
		kind, payload, err := source.Read(ctx)
		if err != nil {
			return err
		}
		if len(payload) == 0 || len(payload) > executorprotocol.MaxMessageBytes {
			return errors.New("invalid Browser CDP frame")
		}
		if err := target.Write(ctx, kind, payload); err != nil {
			return err
		}
	}
}

func openExpiry(open executorprotocol.Open) time.Time {
	expires, _ := time.Parse(time.RFC3339Nano, open.HandoffExpiresAt)
	return expires
}
