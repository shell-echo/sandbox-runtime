// Package executorbackend implements the operator-owned Browser executor
// backend. It terminates private mTLS, validates the opaque authority, and
// relays frames to an already-running CDP endpoint. It has no Provider or
// Docker dependency.
package executorbackend

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/providerapi"
)

const (
	maxSessions = 256
)

type Config struct {
	Role                    string
	ListenAddress           string
	UpstreamURL             string
	ServerCertificateFile   string
	ServerPrivateKeyFile    string
	ClientCABundleFile      string
	AllowedClientIdentities []string
	MaxSessions             int
	OperationTimeout        time.Duration
}

type Backend struct {
	config    Config
	tls       *tls.Config
	transport *http.Transport
	server    *http.Server
	mu        sync.Mutex
	active    int
	replayMu  sync.Mutex
	replayed  map[string]time.Time
}

func New(config Config) (*Backend, error) {
	if config.Role != executorprotocol.RoleBrowser || config.ListenAddress == "" ||
		config.OperationTimeout < 100*time.Millisecond || config.OperationTimeout > 30*time.Second ||
		config.MaxSessions < 1 || config.MaxSessions > maxSessions {
		return nil, errors.New("invalid Browser executor backend configuration")
	}
	parsed, err := url.Parse(config.UpstreamURL)
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" {
		return nil, errors.New("invalid Browser CDP upstream URL")
	}
	tlsConfig, err := providerapi.LoadMTLSConfig(config.ServerCertificateFile, config.ServerPrivateKeyFile, config.ClientCABundleFile, config.AllowedClientIdentities)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	return &Backend{
		config: config, tls: tlsConfig, transport: transport,
		server:   &http.Server{Addr: config.ListenAddress, Handler: nil, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10},
		replayed: make(map[string]time.Time),
	}, nil
}

func (b *Backend) Ready(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("Browser executor backend is unavailable")
	}
	probeContext, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	defer cancel()
	connection, _, err := b.dialUpstream(probeContext)
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
	if b.transport != nil {
		b.transport.CloseIdleConnections()
	}
	return nil
}

func (b *Backend) handle(writer http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodGet || request.URL.Path != "/executor" || request.TLS == nil || request.Header.Get("Sec-WebSocket-Protocol") != executorprotocol.ProtocolID {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
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
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(document, &open) != nil || open.Role != b.config.Role || open.Validate(now) != nil || !b.claim(open.RequestID, now, openExpiry(open)) || !b.acquire() {
		b.reject(connection, "unavailable")
		return
	}
	defer b.release()
	upstream, _, err := b.dialUpstream(openContext)
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
	if _, exists := b.replayed[requestID]; exists {
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

func (b *Backend) dialUpstream(ctx context.Context) (*websocket.Conn, *http.Response, error) {
	return websocket.Dial(ctx, b.config.UpstreamURL, &websocket.DialOptions{HTTPClient: &http.Client{Transport: b.transport}})
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
