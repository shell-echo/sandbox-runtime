// Package mux owns the Provider-side typed Browser allocation-to-CDP bridge.
// Its Unix peer receives only opaque executor authority and CDP messages;
// Docker coordinates and persistent session truth remain inside Provider.
package mux

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/browsercdp"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

const (
	maxSessions     = 256
	maxReplayClaims = 4096
)

var (
	ErrInvalidOptions = errors.New("invalid Browser allocation mux options")
	ErrUnavailable    = errors.New("Browser allocation mux unavailable")
	socketPattern     = regexp.MustCompile(`^browser-mux-[0-9a-f]{32}\.sock$`)
)

type Authority interface {
	Resolve(context.Context, executorprotocol.Open) (browser.AllocationReceipt, error)
	Claim(context.Context, executorprotocol.Open) error
	Ready(context.Context) error
}

type Runtime interface {
	Attach(context.Context, browser.AllocationReceipt) (browser.Stream, error)
	Ready(context.Context) error
}

type Options struct {
	SocketPath            string
	Layout                restrictedunix.Layout
	AllowedPeerUID        uint32
	MaxSessions           int
	OperationTimeout      time.Duration
	AuthorityPollInterval time.Duration
	Authority             Authority
	Runtime               Runtime
}

type Mux struct {
	options     Options
	server      *http.Server
	mu          sync.Mutex
	listener    *net.UnixListener
	connections map[*websocket.Conn]struct{}
	active      int
	closed      bool
	wait        sync.WaitGroup
	replayMu    sync.Mutex
	replayed    map[string]time.Time
}

func New(options Options) (*Mux, error) {
	if !filepath.IsAbs(options.SocketPath) || filepath.Clean(options.SocketPath) != options.SocketPath ||
		!socketPattern.MatchString(filepath.Base(options.SocketPath)) ||
		!restrictedunix.ValidateParent(options.SocketPath, options.Layout) ||
		options.AllowedPeerUID == 0 || options.MaxSessions < 1 || options.MaxSessions > maxSessions ||
		options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > 30*time.Second ||
		options.AuthorityPollInterval < 10*time.Millisecond || options.AuthorityPollInterval > 5*time.Second ||
		options.Authority == nil || options.Runtime == nil {
		return nil, ErrInvalidOptions
	}
	m := &Mux{options: options, connections: make(map[*websocket.Conn]struct{}), replayed: make(map[string]time.Time)}
	m.server = &http.Server{Handler: http.HandlerFunc(m.handle), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	return m, nil
}

func (m *Mux) Startup(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrUnavailable
	}
	listener, inode, err := restrictedunix.Listen(m.options.SocketPath, m.options.Layout)
	if err != nil {
		return ErrUnavailable
	}
	m.mu.Lock()
	if m.closed || m.listener != nil {
		m.mu.Unlock()
		_ = listener.Close()
		restrictedunix.RemoveIfSame(m.options.SocketPath, inode)
		return ErrUnavailable
	}
	m.listener = listener
	m.mu.Unlock()
	defer func() {
		_ = listener.Close()
		restrictedunix.RemoveIfSame(m.options.SocketPath, inode)
		m.mu.Lock()
		if m.listener == listener {
			m.listener = nil
		}
		m.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() { _ = m.server.Close() })
	defer stop()
	err = m.server.Serve(peerListener{UnixListener: listener, uid: m.options.AllowedPeerUID})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return ErrUnavailable
}

func (m *Mux) Shutdown(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrUnavailable
	}
	m.mu.Lock()
	m.closed = true
	listener := m.listener
	connections := make([]*websocket.Conn, 0, len(m.connections))
	for connection := range m.connections {
		connections = append(connections, connection)
	}
	m.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	_ = m.server.Close()
	for _, connection := range connections {
		_ = connection.CloseNow()
	}
	done := make(chan struct{})
	go func() { m.wait.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Mux) Ready(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrUnavailable
	}
	m.mu.Lock()
	listening := m.listener != nil && !m.closed
	m.mu.Unlock()
	if !listening || m.options.Authority.Ready(ctx) != nil || m.options.Runtime.Ready(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

type peerListener struct {
	*net.UnixListener
	uid uint32
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if restrictedunix.PeerUID(connection, l.uid) {
			return connection, nil
		}
		_ = connection.Close()
	}
}

func (m *Mux) handle(writer http.ResponseWriter, request *http.Request) {
	if request != nil && request.Method == http.MethodGet && request.URL != nil &&
		request.URL.Path == "/readyz" && request.URL.EscapedPath() == "/readyz" && request.URL.RawQuery == "" {
		probeCtx, cancel := context.WithTimeout(request.Context(), m.options.OperationTimeout)
		defer cancel()
		if m.options.Authority.Ready(probeCtx) != nil || m.options.Runtime.Ready(probeCtx) != nil {
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if request == nil || request.Method != http.MethodGet || request.URL == nil ||
		request.URL.Path != "/session" || request.URL.EscapedPath() != "/session" || request.URL.RawQuery != "" ||
		request.Header.Get("Sec-WebSocket-Protocol") != executorprotocol.ProtocolID {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{executorprotocol.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(executorprotocol.MaxMessageBytes)
	if !m.acquire(connection) {
		m.reject(request.Context(), connection, "invalid", "capacity")
		return
	}
	defer m.release(connection)
	openCtx, cancelOpen := context.WithTimeout(request.Context(), m.options.OperationTimeout)
	defer cancelOpen()
	kind, document, err := connection.Read(openCtx)
	var open executorprotocol.Open
	now := time.Now().UTC()
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(document, &open) != nil ||
		open.Role != executorprotocol.RoleBrowser || open.Validate(now) != nil || !canonical(open, document) {
		m.reject(request.Context(), connection, open.RequestID, "unavailable")
		return
	}
	receipt, err := m.options.Authority.Resolve(openCtx, open)
	if err != nil {
		m.reject(request.Context(), connection, open.RequestID, "unavailable")
		return
	}
	// An invalid but well-formed Open must not consume replay capacity. The
	// claim remains bounded, and is made before any Docker attach side effect.
	if !m.claim(open.RequestID, now, expiry(open)) {
		m.reject(request.Context(), connection, open.RequestID, "unavailable")
		return
	}
	if m.options.Authority.Claim(openCtx, open) != nil {
		m.reject(request.Context(), connection, open.RequestID, "unavailable")
		return
	}
	stream, err := m.options.Runtime.Attach(openCtx, receipt)
	if err != nil || stream == nil {
		m.reject(request.Context(), connection, open.RequestID, "unavailable")
		return
	}
	cdp, err := browsercdp.New(stream)
	if err != nil {
		_ = stream.Close()
		m.reject(request.Context(), connection, open.RequestID, "unavailable")
		return
	}
	defer cdp.Close()
	if fresh, err := m.options.Authority.Resolve(openCtx, open); err != nil || !reflect.DeepEqual(fresh, receipt) {
		m.reject(request.Context(), connection, open.RequestID, "unavailable")
		return
	}
	response, _ := executorprotocol.Encode(executorprotocol.Accepted(open.RequestID))
	if connection.Write(openCtx, websocket.MessageText, response) != nil {
		return
	}
	sessionCtx, cancelSession := context.WithDeadline(request.Context(), expiry(open))
	defer cancelSession()
	stop := context.AfterFunc(sessionCtx, func() { _ = cdp.Close(); _ = connection.CloseNow() })
	defer stop()
	monitorDone := make(chan struct{})
	go func() { defer close(monitorDone); m.monitor(sessionCtx, cancelSession, open, receipt) }()
	results := make(chan error, 2)
	go func() { results <- copyToCDP(sessionCtx, connection, cdp) }()
	go func() { results <- copyFromCDP(sessionCtx, cdp, connection) }()
	<-results
	cancelSession()
	_ = cdp.Close()
	_ = connection.CloseNow()
	<-results
	<-monitorDone
}

func (m *Mux) monitor(ctx context.Context, cancel context.CancelFunc, open executorprotocol.Open, receipt browser.AllocationReceipt) {
	ticker := time.NewTicker(m.options.AuthorityPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, stop := context.WithTimeout(ctx, m.options.OperationTimeout)
			fresh, err := m.options.Authority.Resolve(probeCtx, open)
			stop()
			if err != nil || !reflect.DeepEqual(fresh, receipt) {
				cancel()
				return
			}
		}
	}
}

func copyToCDP(ctx context.Context, connection *websocket.Conn, cdp *browsercdp.Conn) error {
	for {
		kind, payload, err := connection.Read(ctx)
		if err != nil {
			return err
		}
		if kind != websocket.MessageText || cdp.Write(ctx, payload) != nil {
			return ErrUnavailable
		}
	}
}

func copyFromCDP(ctx context.Context, cdp *browsercdp.Conn, connection *websocket.Conn) error {
	for {
		payload, err := cdp.Read(ctx)
		if err != nil {
			return err
		}
		if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
			return err
		}
	}
}

func (m *Mux) acquire(connection *websocket.Conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.active >= m.options.MaxSessions {
		return false
	}
	m.active++
	m.connections[connection] = struct{}{}
	m.wait.Add(1)
	return true
}

func (m *Mux) release(connection *websocket.Conn) {
	m.mu.Lock()
	delete(m.connections, connection)
	m.active--
	m.mu.Unlock()
	m.wait.Done()
}

func (m *Mux) claim(id string, now, until time.Time) bool {
	m.replayMu.Lock()
	defer m.replayMu.Unlock()
	for key, expires := range m.replayed {
		if !expires.After(now) {
			delete(m.replayed, key)
		}
	}
	if _, exists := m.replayed[id]; exists || id == "" || !until.After(now) || len(m.replayed) >= maxReplayClaims {
		return false
	}
	m.replayed[id] = until
	return true
}

func (m *Mux) reject(ctx context.Context, connection *websocket.Conn, id, code string) {
	response, _ := executorprotocol.Encode(executorprotocol.Rejected(id, code))
	if response != nil {
		_ = connection.Write(ctx, websocket.MessageText, response)
	}
}

func canonical(open executorprotocol.Open, document []byte) bool {
	encoded, err := executorprotocol.Encode(open)
	return err == nil && bytes.Equal(encoded, document)
}

func expiry(open executorprotocol.Open) time.Time {
	value, _ := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	return value
}
