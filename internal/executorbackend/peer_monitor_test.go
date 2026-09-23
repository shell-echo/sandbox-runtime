package executorbackend

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
)

type executorTestPeerMonitor struct {
	mu      sync.Mutex
	active  map[net.Conn]struct{}
	ready   bool
	closed  bool
	revoked bool
}

func newExecutorTestPeerMonitor() *executorTestPeerMonitor {
	return &executorTestPeerMonitor{active: make(map[net.Conn]struct{}), ready: true}
}

func (m *executorTestPeerMonitor) Track(conn net.Conn, state tls.ConnectionState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready || m.closed || m.revoked || state.Version != tls.VersionTLS13 {
		return errors.New("peer unavailable")
	}
	m.active[conn] = struct{}{}
	return nil
}

func (m *executorTestPeerMonitor) Forget(conn net.Conn) {
	m.mu.Lock()
	delete(m.active, conn)
	m.mu.Unlock()
}

func (m *executorTestPeerMonitor) Poll(context.Context) error {
	m.mu.Lock()
	if m.closed || !m.ready {
		m.mu.Unlock()
		return errors.New("peer source unavailable")
	}
	if !m.revoked {
		m.mu.Unlock()
		return nil
	}
	m.ready = false
	connections := make([]net.Conn, 0, len(m.active))
	for conn := range m.active {
		connections = append(connections, conn)
	}
	m.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return errors.New("peer revoked")
}

func (m *executorTestPeerMonitor) PollInterval() time.Duration { return 100 * time.Millisecond }

func (m *executorTestPeerMonitor) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready && !m.closed
}

func (m *executorTestPeerMonitor) Close() {
	m.mu.Lock()
	m.closed = true
	m.ready = false
	connections := make([]net.Conn, 0, len(m.active))
	for conn := range m.active {
		connections = append(connections, conn)
	}
	m.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (m *executorTestPeerMonitor) Revoke() {
	m.mu.Lock()
	m.revoked = true
	m.mu.Unlock()
}

func (m *executorTestPeerMonitor) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

func executorTestRemoteTLS(t *testing.T, material tlsMaterial) *tls.Config {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(material.serverCertificate, material.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: material.pool,
		GetCertificate:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &certificate, nil },
		VerifyConnection: func(tls.ConnectionState) error { return nil }}
}

func executorTestClient(material tlsMaterial) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: material.pool, Certificates: []tls.Certificate{material.client}, ServerName: "127.0.0.1"}}}
}

func waitExecutorTest(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestLiveExecutorTLSRequiresPeerMonitorAndSigner(t *testing.T) {
	material := writeTLSMaterial(t, t.TempDir())
	remote := executorTestRemoteTLS(t, material)
	browser := Config{Role: executorprotocol.RoleBrowser, ListenAddress: freeListenerAddress(t),
		UpstreamURL: "ws://127.0.0.1:9222/devtools/browser/opaque", RemoteTLSConfig: remote,
		MaxSessions: 1, OperationTimeout: time.Second}
	if _, err := New(browser); err == nil {
		t.Fatal("Browser remote TLS without peer monitor accepted")
	}
	browser.PeerRevocationMonitor = newExecutorTestPeerMonitor()
	if _, err := New(browser); err == nil {
		t.Fatal("Browser remote TLS without signer probe accepted")
	}
	browser.SignerProbe = func(context.Context) error { return nil }
	if _, err := New(browser); err == nil {
		t.Fatal("Browser remote TLS without connection lifetime accepted")
	}
	browser.ConnectionMaxAge = time.Minute
	if _, err := New(browser); err != nil {
		t.Fatal(err)
	}

	socket := testBrokerSocket(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	desktop := DesktopConfig{Role: executorprotocol.RoleDesktop, ListenAddress: freeListenerAddress(t),
		BrokerSocketPath: socket, ExecutorIdentity: "executor-desktop-1", RemoteTLSConfig: remote,
		MaxSessions: 1, OperationTimeout: time.Second}
	if _, err := NewDesktop(desktop); err == nil {
		t.Fatal("Desktop remote TLS without peer monitor accepted")
	}
	desktop.PeerRevocationMonitor = newExecutorTestPeerMonitor()
	if _, err := NewDesktop(desktop); err == nil {
		t.Fatal("Desktop remote TLS without signer probe accepted")
	}
	desktop.SignerProbe = func(context.Context) error { return nil }
	if _, err := NewDesktop(desktop); err == nil {
		t.Fatal("Desktop remote TLS without connection lifetime accepted")
	}
	desktop.ConnectionMaxAge = time.Minute
	if _, err := NewDesktop(desktop); err != nil {
		t.Fatal(err)
	}
}

func TestExecutorUpgradeRechecksPeerSourceAfterTLSHandshake(t *testing.T) {
	for _, role := range []string{executorprotocol.RoleBrowser, executorprotocol.RoleDesktop} {
		t.Run(role, func(t *testing.T) {
			monitor := newExecutorTestPeerMonitor()
			monitor.mu.Lock()
			monitor.ready = false
			monitor.mu.Unlock()
			request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/executor", nil)
			request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			request.Header.Set("Sec-WebSocket-Protocol", executorprotocol.ProtocolID)
			writer := httptest.NewRecorder()
			if role == executorprotocol.RoleBrowser {
				backend := &Backend{config: Config{PeerRevocationMonitor: monitor,
					SignerProbe: func(context.Context) error { return nil }, OperationTimeout: time.Second}}
				backend.handle(writer, request)
			} else {
				backend := &DesktopBackend{config: DesktopConfig{PeerRevocationMonitor: monitor,
					SignerProbe: func(context.Context) error { return nil }, OperationTimeout: time.Second}}
				backend.handle(writer, request)
			}
			if writer.Code != http.StatusServiceUnavailable {
				t.Fatalf("stale reused TLS connection admitted: %d", writer.Code)
			}
		})
	}
}

func TestBrowserLivePeerRevocationDrainsHijackedSessionAndUpstream(t *testing.T) {
	upstreamClosed := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(request.Context())
		upstreamClosed <- struct{}{}
	}))
	defer upstream.Close()
	material := writeTLSMaterial(t, t.TempDir())
	monitor := newExecutorTestPeerMonitor()
	backend, err := New(Config{Role: executorprotocol.RoleBrowser, ListenAddress: freeListenerAddress(t),
		UpstreamURL:     "ws" + strings.TrimPrefix(upstream.URL, "http") + "/cdp",
		RemoteTLSConfig: executorTestRemoteTLS(t, material), PeerRevocationMonitor: monitor,
		SignerProbe: func(context.Context) error { return nil }, ConnectionMaxAge: time.Minute,
		MaxSessions: 2, OperationTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- backend.Serve(ctx) }()
	waitListener(t, backend.config.ListenAddress)
	conn, _, err := websocket.Dial(ctx, "wss://"+backend.config.ListenAddress+"/executor",
		&websocket.DialOptions{HTTPClient: executorTestClient(material), Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	open := testOpen()
	document, _ := executorprotocol.Encode(open)
	if err := conn.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	_, response, err := conn.Read(ctx)
	var accepted executorprotocol.Response
	if err != nil || executorprotocol.Decode(response, &accepted) != nil || accepted.Status != executorprotocol.StatusAccepted {
		t.Fatalf("Browser open was not accepted: %v", err)
	}
	waitExecutorTest(t, "tracked Browser connection", func() bool { return monitor.Active() == 1 && backend.connections.Active() == 1 })
	monitor.Revoke()
	waitExecutorTest(t, "Browser automatic revocation poll", func() bool { return !monitor.Ready() })
	if backend.Ready(ctx) == nil {
		t.Fatal("revoked Browser source remained ready")
	}
	readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
	defer readCancel()
	if _, _, err := conn.Read(readCtx); err == nil {
		t.Fatal("revoked Browser WebSocket remained open")
	}
	select {
	case <-upstreamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("Browser upstream was not closed")
	}
	waitExecutorTest(t, "Browser exact socket cleanup", func() bool { return monitor.Active() == 0 && backend.connections.Active() == 0 })
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Browser backend did not stop")
	}
}

func TestDesktopLivePeerRevocationClosesBrokerSession(t *testing.T) {
	socket := testBrokerSocket(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	brokerClosed := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, readErr := reader.ReadBytes('\n')
		var open desktopbroker.SessionOpen
		if readErr != nil || desktopbroker.DecodeSession(line, &open) != nil {
			return
		}
		accepted, _ := desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID,
			Type: desktopbroker.SessionAcceptedType, RequestID: open.RequestID, OK: true})
		if _, writeErr := conn.Write(accepted); writeErr != nil {
			return
		}
		_, _ = reader.ReadBytes('\n')
		brokerClosed <- struct{}{}
	}()
	material := writeTLSMaterial(t, t.TempDir())
	monitor := newExecutorTestPeerMonitor()
	backend, err := NewDesktop(DesktopConfig{Role: executorprotocol.RoleDesktop, ListenAddress: freeListenerAddress(t),
		BrokerSocketPath: socket, ExecutorIdentity: "executor-desktop-1",
		RemoteTLSConfig: executorTestRemoteTLS(t, material), PeerRevocationMonitor: monitor,
		SignerProbe: func(context.Context) error { return nil }, ConnectionMaxAge: time.Minute,
		MaxSessions: 2, OperationTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- backend.Serve(ctx) }()
	waitListener(t, backend.config.ListenAddress)
	conn, _, err := websocket.Dial(ctx, "wss://"+backend.config.ListenAddress+"/executor",
		&websocket.DialOptions{HTTPClient: executorTestClient(material), Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	open, _, _ := testDesktopOpen(t)
	document, _ := executorprotocol.Encode(open)
	if err := conn.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	_, response, err := conn.Read(ctx)
	var accepted executorprotocol.Response
	if err != nil || executorprotocol.Decode(response, &accepted) != nil || accepted.Status != executorprotocol.StatusAccepted {
		t.Fatalf("Desktop open was not accepted: %v", err)
	}
	waitExecutorTest(t, "tracked Desktop connection", func() bool { return monitor.Active() == 1 && backend.connections.Active() == 1 })
	monitor.Revoke()
	waitExecutorTest(t, "Desktop automatic revocation poll", func() bool { return !monitor.Ready() })
	if backend.Ready(ctx) == nil {
		t.Fatal("revoked Desktop source remained ready")
	}
	readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
	defer readCancel()
	if _, _, err := conn.Read(readCtx); err == nil {
		t.Fatal("revoked Desktop WebSocket remained open")
	}
	select {
	case <-brokerClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("Desktop broker session was not closed")
	}
	waitExecutorTest(t, "Desktop exact socket cleanup", func() bool { return monitor.Active() == 0 && backend.connections.Active() == 0 })
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Desktop backend did not stop")
	}
}
