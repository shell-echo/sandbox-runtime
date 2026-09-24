package roleprocess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/config"
)

type privateLiveTestPeer struct {
	mu      sync.Mutex
	active  map[net.Conn]struct{}
	ready   bool
	revoked bool
	closed  bool
}

func newPrivateLiveTestPeer() *privateLiveTestPeer {
	return &privateLiveTestPeer{active: make(map[net.Conn]struct{}), ready: true}
}

func (p *privateLiveTestPeer) Track(conn net.Conn, state tls.ConnectionState) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.revoked || !p.ready || state.Version != tls.VersionTLS13 {
		return errPrivateLivePeer
	}
	p.active[conn] = struct{}{}
	return nil
}

func (p *privateLiveTestPeer) Forget(conn net.Conn) {
	p.mu.Lock()
	delete(p.active, conn)
	p.mu.Unlock()
}

func (p *privateLiveTestPeer) Poll(context.Context) error {
	p.mu.Lock()
	if p.closed || !p.ready {
		p.mu.Unlock()
		return errPrivateLivePeer
	}
	if !p.revoked {
		p.mu.Unlock()
		return nil
	}
	p.ready = false
	connections := make([]net.Conn, 0, len(p.active))
	for conn := range p.active {
		connections = append(connections, conn)
	}
	p.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return errPrivateLivePeer
}

func (p *privateLiveTestPeer) PollInterval() time.Duration { return 100 * time.Millisecond }

func (p *privateLiveTestPeer) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready && !p.closed
}

func (p *privateLiveTestPeer) Close() {
	p.mu.Lock()
	p.closed = true
	p.ready = false
	connections := make([]net.Conn, 0, len(p.active))
	for conn := range p.active {
		connections = append(connections, conn)
	}
	p.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (p *privateLiveTestPeer) Revoke() {
	p.mu.Lock()
	p.revoked = true
	p.mu.Unlock()
}

func (p *privateLiveTestPeer) Active() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active)
}

var errPrivateLivePeer = &privateLiveError{}

type privateLiveError struct{}

func (*privateLiveError) Error() string { return "test peer unavailable" }

func privateLiveTestTLS(t *testing.T) (*tls.Config, *http.Client) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, server bool) tls.Certificate {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute),
			NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.URIs = []*url.URL{{Scheme: "spiffe", Host: "sandbox-runtime.test", Path: "/provider-browser"}}
		}
		der, issueErr := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	serverCertificate, clientCertificate := issue(2, true), issue(3, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCertificate, nil },
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) < 1 || len(state.VerifiedChains) == 0 {
				return errPrivateLivePeer
			}
			return nil
		}}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}, ServerName: "127.0.0.1"}}}
	return server, client
}

func privateLiveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitPrivateLive(t *testing.T, name string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", name)
}

func TestPrivateRoleLiveTLSRevocationDrainsHijackedWebSocket(t *testing.T) {
	transport, client := privateLiveTestTLS(t)
	peer := newPrivateLiveTestPeer()
	handlerClosed := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(request.Context())
		handlerClosed <- struct{}{}
	})
	address := privateLiveAddress(t)
	server, err := newPrivateTLSServerLive(address, handler, transport, peer, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Startup(ctx) }()
	waitPrivateLive(t, "private listener", func() bool {
		conn, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
	conn, _, err := websocket.Dial(ctx, "wss://"+address+"/executor",
		&websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	waitPrivateLive(t, "tracked private WebSocket", func() bool {
		return peer.Active() == 1 && server.connections.Active() == 1
	})
	peer.Revoke()
	waitPrivateLive(t, "automatic private peer poll", func() bool { return !peer.Ready() })
	if privatePeerReady(ctx, peer, func(context.Context) error { return nil }) == nil {
		t.Fatal("revoked private role remained ready")
	}
	readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
	defer readCancel()
	if _, _, err := conn.Read(readCtx); err == nil {
		t.Fatal("revoked WebSocket remained open")
	}
	select {
	case <-handlerClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("private role handler did not close")
	}
	waitPrivateLive(t, "private exact socket cleanup", func() bool {
		return peer.Active() == 0 && server.connections.Active() == 0
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("private role server did not stop")
	}
}

func TestPrivateRoleLiveTLSRejectsStaticMixAndMissingDrain(t *testing.T) {
	transport, _ := privateLiveTestTLS(t)
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	peer := newPrivateLiveTestPeer()
	address := privateLiveAddress(t)
	if _, err := newPrivateTLSServerLive(address, handler, transport, nil, time.Minute); err == nil {
		t.Fatal("missing peer monitor accepted")
	}
	if _, err := newPrivateTLSServerLive(address, handler, transport, peer, 0); err == nil {
		t.Fatal("unbounded connection lifetime accepted")
	}
	certificate := tls.Certificate{Certificate: [][]byte{[]byte("invalid")}}
	mixed := transport.Clone()
	mixed.Certificates = []tls.Certificate{certificate}
	if _, err := newPrivateTLSServerLive(address, handler, mixed, peer, time.Minute); err == nil {
		t.Fatal("local certificate accepted alongside remote signer")
	}
}

func TestPrivateRoleLiveShutdownClosesHijackedConnection(t *testing.T) {
	transport, client := privateLiveTestTLS(t)
	peer := newPrivateLiveTestPeer()
	handlerClosed := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(request.Context())
		handlerClosed <- struct{}{}
	})
	address := privateLiveAddress(t)
	server, err := newPrivateTLSServerLive(address, handler, transport, peer, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Startup(ctx) }()
	waitPrivateLive(t, "private listener", func() bool {
		conn, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
	conn, _, err := websocket.Dial(ctx, "wss://"+address+"/executor", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	waitPrivateLive(t, "tracked private WebSocket", func() bool {
		return peer.Active() == 1 && server.connections.Active() == 1
	})
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	readContext, readCancel := context.WithTimeout(ctx, 3*time.Second)
	defer readCancel()
	if _, _, err := conn.Read(readContext); err == nil {
		t.Fatal("hijacked WebSocket survived shutdown")
	}
	select {
	case <-handlerClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("private handler survived shutdown")
	}
	waitPrivateLive(t, "shutdown exact socket cleanup", func() bool {
		return peer.Active() == 0 && server.connections.Active() == 0
	})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("private role server did not stop")
	}
}

func TestPrivateRoleV3GraphSelectsOnlyLiveTransport(t *testing.T) {
	for _, role := range []config.DataPlaneRole{config.DataPlaneBrowser, config.DataPlaneDesktop} {
		t.Run(string(role), func(t *testing.T) {
			value := *config.BrowserProcess
			if role == config.DataPlaneDesktop {
				value = *config.DesktopProcess
			}
			value.Role = role
			value.Enabled = true
			value.SchemaVersion = config.DataPlaneProductionSchemaV3
			value.DeploymentLevel = config.ProviderProductionLevel
			directory := t.TempDir()
			path := func(name string) string { return filepath.Join(directory, name) }
			value.Authority = config.DataPlaneAuthorityConfig{
				CredentialFile: path("credential"), DependencyFile: path("dependency"), PolicyFile: path("policy"),
				RecordingKeyRef: "kms://recording/phase6/" + string(role),
			}
			value.TLS = config.DataPlaneTLSConfig{
				SecurityProfilePath: path("profile"), SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
				PeerCRLRoleFile: path("peer-role"), PeerCRLRoleDigest: "sha256:" + strings.Repeat("b", 64),
				PeerCRLSourceMappingDigest: "sha256:" + strings.Repeat("c", 64),
				AgentSocket:                path("agent.sock"), AgentUID: 501, AgentGID: 20, OperationTimeoutMillis: 3000,
			}
			transport, _ := privateLiveTestTLS(t)
			peer := newPrivateLiveTestPeer()
			graph := ApplicationGraph{
				Private: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), TLS: transport,
				PrivatePeer: peer, PrivateSignerProbe: func(context.Context) error { return nil },
				PrivateConnectionAge: time.Minute, Ready: func(context.Context) error { return nil },
				Start: func(ctx context.Context) error { <-ctx.Done(); return nil },
			}
			composition, err := NewWithGraph(context.Background(), &value, graph)
			if err != nil || composition.private == nil {
				t.Fatalf("live private graph: %v", err)
			}
			private, ok := composition.private.(*privateTLSServer)
			if !ok || private.connections == nil || private.peer != peer {
				t.Fatal("v3 private graph did not select tracked live transport")
			}
			missing := graph
			missing.PrivatePeer = nil
			if _, err := NewWithGraph(context.Background(), &value, missing); err == nil {
				t.Fatal("v3 accepted private transport without peer guard")
			}
			static := graph
			static.TLS = transport.Clone()
			static.TLS.Certificates = []tls.Certificate{{Certificate: [][]byte{[]byte("old")}}}
			if _, err := NewWithGraph(context.Background(), &value, static); err == nil {
				t.Fatal("v3 accepted static certificate alongside live signer")
			}
			value.SchemaVersion = config.DataPlaneProductionSchemaV2
			if err := graph.validate(role, value.SchemaVersion); err == nil {
				t.Fatal("v2 selected v3 live peer authority")
			}
		})
	}
}
