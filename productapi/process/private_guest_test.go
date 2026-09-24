package process

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/option"
)

type guestTestPeer struct {
	mu      sync.Mutex
	active  map[net.Conn]struct{}
	revoked bool
	closed  bool
}

func (p *guestTestPeer) Track(connection net.Conn, state tls.ConnectionState) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revoked || p.closed || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) != 1 {
		return errors.New("Guest peer unavailable")
	}
	p.active[connection] = struct{}{}
	return nil
}

func (p *guestTestPeer) Forget(connection net.Conn) {
	p.mu.Lock()
	delete(p.active, connection)
	p.mu.Unlock()
}

func (p *guestTestPeer) Poll(context.Context) error {
	p.mu.Lock()
	revoked := p.revoked
	connections := make([]net.Conn, 0, len(p.active))
	if revoked {
		for connection := range p.active {
			connections = append(connections, connection)
		}
	}
	p.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	if revoked {
		return errors.New("Guest peer revoked")
	}
	return nil
}

func (p *guestTestPeer) PollInterval() time.Duration { return 100 * time.Millisecond }

func (p *guestTestPeer) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.revoked && !p.closed
}

func (p *guestTestPeer) Close() {
	p.mu.Lock()
	p.closed = true
	connections := make([]net.Conn, 0, len(p.active))
	for connection := range p.active {
		connections = append(connections, connection)
	}
	p.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (p *guestTestPeer) Active() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active)
}

func privateGuestTestTLS(t *testing.T) (*tls.Config, *http.Client) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Guest test CA"},
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
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute),
			NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			leaf.URIs = []*url.URL{{Scheme: "spiffe", Host: "sandbox-runtime.test", Path: "/guest"}}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
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
			if len(state.PeerCertificates) < 1 || len(state.VerifiedChains) != 1 ||
				len(state.PeerCertificates[0].URIs) != 1 || state.PeerCertificates[0].URIs[0].String() != "spiffe://sandbox-runtime.test/guest" {
				return errors.New("wrong Guest peer identity")
			}
			return nil
		}}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{clientCertificate}}}}
	return server, client
}

func TestPrivateGuestServerOnlyAgentAndDrainsUpgradedPeer(t *testing.T) {
	transport, client := privateGuestTestTLS(t)
	peer := &guestTestPeer{active: make(map[net.Conn]struct{})}
	handlerStarted := make(chan struct{}, 1)
	hub := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		handlerStarted <- struct{}{}
		_, _, _ = connection.Read(request.Context())
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := option.HTTP{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	server, err := NewPrivateGuestServer(address, hub, transport, peer, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	server.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Startup(ctx) }()
	ws, _, err := websocket.Dial(ctx, "wss://"+address.Addr()+"/agent", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Guest Hub was not reached")
	}
	response, err := client.Get("https://" + address.Addr() + "/api/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("public API leaked onto private Guest listener: %d", response.StatusCode)
	}
	response, err = client.Get("https://" + address.Addr() + "/agent?unexpected=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("query alias reached Guest Hub: %d", response.StatusCode)
	}
	noCertificate := client.Transport.(*http.Transport).TLSClientConfig.Clone()
	noCertificate.Certificates = nil
	withoutIdentity := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: noCertificate}}
	if response, err := withoutIdentity.Get("https://" + address.Addr() + "/agent"); err == nil {
		_ = response.Body.Close()
		t.Fatal("Guest private listener admitted a certificate-less client")
	}
	deadline := time.Now().Add(2 * time.Second)
	for peer.Active() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if peer.Active() != 1 {
		t.Fatalf("tracked peers = %d, want 1", peer.Active())
	}
	peer.mu.Lock()
	peer.revoked = true
	peer.mu.Unlock()
	readContext, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()
	if _, _, err := ws.Read(readContext); err == nil {
		t.Fatal("revoked Guest WebSocket remained open")
	}
	for (peer.Active() != 0 || server.connections.Active() != 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if peer.Active() != 0 || server.connections.Active() != 0 {
		t.Fatalf("Guest socket cleanup incomplete: peers=%d sockets=%d", peer.Active(), server.connections.Active())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Guest private listener did not stop")
	}
}

func TestPrivateGuestServerRejectsStaticOrUnboundedTLS(t *testing.T) {
	transport, _ := privateGuestTestTLS(t)
	peer := &guestTestPeer{active: make(map[net.Conn]struct{})}
	address := option.HTTP{Host: "127.0.0.1", Port: 8449}
	for name, mutate := range map[string]func(*tls.Config){
		"no signer":             func(c *tls.Config) { c.GetCertificate = nil },
		"no client certificate": func(c *tls.Config) { c.ClientAuth = tls.NoClientCert },
		"TLS 1.2":               func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 },
		"no peer verification":  func(c *tls.Config) { c.VerifyConnection = nil },
		"session tickets":       func(c *tls.Config) { c.SessionTicketsDisabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := transport.Clone()
			mutate(candidate)
			if _, err := NewPrivateGuestServer(address, http.NotFoundHandler(), candidate, peer, time.Minute, 4); err == nil {
				t.Fatal("unsafe Product Guest TLS accepted")
			}
		})
	}
	if _, err := NewPrivateGuestServer(address, http.NotFoundHandler(), transport, peer, 0, 4); err == nil {
		t.Fatal("unbounded Product Guest connection accepted")
	}
	if _, err := NewPrivateGuestServer(address, http.NotFoundHandler(), transport, peer, time.Minute, 0); err == nil {
		t.Fatal("unbounded Product Guest capacity accepted")
	}
}

func TestPrivateGuestServerCapacityClosesExcessAndReopensAfterClose(t *testing.T) {
	transport, client := privateGuestTestTLS(t)
	peer := &guestTestPeer{active: make(map[net.Conn]struct{})}
	started := make(chan struct{}, 2)
	hub := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		started <- struct{}{}
		_, _, _ = connection.Read(request.Context())
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := option.HTTP{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	server, err := NewPrivateGuestServer(address, hub, transport, peer, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	server.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Startup(ctx) }()
	first, _, err := websocket.Dial(ctx, "wss://"+address.Addr()+"/agent", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseNow()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first Guest connection did not upgrade")
	}
	secondContext, stopSecond := context.WithTimeout(ctx, time.Second)
	defer stopSecond()
	if second, _, err := websocket.Dial(secondContext, "wss://"+address.Addr()+"/agent",
		&websocket.DialOptions{HTTPClient: client}); err == nil {
		second.CloseNow()
		t.Fatal("over-capacity Guest connection upgraded")
	}
	if server.connections.Active() != 1 {
		t.Fatalf("over-capacity Guest socket entered registry: %d", server.connections.Active())
	}
	first.CloseNow()
	deadline := time.Now().Add(2 * time.Second)
	for server.connections.Active() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.connections.Active() != 0 {
		t.Fatal("first Guest socket did not release capacity")
	}
	third, _, err := websocket.Dial(ctx, "wss://"+address.Addr()+"/agent", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatalf("Guest capacity did not recover: %v", err)
	}
	third.CloseNow()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("recovered Guest connection did not reach Hub")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Guest listener did not shut down")
	}
}
