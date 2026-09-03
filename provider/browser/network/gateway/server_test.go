package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestHTTPEnforcesHostAndPinsResolvedAddress(t *testing.T) {
	var dialed string
	server := testServer(t,
		resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if network != "ip" || host != "allowed.example" {
				t.Fatalf("lookup = %q, %q", network, host)
			}
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		dialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
			dialed = network + ":" + address
			client, upstream := net.Pipe()
			go func() {
				defer upstream.Close()
				request, err := http.ReadRequest(bufio.NewReader(upstream))
				if err != nil {
					t.Errorf("read upstream request: %v", err)
					return
				}
				if request.Host != "allowed.example" || request.URL.Path != "/path" {
					t.Errorf("upstream request = %s %s", request.Host, request.URL.Path)
				}
				_, _ = io.WriteString(upstream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nX-Test: yes\r\n\r\nok")
			}()
			return client, nil
		}),
	)
	request := httptest.NewRequest(http.MethodGet, "/path", nil)
	request.Host = "allowed.example:80"
	response := httptest.NewRecorder()
	server.serveHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "ok" || response.Header().Get("X-Test") != "yes" {
		t.Fatalf("response = %d %q %#v", response.Code, response.Body.String(), response.Header())
	}
	if dialed != "tcp:8.8.8.8:80" {
		t.Fatalf("dialed = %q", dialed)
	}
}

func TestHTTPRejectsDeniedHostAndDNSRebinding(t *testing.T) {
	var dials atomic.Int32
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("must not dial")
	})
	for _, test := range []struct {
		name      string
		host      string
		addresses []netip.Addr
	}{
		{name: "unlisted", host: "denied.example", addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		{name: "wrong port", host: "allowed.example:8080", addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		{name: "mixed public private", host: "allowed.example", addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := testServer(t, resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				return test.addresses, nil
			}), dialer)
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Host = test.host
			response := httptest.NewRecorder()
			server.serveHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
	if dials.Load() != 0 {
		t.Fatalf("unsafe requests dialed %d times", dials.Load())
	}
}

func TestTLSReplaysAllowedClientHelloToPinnedAddress(t *testing.T) {
	seenHost := make(chan string, 1)
	var dialed string
	server := testServer(t, nil, dialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = network + ":" + address
		gateway, upstream := net.Pipe()
		go func() {
			defer upstream.Close()
			parser := tls.Server(upstream, &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					seenHost <- hello.ServerName
					return nil, errors.New("captured")
				},
			})
			_ = parser.Handshake()
		}()
		return gateway, nil
	}))
	client, accepted := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.handleTLS(t.Context(), accepted)
		close(done)
	}()
	tlsClient := tls.Client(client, &tls.Config{ServerName: "allowed.example", MinVersion: tls.VersionTLS12})
	_ = tlsClient.HandshakeContext(t.Context())
	_ = tlsClient.Close()
	select {
	case host := <-seenHost:
		if host != "allowed.example" {
			t.Fatalf("replayed SNI = %q", host)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive ClientHello")
	}
	if dialed != "tcp:1.1.1.1:443" {
		t.Fatalf("dialed = %q", dialed)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TLS handler did not exit")
	}
}

func TestTLSRejectsUnlistedSNIWithoutDial(t *testing.T) {
	var dials atomic.Int32
	server := testServer(t, nil, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("must not dial")
	}))
	client, accepted := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.handleTLS(t.Context(), accepted)
		close(done)
	}()
	tlsClient := tls.Client(client, &tls.Config{ServerName: "denied.example", MinVersion: tls.VersionTLS12})
	_ = tlsClient.HandshakeContext(t.Context())
	_ = tlsClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("denied TLS handler did not exit")
	}
	if dials.Load() != 0 {
		t.Fatalf("denied TLS dialed %d times", dials.Load())
	}
}

func TestProxyContextStopsOnCancellation(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		proxyContext(ctx, left, right)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop")
	}
	for name, connection := range map[string]net.Conn{"left": leftPeer, "right": rightPeer} {
		_ = connection.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := connection.Write([]byte("x")); err == nil {
			t.Errorf("%s peer remained writable", name)
		}
		_ = connection.Close()
	}
}

func TestDestinationHost(t *testing.T) {
	for value, want := range map[string]string{"example.com": "example.com", "EXAMPLE.COM.": "example.com", "example.com:443": "example.com"} {
		got, err := destinationHost(value, TLSPort)
		if err != nil || got != want {
			t.Errorf("destinationHost(%q) = %q, %v", value, got, err)
		}
	}
	for _, value := range []string{"example.com:80", "127.0.0.1", "[::1]", "user@example.com", "example"} {
		if _, err := destinationHost(value, TLSPort); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("destinationHost(%q) error = %v", value, err)
		}
	}
}

func testServer(t *testing.T, resolver Resolver, dialer Dialer) *Server {
	t.Helper()
	if resolver == nil {
		resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		})
	}
	if dialer == nil {
		dialer = dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unexpected dial")
		})
	}
	server, err := New(Config{
		GatewayAddress: "10.88.0.2",
		Policy:         Policy{Reference: "browser-egress-policy-1", AllowedHosts: []string{"allowed.example", "*.assets.example"}},
	}, resolver, dialer)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestCopyResponseHeadersDropsHopByHopFields(t *testing.T) {
	source := http.Header{"Connection": []string{"close"}, "X-Test": []string{"ok"}}
	destination := make(http.Header)
	copyResponseHeaders(destination, source)
	if destination.Get("Connection") != "" || !strings.EqualFold(destination.Get("X-Test"), "ok") {
		t.Fatalf("headers = %#v", destination)
	}
}
