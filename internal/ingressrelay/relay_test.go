package ingressrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func testListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func testMapping(id string, frontend, upstream net.Listener) Mapping {
	return Mapping{ID: id, FrontendAddress: frontend.Addr().String(), UpstreamAddress: upstream.Addr().String(),
		MaxConnections: 1, DialTimeout: time.Second, IdleTimeout: time.Second,
		MaxLifetime: 5 * time.Second, DrainTimeout: time.Second, BufferBytes: 4 << 10}
}

func testRelay(t *testing.T, gateways [2]net.Listener, upstreams [2]net.Listener) *Relay {
	t.Helper()
	value, err := newRelay(Config{Mappings: []Mapping{
		testMapping("gateway-public", gateways[0], upstreams[0]),
		testMapping("product-public", gateways[1], upstreams[1]),
	}}, true)
	if err != nil {
		t.Fatal(err)
	}
	value.listen = func(_ context.Context, _, address string) (net.Listener, error) {
		for _, listener := range gateways {
			if listener.Addr().String() == address {
				return listener, nil
			}
		}
		return nil, errors.New("undeclared listener")
	}
	return value
}

func testUpstream(t *testing.T, listener net.Listener, marker string) {
	t.Helper()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				body, _ := io.ReadAll(io.LimitReader(connection, 1024))
				_, _ = connection.Write(append([]byte(marker), body...))
			}()
		}
	}()
}

func TestRelayForwardsTwoFixedMappingsAndHalfCloses(t *testing.T) {
	frontends := [2]net.Listener{testListener(t), testListener(t)}
	upstreams := [2]net.Listener{testListener(t), testListener(t)}
	testUpstream(t, upstreams[0], "G:")
	testUpstream(t, upstreams[1], "P:")
	relay := testRelay(t, frontends, upstreams)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- relay.Serve(ctx) }()
	for index, expected := range []string{"G:hello", "P:hello"} {
		connection, err := net.DialTimeout("tcp4", frontends[index].Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = connection.Write([]byte("hello"))
		if err := connection.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(io.LimitReader(connection, 128))
		_ = connection.Close()
		if err != nil || string(response) != expected {
			t.Fatalf("mapping %d response=%q err=%v", index, response, err)
		}
	}
	cancel()
	if err := <-result; err != nil || relay.ActiveConnections() != 0 {
		t.Fatalf("drain err=%v active=%d", err, relay.ActiveConnections())
	}
}

func TestRelayRejectsCapacityAndClosesOnCancel(t *testing.T) {
	frontends := [2]net.Listener{testListener(t), testListener(t)}
	upstreams := [2]net.Listener{testListener(t), testListener(t)}
	relay := testRelay(t, frontends, upstreams)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- relay.Serve(ctx) }()
	first, err := net.DialTimeout("tcp4", frontends[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	deadline := time.Now().Add(time.Second)
	for relay.ActiveConnections() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if relay.ActiveConnections() < 1 {
		t.Fatal("first connection was not admitted")
	}
	second, err := net.DialTimeout("tcp4", frontends[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	_, err = second.Read(buffer)
	_ = second.Close()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("capacity connection not closed: %v", err)
	}
	cancel()
	if err := <-result; err != nil || relay.ActiveConnections() != 0 {
		t.Fatalf("cancel drain err=%v active=%d", err, relay.ActiveConnections())
	}
}

func TestRelayRejectsUnboundedOrDynamicEndpoints(t *testing.T) {
	base := Config{Mappings: []Mapping{
		{ID: "gateway-public", FrontendAddress: "10.0.0.2:8445", UpstreamAddress: "10.1.0.3:8445",
			MaxConnections: 1, DialTimeout: time.Second, IdleTimeout: time.Second, MaxLifetime: time.Minute, DrainTimeout: time.Second, BufferBytes: 4 << 10},
		{ID: "product-public", FrontendAddress: "10.0.0.2:8444", UpstreamAddress: "10.2.0.3:8444",
			MaxConnections: 1, DialTimeout: time.Second, IdleTimeout: time.Second, MaxLifetime: time.Minute, DrainTimeout: time.Second, BufferBytes: 4 << 10},
	}}
	if _, err := New(base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"extra mapping":      func(c *Config) { c.Mappings = append(c.Mappings, c.Mappings[0]) },
		"wrong ID":           func(c *Config) { c.Mappings[0].ID = "socks-proxy" },
		"wildcard frontend":  func(c *Config) { c.Mappings[0].FrontendAddress = "0.0.0.0:8445" },
		"public frontend":    func(c *Config) { c.Mappings[0].FrontendAddress = "8.8.8.8:8445" },
		"hostname upstream":  func(c *Config) { c.Mappings[0].UpstreamAddress = "example.test:8445" },
		"public upstream":    func(c *Config) { c.Mappings[0].UpstreamAddress = "8.8.8.8:443" },
		"shared upstream":    func(c *Config) { c.Mappings[1].UpstreamAddress = c.Mappings[0].UpstreamAddress },
		"IPv6":               func(c *Config) { c.Mappings[0].FrontendAddress = "[::1]:8445" },
		"other frontend":     func(c *Config) { c.Mappings[1].FrontendAddress = "10.9.0.2:8444" },
		"unbounded capacity": func(c *Config) { c.Mappings[0].MaxConnections = 0 },
		"unbounded idle":     func(c *Config) { c.Mappings[0].IdleTimeout = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Mappings = append([]Mapping(nil), base.Mappings...)
			mutate(&candidate)
			if _, err := New(candidate); err == nil {
				t.Fatal("unbounded ingress authority accepted")
			}
		})
	}
}
