package providerapi

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type testRevocationMonitor struct {
	mu      sync.Mutex
	ready   bool
	tracked map[net.Conn]bool
	forgets int
	polls   chan struct{}
}

func (m *testRevocationMonitor) Track(connection net.Conn, _ tls.ConnectionState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tracked == nil {
		m.tracked = make(map[net.Conn]bool)
	}
	m.tracked[connection] = true
	return nil
}
func (m *testRevocationMonitor) Forget(connection net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tracked[connection] {
		delete(m.tracked, connection)
		m.forgets++
	}
}
func (m *testRevocationMonitor) Poll(context.Context) error {
	select {
	case m.polls <- struct{}{}:
	default:
	}
	return nil
}
func (m *testRevocationMonitor) PollInterval() time.Duration { return time.Second }
func (m *testRevocationMonitor) Close()                      {}
func (m *testRevocationMonitor) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready
}

func TestPeerRevocationConnStateRetainsHijackUntilUnderlyingClose(t *testing.T) {
	monitor := &testRevocationMonitor{ready: true, polls: make(chan struct{}, 1)}
	callback := peerRevocationConnState(monitor)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	tlsConnection := tls.Server(server, &tls.Config{MinVersion: tls.VersionTLS13})
	callback(tlsConnection, http.StateActive)
	callback(tlsConnection, http.StateHijacked)
	monitor.mu.Lock()
	tracked := len(monitor.tracked)
	monitor.mu.Unlock()
	if tracked != 1 {
		t.Fatalf("hijacked connection was forgotten: %d", tracked)
	}
	monitor.Forget(server)
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.forgets != 1 || len(monitor.tracked) != 0 {
		t.Fatal("underlying socket close did not clean monitor exactly once")
	}
}

func TestPeerRevocationConnStateRejectsNotReady(t *testing.T) {
	monitor := &testRevocationMonitor{polls: make(chan struct{}, 1)}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	tlsConnection := tls.Server(server, &tls.Config{MinVersion: tls.VersionTLS13})
	peerRevocationConnState(monitor)(tlsConnection, http.StateActive)
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if len(monitor.tracked) != 0 {
		t.Fatal("not-ready monitor admitted active connection")
	}
}
