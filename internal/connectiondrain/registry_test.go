package connectiondrain

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDrainClosesHijackedHTTPConnection(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	registry, err := New(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := registry.Wrap(raw)
	if err != nil {
		t.Fatal(err)
	}
	hijacked := make(chan struct{}, 1)
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		connection, buffered, hijackErr := writer.(http.Hijacker).Hijack()
		if hijackErr != nil {
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
		_ = buffered.Flush()
		hijacked <- struct{}{}
		// The upgraded protocol owns this connection. net/http.Shutdown does
		// not close it; the registry must retain and drain it explicitly.
		_ = connection
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer registry.Drain()
	client, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(client, "GET /upgrade HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "101 Switching Protocols") {
		t.Fatalf("hijack response = %q, %v", line, err)
	}
	select {
	case <-hijacked:
	case <-time.After(time.Second):
		t.Fatal("HTTP connection was not hijacked")
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if registry.Active() != 1 {
		t.Fatal("net/http unexpectedly owned the hijacked connection")
	}
	if count := registry.Drain(); count != 1 || registry.Active() != 0 || registry.Drain() != 0 {
		t.Fatalf("drain count=%d active=%d", count, registry.Active())
	}
	for {
		if _, err := reader.ReadByte(); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("hijacked connection close = %v", err)
			}
			break
		}
	}
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("HTTP server exit = %v", err)
	}
}

func TestConnectionLifetimeAndDrainRejectFutureAccept(t *testing.T) {
	if _, err := New(0); err == nil {
		t.Fatal("unbounded connection lifetime accepted")
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	registry, err := New(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := registry.Wrap(raw)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	client, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connection := <-accepted
	defer connection.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("expired socket read = %v", err)
	}
	if registry.Active() != 0 {
		t.Fatalf("expired connection remained registered: %d", registry.Active())
	}
	registry.Drain()
	second, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept after drain = %v", err)
	}
}

func TestCloseHookRunsExactlyOnceForDrainedSocket(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	registry, err := New(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan net.Conn, 2)
	if err := registry.OnClose(func(connection net.Conn) { closed <- connection }); err != nil {
		t.Fatal(err)
	}
	listener, err := registry.Wrap(raw)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.OnClose(func(net.Conn) {}); err == nil {
		t.Fatal("close hook changed after connection acceptance")
	}
	if registry.Drain() != 1 || registry.Drain() != 0 {
		t.Fatal("drain was not exactly once")
	}
	_ = server.Close()
	select {
	case observed := <-closed:
		if observed != server {
			t.Fatal("close hook received a different socket")
		}
	case <-time.After(time.Second):
		t.Fatal("close hook was not called")
	}
	select {
	case <-closed:
		t.Fatal("close hook called twice")
	default:
	}
}

func TestBoundedRegistryRejectsExcessBeforeAdmissionAndRecoversCapacity(t *testing.T) {
	if _, err := NewBounded(time.Minute, 0); err == nil {
		t.Fatal("zero connection capacity accepted")
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	registry, err := NewBounded(time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Drain()
	listener, err := registry.Wrap(raw)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	firstClient, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	firstServer := <-accepted
	if registry.Active() != 1 {
		t.Fatalf("first connection not registered: %d", registry.Active())
	}
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	secondClient, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	_ = secondClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := secondClient.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("over-capacity socket was not closed before admission: %v", err)
	}
	if registry.Active() != 1 {
		t.Fatalf("over-capacity socket entered registry: %d", registry.Active())
	}
	_ = firstServer.Close()
	thirdClient, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer thirdClient.Close()
	select {
	case thirdServer := <-accepted:
		defer thirdServer.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("capacity did not recover after exact close")
	}
	if registry.Active() != 1 {
		t.Fatalf("recovered capacity count = %d", registry.Active())
	}
}
