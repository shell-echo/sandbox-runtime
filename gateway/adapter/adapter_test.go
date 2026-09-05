package adapter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestNewWebSocketServerFailsClosed(t *testing.T) {
	admission := func(context.Context, *http.Request) error { return nil }
	for _, options := range []WebSocketOptions{
		{},
		{Admission: admission, MaxFrameBytes: -1},
		{Admission: admission, MaxFrameBytes: MaxFrameBytes + 1},
		{Admission: admission, OriginPatterns: []string{"*"}},
		{Admission: admission, OriginPatterns: []string{"*.example.test"}},
		{Admission: admission, OriginPatterns: []string{"https://example.test/path"}},
	} {
		server, err := NewWebSocketServer(options)
		if server != nil || !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("NewWebSocketServer(%+v) = %v, %v; want nil, invalid options", options, server, err)
		}
	}
	server, err := NewWebSocketServer(WebSocketOptions{
		Admission: admission, OriginPatterns: []string{"https://gateway.example.test"}, MaxFrameBytes: 7,
	})
	if err != nil || server == nil {
		t.Fatalf("NewWebSocketServer() = %v, %v", server, err)
	}
}

func TestWebSocketUpgradeAdmissionAndBidirectionalBinary(t *testing.T) {
	var gotHeader, gotOrigin string
	server := mustWebSocketServer(t, WebSocketOptions{
		Admission: func(_ context.Context, request *http.Request) error {
			gotHeader = request.Header.Get("X-Caller-Authorization")
			gotOrigin = request.Header.Get("Origin")
			return nil
		},
	})
	endpoint, streams := startWebSocketServer(t, server)
	client := dialWebSocket(t, endpoint, http.Header{
		"Origin":                 {strings.Replace(endpoint, "ws://", "http://", 1)},
		"X-Caller-Authorization": {"caller-token"},
	})
	t.Cleanup(func() { _ = client.CloseNow() })
	stream := awaitStream(t, streams)

	if gotHeader != "caller-token" || gotOrigin == "" {
		t.Fatalf("admission observed header=%q origin=%q", gotHeader, gotOrigin)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Write(ctx, websocket.MessageBinary, []byte("from-client")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	frame, err := stream.Receive(ctx)
	if err != nil {
		t.Fatalf("stream receive: %v", err)
	}
	if frame.Type != gateway.BinaryFrame || string(frame.Payload) != "from-client" {
		t.Fatalf("received frame = %#v", frame)
	}
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.BinaryFrame, Payload: []byte("from-gateway")}); err != nil {
		t.Fatalf("stream send: %v", err)
	}
	messageType, payload, err := client.Read(ctx)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if messageType != websocket.MessageBinary || string(payload) != "from-gateway" {
		t.Fatalf("client message = %v, %q", messageType, payload)
	}
}

func TestWebSocketRejectsFailedAdmissionBeforeUpgrade(t *testing.T) {
	server := mustWebSocketServer(t, WebSocketOptions{
		Admission: func(context.Context, *http.Request) error { return errors.New("denied") },
	})
	endpoint, _ := startWebSocketServer(t, server)
	connection, response, err := websocket.Dial(context.Background(), endpoint, nil)
	if connection != nil {
		_ = connection.CloseNow()
		t.Fatal("unexpected upgraded connection")
	}
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("dial = %v, response %#v; want 403 rejection", err, response)
	}
}

func TestWebSocketOriginPolicyRejectsCrossOriginByDefault(t *testing.T) {
	server := mustWebSocketServer(t, WebSocketOptions{Admission: func(context.Context, *http.Request) error { return nil }})
	endpoint, _ := startWebSocketServer(t, server)
	connection, response, err := websocket.Dial(context.Background(), endpoint, &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {"https://untrusted.example.test"}},
	})
	if connection != nil {
		_ = connection.CloseNow()
		t.Fatal("unexpected cross-origin upgraded connection")
	}
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin dial = %v, response %#v; want 403 rejection", err, response)
	}
}

func TestWebSocketHandlesControlFramesAndCloseOutsideDataPlane(t *testing.T) {
	server := mustWebSocketServer(t, WebSocketOptions{Admission: func(context.Context, *http.Request) error { return nil }})
	endpoint, streams := startWebSocketServer(t, server)
	client := dialWebSocket(t, endpoint, nil)
	stream := awaitStream(t, streams)
	t.Cleanup(func() { _ = client.CloseNow() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientReads := make(chan error, 1)
	go func() {
		_, _, err := client.Read(ctx)
		clientReads <- err
	}()
	received := make(chan receiveResult, 1)
	go func() {
		frame, err := stream.Receive(ctx)
		received <- receiveResult{frame: frame, err: err}
	}()
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("client ping: %v", err)
	}
	if err := client.Write(ctx, websocket.MessageText, []byte("terminal input")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	result := awaitReceive(t, received)
	if result.err != nil || result.frame.Type != gateway.TextFrame || string(result.frame.Payload) != "terminal input" {
		t.Fatalf("receive after ping = %#v, %v", result.frame, result.err)
	}

	closed := make(chan error, 1)
	go func() {
		_, err := stream.Receive(ctx)
		closed <- err
	}()
	if err := client.Close(websocket.StatusNormalClosure, ""); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if status := websocket.CloseStatus(awaitError(t, closed)); status != websocket.StatusNormalClosure {
		t.Fatalf("server receive close status = %v, want %v", status, websocket.StatusNormalClosure)
	}
	if status := websocket.CloseStatus(awaitError(t, clientReads)); status != websocket.StatusNormalClosure {
		t.Fatalf("client reader close status = %v, want %v", status, websocket.StatusNormalClosure)
	}
}

func TestWebSocketEnforcesInboundAndOutboundLimits(t *testing.T) {
	server := mustWebSocketServer(t, WebSocketOptions{
		Admission: func(context.Context, *http.Request) error { return nil }, MaxFrameBytes: 4,
	})
	endpoint, streams := startWebSocketServer(t, server)
	client := dialWebSocket(t, endpoint, nil)
	t.Cleanup(func() { _ = client.CloseNow() })
	stream := awaitStream(t, streams)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := stream.Send(ctx, gateway.Frame{Type: gateway.BinaryFrame, Payload: []byte("12345")}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized outbound send error = %v", err)
	}
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.PingFrame}); !errors.Is(err, ErrUnsupportedFrame) {
		t.Fatalf("control send error = %v", err)
	}
	if err := client.Write(ctx, websocket.MessageBinary, []byte("12345")); err != nil {
		t.Fatalf("oversized client write: %v", err)
	}
	if _, err := stream.Receive(ctx); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized inbound receive error = %v", err)
	}
	if _, _, err := client.Read(ctx); websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Fatalf("client close status = %v, want %v (error %v)", websocket.CloseStatus(err), websocket.StatusMessageTooBig, err)
	}
}

func TestWebSocketHonorsCanceledContextsAndCloseDeadline(t *testing.T) {
	server := mustWebSocketServer(t, WebSocketOptions{Admission: func(context.Context, *http.Request) error { return nil }})
	endpoint, streams := startWebSocketServer(t, server)
	client := dialWebSocket(t, endpoint, nil)
	t.Cleanup(func() { _ = client.CloseNow() })
	stream := awaitStream(t, streams)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stream.Receive(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled receive error = %v", err)
	}
	if err := stream.Send(canceled, gateway.Frame{Type: gateway.BinaryFrame}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled send error = %v", err)
	}
	receiveDone := make(chan error, 1)
	go func() {
		_, err := stream.Receive(context.Background())
		receiveDone <- err
	}()
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer closeCancel()
	if err := stream.Close(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded close error = %v", err)
	}
	if err := awaitError(t, receiveDone); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("receive after local close error = %v; want closed pipe", err)
	}
}

func TestWebSocketCanceledReceivePreservesConnection(t *testing.T) {
	server := mustWebSocketServer(t, WebSocketOptions{Admission: func(context.Context, *http.Request) error { return nil }})
	endpoint, streams := startWebSocketServer(t, server)
	client := dialWebSocket(t, endpoint, nil)
	t.Cleanup(func() { _ = client.CloseNow() })
	stream := awaitStream(t, streams)

	readCtx, cancelRead := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelRead()
	if _, err := stream.Receive(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled receive error = %v; want deadline exceeded", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Write(ctx, websocket.MessageText, []byte("still-open")); err != nil {
		t.Fatalf("client write after canceled receive: %v", err)
	}
	frame, err := stream.Receive(ctx)
	if err != nil || frame.Type != gateway.TextFrame || string(frame.Payload) != "still-open" {
		t.Fatalf("receive after cancellation = %#v, %v", frame, err)
	}
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.BinaryFrame, Payload: []byte("response")}); err != nil {
		t.Fatalf("stream send after canceled receive: %v", err)
	}
	messageType, payload, err := client.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary || string(payload) != "response" {
		t.Fatalf("client read after cancellation = %v, %q, %v", messageType, payload, err)
	}
}

func TestWebSocketReceiveReportsAbruptDisconnect(t *testing.T) {
	server := mustWebSocketServer(t, WebSocketOptions{Admission: func(context.Context, *http.Request) error { return nil }})
	endpoint, streams := startWebSocketServer(t, server)
	client := dialWebSocket(t, endpoint, nil)
	stream := awaitStream(t, streams)
	received := make(chan receiveResult, 1)
	go func() {
		frame, err := stream.Receive(context.Background())
		received <- receiveResult{frame: frame, err: err}
	}()
	if err := client.CloseNow(); err != nil {
		t.Fatalf("abrupt client close: %v", err)
	}
	result := awaitReceive(t, received)
	if result.err == nil {
		t.Fatalf("abrupt disconnect returned frame %#v without error", result.frame)
	}
}

func TestTerminalStreamTransfersBoundedBytesAndPartialWrites(t *testing.T) {
	backend := &memoryTerminal{readData: []byte("abcdef"), writeChunk: 2}
	stream, err := NewTerminalStream(backend, TerminalOptions{MaxFrameBytes: 4})
	if err != nil {
		t.Fatalf("NewTerminalStream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := stream.Receive(ctx)
	if err != nil || first.Type != gateway.BinaryFrame || string(first.Payload) != "abcd" {
		t.Fatalf("first read = %#v, %v", first, err)
	}
	second, err := stream.Receive(ctx)
	if err != nil || second.Type != gateway.BinaryFrame || string(second.Payload) != "ef" {
		t.Fatalf("second read = %#v, %v", second, err)
	}
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.TextFrame, Payload: []byte("abcd")}); err != nil {
		t.Fatalf("partial write send: %v", err)
	}
	if got := backend.written(); got != "abcd" {
		t.Fatalf("backend wrote %q", got)
	}
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.BinaryFrame, Payload: []byte("12345")}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized terminal send error = %v", err)
	}
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.CloseFrame}); !errors.Is(err, ErrUnsupportedFrame) {
		t.Fatalf("terminal control frame error = %v", err)
	}
	if err := stream.Close(ctx); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := stream.Close(ctx); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if calls := backend.closeCalls(); calls != 1 {
		t.Fatalf("backend close calls = %d", calls)
	}
}

func TestTerminalStreamHonorsReadWriteCancellation(t *testing.T) {
	blocked := &memoryTerminal{
		read: func(ctx context.Context, _ []byte) (int, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		},
		write: func(ctx context.Context, _ []byte) (int, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		},
	}
	stream, err := NewTerminalStream(blocked, TerminalOptions{})
	if err != nil {
		t.Fatalf("NewTerminalStream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := stream.Receive(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked receive error = %v", err)
	}
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.BinaryFrame, Payload: []byte("x")}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked send error = %v", err)
	}
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if err := stream.Close(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled close error = %v", err)
	}
	if calls := blocked.closeCalls(); calls != 0 {
		t.Fatalf("canceled close called backend %d times", calls)
	}
}

type receiveResult struct {
	frame gateway.Frame
	err   error
}

func mustWebSocketServer(t *testing.T, options WebSocketOptions) *WebSocketServer {
	t.Helper()
	server, err := NewWebSocketServer(options)
	if err != nil {
		t.Fatalf("NewWebSocketServer: %v", err)
	}
	return server
}

func startWebSocketServer(t *testing.T, adapter *WebSocketServer) (string, <-chan gateway.Stream) {
	t.Helper()
	streams := make(chan gateway.Stream, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		stream, err := adapter.Upgrade(w, request)
		if err != nil {
			return
		}
		streams <- stream
	}))
	t.Cleanup(server.Close)
	return strings.Replace(server.URL, "http://", "ws://", 1), streams
}

func dialWebSocket(t *testing.T, endpoint string, header http.Header) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	return connection
}

func awaitStream(t *testing.T, streams <-chan gateway.Stream) gateway.Stream {
	t.Helper()
	select {
	case stream := <-streams:
		return stream
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for upgraded stream")
		return nil
	}
}

func awaitReceive(t *testing.T, results <-chan receiveResult) receiveResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for receive")
		return receiveResult{}
	}
}

func awaitError(t *testing.T, results <-chan error) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error")
		return nil
	}
}

type memoryTerminal struct {
	mu         sync.Mutex
	readData   []byte
	writes     []byte
	writeChunk int
	closeCount int
	read       func(context.Context, []byte) (int, error)
	write      func(context.Context, []byte) (int, error)
}

func (s *memoryTerminal) Read(ctx context.Context, payload []byte) (int, error) {
	if s.read != nil {
		return s.read(ctx, payload)
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(payload, s.readData)
	s.readData = s.readData[n:]
	return n, nil
}

func (s *memoryTerminal) Write(ctx context.Context, payload []byte) (int, error) {
	if s.write != nil {
		return s.write(ctx, payload)
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(payload)
	if s.writeChunk > 0 && n > s.writeChunk {
		n = s.writeChunk
	}
	s.writes = append(s.writes, payload[:n]...)
	return n, nil
}

func (s *memoryTerminal) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCount++
	return nil
}

func (s *memoryTerminal) written() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.writes)
}

func (s *memoryTerminal) closeCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeCount
}
