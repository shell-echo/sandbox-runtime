package adapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestBrowserStreamTransfersRFC6455MessagesAndMasksClientFrames(t *testing.T) {
	var incoming bytes.Buffer
	if err := wsutil.WriteServerMessage(&incoming, ws.OpText, []byte(`{"id":1,"result":{}}`)); err != nil {
		t.Fatal(err)
	}
	backend := &memoryBrowserStream{reader: bytes.NewReader(incoming.Bytes()), writeChunk: 2}
	stream, err := NewBrowserStream(backend, BrowserOptions{})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Receive(context.Background())
	if err != nil || frame.Type != gateway.TextFrame || string(frame.Payload) != `{"id":1,"result":{}}` {
		t.Fatalf("Receive() = %#v, %v", frame, err)
	}
	request := gateway.Frame{Type: gateway.TextFrame, Payload: []byte(`{"id":2,"method":"Browser.getVersion"}`)}
	if err := stream.Send(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	written := backend.Written()
	header, err := ws.ReadHeader(bytes.NewReader(written))
	if err != nil {
		t.Fatal(err)
	}
	if !header.Masked || header.OpCode != ws.OpText {
		t.Fatalf("client frame header = %#v; want masked text", header)
	}
	payload, operation, err := wsutil.ReadClientData(bytes.NewBuffer(written))
	if err != nil || operation != ws.OpText || !bytes.Equal(payload, request.Payload) {
		t.Fatalf("client message = %v %q, %v", operation, payload, err)
	}
}

func TestBrowserStreamHandlesFragmentationAndControlFrames(t *testing.T) {
	var incoming bytes.Buffer
	writeFrame(t, &incoming, ws.Header{Fin: false, OpCode: ws.OpText, Length: 3}, []byte("hel"))
	writeFrame(t, &incoming, ws.Header{Fin: true, OpCode: ws.OpPing, Length: 4}, []byte("ping"))
	writeFrame(t, &incoming, ws.Header{Fin: true, OpCode: ws.OpContinuation, Length: 2}, []byte("lo"))
	backend := &memoryBrowserStream{reader: bytes.NewReader(incoming.Bytes())}
	stream, err := NewBrowserStream(backend, BrowserOptions{MaxFrameBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Receive(context.Background())
	if err != nil || frame.Type != gateway.TextFrame || string(frame.Payload) != "hello" {
		t.Fatalf("Receive() = %#v, %v", frame, err)
	}
	pong, err := ws.ReadFrame(bytes.NewReader(backend.Written()))
	if err != nil {
		t.Fatal(err)
	}
	if !pong.Header.Masked || pong.Header.OpCode != ws.OpPong {
		t.Fatalf("control response = %#v; want masked pong", pong.Header)
	}
	pong = ws.UnmaskFrameInPlace(pong)
	if string(pong.Payload) != "ping" {
		t.Fatalf("pong payload = %q", pong.Payload)
	}
}

func TestBrowserStreamAnswersCloseControlFrame(t *testing.T) {
	var incoming bytes.Buffer
	closePayload := ws.NewCloseFrameBody(ws.StatusNormalClosure, "done")
	writeFrame(t, &incoming, ws.Header{Fin: true, OpCode: ws.OpClose, Length: int64(len(closePayload))}, closePayload)
	backend := &memoryBrowserStream{reader: bytes.NewReader(incoming.Bytes())}
	stream, err := NewBrowserStream(backend, BrowserOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Receive(context.Background()); err == nil {
		t.Fatal("Receive() accepted a close frame as Browser data")
	} else {
		var closed wsutil.ClosedError
		if !errors.As(err, &closed) || closed.Code != ws.StatusNormalClosure || closed.Reason != "done" {
			t.Fatalf("Receive() close error = %v", err)
		}
	}
	response, err := ws.ReadFrame(bytes.NewReader(backend.Written()))
	if err != nil {
		t.Fatal(err)
	}
	if !response.Header.Masked || response.Header.OpCode != ws.OpClose {
		t.Fatalf("close response = %#v; want masked close", response.Header)
	}
}

func TestBrowserStreamRejectsInvalidAndOversizedServerFrames(t *testing.T) {
	tests := []struct {
		name  string
		wire  func(*testing.T) []byte
		limit int64
		want  error
	}{
		{
			name: "masked server frame",
			wire: func(t *testing.T) []byte {
				var value bytes.Buffer
				if err := wsutil.WriteClientMessage(&value, ws.OpText, []byte("masked")); err != nil {
					t.Fatal(err)
				}
				return value.Bytes()
			},
			want: ErrInvalidBrowserFrame,
		},
		{
			name: "invalid UTF-8",
			wire: func(t *testing.T) []byte {
				var value bytes.Buffer
				if err := wsutil.WriteServerMessage(&value, ws.OpText, []byte{0xff}); err != nil {
					t.Fatal(err)
				}
				return value.Bytes()
			},
			want: ErrInvalidBrowserFrame,
		},
		{
			name: "single oversized frame",
			wire: func(t *testing.T) []byte {
				var value bytes.Buffer
				if err := wsutil.WriteServerMessage(&value, ws.OpBinary, []byte("12345")); err != nil {
					t.Fatal(err)
				}
				return value.Bytes()
			},
			limit: 4,
			want:  ErrFrameTooLarge,
		},
		{
			name: "fragmented message exceeds aggregate limit",
			wire: func(t *testing.T) []byte {
				var value bytes.Buffer
				writeFrame(t, &value, ws.Header{Fin: false, OpCode: ws.OpBinary, Length: 3}, []byte("123"))
				writeFrame(t, &value, ws.Header{Fin: true, OpCode: ws.OpContinuation, Length: 3}, []byte("456"))
				return value.Bytes()
			},
			limit: 4,
			want:  ErrFrameTooLarge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &memoryBrowserStream{reader: bytes.NewReader(test.wire(t))}
			stream, err := NewBrowserStream(backend, BrowserOptions{MaxFrameBytes: test.limit})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Receive(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("Receive() error = %v; want %v", err, test.want)
			}
		})
	}
}

func TestBrowserStreamValidatesSendCancellationAndClose(t *testing.T) {
	backend := &memoryBrowserStream{}
	stream, err := NewBrowserStream(backend, BrowserOptions{MaxFrameBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(context.Background(), gateway.Frame{Type: gateway.TextFrame, Payload: []byte("12345")}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized Send() error = %v", err)
	}
	if err := stream.Send(context.Background(), gateway.Frame{Type: gateway.PingFrame}); !errors.Is(err, ErrUnsupportedFrame) {
		t.Fatalf("control Send() error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stream.Send(canceled, gateway.Frame{Type: gateway.TextFrame}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Send() error = %v", err)
	}
	if err := stream.Close(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Close() error = %v", err)
	}
	if backend.CloseCalls() != 0 {
		t.Fatal("canceled Close() reached backend")
	}
	if err := stream.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if backend.CloseCalls() != 1 {
		t.Fatalf("backend close calls = %d; want one", backend.CloseCalls())
	}
}

func writeFrame(t *testing.T, target io.Writer, header ws.Header, payload []byte) {
	t.Helper()
	if err := ws.WriteFrame(target, ws.Frame{Header: header, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

type memoryBrowserStream struct {
	mu         sync.Mutex
	reader     io.Reader
	written    bytes.Buffer
	writeChunk int
	closeCalls int
}

func (s *memoryBrowserStream) Read(ctx context.Context, value []byte) (int, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reader == nil {
		return 0, io.EOF
	}
	return s.reader.Read(value)
}

func (s *memoryBrowserStream) Write(ctx context.Context, value []byte) (int, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(value)
	if s.writeChunk > 0 && count > s.writeChunk {
		count = s.writeChunk
	}
	return s.written.Write(value[:count])
}

func (s *memoryBrowserStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalls++
	return nil
}

func (s *memoryBrowserStream) Written() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.written.Bytes()...)
}

func (s *memoryBrowserStream) CloseCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeCalls
}
