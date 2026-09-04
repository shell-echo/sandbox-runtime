// Package adapter provides narrow transport adapters for the Runtime Gateway.
// It deliberately keeps WebSocket and Provider terminal dependencies outside
// the gateway policy package.
package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

const (
	// DefaultMaxFrameBytes matches the WebSocket library's conservative default
	// read limit while making the adapter limit explicit at this boundary.
	DefaultMaxFrameBytes int64 = 32 << 10

	// MaxFrameBytes is the hard upper bound accepted by either adapter. Larger
	// Gateway policies require a separate reviewed protocol decision.
	MaxFrameBytes int64 = 64 << 10
)

var (
	ErrInvalidOptions      = errors.New("invalid Gateway stream adapter options")
	ErrAdmissionRejected   = errors.New("Gateway handshake admission rejected")
	ErrFrameTooLarge       = errors.New("Gateway frame exceeds configured limit")
	ErrUnsupportedFrame    = errors.New("unsupported Gateway frame type")
	ErrInvalidStream       = errors.New("invalid Gateway stream")
	ErrInvalidBrowserFrame = errors.New("invalid Browser WebSocket frame")
)

// HandshakeAdmission is caller-owned policy for the HTTP request before it is
// upgraded. It is intentionally separate from Gateway authorization, which is
// composed in P2.5f5. An enabled WebSocket edge has no allow-all fallback.
type HandshakeAdmission func(context.Context, *http.Request) error

// WebSocketOptions configure one caller-owned WebSocket edge. OriginPatterns
// are optional explicit cross-origin origins; same-origin remains enforced by
// the WebSocket library by default. Compression is always disabled.
type WebSocketOptions struct {
	Admission      HandshakeAdmission
	OriginPatterns []string
	MaxFrameBytes  int64
}

// WebSocketServer upgrades admitted HTTP requests to bounded Gateway streams.
// It does not authorize callers, resolve Provider handoffs, or start a proxy.
type WebSocketServer struct {
	admission      HandshakeAdmission
	originPatterns []string
	maxFrameBytes  int64
}

// NewWebSocketServer validates the caller-owned handshake policy before any
// listener can be exposed.
func NewWebSocketServer(options WebSocketOptions) (*WebSocketServer, error) {
	if options.Admission == nil {
		return nil, fmt.Errorf("%w: handshake admission is required", ErrInvalidOptions)
	}
	maxFrameBytes, err := normalizeFrameLimit(options.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	originPatterns := make([]string, len(options.OriginPatterns))
	for i, pattern := range options.OriginPatterns {
		if !validOriginPattern(pattern) {
			return nil, fmt.Errorf("%w: origin pattern", ErrInvalidOptions)
		}
		originPatterns[i] = pattern
	}
	return &WebSocketServer{
		admission: options.Admission, originPatterns: originPatterns, maxFrameBytes: maxFrameBytes,
	}, nil
}

// Upgrade runs the caller's admission policy before completing the WebSocket
// handshake. It writes only a generic rejection response so policy errors do
// not become endpoint or credential disclosures.
func (s *WebSocketServer) Upgrade(w http.ResponseWriter, r *http.Request) (gateway.Stream, error) {
	if s == nil || s.admission == nil || w == nil || r == nil {
		return nil, ErrInvalidStream
	}
	if err := contextError(r.Context()); err != nil {
		return nil, err
	}
	if err := s.admission(r.Context(), r); err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil, ErrAdmissionRejected
	}
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:  append([]string(nil), s.originPatterns...),
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	connection.SetReadLimit(s.maxFrameBytes)
	return &webSocketStream{
		connection: connection, maxFrameBytes: s.maxFrameBytes, closeDone: make(chan struct{}),
	}, nil
}

type webSocketStream struct {
	connection    *websocket.Conn
	maxFrameBytes int64

	closeOnce sync.Once
	closeDone chan struct{}
	closeMu   sync.Mutex
	closeErr  error
}

func (s *webSocketStream) Receive(ctx context.Context) (gateway.Frame, error) {
	if s == nil || s.connection == nil {
		return gateway.Frame{}, ErrInvalidStream
	}
	if err := contextError(ctx); err != nil {
		return gateway.Frame{}, err
	}
	messageType, payload, err := s.connection.Read(ctx)
	if err != nil {
		if errors.Is(err, websocket.ErrMessageTooBig) {
			return gateway.Frame{}, fmt.Errorf("%w: %v", ErrFrameTooLarge, err)
		}
		return gateway.Frame{}, err
	}
	if int64(len(payload)) > s.maxFrameBytes {
		return gateway.Frame{}, ErrFrameTooLarge
	}
	frame := gateway.Frame{Payload: append([]byte(nil), payload...)}
	switch messageType {
	case websocket.MessageText:
		frame.Type = gateway.TextFrame
	case websocket.MessageBinary:
		frame.Type = gateway.BinaryFrame
	default:
		return gateway.Frame{}, ErrUnsupportedFrame
	}
	return frame, nil
}

func (s *webSocketStream) Send(ctx context.Context, frame gateway.Frame) error {
	if s == nil || s.connection == nil {
		return ErrInvalidStream
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if int64(len(frame.Payload)) > s.maxFrameBytes {
		return ErrFrameTooLarge
	}
	var messageType websocket.MessageType
	switch frame.Type {
	case gateway.TextFrame:
		messageType = websocket.MessageText
	case gateway.BinaryFrame:
		messageType = websocket.MessageBinary
	default:
		return ErrUnsupportedFrame
	}
	return s.connection.Write(ctx, messageType, append([]byte(nil), frame.Payload...))
}

// Close is idempotent. A bounded context can stop waiting for the normal
// close handshake; the connection is then force-closed to release concurrent
// reads and writes. A caller that supplies an unbounded context accepts the
// WebSocket library's standards-compliant close-handshake timeout.
func (s *webSocketStream) Close(ctx context.Context) error {
	if s == nil || s.connection == nil {
		return ErrInvalidStream
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	s.closeOnce.Do(func() {
		go func() {
			err := s.connection.Close(websocket.StatusNormalClosure, "")
			s.closeMu.Lock()
			s.closeErr = err
			s.closeMu.Unlock()
			close(s.closeDone)
		}()
	})
	select {
	case <-s.closeDone:
		s.closeMu.Lock()
		err := s.closeErr
		s.closeMu.Unlock()
		return err
	case <-ctx.Done():
		go func() { _ = s.connection.CloseNow() }()
		return ctx.Err()
	}
}

// TerminalOptions configure the byte-to-frame adapter. The terminal runtime
// has no frame semantics, so every received payload is emitted as binary.
type TerminalOptions struct {
	MaxFrameBytes int64
}

// NewTerminalStream adapts a backend-neutral terminal byte stream to bounded
// Gateway frames. It neither creates a terminal nor owns reconnection policy.
func NewTerminalStream(stream terminal.Stream, options TerminalOptions) (gateway.Stream, error) {
	if stream == nil {
		return nil, ErrInvalidStream
	}
	maxFrameBytes, err := normalizeFrameLimit(options.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	return &terminalStream{stream: stream, maxFrameBytes: maxFrameBytes}, nil
}

type terminalStream struct {
	stream        terminal.Stream
	maxFrameBytes int64

	closeOnce sync.Once
	closeMu   sync.Mutex
	closeErr  error
}

func (s *terminalStream) Receive(ctx context.Context) (gateway.Frame, error) {
	if s == nil || s.stream == nil {
		return gateway.Frame{}, ErrInvalidStream
	}
	if err := contextError(ctx); err != nil {
		return gateway.Frame{}, err
	}
	payload := make([]byte, int(s.maxFrameBytes))
	n, err := s.stream.Read(ctx, payload)
	if n < 0 || n > len(payload) {
		return gateway.Frame{}, ErrInvalidStream
	}
	if n > 0 {
		return gateway.Frame{Type: gateway.BinaryFrame, Payload: append([]byte(nil), payload[:n]...)}, nil
	}
	if err != nil {
		return gateway.Frame{}, err
	}
	return gateway.Frame{}, io.ErrNoProgress
}

func (s *terminalStream) Send(ctx context.Context, frame gateway.Frame) error {
	if s == nil || s.stream == nil {
		return ErrInvalidStream
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if int64(len(frame.Payload)) > s.maxFrameBytes {
		return ErrFrameTooLarge
	}
	switch frame.Type {
	case gateway.TextFrame, gateway.BinaryFrame:
	default:
		return ErrUnsupportedFrame
	}
	payload := append([]byte(nil), frame.Payload...)
	for len(payload) > 0 {
		n, err := s.stream.Write(ctx, payload)
		if n < 0 || n > len(payload) {
			return ErrInvalidStream
		}
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Close is idempotent. terminal.Stream.Close has no context parameter, so
// this adapter checks the context before invoking it but cannot claim to
// interrupt an implementation that blocks inside Close.
func (s *terminalStream) Close(ctx context.Context) error {
	if s == nil || s.stream == nil {
		return ErrInvalidStream
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	s.closeOnce.Do(func() {
		err := s.stream.Close()
		s.closeMu.Lock()
		s.closeErr = err
		s.closeMu.Unlock()
	})
	s.closeMu.Lock()
	err := s.closeErr
	s.closeMu.Unlock()
	return err
}

func normalizeFrameLimit(limit int64) (int64, error) {
	if limit == 0 {
		return DefaultMaxFrameBytes, nil
	}
	if limit < 1 || limit > MaxFrameBytes {
		return 0, fmt.Errorf("%w: frame limit", ErrInvalidOptions)
	}
	return limit, nil
}

func validOriginPattern(pattern string) bool {
	if pattern == "" || pattern != strings.TrimSpace(pattern) || strings.Contains(pattern, "*") {
		return false
	}
	if strings.Contains(pattern, "://") {
		origin, err := url.Parse(pattern)
		return err == nil && origin.Scheme != "" && origin.Host != "" && origin.User == nil &&
			origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
	}
	return !strings.ContainsAny(pattern, "/?#")
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
