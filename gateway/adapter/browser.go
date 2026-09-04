package adapter

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/shell-echo/sandbox-runtime/gateway"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

// BrowserOptions configure the private post-handshake CDP WebSocket adapter.
// The limit applies to the complete logical message, including fragments.
type BrowserOptions struct {
	MaxFrameBytes int64
}

// NewBrowserStream converts RFC 6455 messages on a private Chromium stream to
// the Gateway's bounded logical frames. The Provider has already completed the
// private WebSocket handshake, so this adapter acts as the WebSocket client:
// outbound frames are masked and incoming server frames must be unmasked.
func NewBrowserStream(stream providerbrowser.Stream, options BrowserOptions) (gateway.Stream, error) {
	if stream == nil {
		return nil, ErrInvalidStream
	}
	maxFrameBytes, err := normalizeFrameLimit(options.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	return &browserStream{
		stream: stream, maxFrameBytes: maxFrameBytes,
	}, nil
}

type browserStream struct {
	stream        providerbrowser.Stream
	maxFrameBytes int64

	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeMu   sync.Mutex
	closeErr  error
}

func (s *browserStream) Receive(ctx context.Context) (gateway.Frame, error) {
	if s == nil || s.stream == nil {
		return gateway.Frame{}, ErrInvalidStream
	}
	if err := contextError(ctx); err != nil {
		return gateway.Frame{}, err
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()

	wire := browserWire{ctx: ctx, stream: s.stream}
	reader := wsutil.Reader{
		Source: wire, State: ws.StateClientSide, CheckUTF8: true,
		MaxFrameSize: s.maxFrameBytes,
	}
	handleControl := func(header ws.Header, source io.Reader) error {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		return (wsutil.ControlHandler{
			Src: source, Dst: wire, State: ws.StateClientSide, DisableSrcCiphering: true,
		}).Handle(header)
	}
	reader.OnIntermediate = handleControl

	for {
		header, err := reader.NextFrame()
		if err != nil {
			return gateway.Frame{}, browserFrameError(ctx, err)
		}
		if header.OpCode.IsControl() {
			if err := handleControl(header, &reader); err != nil {
				return gateway.Frame{}, browserFrameError(ctx, err)
			}
			continue
		}
		var frameType gateway.FrameType
		switch header.OpCode {
		case ws.OpText:
			frameType = gateway.TextFrame
		case ws.OpBinary:
			frameType = gateway.BinaryFrame
		default:
			_ = reader.Discard()
			return gateway.Frame{}, ErrUnsupportedFrame
		}
		payload, err := io.ReadAll(io.LimitReader(&reader, s.maxFrameBytes+1))
		if err != nil {
			return gateway.Frame{}, browserFrameError(ctx, err)
		}
		if int64(len(payload)) > s.maxFrameBytes {
			return gateway.Frame{}, ErrFrameTooLarge
		}
		return gateway.Frame{Type: frameType, Payload: payload}, nil
	}
}

func (s *browserStream) Send(ctx context.Context, frame gateway.Frame) error {
	if s == nil || s.stream == nil {
		return ErrInvalidStream
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if int64(len(frame.Payload)) > s.maxFrameBytes {
		return ErrFrameTooLarge
	}
	var operation ws.OpCode
	switch frame.Type {
	case gateway.TextFrame:
		operation = ws.OpText
	case gateway.BinaryFrame:
		operation = ws.OpBinary
	default:
		return ErrUnsupportedFrame
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := wsutil.WriteClientMessage(browserWire{ctx: ctx, stream: s.stream}, operation, append([]byte(nil), frame.Payload...)); err != nil {
		return browserFrameError(ctx, err)
	}
	return nil
}

func (s *browserStream) Close(ctx context.Context) error {
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

type browserWire struct {
	ctx    context.Context
	stream providerbrowser.Stream
}

func (w browserWire) Read(value []byte) (int, error) {
	return w.stream.Read(w.ctx, value)
}

func (w browserWire) Write(value []byte) (int, error) {
	written := 0
	for written < len(value) {
		count, err := w.stream.Write(w.ctx, value[written:])
		if count < 0 || count > len(value)-written {
			return written, ErrInvalidStream
		}
		written += count
		if err != nil {
			return written, err
		}
		if count == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func browserFrameError(ctx context.Context, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if errors.Is(err, wsutil.ErrFrameTooLarge) {
		return ErrFrameTooLarge
	}
	if errors.Is(err, io.EOF) {
		return err
	}
	var closed wsutil.ClosedError
	if errors.As(err, &closed) {
		return err
	}
	return errors.Join(ErrInvalidBrowserFrame, err)
}

var _ gateway.Stream = (*browserStream)(nil)
