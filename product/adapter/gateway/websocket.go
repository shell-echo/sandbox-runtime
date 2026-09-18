package productgateway

import (
	"context"
	"errors"
	"sync"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

type webSocketStream struct {
	connection    *websocket.Conn
	maxFrameBytes int64
	closeOnce     sync.Once
	closeErr      error
}

func (s *webSocketStream) Receive(ctx context.Context) (gateway.Frame, error) {
	messageType, payload, err := s.connection.Read(ctx)
	if err != nil {
		return gateway.Frame{}, err
	}
	if int64(len(payload)) > s.maxFrameBytes {
		return gateway.Frame{}, websocket.ErrMessageTooBig
	}
	if messageType != websocket.MessageBinary {
		return gateway.Frame{}, errors.New("product terminal requires binary frames")
	}
	return gateway.Frame{Type: gateway.BinaryFrame, Payload: append([]byte(nil), payload...)}, nil
}

func (s *webSocketStream) Send(ctx context.Context, frame gateway.Frame) error {
	if frame.Type != gateway.BinaryFrame || int64(len(frame.Payload)) > s.maxFrameBytes {
		return errors.New("invalid product terminal frame")
	}
	return s.connection.Write(ctx, websocket.MessageBinary, append([]byte(nil), frame.Payload...))
}

func (s *webSocketStream) Close(context.Context) error {
	s.closeOnce.Do(func() { s.closeErr = s.connection.CloseNow() })
	return s.closeErr
}

var _ gateway.Stream = (*webSocketStream)(nil)
