package productgateway

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
)

// privateBrowserV2Stream distinguishes a confirmed idle upstream close from
// an unknown CDP write outcome. A pending action that has not produced its
// exact CDP response is terminal on any transport loss, even a normal close;
// the public Gateway must not silently reconnect or replay it.
type privateBrowserV2Stream struct {
	connection      *websocket.Conn
	maxMessageBytes int64

	mu      sync.Mutex
	pending map[int64]struct{}
	closed  bool
	once    sync.Once
}

func newPrivateBrowserV2Stream(connection *websocket.Conn, limit int64) *privateBrowserV2Stream {
	return &privateBrowserV2Stream{connection: connection, maxMessageBytes: limit,
		pending: make(map[int64]struct{})}
}

func (s *privateBrowserV2Stream) Send(ctx context.Context, frame gateway.Frame) error {
	if s == nil || s.connection == nil || ctx == nil || frame.Type != gateway.TextFrame ||
		int64(len(frame.Payload)) > s.maxMessageBytes || rejectDuplicateAutomationMembers(frame.Payload) != nil {
		return gateway.ErrDownstreamUnavailable
	}
	var request struct {
		ID     int64  `json:"id"`
		Method string `json:"method"`
	}
	if json.Unmarshal(frame.Payload, &request) != nil || request.ID < 1 || request.Method == "" {
		return gateway.ErrDownstreamUnavailable
	}
	s.mu.Lock()
	if s.closed || len(s.pending) >= maxPendingActions {
		s.mu.Unlock()
		return gateway.ErrDownstreamUnavailable
	}
	if _, duplicate := s.pending[request.ID]; duplicate {
		s.mu.Unlock()
		return gateway.ErrDownstreamUnavailable
	}
	s.pending[request.ID] = struct{}{}
	s.mu.Unlock()
	if err := s.connection.Write(ctx, websocket.MessageText, append([]byte(nil), frame.Payload...)); err != nil {
		return gateway.ErrDownstreamUnavailable
	}
	return nil
}

func (s *privateBrowserV2Stream) Receive(ctx context.Context) (gateway.Frame, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return gateway.Frame{}, gateway.ErrDownstreamUnavailable
	}
	for ignoredEvents := 0; ignoredEvents <= maxPendingActions; ignoredEvents++ {
		kind, payload, err := s.connection.Read(ctx)
		if err != nil {
			switch websocket.CloseStatus(err) {
			case cdpfence.BrowserActionFenceLostCloseCode:
				return gateway.Frame{}, gateway.ErrDownstreamFenceLost
			case cdpfence.BrowserActionUnavailableCloseCode:
				return gateway.Frame{}, gateway.ErrDownstreamUnavailable
			}
			s.mu.Lock()
			pending := len(s.pending)
			s.mu.Unlock()
			if pending != 0 || websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				if ctx.Err() != nil {
					return gateway.Frame{}, ctx.Err()
				}
				return gateway.Frame{}, gateway.ErrDownstreamUnavailable
			}
			return gateway.Frame{}, io.EOF
		}
		if kind != websocket.MessageText || int64(len(payload)) > s.maxMessageBytes ||
			rejectDuplicateAutomationMembers(payload) != nil {
			return gateway.Frame{}, gateway.ErrDownstreamUnavailable
		}
		var envelope struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		if json.Unmarshal(payload, &envelope) != nil {
			return gateway.Frame{}, gateway.ErrDownstreamUnavailable
		}
		if envelope.ID < 1 {
			// CDP notifications are not public Product action responses.
			if envelope.Method == "" {
				return gateway.Frame{}, gateway.ErrDownstreamUnavailable
			}
			continue
		}
		s.mu.Lock()
		_, known := s.pending[envelope.ID]
		if known {
			delete(s.pending, envelope.ID)
		}
		s.mu.Unlock()
		if !known {
			return gateway.Frame{}, gateway.ErrDownstreamUnavailable
		}
		return gateway.Frame{Type: gateway.TextFrame, Payload: append([]byte(nil), payload...)}, nil
	}
	return gateway.Frame{}, gateway.ErrDownstreamUnavailable
}

func (s *privateBrowserV2Stream) Close(context.Context) error {
	if s == nil || s.connection == nil {
		return nil
	}
	var err error
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		err = s.connection.CloseNow()
	})
	return err
}

var _ gateway.Stream = (*privateBrowserV2Stream)(nil)
