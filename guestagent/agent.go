package guestagent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type OperationHandler func(context.Context, json.RawMessage) (any, error)

type AgentOptions struct {
	URL, GuestID      string
	BindingGeneration int64
	PrivateKey        ed25519.PrivateKey
	Handlers          map[string]OperationHandler
	ReconnectBackoff  time.Duration
	HTTPClient        *http.Client
}

type Agent struct {
	options      AgentOptions
	capabilities []string
	mu           sync.RWMutex
	connected    bool
}

func NewAgent(options AgentOptions) (*Agent, error) {
	parsedURL, parseErr := url.Parse(options.URL)
	if parseErr != nil || parsedURL.Host == "" || (parsedURL.Scheme != "ws" && parsedURL.Scheme != "wss") || parsedURL.User != nil || parsedURL.Fragment != "" ||
		!validID(options.GuestID) || options.BindingGeneration < 1 ||
		len(options.PrivateKey) != ed25519.PrivateKeySize || len(options.Handlers) == 0 || len(options.Handlers) > MaxCapabilities {
		return nil, ErrInvalid
	}
	capabilities := make([]string, 0, len(options.Handlers))
	for capability, handler := range options.Handlers {
		if !validID(capability) || handler == nil {
			return nil, ErrInvalid
		}
		capabilities = append(capabilities, capability)
	}
	options.PrivateKey = append(ed25519.PrivateKey(nil), options.PrivateKey...)
	if options.ReconnectBackoff == 0 {
		options.ReconnectBackoff = 100 * time.Millisecond
	}
	if options.ReconnectBackoff < 10*time.Millisecond || options.ReconnectBackoff > 30*time.Second {
		return nil, ErrInvalid
	}
	return &Agent{options: options, capabilities: capabilities}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrInvalid
	}
	a.setConnected(false)
	for {
		err := a.connect(ctx)
		if errors.Is(err, ErrIncompatible) || errors.Is(err, ErrUnauthorized) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(a.options.ReconnectBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Ready reports whether the Guest has an authenticated, currently serving
// connection. A configured outbound URL or a successful process start is not
// sufficient for role readiness.
func (a *Agent) Ready(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.RLock()
	connected := a.connected
	a.mu.RUnlock()
	if !connected {
		return ErrUnavailable
	}
	return nil
}

func (a *Agent) connect(ctx context.Context) error {
	connection, response, err := websocket.Dial(ctx, a.options.URL, &websocket.DialOptions{HTTPClient: a.options.HTTPClient, Subprotocols: []string{Subprotocol}})
	if err != nil {
		if response != nil && response.StatusCode == http.StatusUnauthorized {
			return ErrUnauthorized
		}
		return ErrUnavailable
	}
	defer connection.CloseNow()
	connection.SetReadLimit(MaxMessageBytes)
	var challenge Challenge
	if err := readJSON(ctx, connection, &challenge); err != nil {
		return ErrUnavailable
	}
	clientNonce, err := randomNonce()
	if err != nil {
		return ErrUnavailable
	}
	hello := Hello{Type: "hello", GuestID: a.options.GuestID, BindingGeneration: a.options.BindingGeneration, ProtocolVersion: ProtocolVersion, Capabilities: append([]string(nil), a.capabilities...), ClientNonce: clientNonce}
	auth := AuthRequest{Hello: hello, Challenge: challenge}
	signing, err := auth.SigningBytes()
	if err != nil {
		return err
	}
	hello.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(a.options.PrivateKey, signing))
	if err := writeJSON(ctx, connection, hello); err != nil {
		return ErrUnavailable
	}
	var welcome Welcome
	if err := readJSON(ctx, connection, &welcome); err != nil {
		return ErrUnauthorized
	}
	if welcome.Type != "welcome" || welcome.ProtocolVersion != ProtocolVersion || welcome.BindingGeneration != a.options.BindingGeneration || !subset(welcome.Capabilities, a.capabilities) {
		return ErrIncompatible
	}
	a.setConnected(true)
	defer a.setConnected(false)
	return a.serve(ctx, connection, welcome.Capabilities)
}

func (a *Agent) setConnected(value bool) {
	a.mu.Lock()
	a.connected = value
	a.mu.Unlock()
}

func (a *Agent) serve(ctx context.Context, connection *websocket.Conn, selected []string) error {
	connectionCtx, stopConnection := context.WithCancel(ctx)
	defer stopConnection()
	allowed := make(map[string]OperationHandler, len(selected))
	for _, capability := range selected {
		allowed[capability] = a.options.Handlers[capability]
	}
	writeMu := &sync.Mutex{}
	running := make(map[string]context.CancelFunc)
	var runningMu sync.Mutex
	sem := make(chan struct{}, MaxInFlight)
	for {
		messageType, document, err := connection.Read(connectionCtx)
		if err != nil {
			return ErrUnavailable
		}
		if messageType != websocket.MessageText {
			return ErrInvalid
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(document, &envelope); err != nil {
			return ErrInvalid
		}
		switch envelope.Type {
		case "cancel":
			var cancelMessage Cancel
			if DecodeStrict(document, &cancelMessage) != nil {
				return ErrInvalid
			}
			runningMu.Lock()
			cancel := running[cancelMessage.RequestID]
			runningMu.Unlock()
			if cancel != nil {
				cancel()
			}
		case "request":
			var request Request
			if DecodeStrict(document, &request) != nil || !validID(request.RequestID) || !validID(request.Operation) {
				return ErrInvalid
			}
			deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
			if err != nil || deadline.Before(time.Now()) || deadline.After(time.Now().Add(30*time.Second)) {
				return ErrInvalid
			}
			handler := allowed[request.Operation]
			if handler == nil {
				if err := agentWrite(ctx, connection, writeMu, Response{Type: "response", RequestID: request.RequestID, OK: false, ErrorCode: "capability_unavailable"}); err != nil {
					return ErrUnavailable
				}
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-connectionCtx.Done():
				return connectionCtx.Err()
			default:
				if err := agentWrite(ctx, connection, writeMu, Response{Type: "response", RequestID: request.RequestID, OK: false, ErrorCode: "capacity_exhausted"}); err != nil {
					return ErrUnavailable
				}
				continue
			}
			opCtx, cancel := context.WithDeadline(connectionCtx, deadline)
			runningMu.Lock()
			running[request.RequestID] = cancel
			runningMu.Unlock()
			go func(request Request) {
				defer func() {
					cancel()
					<-sem
					runningMu.Lock()
					delete(running, request.RequestID)
					runningMu.Unlock()
				}()
				value, operationErr := handler(opCtx, append(json.RawMessage(nil), request.Payload...))
				response := Response{Type: "response", RequestID: request.RequestID, OK: operationErr == nil}
				if operationErr != nil {
					response.ErrorCode = "operation_failed"
				} else if encoded, err := json.Marshal(value); err != nil || int64(len(encoded)) > MaxMessageBytes {
					response.OK = false
					response.ErrorCode = "invalid_result"
				} else {
					response.Payload = encoded
				}
				writeCtx, writeCancel := context.WithTimeout(connectionCtx, 2*time.Second)
				_ = agentWrite(writeCtx, connection, writeMu, response)
				writeCancel()
			}(request)
		default:
			return ErrInvalid
		}
	}
}

func agentWrite(ctx context.Context, connection *websocket.Conn, mu *sync.Mutex, value any) error {
	document, err := encodeMessage(value)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	return connection.Write(ctx, websocket.MessageText, document)
}
