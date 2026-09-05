package caller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
)

const (
	minimumTimeout = 25 * time.Millisecond
	maximumTimeout = 60 * time.Second
	maxFrameBytes  = 4 << 10
)

type heldConnection struct {
	connection *websocket.Conn
	closed     bool
	closeCode  int
}

// Caller executes the bounded durable-revocation black-box protocol.
type Caller struct {
	mu          sync.Mutex
	client      *http.Client
	transport   *http.Transport
	gateways    map[string]*url.URL
	bindings    map[string]resolvedGrantBinding
	connections map[string]heldConnection
	lastSeq     uint64
	terminated  bool
}

// New creates a caller with immutable grant bindings and TLS 1.3-only WSS.
func New(config wire.CallerConfig) (*Caller, error) {
	roots, gateways, bindings, err := prepareConfig(config)
	if err != nil {
		return nil, err
	}
	transport := newTransport(roots)
	return &Caller{
		client:      &http.Client{Transport: transport, CheckRedirect: rejectRedirect},
		transport:   transport,
		gateways:    gateways,
		bindings:    bindings,
		connections: make(map[string]heldConnection),
	}, nil
}

func newTransport(roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			RootCAs:    roots,
			ServerName: "localhost",
			NextProtos: []string{"http/1.1"},
		},
	}
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// Execute applies one command and returns only bounded, diagnostic-free data.
func (c *Caller) Execute(ctx context.Context, command wire.Command) wire.Response {
	if c == nil || ctx == nil {
		return wire.Response{Version: wire.ProtocolVersion, Sequence: command.Sequence, ErrorCode: wire.ErrorInternal}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	response := wire.Response{Version: wire.ProtocolVersion, Sequence: command.Sequence}
	if c.terminated || command.Version != wire.ProtocolVersion || command.Sequence == 0 || command.Sequence <= c.lastSeq {
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
	c.lastSeq = command.Sequence

	switch command.Action {
	case wire.ActionOpen:
		return c.open(ctx, command, response)
	case wire.ActionRoundTrip:
		return c.roundTrip(ctx, command, response)
	case wire.ActionExpectClosed:
		return c.expectClosed(ctx, command, response)
	case wire.ActionClose:
		return c.closeConnection(ctx, command, response)
	case wire.ActionShutdown:
		if !validShutdown(command) {
			response.ErrorCode = wire.ErrorInvalidCommand
			return response
		}
		c.closeAllLocked()
		c.terminated = true
		response.OK = true
		response.Outcome = wire.OutcomeTerminated
		return response
	default:
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
}

func (c *Caller) open(ctx context.Context, command wire.Command, response wire.Response) wire.Response {
	if !validOpen(command) {
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
	if _, exists := c.connections[command.ConnectionID]; exists {
		response.ErrorCode = wire.ErrorConnectionExists
		return response
	}
	base, exists := c.gateways[command.GatewayID]
	if !exists {
		response.ErrorCode = wire.ErrorUnknownGateway
		return response
	}
	binding, exists := c.bindings[command.GrantBindingID]
	if !exists {
		response.ErrorCode = wire.ErrorUnknownGrantBinding
		return response
	}

	dialURL := *base
	dialURL.Scheme = "wss"
	dialURL.Path = "/v1/browser/connect"
	query := url.Values{}
	query.Set("grant_id", binding.grantID)
	query.Set("caller_id", binding.principal.CallerID)
	query.Set("tenant_id", binding.principal.TenantID)
	query.Set("sandbox_id", binding.endpoint.SandboxID)
	query.Set("browser_session_id", binding.endpoint.BrowserSessionID)
	query.Set("capability_profile_id", binding.endpoint.CapabilityProfileID)
	query.Set("handoff_reference", binding.endpoint.HandoffReference)
	query.Set("connection_generation", strconv.FormatInt(binding.endpoint.ConnectionGeneration, 10))
	query.Set("expires_at", binding.expiresAt.Format(time.RFC3339Nano))
	dialURL.RawQuery = query.Encode()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+binding.principal.Token)
	header.Set("Origin", "https://reference-caller.invalid")
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	connection, httpResponse, err := websocket.Dial(dialCtx, dialURL.String(), &websocket.DialOptions{
		HTTPClient: c.client,
		HTTPHeader: header,
	})
	cancel()
	if httpResponse != nil && httpResponse.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResponse.Body, 1024))
		_ = httpResponse.Body.Close()
	}
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.CloseNow()
		}
		response.ErrorCode = wire.ErrorUpgradeFailed
		if httpResponse != nil {
			response.ErrorCode = wire.ErrorNotUpgraded
		}
		return response
	}
	connection.SetReadLimit(maxFrameBytes)
	c.connections[command.ConnectionID] = heldConnection{connection: connection}
	response.OK = true
	response.Outcome = wire.OutcomeOpened
	response.Upgraded = true
	return response
}

func (c *Caller) roundTrip(ctx context.Context, command wire.Command, response wire.Response) wire.Response {
	if !validConnectionCommand(command) {
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
	held, exists := c.connections[command.ConnectionID]
	if !exists {
		response.ErrorCode = wire.ErrorConnectionNotFound
		return response
	}
	marker := []byte("durable-revocation:" + strconv.FormatUint(command.Sequence, 10))
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	if err := held.connection.Write(callCtx, websocket.MessageBinary, marker); err != nil {
		c.rememberClose(command.ConnectionID, held, callCtx, err)
		response.ErrorCode = wire.ErrorRoundTripFailed
		return response
	}
	messageType, received, err := held.connection.Read(callCtx)
	if err != nil || messageType != websocket.MessageBinary || !bytesEqual(marker, received) {
		c.rememberClose(command.ConnectionID, held, callCtx, err)
		response.ErrorCode = wire.ErrorRoundTripFailed
		return response
	}
	response.OK = true
	response.Outcome = wire.OutcomeEchoed
	return response
}

func (c *Caller) expectClosed(ctx context.Context, command wire.Command, response wire.Response) wire.Response {
	if !validConnectionCommand(command) {
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
	held, exists := c.connections[command.ConnectionID]
	if !exists {
		response.ErrorCode = wire.ErrorConnectionNotFound
		return response
	}
	if held.closed {
		delete(c.connections, command.ConnectionID)
		response.OK = true
		response.Outcome = wire.OutcomeClosed
		response.CloseCode = held.closeCode
		return response
	}
	readCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	for {
		_, _, err := held.connection.Read(readCtx)
		if err == nil {
			continue
		}
		if errors.Is(readCtx.Err(), context.DeadlineExceeded) {
			response.ErrorCode = wire.ErrorCloseTimeout
			return response
		}
		status := websocket.CloseStatus(err)
		if status < 0 {
			if readCtx.Err() != nil {
				response.ErrorCode = wire.ErrorCloseFailed
				return response
			}
			status = websocket.StatusAbnormalClosure
		}
		delete(c.connections, command.ConnectionID)
		_ = held.connection.CloseNow()
		response.OK = true
		response.Outcome = wire.OutcomeClosed
		response.CloseCode = int(status)
		return response
	}
}

func (c *Caller) rememberClose(connectionID string, held heldConnection, operationCtx context.Context, err error) {
	if err == nil || operationCtx == nil || operationCtx.Err() != nil {
		return
	}
	status := websocket.CloseStatus(err)
	if status < 0 {
		status = websocket.StatusAbnormalClosure
	}
	held.closed = true
	held.closeCode = int(status)
	c.connections[connectionID] = held
	_ = held.connection.CloseNow()
}

func (c *Caller) closeConnection(ctx context.Context, command wire.Command, response wire.Response) wire.Response {
	if !validConnectionCommand(command) {
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
	held, exists := c.connections[command.ConnectionID]
	if !exists {
		response.ErrorCode = wire.ErrorConnectionNotFound
		return response
	}
	delete(c.connections, command.ConnectionID)
	closeCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	if err := closeNormal(closeCtx, held.connection); err != nil {
		if errors.Is(closeCtx.Err(), context.DeadlineExceeded) {
			response.ErrorCode = wire.ErrorCloseTimeout
		} else {
			response.ErrorCode = wire.ErrorCloseFailed
		}
		return response
	}
	response.OK = true
	response.Outcome = wire.OutcomeReleased
	return response
}

func closeNormal(ctx context.Context, connection *websocket.Conn) error {
	result := make(chan error, 1)
	go func() { result <- connection.Close(websocket.StatusNormalClosure, "released") }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		go func() { _ = connection.CloseNow() }()
		return ctx.Err()
	}
}

// Close immediately releases all process-local connection resources.
func (c *Caller) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeAllLocked()
	return nil
}

func (c *Caller) closeAllLocked() {
	for id, held := range c.connections {
		_ = held.connection.CloseNow()
		delete(c.connections, id)
	}
	c.transport.CloseIdleConnections()
}

func validOpen(command wire.Command) bool {
	return validLogicalID(command.ConnectionID) && validLogicalID(command.GatewayID) && validLogicalID(command.GrantBindingID) &&
		validDuration(command.TimeoutMillis, minimumTimeout, maximumTimeout)
}

func validConnectionCommand(command wire.Command) bool {
	return validLogicalID(command.ConnectionID) && command.GatewayID == "" && command.GrantBindingID == "" &&
		validDuration(command.TimeoutMillis, minimumTimeout, maximumTimeout)
}

func validShutdown(command wire.Command) bool {
	return command.ConnectionID == "" && command.GatewayID == "" && command.GrantBindingID == "" && command.TimeoutMillis == 0
}

func validDuration(milliseconds int64, minimum, maximum time.Duration) bool {
	return milliseconds >= minimum.Milliseconds() && milliseconds <= maximum.Milliseconds()
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
