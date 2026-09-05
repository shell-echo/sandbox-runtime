package caller

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
)

const (
	minimumTimeout  = 25 * time.Millisecond
	maximumTimeout  = 60 * time.Second
	minimumGrantTTL = 100 * time.Millisecond
	maximumGrantTTL = 10 * time.Minute
	maxFrameBytes   = 4 << 10
)

const (
	errorInvalidCommand     = "invalid_command"
	errorUnknownGateway     = "unknown_gateway"
	errorUnknownPrincipal   = "unknown_principal"
	errorUnknownEndpoint    = "unknown_endpoint"
	errorConnectionExists   = "connection_exists"
	errorConnectionNotFound = "connection_not_found"
	errorUpgradeFailed      = "upgrade_failed"
	errorNotUpgraded        = "not_upgraded"
	errorRoundTripFailed    = "round_trip_failed"
	errorCloseTimeout       = "close_timeout"
	errorCloseFailed        = "close_failed"
	errorInternal           = "internal"
)

type heldConnection struct {
	connection *websocket.Conn
	closed     bool
	closeCode  int
}

// Caller executes the bounded shared-capacity control protocol.
type Caller struct {
	mu          sync.Mutex
	client      *http.Client
	transport   *http.Transport
	gateways    map[string]*url.URL
	principals  map[string]wire.Principal
	endpoints   map[string]wire.Endpoint
	connections map[string]heldConnection
	lastSeq     uint64
	terminated  bool
}

// New creates a caller with a fixed CA and TLS 1.3-only transport.
func New(config wire.CallerConfig) (*Caller, error) {
	roots, gateways, principals, endpoints, err := prepareConfig(config)
	if err != nil {
		return nil, err
	}
	transport := newTransport(roots)
	return &Caller{
		client:      &http.Client{Transport: transport, CheckRedirect: rejectRedirect},
		transport:   transport,
		gateways:    gateways,
		principals:  principals,
		endpoints:   endpoints,
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

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// Execute applies one command and returns only bounded, diagnostic-free data.
func (c *Caller) Execute(ctx context.Context, command wire.Command) wire.Response {
	if c == nil || ctx == nil {
		return wire.Response{Version: wire.ProtocolVersion, Sequence: command.Sequence, ErrorCode: errorInternal}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	response := wire.Response{Version: wire.ProtocolVersion, Sequence: command.Sequence}
	if c.terminated || command.Version != wire.ProtocolVersion || command.Sequence == 0 || command.Sequence <= c.lastSeq {
		response.ErrorCode = errorInvalidCommand
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
			response.ErrorCode = errorInvalidCommand
			return response
		}
		c.closeAllLocked()
		c.terminated = true
		response.OK = true
		response.Outcome = wire.OutcomeTerminated
		return response
	default:
		response.ErrorCode = errorInvalidCommand
		return response
	}
}

func (c *Caller) open(ctx context.Context, command wire.Command, response wire.Response) wire.Response {
	if !validOpen(command) {
		response.ErrorCode = errorInvalidCommand
		return response
	}
	if _, exists := c.connections[command.ConnectionID]; exists {
		response.ErrorCode = errorConnectionExists
		return response
	}
	base, exists := c.gateways[command.GatewayID]
	if !exists {
		response.ErrorCode = errorUnknownGateway
		return response
	}
	principal, exists := c.principals[command.PrincipalID]
	if !exists {
		response.ErrorCode = errorUnknownPrincipal
		return response
	}
	endpoint, exists := c.endpoints[command.EndpointID]
	if !exists {
		response.ErrorCode = errorUnknownEndpoint
		return response
	}
	if principal.TenantID != endpoint.TenantID {
		response.ErrorCode = errorInvalidCommand
		return response
	}

	dialURL := *base
	dialURL.Scheme = "wss"
	dialURL.Path = "/v1/browser/connect"
	query := url.Values{}
	query.Set("grant_id", grantID(command.ConnectionID, command.Sequence))
	query.Set("caller_id", principal.CallerID)
	query.Set("tenant_id", principal.TenantID)
	query.Set("sandbox_id", endpoint.SandboxID)
	query.Set("browser_session_id", endpoint.BrowserSessionID)
	query.Set("capability_profile_id", endpoint.CapabilityProfileID)
	query.Set("handoff_reference", endpoint.HandoffReference)
	query.Set("connection_generation", strconv.FormatInt(endpoint.ConnectionGeneration, 10))
	query.Set("expires_at", time.Now().UTC().Add(time.Duration(command.GrantTTLMillis)*time.Millisecond).Format(time.RFC3339Nano))
	dialURL.RawQuery = query.Encode()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+principal.Token)
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
		response.ErrorCode = errorUpgradeFailed
		if httpResponse != nil {
			response.ErrorCode = errorNotUpgraded
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
		response.ErrorCode = errorInvalidCommand
		return response
	}
	held, exists := c.connections[command.ConnectionID]
	if !exists {
		response.ErrorCode = errorConnectionNotFound
		return response
	}
	marker := []byte("shared-capacity:" + strconv.FormatUint(command.Sequence, 10))
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	if err := held.connection.Write(callCtx, websocket.MessageBinary, marker); err != nil {
		c.rememberClose(command.ConnectionID, held, callCtx, err)
		response.ErrorCode = errorRoundTripFailed
		return response
	}
	messageType, received, err := held.connection.Read(callCtx)
	if err != nil || messageType != websocket.MessageBinary || !bytesEqual(marker, received) {
		c.rememberClose(command.ConnectionID, held, callCtx, err)
		response.ErrorCode = errorRoundTripFailed
		return response
	}
	response.OK = true
	response.Outcome = wire.OutcomeEchoed
	return response
}

func (c *Caller) expectClosed(ctx context.Context, command wire.Command, response wire.Response) wire.Response {
	if !validConnectionCommand(command) {
		response.ErrorCode = errorInvalidCommand
		return response
	}
	held, exists := c.connections[command.ConnectionID]
	if !exists {
		response.ErrorCode = errorConnectionNotFound
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
			response.ErrorCode = errorCloseTimeout
			return response
		}
		status := websocket.CloseStatus(err)
		if status < 0 {
			if readCtx.Err() != nil {
				response.ErrorCode = errorCloseFailed
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
		response.ErrorCode = errorInvalidCommand
		return response
	}
	held, exists := c.connections[command.ConnectionID]
	if !exists {
		response.ErrorCode = errorConnectionNotFound
		return response
	}
	delete(c.connections, command.ConnectionID)
	closeCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	if err := closeNormal(closeCtx, held.connection); err != nil {
		if errors.Is(closeCtx.Err(), context.DeadlineExceeded) {
			response.ErrorCode = errorCloseTimeout
		} else {
			response.ErrorCode = errorCloseFailed
		}
		return response
	}
	response.OK = true
	response.Outcome = wire.OutcomeReleased
	return response
}

func closeNormal(ctx context.Context, connection *websocket.Conn) error {
	result := make(chan error, 1)
	go func() {
		result <- connection.Close(websocket.StatusNormalClosure, "released")
	}()
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
	return validLogicalID(command.ConnectionID) && validLogicalID(command.GatewayID) && validLogicalID(command.PrincipalID) && validLogicalID(command.EndpointID) &&
		validDuration(command.GrantTTLMillis, minimumGrantTTL, maximumGrantTTL) && validDuration(command.TimeoutMillis, minimumTimeout, maximumTimeout)
}

func validConnectionCommand(command wire.Command) bool {
	return validLogicalID(command.ConnectionID) && command.GatewayID == "" && command.PrincipalID == "" && command.EndpointID == "" && command.GrantTTLMillis == 0 &&
		validDuration(command.TimeoutMillis, minimumTimeout, maximumTimeout)
}

func validShutdown(command wire.Command) bool {
	return command.ConnectionID == "" && command.GatewayID == "" && command.PrincipalID == "" && command.EndpointID == "" && command.GrantTTLMillis == 0 && command.TimeoutMillis == 0
}

func validDuration(milliseconds int64, minimum, maximum time.Duration) bool {
	return milliseconds >= minimum.Milliseconds() && milliseconds <= maximum.Milliseconds()
}

func grantID(connectionID string, sequence uint64) string {
	digest := sha256.Sum256([]byte(connectionID + ":" + strconv.FormatUint(sequence, 10)))
	return "shared-" + strconv.FormatUint(sequence, 10) + "-" + hex.EncodeToString(digest[:8])
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
