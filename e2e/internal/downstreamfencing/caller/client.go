package caller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

const (
	minimumTimeout         = 25 * time.Millisecond
	maximumTimeout         = 60 * time.Second
	maxMessageBytes        = 64 << 10
	maxEncodedMessageBytes = ((maxMessageBytes + 2) / 3) * 4
	maxPendingMessages     = 32
	maxPendingBytes        = 256 << 10
	maxActiveConnections   = 32
	maxOpenedConnections   = 256
	maxUsedCDPIDs          = 4096
)

type receivedMessage struct {
	messageType websocket.MessageType
	payload     []byte
}

type heldConnection struct {
	connection   *websocket.Conn
	readMu       sync.Mutex
	writeMu      sync.Mutex
	stateMu      sync.Mutex
	pending      []receivedMessage
	pendingBytes int
	usedCDPIDs   map[uint64]struct{}
	closed       bool
	closeCode    int
}

type Caller struct {
	mu          sync.Mutex
	client      *http.Client
	transport   *http.Transport
	gateways    map[string]*url.URL
	bindings    map[string]resolvedGrantBinding
	privateText [][]byte
	connections map[string]*heldConnection
	lastSeq     uint64
	openedCount int
	terminated  bool
	openWG      sync.WaitGroup
	operationWG sync.WaitGroup
	cleanupWG   sync.WaitGroup
}

// New builds a TLS 1.3-only black-box client from immutable private bindings.
func New(config Config) (*Caller, error) {
	prepared, err := prepareConfig(config)
	if err != nil {
		return nil, err
	}
	transport := newTransport(prepared.roots)
	return &Caller{
		client: &http.Client{Transport: transport, CheckRedirect: rejectRedirect}, transport: transport,
		gateways: prepared.gateways, bindings: prepared.bindings, privateText: prepared.privateText,
		connections: make(map[string]*heldConnection),
	}, nil
}

func newTransport(roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: roots, ServerName: "localhost", NextProtos: []string{"http/1.1"},
		},
	}
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// Execute applies one bounded command. Per-connection read and write locks
// permit one reader and one writer concurrently, as required by RFC 6455.
func (c *Caller) Execute(ctx context.Context, command Command) Response {
	response := Response{Version: ProtocolVersion, Sequence: command.Sequence}
	if c == nil || ctx == nil {
		response.ErrorCode = ErrorInternal
		return response
	}
	if !c.begin(command) {
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
	if command.Action != ActionShutdown {
		defer c.operationWG.Done()
	}
	switch command.Action {
	case ActionOpen:
		return c.open(ctx, command, response)
	case ActionCallCDP:
		return c.callCDP(ctx, command, response)
	case ActionQueueCDP:
		return c.queueCDP(ctx, command, response)
	case ActionReadCDP:
		return c.readCDP(ctx, command, response)
	case ActionExpectClosed:
		return c.expectClosed(ctx, command, response)
	case ActionClose:
		return c.closeConnection(ctx, command, response)
	case ActionShutdown:
		return c.shutdown(command, response)
	default:
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
}

func (c *Caller) begin(command Command) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminated || command.Version != ProtocolVersion || command.Sequence == 0 || command.Sequence <= c.lastSeq {
		return false
	}
	c.lastSeq = command.Sequence
	if command.Action != ActionShutdown {
		c.operationWG.Add(1)
	}
	return true
}

func (c *Caller) open(ctx context.Context, command Command, response Response) Response {
	if !validOpen(command) {
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
	base, exists := c.gateways[command.GatewayID]
	if !exists {
		response.ErrorCode = ErrorUnknownGateway
		return response
	}
	binding, exists := c.bindings[command.GrantBindingID]
	if !exists {
		response.ErrorCode = ErrorUnknownGrantBinding
		return response
	}
	if reserveError := c.reserve(command.ConnectionID); reserveError != "" {
		response.ErrorCode = reserveError
		return response
	}
	defer c.openWG.Done()

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
	connection, httpResponse, err := websocket.Dial(dialCtx, dialURL.String(), &websocket.DialOptions{HTTPClient: c.client, HTTPHeader: header})
	dialContextErr := dialCtx.Err()
	cancel()
	if httpResponse != nil && httpResponse.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResponse.Body, 1024))
		_ = httpResponse.Body.Close()
	}
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.CloseNow()
		}
		c.remove(command.ConnectionID, nil)
		response.ErrorCode = ErrorUpgradeFailed
		if httpResponse != nil {
			response.ErrorCode = ErrorNotUpgraded
		} else if errors.Is(dialContextErr, context.DeadlineExceeded) {
			response.ErrorCode = ErrorOperationTimeout
		} else if errors.Is(dialContextErr, context.Canceled) {
			response.ErrorCode = ErrorOperationCanceled
		}
		return response
	}
	connection.SetReadLimit(maxMessageBytes)
	held := &heldConnection{connection: connection, usedCDPIDs: make(map[uint64]struct{})}
	if !c.commitReservation(command.ConnectionID, held) {
		_ = connection.CloseNow()
		response.ErrorCode = ErrorInternal
		return response
	}
	response.OK, response.Outcome, response.Upgraded = true, OutcomeOpened, true
	return response
}

func (c *Caller) callCDP(ctx context.Context, command Command, response Response) Response {
	held, payload, messageType, ok := c.prepareMessageCommand(command, &response)
	if !ok {
		return response
	}
	requestID, ok := cdpMessageID(payload)
	if messageType != websocket.MessageText || !ok {
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
	operationCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	if !c.writeMessage(operationCtx, held, messageType, payload, &response) {
		return response
	}
	held.readMu.Lock()
	defer held.readMu.Unlock()
	if receivedType, received, found := held.takePendingByCDPID(requestID); found {
		if !c.projectMessage(receivedType, received, &response) {
			return response
		}
		response.OK, response.Outcome = true, OutcomeCompleted
		return response
	}
	for {
		receivedType, received, ok := c.readNetworkMessageLocked(operationCtx, held, &response)
		if !ok {
			return response
		}
		responseID, isResponse := cdpMessageID(received)
		if receivedType == websocket.MessageText && isResponse && responseID == requestID {
			if !c.projectMessage(receivedType, received, &response) {
				return response
			}
			response.OK, response.Outcome = true, OutcomeCompleted
			return response
		}
		if !held.queuePending(receivedType, received) {
			held.rememberClosed(nil)
			response.ErrorCode = ErrorReadFailed
			return response
		}
	}
}

func (c *Caller) queueCDP(ctx context.Context, command Command, response Response) Response {
	held, payload, messageType, ok := c.prepareMessageCommand(command, &response)
	if !ok {
		return response
	}
	operationCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	if !c.writeMessage(operationCtx, held, messageType, payload, &response) {
		return response
	}
	response.OK, response.Outcome = true, OutcomeWritten
	return response
}

func (c *Caller) readCDP(ctx context.Context, command Command, response Response) Response {
	if !validReadCommand(command) {
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
	held, ok := c.connection(command.ConnectionID)
	if !ok {
		response.ErrorCode = ErrorConnectionNotFound
		return response
	}
	operationCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	held.readMu.Lock()
	defer held.readMu.Unlock()
	messageType, payload, ok := held.takePending()
	if !ok {
		messageType, payload, ok = c.readNetworkMessageLocked(operationCtx, held, &response)
	}
	if !ok {
		return response
	}
	if !c.projectMessage(messageType, payload, &response) {
		return response
	}
	response.OK, response.Outcome = true, OutcomeRead
	return response
}

func (c *Caller) prepareMessageCommand(command Command, response *Response) (*heldConnection, []byte, websocket.MessageType, bool) {
	if !validMessageCommand(command) {
		response.ErrorCode = ErrorInvalidCommand
		return nil, nil, 0, false
	}
	payload, err := base64.StdEncoding.DecodeString(command.PayloadBase64)
	if err != nil || len(payload) == 0 || len(payload) > maxMessageBytes || base64.StdEncoding.EncodeToString(payload) != command.PayloadBase64 {
		response.ErrorCode = ErrorInvalidCommand
		return nil, nil, 0, false
	}
	messageType := websocket.MessageBinary
	if command.MessageType == MessageText {
		if !utf8.Valid(payload) {
			response.ErrorCode = ErrorInvalidCommand
			return nil, nil, 0, false
		}
		messageType = websocket.MessageText
	}
	held, ok := c.connection(command.ConnectionID)
	if !ok {
		response.ErrorCode = ErrorConnectionNotFound
		return nil, nil, 0, false
	}
	return held, payload, messageType, true
}

func (c *Caller) writeMessage(ctx context.Context, held *heldConnection, messageType websocket.MessageType, payload []byte, response *Response) bool {
	held.writeMu.Lock()
	defer held.writeMu.Unlock()
	if held.isClosed() {
		response.ErrorCode = ErrorConnectionClosed
		return false
	}
	if messageType == websocket.MessageText {
		if id, ok := cdpMessageID(payload); ok {
			if _, exists := held.usedCDPIDs[id]; exists || len(held.usedCDPIDs) >= maxUsedCDPIDs {
				response.ErrorCode = ErrorInvalidCommand
				return false
			}
			// Reserve before the write. A failed write has an unknown outcome and
			// therefore cannot make this id safe to reuse.
			held.usedCDPIDs[id] = struct{}{}
		}
	}
	if err := held.connection.Write(ctx, messageType, payload); err != nil {
		held.rememberClosed(err)
		response.ErrorCode = operationError(ctx, ErrorOperationTimeout, ErrorWriteFailed)
		return false
	}
	return true
}

func (c *Caller) readNetworkMessageLocked(ctx context.Context, held *heldConnection, response *Response) (websocket.MessageType, []byte, bool) {
	if held.isClosed() {
		response.ErrorCode = ErrorConnectionClosed
		return 0, nil, false
	}
	messageType, payload, err := held.connection.Read(ctx)
	if err != nil {
		held.rememberClosed(err)
		response.ErrorCode = operationError(ctx, ErrorOperationTimeout, ErrorReadFailed)
		return 0, nil, false
	}
	if (messageType != websocket.MessageText && messageType != websocket.MessageBinary) || len(payload) > maxMessageBytes {
		held.rememberClosed(nil)
		response.ErrorCode = ErrorReadFailed
		return 0, nil, false
	}
	return messageType, payload, true
}

func cdpMessageID(payload []byte) (uint64, bool) {
	if len(payload) == 0 || len(payload) > maxMessageBytes || validateUniqueJSONFields(payload) != nil {
		return 0, false
	}
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&envelope); err != nil || len(envelope.ID) == 0 {
		return 0, false
	}
	id, err := strconv.ParseUint(string(envelope.ID), 10, 64)
	return id, err == nil && id > 0
}

func (c *Caller) projectMessage(messageType websocket.MessageType, payload []byte, response *Response) bool {
	if c.containsPrivate(payload) {
		response.ErrorCode = ErrorUnsafeResponse
		return false
	}
	response.MessageType = MessageBinary
	if messageType == websocket.MessageText {
		response.MessageType = MessageText
	}
	response.PayloadBase64 = base64.StdEncoding.EncodeToString(payload)
	return true
}

func (c *Caller) expectClosed(ctx context.Context, command Command, response Response) Response {
	if !validReadCommand(command) {
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
	held, ok := c.connection(command.ConnectionID)
	if !ok {
		response.ErrorCode = ErrorConnectionNotFound
		return response
	}
	if code, closed := held.closeStatus(); closed {
		c.remove(command.ConnectionID, held)
		response.OK, response.Outcome, response.CloseCode = true, OutcomeClosed, code
		return response
	}
	readCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	held.readMu.Lock()
	defer held.readMu.Unlock()
	for {
		_, _, err := held.connection.Read(readCtx)
		if err == nil {
			continue
		}
		if readCtx.Err() != nil {
			held.rememberClosed(err)
			response.ErrorCode = operationError(readCtx, ErrorCloseTimeout, ErrorCloseFailed)
			return response
		}
		held.rememberClosed(err)
		code, _ := held.closeStatus()
		c.remove(command.ConnectionID, held)
		response.OK, response.Outcome, response.CloseCode = true, OutcomeClosed, code
		return response
	}
}

func (c *Caller) closeConnection(ctx context.Context, command Command, response Response) Response {
	if !validReadCommand(command) {
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
	held, ok := c.takeConnection(command.ConnectionID)
	if !ok {
		response.ErrorCode = ErrorConnectionNotFound
		return response
	}
	closeCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	defer cancel()
	if err := c.closeNormal(closeCtx, held.connection); err != nil {
		response.ErrorCode = operationError(closeCtx, ErrorCloseTimeout, ErrorCloseFailed)
		return response
	}
	response.OK, response.Outcome = true, OutcomeReleased
	return response
}

func (c *Caller) shutdown(command Command, response Response) Response {
	if !validShutdown(command) {
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
	c.mu.Lock()
	if c.terminated {
		c.mu.Unlock()
		response.ErrorCode = ErrorInvalidCommand
		return response
	}
	c.terminated = true
	connections := c.takeAllLocked()
	c.mu.Unlock()
	for _, held := range connections {
		if held != nil {
			go c.closeNowTracked(held.connection)
		}
	}
	c.operationWG.Wait()
	c.openWG.Wait()
	c.cleanupWG.Wait()
	c.transport.CloseIdleConnections()
	response.OK, response.Outcome = true, OutcomeTerminated
	return response
}

func (c *Caller) reserve(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminated {
		return ErrorInternal
	}
	if _, exists := c.connections[id]; exists {
		return ErrorConnectionExists
	}
	if len(c.connections) >= maxActiveConnections || c.openedCount >= maxOpenedConnections {
		return ErrorConnectionCapacity
	}
	c.connections[id] = nil
	c.openedCount++
	c.openWG.Add(1)
	return ""
}

func (c *Caller) commitReservation(id string, held *heldConnection) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, exists := c.connections[id]
	if c.terminated || !exists || current != nil {
		return false
	}
	c.connections[id] = held
	return true
}

func (c *Caller) connection(id string) (*heldConnection, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	held, exists := c.connections[id]
	return held, exists && held != nil
}

func (c *Caller) takeConnection(id string) (*heldConnection, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	held, exists := c.connections[id]
	if exists {
		delete(c.connections, id)
	}
	if exists && held != nil {
		c.cleanupWG.Add(1)
	}
	return held, exists && held != nil
}

func (c *Caller) remove(id string, expected *heldConnection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, exists := c.connections[id]
	if exists && (expected == nil || current == expected) {
		delete(c.connections, id)
	}
}

func (c *Caller) takeAllLocked() []*heldConnection {
	result := make([]*heldConnection, 0, len(c.connections))
	for id, held := range c.connections {
		result = append(result, held)
		if held != nil {
			c.cleanupWG.Add(1)
		}
		delete(c.connections, id)
	}
	return result
}

func (c *Caller) containsPrivate(payload []byte) bool {
	for _, forbidden := range c.privateText {
		if len(forbidden) > 0 && bytes.Contains(payload, forbidden) {
			return true
		}
	}
	return false
}

func (h *heldConnection) rememberClosed(err error) {
	h.recordClosed(err)
	if h.connection != nil {
		_ = h.connection.CloseNow()
	}
}

func (h *heldConnection) recordClosed(err error) {
	observed := websocket.CloseStatus(err)
	code := observed
	if code < 0 {
		code = websocket.StatusAbnormalClosure
	}
	h.stateMu.Lock()
	if !h.closed || (h.closeCode == int(websocket.StatusAbnormalClosure) && observed >= 0) {
		h.closed, h.closeCode = true, int(code)
	}
	h.stateMu.Unlock()
}

func (h *heldConnection) isClosed() bool {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	return h.closed
}

func (h *heldConnection) closeStatus() (int, bool) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	return h.closeCode, h.closed
}

// queuePending and takePending are called only while readMu is held.
func (h *heldConnection) queuePending(messageType websocket.MessageType, payload []byte) bool {
	if len(h.pending) >= maxPendingMessages || h.pendingBytes+len(payload) > maxPendingBytes {
		return false
	}
	cloned := append([]byte(nil), payload...)
	h.pending = append(h.pending, receivedMessage{messageType: messageType, payload: cloned})
	h.pendingBytes += len(cloned)
	return true
}

func (h *heldConnection) takePending() (websocket.MessageType, []byte, bool) {
	if len(h.pending) == 0 {
		return 0, nil, false
	}
	message := h.pending[0]
	h.pending[0] = receivedMessage{}
	h.pending = h.pending[1:]
	h.pendingBytes -= len(message.payload)
	return message.messageType, message.payload, true
}

func (h *heldConnection) takePendingByCDPID(id uint64) (websocket.MessageType, []byte, bool) {
	for index, message := range h.pending {
		candidate, ok := cdpMessageID(message.payload)
		if message.messageType != websocket.MessageText || !ok || candidate != id {
			continue
		}
		h.pendingBytes -= len(message.payload)
		copy(h.pending[index:], h.pending[index+1:])
		h.pending[len(h.pending)-1] = receivedMessage{}
		h.pending = h.pending[:len(h.pending)-1]
		return message.messageType, message.payload, true
	}
	return 0, nil, false
}

func operationError(ctx context.Context, timeout, fallback string) string {
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return timeout
	}
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return ErrorOperationCanceled
	}
	return fallback
}

func (c *Caller) closeNormal(ctx context.Context, connection *websocket.Conn) error {
	result := make(chan error, 1)
	go func() {
		defer c.cleanupWG.Done()
		result <- connection.Close(websocket.StatusNormalClosure, "released")
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Caller) closeNowTracked(connection *websocket.Conn) {
	defer c.cleanupWG.Done()
	_ = connection.CloseNow()
}

// Close immediately releases every process-local connection.
func (c *Caller) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	c.terminated = true
	connections := c.takeAllLocked()
	c.mu.Unlock()
	for _, held := range connections {
		if held != nil {
			go c.closeNowTracked(held.connection)
		}
	}
	c.operationWG.Wait()
	c.openWG.Wait()
	c.cleanupWG.Wait()
	c.transport.CloseIdleConnections()
	return nil
}

func validOpen(command Command) bool {
	return validLogicalID(command.ConnectionID) && validLogicalID(command.GatewayID) && validLogicalID(command.GrantBindingID) &&
		command.MessageType == "" && command.PayloadBase64 == "" && validTimeout(command.TimeoutMillis)
}

func validMessageCommand(command Command) bool {
	return validLogicalID(command.ConnectionID) && command.GatewayID == "" && command.GrantBindingID == "" &&
		(command.MessageType == MessageText || command.MessageType == MessageBinary) && len(command.PayloadBase64) > 0 &&
		len(command.PayloadBase64) <= maxEncodedMessageBytes && validTimeout(command.TimeoutMillis)
}

func validReadCommand(command Command) bool {
	return validLogicalID(command.ConnectionID) && command.GatewayID == "" && command.GrantBindingID == "" &&
		command.MessageType == "" && command.PayloadBase64 == "" && validTimeout(command.TimeoutMillis)
}

func validShutdown(command Command) bool {
	return command.ConnectionID == "" && command.GatewayID == "" && command.GrantBindingID == "" && command.MessageType == "" &&
		command.PayloadBase64 == "" && command.TimeoutMillis == 0
}

func validTimeout(milliseconds int64) bool {
	return milliseconds >= minimumTimeout.Milliseconds() && milliseconds <= maximumTimeout.Milliseconds()
}
