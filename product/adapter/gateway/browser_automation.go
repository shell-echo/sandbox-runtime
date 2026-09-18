package productgateway

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	BrowserAutomationSubprotocol = product.SessionProfileBrowserAutomation
	defaultAutomationMessageSize = int64(64 << 10)
	maxAutomationMessageSize     = int64(256 << 10)
	defaultPendingActions        = 8
	maxPendingActions            = 32
)

// BrowserAutomationOptions composes the public Product automation edge with
// the trusted, downstream-fenced private Browser ingress. The resolver must
// never return a direct Chromium endpoint.
type BrowserAutomationOptions struct {
	Grants                   product.ConnectionGrantStore
	FencedResolver           gateway.FencedReferenceResolver
	Audit                    AuditStore
	OriginPatterns           []string
	MaxMessageBytes          int64
	MaxPendingActions        int
	AuthorityPollInterval    time.Duration
	MaxReconnects            int
	ReconnectBackoff         time.Duration
	Capacity                 gateway.ConnectionCapacity
	MaxConnections           int
	MaxConnectionsPerSession int
	Clock                    gateway.Clock
}

// BrowserAutomationHandler accepts only the closed Product Browser automation
// protocol. It converts the small allowlist into private CDP messages after
// Product authorization and downstream-fence admission.
type BrowserAutomationHandler struct {
	grants           product.ConnectionGrantStore
	fencedResolver   gateway.FencedReferenceResolver
	audit            AuditStore
	originPatterns   []string
	maxMessageBytes  int64
	maxPending       int
	pollInterval     time.Duration
	maxReconnects    int
	reconnectBackoff time.Duration
	capacity         gateway.ConnectionCapacity
	maxConnections   int
	maxPerSession    int
	clock            gateway.Clock
}

func NewBrowserAutomationHandler(options BrowserAutomationOptions) (*BrowserAutomationHandler, error) {
	messageLimit := options.MaxMessageBytes
	if messageLimit == 0 {
		messageLimit = defaultAutomationMessageSize
	}
	pendingLimit := options.MaxPendingActions
	if pendingLimit == 0 {
		pendingLimit = defaultPendingActions
	}
	poll := options.AuthorityPollInterval
	if poll == 0 {
		poll = 250 * time.Millisecond
	}
	maxConnections := options.MaxConnections
	if maxConnections == 0 {
		maxConnections = 100
	}
	maxPerSession := options.MaxConnectionsPerSession
	if maxPerSession == 0 {
		maxPerSession = 1
	}
	if nilInterface(options.Grants) || nilInterface(options.FencedResolver) || nilInterface(options.Audit) || nilInterface(options.Capacity) ||
		messageLimit < 1 || messageLimit > maxAutomationMessageSize || pendingLimit < 1 || pendingLimit > maxPendingActions ||
		poll < 10*time.Millisecond || poll > 5*time.Second || maxConnections < 1 || maxConnections > gateway.MaxConnectionCapacity ||
		maxPerSession != 1 || len(options.OriginPatterns) > 32 {
		return nil, product.ErrInvalid
	}
	for _, pattern := range options.OriginPatterns {
		if pattern == "" || len(pattern) > 255 || strings.ContainsAny(pattern, "\r\n\t ") {
			return nil, product.ErrInvalid
		}
	}
	return &BrowserAutomationHandler{
		grants: options.Grants, fencedResolver: options.FencedResolver, audit: options.Audit,
		originPatterns: append([]string(nil), options.OriginPatterns...), maxMessageBytes: messageLimit,
		maxPending: pendingLimit, pollInterval: poll, maxReconnects: options.MaxReconnects,
		reconnectBackoff: options.ReconnectBackoff, capacity: options.Capacity,
		maxConnections: maxConnections, maxPerSession: maxPerSession, clock: options.Clock,
	}, nil
}

func (h *BrowserAutomationHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	ticket, protocolOK := websocketCredentialsFor(BrowserAutomationSubprotocol, request.Header.Values("Authorization"), request.Header.Values("Sec-WebSocket-Protocol"))
	request.Header.Del("Authorization")
	request.Header.Set("Sec-WebSocket-Protocol", BrowserAutomationSubprotocol)
	if !protocolOK || ticket == "" {
		writer.Header().Set("WWW-Authenticate", "Ticket")
		status := http.StatusUnauthorized
		if !protocolOK {
			status = http.StatusBadRequest
		}
		http.Error(writer, http.StatusText(status), status)
		return
	}
	binding, err := h.grants.ConsumeConnectionGrant(request.Context(), ticket)
	ticket = ""
	if err != nil || binding.ProtocolProfile != BrowserAutomationSubprotocol || binding.AccessMode != product.GrantAccessControl || binding.ControlLeaseID == "" || binding.ControlFence < 1 {
		writer.Header().Set("WWW-Authenticate", "Ticket")
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols:    []string{BrowserAutomationSubprotocol},
		OriginPatterns:  append([]string(nil), h.originPatterns...),
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	if connection.Subprotocol() != BrowserAutomationSubprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "required subprotocol")
		return
	}
	connection.SetReadLimit(h.maxMessageBytes)
	client := newBrowserAutomationStream(connection, h.maxMessageBytes, h.maxPending)
	requestBinding, grant := browserGatewayValues(binding)
	proxy, err := gateway.New(gateway.Options{
		Authorizer:               &oneShotAuthorizer{grant: grant},
		FencedResolver:           h.fencedResolver,
		RequireDownstreamFencing: true,
		Revocations:              &authoritySource{store: h.grants, binding: binding, pollInterval: h.pollInterval},
		Recorder:                 &bindingRecorder{store: h.audit, binding: binding},
		Clock:                    h.clock, MaxReconnects: h.maxReconnects, ReconnectBackoff: h.reconnectBackoff,
		Capacity: h.capacity, MaxConnections: h.maxConnections, MaxConnectionsPerSession: h.maxPerSession,
	})
	if err != nil {
		_ = client.Close(context.Background())
		return
	}
	_ = proxy.Connect(request.Context(), requestBinding, client)
}

func browserGatewayValues(binding product.GatewayBinding) (gateway.ConnectRequest, gateway.Grant) {
	expires := minTime(binding.ExpiresAt, binding.HandoffExpiresAt)
	request := gateway.ConnectRequest{
		CallerID: binding.Actor.ID, TenantID: binding.TenantID, SandboxID: binding.SandboxID,
		BrowserSessionID: binding.SessionID, CapabilityProfileID: binding.ProtocolProfile,
		HandoffReference: binding.HandoffReference,
	}
	grant := gateway.Grant{
		GrantID: binding.ConnectionID, CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: binding.ConnectionGeneration, ExpiresAt: expires,
	}
	return request, grant
}

var _ http.Handler = (*BrowserAutomationHandler)(nil)
