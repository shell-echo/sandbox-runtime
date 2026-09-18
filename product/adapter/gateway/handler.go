// Package productgateway exposes the Product-owned terminal WebSocket edge.
// Public callers present only a short-lived, single-use Product ticket. The
// Provider sandbox identity and opaque handoff remain private to this adapter.
package productgateway

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	Subprotocol          = "product-terminal.v1"
	defaultMaxFrameBytes = int64(32 << 10)
	maxFrameBytes        = int64(64 << 10)
)

// AuditStore is the durable Product audit boundary. It receives metadata only;
// frame payloads, tickets, handoff references, and Provider endpoints are never
// included in gateway.AuditEvent.
type AuditStore interface {
	RecordGatewayEvent(context.Context, product.GatewayBinding, gateway.AuditEvent) error
}

type Options struct {
	Grants                   product.ConnectionGrantStore
	Resolver                 gateway.ReferenceResolver
	Audit                    AuditStore
	OriginPatterns           []string
	MaxFrameBytes            int64
	AuthorityPollInterval    time.Duration
	MaxReconnects            int
	ReconnectBackoff         time.Duration
	Capacity                 gateway.ConnectionCapacity
	MaxConnections           int
	MaxConnectionsPerSession int
	Clock                    gateway.Clock
}

type Handler struct {
	grants           product.ConnectionGrantStore
	resolver         gateway.ReferenceResolver
	audit            AuditStore
	originPatterns   []string
	maxFrameBytes    int64
	pollInterval     time.Duration
	maxReconnects    int
	reconnectBackoff time.Duration
	capacity         gateway.ConnectionCapacity
	clock            gateway.Clock
}

func NewHandler(options Options) (*Handler, error) {
	limit := options.MaxFrameBytes
	if limit == 0 {
		limit = defaultMaxFrameBytes
	}
	poll := options.AuthorityPollInterval
	if poll == 0 {
		poll = 250 * time.Millisecond
	}
	if nilInterface(options.Grants) || nilInterface(options.Resolver) || nilInterface(options.Audit) ||
		limit < 1 || limit > maxFrameBytes || poll < 10*time.Millisecond || poll > 5*time.Second {
		return nil, product.ErrInvalid
	}
	capacity := options.Capacity
	if capacity == nil {
		maxConnections := options.MaxConnections
		maxPerSession := options.MaxConnectionsPerSession
		if maxConnections == 0 {
			maxConnections = 100
		}
		if maxPerSession == 0 {
			maxPerSession = 4
		}
		var err error
		capacity, err = gateway.NewLocalConnectionCapacity(gateway.LocalConnectionCapacityOptions{MaxTotal: maxConnections, MaxPerTenant: maxConnections, MaxPerSession: maxPerSession})
		if err != nil {
			return nil, product.ErrInvalid
		}
	} else if nilInterface(capacity) {
		return nil, product.ErrInvalid
	}
	return &Handler{
		grants: options.Grants, resolver: options.Resolver, audit: options.Audit,
		originPatterns: append([]string(nil), options.OriginPatterns...), maxFrameBytes: limit,
		pollInterval: poll, maxReconnects: options.MaxReconnects, reconnectBackoff: options.ReconnectBackoff,
		capacity: capacity, clock: options.Clock,
	}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet || !offersOnlySubprotocol(request.Header.Values("Sec-WebSocket-Protocol")) {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	ticket, ok := singleTicket(request.Header.Values("Authorization"))
	request.Header.Del("Authorization")
	if !ok {
		writer.Header().Set("WWW-Authenticate", "Ticket")
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	binding, err := h.grants.ConsumeConnectionGrant(request.Context(), ticket)
	ticket = ""
	if err != nil {
		writer.Header().Set("WWW-Authenticate", "Ticket")
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{Subprotocol}, OriginPatterns: append([]string(nil), h.originPatterns...),
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	if connection.Subprotocol() != Subprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "required subprotocol")
		return
	}
	connection.SetReadLimit(h.maxFrameBytes)
	stream := &webSocketStream{connection: connection, maxFrameBytes: h.maxFrameBytes}
	requestBinding, grant := gatewayValues(binding)
	proxy, err := gateway.New(gateway.Options{
		Authorizer: &oneShotAuthorizer{grant: grant}, Resolver: h.resolver,
		Revocations: &authoritySource{store: h.grants, binding: binding, pollInterval: h.pollInterval},
		Recorder:    &bindingRecorder{store: h.audit, binding: binding}, Clock: h.clock,
		MaxReconnects: h.maxReconnects, ReconnectBackoff: h.reconnectBackoff,
		Capacity: h.capacity,
	})
	if err != nil {
		_ = stream.Close(context.Background())
		return
	}
	_ = proxy.Connect(request.Context(), requestBinding, stream)
}

func gatewayValues(binding product.GatewayBinding) (gateway.ConnectRequest, gateway.Grant) {
	expires := binding.ExpiresAt
	if binding.HandoffExpiresAt.Before(expires) {
		expires = binding.HandoffExpiresAt
	}
	request := gateway.ConnectRequest{
		CallerID: binding.Actor.ID, TenantID: binding.TenantID, SandboxID: binding.SandboxID,
		RuntimeSessionID: binding.SessionID, CapabilityProfileID: binding.ProtocolProfile,
		HandoffReference: binding.HandoffReference,
	}
	grant := gateway.Grant{
		GrantID: binding.ConnectionID, CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: binding.ConnectionGeneration, ExpiresAt: expires,
	}
	return request, grant
}

func singleTicket(values []string) (string, bool) {
	if len(values) != 1 || !strings.HasPrefix(values[0], "Ticket ") {
		return "", false
	}
	ticket := strings.TrimPrefix(values[0], "Ticket ")
	return ticket, len(ticket) >= 32 && len(ticket) <= 512 && !strings.ContainsAny(ticket, " \t\r\n,")
}

func offersOnlySubprotocol(values []string) bool {
	if len(values) != 1 {
		return false
	}
	parts := strings.Split(values[0], ",")
	return len(parts) == 1 && strings.TrimSpace(parts[0]) == Subprotocol
}

type oneShotAuthorizer struct {
	mu    sync.Mutex
	used  bool
	grant gateway.Grant
}

func (a *oneShotAuthorizer) Authorize(_ context.Context, _ gateway.ConnectRequest) (gateway.Grant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used {
		return gateway.Grant{}, gateway.ErrUnauthorized
	}
	a.used = true
	return a.grant, nil
}

type bindingRecorder struct {
	store   AuditStore
	binding product.GatewayBinding
}

func (r *bindingRecorder) Record(ctx context.Context, event gateway.AuditEvent) error {
	return r.store.RecordGatewayEvent(ctx, r.binding, event)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Ptr && reflected.IsNil()
}

var _ http.Handler = (*Handler)(nil)
var _ gateway.Authorizer = (*oneShotAuthorizer)(nil)
var _ gateway.Recorder = (*bindingRecorder)(nil)
