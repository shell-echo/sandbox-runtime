package productgateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/product"
)

func TestHandlerConsumesTicketProxiesBinaryFramesAndRejectsReplay(t *testing.T) {
	now := time.Now().UTC()
	store := &grantStoreSpy{ticket: strings.Repeat("t", 43), active: true, binding: testBinding(now)}
	audit := &auditStoreSpy{}
	handler, err := NewHandler(Options{Grants: store, Resolver: &echoResolver{}, Audit: audit, AuthorityPollInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	address := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{"Authorization": []string{"Ticket " + store.ticket}}
	connection, response, err := websocket.Dial(context.Background(), address, &websocket.DialOptions{HTTPHeader: headers, Subprotocols: []string{Subprotocol}})
	if err != nil {
		t.Fatalf("Dial() = %v, response=%v", err, response)
	}
	if connection.Subprotocol() != Subprotocol {
		t.Fatalf("subprotocol = %q", connection.Subprotocol())
	}
	payload := []byte("opaque terminal bytes")
	if err := connection.Write(context.Background(), websocket.MessageBinary, payload); err != nil {
		t.Fatal(err)
	}
	messageType, echoed, err := connection.Read(context.Background())
	if err != nil || messageType != websocket.MessageBinary || string(echoed) != string(payload) {
		t.Fatalf("Read() = %v %q %v", messageType, echoed, err)
	}
	_ = connection.Close(websocket.StatusNormalClosure, "")

	_, replayResponse, replayErr := websocket.Dial(context.Background(), address, &websocket.DialOptions{HTTPHeader: headers, Subprotocols: []string{Subprotocol}})
	if replayErr == nil || replayResponse == nil || replayResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay = response %v error %v; want 401", replayResponse, replayErr)
	}
	if store.consumeCalls != 2 {
		t.Fatalf("consume calls = %d", store.consumeCalls)
	}
	if audit.count(gateway.AuditConnected) == 0 || audit.containsSensitive(store.ticket, store.binding.HandoffReference) {
		t.Fatal("gateway audit missing or contains bearer/private handoff")
	}
}

func TestHandlerAcceptsBrowserTicketSubprotocolWithoutAuthorization(t *testing.T) {
	now := time.Now().UTC()
	store := &grantStoreSpy{ticket: strings.Repeat("b", 43), active: true, binding: testBinding(now)}
	handler, err := NewHandler(Options{Grants: store, Resolver: &echoResolver{}, Audit: &auditStoreSpy{}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	address := "ws" + strings.TrimPrefix(server.URL, "http")
	connection, response, err := websocket.Dial(context.Background(), address, &websocket.DialOptions{Subprotocols: []string{Subprotocol, TicketSubprotocolPrefix + store.ticket}})
	if err != nil {
		t.Fatalf("Dial() = %v, response=%v", err, response)
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != Subprotocol || store.consumeCalls != 1 {
		t.Fatalf("subprotocol=%q consume=%d", connection.Subprotocol(), store.consumeCalls)
	}
}

func TestHandlerRejectsAmbiguousBrowserCredentialsBeforeConsume(t *testing.T) {
	store := &grantStoreSpy{ticket: strings.Repeat("b", 43), active: true, binding: testBinding(time.Now().UTC())}
	handler, err := NewHandler(Options{Grants: store, Resolver: &echoResolver{}, Audit: &auditStoreSpy{}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://gateway.example.test/connect", nil)
	request.Header.Set("Authorization", "Ticket "+store.ticket)
	request.Header.Set("Sec-WebSocket-Protocol", Subprotocol+", "+TicketSubprotocolPrefix+store.ticket)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || store.consumeCalls != 0 {
		t.Fatalf("response=%d consume=%d", response.Code, store.consumeCalls)
	}
}

func TestHandlerRevokesActiveConnectionWhenProductAuthorityIsLost(t *testing.T) {
	now := time.Now().UTC()
	store := &grantStoreSpy{ticket: strings.Repeat("r", 43), active: true, binding: testBinding(now)}
	handler, err := NewHandler(Options{Grants: store, Resolver: &echoResolver{}, Audit: &auditStoreSpy{}, AuthorityPollInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	address := "ws" + strings.TrimPrefix(server.URL, "http")
	connection, _, err := websocket.Dial(context.Background(), address, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Ticket " + store.ticket}}, Subprotocols: []string{Subprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(context.Background(), websocket.MessageBinary, []byte("ready")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.revoke()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("Read() succeeded after Product authority revocation")
	}
}

func TestHandlerRejectsProtocolBeforeConsumingBearer(t *testing.T) {
	store := &grantStoreSpy{ticket: strings.Repeat("x", 43), active: true, binding: testBinding(time.Now().UTC())}
	handler, err := NewHandler(Options{Grants: store, Resolver: &echoResolver{}, Audit: &auditStoreSpy{}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://gateway.example.test/connect", nil)
	request.Header.Set("Authorization", "Ticket "+store.ticket)
	request.Header.Set("Sec-WebSocket-Protocol", "wrong.v1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || store.consumeCalls != 0 {
		t.Fatalf("response=%d consume=%d", response.Code, store.consumeCalls)
	}
}

func testBinding(now time.Time) product.GatewayBinding {
	return product.GatewayBinding{
		ConnectionID: "con-test", TenantID: "tenant-test", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-test"},
		WorkspaceID: "wrk-test", SlotKey: product.PrimarySlotKey, SlotGeneration: 1,
		SessionID: "ses-test", ProtocolProfile: Subprotocol, ExpiresAt: now.Add(time.Minute),
		ProviderRevisionID: strings.Repeat("a", 40), SandboxID: "sandbox-test",
		HandoffReference: "ref:session:test", ConnectionGeneration: 1, HandoffExpiresAt: now.Add(2 * time.Minute),
	}
}

type grantStoreSpy struct {
	mu           sync.Mutex
	ticket       string
	binding      product.GatewayBinding
	active       bool
	consumed     bool
	consumeCalls int
}

func (*grantStoreSpy) MintConnectionGrant(context.Context, product.ConnectionGrantCommand) (product.ConnectionGrant, bool, error) {
	return product.ConnectionGrant{}, false, product.ErrStoreUnavailable
}
func (s *grantStoreSpy) ConsumeConnectionGrant(_ context.Context, ticket string) (product.GatewayBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumeCalls++
	if ticket != s.ticket || s.consumed || !s.active {
		return product.GatewayBinding{}, product.ErrNotFound
	}
	s.consumed = true
	return s.binding, nil
}
func (s *grantStoreSpy) CheckGatewayAuthority(context.Context, product.GatewayBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return product.ErrControlStale
	}
	return nil
}
func (s *grantStoreSpy) revoke() { s.mu.Lock(); s.active = false; s.mu.Unlock() }

type auditStoreSpy struct {
	mu     sync.Mutex
	events []gateway.AuditEvent
}

func (s *auditStoreSpy) RecordGatewayEvent(_ context.Context, _ product.GatewayBinding, event gateway.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}
func (s *auditStoreSpy) count(kind gateway.AuditEventType) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, event := range s.events {
		if event.Type == kind {
			count++
		}
	}
	return count
}
func (s *auditStoreSpy) containsSensitive(values ...string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		for _, value := range values {
			if strings.Contains(event.Reason, value) {
				return true
			}
		}
	}
	return false
}

type echoResolver struct{}

func (*echoResolver) Resolve(_ context.Context, reference string) (gateway.Endpoint, error) {
	return gateway.Endpoint{
		Reference: reference, SandboxID: "sandbox-test", RuntimeSessionID: "ses-test",
		CapabilityProfileID: Subprotocol, ConnectionGeneration: 1, ExpiresAt: time.Now().UTC().Add(time.Minute),
		Dial: func(context.Context) (gateway.Stream, error) { return newEchoStream(), nil },
	}, nil
}

type echoStream struct {
	frames chan gateway.Frame
	done   chan struct{}
	once   sync.Once
}

func newEchoStream() *echoStream {
	return &echoStream{frames: make(chan gateway.Frame, 1), done: make(chan struct{})}
}
func (s *echoStream) Receive(ctx context.Context) (gateway.Frame, error) {
	select {
	case frame := <-s.frames:
		return frame, nil
	case <-s.done:
		return gateway.Frame{}, io.EOF
	case <-ctx.Done():
		return gateway.Frame{}, ctx.Err()
	}
}
func (s *echoStream) Send(ctx context.Context, frame gateway.Frame) error {
	select {
	case s.frames <- frame.Clone():
		return nil
	case <-s.done:
		return io.ErrClosedPipe
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *echoStream) Close(context.Context) error { s.once.Do(func() { close(s.done) }); return nil }

var _ product.ConnectionGrantStore = (*grantStoreSpy)(nil)
var _ AuditStore = (*auditStoreSpy)(nil)
var _ gateway.ReferenceResolver = (*echoResolver)(nil)
var _ gateway.Stream = (*echoStream)(nil)
