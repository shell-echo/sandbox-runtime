package productgateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	"github.com/shell-echo/sandbox-runtime/product"
)

func TestBrowserAutomationHandlerTranslatesClosedProtocolThroughFence(t *testing.T) {
	now := time.Now().UTC()
	store := &grantStoreSpy{ticket: strings.Repeat("a", 43), active: true, binding: testBrowserAutomationBinding(now)}
	resolver := &automationFencedResolver{}
	capacity := newAutomationFencedCapacity(t, "v1."+strings.Repeat("a", 32))
	handler, err := NewBrowserAutomationHandler(BrowserAutomationOptions{
		Grants: store, FencedResolver: resolver, Audit: &auditStoreSpy{}, Capacity: capacity,
		AuthorityPollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	connection, response, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": []string{"Ticket " + store.ticket}},
		Subprotocols: []string{BrowserAutomationSubprotocol},
	})
	if err != nil {
		t.Fatalf("dial err=%v response=%v", err, response)
	}
	defer connection.CloseNow()

	action := `{"type":"action","action_id":"action-1","sequence":1,"name":"page.info","parameters":{}}`
	if err := connection.Write(context.Background(), websocket.MessageText, []byte(action)); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := connection.Read(context.Background())
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("read type=%v payload=%s err=%v", messageType, payload, err)
	}
	var result automationResult
	if err := json.Unmarshal(payload, &result); err != nil || !result.OK || result.ActionID != "action-1" || result.Sequence != 1 || !strings.Contains(string(result.Value), `"title":"example"`) {
		t.Fatalf("result=%s parsed=%#v err=%v", payload, result, err)
	}
	if strings.Contains(string(payload), "Runtime.evaluate") || strings.Contains(string(payload), store.binding.HandoffReference) {
		t.Fatalf("private Browser detail leaked: %s", payload)
	}
	resolver.mu.Lock()
	resolveCalls := resolver.resolveCalls
	subject := resolver.subject
	privateAction := resolver.lastAction
	resolver.mu.Unlock()
	if resolveCalls != 1 || subject.BrowserSessionID != store.binding.SessionID || subject.ConnectionGeneration != store.binding.ConnectionGeneration ||
		!strings.Contains(privateAction, `"method":"Runtime.evaluate"`) || strings.Contains(privateAction, "action-1") {
		t.Fatalf("resolveCalls=%d subject=%#v privateAction=%s", resolveCalls, subject, privateAction)
	}
}

func TestBrowserAutomationHandlerRejectsViewGrantAndRawCDP(t *testing.T) {
	now := time.Now().UTC()
	viewStore := &grantStoreSpy{ticket: strings.Repeat("v", 43), active: true, binding: testBrowserAutomationBinding(now)}
	viewStore.binding.AccessMode = product.GrantAccessView
	handler, err := NewBrowserAutomationHandler(BrowserAutomationOptions{
		Grants: viewStore, FencedResolver: &automationFencedResolver{}, Audit: &auditStoreSpy{}, Capacity: newAutomationFencedCapacity(t, "v1."+strings.Repeat("v", 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	_, response, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Ticket " + viewStore.ticket}}, Subprotocols: []string{BrowserAutomationSubprotocol},
	})
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("view dial err=%v response=%v", err, response)
	}

	rawStore := &grantStoreSpy{ticket: strings.Repeat("r", 43), active: true, binding: testBrowserAutomationBinding(now)}
	rawHandler, err := NewBrowserAutomationHandler(BrowserAutomationOptions{
		Grants: rawStore, FencedResolver: &automationFencedResolver{}, Audit: &auditStoreSpy{}, Capacity: newAutomationFencedCapacity(t, "v1."+strings.Repeat("r", 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rawServer := httptest.NewServer(rawHandler)
	defer rawServer.Close()
	connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(rawServer.URL, "http"), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Ticket " + rawStore.ticket}}, Subprotocols: []string{BrowserAutomationSubprotocol},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if err := connection.Write(context.Background(), websocket.MessageText, []byte(`{"id":1,"method":"Runtime.evaluate","params":{}}`)); err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := connection.Read(readCtx); err == nil {
		t.Fatal("raw CDP message remained connected")
	}
}

func TestBrowserAutomationActionDecoderRejectsAmbiguousOrOutOfContractJSON(t *testing.T) {
	invalid := []string{
		`{"type":"action","action_id":"one","action_id":"two","sequence":1,"name":"page.info"}`,
		`{"type":"action","action_id":"one","sequence":9007199254740992,"name":"page.info"}`,
		`{"type":"action","action_id":"one","sequence":1,"name":"page.info","parameters":null}`,
		`{"type":"action","action_id":"one","sequence":1,"name":"page.text","parameters":{"max_characters":1,"max_characters":2}}`,
	}
	for _, document := range invalid {
		action, err := decodeAutomationAction([]byte(document))
		if err == nil {
			if _, translateErr := translateAutomationAction(1, action); translateErr == nil {
				t.Fatalf("invalid action accepted: %s", document)
			}
		}
	}
}

func TestBrowserAutomationHandlerRejectsOutOfOrderOrUnboundedActions(t *testing.T) {
	for _, test := range []struct {
		name    string
		first   string
		second  string
		pending int
	}{
		{name: "out of order", first: `{"type":"action","action_id":"action-2","sequence":2,"name":"page.info"}`, pending: 8},
		{name: "pending limit", first: `{"type":"action","action_id":"action-1","sequence":1,"name":"page.info"}`, second: `{"type":"action","action_id":"action-2","sequence":2,"name":"page.info"}`, pending: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &grantStoreSpy{ticket: strings.Repeat("q", 43), active: true, binding: testBrowserAutomationBinding(time.Now().UTC())}
			resolver := &automationFencedResolver{blockResponses: test.second != ""}
			handler, err := NewBrowserAutomationHandler(BrowserAutomationOptions{
				Grants: store, FencedResolver: resolver, Audit: &auditStoreSpy{}, Capacity: newAutomationFencedCapacity(t, "v1."+strings.Repeat("q", 32)), MaxPendingActions: test.pending,
			})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
				HTTPHeader: http.Header{"Authorization": []string{"Ticket " + store.ticket}}, Subprotocols: []string{BrowserAutomationSubprotocol},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.CloseNow()
			if err := connection.Write(context.Background(), websocket.MessageText, []byte(test.first)); err != nil {
				t.Fatal(err)
			}
			if test.second != "" {
				if err := connection.Write(context.Background(), websocket.MessageText, []byte(test.second)); err != nil {
					t.Fatal(err)
				}
			}
			readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, _, err := connection.Read(readCtx); err == nil {
				t.Fatal("invalid action sequence remained connected")
			}
		})
	}
}

func TestBrowserAutomationHandlerReconnectsThroughFreshFencedResolution(t *testing.T) {
	store := &grantStoreSpy{ticket: strings.Repeat("c", 43), active: true, binding: testBrowserAutomationBinding(time.Now().UTC())}
	resolver := &automationFencedResolver{closeFirst: true}
	handler, err := NewBrowserAutomationHandler(BrowserAutomationOptions{
		Grants: store, FencedResolver: resolver, Audit: &auditStoreSpy{}, Capacity: newAutomationFencedCapacity(t, "v1."+strings.Repeat("c", 32)),
		AuthorityPollInterval: 10 * time.Millisecond, MaxReconnects: 2, ReconnectBackoff: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Ticket " + store.ticket}}, Subprotocols: []string{BrowserAutomationSubprotocol},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	deadline := time.Now().Add(time.Second)
	for {
		resolver.mu.Lock()
		calls := resolver.resolveCalls
		resolver.mu.Unlock()
		if calls >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fresh resolution did not occur: calls=%d", calls)
		}
		time.Sleep(time.Millisecond)
	}
	if err := connection.Write(context.Background(), websocket.MessageText, []byte(`{"type":"action","action_id":"after-reconnect","sequence":1,"name":"page.info"}`)); err != nil {
		t.Fatal(err)
	}
	_, payload, err := connection.Read(context.Background())
	if err != nil || !strings.Contains(string(payload), `"action_id":"after-reconnect"`) {
		t.Fatalf("payload=%s err=%v", payload, err)
	}
}

func TestBrowserAutomationHandlerClosesWhenProductAuthorityIsRevoked(t *testing.T) {
	store := &grantStoreSpy{ticket: strings.Repeat("z", 43), active: true, binding: testBrowserAutomationBinding(time.Now().UTC())}
	handler, err := NewBrowserAutomationHandler(BrowserAutomationOptions{
		Grants: store, FencedResolver: &automationFencedResolver{}, Audit: &auditStoreSpy{}, Capacity: newAutomationFencedCapacity(t, "v1."+strings.Repeat("z", 32)),
		AuthorityPollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Ticket " + store.ticket}}, Subprotocols: []string{BrowserAutomationSubprotocol},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if err := connection.Write(context.Background(), websocket.MessageText, []byte(`{"type":"action","action_id":"before-revoke","sequence":1,"name":"page.info"}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.revoke()
	readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := connection.Read(readCtx); err == nil {
		t.Fatal("revoked Browser automation connection remained open")
	}
}

func TestBrowserAutomationUsesTLSPrivateIngressWithoutExposingCDP(t *testing.T) {
	now := time.Now().UTC()
	backendResolver := &automationFencedResolver{}
	authority := &networkFenceAuthority{}
	ingress, err := cdpfence.New(cdpfence.Options{Authority: authority, ActionTimeout: time.Second, CloseTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	privateHandler, err := cdpfence.NewNetworkHandler(cdpfence.NetworkOptions{
		Ingress: ingress, Resolver: networkProviderResolver{resolver: backendResolver}, MaxMessageBytes: defaultAutomationMessageSize,
		PeerAuthorizer: cdpfence.PeerAuthorizerFunc(func(_ context.Context, state tls.ConnectionState) error {
			if !state.HandshakeComplete {
				return errors.New("TLS handshake incomplete")
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	privateServer := httptest.NewTLSServer(privateHandler)
	defer privateServer.Close()
	privateResolver, err := NewPrivateBrowserResolver(PrivateBrowserResolverOptions{
		Origin: "wss" + strings.TrimPrefix(privateServer.URL, "https") + "/private/browser", HTTPClient: privateServer.Client(), MaxMessageBytes: defaultAutomationMessageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &grantStoreSpy{ticket: strings.Repeat("n", 43), active: true, binding: testBrowserAutomationBinding(now)}
	publicHandler, err := NewBrowserAutomationHandler(BrowserAutomationOptions{
		Grants: store, FencedResolver: privateResolver, Audit: &auditStoreSpy{}, Capacity: newAutomationFencedCapacity(t, "v1."+strings.Repeat("n", 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	publicServer := httptest.NewTLSServer(publicHandler)
	defer publicServer.Close()
	connection, response, err := websocket.Dial(context.Background(), "wss"+strings.TrimPrefix(publicServer.URL, "https"), &websocket.DialOptions{
		HTTPClient: publicServer.Client(), HTTPHeader: http.Header{"Authorization": []string{"Ticket " + store.ticket}}, Subprotocols: []string{BrowserAutomationSubprotocol},
	})
	if err != nil {
		t.Fatalf("dial err=%v response=%v", err, response)
	}
	defer connection.CloseNow()
	if err := connection.Write(context.Background(), websocket.MessageText, []byte(`{"type":"action","action_id":"network-action","sequence":1,"name":"page.text","parameters":{"max_characters":128}}`)); err != nil {
		t.Fatal(err)
	}
	_, payload, err := connection.Read(context.Background())
	if err != nil || !strings.Contains(string(payload), `"action_id":"network-action"`) || strings.Contains(string(payload), "Runtime.evaluate") {
		t.Fatalf("payload=%s err=%v", payload, err)
	}
	backendResolver.mu.Lock()
	privateAction := backendResolver.lastAction
	backendResolver.mu.Unlock()
	if !strings.Contains(privateAction, `"method":"Runtime.evaluate"`) || strings.Contains(privateAction, "network-action") {
		t.Fatalf("private action=%s", privateAction)
	}
}

func testBrowserAutomationBinding(now time.Time) product.GatewayBinding {
	return product.GatewayBinding{
		ConnectionID: "con-browser", TenantID: "tenant-browser", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-browser"},
		WorkspaceID: "wrk-browser", SlotKey: "browser-main", SlotGeneration: 1,
		SessionID: "ses-browser", ProtocolProfile: BrowserAutomationSubprotocol,
		ControlLeaseID: "ctl-browser", ControlFence: 7, AccessMode: product.GrantAccessControl,
		ExpiresAt: now.Add(time.Minute), ProviderRevisionID: strings.Repeat("a", 40), SandboxID: "sandbox-browser",
		HandoffReference: "ref:browser-session:browser-test", ConnectionGeneration: 3, HandoffExpiresAt: now.Add(2 * time.Minute),
	}
}

type automationFencedCapacity struct {
	fence gateway.DownstreamFence
}

func newAutomationFencedCapacity(t *testing.T, value string) *automationFencedCapacity {
	t.Helper()
	fence, err := gateway.NewDownstreamFence(value)
	if err != nil {
		t.Fatal(err)
	}
	return &automationFencedCapacity{fence: fence}
}

func (c *automationFencedCapacity) Acquire(context.Context, gateway.CapacitySubject) (gateway.ConnectionLease, error) {
	return &automationFencedLease{fence: c.fence, events: make(chan gateway.CapacityEvent)}, nil
}

type automationFencedLease struct {
	fence  gateway.DownstreamFence
	events chan gateway.CapacityEvent
	once   sync.Once
}

func (l *automationFencedLease) Events() <-chan gateway.CapacityEvent { return l.events }
func (l *automationFencedLease) Release(context.Context) error {
	l.once.Do(func() { close(l.events) })
	return nil
}
func (l *automationFencedLease) DownstreamFence() (gateway.DownstreamFence, error) {
	return l.fence, nil
}

type automationFencedResolver struct {
	mu             sync.Mutex
	resolveCalls   int
	subject        gateway.DownstreamFenceSubject
	lastAction     string
	blockResponses bool
	closeFirst     bool
}

type networkFenceAuthority struct {
	mu      sync.Mutex
	current string
}

func (a *networkFenceAuthority) AuthorizeAction(_ context.Context, _ gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current == "" {
		a.current = fence.Opaque()
		return gateway.DownstreamFenceDecision{Activated: true}, nil
	}
	if a.current != fence.Opaque() {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamFenceLost
	}
	return gateway.DownstreamFenceDecision{}, nil
}

type networkProviderResolver struct {
	resolver *automationFencedResolver
}

func (r networkProviderResolver) Resolve(_ context.Context, reference string) (gateway.Endpoint, error) {
	if reference != "ref:browser-session:browser-test" {
		return gateway.Endpoint{}, gateway.ErrReferenceUnavailable
	}
	return gateway.Endpoint{
		Reference: reference, SandboxID: "sandbox-browser", BrowserSessionID: "ses-browser",
		CapabilityProfileID: BrowserAutomationSubprotocol, ConnectionGeneration: 3,
		ExpiresAt: time.Now().UTC().Add(time.Minute),
		Dial: func(context.Context) (gateway.Stream, error) {
			return newAutomationBackendStream(r.resolver), nil
		},
	}, nil
}

func (r *automationFencedResolver) ResolveFenced(_ context.Context, reference string, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence) (gateway.Endpoint, error) {
	if reference != "ref:browser-session:browser-test" || fence.Validate() != nil {
		return gateway.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	r.mu.Lock()
	r.resolveCalls++
	resolveCall := r.resolveCalls
	r.subject = subject
	r.mu.Unlock()
	return gateway.Endpoint{
		Reference: reference, SandboxID: subject.SandboxID, BrowserSessionID: subject.BrowserSessionID,
		CapabilityProfileID: subject.CapabilityProfileID, ConnectionGeneration: subject.ConnectionGeneration,
		ExpiresAt: subject.ExpiresAt,
		Dial: func(context.Context) (gateway.Stream, error) {
			stream := newAutomationBackendStream(r)
			if r.closeFirst && resolveCall == 1 {
				stream.once.Do(func() { close(stream.done) })
			}
			return stream, nil
		},
	}, nil
}

type automationBackendStream struct {
	resolver *automationFencedResolver
	frames   chan gateway.Frame
	done     chan struct{}
	once     sync.Once
}

func newAutomationBackendStream(resolver *automationFencedResolver) *automationBackendStream {
	return &automationBackendStream{resolver: resolver, frames: make(chan gateway.Frame, 1), done: make(chan struct{})}
}

func (s *automationBackendStream) Send(ctx context.Context, frame gateway.Frame) error {
	if frame.Type != gateway.TextFrame {
		return errors.New("expected CDP text frame")
	}
	var request cdpRequest
	if err := json.Unmarshal(frame.Payload, &request); err != nil || request.ID < 1 || request.Method != "Runtime.evaluate" {
		return errors.New("invalid translated CDP request")
	}
	s.resolver.mu.Lock()
	s.resolver.lastAction = string(frame.Payload)
	blocked := s.resolver.blockResponses
	s.resolver.mu.Unlock()
	if blocked {
		return nil
	}
	response := map[string]any{"id": request.ID, "result": map[string]any{"result": map[string]any{"type": "object", "value": map[string]any{"title": "example", "url": "https://example.test/"}}}}
	encoded, _ := json.Marshal(response)
	select {
	case s.frames <- gateway.Frame{Type: gateway.TextFrame, Payload: encoded}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return io.ErrClosedPipe
	}
}

func (s *automationBackendStream) Receive(ctx context.Context) (gateway.Frame, error) {
	select {
	case frame := <-s.frames:
		return frame, nil
	case <-s.done:
		return gateway.Frame{}, io.EOF
	case <-ctx.Done():
		return gateway.Frame{}, ctx.Err()
	}
}

func (s *automationBackendStream) Close(context.Context) error {
	s.once.Do(func() { close(s.done) })
	return nil
}

var _ gateway.ConnectionCapacity = (*automationFencedCapacity)(nil)
var _ gateway.FencedConnectionLease = (*automationFencedLease)(nil)
var _ gateway.FencedReferenceResolver = (*automationFencedResolver)(nil)
var _ gateway.DownstreamFenceAuthority = (*networkFenceAuthority)(nil)
var _ gateway.ReferenceResolver = networkProviderResolver{}
var _ gateway.Stream = (*automationBackendStream)(nil)
