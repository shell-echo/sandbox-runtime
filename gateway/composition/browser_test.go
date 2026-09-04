package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

func TestNewBrowserFailsClosedForEveryRequiredDependency(t *testing.T) {
	base := validBrowserOptions(t, &browserProviderResolverSpy{})
	tests := []struct {
		name string
		edit func(*BrowserOptions)
	}{
		{"authorizer", func(options *BrowserOptions) { options.Authorizer = nil }},
		{"revocations", func(options *BrowserOptions) { options.Revocations = nil }},
		{"recorder", func(options *BrowserOptions) { options.Recorder = nil }},
		{"provider resolver", func(options *BrowserOptions) { options.Resolver = nil }},
		{"typed nil provider resolver", func(options *BrowserOptions) {
			var resolver *browserProviderResolverSpy
			options.Resolver = resolver
		}},
		{"WebSocket admission", func(options *BrowserOptions) { options.WebSocket.Admission = nil }},
		{"invalid frame limit", func(options *BrowserOptions) { options.WebSocket.MaxFrameBytes = adapter.MaxFrameBytes + 1 }},
		{"invalid reconnect limit", func(options *BrowserOptions) { options.MaxReconnects = gateway.MaxReconnectAttempts + 1 }},
		{"missing total connection capacity", func(options *BrowserOptions) { options.MaxConnections = 0 }},
		{"missing per-session connection capacity", func(options *BrowserOptions) { options.MaxConnectionsPerSession = 0 }},
		{"per-session capacity exceeds total", func(options *BrowserOptions) { options.MaxConnectionsPerSession = options.MaxConnections + 1 }},
		{"total connection capacity exceeds bound", func(options *BrowserOptions) { options.MaxConnections = gateway.MaxConnectionCapacity + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.edit(&options)
			service, err := NewBrowser(options)
			if service != nil || !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("NewBrowser() = %v, %v; want nil, invalid options", service, err)
			}
		})
	}
}

func TestBrowserConnectDeniesCrossTenantBeforeReferenceResolution(t *testing.T) {
	resolver := &browserProviderResolverSpy{resolve: func(context.Context, string) (browserreference.Endpoint, error) {
		t.Fatal("Browser reference resolved before caller authorization")
		return browserreference.Endpoint{}, nil
	}}
	options := validBrowserOptions(t, resolver)
	options.Authorizer = testAuthorizer(func(_ context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
		if request.TenantID != "tenant-1" {
			return gateway.Grant{}, gateway.ErrUnauthorized
		}
		return browserGrantFor(request), nil
	})
	service, err := NewBrowser(options)
	if err != nil {
		t.Fatal(err)
	}
	request := validBrowserRequest()
	request.TenantID = "tenant-other"
	client := newGatewayStream()
	if err := service.Connect(context.Background(), request, client); !errors.Is(err, gateway.ErrUnauthorized) {
		t.Fatalf("Connect() error = %v; want unauthorized", err)
	}
	if resolver.Calls() != 0 || !client.Closed() {
		t.Fatalf("denied connect resolved=%d closed=%t", resolver.Calls(), client.Closed())
	}
}

func TestBrowserConnectRejectsMismatchedProviderIdentity(t *testing.T) {
	resolver := &browserProviderResolverSpy{resolve: func(_ context.Context, value string) (browserreference.Endpoint, error) {
		endpoint := browserEndpoint(value, newBrowserRawStream())
		endpoint.BrowserSessionID = "browser-session-other"
		return endpoint, nil
	}}
	service, err := NewBrowser(validBrowserOptions(t, resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Connect(context.Background(), validBrowserRequest(), newGatewayStream()); !errors.Is(err, gateway.ErrStaleReference) {
		t.Fatalf("Connect() error = %v; want stale reference", err)
	}
}

func TestBrowserConnectRejectsExpiredAndTypedNilProviderEndpoints(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		resolver := &browserProviderResolverSpy{resolve: func(_ context.Context, value string) (browserreference.Endpoint, error) {
			endpoint := browserEndpoint(value, newBrowserRawStream())
			endpoint.ExpiresAt = compositionTestTime
			return endpoint, nil
		}}
		service, err := NewBrowser(validBrowserOptions(t, resolver))
		if err != nil {
			t.Fatal(err)
		}
		client := newGatewayStream()
		if err := service.Connect(context.Background(), validBrowserRequest(), client); !errors.Is(err, gateway.ErrExpired) {
			t.Fatalf("Connect() error = %v; want expired", err)
		}
		if !client.Closed() {
			t.Fatal("expired Browser endpoint left caller stream open")
		}
	})
	t.Run("typed nil stream", func(t *testing.T) {
		resolver := &browserProviderResolverSpy{resolve: func(_ context.Context, value string) (browserreference.Endpoint, error) {
			var stream *browserRawStream
			return browserEndpoint(value, stream), nil
		}}
		service, err := NewBrowser(validBrowserOptions(t, resolver))
		if err != nil {
			t.Fatal(err)
		}
		client := newGatewayStream()
		if err := service.Connect(context.Background(), validBrowserRequest(), client); !errors.Is(err, gateway.ErrReconnectExhausted) {
			t.Fatalf("Connect() error = %v; want reconnect exhausted", err)
		}
		if resolver.Calls() != gateway.MaxReconnectAttempts+1 || !client.Closed() {
			t.Fatalf("typed nil handling: calls=%d closed=%t", resolver.Calls(), client.Closed())
		}
	})
}

func TestBrowserConnectBridgesCDPFramesAndRecordsMetadataOnly(t *testing.T) {
	backend := newBrowserRawStream()
	resolver := &browserProviderResolverSpy{resolve: func(_ context.Context, value string) (browserreference.Endpoint, error) {
		return browserEndpoint(value, backend), nil
	}}
	recorder := &testRecorder{}
	options := validBrowserOptions(t, resolver)
	options.Recorder = recorder
	service, err := NewBrowser(options)
	if err != nil {
		t.Fatal(err)
	}
	client := newGatewayStream()
	done := make(chan error, 1)
	go func() { done <- service.Connect(context.Background(), validBrowserRequest(), client) }()

	secretRequest := []byte(`{"id":1,"method":"Browser.getVersion"}`)
	client.ReceiveFrame(gateway.Frame{Type: gateway.TextFrame, Payload: secretRequest})
	operation, payload := backend.WaitClientMessage(t)
	if operation != ws.OpText || !bytes.Equal(payload, secretRequest) {
		t.Fatalf("private Browser message = %v %q", operation, payload)
	}
	secretResponse := []byte(`{"id":1,"result":{"product":"Chrome"}}`)
	backend.SendServerMessage(t, ws.OpText, secretResponse)
	frame := client.WaitSent(t)
	if frame.Type != gateway.TextFrame || !bytes.Equal(frame.Payload, secretResponse) {
		t.Fatalf("public Browser frame = %#v", frame)
	}
	client.CloseNow()
	if err := waitError(t, done); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	events := recorder.Events()
	if len(events) < 3 {
		t.Fatalf("audit events = %#v", events)
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, secretRequest) || bytes.Contains(encoded, secretResponse) {
		t.Fatalf("audit leaked CDP payload: %s", encoded)
	}
	for _, event := range events {
		if event.BrowserSessionID != "browser-session-1" || event.RuntimeSessionID != "" || event.TenantID == "" || event.SandboxID == "" {
			t.Fatalf("Browser audit identity = %#v", event)
		}
	}
}

func TestBrowserConnectRechecksReferenceOnReconnect(t *testing.T) {
	first, second := newBrowserRawStream(), newBrowserRawStream()
	resolver := &browserProviderResolverSpy{}
	resolver.resolve = func(_ context.Context, value string) (browserreference.Endpoint, error) {
		if resolver.Calls() == 1 {
			return browserEndpoint(value, first), nil
		}
		return browserEndpoint(value, second), nil
	}
	service, err := NewBrowser(validBrowserOptions(t, resolver))
	if err != nil {
		t.Fatal(err)
	}
	client := newGatewayStream()
	done := make(chan error, 1)
	go func() { done <- service.Connect(context.Background(), validBrowserRequest(), client) }()
	resolver.WaitCalls(t, 1)
	first.EndReads()
	resolver.WaitCalls(t, 2)
	second.SendServerMessage(t, ws.OpText, []byte(`{"method":"Target.targetCreated"}`))
	if frame := client.WaitSent(t); frame.Type != gateway.TextFrame || !bytes.Contains(frame.Payload, []byte("Target.targetCreated")) {
		t.Fatalf("reconnected frame = %#v", frame)
	}
	client.CloseNow()
	if err := waitError(t, done); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if resolver.Calls() != 2 || first.CloseCalls() == 0 || second.CloseCalls() == 0 {
		t.Fatalf("reconnect evidence: calls=%d first closes=%d second closes=%d", resolver.Calls(), first.CloseCalls(), second.CloseCalls())
	}
}

func TestBrowserConnectRevocationInterruptsActiveProxy(t *testing.T) {
	backend := newBrowserRawStream()
	resolver := &browserProviderResolverSpy{resolve: func(_ context.Context, value string) (browserreference.Endpoint, error) {
		return browserEndpoint(value, backend), nil
	}}
	revocations := newTestRevocations()
	recorder := &testRecorder{}
	options := validBrowserOptions(t, resolver)
	options.Revocations = revocations
	options.Recorder = recorder
	service, err := NewBrowser(options)
	if err != nil {
		t.Fatal(err)
	}
	client := newGatewayStream()
	done := make(chan error, 1)
	go func() { done <- service.Connect(context.Background(), validBrowserRequest(), client) }()
	revocations.WaitWatch(t)
	recorder.WaitEvent(t, gateway.AuditConnected)
	revocations.Revoke()
	if err := waitError(t, done); !errors.Is(err, gateway.ErrRevoked) {
		t.Fatalf("Connect() error = %v; want revoked", err)
	}
	if !client.Closed() || backend.CloseCalls() == 0 {
		t.Fatalf("revocation closure: client=%t backend=%d", client.Closed(), backend.CloseCalls())
	}
	retry := newGatewayStream()
	if err := service.Connect(context.Background(), validBrowserRequest(), retry); !errors.Is(err, gateway.ErrRevoked) {
		t.Fatalf("Connect() after revocation error = %v; want revoked", err)
	}
	if !retry.Closed() {
		t.Fatal("revoked retry stream was not closed")
	}
}

func TestBrowserConnectEnforcesAndReleasesLocalCapacity(t *testing.T) {
	resolver := &browserProviderResolverSpy{resolve: func(_ context.Context, value string) (browserreference.Endpoint, error) {
		stream := newBrowserRawStream()
		request := browserRequestFor(value)
		endpoint := browserEndpoint(value, stream)
		endpoint.SandboxID = request.SandboxID
		endpoint.BrowserSessionID = request.BrowserSessionID
		return endpoint, nil
	}}
	recorder := &testRecorder{}
	revocations := newTestRevocations()
	options := validBrowserOptions(t, resolver)
	options.MaxConnections = 2
	options.MaxConnectionsPerSession = 1
	options.Recorder = recorder
	options.Revocations = revocations
	options.Authorizer = testAuthorizer(func(_ context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
		grant := browserGrantFor(request)
		grant.GrantID = "grant-" + request.BrowserSessionID
		return grant, nil
	})
	service, err := NewBrowser(options)
	if err != nil {
		t.Fatal(err)
	}

	firstRequest := browserRequestFor("ref:browser-session:11111111111111111111111111111111")
	secondRequest := browserRequestFor("ref:browser-session:22222222222222222222222222222222")
	firstClient := newGatewayStream()
	firstDone := make(chan error, 1)
	go func() { firstDone <- service.Connect(context.Background(), firstRequest, firstClient) }()
	resolver.WaitCalls(t, 1)
	wantChecks, wantWatches := revocations.Counts()
	perSessionClient := newGatewayStream()
	if err := service.Connect(context.Background(), firstRequest, perSessionClient); !errors.Is(err, gateway.ErrCapacityExhausted) {
		t.Fatalf("per-session Connect() error = %v; want capacity exhausted", err)
	}
	if resolver.Calls() != 1 || !perSessionClient.Closed() {
		t.Fatalf("per-session rejection resolved=%d closed=%t", resolver.Calls(), perSessionClient.Closed())
	}
	if checks, watches := revocations.Counts(); checks != wantChecks || watches != wantWatches {
		t.Fatalf("per-session rejection reached revocations: checks=%d/%d watches=%d/%d", checks, wantChecks, watches, wantWatches)
	}

	secondClient := newGatewayStream()
	secondDone := make(chan error, 1)
	go func() { secondDone <- service.Connect(context.Background(), secondRequest, secondClient) }()
	resolver.WaitCalls(t, 2)
	wantChecks, wantWatches = revocations.Counts()

	const contenders = 32
	results := make(chan error, contenders)
	clients := make([]*gatewayStream, contenders)
	for index := range clients {
		clients[index] = newGatewayStream()
		go func(client *gatewayStream) {
			results <- service.Connect(context.Background(), firstRequest, client)
		}(clients[index])
	}
	for range contenders {
		if err := <-results; !errors.Is(err, gateway.ErrCapacityExhausted) {
			t.Fatalf("same-session concurrent Connect() error = %v; want capacity exhausted", err)
		}
	}
	thirdClient := newGatewayStream()
	if err := service.Connect(context.Background(), browserRequestFor("ref:browser-session:33333333333333333333333333333333"), thirdClient); !errors.Is(err, gateway.ErrCapacityExhausted) {
		t.Fatalf("total-capacity Connect() error = %v; want capacity exhausted", err)
	}
	if resolver.Calls() != 2 {
		t.Fatalf("capacity rejection reached Provider resolver %d times; want 2", resolver.Calls())
	}
	if checks, watches := revocations.Counts(); checks != wantChecks || watches != wantWatches {
		t.Fatalf("global rejection reached revocations: checks=%d/%d watches=%d/%d", checks, wantChecks, watches, wantWatches)
	}
	for _, client := range append(clients, thirdClient) {
		if !client.Closed() {
			t.Fatal("capacity-rejected Browser stream was not closed")
		}
	}

	firstClient.CloseNow()
	if err := waitError(t, firstDone); err != nil {
		t.Fatalf("first Connect() error = %v", err)
	}
	replacement := newGatewayStream()
	replacementDone := make(chan error, 1)
	go func() { replacementDone <- service.Connect(context.Background(), firstRequest, replacement) }()
	resolver.WaitCalls(t, 3)
	replacement.CloseNow()
	if err := waitError(t, replacementDone); err != nil {
		t.Fatalf("replacement Connect() error = %v", err)
	}
	secondClient.CloseNow()
	if err := waitError(t, secondDone); err != nil {
		t.Fatalf("second Connect() error = %v", err)
	}

	capacityEvents := 0
	for _, event := range recorder.Events() {
		if event.Type == gateway.AuditCapacityRejected {
			capacityEvents++
			if event.BrowserSessionID == "" || event.RuntimeSessionID != "" || event.TenantID == "" || event.SandboxID == "" {
				t.Fatalf("capacity audit identity = %#v", event)
			}
		}
	}
	if capacityEvents != contenders+2 {
		t.Fatalf("capacity audit events = %d; want %d", capacityEvents, contenders+2)
	}
}

func TestBrowserServeUsesPublicAndPrivateWebSocketAdapters(t *testing.T) {
	backend := newBrowserRawStream()
	resolver := &browserProviderResolverSpy{resolve: func(_ context.Context, value string) (browserreference.Endpoint, error) {
		return browserEndpoint(value, backend), nil
	}}
	admitted := 0
	options := validBrowserOptions(t, resolver)
	options.WebSocket.Admission = func(context.Context, *http.Request) error {
		admitted++
		return nil
	}
	service, err := NewBrowser(options)
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		serveResult <- service.Serve(request.Context(), response, request, validBrowserRequest())
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	requestPayload := []byte(`{"id":7,"method":"Browser.getVersion"}`)
	if err := client.Write(ctx, websocket.MessageText, requestPayload); err != nil {
		t.Fatal(err)
	}
	operation, payload := backend.WaitClientMessage(t)
	if operation != ws.OpText || !reflect.DeepEqual(payload, requestPayload) {
		t.Fatalf("private Browser message = %v %q", operation, payload)
	}
	responsePayload := []byte(`{"id":7,"result":{"product":"Chrome"}}`)
	backend.SendServerMessage(t, ws.OpText, responsePayload)
	messageType, payload, err := client.Read(ctx)
	if err != nil || messageType != websocket.MessageText || !reflect.DeepEqual(payload, responsePayload) {
		t.Fatalf("public Browser response = %v %q, %v", messageType, payload, err)
	}
	if err := client.Close(websocket.StatusNormalClosure, ""); err != nil {
		t.Fatal(err)
	}
	if err := waitError(t, serveResult); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if admitted != 1 {
		t.Fatalf("handshake admissions = %d; want one", admitted)
	}
}

func validBrowserOptions(t *testing.T, resolver BrowserProviderResolver) BrowserOptions {
	t.Helper()
	return BrowserOptions{
		Authorizer: testAuthorizer(func(_ context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
			return browserGrantFor(request), nil
		}),
		Revocations: newTestRevocations(), Recorder: &testRecorder{}, Resolver: resolver,
		WebSocket:      adapter.WebSocketOptions{Admission: func(context.Context, *http.Request) error { return nil }},
		Clock:          gateway.ClockFunc(func() time.Time { return compositionTestTime }),
		MaxConnections: 8, MaxConnectionsPerSession: 1,
	}
}

func validBrowserRequest() gateway.ConnectRequest {
	return browserRequestFor("ref:browser-session:11111111111111111111111111111111")
}

func browserRequestFor(reference string) gateway.ConnectRequest {
	sessionID := "browser-session-" + string(reference[len(reference)-1])
	return gateway.ConnectRequest{
		CallerID: "caller-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
		BrowserSessionID: sessionID, CapabilityProfileID: providerbrowser.CapabilityProfileID,
		HandoffReference: reference,
	}
}

func browserGrantFor(request gateway.ConnectRequest) gateway.Grant {
	return gateway.Grant{
		GrantID: "browser-grant-1", CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: 1, ExpiresAt: compositionTestTime.Add(time.Minute),
	}
}

func browserEndpoint(value string, stream providerbrowser.Stream) browserreference.Endpoint {
	return browserreference.Endpoint{
		Reference: value, SandboxID: "sandbox-1", BrowserSessionID: "browser-session-1",
		CapabilityProfileID: providerbrowser.CapabilityProfileID, ConnectionGeneration: 1,
		ExpiresAt: compositionTestTime.Add(time.Minute),
		Dial:      func(context.Context) (providerbrowser.Stream, error) { return stream, nil },
	}
}

type browserProviderResolverSpy struct {
	mu      sync.Mutex
	calls   int
	resolve func(context.Context, string) (browserreference.Endpoint, error)
}

func (r *browserProviderResolverSpy) Resolve(ctx context.Context, value string) (browserreference.Endpoint, error) {
	r.mu.Lock()
	r.calls++
	resolve := r.resolve
	r.mu.Unlock()
	if resolve == nil {
		return browserreference.Endpoint{}, errors.New("test Browser resolver is not configured")
	}
	return resolve(ctx, value)
}

func (r *browserProviderResolverSpy) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *browserProviderResolverSpy) WaitCalls(t *testing.T, want int) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if r.Calls() >= want {
			return
		}
		select {
		case <-time.After(time.Millisecond):
		case <-deadline.C:
			t.Fatalf("Browser resolver calls = %d; want at least %d", r.Calls(), want)
		}
	}
}

type browserRead struct {
	payload []byte
	err     error
}

type browserRawStream struct {
	reads  chan browserRead
	done   chan struct{}
	notify chan struct{}
	once   sync.Once

	readMu     sync.Mutex
	pending    []byte
	pendingErr error
	writeMu    sync.Mutex
	written    bytes.Buffer
	closeMu    sync.Mutex
	closes     int
}

func newBrowserRawStream() *browserRawStream {
	return &browserRawStream{reads: make(chan browserRead, 8), done: make(chan struct{}), notify: make(chan struct{}, 1)}
}

func (s *browserRawStream) Read(ctx context.Context, target []byte) (int, error) {
	for {
		s.readMu.Lock()
		if len(s.pending) > 0 {
			count := copy(target, s.pending)
			s.pending = s.pending[count:]
			var err error
			if len(s.pending) == 0 {
				err, s.pendingErr = s.pendingErr, nil
			}
			s.readMu.Unlock()
			return count, err
		}
		if s.pendingErr != nil {
			err := s.pendingErr
			s.pendingErr = nil
			s.readMu.Unlock()
			return 0, err
		}
		s.readMu.Unlock()
		select {
		case result := <-s.reads:
			s.readMu.Lock()
			s.pending = append(s.pending[:0], result.payload...)
			s.pendingErr = result.err
			s.readMu.Unlock()
		case <-s.done:
			return 0, io.EOF
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (s *browserRawStream) Write(ctx context.Context, value []byte) (int, error) {
	select {
	case <-s.done:
		return 0, io.ErrClosedPipe
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	s.writeMu.Lock()
	count, err := s.written.Write(value)
	s.writeMu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return count, err
}

func (s *browserRawStream) Close() error {
	s.closeMu.Lock()
	s.closes++
	s.closeMu.Unlock()
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *browserRawStream) SendServerMessage(t *testing.T, operation ws.OpCode, payload []byte) {
	t.Helper()
	var wire bytes.Buffer
	if err := wsutil.WriteServerMessage(&wire, operation, payload); err != nil {
		t.Fatal(err)
	}
	s.reads <- browserRead{payload: wire.Bytes()}
}

func (s *browserRawStream) EndReads() { s.reads <- browserRead{err: io.EOF} }

func (s *browserRawStream) WaitClientMessage(t *testing.T) (ws.OpCode, []byte) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		s.writeMu.Lock()
		wire := append([]byte(nil), s.written.Bytes()...)
		s.writeMu.Unlock()
		if len(wire) > 0 {
			payload, operation, err := wsutil.ReadClientData(bytes.NewBuffer(wire))
			if err == nil {
				return operation, payload
			}
		}
		select {
		case <-s.notify:
		case <-time.After(time.Millisecond):
		case <-deadline.C:
			t.Fatal("timed out waiting for private Browser message")
			return 0, nil
		}
	}
}

func (s *browserRawStream) CloseCalls() int {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closes
}
