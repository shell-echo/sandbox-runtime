package composition

import (
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
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

var compositionTestTime = time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)

func TestNewFailsClosedForEveryRequiredDependency(t *testing.T) {
	base := validOptions(t, &testProviderResolver{})
	tests := []struct {
		name string
		edit func(*Options)
	}{
		{"authorizer", func(options *Options) { options.Authorizer = nil }},
		{"revocations", func(options *Options) { options.Revocations = nil }},
		{"recorder", func(options *Options) { options.Recorder = nil }},
		{"provider resolver", func(options *Options) { options.Resolver = nil }},
		{"typed nil provider resolver", func(options *Options) {
			var resolver *testProviderResolver
			options.Resolver = resolver
		}},
		{"WebSocket admission", func(options *Options) { options.WebSocket.Admission = nil }},
		{"invalid WebSocket limits", func(options *Options) { options.WebSocket.MaxFrameBytes = adapter.MaxFrameBytes + 1 }},
		{"invalid reconnect limit", func(options *Options) { options.MaxReconnects = gateway.MaxReconnectAttempts + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.edit(&options)
			service, err := New(options)
			if service != nil || !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("New() = %v, %v; want nil, invalid options", service, err)
			}
		})
	}
}

func TestConnectEnforcesAuthorizationBindingAndCrossTenantDenial(t *testing.T) {
	tests := []struct {
		name       string
		authorize  func(context.Context, gateway.ConnectRequest) (gateway.Grant, error)
		want       error
		resolverOK bool
	}{
		{
			name: "mismatched grant binding",
			authorize: func(_ context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
				grant := grantFor(request)
				grant.TenantID = "other-tenant"
				return grant, nil
			},
			want: gateway.ErrUnauthorized,
		},
		{
			name: "cross tenant denied by caller policy",
			authorize: func(_ context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
				if request.TenantID == "other-tenant" {
					return gateway.Grant{}, errors.New("caller tenant policy denied request")
				}
				return grantFor(request), nil
			},
			want: gateway.ErrUnauthorized,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &testProviderResolver{resolve: func(context.Context, string) (reference.Endpoint, error) {
				t.Fatal("Provider resolver must not run before a valid caller grant")
				return reference.Endpoint{}, nil
			}}
			options := validOptions(t, resolver)
			options.Authorizer = testAuthorizer(test.authorize)
			service, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			request := validRequest()
			if test.name == "cross tenant denied by caller policy" {
				request.TenantID = "other-tenant"
			}
			client := newGatewayStream()
			err = service.Connect(context.Background(), request, client)
			if !errors.Is(err, test.want) {
				t.Fatalf("Connect() error = %v; want %v", err, test.want)
			}
			if !client.Closed() {
				t.Fatal("Connect() did not close denied caller stream")
			}
			if resolver.Calls() != 0 {
				t.Fatalf("resolver calls = %d; want 0", resolver.Calls())
			}
		})
	}
}

func TestConnectProjectsFreshProviderTerminalStreamAndMetadataOnlyAudit(t *testing.T) {
	first := newTerminalStream()
	resolver := &testProviderResolver{resolve: func(_ context.Context, value string) (reference.Endpoint, error) {
		return terminalEndpoint(value, first), nil
	}}
	recorder := &testRecorder{}
	options := validOptions(t, resolver)
	options.Recorder = recorder
	service, err := New(options)
	if err != nil {
		t.Fatal(err)
	}

	client := newGatewayStream()
	done := make(chan error, 1)
	go func() { done <- service.Connect(context.Background(), validRequest(), client) }()

	secretInput := []byte("terminal-input-must-not-be-audit-data")
	client.ReceiveFrame(gateway.Frame{Type: gateway.TextFrame, Payload: secretInput})
	if got := first.WaitWrite(t); !reflect.DeepEqual(got, secretInput) {
		t.Fatalf("terminal write = %q; want %q", got, secretInput)
	}

	secretOutput := []byte("terminal-output-must-not-be-audit-data")
	first.ReadFrame(secretOutput)
	frame := client.WaitSent(t)
	if frame.Type != gateway.BinaryFrame || !reflect.DeepEqual(frame.Payload, secretOutput) {
		t.Fatalf("client frame = %#v; want binary %q", frame, secretOutput)
	}
	client.CloseNow()
	if err := waitError(t, done); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if resolver.Calls() != 1 || first.CloseCalls() == 0 {
		t.Fatalf("resolver calls = %d, terminal close calls = %d; want 1 and nonzero", resolver.Calls(), first.CloseCalls())
	}

	events := recorder.Events()
	if len(events) < 3 {
		t.Fatalf("audit events = %d; want authorization, connect, close", len(events))
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), string(secretInput)) || strings.Contains(string(encoded), string(secretOutput)) {
		t.Fatalf("audit records leaked terminal payload: %s", encoded)
	}
	for _, event := range events {
		if event.GrantID == "" || event.TenantID == "" || event.SandboxID == "" || event.RuntimeSessionID == "" {
			t.Fatalf("audit event lacks identity metadata: %#v", event)
		}
	}
}

func TestConnectRejectsExpiredProviderEndpoint(t *testing.T) {
	resolver := &testProviderResolver{resolve: func(_ context.Context, value string) (reference.Endpoint, error) {
		endpoint := terminalEndpoint(value, newTerminalStream())
		endpoint.ExpiresAt = compositionTestTime
		return endpoint, nil
	}}
	service, err := New(validOptions(t, resolver))
	if err != nil {
		t.Fatal(err)
	}
	client := newGatewayStream()
	err = service.Connect(context.Background(), validRequest(), client)
	if !errors.Is(err, gateway.ErrExpired) {
		t.Fatalf("Connect() error = %v; want expired", err)
	}
	if !client.Closed() {
		t.Fatal("expired endpoint left caller stream open")
	}
}

func TestConnectFailsClosedForIncompleteProviderEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint reference.Endpoint
		want     error
	}{
		{"missing dial", reference.Endpoint{
			Reference: validRequest().HandoffReference, ConnectionGeneration: 1,
			ExpiresAt: compositionTestTime.Add(time.Minute),
		}, gateway.ErrReferenceUnavailable},
		{"typed nil terminal stream", reference.Endpoint{
			Reference: validRequest().HandoffReference, ConnectionGeneration: 1,
			SandboxID: "sandbox-1", RuntimeSessionID: "session-1", CapabilityProfileID: "terminal-v1",
			ExpiresAt: compositionTestTime.Add(time.Minute),
			Dial: func(context.Context) (terminal.Stream, error) {
				var stream *terminalStream
				return stream, nil
			},
		}, gateway.ErrReconnectExhausted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &testProviderResolver{resolve: func(context.Context, string) (reference.Endpoint, error) {
				return test.endpoint, nil
			}}
			service, err := New(validOptions(t, resolver))
			if err != nil {
				t.Fatal(err)
			}
			client := newGatewayStream()
			err = service.Connect(context.Background(), validRequest(), client)
			if !errors.Is(err, test.want) {
				t.Fatalf("Connect() error = %v; want %v", err, test.want)
			}
			if !client.Closed() {
				t.Fatal("incomplete Provider endpoint left caller stream open")
			}
		})
	}
}

func TestConnectRechecksProviderReferenceForEachReconnect(t *testing.T) {
	first := newTerminalStream()
	first.EndReads()
	second := newTerminalStream()
	resolver := &testProviderResolver{}
	resolver.resolve = func(_ context.Context, value string) (reference.Endpoint, error) {
		if resolver.Calls() == 1 {
			return terminalEndpoint(value, first), nil
		}
		return terminalEndpoint(value, second), nil
	}
	service, err := New(validOptions(t, resolver))
	if err != nil {
		t.Fatal(err)
	}
	client := newGatewayStream()
	done := make(chan error, 1)
	go func() { done <- service.Connect(context.Background(), validRequest(), client) }()
	resolver.WaitCalls(t, 2)
	client.CloseNow()
	if err := waitError(t, done); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if calls := resolver.Calls(); calls != 2 {
		t.Fatalf("resolver calls = %d; want 2 fresh resolutions", calls)
	}
	if first.CloseCalls() == 0 || second.CloseCalls() == 0 {
		t.Fatalf("terminal streams were not both closed: first=%d second=%d", first.CloseCalls(), second.CloseCalls())
	}
}

func TestConnectFailsAfterReconnectExhaustion(t *testing.T) {
	first := newTerminalStream()
	first.EndReads()
	resolver := &testProviderResolver{}
	resolver.resolve = func(_ context.Context, value string) (reference.Endpoint, error) {
		if resolver.Calls() == 1 {
			return terminalEndpoint(value, first), nil
		}
		return reference.Endpoint{}, errors.New("Provider reference temporarily unavailable")
	}
	service, err := New(validOptions(t, resolver))
	if err != nil {
		t.Fatal(err)
	}
	client := newGatewayStream()
	err = service.Connect(context.Background(), validRequest(), client)
	if !errors.Is(err, gateway.ErrReconnectExhausted) {
		t.Fatalf("Connect() error = %v; want reconnect exhaustion", err)
	}
	if calls := resolver.Calls(); calls != gateway.MaxReconnectAttempts+1 {
		t.Fatalf("resolver calls = %d; want %d", calls, gateway.MaxReconnectAttempts+1)
	}
	if !client.Closed() {
		t.Fatal("reconnect exhaustion left caller stream open")
	}
}

func TestConnectRevocationInterruptsActiveTerminalProxy(t *testing.T) {
	backend := newTerminalStream()
	resolver := &testProviderResolver{resolve: func(_ context.Context, value string) (reference.Endpoint, error) {
		return terminalEndpoint(value, backend), nil
	}}
	revocations := newTestRevocations()
	recorder := &testRecorder{}
	options := validOptions(t, resolver)
	options.Revocations = revocations
	options.Recorder = recorder
	service, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	client := newGatewayStream()
	done := make(chan error, 1)
	go func() { done <- service.Connect(context.Background(), validRequest(), client) }()
	revocations.WaitWatch(t)
	recorder.WaitEvent(t, gateway.AuditConnected)
	revocations.Revoke()
	if err := waitError(t, done); !errors.Is(err, gateway.ErrRevoked) {
		t.Fatalf("Connect() error = %v; want revoked", err)
	}
	if !client.Closed() || backend.CloseCalls() == 0 {
		t.Fatalf("revocation did not close both streams: client=%t backend=%d", client.Closed(), backend.CloseCalls())
	}
}

func TestServeUsesCallerAdmissionAndBothWireAdapters(t *testing.T) {
	backend := newTerminalStream()
	resolver := &testProviderResolver{resolve: func(_ context.Context, value string) (reference.Endpoint, error) {
		return terminalEndpoint(value, backend), nil
	}}
	var admitted int
	options := validOptions(t, resolver)
	options.WebSocket.Admission = func(context.Context, *http.Request) error {
		admitted++
		return nil
	}
	service, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	handler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveResult <- service.Serve(r.Context(), w, r, validRequest())
	}))
	defer handler.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(handler.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	input := []byte("WebSocket input")
	if err := client.Write(ctx, websocket.MessageBinary, input); err != nil {
		t.Fatal(err)
	}
	if got := backend.WaitWrite(t); !reflect.DeepEqual(got, input) {
		t.Fatalf("terminal write = %q; want %q", got, input)
	}
	output := []byte("WebSocket output")
	backend.ReadFrame(output)
	messageType, payload, err := client.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageBinary || !reflect.DeepEqual(payload, output) {
		t.Fatalf("WebSocket output = %v %q; want binary %q", messageType, payload, output)
	}
	if err := client.Close(websocket.StatusNormalClosure, ""); err != nil {
		t.Fatal(err)
	}
	if err := waitError(t, serveResult); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if admitted != 1 {
		t.Fatalf("handshake admissions = %d; want 1", admitted)
	}
}

func validOptions(t *testing.T, resolver ProviderResolver) Options {
	t.Helper()
	return Options{
		Authorizer: testAuthorizer(func(_ context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
			return grantFor(request), nil
		}),
		Revocations: newTestRevocations(),
		Recorder:    &testRecorder{},
		Resolver:    resolver,
		WebSocket: adapter.WebSocketOptions{
			Admission: func(context.Context, *http.Request) error { return nil },
		},
		Clock: gateway.ClockFunc(func() time.Time { return compositionTestTime }),
	}
}

func validRequest() gateway.ConnectRequest {
	return gateway.ConnectRequest{
		CallerID: "caller-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
		RuntimeSessionID: "session-1", CapabilityProfileID: "terminal-v1",
		HandoffReference: "ref:session:11111111111111111111111111111111",
	}
}

func grantFor(request gateway.ConnectRequest) gateway.Grant {
	return gateway.Grant{
		GrantID: "grant-1", CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: 1, ExpiresAt: compositionTestTime.Add(time.Minute),
	}
}

func terminalEndpoint(referenceValue string, stream terminal.Stream) reference.Endpoint {
	return reference.Endpoint{
		Reference: referenceValue, SandboxID: "sandbox-1", RuntimeSessionID: "session-1",
		CapabilityProfileID: "terminal-v1", ConnectionGeneration: 1,
		ExpiresAt: compositionTestTime.Add(time.Minute),
		Dial:      func(context.Context) (terminal.Stream, error) { return stream, nil },
	}
}

type testAuthorizer func(context.Context, gateway.ConnectRequest) (gateway.Grant, error)

func (a testAuthorizer) Authorize(ctx context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
	return a(ctx, request)
}

type testProviderResolver struct {
	mu      sync.Mutex
	calls   int
	resolve func(context.Context, string) (reference.Endpoint, error)
	called  chan struct{}
}

func (r *testProviderResolver) Resolve(ctx context.Context, value string) (reference.Endpoint, error) {
	r.mu.Lock()
	r.calls++
	resolve := r.resolve
	called := r.called
	r.mu.Unlock()
	if called != nil {
		select {
		case called <- struct{}{}:
		default:
		}
	}
	if resolve == nil {
		return reference.Endpoint{}, errors.New("test Provider resolver is not configured")
	}
	return resolve(ctx, value)
}

func (r *testProviderResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *testProviderResolver) WaitCalls(t *testing.T, want int) {
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
			t.Fatalf("resolver calls = %d; want at least %d", r.Calls(), want)
		}
	}
}

type testRevocations struct {
	mu      sync.Mutex
	revoked bool
	watch   *compositionRevocationWatch
	watched chan struct{}
	once    sync.Once
	watches int
}

func newTestRevocations() *testRevocations {
	return &testRevocations{watch: newCompositionRevocationWatch(), watched: make(chan struct{})}
}

type compositionRevocationWatch struct {
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newCompositionRevocationWatch() *compositionRevocationWatch {
	return &compositionRevocationWatch{done: make(chan struct{})}
}

func (w *compositionRevocationWatch) Done() <-chan struct{} { return w.done }

func (w *compositionRevocationWatch) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *compositionRevocationWatch) finish(err error) {
	w.once.Do(func() {
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
		close(w.done)
	})
}

func (r *testRevocations) Watch(context.Context, gateway.RevocationSubject) (gateway.RevocationWatch, error) {
	r.mu.Lock()
	r.watches++
	revoked := r.revoked
	r.mu.Unlock()
	if revoked {
		r.watch.finish(gateway.ErrRevoked)
	}
	r.once.Do(func() { close(r.watched) })
	return r.watch, nil
}

func (r *testRevocations) Counts() (checks, watches int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return 0, r.watches
}

func (r *testRevocations) Revoke() {
	r.mu.Lock()
	if !r.revoked {
		r.revoked = true
		r.watch.finish(gateway.ErrRevoked)
	}
	r.mu.Unlock()
}

func (r *testRevocations) WaitWatch(t *testing.T) {
	t.Helper()
	select {
	case <-r.watched:
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway did not establish a revocation watch")
	}
}

type testRecorder struct {
	mu     sync.Mutex
	events []gateway.AuditEvent
	err    error
}

func (r *testRecorder) Record(_ context.Context, event gateway.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return r.err
}

func (r *testRecorder) Events() []gateway.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]gateway.AuditEvent(nil), r.events...)
}

func (r *testRecorder) WaitEvent(t *testing.T, eventType gateway.AuditEventType) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		for _, event := range r.Events() {
			if event.Type == eventType {
				return
			}
		}
		select {
		case <-time.After(time.Millisecond):
		case <-deadline.C:
			t.Fatalf("Gateway audit events = %#v; want %s", r.Events(), eventType)
		}
	}
}

type gatewayStream struct {
	incoming chan gateway.Frame
	sent     chan gateway.Frame
	closed   chan struct{}
	once     sync.Once
}

func newGatewayStream() *gatewayStream {
	return &gatewayStream{incoming: make(chan gateway.Frame, 4), sent: make(chan gateway.Frame, 4), closed: make(chan struct{})}
}

func (s *gatewayStream) Receive(ctx context.Context) (gateway.Frame, error) {
	select {
	case frame := <-s.incoming:
		return frame.Clone(), nil
	case <-s.closed:
		return gateway.Frame{}, io.EOF
	case <-ctx.Done():
		return gateway.Frame{}, ctx.Err()
	}
}

func (s *gatewayStream) Send(ctx context.Context, frame gateway.Frame) error {
	select {
	case <-s.closed:
		return io.ErrClosedPipe
	case <-ctx.Done():
		return ctx.Err()
	case s.sent <- frame.Clone():
		return nil
	}
}

func (s *gatewayStream) Close(context.Context) error {
	s.CloseNow()
	return nil
}

func (s *gatewayStream) CloseNow() { s.once.Do(func() { close(s.closed) }) }

func (s *gatewayStream) Closed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *gatewayStream) ReceiveFrame(frame gateway.Frame) { s.incoming <- frame.Clone() }

func (s *gatewayStream) WaitSent(t *testing.T) gateway.Frame {
	t.Helper()
	select {
	case frame := <-s.sent:
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway did not send a frame to the caller")
		return gateway.Frame{}
	}
}

type terminalRead struct {
	payload []byte
	err     error
}

type terminalStream struct {
	reads  chan terminalRead
	writes chan []byte
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	closes int
}

func newTerminalStream() *terminalStream {
	return &terminalStream{reads: make(chan terminalRead, 4), writes: make(chan []byte, 4), closed: make(chan struct{})}
}

func (s *terminalStream) Read(ctx context.Context, target []byte) (int, error) {
	select {
	case result := <-s.reads:
		if len(result.payload) > len(target) {
			return 0, errors.New("test terminal payload exceeds adapter frame limit")
		}
		return copy(target, result.payload), result.err
	case <-s.closed:
		return 0, io.EOF
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (s *terminalStream) Write(ctx context.Context, value []byte) (int, error) {
	clone := append([]byte(nil), value...)
	select {
	case <-s.closed:
		return 0, io.ErrClosedPipe
	case <-ctx.Done():
		return 0, ctx.Err()
	case s.writes <- clone:
		return len(value), nil
	}
}

func (s *terminalStream) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closes++
		s.mu.Unlock()
		close(s.closed)
	})
	return nil
}

func (s *terminalStream) ReadFrame(payload []byte) {
	s.reads <- terminalRead{payload: append([]byte(nil), payload...)}
}
func (s *terminalStream) EndReads() { s.reads <- terminalRead{err: io.EOF} }

func (s *terminalStream) WaitWrite(t *testing.T) []byte {
	t.Helper()
	select {
	case value := <-s.writes:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway did not write to the terminal")
		return nil
	}
}

func (s *terminalStream) CloseCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

func waitError(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway operation did not complete")
		return nil
	}
}
