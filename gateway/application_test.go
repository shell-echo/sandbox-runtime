package gateway

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

var gatewayTestNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

type testAuthorizer struct {
	grant Grant
	err   error
}

func (a testAuthorizer) Authorize(context.Context, ConnectRequest) (Grant, error) {
	return a.grant, a.err
}

type testResolver struct {
	mu        sync.Mutex
	endpoints []Endpoint
	calls     int
}

func (r *testResolver) Resolve(context.Context, string) (Endpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if len(r.endpoints) == 0 {
		return Endpoint{}, ErrReferenceUnavailable
	}
	endpoint := r.endpoints[0]
	if len(r.endpoints) > 1 {
		r.endpoints = r.endpoints[1:]
	}
	return endpoint, nil
}

func (r *testResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type testRevocations struct {
	mu      sync.Mutex
	revoked map[string]bool
	watch   map[string]*testRevocationWatch
}

func newTestRevocations() *testRevocations {
	return &testRevocations{revoked: make(map[string]bool), watch: make(map[string]*testRevocationWatch)}
}

type testRevocationWatch struct {
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newTestRevocationWatch() *testRevocationWatch {
	return &testRevocationWatch{done: make(chan struct{})}
}

func (w *testRevocationWatch) Done() <-chan struct{} { return w.done }

func (w *testRevocationWatch) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *testRevocationWatch) finish(err error) {
	w.once.Do(func() {
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
		close(w.done)
	})
}

func (r *testRevocations) Watch(_ context.Context, subject RevocationSubject) (RevocationWatch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	watch := newTestRevocationWatch()
	if r.revoked[subject.GrantID] {
		watch.finish(ErrRevoked)
	} else {
		r.watch[subject.GrantID] = watch
	}
	return watch, nil
}

func (r *testRevocations) Revoke(grantID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked[grantID] {
		return
	}
	r.revoked[grantID] = true
	if watch := r.watch[grantID]; watch != nil {
		watch.finish(ErrRevoked)
		delete(r.watch, grantID)
	}
}

type testRecorder struct {
	mu     sync.Mutex
	events []AuditEvent
	err    error
}

func (r *testRecorder) Record(_ context.Context, event AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, event)
	return nil
}

func (r *testRecorder) Events() []AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AuditEvent(nil), r.events...)
}

type testStream struct {
	mu     sync.Mutex
	in     chan Frame
	out    chan Frame
	done   chan struct{}
	closed bool
}

func newTestStream() *testStream {
	return &testStream{in: make(chan Frame, 8), out: make(chan Frame, 8), done: make(chan struct{})}
}

func (s *testStream) Receive(ctx context.Context) (Frame, error) {
	select {
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case <-s.done:
		return Frame{}, io.EOF
	case frame := <-s.in:
		return frame, nil
	}
}

func (s *testStream) Send(ctx context.Context, frame Frame) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return io.EOF
	case s.out <- frame:
		return nil
	}
}

func (s *testStream) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.done)
	}
	return nil
}

func (s *testStream) push(frame Frame) { s.in <- frame }

func (s *testStream) pull(t *testing.T) Frame {
	t.Helper()
	select {
	case frame := <-s.out:
		return frame
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxied frame")
		return Frame{}
	}
}

func gatewayRequest() ConnectRequest {
	return ConnectRequest{
		CallerID: "user-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
		RuntimeSessionID: "session-1", CapabilityProfileID: "terminal-v1",
		HandoffReference: "ref:session:opaque-1",
	}
}

func gatewayGrant() Grant {
	request := gatewayRequest()
	return Grant{
		GrantID: "grant-1", CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: 4, ExpiresAt: gatewayTestNow.Add(time.Hour),
	}
}

func newTestGateway(t *testing.T, resolver ReferenceResolver, authorizer Authorizer, revocations *testRevocations, recorder *testRecorder) *Gateway {
	t.Helper()
	gateway, err := New(Options{
		Authorizer: authorizer, Resolver: resolver, Revocations: revocations, Recorder: recorder,
		Clock: ClockFunc(func() time.Time { return gatewayTestNow }), MaxReconnects: 2,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return gateway
}

func validEndpoint(stream *testStream) Endpoint {
	grant := gatewayGrant()
	return Endpoint{
		Reference: grant.HandoffReference, SandboxID: grant.SandboxID,
		RuntimeSessionID: grant.RuntimeSessionID, CapabilityProfileID: grant.CapabilityProfileID,
		ConnectionGeneration: grant.ConnectionGeneration,
		ExpiresAt:            grant.ExpiresAt, Dial: func(context.Context) (Stream, error) { return stream, nil },
	}
}

func TestValidateEndpointBoundsGrantToProviderExpiry(t *testing.T) {
	grant := gatewayGrant()
	endpoint := validEndpoint(newTestStream())
	endpoint.ExpiresAt = grant.ExpiresAt.Add(time.Minute)
	if err := validateEndpoint(endpoint, grant, gatewayTestNow); err != nil {
		t.Fatalf("shorter grant rejected: %v", err)
	}

	endpoint.ExpiresAt = grant.ExpiresAt.Add(-time.Minute)
	if err := validateEndpoint(endpoint, grant, gatewayTestNow); !errors.Is(err, ErrStaleReference) {
		t.Fatalf("grant beyond Provider expiry = %v, want ErrStaleReference", err)
	}
}

func TestGatewayConnectProxiesOpaqueFramesAndRecordsMetadataOnly(t *testing.T) {
	client, backend := newTestStream(), newTestStream()
	revocations, recorder := newTestRevocations(), &testRecorder{}
	gateway := newTestGateway(t, &testResolver{endpoints: []Endpoint{validEndpoint(backend)}}, testAuthorizer{grant: gatewayGrant()}, revocations, recorder)

	result := make(chan error, 1)
	go func() { result <- gateway.Connect(context.Background(), gatewayRequest(), client) }()

	client.push(Frame{Type: TextFrame, Payload: []byte("secret command")})
	gotBackend := backend.pull(t)
	if string(gotBackend.Payload) != "secret command" || gotBackend.Type != TextFrame {
		t.Fatalf("backend frame = %#v", gotBackend)
	}
	backend.push(Frame{Type: BinaryFrame, Payload: []byte("opaque output")})
	gotClient := client.pull(t)
	if string(gotClient.Payload) != "opaque output" || gotClient.Type != BinaryFrame {
		t.Fatalf("client frame = %#v", gotClient)
	}
	_ = client.Close(context.Background())
	if err := <-result; err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	events := recorder.Events()
	if len(events) < 3 || events[0].Type != AuditAuthorized || events[1].Type != AuditConnected || events[len(events)-1].Type != AuditClientClosed {
		t.Fatalf("audit events = %#v", events)
	}
	for _, event := range events {
		if event.Reason == "secret command" || event.Reason == "opaque output" || event.Bytes == 0 && event.Frames > 0 {
			t.Fatalf("audit event contains frame data: %#v", event)
		}
	}
}

func TestGatewayProxyExpiryUsesConfiguredClock(t *testing.T) {
	fixedNow := time.Unix(1, 0).UTC()
	client, backend := newTestStream(), newTestStream()
	revocations, recorder := newTestRevocations(), &testRecorder{}
	grant := gatewayGrant()
	grant.ExpiresAt = fixedNow.Add(time.Hour)
	endpoint := validEndpoint(backend)
	endpoint.ExpiresAt = grant.ExpiresAt
	gateway, err := New(Options{
		Authorizer:  testAuthorizer{grant: grant},
		Resolver:    &testResolver{endpoints: []Endpoint{endpoint}},
		Revocations: revocations,
		Recorder:    recorder,
		Clock:       ClockFunc(func() time.Time { return fixedNow }),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result := make(chan error, 1)
	go func() { result <- gateway.Connect(context.Background(), gatewayRequest(), client) }()
	client.push(Frame{Type: TextFrame, Payload: []byte("configured-clock")})
	if got := backend.pull(t); string(got.Payload) != "configured-clock" {
		t.Fatalf("backend frame = %#v", got)
	}
	_ = client.Close(context.Background())
	if err := <-result; err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
}

func TestGatewayReconnectsWithFreshOpaqueResolution(t *testing.T) {
	client, first, second := newTestStream(), newTestStream(), newTestStream()
	revocations, recorder := newTestRevocations(), &testRecorder{}
	resolver := &testResolver{endpoints: []Endpoint{validEndpoint(first), validEndpoint(second)}}
	gateway := newTestGateway(t, resolver, testAuthorizer{grant: gatewayGrant()}, revocations, recorder)
	result := make(chan error, 1)
	go func() { result <- gateway.Connect(context.Background(), gatewayRequest(), client) }()

	deadline := time.After(time.Second)
	for len(recorder.Events()) < 2 {
		select {
		case err := <-result:
			t.Fatalf("Connect() ended before initial connection: %v", err)
		case <-deadline:
			t.Fatal("gateway did not establish the initial proxy")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	client.push(Frame{Type: TextFrame, Payload: []byte("before reconnect")})
	if got := first.pull(t); string(got.Payload) != "before reconnect" {
		t.Fatalf("first backend frame = %#v", got)
	}
	_ = first.Close(context.Background())
	deadline = time.After(time.Second)
	for resolver.Calls() < 2 {
		select {
		case <-deadline:
			t.Fatal("gateway did not resolve a fresh handoff")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	second.push(Frame{Type: TextFrame, Payload: []byte("after reconnect")})
	if got := client.pull(t); string(got.Payload) != "after reconnect" {
		t.Fatalf("reconnected client frame = %#v", got)
	}
	_ = client.Close(context.Background())
	if err := <-result; err != nil {
		t.Fatalf("Connect() after reconnect error = %v", err)
	}
	events := recorder.Events()
	seenReconnect := false
	for _, event := range events {
		if event.Type == AuditReconnected {
			seenReconnect = true
		}
	}
	if !seenReconnect {
		t.Fatalf("audit events lack reconnect: %#v", events)
	}
}

func TestGatewayRevocationInterruptsActiveProxy(t *testing.T) {
	client, backend := newTestStream(), newTestStream()
	revocations, recorder := newTestRevocations(), &testRecorder{}
	gateway := newTestGateway(t, &testResolver{endpoints: []Endpoint{validEndpoint(backend)}}, testAuthorizer{grant: gatewayGrant()}, revocations, recorder)
	result := make(chan error, 1)
	go func() { result <- gateway.Connect(context.Background(), gatewayRequest(), client) }()
	deadline := time.After(time.Second)
	for len(recorder.Events()) < 2 {
		select {
		case <-deadline:
			t.Fatal("gateway did not establish the proxy before revocation")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	revocations.Revoke("grant-1")
	select {
	case err := <-result:
		if !errors.Is(err, ErrRevoked) {
			t.Fatalf("Connect() error = %v, want ErrRevoked", err)
		}
	case <-time.After(time.Second):
		t.Fatal("revocation did not interrupt proxy")
	}
	events := recorder.Events()
	seenRevoked := false
	for _, event := range events {
		if event.Type == AuditRevoked {
			seenRevoked = true
		}
	}
	if !seenRevoked {
		t.Fatalf("audit events lack revocation: %#v", events)
	}
}

func TestGatewayRejectsGrantBindingAndStaleEndpoint(t *testing.T) {
	t.Run("grant binding", func(t *testing.T) {
		revocations, recorder := newTestRevocations(), &testRecorder{}
		grant := gatewayGrant()
		grant.TenantID = "tenant-other"
		gateway := newTestGateway(t, &testResolver{}, testAuthorizer{grant: grant}, revocations, recorder)
		err := gateway.Connect(context.Background(), gatewayRequest(), newTestStream())
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Connect() error = %v, want ErrUnauthorized", err)
		}
	})
	t.Run("stale endpoint", func(t *testing.T) {
		client, backend := newTestStream(), newTestStream()
		grant := gatewayGrant()
		endpoint := validEndpoint(backend)
		endpoint.ConnectionGeneration++
		revocations, recorder := newTestRevocations(), &testRecorder{}
		gateway := newTestGateway(t, &testResolver{endpoints: []Endpoint{endpoint}}, testAuthorizer{grant: grant}, revocations, recorder)
		err := gateway.Connect(context.Background(), gatewayRequest(), client)
		if !errors.Is(err, ErrStaleReference) {
			t.Fatalf("Connect() error = %v, want ErrStaleReference", err)
		}
	})
	t.Run("mismatched endpoint identity", func(t *testing.T) {
		client, backend := newTestStream(), newTestStream()
		endpoint := validEndpoint(backend)
		endpoint.SandboxID = "sandbox-other"
		revocations, recorder := newTestRevocations(), &testRecorder{}
		gateway := newTestGateway(t, &testResolver{endpoints: []Endpoint{endpoint}}, testAuthorizer{grant: gatewayGrant()}, revocations, recorder)
		err := gateway.Connect(context.Background(), gatewayRequest(), client)
		if !errors.Is(err, ErrStaleReference) {
			t.Fatalf("Connect() error = %v, want ErrStaleReference", err)
		}
	})
}

func TestGatewayFailsClosedWhenAuditCannotBeRecorded(t *testing.T) {
	client, backend := newTestStream(), newTestStream()
	revocations := newTestRevocations()
	recorder := &testRecorder{err: errors.New("audit store down")}
	gateway := newTestGateway(t, &testResolver{endpoints: []Endpoint{validEndpoint(backend)}}, testAuthorizer{grant: gatewayGrant()}, revocations, recorder)
	err := gateway.Connect(context.Background(), gatewayRequest(), client)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Connect() error = %v, want ErrAuditUnavailable", err)
	}
}

func TestGatewayRejectsPublicEndpointLikeReference(t *testing.T) {
	request := gatewayRequest()
	request.HandoffReference = "wss://127.0.0.1:8080/session"
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Validate() error = %v, want ErrInvalidRequest", err)
	}
}

func TestBrowserRequestRequiresExclusiveIdentityAndReferenceNamespace(t *testing.T) {
	valid := ConnectRequest{
		CallerID: "user-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
		BrowserSessionID: "browser-session-1", CapabilityProfileID: "browser-v1",
		HandoffReference: "ref:browser-session:opaque-1",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid Browser request rejected: %v", err)
	}
	for name, edit := range map[string]func(*ConnectRequest){
		"missing session":                 func(request *ConnectRequest) { request.BrowserSessionID = "" },
		"both sessions":                   func(request *ConnectRequest) { request.RuntimeSessionID = "terminal-session-1" },
		"nonempty invalid second session": func(request *ConnectRequest) { request.RuntimeSessionID = "invalid session" },
		"terminal reference":              func(request *ConnectRequest) { request.HandoffReference = "ref:session:opaque-1" },
		"public endpoint": func(request *ConnectRequest) {
			request.HandoffReference = "ws://127.0.0.1:9222/devtools/browser/secret"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			edit(&request)
			if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Validate() error = %v; want invalid request", err)
			}
		})
	}
}

func TestBrowserGrantBindsSessionBeforeReferenceResolution(t *testing.T) {
	request := ConnectRequest{
		CallerID: "user-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
		BrowserSessionID: "browser-session-1", CapabilityProfileID: "browser-v1",
		HandoffReference: "ref:browser-session:opaque-1",
	}
	grant := Grant{
		GrantID: "grant-1", CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, BrowserSessionID: "browser-session-other",
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: 1, ExpiresAt: gatewayTestNow.Add(time.Hour),
	}
	resolver := &testResolver{}
	recorder := &testRecorder{}
	proxy := newTestGateway(t, resolver, testAuthorizer{grant: grant}, newTestRevocations(), recorder)
	if err := proxy.Connect(context.Background(), request, newTestStream()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Connect() error = %v; want unauthorized", err)
	}
	if resolver.Calls() != 0 {
		t.Fatalf("resolver calls = %d; want zero", resolver.Calls())
	}
	events := recorder.Events()
	if len(events) != 1 || events[0].Type != AuditDenied || events[0].BrowserSessionID != request.BrowserSessionID || events[0].RuntimeSessionID != "" {
		t.Fatalf("denied Browser audit = %#v", events)
	}
}
