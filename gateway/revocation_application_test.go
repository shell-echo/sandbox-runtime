package gateway

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixedRevocationSource struct {
	mu      sync.Mutex
	watch   RevocationWatch
	err     error
	subject RevocationSubject
	calls   int
}

type revocationBlockingResolver struct {
	mu           sync.Mutex
	boundary     string
	started      chan struct{}
	resolveCalls int
	dialCalls    int
	backend      Stream
}

func (r *revocationBlockingResolver) Resolve(ctx context.Context, _ string) (Endpoint, error) {
	r.mu.Lock()
	r.resolveCalls++
	r.mu.Unlock()
	if r.boundary == "resolve" {
		close(r.started)
		<-ctx.Done()
		return Endpoint{}, ctx.Err()
	}
	endpoint := validEndpoint(nil)
	endpoint.Dial = func(ctx context.Context) (Stream, error) {
		r.mu.Lock()
		r.dialCalls++
		r.mu.Unlock()
		close(r.started)
		<-ctx.Done()
		return r.backend, ctx.Err()
	}
	return endpoint, nil
}

func (r *revocationBlockingResolver) snapshot() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolveCalls, r.dialCalls
}

func (s *fixedRevocationSource) Watch(_ context.Context, subject RevocationSubject) (RevocationWatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.subject = subject
	return s.watch, s.err
}

func (s *fixedRevocationSource) snapshot() (int, RevocationSubject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.subject
}

func gatewayWithRevocationSource(t *testing.T, source RevocationSource, resolver ReferenceResolver, recorder Recorder, backoff time.Duration) *Gateway {
	t.Helper()
	result, err := New(Options{
		Authorizer: testAuthorizer{grant: gatewayGrant()}, Resolver: resolver,
		Revocations: source, Recorder: recorder,
		Clock:         ClockFunc(func() time.Time { return gatewayTestNow }),
		MaxReconnects: 2, ReconnectBackoff: backoff,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return result
}

func TestGatewayRejectsTypedNilRevocationSource(t *testing.T) {
	var source *fixedRevocationSource
	if result, err := New(Options{
		Authorizer: testAuthorizer{}, Resolver: &testResolver{}, Revocations: source, Recorder: &testRecorder{},
	}); result != nil || !errors.Is(err, ErrProxyUnavailable) {
		t.Fatalf("New() = %#v, %v; want nil, ErrProxyUnavailable", result, err)
	}
}

func TestGatewayPreRevokedGrantStopsBeforeResolution(t *testing.T) {
	watch := newTestRevocationWatch()
	watch.finish(ErrRevoked)
	source := &fixedRevocationSource{watch: watch}
	resolver := &testResolver{}
	recorder := &testRecorder{}
	proxy := gatewayWithRevocationSource(t, source, resolver, recorder, 0)

	err := proxy.Connect(context.Background(), gatewayRequest(), newTestStream())
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("Connect() error = %v; want ErrRevoked", err)
	}
	if calls := resolver.Calls(); calls != 0 {
		t.Fatalf("resolver calls = %d; want 0", calls)
	}
	calls, subject := source.snapshot()
	if calls != 1 || subject != revocationSubjectForGrant(gatewayGrant()) {
		t.Fatalf("Watch() calls/subject = %d/%#v; want exact grant subject", calls, subject)
	}
	assertOnlyBoundedRevocationAudit(t, recorder.Events(), AuditRevoked, "grant revoked", nil)
}

func TestGatewayMalformedRevocationWatchFailsClosedBeforeResolution(t *testing.T) {
	diagnostic := errors.New("redis://secret.example.invalid:6379 private backend failure")
	closedWithoutStatus := newTestRevocationWatch()
	closedWithoutStatus.finish(nil)
	conflictingRevokedUnavailable := newTestRevocationWatch()
	conflictingRevokedUnavailable.finish(errors.Join(ErrRevoked, ErrRevocationUnavailable))
	conflictingRevokedCanceled := newTestRevocationWatch()
	conflictingRevokedCanceled.finish(errors.Join(ErrRevoked, context.Canceled))
	var typedNil *testRevocationWatch
	tests := []struct {
		name  string
		watch RevocationWatch
		err   error
	}{
		{name: "source error", err: diagnostic},
		{name: "source claims revocation as error", err: ErrRevoked},
		{name: "nil watch"},
		{name: "typed nil watch", watch: typedNil},
		{name: "nil done channel", watch: &testRevocationWatch{}},
		{name: "closed without status", watch: closedWithoutStatus},
		{name: "conflicting revoked and unavailable", watch: conflictingRevokedUnavailable},
		{name: "conflicting revoked and canceled", watch: conflictingRevokedCanceled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &fixedRevocationSource{watch: test.watch, err: test.err}
			resolver := &testResolver{}
			recorder := &testRecorder{}
			proxy := gatewayWithRevocationSource(t, source, resolver, recorder, 0)

			err := proxy.Connect(context.Background(), gatewayRequest(), newTestStream())
			if !errors.Is(err, ErrProxyUnavailable) || !errors.Is(err, ErrRevocationUnavailable) {
				t.Fatalf("Connect() error = %v; want proxy and revocation unavailable", err)
			}
			if calls := resolver.Calls(); calls != 0 {
				t.Fatalf("resolver calls = %d; want 0", calls)
			}
			assertOnlyBoundedRevocationAudit(t, recorder.Events(), AuditRevocationUnavailable, "revocation authority unavailable", []string{diagnostic.Error(), gatewayRequest().HandoffReference})
		})
	}
}

func TestGatewayRevocationCancelsBlockedExternalWork(t *testing.T) {
	for _, boundary := range []string{"resolve", "dial"} {
		for _, terminal := range []struct {
			name      string
			err       error
			want      error
			wantAudit AuditEventType
			reason    string
		}{
			{name: "revoked", err: ErrRevoked, want: ErrRevoked, wantAudit: AuditRevoked, reason: "grant revoked"},
			{name: "unavailable", err: ErrRevocationUnavailable, want: ErrRevocationUnavailable, wantAudit: AuditRevocationUnavailable, reason: "revocation authority unavailable"},
		} {
			t.Run(boundary+"/"+terminal.name, func(t *testing.T) {
				watch := newTestRevocationWatch()
				source := &fixedRevocationSource{watch: watch}
				backend := newTestStream()
				resolver := &revocationBlockingResolver{boundary: boundary, started: make(chan struct{}), backend: backend}
				recorder := &testRecorder{}
				client := newTestStream()
				proxy := gatewayWithRevocationSource(t, source, resolver, recorder, 0)
				result := make(chan error, 1)
				go func() { result <- proxy.Connect(context.Background(), gatewayRequest(), client) }()
				select {
				case <-resolver.started:
				case <-time.After(time.Second):
					t.Fatalf("Gateway did not reach blocked %s", boundary)
				}

				watch.finish(terminal.err)
				select {
				case err := <-result:
					if !errors.Is(err, terminal.want) {
						t.Fatalf("Connect() error = %v; want %v", err, terminal.want)
					}
				case <-time.After(time.Second):
					t.Fatalf("%s did not cancel blocked %s", terminal.name, boundary)
				}
				resolveCalls, dialCalls := resolver.snapshot()
				wantDialCalls := 0
				if boundary == "dial" {
					wantDialCalls = 1
				}
				if resolveCalls != 1 || dialCalls != wantDialCalls {
					t.Fatalf("Resolve/Dial calls = %d/%d; want 1/%d", resolveCalls, dialCalls, wantDialCalls)
				}
				if boundary == "dial" && !streamClosed(backend) {
					t.Fatal("canceled Dial returned a backend that was not closed")
				}
				if !streamClosed(client) {
					t.Fatal("authority termination left caller stream open")
				}
				assertOnlyBoundedRevocationAudit(t, recorder.Events(), terminal.wantAudit, terminal.reason, nil)
			})
		}
	}
}

func TestGatewayInitialWatchCancellationIsNotAuthorityOutage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := &fixedRevocationSource{err: context.Canceled}
	recorder := &testRecorder{}
	proxy := gatewayWithRevocationSource(t, source, &testResolver{}, recorder, 0)
	err := proxy.Connect(ctx, gatewayRequest(), newTestStream())
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrRevocationUnavailable) {
		t.Fatalf("Connect() error = %v; want only context cancellation", err)
	}
	for _, event := range recorder.Events() {
		if event.Type == AuditRevocationUnavailable || event.Type == AuditRevoked {
			t.Fatalf("context cancellation produced false authority audit: %#v", recorder.Events())
		}
	}
}

func TestGatewayActiveRevocationAuthorityLossClosesWithoutReconnect(t *testing.T) {
	watch := newTestRevocationWatch()
	source := &fixedRevocationSource{watch: watch}
	resolver := &testResolver{endpoints: []Endpoint{validEndpoint(newTestStream()), validEndpoint(newTestStream())}}
	recorder := &testRecorder{}
	client := newTestStream()
	proxy := gatewayWithRevocationSource(t, source, resolver, recorder, time.Second)
	result := make(chan error, 1)
	go func() { result <- proxy.Connect(context.Background(), gatewayRequest(), client) }()
	waitForRevocationAudit(t, recorder, AuditConnected)

	diagnostic := errors.New("redis://private.example.invalid:6379 authority lost")
	watch.finish(diagnostic)
	select {
	case err := <-result:
		if !errors.Is(err, ErrProxyUnavailable) || !errors.Is(err, ErrRevocationUnavailable) || errors.Is(err, ErrRevoked) {
			t.Fatalf("Connect() error = %v; want revocation unavailable only", err)
		}
	case <-time.After(time.Second):
		t.Fatal("revocation authority loss did not interrupt active proxy")
	}
	if !streamClosed(client) {
		t.Fatal("revocation authority loss left caller stream open")
	}
	if calls := resolver.Calls(); calls != 1 {
		t.Fatalf("resolver calls = %d; want 1 without reconnect", calls)
	}
	assertOnlyBoundedRevocationAudit(t, recorder.Events(), AuditRevocationUnavailable, "revocation authority unavailable", []string{diagnostic.Error(), gatewayRequest().HandoffReference})
}

func TestGatewayRevocationAuthorityLossInterruptsReconnectBackoff(t *testing.T) {
	watch := newTestRevocationWatch()
	source := &fixedRevocationSource{watch: watch}
	backend := newTestStream()
	resolver := &testResolver{endpoints: []Endpoint{validEndpoint(backend), validEndpoint(newTestStream())}}
	recorder := &testRecorder{}
	proxy := gatewayWithRevocationSource(t, source, resolver, recorder, time.Second)
	result := make(chan error, 1)
	go func() { result <- proxy.Connect(context.Background(), gatewayRequest(), newTestStream()) }()
	waitForRevocationAudit(t, recorder, AuditConnected)
	if err := backend.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForRevocationAudit(t, recorder, AuditBackendClosed)

	watch.finish(ErrRevocationUnavailable)
	select {
	case err := <-result:
		if !errors.Is(err, ErrRevocationUnavailable) {
			t.Fatalf("Connect() error = %v; want ErrRevocationUnavailable", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("revocation authority loss did not interrupt reconnect backoff")
	}
	if calls := resolver.Calls(); calls != 1 {
		t.Fatalf("resolver calls = %d; want 1 without reconnect", calls)
	}
}

func TestGatewayRevocationAuthorityPriority(t *testing.T) {
	proxy := &Gateway{clock: ClockFunc(func() time.Time { return gatewayTestNow })}
	capacityCtx, cancelCapacity := context.WithCancelCause(context.Background())
	cancelCapacity(ErrCapacityUnavailable)

	revoked := newTestRevocationWatch()
	revoked.finish(ErrRevoked)
	if err := proxy.authorityError(capacityCtx, revoked, gatewayTestNow); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked priority error = %v; want ErrRevoked", err)
	}

	unavailable := newTestRevocationWatch()
	unavailable.finish(ErrRevocationUnavailable)
	if err := proxy.authorityError(capacityCtx, unavailable, gatewayTestNow); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry priority error = %v; want ErrExpired", err)
	}
	if err := proxy.authorityError(capacityCtx, unavailable, gatewayTestNow.Add(time.Hour)); !errors.Is(err, ErrCapacityUnavailable) {
		t.Fatalf("capacity priority error = %v; want ErrCapacityUnavailable", err)
	}
	if err := proxy.authorityError(context.Background(), unavailable, gatewayTestNow.Add(time.Hour)); !errors.Is(err, ErrRevocationUnavailable) {
		t.Fatalf("unavailable priority error = %v; want ErrRevocationUnavailable", err)
	}
}

func waitForRevocationAudit(t *testing.T, recorder *testRecorder, eventType AuditEventType) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		for _, event := range recorder.Events() {
			if event.Type == eventType {
				return
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("audit never recorded %q: %#v", eventType, recorder.Events())
		case <-time.After(time.Millisecond):
		}
	}
}

func assertOnlyBoundedRevocationAudit(t *testing.T, events []AuditEvent, expected AuditEventType, reason string, forbidden []string) {
	t.Helper()
	count := 0
	for _, event := range events {
		if event.Type == expected {
			count++
			if event.Reason != reason {
				t.Fatalf("%s audit reason = %q; want %q", expected, event.Reason, reason)
			}
		}
		if event.Type == AuditRevoked && expected != AuditRevoked {
			t.Fatalf("unavailable authority was recorded as revoked: %#v", events)
		}
		for _, secret := range forbidden {
			if secret != "" && strings.Contains(event.Reason, secret) {
				t.Fatalf("audit leaked private diagnostic %q: %#v", secret, event)
			}
		}
	}
	if count != 1 {
		t.Fatalf("%s audit count = %d; want 1 in %#v", expected, count, events)
	}
}

func streamClosed(stream *testStream) bool {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.closed
}
