package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type fencedCapacityLeaseSpy struct {
	*authenticatedCapacityLeaseSpy
	fence    DownstreamFence
	fenceErr error
}

func (l *fencedCapacityLeaseSpy) DownstreamFence() (DownstreamFence, error) {
	return l.fence, l.fenceErr
}

type fencedResolverSpy struct {
	mu         sync.Mutex
	endpoint   Endpoint
	err        error
	calls      int
	references []string
	subjects   []DownstreamFenceSubject
	fences     []DownstreamFence
}

func (r *fencedResolverSpy) ResolveFenced(_ context.Context, reference string, subject DownstreamFenceSubject, fence DownstreamFence) (Endpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.references = append(r.references, reference)
	r.subjects = append(r.subjects, subject)
	r.fences = append(r.fences, fence)
	return r.endpoint, r.err
}

func (r *fencedResolverSpy) snapshot() (int, []string, []DownstreamFenceSubject, []DownstreamFence) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls, append([]string(nil), r.references...), append([]DownstreamFenceSubject(nil), r.subjects...), append([]DownstreamFence(nil), r.fences...)
}

type fenceFailureStream struct {
	err       error
	closeOnce sync.Once
	closed    chan struct{}
}

type controlledCallerContext struct {
	done chan struct{}
	mu   sync.Mutex
	err  error
}

func newControlledCallerContext() *controlledCallerContext {
	return &controlledCallerContext{done: make(chan struct{})}
}

func (c *controlledCallerContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *controlledCallerContext) Done() <-chan struct{}       { return c.done }
func (c *controlledCallerContext) Value(any) any               { return nil }

func (c *controlledCallerContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *controlledCallerContext) finish(err error) {
	c.mu.Lock()
	c.err = err
	close(c.done)
	c.mu.Unlock()
}

type callerCancellationStream struct {
	receiveStarted chan struct{}
	returnFrame    bool
	sendErr        error
}

func (s *callerCancellationStream) Receive(ctx context.Context) (Frame, error) {
	close(s.receiveStarted)
	<-ctx.Done()
	if s.returnFrame {
		return Frame{Type: TextFrame, Payload: []byte("canceled action")}, nil
	}
	return Frame{}, ctx.Err()
}

func (s *callerCancellationStream) Send(ctx context.Context, _ Frame) error {
	<-ctx.Done()
	if s.sendErr != nil {
		return s.sendErr
	}
	return ctx.Err()
}

func (*callerCancellationStream) Close(context.Context) error { return nil }

func newFenceFailureStream(err error) *fenceFailureStream {
	return &fenceFailureStream{err: err, closed: make(chan struct{})}
}

func (s *fenceFailureStream) Receive(ctx context.Context) (Frame, error) {
	select {
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case <-s.closed:
		return Frame{}, io.EOF
	}
}

func (s *fenceFailureStream) Send(context.Context, Frame) error { return s.err }

func (s *fenceFailureStream) Close(context.Context) error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func TestGatewayDownstreamFencingConfigurationFailsClosed(t *testing.T) {
	base := Options{
		Authorizer:  testAuthorizer{grant: fencedBrowserGrant()},
		Revocations: newTestRevocations(), Recorder: &testRecorder{},
		Clock:    ClockFunc(func() time.Time { return gatewayTestNow }),
		Capacity: &authenticatedCapacitySpy{},
	}
	var typedNilFenced *fencedResolverSpy
	for _, test := range []struct {
		name string
		edit func(*Options)
	}{
		{"fenced mode missing resolver", func(options *Options) { options.RequireDownstreamFencing = true }},
		{"fenced mode typed nil resolver", func(options *Options) {
			options.RequireDownstreamFencing, options.FencedResolver = true, typedNilFenced
		}},
		{"fenced mode missing capacity", func(options *Options) {
			options.RequireDownstreamFencing, options.FencedResolver, options.Capacity = true, &fencedResolverSpy{}, nil
		}},
		{"fenced mode retains raw resolver", func(options *Options) {
			options.RequireDownstreamFencing, options.FencedResolver, options.Resolver = true, &fencedResolverSpy{}, &testResolver{}
		}},
		{"ordinary mode has fenced resolver", func(options *Options) {
			options.Resolver, options.FencedResolver = &testResolver{}, &fencedResolverSpy{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.edit(&options)
			if proxy, err := New(options); proxy != nil || !errors.Is(err, ErrProxyUnavailable) {
				t.Fatalf("New() = %#v, %v; want nil, proxy unavailable", proxy, err)
			}
		})
	}
}

func TestGatewayDownstreamFenceForwardsExactBindingAndReleasesLease(t *testing.T) {
	fence := mustDownstreamFence(t, "v1.exact-private-claim")
	events := make(chan CapacityEvent)
	lease := &fencedCapacityLeaseSpy{authenticatedCapacityLeaseSpy: &authenticatedCapacityLeaseSpy{events: events}, fence: fence}
	backend, client := newTestStream(), newTestStream()
	endpoint := fencedBrowserEndpoint(backend)
	resolver := &fencedResolverSpy{endpoint: endpoint}
	recorder := &authenticatedCapacityRecorderSpy{}
	proxy := newFencedTestGateway(t, lease, resolver, recorder, ClockFunc(func() time.Time { return gatewayTestNow }))

	result := make(chan error, 1)
	go func() { result <- proxy.Connect(context.Background(), fencedBrowserRequest(), client) }()
	waitForAuthenticatedCapacityAudit(t, recorder, AuditConnected)
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Connect() error = %v; want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect() did not stop after the client closed")
	}

	calls, references, subjects, fences := resolver.snapshot()
	wantSubject := downstreamFenceSubjectForGrant(fencedBrowserGrant())
	if calls != 1 || len(references) != 1 || references[0] != fencedBrowserRequest().HandoffReference ||
		len(subjects) != 1 || subjects[0] != wantSubject || len(fences) != 1 || fences[0].Opaque() != fence.Opaque() {
		t.Fatalf("ResolveFenced observations = calls %d references %#v subjects %#v fences %#v", calls, references, subjects, fences)
	}
	if releaseCalls, _ := lease.snapshot(); releaseCalls != 1 {
		t.Fatalf("Release() calls = %d; want 1", releaseCalls)
	}
}

func TestGatewayDownstreamFenceRejectsMissingOrMalformedLeaseClaimWithoutLeak(t *testing.T) {
	secret := "v1.private-claim-secret"
	events := make(chan CapacityEvent)
	for _, test := range []struct {
		name  string
		lease ConnectionLease
	}{
		{"missing capability", &authenticatedCapacityLeaseSpy{events: events}},
		{"claim error", &fencedCapacityLeaseSpy{authenticatedCapacityLeaseSpy: &authenticatedCapacityLeaseSpy{events: events}, fenceErr: errors.New(secret)}},
		{"empty claim", &fencedCapacityLeaseSpy{authenticatedCapacityLeaseSpy: &authenticatedCapacityLeaseSpy{events: events}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fencedResolverSpy{}
			recorder := &authenticatedCapacityRecorderSpy{}
			proxy := newFencedTestGateway(t, test.lease, resolver, recorder, ClockFunc(func() time.Time { return gatewayTestNow }))
			err := proxy.Connect(context.Background(), fencedBrowserRequest(), newTestStream())
			if !errors.Is(err, ErrDownstreamUnavailable) || strings.Contains(err.Error(), secret) {
				t.Fatalf("Connect() error = %v; want bounded downstream unavailable", err)
			}
			if calls, _, _, _ := resolver.snapshot(); calls != 0 {
				t.Fatalf("ResolveFenced calls = %d; want zero", calls)
			}
			audits := recorder.snapshot()
			if countAuthenticatedCapacityAudit(audits, AuditDownstreamUnavailable) != 1 || strings.Contains(fmt.Sprint(audits), secret) {
				t.Fatalf("audit events = %#v; want one bounded downstream unavailable", audits)
			}
		})
	}
}

func TestGatewayDownstreamFenceFailuresAreTerminalAtEveryBoundary(t *testing.T) {
	secret := "private-ingress-diagnostic"
	for _, boundary := range []string{"resolve", "dial", "proxy"} {
		for _, failure := range []struct {
			name      string
			err       error
			wantAudit AuditEventType
		}{
			{"lost", ErrDownstreamFenceLost, AuditDownstreamFenceLost},
			{"unavailable", ErrDownstreamUnavailable, AuditDownstreamUnavailable},
			{"unknown", errors.New("unknown private failure"), AuditDownstreamUnavailable},
		} {
			t.Run(boundary+"/"+failure.name, func(t *testing.T) {
				fence := mustDownstreamFence(t, "v1.boundary-claim")
				events := make(chan CapacityEvent)
				lease := &fencedCapacityLeaseSpy{authenticatedCapacityLeaseSpy: &authenticatedCapacityLeaseSpy{events: events}, fence: fence}
				recorder := &authenticatedCapacityRecorderSpy{}
				client := newTestStream()
				resolver := &fencedResolverSpy{}
				boundedFailure := errors.Join(failure.err, errors.New(secret))
				switch boundary {
				case "resolve":
					resolver.err = boundedFailure
				case "dial":
					resolver.endpoint = fencedBrowserEndpointWithDial(func(context.Context) (Stream, error) { return nil, boundedFailure })
				case "proxy":
					resolver.endpoint = fencedBrowserEndpoint(newFenceFailureStream(boundedFailure))
				}
				proxy := newFencedTestGateway(t, lease, resolver, recorder, ClockFunc(func() time.Time { return gatewayTestNow }))
				if boundary == "proxy" {
					client.push(Frame{Type: TextFrame, Payload: []byte("action")})
				}
				err := proxy.Connect(context.Background(), fencedBrowserRequest(), client)
				want := failure.err
				if failure.name == "unknown" {
					want = ErrDownstreamUnavailable
				}
				leakedUnknown := failure.name == "unknown" && strings.Contains(err.Error(), failure.err.Error())
				if !errors.Is(err, want) || strings.Contains(err.Error(), secret) || leakedUnknown {
					t.Fatalf("Connect() error = %v; want bounded %v", err, want)
				}
				calls, _, _, _ := resolver.snapshot()
				if calls != 1 {
					t.Fatalf("ResolveFenced calls = %d; want 1 without reconnect", calls)
				}
				audits := recorder.snapshot()
				if countAuthenticatedCapacityAudit(audits, failure.wantAudit) != 1 ||
					countAuthenticatedCapacityAudit(audits, AuditReconnected) != 0 ||
					countAuthenticatedCapacityAudit(audits, AuditReconnectFailed) != 0 || strings.Contains(fmt.Sprint(audits), secret) {
					t.Fatalf("audit events = %#v; want one bounded %q and no reconnect", audits, failure.wantAudit)
				}
			})
		}
	}
}

func TestGatewayDownstreamFenceReleaseAndDialDiagnosticsStayPrivate(t *testing.T) {
	secret := "private-release-or-dial-diagnostic"
	fence := mustDownstreamFence(t, "v1.private-release-claim")
	events := make(chan CapacityEvent)
	lease := &fencedCapacityLeaseSpy{authenticatedCapacityLeaseSpy: &authenticatedCapacityLeaseSpy{
		events: events, releaseErr: errors.New(secret),
	}, fence: fence}
	backend := newTestStream()
	resolver := &fencedResolverSpy{endpoint: fencedBrowserEndpointWithDial(func(context.Context) (Stream, error) {
		return backend, errors.New(secret)
	})}
	recorder := &authenticatedCapacityRecorderSpy{}
	proxy := newFencedTestGateway(t, lease, resolver, recorder, ClockFunc(func() time.Time { return gatewayTestNow }))
	err := proxy.Connect(context.Background(), fencedBrowserRequest(), newTestStream())
	if !errors.Is(err, ErrDownstreamUnavailable) || strings.Contains(err.Error(), secret) {
		t.Fatalf("Connect() error = %v; want bounded downstream unavailable", err)
	}
	if !authenticatedCapacityStreamClosed(backend) {
		t.Fatal("Dial returned stream with an error and Gateway did not close it")
	}
	audits := recorder.snapshot()
	if countAuthenticatedCapacityAudit(audits, AuditDownstreamUnavailable) != 1 ||
		countAuthenticatedCapacityAudit(audits, AuditCapacityReleaseFailed) != 1 || strings.Contains(fmt.Sprint(audits), secret) {
		t.Fatalf("audit events = %#v; want bounded downstream and release failures", audits)
	}
}

func TestGatewayDownstreamFenceRejectsTypedNilDependenciesAndStreams(t *testing.T) {
	var typedNilAuthorizer *authenticatedCapacityAuthorizerSpy
	var typedNilRecorder *authenticatedCapacityRecorderSpy
	var typedNilClock *downstreamFenceClock
	base := Options{
		Authorizer: testAuthorizer{grant: fencedBrowserGrant()}, Resolver: &testResolver{},
		Revocations: newTestRevocations(), Recorder: &testRecorder{},
	}
	for _, test := range []struct {
		name string
		edit func(*Options)
	}{
		{"authorizer", func(options *Options) { options.Authorizer = typedNilAuthorizer }},
		{"recorder", func(options *Options) { options.Recorder = typedNilRecorder }},
		{"clock", func(options *Options) { options.Clock = typedNilClock }},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.edit(&options)
			if proxy, err := New(options); proxy != nil || !errors.Is(err, ErrProxyUnavailable) {
				t.Fatalf("New() = %#v, %v; want proxy unavailable", proxy, err)
			}
		})
	}

	var typedNilClient *testStream
	ordinary, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := ordinary.Connect(context.Background(), fencedBrowserRequest(), typedNilClient); !errors.Is(err, ErrProxyUnavailable) {
		t.Fatalf("Connect(typed nil client) error = %v; want proxy unavailable", err)
	}

	fence := mustDownstreamFence(t, "v1.typed-nil-claim")
	lease := &fencedCapacityLeaseSpy{authenticatedCapacityLeaseSpy: &authenticatedCapacityLeaseSpy{events: make(chan CapacityEvent)}, fence: fence}
	var typedNilBackend *testStream
	resolver := &fencedResolverSpy{endpoint: fencedBrowserEndpointWithDial(func(context.Context) (Stream, error) {
		return typedNilBackend, nil
	})}
	proxy := newFencedTestGateway(t, lease, resolver, &authenticatedCapacityRecorderSpy{}, ClockFunc(func() time.Time { return gatewayTestNow }))
	if err := proxy.Connect(context.Background(), fencedBrowserRequest(), newTestStream()); !errors.Is(err, ErrDownstreamUnavailable) {
		t.Fatalf("Connect(typed nil backend) error = %v; want downstream unavailable", err)
	}
}

func TestDownstreamFenceSentinelsRequireFencedBackendSource(t *testing.T) {
	for _, test := range []struct {
		name    string
		fenced  bool
		results []transferResult
		want    error
	}{
		{"ordinary backend", false, []transferResult{{side: backendSide, err: ErrDownstreamFenceLost}}, nil},
		{"fenced public client", true, []transferResult{{side: clientSide, writeFailed: true, err: ErrDownstreamFenceLost}}, nil},
		{"fenced backend lost", true, []transferResult{{side: backendSide, err: ErrDownstreamFenceLost}}, ErrDownstreamFenceLost},
		{"fenced backend write unknown", true, []transferResult{{side: backendSide, writeFailed: true, err: errors.New("private")}}, ErrDownstreamUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy := &Gateway{requireDownstreamFence: test.fenced}
			got := proxy.downstreamFenceTransferError(context.Background(), test.results...)
			if !errors.Is(got, test.want) || (test.want == nil && got != nil) {
				t.Fatalf("downstreamFenceTransferError() = %v; want %v", got, test.want)
			}
		})
	}
}

func TestGatewayDownstreamFenceCallerContextOutranksDerivedBackendWriteFailure(t *testing.T) {
	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(want.Error(), func(t *testing.T) {
			callerCtx := newControlledCallerContext()
			attemptCtx := newControlledCallerContext()
			clientStarted := make(chan struct{})
			backendStarted := make(chan struct{})
			client := &callerCancellationStream{receiveStarted: clientStarted, returnFrame: true}
			backend := &callerCancellationStream{receiveStarted: backendStarted, sendErr: want}
			proxy := &Gateway{
				clock:                  ClockFunc(func() time.Time { return gatewayTestNow }),
				requireDownstreamFence: true,
			}
			result := make(chan proxyResult, 1)
			go func() {
				result <- proxy.proxyAttempt(attemptCtx, callerCtx, client, backend, fencedBrowserGrant(), newTestRevocationWatch())
			}()
			<-clientStarted
			<-backendStarted
			callerCtx.finish(want)
			attemptCtx.finish(want)

			select {
			case got := <-result:
				if !errors.Is(got.err, want) || errors.Is(got.err, ErrDownstreamUnavailable) {
					t.Fatalf("proxyAttempt() error = %v; want only %v", got.err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("proxyAttempt() did not stop after caller context completion")
			}
		})
	}
}

func TestGatewayDownstreamFenceExplicitLossOutranksCallerCancellation(t *testing.T) {
	callerCtx := newControlledCallerContext()
	attemptCtx := newControlledCallerContext()
	clientStarted := make(chan struct{})
	backendStarted := make(chan struct{})
	client := &callerCancellationStream{receiveStarted: clientStarted, returnFrame: true}
	backend := &callerCancellationStream{receiveStarted: backendStarted, sendErr: ErrDownstreamFenceLost}
	proxy := &Gateway{
		clock:                  ClockFunc(func() time.Time { return gatewayTestNow }),
		requireDownstreamFence: true,
	}
	result := make(chan proxyResult, 1)
	go func() {
		result <- proxy.proxyAttempt(attemptCtx, callerCtx, client, backend, fencedBrowserGrant(), newTestRevocationWatch())
	}()
	<-clientStarted
	<-backendStarted
	callerCtx.finish(context.Canceled)
	attemptCtx.finish(context.Canceled)

	select {
	case got := <-result:
		if !errors.Is(got.err, ErrDownstreamFenceLost) {
			t.Fatalf("proxyAttempt() error = %v; want downstream fence lost", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxyAttempt() did not stop after caller cancellation")
	}
}

func TestGatewayDownstreamFenceRevocationUnavailableOutranksCallerCancellation(t *testing.T) {
	callerCtx := newControlledCallerContext()
	callerCtx.finish(context.Canceled)
	clientStarted := make(chan struct{})
	backendStarted := make(chan struct{})
	client := &callerCancellationStream{receiveStarted: clientStarted}
	backend := &callerCancellationStream{receiveStarted: backendStarted}
	proxy := &Gateway{
		clock:                  ClockFunc(func() time.Time { return gatewayTestNow }),
		requireDownstreamFence: true,
	}

	got := proxy.proxyAttempt(
		context.Background(), callerCtx, client, backend, fencedBrowserGrant(),
		finishedRevocationWatch(ErrRevocationUnavailable),
	)
	if !errors.Is(got.err, ErrRevocationUnavailable) || errors.Is(got.err, context.Canceled) {
		t.Fatalf("proxyAttempt() error = %v; want only revocation unavailable", got.err)
	}
}

func TestGatewayDownstreamFenceUsesStableAuthorityPriority(t *testing.T) {
	activeClock := ClockFunc(func() time.Time { return gatewayTestNow })
	expiredClock := ClockFunc(func() time.Time { return fencedBrowserGrant().ExpiresAt })
	for _, test := range []struct {
		name  string
		clock Clock
		ctx   context.Context
		watch *testRevocationWatch
		opErr error
		want  error
	}{
		{"revocation before fence", activeClock, context.Background(), finishedRevocationWatch(ErrRevoked), ErrDownstreamFenceLost, ErrRevoked},
		{"expiry before fence", expiredClock, context.Background(), newTestRevocationWatch(), ErrDownstreamFenceLost, ErrExpired},
		{"capacity before fence", activeClock, canceledCapacityContext(), newTestRevocationWatch(), ErrDownstreamFenceLost, ErrCapacityUnavailable},
		{"fence loss before revocation outage", activeClock, context.Background(), finishedRevocationWatch(ErrRevocationUnavailable), ErrDownstreamFenceLost, ErrDownstreamFenceLost},
		{"fence outage before revocation outage", activeClock, context.Background(), finishedRevocationWatch(ErrRevocationUnavailable), ErrDownstreamUnavailable, ErrDownstreamUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy := &Gateway{clock: test.clock, requireDownstreamFence: true}
			if got := proxy.externalBoundaryError(test.ctx, test.watch, fencedBrowserGrant().ExpiresAt, test.opErr); !errors.Is(got, test.want) {
				t.Fatalf("externalBoundaryError() = %v; want %v", got, test.want)
			}
		})
	}
}

func TestDownstreamFenceRedactsOpaqueClaim(t *testing.T) {
	secret := "v1.private-claim-secret"
	fence := mustDownstreamFence(t, secret)
	encoded, err := json.Marshal(struct {
		Fence DownstreamFence `json:"fence"`
	}{Fence: fence})
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%s %v %+v %#v %s", fence, fence, fence, fence, encoded)
	if strings.Contains(formatted, secret) || !strings.Contains(formatted, "redacted") {
		t.Fatalf("formatted fence was not redacted: %s", formatted)
	}
}

func newFencedTestGateway(t *testing.T, lease ConnectionLease, resolver FencedReferenceResolver, recorder Recorder, clock Clock) *Gateway {
	t.Helper()
	proxy, err := New(Options{
		Authorizer:     testAuthorizer{grant: fencedBrowserGrant()},
		FencedResolver: resolver, RequireDownstreamFencing: true,
		Revocations: newTestRevocations(), Recorder: recorder, Clock: clock,
		Capacity: &authenticatedCapacitySpy{lease: lease}, MaxReconnects: 2,
		CapacityReleaseTimeout: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proxy
}

func fencedBrowserRequest() ConnectRequest {
	return ConnectRequest{
		CallerID: "user-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
		BrowserSessionID: "browser-1", CapabilityProfileID: "browser-v1",
		HandoffReference: "ref:browser-session:opaque-1",
	}
}

func fencedBrowserGrant() Grant {
	request := fencedBrowserRequest()
	return Grant{
		GrantID: "grant-1", CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: 4, ExpiresAt: gatewayTestNow.Add(time.Hour),
	}
}

func fencedBrowserEndpoint(stream Stream) Endpoint {
	return fencedBrowserEndpointWithDial(func(context.Context) (Stream, error) { return stream, nil })
}

func fencedBrowserEndpointWithDial(dial func(context.Context) (Stream, error)) Endpoint {
	grant := fencedBrowserGrant()
	return Endpoint{
		Reference: grant.HandoffReference, SandboxID: grant.SandboxID,
		BrowserSessionID: grant.BrowserSessionID, CapabilityProfileID: grant.CapabilityProfileID,
		ConnectionGeneration: grant.ConnectionGeneration, ExpiresAt: grant.ExpiresAt.Add(time.Minute), Dial: dial,
	}
}

func mustDownstreamFence(t *testing.T, opaque string) DownstreamFence {
	t.Helper()
	fence, err := NewDownstreamFence(opaque)
	if err != nil {
		t.Fatal(err)
	}
	return fence
}

func finishedRevocationWatch(err error) *testRevocationWatch {
	watch := newTestRevocationWatch()
	watch.finish(err)
	return watch
}

func canceledCapacityContext() context.Context {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.Join(ErrCapacityUnavailable, errCapacityLeaseLost))
	return ctx
}

type downstreamFenceClock struct{}

func (*downstreamFenceClock) Now() time.Time { return gatewayTestNow }
