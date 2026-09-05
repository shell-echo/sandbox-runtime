package gateway

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type authenticatedCapacityCallLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *authenticatedCapacityCallLog) add(call string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, call)
}

func (l *authenticatedCapacityCallLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

type authenticatedCapacityAuthorizerSpy struct {
	mu    sync.Mutex
	grant Grant
	calls int
	log   *authenticatedCapacityCallLog
}

func (a *authenticatedCapacityAuthorizerSpy) Authorize(context.Context, ConnectRequest) (Grant, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	a.log.add("authorize")
	return a.grant, nil
}

func (a *authenticatedCapacityAuthorizerSpy) snapshot() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

type authenticatedCapacitySpy struct {
	mu       sync.Mutex
	lease    ConnectionLease
	err      error
	calls    int
	subjects []CapacitySubject
	log      *authenticatedCapacityCallLog
}

func (c *authenticatedCapacitySpy) Acquire(_ context.Context, subject CapacitySubject) (ConnectionLease, error) {
	c.mu.Lock()
	c.calls++
	c.subjects = append(c.subjects, subject)
	c.mu.Unlock()
	c.log.add("capacity acquire")
	return c.lease, c.err
}

func (c *authenticatedCapacitySpy) snapshot() (int, []CapacitySubject) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, append([]CapacitySubject(nil), c.subjects...)
}

type authenticatedCapacityReleaseObservation struct {
	errAtCall   error
	deadline    time.Time
	hasDeadline bool
	requestTag  any
}

type authenticatedCapacityLeaseSpy struct {
	mu           sync.Mutex
	events       <-chan CapacityEvent
	releaseErr   error
	releaseCalls int
	releases     []authenticatedCapacityReleaseObservation
	requestKey   any
	log          *authenticatedCapacityCallLog
}

func (l *authenticatedCapacityLeaseSpy) Events() <-chan CapacityEvent {
	return l.events
}

func (l *authenticatedCapacityLeaseSpy) Release(ctx context.Context) error {
	deadline, hasDeadline := ctx.Deadline()
	observation := authenticatedCapacityReleaseObservation{
		errAtCall: ctx.Err(), deadline: deadline, hasDeadline: hasDeadline,
	}
	if l.requestKey != nil {
		observation.requestTag = ctx.Value(l.requestKey)
	}
	l.mu.Lock()
	l.releaseCalls++
	l.releases = append(l.releases, observation)
	l.mu.Unlock()
	l.log.add("capacity release")
	return l.releaseErr
}

func (l *authenticatedCapacityLeaseSpy) snapshot() (int, []authenticatedCapacityReleaseObservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.releaseCalls, append([]authenticatedCapacityReleaseObservation(nil), l.releases...)
}

type authenticatedCapacityRevocationsSpy struct {
	mu         sync.Mutex
	watchCalls int
	watch      *testRevocationWatch
	log        *authenticatedCapacityCallLog
}

func newAuthenticatedCapacityRevocationsSpy(log *authenticatedCapacityCallLog) *authenticatedCapacityRevocationsSpy {
	return &authenticatedCapacityRevocationsSpy{watch: newTestRevocationWatch(), log: log}
}

func (r *authenticatedCapacityRevocationsSpy) Watch(context.Context, RevocationSubject) (RevocationWatch, error) {
	r.mu.Lock()
	r.watchCalls++
	r.mu.Unlock()
	r.log.add("revocation watch")
	return r.watch, nil
}

func (r *authenticatedCapacityRevocationsSpy) snapshot() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return 0, r.watchCalls
}

type authenticatedCapacityResolverSpy struct {
	mu           sync.Mutex
	backend      Stream
	resolveCalls int
	dialCalls    int
	dialed       chan struct{}
	log          *authenticatedCapacityCallLog
}

type authenticatedCapacityBlockingResolver struct {
	mu             sync.Mutex
	backend        Stream
	resolveStarted chan struct{}
	resolveRelease <-chan struct{}
	dialStarted    chan struct{}
	dialRelease    <-chan struct{}
	resolveCalls   int
	dialCalls      int
}

func (r *authenticatedCapacityBlockingResolver) Resolve(context.Context, string) (Endpoint, error) {
	r.mu.Lock()
	r.resolveCalls++
	r.mu.Unlock()
	if r.resolveStarted != nil {
		select {
		case r.resolveStarted <- struct{}{}:
		default:
		}
	}
	if r.resolveRelease != nil {
		<-r.resolveRelease
	}
	endpoint := validEndpoint(nil)
	endpoint.Dial = func(context.Context) (Stream, error) {
		r.mu.Lock()
		r.dialCalls++
		r.mu.Unlock()
		if r.dialStarted != nil {
			select {
			case r.dialStarted <- struct{}{}:
			default:
			}
		}
		if r.dialRelease != nil {
			<-r.dialRelease
		}
		return r.backend, nil
	}
	return endpoint, nil
}

func (r *authenticatedCapacityBlockingResolver) snapshot() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolveCalls, r.dialCalls
}

func newAuthenticatedCapacityResolverSpy(backend Stream, log *authenticatedCapacityCallLog) *authenticatedCapacityResolverSpy {
	return &authenticatedCapacityResolverSpy{backend: backend, dialed: make(chan struct{}, 1), log: log}
}

func (r *authenticatedCapacityResolverSpy) Resolve(context.Context, string) (Endpoint, error) {
	r.mu.Lock()
	r.resolveCalls++
	r.mu.Unlock()
	r.log.add("resolver resolve")
	endpoint := validEndpoint(nil)
	endpoint.Dial = func(context.Context) (Stream, error) {
		r.mu.Lock()
		r.dialCalls++
		r.mu.Unlock()
		r.log.add("endpoint dial")
		select {
		case r.dialed <- struct{}{}:
		default:
		}
		return r.backend, nil
	}
	return endpoint, nil
}

func (r *authenticatedCapacityResolverSpy) snapshot() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolveCalls, r.dialCalls
}

type authenticatedCapacityRecorderSpy struct {
	mu     sync.Mutex
	events []AuditEvent
	log    *authenticatedCapacityCallLog
}

func (r *authenticatedCapacityRecorderSpy) Record(_ context.Context, event AuditEvent) error {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
	r.log.add("audit " + string(event.Type))
	return nil
}

func (r *authenticatedCapacityRecorderSpy) snapshot() []AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AuditEvent(nil), r.events...)
}

func newAuthenticatedCapacityGateway(
	t *testing.T,
	authorizer Authorizer,
	capacity ConnectionCapacity,
	revocations RevocationSource,
	recorder Recorder,
	resolver ReferenceResolver,
) *Gateway {
	t.Helper()
	gateway, err := New(Options{
		Authorizer: authorizer, Capacity: capacity, Revocations: revocations,
		Recorder: recorder, Resolver: resolver,
		Clock:         ClockFunc(func() time.Time { return gatewayTestNow }),
		MaxReconnects: 2, CapacityReleaseTimeout: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return gateway
}

func waitForAuthenticatedCapacityAudit(t *testing.T, recorder *authenticatedCapacityRecorderSpy, eventType AuditEventType) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		for _, event := range recorder.snapshot() {
			if event.Type == eventType {
				return
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %q audit; events = %#v", eventType, recorder.snapshot())
		case <-ticker.C:
		}
	}
}

func authenticatedCapacityStreamClosed(stream *testStream) bool {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.closed
}

func countAuthenticatedCapacityAudit(events []AuditEvent, eventType AuditEventType) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func TestGatewayAuthenticatedCapacityFollowsAdmissionOrder(t *testing.T) {
	log := &authenticatedCapacityCallLog{}
	events := make(chan CapacityEvent)
	lease := &authenticatedCapacityLeaseSpy{events: events, log: log}
	capacity := &authenticatedCapacitySpy{lease: lease, log: log}
	authorizer := &authenticatedCapacityAuthorizerSpy{grant: gatewayGrant(), log: log}
	revocations := newAuthenticatedCapacityRevocationsSpy(log)
	recorder := &authenticatedCapacityRecorderSpy{log: log}
	client, backend := newTestStream(), newTestStream()
	resolver := newAuthenticatedCapacityResolverSpy(backend, log)
	gateway := newAuthenticatedCapacityGateway(t, authorizer, capacity, revocations, recorder, resolver)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	go func() { result <- gateway.Connect(ctx, gatewayRequest(), client) }()
	select {
	case <-resolver.dialed:
	case <-time.After(time.Second):
		t.Fatal("Gateway did not reach endpoint dial")
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Connect() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect() did not stop after the caller closed")
	}

	wantPrefix := []string{
		"authorize",
		"capacity acquire",
		"revocation watch",
		"audit authorized",
		"resolver resolve",
		"endpoint dial",
	}
	got := log.snapshot()
	if len(got) < len(wantPrefix) || !slices.Equal(got[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("admission calls = %#v; want prefix %#v", got, wantPrefix)
	}
	acquireCalls, subjects := capacity.snapshot()
	if acquireCalls != 1 || len(subjects) != 1 || subjects[0] != capacitySubjectForGrant(gatewayGrant()) {
		t.Fatalf("capacity acquisition = calls %d, subjects %#v", acquireCalls, subjects)
	}
	if releaseCalls, _ := lease.snapshot(); releaseCalls != 1 {
		t.Fatalf("Release() calls = %d; want 1", releaseCalls)
	}
}

func TestGatewayAuthenticatedCapacityRejectsBeforeAcquisition(t *testing.T) {
	tests := []struct {
		name                string
		request             ConnectRequest
		grant               Grant
		wantErr             error
		wantAuthorizerCalls int
		wantAudit           AuditEventType
	}{
		{
			name: "invalid request", request: func() ConnectRequest {
				request := gatewayRequest()
				request.CallerID = ""
				return request
			}(),
			grant: gatewayGrant(), wantErr: ErrInvalidRequest,
		},
		{
			name: "grant binding mismatch", request: gatewayRequest(), grant: func() Grant {
				grant := gatewayGrant()
				grant.TenantID = "tenant-other"
				return grant
			}(),
			wantErr: ErrUnauthorized, wantAuthorizerCalls: 1, wantAudit: AuditDenied,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorizer := &authenticatedCapacityAuthorizerSpy{grant: test.grant}
			capacity := &authenticatedCapacitySpy{}
			revocations := newAuthenticatedCapacityRevocationsSpy(nil)
			recorder := &authenticatedCapacityRecorderSpy{}
			resolver := newAuthenticatedCapacityResolverSpy(newTestStream(), nil)
			gateway := newAuthenticatedCapacityGateway(t, authorizer, capacity, revocations, recorder, resolver)

			err := gateway.Connect(context.Background(), test.request, newTestStream())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Connect() error = %v; want %v", err, test.wantErr)
			}
			if calls := authorizer.snapshot(); calls != test.wantAuthorizerCalls {
				t.Fatalf("Authorize() calls = %d; want %d", calls, test.wantAuthorizerCalls)
			}
			if acquireCalls, _ := capacity.snapshot(); acquireCalls != 0 {
				t.Fatalf("Acquire() calls = %d; want 0", acquireCalls)
			}
			isRevokedCalls, watchCalls := revocations.snapshot()
			resolveCalls, dialCalls := resolver.snapshot()
			if isRevokedCalls != 0 || watchCalls != 0 || resolveCalls != 0 || dialCalls != 0 {
				t.Fatalf("downstream calls = IsRevoked %d, Watch %d, Resolve %d, Dial %d; want all zero", isRevokedCalls, watchCalls, resolveCalls, dialCalls)
			}
			auditEvents := recorder.snapshot()
			if test.wantAudit == "" {
				if len(auditEvents) != 0 {
					t.Fatalf("audit events = %#v; want none", auditEvents)
				}
			} else if len(auditEvents) != 1 || auditEvents[0].Type != test.wantAudit {
				t.Fatalf("audit events = %#v; want one %q", auditEvents, test.wantAudit)
			}
		})
	}
}

func TestGatewayAuthenticatedCapacityInitialFailureIsClosed(t *testing.T) {
	diagnosticErr := errors.New("sensitive capacity backend diagnostic")
	closedEvents := make(chan CapacityEvent)
	close(closedEvents)
	invalidEvents := make(chan CapacityEvent, 1)
	invalidEvents <- CapacityEvent{Kind: CapacityEventKind("invalid"), Err: diagnosticErr}
	lostEvents := make(chan CapacityEvent, 1)
	lostEvents <- CapacityEvent{Kind: CapacityEventLost, Err: diagnosticErr}
	unavailableEvents := make(chan CapacityEvent, 1)
	unavailableEvents <- CapacityEvent{Kind: CapacityEventUnavailable, Err: diagnosticErr}
	var typedNilLease *authenticatedCapacityLeaseSpy

	tests := []struct {
		name            string
		lease           ConnectionLease
		acquireErr      error
		wantErr         error
		wantAudit       AuditEventType
		wantReleaseCall bool
	}{
		{name: "acquire exhausted", acquireErr: ErrCapacityExhausted, wantErr: ErrCapacityExhausted, wantAudit: AuditCapacityRejected},
		{name: "acquire unavailable", acquireErr: ErrCapacityUnavailable, wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityUnavailable},
		{name: "acquire generic error", acquireErr: diagnosticErr, wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityUnavailable},
		{name: "nil lease", wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityUnavailable},
		{name: "typed nil lease", lease: typedNilLease, wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityUnavailable},
		{name: "nil event channel", lease: &authenticatedCapacityLeaseSpy{}, wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityUnavailable, wantReleaseCall: true},
		{name: "closed event channel", lease: &authenticatedCapacityLeaseSpy{events: closedEvents}, wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityUnavailable, wantReleaseCall: true},
		{name: "invalid event kind", lease: &authenticatedCapacityLeaseSpy{events: invalidEvents}, wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityUnavailable, wantReleaseCall: true},
		{name: "preloaded lost event", lease: &authenticatedCapacityLeaseSpy{events: lostEvents}, wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityLost, wantReleaseCall: true},
		{name: "preloaded unavailable event", lease: &authenticatedCapacityLeaseSpy{events: unavailableEvents}, wantErr: ErrCapacityUnavailable, wantAudit: AuditCapacityUnavailable, wantReleaseCall: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capacity := &authenticatedCapacitySpy{lease: test.lease, err: test.acquireErr}
			revocations := newAuthenticatedCapacityRevocationsSpy(nil)
			recorder := &authenticatedCapacityRecorderSpy{}
			resolver := newAuthenticatedCapacityResolverSpy(newTestStream(), nil)
			gateway := newAuthenticatedCapacityGateway(
				t,
				&authenticatedCapacityAuthorizerSpy{grant: gatewayGrant()},
				capacity,
				revocations,
				recorder,
				resolver,
			)

			err := gateway.Connect(context.Background(), gatewayRequest(), newTestStream())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Connect() error = %v; want %v", err, test.wantErr)
			}
			isRevokedCalls, watchCalls := revocations.snapshot()
			resolveCalls, dialCalls := resolver.snapshot()
			if isRevokedCalls != 0 || watchCalls != 0 || resolveCalls != 0 || dialCalls != 0 {
				t.Fatalf("downstream calls = IsRevoked %d, Watch %d, Resolve %d, Dial %d; want all zero", isRevokedCalls, watchCalls, resolveCalls, dialCalls)
			}
			auditEvents := recorder.snapshot()
			if len(auditEvents) != 1 || auditEvents[0].Type != test.wantAudit {
				t.Fatalf("audit events = %#v; want one %q", auditEvents, test.wantAudit)
			}
			if countAuthenticatedCapacityAudit(auditEvents, AuditAuthorized) != 0 {
				t.Fatalf("authorized audit recorded after initial capacity failure: %#v", auditEvents)
			}
			if strings.Contains(auditEvents[0].Reason, diagnosticErr.Error()) || strings.Contains(auditEvents[0].Reason, gatewayRequest().HandoffReference) {
				t.Fatalf("capacity audit exposed sensitive detail: %#v", auditEvents[0])
			}
			if lease, ok := test.lease.(*authenticatedCapacityLeaseSpy); ok && lease != nil {
				releaseCalls, _ := lease.snapshot()
				wantReleaseCalls := 0
				if test.wantReleaseCall {
					wantReleaseCalls = 1
				}
				if releaseCalls != wantReleaseCalls {
					t.Fatalf("Release() calls = %d; want %d", releaseCalls, wantReleaseCalls)
				}
			}
		})
	}
}

func TestGatewayAuthenticatedCapacityActiveEventTerminatesBothStreamsWithoutReconnect(t *testing.T) {
	diagnosticErr := errors.New("sensitive shared store endpoint https://capacity.internal")
	for _, test := range []struct {
		name       string
		kind       CapacityEventKind
		wantAudit  AuditEventType
		wantReason string
	}{
		{name: "lost", kind: CapacityEventLost, wantAudit: AuditCapacityLost, wantReason: "connection capacity lease lost"},
		{name: "unavailable", kind: CapacityEventUnavailable, wantAudit: AuditCapacityUnavailable, wantReason: "connection capacity unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := make(chan CapacityEvent, 1)
			lease := &authenticatedCapacityLeaseSpy{events: events}
			capacity := &authenticatedCapacitySpy{lease: lease}
			revocations := newAuthenticatedCapacityRevocationsSpy(nil)
			recorder := &authenticatedCapacityRecorderSpy{}
			client, backend := newTestStream(), newTestStream()
			resolver := newAuthenticatedCapacityResolverSpy(backend, nil)
			gateway := newAuthenticatedCapacityGateway(
				t,
				&authenticatedCapacityAuthorizerSpy{grant: gatewayGrant()},
				capacity,
				revocations,
				recorder,
				resolver,
			)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- gateway.Connect(ctx, gatewayRequest(), client) }()
			waitForAuthenticatedCapacityAudit(t, recorder, AuditConnected)

			events <- CapacityEvent{Kind: test.kind, Err: diagnosticErr}
			select {
			case err := <-result:
				if !errors.Is(err, ErrCapacityUnavailable) {
					t.Fatalf("Connect() error = %v; want ErrCapacityUnavailable", err)
				}
			case <-time.After(time.Second):
				t.Fatal("capacity event did not terminate the active proxy")
			}

			if !authenticatedCapacityStreamClosed(client) || !authenticatedCapacityStreamClosed(backend) {
				t.Fatalf("stream closed state = client %t, backend %t; want both true", authenticatedCapacityStreamClosed(client), authenticatedCapacityStreamClosed(backend))
			}
			resolveCalls, dialCalls := resolver.snapshot()
			if resolveCalls != 1 || dialCalls != 1 {
				t.Fatalf("Resolve/Dial calls = %d/%d; want 1/1 without reconnect", resolveCalls, dialCalls)
			}
			if releaseCalls, _ := lease.snapshot(); releaseCalls != 1 {
				t.Fatalf("Release() calls = %d; want 1", releaseCalls)
			}
			auditEvents := recorder.snapshot()
			primaryCount := countAuthenticatedCapacityAudit(auditEvents, AuditCapacityLost) + countAuthenticatedCapacityAudit(auditEvents, AuditCapacityUnavailable)
			if primaryCount != 1 || countAuthenticatedCapacityAudit(auditEvents, test.wantAudit) != 1 {
				t.Fatalf("capacity audit events = %#v; want one primary %q", auditEvents, test.wantAudit)
			}
			if countAuthenticatedCapacityAudit(auditEvents, AuditReconnected) != 0 || countAuthenticatedCapacityAudit(auditEvents, AuditReconnectFailed) != 0 {
				t.Fatalf("capacity event entered reconnect path: %#v", auditEvents)
			}
			for _, event := range auditEvents {
				if strings.Contains(event.Reason, diagnosticErr.Error()) || strings.Contains(event.Reason, gatewayRequest().HandoffReference) {
					t.Fatalf("audit exposed capacity diagnostic or handoff reference: %#v", event)
				}
				if event.Type == test.wantAudit && (event.Reason != test.wantReason || event.Frames != 0 || event.Bytes != 0) {
					t.Fatalf("primary capacity audit is not bounded metadata: %#v", event)
				}
			}
		})
	}
}

func TestGatewayAuthenticatedCapacityUsesStableAuthorityPriority(t *testing.T) {
	t.Run("revocation before capacity loss", func(t *testing.T) {
		events := make(chan CapacityEvent, 1)
		lease := &authenticatedCapacityLeaseSpy{events: events}
		revocations := newAuthenticatedCapacityRevocationsSpy(nil)
		recorder := &authenticatedCapacityRecorderSpy{}
		client, backend := newTestStream(), newTestStream()
		gateway := newAuthenticatedCapacityGateway(
			t,
			&authenticatedCapacityAuthorizerSpy{grant: gatewayGrant()},
			&authenticatedCapacitySpy{lease: lease},
			revocations,
			recorder,
			newAuthenticatedCapacityResolverSpy(backend, nil),
		)
		result := make(chan error, 1)
		go func() { result <- gateway.Connect(context.Background(), gatewayRequest(), client) }()
		waitForAuthenticatedCapacityAudit(t, recorder, AuditConnected)

		revocations.watch.finish(ErrRevoked)
		events <- CapacityEvent{Kind: CapacityEventLost}
		select {
		case err := <-result:
			if !errors.Is(err, ErrRevoked) {
				t.Fatalf("Connect() error = %v; want ErrRevoked", err)
			}
		case <-time.After(time.Second):
			t.Fatal("simultaneous revocation and capacity loss did not terminate")
		}
		auditEvents := recorder.snapshot()
		if countAuthenticatedCapacityAudit(auditEvents, AuditRevoked) != 1 ||
			countAuthenticatedCapacityAudit(auditEvents, AuditCapacityLost) != 0 ||
			countAuthenticatedCapacityAudit(auditEvents, AuditCapacityUnavailable) != 0 {
			t.Fatalf("authority audit events = %#v; want one revoked primary", auditEvents)
		}
	})

	t.Run("expiry before capacity loss", func(t *testing.T) {
		events := make(chan CapacityEvent, 1)
		lease := &authenticatedCapacityLeaseSpy{events: events}
		recorder := &authenticatedCapacityRecorderSpy{}
		client, backend := newTestStream(), newTestStream()
		grant := gatewayGrant()
		var clockMu sync.Mutex
		now := gatewayTestNow
		clock := ClockFunc(func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		})
		resolver := newAuthenticatedCapacityResolverSpy(backend, nil)
		gateway, err := New(Options{
			Authorizer:  &authenticatedCapacityAuthorizerSpy{grant: grant},
			Capacity:    &authenticatedCapacitySpy{lease: lease},
			Revocations: newAuthenticatedCapacityRevocationsSpy(nil),
			Recorder:    recorder, Resolver: resolver, Clock: clock,
			MaxReconnects: 2, CapacityReleaseTimeout: 250 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- gateway.Connect(context.Background(), gatewayRequest(), client) }()
		waitForAuthenticatedCapacityAudit(t, recorder, AuditConnected)

		clockMu.Lock()
		now = grant.ExpiresAt
		clockMu.Unlock()
		events <- CapacityEvent{Kind: CapacityEventLost}
		select {
		case err := <-result:
			if !errors.Is(err, ErrExpired) {
				t.Fatalf("Connect() error = %v; want ErrExpired", err)
			}
		case <-time.After(time.Second):
			t.Fatal("simultaneous expiry and capacity loss did not terminate")
		}
		auditEvents := recorder.snapshot()
		if countAuthenticatedCapacityAudit(auditEvents, AuditExpired) != 1 ||
			countAuthenticatedCapacityAudit(auditEvents, AuditCapacityLost) != 0 ||
			countAuthenticatedCapacityAudit(auditEvents, AuditCapacityUnavailable) != 0 {
			t.Fatalf("authority audit events = %#v; want one expired primary", auditEvents)
		}
	})
}

func TestGatewayAuthenticatedCapacityUsesStablePriorityAcrossExternalBoundaries(t *testing.T) {
	for _, boundary := range []string{"resolve", "dial"} {
		t.Run(boundary, func(t *testing.T) {
			events := make(chan CapacityEvent, 1)
			lease := &authenticatedCapacityLeaseSpy{events: events}
			revocations := newAuthenticatedCapacityRevocationsSpy(nil)
			recorder := &authenticatedCapacityRecorderSpy{}
			client, backend := newTestStream(), newTestStream()
			resolver := &authenticatedCapacityBlockingResolver{backend: backend}
			releaseBoundary := make(chan struct{})
			started := make(chan struct{}, 1)
			if boundary == "resolve" {
				resolver.resolveStarted = started
				resolver.resolveRelease = releaseBoundary
			} else {
				resolver.dialStarted = started
				resolver.dialRelease = releaseBoundary
			}
			gateway := newAuthenticatedCapacityGateway(
				t,
				&authenticatedCapacityAuthorizerSpy{grant: gatewayGrant()},
				&authenticatedCapacitySpy{lease: lease},
				revocations,
				recorder,
				resolver,
			)
			result := make(chan error, 1)
			go func() { result <- gateway.Connect(context.Background(), gatewayRequest(), client) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatalf("Gateway did not reach %s boundary", boundary)
			}

			revocations.watch.finish(ErrRevoked)
			events <- CapacityEvent{Kind: CapacityEventLost}
			close(releaseBoundary)
			select {
			case err := <-result:
				if !errors.Is(err, ErrRevoked) {
					t.Fatalf("Connect() error = %v; want ErrRevoked", err)
				}
			case <-time.After(time.Second):
				t.Fatalf("authority change did not stop blocked %s", boundary)
			}

			resolveCalls, dialCalls := resolver.snapshot()
			wantDialCalls := 0
			if boundary == "dial" {
				wantDialCalls = 1
			}
			if resolveCalls != 1 || dialCalls != wantDialCalls {
				t.Fatalf("Resolve/Dial calls = %d/%d; want 1/%d", resolveCalls, dialCalls, wantDialCalls)
			}
			if !authenticatedCapacityStreamClosed(client) {
				t.Fatal("revocation left caller stream open")
			}
			if boundary == "dial" && !authenticatedCapacityStreamClosed(backend) {
				t.Fatal("revocation after Dial left backend stream open")
			}
			auditEvents := recorder.snapshot()
			if countAuthenticatedCapacityAudit(auditEvents, AuditRevoked) != 1 ||
				countAuthenticatedCapacityAudit(auditEvents, AuditCapacityLost) != 0 ||
				countAuthenticatedCapacityAudit(auditEvents, AuditCapacityUnavailable) != 0 {
				t.Fatalf("authority audit events = %#v; want one revoked primary", auditEvents)
			}
			if releaseCalls, _ := lease.snapshot(); releaseCalls != 1 {
				t.Fatalf("Release() calls = %d; want 1", releaseCalls)
			}
		})
	}

	t.Run("reconnect backoff", func(t *testing.T) {
		events := make(chan CapacityEvent, 1)
		lease := &authenticatedCapacityLeaseSpy{events: events}
		revocations := newAuthenticatedCapacityRevocationsSpy(nil)
		recorder := &authenticatedCapacityRecorderSpy{}
		client, backend := newTestStream(), newTestStream()
		resolver := &authenticatedCapacityBlockingResolver{backend: backend}
		gateway, err := New(Options{
			Authorizer:  &authenticatedCapacityAuthorizerSpy{grant: gatewayGrant()},
			Capacity:    &authenticatedCapacitySpy{lease: lease},
			Revocations: revocations, Recorder: recorder, Resolver: resolver,
			Clock:         ClockFunc(func() time.Time { return gatewayTestNow }),
			MaxReconnects: 2, ReconnectBackoff: time.Second,
			CapacityReleaseTimeout: 250 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- gateway.Connect(context.Background(), gatewayRequest(), client) }()
		waitForAuthenticatedCapacityAudit(t, recorder, AuditConnected)
		if err := backend.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitForAuthenticatedCapacityAudit(t, recorder, AuditBackendClosed)

		revocations.watch.finish(ErrRevoked)
		events <- CapacityEvent{Kind: CapacityEventLost}
		select {
		case err := <-result:
			if !errors.Is(err, ErrRevoked) {
				t.Fatalf("Connect() error = %v; want ErrRevoked", err)
			}
		case <-time.After(time.Second):
			t.Fatal("authority change did not interrupt reconnect backoff")
		}
		resolveCalls, dialCalls := resolver.snapshot()
		if resolveCalls != 1 || dialCalls != 1 {
			t.Fatalf("Resolve/Dial calls = %d/%d; want 1/1 without reconnect", resolveCalls, dialCalls)
		}
		auditEvents := recorder.snapshot()
		if countAuthenticatedCapacityAudit(auditEvents, AuditRevoked) != 1 ||
			countAuthenticatedCapacityAudit(auditEvents, AuditCapacityLost) != 0 ||
			countAuthenticatedCapacityAudit(auditEvents, AuditCapacityUnavailable) != 0 {
			t.Fatalf("authority audit events = %#v; want one revoked primary", auditEvents)
		}
		if releaseCalls, _ := lease.snapshot(); releaseCalls != 1 {
			t.Fatalf("Release() calls = %d; want 1", releaseCalls)
		}
	})
}

func TestGatewayAuthenticatedCapacityReleaseUsesIndependentDeadline(t *testing.T) {
	type requestContextKey struct{}
	key := requestContextKey{}
	events := make(chan CapacityEvent)
	lease := &authenticatedCapacityLeaseSpy{events: events, requestKey: key}
	capacity := &authenticatedCapacitySpy{lease: lease}
	recorder := &authenticatedCapacityRecorderSpy{}
	client, backend := newTestStream(), newTestStream()
	resolver := newAuthenticatedCapacityResolverSpy(backend, nil)
	gateway := newAuthenticatedCapacityGateway(
		t,
		&authenticatedCapacityAuthorizerSpy{grant: gatewayGrant()},
		capacity,
		newAuthenticatedCapacityRevocationsSpy(nil),
		recorder,
		resolver,
	)
	requestCtx := context.WithValue(context.Background(), key, "request-context")
	requestCtx, cancel := context.WithCancel(requestCtx)
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() { result <- gateway.Connect(requestCtx, gatewayRequest(), client) }()
	waitForAuthenticatedCapacityAudit(t, recorder, AuditConnected)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v; want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not terminate the proxy")
	}
	releaseCalls, releases := lease.snapshot()
	if releaseCalls != 1 || len(releases) != 1 {
		t.Fatalf("Release() observations = calls %d, %#v; want exactly one", releaseCalls, releases)
	}
	release := releases[0]
	if release.errAtCall != nil || !release.hasDeadline || release.deadline.IsZero() {
		t.Fatalf("Release() context = %#v; want live context with deadline", release)
	}
	if release.requestTag != nil {
		t.Fatalf("Release() inherited request context value %v; want independent context", release.requestTag)
	}
}

func TestGatewayAuthenticatedCapacityReleaseErrorPreservesPrimaryAndRecordsFailure(t *testing.T) {
	releaseErr := errors.New("capacity release failed")
	events := make(chan CapacityEvent, 1)
	lease := &authenticatedCapacityLeaseSpy{events: events, releaseErr: releaseErr}
	capacity := &authenticatedCapacitySpy{lease: lease}
	recorder := &authenticatedCapacityRecorderSpy{}
	client, backend := newTestStream(), newTestStream()
	resolver := newAuthenticatedCapacityResolverSpy(backend, nil)
	gateway := newAuthenticatedCapacityGateway(
		t,
		&authenticatedCapacityAuthorizerSpy{grant: gatewayGrant()},
		capacity,
		newAuthenticatedCapacityRevocationsSpy(nil),
		recorder,
		resolver,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- gateway.Connect(ctx, gatewayRequest(), client) }()
	waitForAuthenticatedCapacityAudit(t, recorder, AuditConnected)
	events <- CapacityEvent{Kind: CapacityEventLost}

	select {
	case err := <-result:
		if !errors.Is(err, ErrCapacityUnavailable) || !errors.Is(err, errCapacityLeaseLost) || !errors.Is(err, releaseErr) {
			t.Fatalf("Connect() error = %v; want capacity-unavailable, lease-lost, and release errors", err)
		}
	case <-time.After(time.Second):
		t.Fatal("capacity loss did not terminate the proxy")
	}
	if releaseCalls, _ := lease.snapshot(); releaseCalls != 1 {
		t.Fatalf("Release() calls = %d; want 1", releaseCalls)
	}
	auditEvents := recorder.snapshot()
	if countAuthenticatedCapacityAudit(auditEvents, AuditCapacityLost) != 1 || countAuthenticatedCapacityAudit(auditEvents, AuditCapacityReleaseFailed) != 1 {
		t.Fatalf("capacity release audit events = %#v; want one lost and one release_failed", auditEvents)
	}
}
