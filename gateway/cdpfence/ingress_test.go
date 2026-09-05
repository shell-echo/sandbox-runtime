package cdpfence

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestNewAndOpenFailClosed(t *testing.T) {
	valid := Options{Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
		return gateway.DownstreamFenceDecision{Activated: true}, nil
	})}
	for _, test := range []struct {
		name string
		edit func(*Options)
	}{
		{"nil authority", func(options *Options) { options.Authority = nil }},
		{"typed nil authority", func(options *Options) { options.Authority = (*authoritySpy)(nil) }},
		{"short action timeout", func(options *Options) { options.ActionTimeout = MinOperationTimeout - time.Millisecond }},
		{"long close timeout", func(options *Options) { options.CloseTimeout = MaxOperationTimeout + time.Millisecond }},
		{"negative sessions", func(options *Options) { options.MaxSessions = -1 }},
		{"too many sessions", func(options *Options) { options.MaxSessions = MaxSessions + 1 }},
		{"negative action bytes", func(options *Options) { options.MaxActionBytes = -1 }},
		{"excessive action bytes", func(options *Options) { options.MaxActionBytes = MaxActionBytes + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.edit(&options)
			if ingress, err := New(options); ingress != nil || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
				t.Fatalf("New() = %#v, %v; want nil, downstream unavailable", ingress, err)
			}
		})
	}

	ingress := newTestIngress(t, valid)
	subject := testSubject("browser-a")
	fence := testFence(t, "claim-a")
	var typedNilStream *streamSpy
	for _, test := range []struct {
		name    string
		ctx     context.Context
		subject gateway.DownstreamFenceSubject
		fence   gateway.DownstreamFence
		dial    DownstreamDial
		want    error
	}{
		{"nil context", nil, subject, fence, testDial(&streamSpy{}), context.Canceled},
		{"invalid subject", context.Background(), gateway.DownstreamFenceSubject{}, fence, testDial(&streamSpy{}), gateway.ErrDownstreamUnavailable},
		{"invalid fence", context.Background(), subject, gateway.DownstreamFence{}, testDial(&streamSpy{}), gateway.ErrDownstreamUnavailable},
		{"nil dial", context.Background(), subject, fence, nil, gateway.ErrDownstreamUnavailable},
		{"nil stream", context.Background(), subject, fence, func(context.Context) (gateway.Stream, error) { return nil, nil }, gateway.ErrDownstreamUnavailable},
		{"typed nil stream", context.Background(), subject, fence, func(context.Context) (gateway.Stream, error) { return typedNilStream, nil }, gateway.ErrDownstreamUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if stream, err := ingress.Open(test.ctx, test.subject, test.fence, test.dial); stream != nil || !errors.Is(err, test.want) {
				t.Fatalf("Open() = %#v, %v; want nil, %v", stream, err, test.want)
			}
		})
	}
}

func TestOpenAuthorizesExactBindingBeforeDialAndBoundsErrors(t *testing.T) {
	secret := "private-authority-diagnostic"
	expectedSubject := testSubject("browser-a")
	expectedFence := testFence(t, "claim-a")
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{"lost", errors.Join(gateway.ErrDownstreamFenceLost, errors.New(secret)), gateway.ErrDownstreamFenceLost},
		{"unavailable", errors.Join(gateway.ErrDownstreamUnavailable, errors.New(secret)), gateway.ErrDownstreamUnavailable},
		{"unknown", errors.New(secret), gateway.ErrDownstreamUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			dials := 0
			ingress := newTestIngress(t, Options{ActionTimeout: 100 * time.Millisecond, Authority: authorityFunc(func(_ context.Context, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, window time.Duration) (gateway.DownstreamFenceDecision, error) {
				if subject != expectedSubject || fence.Opaque() != expectedFence.Opaque() || window != 100*time.Millisecond {
					t.Fatalf("authority binding = %#v, %v, %s", subject, fence, window)
				}
				return gateway.DownstreamFenceDecision{}, test.err
			})})
			stream, err := ingress.Open(context.Background(), expectedSubject, expectedFence, func(context.Context) (gateway.Stream, error) {
				dials++
				return &streamSpy{}, nil
			})
			if stream != nil || !errors.Is(err, test.want) || strings.Contains(err.Error(), secret) || dials != 0 {
				t.Fatalf("Open() = %#v, %v; dials=%d; want bounded %v before dial", stream, err, dials, test.want)
			}
		})
	}
}

func TestOpenRejectsDuplicateActiveClaimWithoutSecondDial(t *testing.T) {
	var calls int
	ingress := newTestIngress(t, Options{Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
		calls++
		return gateway.DownstreamFenceDecision{Activated: calls == 1}, nil
	})})
	subject, fence := testSubject("browser-a"), testFence(t, "claim-a")
	first := openTestStream(t, ingress, subject, fence, &streamSpy{})
	dials := 0
	second, err := ingress.Open(context.Background(), subject, fence, func(context.Context) (gateway.Stream, error) {
		dials++
		return &streamSpy{}, nil
	})
	if second != nil || !errors.Is(err, gateway.ErrDownstreamUnavailable) || dials != 0 {
		t.Fatalf("duplicate Open() = %#v, %v; dials=%d", second, err, dials)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCleanReconnectAllowsRetainedCurrentClaim(t *testing.T) {
	var calls int
	ingress := newTestIngress(t, Options{Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
		calls++
		return gateway.DownstreamFenceDecision{Activated: calls == 1}, nil
	})})
	subject, fence := testSubject("browser-a"), testFence(t, "claim-a")
	first := openTestStream(t, ingress, subject, fence, &streamSpy{})
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := openTestStream(t, ingress, subject, fence, &streamSpy{})
	if err := second.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSendAuthorizesEveryCompleteBufferedAction(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var claims []string
	var calls int
	expectedSubject := testSubject("browser-a")
	authority := authorityFunc(func(ctx context.Context, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
		mu.Lock()
		calls++
		call := calls
		claims = append(claims, fence.Opaque())
		mu.Unlock()
		if subject != expectedSubject {
			t.Fatalf("unexpected subject = %#v", subject)
		}
		if call == 1 {
			return gateway.DownstreamFenceDecision{Activated: true}, nil
		}
		if call == 2 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return gateway.DownstreamFenceDecision{}, ctx.Err()
			}
		}
		return gateway.DownstreamFenceDecision{}, nil
	})
	ingress := newTestIngress(t, Options{Authority: authority, MaxActionBytes: 8})
	downstream := &streamSpy{receiveFrame: gateway.Frame{Type: gateway.TextFrame, Payload: []byte("response")}}
	stream := openTestStream(t, ingress, expectedSubject, testFence(t, "claim-a"), downstream)

	first := gateway.Frame{Type: gateway.TextFrame, Payload: []byte("one")}
	result := make(chan error, 1)
	go func() { result <- stream.Send(context.Background(), first) }()
	<-entered
	first.Payload[0] = 'x'
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(context.Background(), gateway.Frame{Type: gateway.BinaryFrame, Payload: []byte("two")}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Receive(context.Background())
	if err != nil || string(response.Payload) != "response" {
		t.Fatalf("Receive() = %#v, %v", response, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(claims) != 3 || claims[0] != claims[1] || claims[1] != claims[2] ||
		downstream.sendCount != 2 || string(downstream.sent[0].Payload) != "one" {
		t.Fatalf("claims=%d sends=%#v", len(claims), downstream.sent)
	}
}

func TestSessionGateSerializesActionAndHigherActivationAcrossGeneration(t *testing.T) {
	oldActionEntered := make(chan struct{})
	releaseOldAction := make(chan struct{})
	newActivationEntered := make(chan struct{}, 1)
	var mu sync.Mutex
	var calls int
	authority := authorityFunc(func(ctx context.Context, _ gateway.DownstreamFenceSubject, _ gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		switch call {
		case 1:
			return gateway.DownstreamFenceDecision{Activated: true}, nil
		case 2:
			close(oldActionEntered)
			select {
			case <-releaseOldAction:
				return gateway.DownstreamFenceDecision{}, nil
			case <-ctx.Done():
				return gateway.DownstreamFenceDecision{}, ctx.Err()
			}
		case 3:
			newActivationEntered <- struct{}{}
			return gateway.DownstreamFenceDecision{Activated: true}, nil
		default:
			return gateway.DownstreamFenceDecision{}, nil
		}
	})
	ingress := newTestIngress(t, Options{Authority: authority})
	oldBackend := &streamSpy{}
	oldSubject := testSubject("browser-a")
	old := openTestStream(t, ingress, oldSubject, testFence(t, "claim-old"), oldBackend)
	oldResult := make(chan error, 1)
	go func() {
		oldResult <- old.Send(context.Background(), gateway.Frame{Type: gateway.TextFrame, Payload: []byte("old")})
	}()
	<-oldActionEntered

	newSubject := oldSubject
	newSubject.CapabilityProfileID = "browser-v2"
	newSubject.ConnectionGeneration++
	newResult := make(chan *Stream, 1)
	go func() {
		stream, _ := ingress.Open(context.Background(), newSubject, testFence(t, "claim-new"), testDial(&streamSpy{}))
		newResult <- stream
	}()
	select {
	case <-newActivationEntered:
		t.Fatal("new generation entered authority before the old action write completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseOldAction)
	if err := <-oldResult; err != nil {
		t.Fatal(err)
	}
	newStream := <-newResult
	if newStream == nil || oldBackend.closeCount != 1 {
		t.Fatalf("replacement stream=%#v old closes=%d", newStream, oldBackend.closeCount)
	}
	if err := old.Send(context.Background(), gateway.Frame{Type: gateway.TextFrame}); !errors.Is(err, gateway.ErrDownstreamFenceLost) {
		t.Fatalf("old Send() error = %v; want fence lost", err)
	}
	if err := newStream.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHigherActivationInterruptsOldReceiveWithFenceLoss(t *testing.T) {
	var calls int
	authority := authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
		calls++
		return gateway.DownstreamFenceDecision{Activated: calls == 1 || calls == 2}, nil
	})
	ingress := newTestIngress(t, Options{Authority: authority})
	oldBackend := newBlockingStream()
	old := openTestStream(t, ingress, testSubject("browser-a"), testFence(t, "claim-old"), oldBackend)
	receiveResult := make(chan error, 1)
	go func() {
		_, err := old.Receive(context.Background())
		receiveResult <- err
	}()
	<-oldBackend.receiveStarted
	newStream := openTestStream(t, ingress, testSubject("browser-a"), testFence(t, "claim-new"), newBlockingStream())
	select {
	case err := <-receiveResult:
		if !errors.Is(err, gateway.ErrDownstreamFenceLost) {
			t.Fatalf("old Receive() error = %v; want fence lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("higher activation did not interrupt old Receive")
	}
	if err := newStream.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHigherActivationDoesNotDialUntilOldUpstreamCloses(t *testing.T) {
	var authorityCalls int
	ingress := newTestIngress(t, Options{
		CloseTimeout: MinOperationTimeout,
		Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
			authorityCalls++
			return gateway.DownstreamFenceDecision{Activated: true}, nil
		}),
	})
	oldBackend := &blockingCloseStream{}
	old := openTestStream(t, ingress, testSubject("browser-a"), testFence(t, "claim-old"), oldBackend)
	dials := 0
	replacement, err := ingress.Open(context.Background(), testSubject("browser-a"), testFence(t, "claim-new"), func(context.Context) (gateway.Stream, error) {
		dials++
		return &streamSpy{}, nil
	})
	if replacement != nil || !errors.Is(err, gateway.ErrDownstreamUnavailable) || dials != 0 {
		t.Fatalf("replacement Open() = %#v, %v; dials=%d; want unavailable before dial", replacement, err, dials)
	}
	if ingress.sessions[keyForSubject(testSubject("browser-a"))].active != old {
		t.Fatal("old stream was discarded without confirmed downstream closure")
	}
}

func TestAuthorityAndDownstreamFailuresCloseWithoutForwardOrSecretLeak(t *testing.T) {
	secret := "private-ingress-secret"
	for _, test := range []struct {
		name          string
		authorityErr  error
		downstreamErr error
		want          error
	}{
		{"authority lost", errors.Join(gateway.ErrDownstreamFenceLost, errors.New(secret)), nil, gateway.ErrDownstreamFenceLost},
		{"authority unavailable", errors.New(secret), nil, gateway.ErrDownstreamUnavailable},
		{"downstream write", nil, errors.New(secret), gateway.ErrDownstreamUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			authority := authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
				calls++
				if calls == 1 {
					return gateway.DownstreamFenceDecision{Activated: true}, nil
				}
				return gateway.DownstreamFenceDecision{}, test.authorityErr
			})
			ingress := newTestIngress(t, Options{Authority: authority})
			backend := &streamSpy{sendErr: test.downstreamErr}
			stream := openTestStream(t, ingress, testSubject("browser-a"), testFence(t, "claim-a"), backend)
			err := stream.Send(context.Background(), gateway.Frame{Type: gateway.TextFrame, Payload: []byte("payload")})
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), secret) {
				t.Fatalf("Send() error = %v; want bounded %v", err, test.want)
			}
			wantSends := 1
			if test.authorityErr != nil {
				wantSends = 0
			}
			if backend.sendCount != wantSends || backend.closeCount != 1 {
				t.Fatalf("sends=%d closes=%d; want %d/1", backend.sendCount, backend.closeCount, wantSends)
			}
			if err := stream.Send(context.Background(), gateway.Frame{Type: gateway.TextFrame}); !errors.Is(err, test.want) {
				t.Fatalf("later Send() error = %v; want %v", err, test.want)
			}
		})
	}
}

func TestDialFailureClosesReturnedStreamAndBoundsError(t *testing.T) {
	secret := "private-dial-secret"
	ingress := newTestIngress(t, Options{Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
		return gateway.DownstreamFenceDecision{Activated: true}, nil
	})})
	backend := &streamSpy{}
	stream, err := ingress.Open(context.Background(), testSubject("browser-a"), testFence(t, "claim-a"), func(context.Context) (gateway.Stream, error) {
		return backend, errors.New(secret)
	})
	if stream != nil || !errors.Is(err, gateway.ErrDownstreamUnavailable) || strings.Contains(err.Error(), secret) || backend.closeCount != 1 {
		t.Fatalf("Open() = %#v, %v; closes=%d", stream, err, backend.closeCount)
	}
}

func TestFrameBoundaryAndSessionCapacity(t *testing.T) {
	var authorityCalls int
	ingress := newTestIngress(t, Options{
		Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
			authorityCalls++
			return gateway.DownstreamFenceDecision{Activated: authorityCalls == 1 || authorityCalls == 2}, nil
		}),
		MaxSessions: 1, MaxActionBytes: 4,
	})
	first := openTestStream(t, ingress, testSubject("browser-a"), testFence(t, "claim-a"), &streamSpy{})
	if stream, err := ingress.Open(context.Background(), testSubject("browser-b"), testFence(t, "claim-b"), testDial(&streamSpy{})); stream != nil || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("second session Open() = %#v, %v", stream, err)
	}
	for _, frame := range []gateway.Frame{
		{Type: gateway.PingFrame},
		{Type: gateway.TextFrame, Payload: []byte("12345")},
	} {
		if err := first.Send(context.Background(), frame); !errors.Is(err, gateway.ErrDownstreamUnavailable) {
			t.Fatalf("invalid frame Send() error = %v", err)
		}
	}
	if authorityCalls != 1 {
		t.Fatalf("invalid frames reached authority; calls=%d", authorityCalls)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := openTestStream(t, ingress, testSubject("browser-b"), testFence(t, "claim-b"), &streamSpy{})
	if err := second.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalFailureReleasesSessionWithoutExplicitClose(t *testing.T) {
	var calls int
	ingress := newTestIngress(t, Options{
		Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
			calls++
			if calls == 1 || calls == 3 {
				return gateway.DownstreamFenceDecision{Activated: true}, nil
			}
			return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamFenceLost
		}),
		MaxSessions: 1,
	})
	first := openTestStream(t, ingress, testSubject("browser-a"), testFence(t, "claim-a"), &streamSpy{})
	if err := first.Send(context.Background(), gateway.Frame{Type: gateway.TextFrame}); !errors.Is(err, gateway.ErrDownstreamFenceLost) {
		t.Fatalf("first Send() error = %v; want fence lost", err)
	}
	second := openTestStream(t, ingress, testSubject("browser-b"), testFence(t, "claim-b"), &streamSpy{})
	if err := second.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGateWaitAndCloseAreBounded(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls int
	ingress := newTestIngress(t, Options{
		ActionTimeout: 200 * time.Millisecond, CloseTimeout: MinOperationTimeout,
		Authority: authorityFunc(func(ctx context.Context, _ gateway.DownstreamFenceSubject, _ gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
			calls++
			if calls == 1 {
				return gateway.DownstreamFenceDecision{Activated: true}, nil
			}
			close(entered)
			select {
			case <-release:
				return gateway.DownstreamFenceDecision{}, nil
			case <-ctx.Done():
				return gateway.DownstreamFenceDecision{}, ctx.Err()
			}
		}),
	})
	stream := openTestStream(t, ingress, testSubject("browser-a"), testFence(t, "claim-a"), &streamSpy{})
	firstResult := make(chan error, 1)
	go func() { firstResult <- stream.Send(context.Background(), gateway.Frame{Type: gateway.TextFrame}) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), MinOperationTimeout)
	defer cancel()
	started := time.Now()
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.TextFrame}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued Send() error = %v; want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed < MinOperationTimeout || elapsed > 4*MinOperationTimeout {
		t.Fatalf("queued Send() elapsed = %s", elapsed)
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	closeIngress := newTestIngress(t, Options{
		CloseTimeout: MinOperationTimeout,
		Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
			return gateway.DownstreamFenceDecision{Activated: true}, nil
		}),
	})
	blocking := &blockingCloseStream{}
	closing := openTestStream(t, closeIngress, testSubject("browser-b"), testFence(t, "claim-b"), blocking)
	started = time.Now()
	if err := closing.Close(context.Background()); !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("Close() error = %v; want downstream unavailable", err)
	}
	if elapsed := time.Since(started); elapsed < MinOperationTimeout || elapsed > 4*MinOperationTimeout {
		t.Fatalf("Close() elapsed = %s", elapsed)
	}
}

func TestTerminalTimeoutClosesWithIndependentBoundedContext(t *testing.T) {
	for _, test := range []struct {
		name             string
		authorityTimeout bool
	}{
		{name: "authority timeout", authorityTimeout: true},
		{name: "downstream send timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var authorityCalls int
			ingress := newTestIngress(t, Options{
				ActionTimeout: MinOperationTimeout,
				CloseTimeout:  MinOperationTimeout,
				Authority: authorityFunc(func(ctx context.Context, _ gateway.DownstreamFenceSubject, _ gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
					authorityCalls++
					if authorityCalls == 1 {
						return gateway.DownstreamFenceDecision{Activated: true}, nil
					}
					if test.authorityTimeout {
						<-ctx.Done()
						return gateway.DownstreamFenceDecision{}, ctx.Err()
					}
					return gateway.DownstreamFenceDecision{}, nil
				}),
			})
			backend := &timeoutThenCloseStream{sendTimeout: !test.authorityTimeout}
			stream := openTestStream(t, ingress, testSubject("browser-timeout"), testFence(t, "claim-timeout"), backend)

			if err := stream.Send(context.Background(), gateway.Frame{Type: gateway.TextFrame}); !errors.Is(err, gateway.ErrDownstreamUnavailable) {
				t.Fatalf("Send() error = %v; want downstream unavailable", err)
			}
			closeCalls, closeContextErr := backend.closeSnapshot()
			if closeCalls != 1 || closeContextErr != nil {
				t.Fatalf("downstream Close() = calls %d, context error %v; want one live bounded cleanup", closeCalls, closeContextErr)
			}
			ingress.mu.Lock()
			remainingSessions := len(ingress.sessions)
			ingress.mu.Unlock()
			if remainingSessions != 0 {
				t.Fatalf("retained sessions = %d; want zero after confirmed downstream close", remainingSessions)
			}
		})
	}
}

type authorityFunc func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error)

func (f authorityFunc) AuthorizeAction(ctx context.Context, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, window time.Duration) (gateway.DownstreamFenceDecision, error) {
	return f(ctx, subject, fence, window)
}

type authoritySpy struct{}

func (*authoritySpy) AuthorizeAction(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
	return gateway.DownstreamFenceDecision{}, nil
}

type streamSpy struct {
	mu           sync.Mutex
	receiveFrame gateway.Frame
	receiveErr   error
	sendErr      error
	closeErr     error
	sent         []gateway.Frame
	sendCount    int
	closeCount   int
}

func (s *streamSpy) Receive(context.Context) (gateway.Frame, error) {
	if s == nil {
		return gateway.Frame{}, io.ErrClosedPipe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receiveFrame.Clone(), s.receiveErr
}

func (s *streamSpy) Send(_ context.Context, frame gateway.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendCount++
	s.sent = append(s.sent, frame.Clone())
	return s.sendErr
}

func (s *streamSpy) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCount++
	return s.closeErr
}

type blockingCloseStream struct{ streamSpy }

func (s *blockingCloseStream) Close(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

type timeoutThenCloseStream struct {
	streamSpy
	sendTimeout     bool
	closeContextErr error
}

func (s *timeoutThenCloseStream) Send(ctx context.Context, _ gateway.Frame) error {
	if !s.sendTimeout {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (s *timeoutThenCloseStream) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCount++
	s.closeContextErr = ctx.Err()
	return s.closeContextErr
}

func (s *timeoutThenCloseStream) closeSnapshot() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeCount, s.closeContextErr
}

type blockingStream struct {
	receiveStarted chan struct{}
	closed         chan struct{}
	closeOnce      sync.Once
}

func newBlockingStream() *blockingStream {
	return &blockingStream{receiveStarted: make(chan struct{}), closed: make(chan struct{})}
}

func (s *blockingStream) Receive(ctx context.Context) (gateway.Frame, error) {
	select {
	case <-s.receiveStarted:
	default:
		close(s.receiveStarted)
	}
	select {
	case <-ctx.Done():
		return gateway.Frame{}, ctx.Err()
	case <-s.closed:
		return gateway.Frame{}, io.EOF
	}
}

func (s *blockingStream) Send(context.Context, gateway.Frame) error { return nil }

func (s *blockingStream) Close(context.Context) error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func newTestIngress(t *testing.T, options Options) *Ingress {
	t.Helper()
	ingress, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return ingress
}

func openTestStream(t *testing.T, ingress *Ingress, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, downstream gateway.Stream) *Stream {
	t.Helper()
	stream, err := ingress.Open(context.Background(), subject, fence, testDial(downstream))
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func testDial(stream gateway.Stream) DownstreamDial {
	return func(context.Context) (gateway.Stream, error) { return stream, nil }
}

func testSubject(browserSessionID string) gateway.DownstreamFenceSubject {
	return gateway.DownstreamFenceSubject{
		TenantID: "tenant-a", SandboxID: "sandbox-a", BrowserSessionID: browserSessionID,
		CapabilityProfileID: "browser-v1", ConnectionGeneration: 1,
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
}

func testFence(t *testing.T, suffix string) gateway.DownstreamFence {
	t.Helper()
	fence, err := gateway.NewDownstreamFence("v1." + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return fence
}
