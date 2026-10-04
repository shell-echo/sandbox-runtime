package guestagent

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type delayedDependencyAuthenticator struct {
	Authenticator
	delay time.Duration
}

func (a delayedDependencyAuthenticator) Authenticate(ctx context.Context, _ AuthRequest) (Identity, error) {
	timer := time.NewTimer(a.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return Identity{}, ErrAuthDependencyUnavailable
	case <-ctx.Done():
		return Identity{}, ctx.Err()
	}
}

type failWelcomeConn struct {
	net.Conn
	writes int
	mu     sync.Mutex
	failed chan struct{}
}

func (c *failWelcomeConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes >= 2 {
		if c.writes == 2 {
			close(c.failed)
		}
		return 0, errors.New("test welcome transport failure")
	}
	return c.Conn.Write(data)
}

type failWelcomeWriter struct {
	http.ResponseWriter
	failed chan struct{}
}

func (w failWelcomeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	if err := buffered.Flush(); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	failing := &failWelcomeConn{Conn: conn, failed: w.failed}
	buffered.Reader.Reset(failing)
	buffered.Writer.Reset(failing)
	return failing, buffered, nil
}

func TestOutboundAgentAuthenticatesCallsCancelsAndReconnects(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := newMemoryAuthenticator(publicKey, 1)
	hub, err := NewHub(HubOptions{Authenticator: auth, AuthorityPollPeriod: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	var cancelled atomic.Bool
	agent, err := NewAgent(AgentOptions{
		URL: "ws" + strings.TrimPrefix(server.URL, "http"), GuestID: "gst-test", BindingGeneration: 1, PrivateKey: privateKey,
		Handlers: map[string]OperationHandler{
			"guest.health": func(context.Context, json.RawMessage) (any, error) { return map[string]any{"ready": true}, nil },
			"guest.wait": func(ctx context.Context, _ json.RawMessage) (any, error) {
				<-ctx.Done()
				cancelled.Store(true)
				return nil, ctx.Err()
			},
		}, ReconnectBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- agent.Run(ctx) }()

	response := waitForCall(t, hub, "guest.health", map[string]any{"probe": true})
	readyContext, readyCancel := context.WithTimeout(context.Background(), time.Second)
	if err := waitForAgentReady(readyContext, agent); err != nil {
		readyCancel()
		t.Fatalf("Agent.Ready() = %v", err)
	}
	readyCancel()
	var health struct {
		Ready bool `json:"ready"`
	}
	if json.Unmarshal(response, &health) != nil || !health.Ready {
		t.Fatalf("health response = %s", response)
	}
	callCtx, stopCall := context.WithTimeout(context.Background(), 40*time.Millisecond)
	_, err = hub.Call(callCtx, "tenant-test", "wrk-test", "primary-code", "guest.wait", map[string]any{})
	stopCall()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Call() err=%v", err)
	}
	deadline := time.Now().Add(time.Second)
	for !cancelled.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cancelled.Load() {
		t.Fatal("Guest operation did not observe cancellation")
	}

	hub.Disconnect("tenant-test", "wrk-test", "primary-code")
	_ = waitForCall(t, hub, "guest.health", map[string]any{"after": "reconnect"})
	if auth.authentications() < 2 {
		t.Fatalf("authentications=%d; want reconnect", auth.authentications())
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Agent.Run() err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Agent.Run() did not stop")
	}
}

func TestOptionalRetirementOwnsDisconnectAndFreshReconnect(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := newMemoryAuthenticator(publicKey, 1)
	var retired atomic.Int64
	var observedMu sync.Mutex
	var observed []Observation
	hub, err := NewHub(HubOptions{Authenticator: auth, AuthorityPollPeriod: 10 * time.Millisecond,
		Observation: func(value Observation) {
			observedMu.Lock()
			observed = append(observed, value)
			observedMu.Unlock()
		},
		Retirement: &RetirementPolicy{Capacity: 2, Readback: retirementTestReadback, Retire: func(ctx context.Context, identity Identity) (RetirementDisposition, error) {
			if err := auth.Disconnected(ctx, identity); err != nil {
				return "", err
			}
			retired.Add(1)
			return RetirementReleased, nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	agent, err := NewAgent(AgentOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"),
		GuestID: "gst-test", BindingGeneration: 1, PrivateKey: privateKey,
		Handlers: map[string]OperationHandler{"guest.health": func(context.Context, json.RawMessage) (any, error) {
			return true, nil
		}}, ReconnectBackoff: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- agent.Run(ctx) }()
	_ = waitForCall(t, hub, "guest.health", nil)
	hub.Disconnect("tenant-test", "wrk-test", "primary-code")
	_ = waitForCall(t, hub, "guest.health", nil)
	if auth.authentications() < 2 || retired.Load() < 1 {
		t.Fatalf("fresh reconnect=%d exact retire=%d", auth.authentications(), retired.Load())
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Agent.Run() = %v", err)
	}
	hub.Disconnect("tenant-test", "wrk-test", "primary-code")
	shutdownCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := hub.ShutdownRetirement(shutdownCtx); err != nil {
		t.Fatalf("retirement shutdown = %v", err)
	}
	observedMu.Lock()
	defer observedMu.Unlock()
	var firstAttempt string
	for _, value := range observed {
		if value.Event == ObservationProductPeerInstalled {
			firstAttempt = value.AttemptDigest
			break
		}
	}
	if firstAttempt == "" {
		t.Fatal("no authenticated Product attempt observed")
	}
	var lifecycle []string
	for _, value := range observed {
		if value.AttemptDigest == firstAttempt &&
			(value.Event == ObservationProductDisconnectPending ||
				value.Event == ObservationProductCloseCompleted ||
				value.Event == ObservationProductDisconnectResolved) {
			lifecycle = append(lifecycle, value.Event)
		}
	}
	if len(lifecycle) != 3 || lifecycle[0] != ObservationProductDisconnectPending ||
		lifecycle[1] != ObservationProductCloseCompleted || lifecycle[2] != ObservationProductDisconnectResolved {
		t.Fatalf("old owner cleanup order = %v", lifecycle)
	}
}

type busyOwnerAuthenticator struct{ *memoryAuthenticator }

type blockedAfterCommitAuthenticator struct {
	Authenticator
	committed chan struct{}
	release   chan struct{}
}

func (a *blockedAfterCommitAuthenticator) Authenticate(ctx context.Context, request AuthRequest) (Identity, error) {
	identity, err := a.Authenticator.Authenticate(ctx, request)
	close(a.committed)
	select {
	case <-a.release:
		return identity, err
	case <-ctx.Done():
		return identity, err
	}
}

func (a *busyOwnerAuthenticator) AuthenticateWithLocalOwner(_ context.Context, request AuthRequest, owner Identity) (Identity, error) {
	signing, err := request.SigningBytes()
	if err != nil {
		return Identity{}, ErrUnauthorized
	}
	signature, err := request.SignatureBytes()
	if err != nil || !ed25519.Verify(a.publicKey, signing, signature) {
		return Identity{}, ErrUnauthorized
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.connected || owner.GuestID != request.Hello.GuestID ||
		owner.BindingGeneration != request.Hello.BindingGeneration || owner.ClientNonce != a.nonce {
		return Identity{}, ErrUnauthorized
	}
	return Identity{}, ErrAuthConnectedBusy
}

func signedRawGuestAttempt(t *testing.T, ctx context.Context, address string, privateKey ed25519.PrivateKey) (*websocket.Conn, error) {
	t.Helper()
	connection, _, err := websocket.Dial(ctx, address, &websocket.DialOptions{Subprotocols: []string{Subprotocol}})
	if err != nil {
		return nil, err
	}
	var challenge Challenge
	if err := readJSON(ctx, connection, &challenge); err != nil {
		connection.CloseNow()
		return nil, err
	}
	nonce, err := randomNonce()
	if err != nil {
		connection.CloseNow()
		return nil, err
	}
	hello := Hello{Type: "hello", GuestID: "gst-test", BindingGeneration: 1,
		ProtocolVersion: ProtocolVersion, Capabilities: []string{"guest.health"}, ClientNonce: nonce}
	request := AuthRequest{Hello: hello, Challenge: challenge}
	signing, err := request.SigningBytes()
	if err != nil {
		connection.CloseNow()
		return nil, err
	}
	hello.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, signing))
	if err := writeJSON(ctx, connection, hello); err != nil {
		connection.CloseNow()
		return nil, err
	}
	return connection, nil
}

func TestPinnedLocalOwnerProducesOnlySignedBusy1013(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := &busyOwnerAuthenticator{newMemoryAuthenticator(publicKey, 1)}
	var retired atomic.Int64
	var retryable atomic.Int64
	hub, err := NewHub(HubOptions{Authenticator: auth, RetryTemporaryAuth: true,
		Observation: func(value Observation) {
			if value.Event == ObservationProductAuthRetryable && value.Reason == "connected_busy" {
				retryable.Add(1)
			}
		},
		Retirement: &RetirementPolicy{Capacity: 2, Readback: retirementTestReadback,
			Retire: func(ctx context.Context, identity Identity) (RetirementDisposition, error) {
				if err := auth.Disconnected(ctx, identity); err != nil {
					return "", err
				}
				retired.Add(1)
				return RetirementReleased, nil
			}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	address := "ws" + strings.TrimPrefix(server.URL, "http")
	agent, err := NewAgent(AgentOptions{URL: address, GuestID: "gst-test", BindingGeneration: 1,
		PrivateKey: privateKey, ReconnectBackoff: 10 * time.Millisecond,
		Handlers: map[string]OperationHandler{"guest.health": func(context.Context, json.RawMessage) (any, error) {
			return true, nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	firstCtx, stopFirst := context.WithCancel(t.Context())
	firstDone := make(chan error, 1)
	go func() { firstDone <- agent.Run(firstCtx) }()
	_ = waitForCall(t, hub, "guest.health", nil)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	second, err := signedRawGuestAttempt(t, ctx, address, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var welcome Welcome
	err = readJSON(ctx, second, &welcome)
	second.CloseNow()
	if websocket.CloseStatus(err) != websocket.StatusTryAgainLater || retryable.Load() != 1 || auth.authentications() != 1 {
		t.Fatalf("local connected-busy = %v, retryable=%d authentications=%d", err, retryable.Load(), auth.authentications())
	}
	stopFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("old Guest exit = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for (!hub.RetirementReady() || retired.Load() < 1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !hub.RetirementReady() || retired.Load() < 1 {
		t.Fatal("old owner did not retire before fresh attempt")
	}
	fresh, err := signedRawGuestAttempt(t, ctx, address, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := readJSON(ctx, fresh, &welcome); err != nil || welcome.Type != "welcome" {
		fresh.CloseNow()
		t.Fatalf("fresh signed attempt = %+v, %v", welcome, err)
	}
	fresh.CloseNow()
	shutdownCtx, stopShutdown := context.WithTimeout(context.Background(), time.Second)
	defer stopShutdown()
	if err := hub.ShutdownRetirement(shutdownCtx); err != nil {
		t.Fatalf("retirement shutdown = %v", err)
	}
}

func TestCommittedAuthenticationOwnsCleanupWhenWelcomeWriteFails(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	underlying := newMemoryAuthenticator(publicKey, 1)
	auth := &blockedAfterCommitAuthenticator{Authenticator: underlying,
		committed: make(chan struct{}), release: make(chan struct{})}
	var retired atomic.Int64
	hub, err := NewHub(HubOptions{Authenticator: auth,
		Retirement: &RetirementPolicy{Capacity: 1, Readback: retirementTestReadback,
			Retire: func(ctx context.Context, identity Identity) (RetirementDisposition, error) {
				if err := underlying.Disconnected(ctx, identity); err != nil {
					return "", err
				}
				retired.Add(1)
				return RetirementReleased, nil
			}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	connection, err := signedRawGuestAttempt(t, ctx, "ws"+strings.TrimPrefix(server.URL, "http"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-auth.committed:
	case <-ctx.Done():
		t.Fatal("authentication did not commit before transport loss")
	}
	connection.CloseNow()
	close(auth.release)
	deadline := time.Now().Add(time.Second)
	for (retired.Load() != 1 || !hub.RetirementReady()) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if retired.Load() != 1 || !hub.RetirementReady() {
		t.Fatal("post-commit welcome failure lost cleanup ownership")
	}
	shutdownCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := hub.ShutdownRetirement(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}

type firstAuthenticationFailure struct {
	Authenticator
	mu       sync.Mutex
	attempts int
	failure  error
}

func (a *firstAuthenticationFailure) Authenticate(ctx context.Context, request AuthRequest) (Identity, error) {
	a.mu.Lock()
	a.attempts++
	first := a.attempts == 1
	a.mu.Unlock()
	if first {
		return Identity{}, a.failure
	}
	return a.Authenticator.Authenticate(ctx, request)
}

func (a *firstAuthenticationFailure) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.attempts
}

func TestTemporaryAuthCloseRequiresBothExplicitEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, failure        string
		hubRetry, agentRetry bool
		wantReconnect        bool
	}{
		{name: "new endpoints", failure: "definite", hubRetry: true, agentRetry: true, wantReconnect: true},
		{name: "old Guest", failure: "definite", hubRetry: true, agentRetry: false},
		{name: "old Product", failure: "definite", hubRetry: false, agentRetry: true},
		{name: "unknown outcome", failure: "unknown", hubRetry: true, agentRetry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			failure := ErrAuthDependencyUnavailable
			if tc.failure == "unknown" {
				failure = ErrUnavailable
			}
			auth := &firstAuthenticationFailure{Authenticator: newMemoryAuthenticator(publicKey, 1), failure: failure}
			hub, err := NewHub(HubOptions{Authenticator: auth, RetryTemporaryAuth: tc.hubRetry})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(hub)
			defer server.Close()
			var actual1013Retries atomic.Int64
			agent, err := NewAgent(AgentOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"),
				GuestID: "gst-test", BindingGeneration: 1, PrivateKey: privateKey,
				Handlers:         map[string]OperationHandler{"guest.health": func(context.Context, json.RawMessage) (any, error) { return true, nil }},
				ReconnectBackoff: 10 * time.Millisecond, RetryTemporaryAuth: tc.agentRetry,
				Observation: func(value Observation) {
					if value.Event == ObservationGuestAuthRetry {
						actual1013Retries.Add(1)
					}
				}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- agent.Run(ctx) }()
			if tc.wantReconnect {
				_ = waitForCall(t, hub, "guest.health", nil)
				if auth.count() < 2 || actual1013Retries.Load() != 1 {
					t.Fatalf("temporary dependency retry attempts=%d actual1013=%d", auth.count(), actual1013Retries.Load())
				}
				cancel()
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatalf("Agent.Run after reconnect = %v", err)
				}
				return
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrUnauthorized) || auth.count() != 1 || actual1013Retries.Load() != 0 {
					t.Fatalf("mixed/unknown endpoint admission = %v attempts=%d actual1013=%d", err, auth.count(), actual1013Retries.Load())
				}
			case <-ctx.Done():
				t.Fatal("mixed/unknown endpoint retried or failed to stop")
			}
		})
	}
}

func TestRetryableCloseAndReceiptOffHandlerJoinHonorCancellation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := &firstAuthenticationFailure{Authenticator: newMemoryAuthenticator(publicKey, 1),
		failure: ErrAuthDependencyUnavailable}
	hub, err := NewHub(HubOptions{Authenticator: auth,
		RetryTemporaryAuth: true,
		Retirement: &RetirementPolicy{Capacity: 1, Readback: retirementTestReadback,
			Retire: func(context.Context, Identity) (RetirementDisposition, error) {
				return RetirementReleased, nil
			}}})
	if err != nil {
		t.Fatal(err)
	}
	// The same producer lifecycle is required with receipts disabled.
	requestCancel := make(chan context.CancelFunc, 1)
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithCancel(request.Context())
		requestCancel <- cancel
		defer close(handlerDone)
		hub.ServeHTTP(writer, request.WithContext(ctx))
	}))
	defer server.Close()
	ctx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	connection, err := signedRawGuestAttempt(t, ctx, "ws"+strings.TrimPrefix(server.URL, "http"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	for (auth.count() == 0 || !hub.RetirementReady()) && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("definite pre-commit refusal did not abandon reservation")
	}
	joined := make(chan error, 1)
	go func() { joined <- hub.QuiesceObservation(ctx) }()
	select {
	case <-joined:
		t.Fatal("abandoned reservation was mistaken for handler completion")
	case <-time.After(25 * time.Millisecond):
	}
	(<-requestCancel)()
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not interrupt 1013 close handshake")
	}
	if err := <-joined; err != nil {
		t.Fatalf("handler join after transport cancellation = %v", err)
	}
	if hub.RetirementReady() {
		t.Fatal("quiesced Hub reopened admission")
	}
	if err := hub.ShutdownRetirement(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRetryableCloseUsesRemainingHandshakeBudget(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub(HubOptions{Authenticator: delayedDependencyAuthenticator{
		Authenticator: newMemoryAuthenticator(publicKey, 1), delay: 550 * time.Millisecond},
		RetryTemporaryAuth: true, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer close(finished)
		hub.ServeHTTP(writer, request)
	}))
	defer server.Close()
	ctx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	started := time.Now()
	connection, err := signedRawGuestAttempt(t, ctx, "ws"+strings.TrimPrefix(server.URL, "http"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	// Do not read the server close frame: there is deliberately no peer close
	// response. The parent context remains live throughout this assertion.
	select {
	case <-finished:
		if elapsed := time.Since(started); elapsed > 2*time.Second || ctx.Err() != nil {
			t.Fatalf("1013 close exceeded the original handshake budget: %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("1013 close waited for coder/websocket's fresh background timeout")
	}
}

func TestWelcomeWriteFailureConfirmsTransportBeforeExactRetirement(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := newMemoryAuthenticator(publicKey, 1)
	var mu sync.Mutex
	var events []string
	retired := make(chan struct{})
	resolved := make(chan struct{})
	hub, err := NewHub(HubOptions{Authenticator: auth,
		Observation: func(value Observation) {
			mu.Lock()
			events = append(events, value.Event)
			mu.Unlock()
			if value.Event == ObservationProductDisconnectResolved {
				close(resolved)
			}
		},
		Retirement: &RetirementPolicy{Capacity: 1, Readback: retirementTestReadback,
			Retire: func(ctx context.Context, identity Identity) (RetirementDisposition, error) {
				if err := auth.Disconnected(ctx, identity); err != nil {
					return "", err
				}
				close(retired)
				return RetirementReleased, nil
			}}})
	if err != nil {
		t.Fatal(err)
	}
	failed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hub.ServeHTTP(failWelcomeWriter{ResponseWriter: writer, failed: failed}, request)
	}))
	defer server.Close()
	ctx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	connection, err := signedRawGuestAttempt(t, ctx, "ws"+strings.TrimPrefix(server.URL, "http"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	select {
	case <-failed:
	case <-ctx.Done():
		t.Fatal("controlled transport did not reject welcome write")
	}
	select {
	case <-retired:
	case <-ctx.Done():
		t.Fatal("committed auth with failed welcome did not retire the old nonce")
	}
	select {
	case <-resolved:
	case <-ctx.Done():
		t.Fatal("exact retirement did not reach the resolved callback")
	}
	if !hub.RetirementReady() {
		t.Fatal("exact retired nonce did not restore local capacity")
	}
	mu.Lock()
	got := append([]string(nil), events...)
	mu.Unlock()
	want := []string{ObservationProductAuthAccepted, ObservationProductDisconnectPending,
		ObservationProductCloseCompleted, ObservationProductDisconnectResolved}
	if !slices.Equal(got, want) {
		t.Fatalf("welcome-failure event order = %v, want %v", got, want)
	}
	if _, _, err := hub.CallWithIdentity(ctx, "tenant-test", "wrk-test", "primary-code", "guest.health", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed welcome installed a peer: %v", err)
	}
	if err := hub.QuiesceObservation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := hub.ShutdownRetirement(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitForAgentReady(ctx context.Context, agent *Agent) error {
	for {
		if err := agent.Ready(ctx); err == nil {
			return nil
		} else if ctx.Err() != nil {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRotatedOrRevokedGuestCannotConnectAndAuthorityLossClosesChannel(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	auth := newMemoryAuthenticator(publicKey, 1)
	hub, _ := NewHub(HubOptions{Authenticator: auth, AuthorityPollPeriod: 10 * time.Millisecond})
	server := httptest.NewServer(hub)
	defer server.Close()
	agent, _ := NewAgent(AgentOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"), GuestID: "gst-test", BindingGeneration: 1, PrivateKey: privateKey, Handlers: map[string]OperationHandler{"guest.health": func(context.Context, json.RawMessage) (any, error) { return true, nil }}, ReconnectBackoff: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- agent.Run(ctx) }()
	_ = waitForCall(t, hub, "guest.health", nil)
	auth.revoke()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		callCtx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := hub.Call(callCtx, "tenant-test", "wrk-test", "primary-code", "guest.health", nil)
		stop()
		if errors.Is(err, ErrUnavailable) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Agent.Run() after revoke err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("revoked Agent did not terminate")
	}
	if auth.deniedAuthentications() < 1 {
		t.Fatal("revoked Agent exited without an observed denied reconnect authentication")
	}
	if err := agent.Ready(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoked Agent readiness = %v; want unavailable", err)
	}

	newPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	auth.rotate(newPublic, 2)
	oldAgent, _ := NewAgent(AgentOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"), GuestID: "gst-test", BindingGeneration: 1, PrivateKey: privateKey, Handlers: map[string]OperationHandler{"guest.health": func(context.Context, json.RawMessage) (any, error) { return true, nil }}})
	oldCtx, oldCancel := context.WithTimeout(context.Background(), time.Second)
	defer oldCancel()
	if err := oldAgent.Run(oldCtx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("rotated old Agent.Run() err=%v", err)
	}
}

func TestChallengeSignatureCannotBeReplayedAgainstAnotherChallenge(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	clientNonce, _ := randomNonce()
	firstNonce, _ := randomNonce()
	secondNonce, _ := randomNonce()
	hello := Hello{Type: "hello", GuestID: "gst-test", BindingGeneration: 1, ProtocolVersion: ProtocolVersion, Capabilities: []string{"guest.health"}, ClientNonce: clientNonce}
	first := AuthRequest{Hello: hello, Challenge: Challenge{Type: "challenge", Nonce: firstNonce, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}}
	signing, _ := first.SigningBytes()
	first.Hello.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, signing))
	signature, _ := first.SignatureBytes()
	if !ed25519.Verify(publicKey, signing, signature) {
		t.Fatal("first signature failed")
	}
	second := first
	second.Challenge.Nonce = secondNonce
	secondSigning, _ := second.SigningBytes()
	if ed25519.Verify(publicKey, secondSigning, signature) {
		t.Fatal("signature replay succeeded against a different challenge")
	}
}

func TestAttemptDigestBindsBothNoncesAndCanonicalRequest(t *testing.T) {
	challengeNonce, _ := randomNonce()
	clientNonce, _ := randomNonce()
	request := AuthRequest{
		Hello: Hello{Type: "hello", GuestID: "gst-test", BindingGeneration: 1,
			ProtocolVersion: ProtocolVersion, Capabilities: []string{"guest.health", "guest.files"}, ClientNonce: clientNonce},
		Challenge: Challenge{Type: "challenge", Nonce: challengeNonce,
			ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)},
	}
	digest, err := request.AttemptDigest()
	if err != nil || len(digest) != len("sha256:")+64 {
		t.Fatalf("AttemptDigest() length/error = %d/%v", len(digest), err)
	}
	reordered := request
	reordered.Hello.Capabilities = []string{"guest.files", "guest.health"}
	if got, err := reordered.AttemptDigest(); err != nil || got != digest {
		t.Fatalf("canonical capability order changed digest: %v", err)
	}
	mutations := []func(*AuthRequest){
		func(value *AuthRequest) { value.Challenge.Nonce, _ = randomNonce() },
		func(value *AuthRequest) { value.Hello.ClientNonce, _ = randomNonce() },
		func(value *AuthRequest) { value.Hello.BindingGeneration++ },
		func(value *AuthRequest) { value.Hello.Capabilities = []string{"guest.health"} },
	}
	for i, mutate := range mutations {
		changed := request
		mutate(&changed)
		if got, err := changed.AttemptDigest(); err != nil || got == digest {
			t.Fatalf("mutation %d was not bound: %v", i, err)
		}
	}
	invalid := request
	invalid.Hello.ClientNonce = "invalid"
	if got, err := invalid.AttemptDigest(); !errors.Is(err, ErrInvalid) || got != "" {
		t.Fatalf("invalid request digest = %q, %v", got, err)
	}
}

func TestPrivateObservationCorrelatesInstalledPeerAndCompletedTransportClose(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	auth := newMemoryAuthenticator(publicKey, 1)
	productEvents := make(chan Observation, 32)
	guestEvents := make(chan Observation, 32)
	hub, err := NewHub(HubOptions{Authenticator: auth, AuthorityPollPeriod: 10 * time.Millisecond,
		Observation: func(value Observation) { productEvents <- value }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	agent, err := NewAgent(AgentOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"),
		GuestID: "gst-test", BindingGeneration: 1, PrivateKey: privateKey,
		Handlers:    map[string]OperationHandler{"guest.health": func(context.Context, json.RawMessage) (any, error) { return true, nil }},
		Observation: func(value Observation) { guestEvents <- value }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- agent.Run(ctx) }()
	_ = waitForCall(t, hub, "guest.health", nil)
	installed := awaitObservation(t, productEvents, ObservationProductPeerInstalled)
	accepted := awaitObservation(t, guestEvents, ObservationGuestWelcomeAccepted)
	if installed.AttemptDigest == "" || installed.AttemptDigest != accepted.AttemptDigest {
		t.Fatal("Product and Guest did not bind the same installed attempt")
	}
	hub.Disconnect("tenant-test", "wrk-test", "primary-code")
	closed := awaitObservation(t, productEvents, ObservationProductCloseCompleted)
	terminated := awaitObservation(t, guestEvents, ObservationGuestReadTerminated)
	if closed.AttemptDigest != installed.AttemptDigest || terminated.AttemptDigest != installed.AttemptDigest ||
		closed.Reason != "operator_disconnect" {
		t.Fatalf("completed-close correlation/reason mismatch: %q", closed.Reason)
	}
	cancel()
	select {
	case <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("Agent did not stop")
	}
}

type blockedAuthorityMonitor struct {
	Authenticator
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (a *blockedAuthorityMonitor) CheckAuthority(ctx context.Context, identity Identity) error {
	a.once.Do(func() { close(a.entered) })
	<-a.release
	return a.Authenticator.CheckAuthority(ctx, identity)
}

func TestPrivateObservationQuiescenceJoinsActualAuthorityMonitor(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	auth := &blockedAuthorityMonitor{Authenticator: newMemoryAuthenticator(publicKey, 1),
		entered: make(chan struct{}), release: make(chan struct{})}
	hub, err := NewHub(HubOptions{Authenticator: auth, AuthorityPollPeriod: 10 * time.Millisecond,
		Observation: func(Observation) {}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	agent, err := NewAgent(AgentOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"),
		GuestID: "gst-test", BindingGeneration: 1, PrivateKey: privateKey,
		Handlers: map[string]OperationHandler{"guest.health": func(context.Context, json.RawMessage) (any, error) { return true, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	_ = waitForCall(t, hub, "guest.health", nil)
	select {
	case <-auth.entered:
	case <-ctx.Done():
		t.Fatal("actual authority monitor did not enter")
	}
	hub.Disconnect("tenant-test", "wrk-test", "primary-code")
	joined := make(chan error, 1)
	go func() { joined <- hub.QuiesceObservation(ctx) }()
	select {
	case err := <-joined:
		t.Fatalf("quiescence completed with active authority monitor: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(auth.release)
	select {
	case err := <-joined:
		if err != nil {
			t.Fatalf("joined authority monitor: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("authority monitor did not join")
	}
	cancel()
	select {
	case <-agentDone:
	case <-time.After(time.Second):
		t.Fatal("Guest agent did not stop after monitor join")
	}
}

func awaitObservation(t *testing.T, events <-chan Observation, kind string) Observation {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case value := <-events:
			if value.Event == kind {
				return value
			}
		case <-deadline:
			t.Fatalf("missing private observation %s", kind)
		}
	}
}

func waitForCall(t *testing.T, hub *Hub, operation string, payload any) json.RawMessage {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		response, err := hub.Call(ctx, "tenant-test", "wrk-test", "primary-code", operation, payload)
		cancel()
		if err == nil {
			return response
		}
		if time.Now().After(deadline) {
			t.Fatalf("Call(%s) err=%v", operation, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type memoryAuthenticator struct {
	mu          sync.Mutex
	publicKey   ed25519.PublicKey
	generation  int64
	active      bool
	connected   bool
	nonce       string
	authCount   int
	deniedCount int
}

func newMemoryAuthenticator(publicKey ed25519.PublicKey, generation int64) *memoryAuthenticator {
	return &memoryAuthenticator{publicKey: append(ed25519.PublicKey(nil), publicKey...), generation: generation, active: true}
}

func (a *memoryAuthenticator) Authenticate(_ context.Context, request AuthRequest) (Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	signing, err := request.SigningBytes()
	if err != nil {
		a.deniedCount++
		return Identity{}, ErrUnauthorized
	}
	signature, err := request.SignatureBytes()
	if err != nil || !a.active || a.connected || request.Hello.BindingGeneration != a.generation || !ed25519.Verify(a.publicKey, signing, signature) {
		a.deniedCount++
		return Identity{}, ErrUnauthorized
	}
	a.connected = true
	a.nonce = request.Hello.ClientNonce
	a.authCount++
	return Identity{TenantID: "tenant-test", WorkspaceID: "wrk-test", SlotKey: "primary-code", GuestID: request.Hello.GuestID, SlotGeneration: 1, BindingGeneration: a.generation, ProtocolVersion: ProtocolVersion, Capabilities: append([]string(nil), request.Hello.Capabilities...), ClientNonce: a.nonce, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (a *memoryAuthenticator) CheckAuthority(_ context.Context, identity Identity) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.active || !a.connected || identity.BindingGeneration != a.generation || identity.ClientNonce != a.nonce {
		return ErrUnauthorized
	}
	return nil
}
func (a *memoryAuthenticator) Disconnected(_ context.Context, identity Identity) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if identity.ClientNonce == a.nonce {
		a.connected = false
		a.nonce = ""
	}
	return nil
}
func (a *memoryAuthenticator) revoke() { a.mu.Lock(); a.active = false; a.mu.Unlock() }
func (a *memoryAuthenticator) rotate(publicKey ed25519.PublicKey, generation int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.publicKey = append(ed25519.PublicKey(nil), publicKey...)
	a.generation = generation
	a.active = true
	a.connected = false
	a.nonce = ""
}
func (a *memoryAuthenticator) authentications() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authCount
}
func (a *memoryAuthenticator) deniedAuthentications() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deniedCount
}

var _ Authenticator = (*memoryAuthenticator)(nil)
