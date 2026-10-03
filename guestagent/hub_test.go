package guestagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	return Identity{TenantID: "tenant-test", WorkspaceID: "wrk-test", SlotKey: "primary-code", GuestID: request.Hello.GuestID, BindingGeneration: a.generation, ProtocolVersion: ProtocolVersion, Capabilities: append([]string(nil), request.Hello.Capabilities...), ClientNonce: a.nonce, ExpiresAt: time.Now().Add(time.Minute)}, nil
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
