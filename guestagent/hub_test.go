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
	mu         sync.Mutex
	publicKey  ed25519.PublicKey
	generation int64
	active     bool
	connected  bool
	nonce      string
	authCount  int
}

func newMemoryAuthenticator(publicKey ed25519.PublicKey, generation int64) *memoryAuthenticator {
	return &memoryAuthenticator{publicKey: append(ed25519.PublicKey(nil), publicKey...), generation: generation, active: true}
}

func (a *memoryAuthenticator) Authenticate(_ context.Context, request AuthRequest) (Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	signing, err := request.SigningBytes()
	if err != nil {
		return Identity{}, ErrUnauthorized
	}
	signature, err := request.SignatureBytes()
	if err != nil || !a.active || a.connected || request.Hello.BindingGeneration != a.generation || !ed25519.Verify(a.publicKey, signing, signature) {
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

var _ Authenticator = (*memoryAuthenticator)(nil)
